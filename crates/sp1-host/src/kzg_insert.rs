use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use ark_bls12_381::{Fr, G1Projective};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField};
use common::crypto::{hex_decode, hex_encode};
use common::types::{ChainBalanceProofInput, OwnershipWitnessInput};
use sp1_programs_common::io::{Sp1G1Affine, Sp1KzgInsertPublicValues, Sp1KzgInsertStdin};
use sp1_sdk::blocking::{Prover as BlockingProver, ProverClient};
use sp1_sdk::include_elf;
use sp1_sdk::{ProvingKey, SP1ProofWithPublicValues, SP1Stdin};

use crate::init::{convert_chain_proof, convert_ownership};
use crate::proof_mode::{configured_proof_mode, ensure_trusted_vk};
use crate::prover_backend::ProofGenerator;
use crate::setup::{default_setup_dir, load_kzg_insert_vk};

const KZG_INSERT_ELF: sp1_sdk::Elf = include_elf!("sp1-kzg-insert");

#[derive(Clone)]
struct Context {
    prover: sp1_sdk::blocking::CpuProver,
    generator: ProofGenerator,
    pk: Arc<sp1_sdk::SP1ProvingKey>,
}

static CONTEXT: OnceLock<Mutex<Option<Context>>> = OnceLock::new();

/// Preloads the insert guest into the selected prover backend. The returned
/// duration includes context/VK loading and, for CUDA, one-time guest setup.
pub fn prepare_prover() -> Result<Duration, String> {
    let started = Instant::now();
    let ctx = context()?;
    ctx.generator.prepare(&ctx.pk, "kzg-insert")?;
    Ok(started.elapsed())
}

#[allow(clippy::too_many_arguments)]
pub fn build_stdin(
    chain_id: &str,
    state_root: &str,
    address: &str,
    balance: i128,
    ownership: &OwnershipWitnessInput,
    chain_balance_proof: &ChainBalanceProofInput,
    encoded_address: Fr,
    encoded_address_blind: Fr,
    balance_blind: Fr,
    eval_value_base: &G1Projective,
    eval_blind_base: &G1Projective,
    balance_value_base: &G1Projective,
    balance_blind_base: &G1Projective,
    c_u: &G1Projective,
    c_balance: &G1Projective,
) -> Result<Sp1KzgInsertStdin, String> {
    Ok(Sp1KzgInsertStdin {
        chain_id: chain_id.to_string(),
        state_root: state_root.to_string(),
        address: address.to_string(),
        balance,
        ownership: convert_ownership(ownership)?,
        chain_balance_proof: convert_chain_proof(chain_balance_proof)?,
        encoded_address_le: fr_to_le_bytes(encoded_address),
        encoded_address_blind_le: fr_to_le_bytes(encoded_address_blind),
        balance_blind_le: fr_to_le_bytes(balance_blind),
        eval_value_base: point_to_io(eval_value_base),
        eval_blind_base: point_to_io(eval_blind_base),
        balance_value_base: point_to_io(balance_value_base),
        balance_blind_base: point_to_io(balance_blind_base),
        c_u: point_to_io(c_u),
        c_balance: point_to_io(c_balance),
    })
}

pub fn commitment_params_digest(
    eval_value: &G1Projective,
    eval_blind: &G1Projective,
    balance_value: &G1Projective,
    balance_blind: &G1Projective,
) -> String {
    let mut hasher = sp1_programs_common::ethereum_eoa::Keccak256Stream::new();
    hasher.update(b"dynamic-poa-hidden-insert-commitment-params-keccak-v1");
    for point in [eval_value, eval_blind, balance_value, balance_blind] {
        let point = point_to_io(point);
        hasher.update(&point.x_be);
        hasher.update(&point.y_be);
    }
    hex_encode(&hasher.finalize())
}

pub fn prove(
    stdin_value: Sp1KzgInsertStdin,
) -> Result<(String, String, String, Sp1KzgInsertPublicValues), String> {
    let ctx = context()?;
    if common::profiling::enabled() {
        let execution_span = tracing::info_span!("poa_sp1_execute", guest = "kzg-insert");
        let _execution_span_guard = execution_span.enter();
        let mut execution_stdin = SP1Stdin::new();
        execution_stdin.write(&true);
        execution_stdin.write(&stdin_value);
        let start = Instant::now();
        let (_, report) = ctx
            .prover
            .execute(KZG_INSERT_ELF, execution_stdin)
            .calculate_gas(true)
            .run()
            .map_err(|err| format!("SP1 KZG insert profile execute failed: {err}"))?;
        crate::profiling::record_execution("kzg-insert", start.elapsed(), &report);
    }
    let mut stdin = SP1Stdin::new();
    stdin.write(&false);
    stdin.write(&stdin_value);
    drop(stdin_value);
    let proof_span = tracing::info_span!("poa_sp1_proof", guest = "kzg-insert");
    let _proof_span_guard = proof_span.enter();
    let prove_start = Instant::now();
    let bundle_result = ctx.generator.prove(
        &ctx.prover,
        &ctx.pk,
        stdin,
        configured_proof_mode()?,
        "kzg-insert",
    );
    common::profiling::record_phase("sp1-prove", "kzg-insert", prove_start.elapsed());
    let bundle = bundle_result.map_err(|err| format!("SP1 KZG insert prove failed: {err}"))?;
    let public_values = decode_public_values(&bundle);
    Ok((
        serialize_proof(&bundle)?,
        serialize_vk(&ctx)?,
        hex_encode(bundle.public_values.as_slice()),
        public_values,
    ))
}

pub fn verify(
    proof_hex: &str,
    vk_hex: &str,
    public_values_hex: &str,
) -> Result<Sp1KzgInsertPublicValues, String> {
    let ctx = context()?;
    ensure_trusted_vk(vk_hex, ctx.pk.verifying_key(), hex_decode, "KZG insert")?;
    let bundle = deserialize_proof(proof_hex)?;
    if !public_values_hex.is_empty()
        && public_values_hex != hex_encode(bundle.public_values.as_slice())
    {
        return Err("stored SP1 KZG insert public values mismatch".to_string());
    }
    ctx.prover
        .verify(&bundle, ctx.pk.verifying_key(), None)
        .map_err(|err| format!("SP1 KZG insert verify failed: {err}"))?;
    Ok(decode_public_values(&bundle))
}

pub fn point_matches(value: &Sp1G1Affine, expected: &G1Projective) -> bool {
    value == &point_to_io(expected)
}

fn context() -> Result<Context, String> {
    context_with_setup_dir(&default_setup_dir())
}

fn context_with_setup_dir(setup_dir: &Path) -> Result<Context, String> {
    let slot = CONTEXT.get_or_init(|| Mutex::new(None));
    let mut guard = slot
        .lock()
        .map_err(|_| "SP1 KZG insert context poisoned".to_string())?;
    if let Some(ctx) = guard.as_ref() {
        return Ok(ctx.clone());
    }
    let start = Instant::now();
    let prover = ProverClient::builder().cpu().build();
    let generator = ProofGenerator::from_env()?;
    let vk = load_kzg_insert_vk(setup_dir, KZG_INSERT_ELF)?;
    let pk = sp1_sdk::SP1ProvingKey::new(vk, KZG_INSERT_ELF);
    let ctx = Context {
        prover,
        generator,
        pk: Arc::new(pk),
    };
    *guard = Some(ctx.clone());
    common::profiling::record_phase("sp1-context", "kzg-insert", start.elapsed());
    Ok(ctx)
}

pub(crate) fn point_to_io(point: &G1Projective) -> Sp1G1Affine {
    let affine = point.into_affine();
    Sp1G1Affine {
        x_be: fixed_be(affine.x.into_bigint().to_bytes_be(), 48),
        y_be: fixed_be(affine.y.into_bigint().to_bytes_be(), 48),
    }
}

fn fixed_be(raw: Vec<u8>, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let copy_len = raw.len().min(len);
    out[len - copy_len..].copy_from_slice(&raw[raw.len() - copy_len..]);
    out
}

fn fr_to_le_bytes(value: Fr) -> [u8; 32] {
    let raw = value.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    let len = raw.len().min(32);
    out[..len].copy_from_slice(&raw[..len]);
    out
}

fn decode_public_values(bundle: &SP1ProofWithPublicValues) -> Sp1KzgInsertPublicValues {
    let mut public_values = bundle.public_values.clone();
    public_values.read::<Sp1KzgInsertPublicValues>()
}

fn serialize_proof(bundle: &SP1ProofWithPublicValues) -> Result<String, String> {
    let bytes = bincode::serialize(bundle)
        .map_err(|err| format!("serialize SP1 KZG insert proof: {err}"))?;
    Ok(hex_encode(&bytes))
}

fn deserialize_proof(value: &str) -> Result<SP1ProofWithPublicValues, String> {
    let bytes = hex_decode(value)?;
    bincode::deserialize(&bytes).map_err(|err| format!("deserialize SP1 KZG insert proof: {err}"))
}

fn serialize_vk(ctx: &Context) -> Result<String, String> {
    let bytes = bincode::serialize(ctx.pk.verifying_key())
        .map_err(|err| format!("serialize SP1 KZG insert VK: {err}"))?;
    Ok(hex_encode(&bytes))
}
