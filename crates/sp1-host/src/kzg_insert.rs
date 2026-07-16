use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use ark_bls12_381::{Fr, G1Projective};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField};
use common::crypto::{hex_decode, hex_encode};
use common::types::{ChainBalanceProofInput, OwnershipWitnessInput};
use sp1_programs_common::io::{Sp1G1Affine, Sp1KzgInsertPublicValues, Sp1KzgInsertStdin};
use sp1_sdk::blocking::{ProveRequest, Prover as BlockingProver, ProverClient};
use sp1_sdk::include_elf;
use sp1_sdk::{ProvingKey, SP1ProofWithPublicValues, SP1Stdin};

use crate::init::{convert_chain_proof, convert_ownership};
use crate::proof_mode::{configured_proof_mode, ensure_trusted_vk, ConfiguredProofMode};
use crate::setup::{default_setup_dir, load_kzg_insert_vk};

const KZG_INSERT_ELF: sp1_sdk::Elf = include_elf!("sp1-kzg-insert");

#[derive(Clone)]
struct Context {
    prover: sp1_sdk::blocking::CpuProver,
    pk: Arc<sp1_sdk::SP1ProvingKey>,
}

static CONTEXT: OnceLock<Mutex<Option<Context>>> = OnceLock::new();

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
    balance_blind_delta: Fr,
    zeta: Fr,
    quotient_salt: [u8; 32],
    quotient_coefficients: &[Fr],
    quotient_commitment: [u8; 32],
    quotient_eval: Fr,
    quotient_eval_blind: Fr,
    eval_value_base: &G1Projective,
    eval_blind_base: &G1Projective,
    balance_value_base: &G1Projective,
    balance_blind_base: &G1Projective,
    c_x: &G1Projective,
    c_quotient_eval: &G1Projective,
    c_balance_delta: &G1Projective,
    old_accumulator_hex: &str,
    new_accumulator_hex: &str,
    old_balance_commitment_hex: &str,
    new_balance_commitment_hex: &str,
    reserve_count_before: usize,
    reserve_count_after: usize,
    transcript_hex: &str,
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
        balance_blind_delta_le: fr_to_le_bytes(balance_blind_delta),
        zeta_le: fr_to_le_bytes(zeta),
        quotient_salt,
        quotient_coefficients_le: quotient_coefficients
            .iter()
            .copied()
            .map(fr_to_le_bytes)
            .collect(),
        quotient_commitment,
        quotient_eval_le: fr_to_le_bytes(quotient_eval),
        quotient_eval_blind_le: fr_to_le_bytes(quotient_eval_blind),
        eval_value_base: point_to_io(eval_value_base),
        eval_blind_base: point_to_io(eval_blind_base),
        balance_value_base: point_to_io(balance_value_base),
        balance_blind_base: point_to_io(balance_blind_base),
        c_x: point_to_io(c_x),
        c_quotient_eval: point_to_io(c_quotient_eval),
        c_balance_delta: point_to_io(c_balance_delta),
        old_accumulator_hex: old_accumulator_hex.to_string(),
        new_accumulator_hex: new_accumulator_hex.to_string(),
        old_balance_commitment_hex: old_balance_commitment_hex.to_string(),
        new_balance_commitment_hex: new_balance_commitment_hex.to_string(),
        reserve_count_before,
        reserve_count_after,
        transcript_hex: transcript_hex.to_string(),
    })
}

pub fn quotient_commitment(coefficients: &[Fr], salt: &[u8; 32]) -> [u8; 32] {
    sp1_programs_common::io::insert_quotient_commitment(
        salt,
        coefficients.len(),
        coefficients.iter().copied().map(fr_to_le_bytes),
    )
}

pub fn commitment_params_digest(
    eval_value: &G1Projective,
    eval_blind: &G1Projective,
    balance_value: &G1Projective,
    balance_blind: &G1Projective,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"dynamic-poa-insert-commitment-params-v1");
    for point in [eval_value, eval_blind, balance_value, balance_blind] {
        let point = point_to_io(point);
        hasher.update(&point.x_be);
        hasher.update(&point.y_be);
    }
    hex_encode(hasher.finalize().as_bytes())
}

pub fn prove(
    stdin_value: Sp1KzgInsertStdin,
) -> Result<(String, String, String, Sp1KzgInsertPublicValues), String> {
    let ctx = context()?;
    let mut stdin = SP1Stdin::new();
    stdin.write(&stdin_value);
    let request = ctx.prover.prove(&ctx.pk, stdin);
    let bundle = match configured_proof_mode()? {
        ConfiguredProofMode::Groth16 => request.groth16().run(),
        ConfiguredProofMode::Plonk => request.plonk().run(),
        ConfiguredProofMode::Compressed => request.compressed().run(),
    }
    .map_err(|err| format!("SP1 KZG insert prove failed: {err}"))?;
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
    let prover = ProverClient::builder().cpu().build();
    let vk = load_kzg_insert_vk(setup_dir, KZG_INSERT_ELF)?;
    let pk = sp1_sdk::SP1ProvingKey::new(vk, KZG_INSERT_ELF);
    let ctx = Context {
        prover,
        pk: Arc::new(pk),
    };
    *guard = Some(ctx.clone());
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
