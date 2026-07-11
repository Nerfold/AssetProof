use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField};
use common::crypto::{hex_decode, hex_encode};
use common::types::StoredInitProof;
use sp1_programs_common::io::{Sp1InitPublicValues, Sp1InitReserveEntry, Sp1InitStdin};
use sp1_sdk::blocking::{ProveRequest, Prover as BlockingProver, ProverClient};
use sp1_sdk::include_elf;
use sp1_sdk::{ProvingKey, SP1ProofWithPublicValues, SP1Stdin};

use crate::setup::{default_setup_dir, ensure_all_setups, load_init_vk};

const INIT_ELF: sp1_sdk::Elf = include_elf!("sp1-init-merkle");
const SMT_UPDATE_ELF: sp1_sdk::Elf = include_elf!("sp1-smt-update");
const SMT_INSERT_ELF: sp1_sdk::Elf = include_elf!("sp1-smt-insert");

#[derive(Clone)]
struct Sp1InitContext {
    prover: sp1_sdk::blocking::CpuProver,
    pk: Arc<sp1_sdk::SP1ProvingKey>,
}

static SP1_INIT_CONTEXT: OnceLock<Mutex<Option<Sp1InitContext>>> = OnceLock::new();

pub fn ensure_sp1_setup(setup_dir: &Path) -> Result<(), String> {
    ensure_all_setups(setup_dir, SMT_UPDATE_ELF, SMT_INSERT_ELF, INIT_ELF)
}

pub fn prove_init(
    stdin_value: Sp1InitStdin,
) -> Result<(String, String, String, Sp1InitPublicValues), String> {
    let ctx = sp1_context()?;
    let proof_bundle = run_sp1_proof(&ctx, &stdin_value)?;
    let public_values = decode_public_values(&proof_bundle);
    Ok((
        serialize_sp1_proof(&proof_bundle)?,
        serialize_sp1_vk(&ctx)?,
        hex_encode(proof_bundle.public_values.as_slice()),
        public_values,
    ))
}

pub fn verify_init_proof(proof: &StoredInitProof) -> Result<Sp1InitPublicValues, String> {
    if proof.sp1_proof_hex.is_empty() || proof.sp1_vk_hex.is_empty() {
        return Err("missing serialized SP1 init proof artifacts".to_string());
    }
    let ctx = sp1_context()?;
    let bundle = deserialize_sp1_proof(&proof.sp1_proof_hex)?;
    if !proof.sp1_public_values_hex.is_empty()
        && proof.sp1_public_values_hex != hex_encode(bundle.public_values.as_slice())
    {
        return Err("stored SP1 init public values do not match proof bundle".to_string());
    }
    let vk = deserialize_sp1_vk(&proof.sp1_vk_hex)?;
    ctx.prover
        .verify(&bundle, &vk, None)
        .map_err(|err| format!("sp1 init verify failed: {err}"))?;
    Ok(decode_public_values(&bundle))
}

pub fn build_init_stdin(
    chain_id: &str,
    state_root: &str,
    session_id: &str,
    init_salt: Fr,
    alpha: Fr,
    zeta: Fr,
    p_zeta: Fr,
    product_zeta: Fr,
    balance_total: i128,
    init_digest_hex: &str,
    ownership_artifact_digest_hex: &str,
    chain_balance_artifact_digest_hex: &str,
    addresses: &[String],
    encoded_addresses: &[Fr],
    balances: &[i128],
) -> Result<Sp1InitStdin, String> {
    if addresses.len() != encoded_addresses.len() || addresses.len() != balances.len() {
        return Err("init SP1 stdin vector length mismatch".to_string());
    }
    let reserves = addresses
        .iter()
        .zip(encoded_addresses.iter())
        .zip(balances.iter())
        .map(|((address, encoded), balance)| Sp1InitReserveEntry {
            address: address.clone(),
            encoded_address_le: fr_to_le_bytes(*encoded),
            balance: *balance,
        })
        .collect::<Vec<_>>();
    Ok(Sp1InitStdin {
        chain_id: chain_id.to_string(),
        state_root: state_root.to_string(),
        session_id: session_id.to_string(),
        reserve_count: addresses.len(),
        init_salt_le: fr_to_le_bytes(init_salt),
        alpha_le: fr_to_le_bytes(alpha),
        zeta_le: fr_to_le_bytes(zeta),
        p_zeta_le: fr_to_le_bytes(p_zeta),
        product_zeta_le: fr_to_le_bytes(product_zeta),
        balance_total,
        init_digest_hex: init_digest_hex.to_string(),
        ownership_artifact_digest_hex: ownership_artifact_digest_hex.to_string(),
        chain_balance_artifact_digest_hex: chain_balance_artifact_digest_hex.to_string(),
        reserves,
    })
}

fn sp1_context() -> Result<Sp1InitContext, String> {
    let slot = SP1_INIT_CONTEXT.get_or_init(|| Mutex::new(None));
    let mut guard = slot
        .lock()
        .map_err(|_| "sp1 init context poisoned".to_string())?;
    if let Some(ctx) = guard.as_ref() {
        return Ok(ctx.clone());
    }
    let setup_dir = default_setup_dir();
    let prover = ProverClient::builder().cpu().build();
    let vk = load_init_vk(&setup_dir, INIT_ELF)?;
    let pk = sp1_sdk::SP1ProvingKey::new(vk, INIT_ELF);
    let ctx = Sp1InitContext {
        prover,
        pk: Arc::new(pk),
    };
    *guard = Some(ctx.clone());
    Ok(ctx)
}

fn run_sp1_proof(
    ctx: &Sp1InitContext,
    stdin_value: &Sp1InitStdin,
) -> Result<SP1ProofWithPublicValues, String> {
    let mut stdin = SP1Stdin::new();
    stdin.write(stdin_value);
    ctx.prover
        .prove(&ctx.pk, stdin)
        .compressed()
        .run()
        .map_err(|err| format!("sp1 init prove failed: {err}"))
}

fn decode_public_values(bundle: &SP1ProofWithPublicValues) -> Sp1InitPublicValues {
    let mut public_values = bundle.public_values.clone();
    public_values.read::<Sp1InitPublicValues>()
}

fn serialize_sp1_proof(bundle: &SP1ProofWithPublicValues) -> Result<String, String> {
    let bytes =
        bincode::serialize(bundle).map_err(|err| format!("serialize sp1 init proof: {err}"))?;
    Ok(hex_encode(&bytes))
}

fn deserialize_sp1_proof(value: &str) -> Result<SP1ProofWithPublicValues, String> {
    let bytes = hex_decode(value)?;
    bincode::deserialize(&bytes).map_err(|err| format!("deserialize sp1 init proof: {err}"))
}

fn serialize_sp1_vk(ctx: &Sp1InitContext) -> Result<String, String> {
    let bytes = bincode::serialize(ctx.pk.verifying_key())
        .map_err(|err| format!("serialize sp1 init vk: {err}"))?;
    Ok(hex_encode(&bytes))
}

fn deserialize_sp1_vk(value: &str) -> Result<sp1_sdk::SP1VerifyingKey, String> {
    let bytes = hex_decode(value)?;
    bincode::deserialize(&bytes).map_err(|err| format!("deserialize sp1 init vk: {err}"))
}

fn fr_to_le_bytes(value: Fr) -> [u8; 32] {
    let raw = value.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    let len = raw.len().min(32);
    out[..len].copy_from_slice(&raw[..len]);
    out
}
