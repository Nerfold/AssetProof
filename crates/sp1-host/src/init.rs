use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use ark_bls12_381::{Fr, G1Projective};
use ark_ff::{BigInteger, PrimeField};
use common::crypto::{hex_decode, hex_encode};
use common::types::{InitChainBatchProofInput, InitReserveWitness, StoredInitProof};
use sp1_programs_common::io::{Sp1BinaryMerklePrefixProof, Sp1G1Affine, Sp1MerkleSubtree};
#[cfg(feature = "smt-sp1")]
use sp1_programs_common::io::{
    Sp1InitOwnershipEntry, Sp1InitOwnershipPublicValues, Sp1InitOwnershipStdin,
};
use sp1_programs_common::io::{Sp1InitPublicValues, Sp1InitReserveEntry, Sp1InitStdin};
use sp1_sdk::blocking::Prover as BlockingProver;
use sp1_sdk::include_elf;
use sp1_sdk::{ProvingKey, SP1ProofWithPublicValues, SP1Stdin};

use crate::proof_mode::{configured_proof_mode, ensure_trusted_vk};
use crate::prover_backend::{shared_cpu_prover, ProofGenerator};
#[cfg(feature = "smt-sp1")]
use crate::setup::load_init_ownership_vk;
use crate::setup::{
    default_setup_dir, ensure_protocol_setup_components, ensure_protocol_setups, load_init_vk,
};
use crate::witness::{convert_chain_proof, convert_ownership};

const INIT_ELF: sp1_sdk::Elf = include_elf!("sp1-init");
#[cfg(feature = "smt-sp1")]
const INIT_OWNERSHIP_ELF: sp1_sdk::Elf = include_elf!("sp1-init-ownership");
const KZG_INSERT_ELF: sp1_sdk::Elf = include_elf!("sp1-kzg-insert");

#[derive(Clone)]
struct Sp1InitContext {
    prover: sp1_sdk::blocking::CpuProver,
    generator: ProofGenerator,
    pk: Arc<sp1_sdk::SP1ProvingKey>,
}

static SP1_INIT_CONTEXT: OnceLock<Mutex<Option<Sp1InitContext>>> = OnceLock::new();
#[cfg(feature = "smt-sp1")]
static SP1_INIT_OWNERSHIP_CONTEXT: OnceLock<Mutex<Option<Sp1InitContext>>> = OnceLock::new();

pub struct ProvedInit {
    pub proof_hex: String,
    pub public: Sp1InitPublicValues,
}

#[cfg(feature = "smt-sp1")]
pub struct ProvedInitOwnership {
    pub proof_hex: String,
    pub public: Sp1InitOwnershipPublicValues,
}

pub fn ensure_sp1_setup(setup_dir: &Path) -> Result<(), String> {
    ensure_protocol_setups(setup_dir, INIT_ELF, KZG_INSERT_ELF)
}

pub fn ensure_sp1_setup_components(
    setup_dir: &Path,
    include_init: bool,
    include_insert: bool,
) -> Result<(), String> {
    ensure_protocol_setup_components(
        setup_dir,
        include_init.then_some(INIT_ELF),
        include_insert.then_some(KZG_INSERT_ELF),
    )
}

/// Preloads the unified initialization guest into the selected prover backend.
///
/// Durations include runtime context/VK loading. For CUDA they additionally
/// include persistent worker startup and the one-time guest ELF setup.
pub fn prepare_prover() -> Result<Duration, String> {
    let started = Instant::now();
    let init = sp1_context()?;
    init.generator.prepare(&init.pk, "init")?;
    Ok(started.elapsed())
}

/// Preloads only the shared ECDSA ownership guest.
///
/// SMT initialization reuses this guest but must not also prepare the unrelated
/// KZG/Merkle initialization guest. Keeping this hook separate lets benchmark
/// runners move process startup, VK loading, and CUDA ELF setup outside sample
/// timers without changing the proof path.
#[cfg(feature = "smt-sp1")]
pub fn prepare_ownership_prover() -> Result<Duration, String> {
    let started = Instant::now();
    let ownership = sp1_ownership_context()?;
    ownership
        .generator
        .prepare(&ownership.pk, "init-ownership")?;
    Ok(started.elapsed())
}

#[cfg(feature = "smt-sp1")]
pub fn prove_init_ownership(
    ownership_stdin: Sp1InitOwnershipStdin,
) -> Result<ProvedInitOwnership, String> {
    let ownership_ctx = sp1_ownership_context()?;
    let ownership_bundle = run_sp1_proof(
        &ownership_ctx,
        INIT_OWNERSHIP_ELF,
        ownership_stdin,
        "init-ownership",
    )?;
    Ok(ProvedInitOwnership {
        proof_hex: serialize_sp1_proof(&ownership_bundle)?,
        public: decode_ownership_public_values(&ownership_bundle),
    })
}

pub fn prove_init(init_stdin: Sp1InitStdin) -> Result<ProvedInit, String> {
    let init_ctx = sp1_context()?;
    let init_bundle = run_sp1_proof(&init_ctx, INIT_ELF, init_stdin, "init")?;
    Ok(ProvedInit {
        proof_hex: serialize_sp1_proof(&init_bundle)?,
        public: decode_public_values(&init_bundle),
    })
}

pub fn verify_init_proof(proof: &StoredInitProof) -> Result<Sp1InitPublicValues, String> {
    if proof.sp1_proof_hex.is_empty() {
        return Err("missing serialized unified SP1 init proof artifact".to_string());
    }
    let init_ctx = sp1_context()?;
    let init_bundle = deserialize_sp1_proof(&proof.sp1_proof_hex)?;
    if !proof.sp1_public_values_hex.is_empty()
        && proof.sp1_public_values_hex != hex_encode(init_bundle.public_values.as_slice())
    {
        return Err("stored SP1 init public values do not match proof bundle".to_string());
    }
    if !proof.sp1_vk_hex.is_empty() {
        ensure_trusted_vk(
            &proof.sp1_vk_hex,
            init_ctx.pk.verifying_key(),
            hex_decode,
            "unified init",
        )?;
    }
    init_ctx
        .prover
        .verify(&init_bundle, init_ctx.pk.verifying_key(), None)
        .map_err(|err| format!("SP1 unified initialization verify failed: {err}"))?;
    Ok(decode_public_values(&init_bundle))
}

pub fn build_init_stdin(
    chain_id: &str,
    state_root: &str,
    session_id: &str,
    alpha: Fr,
    zeta: Fr,
    p_zeta: Fr,
    product_zeta: Fr,
    balance_total: i128,
    balance_blind: Fr,
    shape_salt: [u8; 32],
    shape_commitment: [u8; 32],
    eval_blind: Fr,
    balance_value_base: &G1Projective,
    balance_blind_base: &G1Projective,
    eval_value_base: &G1Projective,
    eval_blind_base: &G1Projective,
    balance_commitment: &G1Projective,
    eval_commitment: &G1Projective,
    addresses: &[String],
    encoded_addresses: &[Fr],
    balances: &[i128],
    witnesses: &[&InitReserveWitness],
    chain_batch_proof: Option<&InitChainBatchProofInput>,
) -> Result<Sp1InitStdin, String> {
    if addresses.len() != encoded_addresses.len()
        || addresses.len() != balances.len()
        || addresses.len() != witnesses.len()
    {
        return Err("init SP1 stdin vector length mismatch".to_string());
    }
    let reserves = addresses
        .iter()
        .zip(encoded_addresses.iter())
        .zip(balances.iter())
        .zip(witnesses.iter())
        .map(|(((address, encoded), balance), witness)| {
            Ok(Sp1InitReserveEntry {
                address: address.clone(),
                encoded_address_le: fr_to_le_bytes(*encoded),
                balance: *balance,
                ownership: convert_ownership(&witness.ownership)?,
                chain_balance_proof: convert_chain_proof(&witness.chain_balance_proof)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let merkle_prefix_proof = chain_batch_proof.map(|proof| match proof {
        InitChainBatchProofInput::BinaryMerklePrefixV2 {
            depth,
            suffix_subtrees,
        } => Sp1BinaryMerklePrefixProof {
            depth: *depth,
            suffix_subtrees: suffix_subtrees
                .iter()
                .map(|(level, root)| Sp1MerkleSubtree {
                    level: *level,
                    root: *root,
                })
                .collect(),
        },
    });
    Ok(Sp1InitStdin {
        chain_id: chain_id.to_string(),
        state_root: state_root.to_string(),
        session_id: session_id.to_string(),
        reserve_count: addresses.len(),
        alpha_le: fr_to_le_bytes(alpha),
        zeta_le: fr_to_le_bytes(zeta),
        p_zeta_le: fr_to_le_bytes(p_zeta),
        product_zeta_le: fr_to_le_bytes(product_zeta),
        balance_total,
        balance_blind_le: fr_to_le_bytes(balance_blind),
        shape_salt,
        eval_blind_le: fr_to_le_bytes(eval_blind),
        balance_value_base: crate::kzg_insert::point_to_io(balance_value_base),
        balance_blind_base: crate::kzg_insert::point_to_io(balance_blind_base),
        eval_value_base: crate::kzg_insert::point_to_io(eval_value_base),
        eval_blind_base: crate::kzg_insert::point_to_io(eval_blind_base),
        balance_commitment: crate::kzg_insert::point_to_io(balance_commitment),
        shape_commitment,
        eval_commitment: crate::kzg_insert::point_to_io(eval_commitment),
        commitment_params_digest_hex: commitment_params_digest(
            balance_value_base,
            balance_blind_base,
            eval_value_base,
            eval_blind_base,
        ),
        merkle_prefix_proof,
        reserves,
    })
}

#[cfg(feature = "smt-sp1")]
pub fn build_init_ownership_stdin(
    chain_id: &str,
    state_root: &str,
    session_id: &str,
    addresses: &[String],
    balances: &[i128],
    witnesses: &[&InitReserveWitness],
) -> Result<Sp1InitOwnershipStdin, String> {
    if addresses.len() != balances.len() || addresses.len() != witnesses.len() {
        return Err("init ownership SP1 stdin vector length mismatch".to_string());
    }
    let reserves = addresses
        .iter()
        .zip(balances.iter())
        .zip(witnesses.iter())
        .map(|((address, balance), witness)| {
            Ok(Sp1InitOwnershipEntry {
                address: address.clone(),
                balance: *balance,
                ownership: convert_ownership(&witness.ownership)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(Sp1InitOwnershipStdin {
        chain_id: chain_id.to_string(),
        state_root: state_root.to_string(),
        session_id: session_id.to_string(),
        reserves,
    })
}

pub fn commitment_params_digest(
    balance_value: &G1Projective,
    balance_blind: &G1Projective,
    eval_value: &G1Projective,
    eval_blind: &G1Projective,
) -> String {
    let points = [balance_value, balance_blind, eval_value, eval_blind]
        .into_iter()
        .map(crate::kzg_insert::point_to_io)
        .collect::<Vec<Sp1G1Affine>>();
    let mut hasher = sp1_programs_common::ethereum_eoa::Keccak256Stream::new();
    hasher.update(b"dynamic-poa-init-commitment-params-keccak-v3");
    for point in &points {
        hasher.update(&point.x_be);
        hasher.update(&point.y_be);
    }
    hex_encode(&hasher.finalize())
}

pub fn shape_commitment(alpha: Fr, roots: &[Fr], salt: &[u8; 32]) -> [u8; 32] {
    sp1_programs_common::io::init_shape_commitment(
        salt,
        &fr_to_le_bytes(alpha),
        roots.len(),
        roots.iter().copied().map(fr_to_le_bytes),
    )
}

fn sp1_context() -> Result<Sp1InitContext, String> {
    let slot = SP1_INIT_CONTEXT.get_or_init(|| Mutex::new(None));
    let mut guard = slot
        .lock()
        .map_err(|_| "sp1 init context poisoned".to_string())?;
    if let Some(ctx) = guard.as_ref() {
        return Ok(ctx.clone());
    }
    let start = Instant::now();
    let setup_dir = default_setup_dir();
    let prover = shared_cpu_prover();
    let generator = ProofGenerator::from_env()?;
    let vk = load_init_vk(&setup_dir, INIT_ELF)?;
    let pk = sp1_sdk::SP1ProvingKey::new(vk, INIT_ELF);
    let ctx = Sp1InitContext {
        prover,
        generator,
        pk: Arc::new(pk),
    };
    *guard = Some(ctx.clone());
    common::profiling::record_phase("sp1-context", "init", start.elapsed());
    Ok(ctx)
}

#[cfg(feature = "smt-sp1")]
fn sp1_ownership_context() -> Result<Sp1InitContext, String> {
    let slot = SP1_INIT_OWNERSHIP_CONTEXT.get_or_init(|| Mutex::new(None));
    let mut guard = slot
        .lock()
        .map_err(|_| "sp1 init ownership context poisoned".to_string())?;
    if let Some(ctx) = guard.as_ref() {
        return Ok(ctx.clone());
    }
    let start = Instant::now();
    let setup_dir = default_setup_dir();
    let prover = shared_cpu_prover();
    let generator = ProofGenerator::from_env()?;
    let vk = load_init_ownership_vk(&setup_dir, INIT_OWNERSHIP_ELF)?;
    let pk = sp1_sdk::SP1ProvingKey::new(vk, INIT_OWNERSHIP_ELF);
    let ctx = Sp1InitContext {
        prover,
        generator,
        pk: Arc::new(pk),
    };
    *guard = Some(ctx.clone());
    common::profiling::record_phase("sp1-context", "init-ownership", start.elapsed());
    Ok(ctx)
}

fn run_sp1_proof<T: serde::Serialize>(
    ctx: &Sp1InitContext,
    elf: sp1_sdk::Elf,
    stdin_value: T,
    guest: &str,
) -> Result<SP1ProofWithPublicValues, String> {
    if common::profiling::enabled() {
        let execution_span = tracing::info_span!("poa_sp1_execute", guest = guest);
        let _execution_span_guard = execution_span.enter();
        let mut execution_stdin = SP1Stdin::new();
        execution_stdin.write(&true);
        execution_stdin.write(&stdin_value);
        let start = Instant::now();
        let (_, report) = ctx
            .prover
            .execute(elf, execution_stdin)
            .calculate_gas(true)
            .run()
            .map_err(|err| format!("sp1 {guest} profile execute failed: {err}"))?;
        crate::profiling::record_execution(guest, start.elapsed(), &report);
    }
    let mut stdin = SP1Stdin::new();
    stdin.write(&false);
    stdin.write(&stdin_value);
    drop(stdin_value);
    let proof_span = tracing::info_span!("poa_sp1_proof", guest = guest);
    let _proof_span_guard = proof_span.enter();
    let prove_start = Instant::now();
    let result = ctx
        .generator
        .prove(&ctx.prover, &ctx.pk, stdin, configured_proof_mode()?, guest);
    common::profiling::record_phase("sp1-prove", guest, prove_start.elapsed());
    result
}

fn decode_public_values(bundle: &SP1ProofWithPublicValues) -> Sp1InitPublicValues {
    let mut public_values = bundle.public_values.clone();
    public_values.read::<Sp1InitPublicValues>()
}

#[cfg(feature = "smt-sp1")]
fn decode_ownership_public_values(
    bundle: &SP1ProofWithPublicValues,
) -> Sp1InitOwnershipPublicValues {
    let mut public_values = bundle.public_values.clone();
    public_values.read::<Sp1InitOwnershipPublicValues>()
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

fn fr_to_le_bytes(value: Fr) -> [u8; 32] {
    let raw = value.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    let len = raw.len().min(32);
    out[..len].copy_from_slice(&raw[..len]);
    out
}
