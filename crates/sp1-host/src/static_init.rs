use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use common::crypto::{hash_bytes, hex_decode, hex_encode};
use common::types::{InitChainBatchProofInput, InitProvingContext, InitReserveWitness};
use sp1_programs_common::io::{
    Sp1BinaryMerklePrefixProof, Sp1MerkleSubtree, Sp1StaticInitPublicValues,
    Sp1StaticInitReserveEntry, Sp1StaticInitStdin,
};
use sp1_sdk::blocking::Prover as BlockingProver;
use sp1_sdk::include_elf;
use sp1_sdk::{ProvingKey, SP1ProofWithPublicValues, SP1Stdin};

use crate::proof_mode::configured_proof_mode;
use crate::prover_backend::{shared_cpu_prover, ProofGenerator};
use crate::setup::{default_setup_dir, ensure_static_init_setup, load_static_init_vk};
use crate::witness::{convert_chain_proof, convert_ownership};

const STATIC_INIT_ELF: sp1_sdk::Elf = include_elf!("sp1-static-init");

#[derive(Clone)]
struct Context {
    prover: sp1_sdk::blocking::CpuProver,
    generator: ProofGenerator,
    pk: Arc<sp1_sdk::SP1ProvingKey>,
}

static CONTEXT: OnceLock<Mutex<Option<Context>>> = OnceLock::new();

#[derive(Clone, Debug)]
pub struct StaticInitProof {
    pub proof_hex: String,
    pub proof_digest_hex: String,
}

pub fn ensure_setup(setup_dir: &Path) -> Result<(), String> {
    ensure_static_init_setup(setup_dir, STATIC_INIT_ELF)
}

/// Initializes the CPU verification context and selected proof backend, then
/// uploads the guest to a persistent CUDA worker if applicable.
pub fn prepare_prover() -> Result<Duration, String> {
    let started = Instant::now();
    let ctx = context()?;
    ctx.generator.prepare(&ctx.pk, "static-init")?;
    Ok(started.elapsed())
}

pub fn prove_static_initialization(
    proving_context: &InitProvingContext,
    witnesses: &[InitReserveWitness],
) -> Result<(StaticInitProof, Sp1StaticInitPublicValues), String> {
    let stdin_timer = common::profiling::PhaseTimer::start("static-init-host", "build_sp1_stdin");
    let stdin_value = build_stdin(proving_context, witnesses)?;
    stdin_timer.finish();
    let ctx = context()?;

    if common::profiling::enabled() {
        let mut stdin = SP1Stdin::new();
        stdin.write(&true);
        stdin.write(&stdin_value);
        let started = Instant::now();
        let (_, report) = ctx
            .prover
            .execute(STATIC_INIT_ELF, stdin)
            .calculate_gas(true)
            .run()
            .map_err(|err| format!("SP1 static initialization execute failed: {err}"))?;
        crate::profiling::record_execution("static-init", started.elapsed(), &report);
    }

    let mut stdin = SP1Stdin::new();
    stdin.write(&false);
    stdin.write(&stdin_value);
    drop(stdin_value);
    let prove_timer = common::profiling::PhaseTimer::start("static-init-prover", "sp1_prove");
    let bundle = ctx.generator.prove(
        &ctx.prover,
        &ctx.pk,
        stdin,
        configured_proof_mode()?,
        "static-init",
    )?;
    prove_timer.finish();

    let public = decode_public_values(&bundle);
    validate_public_context(proving_context, witnesses, &public)?;
    let bytes = bincode::serialize(&bundle)
        .map_err(|err| format!("serialize static initialization proof: {err}"))?;
    Ok((
        StaticInitProof {
            proof_hex: hex_encode(&bytes),
            proof_digest_hex: hex_encode(&hash_bytes("static-poa-init-sp1-v1", &[&bytes])),
        },
        public,
    ))
}

pub fn verify_static_initialization(
    expected_context: &InitProvingContext,
    expected_reserve_count: usize,
    proof: &StaticInitProof,
) -> Result<Sp1StaticInitPublicValues, String> {
    let bytes = hex_decode(&proof.proof_hex)?;
    if hex_encode(&hash_bytes("static-poa-init-sp1-v1", &[&bytes])) != proof.proof_digest_hex {
        return Err("static initialization proof digest mismatch".to_string());
    }
    let bundle: SP1ProofWithPublicValues = bincode::deserialize(&bytes)
        .map_err(|err| format!("deserialize static initialization proof: {err}"))?;
    let ctx = context()?;
    ctx.prover
        .verify(&bundle, ctx.pk.verifying_key(), None)
        .map_err(|err| format!("SP1 static initialization verify failed: {err}"))?;
    let public = decode_public_values(&bundle);
    if public.chain_id != expected_context.chain_id
        || public.state_root != expected_context.state_root
        || public.session_id != expected_context.session_id
        || public.reserve_count != expected_reserve_count
    {
        return Err("static initialization public context mismatch".to_string());
    }
    Ok(public)
}

fn build_stdin(
    context: &InitProvingContext,
    witnesses: &[InitReserveWitness],
) -> Result<Sp1StaticInitStdin, String> {
    if witnesses.is_empty() {
        return Err("static initialization requires at least one reserve".to_string());
    }
    let mut ordered = witnesses.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.address.cmp(&right.address));
    let reserves = ordered
        .iter()
        .map(|witness| {
            let address_bytes: [u8; 20] = hex_decode(
                witness
                    .address
                    .strip_prefix("0x")
                    .unwrap_or(&witness.address),
            )?
            .try_into()
            .map_err(|_| "static initialization address must contain 20 bytes".to_string())?;
            Ok(Sp1StaticInitReserveEntry {
                address: witness.address.clone(),
                address_bytes,
                balance: witness.balance,
                ownership: convert_ownership(&witness.ownership)?,
                chain_balance_proof: convert_chain_proof(&witness.chain_balance_proof)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let merkle_prefix_proof = context.chain_batch_proof.as_ref().map(|proof| match proof {
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
    Ok(Sp1StaticInitStdin {
        chain_id: context.chain_id.clone(),
        state_root: context.state_root.clone(),
        session_id: context.session_id.clone(),
        reserves,
        merkle_prefix_proof,
    })
}

fn validate_public_context(
    context: &InitProvingContext,
    witnesses: &[InitReserveWitness],
    public: &Sp1StaticInitPublicValues,
) -> Result<(), String> {
    if public.chain_id != context.chain_id
        || public.state_root != context.state_root
        || public.session_id != context.session_id
        || public.reserve_count != witnesses.len()
    {
        return Err("static initialization guest returned an unexpected context".to_string());
    }
    Ok(())
}

fn context() -> Result<Context, String> {
    let slot = CONTEXT.get_or_init(|| Mutex::new(None));
    let mut guard = slot
        .lock()
        .map_err(|_| "static initialization context poisoned".to_string())?;
    if let Some(ctx) = guard.as_ref() {
        return Ok(ctx.clone());
    }
    let started = Instant::now();
    let prover = shared_cpu_prover();
    let generator = ProofGenerator::from_env()?;
    let vk = load_static_init_vk(&default_setup_dir(), STATIC_INIT_ELF)?;
    let pk = sp1_sdk::SP1ProvingKey::new(vk, STATIC_INIT_ELF);
    let ctx = Context {
        prover,
        generator,
        pk: Arc::new(pk),
    };
    *guard = Some(ctx.clone());
    common::profiling::record_phase("sp1-context", "static-init", started.elapsed());
    Ok(ctx)
}

fn decode_public_values(bundle: &SP1ProofWithPublicValues) -> Sp1StaticInitPublicValues {
    let mut public_values = bundle.public_values.clone();
    public_values.read::<Sp1StaticInitPublicValues>()
}
