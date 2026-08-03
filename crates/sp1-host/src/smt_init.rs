use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use common::crypto::{hash_bytes, hex_decode, hex_encode};
use common::encoding::normalize_address;
use common::types::{
    ChainBalanceProofInput, InitChainBatchProofInput, InitProvingContext, InitReserveWitness,
    StoredSmtInitProof,
};
use smt::leaf::Leaf;
use smt::state::{SmtPublicState, SmtState};
use sp1_programs_common::io::{
    Sp1BinaryMerklePrefixProof, Sp1MerkleSubtree, Sp1SmtInitPublicValues, Sp1SmtInitReserveEntry,
    Sp1SmtInitStdin,
};
use sp1_sdk::blocking::Prover as BlockingProver;
use sp1_sdk::include_elf;
use sp1_sdk::{ProvingKey, SP1ProofWithPublicValues, SP1Stdin};

use crate::proof_mode::configured_proof_mode;
use crate::prover_backend::{shared_cpu_prover, ProofGenerator};
use crate::setup::{
    default_setup_dir, ensure_smt_init_setups, load_init_ownership_vk, load_smt_init_vk,
};

const SMT_INIT_ELF: sp1_sdk::Elf = include_elf!("sp1-smt-init");
const INIT_OWNERSHIP_ELF: sp1_sdk::Elf = include_elf!("sp1-init-ownership");

#[derive(Clone)]
struct Context {
    prover: sp1_sdk::blocking::CpuProver,
    generator: ProofGenerator,
    pk: Arc<sp1_sdk::SP1ProvingKey>,
}

static SMT_INIT_CONTEXT: OnceLock<Mutex<Option<Context>>> = OnceLock::new();

#[derive(Clone, Debug)]
pub struct SmtInitializationResult {
    pub state: SmtState,
    pub proof: StoredSmtInitProof,
}

pub fn prove_smt_initialization(
    context: &InitProvingContext,
    witnesses: &[InitReserveWitness],
    depth: usize,
) -> Result<SmtInitializationResult, String> {
    let validate_timer = common::profiling::PhaseTimer::start("smt-init-host", "validate_inputs");
    if witnesses.is_empty() {
        return Err("cannot initialize an empty SMT reserve set".to_string());
    }

    let mut previous_address: Option<&str> = None;
    for witness in witnesses {
        validate_chain_id(&context.chain_id, &witness.chain_balance_proof)?;
        let normalized = normalize_address(&witness.address)?;
        if witness.address != normalized {
            return Err(format!(
                "initialization address must be canonical: {}",
                witness.address
            ));
        }
        if witness.balance < 0 {
            return Err(format!("negative initial balance for {}", witness.address));
        }
        if let Some(previous) = previous_address {
            if witness.address.as_str() <= previous {
                return Err(
                    "initialization witnesses must be strictly sorted and duplicate-free"
                        .to_string(),
                );
            }
        }
        previous_address = Some(&witness.address);
    }
    validate_timer.finish();

    let state_timer = common::profiling::PhaseTimer::start("smt-init-host", "build_private_tree");
    let leaves = witnesses
        .iter()
        .map(|witness| {
            Leaf::new(
                witness.address.clone(),
                witness.balance,
                SmtState::random_salt(),
            )
        })
        .collect::<Result<Vec<_>, String>>()?;
    let state = SmtState::new(
        context.state_root.clone(),
        depth,
        leaves,
        SmtState::random_blind(),
    )?;
    state_timer.finish();

    let stdin_timer = common::profiling::PhaseTimer::start("smt-init-host", "build_smt_stdin");
    let init_stdin = build_smt_init_stdin(context, witnesses, &state)?;
    stdin_timer.finish();
    let ctx = smt_init_context()?;
    let prove_timer = common::profiling::PhaseTimer::start("smt-init-prover", "smt_sp1_prove");
    let bundle = run_smt_init_proof(&ctx, init_stdin)?;
    prove_timer.finish();
    let public = decode_smt_init_public_values(&bundle);
    let ownership_stdin_timer =
        common::profiling::PhaseTimer::start("smt-init-host", "build_ownership_stdin");
    let ownership_stdin = build_ownership_stdin(context, witnesses)?;
    ownership_stdin_timer.finish();
    let ownership_timer =
        common::profiling::PhaseTimer::start("smt-init-prover", "ownership_sp1_prove");
    let ownership = crate::init::prove_init_ownership(ownership_stdin)?;
    ownership_timer.finish();

    let finalize_timer = common::profiling::PhaseTimer::start("smt-init-host", "finalize");
    validate_split_public_values(context, &state.public_state(), &public, &ownership.public)?;
    let chain_bytes = bincode::serialize(&bundle)
        .map_err(|err| format!("serialize SP1 SMT initialization proof: {err}"))?;
    let ownership_bytes = hex_decode(&ownership.proof_hex)?;
    let digest = hash_bytes(
        "smt-initialization-sp1-proof-v1",
        &[&chain_bytes, &ownership_bytes],
    );
    let sp1_proof_hex = hex_encode(&chain_bytes);
    finalize_timer.finish();

    Ok(SmtInitializationResult {
        proof: StoredSmtInitProof {
            scheme: "smt-poseidon-init-sp1-v1".to_string(),
            mode: "sp1".to_string(),
            chain_id: context.chain_id.clone(),
            state_root: context.state_root.clone(),
            session_id: context.session_id.clone(),
            depth,
            smt_root_hex: hex_encode(&state.smt_root()),
            balance_total: state.balance_total,
            reserve_count: state.leaf_count(),
            reserve_commitment_hex: hex_encode(&public.reserve_commitment),
            uses_mock_inputs: public.uses_mock_inputs,
            proof_digest_hex: hex_encode(&digest),
            sp1_proof_hex,
            ownership_sp1_proof_hex: ownership.proof_hex,
        },
        state,
    })
}

/// Preloads both guests used by split SMT initialization.
///
/// Returned durations include host context/VK construction and, for CUDA, the
/// persistent worker startup plus one-time ELF setup. Benchmark runners record
/// these as preparation and exclude them from warmup/measured samples.
pub fn prepare_provers() -> Result<Vec<(&'static str, Duration)>, String> {
    let smt_started = Instant::now();
    let smt = smt_init_context()?;
    smt.generator.prepare(&smt.pk, "smt-init")?;
    let smt_elapsed = smt_started.elapsed();
    let ownership_elapsed = crate::init::prepare_ownership_prover()?;
    Ok(vec![
        ("smt-init", smt_elapsed),
        ("init-ownership", ownership_elapsed),
    ])
}

fn validate_chain_id(expected: &str, proof: &ChainBalanceProofInput) -> Result<(), String> {
    let actual = match proof {
        ChainBalanceProofInput::Mock { .. } => {
            if expected != "mock-chain" {
                return Err("mock chain proof used outside mock-chain".to_string());
            }
            return Ok(());
        }
        ChainBalanceProofInput::EthereumAccountProof { chain_id, .. }
        | ChainBalanceProofInput::GenericMerkleProof { chain_id, .. }
        | ChainBalanceProofInput::BinaryMerkleV1 { chain_id, .. }
        | ChainBalanceProofInput::EthereumVerkleBatchMember { chain_id, .. }
        | ChainBalanceProofInput::EthereumVerkleProof { chain_id, .. } => chain_id,
    };
    if actual != expected {
        return Err(format!(
            "chain proof chain_id mismatch: expected {expected}, got {actual}"
        ));
    }
    Ok(())
}

pub fn verify_smt_initialization(
    expected_context: &InitProvingContext,
    expected_state: &SmtPublicState,
    proof: &StoredSmtInitProof,
) -> Result<(), String> {
    if proof.scheme != "smt-poseidon-init-sp1-v1" || proof.mode != "sp1" {
        return Err("unexpected SMT initialization proof scheme or mode".to_string());
    }
    if proof.chain_id != expected_context.chain_id
        || proof.state_root != expected_context.state_root
        || proof.session_id != expected_context.session_id
    {
        return Err("SMT initialization context mismatch".to_string());
    }
    if proof.depth != expected_state.depth
        || proof.smt_root_hex != hex_encode(&expected_state.smt_root)
        || proof.balance_total != expected_state.balance_total
        || proof.reserve_count != expected_state.leaf_count
    {
        return Err("SMT initialization public state mismatch".to_string());
    }
    if proof.sp1_proof_hex.is_empty() || proof.ownership_sp1_proof_hex.is_empty() {
        return Err("missing SMT initialization SP1 proof".to_string());
    }

    let ctx = smt_init_context()?;
    let chain_bundle = deserialize_sp1_proof(&proof.sp1_proof_hex)?;
    ctx.prover
        .verify(&chain_bundle, ctx.pk.verifying_key(), None)
        .map_err(|err| format!("SP1 SMT initialization verify failed: {err}"))?;

    let ownership_prover = shared_cpu_prover();
    let ownership_vk = load_init_ownership_vk(&default_setup_dir(), INIT_OWNERSHIP_ELF)?;
    let ownership_bundle = deserialize_sp1_proof(&proof.ownership_sp1_proof_hex)?;
    ownership_prover
        .verify(&ownership_bundle, &ownership_vk, None)
        .map_err(|err| format!("SP1 SMT ownership verify failed: {err}"))?;

    let chain_public = decode_smt_init_public_values(&chain_bundle);
    let mut ownership_values = ownership_bundle.public_values.clone();
    let ownership_public =
        ownership_values.read::<sp1_programs_common::io::Sp1InitOwnershipPublicValues>();
    validate_split_public_values(
        expected_context,
        expected_state,
        &chain_public,
        &ownership_public,
    )?;
    if proof.reserve_count != chain_public.reserve_count
        || proof.reserve_commitment_hex != hex_encode(&chain_public.reserve_commitment)
        || proof.uses_mock_inputs != chain_public.uses_mock_inputs
    {
        return Err("stored SMT initialization public metadata mismatch".to_string());
    }

    let chain_bytes = hex_decode(&proof.sp1_proof_hex)?;
    let ownership_bytes = hex_decode(&proof.ownership_sp1_proof_hex)?;
    let digest = hash_bytes(
        "smt-initialization-sp1-proof-v1",
        &[&chain_bytes, &ownership_bytes],
    );
    if proof.proof_digest_hex != hex_encode(&digest) {
        return Err("SMT initialization proof digest mismatch".to_string());
    }
    Ok(())
}

fn build_smt_init_stdin(
    context: &InitProvingContext,
    witnesses: &[InitReserveWitness],
    state: &SmtState,
) -> Result<Sp1SmtInitStdin, String> {
    if state.leaf_count() != witnesses.len() {
        return Err("SMT initialization leaf/witness length mismatch".to_string());
    }
    let reserves = witnesses
        .iter()
        .map(|witness| {
            Ok(Sp1SmtInitReserveEntry {
                address: witness.address.clone(),
                balance: witness.balance,
                chain_balance_proof: crate::init::convert_chain_proof(
                    &witness.chain_balance_proof,
                )?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let leaf_salts = witnesses
        .iter()
        .map(|witness| {
            state
                .tree()
                .get(&witness.address)
                .map(|leaf| leaf.salt)
                .ok_or_else(|| format!("missing SMT leaf for {}", witness.address))
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
    Ok(Sp1SmtInitStdin {
        chain_id: context.chain_id.clone(),
        state_root: context.state_root.clone(),
        session_id: context.session_id.clone(),
        depth: state.depth,
        reserves,
        leaf_salts,
        merkle_prefix_proof,
    })
}

fn build_ownership_stdin(
    context: &InitProvingContext,
    witnesses: &[InitReserveWitness],
) -> Result<sp1_programs_common::io::Sp1InitOwnershipStdin, String> {
    let reserves = witnesses
        .iter()
        .map(|witness| {
            Ok(sp1_programs_common::io::Sp1InitOwnershipEntry {
                address: witness.address.clone(),
                balance: witness.balance,
                ownership: crate::init::convert_ownership(&witness.ownership)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(sp1_programs_common::io::Sp1InitOwnershipStdin {
        chain_id: context.chain_id.clone(),
        state_root: context.state_root.clone(),
        session_id: context.session_id.clone(),
        reserves,
    })
}

fn validate_split_public_values(
    context: &InitProvingContext,
    state: &SmtPublicState,
    chain: &Sp1SmtInitPublicValues,
    ownership: &sp1_programs_common::io::Sp1InitOwnershipPublicValues,
) -> Result<(), String> {
    if chain.chain_id != context.chain_id
        || chain.state_root != context.state_root
        || chain.session_id != context.session_id
        || ownership.chain_id != context.chain_id
        || ownership.state_root != context.state_root
        || ownership.session_id != context.session_id
    {
        return Err("split SMT initialization context mismatch".to_string());
    }
    if chain.depth != state.depth
        || chain.smt_root != state.smt_root
        || chain.balance_total != state.balance_total
        || chain.reserve_count != state.leaf_count
    {
        return Err("SMT initialization guest/state mismatch".to_string());
    }
    if chain.reserve_count != ownership.reserve_count
        || chain.reserve_commitment != ownership.reserve_commitment
    {
        return Err("SMT initialization split proofs use different reserves".to_string());
    }
    if chain.uses_mock_inputs != ownership.uses_mock_inputs {
        return Err("SMT initialization mixes mock and real witness modes".to_string());
    }
    Ok(())
}

fn smt_init_context() -> Result<Context, String> {
    let slot = SMT_INIT_CONTEXT.get_or_init(|| Mutex::new(None));
    let mut guard = slot
        .lock()
        .map_err(|_| "SP1 SMT initialization context poisoned".to_string())?;
    if let Some(context) = guard.as_ref() {
        return Ok(context.clone());
    }
    let prover = shared_cpu_prover();
    let generator = ProofGenerator::from_env()?;
    let vk = load_smt_init_vk(&default_setup_dir(), SMT_INIT_ELF)?;
    let pk = sp1_sdk::SP1ProvingKey::new(vk, SMT_INIT_ELF);
    let context = Context {
        prover,
        generator,
        pk: Arc::new(pk),
    };
    *guard = Some(context.clone());
    Ok(context)
}

fn run_smt_init_proof(
    context: &Context,
    stdin_value: Sp1SmtInitStdin,
) -> Result<SP1ProofWithPublicValues, String> {
    if common::profiling::enabled() {
        let mut stdin = SP1Stdin::new();
        stdin.write(&true);
        stdin.write(&stdin_value);
        let started = std::time::Instant::now();
        let (_, report) = context
            .prover
            .execute(SMT_INIT_ELF, stdin)
            .calculate_gas(true)
            .run()
            .map_err(|err| format!("SP1 SMT initialization execute failed: {err}"))?;
        crate::profiling::record_execution("smt-init", started.elapsed(), &report);
    }
    let mut stdin = SP1Stdin::new();
    stdin.write(&false);
    stdin.write(&stdin_value);
    context.generator.prove(
        &context.prover,
        &context.pk,
        stdin,
        configured_proof_mode()?,
        "smt-init",
    )
}

fn decode_smt_init_public_values(bundle: &SP1ProofWithPublicValues) -> Sp1SmtInitPublicValues {
    let mut public_values = bundle.public_values.clone();
    public_values.read::<Sp1SmtInitPublicValues>()
}

fn deserialize_sp1_proof(value: &str) -> Result<SP1ProofWithPublicValues, String> {
    let bytes = hex_decode(value)?;
    bincode::deserialize(&bytes)
        .map_err(|err| format!("deserialize SP1 SMT initialization proof: {err}"))
}

pub fn ensure_setup(setup_dir: &Path) -> Result<(), String> {
    ensure_smt_init_setups(setup_dir, SMT_INIT_ELF, INIT_OWNERSHIP_ELF)
}
