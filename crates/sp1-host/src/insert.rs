use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use common::crypto::{hash_bytes, hex_decode, hex_encode};
use common::types::StoredSmtProof;
use smt::insert::{
    apply_insert_in_place, apply_insert_with_witness, build_insert_witness, InsertResult,
    InsertWitness,
};
use smt::key::key_for_address;
use smt::proof::{CompactNonMembershipProof, SiblingRef};
use smt::state::{SmtPublicState, SmtState};
use sp1_programs_common::io::{
    Sp1DefaultNonMembershipProof, Sp1InsertPublicValues, Sp1InsertStdin, Sp1NonMembershipProof,
    Sp1SiblingRef,
};
use sp1_sdk::blocking::Prover as BlockingProver;
use sp1_sdk::include_elf;
use sp1_sdk::{ProvingKey, SP1ProofWithPublicValues, SP1Stdin};

use crate::proof_mode::configured_proof_mode;
use crate::prover_backend::{shared_cpu_prover, ProofGenerator};
use crate::setup::{default_setup_dir, load_insert_vk};

const SMT_INSERT_ELF: sp1_sdk::Elf = include_elf!("sp1-smt-insert");

#[derive(Clone)]
struct Sp1InsertContext {
    prover: sp1_sdk::blocking::CpuProver,
    generator: ProofGenerator,
    pk: Arc<sp1_sdk::SP1ProvingKey>,
}

static SP1_INSERT_CONTEXT: OnceLock<Mutex<Option<Sp1InsertContext>>> = OnceLock::new();

#[derive(Clone, Debug)]
pub struct InsertExecutionResult {
    pub next_state: SmtState,
    pub public_values: Sp1InsertPublicValues,
    pub instruction_count: u64,
}

fn sp1_insert_context() -> Result<Sp1InsertContext, String> {
    sp1_insert_context_with_setup_dir(&default_setup_dir())
}

fn sp1_insert_context_with_setup_dir(setup_dir: &Path) -> Result<Sp1InsertContext, String> {
    let slot = SP1_INSERT_CONTEXT.get_or_init(|| Mutex::new(None));
    let mut guard = slot
        .lock()
        .map_err(|_| "sp1 insert context poisoned".to_string())?;
    if let Some(ctx) = guard.as_ref() {
        return Ok(ctx.clone());
    }

    let prover = shared_cpu_prover();
    let generator = ProofGenerator::from_env()?;
    let vk = load_insert_vk(setup_dir, SMT_INSERT_ELF)?;
    let pk = sp1_sdk::SP1ProvingKey::new(vk, SMT_INSERT_ELF);
    let ctx = Sp1InsertContext {
        prover,
        generator,
        pk: Arc::new(pk),
    };
    *guard = Some(ctx.clone());
    Ok(ctx)
}

/// Preloads the SMT insert guest into the selected backend.
pub fn prepare_prover() -> Result<Duration, String> {
    let started = Instant::now();
    let ctx = sp1_insert_context()?;
    ctx.generator.prepare(&ctx.pk, "smt-insert")?;
    Ok(started.elapsed())
}

pub fn prove_insert(
    old_state: &SmtState,
    new_state_root: &str,
    witness: InsertWitness,
) -> Result<InsertResult, String> {
    let mut next_state = old_state.clone();
    let proof = prove_insert_into(old_state, &mut next_state, new_state_root, witness)?;
    Ok(InsertResult { next_state, proof })
}

/// Proves an insertion into an already reset mutable state without performing
/// a full-tree clone in the measured proof path.
pub fn prove_insert_into(
    old_state: &SmtState,
    next_state: &mut SmtState,
    new_state_root: &str,
    witness: InsertWitness,
) -> Result<StoredSmtProof, String> {
    if next_state.public_state() != old_state.public_state() {
        return Err("reset SMT state does not match insert old state".to_string());
    }
    let ctx = sp1_insert_context()?;
    let stdin_timer = common::profiling::PhaseTimer::start("smt-insert-host", "build_sp1_stdin");
    let stdin_value = build_sp1_insert_stdin(old_state, new_state_root, &witness)?;
    stdin_timer.finish();
    let transition_timer =
        common::profiling::PhaseTimer::start("smt-insert-host", "apply_private_transition");
    let mut proof = apply_insert_in_place(next_state, new_state_root, &witness)?;
    transition_timer.finish();
    let prove_timer = common::profiling::PhaseTimer::start("smt-insert-prover", "sp1_prove");
    let proof_bundle = run_sp1_insert_proof(&ctx, &stdin_value)?;
    prove_timer.finish();
    let finalize_timer = common::profiling::PhaseTimer::start("smt-insert-host", "finalize");
    let public_values = decode_insert_public_values(&proof_bundle)?;

    if public_values.old_state_root != old_state.state_root {
        return Err("sp1 insert old state root mismatch".to_string());
    }
    if public_values.new_state_root != new_state_root {
        return Err("sp1 insert new state root mismatch".to_string());
    }
    if public_values.old_smt_root != old_state.smt_root() {
        return Err("sp1 insert old smt root mismatch".to_string());
    }
    if public_values.depth != old_state.depth {
        return Err("sp1 insert SMT depth mismatch".to_string());
    }
    if public_values.new_smt_root != next_state.smt_root() {
        return Err("sp1 insert new smt root mismatch".to_string());
    }
    if public_values.inserted_balance != witness.balance {
        return Err("sp1 insert balance mismatch".to_string());
    }
    if public_values.new_balance_total != next_state.balance_total {
        return Err("sp1 insert balance total mismatch".to_string());
    }
    if public_values.old_balance_total != old_state.balance_total {
        return Err("sp1 insert old balance total mismatch".to_string());
    }
    if public_values.old_leaf_count != old_state.leaf_count()
        || public_values.new_leaf_count != next_state.leaf_count()
    {
        return Err("sp1 insert leaf count mismatch".to_string());
    }
    if public_values.transition_commitment != expected_insert_transition(&stdin_value) {
        return Err("sp1 insert transition commitment mismatch".to_string());
    }

    make_sp1_proof_public(&mut proof, &proof_bundle, &public_values)?;
    finalize_timer.finish();
    Ok(proof)
}

pub fn build_and_prove_insert(
    old_state: &SmtState,
    address: &str,
    balance: i128,
    new_state_root: &str,
    balance_blind_delta: ark_bls12_381::Fr,
) -> Result<InsertResult, String> {
    let witness_timer =
        common::profiling::PhaseTimer::start("smt-insert-host", "build_insert_witness");
    let witness = build_insert_witness(old_state, address, balance, balance_blind_delta)?;
    witness_timer.finish();
    prove_insert(old_state, new_state_root, witness)
}

pub fn build_and_prove_insert_into(
    old_state: &SmtState,
    next_state: &mut SmtState,
    address: &str,
    balance: i128,
    new_state_root: &str,
    balance_blind_delta: ark_bls12_381::Fr,
) -> Result<StoredSmtProof, String> {
    let witness_timer =
        common::profiling::PhaseTimer::start("smt-insert-host", "build_insert_witness");
    let witness = build_insert_witness(old_state, address, balance, balance_blind_delta)?;
    witness_timer.finish();
    prove_insert_into(old_state, next_state, new_state_root, witness)
}

pub fn execute_insert(
    old_state: &SmtState,
    new_state_root: &str,
    witness: InsertWitness,
) -> Result<InsertExecutionResult, String> {
    let result = apply_insert_with_witness(old_state, new_state_root, &witness)?;
    let ctx = sp1_insert_context()?;
    let stdin_value = build_sp1_insert_stdin(old_state, new_state_root, &witness)?;
    let (public_values, instruction_count) = run_sp1_insert_execute(&ctx, &stdin_value)?;

    if public_values.old_state_root != old_state.state_root {
        return Err("sp1 insert execute old state root mismatch".to_string());
    }
    if public_values.new_state_root != new_state_root {
        return Err("sp1 insert execute new state root mismatch".to_string());
    }
    if public_values.old_smt_root != old_state.smt_root() {
        return Err("sp1 insert execute old smt root mismatch".to_string());
    }
    if public_values.depth != old_state.depth {
        return Err("sp1 insert execute SMT depth mismatch".to_string());
    }
    if public_values.new_smt_root != result.next_state.smt_root() {
        return Err("sp1 insert execute new smt root mismatch".to_string());
    }
    if public_values.inserted_balance != witness.balance {
        return Err("sp1 insert execute balance mismatch".to_string());
    }
    if public_values.new_balance_total != result.next_state.balance_total {
        return Err("sp1 insert execute balance total mismatch".to_string());
    }
    if public_values.old_leaf_count != old_state.leaf_count()
        || public_values.new_leaf_count != result.next_state.leaf_count()
    {
        return Err("sp1 insert execute leaf count mismatch".to_string());
    }
    if public_values.transition_commitment != expected_insert_transition(&stdin_value) {
        return Err("sp1 insert execute transition commitment mismatch".to_string());
    }

    Ok(InsertExecutionResult {
        next_state: result.next_state,
        public_values,
        instruction_count,
    })
}

pub fn build_and_execute_insert(
    old_state: &SmtState,
    address: &str,
    balance: i128,
    new_state_root: &str,
    balance_blind_delta: ark_bls12_381::Fr,
) -> Result<InsertExecutionResult, String> {
    let witness = build_insert_witness(old_state, address, balance, balance_blind_delta)?;
    execute_insert(old_state, new_state_root, witness)
}

pub fn verify_insert_proof(
    old_state: &SmtState,
    new_state: &SmtState,
    proof: &StoredSmtProof,
) -> Result<(), String> {
    verify_insert_proof_public(&old_state.public_state(), &new_state.public_state(), proof)
}

pub fn verify_insert_proof_public(
    old_state: &SmtPublicState,
    new_state: &SmtPublicState,
    proof: &StoredSmtProof,
) -> Result<(), String> {
    verify_sp1_insert_metadata(old_state, new_state, proof)?;
    if proof.mode != "sp1" {
        return Err(format!("unexpected insert proof mode {}", proof.mode));
    }
    if proof.sp1_proof_hex.is_empty() {
        return Err("missing serialized sp1 insert proof".to_string());
    }

    let ctx = sp1_insert_context()?;
    let bundle = deserialize_sp1_proof(&proof.sp1_proof_hex)?;
    ctx.prover
        .verify(&bundle, ctx.pk.verifying_key(), None)
        .map_err(|err| format!("sp1 insert verify failed: {err}"))?;

    let public_values = decode_insert_public_values(&bundle)?;
    if public_values.old_state_root != old_state.state_root
        || public_values.new_state_root != new_state.state_root
    {
        return Err("sp1 insert public state root mismatch".to_string());
    }
    if public_values.old_smt_root != old_state.smt_root
        || public_values.new_smt_root != new_state.smt_root
    {
        return Err("sp1 insert public smt root mismatch".to_string());
    }
    if public_values.depth != old_state.depth || public_values.depth != new_state.depth {
        return Err("sp1 insert public SMT depth mismatch".to_string());
    }
    if public_values.inserted_balance != proof.aggregate_delta {
        return Err("sp1 insert public balance mismatch".to_string());
    }
    if public_values.old_balance_total != old_state.balance_total
        || public_values.new_balance_total != new_state.balance_total
    {
        return Err("sp1 insert public balance total mismatch".to_string());
    }
    if public_values.old_leaf_count != old_state.leaf_count
        || public_values.new_leaf_count != new_state.leaf_count
    {
        return Err("sp1 insert public leaf count mismatch".to_string());
    }
    if hex_encode(&public_values.transition_commitment) != proof.transition_commitment_hex {
        return Err("sp1 insert public transition commitment mismatch".to_string());
    }
    let proof_bytes = hex_decode(&proof.sp1_proof_hex)?;
    let expected_digest = hash_bytes("smt-sp1-insert-proof-v1", &[&proof_bytes]);
    if hex_encode(&expected_digest) != proof.proof_digest_hex {
        return Err("sp1 insert proof digest mismatch".to_string());
    }
    Ok(())
}

fn build_sp1_insert_stdin(
    old_state: &SmtState,
    new_state_root: &str,
    witness: &InsertWitness,
) -> Result<Sp1InsertStdin, String> {
    let multiproof = old_state
        .tree()
        .compact_multiproof(&[witness.address.clone()])?;
    let compact_entry = multiproof
        .entries
        .first()
        .ok_or_else(|| "missing compact insert proof entry".to_string())?;
    let non_membership_proof = match &compact_entry.proof {
        smt::proof::CompactAddressProof::Membership(_) => {
            return Err("insert address unexpectedly has membership compact proof".to_string())
        }
        smt::proof::CompactAddressProof::NonMembership(CompactNonMembershipProof::Default(
            proof,
        )) => Sp1NonMembershipProof::Default(Sp1DefaultNonMembershipProof {
            default_depth: proof.default_depth,
            siblings: proof.siblings.iter().map(convert_sibling_ref).collect(),
        }),
        smt::proof::CompactAddressProof::NonMembership(CompactNonMembershipProof::Collision(_)) => {
            return Err(format!(
                "cannot insert {}: occupied SMT path at depth {}; use a deeper tree",
                witness.address, old_state.depth
            ))
        }
    };

    Ok(Sp1InsertStdin {
        state_root: old_state.state_root.clone(),
        new_state_root: new_state_root.to_string(),
        depth: old_state.depth,
        old_smt_root: old_state.smt_root(),
        old_balance_total: old_state.balance_total,
        old_leaf_count: old_state.leaf_count(),
        frontier_hashes: multiproof.frontier_hashes,
        address: witness.address.clone(),
        key: key_for_address(&witness.address)?,
        balance: witness.balance,
        salt: witness.salt,
        transition_salt: witness.transition_salt,
        non_membership_proof,
    })
}

fn convert_sibling_ref(value: &SiblingRef) -> Sp1SiblingRef {
    match value {
        SiblingRef::Default => Sp1SiblingRef::Default,
        SiblingRef::Frontier(index) => Sp1SiblingRef::Frontier(*index),
    }
}

fn run_sp1_insert_proof(
    ctx: &Sp1InsertContext,
    stdin_value: &Sp1InsertStdin,
) -> Result<SP1ProofWithPublicValues, String> {
    let mut stdin = SP1Stdin::new();
    stdin.write(stdin_value);
    ctx.generator.prove(
        &ctx.prover,
        &ctx.pk,
        stdin,
        configured_proof_mode()?,
        "smt-insert",
    )
}

fn run_sp1_insert_execute(
    ctx: &Sp1InsertContext,
    stdin_value: &Sp1InsertStdin,
) -> Result<(Sp1InsertPublicValues, u64), String> {
    let mut stdin = SP1Stdin::new();
    stdin.write(stdin_value);
    let (mut public_values, report) = ctx
        .prover
        .execute(SMT_INSERT_ELF, stdin)
        .calculate_gas(false)
        .run()
        .map_err(|err| format!("sp1 insert execute failed: {err}"))?;
    Ok((
        public_values.read::<Sp1InsertPublicValues>(),
        report.total_instruction_count(),
    ))
}

fn decode_insert_public_values(
    bundle: &SP1ProofWithPublicValues,
) -> Result<Sp1InsertPublicValues, String> {
    let mut public_values = bundle.public_values.clone();
    Ok(public_values.read::<Sp1InsertPublicValues>())
}

fn deserialize_sp1_proof(value: &str) -> Result<SP1ProofWithPublicValues, String> {
    let bytes = hex_decode(value)?;
    bincode::deserialize(&bytes).map_err(|err| format!("deserialize sp1 insert proof: {err}"))
}

fn expected_insert_transition(stdin: &Sp1InsertStdin) -> [u8; 32] {
    sp1_programs_common::smt::insert_transition_commitment(
        &stdin.transition_salt,
        &stdin.key,
        stdin.balance,
        &stdin.salt,
    )
}

fn make_sp1_proof_public(
    proof: &mut StoredSmtProof,
    bundle: &SP1ProofWithPublicValues,
    public_values: &Sp1InsertPublicValues,
) -> Result<(), String> {
    let encoded =
        bincode::serialize(bundle).map_err(|err| format!("serialize sp1 insert proof: {err}"))?;
    proof.mode = "sp1".to_string();
    proof.scheme = "smt-poseidon-sp1-v1".to_string();
    proof.proof_digest_hex = hex_encode(&hash_bytes("smt-sp1-insert-proof-v1", &[&encoded]));
    proof.transition_commitment_hex = hex_encode(&public_values.transition_commitment);
    proof.sp1_proof_hex = hex_encode(&encoded);
    proof.balance_blind_delta = ark_bls12_381::Fr::from(0u64);
    proof.old_balance_commitment_hex.clear();
    proof.new_balance_commitment_hex.clear();
    proof.witness_hex.clear();
    proof.touched_addresses.clear();
    proof.membership_flags.clear();
    proof.sp1_vk_hex.clear();
    proof.sp1_public_values_hex.clear();
    Ok(())
}

fn verify_sp1_insert_metadata(
    old_state: &SmtPublicState,
    new_state: &SmtPublicState,
    proof: &StoredSmtProof,
) -> Result<(), String> {
    if proof.scheme != "smt-poseidon-sp1-v1" {
        return Err("unexpected proof scheme".to_string());
    }
    if proof.old_state_root != old_state.state_root || proof.new_state_root != new_state.state_root
    {
        return Err("insert state root labels mismatch".to_string());
    }
    if proof.old_smt_root_hex != smt::state::hex_string(&old_state.smt_root)
        || proof.new_smt_root_hex != smt::state::hex_string(&new_state.smt_root)
    {
        return Err("insert SMT root metadata mismatch".to_string());
    }
    if !proof.old_balance_commitment_hex.is_empty() || !proof.new_balance_commitment_hex.is_empty()
    {
        return Err("SP1 SMT proof contains obsolete external balance commitments".to_string());
    }
    let expected_delta = new_state
        .balance_total
        .checked_sub(old_state.balance_total)
        .ok_or_else(|| "insert balance delta overflow".to_string())?;
    if proof.aggregate_delta != expected_delta {
        return Err("insert aggregate delta metadata mismatch".to_string());
    }
    let expected_count = old_state
        .leaf_count
        .checked_add(1)
        .ok_or_else(|| "insert leaf count overflow".to_string())?;
    if new_state.leaf_count != expected_count {
        return Err("insert leaf count transition mismatch".to_string());
    }
    if !proof.witness_hex.is_empty()
        || !proof.touched_addresses.is_empty()
        || !proof.membership_flags.is_empty()
    {
        return Err("SP1 insert artifact contains private SMT witness metadata".to_string());
    }
    Ok(())
}
