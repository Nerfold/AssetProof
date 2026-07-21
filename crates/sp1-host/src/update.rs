use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use common::crypto::{hash_bytes, hex_decode, hex_encode};
use common::types::{Delta, StoredSmtProof};
use smt::key::key_for_address;
use smt::proof::{CompactAddressProof, CompactNonMembershipProof, CompactProofEntry, SiblingRef};
use smt::state::{SmtPublicState, SmtState};
use smt::update::{
    apply_update_with_witness, build_update_multiproof, build_update_witness, UpdateResult,
    UpdateWitness,
};
use sp1_programs_common::io::{
    Sp1AddressProof, Sp1CollisionNonMembershipProof, Sp1DefaultNonMembershipProof, Sp1Leaf,
    Sp1MembershipProof, Sp1NonMembershipProof, Sp1SiblingRef, Sp1UpdateEntryWitness,
    Sp1UpdatePublicValues, Sp1UpdateStdin,
};
use sp1_sdk::blocking::{Prover as BlockingProver, ProverClient};
use sp1_sdk::include_elf;
use sp1_sdk::{ProvingKey, SP1ProofWithPublicValues, SP1Stdin};

use crate::proof_mode::configured_proof_mode;
use crate::prover_backend::ProofGenerator;
use crate::setup::{default_setup_dir, ensure_smt_setups, load_update_vk};

const SMT_UPDATE_ELF: sp1_sdk::Elf = include_elf!("sp1-smt-update");
const SMT_INSERT_ELF: sp1_sdk::Elf = include_elf!("sp1-smt-insert");
const SMT_INIT_ELF: sp1_sdk::Elf = include_elf!("sp1-smt-init");
const INIT_OWNERSHIP_ELF: sp1_sdk::Elf = include_elf!("sp1-init-ownership");

#[derive(Clone)]
struct Sp1Context {
    prover: sp1_sdk::blocking::CpuProver,
    generator: ProofGenerator,
    pk: Arc<sp1_sdk::SP1ProvingKey>,
}

static SP1_CONTEXT: OnceLock<Mutex<Option<Sp1Context>>> = OnceLock::new();

#[derive(Clone, Debug)]
pub struct UpdateExecutionResult {
    pub next_state: SmtState,
    pub public_values: Sp1UpdatePublicValues,
    pub instruction_count: u64,
}

fn sp1_context() -> Result<Sp1Context, String> {
    sp1_context_with_setup_dir(&default_setup_dir())
}

fn sp1_context_with_setup_dir(setup_dir: &Path) -> Result<Sp1Context, String> {
    let slot = SP1_CONTEXT.get_or_init(|| Mutex::new(None));
    let mut guard = slot
        .lock()
        .map_err(|_| "sp1 context poisoned".to_string())?;
    if let Some(ctx) = guard.as_ref() {
        return Ok(ctx.clone());
    }

    let prover = ProverClient::builder().cpu().build();
    let generator = ProofGenerator::from_env()?;
    let vk = load_update_vk(setup_dir, SMT_UPDATE_ELF)?;
    let pk = sp1_sdk::SP1ProvingKey::new(vk, SMT_UPDATE_ELF);
    let ctx = Sp1Context {
        prover,
        generator,
        pk: Arc::new(pk),
    };
    *guard = Some(ctx.clone());
    Ok(ctx)
}

pub fn ensure_sp1_setup(setup_dir: &Path) -> Result<(), String> {
    ensure_smt_setups(
        setup_dir,
        SMT_INIT_ELF,
        INIT_OWNERSHIP_ELF,
        SMT_UPDATE_ELF,
        SMT_INSERT_ELF,
    )
}

pub fn prove_update(
    old_state: &SmtState,
    new_state_root: &str,
    witness: UpdateWitness,
) -> Result<UpdateResult, String> {
    let mut result = apply_update_with_witness(old_state, new_state_root, &witness)?;

    let ctx = sp1_context()?;
    let stdin_value = build_sp1_stdin(old_state, new_state_root, &witness)?;
    let proof_bundle = run_sp1_proof(&ctx, &stdin_value)?;
    let public_values = decode_public_values(&proof_bundle)?;

    if public_values.old_state_root != old_state.state_root {
        return Err("sp1 old state root mismatch".to_string());
    }
    if public_values.new_state_root != new_state_root {
        return Err("sp1 new state root mismatch".to_string());
    }
    if public_values.old_smt_root != old_state.smt_root() {
        return Err("sp1 old smt root mismatch".to_string());
    }
    if public_values.depth != old_state.depth {
        return Err("sp1 SMT depth mismatch".to_string());
    }
    if public_values.new_smt_root != result.next_state.smt_root() {
        return Err("sp1 new smt root mismatch".to_string());
    }
    if public_values.aggregate_delta != result.proof.aggregate_delta {
        return Err("sp1 aggregate delta mismatch".to_string());
    }
    if public_values.old_balance_total != old_state.balance_total {
        return Err("sp1 old balance total mismatch".to_string());
    }
    if public_values.new_balance_total != result.next_state.balance_total {
        return Err("sp1 balance total mismatch".to_string());
    }
    if public_values.old_leaf_count != old_state.leaf_count()
        || public_values.new_leaf_count != result.next_state.leaf_count()
    {
        return Err("sp1 leaf count mismatch".to_string());
    }

    let expected_transition = expected_update_transition(&stdin_value);
    if public_values.transition_commitment != expected_transition {
        return Err("sp1 update transition commitment mismatch".to_string());
    }

    make_sp1_proof_public(&mut result.proof, &proof_bundle, &public_values)?;
    Ok(result)
}

pub fn build_and_prove_update(
    old_state: &SmtState,
    deltas: &[Delta],
    new_state_root: &str,
    balance_blind_delta: ark_bls12_381::Fr,
) -> Result<UpdateResult, String> {
    let witness = build_update_witness(old_state, deltas, balance_blind_delta)?;
    prove_update(old_state, new_state_root, witness)
}

pub fn execute_update(
    old_state: &SmtState,
    new_state_root: &str,
    witness: UpdateWitness,
) -> Result<UpdateExecutionResult, String> {
    let result = apply_update_with_witness(old_state, new_state_root, &witness)?;
    let ctx = sp1_context()?;
    let stdin_value = build_sp1_stdin(old_state, new_state_root, &witness)?;
    let (public_values, instruction_count) = run_sp1_execute(&ctx, &stdin_value)?;

    if public_values.old_state_root != old_state.state_root {
        return Err("sp1 execute old state root mismatch".to_string());
    }
    if public_values.new_state_root != new_state_root {
        return Err("sp1 execute new state root mismatch".to_string());
    }
    if public_values.old_smt_root != old_state.smt_root() {
        return Err("sp1 execute old smt root mismatch".to_string());
    }
    if public_values.depth != old_state.depth {
        return Err("sp1 execute SMT depth mismatch".to_string());
    }
    if public_values.new_smt_root != result.next_state.smt_root() {
        return Err("sp1 execute new smt root mismatch".to_string());
    }
    if public_values.aggregate_delta != result.proof.aggregate_delta {
        return Err("sp1 execute aggregate delta mismatch".to_string());
    }
    if public_values.new_balance_total != result.next_state.balance_total {
        return Err("sp1 execute balance total mismatch".to_string());
    }
    if public_values.old_leaf_count != old_state.leaf_count()
        || public_values.new_leaf_count != result.next_state.leaf_count()
    {
        return Err("sp1 execute leaf count mismatch".to_string());
    }
    if public_values.transition_commitment != expected_update_transition(&stdin_value) {
        return Err("sp1 execute transition commitment mismatch".to_string());
    }

    Ok(UpdateExecutionResult {
        next_state: result.next_state,
        public_values,
        instruction_count,
    })
}

pub fn build_and_execute_update(
    old_state: &SmtState,
    deltas: &[Delta],
    new_state_root: &str,
    balance_blind_delta: ark_bls12_381::Fr,
) -> Result<UpdateExecutionResult, String> {
    let witness = build_update_witness(old_state, deltas, balance_blind_delta)?;
    execute_update(old_state, new_state_root, witness)
}

pub fn verify_update_proof(
    old_state: &SmtState,
    new_state: &SmtState,
    proof: &StoredSmtProof,
) -> Result<(), String> {
    verify_update_proof_public(&old_state.public_state(), &new_state.public_state(), proof)
}

pub fn verify_update_proof_public(
    old_state: &SmtPublicState,
    new_state: &SmtPublicState,
    proof: &StoredSmtProof,
) -> Result<(), String> {
    verify_sp1_update_metadata(old_state, new_state, proof)?;
    if proof.mode != "sp1" {
        return Err(format!("unexpected update proof mode {}", proof.mode));
    }
    if proof.sp1_proof_hex.is_empty() {
        return Err("missing serialized sp1 proof".to_string());
    }

    let ctx = sp1_context()?;
    let bundle = deserialize_sp1_proof(&proof.sp1_proof_hex)?;
    ctx.prover
        .verify(&bundle, ctx.pk.verifying_key(), None)
        .map_err(|err| format!("sp1 verify failed: {err}"))?;

    let public_values = decode_public_values(&bundle)?;
    if public_values.old_state_root != old_state.state_root
        || public_values.new_state_root != new_state.state_root
    {
        return Err("sp1 public state root mismatch".to_string());
    }
    if public_values.old_smt_root != old_state.smt_root
        || public_values.new_smt_root != new_state.smt_root
    {
        return Err("sp1 public smt root mismatch".to_string());
    }
    if public_values.depth != old_state.depth || public_values.depth != new_state.depth {
        return Err("sp1 public SMT depth mismatch".to_string());
    }
    if public_values.aggregate_delta != proof.aggregate_delta {
        return Err("sp1 public aggregate delta mismatch".to_string());
    }
    if public_values.old_balance_total != old_state.balance_total
        || public_values.new_balance_total != new_state.balance_total
    {
        return Err("sp1 public balance total mismatch".to_string());
    }
    if public_values.old_leaf_count != old_state.leaf_count
        || public_values.new_leaf_count != new_state.leaf_count
    {
        return Err("sp1 public leaf count mismatch".to_string());
    }
    if hex_encode(&public_values.transition_commitment) != proof.transition_commitment_hex {
        return Err("sp1 public transition commitment mismatch".to_string());
    }
    let proof_bytes = hex_decode(&proof.sp1_proof_hex)?;
    let expected_digest = hash_bytes("smt-sp1-update-proof-v1", &[&proof_bytes]);
    if hex_encode(&expected_digest) != proof.proof_digest_hex {
        return Err("sp1 update proof digest mismatch".to_string());
    }
    Ok(())
}

fn build_sp1_stdin(
    old_state: &SmtState,
    new_state_root: &str,
    witness: &UpdateWitness,
) -> Result<Sp1UpdateStdin, String> {
    let mut entries = Vec::with_capacity(witness.entries.len());
    let tree = old_state.tree();
    let multiproof = build_update_multiproof(
        old_state,
        &witness
            .entries
            .iter()
            .map(|entry| Delta {
                address: entry.address.clone(),
                delta: entry.delta,
            })
            .collect::<Vec<_>>(),
    )?;

    for (entry, compact_entry) in witness.entries.iter().zip(multiproof.entries.iter()) {
        let (old_leaf, proof) = build_compact_sp1_entry(tree, entry, compact_entry)?;
        entries.push(Sp1UpdateEntryWitness {
            address: entry.address.clone(),
            key: key_for_address(&entry.address)?,
            delta: entry.delta,
            old_leaf,
            proof,
        });
    }

    Ok(Sp1UpdateStdin {
        state_root: old_state.state_root.clone(),
        new_state_root: new_state_root.to_string(),
        depth: old_state.depth,
        old_smt_root: old_state.smt_root(),
        old_balance_total: old_state.balance_total,
        old_leaf_count: old_state.leaf_count(),
        transition_salt: witness.transition_salt,
        frontier_hashes: multiproof.frontier_hashes,
        entries,
    })
}

fn build_compact_sp1_entry(
    tree: &smt::tree::SparseMerkleTree,
    witness_entry: &smt::update::UpdateWitnessEntry,
    compact_entry: &CompactProofEntry,
) -> Result<(Option<Sp1Leaf>, Sp1AddressProof), String> {
    let old_leaf = tree.get(&witness_entry.address).map(|leaf| Sp1Leaf {
        key: leaf.key,
        balance: leaf.balance,
        salt: leaf.salt,
    });

    let proof = match &compact_entry.proof {
        CompactAddressProof::Membership(proof) => Sp1AddressProof::Membership(Sp1MembershipProof {
            siblings: proof.siblings.iter().map(convert_sibling_ref).collect(),
        }),
        CompactAddressProof::NonMembership(CompactNonMembershipProof::Default(proof)) => {
            Sp1AddressProof::NonMembership(Sp1NonMembershipProof::Default(
                Sp1DefaultNonMembershipProof {
                    default_depth: proof.default_depth,
                    siblings: proof.siblings.iter().map(convert_sibling_ref).collect(),
                },
            ))
        }
        CompactAddressProof::NonMembership(CompactNonMembershipProof::Collision(proof)) => {
            Sp1AddressProof::NonMembership(Sp1NonMembershipProof::Collision(
                Sp1CollisionNonMembershipProof {
                    collision_leaf: Sp1Leaf {
                        key: key_for_address(&proof.collision_address)?,
                        balance: proof.collision_balance,
                        salt: proof.collision_salt,
                    },
                    siblings: proof.siblings.iter().map(convert_sibling_ref).collect(),
                },
            ))
        }
    };

    Ok((old_leaf, proof))
}

fn convert_sibling_ref(value: &SiblingRef) -> Sp1SiblingRef {
    match value {
        SiblingRef::Default => Sp1SiblingRef::Default,
        SiblingRef::Frontier(index) => Sp1SiblingRef::Frontier(*index),
    }
}

fn run_sp1_proof(
    ctx: &Sp1Context,
    stdin_value: &Sp1UpdateStdin,
) -> Result<SP1ProofWithPublicValues, String> {
    let mut stdin = SP1Stdin::new();
    stdin.write(stdin_value);
    ctx.generator.prove(
        &ctx.prover,
        &ctx.pk,
        stdin,
        configured_proof_mode()?,
        "smt-update",
    )
}

fn run_sp1_execute(
    ctx: &Sp1Context,
    stdin_value: &Sp1UpdateStdin,
) -> Result<(Sp1UpdatePublicValues, u64), String> {
    let mut stdin = SP1Stdin::new();
    stdin.write(stdin_value);
    let (mut public_values, report) = ctx
        .prover
        .execute(SMT_UPDATE_ELF, stdin)
        .calculate_gas(false)
        .run()
        .map_err(|err| format!("sp1 execute failed: {err}"))?;
    Ok((
        public_values.read::<Sp1UpdatePublicValues>(),
        report.total_instruction_count(),
    ))
}

fn decode_public_values(
    bundle: &SP1ProofWithPublicValues,
) -> Result<Sp1UpdatePublicValues, String> {
    let mut public_values = bundle.public_values.clone();
    Ok(public_values.read::<Sp1UpdatePublicValues>())
}

fn deserialize_sp1_proof(value: &str) -> Result<SP1ProofWithPublicValues, String> {
    let bytes = hex_decode(value)?;
    bincode::deserialize(&bytes).map_err(|err| format!("deserialize sp1 proof: {err}"))
}

fn expected_update_transition(stdin: &Sp1UpdateStdin) -> [u8; 32] {
    let entries = stdin
        .entries
        .iter()
        .map(|entry| (entry.key, entry.delta))
        .collect::<Vec<_>>();
    sp1_programs_common::smt::update_transition_commitment(&stdin.transition_salt, &entries)
}

fn make_sp1_proof_public(
    proof: &mut StoredSmtProof,
    bundle: &SP1ProofWithPublicValues,
    public_values: &Sp1UpdatePublicValues,
) -> Result<(), String> {
    let encoded =
        bincode::serialize(bundle).map_err(|err| format!("serialize sp1 proof: {err}"))?;
    proof.mode = "sp1".to_string();
    proof.scheme = "smt-poseidon-sp1-v1".to_string();
    proof.proof_digest_hex = hex_encode(&hash_bytes("smt-sp1-update-proof-v1", &[&encoded]));
    proof.transition_commitment_hex = hex_encode(&public_values.transition_commitment);
    proof.sp1_proof_hex = hex_encode(&encoded);

    // These fields existed in the mock/replay format. A real SNARK artifact
    // must not persist its private witness or a prover-selected VK.
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

fn verify_sp1_update_metadata(
    old_state: &SmtPublicState,
    new_state: &SmtPublicState,
    proof: &StoredSmtProof,
) -> Result<(), String> {
    if proof.scheme != "smt-poseidon-sp1-v1" {
        return Err("unexpected proof scheme".to_string());
    }
    if proof.old_state_root != old_state.state_root || proof.new_state_root != new_state.state_root
    {
        return Err("state root labels mismatch".to_string());
    }
    if proof.old_smt_root_hex != smt::state::hex_string(&old_state.smt_root)
        || proof.new_smt_root_hex != smt::state::hex_string(&new_state.smt_root)
    {
        return Err("SMT root metadata mismatch".to_string());
    }
    if !proof.old_balance_commitment_hex.is_empty() || !proof.new_balance_commitment_hex.is_empty()
    {
        return Err("SP1 SMT proof contains obsolete external balance commitments".to_string());
    }
    let expected_delta = new_state
        .balance_total
        .checked_sub(old_state.balance_total)
        .ok_or_else(|| "balance total delta overflow".to_string())?;
    if proof.aggregate_delta != expected_delta {
        return Err("aggregate delta metadata mismatch".to_string());
    }
    if old_state.leaf_count != new_state.leaf_count {
        return Err("SMT update changed the leaf count".to_string());
    }
    if !proof.witness_hex.is_empty()
        || !proof.touched_addresses.is_empty()
        || !proof.membership_flags.is_empty()
    {
        return Err("SP1 proof artifact contains private SMT witness metadata".to_string());
    }
    Ok(())
}
