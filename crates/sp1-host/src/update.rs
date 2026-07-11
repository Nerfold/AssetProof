use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use common::crypto::{hex_decode, hex_encode};
use common::types::{Delta, StoredSmtProof};
use smt::key::key_for_address;
use smt::proof::{CompactAddressProof, CompactNonMembershipProof, CompactProofEntry, SiblingRef};
use smt::state::SmtState;
use smt::update::{
    apply_update_with_witness, build_update_multiproof, build_update_witness, verify_update,
    UpdateResult, UpdateWitness,
};
use sp1_programs_common::io::{
    Sp1AddressProof, Sp1CollisionNonMembershipProof, Sp1DefaultNonMembershipProof, Sp1Leaf,
    Sp1MembershipProof, Sp1NonMembershipProof, Sp1SiblingRef, Sp1UpdateEntryWitness,
    Sp1UpdatePublicValues, Sp1UpdateStdin,
};
use sp1_sdk::blocking::{ProveRequest, Prover as BlockingProver, ProverClient};
use sp1_sdk::include_elf;
use sp1_sdk::{ProvingKey, SP1ProofWithPublicValues, SP1Stdin};

use crate::setup::{default_setup_dir, ensure_all_setups, load_update_vk};

const SMT_UPDATE_ELF: sp1_sdk::Elf = include_elf!("sp1-smt-update");
const SMT_INSERT_ELF: sp1_sdk::Elf = include_elf!("sp1-smt-insert");
const INIT_ELF: sp1_sdk::Elf = include_elf!("sp1-init-merkle");

#[derive(Clone)]
struct Sp1Context {
    prover: sp1_sdk::blocking::CpuProver,
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
    let vk = load_update_vk(setup_dir, SMT_UPDATE_ELF)?;
    let pk = sp1_sdk::SP1ProvingKey::new(vk, SMT_UPDATE_ELF);
    let ctx = Sp1Context {
        prover,
        pk: Arc::new(pk),
    };
    *guard = Some(ctx.clone());
    Ok(ctx)
}

pub fn ensure_sp1_setup(setup_dir: &Path) -> Result<(), String> {
    ensure_all_setups(setup_dir, SMT_UPDATE_ELF, SMT_INSERT_ELF, INIT_ELF)
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
    if public_values.new_smt_root != result.next_state.smt_root() {
        return Err("sp1 new smt root mismatch".to_string());
    }
    if public_values.aggregate_delta != result.proof.aggregate_delta {
        return Err("sp1 aggregate delta mismatch".to_string());
    }
    if public_values.membership_flags != result.proof.membership_flags {
        return Err("sp1 membership flags mismatch".to_string());
    }
    if public_values.new_balance_total != result.next_state.balance_total {
        return Err("sp1 balance total mismatch".to_string());
    }

    result.proof.mode = "sp1".to_string();
    result.proof.sp1_proof_hex = serialize_sp1_proof(&proof_bundle)?;
    result.proof.sp1_vk_hex = serialize_sp1_vk(&ctx)?;
    result.proof.sp1_public_values_hex = hex_encode(proof_bundle.public_values.as_slice());
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
    if public_values.new_smt_root != result.next_state.smt_root() {
        return Err("sp1 execute new smt root mismatch".to_string());
    }
    if public_values.aggregate_delta != result.proof.aggregate_delta {
        return Err("sp1 execute aggregate delta mismatch".to_string());
    }
    if public_values.membership_flags != result.proof.membership_flags {
        return Err("sp1 execute membership flags mismatch".to_string());
    }
    if public_values.new_balance_total != result.next_state.balance_total {
        return Err("sp1 execute balance total mismatch".to_string());
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
    verify_update(old_state, new_state, proof)?;
    if proof.mode != "sp1" {
        return Err(format!("unexpected update proof mode {}", proof.mode));
    }
    if proof.sp1_proof_hex.is_empty() || proof.sp1_vk_hex.is_empty() {
        return Err("missing serialized sp1 proof artifacts".to_string());
    }

    let ctx = sp1_context()?;
    let bundle = deserialize_sp1_proof(&proof.sp1_proof_hex)?;
    let vk = deserialize_sp1_vk(&proof.sp1_vk_hex)?;
    ctx.prover
        .verify(&bundle, &vk, None)
        .map_err(|err| format!("sp1 verify failed: {err}"))?;

    let public_values = decode_public_values(&bundle)?;
    if public_values.old_state_root != old_state.state_root
        || public_values.new_state_root != new_state.state_root
    {
        return Err("sp1 public state root mismatch".to_string());
    }
    if public_values.old_smt_root != old_state.smt_root()
        || public_values.new_smt_root != new_state.smt_root()
    {
        return Err("sp1 public smt root mismatch".to_string());
    }
    if public_values.aggregate_delta != proof.aggregate_delta {
        return Err("sp1 public aggregate delta mismatch".to_string());
    }
    if public_values.membership_flags != proof.membership_flags {
        return Err("sp1 public membership flags mismatch".to_string());
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
    let proof = ctx
        .prover
        .prove(&ctx.pk, stdin)
        .compressed()
        .run()
        .map_err(|err| format!("sp1 prove failed: {err}"))?;
    Ok(proof)
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

fn serialize_sp1_proof(bundle: &SP1ProofWithPublicValues) -> Result<String, String> {
    let bytes = bincode::serialize(bundle).map_err(|err| format!("serialize sp1 proof: {err}"))?;
    Ok(hex_encode(&bytes))
}

fn deserialize_sp1_proof(value: &str) -> Result<SP1ProofWithPublicValues, String> {
    let bytes = hex_decode(value)?;
    bincode::deserialize(&bytes).map_err(|err| format!("deserialize sp1 proof: {err}"))
}

fn serialize_sp1_vk(ctx: &Sp1Context) -> Result<String, String> {
    let bytes = bincode::serialize(ctx.pk.verifying_key())
        .map_err(|err| format!("serialize sp1 vk: {err}"))?;
    Ok(hex_encode(&bytes))
}

fn deserialize_sp1_vk(value: &str) -> Result<sp1_sdk::SP1VerifyingKey, String> {
    let bytes = hex_decode(value)?;
    bincode::deserialize(&bytes).map_err(|err| format!("deserialize sp1 vk: {err}"))
}
