use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use common::crypto::{hex_decode, hex_encode};
use common::types::StoredSmtProof;
use smt::insert::{
    apply_insert_with_witness, build_insert_witness, verify_insert, InsertResult, InsertWitness,
};
use smt::key::key_for_address;
use smt::proof::{CompactNonMembershipProof, SiblingRef};
use smt::state::SmtState;
use sp1_programs_common::io::{
    Sp1CollisionNonMembershipProof, Sp1DefaultNonMembershipProof, Sp1InsertPublicValues,
    Sp1InsertStdin, Sp1Leaf, Sp1NonMembershipProof, Sp1SiblingRef,
};
use sp1_sdk::blocking::{ProveRequest, Prover as BlockingProver, ProverClient};
use sp1_sdk::include_elf;
use sp1_sdk::{ProvingKey, SP1ProofWithPublicValues, SP1Stdin};

use crate::proof_mode::{configured_proof_mode, ensure_trusted_vk, ConfiguredProofMode};
use crate::setup::{default_setup_dir, load_insert_vk};

const SMT_INSERT_ELF: sp1_sdk::Elf = include_elf!("sp1-smt-insert");

#[derive(Clone)]
struct Sp1InsertContext {
    prover: sp1_sdk::blocking::CpuProver,
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

    let prover = ProverClient::builder().cpu().build();
    let vk = load_insert_vk(setup_dir, SMT_INSERT_ELF)?;
    let pk = sp1_sdk::SP1ProvingKey::new(vk, SMT_INSERT_ELF);
    let ctx = Sp1InsertContext {
        prover,
        pk: Arc::new(pk),
    };
    *guard = Some(ctx.clone());
    Ok(ctx)
}

pub fn prove_insert(
    old_state: &SmtState,
    new_state_root: &str,
    witness: InsertWitness,
) -> Result<InsertResult, String> {
    let mut result = apply_insert_with_witness(old_state, new_state_root, &witness)?;
    let ctx = sp1_insert_context()?;
    let stdin_value = build_sp1_insert_stdin(old_state, new_state_root, &witness)?;
    let proof_bundle = run_sp1_insert_proof(&ctx, &stdin_value)?;
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
    if public_values.new_smt_root != result.next_state.smt_root() {
        return Err("sp1 insert new smt root mismatch".to_string());
    }
    if public_values.inserted_balance != witness.balance {
        return Err("sp1 insert balance mismatch".to_string());
    }
    if public_values.new_balance_total != result.next_state.balance_total {
        return Err("sp1 insert balance total mismatch".to_string());
    }

    result.proof.mode = "sp1".to_string();
    result.proof.sp1_proof_hex = serialize_sp1_proof(&proof_bundle)?;
    result.proof.sp1_vk_hex = serialize_sp1_vk(&ctx)?;
    result.proof.sp1_public_values_hex = hex_encode(proof_bundle.public_values.as_slice());
    Ok(result)
}

pub fn build_and_prove_insert(
    old_state: &SmtState,
    address: &str,
    balance: i128,
    new_state_root: &str,
    balance_blind_delta: ark_bls12_381::Fr,
) -> Result<InsertResult, String> {
    let witness = build_insert_witness(old_state, address, balance, balance_blind_delta)?;
    prove_insert(old_state, new_state_root, witness)
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
    if public_values.new_smt_root != result.next_state.smt_root() {
        return Err("sp1 insert execute new smt root mismatch".to_string());
    }
    if public_values.inserted_balance != witness.balance {
        return Err("sp1 insert execute balance mismatch".to_string());
    }
    if public_values.new_balance_total != result.next_state.balance_total {
        return Err("sp1 insert execute balance total mismatch".to_string());
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
    verify_insert(old_state, new_state, proof)?;
    if proof.mode != "sp1" {
        return Err(format!("unexpected insert proof mode {}", proof.mode));
    }
    if proof.sp1_proof_hex.is_empty() || proof.sp1_vk_hex.is_empty() {
        return Err("missing serialized sp1 insert proof artifacts".to_string());
    }

    let ctx = sp1_insert_context()?;
    let bundle = deserialize_sp1_proof(&proof.sp1_proof_hex)?;
    ensure_trusted_vk(
        &proof.sp1_vk_hex,
        ctx.pk.verifying_key(),
        hex_decode,
        "insert",
    )?;
    ctx.prover
        .verify(&bundle, ctx.pk.verifying_key(), None)
        .map_err(|err| format!("sp1 insert verify failed: {err}"))?;

    let public_values = decode_insert_public_values(&bundle)?;
    if public_values.old_state_root != old_state.state_root
        || public_values.new_state_root != new_state.state_root
    {
        return Err("sp1 insert public state root mismatch".to_string());
    }
    if public_values.old_smt_root != old_state.smt_root()
        || public_values.new_smt_root != new_state.smt_root()
    {
        return Err("sp1 insert public smt root mismatch".to_string());
    }
    if public_values.inserted_balance != proof.aggregate_delta {
        return Err("sp1 insert public balance mismatch".to_string());
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
        smt::proof::CompactAddressProof::NonMembership(CompactNonMembershipProof::Collision(
            proof,
        )) => Sp1NonMembershipProof::Collision(Sp1CollisionNonMembershipProof {
            collision_leaf: Sp1Leaf {
                key: key_for_address(&proof.collision_address)?,
                balance: proof.collision_balance,
                salt: proof.collision_salt,
            },
            siblings: proof.siblings.iter().map(convert_sibling_ref).collect(),
        }),
    };

    Ok(Sp1InsertStdin {
        state_root: old_state.state_root.clone(),
        new_state_root: new_state_root.to_string(),
        depth: old_state.depth,
        old_smt_root: old_state.smt_root(),
        old_balance_total: old_state.balance_total,
        frontier_hashes: multiproof.frontier_hashes,
        key: key_for_address(&witness.address)?,
        balance: witness.balance,
        salt: witness.salt,
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
    let request = ctx.prover.prove(&ctx.pk, stdin);
    let proof = match configured_proof_mode()? {
        ConfiguredProofMode::Groth16 => request.groth16().run(),
        ConfiguredProofMode::Plonk => request.plonk().run(),
        ConfiguredProofMode::Compressed => request.compressed().run(),
    }
    .map_err(|err| format!("sp1 insert prove failed: {err}"))?;
    Ok(proof)
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

fn serialize_sp1_proof(bundle: &SP1ProofWithPublicValues) -> Result<String, String> {
    let bytes =
        bincode::serialize(bundle).map_err(|err| format!("serialize sp1 insert proof: {err}"))?;
    Ok(hex_encode(&bytes))
}

fn deserialize_sp1_proof(value: &str) -> Result<SP1ProofWithPublicValues, String> {
    let bytes = hex_decode(value)?;
    bincode::deserialize(&bytes).map_err(|err| format!("deserialize sp1 insert proof: {err}"))
}

fn serialize_sp1_vk(ctx: &Sp1InsertContext) -> Result<String, String> {
    let bytes = bincode::serialize(ctx.pk.verifying_key())
        .map_err(|err| format!("serialize sp1 insert vk: {err}"))?;
    Ok(hex_encode(&bytes))
}
