use ark_bls12_381::Fr;

use common::crypto::{commit_balance, hash_bytes, point_g1_to_hex};
use common::types::StoredSmtProof;

use crate::leaf::Leaf;
use crate::proof::{AddressProof, NonMembershipProof};
use crate::state::{hex_string, parse_hash_hex, SmtState};
use crate::update::{verify_collision_non_membership_proof, verify_default_non_membership_proof};
use crate::{key::key_for_address, proof::CollisionNonMembershipProof};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InsertWitness {
    pub address: String,
    pub balance: i128,
    pub salt: [u8; 32],
    pub ownership_proof: String,
    pub chain_proof: String,
    pub non_membership_proof: NonMembershipProof,
    pub balance_blind_delta: Fr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InsertResult {
    pub next_state: SmtState,
    pub proof: StoredSmtProof,
}

pub fn build_insert_witness(
    state: &SmtState,
    address: &str,
    balance: i128,
    balance_blind_delta: Fr,
) -> Result<InsertWitness, String> {
    if balance < 0 {
        return Err("insert balance must be non-negative".to_string());
    }
    let proof = state.tree().proof_for(address)?;
    let AddressProof::NonMembership(non_membership_proof) = proof else {
        return Err(format!("address {address} already exists in SMT"));
    };
    Ok(InsertWitness {
        address: address.to_string(),
        balance,
        salt: SmtState::fresh_salt("smt-insert-salt", address, balance),
        ownership_proof: format!("dummy-ownership:{address}"),
        chain_proof: format!("dummy-chain-balance:{address}:{balance}"),
        non_membership_proof,
        balance_blind_delta,
    })
}

pub fn apply_insert_with_witness(
    state: &SmtState,
    new_state_root: &str,
    witness: &InsertWitness,
) -> Result<InsertResult, String> {
    let mut next_state = state.clone();
    let proof = apply_insert_in_place(&mut next_state, new_state_root, witness)?;
    Ok(InsertResult { next_state, proof })
}

pub fn apply_insert_in_place(
    state: &mut SmtState,
    new_state_root: &str,
    witness: &InsertWitness,
) -> Result<StoredSmtProof, String> {
    if state.tree().get(&witness.address).is_some() {
        return Err(format!("address {} already present", witness.address));
    }
    verify_non_membership(&state, &witness.address, &witness.non_membership_proof)?;
    if witness.balance < 0 {
        return Err("negative inserted balance".to_string());
    }
    if !witness.ownership_proof.starts_with("dummy-ownership:") {
        return Err("ownership proof rejected".to_string());
    }
    if !witness
        .chain_proof
        .ends_with(&format!(":{}", witness.balance))
    {
        return Err("chain proof rejected".to_string());
    }

    let old_state_root = state.state_root.clone();
    let old_root = state.smt_root();
    let old_commitment = state.balance_commitment();
    let old_balance_total = state.balance_total;
    let old_blind = state.balance_blind;

    state.tree_mut().upsert(Leaf::new(
        witness.address.clone(),
        witness.balance,
        witness.salt,
    )?);
    state.balance_total = old_balance_total + witness.balance;
    state.balance_blind = old_blind + witness.balance_blind_delta;
    state.state_root = new_state_root.to_string();

    let new_commitment = state.balance_commitment();
    let expected_commitment =
        old_commitment + commit_balance(witness.balance, witness.balance_blind_delta);
    if new_commitment != expected_commitment {
        return Err("insert commitment transition mismatch".to_string());
    }

    let witness_hex = serialize_insert_witness(witness)?;
    let proof_digest = hash_bytes(
        "mock-sp1-smt-insert-proof",
        &[
            old_state_root.as_bytes(),
            new_state_root.as_bytes(),
            witness_hex.as_bytes(),
        ],
    );

    let next_root_hex = hex_string(&state.smt_root());
    Ok(StoredSmtProof {
        scheme: "smt+snarks".to_string(),
        mode: "mock-sp1".to_string(),
        old_state_root: old_state_root,
        new_state_root: new_state_root.to_string(),
        old_smt_root_hex: hex_string(&old_root),
        new_smt_root_hex: next_root_hex,
        aggregate_delta: witness.balance,
        balance_blind_delta: witness.balance_blind_delta,
        old_balance_commitment_hex: point_g1_to_hex(&old_commitment)?,
        new_balance_commitment_hex: point_g1_to_hex(&new_commitment)?,
        proof_digest_hex: common::crypto::hex_encode(&proof_digest),
        witness_hex,
        touched_addresses: vec![witness.address.clone()],
        membership_flags: vec![0],
        sp1_proof_hex: String::new(),
        sp1_vk_hex: String::new(),
        sp1_public_values_hex: String::new(),
    })
}

pub fn verify_insert(
    old_state: &SmtState,
    new_state: &SmtState,
    proof: &StoredSmtProof,
) -> Result<(), String> {
    let witness = deserialize_insert_witness(&proof.witness_hex)?;
    let replay = apply_insert_with_witness(old_state, &new_state.state_root, &witness)?;
    if replay.next_state != *new_state {
        return Err("replayed insert state mismatch".to_string());
    }
    if replay.proof.proof_digest_hex != proof.proof_digest_hex {
        return Err("insert proof digest mismatch".to_string());
    }
    Ok(())
}

fn verify_non_membership(
    state: &SmtState,
    address: &str,
    proof: &NonMembershipProof,
) -> Result<(), String> {
    let key = key_for_address(address)?;
    match proof {
        NonMembershipProof::Default(default) => {
            verify_default_non_membership_proof(state.depth, state.smt_root(), &key, default)
        }
        NonMembershipProof::Collision(collision) => verify_collision_non_membership_proof(
            state.depth,
            state.smt_root(),
            &key,
            &CollisionNonMembershipProof {
                collision_address: collision.collision_address.clone(),
                collision_balance: collision.collision_balance,
                collision_salt: collision.collision_salt,
                siblings: collision.siblings.clone(),
            },
        ),
    }
}

pub fn serialize_insert_witness(witness: &InsertWitness) -> Result<String, String> {
    let siblings = match &witness.non_membership_proof {
        NonMembershipProof::Default(default) => {
            format!(
                "kind=default\ndefault_depth={}\nsiblings={}",
                default.default_depth,
                default
                    .siblings
                    .iter()
                    .map(hex_string)
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
        NonMembershipProof::Collision(collision) => {
            format!(
                "kind=collision\ncollision_address={}\ncollision_balance={}\ncollision_salt={}\nsiblings={}",
                collision.collision_address,
                collision.collision_balance,
                hex_string(&collision.collision_salt),
                collision
                    .siblings
                    .iter()
                    .map(hex_string)
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    };
    let body = format!(
        "address={}\nbalance={}\nsalt={}\nownership={}\nchain={}\nblind={}\n{}",
        witness.address,
        witness.balance,
        hex_string(&witness.salt),
        witness.ownership_proof,
        witness.chain_proof,
        common::crypto::scalar_to_hex(&witness.balance_blind_delta)?,
        siblings
    );
    Ok(common::crypto::hex_encode(body.as_bytes()))
}

pub fn deserialize_insert_witness(encoded: &str) -> Result<InsertWitness, String> {
    let raw = common::crypto::hex_decode(encoded)?;
    let text =
        String::from_utf8(raw).map_err(|err| format!("invalid insert witness utf8: {err}"))?;
    let mut address = None;
    let mut balance = None;
    let mut salt = None;
    let mut ownership = None;
    let mut chain = None;
    let mut blind = None;
    let mut kind = None;
    let mut default_depth = None;
    let mut collision_address = None;
    let mut collision_balance = None;
    let mut collision_salt = None;
    let mut siblings = Vec::new();

    for line in text.lines() {
        if let Some(value) = line.strip_prefix("address=") {
            address = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("balance=") {
            balance = Some(
                value
                    .parse::<i128>()
                    .map_err(|err| format!("invalid balance: {err}"))?,
            );
        } else if let Some(value) = line.strip_prefix("salt=") {
            salt = Some(parse_hash_hex(value)?);
        } else if let Some(value) = line.strip_prefix("ownership=") {
            ownership = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("chain=") {
            chain = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("blind=") {
            blind = Some(common::crypto::scalar_from_hex(value)?);
        } else if let Some(value) = line.strip_prefix("kind=") {
            kind = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("default_depth=") {
            default_depth = Some(
                value
                    .parse::<usize>()
                    .map_err(|err| format!("invalid depth: {err}"))?,
            );
        } else if let Some(value) = line.strip_prefix("collision_address=") {
            collision_address = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("collision_balance=") {
            collision_balance = Some(
                value
                    .parse::<i128>()
                    .map_err(|err| format!("invalid collision balance: {err}"))?,
            );
        } else if let Some(value) = line.strip_prefix("collision_salt=") {
            collision_salt = Some(parse_hash_hex(value)?);
        } else if let Some(value) = line.strip_prefix("siblings=") {
            siblings = if value.is_empty() {
                Vec::new()
            } else {
                value
                    .split(',')
                    .map(parse_hash_hex)
                    .collect::<Result<Vec<_>, _>>()?
            };
        }
    }

    let non_membership_proof = match kind.as_deref() {
        Some("default") => NonMembershipProof::Default(crate::proof::DefaultNonMembershipProof {
            default_depth: default_depth.ok_or_else(|| "missing default depth".to_string())?,
            siblings,
        }),
        Some("collision") => {
            NonMembershipProof::Collision(crate::proof::CollisionNonMembershipProof {
                collision_address: collision_address
                    .ok_or_else(|| "missing collision address".to_string())?,
                collision_balance: collision_balance
                    .ok_or_else(|| "missing collision balance".to_string())?,
                collision_salt: collision_salt
                    .ok_or_else(|| "missing collision salt".to_string())?,
                siblings,
            })
        }
        Some(other) => return Err(format!("unknown non-membership kind {other}")),
        None => return Err("missing non-membership kind".to_string()),
    };

    Ok(InsertWitness {
        address: address.ok_or_else(|| "missing address".to_string())?,
        balance: balance.ok_or_else(|| "missing balance".to_string())?,
        salt: salt.ok_or_else(|| "missing salt".to_string())?,
        ownership_proof: ownership.ok_or_else(|| "missing ownership proof".to_string())?,
        chain_proof: chain.ok_or_else(|| "missing chain proof".to_string())?,
        non_membership_proof,
        balance_blind_delta: blind.ok_or_else(|| "missing blind".to_string())?,
    })
}
