use ark_bls12_381::Fr;

use common::crypto::{commit_balance, hash_bytes, point_g1_to_hex, scalar_to_hex};
use common::types::{Delta, StoredSmtProof};

use crate::leaf::Leaf;
use crate::proof::{
    AddressProof, CollisionNonMembershipProof, CompactMultiproof, DefaultNonMembershipProof,
    MembershipProof, NonMembershipProof,
};
use crate::state::{hex_string, parse_hash_hex, SmtState};
use crate::tree::SparseMerkleTree;
use crate::{
    hash::{default_hashes, internal_hash, leaf_hash, Hash},
    key::{common_prefix_len, key_for_address},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateWitnessEntry {
    pub address: String,
    pub delta: i128,
    pub proof: AddressProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateWitness {
    pub entries: Vec<UpdateWitnessEntry>,
    pub balance_blind_delta: Fr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateResult {
    pub next_state: SmtState,
    pub proof: StoredSmtProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PreparedMemberUpdate {
    new_leaf: Leaf,
}

pub fn build_update_multiproof(
    state: &SmtState,
    deltas: &[Delta],
) -> Result<CompactMultiproof, String> {
    ensure_canonical_deltas(deltas)?;
    let tree = state.tree();
    let addresses = deltas
        .iter()
        .map(|delta| delta.address.clone())
        .collect::<Vec<_>>();
    tree.compact_multiproof(&addresses)
}

pub fn build_update_witness(
    state: &SmtState,
    deltas: &[Delta],
    balance_blind_delta: Fr,
) -> Result<UpdateWitness, String> {
    ensure_canonical_deltas(deltas)?;
    let tree = state.tree();
    let mut entries = Vec::with_capacity(deltas.len());
    for delta in deltas {
        entries.push(UpdateWitnessEntry {
            address: delta.address.clone(),
            delta: delta.delta,
            proof: tree.proof_for(&delta.address)?,
        });
    }
    Ok(UpdateWitness {
        entries,
        balance_blind_delta,
    })
}

pub fn apply_update_with_witness(
    state: &SmtState,
    new_state_root: &str,
    witness: &UpdateWitness,
) -> Result<UpdateResult, String> {
    let mut next_state = state.clone();
    let proof = apply_update_in_place(&mut next_state, new_state_root, witness)?;
    Ok(UpdateResult { next_state, proof })
}

pub fn apply_update_in_place(
    state: &mut SmtState,
    new_state_root: &str,
    witness: &UpdateWitness,
) -> Result<StoredSmtProof, String> {
    verify_witness_shape(witness)?;
    let old_tree = state.tree();
    let old_state_root = state.state_root.clone();
    let old_root = old_tree.root();
    let old_balance_total = state.balance_total;
    let old_blind = state.balance_blind;
    let old_commitment = state.balance_commitment();
    let mut aggregate_delta = 0i128;
    let mut flags = Vec::with_capacity(witness.entries.len());
    let mut prepared = Vec::with_capacity(witness.entries.len());

    for entry in &witness.entries {
        match &entry.proof {
            AddressProof::Membership(MembershipProof { .. }) => {
                let leaf = old_tree
                    .get(&entry.address)
                    .cloned()
                    .ok_or_else(|| format!("missing member leaf {}", entry.address))?;
                verify_address_proof(&old_tree, &entry.address, &entry.proof)?;
                let new_balance = leaf
                    .balance
                    .checked_add(entry.delta)
                    .ok_or_else(|| format!("balance overflow for {}", entry.address))?;
                if new_balance < 0 {
                    return Err(format!("negative updated balance for {}", entry.address));
                }
                let new_leaf = Leaf::new(entry.address.clone(), new_balance, leaf.salt)?;
                aggregate_delta += entry.delta;
                flags.push(1);
                prepared.push(Some(PreparedMemberUpdate { new_leaf }));
            }
            AddressProof::NonMembership(_) => {
                verify_address_proof(&old_tree, &entry.address, &entry.proof)?;
                flags.push(0);
                prepared.push(None);
            }
        }
    }

    for update in prepared.into_iter().flatten() {
        state.tree_mut().upsert(update.new_leaf);
    }
    state.balance_total = old_balance_total + aggregate_delta;
    state.balance_blind = old_blind + witness.balance_blind_delta;
    state.state_root = new_state_root.to_string();

    let new_commitment = state.balance_commitment();
    let expected_commitment =
        old_commitment + commit_balance(aggregate_delta, witness.balance_blind_delta);
    if new_commitment != expected_commitment {
        return Err("balance commitment transition mismatch".to_string());
    }

    let witness_hex = serialize_update_witness(witness)?;
    let proof_digest = hash_bytes(
        "mock-sp1-smt-update-proof",
        &[
            old_state_root.as_bytes(),
            new_state_root.as_bytes(),
            witness_hex.as_bytes(),
            &aggregate_delta.to_le_bytes(),
        ],
    );

    let new_root_hex = hex_string(&state.smt_root());
    Ok(StoredSmtProof {
        scheme: "smt+snarks".to_string(),
        mode: "mock-sp1".to_string(),
        old_state_root: old_state_root,
        new_state_root: new_state_root.to_string(),
        old_smt_root_hex: hex_string(&old_root),
        new_smt_root_hex: new_root_hex,
        aggregate_delta,
        balance_blind_delta: witness.balance_blind_delta,
        old_balance_commitment_hex: point_g1_to_hex(&old_commitment)?,
        new_balance_commitment_hex: point_g1_to_hex(&new_commitment)?,
        proof_digest_hex: common::crypto::hex_encode(&proof_digest),
        witness_hex,
        touched_addresses: witness
            .entries
            .iter()
            .map(|entry| entry.address.clone())
            .collect(),
        membership_flags: flags,
        sp1_proof_hex: String::new(),
        sp1_vk_hex: String::new(),
        sp1_public_values_hex: String::new(),
    })
}

pub fn verify_update(
    old_state: &SmtState,
    new_state: &SmtState,
    proof: &StoredSmtProof,
) -> Result<(), String> {
    if proof.scheme != "smt+snarks" {
        return Err("unexpected proof scheme".to_string());
    }
    if proof.old_state_root != old_state.state_root || proof.new_state_root != new_state.state_root
    {
        return Err("state root labels mismatch".to_string());
    }
    if proof.old_smt_root_hex != hex_string(&old_state.smt_root()) {
        return Err("old SMT root mismatch".to_string());
    }
    if proof.new_smt_root_hex != hex_string(&new_state.smt_root()) {
        return Err("new SMT root mismatch".to_string());
    }
    let witness = deserialize_update_witness(&proof.witness_hex)?;
    let replay = apply_update_with_witness(old_state, &new_state.state_root, &witness)?;
    if replay.next_state != *new_state {
        return Err("replayed state does not match provided new state".to_string());
    }
    if replay.proof.aggregate_delta != proof.aggregate_delta {
        return Err("aggregate delta mismatch".to_string());
    }
    if replay.proof.membership_flags != proof.membership_flags {
        return Err("membership flags mismatch".to_string());
    }
    if replay.proof.proof_digest_hex != proof.proof_digest_hex {
        return Err("proof digest mismatch".to_string());
    }
    Ok(())
}

pub fn ensure_canonical_deltas(deltas: &[Delta]) -> Result<(), String> {
    let mut last_address: Option<&str> = None;
    for delta in deltas {
        if delta.delta == 0 {
            return Err("zero delta not allowed in canonical list".to_string());
        }
        if let Some(prev) = last_address {
            if delta.address.as_str() <= prev {
                return Err("delta list must be strictly sorted and deduplicated".to_string());
            }
        }
        last_address = Some(&delta.address);
    }
    Ok(())
}

fn verify_witness_shape(witness: &UpdateWitness) -> Result<(), String> {
    let mut last_address: Option<&str> = None;
    for entry in &witness.entries {
        if let Some(prev) = last_address {
            if entry.address.as_str() <= prev {
                return Err("update witness entries must be sorted".to_string());
            }
        }
        last_address = Some(&entry.address);
    }
    Ok(())
}

fn verify_address_proof(
    tree: &SparseMerkleTree,
    address: &str,
    proof: &AddressProof,
) -> Result<(), String> {
    let key = key_for_address(address)?;
    match proof {
        AddressProof::Membership(MembershipProof { siblings }) => {
            let leaf = tree
                .get(address)
                .ok_or_else(|| format!("missing leaf for member proof {address}"))?;
            verify_membership_proof(
                tree.depth,
                tree.root(),
                &key,
                leaf.balance,
                &leaf.salt,
                siblings,
            )
        }
        AddressProof::NonMembership(NonMembershipProof::Default(default)) => {
            verify_default_non_membership_proof(tree.depth, tree.root(), &key, default)
        }
        AddressProof::NonMembership(NonMembershipProof::Collision(collision)) => {
            verify_collision_non_membership_proof(tree.depth, tree.root(), &key, collision)
        }
    }
}

pub fn verify_membership_proof(
    depth: usize,
    root: Hash,
    key: &Hash,
    balance: i128,
    salt: &Hash,
    siblings: &[Hash],
) -> Result<(), String> {
    if siblings.len() != depth {
        return Err(format!(
            "membership sibling length mismatch: expected {depth}, got {}",
            siblings.len()
        ));
    }
    let mut current = leaf_hash(key, balance, salt);
    for (level_from_leaf, sibling) in siblings.iter().enumerate() {
        let node_depth = depth - level_from_leaf - 1;
        current = if key_bit_at(key, node_depth) {
            internal_hash(node_depth, sibling, &current)
        } else {
            internal_hash(node_depth, &current, sibling)
        };
    }
    if current != root {
        return Err("membership proof root mismatch".to_string());
    }
    Ok(())
}

pub fn verify_default_non_membership_proof(
    depth: usize,
    root: Hash,
    key: &Hash,
    proof: &DefaultNonMembershipProof,
) -> Result<(), String> {
    if proof.default_depth > depth {
        return Err("default non-membership depth exceeds tree depth".to_string());
    }
    if proof.siblings.len() != proof.default_depth {
        return Err("default non-membership sibling length mismatch".to_string());
    }
    let mut current = default_hashes(depth)[depth.saturating_sub(proof.default_depth)];
    for (offset, sibling) in proof.siblings.iter().enumerate() {
        let node_depth = proof.default_depth - offset - 1;
        current = if key_bit_at(key, node_depth) {
            internal_hash(node_depth, sibling, &current)
        } else {
            internal_hash(node_depth, &current, sibling)
        };
    }
    if current != root {
        return Err("default non-membership proof root mismatch".to_string());
    }
    Ok(())
}

pub fn verify_collision_non_membership_proof(
    depth: usize,
    root: Hash,
    key: &Hash,
    proof: &CollisionNonMembershipProof,
) -> Result<(), String> {
    let collision_key = key_for_address(&proof.collision_address)?;
    if &collision_key == key {
        return Err("collision proof uses identical key".to_string());
    }
    if common_prefix_len(key, &collision_key, depth) != depth {
        return Err("collision proof key does not share full path at configured depth".to_string());
    }
    verify_membership_proof(
        depth,
        root,
        &collision_key,
        proof.collision_balance,
        &proof.collision_salt,
        &proof.siblings,
    )
}

fn key_bit_at(key: &Hash, depth: usize) -> bool {
    let byte = key[depth / 8];
    let offset = 7 - (depth % 8);
    ((byte >> offset) & 1) == 1
}

pub fn serialize_update_witness(witness: &UpdateWitness) -> Result<String, String> {
    let mut lines = Vec::new();
    lines.push(format!(
        "blind={}",
        scalar_to_hex(&witness.balance_blind_delta)?
    ));
    for entry in &witness.entries {
        lines.push(format!("entry.address={}", entry.address));
        lines.push(format!("entry.delta={}", entry.delta));
        match &entry.proof {
            AddressProof::Membership(MembershipProof { siblings }) => {
                lines.push("entry.kind=member".to_string());
                lines.push(format!("entry.siblings={}", hashes_csv(siblings)));
            }
            AddressProof::NonMembership(NonMembershipProof::Default(default)) => {
                lines.push("entry.kind=nonmember-default".to_string());
                lines.push(format!("entry.default_depth={}", default.default_depth));
                lines.push(format!("entry.siblings={}", hashes_csv(&default.siblings)));
            }
            AddressProof::NonMembership(NonMembershipProof::Collision(collision)) => {
                lines.push("entry.kind=nonmember-collision".to_string());
                lines.push(format!(
                    "entry.collision_address={}",
                    collision.collision_address
                ));
                lines.push(format!(
                    "entry.collision_balance={}",
                    collision.collision_balance
                ));
                lines.push(format!(
                    "entry.collision_salt={}",
                    hex_string(&collision.collision_salt)
                ));
                lines.push(format!(
                    "entry.siblings={}",
                    hashes_csv(&collision.siblings)
                ));
            }
        }
    }
    Ok(common::crypto::hex_encode(lines.join("\n").as_bytes()))
}

pub fn deserialize_update_witness(encoded: &str) -> Result<UpdateWitness, String> {
    let raw = common::crypto::hex_decode(encoded)?;
    let text =
        String::from_utf8(raw).map_err(|err| format!("invalid update witness utf8: {err}"))?;
    let mut lines = text.lines();
    let blind_line = lines
        .next()
        .ok_or_else(|| "missing witness blind".to_string())?;
    let blind_hex = blind_line
        .strip_prefix("blind=")
        .ok_or_else(|| "invalid witness blind prefix".to_string())?;
    let mut entries = Vec::new();
    let mut current: Vec<String> = Vec::new();
    for line in lines {
        if line.starts_with("entry.address=") && !current.is_empty() {
            entries.push(parse_entry_block(&current)?);
            current.clear();
        }
        current.push(line.to_string());
    }
    if !current.is_empty() {
        entries.push(parse_entry_block(&current)?);
    }
    Ok(UpdateWitness {
        entries,
        balance_blind_delta: common::crypto::scalar_from_hex(blind_hex)?,
    })
}

fn parse_entry_block(lines: &[String]) -> Result<UpdateWitnessEntry, String> {
    let mut address = None;
    let mut delta = None;
    let mut kind = None;
    let mut siblings = None;
    let mut default_depth = None;
    let mut collision_address = None;
    let mut collision_balance = None;
    let mut collision_salt = None;
    for line in lines {
        if let Some(value) = line.strip_prefix("entry.address=") {
            address = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("entry.delta=") {
            delta = Some(
                value
                    .parse::<i128>()
                    .map_err(|err| format!("invalid delta: {err}"))?,
            );
        } else if let Some(value) = line.strip_prefix("entry.kind=") {
            kind = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("entry.siblings=") {
            siblings = Some(parse_hashes_csv(value)?);
        } else if let Some(value) = line.strip_prefix("entry.default_depth=") {
            default_depth = Some(
                value
                    .parse::<usize>()
                    .map_err(|err| format!("invalid depth: {err}"))?,
            );
        } else if let Some(value) = line.strip_prefix("entry.collision_address=") {
            collision_address = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("entry.collision_balance=") {
            collision_balance = Some(
                value
                    .parse::<i128>()
                    .map_err(|err| format!("invalid collision balance: {err}"))?,
            );
        } else if let Some(value) = line.strip_prefix("entry.collision_salt=") {
            collision_salt = Some(parse_hash_hex(value)?);
        }
    }

    let address = address.ok_or_else(|| "missing entry address".to_string())?;
    let delta = delta.ok_or_else(|| "missing entry delta".to_string())?;
    let kind = kind.ok_or_else(|| "missing entry kind".to_string())?;
    let siblings = siblings.unwrap_or_default();

    let proof = match kind.as_str() {
        "member" => AddressProof::Membership(MembershipProof { siblings }),
        "nonmember-default" => AddressProof::NonMembership(NonMembershipProof::Default(
            crate::proof::DefaultNonMembershipProof {
                default_depth: default_depth.ok_or_else(|| "missing default depth".to_string())?,
                siblings,
            },
        )),
        "nonmember-collision" => AddressProof::NonMembership(NonMembershipProof::Collision(
            crate::proof::CollisionNonMembershipProof {
                collision_address: collision_address
                    .ok_or_else(|| "missing collision address".to_string())?,
                collision_balance: collision_balance
                    .ok_or_else(|| "missing collision balance".to_string())?,
                collision_salt: collision_salt
                    .ok_or_else(|| "missing collision salt".to_string())?,
                siblings,
            },
        )),
        _ => return Err(format!("unknown witness kind {kind}")),
    };

    Ok(UpdateWitnessEntry {
        address,
        delta,
        proof,
    })
}

fn hashes_csv(values: &[[u8; 32]]) -> String {
    values.iter().map(hex_string).collect::<Vec<_>>().join(",")
}

fn parse_hashes_csv(raw: &str) -> Result<Vec<[u8; 32]>, String> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    raw.split(',').map(parse_hash_hex).collect()
}
