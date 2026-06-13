#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use slop_algebra::{AbstractField, PrimeField32};
use sp1_primitives::{poseidon2_hash, SP1Field};
use sp1_programs_common::io::{
    Hash, Sp1CollisionNonMembershipProof, Sp1InsertPublicValues, Sp1InsertStdin, Sp1Leaf,
    Sp1NonMembershipProof, Sp1SiblingRef,
};
use sp1_zkvm::entrypoint;

entrypoint!(main);

const LEAF_TAG: u32 = 1;
const NODE_TAG: u32 = 2;
const EMPTY_TAG: u32 = 3;
const KEY_TAG: u32 = 4;

fn main() {
    let input: Sp1InsertStdin = sp1_zkvm::io::read();
    let pv = verify_and_apply_insert(input);
    sp1_zkvm::io::commit(&pv);
}

fn verify_and_apply_insert(input: Sp1InsertStdin) -> Sp1InsertPublicValues {
    assert!(input.balance >= 0, "negative inserted balance");
    let key = key_for_address(&input.address);
    let defaults = default_hashes(input.depth);

    match &input.non_membership_proof {
        Sp1NonMembershipProof::Default(proof) => {
            let resolved = resolve_default_siblings(
                proof.default_depth,
                &proof.siblings,
                &input.frontier_hashes,
                &defaults,
            );
            verify_default_non_membership_root(
                &key,
                input.old_smt_root,
                input.depth,
                &defaults,
                proof.default_depth,
                &resolved,
            )
        }
        Sp1NonMembershipProof::Collision(proof) => {
            let resolved = resolve_membership_siblings(
                &proof.siblings,
                &input.frontier_hashes,
                &defaults,
            );
            verify_collision_non_membership_root(
                &key,
                input.old_smt_root,
                input.depth,
                proof,
                &resolved,
            )
        }
    }

    let new_leaf = Sp1Leaf {
        address: input.address.clone(),
        balance: input.balance,
        salt: input.salt,
    };
    let membership_siblings = match &input.non_membership_proof {
        Sp1NonMembershipProof::Default(proof) => expand_default_to_membership(
            input.depth,
            &defaults,
            &resolve_default_siblings(
                proof.default_depth,
                &proof.siblings,
                &input.frontier_hashes,
                &defaults,
            ),
            proof.default_depth,
        ),
        Sp1NonMembershipProof::Collision(proof) => resolve_membership_siblings(
            &proof.siblings,
            &input.frontier_hashes,
            &defaults,
        ),
    };
    let new_root = compute_membership_root(&new_leaf, &membership_siblings, input.depth);
    let new_balance_total = input
        .old_balance_total
        .checked_add(input.balance)
        .expect("balance total overflow");

    Sp1InsertPublicValues {
        old_state_root: input.state_root,
        new_state_root: input.new_state_root,
        old_smt_root: input.old_smt_root,
        new_smt_root: new_root,
        inserted_balance: input.balance,
        old_balance_total: input.old_balance_total,
        new_balance_total,
    }
}

fn expand_default_to_membership(
    depth: usize,
    defaults: &[Hash],
    resolved_default_siblings: &[Hash],
    default_depth: usize,
) -> Vec<Hash> {
    let mut siblings = Vec::with_capacity(depth);
    let default_subtree_height = depth.saturating_sub(default_depth);
    for level_from_leaf in 0..default_subtree_height {
        siblings.push(defaults[level_from_leaf]);
    }
    for sibling in resolved_default_siblings.iter().rev() {
        siblings.push(*sibling);
    }
    assert_eq!(siblings.len(), depth, "expanded default path length mismatch");
    siblings
}

fn verify_default_non_membership_root(
    key: &Hash,
    root: Hash,
    depth: usize,
    defaults: &[Hash],
    default_depth: usize,
    siblings: &[Hash],
) {
    assert!(default_depth <= depth, "default depth exceeds tree depth");
    assert_eq!(
        siblings.len(),
        default_depth,
        "default non-membership sibling length mismatch"
    );

    let mut current = defaults[depth.saturating_sub(default_depth)];
    for (offset, sibling) in siblings.iter().enumerate() {
        let node_depth = default_depth - offset - 1;
        current = if key_bit(key, node_depth) {
            internal_hash(node_depth, sibling, &current)
        } else {
            internal_hash(node_depth, &current, sibling)
        };
    }
    assert_eq!(current, root, "default non-membership root mismatch");
}

fn verify_collision_non_membership_root(
    key: &Hash,
    root: Hash,
    depth: usize,
    proof: &Sp1CollisionNonMembershipProof,
    siblings: &[Hash],
) {
    let collision_key = key_for_address(&proof.collision_leaf.address);
    assert!(collision_key != *key, "collision proof uses identical key");
    let collision_root = compute_membership_root(&proof.collision_leaf, siblings, depth);
    assert_eq!(collision_root, root, "collision non-membership root mismatch");
}

fn resolve_membership_siblings(
    siblings: &[Sp1SiblingRef],
    frontier_hashes: &[Hash],
    defaults: &[Hash],
) -> Vec<Hash> {
    siblings
        .iter()
        .enumerate()
        .map(|(level, sibling)| resolve_sibling_ref(sibling, defaults[level], frontier_hashes))
        .collect()
}

fn resolve_default_siblings(
    default_depth: usize,
    siblings: &[Sp1SiblingRef],
    frontier_hashes: &[Hash],
    defaults: &[Hash],
) -> Vec<Hash> {
    let tree_depth = defaults.len().saturating_sub(1);
    siblings
        .iter()
        .enumerate()
        .map(|(offset, sibling)| {
            let layer_index = tree_depth - default_depth + offset;
            resolve_sibling_ref(sibling, defaults[layer_index], frontier_hashes)
        })
        .collect()
}

fn resolve_sibling_ref(
    sibling: &Sp1SiblingRef,
    default_hash: Hash,
    frontier_hashes: &[Hash],
) -> Hash {
    match sibling {
        Sp1SiblingRef::Default => default_hash,
        Sp1SiblingRef::Frontier(index) => frontier_hashes
            .get(*index)
            .copied()
            .expect("frontier sibling index out of range"),
    }
}

fn compute_membership_root(leaf: &Sp1Leaf, siblings: &[Hash], depth: usize) -> Hash {
    assert_eq!(siblings.len(), depth, "membership proof length mismatch");
    let key = key_for_address(&leaf.address);
    let mut hash = leaf_hash(&key, leaf.balance, &leaf.salt);
    for (level_from_leaf, sibling) in siblings.iter().enumerate() {
        let depth_tag = depth - level_from_leaf - 1;
        hash = if key_bit(&key, depth_tag) {
            internal_hash(depth_tag, sibling, &hash)
        } else {
            internal_hash(depth_tag, &hash, sibling)
        };
    }
    hash
}

fn key_for_address(address: &str) -> Hash {
    let normalized = normalize_address(address);
    let raw = normalized.strip_prefix("0x").unwrap_or(&normalized);
    let mut bytes = [0u8; 20];
    for (index, chunk) in raw.as_bytes().chunks(2).enumerate() {
        bytes[index] = (from_hex_nibble(chunk[0]) << 4) | from_hex_nibble(chunk[1]);
    }

    let mut words = Vec::with_capacity(6);
    words.push(SP1Field::from_wrapped_u32(KEY_TAG));
    for chunk in bytes.chunks(4) {
        let mut word = [0u8; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        words.push(SP1Field::from_wrapped_u32(u32::from_be_bytes(word)));
    }
    poseidon_digest(words)
}

fn leaf_hash(key: &Hash, balance: i128, salt: &Hash) -> Hash {
    let mut inputs = Vec::with_capacity(21);
    inputs.push(SP1Field::from_wrapped_u32(LEAF_TAG));
    inputs.extend(bytes_to_fields(key));
    inputs.extend(i128_to_fields(balance));
    inputs.extend(bytes_to_fields(salt));
    poseidon_digest(inputs)
}

fn internal_hash(depth: usize, left: &Hash, right: &Hash) -> Hash {
    let mut inputs = Vec::with_capacity(18);
    inputs.push(SP1Field::from_wrapped_u32(NODE_TAG));
    inputs.push(SP1Field::from_wrapped_u32(depth as u32));
    inputs.extend(bytes_to_fields(left));
    inputs.extend(bytes_to_fields(right));
    poseidon_digest(inputs)
}

fn default_hashes(depth: usize) -> Vec<Hash> {
    let mut values = Vec::with_capacity(depth + 1);
    values.push(poseidon_digest(vec![SP1Field::from_wrapped_u32(EMPTY_TAG)]));
    for height in 1..=depth {
        let child = values[height - 1];
        values.push(internal_hash(depth - height, &child, &child));
    }
    values
}

fn poseidon_digest(inputs: Vec<SP1Field>) -> Hash {
    let digest = poseidon2_hash(inputs);
    fields_to_bytes(&digest)
}

fn bytes_to_fields(bytes: &[u8; 32]) -> Vec<SP1Field> {
    bytes.chunks(4)
        .map(|chunk| {
            let mut word = [0u8; 4];
            word.copy_from_slice(chunk);
            SP1Field::from_wrapped_u32(u32::from_be_bytes(word))
        })
        .collect()
}

fn i128_to_fields(value: i128) -> Vec<SP1Field> {
    value
        .to_be_bytes()
        .chunks(4)
        .map(|chunk| {
            let mut word = [0u8; 4];
            word.copy_from_slice(chunk);
            SP1Field::from_wrapped_u32(u32::from_be_bytes(word))
        })
        .collect()
}

fn fields_to_bytes(fields: &[SP1Field; 8]) -> Hash {
    let mut out = [0u8; 32];
    for (index, field) in fields.iter().enumerate() {
        out[index * 4..(index + 1) * 4].copy_from_slice(&field.as_canonical_u32().to_be_bytes());
    }
    out
}

fn normalize_address(address: &str) -> String {
    let trimmed = address.trim();
    let raw = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    assert_eq!(raw.len(), 40, "address must have 40 hex chars");
    for ch in raw.bytes() {
        assert!(ch.is_ascii_hexdigit(), "invalid address hex");
    }
    let mut normalized = String::with_capacity(42);
    normalized.push_str("0x");
    for ch in raw.bytes() {
        normalized.push((ch as char).to_ascii_lowercase());
    }
    normalized
}

fn key_bit(key: &Hash, depth: usize) -> bool {
    let byte = key[depth / 8];
    let offset = 7 - (depth % 8);
    ((byte >> offset) & 1) == 1
}

fn from_hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex nibble"),
    }
}
