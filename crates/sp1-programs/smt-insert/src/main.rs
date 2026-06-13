#![no_main]

extern crate alloc;

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
fn main() {
    let input: Sp1InsertStdin = sp1_zkvm::io::read();
    let pv = verify_and_apply_insert(input);
    sp1_zkvm::io::commit(&pv);
}

fn verify_and_apply_insert(input: Sp1InsertStdin) -> Sp1InsertPublicValues {
    assert!(input.balance >= 0, "negative inserted balance");
    let defaults = default_hashes(input.depth);

    let membership_siblings = match &input.non_membership_proof {
        Sp1NonMembershipProof::Default(proof) => {
            let resolved = resolve_default_siblings(
                proof.default_depth,
                &proof.siblings,
                &input.frontier_hashes,
                &defaults,
            );
            verify_default_non_membership_root(
                &input.key,
                input.old_smt_root,
                input.depth,
                &defaults,
                proof.default_depth,
                &resolved,
            );
            expand_default_to_membership(input.depth, &defaults, &resolved, proof.default_depth)
        }
        Sp1NonMembershipProof::Collision(proof) => {
            let resolved =
                resolve_membership_siblings(&proof.siblings, &input.frontier_hashes, &defaults);
            verify_collision_non_membership_root(
                &input.key,
                input.old_smt_root,
                input.depth,
                proof,
                &resolved,
            );
            resolved
        }
    };

    let new_leaf = Sp1Leaf {
        key: input.key,
        balance: input.balance,
        salt: input.salt,
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
    assert_eq!(
        siblings.len(),
        depth,
        "expanded default path length mismatch"
    );
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
    assert!(
        proof.collision_leaf.key != *key,
        "collision proof uses identical key"
    );
    let collision_root = compute_membership_root(&proof.collision_leaf, siblings, depth);
    assert_eq!(
        collision_root, root,
        "collision non-membership root mismatch"
    );
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
    let mut hash = leaf_hash(&leaf.key, leaf.balance, &leaf.salt);
    for (level_from_leaf, sibling) in siblings.iter().enumerate() {
        let depth_tag = depth - level_from_leaf - 1;
        hash = if key_bit(&leaf.key, depth_tag) {
            internal_hash(depth_tag, sibling, &hash)
        } else {
            internal_hash(depth_tag, &hash, sibling)
        };
    }
    hash
}

fn leaf_hash(key: &Hash, balance: i128, salt: &Hash) -> Hash {
    let mut inputs = Vec::with_capacity(21);
    inputs.push(SP1Field::from_wrapped_u32(LEAF_TAG));
    push_bytes_fields(&mut inputs, key);
    push_i128_fields(&mut inputs, balance);
    push_bytes_fields(&mut inputs, salt);
    poseidon_digest(inputs)
}

fn internal_hash(depth: usize, left: &Hash, right: &Hash) -> Hash {
    let mut inputs = Vec::with_capacity(18);
    inputs.push(SP1Field::from_wrapped_u32(NODE_TAG));
    inputs.push(SP1Field::from_wrapped_u32(depth as u32));
    push_bytes_fields(&mut inputs, left);
    push_bytes_fields(&mut inputs, right);
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

fn push_bytes_fields(out: &mut Vec<SP1Field>, bytes: &[u8; 32]) {
    for chunk in bytes.chunks(4) {
        let mut word = [0u8; 4];
        word.copy_from_slice(chunk);
        out.push(SP1Field::from_wrapped_u32(u32::from_be_bytes(word)));
    }
}

fn push_i128_fields(out: &mut Vec<SP1Field>, value: i128) {
    for chunk in value.to_be_bytes().chunks(4) {
        let mut word = [0u8; 4];
        word.copy_from_slice(chunk);
        out.push(SP1Field::from_wrapped_u32(u32::from_be_bytes(word)));
    }
}

fn fields_to_bytes(fields: &[SP1Field; 8]) -> Hash {
    let mut out = [0u8; 32];
    for (index, field) in fields.iter().enumerate() {
        out[index * 4..(index + 1) * 4].copy_from_slice(&field.as_canonical_u32().to_be_bytes());
    }
    out
}

fn key_bit(key: &Hash, depth: usize) -> bool {
    let byte = key[depth / 8];
    let offset = 7 - (depth % 8);
    ((byte >> offset) & 1) == 1
}
