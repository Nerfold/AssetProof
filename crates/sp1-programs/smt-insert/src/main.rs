#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use sp1_programs_common::io::{
    Hash, Sp1InsertPublicValues, Sp1InsertStdin, Sp1Leaf, Sp1NonMembershipProof, Sp1SiblingRef,
};
use sp1_programs_common::smt::{
    default_hashes, expand_default_membership_siblings, insert_transition_commitment,
    internal_hash, key_bit, key_hash, leaf_hash, valid_depth,
};
use sp1_zkvm::entrypoint;

entrypoint!(main);

fn main() {
    let input: Sp1InsertStdin = sp1_zkvm::io::read();
    let pv = verify_and_apply_insert(input);
    sp1_zkvm::io::commit(&pv);
}

fn verify_and_apply_insert(input: Sp1InsertStdin) -> Sp1InsertPublicValues {
    assert!(valid_depth(input.depth), "SMT depth must be in 1..=128");
    assert!(input.balance >= 0, "negative inserted balance");
    assert_eq!(
        key_hash(&input.address).expect("invalid Ethereum insert address"),
        input.key,
        "insert address/key mismatch"
    );
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
            expand_default_membership_siblings(
                input.depth,
                &defaults,
                &resolved,
                proof.default_depth,
            )
        }
        Sp1NonMembershipProof::Collision(_) => {
            panic!("cannot insert into an occupied fixed-depth SMT path; use a deeper tree")
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
    let new_leaf_count = input
        .old_leaf_count
        .checked_add(1)
        .expect("leaf count overflow");
    let transition_commitment = insert_transition_commitment(
        &input.transition_salt,
        &input.key,
        input.balance,
        &input.salt,
    );

    Sp1InsertPublicValues {
        old_state_root: input.state_root,
        new_state_root: input.new_state_root,
        depth: input.depth,
        old_smt_root: input.old_smt_root,
        new_smt_root: new_root,
        inserted_balance: input.balance,
        old_balance_total: input.old_balance_total,
        new_balance_total,
        old_leaf_count: input.old_leaf_count,
        new_leaf_count,
        transition_commitment,
    }
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
