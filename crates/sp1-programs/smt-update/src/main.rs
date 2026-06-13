#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use slop_algebra::{AbstractField, PrimeField32};
use sp1_primitives::{poseidon2_hash, SP1Field};
use sp1_programs_common::io::{
    Hash, Sp1AddressProof, Sp1CollisionNonMembershipProof, Sp1Leaf, Sp1MembershipProof,
    Sp1NonMembershipProof, Sp1SiblingRef, Sp1UpdatePublicValues, Sp1UpdateStdin,
};
use sp1_zkvm::entrypoint;

entrypoint!(main);

const LEAF_TAG: u32 = 1;
const NODE_TAG: u32 = 2;
const EMPTY_TAG: u32 = 3;

type HashPair = (Hash, Hash);
type IndexedNodePair = (u128, HashPair);
type IndexedHash = (u128, Hash);

fn main() {
    let input: Sp1UpdateStdin = sp1_zkvm::io::read();
    let pv = verify_and_apply_update(input);
    sp1_zkvm::io::commit(&pv);
}

fn verify_and_apply_update(input: Sp1UpdateStdin) -> Sp1UpdatePublicValues {
    let defaults = default_hashes(input.depth);
    let mut aggregate_delta = 0i128;
    let mut membership_flags = Vec::with_capacity(input.entries.len());
    let mut leaf_updates = Vec::<IndexedNodePair>::with_capacity(input.entries.len());
    let mut witness_siblings = vec![Vec::<IndexedHash>::new(); input.depth];

    for entry in &input.entries {
        match &entry.proof {
            Sp1AddressProof::Membership(Sp1MembershipProof { siblings }) => {
                let old_leaf = entry
                    .old_leaf
                    .as_ref()
                    .expect("member update requires old leaf");
                assert_eq!(old_leaf.key, entry.key, "old leaf key mismatch");
                let resolved =
                    resolve_membership_siblings(siblings, &input.frontier_hashes, &defaults);
                let old_root = compute_membership_root(old_leaf, &resolved, input.depth);
                assert_eq!(old_root, input.old_smt_root, "membership root mismatch");

                let new_balance = old_leaf
                    .balance
                    .checked_add(entry.delta)
                    .expect("balance overflow");
                assert!(new_balance >= 0, "negative updated balance");
                let new_leaf = Sp1Leaf {
                    key: old_leaf.key,
                    balance: new_balance,
                    salt: old_leaf.salt,
                };

                let leaf_index = prefix_index(&entry.key, input.depth);
                let old_hash = leaf_hash(&entry.key, old_leaf.balance, &old_leaf.salt);
                let new_hash = leaf_hash(&entry.key, new_leaf.balance, &new_leaf.salt);
                for (level_from_leaf, sibling_hash) in resolved.iter().enumerate() {
                    let node_index = leaf_index >> level_from_leaf;
                    let sibling_index = sibling_index(node_index);
                    witness_siblings[level_from_leaf].push((sibling_index, *sibling_hash));
                }

                leaf_updates.push((leaf_index, (old_hash, new_hash)));
                aggregate_delta = aggregate_delta
                    .checked_add(entry.delta)
                    .expect("aggregate delta overflow");
                membership_flags.push(1);
            }
            Sp1AddressProof::NonMembership(Sp1NonMembershipProof::Default(proof)) => {
                let resolved = resolve_default_siblings(
                    proof.default_depth,
                    &proof.siblings,
                    &input.frontier_hashes,
                    &defaults,
                );
                verify_default_non_membership_root(
                    &entry.key,
                    input.old_smt_root,
                    input.depth,
                    &defaults,
                    proof.default_depth,
                    &resolved,
                );
                membership_flags.push(0);
            }
            Sp1AddressProof::NonMembership(Sp1NonMembershipProof::Collision(proof)) => {
                let resolved =
                    resolve_membership_siblings(&proof.siblings, &input.frontier_hashes, &defaults);
                verify_collision_non_membership_root(
                    &entry.key,
                    input.old_smt_root,
                    input.depth,
                    proof,
                    &resolved,
                );
                membership_flags.push(0);
            }
        }
    }

    sort_and_validate_leaf_updates(&mut leaf_updates);
    canonicalize_witness_siblings(&mut witness_siblings);

    let (recomputed_old_root, new_root) = if leaf_updates.is_empty() {
        (input.old_smt_root, input.old_smt_root)
    } else {
        compute_updated_roots(input.depth, &defaults, &leaf_updates, &witness_siblings)
    };
    assert_eq!(
        recomputed_old_root, input.old_smt_root,
        "old root recomputation mismatch"
    );

    let new_balance_total = input
        .old_balance_total
        .checked_add(aggregate_delta)
        .expect("balance total overflow");

    Sp1UpdatePublicValues {
        old_state_root: input.state_root,
        new_state_root: input.new_state_root,
        old_smt_root: input.old_smt_root,
        new_smt_root: new_root,
        aggregate_delta,
        old_balance_total: input.old_balance_total,
        new_balance_total,
        membership_flags,
    }
}

fn compute_updated_roots(
    depth: usize,
    defaults: &[Hash],
    leaf_updates: &[IndexedNodePair],
    witness_siblings: &[Vec<IndexedHash>],
) -> (Hash, Hash) {
    let mut current = leaf_updates.to_vec();

    for level_from_leaf in 0..depth {
        let merged = merge_level_nodes(&current, &witness_siblings[level_from_leaf]);
        let default_pair = (defaults[level_from_leaf], defaults[level_from_leaf]);
        let mut next = Vec::<IndexedNodePair>::with_capacity((merged.len() + 1) / 2);
        let mut cursor = 0usize;

        while cursor < merged.len() {
            let (index, pair) = merged[cursor];
            let parent_index = index / 2;
            let left_index = parent_index * 2;
            let right_index = left_index + 1;
            let mut left = default_pair;
            let mut right = default_pair;

            if index == left_index {
                left = pair;
                cursor += 1;
                if cursor < merged.len() && merged[cursor].0 == right_index {
                    right = merged[cursor].1;
                    cursor += 1;
                }
            } else {
                assert_eq!(index, right_index, "non-canonical merged level order");
                right = pair;
                cursor += 1;
            }

            let node_depth = depth - level_from_leaf - 1;
            next.push((
                parent_index,
                (
                    internal_hash(node_depth, &left.0, &right.0),
                    internal_hash(node_depth, &left.1, &right.1),
                ),
            ));
        }
        current = next;
    }

    assert_eq!(current.len(), 1, "missing root after update");
    let (_, roots) = current.pop().expect("missing root after update");
    roots
}

fn sort_and_validate_leaf_updates(leaf_updates: &mut Vec<IndexedNodePair>) {
    leaf_updates.sort_unstable_by_key(|(index, _)| *index);
    for pair in leaf_updates.windows(2) {
        assert_ne!(pair[0].0, pair[1].0, "duplicate leaf update index");
    }
}

fn canonicalize_witness_siblings(witness_siblings: &mut [Vec<IndexedHash>]) {
    for siblings in witness_siblings {
        if siblings.len() < 2 {
            continue;
        }

        siblings.sort_unstable_by_key(|(index, _)| *index);
        let mut deduped = Vec::<IndexedHash>::with_capacity(siblings.len());
        for (index, hash) in siblings.iter().copied() {
            if let Some((prev_index, prev_hash)) = deduped.last() {
                if *prev_index == index {
                    assert_eq!(*prev_hash, hash, "inconsistent frontier witness");
                    continue;
                }
            }
            deduped.push((index, hash));
        }
        *siblings = deduped;
    }
}

fn merge_level_nodes(
    current: &[IndexedNodePair],
    siblings: &[IndexedHash],
) -> Vec<IndexedNodePair> {
    let mut merged = Vec::<IndexedNodePair>::with_capacity(current.len() + siblings.len());
    let mut current_index = 0usize;
    let mut sibling_index = 0usize;

    while current_index < current.len() && sibling_index < siblings.len() {
        let (current_node_index, current_pair) = current[current_index];
        let (sibling_node_index, sibling_hash) = siblings[sibling_index];
        match current_node_index.cmp(&sibling_node_index) {
            core::cmp::Ordering::Less => {
                merged.push((current_node_index, current_pair));
                current_index += 1;
            }
            core::cmp::Ordering::Equal => {
                assert_eq!(
                    current_pair.0, sibling_hash,
                    "frontier witness does not match updated old hash"
                );
                merged.push((current_node_index, current_pair));
                current_index += 1;
                sibling_index += 1;
            }
            core::cmp::Ordering::Greater => {
                merged.push((sibling_node_index, (sibling_hash, sibling_hash)));
                sibling_index += 1;
            }
        }
    }

    while current_index < current.len() {
        merged.push(current[current_index]);
        current_index += 1;
    }
    while sibling_index < siblings.len() {
        let (index, hash) = siblings[sibling_index];
        merged.push((index, (hash, hash)));
        sibling_index += 1;
    }

    merged
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
    assert!(
        common_prefix_len(key, &proof.collision_leaf.key, depth) == depth,
        "collision proof key must share the configured path prefix"
    );
    let collision_root = compute_membership_root(&proof.collision_leaf, siblings, depth);
    assert_eq!(
        collision_root, root,
        "collision non-membership root mismatch"
    );
}

fn compute_membership_root(leaf: &Sp1Leaf, siblings: &[Hash], depth: usize) -> Hash {
    assert_eq!(siblings.len(), depth, "membership proof length mismatch");
    let mut hash = leaf_hash(&leaf.key, leaf.balance, &leaf.salt);
    for (level_from_leaf, sibling) in siblings.iter().enumerate() {
        let node_depth = depth - level_from_leaf - 1;
        hash = if key_bit(&leaf.key, node_depth) {
            internal_hash(node_depth, sibling, &hash)
        } else {
            internal_hash(node_depth, &hash, sibling)
        };
    }
    hash
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

fn sibling_index(index: u128) -> u128 {
    if index % 2 == 0 {
        index + 1
    } else {
        index - 1
    }
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

fn prefix_index(key: &Hash, prefix_len: usize) -> u128 {
    let mut index = 0u128;
    for depth in 0..prefix_len {
        index <<= 1;
        if key_bit(key, depth) {
            index |= 1;
        }
    }
    index
}

fn common_prefix_len(a: &Hash, b: &Hash, max_depth: usize) -> usize {
    for depth in 0..max_depth {
        if key_bit(a, depth) != key_bit(b, depth) {
            return depth;
        }
    }
    max_depth
}
