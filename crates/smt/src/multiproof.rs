use crate::hash::{default_hashes, Hash};
use crate::proof::{
    AddressProof, CollisionNonMembershipProof, CompactAddressProof, CompactMultiproof,
    CompactNonMembershipProof, DefaultNonMembershipProof, MembershipProof, NonMembershipProof,
    SiblingRef,
};
use crate::tree::SparseMerkleTree;

pub fn build_compact_multiproof(
    tree: &SparseMerkleTree,
    addresses: &[String],
) -> Result<CompactMultiproof, String> {
    tree.compact_multiproof(addresses)
}

pub fn expand_compact_multiproof(
    tree: &SparseMerkleTree,
    multiproof: &CompactMultiproof,
) -> Result<Vec<AddressProof>, String> {
    multiproof
        .entries
        .iter()
        .map(|entry| expand_compact_address_proof(tree, &multiproof.frontier_hashes, &entry.proof))
        .collect()
}

fn expand_compact_address_proof(
    tree: &SparseMerkleTree,
    frontier_hashes: &[Hash],
    proof: &CompactAddressProof,
) -> Result<AddressProof, String> {
    let defaults = default_hashes(tree.depth);
    match proof {
        CompactAddressProof::Membership(proof) => Ok(AddressProof::Membership(MembershipProof {
            siblings: expand_membership_siblings(&proof.siblings, &defaults, frontier_hashes)?,
        })),
        CompactAddressProof::NonMembership(CompactNonMembershipProof::Default(proof)) => {
            Ok(AddressProof::NonMembership(NonMembershipProof::Default(
                DefaultNonMembershipProof {
                    default_depth: proof.default_depth,
                    siblings: expand_default_siblings(
                        proof.default_depth,
                        &proof.siblings,
                        &defaults,
                        frontier_hashes,
                    )?,
                },
            )))
        }
        CompactAddressProof::NonMembership(CompactNonMembershipProof::Collision(proof)) => {
            Ok(AddressProof::NonMembership(NonMembershipProof::Collision(
                CollisionNonMembershipProof {
                    collision_address: proof.collision_address.clone(),
                    collision_balance: proof.collision_balance,
                    collision_salt: proof.collision_salt,
                    siblings: expand_membership_siblings(
                        &proof.siblings,
                        &defaults,
                        frontier_hashes,
                    )?,
                },
            )))
        }
    }
}

fn expand_membership_siblings(
    siblings: &[SiblingRef],
    defaults: &[Hash],
    frontier_hashes: &[Hash],
) -> Result<Vec<Hash>, String> {
    siblings
        .iter()
        .enumerate()
        .map(|(level, sibling)| expand_sibling_ref(sibling, defaults[level], frontier_hashes))
        .collect()
}

fn expand_default_siblings(
    default_depth: usize,
    siblings: &[SiblingRef],
    defaults: &[Hash],
    frontier_hashes: &[Hash],
) -> Result<Vec<Hash>, String> {
    let tree_depth = defaults.len().saturating_sub(1);
    siblings
        .iter()
        .enumerate()
        .map(|(offset, sibling)| {
            let layer_index = tree_depth - default_depth + offset;
            expand_sibling_ref(sibling, defaults[layer_index], frontier_hashes)
        })
        .collect()
}

fn expand_sibling_ref(
    sibling: &SiblingRef,
    default_hash: Hash,
    frontier_hashes: &[Hash],
) -> Result<Hash, String> {
    match sibling {
        SiblingRef::Default => Ok(default_hash),
        SiblingRef::Frontier(index) => frontier_hashes
            .get(*index)
            .copied()
            .ok_or_else(|| format!("frontier sibling index {index} out of range")),
    }
}
