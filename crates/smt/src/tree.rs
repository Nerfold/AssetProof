use std::collections::BTreeMap;

use crate::hash::{default_hashes, internal_hash, Hash};
use crate::key::{common_prefix_len, key_bit, key_for_address};
use crate::leaf::Leaf;
use crate::proof::{
    AddressProof, CollisionNonMembershipProof, CompactAddressProof, CompactCollisionNonMembershipProof,
    CompactDefaultNonMembershipProof, CompactMembershipProof, CompactMultiproof, CompactNonMembershipProof,
    CompactProofEntry, DefaultNonMembershipProof, MembershipProof, NonMembershipProof, SiblingRef,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseMerkleTree {
    pub depth: usize,
    pub leaves: BTreeMap<String, Leaf>,
    layers: Vec<BTreeMap<u128, Hash>>,
    root: Hash,
    defaults: Vec<Hash>,
}

impl SparseMerkleTree {
    pub fn new(depth: usize) -> Self {
        Self::from_leaves(depth, Vec::new())
    }

    pub fn from_leaves(depth: usize, leaves: Vec<Leaf>) -> Self {
        let mut map = BTreeMap::new();
        for leaf in leaves {
            map.insert(leaf.address.clone(), leaf);
        }
        let defaults = default_hashes(depth);
        let (layers, root) = compute_layers(depth, &map, &defaults);
        Self {
            depth,
            leaves: map,
            layers,
            root,
            defaults,
        }
    }

    pub fn root(&self) -> Hash {
        self.root
    }

    pub fn get(&self, address: &str) -> Option<&Leaf> {
        self.leaves.get(address)
    }

    pub fn leaf_records(&self) -> Vec<Leaf> {
        self.leaves.values().cloned().collect()
    }

    pub fn upsert(&mut self, leaf: Leaf) {
        let leaf_hash = leaf.hash();
        let leaf_key = leaf.key;
        self.leaves.insert(leaf.address.clone(), leaf);

        let mut index = prefix_index(&leaf_key, self.depth);
        self.layers[0].insert(index, leaf_hash);

        let mut current = leaf_hash;
        for level_from_leaf in 0..self.depth {
            let sibling_idx = sibling_index(index);
            let sibling_hash = self.layers[level_from_leaf]
                .get(&sibling_idx)
                .copied()
                .unwrap_or(self.defaults[level_from_leaf]);
            let node_depth = self.depth - level_from_leaf - 1;
            let parent_hash = if index % 2 == 0 {
                internal_hash(node_depth, &current, &sibling_hash)
            } else {
                internal_hash(node_depth, &sibling_hash, &current)
            };
            index /= 2;
            self.layers[level_from_leaf + 1].insert(index, parent_hash);
            current = parent_hash;
        }
        self.root = current;
    }

    pub fn leaves_len(&self) -> usize {
        self.leaves.len()
    }

    pub fn proof_for(&self, address: &str) -> Result<AddressProof, String> {
        let key = key_for_address(address)?;
        if let Some(leaf) = self.get(address) {
            Ok(AddressProof::Membership(MembershipProof {
                siblings: self.membership_siblings(&leaf.key),
            }))
        } else if let Some(collision_leaf) = self.collision_leaf(&key) {
            Ok(AddressProof::NonMembership(NonMembershipProof::Collision(
                CollisionNonMembershipProof {
                    collision_address: collision_leaf.address.clone(),
                    collision_balance: collision_leaf.balance,
                    collision_salt: collision_leaf.salt,
                    siblings: self.membership_siblings(&collision_leaf.key),
                },
            )))
        } else {
            let default_depth = self.default_subtree_depth(&key);
            Ok(AddressProof::NonMembership(NonMembershipProof::Default(
                DefaultNonMembershipProof {
                    default_depth,
                    siblings: self.default_siblings(&key, default_depth),
                },
            )))
        }
    }

    pub fn proofs_for(&self, addresses: &[String]) -> Result<Vec<AddressProof>, String> {
        let mut proofs = Vec::with_capacity(addresses.len());
        for address in addresses {
            proofs.push(self.proof_for(address)?);
        }
        Ok(proofs)
    }

    pub fn compact_multiproof(&self, addresses: &[String]) -> Result<CompactMultiproof, String> {
        let proofs = self.proofs_for(addresses)?;
        let mut frontier_index = BTreeMap::<Hash, usize>::new();
        let mut frontier_hashes = Vec::<Hash>::new();
        let mut total_sibling_hashes = 0usize;
        let mut entries = Vec::with_capacity(addresses.len());
        for (address, proof) in addresses.iter().zip(proofs.into_iter()) {
            let compact_proof =
                compact_address_proof(proof, &self.defaults, &mut frontier_index, &mut frontier_hashes);
            total_sibling_hashes += compact_sibling_len(&compact_proof);
            entries.push(CompactProofEntry {
                address: address.clone(),
                proof: compact_proof,
            });
        }

        Ok(CompactMultiproof {
            entries,
            frontier_hashes,
            total_sibling_hashes,
        })
    }

    fn membership_siblings(&self, key: &Hash) -> Vec<Hash> {
        let mut out = Vec::with_capacity(self.depth);
        let mut index = prefix_index(key, self.depth);
        for (distance, layer) in self.layers.iter().take(self.depth).enumerate() {
            let sibling_index = sibling_index(index);
            out.push(
                layer.get(&sibling_index)
                    .copied()
                    .unwrap_or(self.defaults[distance]),
            );
            index /= 2;
        }
        out
    }

    fn default_siblings(&self, key: &Hash, default_depth: usize) -> Vec<Hash> {
        let mut out = Vec::with_capacity(default_depth);
        let mut index = prefix_index(key, default_depth);
        for layer_index in (self.depth - default_depth)..self.depth {
            let sibling_index = sibling_index(index);
            out.push(
                self.layers[layer_index]
                    .get(&sibling_index)
                    .copied()
                    .unwrap_or(self.defaults[layer_index]),
            );
            index /= 2;
        }
        out
    }

    fn collision_leaf(&self, key: &Hash) -> Option<&Leaf> {
        self.leaves
            .values()
            .find(|leaf| common_prefix_len(&leaf.key, key, self.depth) == self.depth)
    }

    fn deepest_non_default_prefix(&self, key: &Hash) -> usize {
        let mut longest = 0usize;
        for leaf in self.leaves.values() {
            let prefix_len = common_prefix_len(&leaf.key, key, self.depth);
            if prefix_len > longest {
                longest = prefix_len;
                if longest == self.depth {
                    break;
                }
            }
        }
        longest
    }

    fn default_subtree_depth(&self, key: &Hash) -> usize {
        if self.leaves.is_empty() {
            0
        } else {
            (self.deepest_non_default_prefix(key) + 1).min(self.depth)
        }
    }
}

fn compact_address_proof(
    proof: AddressProof,
    defaults: &[Hash],
    frontier_index: &mut BTreeMap<Hash, usize>,
    frontier_hashes: &mut Vec<Hash>,
) -> CompactAddressProof {
    match proof {
        AddressProof::Membership(MembershipProof { siblings }) => {
            CompactAddressProof::Membership(CompactMembershipProof {
                siblings: compact_membership_siblings(
                    siblings,
                    defaults,
                    frontier_index,
                    frontier_hashes,
                ),
            })
        }
        AddressProof::NonMembership(NonMembershipProof::Default(default)) => {
            CompactAddressProof::NonMembership(CompactNonMembershipProof::Default(
                CompactDefaultNonMembershipProof {
                    default_depth: default.default_depth,
                    siblings: compact_default_siblings(
                        default.siblings,
                        default.default_depth,
                        defaults,
                        frontier_index,
                        frontier_hashes,
                    ),
                },
            ))
        }
        AddressProof::NonMembership(NonMembershipProof::Collision(collision)) => {
            CompactAddressProof::NonMembership(CompactNonMembershipProof::Collision(
                CompactCollisionNonMembershipProof {
                    collision_address: collision.collision_address,
                    collision_balance: collision.collision_balance,
                    collision_salt: collision.collision_salt,
                    siblings: compact_membership_siblings(
                        collision.siblings,
                        defaults,
                        frontier_index,
                        frontier_hashes,
                    ),
                },
            ))
        }
    }
}

fn compact_membership_siblings(
    siblings: Vec<Hash>,
    defaults: &[Hash],
    frontier_index: &mut BTreeMap<Hash, usize>,
    frontier_hashes: &mut Vec<Hash>,
) -> Vec<SiblingRef> {
    siblings
        .into_iter()
        .enumerate()
        .map(|(level, hash)| {
            if hash == defaults[level] {
                SiblingRef::Default
            } else {
                let index = if let Some(index) = frontier_index.get(&hash) {
                    *index
                } else {
                    let index = frontier_hashes.len();
                    frontier_hashes.push(hash);
                    frontier_index.insert(hash, index);
                    index
                };
                SiblingRef::Frontier(index)
            }
        })
        .collect()
}

fn compact_default_siblings(
    siblings: Vec<Hash>,
    default_depth: usize,
    defaults: &[Hash],
    frontier_index: &mut BTreeMap<Hash, usize>,
    frontier_hashes: &mut Vec<Hash>,
) -> Vec<SiblingRef> {
    let tree_depth = defaults.len().saturating_sub(1);
    siblings
        .into_iter()
        .enumerate()
        .map(|(offset, hash)| {
            let layer_index = tree_depth - default_depth + offset;
            let default_hash = defaults[layer_index];
            if hash == default_hash {
                SiblingRef::Default
            } else {
                let index = if let Some(index) = frontier_index.get(&hash) {
                    *index
                } else {
                    let index = frontier_hashes.len();
                    frontier_hashes.push(hash);
                    frontier_index.insert(hash, index);
                    index
                };
                SiblingRef::Frontier(index)
            }
        })
        .collect()
}

fn compact_sibling_len(proof: &CompactAddressProof) -> usize {
    match proof {
        CompactAddressProof::Membership(proof) => proof.siblings.len(),
        CompactAddressProof::NonMembership(CompactNonMembershipProof::Default(proof)) => {
            proof.siblings.len()
        }
        CompactAddressProof::NonMembership(CompactNonMembershipProof::Collision(proof)) => {
            proof.siblings.len()
        }
    }
}

fn compute_layers(
    depth: usize,
    leaves: &BTreeMap<String, Leaf>,
    defaults: &[Hash],
) -> (Vec<BTreeMap<u128, Hash>>, Hash) {
    let mut layers = Vec::with_capacity(depth + 1);
    let mut current = BTreeMap::<u128, Hash>::new();
    for leaf in leaves.values() {
        current.insert(prefix_index(&leaf.key, depth), leaf.hash());
    }
    layers.push(current.clone());

    for level_from_leaf in 0..depth {
        if current.is_empty() {
            layers.push(BTreeMap::new());
            continue;
        }

        let mut parent = BTreeMap::<u128, Hash>::new();
        for (&index, hash) in &current {
            if index % 2 == 1 && current.contains_key(&(index - 1)) {
                continue;
            }

            let sibling_idx = sibling_index(index);
            let sibling_hash = current
                .get(&sibling_idx)
                .copied()
                .unwrap_or(defaults[level_from_leaf]);
            let depth_tag = depth - level_from_leaf - 1;
            let parent_hash = if index % 2 == 0 {
                internal_hash(depth_tag, hash, &sibling_hash)
            } else {
                internal_hash(depth_tag, &sibling_hash, hash)
            };
            parent.insert(index / 2, parent_hash);
        }
        current = parent.clone();
        layers.push(parent);
    }

    let root = layers
        .last()
        .and_then(|layer| layer.get(&0).copied())
        .unwrap_or(defaults[depth]);
    (layers, root)
}

fn sibling_index(index: u128) -> u128 {
    if index % 2 == 0 {
        index + 1
    } else {
        index - 1
    }
}

pub fn prefix_index(key: &Hash, prefix_len: usize) -> u128 {
    let mut index = 0u128;
    for depth in 0..prefix_len {
        index <<= 1;
        if key_bit(key, depth) {
            index |= 1;
        }
    }
    index
}
