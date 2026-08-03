use std::collections::BTreeMap;

use crate::hash::{default_hashes, internal_hash, valid_depth, Hash};
use crate::key::{common_prefix_len, key_for_address};
use crate::leaf::Leaf;
use crate::proof::{
    AddressProof, CollisionNonMembershipProof, CompactAddressProof,
    CompactCollisionNonMembershipProof, CompactDefaultNonMembershipProof, CompactMembershipProof,
    CompactMultiproof, CompactNonMembershipProof, CompactProofEntry, DefaultNonMembershipProof,
    MembershipProof, NonMembershipProof, SiblingRef,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseMerkleTree {
    pub depth: usize,
    pub leaves: BTreeMap<String, Leaf>,
    paths: BTreeMap<u128, String>,
    layers: Vec<BTreeMap<u128, Hash>>,
    root: Hash,
    defaults: Vec<Hash>,
}

impl SparseMerkleTree {
    pub fn new(depth: usize) -> Result<Self, String> {
        Self::from_leaves(depth, Vec::new())
    }

    pub fn from_leaves(depth: usize, leaves: Vec<Leaf>) -> Result<Self, String> {
        validate_depth(depth)?;
        let mut map = BTreeMap::new();
        let mut occupied_paths = BTreeMap::<u128, String>::new();
        for leaf in leaves {
            let path = prefix_index(&leaf.key, depth);
            if let Some(existing) = occupied_paths.insert(path, leaf.address.clone()) {
                return Err(format!(
                    "SMT path collision at depth {depth}: {existing} and {}",
                    leaf.address
                ));
            }
            if map.insert(leaf.address.clone(), leaf).is_some() {
                return Err("duplicate SMT leaf address".to_string());
            }
        }
        let defaults = default_hashes(depth);
        let (layers, root) = compute_layers(depth, &map, &defaults);
        Ok(Self {
            depth,
            leaves: map,
            paths: occupied_paths,
            layers,
            root,
            defaults,
        })
    }

    pub fn from_leaves_and_layers(
        depth: usize,
        leaves: Vec<Leaf>,
        layers: Vec<BTreeMap<u128, Hash>>,
    ) -> Result<Self, String> {
        validate_depth(depth)?;
        if layers.len() != depth + 1 {
            return Err(format!(
                "SMT layer count mismatch: expected {}, got {}",
                depth + 1,
                layers.len()
            ));
        }
        let mut map = BTreeMap::new();
        let mut occupied_paths = BTreeMap::<u128, String>::new();
        for leaf in leaves {
            let path = prefix_index(&leaf.key, depth);
            if let Some(existing) = occupied_paths.insert(path, leaf.address.clone()) {
                return Err(format!(
                    "stored SMT path collision at depth {depth}: {existing} and {}",
                    leaf.address
                ));
            }
            if map.insert(leaf.address.clone(), leaf).is_some() {
                return Err("duplicate SMT leaf in stored state".to_string());
            }
        }
        let stored_root = layers
            .last()
            .and_then(|layer| layer.get(&0).copied())
            .unwrap_or_else(|| default_hashes(depth)[depth]);
        // Nodes are a rebuildable cache. Normalize legacy full-layer snapshots
        // into the compact branch-frontier representation and validate them by
        // the root derived from the authenticated leaf records.
        let defaults = default_hashes(depth);
        let (layers, root) = compute_layers(depth, &map, &defaults);
        if root != stored_root {
            return Err("stored SMT nodes/root do not match stored leaves".to_string());
        }
        let tree = Self {
            depth,
            leaves: map,
            paths: occupied_paths,
            layers,
            root,
            defaults,
        };
        tree.validate_snapshot_shape()?;
        Ok(tree)
    }

    pub fn root(&self) -> Hash {
        self.root
    }

    pub fn get(&self, address: &str) -> Option<&Leaf> {
        let normalized = common::encoding::normalize_address(address).ok()?;
        self.leaves.get(&normalized)
    }

    pub fn leaf_records(&self) -> Vec<Leaf> {
        self.leaves.values().cloned().collect()
    }

    pub fn leaves_iter(&self) -> impl Iterator<Item = &Leaf> {
        self.leaves.values()
    }

    pub fn node_count(&self) -> usize {
        self.layers.iter().map(BTreeMap::len).sum()
    }

    pub fn nodes_iter(&self) -> impl Iterator<Item = (usize, u128, &Hash)> {
        self.layers
            .iter()
            .enumerate()
            .flat_map(|(level, layer)| layer.iter().map(move |(index, hash)| (level, *index, hash)))
    }

    pub fn upsert(&mut self, leaf: Leaf) -> Result<(), String> {
        let leaf_hash = leaf.hash();
        let leaf_key = leaf.key;
        let path = prefix_index(&leaf_key, self.depth);
        if let Some(existing) = self
            .paths
            .get(&path)
            .filter(|existing| existing.as_str() != leaf.address)
        {
            return Err(format!(
                "SMT path collision at depth {}: {} and {}",
                self.depth, existing, leaf.address
            ));
        }
        let structural_insert = !self.leaves.contains_key(&leaf.address);
        self.paths.insert(path, leaf.address.clone());
        self.leaves.insert(leaf.address.clone(), leaf);

        if structural_insert {
            let (layers, root) = compute_layers(self.depth, &self.leaves, &self.defaults);
            self.layers = layers;
            self.root = root;
            return Ok(());
        }

        let mut index = path;
        if self.layers[0].contains_key(&index) {
            self.layers[0].insert(index, leaf_hash);
        }

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
            if level_from_leaf + 1 == self.depth
                || self.layers[level_from_leaf + 1].contains_key(&index)
            {
                self.layers[level_from_leaf + 1].insert(index, parent_hash);
            }
            current = parent_hash;
        }
        self.root = current;
        Ok(())
    }

    pub fn leaves_len(&self) -> usize {
        self.leaves.len()
    }

    pub fn proof_for(&self, address: &str) -> Result<AddressProof, String> {
        let normalized = common::encoding::normalize_address(address)?;
        let key = key_for_address(address)?;
        if let Some(leaf) = self.leaves.get(&normalized) {
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
            let compact_proof = compact_address_proof(
                proof,
                &self.defaults,
                &mut frontier_index,
                &mut frontier_hashes,
            );
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
                layer
                    .get(&sibling_index)
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
                    .or_else(|| self.rebuild_subtree_hash(layer_index, sibling_index))
                    .unwrap_or(self.defaults[layer_index]),
            );
            index /= 2;
        }
        out
    }

    /// Reconstructs a pruned unary subtree only when a default
    /// non-membership proof crosses into an empty sibling. Normal membership
    /// and update paths are served by the O(n)-size branch frontier.
    fn rebuild_subtree_hash(&self, layer: usize, index: u128) -> Option<Hash> {
        if layer > self.depth {
            return None;
        }
        let (lower, upper) = subtree_leaf_range(layer, index)?;
        let mut current = BTreeMap::<u128, Hash>::new();
        match upper {
            Some(upper) => {
                for (path, address) in self.paths.range(lower..upper) {
                    let leaf = self.leaves.get(address)?;
                    current.insert(*path, leaf.hash());
                }
            }
            None => {
                for (path, address) in self.paths.range(lower..) {
                    let leaf = self.leaves.get(address)?;
                    current.insert(*path, leaf.hash());
                }
            }
        }
        if current.is_empty() {
            return None;
        }
        for level_from_leaf in 0..layer {
            let mut parent = BTreeMap::<u128, Hash>::new();
            for (&child_index, hash) in &current {
                if child_index & 1 == 1 && current.contains_key(&(child_index - 1)) {
                    continue;
                }
                let sibling = current
                    .get(&(child_index ^ 1))
                    .copied()
                    .unwrap_or(self.defaults[level_from_leaf]);
                let node_depth = self.depth - level_from_leaf - 1;
                let hash = if child_index & 1 == 0 {
                    internal_hash(node_depth, hash, &sibling)
                } else {
                    internal_hash(node_depth, &sibling, hash)
                };
                parent.insert(child_index / 2, hash);
            }
            current = parent;
        }
        current.get(&index).copied()
    }

    fn collision_leaf(&self, key: &Hash) -> Option<&Leaf> {
        self.paths
            .get(&prefix_index(key, self.depth))
            .and_then(|address| self.leaves.get(address))
    }

    fn deepest_non_default_prefix(&self, key: &Hash) -> usize {
        let target = prefix_index(key, self.depth);
        let predecessor = self.paths.range(..=target).next_back();
        let successor = self.paths.range(target..).next();
        predecessor
            .into_iter()
            .chain(successor)
            .filter_map(|(_, address)| self.leaves.get(address))
            .map(|leaf| common_prefix_len(&leaf.key, key, self.depth))
            .max()
            .unwrap_or(0)
    }

    fn default_subtree_depth(&self, key: &Hash) -> usize {
        if self.leaves.is_empty() {
            0
        } else {
            (self.deepest_non_default_prefix(key) + 1).min(self.depth)
        }
    }

    fn validate_snapshot_shape(&self) -> Result<(), String> {
        for (level, layer) in self.layers.iter().enumerate() {
            let width_bits = self.depth.saturating_sub(level);
            if width_bits < 128 {
                let max_width = 1u128 << width_bits;
                for index in layer.keys() {
                    if *index >= max_width {
                        return Err(format!(
                            "stored SMT node index out of range at level {level}"
                        ));
                    }
                }
            }
        }

        if !self.layers[self.depth].contains_key(&0) && self.root != self.defaults[self.depth] {
            return Err("stored SMT root layer is missing root node".to_string());
        }
        Ok(())
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
    let mut layers = (0..=depth)
        .map(|_| BTreeMap::<u128, Hash>::new())
        .collect::<Vec<_>>();
    let mut current = leaves
        .values()
        .map(|leaf| (prefix_index(&leaf.key, depth), leaf.hash()))
        .collect::<Vec<_>>();
    // Address order is unrelated to the Poseidon key order. Sort once here;
    // every parent layer produced below remains sorted automatically.
    current.sort_unstable_by_key(|(index, _)| *index);

    for level_from_leaf in 0..depth {
        if current.is_empty() {
            continue;
        }

        let mut parent = Vec::<(u128, Hash)>::with_capacity((current.len() + 1) / 2);
        let mut cursor = 0usize;
        while cursor < current.len() {
            let (index, hash) = current[cursor];
            let paired =
                index & 1 == 0 && cursor + 1 < current.len() && current[cursor + 1].0 == index + 1;
            let sibling_hash = if paired {
                current[cursor + 1].1
            } else {
                defaults[level_from_leaf]
            };
            // Persist only children of actual branch nodes. Unary chains can be
            // reconstructed by hashing with the public default values and were
            // the source of the previous O(n * depth) memory footprint.
            if paired {
                layers[level_from_leaf].insert(index, hash);
                layers[level_from_leaf].insert(index + 1, sibling_hash);
            }
            let depth_tag = depth - level_from_leaf - 1;
            let parent_hash = if index & 1 == 0 {
                internal_hash(depth_tag, &hash, &sibling_hash)
            } else {
                internal_hash(depth_tag, &sibling_hash, &hash)
            };
            parent.push((index / 2, parent_hash));
            cursor += if paired { 2 } else { 1 };
        }
        current = parent;
    }

    let root = current
        .first()
        .filter(|(index, _)| *index == 0)
        .map(|(_, hash)| *hash)
        .unwrap_or(defaults[depth]);
    if !leaves.is_empty() {
        layers[depth].insert(0, root);
    }
    (layers, root)
}

fn sibling_index(index: u128) -> u128 {
    if index % 2 == 0 {
        index + 1
    } else {
        index - 1
    }
}

/// Returns the half-open leaf-path range covered by a node `layer` levels
/// above the leaves. `None` as the upper bound means the range reaches the end
/// of the u128 key space.
///
/// `u128::checked_shl` is deliberately not used here: it only checks whether
/// the shift count is in range and silently truncates value overflow. For the
/// rightmost subtree that would turn the mathematical upper bound 2^128 into
/// zero and make `BTreeMap::range(lower..upper)` panic.
fn subtree_leaf_range(layer: usize, index: u128) -> Option<(u128, Option<u128>)> {
    if layer > 128 {
        return None;
    }
    if layer == 128 {
        return (index == 0).then_some((0, None));
    }
    let span = 1u128 << layer;
    let lower = index.checked_mul(span)?;
    let upper = index
        .checked_add(1)
        .and_then(|value| value.checked_mul(span));
    Some((lower, upper))
}

pub fn prefix_index(key: &Hash, prefix_len: usize) -> u128 {
    crate::hash::prefix_index(key, prefix_len)
}

fn validate_depth(depth: usize) -> Result<(), String> {
    if !valid_depth(depth) {
        return Err(format!("SMT depth must be in 1..=128, got {depth}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::subtree_leaf_range;

    #[test]
    fn rightmost_subtree_uses_unbounded_upper_range() {
        assert_eq!(subtree_leaf_range(0, u128::MAX), Some((u128::MAX, None)));
        assert_eq!(subtree_leaf_range(127, 1), Some((1u128 << 127, None)));
    }

    #[test]
    fn subtree_range_rejects_invalid_overflowing_indices() {
        assert_eq!(subtree_leaf_range(127, 2), None);
        assert_eq!(subtree_leaf_range(128, 0), Some((0, None)));
        assert_eq!(subtree_leaf_range(128, 1), None);
    }
}
