use ark_bls12_381::{Fr, G1Projective};
use ark_ff::UniformRand;
use rand::RngCore;
use std::collections::BTreeMap;
use std::path::Path;

use common::crypto::{commit_balance, hash_bytes, point_g1_to_hex};
use common::types::{SmtLeafRecord, SmtNodeRecord, StoredSmtState};

use crate::hash::{default_hashes, Hash};
use crate::leaf::Leaf;
use crate::tree::SparseMerkleTree;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmtState {
    pub state_root: String,
    pub depth: usize,
    pub balance_total: i128,
    pub balance_blind: Fr,
    tree: SparseMerkleTree,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmtPublicState {
    pub state_root: String,
    pub depth: usize,
    pub smt_root: Hash,
    pub balance_total: i128,
    pub leaf_count: usize,
}

impl SmtState {
    pub fn new(
        state_root: String,
        depth: usize,
        leaves: Vec<Leaf>,
        balance_blind: Fr,
    ) -> Result<Self, String> {
        let balance_total = leaves.iter().try_fold(0i128, |total, leaf| {
            total
                .checked_add(leaf.balance)
                .ok_or_else(|| "SMT balance total overflow".to_string())
        })?;
        let mut dedup = std::collections::BTreeSet::new();
        for leaf in &leaves {
            if leaf.balance < 0 {
                return Err(format!("negative SMT balance for {}", leaf.address));
            }
            if !dedup.insert(leaf.address.clone()) {
                return Err(format!("duplicate reserve address {}", leaf.address));
            }
        }
        let tree = SparseMerkleTree::from_leaves(depth, leaves)?;
        Ok(Self {
            state_root,
            depth,
            balance_total,
            balance_blind,
            tree,
        })
    }

    pub fn tree(&self) -> &SparseMerkleTree {
        &self.tree
    }

    pub fn smt_root(&self) -> Hash {
        self.tree.root()
    }

    pub fn balance_commitment(&self) -> G1Projective {
        commit_balance(self.balance_total, self.balance_blind)
    }

    pub fn public_state(&self) -> SmtPublicState {
        SmtPublicState {
            state_root: self.state_root.clone(),
            depth: self.depth,
            smt_root: self.smt_root(),
            balance_total: self.balance_total,
            leaf_count: self.leaf_count(),
        }
    }

    pub fn leaf_count(&self) -> usize {
        self.tree.leaves_len()
    }

    pub fn leaf_records(&self) -> Vec<Leaf> {
        self.tree.leaf_records()
    }

    pub fn tree_mut(&mut self) -> &mut SparseMerkleTree {
        &mut self.tree
    }

    pub fn to_stored(&self) -> Result<StoredSmtState, String> {
        let leaves = self
            .tree
            .leaves_iter()
            .map(|leaf| SmtLeafRecord {
                address: leaf.address.clone(),
                balance: leaf.balance,
                salt_hex: hex_string(&leaf.salt),
            })
            .collect();
        let nodes = self
            .tree
            .nodes_iter()
            .map(|(level, index, hash)| SmtNodeRecord {
                level,
                index,
                hash_hex: hex_string(hash),
            })
            .collect();
        Ok(StoredSmtState {
            state_root: self.state_root.clone(),
            smt_root_hex: hex_string(&self.smt_root()),
            depth: self.depth,
            balance_total: self.balance_total,
            balance_blind: self.balance_blind,
            balance_commitment_hex: point_g1_to_hex(&self.balance_commitment())?,
            leaves,
            nodes,
            nodes_path: String::new(),
        })
    }

    pub fn persist(&self, path: &Path) -> Result<(), String> {
        let balance_commitment_hex = point_g1_to_hex(&self.balance_commitment())?;
        common::io::write_smt_state_streaming(
            path,
            &self.state_root,
            &hex_string(&self.smt_root()),
            self.depth,
            self.balance_total,
            &self.balance_blind,
            &balance_commitment_hex,
            self.tree.leaves_len(),
            self.tree
                .leaves_iter()
                .map(|leaf| (leaf.address.as_str(), leaf.balance, leaf.salt)),
            self.tree.node_count(),
            self.tree.nodes_iter(),
        )
    }

    pub fn from_stored(stored: &StoredSmtState) -> Result<Self, String> {
        Self::from_stored_owned(stored.clone())
    }

    pub fn from_stored_owned(stored: StoredSmtState) -> Result<Self, String> {
        let StoredSmtState {
            state_root,
            smt_root_hex,
            depth,
            balance_total,
            balance_blind,
            balance_commitment_hex,
            leaves: stored_leaves,
            nodes,
            ..
        } = stored;
        let mut leaves = Vec::with_capacity(stored_leaves.len());
        for record in stored_leaves {
            leaves.push(Leaf::new(
                record.address,
                record.balance,
                parse_hash_hex(&record.salt_hex)?,
            )?);
        }
        let state = if nodes.is_empty() {
            Self::new(state_root, depth, leaves, balance_blind)?
        } else {
            let layers = restore_layers_owned(depth, nodes)?;
            let tree = SparseMerkleTree::from_leaves_and_layers(depth, leaves, layers)?;
            Self::from_tree_with_total(state_root, tree, balance_total, balance_blind)?
        };
        let root = state.smt_root();
        if hex_string(&root) != smt_root_hex {
            return Err("stored SMT root mismatch".to_string());
        }
        let commitment = point_g1_to_hex(&state.balance_commitment())?;
        if commitment != balance_commitment_hex {
            return Err("stored balance commitment mismatch".to_string());
        }
        Ok(state)
    }

    pub fn random_salt() -> Hash {
        let mut salt = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        salt
    }

    pub fn random_blind() -> Fr {
        Fr::rand(&mut rand::rngs::OsRng)
    }

    /// Deterministic fixture salt. Never use this for private production state.
    pub fn mock_salt(label: &str, address: &str, balance: i128) -> Hash {
        hash_bytes(label, &[address.as_bytes(), &balance.to_le_bytes()])
    }

    pub fn _default_hashes(&self) -> Vec<Hash> {
        default_hashes(self.depth)
    }

    pub fn from_tree(
        state_root: String,
        tree: SparseMerkleTree,
        balance_blind: Fr,
    ) -> Result<Self, String> {
        let balance_total = checked_tree_total(&tree)?;
        Ok(Self {
            state_root,
            depth: tree.depth,
            balance_total,
            balance_blind,
            tree,
        })
    }

    pub fn from_tree_with_total(
        state_root: String,
        tree: SparseMerkleTree,
        balance_total: i128,
        balance_blind: Fr,
    ) -> Result<Self, String> {
        let expected_total = checked_tree_total(&tree)?;
        if balance_total != expected_total {
            return Err("SMT balance total does not match stored leaves".to_string());
        }
        Ok(Self {
            state_root,
            depth: tree.depth,
            balance_total,
            balance_blind,
            tree,
        })
    }
}

fn checked_tree_total(tree: &SparseMerkleTree) -> Result<i128, String> {
    tree.leaves_iter().try_fold(0i128, |total, leaf| {
        if leaf.balance < 0 {
            return Err(format!("negative SMT balance for {}", leaf.address));
        }
        total
            .checked_add(leaf.balance)
            .ok_or_else(|| "SMT balance total overflow".to_string())
    })
}

fn restore_layers_owned(
    depth: usize,
    nodes: Vec<SmtNodeRecord>,
) -> Result<Vec<BTreeMap<u128, Hash>>, String> {
    let mut layers = vec![BTreeMap::<u128, Hash>::new(); depth + 1];
    for node in nodes {
        if node.level > depth {
            return Err(format!(
                "stored SMT node level {} exceeds depth {}",
                node.level, depth
            ));
        }
        layers[node.level].insert(node.index, parse_hash_hex(&node.hash_hex)?);
    }
    Ok(layers)
}

pub fn hex_string(hash: &Hash) -> String {
    common::crypto::hex_encode(hash)
}

pub fn parse_hash_hex(value: &str) -> Result<Hash, String> {
    let bytes = common::crypto::hex_decode(value)?;
    if bytes.len() != 32 {
        return Err(format!("expected 32-byte hash, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
