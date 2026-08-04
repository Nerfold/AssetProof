use crate::ethereum_eoa::keccak256;
use alloc::vec::Vec;

pub type Hash = [u8; 32];

const LEAF_DOMAIN: &[u8] = b"DPOA_ETH_ACCOUNT_LEAF_V2";
const NODE_DOMAIN: &[u8] = b"DPOA_ETH_ACCOUNT_NODE_V2";
const EMPTY_DOMAIN: &[u8] = b"DPOA_ETH_ACCOUNT_EMPTY_V2";

pub fn leaf_hash(address: &[u8; 20], balance: i128) -> Hash {
    let mut input = [0u8; 64];
    input[..LEAF_DOMAIN.len()].copy_from_slice(LEAF_DOMAIN);
    input[28..48].copy_from_slice(address);
    input[48..].copy_from_slice(&balance.to_le_bytes());
    keccak256(&input)
}

pub fn node_hash(level: usize, left: &Hash, right: &Hash) -> Hash {
    let mut input = [0u8; 104];
    input[..NODE_DOMAIN.len()].copy_from_slice(NODE_DOMAIN);
    input[32..40].copy_from_slice(&(level as u64).to_le_bytes());
    input[40..72].copy_from_slice(left);
    input[72..].copy_from_slice(right);
    keccak256(&input)
}

pub fn empty_leaf_hash() -> Hash {
    let mut input = [0u8; 32];
    input[..EMPTY_DOMAIN.len()].copy_from_slice(EMPTY_DOMAIN);
    keccak256(&input)
}

/// Returns the canonical roots of completely empty subtrees. Entry `level`
/// commits to `2^level` empty leaves. Keeping these roots independent of the
/// leaf index lets a fixed-depth sparse tree represent a 2^32 capacity without
/// allocating that many leaves.
pub fn default_subtree_hashes(depth: usize) -> Vec<Hash> {
    let mut roots = Vec::with_capacity(depth + 1);
    roots.push(empty_leaf_hash());
    for level in 0..depth {
        roots.push(node_hash(level, &roots[level], &roots[level]));
    }
    roots
}
