use common::encoding::normalize_address;

use crate::hash::{key_hash, Hash};

pub fn key_for_address(address: &str) -> Result<Hash, String> {
    let normalized = normalize_address(address)?;
    Ok(key_hash(&normalized))
}

pub fn key_bit(key: &Hash, depth: usize) -> bool {
    let byte = key[depth / 8];
    let offset = 7 - (depth % 8);
    ((byte >> offset) & 1) == 1
}

pub fn common_prefix_len(a: &Hash, b: &Hash, max_depth: usize) -> usize {
    for depth in 0..max_depth {
        if key_bit(a, depth) != key_bit(b, depth) {
            return depth;
        }
    }
    max_depth
}
