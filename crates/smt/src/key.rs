use common::encoding::normalize_address;

use crate::hash::{
    common_prefix_len as shared_common_prefix_len, key_bit as shared_key_bit, key_hash, Hash,
};

pub fn key_for_address(address: &str) -> Result<Hash, String> {
    let normalized = normalize_address(address)?;
    Ok(key_hash(&normalized))
}

pub fn key_bit(key: &Hash, depth: usize) -> bool {
    shared_key_bit(key, depth)
}

pub fn common_prefix_len(a: &Hash, b: &Hash, max_depth: usize) -> usize {
    shared_common_prefix_len(a, b, max_depth)
}
