pub use sp1_programs_common::smt::{
    common_prefix_len, compute_sparse_root, default_hashes, empty_leaf_hash,
    insert_transition_commitment, internal_hash, key_bit, leaf_hash, prefix_index,
    update_transition_commitment, valid_depth, Hash, MAX_SMT_DEPTH,
};

pub fn key_hash(normalized_address: &str) -> Hash {
    sp1_programs_common::smt::key_hash(normalized_address)
        .expect("normalized Ethereum address must be valid")
}
