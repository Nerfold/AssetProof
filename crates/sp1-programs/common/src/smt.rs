use alloc::{vec, vec::Vec};

use slop_algebra::{AbstractField, PrimeField32};
#[cfg(not(target_os = "zkvm"))]
use sp1_primitives::poseidon2_hash;
use sp1_primitives::SP1Field;

pub type Hash = [u8; 32];

pub const MAX_SMT_DEPTH: usize = 128;

const LEAF_TAG: u32 = 1;
const NODE_TAG: u32 = 2;
const EMPTY_TAG: u32 = 3;
const KEY_TAG: u32 = 4;
const UPDATE_TRANSITION_TAG: u32 = 5;
const INSERT_TRANSITION_TAG: u32 = 6;

pub fn key_hash(address: &str) -> Result<Hash, &'static str> {
    let raw = address.strip_prefix("0x").unwrap_or(address);
    if raw.len() != 40 {
        return Err("Ethereum address must contain exactly 40 hex characters");
    }

    let mut bytes = [0u8; 20];
    for (index, chunk) in raw.as_bytes().chunks_exact(2).enumerate() {
        let high = from_hex_nibble(chunk[0]).ok_or("invalid Ethereum address hex")?;
        let low = from_hex_nibble(chunk[1]).ok_or("invalid Ethereum address hex")?;
        bytes[index] = (high << 4) | low;
    }

    let mut words = Vec::with_capacity(6);
    words.push(SP1Field::from_wrapped_u32(KEY_TAG));
    for chunk in bytes.chunks_exact(4) {
        let word: [u8; 4] = chunk.try_into().expect("four-byte address word");
        words.push(SP1Field::from_wrapped_u32(u32::from_be_bytes(word)));
    }
    Ok(poseidon_digest(words))
}

pub fn leaf_hash(key: &Hash, balance: i128, salt: &Hash) -> Hash {
    let mut inputs = Vec::with_capacity(21);
    inputs.push(SP1Field::from_wrapped_u32(LEAF_TAG));
    push_hash_fields(&mut inputs, key);
    push_i128_fields(&mut inputs, balance);
    push_hash_fields(&mut inputs, salt);
    poseidon_digest(inputs)
}

pub fn internal_hash(depth: usize, left: &Hash, right: &Hash) -> Hash {
    let mut inputs = Vec::with_capacity(18);
    inputs.push(SP1Field::from_wrapped_u32(NODE_TAG));
    inputs.push(SP1Field::from_wrapped_u32(depth as u32));
    push_hash_fields(&mut inputs, left);
    push_hash_fields(&mut inputs, right);
    poseidon_digest(inputs)
}

pub fn empty_leaf_hash() -> Hash {
    poseidon_digest(vec![SP1Field::from_wrapped_u32(EMPTY_TAG)])
}

pub fn default_hashes(depth: usize) -> Vec<Hash> {
    assert!(valid_depth(depth), "SMT depth must be in 1..=128");
    let mut values = Vec::with_capacity(depth + 1);
    values.push(empty_leaf_hash());
    for height in 1..=depth {
        let child = values[height - 1];
        values.push(internal_hash(depth - height, &child, &child));
    }
    values
}

/// Hides the private touch list behind a salted Poseidon commitment. The old
/// and new state roots are committed separately as public values.
pub fn update_transition_commitment(salt: &Hash, entries: &[(Hash, i128)]) -> Hash {
    let mut inputs = Vec::with_capacity(10 + entries.len() * 12);
    inputs.push(SP1Field::from_wrapped_u32(UPDATE_TRANSITION_TAG));
    inputs.push(SP1Field::from_wrapped_u32(entries.len() as u32));
    push_hash_fields(&mut inputs, salt);
    for (key, delta) in entries {
        push_hash_fields(&mut inputs, key);
        push_i128_fields(&mut inputs, *delta);
    }
    poseidon_digest(inputs)
}

pub fn insert_transition_commitment(
    transition_salt: &Hash,
    key: &Hash,
    balance: i128,
    leaf_salt: &Hash,
) -> Hash {
    let mut inputs = Vec::with_capacity(30);
    inputs.push(SP1Field::from_wrapped_u32(INSERT_TRANSITION_TAG));
    push_hash_fields(&mut inputs, transition_salt);
    push_hash_fields(&mut inputs, key);
    push_i128_fields(&mut inputs, balance);
    push_hash_fields(&mut inputs, leaf_salt);
    poseidon_digest(inputs)
}

pub fn valid_depth(depth: usize) -> bool {
    (1..=MAX_SMT_DEPTH).contains(&depth)
}

pub fn key_bit(key: &Hash, depth: usize) -> bool {
    assert!(depth < 256, "SMT key bit exceeds digest width");
    let byte = key[depth / 8];
    let offset = 7 - (depth % 8);
    ((byte >> offset) & 1) == 1
}

pub fn prefix_index(key: &Hash, prefix_len: usize) -> u128 {
    assert!(prefix_len <= MAX_SMT_DEPTH, "SMT prefix exceeds u128");
    let mut index = 0u128;
    for depth in 0..prefix_len {
        index <<= 1;
        if key_bit(key, depth) {
            index |= 1;
        }
    }
    index
}

pub fn common_prefix_len(a: &Hash, b: &Hash, max_depth: usize) -> usize {
    assert!(max_depth <= 256, "SMT prefix exceeds digest width");
    for depth in 0..max_depth {
        if key_bit(a, depth) != key_bit(b, depth) {
            return depth;
        }
    }
    max_depth
}

/// Expands a proof that starts at an empty subtree into the full leaf-to-root
/// sibling path needed to insert a leaf at that position.
pub fn expand_default_membership_siblings(
    depth: usize,
    defaults: &[Hash],
    resolved_default_siblings: &[Hash],
    default_depth: usize,
) -> Vec<Hash> {
    assert!(default_depth <= depth, "default depth exceeds tree depth");
    assert_eq!(
        resolved_default_siblings.len(),
        default_depth,
        "default proof sibling length mismatch"
    );
    assert_eq!(defaults.len(), depth + 1, "default hash vector mismatch");

    let mut siblings = Vec::with_capacity(depth);
    let default_subtree_height = depth - default_depth;
    siblings.extend_from_slice(&defaults[..default_subtree_height]);
    siblings.extend_from_slice(resolved_default_siblings);
    siblings
}

pub fn compute_sparse_root(depth: usize, mut current: Vec<(u128, Hash)>) -> Hash {
    assert!(valid_depth(depth), "SMT depth must be in 1..=128");
    assert!(!current.is_empty(), "empty SMT leaf set");
    current.sort_unstable_by_key(|(index, _)| *index);
    for pair in current.windows(2) {
        assert_ne!(
            pair[0].0, pair[1].0,
            "SMT path collision at configured depth"
        );
    }

    let defaults = default_hashes(depth);
    for level_from_leaf in 0..depth {
        let mut next = Vec::with_capacity((current.len() + 1) / 2);
        let mut cursor = 0usize;
        while cursor < current.len() {
            let (index, hash) = current[cursor];
            let sibling_index = index ^ 1;
            let sibling = if cursor + 1 < current.len() && current[cursor + 1].0 == sibling_index {
                cursor += 1;
                current[cursor].1
            } else {
                defaults[level_from_leaf]
            };
            let node_depth = depth - level_from_leaf - 1;
            let parent = if index & 1 == 0 {
                internal_hash(node_depth, &hash, &sibling)
            } else {
                internal_hash(node_depth, &sibling, &hash)
            };
            next.push((index / 2, parent));
            cursor += 1;
        }
        current = next;
    }

    assert_eq!(
        current.len(),
        1,
        "SMT initialization did not produce one root"
    );
    current[0].1
}

fn poseidon_digest(inputs: Vec<SP1Field>) -> Hash {
    let digest = poseidon2_hash_accelerated(inputs);
    let mut out = [0u8; 32];
    for (index, field) in digest.iter().enumerate() {
        out[index * 4..(index + 1) * 4].copy_from_slice(&field.as_canonical_u32().to_be_bytes());
    }
    out
}

#[cfg(not(target_os = "zkvm"))]
fn poseidon2_hash_accelerated(inputs: Vec<SP1Field>) -> [SP1Field; 8] {
    poseidon2_hash(inputs)
}

/// Syscall-backed equivalent of SP1's `PaddingFreeSponge<_, 16, 8, 8>`.
///
/// The upstream padding-free sponge overwrites only the supplied rate words in
/// its final partial block and retains the remaining words from the previous
/// permutation. Preserve that exact behavior so host and zkVM roots remain
/// byte-for-byte identical while every permutation uses the Poseidon2
/// precompile.
#[cfg(target_os = "zkvm")]
fn poseidon2_hash_accelerated(inputs: Vec<SP1Field>) -> [SP1Field; 8] {
    use sp1_lib::poseidon2::{Poseidon2State, RATE};

    let mut state = Poseidon2State::default();
    for chunk in inputs.chunks(RATE) {
        let mut rate_words = [0u32; RATE];
        // `Poseidon2State` is repr(C), and SP1 intentionally exposes its
        // aligned state pointer for syscall integrations. Read the current rate
        // so a final partial chunk retains the untouched words exactly like
        // `PaddingFreeSponge`.
        unsafe {
            rate_words.copy_from_slice(core::slice::from_raw_parts(state.as_mut_ptr(), RATE));
        }
        for (slot, value) in rate_words.iter_mut().zip(chunk.iter()) {
            *slot = value.as_canonical_u32();
        }
        state.absorb_field_block_unchecked(&rate_words);
    }
    let mut output = [0u32; RATE];
    unsafe {
        output.copy_from_slice(core::slice::from_raw_parts(state.as_mut_ptr(), RATE));
    }
    output.map(SP1Field::from_wrapped_u32)
}

fn push_hash_fields(out: &mut Vec<SP1Field>, bytes: &Hash) {
    for chunk in bytes.chunks_exact(4) {
        let word: [u8; 4] = chunk.try_into().expect("four-byte hash word");
        out.push(SP1Field::from_wrapped_u32(u32::from_be_bytes(word)));
    }
}

fn push_i128_fields(out: &mut Vec<SP1Field>, value: i128) {
    for chunk in value.to_be_bytes().chunks_exact(4) {
        let word: [u8; 4] = chunk.try_into().expect("four-byte i128 word");
        out.push(SP1Field::from_wrapped_u32(u32::from_be_bytes(word)));
    }
}

fn from_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_insert_path_keeps_leaf_to_root_order() {
        let defaults = default_hashes(4);
        let upper = [[9u8; 32], [10u8; 32]];
        let expanded = expand_default_membership_siblings(4, &defaults, &upper, 2);
        assert_eq!(expanded, vec![defaults[0], defaults[1], upper[0], upper[1]]);
    }

    #[test]
    fn ethereum_address_hash_is_case_insensitive() {
        let lower = key_hash("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd").unwrap();
        let upper = key_hash("0xABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD").unwrap();
        assert_eq!(lower, upper);
    }
}
