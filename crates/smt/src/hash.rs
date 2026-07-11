use slop_algebra::{AbstractField, PrimeField32};
use sp1_primitives::{poseidon2_hash, SP1Field};

pub type Hash = [u8; 32];

const LEAF_TAG: u32 = 1;
const NODE_TAG: u32 = 2;
const EMPTY_TAG: u32 = 3;
const KEY_TAG: u32 = 4;

pub fn key_hash(normalized_address: &str) -> Hash {
    let raw = normalized_address
        .strip_prefix("0x")
        .unwrap_or(normalized_address);
    let mut bytes = [0u8; 20];
    for (index, chunk) in raw.as_bytes().chunks(2).enumerate() {
        bytes[index] = (from_hex_nibble(chunk[0]) << 4) | from_hex_nibble(chunk[1]);
    }

    let mut words = Vec::with_capacity(1 + 5);
    words.push(SP1Field::from_wrapped_u32(KEY_TAG));
    for chunk in bytes.chunks(4) {
        let mut word = [0u8; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        words.push(SP1Field::from_wrapped_u32(u32::from_be_bytes(word)));
    }
    poseidon_digest(words)
}

pub fn leaf_hash(key: &Hash, balance: i128, salt: &Hash) -> Hash {
    let mut inputs = Vec::with_capacity(1 + 8 + 4 + 8);
    inputs.push(SP1Field::from_wrapped_u32(LEAF_TAG));
    inputs.extend(bytes_to_fields(key));
    inputs.extend(i128_to_fields(balance));
    inputs.extend(bytes_to_fields(salt));
    poseidon_digest(inputs)
}

pub fn internal_hash(depth: usize, left: &Hash, right: &Hash) -> Hash {
    let mut inputs = Vec::with_capacity(1 + 1 + 8 + 8);
    inputs.push(SP1Field::from_wrapped_u32(NODE_TAG));
    inputs.push(SP1Field::from_wrapped_u32(depth as u32));
    inputs.extend(bytes_to_fields(left));
    inputs.extend(bytes_to_fields(right));
    poseidon_digest(inputs)
}

pub fn empty_leaf_hash() -> Hash {
    poseidon_digest(vec![SP1Field::from_wrapped_u32(EMPTY_TAG)])
}

pub fn default_hashes(depth: usize) -> Vec<Hash> {
    let mut values = Vec::with_capacity(depth + 1);
    values.push(empty_leaf_hash());
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

fn bytes_to_fields(bytes: &[u8; 32]) -> Vec<SP1Field> {
    bytes
        .chunks(4)
        .map(|chunk| {
            let mut word = [0u8; 4];
            word.copy_from_slice(chunk);
            SP1Field::from_wrapped_u32(u32::from_be_bytes(word))
        })
        .collect()
}

fn i128_to_fields(value: i128) -> Vec<SP1Field> {
    value
        .to_be_bytes()
        .chunks(4)
        .map(|chunk| {
            let mut word = [0u8; 4];
            word.copy_from_slice(chunk);
            SP1Field::from_wrapped_u32(u32::from_be_bytes(word))
        })
        .collect()
}

fn fields_to_bytes(fields: &[SP1Field; 8]) -> Hash {
    let mut out = [0u8; 32];
    for (index, field) in fields.iter().enumerate() {
        out[index * 4..(index + 1) * 4].copy_from_slice(&field.as_canonical_u32().to_be_bytes());
    }
    out
}

fn from_hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex nibble"),
    }
}
