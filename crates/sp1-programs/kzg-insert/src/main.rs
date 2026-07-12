#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use num::BigUint;
use sha3::{Digest, Keccak256};
use sp1_curves::params::FieldParameters;
use sp1_curves::weierstrass::bls12_381::{Bls12381, Bls12381BaseField};
use sp1_curves::AffinePoint;
use sp1_programs_common::io::{
    Hash, Sp1ChainBalanceProof, Sp1G1Affine, Sp1KzgInsertPublicValues, Sp1KzgInsertStdin,
    Sp1OwnershipWitness,
};
use sp1_zkvm::entrypoint;

entrypoint!(main);

fn main() {
    let input: Sp1KzgInsertStdin = sp1_zkvm::io::read();
    let public = verify_insert(input);
    sp1_zkvm::io::commit(&public);
}

fn verify_insert(input: Sp1KzgInsertStdin) -> Sp1KzgInsertPublicValues {
    assert!(input.balance >= 0, "negative inserted balance");
    assert_eq!(
        input.reserve_count_after,
        input.reserve_count_before + 1,
        "insert reserve count mismatch"
    );
    verify_ownership(&input.chain_id, &input.address, &input.ownership);
    verify_chain_balance(
        &input.chain_id,
        &input.state_root,
        &input.address,
        input.balance,
        &input.chain_balance_proof,
    );

    let encoded = encode_address(&input.address);
    assert_eq!(
        scalar_bytes(&encoded),
        input.encoded_address_le,
        "inserted address encoding mismatch"
    );
    let balance_scalar = BigUint::from(input.balance as u128);
    let c_x = commit_two(
        &input.eval_value_base,
        &encoded,
        &input.eval_blind_base,
        &BigUint::from_bytes_le(&input.encoded_address_blind_le),
    );
    let c_balance_delta = commit_two(
        &input.balance_value_base,
        &balance_scalar,
        &input.balance_blind_base,
        &BigUint::from_bytes_le(&input.balance_blind_delta_le),
    );
    assert_eq!(point_to_io(&c_x), input.c_x, "C_x opening mismatch");
    assert_eq!(
        point_to_io(&c_balance_delta),
        input.c_balance_delta,
        "balance-delta commitment opening mismatch"
    );

    Sp1KzgInsertPublicValues {
        chain_id: input.chain_id,
        state_root: input.state_root,
        c_x: input.c_x,
        c_balance_delta: input.c_balance_delta,
        old_accumulator_hex: input.old_accumulator_hex,
        new_accumulator_hex: input.new_accumulator_hex,
        old_balance_commitment_hex: input.old_balance_commitment_hex,
        new_balance_commitment_hex: input.new_balance_commitment_hex,
        reserve_count_before: input.reserve_count_before,
        reserve_count_after: input.reserve_count_after,
        transcript_hex: input.transcript_hex,
    }
}

fn commit_two(
    left_base: &Sp1G1Affine,
    left_scalar: &BigUint,
    right_base: &Sp1G1Affine,
    right_scalar: &BigUint,
) -> AffinePoint<Bls12381> {
    let left_base = point_from_io(left_base);
    let right_base = point_from_io(right_base);
    assert_on_curve(&left_base);
    assert_on_curve(&right_base);
    let left = (!is_zero(left_scalar)).then(|| left_base.scalar_mul(left_scalar));
    let right = (!is_zero(right_scalar)).then(|| right_base.scalar_mul(right_scalar));
    match (left, right) {
        (Some(left), Some(right)) => &left + &right,
        (Some(left), None) => left,
        (None, Some(right)) => right,
        (None, None) => panic!("commitment cannot be the identity"),
    }
}

fn point_from_io(value: &Sp1G1Affine) -> AffinePoint<Bls12381> {
    assert!(
        value.x_be.len() <= 48 && value.y_be.len() <= 48,
        "invalid G1 coordinate length"
    );
    AffinePoint::new(
        BigUint::from_bytes_be(&value.x_be),
        BigUint::from_bytes_be(&value.y_be),
    )
}

fn point_to_io(value: &AffinePoint<Bls12381>) -> Sp1G1Affine {
    Sp1G1Affine {
        x_be: fixed_be(&value.x, 48),
        y_be: fixed_be(&value.y, 48),
    }
}

fn assert_on_curve(point: &AffinePoint<Bls12381>) {
    let modulus = Bls12381BaseField::modulus();
    assert!(
        point.x < modulus && point.y < modulus,
        "G1 coordinate out of range"
    );
    let lhs = (&point.y * &point.y) % &modulus;
    let rhs = ((&point.x * &point.x % &modulus) * &point.x + BigUint::from(4u32)) % &modulus;
    assert_eq!(lhs, rhs, "point is not on BLS12-381 G1");
}

fn fixed_be(value: &BigUint, len: usize) -> Vec<u8> {
    let raw = value.to_bytes_be();
    assert!(raw.len() <= len, "integer does not fit fixed encoding");
    let mut out = vec![0u8; len];
    out[len - raw.len()..].copy_from_slice(&raw);
    out
}

fn scalar_bytes(value: &BigUint) -> [u8; 32] {
    let raw = value.to_bytes_le();
    assert!(raw.len() <= 32, "scalar too large");
    let mut out = [0u8; 32];
    out[..raw.len()].copy_from_slice(&raw);
    out
}

fn is_zero(value: &BigUint) -> bool {
    value.to_bytes_le().iter().all(|byte| *byte == 0)
}

fn encode_address(address: &str) -> BigUint {
    let raw = address.strip_prefix("0x").unwrap_or(address);
    assert_eq!(raw.len(), 40, "address must contain 20 bytes");
    let mut bytes = [0u8; 20];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = (hex_nibble(raw.as_bytes()[index * 2]) << 4)
            | hex_nibble(raw.as_bytes()[index * 2 + 1]);
    }
    BigUint::from_bytes_be(&bytes)
}

fn verify_ownership(chain_id: &str, address: &str, proof: &Sp1OwnershipWitness) {
    match proof {
        Sp1OwnershipWitness::MockPrivateKey { private_key } => {
            assert_eq!(
                chain_id, "mock-chain",
                "mock ownership used outside mock chain"
            );
            assert_eq!(private_key, &alloc::format!("mock-private-key:{address}"));
        }
        Sp1OwnershipWitness::EthereumEoaPrivateKey { private_key } => {
            assert_ethereum_eoa(address, private_key);
        }
        Sp1OwnershipWitness::UnsupportedExternal { .. } => {
            panic!("unsupported external ownership verifier")
        }
    }
}

fn assert_ethereum_eoa(address: &str, private_key: &[u8; 32]) {
    let secret = k256::SecretKey::from_slice(private_key).expect("invalid secp256k1 private key");
    let public = secret.public_key();
    let encoded = public.to_encoded_point(false);
    let encoded = encoded.as_bytes();
    assert_eq!(encoded[0], 4, "expected uncompressed secp256k1 key");
    let digest = Keccak256::digest(&encoded[1..]);
    let expected = decode_address_bytes(address);
    assert_eq!(&digest[12..], &expected, "private key does not own address");
}

fn decode_address_bytes(address: &str) -> [u8; 20] {
    let raw = address.strip_prefix("0x").unwrap_or(address);
    assert_eq!(raw.len(), 40, "address must contain 20 bytes");
    let mut out = [0u8; 20];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = (hex_nibble(raw.as_bytes()[index * 2]) << 4)
            | hex_nibble(raw.as_bytes()[index * 2 + 1]);
    }
    out
}

fn verify_chain_balance(
    chain_id: &str,
    state_root: &str,
    address: &str,
    balance: i128,
    proof: &Sp1ChainBalanceProof,
) {
    match proof {
        Sp1ChainBalanceProof::MockBinding { proof_label } => {
            assert_eq!(
                chain_id, "mock-chain",
                "mock state proof used outside mock chain"
            );
            assert_eq!(proof_label, &alloc::format!("mock-balance-proof:{address}"));
        }
        Sp1ChainBalanceProof::BinaryMerkleV1 {
            leaf_index,
            siblings,
        } => {
            let mut current = chain_leaf_hash(address, balance);
            let mut index = *leaf_index;
            for (level, sibling) in siblings.iter().enumerate() {
                current = if index & 1 == 0 {
                    chain_node_hash(level, &current, sibling)
                } else {
                    chain_node_hash(level, sibling, &current)
                };
                index >>= 1;
            }
            assert_eq!(index, 0, "Merkle leaf index exceeds proof depth");
            assert_eq!(
                current,
                decode_hash(state_root),
                "native chain Merkle proof mismatch"
            );
        }
        Sp1ChainBalanceProof::EthereumAccountProof { nodes } => {
            let root = decode_hash(state_root);
            let address = decode_address_bytes(address);
            sp1_programs_common::ethereum_mpt::verify_account_balance(
                &root, &address, balance, nodes,
            )
            .expect("invalid Ethereum account proof");
        }
        Sp1ChainBalanceProof::UnsupportedGeneric { .. } => panic!("unsupported chain proof"),
    }
}

fn chain_leaf_hash(address: &str, balance: i128) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"dpoa-chain-leaf-v1");
    hasher.update(&(address.len() as u64).to_le_bytes());
    hasher.update(address.as_bytes());
    hasher.update(&balance.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn chain_node_hash(level: usize, left: &Hash, right: &Hash) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"dpoa-chain-node-v1");
    hasher.update(&(level as u64).to_le_bytes());
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

fn decode_hash(value: &str) -> Hash {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    assert_eq!(raw.len(), 64, "state root must contain 32 bytes");
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = (hex_nibble(raw.as_bytes()[index * 2]) << 4)
            | hex_nibble(raw.as_bytes()[index * 2 + 1]);
    }
    out
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hex"),
    }
}
