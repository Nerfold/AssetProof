#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use num::BigUint;
use sp1_curves::params::FieldParameters;
use sp1_curves::weierstrass::bls12_381::Bls12381BaseField;
use sp1_lib::bls12381::Bls12381Point;
use sp1_lib::utils::AffinePoint as Sp1AffinePoint;
use sp1_programs_common::ethereum_binary_merkle::{leaf_hash, node_hash};
use sp1_programs_common::io::{
    Hash, Sp1ChainBalanceProof, Sp1G1Affine, Sp1KzgInsertPublicValues, Sp1KzgInsertStdin,
    Sp1OwnershipWitness,
};
use sp1_zkvm::entrypoint;

entrypoint!(main);

macro_rules! cycle_start {
    ($enabled:expr, $name:literal) => {
        if $enabled {
            println!(concat!("cycle-tracker-report-start: ", $name));
        }
    };
}

macro_rules! cycle_end {
    ($enabled:expr, $name:literal) => {
        if $enabled {
            println!(concat!("cycle-tracker-report-end: ", $name));
        }
    };
}

fn main() {
    let profile: bool = sp1_zkvm::io::read();
    cycle_start!(profile, "input_decode");
    let input: Sp1KzgInsertStdin = sp1_zkvm::io::read();
    cycle_end!(profile, "input_decode");
    let public = verify_insert(input, profile);
    cycle_start!(profile, "public_values_commit");
    sp1_zkvm::io::commit(&public);
    cycle_end!(profile, "public_values_commit");
}

fn verify_insert(input: Sp1KzgInsertStdin, profile: bool) -> Sp1KzgInsertPublicValues {
    assert!(input.balance >= 0, "negative inserted balance");
    cycle_start!(profile, "ownership_context_hash");
    let ownership_context = matches!(
        &input.ownership,
        Sp1OwnershipWitness::EthereumEoaSignature { .. }
    )
    .then(|| {
        sp1_programs_common::ethereum_eoa::ownership_context_hash(
            sp1_programs_common::ethereum_eoa::OwnershipOperation::Insert,
            &input.chain_id,
            &input.state_root,
        )
    });
    cycle_end!(profile, "ownership_context_hash");
    cycle_start!(profile, "ownership_verify");
    verify_ownership(
        &input.chain_id,
        ownership_context.as_ref(),
        &input.address,
        &input.ownership,
    );
    cycle_end!(profile, "ownership_verify");
    cycle_start!(profile, "merkle_balance_verify");
    verify_chain_balance(
        &input.chain_id,
        &input.state_root,
        &input.address,
        input.balance,
        &input.chain_balance_proof,
    );
    cycle_end!(profile, "merkle_balance_verify");

    cycle_start!(profile, "address_and_balance_commitments");
    let encoded = encode_address(&input.address);
    assert_eq!(
        scalar_bytes(&encoded),
        input.encoded_address_le,
        "inserted address encoding mismatch"
    );
    let balance_scalar = BigUint::from(input.balance as u128);
    let c_u = commit_two(
        &input.eval_value_base,
        &encoded,
        &input.eval_blind_base,
        &BigUint::from_bytes_le(&input.encoded_address_blind_le),
    );
    let c_balance = commit_two(
        &input.balance_value_base,
        &balance_scalar,
        &input.balance_blind_base,
        &BigUint::from_bytes_le(&input.balance_blind_le),
    );
    assert_eq!(point_to_io(&c_u), input.c_u, "C_u opening mismatch");
    assert_eq!(
        point_to_io(&c_balance),
        input.c_balance,
        "C_B opening mismatch"
    );
    cycle_end!(profile, "address_and_balance_commitments");

    let uses_mock_inputs = matches!(input.ownership, Sp1OwnershipWitness::MockPrivateKey { .. })
        || matches!(
            input.chain_balance_proof,
            Sp1ChainBalanceProof::MockBinding { .. }
        );

    cycle_start!(profile, "public_values_build");
    let commitment_params_digest_hex = commitment_params_digest(
        &input.eval_value_base,
        &input.eval_blind_base,
        &input.balance_value_base,
        &input.balance_blind_base,
    );
    let public = Sp1KzgInsertPublicValues {
        chain_id: input.chain_id,
        state_root: input.state_root,
        commitment_params_digest_hex,
        uses_mock_inputs,
        c_u: input.c_u,
        c_balance: input.c_balance,
    };
    cycle_end!(profile, "public_values_build");
    public
}

fn commit_two(
    left_base: &Sp1G1Affine,
    left_scalar: &BigUint,
    right_base: &Sp1G1Affine,
    right_scalar: &BigUint,
) -> Bls12381Point {
    let left_base = point_from_io(left_base);
    let right_base = point_from_io(right_base);
    let left = (!is_zero(left_scalar)).then(|| scalar_mul_safe(&left_base, left_scalar));
    let right = (!is_zero(right_scalar)).then(|| scalar_mul_safe(&right_base, right_scalar));
    match (left, right) {
        (Some(mut left), Some(right)) => {
            left.complete_add_assign(&right);
            assert!(!left.is_identity(), "commitment addition produced identity");
            left
        }
        (Some(left), None) => left,
        (None, Some(right)) => right,
        (None, None) => panic!("commitment cannot be the identity"),
    }
}

fn scalar_mul_safe(base: &Bls12381Point, scalar: &BigUint) -> Bls12381Point {
    assert!(!is_zero(scalar), "zero commitment scalar");
    let digits = scalar.to_u64_digits();
    assert!(digits.len() <= 6, "BLS12-381 scalar is too large");
    let mut words = [0u64; 6];
    words[..digits.len()].copy_from_slice(&digits);
    let mut result = *base;
    result.mul_assign(&words);
    assert!(
        !result.is_identity(),
        "commitment scalar multiplication produced identity"
    );
    result
}

fn commitment_params_digest(
    eval_value: &Sp1G1Affine,
    eval_blind: &Sp1G1Affine,
    balance_value: &Sp1G1Affine,
    balance_blind: &Sp1G1Affine,
) -> alloc::string::String {
    let mut hasher = sp1_programs_common::ethereum_eoa::Keccak256Stream::new();
    hasher.update(b"dynamic-poa-hidden-insert-commitment-params-keccak-v1");
    for point in [eval_value, eval_blind, balance_value, balance_blind] {
        hasher.update(&point.x_be);
        hasher.update(&point.y_be);
    }
    hex_hash(&hasher.finalize())
}

fn hex_hash(bytes: &[u8]) -> alloc::string::String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = alloc::string::String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn point_from_io(value: &Sp1G1Affine) -> Bls12381Point {
    assert!(
        value.x_be.len() <= 48 && value.y_be.len() <= 48,
        "invalid G1 coordinate length"
    );
    let x = BigUint::from_bytes_be(&value.x_be);
    let y = BigUint::from_bytes_be(&value.y_be);
    assert_on_curve(&x, &y);
    let mut x_le = fixed_be(&x, 48);
    let mut y_le = fixed_be(&y, 48);
    x_le.reverse();
    y_le.reverse();
    <Bls12381Point as Sp1AffinePoint<12>>::from(&x_le, &y_le)
}

fn point_to_io(value: &Bls12381Point) -> Sp1G1Affine {
    assert!(!value.is_identity(), "cannot encode identity commitment");
    let limbs = value.limbs_ref();
    let mut x_be = limbs[..6]
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    let mut y_be = limbs[6..]
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    x_be.reverse();
    y_be.reverse();
    Sp1G1Affine { x_be, y_be }
}

fn assert_on_curve(x: &BigUint, y: &BigUint) {
    let modulus = Bls12381BaseField::modulus();
    assert!(x < &modulus && y < &modulus, "G1 coordinate out of range");
    let lhs = (y * y) % &modulus;
    let rhs = ((x * x % &modulus) * x + BigUint::from(4u32)) % &modulus;
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

fn verify_ownership(
    chain_id: &str,
    ownership_context: Option<&[u8; 32]>,
    address: &str,
    proof: &Sp1OwnershipWitness,
) {
    match proof {
        Sp1OwnershipWitness::MockPrivateKey { private_key } => {
            assert_eq!(
                chain_id, "mock-chain",
                "mock ownership used outside mock chain"
            );
            assert_eq!(private_key, &alloc::format!("mock-private-key:{address}"));
        }
        Sp1OwnershipWitness::EthereumEoaSignature { r, s, recovery_id } => {
            sp1_programs_common::ethereum_eoa::verify_ownership_signature_with_context(
                ownership_context.expect("missing Ethereum ownership context"),
                address,
                r,
                s,
                *recovery_id,
            );
        }
        Sp1OwnershipWitness::UnsupportedExternal { .. } => {
            panic!("unsupported external ownership verifier")
        }
    }
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
            let address_bytes = decode_address_bytes(address);
            let mut current = leaf_hash(&address_bytes, balance);
            let mut index = *leaf_index;
            for (level, sibling) in siblings.iter().enumerate() {
                current = if index & 1 == 0 {
                    node_hash(level, &current, sibling)
                } else {
                    node_hash(level, sibling, &current)
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
        Sp1ChainBalanceProof::EthereumVerkleBatchMember { .. } => {
            panic!("Verkle proofs are disabled in the Merkle insert guest")
        }
        Sp1ChainBalanceProof::EthereumVerkleProof { .. } => {
            panic!("Verkle proofs are disabled in the Merkle insert guest")
        }
        Sp1ChainBalanceProof::UnsupportedGeneric { .. } => panic!("unsupported chain proof"),
    }
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
