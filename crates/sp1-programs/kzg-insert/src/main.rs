#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use banderwagon::trait_defs::CanonicalSerialize;
use num::BigUint;
use sp1_curves::params::FieldParameters;
use sp1_curves::weierstrass::bls12_381::{Bls12381, Bls12381BaseField};
use sp1_curves::AffinePoint;
use sp1_programs_common::bls12_381_scalar::{
    add_mod, from_le_bytes, mul_by_montgomery, to_le_bytes, to_montgomery,
};
use sp1_programs_common::io::{
    insert_quotient_commitment, Hash, Sp1ChainBalanceProof, Sp1G1Affine, Sp1KzgInsertPublicValues,
    Sp1KzgInsertStdin, Sp1OwnershipWitness,
};
use sp1_zkvm::entrypoint;
use verkle_trie::{proof::VerkleProof, Element};

entrypoint!(main);

fn main() {
    let input: Sp1KzgInsertStdin = sp1_zkvm::io::read();
    let public = verify_insert(input);
    sp1_zkvm::io::commit(&public);
}

fn verify_insert(input: Sp1KzgInsertStdin) -> Sp1KzgInsertPublicValues {
    assert!(input.balance >= 0, "negative inserted balance");
    let expected_reserve_count_after = input
        .reserve_count_before
        .checked_add(1)
        .expect("insert reserve count overflow");
    assert_eq!(
        input.reserve_count_after, expected_reserve_count_after,
        "insert reserve count mismatch"
    );
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
    verify_ownership(
        &input.chain_id,
        ownership_context.as_ref(),
        &input.address,
        &input.ownership,
    );
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
        input.quotient_coefficients_le.len(),
        input.reserve_count_before,
        "insert quotient must have exactly n coefficients"
    );
    assert_eq!(
        insert_quotient_commitment(
            &input.quotient_salt,
            input.quotient_coefficients_le.len(),
            input.quotient_coefficients_le.iter().copied(),
        ),
        input.quotient_commitment,
        "insert salted quotient commitment mismatch"
    );
    let zeta = from_le_bytes(input.zeta_le);
    let zeta_montgomery = to_montgomery(zeta);
    let quotient_eval =
        input
            .quotient_coefficients_le
            .iter()
            .rev()
            .fold([0u64; 4], |acc, coefficient| {
                add_mod(
                    mul_by_montgomery(acc, zeta_montgomery),
                    from_le_bytes(*coefficient),
                )
            });
    assert_eq!(
        to_le_bytes(quotient_eval),
        input.quotient_eval_le,
        "insert quotient evaluation mismatch"
    );
    let c_quotient_eval = commit_two(
        &input.eval_value_base,
        &BigUint::from_bytes_le(&input.quotient_eval_le),
        &input.eval_blind_base,
        &BigUint::from_bytes_le(&input.quotient_eval_blind_le),
    );
    assert_eq!(
        point_to_io(&c_quotient_eval),
        input.c_quotient_eval,
        "insert quotient evaluation commitment opening mismatch"
    );
    assert_eq!(
        point_to_io(&c_balance_delta),
        input.c_balance_delta,
        "balance-delta commitment opening mismatch"
    );

    let uses_mock_inputs = matches!(input.ownership, Sp1OwnershipWitness::MockPrivateKey { .. })
        || matches!(
            input.chain_balance_proof,
            Sp1ChainBalanceProof::MockBinding { .. }
        );

    Sp1KzgInsertPublicValues {
        chain_id: input.chain_id,
        state_root: input.state_root,
        zeta_le: input.zeta_le,
        commitment_params_digest_hex: commitment_params_digest(
            &input.eval_value_base,
            &input.eval_blind_base,
            &input.balance_value_base,
            &input.balance_blind_base,
        ),
        uses_mock_inputs,
        c_x: input.c_x,
        quotient_commitment: input.quotient_commitment,
        c_quotient_eval: input.c_quotient_eval,
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
    let left = (!is_zero(left_scalar)).then(|| scalar_mul_safe(&left_base, left_scalar));
    let right = (!is_zero(right_scalar)).then(|| scalar_mul_safe(&right_base, right_scalar));
    match (left, right) {
        (Some(left), Some(right)) => add_safe(&left, &right),
        (Some(left), None) => left,
        (None, Some(right)) => right,
        (None, None) => panic!("commitment cannot be the identity"),
    }
}

fn scalar_mul_safe(base: &AffinePoint<Bls12381>, scalar: &BigUint) -> AffinePoint<Bls12381> {
    let mut result = None;
    let mut power = base.clone();
    for byte in scalar.to_bytes_le() {
        for bit in 0..8 {
            if byte & (1 << bit) != 0 {
                result = Some(match result {
                    Some(current) => add_safe(&current, &power),
                    None => power.clone(),
                });
            }
            power = power.sw_double();
        }
    }
    result.expect("non-zero commitment scalar")
}

fn add_safe(left: &AffinePoint<Bls12381>, right: &AffinePoint<Bls12381>) -> AffinePoint<Bls12381> {
    if left == right {
        left.sw_double()
    } else {
        assert!(left.x != right.x, "commitment addition produced identity");
        left + right
    }
}

fn commitment_params_digest(
    eval_value: &Sp1G1Affine,
    eval_blind: &Sp1G1Affine,
    balance_value: &Sp1G1Affine,
    balance_blind: &Sp1G1Affine,
) -> alloc::string::String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"dynamic-poa-insert-commitment-params-v1");
    for point in [eval_value, eval_blind, balance_value, balance_blind] {
        hasher.update(&point.x_be);
        hasher.update(&point.y_be);
    }
    hex_hash(hasher.finalize().as_bytes())
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
        Sp1ChainBalanceProof::EthereumVerkleBatchMember { .. } => {
            panic!("insert requires a self-contained Verkle proof")
        }
        Sp1ChainBalanceProof::EthereumVerkleProof {
            tree_key,
            basic_data,
            proof,
        } => verify_ethereum_verkle_opening(
            state_root, address, balance, tree_key, basic_data, proof,
        ),
        Sp1ChainBalanceProof::UnsupportedGeneric { .. } => panic!("unsupported chain proof"),
    }
}

fn verify_ethereum_verkle_opening(
    state_root: &str,
    address: &str,
    balance: i128,
    tree_key: &Hash,
    basic_data: &Hash,
    proof_bytes: &[u8],
) {
    assert!(balance >= 0, "negative EIP-6800 balance");
    let address_bytes = decode_address_bytes(address);
    assert_eq!(
        *tree_key,
        eip6800_basic_data_key(&address_bytes),
        "EIP-6800 account tree key mismatch"
    );
    assert_eq!(basic_data[0], 0, "unsupported EIP-6800 account version");
    assert_eq!(
        &basic_data[1..16],
        &[0u8; 15],
        "benchmark EOA metadata must be zero"
    );
    assert_eq!(
        &basic_data[16..32],
        &(balance as u128).to_be_bytes(),
        "EIP-6800 account balance mismatch"
    );

    let root_bytes = decode_hash(state_root);
    let root = Element::from_bytes(&root_bytes).expect("invalid Banderwagon root commitment");
    let proof = VerkleProof::read(proof_bytes).expect("invalid Verkle proof encoding");
    let (valid, _) = proof.check(vec![*tree_key], vec![Some(*basic_data)], root);
    assert!(valid, "Ethereum Verkle account proof mismatch");
}

fn eip6800_basic_data_key(address: &[u8; 20]) -> Hash {
    let mut input = [0u8; 64];
    input[12..32].copy_from_slice(address);
    let scalars = verkle_spec::chunk64(input).map(verkle_trie::Fr::from);
    let mut commitment = Element::zero();
    for (base, scalar) in verkle_trie::constants::CRS.G.iter().take(5).zip(scalars) {
        commitment = commitment + (*base * scalar);
    }
    let hash = commitment.map_to_scalar_field();
    let mut key = [0u8; 32];
    hash.serialize_compressed(&mut key[..])
        .expect("serialize EIP-6800 Pedersen hash");
    key[31] = 0;
    key
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
