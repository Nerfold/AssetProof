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
    Hash, Sp1ChainBalanceProof, Sp1G1Affine, Sp1InitPublicValues, Sp1InitReserveEntry,
    Sp1InitStdin, Sp1OwnershipWitness,
};
use sp1_zkvm::entrypoint;
use verkle_spec::Hasher as VerkleKeyHasher;
use verkle_trie::{proof::VerkleProof, Element};

entrypoint!(main);

const BLS12_381_FR_MODULUS_LE: [u64; 4] = [
    0xffffffff00000001,
    0x53bda402fffe5bfe,
    0x3339d80809a1d805,
    0x73eda753299d7d48,
];

fn main() {
    let input: Sp1InitStdin = sp1_zkvm::io::read();
    let pv = verify_init(input);
    sp1_zkvm::io::commit(&pv);
}

fn verify_init(input: Sp1InitStdin) -> Sp1InitPublicValues {
    assert_eq!(
        input.reserve_count,
        input.reserves.len(),
        "reserve count mismatch"
    );
    assert!(!input.reserves.is_empty(), "empty reserve set");
    verify_ethereum_verkle_batch(&input);

    let mut balance_total = 0i128;
    let mut product = scalar_from_le_bytes(input.alpha_le);
    assert!(
        product.iter().any(|limb| *limb != 0),
        "alpha must be non-zero"
    );
    let zeta = scalar_from_le_bytes(input.zeta_le);
    let claimed_product = scalar_from_le_bytes(input.product_zeta_le);
    let mut previous_x = None;
    for reserve in &input.reserves {
        assert!(reserve.balance >= 0, "negative reserve balance");
        verify_ownership(&input.chain_id, reserve);
        verify_chain_balance(&input.chain_id, &input.state_root, reserve);
        let x = scalar_from_le_bytes(reserve.encoded_address_le);
        assert_eq!(
            reserve.encoded_address_le,
            encode_address(&reserve.address),
            "reserve address encoding mismatch"
        );
        if let Some(previous) = previous_x {
            assert!(
                cmp_limbs(&previous, &x) < 0,
                "reserve addresses are not canonical and duplicate-free"
            );
        }
        previous_x = Some(x);
        product = mul_mod(product, sub_mod(zeta, x));
        balance_total = balance_total
            .checked_add(reserve.balance)
            .expect("balance total overflow");
    }
    assert_eq!(balance_total, input.balance_total, "balance total mismatch");
    assert_eq!(
        scalar_to_le_bytes(product),
        scalar_to_le_bytes(claimed_product),
        "product identity mismatch"
    );
    assert_eq!(
        input.p_zeta_le, input.product_zeta_le,
        "p(zeta) and product(zeta) mismatch"
    );
    verify_private_commitment_openings(&input);

    let uses_mock_inputs = input.reserves.iter().any(|reserve| {
        matches!(
            &reserve.ownership,
            Sp1OwnershipWitness::MockPrivateKey { .. }
        ) || matches!(
            &reserve.chain_balance_proof,
            Sp1ChainBalanceProof::MockBinding { .. }
        )
    });

    Sp1InitPublicValues {
        chain_id: input.chain_id,
        state_root: input.state_root,
        session_id: input.session_id,
        reserve_count: input.reserve_count,
        zeta_le: input.zeta_le,
        balance_commitment: input.balance_commitment,
        shape_commitment: input.shape_commitment,
        eval_commitment: input.eval_commitment,
        commitment_params_digest_hex: input.commitment_params_digest_hex,
        uses_mock_inputs,
    }
}

fn verify_private_commitment_openings(input: &Sp1InitStdin) {
    let expected_shape_base_count = input
        .reserves
        .len()
        .checked_add(1)
        .expect("shape commitment base count overflow");
    assert_eq!(
        input.shape_value_bases.len(),
        expected_shape_base_count,
        "shape commitment base count mismatch"
    );
    let expected_params_digest = commitment_params_digest(
        &input.balance_value_base,
        &input.balance_blind_base,
        &input.eval_value_base,
        &input.eval_blind_base,
        &input.shape_value_bases,
        &input.shape_blind_base,
    );
    assert_eq!(
        expected_params_digest, input.commitment_params_digest_hex,
        "initialization commitment parameters mismatch"
    );

    let balance = commit_many(
        &[input.balance_value_base.clone()],
        &[BigUint::from(input.balance_total as u128)],
        &input.balance_blind_base,
        &BigUint::from_bytes_le(&input.balance_blind_le),
    );
    assert_eq!(
        point_to_io(&balance),
        input.balance_commitment,
        "initial balance commitment opening mismatch"
    );

    let mut shape_values = Vec::with_capacity(input.reserves.len() + 1);
    shape_values.push(BigUint::from_bytes_le(&input.alpha_le));
    shape_values.extend(
        input
            .reserves
            .iter()
            .map(|reserve| BigUint::from_bytes_le(&reserve.encoded_address_le)),
    );
    let shape = commit_many(
        &input.shape_value_bases,
        &shape_values,
        &input.shape_blind_base,
        &BigUint::from_bytes_le(&input.shape_blind_le),
    );
    assert_eq!(
        point_to_io(&shape),
        input.shape_commitment,
        "initial shape commitment opening mismatch"
    );

    let evaluation = commit_many(
        &[input.eval_value_base.clone()],
        &[BigUint::from_bytes_le(&input.p_zeta_le)],
        &input.eval_blind_base,
        &BigUint::from_bytes_le(&input.eval_blind_le),
    );
    assert_eq!(
        point_to_io(&evaluation),
        input.eval_commitment,
        "initial evaluation commitment opening mismatch"
    );
}

fn commit_many(
    bases: &[Sp1G1Affine],
    scalars: &[BigUint],
    blind_base: &Sp1G1Affine,
    blind: &BigUint,
) -> AffinePoint<Bls12381> {
    assert_eq!(bases.len(), scalars.len(), "commitment arity mismatch");
    let mut terms = bases
        .iter()
        .zip(scalars.iter())
        .filter(|(_, scalar)| !is_zero(scalar))
        .map(|(base, scalar)| {
            let base = point_from_io(base);
            assert_on_curve(&base);
            scalar_mul_safe(&base, scalar)
        })
        .collect::<Vec<_>>();
    if !is_zero(blind) {
        let base = point_from_io(blind_base);
        assert_on_curve(&base);
        terms.push(scalar_mul_safe(&base, blind));
    }
    let mut terms = terms.into_iter();
    let mut result = terms.next().expect("commitment cannot be identity");
    for term in terms {
        result = add_safe(&result, &term);
    }
    result
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

fn point_from_io(value: &Sp1G1Affine) -> AffinePoint<Bls12381> {
    assert!(value.x_be.len() <= 48 && value.y_be.len() <= 48);
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
    assert!(point.x < modulus && point.y < modulus);
    let lhs = (&point.y * &point.y) % &modulus;
    let rhs = ((&point.x * &point.x % &modulus) * &point.x + BigUint::from(4u32)) % &modulus;
    assert_eq!(lhs, rhs, "point is not on BLS12-381 G1");
}

fn fixed_be(value: &BigUint, len: usize) -> Vec<u8> {
    let raw = value.to_bytes_be();
    assert!(raw.len() <= len);
    let mut out = vec![0u8; len];
    out[len - raw.len()..].copy_from_slice(&raw);
    out
}

fn is_zero(value: &BigUint) -> bool {
    value.to_bytes_le().iter().all(|byte| *byte == 0)
}

fn commitment_params_digest(
    balance_value: &Sp1G1Affine,
    balance_blind: &Sp1G1Affine,
    eval_value: &Sp1G1Affine,
    eval_blind: &Sp1G1Affine,
    shape_values: &[Sp1G1Affine],
    shape_blind: &Sp1G1Affine,
) -> alloc::string::String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"dynamic-poa-init-commitment-params-v1");
    for point in [balance_value, balance_blind, eval_value, eval_blind] {
        hasher.update(&point.x_be);
        hasher.update(&point.y_be);
    }
    hasher.update(&(shape_values.len() as u64).to_le_bytes());
    for point in shape_values {
        hasher.update(&point.x_be);
        hasher.update(&point.y_be);
    }
    hasher.update(&shape_blind.x_be);
    hasher.update(&shape_blind.y_be);
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

fn encode_address(address: &str) -> [u8; 32] {
    let raw = address.strip_prefix("0x").unwrap_or(address);
    assert_eq!(raw.len(), 40, "address must contain 20 bytes");
    let mut out = [0u8; 32];
    for index in 0..20 {
        out[index] = (hex_nibble(raw.as_bytes()[index * 2]) << 4)
            | hex_nibble(raw.as_bytes()[index * 2 + 1]);
    }
    out[..20].reverse();
    out
}

fn verify_ownership(chain_id: &str, reserve: &Sp1InitReserveEntry) {
    match &reserve.ownership {
        Sp1OwnershipWitness::MockPrivateKey { private_key } => {
            assert_eq!(
                chain_id, "mock-chain",
                "mock ownership used outside mock chain"
            );
            assert_eq!(
                private_key,
                &alloc::format!("mock-private-key:{}", reserve.address),
                "mock private key does not bind the reserve address"
            );
        }
        Sp1OwnershipWitness::EthereumEoaPrivateKey { private_key } => {
            assert_ethereum_eoa(&reserve.address, private_key);
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
    let expected = decode_address(address);
    assert_eq!(&digest[12..], &expected, "private key does not own address");
}

fn decode_address(address: &str) -> [u8; 20] {
    let raw = address.strip_prefix("0x").unwrap_or(address);
    assert_eq!(raw.len(), 40, "address must contain 20 bytes");
    let mut out = [0u8; 20];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = (hex_nibble(raw.as_bytes()[index * 2]) << 4)
            | hex_nibble(raw.as_bytes()[index * 2 + 1]);
    }
    out
}

fn verify_chain_balance(chain_id: &str, state_root: &str, reserve: &Sp1InitReserveEntry) {
    match &reserve.chain_balance_proof {
        Sp1ChainBalanceProof::MockBinding { proof_label } => {
            assert_eq!(
                chain_id, "mock-chain",
                "mock state proof used outside mock chain"
            );
            assert_eq!(
                proof_label,
                &alloc::format!("mock-balance-proof:{}", reserve.address),
                "invalid mock balance proof"
            );
        }
        Sp1ChainBalanceProof::BinaryMerkleV1 {
            leaf_index,
            siblings,
        } => {
            let expected_root = decode_hash(state_root);
            let mut current = chain_leaf_hash(&reserve.address, reserve.balance);
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
            assert_eq!(current, expected_root, "native chain Merkle proof mismatch");
        }
        Sp1ChainBalanceProof::EthereumAccountProof { nodes } => {
            let root = decode_hash(state_root);
            let address = decode_address(&reserve.address);
            sp1_programs_common::ethereum_mpt::verify_account_balance(
                &root,
                &address,
                reserve.balance,
                nodes,
            )
            .expect("invalid Ethereum account proof");
        }
        Sp1ChainBalanceProof::EthereumVerkleBatchMember { .. } => {
            // All batch members are checked together before the reserve loop so
            // the IPA multiproof is verified exactly once.
        }
        Sp1ChainBalanceProof::EthereumVerkleProof {
            tree_key,
            basic_data,
            proof,
        } => verify_ethereum_verkle_opening(
            state_root,
            &reserve.address,
            reserve.balance,
            tree_key,
            basic_data,
            proof,
        ),
        Sp1ChainBalanceProof::UnsupportedGeneric { .. } => {
            panic!("unsupported generic chain proof verifier")
        }
    }
}

struct Eip6800PedersenHasher;

impl VerkleKeyHasher for Eip6800PedersenHasher {}

fn verify_ethereum_verkle_batch(input: &Sp1InitStdin) {
    let mut keys = Vec::new();
    let mut values = Vec::new();
    for reserve in &input.reserves {
        if let Sp1ChainBalanceProof::EthereumVerkleBatchMember {
            tree_key,
            basic_data,
        } = &reserve.chain_balance_proof
        {
            assert_eip6800_account_opening(&reserve.address, reserve.balance, tree_key, basic_data);
            keys.push(*tree_key);
            values.push(Some(*basic_data));
        }
    }

    match (&input.ethereum_verkle_batch_proof, keys.is_empty()) {
        (None, true) => return,
        (Some(_), true) => panic!("Verkle batch proof has no members"),
        (None, false) => panic!("Verkle batch members require a shared proof"),
        (Some(_), false) => {}
    }
    assert_eq!(
        keys.len(),
        input.reserves.len(),
        "initialization cannot mix Verkle batch members with other chain proofs"
    );

    let batch = input
        .ethereum_verkle_batch_proof
        .as_ref()
        .expect("checked above");
    let root_bytes = decode_hash(&input.state_root);
    let root = Element::from_bytes(&root_bytes).expect("invalid Banderwagon root commitment");
    let proof = VerkleProof::read(batch.proof.as_slice()).expect("invalid Verkle proof encoding");
    let (valid, _) = proof.check(keys, values, root);
    assert!(valid, "Ethereum Verkle batch proof mismatch");
}

fn verify_ethereum_verkle_opening(
    state_root: &str,
    address: &str,
    balance: i128,
    tree_key: &Hash,
    basic_data: &Hash,
    proof_bytes: &[u8],
) {
    assert_eip6800_account_opening(address, balance, tree_key, basic_data);
    let root_bytes = decode_hash(state_root);
    let root = Element::from_bytes(&root_bytes).expect("invalid Banderwagon root commitment");
    let proof = VerkleProof::read(proof_bytes).expect("invalid Verkle proof encoding");
    let (valid, _) = proof.check(vec![*tree_key], vec![Some(*basic_data)], root);
    assert!(valid, "Ethereum Verkle account proof mismatch");
}

fn assert_eip6800_account_opening(
    address: &str,
    balance: i128,
    tree_key: &Hash,
    basic_data: &Hash,
) {
    assert!(balance >= 0, "negative EIP-6800 balance");
    assert_eq!(
        *tree_key,
        eip6800_basic_data_key(&decode_address(address)),
        "EIP-6800 account tree key mismatch"
    );
    assert_eq!(basic_data[0], 0, "unsupported EIP-6800 account version");
    assert_eq!(
        &basic_data[1..5],
        &[0u8; 4],
        "non-zero EIP-6800 reserved account bytes"
    );
    assert_eq!(
        &basic_data[5..16],
        &[0u8; 11],
        "benchmark EOA must have zero code-size and nonce"
    );
    assert_eq!(
        &basic_data[16..32],
        &(balance as u128).to_be_bytes(),
        "EIP-6800 account balance mismatch"
    );
}

fn eip6800_basic_data_key(address: &[u8; 20]) -> Hash {
    let mut input = [0u8; 64];
    input[12..32].copy_from_slice(address);
    let hash = <Eip6800PedersenHasher as VerkleKeyHasher>::hash64(input);
    let mut key = *hash.as_fixed_bytes();
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
        _ => panic!("invalid state-root hex"),
    }
}

fn scalar_from_le_bytes(bytes: [u8; 32]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for index in 0..4 {
        let mut word = [0u8; 8];
        word.copy_from_slice(&bytes[index * 8..(index + 1) * 8]);
        out[index] = u64::from_le_bytes(word);
    }
    assert!(
        cmp_limbs(&out, &BLS12_381_FR_MODULUS_LE) < 0,
        "scalar out of range"
    );
    out
}

fn scalar_to_le_bytes(value: [u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for index in 0..4 {
        out[index * 8..(index + 1) * 8].copy_from_slice(&value[index].to_le_bytes());
    }
    out
}

fn sub_mod(left: [u64; 4], right: [u64; 4]) -> [u64; 4] {
    if cmp_limbs(&left, &right) >= 0 {
        sub_raw(left, right).0
    } else {
        let (tmp, _) = sub_raw(BLS12_381_FR_MODULUS_LE, right);
        add_mod(tmp, left)
    }
}

fn add_mod(left: [u64; 4], right: [u64; 4]) -> [u64; 4] {
    let (sum, carry) = add_raw(left, right);
    if carry || cmp_limbs(&sum, &BLS12_381_FR_MODULUS_LE) >= 0 {
        sub_raw(sum, BLS12_381_FR_MODULUS_LE).0
    } else {
        sum
    }
}

fn mul_mod(left: [u64; 4], right: [u64; 4]) -> [u64; 4] {
    let mut acc = [0u64; 4];
    let mut base = left;
    for limb in right {
        for bit in 0..64 {
            if ((limb >> bit) & 1) == 1 {
                acc = add_mod(acc, base);
            }
            base = add_mod(base, base);
        }
    }
    acc
}

fn add_raw(left: [u64; 4], right: [u64; 4]) -> ([u64; 4], bool) {
    let mut out = [0u64; 4];
    let mut carry = 0u128;
    for index in 0..4 {
        let value = left[index] as u128 + right[index] as u128 + carry;
        out[index] = value as u64;
        carry = value >> 64;
    }
    (out, carry != 0)
}

fn sub_raw(left: [u64; 4], right: [u64; 4]) -> ([u64; 4], bool) {
    let mut out = [0u64; 4];
    let mut borrow = 0u128;
    for index in 0..4 {
        let rhs = right[index] as u128 + borrow;
        if (left[index] as u128) >= rhs {
            out[index] = (left[index] as u128 - rhs) as u64;
            borrow = 0;
        } else {
            out[index] = ((1u128 << 64) + left[index] as u128 - rhs) as u64;
            borrow = 1;
        }
    }
    (out, borrow != 0)
}

fn cmp_limbs(left: &[u64; 4], right: &[u64; 4]) -> i8 {
    for index in (0..4).rev() {
        if left[index] < right[index] {
            return -1;
        }
        if left[index] > right[index] {
            return 1;
        }
    }
    0
}
