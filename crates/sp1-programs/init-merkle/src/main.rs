#![no_main]

extern crate alloc;

use num::BigUint;
use sp1_curves::params::FieldParameters;
use sp1_curves::weierstrass::bls12_381::{Bls12381, Bls12381BaseField};
use sp1_curves::AffinePoint;
use sp1_programs_common::bls12_381_scalar::{
    from_le_bytes as scalar_from_le_bytes, mul_mod, sub_mod, to_le_bytes as scalar_to_le_bytes,
    Scalar,
};
use sp1_programs_common::io::{
    init_reserve_commitment, init_shape_commitment, Hash, Sp1ChainBalanceProof, Sp1G1Affine,
    Sp1InitPublicValues, Sp1InitReserveEntry, Sp1InitStdin,
};
use sp1_zkvm::entrypoint;

entrypoint!(main);

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
            &reserve.chain_balance_proof,
            Sp1ChainBalanceProof::MockBinding { .. }
        )
    });

    Sp1InitPublicValues {
        chain_id: input.chain_id,
        state_root: input.state_root,
        session_id: input.session_id,
        reserve_count: input.reserve_count,
        reserve_commitment: init_reserve_commitment(
            input.reserves.len(),
            input
                .reserves
                .iter()
                .map(|reserve| (reserve.address.as_str(), reserve.balance)),
        ),
        zeta_le: input.zeta_le,
        balance_commitment: input.balance_commitment,
        shape_commitment: input.shape_commitment,
        eval_commitment: input.eval_commitment,
        commitment_params_digest_hex: input.commitment_params_digest_hex,
        uses_mock_inputs,
    }
}

fn verify_private_commitment_openings(input: &Sp1InitStdin) {
    let expected_params_digest = commitment_params_digest(
        &input.balance_value_base,
        &input.balance_blind_base,
        &input.eval_value_base,
        &input.eval_blind_base,
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

    assert_eq!(
        init_shape_commitment(
            &input.shape_salt,
            &input.alpha_le,
            input.reserves.len(),
            input
                .reserves
                .iter()
                .map(|reserve| reserve.encoded_address_le),
        ),
        input.shape_commitment,
        "initial salted shape commitment mismatch"
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
) -> alloc::string::String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"dynamic-poa-init-commitment-params-v2-salted-shape-hash");
    for point in [balance_value, balance_blind, eval_value, eval_blind] {
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
            panic!("Verkle proofs are disabled in the Merkle initialization guest")
        }
        Sp1ChainBalanceProof::EthereumVerkleProof { .. } => {
            panic!("Verkle proofs are disabled in the Merkle initialization guest")
        }
        Sp1ChainBalanceProof::UnsupportedGeneric { .. } => {
            panic!("unsupported generic chain proof verifier")
        }
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
        _ => panic!("invalid state-root hex"),
    }
}

fn cmp_limbs(left: &Scalar, right: &Scalar) -> i8 {
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
