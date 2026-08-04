#![no_main]

extern crate alloc;

use num::BigUint;
use sp1_curves::params::FieldParameters;
use sp1_curves::weierstrass::bls12_381::Bls12381BaseField;
use sp1_lib::bls12381::Bls12381Point;
use sp1_lib::utils::AffinePoint as Sp1AffinePoint;
use sp1_programs_common::bls12_381_scalar::{
    from_le_bytes as scalar_from_le_bytes, mul_mod, sub_mod, to_le_bytes as scalar_to_le_bytes,
    Scalar,
};
use sp1_programs_common::chain_balance::{decode_hash, verify_chain_balance, verify_merkle_prefix};
use sp1_programs_common::io::{
    init_shape_commitment, InitReserveCommitment, Sp1ChainBalanceProof, Sp1G1Affine,
    Sp1InitPublicValues, Sp1InitStdin, Sp1OwnershipWitness,
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
    let input: Sp1InitStdin = sp1_zkvm::io::read();
    cycle_end!(profile, "input_decode");
    let pv = verify_init(input, profile);
    cycle_start!(profile, "public_values_commit");
    sp1_zkvm::io::commit(&pv);
    cycle_end!(profile, "public_values_commit");
}

fn verify_init(input: Sp1InitStdin, profile: bool) -> Sp1InitPublicValues {
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
    let mut uses_mock_inputs = false;
    let expected_root = decode_hash(&input.state_root);
    cycle_start!(profile, "ownership_context_hash");
    let ownership_context = (input.chain_id != "mock-chain").then(|| {
        sp1_programs_common::ethereum_eoa::ownership_context_hash(
            sp1_programs_common::ethereum_eoa::OwnershipOperation::Initialization,
            &input.chain_id,
            &input.state_root,
        )
    });
    cycle_end!(profile, "ownership_context_hash");
    if let Some(prefix_proof) = input.merkle_prefix_proof.as_ref() {
        cycle_start!(profile, "merkle_prefix_verify");
        verify_merkle_prefix(&expected_root, &input.reserves, prefix_proof);
        cycle_end!(profile, "merkle_prefix_verify");
    }
    let mut reserve_commitment = InitReserveCommitment::new(input.reserves.len());
    cycle_start!(profile, "reserve_scan_product_ownership_and_commitment");
    for reserve in &input.reserves {
        assert!(reserve.balance >= 0, "negative reserve balance");
        uses_mock_inputs |= matches!(
            &reserve.chain_balance_proof,
            Sp1ChainBalanceProof::MockBinding { .. }
        );
        if input.merkle_prefix_proof.is_none() {
            verify_chain_balance(&input.chain_id, &expected_root, reserve);
        }
        let x = scalar_from_le_bytes(reserve.encoded_address_le);
        assert_eq!(
            reserve.encoded_address_le,
            encode_address(&reserve.address),
            "reserve address encoding mismatch"
        );
        let address_bytes = address_bytes_from_encoded(&reserve.encoded_address_le);
        if let Some(previous) = previous_x {
            assert!(
                cmp_limbs(&previous, &x) < 0,
                "reserve addresses are not canonical and duplicate-free"
            );
        }
        previous_x = Some(x);
        match &reserve.ownership {
            Sp1OwnershipWitness::MockPrivateKey { private_key } => {
                uses_mock_inputs = true;
                assert_eq!(
                    input.chain_id, "mock-chain",
                    "mock ownership used outside mock chain"
                );
                assert_eq!(
                    private_key,
                    &alloc::format!("mock-private-key:{}", reserve.address),
                    "mock private key does not bind reserve address"
                );
            }
            Sp1OwnershipWitness::EthereumEoaSignature { r, s, recovery_id } => {
                sp1_programs_common::ethereum_eoa::verify_ownership_signature_with_context_and_address(
                    ownership_context
                        .as_ref()
                        .expect("missing Ethereum ownership context"),
                    &address_bytes,
                    r,
                    s,
                    *recovery_id,
                );
            }
            Sp1OwnershipWitness::UnsupportedExternal { .. } => {
                panic!("unsupported external ownership verifier")
            }
        }
        product = mul_mod(product, sub_mod(zeta, x));
        balance_total = balance_total
            .checked_add(reserve.balance)
            .expect("balance total overflow");
        reserve_commitment.update(&reserve.address, reserve.balance);
    }
    cycle_end!(profile, "reserve_scan_product_ownership_and_commitment");
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
    cycle_start!(profile, "private_commitment_openings");
    verify_private_commitment_openings(&input);
    cycle_end!(profile, "private_commitment_openings");

    cycle_start!(profile, "public_values_build");
    let reserve_commitment = reserve_commitment.finalize();
    let public = Sp1InitPublicValues {
        chain_id: input.chain_id,
        state_root: input.state_root,
        session_id: input.session_id,
        reserve_count: input.reserve_count,
        reserve_commitment,
        zeta_le: input.zeta_le,
        balance_commitment: input.balance_commitment,
        shape_commitment: input.shape_commitment,
        eval_commitment: input.eval_commitment,
        commitment_params_digest_hex: input.commitment_params_digest_hex,
        uses_mock_inputs,
    };
    cycle_end!(profile, "public_values_build");
    public
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
) -> Bls12381Point {
    assert_eq!(bases.len(), scalars.len(), "commitment arity mismatch");
    let mut terms = bases
        .iter()
        .zip(scalars.iter())
        .filter(|(_, scalar)| !is_zero(scalar))
        .map(|(base, scalar)| {
            let base = point_from_io(base);
            scalar_mul_safe(&base, scalar)
        })
        .collect::<Vec<_>>();
    if !is_zero(blind) {
        let base = point_from_io(blind_base);
        terms.push(scalar_mul_safe(&base, blind));
    }
    let mut terms = terms.into_iter();
    let mut result = terms.next().expect("commitment cannot be identity");
    for term in terms {
        result.complete_add_assign(&term);
    }
    result
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

fn point_from_io(value: &Sp1G1Affine) -> Bls12381Point {
    assert!(value.x_be.len() <= 48 && value.y_be.len() <= 48);
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
    assert!(x < &modulus && y < &modulus);
    let lhs = (y * y) % &modulus;
    let rhs = ((x * x % &modulus) * x + BigUint::from(4u32)) % &modulus;
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
    let mut hasher = sp1_programs_common::ethereum_eoa::Keccak256Stream::new();
    hasher.update(b"dynamic-poa-init-commitment-params-keccak-v3");
    for point in [balance_value, balance_blind, eval_value, eval_blind] {
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

fn address_bytes_from_encoded(encoded_address_le: &[u8; 32]) -> [u8; 20] {
    let mut address = [0u8; 20];
    for (index, byte) in address.iter_mut().enumerate() {
        *byte = encoded_address_le[19 - index];
    }
    address
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
