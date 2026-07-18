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
use sp1_programs_common::ethereum_binary_merkle::{leaf_hash, node_hash};
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
    let mut uses_mock_inputs = false;
    let expected_root = decode_hash(&input.state_root);
    if let Some(prefix_proof) = input.merkle_prefix_proof.as_ref() {
        verify_merkle_prefix(&expected_root, &input.reserves, prefix_proof);
    }
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

fn verify_chain_balance(chain_id: &str, expected_root: &Hash, reserve: &Sp1InitReserveEntry) {
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
            let address = decode_address(&reserve.address);
            let mut current = leaf_hash(&address, reserve.balance);
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
                &current, expected_root,
                "native chain Merkle proof mismatch"
            );
        }
        Sp1ChainBalanceProof::EthereumAccountProof { nodes } => {
            let address = decode_address(&reserve.address);
            sp1_programs_common::ethereum_mpt::verify_account_balance(
                expected_root,
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

fn verify_merkle_prefix(
    expected_root: &Hash,
    reserves: &[Sp1InitReserveEntry],
    proof: &sp1_programs_common::io::Sp1BinaryMerklePrefixProof,
) {
    assert!(
        proof.depth < usize::BITS as usize,
        "Merkle depth is too large"
    );
    let capacity = 1usize << proof.depth;
    assert!(
        reserves.len() <= capacity,
        "reserve prefix exceeds Merkle capacity"
    );
    assert!(
        proof.suffix_subtrees.len() <= proof.depth + 1,
        "Merkle prefix contains too many suffix subtrees"
    );
    let mut stack = vec![None; proof.depth + 1];
    let mut cursor = 0usize;
    for (expected_index, reserve) in reserves.iter().enumerate() {
        let Sp1ChainBalanceProof::BinaryMerkleV1 {
            leaf_index,
            siblings,
        } = &reserve.chain_balance_proof
        else {
            panic!("shared Merkle prefix proof requires binary Merkle members")
        };
        assert_eq!(
            *leaf_index as usize, expected_index,
            "non-canonical Merkle prefix index"
        );
        assert!(
            siblings.is_empty(),
            "prefix member repeated an individual Merkle path"
        );
        let address = decode_address(&reserve.address);
        append_subtree(
            &mut stack,
            &mut cursor,
            0,
            leaf_hash(&address, reserve.balance),
        );
    }
    for subtree in &proof.suffix_subtrees {
        append_subtree(
            &mut stack,
            &mut cursor,
            subtree.level as usize,
            subtree.root,
        );
    }
    assert_eq!(
        cursor, capacity,
        "Merkle prefix proof did not cover the tree"
    );
    assert!(
        stack[..proof.depth].iter().all(Option::is_none),
        "Merkle prefix proof left an incomplete frontier"
    );
    assert_eq!(
        stack[proof.depth].expect("missing reconstructed Merkle root"),
        *expected_root,
        "native chain Merkle prefix proof mismatch"
    );
}

fn append_subtree(
    stack: &mut [Option<Hash>],
    cursor: &mut usize,
    mut level: usize,
    mut current: Hash,
) {
    assert!(
        level < stack.len(),
        "Merkle subtree level exceeds tree depth"
    );
    let width = 1usize << level;
    assert_eq!(*cursor % width, 0, "unaligned Merkle suffix subtree");
    *cursor = cursor.checked_add(width).expect("Merkle cursor overflow");
    loop {
        let Some(left) = stack[level].take() else {
            stack[level] = Some(current);
            return;
        };
        current = node_hash(level, &left, &current);
        level += 1;
        assert!(level < stack.len(), "Merkle prefix exceeded declared depth");
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
