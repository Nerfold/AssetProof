#![no_main]

extern crate alloc;

use sp1_programs_common::io::{Sp1InitPublicValues, Sp1InitStdin};
use sp1_zkvm::entrypoint;

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

    let mut balance_total = 0i128;
    let mut product = scalar_from_le_bytes(input.alpha_le);
    let zeta = scalar_from_le_bytes(input.zeta_le);
    let claimed_product = scalar_from_le_bytes(input.product_zeta_le);
    let mut previous_x = None;
    for (index, reserve) in input.reserves.iter().enumerate() {
        assert!(reserve.balance >= 0, "negative reserve balance");
        let x = scalar_from_le_bytes(reserve.encoded_address_le);
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

    Sp1InitPublicValues {
        chain_id: input.chain_id,
        state_root: input.state_root,
        session_id: input.session_id,
        reserve_count: input.reserve_count,
        init_digest_hex: input.init_digest_hex,
        ownership_artifact_digest_hex: input.ownership_artifact_digest_hex,
        chain_balance_artifact_digest_hex: input.chain_balance_artifact_digest_hex,
        alpha_le: input.alpha_le,
        zeta_le: input.zeta_le,
        p_zeta_le: input.p_zeta_le,
        product_zeta_le: input.product_zeta_le,
        balance_total: input.balance_total,
    }
}

fn scalar_from_le_bytes(bytes: [u8; 32]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for index in 0..4 {
        let mut word = [0u8; 8];
        word.copy_from_slice(&bytes[index * 8..(index + 1) * 8]);
        out[index] = u64::from_le_bytes(word);
    }
    assert!(cmp_limbs(&out, &BLS12_381_FR_MODULUS_LE) < 0, "scalar out of range");
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
