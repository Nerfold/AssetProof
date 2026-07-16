pub type Scalar = [u64; 4];

const MODULUS_LE: Scalar = [
    0xffffffff00000001,
    0x53bda402fffe5bfe,
    0x3339d80809a1d805,
    0x73eda753299d7d48,
];

const MONTGOMERY_NEG_INV: u64 = 0xfffffffeffffffff;
const MONTGOMERY_R2: Scalar = [
    0xc999e990f3f29c6d,
    0x2b6cedcb87925c23,
    0x05d314967254398f,
    0x0748d9d99f59ff11,
];

pub fn from_le_bytes(bytes: [u8; 32]) -> Scalar {
    let mut out = [0u64; 4];
    for index in 0..4 {
        let mut word = [0u8; 8];
        word.copy_from_slice(&bytes[index * 8..(index + 1) * 8]);
        out[index] = u64::from_le_bytes(word);
    }
    assert!(cmp(&out, &MODULUS_LE) < 0, "scalar out of range");
    out
}

pub fn to_le_bytes(value: Scalar) -> [u8; 32] {
    let mut out = [0u8; 32];
    for index in 0..4 {
        out[index * 8..(index + 1) * 8].copy_from_slice(&value[index].to_le_bytes());
    }
    out
}

pub fn add_mod(left: Scalar, right: Scalar) -> Scalar {
    let (sum, carry) = add_raw(left, right);
    if carry || cmp(&sum, &MODULUS_LE) >= 0 {
        sub_raw(sum, MODULUS_LE).0
    } else {
        sum
    }
}

pub fn sub_mod(left: Scalar, right: Scalar) -> Scalar {
    if cmp(&left, &right) >= 0 {
        sub_raw(left, right).0
    } else {
        let (offset, _) = sub_raw(MODULUS_LE, right);
        add_mod(offset, left)
    }
}

pub fn mul_mod(left: Scalar, right: Scalar) -> Scalar {
    mul_by_montgomery(left, to_montgomery(right))
}

pub fn to_montgomery(value: Scalar) -> Scalar {
    montgomery_mul(value, MONTGOMERY_R2)
}

/// Multiplies a canonical scalar by a Montgomery-form scalar and returns a
/// canonical scalar. This is useful for Horner evaluation at one fixed point:
/// convert the point once, then use one reduction per coefficient.
pub fn mul_by_montgomery(left: Scalar, right_montgomery: Scalar) -> Scalar {
    montgomery_mul(left, right_montgomery)
}

fn montgomery_mul(left: Scalar, right: Scalar) -> Scalar {
    montgomery_reduce(full_mul(left, right))
}

fn full_mul(left: Scalar, right: Scalar) -> [u64; 9] {
    let mut product = [0u64; 9];
    for (left_index, left_limb) in left.into_iter().enumerate() {
        let mut carry = 0u64;
        for (right_index, right_limb) in right.into_iter().enumerate() {
            let index = left_index + right_index;
            product[index] = mac(product[index], left_limb, right_limb, &mut carry);
        }
        propagate_carry(&mut product, left_index + 4, carry);
    }
    product
}

fn montgomery_reduce(mut value: [u64; 9]) -> Scalar {
    for index in 0..4 {
        let factor = value[index].wrapping_mul(MONTGOMERY_NEG_INV);
        let mut carry = 0u64;
        value[index] = mac(value[index], factor, MODULUS_LE[0], &mut carry);
        for modulus_index in 1..4 {
            let target = index + modulus_index;
            value[target] = mac(value[target], factor, MODULUS_LE[modulus_index], &mut carry);
        }
        propagate_carry(&mut value, index + 4, carry);
    }
    assert_eq!(value[8], 0, "Montgomery reduction overflow");
    let result = [value[4], value[5], value[6], value[7]];
    if cmp(&result, &MODULUS_LE) >= 0 {
        sub_raw(result, MODULUS_LE).0
    } else {
        result
    }
}

fn mac(accumulator: u64, left: u64, right: u64, carry: &mut u64) -> u64 {
    let value = accumulator as u128 + left as u128 * right as u128 + *carry as u128;
    *carry = (value >> 64) as u64;
    value as u64
}

fn propagate_carry(value: &mut [u64; 9], mut index: usize, mut carry: u64) {
    while carry != 0 {
        assert!(index < value.len(), "multi-limb carry overflow");
        let sum = value[index] as u128 + carry as u128;
        value[index] = sum as u64;
        carry = (sum >> 64) as u64;
        index += 1;
    }
}

fn add_raw(left: Scalar, right: Scalar) -> (Scalar, bool) {
    let mut out = [0u64; 4];
    let mut carry = 0u128;
    for index in 0..4 {
        let value = left[index] as u128 + right[index] as u128 + carry;
        out[index] = value as u64;
        carry = value >> 64;
    }
    (out, carry != 0)
}

fn sub_raw(left: Scalar, right: Scalar) -> (Scalar, bool) {
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

fn cmp(left: &Scalar, right: &Scalar) -> i8 {
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

#[cfg(test)]
mod tests {
    use super::{add_mod, mul_mod, Scalar, MODULUS_LE};

    fn slow_mul(left: Scalar, right: Scalar) -> Scalar {
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

    #[test]
    fn montgomery_multiplication_matches_reference() {
        let modulus_minus_one = [
            MODULUS_LE[0] - 1,
            MODULUS_LE[1],
            MODULUS_LE[2],
            MODULUS_LE[3],
        ];
        for (left, right) in [
            ([0, 0, 0, 0], [7, 0, 0, 0]),
            ([1, 0, 0, 0], modulus_minus_one),
            (modulus_minus_one, modulus_minus_one),
            (
                [0x0123456789abcdef, 17, 29, 31],
                [0xfedcba9876543210, 37, 41, 43],
            ),
        ] {
            assert_eq!(mul_mod(left, right), slow_mul(left, right));
        }
    }
}
