use ark_bls12_381::{Fr, G1Projective};
use ark_ec::PrimeGroup;
use ark_ff::{Field, PrimeField, UniformRand};
use bulletproofs_bls::{BulletproofGens, PedersenGens, RangeProof};
use common::crypto::{hex_decode, hex_encode, point_g1_from_hex, point_g1_to_hex};
use common::types::Delta;
use merlin::Transcript;

use crate::bp::{ark_g1_to_bp, bp_g1_to_ark, fr_to_bp_scalar};
use crate::commitment::derive_generator;

pub const THRESHOLD_RANGE_BITS: usize = 128;
const LIMB_BITS: usize = 64;
const RANGE_PROOF_TAG: &str = "crange";
const RANGE_PROOF_VERSION: &str = "v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangePolicy {
    pub max_abs_epoch_delta: i128,
    pub max_abs_single_delta: i128,
}

impl RangePolicy {
    pub fn protocol_default() -> Self {
        Self {
            max_abs_epoch_delta: 1_i128 << 96,
            max_abs_single_delta: 1_i128 << 80,
        }
    }

    #[deprecated(note = "use protocol_default")]
    pub fn conservative_demo() -> Self {
        Self::protocol_default()
    }
}

/// Checks public integer inputs before they are embedded in field equations.
/// The sum of absolute values bounds every hidden subset projection, unlike
/// merely checking the signed sum of all public deltas.
pub fn check_public_delta_range(deltas: &[Delta], policy: &RangePolicy) -> Result<(), String> {
    if policy.max_abs_epoch_delta < 0 || policy.max_abs_single_delta < 0 {
        return Err("range policy bounds must be non-negative".to_string());
    }
    let mut absolute_total = 0u128;
    for delta in deltas {
        let absolute = delta.delta.unsigned_abs();
        if absolute > policy.max_abs_single_delta as u128 {
            return Err("delta exceeds configured integer range".to_string());
        }
        absolute_total = absolute_total
            .checked_add(absolute)
            .ok_or_else(|| "absolute delta sum overflowed u128".to_string())?;
    }
    if absolute_total > policy.max_abs_epoch_delta as u128 {
        return Err("absolute epoch delta sum exceeds configured integer range".to_string());
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedRangeProof {
    pub bit_length: usize,
    pub limb_commitments_hex: Vec<String>,
    pub range_proof_hex: String,
}

impl CommittedRangeProof {
    pub fn encode(&self) -> String {
        format!(
            "{RANGE_PROOF_TAG}:{RANGE_PROOF_VERSION}:{}:{}:{}",
            self.bit_length,
            self.limb_commitments_hex.join(","),
            self.range_proof_hex
        )
    }

    pub fn decode(encoded: &str) -> Result<Self, String> {
        let parts = encoded.split(':').collect::<Vec<_>>();
        if parts.len() != 5 || parts[0] != RANGE_PROOF_TAG || parts[1] != RANGE_PROOF_VERSION {
            return Err("invalid committed range proof encoding".to_string());
        }
        let bit_length = parts[2]
            .parse::<usize>()
            .map_err(|err| format!("invalid range bit length: {err}"))?;
        let limb_commitments_hex = if parts[3].is_empty() {
            Vec::new()
        } else {
            parts[3].split(',').map(str::to_string).collect()
        };
        Ok(Self {
            bit_length,
            limb_commitments_hex,
            range_proof_hex: parts[4].to_string(),
        })
    }
}

pub fn prove_committed_nonnegative(
    value: u128,
    blinding: Fr,
    expected_commitment: &G1Projective,
    bit_length: usize,
    statement_binding: &[u8],
) -> Result<CommittedRangeProof, String> {
    let (values, blindings) = limb_witness(value, blinding, bit_length)?;
    let pc_gens = balance_pedersen_gens()?;
    let bp_gens = BulletproofGens::new(LIMB_BITS, values.len());
    let expected_hex = point_g1_to_hex(expected_commitment)?;
    let mut transcript =
        range_transcript(statement_binding, &expected_hex, bit_length, values.len());
    let bp_blindings = blindings
        .iter()
        .map(fr_to_bp_scalar)
        .collect::<Result<Vec<_>, _>>()?;
    let (proof, commitments) = RangeProof::prove_multiple(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        &values,
        &bp_blindings,
        LIMB_BITS,
    )
    .map_err(|err| format!("prove committed range: {err}"))?;
    let ark_commitments = commitments
        .iter()
        .map(bp_g1_to_ark)
        .collect::<Result<Vec<_>, _>>()?;
    ensure_limb_link(expected_commitment, &ark_commitments, bit_length)?;
    Ok(CommittedRangeProof {
        bit_length,
        limb_commitments_hex: ark_commitments
            .iter()
            .map(point_g1_to_hex)
            .collect::<Result<Vec<_>, _>>()?,
        range_proof_hex: hex_encode(&proof.to_bytes()),
    })
}

pub fn verify_committed_nonnegative(
    expected_commitment: &G1Projective,
    proof: &CommittedRangeProof,
    statement_binding: &[u8],
) -> Result<(), String> {
    let expected_limbs = limb_count(proof.bit_length)?;
    if proof.limb_commitments_hex.len() != expected_limbs {
        return Err("range proof limb count mismatch".to_string());
    }
    let ark_commitments = proof
        .limb_commitments_hex
        .iter()
        .map(|encoded| point_g1_from_hex(encoded))
        .collect::<Result<Vec<_>, _>>()?;
    ensure_limb_link(expected_commitment, &ark_commitments, proof.bit_length)?;
    let bp_commitments = ark_commitments
        .iter()
        .map(ark_g1_to_bp)
        .collect::<Result<Vec<_>, _>>()?;
    let bytes = hex_decode(&proof.range_proof_hex)?;
    let range_proof = RangeProof::from_bytes(&bytes)
        .map_err(|err| format!("parse committed range proof: {err}"))?;
    let expected_hex = point_g1_to_hex(expected_commitment)?;
    let mut transcript = range_transcript(
        statement_binding,
        &expected_hex,
        proof.bit_length,
        expected_limbs,
    );
    let pc_gens = balance_pedersen_gens()?;
    let bp_gens = BulletproofGens::new(LIMB_BITS, expected_limbs);
    range_proof
        .verify_multiple(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            &bp_commitments,
            LIMB_BITS,
        )
        .map_err(|err| format!("verify committed range: {err}"))
}

fn limb_witness(
    value: u128,
    blinding: Fr,
    bit_length: usize,
) -> Result<(Vec<u64>, Vec<Fr>), String> {
    match bit_length {
        64 => {
            let value = u64::try_from(value).map_err(|_| {
                "range witness does not fit the configured 64-bit range".to_string()
            })?;
            Ok((vec![value], vec![blinding]))
        }
        128 => {
            let low = value as u64;
            let high = (value >> LIMB_BITS) as u64;
            let mut rng = rand::rngs::OsRng;
            let low_blind = Fr::rand(&mut rng);
            let radix = limb_radix();
            let radix_inverse = radix
                .inverse()
                .ok_or_else(|| "range limb radix is not invertible".to_string())?;
            let high_blind = (blinding - low_blind) * radix_inverse;
            Ok((vec![low, high], vec![low_blind, high_blind]))
        }
        _ => Err("committed range proof supports exactly 64 or 128 bits".to_string()),
    }
}

fn limb_count(bit_length: usize) -> Result<usize, String> {
    match bit_length {
        64 => Ok(1),
        128 => Ok(2),
        _ => Err("committed range proof supports exactly 64 or 128 bits".to_string()),
    }
}

fn ensure_limb_link(
    expected_commitment: &G1Projective,
    commitments: &[G1Projective],
    bit_length: usize,
) -> Result<(), String> {
    let linked = match bit_length {
        64 if commitments.len() == 1 => commitments[0],
        128 if commitments.len() == 2 => {
            commitments[0] + commitments[1].mul_bigint(limb_radix().into_bigint())
        }
        _ => return Err("invalid committed range limb layout".to_string()),
    };
    if linked != *expected_commitment {
        return Err("range limb commitments do not open the statement commitment".to_string());
    }
    Ok(())
}

fn balance_pedersen_gens() -> Result<PedersenGens, String> {
    Ok(PedersenGens {
        B: ark_g1_to_bp(&derive_generator("balance-v", 0))?,
        B_blinding: ark_g1_to_bp(&derive_generator("balance-h", 0))?,
    })
}

fn range_transcript(
    statement_binding: &[u8],
    expected_commitment_hex: &str,
    bit_length: usize,
    limb_count: usize,
) -> Transcript {
    let mut transcript = Transcript::new(b"dynamic-poa-committed-range-v1");
    transcript.append_message(b"statement", statement_binding);
    transcript.append_message(b"commitment", expected_commitment_hex.as_bytes());
    transcript.append_message(b"bits", &(bit_length as u64).to_le_bytes());
    transcript.append_message(b"limbs", &(limb_count as u64).to_le_bytes());
    transcript
}

fn limb_radix() -> Fr {
    Fr::from(2u64).pow([LIMB_BITS as u64])
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;

    use super::{
        check_public_delta_range, prove_committed_nonnegative, verify_committed_nonnegative,
        CommittedRangeProof, RangePolicy, THRESHOLD_RANGE_BITS,
    };
    use crate::commitment::commit_balance;
    use common::types::Delta;

    #[test]
    fn committed_128_bit_range_proof_supports_values_above_u64() {
        let value = (1u128 << 96) + 17;
        let blind = Fr::from(29u64);
        let commitment = commit_balance(value as i128, blind);
        let proof = prove_committed_nonnegative(
            value,
            blind,
            &commitment,
            THRESHOLD_RANGE_BITS,
            b"range-test",
        )
        .unwrap();
        let decoded = CommittedRangeProof::decode(&proof.encode()).unwrap();
        verify_committed_nonnegative(&commitment, &decoded, b"range-test").unwrap();
        assert!(verify_committed_nonnegative(&commitment, &decoded, b"other").is_err());
    }

    #[test]
    fn absolute_delta_bound_covers_hidden_subset_projection() {
        let deltas = vec![
            Delta {
                address: "0x0000000000000000000000000000000000000001".to_string(),
                delta: 90,
            },
            Delta {
                address: "0x0000000000000000000000000000000000000002".to_string(),
                delta: -90,
            },
        ];
        let policy = RangePolicy {
            max_abs_epoch_delta: 100,
            max_abs_single_delta: 100,
        };
        assert!(check_public_delta_range(&deltas, &policy).is_err());
    }
}
