use ark_bls12_381::Fr;
use ark_ec::PrimeGroup;
use ark_ff::PrimeField;
use common::crypto::{hash_bytes, point_g1_from_hex, point_g1_to_hex, scalar_from_i128};
use common::types::{PublicState, StoredState};

use crate::commitment::{commit_balance, derive_generator};
use crate::range::{
    prove_committed_nonnegative, verify_committed_nonnegative, CommittedRangeProof,
    THRESHOLD_RANGE_BITS,
};

pub const THRESHOLD_PROOF_SCHEME: &str = "dpoa-threshold-bulletproof-v2-bounded-i128";
const BOUNDED_RANGE_PREFIX: &str = "bounded-i128:v1:";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThresholdStatement {
    pub public_state: PublicState,
    pub threshold: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThresholdWitness {
    pub asset_total: i128,
    pub asset_blind: Fr,
}

impl ThresholdWitness {
    pub fn from_state(state: &StoredState) -> Self {
        Self {
            asset_total: state.balance_total,
            asset_blind: state.balance_blind,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedLiabilityStatement {
    pub public_state: PublicState,
    pub liability_commitment_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedLiabilityWitness {
    pub asset_total: i128,
    pub asset_blind: Fr,
    pub liability_total: i128,
    pub liability_blind: Fr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThresholdProof {
    pub scheme: String,
    pub proof_hex: String,
}

pub fn prove_threshold(
    statement: &ThresholdStatement,
    witness: &ThresholdWitness,
) -> Result<ThresholdProof, String> {
    ensure_asset_opening(
        &statement.public_state,
        witness.asset_total,
        witness.asset_blind,
    )?;
    let slack = nonnegative_difference(witness.asset_total, statement.threshold)?;
    let slack_commitment = public_threshold_difference_commitment(statement)?;
    let binding = public_threshold_binding(statement);
    let proof_hex = prove_bounded_i128(slack, witness.asset_blind, &slack_commitment, &binding)?;
    Ok(ThresholdProof {
        scheme: THRESHOLD_PROOF_SCHEME.to_string(),
        proof_hex,
    })
}

pub fn verify_threshold(
    statement: &ThresholdStatement,
    proof: &ThresholdProof,
) -> Result<(), String> {
    verify_threshold_encoded(statement, &proof.scheme, &proof.proof_hex)
}

/// Verifies an encoded threshold proof without copying its (potentially large)
/// proof string into a temporary `ThresholdProof`.
pub fn verify_threshold_encoded(
    statement: &ThresholdStatement,
    scheme: &str,
    proof_hex: &str,
) -> Result<(), String> {
    ensure_scheme_name(scheme)?;
    let slack_commitment = public_threshold_difference_commitment(statement)?;
    verify_bounded_i128(
        &slack_commitment,
        proof_hex,
        &public_threshold_binding(statement),
    )
}

pub fn prove_committed_liability_threshold(
    statement: &CommittedLiabilityStatement,
    witness: &CommittedLiabilityWitness,
) -> Result<ThresholdProof, String> {
    ensure_asset_opening(
        &statement.public_state,
        witness.asset_total,
        witness.asset_blind,
    )?;
    if witness.liability_total < 0 {
        return Err("liability total is outside the accepted nonnegative range".to_string());
    }
    let expected_liability = commit_balance(witness.liability_total, witness.liability_blind);
    if point_g1_to_hex(&expected_liability)? != statement.liability_commitment_hex {
        return Err("liability witness does not open the public commitment".to_string());
    }
    let slack = nonnegative_difference(witness.asset_total, witness.liability_total)?;
    let slack_blind = witness.asset_blind - witness.liability_blind;
    let slack_commitment = committed_liability_difference_commitment(statement)?;
    let proof_hex = prove_bounded_i128(
        slack,
        slack_blind,
        &slack_commitment,
        &committed_liability_binding(statement),
    )?;
    Ok(ThresholdProof {
        scheme: THRESHOLD_PROOF_SCHEME.to_string(),
        proof_hex,
    })
}

pub fn verify_committed_liability_threshold(
    statement: &CommittedLiabilityStatement,
    proof: &ThresholdProof,
) -> Result<(), String> {
    ensure_scheme(proof)?;
    let slack_commitment = committed_liability_difference_commitment(statement)?;
    verify_bounded_i128(
        &slack_commitment,
        &proof.proof_hex,
        &committed_liability_binding(statement),
    )
}

fn prove_bounded_i128(
    value: u128,
    blinding: Fr,
    commitment: &ark_bls12_381::G1Projective,
    statement_binding: &[u8],
) -> Result<String, String> {
    let upper_slack = (i128::MAX as u128)
        .checked_sub(value)
        .ok_or_else(|| "range witness exceeds i128::MAX".to_string())?;
    let lower = prove_committed_nonnegative(
        value,
        blinding,
        commitment,
        THRESHOLD_RANGE_BITS,
        &bounded_range_binding(statement_binding, b"lower"),
    )?;
    let upper_commitment = commit_balance(i128::MAX, Fr::from(0u64)) - *commitment;
    let upper = prove_committed_nonnegative(
        upper_slack,
        -blinding,
        &upper_commitment,
        THRESHOLD_RANGE_BITS,
        &bounded_range_binding(statement_binding, b"upper"),
    )?;
    Ok(format!(
        "{BOUNDED_RANGE_PREFIX}{};{}",
        lower.encode(),
        upper.encode()
    ))
}

fn verify_bounded_i128(
    commitment: &ark_bls12_381::G1Projective,
    encoded: &str,
    statement_binding: &[u8],
) -> Result<(), String> {
    let body = encoded
        .strip_prefix(BOUNDED_RANGE_PREFIX)
        .ok_or_else(|| "invalid bounded i128 range proof encoding".to_string())?;
    let (lower, upper) = body
        .split_once(';')
        .ok_or_else(|| "bounded i128 range proof is missing a component".to_string())?;
    if upper.contains(';') {
        return Err("bounded i128 range proof has trailing components".to_string());
    }
    let lower = CommittedRangeProof::decode(lower)?;
    let upper = CommittedRangeProof::decode(upper)?;
    if lower.bit_length != THRESHOLD_RANGE_BITS || upper.bit_length != THRESHOLD_RANGE_BITS {
        return Err("threshold proof uses an unsupported range bound".to_string());
    }
    verify_committed_nonnegative(
        commitment,
        &lower,
        &bounded_range_binding(statement_binding, b"lower"),
    )?;
    let upper_commitment = commit_balance(i128::MAX, Fr::from(0u64)) - *commitment;
    verify_committed_nonnegative(
        &upper_commitment,
        &upper,
        &bounded_range_binding(statement_binding, b"upper"),
    )
}

fn bounded_range_binding(statement_binding: &[u8], side: &[u8]) -> [u8; 32] {
    hash_bytes(
        "dynamic-poa-bounded-i128-range-v1",
        &[statement_binding, side],
    )
}

fn ensure_scheme(proof: &ThresholdProof) -> Result<(), String> {
    ensure_scheme_name(&proof.scheme)
}

fn ensure_scheme_name(scheme: &str) -> Result<(), String> {
    if scheme != THRESHOLD_PROOF_SCHEME {
        return Err("unexpected threshold proof scheme".to_string());
    }
    Ok(())
}

fn ensure_asset_opening(
    public_state: &PublicState,
    asset_total: i128,
    asset_blind: Fr,
) -> Result<(), String> {
    if asset_total < 0 {
        return Err("asset total is outside the accepted nonnegative range".to_string());
    }
    let expected = commit_balance(asset_total, asset_blind);
    if point_g1_to_hex(&expected)? != public_state.balance_commitment_hex {
        return Err("threshold witness does not open the asset commitment".to_string());
    }
    Ok(())
}

fn nonnegative_difference(left: i128, right: i128) -> Result<u128, String> {
    let difference = left
        .checked_sub(right)
        .ok_or_else(|| "threshold slack overflowed i128".to_string())?;
    u128::try_from(difference).map_err(|_| "threshold is not satisfied".to_string())
}

fn public_threshold_difference_commitment(
    statement: &ThresholdStatement,
) -> Result<ark_bls12_381::G1Projective, String> {
    let asset = point_g1_from_hex(&statement.public_state.balance_commitment_hex)?;
    let threshold_term = derive_generator("balance-v", 0)
        .mul_bigint(scalar_from_i128(statement.threshold).into_bigint());
    Ok(asset - threshold_term)
}

fn committed_liability_difference_commitment(
    statement: &CommittedLiabilityStatement,
) -> Result<ark_bls12_381::G1Projective, String> {
    Ok(
        point_g1_from_hex(&statement.public_state.balance_commitment_hex)?
            - point_g1_from_hex(&statement.liability_commitment_hex)?,
    )
}

fn public_threshold_binding(statement: &ThresholdStatement) -> [u8; 32] {
    state_binding(
        "dynamic-poa-public-threshold-v1",
        &statement.public_state,
        &[&statement.threshold.to_le_bytes()],
    )
}

fn committed_liability_binding(statement: &CommittedLiabilityStatement) -> [u8; 32] {
    state_binding(
        "dynamic-poa-committed-liability-threshold-v1",
        &statement.public_state,
        &[statement.liability_commitment_hex.as_bytes()],
    )
}

fn state_binding(domain: &str, state: &PublicState, extra: &[&[u8]]) -> [u8; 32] {
    let degree = (state.srs_max_degree as u64).to_le_bytes();
    let count = (state.reserve_count as u64).to_le_bytes();
    let mut fields = vec![
        state.state_root.as_bytes(),
        degree.as_slice(),
        count.as_slice(),
        state.accumulator_hex.as_bytes(),
        state.balance_commitment_hex.as_bytes(),
    ];
    fields.extend_from_slice(extra);

    // Length-prefix every field so two different public statements cannot
    // produce the same byte stream merely by shifting a variable-length field
    // boundary.
    let mut framed = Vec::new();
    for field in fields {
        framed.extend_from_slice(&(field.len() as u64).to_le_bytes());
        framed.extend_from_slice(field);
    }
    hash_bytes(domain, &[&framed])
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use common::crypto::point_g1_to_hex;
    use common::types::PublicState;

    use super::{
        prove_committed_liability_threshold, prove_threshold, verify_committed_liability_threshold,
        verify_threshold, CommittedLiabilityStatement, CommittedLiabilityWitness,
        ThresholdStatement, ThresholdWitness,
    };
    use crate::commitment::commit_balance;

    fn public_state(total: i128, blind: Fr) -> PublicState {
        PublicState {
            state_root: "threshold-test-root".to_string(),
            srs_max_degree: 16,
            reserve_count: 4,
            accumulator_hex: "threshold-test-accumulator".to_string(),
            balance_commitment_hex: point_g1_to_hex(&commit_balance(total, blind)).unwrap(),
        }
    }

    #[test]
    fn public_threshold_proves_nonnegative_128_bit_slack() {
        let total = (1i128 << 96) + 100;
        let blind = Fr::from(17u64);
        let statement = ThresholdStatement {
            public_state: public_state(total, blind),
            threshold: 100,
        };
        let proof = prove_threshold(
            &statement,
            &ThresholdWitness {
                asset_total: total,
                asset_blind: blind,
            },
        )
        .unwrap();
        verify_threshold(&statement, &proof).unwrap();

        let mut changed = statement.clone();
        changed.threshold += 1;
        assert!(verify_threshold(&changed, &proof).is_err());
    }

    #[test]
    fn public_threshold_rejects_unsatisfied_or_wrong_opening() {
        let total = 99;
        let blind = Fr::from(19u64);
        let statement = ThresholdStatement {
            public_state: public_state(total, blind),
            threshold: 100,
        };
        assert!(prove_threshold(
            &statement,
            &ThresholdWitness {
                asset_total: total,
                asset_blind: blind,
            }
        )
        .is_err());
        assert!(prove_threshold(
            &ThresholdStatement {
                public_state: public_state(101, blind),
                threshold: 100,
            },
            &ThresholdWitness {
                asset_total: 101,
                asset_blind: Fr::from(20u64),
            }
        )
        .is_err());
    }

    #[test]
    fn committed_liability_comparison_hides_both_totals() {
        let asset_total = 1_000;
        let asset_blind = Fr::from(23u64);
        let liability_total = 750;
        let liability_blind = Fr::from(29u64);
        let statement = CommittedLiabilityStatement {
            public_state: public_state(asset_total, asset_blind),
            liability_commitment_hex: point_g1_to_hex(&commit_balance(
                liability_total,
                liability_blind,
            ))
            .unwrap(),
        };
        let witness = CommittedLiabilityWitness {
            asset_total,
            asset_blind,
            liability_total,
            liability_blind,
        };
        let proof = prove_committed_liability_threshold(&statement, &witness).unwrap();
        verify_committed_liability_threshold(&statement, &proof).unwrap();

        let mut changed = statement.clone();
        changed.liability_commitment_hex =
            point_g1_to_hex(&commit_balance(751, liability_blind)).unwrap();
        assert!(verify_committed_liability_threshold(&changed, &proof).is_err());
    }
}
