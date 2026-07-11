use common::types::PublicState;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThresholdStatement {
    pub public_state: PublicState,
    pub threshold: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThresholdProof {
    pub scheme: String,
    pub proof_hex: String,
}

pub fn prove_threshold(_statement: &ThresholdStatement) -> Result<ThresholdProof, String> {
    Err("KZG NIZK threshold/range proof is not implemented; do not expose aggregate balances as a substitute".to_string())
}

pub fn verify_threshold(
    _statement: &ThresholdStatement,
    proof: &ThresholdProof,
) -> Result<(), String> {
    if proof.scheme != "kzg-nizk-threshold" {
        return Err("unexpected threshold proof scheme".to_string());
    }
    Err("KZG NIZK threshold/range proof verifier is not implemented".to_string())
}
