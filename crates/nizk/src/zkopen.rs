use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{PrimeField, UniformRand, Zero};

use common::crypto::{point_g1_from_hex, point_g1_to_hex, scalar_from_hex, scalar_to_hex};

use crate::commitment::derive_generator;
use crate::kzg::Srs;

#[derive(Clone, Debug)]
pub struct CommittedOpeningProof {
    pub a_p_hex: String,
    pub a_c_hex: String,
    pub s_y: Fr,
    pub s_blind: Fr,
    pub pi_hex: String,
}

pub fn prove_committed_opening(
    srs: &Srs,
    poly_commitment_hex: &str,
    zeta: Fr,
    value_commitment_hex: &str,
    value: Fr,
    value_blind: Fr,
    kzg_opening: &G1Projective,
    domain: &str,
) -> Result<String, String> {
    let poly_commitment = point_g1_from_hex(poly_commitment_hex)?;
    let value_commitment = point_g1_from_hex(value_commitment_hex)?;
    ensure_kzg_statement(srs, &poly_commitment, zeta, &value_commitment)?;

    let mut rng = rand::rngs::OsRng;
    let a = Fr::rand(&mut rng);
    let b = Fr::rand(&mut rng);
    let t = Fr::rand(&mut rng);
    let d_z = kzg_g1_denominator(srs, zeta)?;
    let a_p = eval_commit(a, b);
    let a_c =
        G1Projective::generator().mul_bigint(a.into_bigint()) + d_z.mul_bigint(t.into_bigint());
    let challenge = challenge_scalar(
        srs,
        domain,
        poly_commitment_hex,
        zeta,
        value_commitment_hex,
        &a_p,
        &a_c,
    )?;

    let s_y = a + challenge * value;
    let s_blind = b + challenge * value_blind;
    let pi = G1Projective::generator().mul_bigint(t.into_bigint())
        + kzg_opening.mul_bigint(challenge.into_bigint());

    encode_proof(&CommittedOpeningProof {
        a_p_hex: point_g1_to_hex(&a_p)?,
        a_c_hex: point_g1_to_hex(&a_c)?,
        s_y,
        s_blind,
        pi_hex: point_g1_to_hex(&pi)?,
    })
}

pub fn verify_committed_opening(
    srs: &Srs,
    poly_commitment_hex: &str,
    zeta: Fr,
    value_commitment_hex: &str,
    proof_hex: &str,
    domain: &str,
) -> Result<(), String> {
    let poly_commitment = point_g1_from_hex(poly_commitment_hex)?;
    let value_commitment = point_g1_from_hex(value_commitment_hex)?;
    ensure_kzg_statement(srs, &poly_commitment, zeta, &value_commitment)?;
    let proof = decode_proof(proof_hex)?;
    let a_p = point_g1_from_hex(&proof.a_p_hex)?;
    let a_c = point_g1_from_hex(&proof.a_c_hex)?;
    let pi = point_g1_from_hex(&proof.pi_hex)?;
    let challenge = challenge_scalar(
        srs,
        domain,
        poly_commitment_hex,
        zeta,
        value_commitment_hex,
        &a_p,
        &a_c,
    )?;

    let commit_lhs = eval_commit(proof.s_y, proof.s_blind);
    let commit_rhs = a_p + value_commitment.mul_bigint(challenge.into_bigint());
    if commit_lhs != commit_rhs {
        return Err("ZKOpen scalar commitment equation failed".to_string());
    }

    let lhs_g1 = a_c + poly_commitment.mul_bigint(challenge.into_bigint())
        - G1Projective::generator().mul_bigint(proof.s_y.into_bigint());
    let d_hat_z = kzg_g2_denominator(srs, zeta)?;
    let pair_lhs = Bls12_381::pairing(lhs_g1.into_affine(), G2Affine::generator());
    let pair_rhs = Bls12_381::pairing(pi.into_affine(), d_hat_z.into_affine());
    if pair_lhs != pair_rhs {
        return Err("ZKOpen KZG opening equation failed".to_string());
    }

    Ok(())
}

pub fn eval_commit(value: Fr, blind: Fr) -> G1Projective {
    derive_generator("eval-v", 0).mul_bigint(value.into_bigint())
        + derive_generator("eval-h", 0).mul_bigint(blind.into_bigint())
}

fn ensure_kzg_statement(
    srs: &Srs,
    poly_commitment: &G1Projective,
    zeta: Fr,
    value_commitment: &G1Projective,
) -> Result<(), String> {
    if srs.tau_g2_powers.len() < 2 {
        return Err("SRS must contain tau^0 and tau^1 G2 powers for ZKOpen".to_string());
    }
    if poly_commitment.is_zero() {
        return Err("ZKOpen polynomial commitment must be non-zero".to_string());
    }
    if value_commitment.is_zero() {
        return Err("ZKOpen value commitment must be non-zero".to_string());
    }
    let _ = kzg_g1_denominator(srs, zeta)?;
    let _ = kzg_g2_denominator(srs, zeta)?;
    Ok(())
}

fn kzg_g1_denominator(srs: &Srs, zeta: Fr) -> Result<G1Projective, String> {
    if srs.tau_g1_powers.len() < 2 {
        return Err("SRS must contain tau^1 G1 power for ZKOpen".to_string());
    }
    let value = G1Projective::from(srs.tau_g1_powers[1])
        - G1Projective::generator().mul_bigint(zeta.into_bigint());
    if value.is_zero() {
        return Err("ZKOpen evaluation point equals the KZG trapdoor".to_string());
    }
    Ok(value)
}

fn kzg_g2_denominator(srs: &Srs, zeta: Fr) -> Result<G2Projective, String> {
    if srs.tau_g2_powers.len() < 2 {
        return Err("SRS must contain tau^1 G2 power for ZKOpen".to_string());
    }
    let value = G2Projective::from(srs.tau_g2_powers[1])
        - G2Projective::generator().mul_bigint(zeta.into_bigint());
    if value.is_zero() {
        return Err("ZKOpen evaluation point equals the KZG trapdoor".to_string());
    }
    Ok(value)
}

fn encode_proof(proof: &CommittedOpeningProof) -> Result<String, String> {
    Ok(format!(
        "zkopen:v2:{}:{}:{}:{}:{}",
        proof.a_p_hex,
        proof.a_c_hex,
        scalar_to_hex(&proof.s_y)?,
        scalar_to_hex(&proof.s_blind)?,
        proof.pi_hex
    ))
}

fn decode_proof(raw: &str) -> Result<CommittedOpeningProof, String> {
    let parts = raw.split(':').collect::<Vec<_>>();
    if parts.len() != 7 || parts[0] != "zkopen" || parts[1] != "v2" {
        return Err("invalid ZKOpen proof encoding".to_string());
    }
    Ok(CommittedOpeningProof {
        a_p_hex: parts[2].to_string(),
        a_c_hex: parts[3].to_string(),
        s_y: scalar_from_hex(parts[4])?,
        s_blind: scalar_from_hex(parts[5])?,
        pi_hex: parts[6].to_string(),
    })
}

fn challenge_scalar(
    srs: &Srs,
    domain: &str,
    poly_commitment_hex: &str,
    zeta: Fr,
    value_commitment_hex: &str,
    a_p: &G1Projective,
    a_c: &G1Projective,
) -> Result<Fr, String> {
    let a_p_hex = point_g1_to_hex(a_p)?;
    let a_c_hex = point_g1_to_hex(a_c)?;
    let zeta_hex = scalar_to_hex(&zeta)?;
    let max_degree = srs.max_degree.to_string();
    let tau_g1_hex = common::crypto::serialize_hex(&srs.tau_g1_powers[1])?;
    let tau_g2_hex = common::crypto::serialize_hex(&srs.tau_g2_powers[1])?;
    Ok(common::crypto::hash_to_scalar(
        "dynamic-poa-zkopen-sigma-challenge-v2",
        &[
            domain,
            &max_degree,
            &tau_g1_hex,
            &tau_g2_hex,
            poly_commitment_hex,
            &zeta_hex,
            value_commitment_hex,
            &a_p_hex,
            &a_c_hex,
        ]
        .join("|")
        .into_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;

    use super::{
        decode_proof, encode_proof, eval_commit, prove_committed_opening, verify_committed_opening,
    };
    use crate::kzg::{commit_g1, open, Srs};
    use crate::polynomial::Polynomial;
    use common::crypto::point_g1_to_hex;

    #[test]
    fn sigma_zkopen_accepts_honest_opening_and_rejects_tampering() {
        let srs = Srs::setup_development(8, b"zkopen-sigma-test");
        let polynomial =
            Polynomial::from_coeffs(vec![Fr::from(3u64), Fr::from(7u64), Fr::from(11u64)]);
        let zeta = Fr::from(19u64);
        let value = polynomial.evaluate(zeta);
        let blind = Fr::from(23u64);
        let commitment = commit_g1(&srs, &polynomial).unwrap();
        let value_commitment = eval_commit(value, blind);
        let opening = open(&srs, &polynomial, zeta, value).unwrap();
        let commitment_hex = point_g1_to_hex(&commitment).unwrap();
        let value_commitment_hex = point_g1_to_hex(&value_commitment).unwrap();
        let proof = prove_committed_opening(
            &srs,
            &commitment_hex,
            zeta,
            &value_commitment_hex,
            value,
            blind,
            &opening,
            "zkopen-test-domain",
        )
        .unwrap();
        assert!(proof.starts_with("zkopen:v2:"));
        verify_committed_opening(
            &srs,
            &commitment_hex,
            zeta,
            &value_commitment_hex,
            &proof,
            "zkopen-test-domain",
        )
        .unwrap();

        let wrong_value_commitment = eval_commit(value + Fr::from(1u64), blind);
        assert!(verify_committed_opening(
            &srs,
            &commitment_hex,
            zeta,
            &point_g1_to_hex(&wrong_value_commitment).unwrap(),
            &proof,
            "zkopen-test-domain",
        )
        .is_err());

        let mut decoded = decode_proof(&proof).unwrap();
        decoded.s_y += Fr::from(1u64);
        let tampered = encode_proof(&decoded).unwrap();
        assert!(verify_committed_opening(
            &srs,
            &commitment_hex,
            zeta,
            &value_commitment_hex,
            &tampered,
            "zkopen-test-domain",
        )
        .is_err());
    }

    #[test]
    fn sigma_zkopen_rejects_evaluation_at_tau() {
        let seed = b"zkopen-tau-test";
        let srs = Srs::setup_development(4, seed);
        let mut tau = common::crypto::hash_to_scalar("srs-tau", seed);
        if tau == Fr::from(0u64) {
            tau = Fr::from(7u64);
        }
        let polynomial = Polynomial::from_coeffs(vec![Fr::from(1u64), Fr::from(2u64)]);
        let value = polynomial.evaluate(tau);
        let commitment = commit_g1(&srs, &polynomial).unwrap();
        let value_commitment = eval_commit(value, Fr::from(5u64));
        let opening = open(&srs, &polynomial, tau, value).unwrap();
        let err = prove_committed_opening(
            &srs,
            &point_g1_to_hex(&commitment).unwrap(),
            tau,
            &point_g1_to_hex(&value_commitment).unwrap(),
            value,
            Fr::from(5u64),
            &opening,
            "zkopen-test-domain",
        )
        .unwrap_err();
        assert!(err.contains("trapdoor"));
    }
}
