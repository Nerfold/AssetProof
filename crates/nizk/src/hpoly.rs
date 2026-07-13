use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::{PrimeField, UniformRand, Zero};

use common::crypto::{point_g1_from_hex, point_g1_to_hex, scalar_from_hex, scalar_to_hex};

use crate::kzg::Srs;
use crate::polynomial::Polynomial;
use crate::zkopen::eval_commit;

#[derive(Clone, Debug)]
pub struct HidingPolynomialCommitment {
    pub commitment: G1Projective,
    pub blinding_polynomial: Polynomial,
    pub degree_bound: usize,
}

#[derive(Clone, Debug)]
struct HidingOpeningProof {
    a_p_hex: String,
    a_c_hex: String,
    s_y: Fr,
    s_eval_blind: Fr,
    s_hiding_eval: Fr,
    pi_hex: String,
}

pub fn commit_hiding_polynomial(
    srs: &Srs,
    polynomial: &Polynomial,
    degree_bound: usize,
) -> Result<HidingPolynomialCommitment, String> {
    ensure_hiding_srs(srs, degree_bound)?;
    if polynomial.degree() > degree_bound {
        return Err(format!(
            "hiding polynomial degree {} exceeds bound {degree_bound}",
            polynomial.degree()
        ));
    }
    let mut rng = rand::rngs::OsRng;
    let blinding_polynomial =
        Polynomial::from_coeffs((0..=degree_bound).map(|_| Fr::rand(&mut rng)).collect());
    let commitment = commit_pair(srs, polynomial, &blinding_polynomial, degree_bound)?;
    Ok(HidingPolynomialCommitment {
        commitment,
        blinding_polynomial,
        degree_bound,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn prove_hiding_committed_opening(
    srs: &Srs,
    polynomial_commitment_hex: &str,
    zeta: Fr,
    value_commitment_hex: &str,
    value: Fr,
    value_blind: Fr,
    polynomial: &Polynomial,
    hiding: &HidingPolynomialCommitment,
    domain: &str,
) -> Result<String, String> {
    ensure_hiding_srs(srs, hiding.degree_bound)?;
    let polynomial_commitment = point_g1_from_hex(polynomial_commitment_hex)?;
    let value_commitment = point_g1_from_hex(value_commitment_hex)?;
    if value_commitment != eval_commit(value, value_blind) {
        return Err("HZKOpen value commitment opening mismatch".to_string());
    }
    if polynomial_commitment != hiding.commitment {
        return Err("HPolyCom commitment does not match opening witness".to_string());
    }
    if polynomial.evaluate(zeta) != value {
        return Err("HZKOpen claimed value is not the polynomial evaluation".to_string());
    }
    let recomputed = commit_pair(
        srs,
        polynomial,
        &hiding.blinding_polynomial,
        hiding.degree_bound,
    )?;
    if recomputed != polynomial_commitment {
        return Err("HPolyCom polynomial witness does not match commitment".to_string());
    }

    let hiding_eval = hiding.blinding_polynomial.evaluate(zeta);
    let divisor = Polynomial::from_coeffs(vec![-zeta, Fr::from(1u64)]);
    let value_quotient = polynomial
        .sub(&Polynomial::constant(value))
        .div_exact(&divisor)?;
    let hiding_quotient = hiding
        .blinding_polynomial
        .sub(&Polynomial::constant(hiding_eval))
        .div_exact(&divisor)?;
    let opening = commit_pair(
        srs,
        &value_quotient,
        &hiding_quotient,
        hiding.degree_bound.saturating_sub(1),
    )?;

    let mut rng = rand::rngs::OsRng;
    let a = Fr::rand(&mut rng);
    let b = Fr::rand(&mut rng);
    let d = Fr::rand(&mut rng);
    let t = Fr::rand(&mut rng);
    let h = G1Projective::from(srs.hiding_tau_g1_powers[0]);
    let d_z = g1_denominator(srs, zeta)?;
    let a_p = eval_commit(a, b);
    let a_c = G1Projective::generator().mul_bigint(a.into_bigint())
        + h.mul_bigint(d.into_bigint())
        + d_z.mul_bigint(t.into_bigint());
    let challenge = challenge(
        srs,
        domain,
        hiding.degree_bound,
        polynomial_commitment_hex,
        zeta,
        value_commitment_hex,
        &a_p,
        &a_c,
    )?;
    let proof = HidingOpeningProof {
        a_p_hex: point_g1_to_hex(&a_p)?,
        a_c_hex: point_g1_to_hex(&a_c)?,
        s_y: a + challenge * value,
        s_eval_blind: b + challenge * value_blind,
        s_hiding_eval: d + challenge * hiding_eval,
        pi_hex: point_g1_to_hex(
            &(G1Projective::generator().mul_bigint(t.into_bigint())
                + opening.mul_bigint(challenge.into_bigint())),
        )?,
    };
    encode_proof(&proof)
}

pub fn verify_hiding_committed_opening(
    srs: &Srs,
    polynomial_commitment_hex: &str,
    zeta: Fr,
    value_commitment_hex: &str,
    degree_bound: usize,
    proof_hex: &str,
    domain: &str,
) -> Result<(), String> {
    ensure_hiding_srs(srs, degree_bound)?;
    let polynomial_commitment = point_g1_from_hex(polynomial_commitment_hex)?;
    let value_commitment = point_g1_from_hex(value_commitment_hex)?;
    if polynomial_commitment.is_zero() || value_commitment.is_zero() {
        return Err("HZKOpen commitments must be non-zero".to_string());
    }
    let proof = decode_proof(proof_hex)?;
    let a_p = point_g1_from_hex(&proof.a_p_hex)?;
    let a_c = point_g1_from_hex(&proof.a_c_hex)?;
    let pi = point_g1_from_hex(&proof.pi_hex)?;
    let challenge = challenge(
        srs,
        domain,
        degree_bound,
        polynomial_commitment_hex,
        zeta,
        value_commitment_hex,
        &a_p,
        &a_c,
    )?;

    if eval_commit(proof.s_y, proof.s_eval_blind)
        != a_p + value_commitment.mul_bigint(challenge.into_bigint())
    {
        return Err("HZKOpen scalar commitment equation failed".to_string());
    }
    let h = G1Projective::from(srs.hiding_tau_g1_powers[0]);
    let lhs_g1 = a_c + polynomial_commitment.mul_bigint(challenge.into_bigint())
        - G1Projective::generator().mul_bigint(proof.s_y.into_bigint())
        - h.mul_bigint(proof.s_hiding_eval.into_bigint());
    let lhs = Bls12_381::pairing(lhs_g1.into_affine(), G2Affine::generator());
    let rhs = Bls12_381::pairing(pi.into_affine(), g2_denominator(srs, zeta)?.into_affine());
    if lhs != rhs {
        return Err("HZKOpen hiding KZG equation failed".to_string());
    }
    Ok(())
}

fn commit_pair(
    srs: &Srs,
    value: &Polynomial,
    hiding: &Polynomial,
    degree_bound: usize,
) -> Result<G1Projective, String> {
    ensure_hiding_srs(srs, degree_bound)?;
    if value.degree() > degree_bound || hiding.degree() > degree_bound {
        return Err("HPolyCom witness exceeds degree bound".to_string());
    }
    Ok(
        G1Projective::msm_unchecked(&srs.tau_g1_powers[..value.coeffs.len()], &value.coeffs)
            + G1Projective::msm_unchecked(
                &srs.hiding_tau_g1_powers[..hiding.coeffs.len()],
                &hiding.coeffs,
            ),
    )
}

fn ensure_hiding_srs(srs: &Srs, degree_bound: usize) -> Result<(), String> {
    let needed = degree_bound + 1;
    if srs.tau_g1_powers.len() < needed || srs.hiding_tau_g1_powers.len() < needed {
        return Err(format!(
            "HPolyCom requires {needed} ordinary and independent hiding G1 SRS powers"
        ));
    }
    if srs.tau_g2_powers.len() < 2 {
        return Err("HPolyCom requires tau^0 and tau^1 G2 SRS powers".to_string());
    }
    if srs.hiding_tau_g1_powers[0].is_zero() {
        return Err("HPolyCom hiding base must be non-zero".to_string());
    }
    Ok(())
}

fn g1_denominator(srs: &Srs, zeta: Fr) -> Result<G1Projective, String> {
    let value = G1Projective::from(srs.tau_g1_powers[1])
        - G1Projective::generator().mul_bigint(zeta.into_bigint());
    if value.is_zero() {
        return Err("HZKOpen evaluation point equals KZG trapdoor".to_string());
    }
    Ok(value)
}

fn g2_denominator(srs: &Srs, zeta: Fr) -> Result<G2Projective, String> {
    let value = G2Projective::from(srs.tau_g2_powers[1])
        - G2Projective::generator().mul_bigint(zeta.into_bigint());
    if value.is_zero() {
        return Err("HZKOpen evaluation point equals KZG trapdoor".to_string());
    }
    Ok(value)
}

#[allow(clippy::too_many_arguments)]
fn challenge(
    srs: &Srs,
    domain: &str,
    degree_bound: usize,
    polynomial_commitment_hex: &str,
    zeta: Fr,
    value_commitment_hex: &str,
    a_p: &G1Projective,
    a_c: &G1Projective,
) -> Result<Fr, String> {
    let fields = [
        domain.to_string(),
        srs.max_degree.to_string(),
        degree_bound.to_string(),
        common::crypto::serialize_hex(&srs.tau_g1_powers[1])?,
        common::crypto::serialize_hex(&srs.tau_g2_powers[1])?,
        common::crypto::serialize_hex(&srs.hiding_tau_g1_powers[0])?,
        polynomial_commitment_hex.to_string(),
        scalar_to_hex(&zeta)?,
        value_commitment_hex.to_string(),
        point_g1_to_hex(a_p)?,
        point_g1_to_hex(a_c)?,
    ];
    Ok(common::crypto::hash_to_scalar(
        "dynamic-poa-hzkopen-sigma-challenge-v1",
        fields.join("|").as_bytes(),
    ))
}

fn encode_proof(proof: &HidingOpeningProof) -> Result<String, String> {
    Ok(format!(
        "hzkopen:v1:{}:{}:{}:{}:{}:{}",
        proof.a_p_hex,
        proof.a_c_hex,
        scalar_to_hex(&proof.s_y)?,
        scalar_to_hex(&proof.s_eval_blind)?,
        scalar_to_hex(&proof.s_hiding_eval)?,
        proof.pi_hex,
    ))
}

fn decode_proof(raw: &str) -> Result<HidingOpeningProof, String> {
    let parts = raw.split(':').collect::<Vec<_>>();
    if parts.len() != 8 || parts[0] != "hzkopen" || parts[1] != "v1" {
        return Err("invalid HZKOpen proof encoding".to_string());
    }
    Ok(HidingOpeningProof {
        a_p_hex: parts[2].to_string(),
        a_c_hex: parts[3].to_string(),
        s_y: scalar_from_hex(parts[4])?,
        s_eval_blind: scalar_from_hex(parts[5])?,
        s_hiding_eval: scalar_from_hex(parts[6])?,
        pi_hex: parts[7].to_string(),
    })
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;

    use super::{
        commit_hiding_polynomial, decode_proof, encode_proof, prove_hiding_committed_opening,
        verify_hiding_committed_opening,
    };
    use crate::kzg::{commit_g1, Srs};
    use crate::polynomial::Polynomial;
    use crate::zkopen::eval_commit;
    use common::crypto::point_g1_to_hex;

    #[test]
    fn hpoly_commitment_hides_polynomial_and_hzkopen_verifies() {
        let srs = Srs::setup(8, b"hpoly-test-srs");
        let polynomial =
            Polynomial::from_coeffs(vec![Fr::from(2u64), Fr::from(5u64), Fr::from(7u64)]);
        let hiding = commit_hiding_polynomial(&srs, &polynomial, 4).unwrap();
        let hiding_again = commit_hiding_polynomial(&srs, &polynomial, 4).unwrap();
        assert_ne!(hiding.commitment, hiding_again.commitment);
        assert_ne!(hiding.commitment, commit_g1(&srs, &polynomial).unwrap());

        let zeta = Fr::from(13u64);
        let value = polynomial.evaluate(zeta);
        let value_blind = Fr::from(17u64);
        let value_commitment = eval_commit(value, value_blind);
        let commitment_hex = point_g1_to_hex(&hiding.commitment).unwrap();
        let value_commitment_hex = point_g1_to_hex(&value_commitment).unwrap();
        let proof = prove_hiding_committed_opening(
            &srs,
            &commitment_hex,
            zeta,
            &value_commitment_hex,
            value,
            value_blind,
            &polynomial,
            &hiding,
            "hpoly-test-domain",
        )
        .unwrap();
        assert!(proof.starts_with("hzkopen:v1:"));
        verify_hiding_committed_opening(
            &srs,
            &commitment_hex,
            zeta,
            &value_commitment_hex,
            4,
            &proof,
            "hpoly-test-domain",
        )
        .unwrap();

        let mut tampered = decode_proof(&proof).unwrap();
        tampered.s_hiding_eval += Fr::from(1u64);
        assert!(verify_hiding_committed_opening(
            &srs,
            &commitment_hex,
            zeta,
            &value_commitment_hex,
            4,
            &encode_proof(&tampered).unwrap(),
            "hpoly-test-domain",
        )
        .is_err());
        assert!(verify_hiding_committed_opening(
            &srs,
            &commitment_hex,
            zeta,
            &value_commitment_hex,
            3,
            &proof,
            "hpoly-test-domain",
        )
        .is_err());
    }

    #[test]
    fn hpoly_rejects_srs_without_independent_hiding_powers() {
        let mut srs = Srs::setup(4, b"hpoly-missing-srs");
        srs.hiding_tau_g1_powers.clear();
        let polynomial = Polynomial::from_coeffs(vec![Fr::from(1u64)]);
        assert!(commit_hiding_polynomial(&srs, &polynomial, 1).is_err());
    }
}
