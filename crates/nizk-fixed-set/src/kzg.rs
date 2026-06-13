use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::Zero;

use common::crypto::{g1_mul_generator, g2_mul_generator, hash_to_scalar};

use crate::polynomial::Polynomial;

#[derive(Clone, Debug)]
pub struct Srs {
    pub max_degree: usize,
    pub tau: Fr,
    pub tau_g1_powers: Vec<G1Affine>,
    pub tau_g2_powers: Vec<G2Affine>,
}

impl Srs {
    pub fn setup(max_degree: usize, seed: &[u8]) -> Self {
        let mut tau = hash_to_scalar("srs-tau", seed);
        if tau.is_zero() {
            tau = Fr::from(7u64);
        }

        let mut tau_power = Fr::from(1u64);
        let mut tau_g1_powers = Vec::with_capacity(max_degree + 1);
        let mut tau_g2_powers = Vec::with_capacity(max_degree + 1);
        for _ in 0..=max_degree {
            tau_g1_powers.push(g1_mul_generator(&tau_power).into_affine());
            tau_g2_powers.push(g2_mul_generator(&tau_power).into_affine());
            tau_power *= tau;
        }

        Self {
            max_degree,
            tau,
            tau_g1_powers,
            tau_g2_powers,
        }
    }
}

pub fn commit_g1(srs: &Srs, poly: &Polynomial) -> Result<G1Projective, String> {
    if poly.degree() > srs.max_degree {
        return Err(format!(
            "polynomial degree {} exceeds SRS max degree {}",
            poly.degree(),
            srs.max_degree
        ));
    }
    Ok(G1Projective::msm_unchecked(
        &srs.tau_g1_powers[..poly.coeffs.len()],
        &poly.coeffs,
    ))
}

pub fn commit_g2(srs: &Srs, poly: &Polynomial) -> Result<G2Projective, String> {
    if poly.degree() > srs.max_degree {
        return Err(format!(
            "polynomial degree {} exceeds SRS max degree {}",
            poly.degree(),
            srs.max_degree
        ));
    }
    Ok(G2Projective::msm_unchecked(
        &srs.tau_g2_powers[..poly.coeffs.len()],
        &poly.coeffs,
    ))
}

pub fn verify_batch(
    accumulator: &G1Projective,
    c_y: &G1Projective,
    eval_proof: &G1Projective,
    z_commit_g2: &G2Projective,
) -> bool {
    let lhs = Bls12_381::pairing((*accumulator - *c_y).into_affine(), G2Affine::generator());
    let rhs = Bls12_381::pairing(eval_proof.into_affine(), z_commit_g2.into_affine());
    lhs == rhs
}
