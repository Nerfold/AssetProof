use ark_bls12_381::{g1, Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    pairing::Pairing,
    AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM,
};
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_ff::{PrimeField, Zero};
use sha2::Sha256;

use common::crypto::{g1_mul_generator, g2_mul_generator, hash_to_scalar};

use crate::polynomial::Polynomial;

#[derive(Clone, Debug)]
pub struct Srs {
    pub max_degree: usize,
    pub tau_g1_powers: Vec<G1Affine>,
    pub tau_g2_powers: Vec<G2Affine>,
    pub hiding_tau_g1_powers: Vec<G1Affine>,
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
        let hiding_base = hiding_base().expect("hash-to-curve for hiding KZG base");
        let mut hiding_tau_g1_powers = Vec::with_capacity(max_degree + 1);
        for _ in 0..=max_degree {
            tau_g1_powers.push(g1_mul_generator(&tau_power).into_affine());
            tau_g2_powers.push(g2_mul_generator(&tau_power).into_affine());
            hiding_tau_g1_powers.push(
                hiding_base
                    .mul_bigint(tau_power.into_bigint())
                    .into_affine(),
            );
            tau_power *= tau;
        }

        Self {
            max_degree,
            tau_g1_powers,
            tau_g2_powers,
            hiding_tau_g1_powers,
        }
    }
}

fn hiding_base() -> Result<G1Projective, String> {
    let hasher = MapToCurveBasedHasher::<
        G1Projective,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<g1::Config>,
    >::new(b"DPOA_HPOLYCOM_BLS12381G1_XMD:SHA-256_SSWU_RO_V1")
    .map_err(|err| format!("initialize hiding base hash-to-curve: {err}"))?;
    Ok(hasher
        .hash(b"dynamic-poa-hpolycom-independent-base-v1")
        .map_err(|err| format!("derive hiding base: {err}"))?
        .into_group())
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

pub fn open(srs: &Srs, poly: &Polynomial, point: Fr, value: Fr) -> Result<G1Projective, String> {
    let divisor = Polynomial::from_coeffs(vec![-point, Fr::from(1u64)]);
    let quotient = poly.sub(&Polynomial::constant(value)).div_exact(&divisor)?;
    commit_g1(srs, &quotient)
}

pub fn verify_open(
    srs: &Srs,
    commitment: &G1Projective,
    point: Fr,
    value: Fr,
    proof: &G1Projective,
) -> Result<bool, String> {
    if srs.tau_g2_powers.len() < 2 {
        return Err("SRS must contain tau^1 G2 power for KZG opening".to_string());
    }
    let value_g1 = G1Projective::generator().mul_bigint(value.into_bigint());
    let tau_minus_point = G2Projective::from(srs.tau_g2_powers[1])
        - G2Projective::generator().mul_bigint(point.into_bigint());
    Ok(Bls12_381::pairing(
        (*commitment - value_g1).into_affine(),
        G2Affine::generator(),
    ) == Bls12_381::pairing(proof.into_affine(), tau_minus_point.into_affine()))
}

pub fn verify_batch_many(
    accumulators: &[G1Projective],
    c_y_values: &[G1Projective],
    eval_proofs: &[G1Projective],
    z_commit_g2: &G2Projective,
    transcript_seed: &[u8],
) -> Result<bool, String> {
    if accumulators.len() != c_y_values.len() || accumulators.len() != eval_proofs.len() {
        return Err("KZG batch vector length mismatch".to_string());
    }
    if accumulators.is_empty() {
        return Err("KZG batch must contain at least one opening".to_string());
    }

    let mut lhs = G1Projective::zero();
    let mut rhs = G1Projective::zero();
    for index in 0..accumulators.len() {
        let beta = batch_randomizer(transcript_seed, index);
        lhs += (accumulators[index] - c_y_values[index]).mul_bigint(beta.into_bigint());
        rhs += eval_proofs[index].mul_bigint(beta.into_bigint());
    }

    Ok(Bls12_381::pairing(lhs.into_affine(), G2Affine::generator())
        == Bls12_381::pairing(rhs.into_affine(), z_commit_g2.into_affine()))
}

fn batch_randomizer(seed: &[u8], index: usize) -> Fr {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"dynamic-poa-parallel-kzg-batch");
    hasher.update(seed);
    hasher.update(&(index as u64).to_le_bytes());
    let mut beta = Fr::from_le_bytes_mod_order(hasher.finalize().as_bytes());
    if beta.is_zero() {
        beta = Fr::from((index as u64) + 1);
    }
    beta
}
