use ark_bls12_381::{g1, Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    pairing::Pairing,
    AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM,
};
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_ff::{PrimeField, UniformRand, Zero};
use sha2::Sha256;

use common::crypto::{g1_mul_generator, g2_mul_generator, hash_to_scalar};

use crate::polynomial::Polynomial;

#[derive(Clone, Debug)]
pub struct Srs {
    pub max_degree: usize,
    pub tau_g1_powers: Vec<G1Affine>,
    pub tau_g2_powers: Vec<G2Affine>,
    pub hiding_tau_g1_powers: Vec<G1Affine>,
    pub provenance: SrsProvenance,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SrsProvenance {
    Development,
    ExternalCeremony { ceremony_id: String },
}

impl Srs {
    #[deprecated(
        note = "insecure deterministic setup; use setup_development only for tests or import an external ceremony SRS"
    )]
    pub fn setup(max_degree: usize, seed: &[u8]) -> Self {
        Self::setup_development(max_degree, seed)
    }

    pub fn setup_development(max_degree: usize, seed: &[u8]) -> Self {
        let powers_len = max_degree
            .checked_add(1)
            .expect("development SRS max_degree is too large");
        let mut tau = hash_to_scalar("srs-tau", seed);
        if tau.is_zero() {
            tau = Fr::from(7u64);
        }

        let mut tau_power = Fr::from(1u64);
        let mut tau_g1_powers = Vec::with_capacity(powers_len);
        let mut tau_g2_powers = Vec::with_capacity(powers_len);
        let hiding_base = hiding_base().expect("hash-to-curve for hiding KZG base");
        let mut hiding_tau_g1_powers = Vec::with_capacity(powers_len);
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
            provenance: SrsProvenance::Development,
        }
    }

    pub fn from_external_ceremony(
        max_degree: usize,
        tau_g1_powers: Vec<G1Affine>,
        tau_g2_powers: Vec<G2Affine>,
        hiding_tau_g1_powers: Vec<G1Affine>,
        ceremony_id: impl Into<String>,
    ) -> Result<Self, String> {
        let ceremony_id = ceremony_id.into();
        if ceremony_id.trim().is_empty() {
            return Err("external KZG ceremony id must not be empty".to_string());
        }
        if ceremony_id.len() > 256
            || !ceremony_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
        {
            return Err("external KZG ceremony id contains unsupported characters".to_string());
        }
        let srs = Self {
            max_degree,
            tau_g1_powers,
            tau_g2_powers,
            hiding_tau_g1_powers,
            provenance: SrsProvenance::ExternalCeremony { ceremony_id },
        };
        srs.validate_complete_structure()?;
        Ok(srs)
    }

    pub fn validate_structure(&self) -> Result<(), String> {
        if self.max_degree == 0 {
            return Err("KZG SRS max_degree must be greater than zero".to_string());
        }
        if self.tau_g1_powers.len() < 2 || self.tau_g2_powers.len() < 2 {
            return Err("KZG SRS must contain tau^0 and tau^1 in both groups".to_string());
        }
        let expected_len = self
            .max_degree
            .checked_add(1)
            .ok_or_else(|| "KZG SRS max_degree overflow".to_string())?;
        if self.tau_g1_powers.len() > expected_len
            || self.tau_g2_powers.len() > expected_len
            || self.hiding_tau_g1_powers.len() > expected_len
        {
            return Err("loaded KZG SRS prefix exceeds its declared max_degree".to_string());
        }
        if self.tau_g1_powers.iter().any(|point| point.is_zero())
            || self.tau_g2_powers.iter().any(|point| point.is_zero())
            || self
                .hiding_tau_g1_powers
                .iter()
                .any(|point| point.is_zero())
        {
            return Err("KZG SRS must not contain identity points".to_string());
        }
        if self.tau_g1_powers[0] != G1Affine::generator()
            || self.tau_g2_powers[0] != G2Affine::generator()
        {
            return Err("KZG SRS tau^0 powers are not the standard generators".to_string());
        }
        if !self.hiding_tau_g1_powers.is_empty()
            && self.hiding_tau_g1_powers[0] != hiding_base()?.into_affine()
        {
            return Err("HPolyCom SRS uses an unexpected independent hiding base".to_string());
        }

        let mut rng = rand::rngs::OsRng;
        let mut challenge = Fr::rand(&mut rng);
        while challenge.is_zero() {
            challenge = Fr::rand(&mut rng);
        }
        validate_g1_power_sequence(
            &self.tau_g1_powers,
            challenge,
            self.tau_g2_powers[0],
            self.tau_g2_powers[1],
            "ordinary G1",
        )?;
        if self.tau_g2_powers.len() > 1 {
            validate_g2_power_sequence(
                &self.tau_g2_powers,
                challenge,
                self.tau_g1_powers[0],
                self.tau_g1_powers[1],
            )?;
        }
        if self.hiding_tau_g1_powers.len() > 1 {
            validate_g1_power_sequence(
                &self.hiding_tau_g1_powers,
                challenge,
                self.tau_g2_powers[0],
                self.tau_g2_powers[1],
                "hiding G1",
            )?;
        }
        Ok(())
    }

    pub fn validate_complete_structure(&self) -> Result<(), String> {
        let expected_len = self
            .max_degree
            .checked_add(1)
            .ok_or_else(|| "KZG SRS max_degree overflow".to_string())?;
        if self.tau_g1_powers.len() != expected_len
            || self.tau_g2_powers.len() != expected_len
            || self.hiding_tau_g1_powers.len() != expected_len
        {
            return Err(format!(
                "complete extended KZG SRS for degree {} must contain exactly {} ordinary G1, G2, and hiding G1 powers",
                self.max_degree, expected_len
            ));
        }
        self.validate_structure()
    }

    pub fn require_external_ceremony(&self) -> Result<(), String> {
        self.validate_structure()?;
        match &self.provenance {
            SrsProvenance::ExternalCeremony { ceremony_id } if !ceremony_id.trim().is_empty() => {
                Ok(())
            }
            _ => Err(
                "production verification requires an externally generated KZG ceremony SRS"
                    .to_string(),
            ),
        }
    }
}

fn challenge_powers(challenge: Fr, len: usize) -> Vec<Fr> {
    let mut current = Fr::from(1u64);
    (0..len)
        .map(|_| {
            let result = current;
            current *= challenge;
            result
        })
        .collect()
}

fn validate_g1_power_sequence(
    powers: &[G1Affine],
    challenge: Fr,
    g2_zero: G2Affine,
    g2_one: G2Affine,
    label: &str,
) -> Result<(), String> {
    if powers.len() < 2 {
        return Ok(());
    }
    let scalars = challenge_powers(challenge, powers.len() - 1);
    let next = G1Projective::msm_unchecked(&powers[1..], &scalars);
    let previous = G1Projective::msm_unchecked(&powers[..powers.len() - 1], &scalars);
    if Bls12_381::pairing(next.into_affine(), g2_zero)
        != Bls12_381::pairing(previous.into_affine(), g2_one)
    {
        return Err(format!("inconsistent {label} KZG powers"));
    }
    Ok(())
}

fn validate_g2_power_sequence(
    powers: &[G2Affine],
    challenge: Fr,
    g1_zero: G1Affine,
    g1_one: G1Affine,
) -> Result<(), String> {
    let scalars = challenge_powers(challenge, powers.len() - 1);
    let next = G2Projective::msm_unchecked(&powers[1..], &scalars);
    let previous = G2Projective::msm_unchecked(&powers[..powers.len() - 1], &scalars);
    if Bls12_381::pairing(g1_zero, next.into_affine())
        != Bls12_381::pairing(g1_one, previous.into_affine())
    {
        return Err("inconsistent G2 KZG powers".to_string());
    }
    Ok(())
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
    if poly.coeffs.len() > srs.tau_g1_powers.len() {
        return Err(format!(
            "polynomial requires {} G1 powers but the loaded SRS contains {}",
            poly.coeffs.len(),
            srs.tau_g1_powers.len()
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
    if poly.coeffs.len() > srs.tau_g2_powers.len() {
        return Err(format!(
            "polynomial requires {} G2 powers but the loaded SRS contains {}",
            poly.coeffs.len(),
            srs.tau_g2_powers.len()
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

#[cfg(test)]
mod srs_validation_tests {
    use ark_bls12_381::G1Affine;
    use ark_ec::AffineRepr;

    use super::{Srs, SrsProvenance};

    #[test]
    fn development_srs_is_structurally_valid_but_not_production_trusted() {
        let srs = Srs::setup_development(8, b"srs-validation-test");
        srs.validate_structure().unwrap();
        assert_eq!(srs.provenance, SrsProvenance::Development);
        assert!(srs.require_external_ceremony().is_err());
    }

    #[test]
    fn validation_rejects_inconsistent_power_sequence() {
        let mut srs = Srs::setup_development(8, b"srs-validation-tamper");
        srs.tau_g1_powers[2] = G1Affine::generator();
        assert!(srs.validate_structure().is_err());
    }
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
