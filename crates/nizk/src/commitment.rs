use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM,
};
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_ff::PrimeField;
use sha2::Sha256;

pub fn derive_generator(label: &str, index: usize) -> G1Projective {
    // Transparent Pedersen CRS: each base is independently hash-to-curve derived
    // with the IETF BLS12-381 G1 XMD:SHA-256 SSWU random-oracle suite. Unlike the
    // previous `hash_to_scalar(...) * G` construction, no discrete-log relation
    // between bases is known.
    let hasher = MapToCurveBasedHasher::<
        G1Projective,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<ark_bls12_381::g1::Config>,
    >::new(b"DPOA_PEDERSEN_CRS_BLS12381G1_XMD:SHA-256_SSWU_RO_V1")
    .expect("valid Pedersen CRS hash-to-curve domain");
    let message = format!("{label}\0{index}");
    hasher
        .hash(message.as_bytes())
        .expect("Pedersen CRS hash-to-curve must succeed")
        .into_group()
}

fn derive_generator_affine(label: &str, index: usize) -> G1Affine {
    derive_generator(label, index).into_affine()
}

fn generator_cache() -> &'static Mutex<HashMap<String, Vec<G1Affine>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Vec<G1Affine>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn generator_window(label: &str, len: usize) -> Vec<G1Affine> {
    let mut guard = generator_cache().lock().expect("generator cache poisoned");
    let entry = guard.entry(label.to_string()).or_default();
    if entry.len() < len {
        for index in entry.len()..len {
            entry.push(derive_generator_affine(label, index));
        }
    }
    entry[..len].to_vec()
}

pub fn commit_linear(values: &[Fr], label: &str, blind_label: &str, blind: Fr) -> G1Projective {
    let bases = generator_window(label, values.len());
    G1Projective::msm_unchecked(&bases, values)
        + derive_generator(blind_label, 0).mul_bigint(blind.into_bigint())
}

pub fn commit_balance(value: i128, blind: Fr) -> G1Projective {
    let v = derive_generator("balance-v", 0);
    let h = derive_generator("balance-h", 0);
    acc_balance(value, v, blind, h)
}

#[cfg(test)]
mod tests {
    use super::derive_generator;

    #[test]
    fn transparent_crs_is_deterministic_and_domain_separated() {
        let value_0 = derive_generator("balance-v", 0);
        assert_eq!(value_0, derive_generator("balance-v", 0));
        assert_ne!(value_0, derive_generator("balance-h", 0));
        assert_ne!(value_0, derive_generator("balance-v", 1));
    }
}

pub fn acc_balance(value: i128, v: G1Projective, blind: Fr, h: G1Projective) -> G1Projective {
    v.mul_bigint(common::crypto::scalar_from_i128(value).into_bigint())
        + h.mul_bigint(blind.into_bigint())
}
