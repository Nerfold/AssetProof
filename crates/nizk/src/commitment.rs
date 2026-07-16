use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    AffineRepr, PrimeGroup, VariableBaseMSM,
};
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_ff::PrimeField;
use sha2::Sha256;

type PedersenHasher = MapToCurveBasedHasher<
    G1Projective,
    DefaultFieldHasher<Sha256, 128>,
    WBMap<ark_bls12_381::g1::Config>,
>;

pub fn derive_generator(label: &str, index: usize) -> G1Projective {
    let mut guard = generator_cache().lock().expect("generator cache poisoned");
    let entry = Arc::make_mut(
        guard
            .entry(label.to_string())
            .or_insert_with(|| Arc::new(Vec::new())),
    );
    while entry.len() <= index {
        entry.push(derive_generator_affine_uncached(label, entry.len()));
    }
    entry[index].into_group()
}

fn derive_generator_affine_uncached(label: &str, index: usize) -> G1Affine {
    // Transparent Pedersen CRS: each base is independently hash-to-curve derived
    // with the IETF BLS12-381 G1 XMD:SHA-256 SSWU random-oracle suite. Unlike the
    // previous `hash_to_scalar(...) * G` construction, no discrete-log relation
    // between bases is known.
    let message = format!("{label}\0{index}");
    pedersen_hasher()
        .hash(message.as_bytes())
        .expect("Pedersen CRS hash-to-curve must succeed")
}

fn pedersen_hasher() -> &'static PedersenHasher {
    static HASHER: OnceLock<PedersenHasher> = OnceLock::new();
    HASHER.get_or_init(|| {
        PedersenHasher::new(b"DPOA_PEDERSEN_CRS_BLS12381G1_XMD:SHA-256_SSWU_RO_V1")
            .expect("valid Pedersen CRS hash-to-curve domain")
    })
}

fn generator_cache() -> &'static Mutex<HashMap<String, Arc<Vec<G1Affine>>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Arc<Vec<G1Affine>>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn generator_window(label: &str, len: usize) -> Arc<Vec<G1Affine>> {
    let mut guard = generator_cache().lock().expect("generator cache poisoned");
    let entry = guard
        .entry(label.to_string())
        .or_insert_with(|| Arc::new(Vec::new()));
    if entry.len() < len {
        let values = Arc::make_mut(entry);
        for index in values.len()..len {
            values.push(derive_generator_affine_uncached(label, index));
        }
    }
    Arc::clone(entry)
}

pub fn commit_linear(values: &[Fr], label: &str, blind_label: &str, blind: Fr) -> G1Projective {
    let bases = generator_window(label, values.len());
    G1Projective::msm_unchecked(&bases[..values.len()], values)
        + derive_generator(blind_label, 0).mul_bigint(blind.into_bigint())
}

pub fn commit_balance(value: i128, blind: Fr) -> G1Projective {
    let (v, h) = balance_generators();
    acc_balance(value, *v, blind, *h)
}

pub fn balance_generators() -> &'static (G1Projective, G1Projective) {
    static GENERATORS: OnceLock<(G1Projective, G1Projective)> = OnceLock::new();
    GENERATORS.get_or_init(|| {
        (
            derive_generator("balance-v", 0),
            derive_generator("balance-h", 0),
        )
    })
}

pub fn eval_generators() -> &'static (G1Projective, G1Projective) {
    static GENERATORS: OnceLock<(G1Projective, G1Projective)> = OnceLock::new();
    GENERATORS.get_or_init(|| (derive_generator("eval-v", 0), derive_generator("eval-h", 0)))
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
