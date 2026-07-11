use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::PrimeField;

use common::crypto::{g1_mul_generator, hash_to_scalar};

pub fn derive_generator(label: &str, index: usize) -> G1Projective {
    // Demo CRS derivation. Production deployments must replace this with
    // independently generated CRS points whose discrete-log relations are unknown.
    let scalar = hash_to_scalar(label, index.to_string().as_bytes());
    g1_mul_generator(&scalar)
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

pub fn acc_balance(value: i128, v: G1Projective, blind: Fr, h: G1Projective) -> G1Projective {
    v.mul_bigint(common::crypto::scalar_from_i128(value).into_bigint())
        + h.mul_bigint(blind.into_bigint())
}
