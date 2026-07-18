use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::io::Cursor;
use std::sync::{Mutex, OnceLock};

use common::crypto::{hex_decode, hex_encode};

use crate::commitment::derive_generator;
use crate::kzg::{commit_g1, commit_g2, Srs};
use crate::polynomial::QueryContext;

const PROOF_VERSION: u8 = 1;
const CHALLENGE_DOMAIN: &[u8] = b"dynamic-poa-multizkopen-fs-v1";
const GENERATOR_ID: &[u8] = b"dynamic-poa-update-y-vector-crs-v1";

static Y_GENERATORS: OnceLock<Mutex<Vec<G1Projective>>> = OnceLock::new();
static Y_BLINDING_GENERATOR: OnceLock<G1Projective> = OnceLock::new();

#[derive(Clone, Debug)]
pub struct MultiZkOpenProof {
    pub t_p: G1Projective,
    pub t_k: G1Projective,
    pub s_values: Vec<Fr>,
    pub s_blind: Fr,
    pub pi_response: G1Projective,
}

/// Commits to the complete evaluation vector. This is the single public
/// commitment shared by MultiZKOpen and the Bulletproof relation.
pub fn commit_evaluation_vector(values: &[Fr], blind: Fr) -> Result<G1Projective, String> {
    if values.is_empty() {
        return Err("evaluation vector commitment must not be empty".to_string());
    }
    let generators = evaluation_generators(values.len());
    let affine = G1Projective::normalize_batch(&generators);
    Ok(G1Projective::msm_unchecked(&affine, values)
        + evaluation_blinding_generator().mul_bigint(blind.into_bigint()))
}

pub(crate) fn evaluation_generators(len: usize) -> Vec<G1Projective> {
    let cache = Y_GENERATORS.get_or_init(|| Mutex::new(Vec::new()));
    let mut cache = cache.lock().expect("evaluation generator cache poisoned");
    while cache.len() < len {
        let index = cache.len();
        cache.push(derive_generator("update-y-vector", index));
    }
    cache[..len].to_vec()
}

pub(crate) fn evaluation_blinding_generator() -> G1Projective {
    *Y_BLINDING_GENERATOR.get_or_init(|| derive_generator("update-y-vector-blind", 0))
}

#[allow(clippy::too_many_arguments)]
pub fn prove_multi_zkopen(
    srs: &Srs,
    accumulator: &G1Projective,
    points: &[Fr],
    values: &[Fr],
    d_y: &G1Projective,
    r_y: Fr,
    batch_opening: &G1Projective,
    context: &[u8],
) -> Result<String, String> {
    if points.is_empty() || points.len() != values.len() {
        return Err("MultiZKOpen point/value length mismatch".to_string());
    }
    let query = QueryContext::new(points)?;
    if commit_evaluation_vector(values, r_y)? != *d_y {
        return Err("MultiZKOpen D_Y opening mismatch".to_string());
    }

    let mut rng = rand::rngs::OsRng;
    let masks = (0..values.len())
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();
    let b = Fr::rand(&mut rng);
    let t = Fr::rand(&mut rng);
    let a_poly = query.interpolate(&masks)?;
    let masked_poly = a_poly.add_scaled(query.z_poly(), t);
    let t_p = commit_evaluation_vector(&masks, b)?;
    let t_k = commit_g1(srs, &masked_poly)?;
    let challenge = challenge(srs, accumulator, d_y, points, &t_p, &t_k, context)?;
    let s_values = masks
        .iter()
        .zip(values)
        .map(|(a, y)| *a + challenge * y)
        .collect::<Vec<_>>();
    let s_blind = b + challenge * r_y;
    let pi_response = G1Projective::generator().mul_bigint(t.into_bigint())
        + batch_opening.mul_bigint(challenge.into_bigint());
    encode_proof(&MultiZkOpenProof {
        t_p,
        t_k,
        s_values,
        s_blind,
        pi_response,
    })
}

pub fn verify_multi_zkopen(
    srs: &Srs,
    accumulator: &G1Projective,
    points: &[Fr],
    d_y: &G1Projective,
    encoded_proof: &str,
    context: &[u8],
) -> Result<(), String> {
    if points.is_empty() {
        return Err("MultiZKOpen query set must not be empty".to_string());
    }
    let query = QueryContext::new(points)?;
    let proof = decode_proof(encoded_proof)?;
    if proof.s_values.len() != points.len() {
        return Err("MultiZKOpen response length mismatch".to_string());
    }
    let challenge = challenge(
        srs,
        accumulator,
        d_y,
        points,
        &proof.t_p,
        &proof.t_k,
        context,
    )?;

    let pedersen_lhs = proof.t_p + d_y.mul_bigint(challenge.into_bigint());
    let pedersen_rhs = commit_evaluation_vector(&proof.s_values, proof.s_blind)?;
    if pedersen_lhs != pedersen_rhs {
        return Err("MultiZKOpen vector commitment equation failed".to_string());
    }

    let s_poly = query.interpolate(&proof.s_values)?;
    let s_commit = commit_g1(srs, &s_poly)?;
    let z_commit = commit_g2(srs, query.z_poly())?;
    let pairing_lhs = Bls12_381::pairing(
        (proof.t_k + accumulator.mul_bigint(challenge.into_bigint()) - s_commit).into_affine(),
        G2Affine::generator(),
    );
    let pairing_rhs = Bls12_381::pairing(proof.pi_response.into_affine(), z_commit.into_affine());
    if pairing_lhs != pairing_rhs {
        return Err("MultiZKOpen KZG equation failed".to_string());
    }
    Ok(())
}

fn challenge(
    srs: &Srs,
    accumulator: &G1Projective,
    d_y: &G1Projective,
    points: &[Fr],
    t_p: &G1Projective,
    t_k: &G1Projective,
    context: &[u8],
) -> Result<Fr, String> {
    if srs.tau_g1_powers.len() < 2 || srs.tau_g2_powers.len() < 2 {
        return Err("MultiZKOpen requires tau^0 and tau^1 in both SRS groups".to_string());
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(CHALLENGE_DOMAIN);
    hasher.update(&(srs.max_degree as u64).to_le_bytes());
    append_g1(&mut hasher, &G1Projective::from(srs.tau_g1_powers[1]))?;
    let mut g2_tau = Vec::new();
    srs.tau_g2_powers[1]
        .serialize_compressed(&mut g2_tau)
        .map_err(|err| format!("serialize MultiZKOpen SRS id: {err}"))?;
    append_framed(&mut hasher, &g2_tau);
    append_framed(&mut hasher, GENERATOR_ID);
    append_g1(&mut hasher, accumulator)?;
    append_g1(&mut hasher, d_y)?;
    hasher.update(&(points.len() as u64).to_le_bytes());
    for point in points {
        let mut bytes = Vec::new();
        point
            .serialize_compressed(&mut bytes)
            .map_err(|err| format!("serialize MultiZKOpen point: {err}"))?;
        append_framed(&mut hasher, &bytes);
    }
    append_g1(&mut hasher, t_p)?;
    append_g1(&mut hasher, t_k)?;
    append_framed(&mut hasher, context);
    Ok(Fr::from_le_bytes_mod_order(hasher.finalize().as_bytes()))
}

fn append_g1(hasher: &mut blake3::Hasher, point: &G1Projective) -> Result<(), String> {
    let mut bytes = Vec::new();
    point
        .into_affine()
        .serialize_compressed(&mut bytes)
        .map_err(|err| format!("serialize MultiZKOpen point: {err}"))?;
    append_framed(hasher, &bytes);
    Ok(())
}

fn append_framed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn encode_proof(proof: &MultiZkOpenProof) -> Result<String, String> {
    let mut bytes = vec![PROOF_VERSION];
    let len = u32::try_from(proof.s_values.len())
        .map_err(|_| "MultiZKOpen response vector is too large".to_string())?;
    bytes.extend_from_slice(&len.to_le_bytes());
    proof
        .t_p
        .into_affine()
        .serialize_compressed(&mut bytes)
        .map_err(|err| format!("serialize MultiZKOpen T_P: {err}"))?;
    proof
        .t_k
        .into_affine()
        .serialize_compressed(&mut bytes)
        .map_err(|err| format!("serialize MultiZKOpen T_K: {err}"))?;
    for response in &proof.s_values {
        response
            .serialize_compressed(&mut bytes)
            .map_err(|err| format!("serialize MultiZKOpen response: {err}"))?;
    }
    proof
        .s_blind
        .serialize_compressed(&mut bytes)
        .map_err(|err| format!("serialize MultiZKOpen blind response: {err}"))?;
    proof
        .pi_response
        .into_affine()
        .serialize_compressed(&mut bytes)
        .map_err(|err| format!("serialize MultiZKOpen Pi: {err}"))?;
    Ok(hex_encode(&bytes))
}

fn decode_proof(encoded: &str) -> Result<MultiZkOpenProof, String> {
    let bytes = hex_decode(encoded)?;
    if bytes.len() < 5 || bytes[0] != PROOF_VERSION {
        return Err("unsupported MultiZKOpen proof version".to_string());
    }
    let len = u32::from_le_bytes(bytes[1..5].try_into().expect("fixed slice")) as usize;
    let expected = 5usize
        .checked_add(48 * 3)
        .and_then(|size| size.checked_add(32 * (len + 1)))
        .ok_or_else(|| "MultiZKOpen proof length overflow".to_string())?;
    if bytes.len() != expected {
        return Err(format!(
            "MultiZKOpen proof length mismatch: got {}, expected {expected}",
            bytes.len()
        ));
    }
    let mut cursor = Cursor::new(&bytes[5..]);
    let t_p = G1Affine::deserialize_compressed(&mut cursor)
        .map_err(|err| format!("parse MultiZKOpen T_P: {err}"))?
        .into_group();
    let t_k = G1Affine::deserialize_compressed(&mut cursor)
        .map_err(|err| format!("parse MultiZKOpen T_K: {err}"))?
        .into_group();
    let mut s_values = Vec::with_capacity(len);
    for _ in 0..len {
        s_values.push(
            Fr::deserialize_compressed(&mut cursor)
                .map_err(|err| format!("parse MultiZKOpen response: {err}"))?,
        );
    }
    let s_blind = Fr::deserialize_compressed(&mut cursor)
        .map_err(|err| format!("parse MultiZKOpen blind response: {err}"))?;
    let pi_response = G1Affine::deserialize_compressed(&mut cursor)
        .map_err(|err| format!("parse MultiZKOpen Pi: {err}"))?
        .into_group();
    Ok(MultiZkOpenProof {
        t_p,
        t_k,
        s_values,
        s_blind,
        pi_response,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kzg::commit_g1;
    use crate::polynomial::Polynomial;

    #[test]
    fn multipoint_opening_binds_the_pedersen_vector() {
        let srs = Srs::setup_development(8, b"multizkopen-test");
        let f = Polynomial::from_coeffs(vec![Fr::from(3u64), Fr::from(4u64), Fr::from(2u64)]);
        let accumulator = commit_g1(&srs, &f).unwrap();
        let points = vec![Fr::from(5u64), Fr::from(9u64)];
        let query = QueryContext::new(&points).unwrap();
        let evaluation = query.evaluate_with_quotient_owned(f).unwrap();
        let r_y = Fr::from(17u64);
        let d_y = commit_evaluation_vector(&evaluation.values, r_y).unwrap();
        let batch_opening = commit_g1(&srs, &evaluation.quotient).unwrap();
        let proof = prove_multi_zkopen(
            &srs,
            &accumulator,
            &points,
            &evaluation.values,
            &d_y,
            r_y,
            &batch_opening,
            b"ctx",
        )
        .unwrap();
        verify_multi_zkopen(&srs, &accumulator, &points, &d_y, &proof, b"ctx").unwrap();

        let wrong_d = commit_evaluation_vector(&evaluation.values, r_y + Fr::from(1u64)).unwrap();
        assert!(
            verify_multi_zkopen(&srs, &accumulator, &points, &wrong_d, &proof, b"ctx").is_err()
        );
    }
}
