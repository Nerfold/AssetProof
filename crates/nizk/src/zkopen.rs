use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;

use common::crypto::{
    deserialize_hex, hex_encode, point_g1_from_hex, point_g1_to_hex, scalar_from_hex,
    scalar_to_hex, serialize_hex,
};

use crate::commitment::derive_generator;
use crate::kzg::Srs;

#[derive(Clone, Debug)]
pub struct CommittedOpeningProof {
    pub r_commit_hex: String,
    pub r_pair_hex: String,
    pub s_value: Fr,
    pub s_blind: Fr,
    pub s_opening_hex: String,
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

    let a_value = derive_scalar(
        "zkopen-a-value",
        &[
            domain.as_bytes(),
            poly_commitment_hex.as_bytes(),
            value_commitment_hex.as_bytes(),
            &fr_bytes(value),
            &fr_bytes(value_blind),
            &g1_bytes(kzg_opening)?,
        ],
    );
    let a_blind = derive_scalar(
        "zkopen-a-blind",
        &[
            domain.as_bytes(),
            value_commitment_hex.as_bytes(),
            &fr_bytes(value_blind),
        ],
    );
    let a_opening = derive_g1(
        "zkopen-a-opening",
        &[
            domain.as_bytes(),
            poly_commitment_hex.as_bytes(),
            &fr_bytes(value),
        ],
    );

    let r_commit = eval_commit(a_value, a_blind);
    let r_pair = pairing_generator().mul_bigint(a_value.into_bigint())
        + opening_pair(srs, zeta, &a_opening)?;
    let challenge = challenge_scalar(
        domain,
        poly_commitment_hex,
        zeta,
        value_commitment_hex,
        &r_commit,
        &r_pair,
    )?;

    let s_value = a_value + challenge * value;
    let s_blind = a_blind + challenge * value_blind;
    let s_opening = a_opening + kzg_opening.mul_bigint(challenge.into_bigint());

    encode_proof(&CommittedOpeningProof {
        r_commit_hex: point_g1_to_hex(&r_commit)?,
        r_pair_hex: serialize_hex(&r_pair)?,
        s_value,
        s_blind,
        s_opening_hex: point_g1_to_hex(&s_opening)?,
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
    let r_commit = point_g1_from_hex(&proof.r_commit_hex)?;
    let r_pair = deserialize_hex::<ark_ec::pairing::PairingOutput<Bls12_381>>(&proof.r_pair_hex)?;
    let s_opening = point_g1_from_hex(&proof.s_opening_hex)?;
    let challenge = challenge_scalar(
        domain,
        poly_commitment_hex,
        zeta,
        value_commitment_hex,
        &r_commit,
        &r_pair,
    )?;

    let commit_lhs = eval_commit(proof.s_value, proof.s_blind);
    let commit_rhs = r_commit + value_commitment.mul_bigint(challenge.into_bigint());
    if commit_lhs != commit_rhs {
        return Err("ZKOpen scalar commitment equation failed".to_string());
    }

    let target = kzg_target_statement(srs, &poly_commitment, zeta)?;
    let pair_lhs = pairing_generator().mul_bigint(proof.s_value.into_bigint())
        + opening_pair(srs, zeta, &s_opening)?;
    let pair_rhs = r_pair + target.mul_bigint(challenge.into_bigint());
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
    let _ = zeta;
    Ok(())
}

fn kzg_target_statement(
    srs: &Srs,
    poly_commitment: &G1Projective,
    zeta: Fr,
) -> Result<ark_ec::pairing::PairingOutput<Bls12_381>, String> {
    ensure_kzg_statement(srs, poly_commitment, zeta, &G1Projective::generator())?;
    Ok(Bls12_381::pairing(
        poly_commitment.into_affine(),
        G2Affine::generator(),
    ))
}

fn opening_pair(
    srs: &Srs,
    zeta: Fr,
    opening: &G1Projective,
) -> Result<ark_ec::pairing::PairingOutput<Bls12_381>, String> {
    if srs.tau_g2_powers.len() < 2 {
        return Err("SRS must contain tau^1 G2 power for ZKOpen".to_string());
    }
    let tau_minus_zeta = G2Projective::from(srs.tau_g2_powers[1])
        - G2Projective::generator().mul_bigint(zeta.into_bigint());
    Ok(Bls12_381::pairing(
        opening.into_affine(),
        tau_minus_zeta.into_affine(),
    ))
}

fn pairing_generator() -> ark_ec::pairing::PairingOutput<Bls12_381> {
    Bls12_381::pairing(G1Affine::generator(), G2Affine::generator())
}

fn encode_proof(proof: &CommittedOpeningProof) -> Result<String, String> {
    Ok(format!(
        "zkopen:v1:{}:{}:{}:{}:{}",
        proof.r_commit_hex,
        proof.r_pair_hex,
        scalar_to_hex(&proof.s_value)?,
        scalar_to_hex(&proof.s_blind)?,
        proof.s_opening_hex
    ))
}

fn decode_proof(raw: &str) -> Result<CommittedOpeningProof, String> {
    let parts = raw.split(':').collect::<Vec<_>>();
    if parts.len() != 7 || parts[0] != "zkopen" || parts[1] != "v1" {
        return Err("invalid ZKOpen proof encoding".to_string());
    }
    Ok(CommittedOpeningProof {
        r_commit_hex: parts[2].to_string(),
        r_pair_hex: parts[3].to_string(),
        s_value: scalar_from_hex(parts[4])?,
        s_blind: scalar_from_hex(parts[5])?,
        s_opening_hex: parts[6].to_string(),
    })
}

fn challenge_scalar(
    domain: &str,
    poly_commitment_hex: &str,
    zeta: Fr,
    value_commitment_hex: &str,
    r_commit: &G1Projective,
    r_pair: &ark_ec::pairing::PairingOutput<Bls12_381>,
) -> Result<Fr, String> {
    let mut r_pair_bytes = Vec::new();
    r_pair
        .serialize_compressed(&mut r_pair_bytes)
        .map_err(|err| format!("serialize ZKOpen pairing response: {err}"))?;
    let r_commit_hex = point_g1_to_hex(r_commit)?;
    let zeta_hex = scalar_to_hex(&zeta)?;
    Ok(common::crypto::hash_to_scalar(
        "dynamic-poa-zkopen-challenge",
        &[
            domain,
            poly_commitment_hex,
            &zeta_hex,
            value_commitment_hex,
            &r_commit_hex,
            &hex_encode(&r_pair_bytes),
        ]
        .join("|")
        .into_bytes(),
    ))
}

fn derive_scalar(label: &str, chunks: &[&[u8]]) -> Fr {
    let mut bytes = Vec::new();
    for chunk in chunks {
        bytes.extend_from_slice(chunk);
    }
    common::crypto::hash_to_scalar(label, &bytes)
}

fn derive_g1(label: &str, chunks: &[&[u8]]) -> G1Projective {
    G1Projective::generator().mul_bigint(derive_scalar(label, chunks).into_bigint())
}

fn fr_bytes(value: Fr) -> Vec<u8> {
    value.into_bigint().to_bytes_le()
}

fn g1_bytes(value: &G1Projective) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    value
        .into_affine()
        .serialize_compressed(&mut bytes)
        .map_err(|err| format!("serialize G1: {err}"))?;
    Ok(bytes)
}
