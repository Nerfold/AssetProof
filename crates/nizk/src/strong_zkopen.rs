use std::io::{Cursor, Read};

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup, PrimeGroup,
};
use ark_ff::{PrimeField, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use common::crypto::{hex_decode, hex_encode};

use crate::commitment::eval_generators;
use crate::kzg::Srs;
use crate::zkopen::eval_commit;

const PROOF_VERSION: u8 = 1;
const STRONG_CHALLENGE_DOMAIN: &[u8] = b"dynamic-poa-strong-zkopen-fs-v1";
const NONZERO_CHALLENGE_DOMAIN: &[u8] = b"dynamic-poa-committed-nonzero-fs-v1";

#[derive(Clone, Debug)]
pub struct StrongZkOpenStatement {
    pub commitment: G1Projective,
    pub c_u: G1Projective,
    pub c_y: G1Projective,
    pub d: G2Projective,
}

#[derive(Clone, Debug)]
pub struct StrongZkOpenWitness {
    pub u: Fr,
    pub rho_u: Fr,
    pub y: Fr,
    pub rho_y: Fr,
    pub beta: Fr,
    pub rho_beta: Fr,
    pub mu: Fr,
    pub rho_mu: Fr,
    pub delta: Fr,
    pub w_tilde: G1Projective,
}

#[derive(Clone, Debug)]
struct StrongZkOpenProof {
    c_beta: G1Projective,
    c_mu: G1Projective,
    a_u: G1Projective,
    a_u_beta: G1Projective,
    a_beta: G1Projective,
    a_mu: G1Projective,
    a_d: G2Projective,
    a_y: G1Projective,
    a_e: PairingOutput<Bls12_381>,
    s_u: Fr,
    s_rho_u: Fr,
    s_delta: Fr,
    s_beta: Fr,
    s_rho_beta: Fr,
    s_mu: Fr,
    s_rho_mu: Fr,
    s_y: Fr,
    s_rho_y: Fr,
    z_w: G1Projective,
}

#[derive(Clone, Debug)]
pub struct ComNonZeroWitness {
    pub y: Fr,
    pub rho_y: Fr,
    pub nu: Fr,
    pub rho_nu: Fr,
    pub delta: Fr,
}

#[derive(Clone, Debug)]
struct ComNonZeroProof {
    c_nu: G1Projective,
    a_y: G1Projective,
    a_nu: G1Projective,
    a_y_nu: G1Projective,
    s_y: Fr,
    s_rho_y: Fr,
    s_nu: Fr,
    s_rho_nu: Fr,
    s_delta: Fr,
}

pub fn prove_strong_zkopen(
    srs: &Srs,
    statement: &StrongZkOpenStatement,
    witness: &StrongZkOpenWitness,
    context: &[u8],
) -> Result<String, String> {
    validate_strong_statement(srs, statement)?;
    validate_strong_witness(srs, statement, witness)?;

    let (_, h) = eval_generators();
    let c_beta = eval_commit(witness.beta, witness.rho_beta);
    let c_mu = eval_commit(witness.mu, witness.rho_mu);
    let mut rng = rand::rngs::OsRng;
    let alpha_u = Fr::rand(&mut rng);
    let eta_u = Fr::rand(&mut rng);
    let eta_delta = Fr::rand(&mut rng);
    let alpha_beta = Fr::rand(&mut rng);
    let eta_beta = Fr::rand(&mut rng);
    let alpha_mu = Fr::rand(&mut rng);
    let eta_mu = Fr::rand(&mut rng);
    let alpha_y = Fr::rand(&mut rng);
    let eta_y = Fr::rand(&mut rng);
    // A_W is an internal one-time group mask. It must never be encoded in the
    // transcript: publishing both A_W and Z_W would reveal W_tilde directly.
    let a_w = G1Projective::generator().mul_bigint(Fr::rand(&mut rng).into_bigint());

    let a_u = eval_commit(alpha_u, eta_u);
    let a_u_beta = c_beta.mul_bigint(alpha_u.into_bigint()) + h.mul_bigint(eta_delta.into_bigint());
    let a_beta = eval_commit(alpha_beta, eta_beta);
    let a_mu = eval_commit(alpha_mu, eta_mu);
    let a_d = G2Projective::from(srs.tau_g2_powers[1]).mul_bigint(alpha_beta.into_bigint())
        - G2Projective::generator().mul_bigint(alpha_mu.into_bigint());
    let a_y = eval_commit(alpha_y, eta_y);
    let g_t = Bls12_381::pairing(G1Affine::generator(), G2Affine::generator());
    let a_e = g_t.mul_bigint(alpha_y.into_bigint())
        + Bls12_381::pairing(a_w.into_affine(), statement.d.into_affine());

    let first = StrongZkOpenProof {
        c_beta,
        c_mu,
        a_u,
        a_u_beta,
        a_beta,
        a_mu,
        a_d,
        a_y,
        a_e,
        s_u: Fr::zero(),
        s_rho_u: Fr::zero(),
        s_delta: Fr::zero(),
        s_beta: Fr::zero(),
        s_rho_beta: Fr::zero(),
        s_mu: Fr::zero(),
        s_rho_mu: Fr::zero(),
        s_y: Fr::zero(),
        s_rho_y: Fr::zero(),
        z_w: G1Projective::zero(),
    };
    let challenge = strong_challenge(srs, statement, &first, context)?;
    let proof = StrongZkOpenProof {
        s_u: alpha_u + challenge * witness.u,
        s_rho_u: eta_u + challenge * witness.rho_u,
        s_delta: eta_delta + challenge * witness.delta,
        s_beta: alpha_beta + challenge * witness.beta,
        s_rho_beta: eta_beta + challenge * witness.rho_beta,
        s_mu: alpha_mu + challenge * witness.mu,
        s_rho_mu: eta_mu + challenge * witness.rho_mu,
        s_y: alpha_y + challenge * witness.y,
        s_rho_y: eta_y + challenge * witness.rho_y,
        z_w: a_w + witness.w_tilde.mul_bigint(challenge.into_bigint()),
        ..first
    };
    encode_strong_proof(&proof)
}

pub fn verify_strong_zkopen(
    srs: &Srs,
    statement: &StrongZkOpenStatement,
    encoded_proof: &str,
    context: &[u8],
) -> Result<(), String> {
    validate_strong_statement(srs, statement)?;
    let proof = decode_strong_proof(encoded_proof)?;
    let challenge = strong_challenge(srs, statement, &proof, context)?;
    let (_, h) = eval_generators();

    if eval_commit(proof.s_u, proof.s_rho_u)
        != proof.a_u + statement.c_u.mul_bigint(challenge.into_bigint())
    {
        return Err("StrongZKOpen C_u opening equation failed".to_string());
    }
    if proof.c_beta.mul_bigint(proof.s_u.into_bigint()) + h.mul_bigint(proof.s_delta.into_bigint())
        != proof.a_u_beta + proof.c_mu.mul_bigint(challenge.into_bigint())
    {
        return Err("StrongZKOpen mu=beta*u representation equation failed".to_string());
    }
    if eval_commit(proof.s_beta, proof.s_rho_beta)
        != proof.a_beta + proof.c_beta.mul_bigint(challenge.into_bigint())
    {
        return Err("StrongZKOpen C_beta opening equation failed".to_string());
    }
    if eval_commit(proof.s_mu, proof.s_rho_mu)
        != proof.a_mu + proof.c_mu.mul_bigint(challenge.into_bigint())
    {
        return Err("StrongZKOpen C_mu opening equation failed".to_string());
    }
    if G2Projective::from(srs.tau_g2_powers[1]).mul_bigint(proof.s_beta.into_bigint())
        - G2Projective::generator().mul_bigint(proof.s_mu.into_bigint())
        != proof.a_d + statement.d.mul_bigint(challenge.into_bigint())
    {
        return Err("StrongZKOpen randomized point-handle equation failed".to_string());
    }
    if eval_commit(proof.s_y, proof.s_rho_y)
        != proof.a_y + statement.c_y.mul_bigint(challenge.into_bigint())
    {
        return Err("StrongZKOpen C_y opening equation failed".to_string());
    }
    let g_t = Bls12_381::pairing(G1Affine::generator(), G2Affine::generator());
    let lhs = g_t.mul_bigint(proof.s_y.into_bigint())
        + Bls12_381::pairing(proof.z_w.into_affine(), statement.d.into_affine());
    let rhs = proof.a_e
        + Bls12_381::pairing(statement.commitment.into_affine(), G2Affine::generator())
            .mul_bigint(challenge.into_bigint());
    if lhs != rhs {
        return Err("StrongZKOpen hidden KZG evaluation equation failed".to_string());
    }
    Ok(())
}

pub fn prove_com_nonzero(
    c_y: &G1Projective,
    witness: &ComNonZeroWitness,
    context: &[u8],
) -> Result<String, String> {
    validate_nonzero_witness(c_y, witness)?;
    let (_, h) = eval_generators();
    let c_nu = eval_commit(witness.nu, witness.rho_nu);
    let mut rng = rand::rngs::OsRng;
    let alpha_y = Fr::rand(&mut rng);
    let eta_y = Fr::rand(&mut rng);
    let alpha_nu = Fr::rand(&mut rng);
    let eta_nu = Fr::rand(&mut rng);
    let eta_delta = Fr::rand(&mut rng);
    let a_y = eval_commit(alpha_y, eta_y);
    let a_nu = eval_commit(alpha_nu, eta_nu);
    let a_y_nu = c_nu.mul_bigint(alpha_y.into_bigint()) + h.mul_bigint(eta_delta.into_bigint());
    let first = ComNonZeroProof {
        c_nu,
        a_y,
        a_nu,
        a_y_nu,
        s_y: Fr::zero(),
        s_rho_y: Fr::zero(),
        s_nu: Fr::zero(),
        s_rho_nu: Fr::zero(),
        s_delta: Fr::zero(),
    };
    let challenge = nonzero_challenge(c_y, &first, context)?;
    let proof = ComNonZeroProof {
        s_y: alpha_y + challenge * witness.y,
        s_rho_y: eta_y + challenge * witness.rho_y,
        s_nu: alpha_nu + challenge * witness.nu,
        s_rho_nu: eta_nu + challenge * witness.rho_nu,
        s_delta: eta_delta + challenge * witness.delta,
        ..first
    };
    encode_nonzero_proof(&proof)
}

pub fn verify_com_nonzero(
    c_y: &G1Projective,
    encoded_proof: &str,
    context: &[u8],
) -> Result<(), String> {
    let proof = decode_nonzero_proof(encoded_proof)?;
    let challenge = nonzero_challenge(c_y, &proof, context)?;
    let (v, h) = eval_generators();
    if eval_commit(proof.s_y, proof.s_rho_y) != proof.a_y + c_y.mul_bigint(challenge.into_bigint())
    {
        return Err("ComNonZero C_y opening equation failed".to_string());
    }
    if eval_commit(proof.s_nu, proof.s_rho_nu)
        != proof.a_nu + proof.c_nu.mul_bigint(challenge.into_bigint())
    {
        return Err("ComNonZero C_nu opening equation failed".to_string());
    }
    if proof.c_nu.mul_bigint(proof.s_y.into_bigint()) + h.mul_bigint(proof.s_delta.into_bigint())
        != proof.a_y_nu + v.mul_bigint(challenge.into_bigint())
    {
        return Err("ComNonZero product equation failed".to_string());
    }
    Ok(())
}

pub fn verify_digest_transition(
    old_digest: &G1Projective,
    new_digest: &G1Projective,
    d: &G2Projective,
) -> Result<(), String> {
    if old_digest.is_zero() || new_digest.is_zero() || d.is_zero() {
        return Err("insert digest transition requires non-identity d, d', and D".to_string());
    }
    if Bls12_381::pairing(new_digest.into_affine(), G2Affine::generator())
        != Bls12_381::pairing(old_digest.into_affine(), d.into_affine())
    {
        return Err("insert digest transition pairing failed".to_string());
    }
    Ok(())
}

fn validate_strong_statement(srs: &Srs, statement: &StrongZkOpenStatement) -> Result<(), String> {
    if srs.tau_g1_powers.len() < 2 || srs.tau_g2_powers.len() < 2 {
        return Err("StrongZKOpen requires tau^0 and tau^1 in both SRS groups".to_string());
    }
    if statement.commitment.is_zero() || statement.d.is_zero() {
        return Err("StrongZKOpen requires non-identity KZG commitment and D".to_string());
    }
    Ok(())
}

fn validate_strong_witness(
    srs: &Srs,
    statement: &StrongZkOpenStatement,
    witness: &StrongZkOpenWitness,
) -> Result<(), String> {
    if witness.beta.is_zero() {
        return Err("StrongZKOpen beta must be non-zero".to_string());
    }
    if statement.c_u != eval_commit(witness.u, witness.rho_u)
        || statement.c_y != eval_commit(witness.y, witness.rho_y)
    {
        return Err("StrongZKOpen top-level Pedersen opening mismatch".to_string());
    }
    let (_, h) = eval_generators();
    let c_beta = eval_commit(witness.beta, witness.rho_beta);
    let c_mu = eval_commit(witness.mu, witness.rho_mu);
    if c_mu
        != c_beta.mul_bigint(witness.u.into_bigint()) + h.mul_bigint(witness.delta.into_bigint())
    {
        return Err("StrongZKOpen shared-exponent representation mismatch".to_string());
    }
    let expected_d = G2Projective::from(srs.tau_g2_powers[1])
        .mul_bigint(witness.beta.into_bigint())
        - G2Projective::generator().mul_bigint(witness.mu.into_bigint());
    if statement.d != expected_d {
        return Err("StrongZKOpen D witness mismatch".to_string());
    }
    let g_t = Bls12_381::pairing(G1Affine::generator(), G2Affine::generator());
    if Bls12_381::pairing(statement.commitment.into_affine(), G2Affine::generator())
        != g_t.mul_bigint(witness.y.into_bigint())
            + Bls12_381::pairing(witness.w_tilde.into_affine(), statement.d.into_affine())
    {
        return Err("StrongZKOpen hidden quotient relation failed".to_string());
    }
    Ok(())
}

fn validate_nonzero_witness(c_y: &G1Projective, witness: &ComNonZeroWitness) -> Result<(), String> {
    if witness.y.is_zero() || witness.y * witness.nu != Fr::from(1u64) {
        return Err("ComNonZero requires y*nu=1".to_string());
    }
    if *c_y != eval_commit(witness.y, witness.rho_y) {
        return Err("ComNonZero C_y opening mismatch".to_string());
    }
    let (v, h) = eval_generators();
    let c_nu = eval_commit(witness.nu, witness.rho_nu);
    if *v != c_nu.mul_bigint(witness.y.into_bigint()) + h.mul_bigint(witness.delta.into_bigint()) {
        return Err("ComNonZero inverse representation mismatch".to_string());
    }
    Ok(())
}

fn strong_challenge(
    srs: &Srs,
    statement: &StrongZkOpenStatement,
    proof: &StrongZkOpenProof,
    context: &[u8],
) -> Result<Fr, String> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(STRONG_CHALLENGE_DOMAIN);
    append_srs_id(&mut hasher, srs)?;
    append_eval_params(&mut hasher)?;
    for point in [&statement.commitment, &statement.c_u, &statement.c_y] {
        append_serialized(&mut hasher, &point.into_affine())?;
    }
    append_serialized(&mut hasher, &statement.d.into_affine())?;
    for point in [
        &proof.c_beta,
        &proof.c_mu,
        &proof.a_u,
        &proof.a_u_beta,
        &proof.a_beta,
        &proof.a_mu,
        &proof.a_y,
    ] {
        append_serialized(&mut hasher, &point.into_affine())?;
    }
    append_serialized(&mut hasher, &proof.a_d.into_affine())?;
    append_serialized(&mut hasher, &proof.a_e)?;
    append_framed(&mut hasher, context);
    Ok(Fr::from_le_bytes_mod_order(hasher.finalize().as_bytes()))
}

fn nonzero_challenge(
    c_y: &G1Projective,
    proof: &ComNonZeroProof,
    context: &[u8],
) -> Result<Fr, String> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(NONZERO_CHALLENGE_DOMAIN);
    append_eval_params(&mut hasher)?;
    for point in [c_y, &proof.c_nu, &proof.a_y, &proof.a_nu, &proof.a_y_nu] {
        append_serialized(&mut hasher, &point.into_affine())?;
    }
    append_framed(&mut hasher, context);
    Ok(Fr::from_le_bytes_mod_order(hasher.finalize().as_bytes()))
}

fn append_srs_id(hasher: &mut blake3::Hasher, srs: &Srs) -> Result<(), String> {
    hasher.update(&(srs.max_degree as u64).to_le_bytes());
    append_serialized(hasher, &srs.tau_g1_powers[1])?;
    append_serialized(hasher, &srs.tau_g2_powers[1])
}

fn append_eval_params(hasher: &mut blake3::Hasher) -> Result<(), String> {
    let (v, h) = eval_generators();
    append_serialized(hasher, &v.into_affine())?;
    append_serialized(hasher, &h.into_affine())
}

fn append_serialized<T: CanonicalSerialize>(
    hasher: &mut blake3::Hasher,
    value: &T,
) -> Result<(), String> {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .map_err(|err| format!("serialize StrongZKOpen transcript element: {err}"))?;
    append_framed(hasher, &bytes);
    Ok(())
}

fn append_framed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn encode_strong_proof(proof: &StrongZkOpenProof) -> Result<String, String> {
    let mut bytes = vec![PROOF_VERSION];
    for point in [
        &proof.c_beta,
        &proof.c_mu,
        &proof.a_u,
        &proof.a_u_beta,
        &proof.a_beta,
        &proof.a_mu,
        &proof.a_y,
        &proof.z_w,
    ] {
        point
            .into_affine()
            .serialize_compressed(&mut bytes)
            .map_err(|err| format!("serialize StrongZKOpen G1 element: {err}"))?;
    }
    proof
        .a_d
        .into_affine()
        .serialize_compressed(&mut bytes)
        .map_err(|err| format!("serialize StrongZKOpen G2 element: {err}"))?;
    proof
        .a_e
        .serialize_compressed(&mut bytes)
        .map_err(|err| format!("serialize StrongZKOpen GT element: {err}"))?;
    for response in [
        proof.s_u,
        proof.s_rho_u,
        proof.s_delta,
        proof.s_beta,
        proof.s_rho_beta,
        proof.s_mu,
        proof.s_rho_mu,
        proof.s_y,
        proof.s_rho_y,
    ] {
        response
            .serialize_compressed(&mut bytes)
            .map_err(|err| format!("serialize StrongZKOpen response: {err}"))?;
    }
    Ok(hex_encode(&bytes))
}

fn decode_strong_proof(encoded: &str) -> Result<StrongZkOpenProof, String> {
    let bytes = hex_decode(encoded)?;
    if bytes.first().copied() != Some(PROOF_VERSION) {
        return Err("unsupported StrongZKOpen proof version".to_string());
    }
    let mut cursor = Cursor::new(&bytes[1..]);
    let mut read_g1 = || -> Result<G1Projective, String> {
        G1Affine::deserialize_compressed(&mut cursor)
            .map(Into::into)
            .map_err(|err| format!("decode StrongZKOpen G1 element: {err}"))
    };
    let c_beta = read_g1()?;
    let c_mu = read_g1()?;
    let a_u = read_g1()?;
    let a_u_beta = read_g1()?;
    let a_beta = read_g1()?;
    let a_mu = read_g1()?;
    let a_y = read_g1()?;
    let z_w = read_g1()?;
    drop(read_g1);
    let a_d = G2Affine::deserialize_compressed(&mut cursor)
        .map(Into::into)
        .map_err(|err| format!("decode StrongZKOpen G2 element: {err}"))?;
    let a_e = PairingOutput::<Bls12_381>::deserialize_compressed(&mut cursor)
        .map_err(|err| format!("decode StrongZKOpen GT element: {err}"))?;
    let mut read_fr = || {
        Fr::deserialize_compressed(&mut cursor)
            .map_err(|err| format!("decode StrongZKOpen response: {err}"))
    };
    let proof = StrongZkOpenProof {
        c_beta,
        c_mu,
        a_u,
        a_u_beta,
        a_beta,
        a_mu,
        a_d,
        a_y,
        a_e,
        s_u: read_fr()?,
        s_rho_u: read_fr()?,
        s_delta: read_fr()?,
        s_beta: read_fr()?,
        s_rho_beta: read_fr()?,
        s_mu: read_fr()?,
        s_rho_mu: read_fr()?,
        s_y: read_fr()?,
        s_rho_y: read_fr()?,
        z_w,
    };
    drop(read_fr);
    reject_trailing(&mut cursor, "StrongZKOpen")?;
    Ok(proof)
}

fn encode_nonzero_proof(proof: &ComNonZeroProof) -> Result<String, String> {
    let mut bytes = vec![PROOF_VERSION];
    for point in [&proof.c_nu, &proof.a_y, &proof.a_nu, &proof.a_y_nu] {
        point
            .into_affine()
            .serialize_compressed(&mut bytes)
            .map_err(|err| format!("serialize ComNonZero G1 element: {err}"))?;
    }
    for response in [
        proof.s_y,
        proof.s_rho_y,
        proof.s_nu,
        proof.s_rho_nu,
        proof.s_delta,
    ] {
        response
            .serialize_compressed(&mut bytes)
            .map_err(|err| format!("serialize ComNonZero response: {err}"))?;
    }
    Ok(hex_encode(&bytes))
}

fn decode_nonzero_proof(encoded: &str) -> Result<ComNonZeroProof, String> {
    let bytes = hex_decode(encoded)?;
    if bytes.first().copied() != Some(PROOF_VERSION) {
        return Err("unsupported ComNonZero proof version".to_string());
    }
    let mut cursor = Cursor::new(&bytes[1..]);
    let mut read_g1 = || -> Result<G1Projective, String> {
        G1Affine::deserialize_compressed(&mut cursor)
            .map(Into::into)
            .map_err(|err| format!("decode ComNonZero G1 element: {err}"))
    };
    let c_nu = read_g1()?;
    let a_y = read_g1()?;
    let a_nu = read_g1()?;
    let a_y_nu = read_g1()?;
    drop(read_g1);
    let mut read_fr = || {
        Fr::deserialize_compressed(&mut cursor)
            .map_err(|err| format!("decode ComNonZero response: {err}"))
    };
    let proof = ComNonZeroProof {
        c_nu,
        a_y,
        a_nu,
        a_y_nu,
        s_y: read_fr()?,
        s_rho_y: read_fr()?,
        s_nu: read_fr()?,
        s_rho_nu: read_fr()?,
        s_delta: read_fr()?,
    };
    drop(read_fr);
    reject_trailing(&mut cursor, "ComNonZero")?;
    Ok(proof)
}

fn reject_trailing(cursor: &mut Cursor<&[u8]>, label: &str) -> Result<(), String> {
    let mut trailing = [0u8; 1];
    if cursor
        .read(&mut trailing)
        .map_err(|err| format!("read {label} trailing bytes: {err}"))?
        != 0
    {
        return Err(format!("{label} proof contains trailing bytes"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kzg::{commit_g1, Srs};
    use crate::polynomial::Polynomial;
    use ark_ff::Field;

    #[test]
    fn strong_open_and_nonzero_round_trip() {
        let srs = Srs::setup_development(8, b"strong-zkopen-test");
        let p = Polynomial::from_coeffs(vec![Fr::from(3u64), Fr::from(5u64)]);
        let u = Fr::from(11u64);
        let y = p.evaluate(u);
        let beta = Fr::from(7u64);
        let mu = beta * u;
        let nu = y.inverse().unwrap();
        let q = p.quotient_at(u, y).unwrap();
        let commitment = commit_g1(&srs, &p).unwrap();
        let w_tilde = commit_g1(&srs, &q)
            .unwrap()
            .mul_bigint(beta.inverse().unwrap().into_bigint());
        let d = G2Projective::from(srs.tau_g2_powers[1]).mul_bigint(beta.into_bigint())
            - G2Projective::generator().mul_bigint(mu.into_bigint());
        let rho_u = Fr::from(13u64);
        let rho_y = Fr::from(17u64);
        let rho_beta = Fr::from(19u64);
        let rho_mu = Fr::from(23u64);
        let rho_nu = Fr::from(29u64);
        let statement = StrongZkOpenStatement {
            commitment,
            c_u: eval_commit(u, rho_u),
            c_y: eval_commit(y, rho_y),
            d,
        };
        let proof = prove_strong_zkopen(
            &srs,
            &statement,
            &StrongZkOpenWitness {
                u,
                rho_u,
                y,
                rho_y,
                beta,
                rho_beta,
                mu,
                rho_mu,
                delta: rho_mu - u * rho_beta,
                w_tilde,
            },
            b"insert-context",
        )
        .unwrap();
        verify_strong_zkopen(&srs, &statement, &proof, b"insert-context").unwrap();
        assert!(verify_strong_zkopen(&srs, &statement, &proof, b"wrong-context").is_err());

        let nonzero = prove_com_nonzero(
            &statement.c_y,
            &ComNonZeroWitness {
                y,
                rho_y,
                nu,
                rho_nu,
                delta: -y * rho_nu,
            },
            b"insert-context",
        )
        .unwrap();
        verify_com_nonzero(&statement.c_y, &nonzero, b"insert-context").unwrap();
        assert!(verify_com_nonzero(&statement.c_y, &nonzero, b"wrong-context").is_err());

        let new_digest = commit_g1(&srs, &p.mul_linear_scaled(u, beta)).unwrap();
        verify_digest_transition(&commitment, &new_digest, &d).unwrap();
    }
}
