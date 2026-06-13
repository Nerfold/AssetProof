use ark_bls12_381::{Fr, G1Projective as ArkG1};
use ark_ec::{CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::{BigInteger, PrimeField, Zero};
use bulletproofs_bls::inner_types::{
    group::{Curve, GroupEncoding},
    G1Projective as BpG1,
    Scalar as BpScalar,
};
use bulletproofs_bls::r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSProof, Verifier};
use bulletproofs_bls::{BulletproofGens, PedersenGens};
use common::crypto::{hex_decode, hex_encode, point_g1_from_hex, point_g1_to_hex};
use common::types::Delta;
use merlin::Transcript;
use ark_serialize::CanonicalSerialize;
use crate::commitment::{derive_generator, generator_window};
use crate::kzg::{commit_g1, Srs};
use crate::polynomial::QueryContext;
use crate::witness::UpdateWitness;

#[derive(Clone, Debug)]
pub struct LogicProof {
    pub bp_proof_hex: String,
    pub bp_commitments_hex: String,
    pub link_proof_hex: String,
}

#[derive(Clone, Debug)]
struct LinkProof {
    r_bp: Vec<BpG1>,
    r_u_ext: ArkG1,
    r_y_ext: ArkG1,
    r_d_ext: ArkG1,
    s_values: Vec<Fr>,
    s_bp_blinds: Vec<BpScalar>,
    s_r_u: Fr,
    s_rho_y: Fr,
    s_r_d: Fr,
}

pub fn prove_logic(
    srs: &Srs,
    witness: &UpdateWitness,
    deltas: &[Delta],
    c_u_hex: &str,
    c_y_hex: &str,
    c_d_hex: &str,
    r_u: Fr,
    rho_y: Fr,
    r_d: Fr,
    query_ctx: Option<&QueryContext>,
) -> Result<LogicProof, String> {
    let values = flatten_values(witness);
    let bp_values = values
        .iter()
        .map(fr_to_bp_scalar)
        .collect::<Result<Vec<_>, _>>()?;
    let bp_blinds = derive_bp_blinds(&values)?;

    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new((deltas.len() * 4).max(1).next_power_of_two(), 1);
    let mut transcript = Transcript::new(b"dynamic-poa-update-r1cs");
    append_public_to_transcript(&mut transcript, c_u_hex, c_y_hex, c_d_hex, deltas);
    let mut prover = Prover::new(&pc_gens, &mut transcript);

    let mut commitments = Vec::with_capacity(values.len());
    let mut vars = Vec::with_capacity(values.len());
    for (value, blind) in bp_values.iter().zip(bp_blinds.iter()) {
        let (commitment, var) = prover.commit(*value, *blind);
        commitments.push(commitment);
        vars.push(var);
    }

    update_relation(&mut prover, &vars, deltas)?;
    let bp_proof = prover
        .prove(&bp_gens)
        .map_err(|err| format!("bulletproof prove: {err}"))?;
    let link_proof = prove_link(
        srs,
        witness,
        deltas,
        &commitments,
        &values,
        &bp_blinds,
        c_u_hex,
        c_y_hex,
        c_d_hex,
        r_u,
        rho_y,
        r_d,
        query_ctx,
    )?;

    Ok(LogicProof {
        bp_proof_hex: hex_encode(&bp_proof.to_bytes()),
        bp_commitments_hex: encode_bp_points(&commitments),
        link_proof_hex: encode_link_proof(&link_proof)?,
    })
}

pub fn verify_logic(
    srs: &Srs,
    deltas: &[Delta],
    x_values: &[Fr],
    c_u_hex: &str,
    c_y_hex: &str,
    c_d_hex: &str,
    bp_proof_hex: &str,
    bp_commitments_hex: &str,
    link_proof_hex: &str,
) -> Result<(), String> {
    let commitments = decode_bp_points(bp_commitments_hex)?;
    let expected_len = deltas.len() * 4 + 1;
    if commitments.len() != expected_len {
        return Err(format!(
            "Bulletproof commitment length mismatch: got {}, expected {}",
            commitments.len(),
            expected_len
        ));
    }

    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new((deltas.len() * 4).max(1).next_power_of_two(), 1);
    let mut transcript = Transcript::new(b"dynamic-poa-update-r1cs");
    append_public_to_transcript(&mut transcript, c_u_hex, c_y_hex, c_d_hex, deltas);
    let mut verifier = Verifier::new(&mut transcript);
    let vars = commitments
        .iter()
        .map(|commitment| verifier.commit(*commitment))
        .collect::<Vec<_>>();
    update_relation(&mut verifier, &vars, deltas)?;
    let bp_bytes = hex_decode(bp_proof_hex)?;
    let bp_proof = R1CSProof::from_bytes(&bp_bytes).map_err(|err| format!("bulletproof parse: {err}"))?;
    verifier
        .verify(&bp_proof, &pc_gens, &bp_gens)
        .map_err(|err| format!("bulletproof verify: {err}"))?;

    let link_proof = decode_link_proof(link_proof_hex, expected_len)?;
    verify_link(
        srs,
        deltas,
        x_values,
        &commitments,
        c_u_hex,
        c_y_hex,
        c_d_hex,
        &link_proof,
    )
}

fn update_relation<CS: ConstraintSystem>(
    cs: &mut CS,
    vars: &[bulletproofs_bls::r1cs::Variable],
    deltas: &[Delta],
) -> Result<(), String> {
    let m = deltas.len();
    let u_offset = 0;
    let y_offset = m;
    let z_offset = 2 * m;
    let w_offset = 3 * m;
    let d_index = 4 * m;

    for j in 0..m {
        let u = vars[u_offset + j];
        let y = vars[y_offset + j];
        let z = vars[z_offset + j];
        let w = vars[w_offset + j];

        let (_, _, u_sq) = cs.multiply(u.into(), u.into());
        cs.constrain(u_sq - u);

        let (_, _, uy) = cs.multiply(u.into(), y.into());
        cs.constrain(uy.into());

        let (_, _, yz) = cs.multiply(y.into(), z.into());
        cs.constrain(yz - w);

        let (_, _, one_minus_u_times_w_minus_one) =
            cs.multiply(bp_one() - u, w - bp_one());
        cs.constrain(one_minus_u_times_w_minus_one.into());
    }

    let mut delta_lc: LinearCombination = vars[d_index].into();
    for (j, delta) in deltas.iter().enumerate() {
        delta_lc = delta_lc - bp_scalar_from_i128(delta.delta)? * vars[u_offset + j];
    }
    cs.constrain(delta_lc);
    Ok(())
}

fn prove_link(
    srs: &Srs,
    witness: &UpdateWitness,
    deltas: &[Delta],
    bp_commitments: &[BpG1],
    values: &[Fr],
    bp_blinds: &[BpScalar],
    c_u_hex: &str,
    c_y_hex: &str,
    c_d_hex: &str,
    r_u: Fr,
    rho_y: Fr,
    r_d: Fr,
    query_ctx: Option<&QueryContext>,
) -> Result<LinkProof, String> {
    let m = deltas.len();
    let pc_gens = PedersenGens::default();
    let mut t_values = Vec::with_capacity(values.len());
    let mut t_bp_blinds = Vec::with_capacity(values.len());
    for idx in 0..values.len() {
        t_values.push(hash_fr("link-tv", &[idx as u64]));
        t_bp_blinds.push(hash_bp("link-tb", &[idx as u64])?);
    }
    let t_r_u = hash_fr("link-tru", &[m as u64]);
    let t_rho_y = hash_fr("link-try", &[m as u64]);
    let t_r_d = hash_fr("link-trd", &[m as u64]);

    let r_bp = t_values
        .iter()
        .zip(t_bp_blinds.iter())
        .map(|(value, blind)| {
            pc_gens.commit(
                fr_to_bp_scalar(value).expect("hash scalar conversion must work"),
                *blind,
            )
        })
        .collect::<Vec<_>>();

    let r_u_ext = external_u_commit(&t_values[0..m], t_r_u);
    let r_y_ext = external_y_commit(srs, &witness.x_values, &t_values[m..2 * m], t_rho_y, query_ctx)?;
    let r_d_ext = crate::commitment::commit_balance(0, Fr::zero())
        + crate::commitment::derive_generator("balance-v", 0)
            .mul_bigint(t_values[4 * m].into_bigint())
        + crate::commitment::derive_generator("balance-h", 0)
            .mul_bigint(t_r_d.into_bigint());

    let challenge = link_challenge(
        deltas,
        bp_commitments,
        c_u_hex,
        c_y_hex,
        c_d_hex,
        &r_bp,
        &r_u_ext,
        &r_y_ext,
        &r_d_ext,
    )?;
    let challenge_bp = fr_to_bp_scalar(&challenge)?;

    let mut s_values = Vec::with_capacity(values.len());
    let mut s_bp_blinds = Vec::with_capacity(values.len());
    for ((t_value, value), (t_blind, blind)) in t_values
        .iter()
        .zip(values.iter())
        .zip(t_bp_blinds.iter().zip(bp_blinds.iter()))
    {
        s_values.push(*t_value + challenge * *value);
        s_bp_blinds.push(*t_blind + challenge_bp * *blind);
    }

    Ok(LinkProof {
        r_bp,
        r_u_ext,
        r_y_ext,
        r_d_ext,
        s_values,
        s_bp_blinds,
        s_r_u: t_r_u + challenge * r_u,
        s_rho_y: t_rho_y + challenge * rho_y,
        s_r_d: t_r_d + challenge * r_d,
    })
}

fn verify_link(
    srs: &Srs,
    deltas: &[Delta],
    x_values: &[Fr],
    bp_commitments: &[BpG1],
    c_u_hex: &str,
    c_y_hex: &str,
    c_d_hex: &str,
    proof: &LinkProof,
) -> Result<(), String> {
    let m = deltas.len();
    let expected_len = 4 * m + 1;
    if proof.s_values.len() != expected_len
        || proof.s_bp_blinds.len() != expected_len
        || proof.r_bp.len() != expected_len
    {
        return Err("link proof vector length mismatch".to_string());
    }

    let challenge = link_challenge(
        deltas,
        bp_commitments,
        c_u_hex,
        c_y_hex,
        c_d_hex,
        &proof.r_bp,
        &proof.r_u_ext,
        &proof.r_y_ext,
        &proof.r_d_ext,
    )?;
    let challenge_bp = fr_to_bp_scalar(&challenge)?;
    let pc_gens = PedersenGens::default();

    for idx in 0..expected_len {
        let lhs = pc_gens.commit(fr_to_bp_scalar(&proof.s_values[idx])?, proof.s_bp_blinds[idx]);
        let rhs = proof.r_bp[idx] + bp_commitments[idx] * challenge_bp;
        if lhs != rhs {
            return Err(format!("link proof BP commitment equation failed at index {idx}"));
        }
    }

    let c_u = point_g1_from_hex(c_u_hex)?;
    let c_y = point_g1_from_hex(c_y_hex)?;
    let c_d = point_g1_from_hex(c_d_hex)?;
    let lhs_u = external_u_commit(&proof.s_values[0..m], proof.s_r_u);
    let rhs_u = proof.r_u_ext + c_u.mul_bigint(challenge.into_bigint());
    if lhs_u != rhs_u {
        return Err("link proof C_U equation failed".to_string());
    }

    let lhs_y = external_y_commit(srs, x_values, &proof.s_values[m..2 * m], proof.s_rho_y, None)?;
    let rhs_y = proof.r_y_ext + c_y.mul_bigint(challenge.into_bigint());
    if lhs_y != rhs_y {
        return Err("link proof C_Y equation failed".to_string());
    }

    let lhs_d = crate::commitment::derive_generator("balance-v", 0)
        .mul_bigint(proof.s_values[4 * m].into_bigint())
        + crate::commitment::derive_generator("balance-h", 0).mul_bigint(proof.s_r_d.into_bigint());
    let rhs_d = proof.r_d_ext + c_d.mul_bigint(challenge.into_bigint());
    if lhs_d != rhs_d {
        return Err("link proof C_D equation failed".to_string());
    }

    Ok(())
}

fn flatten_values(witness: &UpdateWitness) -> Vec<Fr> {
    let mut values = Vec::with_capacity(witness.u_values.len() * 4 + 1);
    values.extend_from_slice(&witness.u_values);
    values.extend_from_slice(&witness.y_values);
    values.extend_from_slice(&witness.z_values);
    values.extend_from_slice(&witness.w_values);
    values.push(common::crypto::scalar_from_i128(witness.d_value));
    values
}

fn external_u_commit(values: &[Fr], blind: Fr) -> ArkG1 {
    let bases = generator_window("membership-u", values.len());
    ArkG1::msm_unchecked(&bases, values)
        + derive_generator("membership-h", 0).mul_bigint(blind.into_bigint())
}

fn external_y_commit(
    srs: &Srs,
    x_values: &[Fr],
    values: &[Fr],
    blind: Fr,
    query_ctx: Option<&QueryContext>,
) -> Result<ArkG1, String> {
    let owned_ctx;
    let ctx = match query_ctx {
        Some(ctx) => ctx,
        None => {
            owned_ctx = QueryContext::new(x_values)?;
            &owned_ctx
        }
    };
    let z_poly = ctx.z_poly().clone();
    let i_poly = ctx.interpolate(values)?;
    let j_poly = i_poly.add(&z_poly.mul_scalar(blind));
    commit_g1(srs, &j_poly)
}

fn append_public_to_transcript(transcript: &mut Transcript, c_u: &str, c_y: &str, c_d: &str, deltas: &[Delta]) {
    transcript.append_message(b"dom-sep", b"dynamic-poa-update-relation");
    transcript.append_u64(b"m", deltas.len() as u64);
    transcript.append_message(b"C_U", c_u.as_bytes());
    transcript.append_message(b"C_Y", c_y.as_bytes());
    transcript.append_message(b"C_D", c_d.as_bytes());
    for delta in deltas {
        transcript.append_message(b"addr", delta.address.as_bytes());
        transcript.append_message(b"delta", &delta.delta.to_le_bytes());
    }
}

fn link_challenge(
    deltas: &[Delta],
    bp_commitments: &[BpG1],
    c_u_hex: &str,
    c_y_hex: &str,
    c_d_hex: &str,
    r_bp: &[BpG1],
    r_u_ext: &ArkG1,
    r_y_ext: &ArkG1,
    r_d_ext: &ArkG1,
) -> Result<Fr, String> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"dynamic-poa-link-proof");
    hasher.update(c_u_hex.as_bytes());
    hasher.update(c_y_hex.as_bytes());
    hasher.update(c_d_hex.as_bytes());
    for delta in deltas {
        hasher.update(delta.address.as_bytes());
        hasher.update(&delta.delta.to_le_bytes());
    }
    for point in bp_commitments {
        hasher.update(&point.to_affine().to_compressed());
    }
    for point in r_bp {
        hasher.update(&point.to_affine().to_compressed());
    }
    append_ark_g1_bytes(&mut hasher, r_u_ext)?;
    append_ark_g1_bytes(&mut hasher, r_y_ext)?;
    append_ark_g1_bytes(&mut hasher, r_d_ext)?;
    let digest = hasher.finalize();
    Ok(Fr::from_le_bytes_mod_order(digest.as_bytes()))
}

fn append_ark_g1_bytes(hasher: &mut blake3::Hasher, point: &ArkG1) -> Result<(), String> {
    let mut bytes = Vec::new();
    point
        .into_affine()
        .serialize_compressed(&mut bytes)
        .map_err(|err| format!("serialize link point: {err}"))?;
    hasher.update(&bytes);
    Ok(())
}

fn derive_bp_blinds(values: &[Fr]) -> Result<Vec<BpScalar>, String> {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"bp-blind");
            hasher.update(&(index as u64).to_le_bytes());
            hasher.update(&value.into_bigint().to_bytes_le());
            bp_scalar_from_32(hasher.finalize().as_bytes())
        })
        .collect()
}

fn hash_fr(label: &str, parts: &[u64]) -> Fr {
    let mut hasher = blake3::Hasher::new();
    hasher.update(label.as_bytes());
    for part in parts {
        hasher.update(&part.to_le_bytes());
    }
    Fr::from_le_bytes_mod_order(hasher.finalize().as_bytes())
}

fn hash_bp(label: &str, parts: &[u64]) -> Result<BpScalar, String> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(label.as_bytes());
    for part in parts {
        hasher.update(&part.to_le_bytes());
    }
    bp_scalar_from_32(hasher.finalize().as_bytes())
}

fn fr_to_bp_scalar(value: &Fr) -> Result<BpScalar, String> {
    let ark_repr = value.into_bigint().to_bytes_le();
    let mut array = [0u8; 32];
    let len = ark_repr.len().min(32);
    array[..len].copy_from_slice(&ark_repr[..len]);
    let maybe = <BpScalar as bulletproofs_bls::inner_types::PrimeField>::from_repr(array);
    if bool::from(maybe.is_some()) {
        Ok(maybe.unwrap())
    } else {
        Err("invalid scalar conversion".to_string())
    }
}

fn bp_scalar_from_i128(value: i128) -> Result<BpScalar, String> {
    fr_to_bp_scalar(&common::crypto::scalar_from_i128(value))
}

fn bp_scalar_from_32(bytes: &[u8; 32]) -> Result<BpScalar, String> {
    let maybe = <BpScalar as bulletproofs_bls::inner_types::PrimeField>::from_repr(*bytes);
    if bool::from(maybe.is_some()) {
        Ok(maybe.unwrap())
    } else {
        Err("invalid BP scalar bytes".to_string())
    }
}

fn bp_one() -> BpScalar {
    BpScalar::ONE
}

fn encode_bp_points(points: &[BpG1]) -> String {
    points
        .iter()
        .map(|point| hex_encode(&point.to_affine().to_compressed()))
        .collect::<Vec<_>>()
        .join(",")
}

fn decode_bp_points(raw: &str) -> Result<Vec<BpG1>, String> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    raw.split(',')
        .map(|item| {
            let bytes = hex_decode(item)?;
            if bytes.len() != 48 {
                return Err("invalid BP G1 compressed length".to_string());
            }
            let mut array = [0u8; 48];
            array.copy_from_slice(&bytes);
            {
                let mut repr = <BpG1 as GroupEncoding>::Repr::default();
                repr.as_mut().copy_from_slice(&array);
                let maybe = BpG1::from_bytes(&repr);
                if bool::from(maybe.is_some()) {
                    Ok(maybe.unwrap())
                } else {
                    Err("invalid BP G1 point".to_string())
                }
            }
        })
        .collect()
}

fn encode_link_proof(proof: &LinkProof) -> Result<String, String> {
    let mut parts = Vec::new();
    parts.push(encode_bp_points(&proof.r_bp));
    parts.push(point_g1_to_hex(&proof.r_u_ext)?);
    parts.push(point_g1_to_hex(&proof.r_y_ext)?);
    parts.push(point_g1_to_hex(&proof.r_d_ext)?);
    parts.push(
        proof
            .s_values
            .iter()
            .map(common::crypto::scalar_to_hex)
            .collect::<Result<Vec<_>, _>>()?
            .join(","),
    );
    parts.push(
        proof
            .s_bp_blinds
            .iter()
            .map(|scalar| hex_encode(&scalar.to_le_bytes()))
            .collect::<Vec<_>>()
            .join(","),
    );
    parts.push(common::crypto::scalar_to_hex(&proof.s_r_u)?);
    parts.push(common::crypto::scalar_to_hex(&proof.s_rho_y)?);
    parts.push(common::crypto::scalar_to_hex(&proof.s_r_d)?);
    Ok(parts.join(";"))
}

fn decode_link_proof(raw: &str, expected_len: usize) -> Result<LinkProof, String> {
    let parts = raw.split(';').collect::<Vec<_>>();
    if parts.len() != 9 {
        return Err("invalid link proof part count".to_string());
    }
    let r_bp = decode_bp_points(parts[0])?;
    let s_values = if parts[4].is_empty() {
        Vec::new()
    } else {
        parts[4]
            .split(',')
            .map(common::crypto::scalar_from_hex)
            .collect::<Result<Vec<_>, _>>()?
    };
    let s_bp_blinds = if parts[5].is_empty() {
        Vec::new()
    } else {
        parts[5]
            .split(',')
            .map(|item| {
                let bytes = hex_decode(item)?;
                if bytes.len() != 32 {
                    return Err("invalid BP scalar length".to_string());
                }
                let mut array = [0u8; 32];
                array.copy_from_slice(&bytes);
                bp_scalar_from_32(&array)
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    if r_bp.len() != expected_len || s_values.len() != expected_len || s_bp_blinds.len() != expected_len {
        return Err("invalid link proof vector length".to_string());
    }
    Ok(LinkProof {
        r_bp,
        r_u_ext: point_g1_from_hex(parts[1])?,
        r_y_ext: point_g1_from_hex(parts[2])?,
        r_d_ext: point_g1_from_hex(parts[3])?,
        s_values,
        s_bp_blinds,
        s_r_u: common::crypto::scalar_from_hex(parts[6])?,
        s_rho_y: common::crypto::scalar_from_hex(parts[7])?,
        s_r_d: common::crypto::scalar_from_hex(parts[8])?,
    })
}
