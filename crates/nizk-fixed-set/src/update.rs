use ark_bls12_381::{Fr, G1Projective, G2Projective};
use ark_ec::PrimeGroup;
use ark_ff::{BigInteger, One, PrimeField, Zero};
use std::env;
use std::collections::HashSet;
use std::time::Instant;

use common::crypto::{hash_to_scalar, point_g1_from_hex, point_g1_to_hex, scalar_to_hex};
use common::types::{Delta, StoredProof, StoredState};

use crate::bp::prove_logic;
use crate::commitment::{commit_balance, commit_linear};
use crate::kzg::{commit_g1, commit_g2, verify_batch, Srs};
use crate::polynomial::{QueryContext, lagrange_basis, Polynomial};
use crate::witness::{build_update_witness, UpdateWitness};

#[derive(Clone, Debug)]
pub struct UpdateResult {
    pub next_state: StoredState,
    pub proof: StoredProof,
}

pub fn apply_update(
    srs: &Srs,
    state: &StoredState,
    deltas: &[Delta],
    new_state_root: &str,
) -> Result<UpdateResult, String> {
    if state.srs_max_degree != srs.max_degree {
        return Err("state SRS degree does not match provided SRS".to_string());
    }
    let emit_timing = env::var("POA_TIMING").ok().as_deref() == Some("1");

    let witness_start = Instant::now();
    let polynomial = Polynomial::from_coeffs(state.masked_polynomial_coeffs.clone());
    let witness = build_update_witness(&polynomial, deltas)?;
    ensure_distinct(&witness.x_values)?;
    let query_ctx = QueryContext::new(&witness.x_values)?;
    if emit_timing {
        eprintln!("stage=update_witness millis={}", witness_start.elapsed().as_millis());
    }

    let kzg_start = Instant::now();
    let z_poly = query_ctx.z_poly().clone();
    let i_y = query_ctx.interpolate(&witness.y_values)?;
    let rho_y = derive_scalar("rho-y", &[new_state_root.as_bytes(), &fr_vec_bytes(&witness.y_values)]);
    let j_y = i_y.add(&z_poly.mul_scalar(rho_y));
    let quotient = polynomial.sub(&j_y).div_exact(&z_poly)?;

    let c_y = commit_g1(srs, &j_y)?;
    let eval_proof = commit_g1(srs, &quotient)?;
    let z_commit_g2 = commit_g2(srs, &z_poly)?;
    if emit_timing {
        eprintln!("stage=update_kzg millis={}", kzg_start.elapsed().as_millis());
    }

    let logic_start = Instant::now();
    let r_u = derive_scalar("r-u", &[&fr_vec_bytes(&witness.u_values)]);
    let r_d = derive_scalar("r-d", &[new_state_root.as_bytes(), &witness.d_value.to_le_bytes()]);
    let c_u = commit_linear(&witness.u_values, "membership-u", "membership-h", r_u);
    let c_d = commit_balance(witness.d_value, r_d);

    let old_balance_commitment = point_g1_from_hex(&state.balance_commitment_hex)?;
    let old_accumulator = point_g1_from_hex(&state.accumulator_hex)?;
    let next_balance_commitment = old_balance_commitment + c_d;
    let next_balance_total = state.balance_total + witness.d_value;
    let next_balance_blind = state.balance_blind + r_d;

    let c_u_hex = point_g1_to_hex(&c_u)?;
    let c_y_hex = point_g1_to_hex(&c_y)?;
    let c_d_hex = point_g1_to_hex(&c_d)?;
    let eval_proof_hex = point_g1_to_hex(&eval_proof)?;
    let logic_proof = prove_logic(
        srs,
        &witness,
        deltas,
        &c_u_hex,
        &c_y_hex,
        &c_d_hex,
        r_u,
        rho_y,
        r_d,
        Some(&query_ctx),
    )?;
    if emit_timing {
        eprintln!("stage=update_logic millis={}", logic_start.elapsed().as_millis());
    }

    let transcript_hex = build_transcript_hex(
        &state.state_root,
        new_state_root,
        &state.accumulator_hex,
        &c_u_hex,
        &c_y_hex,
        &c_d_hex,
        &eval_proof_hex,
    );

    let proof = StoredProof {
        old_state_root: state.state_root.clone(),
        new_state_root: new_state_root.to_string(),
        c_u_hex,
        c_y_hex,
        c_d_hex,
        eval_proof_hex,
        d_value: witness.d_value,
        r_u,
        rho_y,
        r_d,
        y_values: Vec::new(),
        u_values: Vec::new(),
        z_values: Vec::new(),
        w_values: Vec::new(),
        gate_count: deltas.len() * 4,
        transcript_hex,
        bp_proof_hex: logic_proof.bp_proof_hex,
        bp_commitments_hex: logic_proof.bp_commitments_hex,
        link_proof_hex: logic_proof.link_proof_hex,
    };

    let next_state = StoredState {
        state_root: new_state_root.to_string(),
        srs_max_degree: state.srs_max_degree,
        alpha: state.alpha,
        reserve_addresses: state.reserve_addresses.clone(),
        reserve_balances: state.reserve_balances.clone(),
        masked_polynomial_coeffs: state.masked_polynomial_coeffs.clone(),
        accumulator_hex: state.accumulator_hex.clone(),
        balance_total: next_balance_total,
        balance_blind: next_balance_blind,
        balance_commitment_hex: point_g1_to_hex(&next_balance_commitment)?,
    };

    #[cfg(debug_assertions)]
    if env::var("POA_DEBUG_INTERNAL_VERIFY").ok().as_deref() == Some("1") {
        verify_internal(
            srs,
            state,
            deltas,
            &next_state,
            &proof,
            &witness,
            &old_accumulator,
            &z_poly,
            &z_commit_g2,
            &j_y,
        )?;
    }

    Ok(UpdateResult { next_state, proof })
}

fn verify_internal(
    srs: &Srs,
    state: &StoredState,
    deltas: &[Delta],
    next_state: &StoredState,
    proof: &StoredProof,
    witness: &UpdateWitness,
    accumulator: &G1Projective,
    z_poly: &Polynomial,
    z_commit_g2: &G2Projective,
    j_y: &Polynomial,
) -> Result<(), String> {
    let c_y = point_g1_from_hex(&proof.c_y_hex)?;
    let eval_proof = point_g1_from_hex(&proof.eval_proof_hex)?;
    if !verify_batch(accumulator, &c_y, &eval_proof, z_commit_g2) {
        return Err("KZG batch verification failed during internal consistency check".to_string());
    }

    let lagrange = lagrange_basis(&witness.x_values)?;
    let mut structured = G1Projective::zero();
    for (basis, y) in lagrange.iter().zip(witness.y_values.iter()) {
        let basis_commit = commit_g1(srs, basis)?;
        structured += basis_commit.mul_bigint(y.into_bigint());
    }
    let h_y = commit_g1(srs, z_poly)?;
    structured += h_y.mul_bigint(proof.rho_y.into_bigint());
    if structured != c_y {
        return Err("structured C_Y opening mismatch".to_string());
    }

    let reopened_j = commit_g1(srs, j_y)?;
    if reopened_j != c_y {
        return Err("J_Y commitment mismatch".to_string());
    }

    let expected_transcript = build_transcript_hex(
        &state.state_root,
        &next_state.state_root,
        &state.accumulator_hex,
        &proof.c_u_hex,
        &proof.c_y_hex,
        &proof.c_d_hex,
        &proof.eval_proof_hex,
    );
    if proof.transcript_hex != expected_transcript {
        return Err("Fiat-Shamir transcript mismatch".to_string());
    }

    let projected_delta: i128 = deltas
        .iter()
        .zip(witness.u_values.iter())
        .map(|(delta, bit)| if *bit == Fr::one() { delta.delta } else { 0 })
        .sum();
    if projected_delta != proof.d_value {
        return Err("delta projection mismatch".to_string());
    }
    Ok(())
}

fn ensure_distinct(points: &[Fr]) -> Result<(), String> {
    let mut seen = HashSet::with_capacity(points.len());
    for point in points {
        if !seen.insert(scalar_to_hex(point).map_err(|err| format!("distinct check encode: {err}"))?) {
            return Err("duplicate encoded query point".to_string());
        }
    }
    Ok(())
}

fn derive_scalar(label: &str, chunks: &[&[u8]]) -> Fr {
    let mut bytes = Vec::new();
    for chunk in chunks {
        bytes.extend_from_slice(chunk);
    }
    let mut scalar = hash_to_scalar(label, &bytes);
    if scalar.is_zero() {
        scalar = Fr::from(29u64);
    }
    scalar
}

fn fr_vec_bytes(values: &[Fr]) -> Vec<u8> {
    let mut out = Vec::new();
    for value in values {
        out.extend_from_slice(&value.into_bigint().to_bytes_le());
        out.push(b'|');
    }
    out
}

fn build_transcript_hex(
    old_root: &str,
    new_root: &str,
    accumulator_hex: &str,
    c_u_hex: &str,
    c_y_hex: &str,
    c_d_hex: &str,
    eval_proof_hex: &str,
) -> String {
    let payload = [
        old_root,
        new_root,
        accumulator_hex,
        c_u_hex,
        c_y_hex,
        c_d_hex,
        eval_proof_hex,
    ]
    .join("|");
    common::crypto::hex_encode(blake3::hash(payload.as_bytes()).as_bytes())
}
