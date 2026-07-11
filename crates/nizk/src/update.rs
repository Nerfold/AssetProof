use ark_bls12_381::{Fr, G1Projective, G2Projective};
use ark_ec::PrimeGroup;
use ark_ff::{BigInteger, One, PrimeField, Zero};
use std::collections::HashSet;
use std::env;
use std::thread;
use std::time::Instant;

use common::crypto::{
    hash_bytes, hash_to_scalar, hex_encode, point_g1_from_hex, point_g1_to_hex, scalar_to_hex,
};
use common::types::{Delta, StoredProof, StoredState};

use crate::bp::{commit_membership_vector, prove_optimized_zero_test_logic, prove_projection_ipa};
use crate::commitment::commit_balance;
use crate::kzg::{commit_g1, verify_batch, Srs};
use crate::polynomial::{lagrange_basis, Polynomial, QueryContext};
use crate::witness::{build_update_witness_from_evaluations, encode_delta_points, UpdateWitness};

#[derive(Clone, Debug)]
pub struct UpdateResult {
    pub next_state: StoredState,
    pub proof: StoredProof,
    pub aggregate_delta: i128,
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
    let polynomial_load_start = Instant::now();
    let polynomial = Polynomial::from_coeffs(state.masked_polynomial_coeffs.clone());
    if emit_timing {
        eprintln!(
            "stage=update_polynomial_load millis={}",
            polynomial_load_start.elapsed().as_millis()
        );
    }
    let query_context_start = Instant::now();
    let x_values = encode_delta_points(deltas)?;
    ensure_distinct(&x_values)?;
    let query_ctx = QueryContext::new(&x_values)?;
    if emit_timing {
        eprintln!(
            "stage=update_query_context millis={}",
            query_context_start.elapsed().as_millis()
        );
    }
    let evaluation_start = Instant::now();
    let evaluation = query_ctx.evaluate_with_quotient(&polynomial)?;
    if emit_timing {
        eprintln!(
            "stage=update_fft_divide_and_evaluate millis={}",
            evaluation_start.elapsed().as_millis()
        );
    }
    let witness_finalize_start = Instant::now();
    let witness = build_update_witness_from_evaluations(x_values, evaluation.values, deltas)?;
    if emit_timing {
        eprintln!(
            "stage=update_witness_finalize millis={}",
            witness_finalize_start.elapsed().as_millis()
        );
    }
    if emit_timing {
        eprintln!(
            "stage=update_witness millis={}",
            witness_start.elapsed().as_millis()
        );
    }

    let kzg_start = Instant::now();
    let kzg_polynomial_start = Instant::now();
    let z_poly = query_ctx.z_poly().clone();
    let i_y = evaluation.remainder;
    let rho_y = derive_scalar(
        "rho-y",
        &[new_state_root.as_bytes(), &fr_vec_bytes(&witness.y_values)],
    );
    let j_y = i_y.add(&z_poly.mul_scalar(rho_y));
    let mut quotient = evaluation.quotient;
    quotient.sub_constant_assign(rho_y);
    if emit_timing {
        eprintln!(
            "stage=update_kzg_polynomial_prepare millis={}",
            kzg_polynomial_start.elapsed().as_millis()
        );
    }

    let c_y_start = Instant::now();
    let c_y = commit_g1(srs, &j_y)?;
    if emit_timing {
        eprintln!(
            "stage=update_kzg_c_y_msm millis={}",
            c_y_start.elapsed().as_millis()
        );
    }
    let r_u = derive_scalar("r-u", &[&fr_vec_bytes(&witness.u_values)]);
    let r_d = derive_scalar(
        "r-d",
        &[new_state_root.as_bytes(), &witness.d_value.to_le_bytes()],
    );
    let c_u = commit_membership_vector(&witness.u_values, r_u)?;
    let c_d = commit_balance(witness.d_value, r_d);

    let old_balance_commitment = point_g1_from_hex(&state.balance_commitment_hex)?;
    let next_balance_commitment = old_balance_commitment + c_d;
    let next_balance_commitment_hex = point_g1_to_hex(&next_balance_commitment)?;
    let next_balance_total = state.balance_total + witness.d_value;
    let next_balance_blind = state.balance_blind + r_d;

    let c_u_hex = point_g1_to_hex(&c_u)?;
    let c_y_hex = point_g1_to_hex(&c_y)?;
    let c_d_hex = point_g1_to_hex(&c_d)?;
    let parallel_phase_start = Instant::now();
    let prove_kzg = || -> Result<G1Projective, String> {
        let quotient_msm_start = Instant::now();
        let result = commit_g1(srs, &quotient);
        if emit_timing {
            eprintln!(
                "stage=update_kzg_quotient_msm millis={}",
                quotient_msm_start.elapsed().as_millis()
            );
        }
        result
    };
    let prove_logic = || -> Result<(_, _), String> {
        let logic_start = Instant::now();
        let zero_test_proof = prove_optimized_zero_test_logic(
            srs,
            &witness,
            deltas,
            &state.state_root,
            new_state_root,
            &state.accumulator_hex,
            &state.balance_commitment_hex,
            &next_balance_commitment_hex,
            &c_u_hex,
            &c_y_hex,
            &c_d_hex,
            r_u,
            rho_y,
            &query_ctx,
            &j_y,
        )?;
        let projection_ipa_proof =
            prove_projection_ipa(&witness.u_values, deltas, &c_u_hex, &c_d_hex, r_u, r_d)?;
        if emit_timing {
            eprintln!(
                "stage=update_logic millis={}",
                logic_start.elapsed().as_millis()
            );
        }
        Ok((zero_test_proof, projection_ipa_proof))
    };
    let parallel_enabled = env::var("POA_DISABLE_PROVER_PARALLEL").ok().as_deref() != Some("1");
    let (eval_proof, zero_test_proof, projection_ipa_proof) = if parallel_enabled {
        thread::scope(|scope| -> Result<_, String> {
            let kzg_handle = scope.spawn(prove_kzg);
            let logic_handle = scope.spawn(prove_logic);
            let eval_proof = kzg_handle
                .join()
                .map_err(|_| "KZG prover worker panicked".to_string())??;
            let (zero_test_proof, projection_ipa_proof) = logic_handle
                .join()
                .map_err(|_| "logic prover worker panicked".to_string())??;
            Ok((eval_proof, zero_test_proof, projection_ipa_proof))
        })?
    } else {
        let eval_proof = prove_kzg()?;
        let (zero_test_proof, projection_ipa_proof) = prove_logic()?;
        (eval_proof, zero_test_proof, projection_ipa_proof)
    };
    if emit_timing {
        eprintln!(
            "stage=update_parallel_proof_phase millis={} enabled={}",
            parallel_phase_start.elapsed().as_millis(),
            parallel_enabled
        );
        eprintln!(
            "stage=update_kzg millis={}",
            kzg_start.elapsed().as_millis()
        );
    }
    let eval_proof_hex = point_g1_to_hex(&eval_proof)?;

    let delta_list_commitment_hex = delta_list_commitment(deltas);
    let transcript_hex = build_transcript_hex(
        &state.state_root,
        new_state_root,
        &state.accumulator_hex,
        &delta_list_commitment_hex,
        &c_u_hex,
        &c_y_hex,
        &c_d_hex,
        &eval_proof_hex,
        &zero_test_proof.c_v_hex,
        zero_test_proof.theta,
        &zero_test_proof.theta_opening_proof_hex,
    );

    let proof = StoredProof {
        old_state_root: state.state_root.clone(),
        new_state_root: new_state_root.to_string(),
        delta_list_commitment_hex,
        c_u_hex,
        c_y_hex,
        c_d_hex,
        eval_proof_hex,
        c_v_hex: zero_test_proof.c_v_hex,
        theta: zero_test_proof.theta,
        theta_opening_proof_hex: zero_test_proof.theta_opening_proof_hex,
        gate_count: deltas.len() * 2,
        transcript_hex,
        bp_proof_hex: zero_test_proof.bp_proof_hex,
        witness_vector_commitment_hex: zero_test_proof.witness_vector_commitment_hex,
        rho_bp_commitment_hex: zero_test_proof.rho_bp_commitment_hex,
        v_bp_commitment_hex: zero_test_proof.v_bp_commitment_hex,
        witness_link_ipa_proof: zero_test_proof.witness_link_ipa_proof,
        v_link_proof: zero_test_proof.v_link_proof,
        projection_ipa_proof,
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
        balance_commitment_hex: next_balance_commitment_hex,
    };

    #[cfg(debug_assertions)]
    if env::var("POA_DEBUG_INTERNAL_VERIFY").ok().as_deref() == Some("1") {
        let z_commit_g2 = crate::kzg::commit_g2(srs, &z_poly)?;
        verify_internal(
            srs,
            state,
            deltas,
            &next_state,
            &proof,
            &witness,
            &z_poly,
            &z_commit_g2,
            &j_y,
            rho_y,
        )?;
    }

    Ok(UpdateResult {
        next_state,
        proof,
        aggregate_delta: witness.d_value,
    })
}

fn verify_internal(
    srs: &Srs,
    state: &StoredState,
    deltas: &[Delta],
    next_state: &StoredState,
    proof: &StoredProof,
    witness: &UpdateWitness,
    z_poly: &Polynomial,
    z_commit_g2: &G2Projective,
    j_y: &Polynomial,
    rho_y: Fr,
) -> Result<(), String> {
    let c_y = point_g1_from_hex(&proof.c_y_hex)?;
    let eval_proof = point_g1_from_hex(&proof.eval_proof_hex)?;
    let accumulator = point_g1_from_hex(&state.accumulator_hex)?;
    if !verify_batch(&accumulator, &c_y, &eval_proof, z_commit_g2) {
        return Err("KZG batch verification failed during internal consistency check".to_string());
    }

    let lagrange = lagrange_basis(&witness.x_values)?;
    let mut structured = G1Projective::zero();
    for (basis, y) in lagrange.iter().zip(witness.y_values.iter()) {
        let basis_commit = commit_g1(srs, basis)?;
        structured += basis_commit.mul_bigint(y.into_bigint());
    }
    let h_y = commit_g1(srs, z_poly)?;
    structured += h_y.mul_bigint(rho_y.into_bigint());
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
        &proof.delta_list_commitment_hex,
        &proof.c_u_hex,
        &proof.c_y_hex,
        &proof.c_d_hex,
        &proof.eval_proof_hex,
        &proof.c_v_hex,
        proof.theta,
        &proof.theta_opening_proof_hex,
    );
    if proof.transcript_hex != expected_transcript {
        return Err("Fiat-Shamir transcript mismatch".to_string());
    }

    let projected_delta: i128 = deltas
        .iter()
        .zip(witness.u_values.iter())
        .map(|(delta, bit)| if *bit == Fr::one() { delta.delta } else { 0 })
        .sum();
    if projected_delta != witness.d_value {
        return Err("delta projection mismatch".to_string());
    }
    Ok(())
}

fn ensure_distinct(points: &[Fr]) -> Result<(), String> {
    let mut seen = HashSet::with_capacity(points.len());
    for point in points {
        if !seen
            .insert(scalar_to_hex(point).map_err(|err| format!("distinct check encode: {err}"))?)
        {
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
    delta_list_commitment_hex: &str,
    c_u_hex: &str,
    c_y_hex: &str,
    c_d_hex: &str,
    eval_proof_hex: &str,
    c_v_hex: &str,
    theta: Fr,
    theta_opening_proof_hex: &str,
) -> String {
    let theta_hex = scalar_to_hex(&theta).unwrap_or_else(|_| "invalid-theta".to_string());
    let payload = [
        old_root,
        new_root,
        accumulator_hex,
        delta_list_commitment_hex,
        c_u_hex,
        c_y_hex,
        c_d_hex,
        eval_proof_hex,
        c_v_hex,
        &theta_hex,
        theta_opening_proof_hex,
    ]
    .join("|");
    common::crypto::hex_encode(blake3::hash(payload.as_bytes()).as_bytes())
}

pub fn delta_list_commitment(deltas: &[Delta]) -> String {
    let mut chunks = Vec::with_capacity(1 + deltas.len() * 2);
    let len = deltas.len().to_string();
    chunks.push(len.into_bytes());
    for delta in deltas {
        chunks.push(delta.address.as_bytes().to_vec());
        chunks.push(delta.delta.to_le_bytes().to_vec());
    }
    let refs = chunks
        .iter()
        .map(|chunk| chunk.as_slice())
        .collect::<Vec<_>>();
    hex_encode(&hash_bytes("dynamic-poa-canonical-delta-list", &refs))
}
