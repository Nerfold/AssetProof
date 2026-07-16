use ark_bls12_381::{Fr, G1Projective, G2Projective};
use ark_ec::PrimeGroup;
use ark_ff::{One, PrimeField, UniformRand, Zero};
use std::collections::HashSet;
use std::env;
use std::thread;
use std::time::Instant;

use common::crypto::{hash_bytes, hex_encode, point_g1_from_hex, point_g1_to_hex, scalar_to_hex};
use common::types::{Delta, StoredProof, StoredState};

use crate::bp::{commit_membership_vector, prove_optimized_zero_test_logic, prove_projection_ipa};
use crate::commitment::commit_balance;
use crate::kzg::{commit_g1, verify_batch, Srs};
use crate::polynomial::{lagrange_basis, Polynomial, QueryContext};
use crate::range::{check_public_delta_range, RangePolicy};
use crate::threshold::{prove_threshold, ThresholdStatement, ThresholdWitness};
use crate::witness::{build_update_witness_from_evaluations, encode_delta_points, UpdateWitness};

#[derive(Clone, Debug)]
pub struct UpdateResult {
    pub next_state: StoredState,
    pub proof: StoredProof,
    pub aggregate_delta: i128,
}

pub(crate) const EMPTY_UPDATE_MARKER: &str = "dpoa-empty-update-v1";

pub fn apply_update(
    srs: &Srs,
    state: &StoredState,
    deltas: &[Delta],
    new_state_root: &str,
) -> Result<UpdateResult, String> {
    if state.srs_max_degree != srs.max_degree {
        return Err("state SRS degree does not match provided SRS".to_string());
    }
    if deltas.len() > srs.max_degree {
        return Err(format!(
            "update has {} entries, exceeding SRS-supported maximum {}",
            deltas.len(),
            srs.max_degree
        ));
    }
    if state.reserve_addresses.len() != state.reserve_balances.len() {
        return Err(
            "stored reserve address and balance vectors have different lengths".to_string(),
        );
    }
    if state.reserve_addresses.len() > srs.max_degree {
        return Err("stored reserve set exceeds the SRS degree bound".to_string());
    }
    if state.reserve_balances.iter().any(|balance| *balance < 0) {
        return Err("stored reserve balances must be non-negative".to_string());
    }
    if deltas.is_empty() {
        return apply_empty_update(state, new_state_root);
    }
    check_public_delta_range(deltas, &RangePolicy::protocol_default())?;
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
    let mut rng = rand::rngs::OsRng;
    let rho_y = Fr::rand(&mut rng);
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
    let r_u = Fr::rand(&mut rng);
    let r_d = Fr::rand(&mut rng);
    let c_u = commit_membership_vector(&witness.u_values, r_u)?;
    let c_d = commit_balance(witness.d_value, r_d);

    let old_balance_commitment = point_g1_from_hex(&state.balance_commitment_hex)?;
    let next_balance_commitment = old_balance_commitment + c_d;
    let next_balance_commitment_hex = point_g1_to_hex(&next_balance_commitment)?;
    let next_balance_total = state
        .balance_total
        .checked_add(witness.d_value)
        .ok_or_else(|| "updated balance total overflowed i128".to_string())?;
    if next_balance_total < 0 {
        return Err("updated balance total is negative".to_string());
    }
    let next_balance_blind = state.balance_blind + r_d;
    if old_balance_commitment != commit_balance(state.balance_total, state.balance_blind) {
        return Err("stored balance opening does not match its commitment".to_string());
    }

    let reserve_roots = state
        .reserve_addresses
        .iter()
        .map(|address| common::encoding::encode_address(address))
        .collect::<Result<Vec<_>, _>>()?;
    if reserve_roots
        .windows(2)
        .any(|pair| pair[0].into_bigint() >= pair[1].into_bigint())
    {
        return Err("stored reserve addresses are not in canonical strict order".to_string());
    }
    let mut next_reserve_balances = state.reserve_balances.clone();
    for (point, delta) in x_values.iter().zip(deltas.iter()) {
        if let Ok(index) = reserve_roots
            .binary_search_by(|candidate| candidate.into_bigint().cmp(&point.into_bigint()))
        {
            let next_balance = next_reserve_balances[index]
                .checked_add(delta.delta)
                .ok_or_else(|| "updated reserve balance overflowed i128".to_string())?;
            if next_balance < 0 {
                return Err(format!(
                    "update would make reserve account {} negative",
                    state.reserve_addresses[index]
                ));
            }
            next_reserve_balances[index] = next_balance;
        }
    }
    let recomputed_total = next_reserve_balances
        .iter()
        .try_fold(0i128, |sum, balance| {
            sum.checked_add(*balance)
                .ok_or_else(|| "updated reserve balance total overflowed i128".to_string())
        })?;
    if recomputed_total != next_balance_total {
        return Err("updated private reserve balances do not match aggregate balance".to_string());
    }

    let next_state = StoredState {
        state_root: new_state_root.to_string(),
        srs_max_degree: state.srs_max_degree,
        alpha: state.alpha,
        reserve_addresses: state.reserve_addresses.clone(),
        reserve_balances: next_reserve_balances,
        masked_polynomial_coeffs: state.masked_polynomial_coeffs.clone(),
        accumulator_hex: state.accumulator_hex.clone(),
        balance_total: next_balance_total,
        balance_blind: next_balance_blind,
        balance_commitment_hex: next_balance_commitment_hex.clone(),
    };

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
    let prove_balance_range = || -> Result<String, String> {
        let range_start = Instant::now();
        let range_proof = prove_threshold(
            &ThresholdStatement {
                public_state: next_state.public_state(),
                threshold: 0,
            },
            &ThresholdWitness {
                asset_total: next_state.balance_total,
                asset_blind: next_state.balance_blind,
            },
        )?;
        if emit_timing {
            eprintln!(
                "stage=update_balance_range_proof millis={}",
                range_start.elapsed().as_millis()
            );
        }
        Ok(range_proof.proof_hex)
    };
    let parallel_enabled = env::var("POA_DISABLE_PROVER_PARALLEL").ok().as_deref() != Some("1");
    let (eval_proof, zero_test_proof, projection_ipa_proof, balance_range_proof_hex) =
        if parallel_enabled {
            thread::scope(|scope| -> Result<_, String> {
                let kzg_handle = scope.spawn(prove_kzg);
                let logic_handle = scope.spawn(prove_logic);
                let range_handle = scope.spawn(prove_balance_range);
                let eval_proof = kzg_handle
                    .join()
                    .map_err(|_| "KZG prover worker panicked".to_string())??;
                let (zero_test_proof, projection_ipa_proof) = logic_handle
                    .join()
                    .map_err(|_| "logic prover worker panicked".to_string())??;
                let balance_range_proof_hex = range_handle
                    .join()
                    .map_err(|_| "balance range prover worker panicked".to_string())??;
                Ok((
                    eval_proof,
                    zero_test_proof,
                    projection_ipa_proof,
                    balance_range_proof_hex,
                ))
            })?
        } else {
            let eval_proof = prove_kzg()?;
            let (zero_test_proof, projection_ipa_proof) = prove_logic()?;
            let balance_range_proof_hex = prove_balance_range()?;
            (
                eval_proof,
                zero_test_proof,
                projection_ipa_proof,
                balance_range_proof_hex,
            )
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
        gate_count: deltas
            .len()
            .checked_mul(2)
            .ok_or_else(|| "update gate count overflow".to_string())?,
        transcript_hex,
        bp_proof_hex: zero_test_proof.bp_proof_hex,
        witness_vector_commitment_hex: zero_test_proof.witness_vector_commitment_hex,
        rho_bp_commitment_hex: zero_test_proof.rho_bp_commitment_hex,
        v_bp_commitment_hex: zero_test_proof.v_bp_commitment_hex,
        witness_link_ipa_proof: zero_test_proof.witness_link_ipa_proof,
        v_link_proof: zero_test_proof.v_link_proof,
        projection_ipa_proof,
        balance_range_proof_hex,
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

fn apply_empty_update(state: &StoredState, new_state_root: &str) -> Result<UpdateResult, String> {
    let balance_commitment = point_g1_from_hex(&state.balance_commitment_hex)?;
    if balance_commitment != commit_balance(state.balance_total, state.balance_blind) {
        return Err("stored balance opening does not match its commitment".to_string());
    }
    let balance_total = state
        .reserve_balances
        .iter()
        .try_fold(0i128, |sum, balance| {
            sum.checked_add(*balance)
                .ok_or_else(|| "stored reserve balance total overflowed i128".to_string())
        })?;
    if balance_total != state.balance_total {
        return Err("stored reserve balances do not match aggregate balance".to_string());
    }
    let reserve_roots = state
        .reserve_addresses
        .iter()
        .map(|address| common::encoding::encode_address(address))
        .collect::<Result<Vec<_>, _>>()?;
    if reserve_roots
        .windows(2)
        .any(|pair| pair[0].into_bigint() >= pair[1].into_bigint())
    {
        return Err("stored reserve addresses are not in canonical strict order".to_string());
    }

    let delta_list_commitment_hex = delta_list_commitment(&[]);
    let theta = Fr::zero();
    let transcript_hex = build_transcript_hex(
        &state.state_root,
        new_state_root,
        &state.accumulator_hex,
        &delta_list_commitment_hex,
        "",
        "",
        "",
        "",
        "",
        theta,
        EMPTY_UPDATE_MARKER,
    );
    let mut next_state = state.clone();
    next_state.state_root = new_state_root.to_string();
    Ok(UpdateResult {
        next_state,
        proof: StoredProof {
            old_state_root: state.state_root.clone(),
            new_state_root: new_state_root.to_string(),
            delta_list_commitment_hex,
            c_u_hex: String::new(),
            c_y_hex: String::new(),
            c_d_hex: String::new(),
            eval_proof_hex: String::new(),
            c_v_hex: String::new(),
            theta,
            theta_opening_proof_hex: EMPTY_UPDATE_MARKER.to_string(),
            gate_count: 0,
            transcript_hex,
            bp_proof_hex: String::new(),
            witness_vector_commitment_hex: String::new(),
            rho_bp_commitment_hex: String::new(),
            v_bp_commitment_hex: String::new(),
            witness_link_ipa_proof: Vec::new(),
            v_link_proof: Vec::new(),
            projection_ipa_proof: Vec::new(),
            balance_range_proof_hex: String::new(),
        },
        aggregate_delta: 0,
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

    let projected_delta =
        deltas
            .iter()
            .zip(witness.u_values.iter())
            .try_fold(0i128, |sum, (delta, bit)| {
                let contribution = if *bit == Fr::one() { delta.delta } else { 0 };
                sum.checked_add(contribution)
                    .ok_or_else(|| "delta projection overflowed i128".to_string())
            })?;
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

pub(crate) fn build_transcript_hex(
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
    let mut chunks = Vec::new();
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
