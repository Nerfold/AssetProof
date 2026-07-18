use ark_bls12_381::Fr;
use ark_ff::{PrimeField, UniformRand};
use std::env;
use std::thread;
use std::time::Instant;

use common::crypto::{hex_encode, point_g1_from_hex, point_g1_to_hex};
use common::encoding::encode_address;
use common::types::{Delta, StoredProof, StoredState};

use crate::bp::{commit_membership_vector, prove_direct_zero_test_logic, prove_projection_ipa};
use crate::commitment::commit_balance;
use crate::kzg::{commit_g1, Srs};
use crate::multizkopen::{commit_evaluation_vector, prove_multi_zkopen};
use crate::polynomial::{Polynomial, QueryContext};
use crate::range::{check_public_delta_range, RangePolicy};
use crate::threshold::{prove_threshold, ThresholdStatement, ThresholdWitness};
use crate::witness::{build_update_witness_from_evaluations, encode_delta_points};

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
    let query_ctx = QueryContext::new(&x_values)?;
    if emit_timing {
        eprintln!(
            "stage=update_query_context millis={}",
            query_context_start.elapsed().as_millis()
        );
    }
    let evaluation_start = Instant::now();
    let evaluation = query_ctx.evaluate_with_quotient_owned(polynomial)?;
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
    let mut rng = rand::rngs::OsRng;
    let r_y = Fr::rand(&mut rng);
    let quotient = evaluation.quotient;
    if emit_timing {
        eprintln!(
            "stage=update_kzg_polynomial_prepare millis={}",
            kzg_polynomial_start.elapsed().as_millis()
        );
    }

    let d_y_start = Instant::now();
    let d_y = commit_evaluation_vector(&witness.y_values, r_y)?;
    if emit_timing {
        eprintln!(
            "stage=update_d_y_vector_msm millis={}",
            d_y_start.elapsed().as_millis()
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
    let mut next_reserve_balances = state.reserve_balances.clone();
    for (point, delta) in witness.x_values.iter().zip(deltas.iter()) {
        if let Some(index) = find_encoded_address(&state.reserve_addresses, *point)? {
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

    let mut next_public_state = state.public_state();
    next_public_state.state_root = new_state_root.to_string();
    next_public_state.balance_commitment_hex = next_balance_commitment_hex.clone();

    let c_u_hex = point_g1_to_hex(&c_u)?;
    let d_y_hex = point_g1_to_hex(&d_y)?;
    let c_d_hex = point_g1_to_hex(&c_d)?;
    let delta_list_commitment_hex = delta_list_commitment(deltas);
    let multi_zkopen_context = build_multi_zkopen_context(
        &state.state_root,
        new_state_root,
        &state.accumulator_hex,
        &state.balance_commitment_hex,
        &next_balance_commitment_hex,
        &delta_list_commitment_hex,
        &c_u_hex,
        &d_y_hex,
        &c_d_hex,
    );
    let parallel_phase_start = Instant::now();
    let prove_kzg = || -> Result<String, String> {
        let quotient_msm_start = Instant::now();
        let batch_opening = commit_g1(srs, &quotient)?;
        if emit_timing {
            eprintln!(
                "stage=update_kzg_quotient_msm millis={}",
                quotient_msm_start.elapsed().as_millis()
            );
        }
        let accumulator = point_g1_from_hex(&state.accumulator_hex)?;
        prove_multi_zkopen(
            srs,
            &accumulator,
            &witness.x_values,
            &witness.y_values,
            &d_y,
            r_y,
            &batch_opening,
            &multi_zkopen_context,
        )
    };
    let prove_logic = || -> Result<(_, _), String> {
        let logic_start = Instant::now();
        let zero_test_proof = prove_direct_zero_test_logic(
            &witness,
            deltas,
            &state.state_root,
            new_state_root,
            &state.accumulator_hex,
            &state.balance_commitment_hex,
            &next_balance_commitment_hex,
            &c_u_hex,
            &d_y_hex,
            &c_d_hex,
            r_u,
            r_y,
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
                public_state: next_public_state.clone(),
                threshold: 0,
            },
            &ThresholdWitness {
                asset_total: next_balance_total,
                asset_blind: next_balance_blind,
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
    let (multi_zkopen_proof_hex, zero_test_proof, projection_ipa_proof, balance_range_proof_hex) =
        if parallel_enabled {
            thread::scope(|scope| -> Result<_, String> {
                let kzg_handle = scope.spawn(prove_kzg);
                let logic_handle = scope.spawn(prove_logic);
                let range_handle = scope.spawn(prove_balance_range);
                let multi_zkopen_proof_hex = kzg_handle
                    .join()
                    .map_err(|_| "KZG prover worker panicked".to_string())??;
                let (zero_test_proof, projection_ipa_proof) = logic_handle
                    .join()
                    .map_err(|_| "logic prover worker panicked".to_string())??;
                let balance_range_proof_hex = range_handle
                    .join()
                    .map_err(|_| "balance range prover worker panicked".to_string())??;
                Ok((
                    multi_zkopen_proof_hex,
                    zero_test_proof,
                    projection_ipa_proof,
                    balance_range_proof_hex,
                ))
            })?
        } else {
            let multi_zkopen_proof_hex = prove_kzg()?;
            let (zero_test_proof, projection_ipa_proof) = prove_logic()?;
            let balance_range_proof_hex = prove_balance_range()?;
            (
                multi_zkopen_proof_hex,
                zero_test_proof,
                projection_ipa_proof,
                balance_range_proof_hex,
            )
        };
    drop(quotient);
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
    let transcript_hex = build_transcript_hex(
        &state.state_root,
        new_state_root,
        &state.accumulator_hex,
        &delta_list_commitment_hex,
        &c_u_hex,
        &d_y_hex,
        &c_d_hex,
        &multi_zkopen_proof_hex,
    );

    let proof = StoredProof {
        old_state_root: state.state_root.clone(),
        new_state_root: new_state_root.to_string(),
        delta_list_commitment_hex,
        c_u_hex,
        d_y_hex,
        c_d_hex,
        multi_zkopen_proof_hex,
        gate_count: deltas
            .len()
            .checked_mul(2)
            .ok_or_else(|| "update gate count overflow".to_string())?,
        transcript_hex,
        bp_proof_hex: zero_test_proof.bp_proof_hex,
        committed_input_link_ipa_proof: zero_test_proof.committed_input_link_ipa_proof,
        projection_ipa_proof,
        balance_range_proof_hex,
    };

    // Materialize the linear-size successor only after the parallel proof
    // workers have released their large MSM/IPA scratch buffers.
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
        balance_commitment_hex: next_balance_commitment_hex,
    };

    Ok(UpdateResult {
        next_state,
        proof,
        aggregate_delta: witness.d_value,
    })
}

fn apply_empty_update(state: &StoredState, new_state_root: &str) -> Result<UpdateResult, String> {
    let delta_list_commitment_hex = delta_list_commitment(&[]);
    let transcript_hex = build_transcript_hex(
        &state.state_root,
        new_state_root,
        &state.accumulator_hex,
        &delta_list_commitment_hex,
        "",
        "",
        "",
        "",
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
            d_y_hex: String::new(),
            c_d_hex: String::new(),
            multi_zkopen_proof_hex: String::new(),
            gate_count: 0,
            transcript_hex,
            bp_proof_hex: String::new(),
            committed_input_link_ipa_proof: Vec::new(),
            projection_ipa_proof: Vec::new(),
            balance_range_proof_hex: String::new(),
        },
        aggregate_delta: 0,
    })
}

pub(crate) fn build_transcript_hex(
    old_root: &str,
    new_root: &str,
    accumulator_hex: &str,
    delta_list_commitment_hex: &str,
    c_u_hex: &str,
    d_y_hex: &str,
    c_d_hex: &str,
    multi_zkopen_proof_hex: &str,
) -> String {
    let fields = [
        old_root,
        new_root,
        accumulator_hex,
        delta_list_commitment_hex,
        c_u_hex,
        d_y_hex,
        c_d_hex,
        multi_zkopen_proof_hex,
    ];
    let mut hasher = blake3::Hasher::new();
    for (index, field) in fields.iter().enumerate() {
        if index != 0 {
            hasher.update(b"|");
        }
        hasher.update(field.as_bytes());
    }
    common::crypto::hex_encode(hasher.finalize().as_bytes())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_multi_zkopen_context(
    old_root: &str,
    new_root: &str,
    accumulator_hex: &str,
    old_balance_commitment_hex: &str,
    new_balance_commitment_hex: &str,
    delta_list_commitment_hex: &str,
    c_u_hex: &str,
    d_y_hex: &str,
    c_d_hex: &str,
) -> Vec<u8> {
    let fields = [
        old_root.as_bytes(),
        new_root.as_bytes(),
        accumulator_hex.as_bytes(),
        old_balance_commitment_hex.as_bytes(),
        new_balance_commitment_hex.as_bytes(),
        delta_list_commitment_hex.as_bytes(),
        c_u_hex.as_bytes(),
        d_y_hex.as_bytes(),
        c_d_hex.as_bytes(),
    ];
    let mut context = Vec::new();
    context.extend_from_slice(b"dynamic-poa-update-multizkopen-context-v1");
    for field in fields {
        context.extend_from_slice(&(field.len() as u64).to_le_bytes());
        context.extend_from_slice(field);
    }
    context
}

pub fn delta_list_commitment(deltas: &[Delta]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"dynamic-poa-canonical-delta-list");
    hasher.update(deltas.len().to_string().as_bytes());
    for delta in deltas {
        hasher.update(delta.address.as_bytes());
        hasher.update(&delta.delta.to_le_bytes());
    }
    hex_encode(hasher.finalize().as_bytes())
}

fn find_encoded_address(addresses: &[String], target: Fr) -> Result<Option<usize>, String> {
    let target = target.into_bigint();
    let mut left = 0usize;
    let mut right = addresses.len();
    while left < right {
        let middle = left + (right - left) / 2;
        let candidate = encode_address(&addresses[middle])?.into_bigint();
        match candidate.cmp(&target) {
            std::cmp::Ordering::Less => left = middle + 1,
            std::cmp::Ordering::Greater => right = middle,
            std::cmp::Ordering::Equal => return Ok(Some(middle)),
        }
    }
    Ok(None)
}
