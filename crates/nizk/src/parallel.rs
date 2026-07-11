use std::env;
use std::thread;
use std::time::Instant;

use ark_bls12_381::{Fr, G1Projective};
use ark_ff::{BigInteger, PrimeField, Zero};
use common::crypto::{hash_to_scalar, point_g1_from_hex, point_g1_to_hex};
use common::types::{
    Delta, ReserveEntry, StoredParallelInitProof, StoredParallelProof, StoredParallelShardProof,
    StoredParallelShardState, StoredParallelState, StoredState,
};

use crate::bp::{
    commit_membership_vector, prove_projection_ipa, prove_zero_test_logic, verify_projection_ipa,
    verify_zero_test_logic,
};
use crate::commitment::commit_balance;
use crate::init_proof::initialize_with_proof;
use crate::kzg::{commit_g1, commit_g2, verify_batch_many, Srs};
use crate::polynomial::{product_from_roots, Polynomial, QueryContext};
use crate::verifier::verify_init_debug;
use crate::witness::{build_update_witness, UpdateWitness};

#[derive(Clone, Debug)]
pub struct ParallelInitResult {
    pub state: StoredParallelState,
    pub proof: StoredParallelInitProof,
}

#[derive(Clone, Debug)]
pub struct ParallelUpdateResult {
    pub next_state: StoredParallelState,
    pub proof: StoredParallelProof,
}

#[derive(Clone, Debug)]
struct ShardWorkerResult {
    next_shard: StoredParallelShardState,
    proof: StoredParallelShardProof,
    witness: UpdateWitness,
    c_u: G1Projective,
}

pub fn initialize_parallel(
    reserve_entries: &[ReserveEntry],
    state_root: &str,
    srs: &Srs,
    shard_count: usize,
) -> Result<ParallelInitResult, String> {
    if shard_count == 0 {
        return Err("shard_count must be greater than zero".to_string());
    }
    if reserve_entries.is_empty() {
        return Err("reserve set must not be empty".to_string());
    }

    let shards = split_reserves(reserve_entries, shard_count);
    let mut results = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(shards.len());
        for shard_entries in &shards {
            handles
                .push(scope.spawn(move || initialize_with_proof(shard_entries, state_root, srs)));
        }
        let mut out = Vec::with_capacity(handles.len());
        for handle in handles {
            out.push(
                handle
                    .join()
                    .map_err(|_| "parallel init worker panicked".to_string())??,
            );
        }
        Ok::<_, String>(out)
    })?;

    let balance_total = results
        .iter()
        .map(|result| result.state.balance_total)
        .sum();
    let balance_blind =
        derive_parallel_balance_blind(state_root, reserve_entries.len(), shard_count);
    let balance_commitment = commit_balance(balance_total, balance_blind);
    let balance_commitment_hex = point_g1_to_hex(&balance_commitment)?;

    let shard_states = results
        .iter()
        .enumerate()
        .map(|(shard_id, result)| StoredParallelShardState {
            shard_id,
            alpha: result.state.alpha,
            reserve_addresses: result.state.reserve_addresses.clone(),
            reserve_balances: result.state.reserve_balances.clone(),
            masked_polynomial_coeffs: result.state.masked_polynomial_coeffs.clone(),
            accumulator_hex: result.state.accumulator_hex.clone(),
            balance_total: result.state.balance_total,
            balance_blind: result.state.balance_blind,
            balance_commitment_hex: result.state.balance_commitment_hex.clone(),
        })
        .collect::<Vec<_>>();
    let shard_proofs = results
        .drain(..)
        .map(|result| result.proof)
        .collect::<Vec<_>>();
    let transcript_hex = build_parallel_transcript(
        state_root,
        state_root,
        &shard_states
            .iter()
            .map(|shard| shard.accumulator_hex.clone())
            .collect::<Vec<_>>(),
        &[],
        &balance_commitment_hex,
        balance_total,
    );

    Ok(ParallelInitResult {
        state: StoredParallelState {
            state_root: state_root.to_string(),
            srs_max_degree: srs.max_degree,
            shards: shard_states,
            balance_total,
            balance_blind,
            balance_commitment_hex: balance_commitment_hex.clone(),
        },
        proof: StoredParallelInitProof {
            state_root: state_root.to_string(),
            shard_proofs,
            balance_total,
            balance_blind,
            balance_commitment_hex,
            transcript_hex,
        },
    })
}

pub fn apply_parallel_update(
    srs: &Srs,
    state: &StoredParallelState,
    deltas: &[Delta],
    new_state_root: &str,
) -> Result<ParallelUpdateResult, String> {
    if state.srs_max_degree != srs.max_degree {
        return Err("state SRS degree does not match provided SRS".to_string());
    }
    if state.shards.is_empty() {
        return Err("parallel state must contain at least one shard".to_string());
    }
    let x_values = deltas
        .iter()
        .map(|delta| common::encoding::encode_address(&delta.address))
        .collect::<Result<Vec<_>, _>>()?;
    let query_ctx = QueryContext::new(&x_values)?;

    let updates = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(state.shards.len());
        for shard in &state.shards {
            handles.push(scope.spawn(|| {
                build_parallel_shard_update(srs, shard, deltas, new_state_root, &query_ctx)
            }));
        }
        let mut out = Vec::with_capacity(handles.len());
        for handle in handles {
            out.push(
                handle
                    .join()
                    .map_err(|_| "parallel update worker panicked".to_string())??,
            );
        }
        Ok::<_, String>(out)
    })?;

    let aggregate_delta = updates
        .iter()
        .map(|update| update.proof.d_value)
        .sum::<i128>();
    let mut aggregate_u = vec![Fr::zero(); deltas.len()];
    let mut aggregate_c_u = G1Projective::zero();
    let mut aggregate_r_u = Fr::zero();
    for update in &updates {
        for (acc, value) in aggregate_u.iter_mut().zip(update.witness.u_values.iter()) {
            *acc += *value;
        }
        aggregate_c_u += update.c_u;
        aggregate_r_u += update.proof.r_u;
    }
    let aggregate_blind = derive_parallel_delta_blind(
        &state.state_root,
        new_state_root,
        aggregate_delta,
        state.shards.len(),
    );
    let c_d = commit_balance(aggregate_delta, aggregate_blind);
    let c_u_hex = point_g1_to_hex(&aggregate_c_u)?;
    let c_d_hex = point_g1_to_hex(&c_d)?;
    let projection_ipa_proof = prove_projection_ipa(
        &aggregate_u,
        deltas,
        &c_u_hex,
        &c_d_hex,
        aggregate_r_u,
        aggregate_blind,
    )?;
    let old_balance_commitment = point_g1_from_hex(&state.balance_commitment_hex)?;
    let next_balance_commitment = old_balance_commitment + c_d;
    let next_balance_total = state.balance_total + aggregate_delta;
    let next_balance_blind = state.balance_blind + aggregate_blind;

    let mut next_shards = Vec::with_capacity(updates.len());
    let mut shard_proofs = Vec::with_capacity(updates.len());
    for update in updates {
        next_shards.push(update.next_shard);
        shard_proofs.push(update.proof);
    }
    let accumulator_hexes = next_shards
        .iter()
        .map(|shard| shard.accumulator_hex.clone())
        .collect::<Vec<_>>();
    let proof_c_d_hexes = shard_proofs
        .iter()
        .map(|shard| shard.c_u_hex.clone())
        .collect::<Vec<_>>();
    let transcript_hex = build_parallel_transcript(
        &state.state_root,
        new_state_root,
        &accumulator_hexes,
        &proof_c_d_hexes,
        &c_d_hex,
        aggregate_delta,
    );

    Ok(ParallelUpdateResult {
        next_state: StoredParallelState {
            state_root: new_state_root.to_string(),
            srs_max_degree: state.srs_max_degree,
            shards: next_shards,
            balance_total: next_balance_total,
            balance_blind: next_balance_blind,
            balance_commitment_hex: point_g1_to_hex(&next_balance_commitment)?,
        },
        proof: StoredParallelProof {
            old_state_root: state.state_root.clone(),
            new_state_root: new_state_root.to_string(),
            shard_proofs,
            c_u_hex,
            c_d_hex,
            d_value: aggregate_delta,
            r_u: aggregate_r_u,
            r_d: aggregate_blind,
            projection_ipa_proof,
            transcript_hex,
        },
    })
}

pub fn verify_parallel_init(
    srs: &Srs,
    state: &StoredParallelState,
    proof: &StoredParallelInitProof,
) -> Result<(), String> {
    if proof.state_root != state.state_root {
        return Err("parallel init state_root mismatch".to_string());
    }
    if proof.shard_proofs.len() != state.shards.len() {
        return Err("parallel init shard count mismatch".to_string());
    }

    for (shard, shard_proof) in state.shards.iter().zip(proof.shard_proofs.iter()) {
        let serial = shard_to_serial_state(&state.state_root, state.srs_max_degree, shard);
        verify_init_debug(srs, &serial, shard_proof)?;
    }

    let expected_total = state
        .shards
        .iter()
        .map(|shard| shard.balance_total)
        .sum::<i128>();
    if expected_total != state.balance_total || proof.balance_total != state.balance_total {
        return Err("parallel init aggregate balance mismatch".to_string());
    }
    if proof.balance_blind != state.balance_blind
        || proof.balance_commitment_hex != state.balance_commitment_hex
    {
        return Err("parallel init aggregate commitment mismatch".to_string());
    }
    if commit_balance(state.balance_total, state.balance_blind)
        != point_g1_from_hex(&state.balance_commitment_hex)?
    {
        return Err("parallel init aggregate commitment does not open".to_string());
    }

    Ok(())
}

pub fn verify_parallel_update(
    srs: &Srs,
    old_state: &StoredParallelState,
    deltas: &[Delta],
    new_state: &StoredParallelState,
    proof: &StoredParallelProof,
) -> Result<(), String> {
    let emit_timing = verify_timing_enabled();
    let total_start = Instant::now();

    let state_checks_start = Instant::now();
    if proof.old_state_root != old_state.state_root {
        return Err("parallel proof old_state_root mismatch".to_string());
    }
    if proof.new_state_root != new_state.state_root {
        return Err("parallel proof new_state_root mismatch".to_string());
    }
    if old_state.shards.len() != new_state.shards.len()
        || proof.shard_proofs.len() != old_state.shards.len()
    {
        return Err("parallel update shard count mismatch".to_string());
    }
    emit_verify_timing(
        emit_timing,
        "parallel_verify_state_shape_checks",
        state_checks_start,
    );

    let block_data_start = Instant::now();
    let x_values = deltas
        .iter()
        .map(|delta| common::encoding::encode_address(&delta.address))
        .collect::<Result<Vec<_>, _>>()?;
    emit_verify_timing(
        emit_timing,
        "parallel_verify_block_data_encode",
        block_data_start,
    );

    let z_poly_start = Instant::now();
    let z_poly = product_from_roots(&x_values);
    emit_verify_timing(
        emit_timing,
        "parallel_verify_query_vanishing_poly",
        z_poly_start,
    );

    let z_commit_start = Instant::now();
    let z_commit_g2 = commit_g2(srs, &z_poly)?;
    emit_verify_timing(
        emit_timing,
        "parallel_verify_query_z_commit_g2",
        z_commit_start,
    );

    let mut accumulators = Vec::with_capacity(old_state.shards.len());
    let mut c_y_values = Vec::with_capacity(old_state.shards.len());
    let mut eval_proofs = Vec::with_capacity(old_state.shards.len());
    let mut aggregate_c_u = G1Projective::zero();
    let mut aggregate_r_u = Fr::zero();
    let mut reported_shard_delta = 0i128;

    let shard_checks_total_start = Instant::now();
    for ((old_shard, new_shard), shard_proof) in old_state
        .shards
        .iter()
        .zip(new_state.shards.iter())
        .zip(proof.shard_proofs.iter())
    {
        if old_shard.shard_id != new_shard.shard_id || old_shard.shard_id != shard_proof.shard_id {
            return Err("parallel update shard id mismatch".to_string());
        }
        if old_shard.accumulator_hex != new_shard.accumulator_hex {
            return Err("parallel fixed-set shard accumulator changed".to_string());
        }
        if old_shard.masked_polynomial_coeffs != new_shard.masked_polynomial_coeffs {
            return Err("parallel fixed-set shard polynomial changed".to_string());
        }
        if old_shard.balance_total != new_shard.balance_total
            || old_shard.balance_blind != new_shard.balance_blind
        {
            return Err(
                "parallel shard local balance state should not change in aggregate-proof mode"
                    .to_string(),
            );
        }
        if old_shard.balance_commitment_hex != new_shard.balance_commitment_hex {
            return Err(
                "parallel shard local balance commitment should not change in aggregate-proof mode"
                    .to_string(),
            );
        }

        accumulators.push(point_g1_from_hex(&old_shard.accumulator_hex)?);
        c_y_values.push(point_g1_from_hex(&shard_proof.c_y_hex)?);
        eval_proofs.push(point_g1_from_hex(&shard_proof.eval_proof_hex)?);
        aggregate_c_u += point_g1_from_hex(&shard_proof.c_u_hex)?;
        aggregate_r_u += shard_proof.r_u;
        reported_shard_delta += shard_proof.d_value;

        let zero_test_start = Instant::now();
        verify_zero_test_logic(
            srs,
            deltas,
            &x_values,
            &shard_proof.c_u_hex,
            &shard_proof.c_y_hex,
            &shard_proof.bp_proof_hex,
            &shard_proof.bp_commitments_hex,
            &shard_proof.link_proof_hex,
        )?;
        emit_verify_timing(
            emit_timing,
            &format!(
                "parallel_verify_shard_{}_zero_test_total",
                shard_proof.shard_id
            ),
            zero_test_start,
        );
    }
    emit_verify_timing(
        emit_timing,
        "parallel_verify_all_shard_zero_tests_total",
        shard_checks_total_start,
    );

    let kzg_batch_start = Instant::now();
    let kzg_seed = build_kzg_batch_seed(old_state, new_state, proof, deltas);
    if !verify_batch_many(
        &accumulators,
        &c_y_values,
        &eval_proofs,
        &z_commit_g2,
        kzg_seed.as_bytes(),
    )? {
        return Err("parallel KZG batch equation failed".to_string());
    }
    emit_verify_timing(
        emit_timing,
        "parallel_verify_kzg_batch_pairing",
        kzg_batch_start,
    );

    let aggregate_checks_start = Instant::now();
    if point_g1_to_hex(&aggregate_c_u)? != proof.c_u_hex || aggregate_r_u != proof.r_u {
        return Err("parallel aggregate C_U mismatch".to_string());
    }
    if reported_shard_delta != proof.d_value {
        return Err("parallel reported shard delta mismatch".to_string());
    }
    let expected_c_d = commit_balance(proof.d_value, proof.r_d);
    if point_g1_to_hex(&expected_c_d)? != proof.c_d_hex {
        return Err("parallel aggregate C_D does not open".to_string());
    }
    emit_verify_timing(
        emit_timing,
        "parallel_verify_aggregate_commitment_checks",
        aggregate_checks_start,
    );

    let projection_start = Instant::now();
    verify_projection_ipa(
        deltas,
        &proof.c_u_hex,
        &proof.c_d_hex,
        &proof.projection_ipa_proof,
    )?;
    emit_verify_timing(
        emit_timing,
        "parallel_verify_projection_total",
        projection_start,
    );

    let balance_checks_start = Instant::now();
    let old_balance_commitment = point_g1_from_hex(&old_state.balance_commitment_hex)?;
    let new_balance_commitment = point_g1_from_hex(&new_state.balance_commitment_hex)?;
    if new_balance_commitment != old_balance_commitment + expected_c_d {
        return Err("parallel aggregate balance commitment mismatch".to_string());
    }
    if old_state.balance_total + proof.d_value != new_state.balance_total {
        return Err("parallel balance_total mismatch".to_string());
    }
    if old_state.balance_blind + proof.r_d != new_state.balance_blind {
        return Err("parallel balance_blind mismatch".to_string());
    }
    emit_verify_timing(
        emit_timing,
        "parallel_verify_final_balance_checks",
        balance_checks_start,
    );

    let direct_shard_update = point_g1_from_hex(&new_state.balance_commitment_hex)?
        - point_g1_from_hex(&old_state.balance_commitment_hex)?;
    if direct_shard_update != expected_c_d {
        return Err("parallel direct commitment update mismatch".to_string());
    }

    let accumulator_hexes = new_state
        .shards
        .iter()
        .map(|shard| shard.accumulator_hex.clone())
        .collect::<Vec<_>>();
    let shard_c_d_hexes = proof
        .shard_proofs
        .iter()
        .map(|shard| shard.c_u_hex.clone())
        .collect::<Vec<_>>();
    let expected_transcript = build_parallel_transcript(
        &old_state.state_root,
        &new_state.state_root,
        &accumulator_hexes,
        &shard_c_d_hexes,
        &proof.c_d_hex,
        proof.d_value,
    );
    if proof.transcript_hex != expected_transcript {
        return Err("parallel update transcript mismatch".to_string());
    }
    emit_verify_timing(emit_timing, "parallel_verify_update_total", total_start);

    Ok(())
}

fn build_parallel_shard_update(
    srs: &Srs,
    shard: &StoredParallelShardState,
    deltas: &[Delta],
    new_state_root: &str,
    query_ctx: &QueryContext,
) -> Result<ShardWorkerResult, String> {
    let polynomial = Polynomial::from_coeffs(shard.masked_polynomial_coeffs.clone());
    let witness = build_update_witness(&polynomial, deltas)?;
    let z_poly = query_ctx.z_poly().clone();
    let i_y = query_ctx.interpolate(&witness.y_values)?;
    let rho_y = derive_shard_scalar(
        "parallel-rho-y",
        shard.shard_id,
        &[new_state_root.as_bytes(), &fr_vec_bytes(&witness.y_values)],
    );
    let j_y = i_y.add(&z_poly.mul_scalar(rho_y));
    let quotient = polynomial.sub(&j_y).div_exact(&z_poly)?;
    let c_y = commit_g1(srs, &j_y)?;
    let eval_proof = commit_g1(srs, &quotient)?;

    let r_u = derive_shard_scalar(
        "parallel-r-u",
        shard.shard_id,
        &[&fr_vec_bytes(&witness.u_values)],
    );
    let c_u = commit_membership_vector(&witness.u_values, r_u)?;
    let c_u_hex = point_g1_to_hex(&c_u)?;
    let c_y_hex = point_g1_to_hex(&c_y)?;
    let zero_test = prove_zero_test_logic(
        srs,
        &witness,
        deltas,
        &c_u_hex,
        &c_y_hex,
        r_u,
        rho_y,
        Some(query_ctx),
    )?;

    Ok(ShardWorkerResult {
        next_shard: StoredParallelShardState {
            shard_id: shard.shard_id,
            alpha: shard.alpha,
            reserve_addresses: shard.reserve_addresses.clone(),
            reserve_balances: shard.reserve_balances.clone(),
            masked_polynomial_coeffs: shard.masked_polynomial_coeffs.clone(),
            accumulator_hex: shard.accumulator_hex.clone(),
            balance_total: shard.balance_total,
            balance_blind: shard.balance_blind,
            balance_commitment_hex: shard.balance_commitment_hex.clone(),
        },
        proof: StoredParallelShardProof {
            shard_id: shard.shard_id,
            c_u_hex,
            c_y_hex,
            eval_proof_hex: point_g1_to_hex(&eval_proof)?,
            r_u,
            rho_y,
            d_value: witness.d_value,
            gate_count: deltas.len() * 2,
            bp_proof_hex: zero_test.bp_proof_hex,
            bp_commitments_hex: zero_test.bp_commitments_hex,
            link_proof_hex: zero_test.link_proof_hex,
        },
        witness,
        c_u,
    })
}

fn split_reserves(entries: &[ReserveEntry], shard_count: usize) -> Vec<Vec<ReserveEntry>> {
    let active = shard_count.min(entries.len());
    let mut shards = vec![Vec::new(); active];
    for (index, entry) in entries.iter().enumerate() {
        shards[index % active].push(entry.clone());
    }
    shards
}

fn shard_to_serial_state(
    root: &str,
    srs_max_degree: usize,
    shard: &StoredParallelShardState,
) -> StoredState {
    StoredState {
        state_root: root.to_string(),
        srs_max_degree,
        alpha: shard.alpha,
        reserve_addresses: shard.reserve_addresses.clone(),
        reserve_balances: shard.reserve_balances.clone(),
        masked_polynomial_coeffs: shard.masked_polynomial_coeffs.clone(),
        accumulator_hex: shard.accumulator_hex.clone(),
        balance_total: shard.balance_total,
        balance_blind: shard.balance_blind,
        balance_commitment_hex: shard.balance_commitment_hex.clone(),
    }
}

fn derive_parallel_balance_blind(state_root: &str, reserve_count: usize, shard_count: usize) -> Fr {
    let payload = format!("{state_root}|{reserve_count}|{shard_count}");
    nonzero_hash("parallel-balance-blind", payload.as_bytes())
}

fn derive_parallel_delta_blind(
    old_state_root: &str,
    new_state_root: &str,
    aggregate_delta: i128,
    shard_count: usize,
) -> Fr {
    let payload = format!("{old_state_root}|{new_state_root}|{aggregate_delta}|{shard_count}");
    nonzero_hash("parallel-delta-blind", payload.as_bytes())
}

fn derive_shard_scalar(label: &str, shard_id: usize, chunks: &[&[u8]]) -> Fr {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(shard_id as u64).to_le_bytes());
    for chunk in chunks {
        bytes.extend_from_slice(chunk);
    }
    nonzero_hash(label, &bytes)
}

fn nonzero_hash(label: &str, payload: &[u8]) -> Fr {
    let mut scalar = hash_to_scalar(label, payload);
    if scalar.is_zero() {
        scalar = Fr::from(41u64);
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

fn verify_timing_enabled() -> bool {
    env::var("POA_VERIFY_TIMING").ok().as_deref() == Some("1")
}

fn emit_verify_timing(enabled: bool, stage: &str, start: Instant) {
    if enabled {
        eprintln!("stage={stage} millis={}", start.elapsed().as_millis());
    }
}

fn build_kzg_batch_seed(
    old_state: &StoredParallelState,
    new_state: &StoredParallelState,
    proof: &StoredParallelProof,
    deltas: &[Delta],
) -> String {
    let mut parts = Vec::new();
    parts.push(old_state.state_root.clone());
    parts.push(new_state.state_root.clone());
    parts.push(proof.c_u_hex.clone());
    parts.push(proof.c_d_hex.clone());
    for shard in &proof.shard_proofs {
        parts.push(shard.shard_id.to_string());
        parts.push(shard.c_u_hex.clone());
        parts.push(shard.c_y_hex.clone());
        parts.push(shard.eval_proof_hex.clone());
    }
    for delta in deltas {
        parts.push(delta.address.clone());
        parts.push(delta.delta.to_string());
    }
    parts.join("|")
}

fn build_parallel_transcript(
    old_root: &str,
    new_root: &str,
    accumulator_hexes: &[String],
    shard_c_d_hexes: &[String],
    c_d_hex: &str,
    d_value: i128,
) -> String {
    let payload = [
        old_root.to_string(),
        new_root.to_string(),
        accumulator_hexes.join(","),
        shard_c_d_hexes.join(","),
        c_d_hex.to_string(),
        d_value.to_string(),
    ]
    .join("|");
    common::crypto::hex_encode(blake3::hash(payload.as_bytes()).as_bytes())
}

#[cfg(test)]
mod tests {
    use common::types::{Delta, ReserveEntry};

    use super::{
        apply_parallel_update, initialize_parallel, verify_parallel_init, verify_parallel_update,
    };
    use crate::kzg::Srs;

    fn sample_reserves() -> Vec<ReserveEntry> {
        vec![
            ReserveEntry {
                address: "0x1111111111111111111111111111111111111111".to_string(),
                balance: 100,
            },
            ReserveEntry {
                address: "0x2222222222222222222222222222222222222222".to_string(),
                balance: 250,
            },
            ReserveEntry {
                address: "0x3333333333333333333333333333333333333333".to_string(),
                balance: 75,
            },
            ReserveEntry {
                address: "0x4444444444444444444444444444444444444444".to_string(),
                balance: 15,
            },
        ]
    }

    #[test]
    fn accepts_parallel_init() {
        let srs = Srs::setup(16, b"parallel-init");
        let init = initialize_parallel(&sample_reserves(), "root-0", &srs, 2).unwrap();
        verify_parallel_init(&srs, &init.state, &init.proof).unwrap();
        assert_eq!(init.state.balance_total, 440);
    }

    #[test]
    fn accepts_parallel_update() {
        let srs = Srs::setup(16, b"parallel-update");
        let init = initialize_parallel(&sample_reserves(), "root-0", &srs, 2).unwrap();
        let deltas = vec![
            Delta {
                address: "0x1111111111111111111111111111111111111111".to_string(),
                delta: -10,
            },
            Delta {
                address: "0x5555555555555555555555555555555555555555".to_string(),
                delta: 40,
            },
        ];
        let updated = apply_parallel_update(&srs, &init.state, &deltas, "root-1").unwrap();
        verify_parallel_update(
            &srs,
            &init.state,
            &deltas,
            &updated.next_state,
            &updated.proof,
        )
        .unwrap();
    }

    #[test]
    fn rejects_tampered_parallel_proof() {
        let srs = Srs::setup(16, b"parallel-bad");
        let init = initialize_parallel(&sample_reserves(), "root-0", &srs, 2).unwrap();
        let deltas = vec![Delta {
            address: "0x1111111111111111111111111111111111111111".to_string(),
            delta: 7,
        }];
        let mut updated = apply_parallel_update(&srs, &init.state, &deltas, "root-1").unwrap();
        updated.proof.shard_proofs[0].c_y_hex.push('0');
        let err = verify_parallel_update(
            &srs,
            &init.state,
            &deltas,
            &updated.next_state,
            &updated.proof,
        )
        .expect_err("parallel proof should fail");
        assert!(!err.is_empty());
    }
}
