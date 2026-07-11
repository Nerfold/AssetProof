use ark_bls12_381::Fr;
use std::collections::HashSet;
use std::env;
use std::time::Instant;

use common::crypto::{point_g1_from_hex, scalar_to_hex};
use common::encoding::encode_address;
use common::types::{Delta, PublicState, StoredInitProof, StoredProof, StoredState, SyncProof};

use crate::bp::{verify_optimized_zero_test_logic, verify_projection_ipa};
use crate::external::{ExternalProofAdapter, MockExternalProofAdapter};
use crate::init_proof::{verify_init_proof, verify_init_public_proof};
use crate::kzg::{commit_g2, verify_batch, Srs};
use crate::polynomial::product_from_roots;
use crate::range::{check_public_delta_range, RangePolicy};
use crate::update::delta_list_commitment;

pub fn verify_init(
    srs: &Srs,
    public_state: &PublicState,
    proof: &StoredInitProof,
) -> Result<(), String> {
    verify_init_public_proof(srs, public_state, proof)
}

pub fn verify_init_debug(
    srs: &Srs,
    state: &StoredState,
    proof: &StoredInitProof,
) -> Result<(), String> {
    verify_init_proof(srs, state, proof)
}

pub fn verify_update(
    srs: &Srs,
    old_state: &PublicState,
    deltas: &[Delta],
    new_state: &PublicState,
    proof: &StoredProof,
) -> Result<(), String> {
    verify_update_production_with_adapter_and_sync_proof(
        srs,
        old_state,
        deltas,
        new_state,
        proof,
        &MockExternalProofAdapter,
        None,
    )
}

pub fn verify_update_debug(
    srs: &Srs,
    old_state: &PublicState,
    deltas: &[Delta],
    new_state: &PublicState,
    proof: &StoredProof,
) -> Result<(), String> {
    verify_update_with_adapter_and_sync_proof(
        srs,
        old_state,
        deltas,
        new_state,
        proof,
        &MockExternalProofAdapter,
        None,
    )
}

pub fn verify_update_with_sync_proof(
    srs: &Srs,
    old_state: &PublicState,
    deltas: &[Delta],
    new_state: &PublicState,
    proof: &StoredProof,
    sync_proof: Option<&SyncProof>,
) -> Result<(), String> {
    verify_update_production_with_adapter_and_sync_proof(
        srs,
        old_state,
        deltas,
        new_state,
        proof,
        &MockExternalProofAdapter,
        sync_proof,
    )
}

pub fn verify_update_debug_with_sync_proof(
    srs: &Srs,
    old_state: &PublicState,
    deltas: &[Delta],
    new_state: &PublicState,
    proof: &StoredProof,
    sync_proof: Option<&SyncProof>,
) -> Result<(), String> {
    verify_update_with_adapter_and_sync_proof(
        srs,
        old_state,
        deltas,
        new_state,
        proof,
        &MockExternalProofAdapter,
        sync_proof,
    )
}

pub fn verify_update_production_with_adapter_and_sync_proof(
    srs: &Srs,
    old_state: &PublicState,
    deltas: &[Delta],
    new_state: &PublicState,
    proof: &StoredProof,
    external: &impl ExternalProofAdapter,
    sync_proof: Option<&SyncProof>,
) -> Result<(), String> {
    if proof.theta_opening_proof_hex.is_empty()
        || !proof.theta_opening_proof_hex.starts_with("zkopen:")
    {
        return Err("update proof is missing a production committed-opening proof for ZKOpen(C_Y, theta, C_v); use verify_update_debug only for transparent local tests".to_string());
    }
    verify_update_with_adapter_and_sync_proof(
        srs, old_state, deltas, new_state, proof, external, sync_proof,
    )
}

pub fn verify_update_with_adapter_and_sync_proof(
    srs: &Srs,
    old_state: &PublicState,
    deltas: &[Delta],
    new_state: &PublicState,
    proof: &StoredProof,
    external: &impl ExternalProofAdapter,
    sync_proof: Option<&SyncProof>,
) -> Result<(), String> {
    let emit_timing = env::var("POA_VERIFY_TIMING").ok().as_deref() == Some("1");
    let verify_total_start = Instant::now();

    let state_checks_start = Instant::now();
    if proof.old_state_root != old_state.state_root {
        return Err("proof old_state_root does not match input state".to_string());
    }
    if proof.new_state_root != new_state.state_root {
        return Err("proof new_state_root does not match claimed new state".to_string());
    }
    if old_state.accumulator_hex != new_state.accumulator_hex {
        return Err("fixed-set accumulator changed across update".to_string());
    }
    if old_state.reserve_count != new_state.reserve_count {
        return Err("fixed-set reserve count changed across update".to_string());
    }
    if old_state.srs_max_degree != srs.max_degree || new_state.srs_max_degree != srs.max_degree {
        return Err("state SRS degree does not match provided SRS".to_string());
    }
    let expected_delta_commitment = delta_list_commitment(deltas);
    if proof.delta_list_commitment_hex != expected_delta_commitment {
        return Err("delta list commitment mismatch".to_string());
    }
    if let Some(sync_proof) = sync_proof {
        verify_sync_proof_with_adapter(
            old_state,
            new_state,
            &expected_delta_commitment,
            sync_proof,
            external,
        )?;
    }

    let old_balance_commitment = point_g1_from_hex(&old_state.balance_commitment_hex)?;
    let new_balance_commitment = point_g1_from_hex(&new_state.balance_commitment_hex)?;
    let c_d = point_g1_from_hex(&proof.c_d_hex)?;
    if new_balance_commitment != old_balance_commitment + c_d {
        return Err("claimed balance commitment does not match homomorphic update".to_string());
    }

    if proof.gate_count != deltas.len() * 2 {
        return Err("gate count does not match 4m relation size".to_string());
    }
    emit_verify_timing(
        emit_timing,
        "verify_state_and_commitment_checks",
        state_checks_start,
    );

    let block_data_start = Instant::now();
    check_public_delta_range(deltas, &RangePolicy::conservative_demo())?;
    let x_values: Vec<_> = deltas
        .iter()
        .map(|delta| encode_address(&delta.address))
        .collect::<Result<_, _>>()?;
    ensure_distinct(&x_values)?;
    emit_verify_timing(
        emit_timing,
        "verify_block_data_encode_distinct",
        block_data_start,
    );

    let z_poly_start = Instant::now();
    let z_poly = product_from_roots(&x_values);
    emit_verify_timing(emit_timing, "verify_query_vanishing_poly", z_poly_start);

    let z_commit_start = Instant::now();
    let z_commit_g2 = commit_g2(srs, &z_poly)?;
    emit_verify_timing(emit_timing, "verify_query_z_commit_g2", z_commit_start);

    let kzg_parse_start = Instant::now();
    let accumulator = point_g1_from_hex(&old_state.accumulator_hex)?;
    let c_y = point_g1_from_hex(&proof.c_y_hex)?;
    let eval_proof = point_g1_from_hex(&proof.eval_proof_hex)?;
    emit_verify_timing(emit_timing, "verify_kzg_parse_points", kzg_parse_start);

    let kzg_pairing_start = Instant::now();
    if !verify_batch(&accumulator, &c_y, &eval_proof, &z_commit_g2) {
        return Err("KZG batch equation failed".to_string());
    }
    emit_verify_timing(emit_timing, "verify_kzg_pairing_check", kzg_pairing_start);

    let logic_start = Instant::now();
    verify_optimized_zero_test_logic(
        srs,
        deltas,
        &x_values,
        &proof.old_state_root,
        &proof.new_state_root,
        &old_state.accumulator_hex,
        &old_state.balance_commitment_hex,
        &new_state.balance_commitment_hex,
        &proof.c_u_hex,
        &proof.c_y_hex,
        &proof.c_v_hex,
        &proof.c_d_hex,
        proof.theta,
        &proof.theta_opening_proof_hex,
        &proof.bp_proof_hex,
        &proof.witness_vector_commitment_hex,
        &proof.rho_bp_commitment_hex,
        &proof.v_bp_commitment_hex,
        &proof.witness_link_ipa_proof,
        &proof.v_link_proof,
    )?;
    verify_projection_ipa(
        deltas,
        &proof.c_u_hex,
        &proof.c_d_hex,
        &proof.projection_ipa_proof,
    )?;
    emit_verify_timing(emit_timing, "verify_logic_total", logic_start);

    emit_verify_timing(emit_timing, "verify_update_total", verify_total_start);

    Ok(())
}

pub fn verify_sync_proof(
    old_state: &PublicState,
    new_state: &PublicState,
    delta_list_commitment_hex: &str,
    proof: &SyncProof,
) -> Result<(), String> {
    if proof.delta_list_commitment_hex != delta_list_commitment_hex {
        return Err("sync proof delta commitment mismatch".to_string());
    }
    verify_sync_proof_with_adapter(
        old_state,
        new_state,
        delta_list_commitment_hex,
        proof,
        &MockExternalProofAdapter,
    )
}

pub fn verify_sync_proof_with_adapter(
    old_state: &PublicState,
    new_state: &PublicState,
    delta_list_commitment_hex: &str,
    proof: &SyncProof,
    external: &impl ExternalProofAdapter,
) -> Result<(), String> {
    external.verify_sync(
        &old_state.state_root,
        &new_state.state_root,
        delta_list_commitment_hex,
        proof,
    )
}

pub fn verify_update_from_prover_states(
    srs: &Srs,
    old_state: &StoredState,
    deltas: &[Delta],
    new_state: &StoredState,
    proof: &StoredProof,
) -> Result<(), String> {
    verify_update_debug(
        srs,
        &old_state.public_state(),
        deltas,
        &new_state.public_state(),
        proof,
    )
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

fn emit_verify_timing(enabled: bool, stage: &str, start: Instant) {
    if enabled {
        eprintln!("stage={stage} millis={}", start.elapsed().as_millis());
    }
}

#[cfg(test)]
mod tests {
    use common::types::{Delta, ReserveEntry, SyncProof};

    use super::{verify_init, verify_init_debug, verify_update, verify_update_debug};
    use crate::init::initialize;
    use crate::init_proof::initialize_with_proof;
    use crate::insert::{
        apply_insert, verify_insert, verify_insert_debug, verify_insert_with_srs, KzgInsertWitness,
    };
    use crate::kzg::Srs;
    use crate::update::{apply_update, delta_list_commitment};

    #[test]
    fn accepts_honest_sp1_init() {
        let srs = Srs::setup(16, b"test-srs-init");
        let entries = vec![
            ReserveEntry {
                address: "0x1111111111111111111111111111111111111111".to_string(),
                balance: 100,
            },
            ReserveEntry {
                address: "0x2222222222222222222222222222222222222222".to_string(),
                balance: 250,
            },
        ];
        let init = initialize_with_proof(&entries, "root-0", &srs).unwrap();
        verify_init_debug(&srs, &init.state, &init.proof).unwrap();
        verify_init(&srs, &init.state.public_state(), &init.proof).unwrap();
    }

    #[test]
    fn rejects_tampered_init_digest() {
        let srs = Srs::setup(16, b"test-srs-init-bad");
        let entries = vec![ReserveEntry {
            address: "0x1111111111111111111111111111111111111111".to_string(),
            balance: 100,
        }];
        let mut init = initialize_with_proof(&entries, "root-0", &srs).unwrap();
        init.proof.init_digest_hex.push('0');
        let err = verify_init_debug(&srs, &init.state, &init.proof).expect_err("proof should fail");
        assert!(!err.is_empty());
    }

    #[test]
    fn accepts_honest_update() {
        let srs = Srs::setup(16, b"test-srs");
        let entries = vec![
            ReserveEntry {
                address: "0x1111111111111111111111111111111111111111".to_string(),
                balance: 100,
            },
            ReserveEntry {
                address: "0x2222222222222222222222222222222222222222".to_string(),
                balance: 250,
            },
        ];
        let init = initialize(&entries, "root-0", &srs).unwrap();
        let deltas = vec![
            Delta {
                address: "0x1111111111111111111111111111111111111111".to_string(),
                delta: -10,
            },
            Delta {
                address: "0x3333333333333333333333333333333333333333".to_string(),
                delta: 40,
            },
        ];
        let updated = apply_update(&srs, &init.state, &deltas, "root-1").unwrap();
        verify_update(
            &srs,
            &init.state.public_state(),
            &deltas,
            &updated.next_state.public_state(),
            &updated.proof,
        )
        .unwrap();
        verify_update_debug(
            &srs,
            &init.state.public_state(),
            &deltas,
            &updated.next_state.public_state(),
            &updated.proof,
        )
        .unwrap();
        assert_eq!(updated.next_state.balance_total, 340);
    }

    #[test]
    fn accepts_update_with_mock_sync_proof() {
        let srs = Srs::setup(16, b"test-srs-sync");
        let entries = vec![ReserveEntry {
            address: "0x1111111111111111111111111111111111111111".to_string(),
            balance: 100,
        }];
        let init = initialize(&entries, "root-0", &srs).unwrap();
        let deltas = vec![Delta {
            address: "0x1111111111111111111111111111111111111111".to_string(),
            delta: 7,
        }];
        let updated = apply_update(&srs, &init.state, &deltas, "root-1").unwrap();
        let sync = SyncProof {
            scheme: "mock-canonical-sync".to_string(),
            old_state_root: "root-0".to_string(),
            new_state_root: "root-1".to_string(),
            delta_list_commitment_hex: delta_list_commitment(&deltas),
            proof_hex: "mock-sync-proof".to_string(),
        };
        super::verify_update_debug_with_sync_proof(
            &srs,
            &init.state.public_state(),
            &deltas,
            &updated.next_state.public_state(),
            &updated.proof,
            Some(&sync),
        )
        .unwrap();
    }

    #[test]
    fn rejects_modified_evaluation() {
        let srs = Srs::setup(8, b"test-srs-small");
        let entries = vec![ReserveEntry {
            address: "0x1111111111111111111111111111111111111111".to_string(),
            balance: 100,
        }];
        let init = initialize(&entries, "root-0", &srs).unwrap();
        let deltas = vec![Delta {
            address: "0x1111111111111111111111111111111111111111".to_string(),
            delta: 7,
        }];
        let mut updated = apply_update(&srs, &init.state, &deltas, "root-1").unwrap();
        updated.proof.c_y_hex.push('0');
        let err = verify_update_debug(
            &srs,
            &init.state.public_state(),
            &deltas,
            &updated.next_state.public_state(),
            &updated.proof,
        )
        .expect_err("proof should fail");
        assert!(!err.is_empty());
    }

    #[test]
    fn rejects_tampered_random_link_commitment() {
        let srs = Srs::setup(8, b"test-srs-random-link");
        let entries = vec![ReserveEntry {
            address: "0x1111111111111111111111111111111111111111".to_string(),
            balance: 100,
        }];
        let init = initialize(&entries, "root-0", &srs).unwrap();
        let deltas = vec![Delta {
            address: "0x1111111111111111111111111111111111111111".to_string(),
            delta: 7,
        }];
        let mut updated = apply_update(&srs, &init.state, &deltas, "root-1").unwrap();
        updated.proof.c_v_hex = updated.proof.c_u_hex.clone();
        let err = verify_update_debug(
            &srs,
            &init.state.public_state(),
            &deltas,
            &updated.next_state.public_state(),
            &updated.proof,
        )
        .expect_err("proof should fail");
        assert!(!err.is_empty());
    }

    #[test]
    fn accepts_kzg_insert_mock() {
        let srs = Srs::setup(16, b"test-srs-insert");
        let entries = vec![
            ReserveEntry {
                address: "0x1111111111111111111111111111111111111111".to_string(),
                balance: 100,
            },
            ReserveEntry {
                address: "0x2222222222222222222222222222222222222222".to_string(),
                balance: 250,
            },
        ];
        let init = initialize(&entries, "root-0", &srs).unwrap();
        let insert = apply_insert(
            &srs,
            &init.state,
            &KzgInsertWitness::mock(
                "0x3333333333333333333333333333333333333333".to_string(),
                40,
                String::new(),
                String::new(),
            ),
        )
        .unwrap();
        let err = verify_insert(
            &init.state.public_state(),
            &insert.next_state.public_state(),
            &insert.proof,
        )
        .expect_err("insert verifier without SRS must fail closed");
        assert!(err.contains("requires SRS"));
        verify_insert_with_srs(
            &srs,
            &init.state.public_state(),
            &insert.next_state.public_state(),
            &insert.proof,
        )
        .unwrap();
        verify_insert_debug(
            &init.state.public_state(),
            &insert.next_state.public_state(),
            &insert.proof,
        )
        .unwrap();
        assert_eq!(insert.next_state.balance_total, 390);
        assert_eq!(insert.next_state.reserve_addresses.len(), 3);
    }

    #[test]
    fn rejects_tampered_insert_external_artifact_digest() {
        let srs = Srs::setup(16, b"test-srs-insert-artifact");
        let entries = vec![ReserveEntry {
            address: "0x1111111111111111111111111111111111111111".to_string(),
            balance: 100,
        }];
        let init = initialize(&entries, "root-0", &srs).unwrap();
        let mut insert = apply_insert(
            &srs,
            &init.state,
            &KzgInsertWitness::mock(
                "0x2222222222222222222222222222222222222222".to_string(),
                40,
                String::new(),
                String::new(),
            ),
        )
        .unwrap();
        insert.proof.ownership_artifact_digest_hex.push('0');
        let err = verify_insert_with_srs(
            &srs,
            &init.state.public_state(),
            &insert.next_state.public_state(),
            &insert.proof,
        )
        .expect_err("proof should fail");
        assert!(!err.is_empty());
    }
}
