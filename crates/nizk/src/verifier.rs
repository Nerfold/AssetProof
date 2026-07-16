use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use std::collections::HashSet;
use std::env;
use std::time::Instant;

use common::crypto::point_g1_from_hex;
use common::encoding::encode_address;
use common::types::{Delta, PublicState, StoredInitProof, StoredProof, StoredState, SyncProof};

use crate::bp::{verify_optimized_zero_test_logic, verify_projection_ipa};
use crate::external::{ExternalProofAdapter, MockExternalProofAdapter};
use crate::init_proof::{verify_init_proof, verify_init_public_proof};
use crate::kzg::{commit_g2, verify_batch, Srs};
use crate::polynomial::product_from_roots;
use crate::range::{check_public_delta_range, RangePolicy};
use crate::threshold::{verify_threshold_encoded, ThresholdStatement, THRESHOLD_PROOF_SCHEME};
use crate::update::{build_transcript_hex, delta_list_commitment, EMPTY_UPDATE_MARKER};

#[derive(Clone, Debug)]
pub struct ChainPolicy {
    expected_chain_id: String,
    finalized_state_roots: HashSet<String>,
    last_accepted_state_root: Option<String>,
    last_accepted_public_state_digest: Option<String>,
    max_update_size: usize,
    pub(crate) allow_mock_proofs: bool,
}

impl ChainPolicy {
    pub fn production(
        expected_chain_id: impl Into<String>,
        finalized_state_roots: impl IntoIterator<Item = String>,
        last_accepted_state_root: Option<String>,
        last_accepted_public_state_digest: Option<String>,
        max_update_size: usize,
    ) -> Result<Self, String> {
        if max_update_size == 0 {
            return Err("max_update_size must be greater than zero".to_string());
        }
        let expected_chain_id = expected_chain_id.into();
        if expected_chain_id.trim().is_empty() {
            return Err("expected_chain_id must not be empty".to_string());
        }
        let finalized_state_roots = finalized_state_roots.into_iter().collect::<HashSet<_>>();
        if finalized_state_roots.is_empty()
            || finalized_state_roots
                .iter()
                .any(|root| root.trim().is_empty())
        {
            return Err(
                "finalized_state_roots must contain at least one non-empty root".to_string(),
            );
        }
        if last_accepted_state_root
            .as_ref()
            .is_some_and(|root| root.trim().is_empty())
        {
            return Err("last_accepted_state_root must not be empty".to_string());
        }
        if last_accepted_state_root.is_some() != last_accepted_public_state_digest.is_some() {
            return Err(
                "last accepted root and public-state digest must be supplied together".to_string(),
            );
        }
        if let Some(digest) = &last_accepted_public_state_digest {
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(
                    "last accepted public-state digest must be 32 lowercase hex bytes".to_string(),
                );
            }
        }
        Ok(Self {
            expected_chain_id,
            finalized_state_roots,
            last_accepted_state_root,
            last_accepted_public_state_digest,
            max_update_size,
            allow_mock_proofs: false,
        })
    }

    pub fn development(
        expected_chain_id: impl Into<String>,
        finalized_state_roots: impl IntoIterator<Item = String>,
        last_accepted_state_root: Option<String>,
        last_accepted_public_state_digest: Option<String>,
        max_update_size: usize,
    ) -> Result<Self, String> {
        let mut policy = Self::production(
            expected_chain_id,
            finalized_state_roots,
            last_accepted_state_root,
            last_accepted_public_state_digest,
            max_update_size,
        )?;
        policy.allow_mock_proofs = true;
        Ok(policy)
    }

    pub(crate) fn check_chain_id(&self, actual: &str) -> Result<(), String> {
        if actual != self.expected_chain_id {
            return Err(format!(
                "chain id mismatch: expected {}, got {actual}",
                self.expected_chain_id
            ));
        }
        if !self.allow_mock_proofs && actual == "mock-chain" {
            return Err("mock-chain proofs are forbidden by production policy".to_string());
        }
        Ok(())
    }

    pub(crate) fn check_finalized(&self, state_root: &str) -> Result<(), String> {
        if !self.finalized_state_roots.contains(state_root) {
            return Err(format!(
                "state root is not finalized by policy: {state_root}"
            ));
        }
        Ok(())
    }

    pub(crate) fn check_last_accepted(&self, state: &PublicState) -> Result<(), String> {
        if self.last_accepted_state_root.as_deref() != Some(state.state_root.as_str()) {
            return Err("old state is not the policy's last accepted state".to_string());
        }
        let digest = public_state_digest(state)?;
        if self.last_accepted_public_state_digest.as_deref() != Some(digest.as_str()) {
            return Err(
                "old public state does not match the policy-pinned accepted state".to_string(),
            );
        }
        Ok(())
    }
}

pub fn public_state_digest(state: &PublicState) -> Result<String, String> {
    let degree = u64::try_from(state.srs_max_degree)
        .map_err(|_| "public state SRS degree does not fit digest encoding".to_string())?;
    let count = u64::try_from(state.reserve_count)
        .map_err(|_| "public state reserve count does not fit digest encoding".to_string())?;
    let degree_bytes = degree.to_le_bytes();
    let count_bytes = count.to_le_bytes();
    let fields = [
        state.state_root.as_bytes(),
        degree_bytes.as_slice(),
        count_bytes.as_slice(),
        state.accumulator_hex.as_bytes(),
        state.balance_commitment_hex.as_bytes(),
    ];
    let mut framed = Vec::new();
    for field in fields {
        let len = u64::try_from(field.len())
            .map_err(|_| "public state digest field is too large".to_string())?;
        framed.extend_from_slice(&len.to_le_bytes());
        framed.extend_from_slice(field);
    }
    Ok(common::crypto::hex_encode(&common::crypto::hash_bytes(
        "dynamic-poa-public-state-v1",
        &[&framed],
    )))
}

#[deprecated(note = "use verify_init_with_policy; production verification requires ChainPolicy")]
pub fn verify_init(
    srs: &Srs,
    public_state: &PublicState,
    proof: &StoredInitProof,
) -> Result<(), String> {
    let _ = (srs, public_state, proof);
    Err(
        "production initialization verification requires ChainPolicy; use verify_init_with_policy"
            .to_string(),
    )
}

pub fn verify_init_with_policy(
    srs: &Srs,
    public_state: &PublicState,
    proof: &StoredInitProof,
    policy: &ChainPolicy,
) -> Result<(), String> {
    if !policy.allow_mock_proofs {
        srs.require_external_ceremony()?;
    }
    policy.check_chain_id(&proof.chain_id)?;
    policy.check_finalized(&public_state.state_root)?;
    let uses_mock_inputs = verify_init_public_proof(srs, public_state, proof)?;
    if !policy.allow_mock_proofs && uses_mock_inputs {
        return Err(
            "production initialization proof used mock ownership or chain-balance inputs"
                .to_string(),
        );
    }
    Ok(())
}

pub fn verify_init_debug(
    srs: &Srs,
    state: &StoredState,
    proof: &StoredInitProof,
) -> Result<(), String> {
    verify_init_proof(srs, state, proof)
}

#[deprecated(note = "use verify_update_production with ChainPolicy and a pinned Sync adapter")]
pub fn verify_update(
    srs: &Srs,
    old_state: &PublicState,
    deltas: &[Delta],
    new_state: &PublicState,
    proof: &StoredProof,
) -> Result<(), String> {
    let _ = (srs, old_state, deltas, new_state, proof);
    Err("production update verification requires ChainPolicy, a canonical Sync proof, and a non-mock adapter; use verify_update_production".to_string())
}

#[allow(clippy::too_many_arguments)]
pub fn verify_update_production(
    srs: &Srs,
    old_state: &PublicState,
    deltas: &[Delta],
    new_state: &PublicState,
    proof: &StoredProof,
    policy: &ChainPolicy,
    sync_proof: &SyncProof,
    external: &impl ExternalProofAdapter,
) -> Result<(), String> {
    if !policy.allow_mock_proofs {
        srs.require_external_ceremony()?;
    }
    policy.check_chain_id(&sync_proof.chain_id)?;
    policy.check_last_accepted(old_state)?;
    policy.check_finalized(&new_state.state_root)?;
    if deltas.len() > policy.max_update_size {
        return Err(format!(
            "canonical Sync list has {} entries, exceeding policy maximum {}",
            deltas.len(),
            policy.max_update_size
        ));
    }
    verify_canonical_delta_order(deltas)?;
    verify_update_production_with_adapter_and_sync_proof(
        srs,
        old_state,
        deltas,
        new_state,
        proof,
        external,
        Some(sync_proof),
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

#[deprecated(note = "use verify_update_production with ChainPolicy and a non-mock adapter")]
pub fn verify_update_with_sync_proof(
    srs: &Srs,
    old_state: &PublicState,
    deltas: &[Delta],
    new_state: &PublicState,
    proof: &StoredProof,
    sync_proof: Option<&SyncProof>,
) -> Result<(), String> {
    let _ = (srs, old_state, deltas, new_state, proof, sync_proof);
    Err("production update verification requires ChainPolicy and a non-mock adapter; use verify_update_production".to_string())
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

fn verify_update_production_with_adapter_and_sync_proof(
    srs: &Srs,
    old_state: &PublicState,
    deltas: &[Delta],
    new_state: &PublicState,
    proof: &StoredProof,
    external: &impl ExternalProofAdapter,
    sync_proof: Option<&SyncProof>,
) -> Result<(), String> {
    let sync_proof = sync_proof.ok_or_else(|| {
        "production update verification requires a canonical Sync proof".to_string()
    })?;
    if !deltas.is_empty()
        && (proof.theta_opening_proof_hex.is_empty()
            || !proof.theta_opening_proof_hex.starts_with("zkopen:"))
    {
        return Err("update proof is missing a production committed-opening proof for ZKOpen(C_Y, theta, C_v); use verify_update_debug only for transparent local tests".to_string());
    }
    verify_update_with_adapter_and_sync_proof(
        srs,
        old_state,
        deltas,
        new_state,
        proof,
        external,
        Some(sync_proof),
    )
}

fn verify_update_with_adapter_and_sync_proof(
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
    if deltas.len() > srs.max_degree {
        return Err(format!(
            "update has {} entries, exceeding SRS-supported maximum {}",
            deltas.len(),
            srs.max_degree
        ));
    }
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
    if old_state.reserve_count == 0 || old_state.reserve_count > srs.max_degree {
        return Err("fixed-set reserve count is outside the SRS-supported range".to_string());
    }
    if old_state.srs_max_degree != srs.max_degree || new_state.srs_max_degree != srs.max_degree {
        return Err("state SRS degree does not match provided SRS".to_string());
    }
    let expected_delta_commitment = delta_list_commitment(deltas);
    if proof.delta_list_commitment_hex != expected_delta_commitment {
        return Err("delta list commitment mismatch".to_string());
    }
    let expected_transcript = build_transcript_hex(
        &old_state.state_root,
        &new_state.state_root,
        &old_state.accumulator_hex,
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
        return Err("update transcript mismatch".to_string());
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

    if deltas.is_empty() {
        verify_empty_update(old_state, new_state, proof)?;
        emit_verify_timing(emit_timing, "verify_update_total", verify_total_start);
        return Ok(());
    }

    let old_balance_commitment = point_g1_from_hex(&old_state.balance_commitment_hex)?;
    let new_balance_commitment = point_g1_from_hex(&new_state.balance_commitment_hex)?;
    let c_d = point_g1_from_hex(&proof.c_d_hex)?;
    if new_balance_commitment != old_balance_commitment + c_d {
        return Err("claimed balance commitment does not match homomorphic update".to_string());
    }
    verify_threshold_encoded(
        &ThresholdStatement {
            public_state: new_state.clone(),
            threshold: 0,
        },
        THRESHOLD_PROOF_SCHEME,
        &proof.balance_range_proof_hex,
    )
    .map_err(|err| format!("updated balance range proof failed: {err}"))?;

    let expected_gate_count = deltas
        .len()
        .checked_mul(2)
        .ok_or_else(|| "update gate count overflow".to_string())?;
    if proof.gate_count != expected_gate_count {
        return Err("gate count does not match 2m relation size".to_string());
    }
    emit_verify_timing(
        emit_timing,
        "verify_state_and_commitment_checks",
        state_checks_start,
    );

    let block_data_start = Instant::now();
    check_public_delta_range(deltas, &RangePolicy::protocol_default())?;
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

fn verify_empty_update(
    old_state: &PublicState,
    new_state: &PublicState,
    proof: &StoredProof,
) -> Result<(), String> {
    if old_state.balance_commitment_hex != new_state.balance_commitment_hex {
        return Err("empty update changed the aggregate balance commitment".to_string());
    }
    if proof.theta != Fr::from(0u64)
        || proof.theta_opening_proof_hex != EMPTY_UPDATE_MARKER
        || proof.gate_count != 0
        || !proof.c_u_hex.is_empty()
        || !proof.c_y_hex.is_empty()
        || !proof.c_d_hex.is_empty()
        || !proof.eval_proof_hex.is_empty()
        || !proof.c_v_hex.is_empty()
        || !proof.bp_proof_hex.is_empty()
        || !proof.witness_vector_commitment_hex.is_empty()
        || !proof.rho_bp_commitment_hex.is_empty()
        || !proof.v_bp_commitment_hex.is_empty()
        || !proof.witness_link_ipa_proof.is_empty()
        || !proof.v_link_proof.is_empty()
        || !proof.projection_ipa_proof.is_empty()
        || !proof.balance_range_proof_hex.is_empty()
    {
        return Err("malformed empty-update artifact".to_string());
    }
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
        if !seen.insert(*point) {
            return Err("duplicate encoded query point".to_string());
        }
    }
    Ok(())
}

fn verify_canonical_delta_order(deltas: &[Delta]) -> Result<(), String> {
    let mut previous = None;
    for delta in deltas {
        let current = encode_address(&delta.address)?.into_bigint();
        if previous.as_ref().is_some_and(|value| value >= &current) {
            return Err(
                "canonical Sync delta list must be strictly sorted and deduplicated".to_string(),
            );
        }
        previous = Some(current);
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
    use ark_bls12_381::Fr;
    use common::crypto::point_g1_to_hex;
    use common::types::{Delta, ReserveEntry, StoredState, SyncProof};

    use super::{
        public_state_digest, verify_init_debug, verify_init_with_policy, verify_update_debug,
        verify_update_production, ChainPolicy,
    };
    use crate::external::MockExternalProofAdapter;
    use crate::init::initialize;
    use crate::init_proof::initialize_with_proof;
    use crate::insert::{
        apply_insert, check_insert_metadata_debug, verify_insert,
        verify_insert_with_srs_and_policy, KzgInsertWitness,
    };
    use crate::kzg::Srs;
    use crate::polynomial::product_from_roots;
    use crate::update::{apply_update, delta_list_commitment};

    fn update_test_state(srs: &Srs, address: &str, balance: i128) -> StoredState {
        let alpha = Fr::from(7u64);
        let root = common::encoding::encode_address(address).unwrap();
        let polynomial = product_from_roots(&[root]).mul_scalar(alpha);
        let accumulator = crate::kzg::commit_g1(srs, &polynomial).unwrap();
        let balance_blind = Fr::from(11u64);
        let balance_commitment = crate::commitment::commit_balance(balance, balance_blind);
        StoredState {
            state_root: "root-0".to_string(),
            srs_max_degree: srs.max_degree,
            alpha,
            reserve_addresses: vec![address.to_string()],
            reserve_balances: vec![balance],
            masked_polynomial_coeffs: polynomial.coeffs,
            accumulator_hex: point_g1_to_hex(&accumulator).unwrap(),
            balance_total: balance,
            balance_blind,
            balance_commitment_hex: point_g1_to_hex(&balance_commitment).unwrap(),
        }
    }

    #[test]
    fn accepts_honest_sp1_init() {
        let srs = Srs::setup_development(16, b"test-srs-init");
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
        let policy =
            ChainPolicy::development("mock-chain", ["root-0".to_string()], None, None, 16).unwrap();
        verify_init_with_policy(&srs, &init.state.public_state(), &init.proof, &policy).unwrap();
    }

    #[test]
    fn rejects_tampered_init_shape_commitment() {
        let srs = Srs::setup_development(16, b"test-srs-init-bad");
        let entries = vec![ReserveEntry {
            address: "0x1111111111111111111111111111111111111111".to_string(),
            balance: 100,
        }];
        let mut init = initialize_with_proof(&entries, "root-0", &srs).unwrap();
        init.proof.c_shape_hex.push('0');
        let err = verify_init_debug(&srs, &init.state, &init.proof).expect_err("proof should fail");
        assert!(!err.is_empty());
    }

    #[test]
    fn accepts_honest_update() {
        let srs = Srs::setup_development(16, b"test-srs");
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
        let sync = SyncProof {
            scheme: "mock-canonical-sync".to_string(),
            chain_id: "mock-chain".to_string(),
            old_state_root: "root-0".to_string(),
            new_state_root: "root-1".to_string(),
            delta_list_commitment_hex: delta_list_commitment(&deltas),
            proof_hex: "mock-sync-proof".to_string(),
        };
        let policy = ChainPolicy::development(
            "mock-chain",
            ["root-1".to_string()],
            Some("root-0".to_string()),
            Some(public_state_digest(&init.state.public_state()).unwrap()),
            16,
        )
        .unwrap();
        verify_update_production(
            &srs,
            &init.state.public_state(),
            &deltas,
            &updated.next_state.public_state(),
            &updated.proof,
            &policy,
            &sync,
            &MockExternalProofAdapter,
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
    fn rejects_tampered_update_balance_range_proof() {
        let srs = Srs::setup_development(8, b"test-srs-range-tamper");
        let address = "0x1111111111111111111111111111111111111111";
        let state = update_test_state(&srs, address, 100);
        let deltas = vec![Delta {
            address: address.to_string(),
            delta: 7,
        }];
        let mut updated = apply_update(&srs, &state, &deltas, "root-1").unwrap();
        verify_update_debug(
            &srs,
            &state.public_state(),
            &deltas,
            &updated.next_state.public_state(),
            &updated.proof,
        )
        .unwrap();
        updated.proof.balance_range_proof_hex.push('0');
        let err = verify_update_debug(
            &srs,
            &state.public_state(),
            &deltas,
            &updated.next_state.public_state(),
            &updated.proof,
        )
        .expect_err("tampered balance range proof should fail");
        assert!(err.contains("range proof"));
    }

    #[test]
    fn rejects_update_that_makes_total_negative() {
        let srs = Srs::setup_development(8, b"test-srs-negative-total");
        let address = "0x1111111111111111111111111111111111111111";
        let state = update_test_state(&srs, address, 100);
        let deltas = vec![Delta {
            address: address.to_string(),
            delta: -101,
        }];
        let err = apply_update(&srs, &state, &deltas, "root-1")
            .expect_err("negative updated total should fail");
        assert!(err.contains("negative"));
    }

    #[test]
    fn accepts_update_with_mock_sync_proof() {
        let srs = Srs::setup_development(16, b"test-srs-sync");
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
            chain_id: "mock-chain".to_string(),
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
        let srs = Srs::setup_development(8, b"test-srs-small");
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
        let srs = Srs::setup_development(8, b"test-srs-random-link");
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
        let srs = Srs::setup_development(16, b"test-srs-insert");
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
        let policy = ChainPolicy::development(
            "mock-chain",
            ["root-0".to_string()],
            Some("root-0".to_string()),
            Some(public_state_digest(&init.state.public_state()).unwrap()),
            16,
        )
        .unwrap();
        verify_insert_with_srs_and_policy(
            &srs,
            &init.state.public_state(),
            &insert.next_state.public_state(),
            &insert.proof,
            &policy,
        )
        .unwrap();
        check_insert_metadata_debug(
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
        let srs = Srs::setup_development(16, b"test-srs-insert-artifact");
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
        let policy = ChainPolicy::development(
            "mock-chain",
            ["root-0".to_string()],
            Some("root-0".to_string()),
            Some(public_state_digest(&init.state.public_state()).unwrap()),
            16,
        )
        .unwrap();
        let err = verify_insert_with_srs_and_policy(
            &srs,
            &init.state.public_state(),
            &insert.next_state.public_state(),
            &insert.proof,
            &policy,
        )
        .expect_err("proof should fail");
        assert!(!err.is_empty());
    }
}
