use ark_bls12_381::Fr;
use ark_ec::PrimeGroup;
use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
use common::crypto::{
    hash_bytes, hash_to_scalar, hex_decode, point_g1_from_hex, point_g1_to_hex, scalar_to_hex,
};
use common::types::{
    InitProvingContext, InitReserveWitness, PublicState, ReserveEntry, StoredInitProof, StoredState,
};

use crate::commitment::commit_balance;
use crate::commitment::derive_generator;
use crate::external::{ExternalProofAdapter, MockExternalProofAdapter};
use crate::kzg::{commit_g1, open as kzg_open, Srs};
use crate::polynomial::product_from_roots;
use crate::zkopen::{prove_committed_opening, verify_committed_opening};
use rand::RngCore;

#[derive(Clone, Debug)]
pub struct InitProofResult {
    pub state: StoredState,
    pub proof: StoredInitProof,
}

/// Builds the private state that a successful initialization would leave
/// behind, without producing or accepting an initialization proof.
///
/// This is intentionally restricted to benchmark/fixture preparation.  It
/// preserves the real root-polynomial, KZG accumulator, reserve balances, and
/// Pedersen balance commitment consumed by `apply_update`; only the expensive
/// SP1 ownership/chain-state proof is skipped.
pub fn build_mock_initialized_state(
    reserve_entries: &[ReserveEntry],
    state_root: &str,
    srs: &Srs,
) -> Result<StoredState, String> {
    if reserve_entries.is_empty() {
        return Err("reserve set must not be empty".to_string());
    }
    if reserve_entries.len() > srs.max_degree {
        return Err(format!(
            "reserve set size {} exceeds SRS degree bound {}",
            reserve_entries.len(),
            srs.max_degree
        ));
    }
    if reserve_entries.iter().any(|entry| entry.balance < 0) {
        return Err("reserve balances must be non-negative".to_string());
    }

    let mut canonical_entries = reserve_entries
        .iter()
        .map(|entry| {
            Ok((
                common::encoding::encode_address(&entry.address)?,
                entry.clone(),
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    canonical_entries.sort_by(|left, right| left.0.into_bigint().cmp(&right.0.into_bigint()));

    let mut roots = Vec::with_capacity(canonical_entries.len());
    let mut reserve_addresses = Vec::with_capacity(canonical_entries.len());
    let mut reserve_balances = Vec::with_capacity(canonical_entries.len());
    for (root, entry) in canonical_entries {
        roots.push(root);
        reserve_addresses.push(entry.address);
        reserve_balances.push(entry.balance);
    }
    if !is_strictly_ordered(&roots) {
        return Err("reserve addresses must be canonical and duplicate-free".to_string());
    }

    let mut rng = rand::rngs::OsRng;
    let mut alpha = Fr::rand(&mut rng);
    while alpha.is_zero() {
        alpha = Fr::rand(&mut rng);
    }
    let polynomial = product_from_roots(&roots).mul_scalar(alpha);
    let accumulator = commit_g1(srs, &polynomial)?;
    let balance_total = reserve_balances.iter().try_fold(0i128, |sum, balance| {
        sum.checked_add(*balance)
            .ok_or_else(|| "reserve balance total overflow".to_string())
    })?;
    let balance_blind = Fr::rand(&mut rng);
    let balance_commitment = commit_balance(balance_total, balance_blind);

    Ok(StoredState {
        state_root: state_root.to_string(),
        srs_max_degree: srs.max_degree,
        alpha,
        reserve_addresses,
        reserve_balances,
        masked_polynomial_coeffs: polynomial.coeffs,
        accumulator_hex: point_g1_to_hex(&accumulator)?,
        balance_total,
        balance_blind,
        balance_commitment_hex: point_g1_to_hex(&balance_commitment)?,
    })
}

/// Validates a persisted mock-initialized state before it is used as the
/// untimed starting point of an update benchmark.
pub fn validate_mock_initialized_state_shape(srs: &Srs, state: &StoredState) -> Result<(), String> {
    if state.srs_max_degree != srs.max_degree {
        return Err("mock initialized state SRS degree mismatch".to_string());
    }
    if state.reserve_addresses.is_empty()
        || state.reserve_addresses.len() != state.reserve_balances.len()
    {
        return Err("invalid mock initialized reserve vectors".to_string());
    }
    if state.reserve_addresses.len() > srs.max_degree {
        return Err("mock initialized reserve set exceeds SRS degree".to_string());
    }
    if state.masked_polynomial_coeffs.len() != state.reserve_addresses.len() + 1 {
        return Err("mock initialized polynomial degree mismatch".to_string());
    }
    if state.reserve_balances.iter().any(|balance| *balance < 0) {
        return Err("mock initialized state contains a negative balance".to_string());
    }
    if state.alpha.is_zero() {
        return Err("mock initialized alpha is zero".to_string());
    }
    let balance_total = state
        .reserve_balances
        .iter()
        .try_fold(0i128, |sum, balance| {
            sum.checked_add(*balance)
                .ok_or_else(|| "mock initialized balance total overflow".to_string())
        })?;
    if balance_total != state.balance_total {
        return Err("mock initialized balance total mismatch".to_string());
    }
    let balance_commitment = commit_balance(state.balance_total, state.balance_blind);
    if point_g1_to_hex(&balance_commitment)? != state.balance_commitment_hex {
        return Err("mock initialized balance commitment mismatch".to_string());
    }
    let _ = point_g1_from_hex(&state.accumulator_hex)
        .map_err(|err| format!("invalid mock initialized accumulator: {err}"))?;
    Ok(())
}

/// Performs the expensive one-time polynomial and accumulator validation used
/// while preparing the persisted benchmark artifact.
pub fn verify_mock_initialized_state(srs: &Srs, state: &StoredState) -> Result<(), String> {
    validate_mock_initialized_state_shape(srs, state)?;
    let roots = state
        .reserve_addresses
        .iter()
        .map(|address| common::encoding::encode_address(address))
        .collect::<Result<Vec<_>, _>>()?;
    if !is_strictly_ordered(&roots) {
        return Err("mock initialized addresses are not canonical".to_string());
    }
    let polynomial = product_from_roots(&roots).mul_scalar(state.alpha);
    if polynomial.coeffs != state.masked_polynomial_coeffs {
        return Err("mock initialized polynomial does not match reserve roots".to_string());
    }
    let accumulator = commit_g1(srs, &polynomial)?;
    if point_g1_to_hex(&accumulator)? != state.accumulator_hex {
        return Err("mock initialized accumulator mismatch".to_string());
    }
    Ok(())
}

pub fn initialize_from_witnesses(
    ctx: &InitProvingContext,
    reserve_witnesses: &[InitReserveWitness],
    srs: &Srs,
) -> Result<InitProofResult, String> {
    initialize_from_witnesses_with_adapter(ctx, reserve_witnesses, srs, &MockExternalProofAdapter)
}

pub fn initialize_from_witnesses_with_adapter(
    ctx: &InitProvingContext,
    reserve_witnesses: &[InitReserveWitness],
    srs: &Srs,
    external: &impl ExternalProofAdapter,
) -> Result<InitProofResult, String> {
    let validation_timer = common::profiling::PhaseTimer::start("init-host", "witness_validation");
    if reserve_witnesses.is_empty() {
        return Err("reserve set must not be empty".to_string());
    }
    for witness in reserve_witnesses {
        validate_chain_id(&ctx.chain_id, &witness.chain_balance_proof)?;
    }

    for witness in reserve_witnesses {
        external.validate_init_witness(ctx, witness)?;
    }
    let reserve_entries = reserve_witnesses
        .iter()
        .map(|witness| ReserveEntry {
            address: witness.address.clone(),
            balance: witness.balance,
        })
        .collect::<Vec<_>>();
    validation_timer.finish();
    initialize_core(ctx, &reserve_entries, reserve_witnesses, srs)
}

pub fn initialize_with_proof(
    reserve_entries: &[ReserveEntry],
    state_root: &str,
    srs: &Srs,
) -> Result<InitProofResult, String> {
    initialize_with_proof_and_adapter(reserve_entries, state_root, srs, &MockExternalProofAdapter)
}

pub fn initialize_with_proof_and_adapter(
    reserve_entries: &[ReserveEntry],
    state_root: &str,
    srs: &Srs,
    external: &impl ExternalProofAdapter,
) -> Result<InitProofResult, String> {
    let ctx = InitProvingContext {
        chain_id: "mock-chain".to_string(),
        state_root: state_root.to_string(),
        session_id: "mock-init-session".to_string(),
        chain_batch_proof: None,
    };
    let reserve_witnesses = reserve_entries
        .iter()
        .map(|entry| InitReserveWitness {
            address: entry.address.clone(),
            balance: entry.balance,
            ownership: common::types::OwnershipWitnessInput::MockPrivateKey {
                mock_private_key: format!("mock-private-key:{}", entry.address),
            },
            chain_balance_proof: common::types::ChainBalanceProofInput::Mock {
                proof_label: format!("mock-balance-proof:{}", entry.address),
            },
        })
        .collect::<Vec<_>>();
    for witness in &reserve_witnesses {
        external.validate_init_witness(&ctx, witness)?;
    }
    initialize_core(&ctx, reserve_entries, &reserve_witnesses, srs)
}

fn initialize_core(
    ctx: &InitProvingContext,
    reserve_entries: &[ReserveEntry],
    reserve_witnesses: &[InitReserveWitness],
    srs: &Srs,
) -> Result<InitProofResult, String> {
    let total_timer =
        common::profiling::PhaseTimer::start("init-host", "total_including_profile_probe");
    if reserve_entries.is_empty() {
        return Err("reserve set must not be empty".to_string());
    }
    if reserve_entries.iter().any(|entry| entry.balance < 0) {
        return Err("reserve balances must be non-negative".to_string());
    }
    if reserve_entries.len() > srs.max_degree {
        return Err(format!(
            "reserve set size {} exceeds SRS degree bound {}",
            reserve_entries.len(),
            srs.max_degree
        ));
    }
    if reserve_entries.len() != reserve_witnesses.len() {
        return Err("reserve entries and init witnesses length mismatch".to_string());
    }

    let canonical_timer =
        common::profiling::PhaseTimer::start("init-host", "canonicalize_addresses");
    let mut canonical_entries = Vec::with_capacity(reserve_entries.len());
    for (index, (entry, _witness)) in reserve_entries
        .iter()
        .zip(reserve_witnesses.iter())
        .enumerate()
    {
        canonical_entries.push((common::encoding::encode_address(&entry.address)?, index));
    }
    canonical_entries.sort_by(|left, right| left.0.into_bigint().cmp(&right.0.into_bigint()));

    let mut reserve_addresses = Vec::with_capacity(reserve_entries.len());
    let mut reserve_balances = Vec::with_capacity(reserve_entries.len());
    let mut roots = Vec::with_capacity(reserve_entries.len());
    let mut canonical_witnesses = Vec::with_capacity(reserve_witnesses.len());
    for (root, index) in canonical_entries {
        let entry = &reserve_entries[index];
        roots.push(root);
        reserve_addresses.push(entry.address.clone());
        reserve_balances.push(entry.balance);
        canonical_witnesses.push(&reserve_witnesses[index]);
    }
    if !is_strictly_ordered(&roots) {
        return Err("reserve addresses must be canonical and duplicate-free".to_string());
    }
    canonical_timer.finish();

    let polynomial_timer =
        common::profiling::PhaseTimer::start("init-host", "polynomial_construction");
    let mut rng = rand::rngs::OsRng;
    let mut alpha = Fr::rand(&mut rng);
    while alpha.is_zero() {
        alpha = Fr::rand(&mut rng);
    }
    if alpha.is_zero() {
        return Err("derived alpha must be non-zero".to_string());
    }

    let f_s = product_from_roots(&roots);
    let p_s = f_s.mul_scalar(alpha);
    drop(f_s);
    polynomial_timer.finish();
    let accumulator_timer =
        common::profiling::PhaseTimer::start("init-host", "kzg_accumulator_commit");
    let accumulator = commit_g1(srs, &p_s)?;
    accumulator_timer.finish();
    let balance_timer = common::profiling::PhaseTimer::start("init-host", "balance_commitment");
    let balance_total = reserve_balances.iter().try_fold(0i128, |sum, balance| {
        sum.checked_add(*balance)
            .ok_or_else(|| "reserve balance total overflow".to_string())
    })?;
    let balance_blind = Fr::rand(&mut rng);
    let balance_commitment = commit_balance(balance_total, balance_blind);
    let mut shape_salt = [0u8; 32];
    rng.fill_bytes(&mut shape_salt);
    let c_shape = sp1_host::init::shape_commitment(alpha, &roots, &shape_salt);
    balance_timer.finish();

    let opening_timer =
        common::profiling::PhaseTimer::start("init-host", "challenge_kzg_open_zkopen");
    let zeta = derive_zeta(
        &ctx.chain_id,
        &ctx.state_root,
        &ctx.session_id,
        reserve_entries.len(),
        &accumulator,
        &balance_commitment,
        &c_shape,
    )?;
    let p_zeta = p_s.evaluate(zeta);
    let product_zeta = roots.iter().fold(alpha, |acc, root| acc * (zeta - *root));
    let kzg_opening_proof = kzg_open(srs, &p_s, zeta, p_zeta)?;
    let r_y = Fr::rand(&mut rng);
    let c_y = commit_eval(p_zeta, r_y);
    let accumulator_hex = point_g1_to_hex(&accumulator)?;
    let balance_commitment_hex = point_g1_to_hex(&balance_commitment)?;
    let c_y_hex = point_g1_to_hex(&c_y)?;
    let kzg_opening_proof_hex = prove_committed_opening(
        srs,
        &accumulator_hex,
        zeta,
        &c_y_hex,
        p_zeta,
        r_y,
        &kzg_opening_proof,
        "dynamic-poa-init-eval-zkopen",
    )?;
    opening_timer.finish();
    let transcript_timer =
        common::profiling::PhaseTimer::start("init-host", "transcript_and_generators");
    let transcript_hex = build_transcript_hex(
        &ctx.chain_id,
        &ctx.state_root,
        &ctx.session_id,
        reserve_entries.len(),
        &accumulator_hex,
        &balance_commitment_hex,
        &common::crypto::hex_encode(&c_shape),
        &c_y_hex,
        zeta,
    );
    let srs_hash_hex = point_hash_srs(srs)?;
    let balance_value_base = derive_generator("balance-v", 0);
    let balance_blind_base = derive_generator("balance-h", 0);
    let eval_value_base = derive_generator("eval-v", 0);
    let eval_blind_base = derive_generator("eval-h", 0);
    transcript_timer.finish();
    // Prove ownership first and release its linear-size stdin before building
    // the Merkle/protocol stdin. This keeps the two SP1 executions genuinely
    // sequential instead of retaining both witness encodings at peak memory.
    let ownership_stdin_timer =
        common::profiling::PhaseTimer::start("init-host", "ownership_stdin_encode");
    let ownership_stdin = sp1_host::init::build_init_ownership_stdin(
        &ctx.chain_id,
        &ctx.state_root,
        &ctx.session_id,
        &reserve_addresses,
        &reserve_balances,
        &canonical_witnesses,
    )?;
    ownership_stdin_timer.finish();
    let ownership_prove_timer =
        common::profiling::PhaseTimer::start("init-host", "ownership_sp1_with_profile_probe");
    let ownership_sp1 = sp1_host::init::prove_init_ownership(ownership_stdin)?;
    ownership_prove_timer.finish();

    let merkle_stdin_timer =
        common::profiling::PhaseTimer::start("init-host", "merkle_stdin_encode");
    let merkle_stdin = sp1_host::init::build_init_merkle_stdin(
        &ctx.chain_id,
        &ctx.state_root,
        &ctx.session_id,
        alpha,
        zeta,
        p_zeta,
        product_zeta,
        balance_total,
        balance_blind,
        shape_salt,
        c_shape,
        r_y,
        &balance_value_base,
        &balance_blind_base,
        &eval_value_base,
        &eval_blind_base,
        &balance_commitment,
        &c_y,
        &reserve_addresses,
        &roots,
        &reserve_balances,
        &canonical_witnesses,
        ctx.chain_batch_proof.as_ref(),
    )?;
    merkle_stdin_timer.finish();
    let merkle_prove_timer =
        common::profiling::PhaseTimer::start("init-host", "merkle_sp1_with_profile_probe");
    let merkle_sp1 = sp1_host::init::prove_init_merkle(merkle_stdin)?;
    merkle_prove_timer.finish();
    if merkle_sp1.public.chain_id != ownership_sp1.public.chain_id
        || merkle_sp1.public.state_root != ownership_sp1.public.state_root
        || merkle_sp1.public.session_id != ownership_sp1.public.session_id
        || merkle_sp1.public.reserve_count != ownership_sp1.public.reserve_count
        || merkle_sp1.public.reserve_commitment != ownership_sp1.public.reserve_commitment
    {
        return Err(
            "split initialization SP1 proofs are not bound to the same reserves".to_string(),
        );
    }

    let assembly_timer =
        common::profiling::PhaseTimer::start("init-host", "proof_and_state_assembly");
    let proof = StoredInitProof {
        scheme: "kzg-nizk-init-v8-zkopen-keccak-merkle-prefix-split".to_string(),
        mode: "sp1".to_string(),
        chain_id: ctx.chain_id.clone(),
        state_root: ctx.state_root.clone(),
        session_id: ctx.session_id.clone(),
        accumulator_hex,
        balance_commitment_hex,
        c_shape_hex: common::crypto::hex_encode(&c_shape),
        c_y_hex,
        reserve_count: reserve_entries.len(),
        zeta,
        kzg_opening_proof_hex,
        sp1_proof_hex: merkle_sp1.proof_hex,
        sp1_vk_hex: String::new(),
        sp1_public_values_hex: String::new(),
        ownership_sp1_proof_hex: ownership_sp1.proof_hex,
        ownership_sp1_vk_hex: String::new(),
        ownership_sp1_public_values_hex: String::new(),
        transcript_hex,
        srs_hash_hex,
    };

    let state = StoredState {
        state_root: ctx.state_root.clone(),
        srs_max_degree: srs.max_degree,
        alpha,
        reserve_addresses,
        reserve_balances,
        masked_polynomial_coeffs: p_s.coeffs,
        accumulator_hex: proof.accumulator_hex.clone(),
        balance_total,
        balance_blind,
        balance_commitment_hex: proof.balance_commitment_hex.clone(),
    };

    assembly_timer.finish();
    total_timer.finish();
    Ok(InitProofResult { state, proof })
}

fn validate_chain_id(
    expected: &str,
    proof: &common::types::ChainBalanceProofInput,
) -> Result<(), String> {
    let actual = match proof {
        common::types::ChainBalanceProofInput::Mock { .. } => return Ok(()),
        common::types::ChainBalanceProofInput::EthereumAccountProof { chain_id, .. }
        | common::types::ChainBalanceProofInput::GenericMerkleProof { chain_id, .. }
        | common::types::ChainBalanceProofInput::BinaryMerkleV1 { chain_id, .. }
        | common::types::ChainBalanceProofInput::EthereumVerkleBatchMember { chain_id, .. }
        | common::types::ChainBalanceProofInput::EthereumVerkleProof { chain_id, .. } => chain_id,
    };
    if actual != expected {
        return Err(format!(
            "chain proof chain_id mismatch: expected {expected}, got {actual}"
        ));
    }
    Ok(())
}

pub fn verify_init_proof(
    srs: &Srs,
    state: &StoredState,
    proof: &StoredInitProof,
) -> Result<(), String> {
    verify_init_public_proof(srs, &state.public_state(), proof)?;
    if state.reserve_addresses.len() != state.reserve_balances.len() {
        return Err(
            "private reserve address and balance vectors have different lengths".to_string(),
        );
    }
    if state.reserve_balances.iter().any(|balance| *balance < 0) {
        return Err("private reserve balances must be non-negative".to_string());
    }
    let roots = state
        .reserve_addresses
        .iter()
        .map(|address| common::encoding::encode_address(address))
        .collect::<Result<Vec<_>, _>>()?;
    if state.alpha.is_zero() {
        return Err("private initialization alpha is zero".to_string());
    }
    let f_s = product_from_roots(&roots);
    let p_s = f_s.mul_scalar(state.alpha);
    if p_s.coeffs != state.masked_polynomial_coeffs {
        return Err("private polynomial witness mismatch".to_string());
    }
    let accumulator = commit_g1(srs, &p_s)?;
    if point_g1_to_hex(&accumulator)? != proof.accumulator_hex {
        return Err("recomputed accumulator mismatch".to_string());
    }
    if !is_strictly_ordered(&roots) {
        return Err("reserve address encodings are not duplicate-free strict order".to_string());
    }
    let balance_total = state
        .reserve_balances
        .iter()
        .try_fold(0i128, |sum, balance| {
            sum.checked_add(*balance)
                .ok_or_else(|| "private reserve balance total overflow".to_string())
        })?;
    if balance_total != state.balance_total {
        return Err("private balance total mismatch".to_string());
    }
    let balance_commitment = commit_balance(state.balance_total, state.balance_blind);
    if point_g1_to_hex(&balance_commitment)? != proof.balance_commitment_hex {
        return Err("balance commitment recomputation mismatch".to_string());
    }

    Ok(())
}

pub(crate) fn verify_init_public_proof(
    srs: &Srs,
    public_state: &PublicState,
    proof: &StoredInitProof,
) -> Result<bool, String> {
    if public_state.srs_max_degree != srs.max_degree {
        return Err("state SRS degree does not match provided SRS".to_string());
    }
    if proof.reserve_count == 0 || proof.reserve_count > srs.max_degree {
        return Err("init reserve count is outside the SRS-supported range".to_string());
    }
    if proof.state_root != public_state.state_root {
        return Err("init proof state_root mismatch".to_string());
    }
    if proof.reserve_count != public_state.reserve_count {
        return Err("init proof reserve count mismatch".to_string());
    }
    if proof.accumulator_hex != public_state.accumulator_hex {
        return Err("init proof accumulator mismatch".to_string());
    }
    if proof.balance_commitment_hex != public_state.balance_commitment_hex {
        return Err("init proof balance commitment mismatch".to_string());
    }
    if proof.srs_hash_hex != point_hash_srs(srs)? {
        return Err("SRS hash mismatch".to_string());
    }
    if proof.scheme != "kzg-nizk-init-v8-zkopen-keccak-merkle-prefix-split" {
        return Err("init proof is not a production ZK proof; use verify_init_debug only for transparent local tests".to_string());
    }
    if proof.mode != "sp1" {
        return Err("init proof mode is not sp1".to_string());
    }
    if proof.kzg_opening_proof_hex.is_empty()
        || proof.sp1_proof_hex.is_empty()
        || proof.ownership_sp1_proof_hex.is_empty()
    {
        return Err("missing init proof-system artifact".to_string());
    }
    let accumulator = point_g1_from_hex(&proof.accumulator_hex)?;
    let balance_commitment = point_g1_from_hex(&proof.balance_commitment_hex)?;
    let c_shape = parse_shape_commitment(&proof.c_shape_hex)?;
    let c_y = point_g1_from_hex(&proof.c_y_hex)?;
    let expected_zeta = derive_zeta(
        &proof.chain_id,
        &proof.state_root,
        &proof.session_id,
        proof.reserve_count,
        &accumulator,
        &balance_commitment,
        &c_shape,
    )?;
    if expected_zeta != proof.zeta {
        return Err("init Fiat-Shamir challenge mismatch".to_string());
    }
    verify_committed_opening(
        srs,
        &proof.accumulator_hex,
        proof.zeta,
        &proof.c_y_hex,
        &proof.kzg_opening_proof_hex,
        "dynamic-poa-init-eval-zkopen",
    )?;

    let (sp1_public, ownership_public) = sp1_host::init::verify_init_proof(proof)?;
    let balance_value_base = derive_generator("balance-v", 0);
    let balance_blind_base = derive_generator("balance-h", 0);
    let eval_value_base = derive_generator("eval-v", 0);
    let eval_blind_base = derive_generator("eval-h", 0);
    let expected_params_digest = sp1_host::init::commitment_params_digest(
        &balance_value_base,
        &balance_blind_base,
        &eval_value_base,
        &eval_blind_base,
    );
    if sp1_public.chain_id != proof.chain_id
        || sp1_public.state_root != proof.state_root
        || sp1_public.session_id != proof.session_id
        || sp1_public.reserve_count != proof.reserve_count
        || sp1_public.zeta_le != fr_to_le_bytes(proof.zeta)
        || !sp1_host::kzg_insert::point_matches(&sp1_public.balance_commitment, &balance_commitment)
        || sp1_public.shape_commitment != c_shape
        || !sp1_host::kzg_insert::point_matches(&sp1_public.eval_commitment, &c_y)
        || sp1_public.commitment_params_digest_hex != expected_params_digest
        || ownership_public.chain_id != proof.chain_id
        || ownership_public.state_root != proof.state_root
        || ownership_public.session_id != proof.session_id
        || ownership_public.reserve_count != proof.reserve_count
        || ownership_public.reserve_commitment != sp1_public.reserve_commitment
    {
        return Err("init SP1 public values mismatch".to_string());
    }

    let expected_transcript = build_transcript_hex(
        &proof.chain_id,
        &proof.state_root,
        &proof.session_id,
        proof.reserve_count,
        &proof.accumulator_hex,
        &proof.balance_commitment_hex,
        &proof.c_shape_hex,
        &proof.c_y_hex,
        proof.zeta,
    );
    if expected_transcript != proof.transcript_hex {
        return Err("init transcript mismatch".to_string());
    }
    Ok(sp1_public.uses_mock_inputs || ownership_public.uses_mock_inputs)
}

fn commit_eval(value: Fr, blind: Fr) -> ark_bls12_381::G1Projective {
    derive_generator("eval-v", 0).mul_bigint(value.into_bigint())
        + derive_generator("eval-h", 0).mul_bigint(blind.into_bigint())
}

fn is_strictly_ordered(values: &[Fr]) -> bool {
    values
        .windows(2)
        .all(|pair| pair[0].into_bigint() < pair[1].into_bigint())
}

fn derive_zeta(
    chain_id: &str,
    state_root: &str,
    session_id: &str,
    reserve_count: usize,
    accumulator: &ark_bls12_381::G1Projective,
    balance_commitment: &ark_bls12_381::G1Projective,
    c_shape: &[u8; 32],
) -> Result<Fr, String> {
    let payload = [
        chain_id.as_bytes(),
        state_root.as_bytes(),
        session_id.as_bytes(),
        &reserve_count.to_le_bytes(),
        point_g1_to_hex(accumulator)?.as_bytes(),
        point_g1_to_hex(balance_commitment)?.as_bytes(),
        c_shape,
    ]
    .concat();
    let mut zeta = hash_to_scalar("init-zeta-v2-salted-shape-hash", &payload);
    if zeta.is_zero() {
        zeta = Fr::from(41u64);
    }
    Ok(zeta)
}

fn build_transcript_hex(
    chain_id: &str,
    state_root: &str,
    session_id: &str,
    reserve_count: usize,
    accumulator: &str,
    balance_commitment: &str,
    c_shape: &str,
    c_y: &str,
    zeta: Fr,
) -> String {
    let payload = [
        chain_id.as_bytes(),
        state_root.as_bytes(),
        session_id.as_bytes(),
        reserve_count.to_string().as_bytes(),
        accumulator.as_bytes(),
        balance_commitment.as_bytes(),
        c_shape.as_bytes(),
        c_y.as_bytes(),
        scalar_to_hex(&zeta).unwrap_or_default().as_bytes(),
    ]
    .concat();
    common::crypto::hex_encode(&hash_bytes(
        "init-transcript-v2-salted-shape-hash",
        &[&payload],
    ))
}

fn parse_shape_commitment(value: &str) -> Result<[u8; 32], String> {
    hex_decode(value)?
        .try_into()
        .map_err(|_| "initialization salted shape commitment must contain 32 bytes".to_string())
}

fn point_hash_srs(srs: &Srs) -> Result<String, String> {
    if srs.tau_g1_powers.len() < 2 || srs.tau_g2_powers.len() < 2 {
        return Err(
            "initialization verification requires tau^0 and tau^1 in both SRS groups".to_string(),
        );
    }
    let mut bytes = Vec::new();
    let encoded_degree = u64::try_from(srs.max_degree)
        .map_err(|_| "SRS max_degree does not fit the initialization transcript".to_string())?;
    bytes.extend_from_slice(&encoded_degree.to_le_bytes());
    for point in &srs.tau_g1_powers[..2] {
        bytes.extend_from_slice(&common::crypto::serialize_hex(point)?.into_bytes());
    }
    for point in &srs.tau_g2_powers[..2] {
        bytes.extend_from_slice(&common::crypto::serialize_hex(point)?.into_bytes());
    }
    Ok(common::crypto::hex_encode(&hash_bytes(
        "srs-hash",
        &[&bytes],
    )))
}

fn fr_to_le_bytes(value: Fr) -> [u8; 32] {
    let raw = value.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    let len = raw.len().min(32);
    out[..len].copy_from_slice(&raw[..len]);
    out
}
