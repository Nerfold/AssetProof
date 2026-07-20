use std::sync::OnceLock;

use ark_bls12_381::{Fr, G2Projective};
use ark_ec::PrimeGroup;
use ark_ff::{Field, PrimeField, UniformRand, Zero};

use common::crypto::{point_g1_from_hex, point_g1_to_hex, point_g2_from_hex, point_g2_to_hex};
use common::encoding::encode_address;
use common::types::{ChainBalanceProofInput, OwnershipWitnessInput, PublicState, StoredState};

use crate::commitment::{balance_generators, commit_balance, eval_generators};
use crate::external::{
    ExternalProofAdapter, ExternalProofArtifact, MockExternalProofAdapter, Sp1NativeProofAdapter,
};
use crate::kzg::{commit_g1, Srs};
use crate::polynomial::Polynomial;
use crate::strong_zkopen::{
    prove_com_nonzero, prove_strong_zkopen, verify_com_nonzero, verify_digest_transition,
    verify_strong_zkopen, ComNonZeroWitness, StrongZkOpenStatement, StrongZkOpenWitness,
};
use crate::verifier::ChainPolicy;
use crate::zkopen::eval_commit;

const INSERT_SCHEME: &str = "kzg-strong-zkopen-insert-v1-sp1-committed-input";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KzgInsertWitness {
    pub chain_id: String,
    pub address: String,
    pub balance: i128,
    pub ownership: OwnershipWitnessInput,
    pub chain_balance_proof: ChainBalanceProofInput,
    pub ownership_artifact: ExternalProofArtifact,
    pub chain_balance_artifact: ExternalProofArtifact,
}

impl KzgInsertWitness {
    pub fn mock(
        address: String,
        balance: i128,
        _ownership_witness: String,
        _chain_balance_witness: String,
    ) -> Self {
        let ownership_witness = format!("mock-private-key:{address}");
        let chain_balance_witness = format!("mock-balance-proof:{address}");
        Self {
            chain_id: "mock-chain".to_string(),
            ownership: OwnershipWitnessInput::MockPrivateKey {
                mock_private_key: ownership_witness.clone(),
            },
            chain_balance_proof: ChainBalanceProofInput::Mock {
                proof_label: chain_balance_witness.clone(),
            },
            address,
            balance,
            ownership_artifact: ExternalProofArtifact::mock(ownership_witness),
            chain_balance_artifact: ExternalProofArtifact::mock(chain_balance_witness),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn ethereum(
        chain_id: String,
        address: String,
        balance: i128,
        signature_hex: String,
        block_number: u64,
        block_hash_hex: String,
        account_proof_rlp_hex: Vec<String>,
    ) -> Self {
        Self {
            chain_id: chain_id.clone(),
            address,
            balance,
            ownership: OwnershipWitnessInput::EthereumEoaSignatureHex { signature_hex },
            chain_balance_proof: ChainBalanceProofInput::EthereumAccountProof {
                chain_id,
                block_number,
                block_hash_hex,
                account_proof_rlp_hex,
            },
            ownership_artifact: ExternalProofArtifact {
                scheme: "sp1-native-ownership".to_string(),
                payload_hex: String::new(),
            },
            chain_balance_artifact: ExternalProofArtifact {
                scheme: "sp1-native-chain-balance".to_string(),
                payload_hex: String::new(),
            },
        }
    }

    pub fn ethereum_verkle(
        chain_id: String,
        address: String,
        balance: i128,
        signature_hex: String,
        tree_key: [u8; 32],
        basic_data: [u8; 32],
        proof: Vec<u8>,
    ) -> Self {
        Self {
            chain_id: chain_id.clone(),
            address,
            balance,
            ownership: OwnershipWitnessInput::EthereumEoaSignatureHex { signature_hex },
            chain_balance_proof: ChainBalanceProofInput::EthereumVerkleProof {
                chain_id,
                tree_key,
                basic_data,
                proof,
            },
            ownership_artifact: ExternalProofArtifact {
                scheme: "sp1-native-ownership".to_string(),
                payload_hex: String::new(),
            },
            chain_balance_artifact: ExternalProofArtifact {
                scheme: "sp1-native-chain-balance".to_string(),
                payload_hex: String::new(),
            },
        }
    }

    pub fn ethereum_merkle(
        chain_id: String,
        address: String,
        balance: i128,
        signature_hex: String,
        leaf_index: u64,
        siblings: Vec<[u8; 32]>,
    ) -> Self {
        Self {
            chain_id: chain_id.clone(),
            address,
            balance,
            ownership: OwnershipWitnessInput::EthereumEoaSignatureHex { signature_hex },
            chain_balance_proof: ChainBalanceProofInput::BinaryMerkleV1 {
                chain_id,
                leaf_index,
                siblings,
            },
            ownership_artifact: ExternalProofArtifact {
                scheme: "sp1-native-ownership".to_string(),
                payload_hex: String::new(),
            },
            chain_balance_artifact: ExternalProofArtifact {
                scheme: "sp1-native-chain-balance".to_string(),
                payload_hex: String::new(),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KzgInsertProof {
    pub scheme: String,
    pub chain_id: String,
    pub old_state_root: String,
    pub new_state_root: String,
    pub old_accumulator_hex: String,
    pub new_accumulator_hex: String,
    pub old_balance_commitment_hex: String,
    pub new_balance_commitment_hex: String,
    pub reserve_count_before: usize,
    pub reserve_count_after: usize,
    pub c_u_hex: String,
    pub c_y_hex: String,
    pub c_balance_hex: String,
    pub d_hex: String,
    pub strong_zkopen_proof_hex: String,
    pub nonzero_proof_hex: String,
    pub transcript_hex: String,
    pub sp1_proof_hex: String,
    pub sp1_vk_hex: String,
    pub sp1_public_values_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KzgInsertResult {
    pub next_state: StoredState,
    pub proof: KzgInsertProof,
}

pub fn apply_insert(
    srs: &Srs,
    state: &StoredState,
    witness: &KzgInsertWitness,
) -> Result<KzgInsertResult, String> {
    if matches!(
        &witness.ownership,
        OwnershipWitnessInput::MockPrivateKey { .. }
    ) && matches!(
        &witness.chain_balance_proof,
        ChainBalanceProofInput::Mock { .. }
    ) {
        apply_insert_with_adapter(srs, state, witness, &MockExternalProofAdapter)
    } else {
        apply_insert_with_adapter(srs, state, witness, &Sp1NativeProofAdapter)
    }
}

pub fn apply_insert_with_adapter(
    srs: &Srs,
    state: &StoredState,
    witness: &KzgInsertWitness,
    external: &impl ExternalProofAdapter,
) -> Result<KzgInsertResult, String> {
    let total_timer = common::profiling::PhaseTimer::start("insert-host", "total");
    let validation_timer =
        common::profiling::PhaseTimer::start("insert-host", "input_and_external_validation");
    validate_insert_inputs(srs, state, witness)?;
    // These adapter calls validate the selected backend labels. The actual
    // ownership and chain witnesses stay private and are verified by SP1.
    external.verify_insert_ownership(
        &state.state_root,
        &witness.address,
        &witness.ownership_artifact,
    )?;
    external.verify_insert_balance(
        &state.state_root,
        &witness.address,
        witness.balance,
        &witness.chain_balance_artifact,
    )?;
    validation_timer.finish();

    let algebra_timer = common::profiling::PhaseTimer::start("insert-host", "hidden_point_algebra");
    let old_p = Polynomial::from_coeffs(state.masked_polynomial_coeffs.clone());
    if old_p.degree() != state.reserve_addresses.len() {
        return Err(
            "stored accumulator polynomial degree does not match reserve count".to_string(),
        );
    }
    let u = encode_address(&witness.address)?;
    let insertion_index = encoded_address_insertion_index(&state.reserve_addresses, u)?;
    let y = old_p.evaluate(u);
    if y.is_zero() {
        return Err("inserted address is already a root of the accumulator polynomial".to_string());
    }
    let nu = y
        .inverse()
        .ok_or_else(|| "non-zero insertion evaluation unexpectedly lacked inverse".to_string())?;
    let mut rng = rand::rngs::OsRng;
    let beta = sample_nonzero_scalar(&mut rng);
    let beta_inv = beta
        .inverse()
        .ok_or_else(|| "non-zero insertion rerandomizer unexpectedly lacked inverse".to_string())?;
    let mu = beta * u;

    let rho_u = Fr::rand(&mut rng);
    let rho_beta = Fr::rand(&mut rng);
    let rho_mu = Fr::rand(&mut rng);
    let rho_y = Fr::rand(&mut rng);
    let rho_nu = Fr::rand(&mut rng);
    let c_u = eval_commit(u, rho_u);
    let c_y = eval_commit(y, rho_y);

    let q_poly = old_p.quotient_at(u, y)?;
    if q_poly.coeffs.len() != state.reserve_addresses.len() {
        return Err("hidden insert quotient must have exactly n coefficients".to_string());
    }
    let w_tilde = commit_g1(srs, &q_poly)?.mul_bigint(beta_inv.into_bigint());
    let d = G2Projective::from(srs.tau_g2_powers[1]).mul_bigint(beta.into_bigint())
        - G2Projective::generator().mul_bigint(mu.into_bigint());
    if d.is_zero() {
        return Err("hidden insertion point collided with the KZG trapdoor".to_string());
    }

    let new_p = old_p.mul_linear_scaled(u, beta);
    let old_accumulator = point_g1_from_hex(&state.accumulator_hex)?;
    let new_accumulator = commit_g1(srs, &new_p)?;
    let r_balance = Fr::rand(&mut rng);
    let c_balance = commit_balance(witness.balance, r_balance);
    let old_balance_commitment = point_g1_from_hex(&state.balance_commitment_hex)?;
    let new_balance_commitment = old_balance_commitment + c_balance;
    let next_balance_total = state
        .balance_total
        .checked_add(witness.balance)
        .ok_or_else(|| "inserted balance total overflow".to_string())?;
    let next_reserve_count = state.reserve_addresses.len() + 1;
    algebra_timer.finish();

    let old_accumulator_hex = point_g1_to_hex(&old_accumulator)?;
    let new_accumulator_hex = point_g1_to_hex(&new_accumulator)?;
    let old_balance_commitment_hex = state.balance_commitment_hex.clone();
    let new_balance_commitment_hex = point_g1_to_hex(&new_balance_commitment)?;
    let c_u_hex = point_g1_to_hex(&c_u)?;
    let c_y_hex = point_g1_to_hex(&c_y)?;
    let c_balance_hex = point_g1_to_hex(&c_balance)?;
    let d_hex = point_g2_to_hex(&d)?;

    let statement = StrongZkOpenStatement {
        commitment: old_accumulator,
        c_u,
        c_y,
        d,
    };
    let insertion_context = build_insertion_context(
        &witness.chain_id,
        &state.state_root,
        &old_accumulator_hex,
        &new_accumulator_hex,
        &old_balance_commitment_hex,
        &new_balance_commitment_hex,
        state.reserve_addresses.len(),
        next_reserve_count,
        &c_balance_hex,
    );
    let sigma_timer = common::profiling::PhaseTimer::start("insert-host", "strong_zkopen");
    let strong_zkopen_proof_hex = prove_strong_zkopen(
        srs,
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
        &insertion_context,
    )?;
    sigma_timer.finish();
    let nonzero_timer = common::profiling::PhaseTimer::start("insert-host", "committed_nonzero");
    let nonzero_proof_hex = prove_com_nonzero(
        &c_y,
        &ComNonZeroWitness {
            y,
            rho_y,
            nu,
            rho_nu,
            delta: -y * rho_nu,
        },
        &insertion_context,
    )?;
    nonzero_timer.finish();
    verify_digest_transition(&old_accumulator, &new_accumulator, &d)?;

    let stdin_timer =
        common::profiling::PhaseTimer::start("insert-host", "committed_input_sp1_stdin");
    let (eval_value_base, eval_blind_base) = eval_generators();
    let (balance_value_base, balance_blind_base) = balance_generators();
    let sp1_stdin = sp1_host::kzg_insert::build_stdin(
        &witness.chain_id,
        &state.state_root,
        &witness.address,
        witness.balance,
        &witness.ownership,
        &witness.chain_balance_proof,
        u,
        rho_u,
        r_balance,
        eval_value_base,
        eval_blind_base,
        balance_value_base,
        balance_blind_base,
        &c_u,
        &c_balance,
    )?;
    stdin_timer.finish();

    let sp1_timer = common::profiling::PhaseTimer::start("insert-host", "ownership_merkle_sp1");
    let (sp1_proof_hex, sp1_vk_hex, sp1_public_values_hex, sp1_public) =
        sp1_host::kzg_insert::prove(sp1_stdin)?;
    sp1_timer.finish();
    if sp1_public.chain_id != witness.chain_id
        || sp1_public.state_root != state.state_root
        || !sp1_host::kzg_insert::point_matches(&sp1_public.c_u, &c_u)
        || !sp1_host::kzg_insert::point_matches(&sp1_public.c_balance, &c_balance)
    {
        return Err("SP1 hidden insert public values do not bind C_u and C_B".to_string());
    }

    let transcript_hex = build_transcript_hex(
        &witness.chain_id,
        &state.state_root,
        &old_accumulator_hex,
        &new_accumulator_hex,
        &old_balance_commitment_hex,
        &new_balance_commitment_hex,
        state.reserve_addresses.len(),
        next_reserve_count,
        &c_u_hex,
        &c_y_hex,
        &c_balance_hex,
        &d_hex,
        &strong_zkopen_proof_hex,
        &nonzero_proof_hex,
        &sp1_public_values_hex,
    );

    let assembly_timer =
        common::profiling::PhaseTimer::start("insert-host", "proof_and_state_assembly");
    let mut reserve_addresses = Vec::with_capacity(next_reserve_count);
    reserve_addresses.extend_from_slice(&state.reserve_addresses[..insertion_index]);
    reserve_addresses.push(witness.address.clone());
    reserve_addresses.extend_from_slice(&state.reserve_addresses[insertion_index..]);
    let mut reserve_balances = Vec::with_capacity(next_reserve_count);
    reserve_balances.extend_from_slice(&state.reserve_balances[..insertion_index]);
    reserve_balances.push(witness.balance);
    reserve_balances.extend_from_slice(&state.reserve_balances[insertion_index..]);
    let next_state = StoredState {
        state_root: state.state_root.clone(),
        srs_max_degree: state.srs_max_degree,
        alpha: state.alpha * beta,
        reserve_addresses,
        reserve_balances,
        masked_polynomial_coeffs: new_p.coeffs,
        accumulator_hex: new_accumulator_hex.clone(),
        balance_total: next_balance_total,
        balance_blind: state.balance_blind + r_balance,
        balance_commitment_hex: new_balance_commitment_hex.clone(),
    };
    let proof = KzgInsertProof {
        scheme: INSERT_SCHEME.to_string(),
        chain_id: witness.chain_id.clone(),
        old_state_root: state.state_root.clone(),
        new_state_root: state.state_root.clone(),
        old_accumulator_hex,
        new_accumulator_hex,
        old_balance_commitment_hex,
        new_balance_commitment_hex,
        reserve_count_before: state.reserve_addresses.len(),
        reserve_count_after: next_reserve_count,
        c_u_hex,
        c_y_hex,
        c_balance_hex,
        d_hex,
        strong_zkopen_proof_hex,
        nonzero_proof_hex,
        transcript_hex,
        sp1_proof_hex,
        sp1_vk_hex,
        sp1_public_values_hex,
    };
    assembly_timer.finish();
    total_timer.finish();
    Ok(KzgInsertResult { next_state, proof })
}

#[deprecated(note = "use verify_insert_with_srs_and_policy")]
pub fn verify_insert(
    old_state: &PublicState,
    new_state: &PublicState,
    proof: &KzgInsertProof,
) -> Result<(), String> {
    verify_insert_state(old_state, new_state, proof)?;
    Err("production insert verifier requires SRS; use verify_insert_with_srs".to_string())
}

#[deprecated(note = "use verify_insert_with_srs_and_policy")]
pub fn verify_insert_with_srs(
    _srs: &Srs,
    _old_state: &PublicState,
    _new_state: &PublicState,
    _proof: &KzgInsertProof,
) -> Result<(), String> {
    Err("production insert verification requires ChainPolicy; use verify_insert_with_srs_and_policy"
        .to_string())
}

pub fn verify_insert_with_srs_and_policy(
    srs: &Srs,
    old_state: &PublicState,
    new_state: &PublicState,
    proof: &KzgInsertProof,
    policy: &ChainPolicy,
) -> Result<(), String> {
    if !policy.allow_mock_proofs {
        srs.require_external_ceremony()?;
    }
    policy.check_chain_id(&proof.chain_id)?;
    policy.check_last_accepted(old_state)?;
    policy.check_finalized(&old_state.state_root)?;
    verify_insert_state(old_state, new_state, proof)?;
    if old_state.srs_max_degree != srs.max_degree || new_state.srs_max_degree != srs.max_degree {
        return Err("insert state SRS degree does not match provided SRS".to_string());
    }
    if proof.reserve_count_before == 0
        || proof.reserve_count_before >= srs.max_degree
        || proof.reserve_count_after > srs.max_degree
    {
        return Err("insert reserve count is outside the SRS-supported range".to_string());
    }
    if proof.scheme != INSERT_SCHEME {
        return Err("insert proof does not use StrongZKOpen".to_string());
    }

    let old_digest = point_g1_from_hex(&proof.old_accumulator_hex)?;
    let new_digest = point_g1_from_hex(&proof.new_accumulator_hex)?;
    let c_u = point_g1_from_hex(&proof.c_u_hex)?;
    let c_y = point_g1_from_hex(&proof.c_y_hex)?;
    let c_balance = point_g1_from_hex(&proof.c_balance_hex)?;
    let d = point_g2_from_hex(&proof.d_hex)?;
    let old_balance = point_g1_from_hex(&proof.old_balance_commitment_hex)?;
    let new_balance = point_g1_from_hex(&proof.new_balance_commitment_hex)?;
    if new_balance != old_balance + c_balance {
        return Err("hidden insert aggregate commitment transition failed".to_string());
    }

    let statement = StrongZkOpenStatement {
        commitment: old_digest,
        c_u,
        c_y,
        d,
    };
    let insertion_context = build_insertion_context(
        &proof.chain_id,
        &proof.old_state_root,
        &proof.old_accumulator_hex,
        &proof.new_accumulator_hex,
        &proof.old_balance_commitment_hex,
        &proof.new_balance_commitment_hex,
        proof.reserve_count_before,
        proof.reserve_count_after,
        &proof.c_balance_hex,
    );
    verify_strong_zkopen(
        srs,
        &statement,
        &proof.strong_zkopen_proof_hex,
        &insertion_context,
    )?;
    verify_com_nonzero(&statement.c_y, &proof.nonzero_proof_hex, &insertion_context)?;
    verify_digest_transition(&old_digest, &new_digest, &d)?;

    let sp1_public = sp1_host::kzg_insert::verify(
        &proof.sp1_proof_hex,
        &proof.sp1_vk_hex,
        &proof.sp1_public_values_hex,
    )?;
    if !policy.allow_mock_proofs && sp1_public.uses_mock_inputs {
        return Err(
            "production insert proof used mock ownership or chain-balance inputs".to_string(),
        );
    }
    if sp1_public.chain_id != proof.chain_id
        || sp1_public.state_root != proof.old_state_root
        || sp1_public.commitment_params_digest_hex != canonical_commitment_params_digest()
        || !sp1_host::kzg_insert::point_matches(&sp1_public.c_u, &statement.c_u)
        || !sp1_host::kzg_insert::point_matches(&sp1_public.c_balance, &c_balance)
    {
        return Err("SP1 hidden insert public statement mismatch".to_string());
    }

    let expected_transcript = build_transcript_hex(
        &proof.chain_id,
        &proof.old_state_root,
        &proof.old_accumulator_hex,
        &proof.new_accumulator_hex,
        &proof.old_balance_commitment_hex,
        &proof.new_balance_commitment_hex,
        proof.reserve_count_before,
        proof.reserve_count_after,
        &proof.c_u_hex,
        &proof.c_y_hex,
        &proof.c_balance_hex,
        &proof.d_hex,
        &proof.strong_zkopen_proof_hex,
        &proof.nonzero_proof_hex,
        &proof.sp1_public_values_hex,
    );
    if proof.transcript_hex != expected_transcript {
        return Err("hidden insert transcript mismatch".to_string());
    }
    Ok(())
}

#[deprecated(note = "metadata-only verification is not a proof verifier")]
pub fn verify_insert_debug(
    old_state: &PublicState,
    new_state: &PublicState,
    proof: &KzgInsertProof,
) -> Result<(), String> {
    let _ = (old_state, new_state, proof);
    Err("verify_insert_debug is disabled; use the production verifier".to_string())
}

pub fn check_insert_metadata_debug(
    old_state: &PublicState,
    new_state: &PublicState,
    proof: &KzgInsertProof,
) -> Result<(), String> {
    verify_insert_state(old_state, new_state, proof)?;
    let _ = point_g1_from_hex(&proof.c_u_hex)?;
    let _ = point_g1_from_hex(&proof.c_y_hex)?;
    let _ = point_g1_from_hex(&proof.c_balance_hex)?;
    let _ = point_g2_from_hex(&proof.d_hex)?;
    let expected = build_transcript_hex(
        &proof.chain_id,
        &proof.old_state_root,
        &proof.old_accumulator_hex,
        &proof.new_accumulator_hex,
        &proof.old_balance_commitment_hex,
        &proof.new_balance_commitment_hex,
        proof.reserve_count_before,
        proof.reserve_count_after,
        &proof.c_u_hex,
        &proof.c_y_hex,
        &proof.c_balance_hex,
        &proof.d_hex,
        &proof.strong_zkopen_proof_hex,
        &proof.nonzero_proof_hex,
        &proof.sp1_public_values_hex,
    );
    if proof.transcript_hex != expected {
        return Err("hidden insert transcript mismatch".to_string());
    }
    Ok(())
}

fn validate_insert_inputs(
    srs: &Srs,
    state: &StoredState,
    witness: &KzgInsertWitness,
) -> Result<(), String> {
    if state.srs_max_degree != srs.max_degree {
        return Err("state SRS degree does not match provided SRS".to_string());
    }
    if srs.tau_g1_powers.len() < 2 || srs.tau_g2_powers.len() < 2 {
        return Err("hidden insert requires tau^0 and tau^1 in both SRS groups".to_string());
    }
    if state.reserve_addresses.is_empty() || state.reserve_addresses.len() >= srs.max_degree {
        return Err("insert would exceed the KZG SRS degree bound".to_string());
    }
    if state.reserve_addresses.len() != state.reserve_balances.len() {
        return Err(
            "stored reserve address and balance vectors have different lengths".to_string(),
        );
    }
    if witness.balance < 0 {
        return Err("inserted balance must be non-negative".to_string());
    }
    if state.alpha.is_zero() {
        return Err("stored accumulator mask must be non-zero".to_string());
    }
    validate_insert_chain_id(witness)
}

fn validate_insert_chain_id(witness: &KzgInsertWitness) -> Result<(), String> {
    let proof_chain_id = match &witness.chain_balance_proof {
        ChainBalanceProofInput::Mock { .. } => "mock-chain",
        ChainBalanceProofInput::EthereumAccountProof { chain_id, .. }
        | ChainBalanceProofInput::GenericMerkleProof { chain_id, .. }
        | ChainBalanceProofInput::BinaryMerkleV1 { chain_id, .. }
        | ChainBalanceProofInput::EthereumVerkleBatchMember { chain_id, .. }
        | ChainBalanceProofInput::EthereumVerkleProof { chain_id, .. } => chain_id,
    };
    if proof_chain_id != witness.chain_id {
        return Err(format!(
            "insert chain proof chain_id mismatch: expected {}, got {}",
            witness.chain_id, proof_chain_id
        ));
    }
    Ok(())
}

fn verify_insert_state(
    old_state: &PublicState,
    new_state: &PublicState,
    proof: &KzgInsertProof,
) -> Result<(), String> {
    if old_state.state_root != new_state.state_root {
        return Err("insert must not advance the external chain state root".to_string());
    }
    if proof.old_state_root != old_state.state_root || proof.new_state_root != new_state.state_root
    {
        return Err("insert proof state root mismatch".to_string());
    }
    if proof.old_accumulator_hex != old_state.accumulator_hex
        || proof.new_accumulator_hex != new_state.accumulator_hex
    {
        return Err("insert accumulator state mismatch".to_string());
    }
    if proof.old_balance_commitment_hex != old_state.balance_commitment_hex
        || proof.new_balance_commitment_hex != new_state.balance_commitment_hex
    {
        return Err("insert balance commitment state mismatch".to_string());
    }
    let expected_after = proof
        .reserve_count_before
        .checked_add(1)
        .ok_or_else(|| "insert reserve count overflow".to_string())?;
    if proof.reserve_count_before != old_state.reserve_count
        || proof.reserve_count_after != new_state.reserve_count
        || proof.reserve_count_after != expected_after
    {
        return Err("insert reserve count mismatch".to_string());
    }
    Ok(())
}

fn sample_nonzero_scalar(rng: &mut rand::rngs::OsRng) -> Fr {
    loop {
        let value = Fr::rand(rng);
        if !value.is_zero() {
            return value;
        }
    }
}

fn encoded_address_insertion_index(addresses: &[String], target: Fr) -> Result<usize, String> {
    let target = target.into_bigint();
    let mut left = 0usize;
    let mut right = addresses.len();
    while left < right {
        let middle = left + (right - left) / 2;
        let candidate = encode_address(&addresses[middle])?.into_bigint();
        match candidate.cmp(&target) {
            std::cmp::Ordering::Less => left = middle + 1,
            std::cmp::Ordering::Greater => right = middle,
            std::cmp::Ordering::Equal => {
                return Err("inserted address already exists in reserve set".to_string());
            }
        }
    }
    Ok(left)
}

#[allow(clippy::too_many_arguments)]
fn build_insertion_context(
    chain_id: &str,
    state_root: &str,
    old_accumulator_hex: &str,
    new_accumulator_hex: &str,
    old_balance_commitment_hex: &str,
    new_balance_commitment_hex: &str,
    reserve_count_before: usize,
    reserve_count_after: usize,
    c_balance_hex: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    for field in [
        chain_id.as_bytes(),
        state_root.as_bytes(),
        old_accumulator_hex.as_bytes(),
        new_accumulator_hex.as_bytes(),
        old_balance_commitment_hex.as_bytes(),
        new_balance_commitment_hex.as_bytes(),
        &(reserve_count_before as u64).to_le_bytes(),
        &(reserve_count_after as u64).to_le_bytes(),
        c_balance_hex.as_bytes(),
    ] {
        out.extend_from_slice(&(field.len() as u64).to_le_bytes());
        out.extend_from_slice(field);
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn build_transcript_hex(
    chain_id: &str,
    state_root: &str,
    old_accumulator_hex: &str,
    new_accumulator_hex: &str,
    old_balance_commitment_hex: &str,
    new_balance_commitment_hex: &str,
    reserve_count_before: usize,
    reserve_count_after: usize,
    c_u_hex: &str,
    c_y_hex: &str,
    c_balance_hex: &str,
    d_hex: &str,
    strong_zkopen_proof_hex: &str,
    nonzero_proof_hex: &str,
    sp1_public_values_hex: &str,
) -> String {
    let before = reserve_count_before.to_string();
    let after = reserve_count_after.to_string();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"dynamic-poa-strong-zkopen-insert-transcript-v1");
    for field in [
        chain_id,
        state_root,
        old_accumulator_hex,
        new_accumulator_hex,
        old_balance_commitment_hex,
        new_balance_commitment_hex,
        &before,
        &after,
        c_u_hex,
        c_y_hex,
        c_balance_hex,
        d_hex,
        strong_zkopen_proof_hex,
        nonzero_proof_hex,
        sp1_public_values_hex,
    ] {
        hasher.update(&(field.len() as u64).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    common::crypto::hex_encode(hasher.finalize().as_bytes())
}

fn canonical_commitment_params_digest() -> &'static str {
    static DIGEST: OnceLock<String> = OnceLock::new();
    DIGEST.get_or_init(|| {
        let (eval_value, eval_blind) = eval_generators();
        let (balance_value, balance_blind) = balance_generators();
        sp1_host::kzg_insert::commitment_params_digest(
            eval_value,
            eval_blind,
            balance_value,
            balance_blind,
        )
    })
}
