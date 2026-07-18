use ark_bls12_381::Fr;
use ark_ff::{BigInteger, Field, PrimeField, UniformRand, Zero};
use std::sync::OnceLock;

use common::crypto::{hex_decode, point_g1_from_hex, point_g1_to_hex, scalar_to_hex};
use common::encoding::encode_address;
use common::types::{ChainBalanceProofInput, OwnershipWitnessInput, PublicState, StoredState};

use crate::bp::{prove_insert_relation_logic, verify_insert_relation_logic};
use crate::commitment::{balance_generators, commit_balance, eval_generators};
use crate::external::{
    ExternalProofAdapter, ExternalProofArtifact, MockExternalProofAdapter, Sp1NativeProofAdapter,
};
use crate::kzg::{commit_g1, Srs};
use crate::polynomial::Polynomial;
use crate::threshold::{
    prove_threshold, verify_threshold_encoded, ThresholdStatement, ThresholdWitness,
    THRESHOLD_PROOF_SCHEME,
};
use crate::verifier::ChainPolicy;
use crate::zkopen::{eval_commit, prove_committed_opening, verify_committed_opening};
use rand::RngCore;

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
    pub quotient_commitment_hex: String,
    pub c_x_hex: String,
    pub c_beta_hex: String,
    pub c_y_x_hex: String,
    pub c_y_hex: String,
    pub c_y_prime_hex: String,
    pub c_q_hex: String,
    pub zeta: Fr,
    pub old_eval_opening_proof_hex: String,
    pub new_eval_opening_proof_hex: String,
    pub balance_range_proof_hex: String,
    pub relation_bp_proof_hex: String,
    pub relation_bp_commitments_hex: String,
    pub relation_link_proof_hex: String,
    pub ownership_artifact_digest_hex: String,
    pub chain_balance_artifact_digest_hex: String,
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
    if state.srs_max_degree != srs.max_degree {
        return Err("state SRS degree does not match provided SRS".to_string());
    }
    if state.reserve_addresses.len() >= srs.max_degree {
        return Err("insert would exceed the KZG SRS degree bound".to_string());
    }
    if state.reserve_addresses.len() != state.reserve_balances.len() {
        return Err(
            "stored reserve address and balance vectors have different lengths".to_string(),
        );
    }
    let next_reserve_count = state
        .reserve_addresses
        .len()
        .checked_add(1)
        .ok_or_else(|| "insert reserve count overflow".to_string())?;
    if witness.balance < 0 {
        return Err("inserted balance must be non-negative".to_string());
    }
    validate_insert_chain_id(witness)?;
    let ownership_artifact = external.verify_insert_ownership(
        &state.state_root,
        &witness.address,
        &witness.ownership_artifact,
    )?;
    let chain_balance_artifact = external.verify_insert_balance(
        &state.state_root,
        &witness.address,
        witness.balance,
        &witness.chain_balance_artifact,
    )?;

    let old_p = Polynomial::from_coeffs(state.masked_polynomial_coeffs.clone());
    if old_p.degree() != state.reserve_addresses.len() {
        return Err(
            "stored accumulator polynomial degree does not match reserve count".to_string(),
        );
    }
    let x = encode_address(&witness.address)?;
    if state.alpha.is_zero() {
        return Err("stored accumulator mask must be non-zero".to_string());
    }
    let insertion_index = encoded_address_insertion_index(&state.reserve_addresses, x)?;
    let y_x = old_p.evaluate(x);
    if y_x.is_zero() {
        return Err("inserted address is already a root of the accumulator polynomial".to_string());
    }
    let z_x = y_x
        .inverse()
        .ok_or_else(|| "non-zero y_x unexpectedly lacked inverse".to_string())?;

    let mut rng = rand::rngs::OsRng;
    let mut beta = Fr::rand(&mut rng);
    while beta.is_zero() {
        beta = Fr::rand(&mut rng);
    }
    let z_beta = beta
        .inverse()
        .ok_or_else(|| "non-zero beta unexpectedly lacked inverse".to_string())?;
    let r_x = Fr::rand(&mut rng);
    let r_beta = Fr::rand(&mut rng);
    let r_y_x = Fr::rand(&mut rng);

    let c_x = eval_commit(x, r_x);
    let c_beta = eval_commit(beta, r_beta);
    let c_y_x = eval_commit(y_x, r_y_x);

    let new_p = old_p.mul_linear_scaled(x, beta);
    let new_accumulator = commit_g1(srs, &new_p)?;
    let old_accumulator = point_g1_from_hex(&state.accumulator_hex)?;

    let r_ins = Fr::rand(&mut rng);
    let old_balance_commitment = point_g1_from_hex(&state.balance_commitment_hex)?;
    let c_insert_balance = commit_balance(witness.balance, r_ins);
    let new_balance_commitment = old_balance_commitment + c_insert_balance;
    let next_balance_total = state
        .balance_total
        .checked_add(witness.balance)
        .ok_or_else(|| "inserted balance total overflow".to_string())?;

    let q_poly = old_p.quotient_at(x, y_x)?;
    if q_poly.coeffs.len() != state.reserve_addresses.len() {
        return Err("insert quotient must have exactly n coefficients".to_string());
    }
    let mut quotient_salt = [0u8; 32];
    rng.fill_bytes(&mut quotient_salt);
    let quotient_commitment =
        sp1_host::kzg_insert::quotient_commitment(&q_poly.coeffs, &quotient_salt);

    let old_accumulator_hex = point_g1_to_hex(&old_accumulator)?;
    let new_accumulator_hex = point_g1_to_hex(&new_accumulator)?;
    let old_balance_commitment_hex = state.balance_commitment_hex.clone();
    let new_balance_commitment_hex = point_g1_to_hex(&new_balance_commitment)?;
    let quotient_commitment_hex = common::crypto::hex_encode(&quotient_commitment);
    let c_x_hex = point_g1_to_hex(&c_x)?;
    let c_beta_hex = point_g1_to_hex(&c_beta)?;
    let c_y_x_hex = point_g1_to_hex(&c_y_x)?;

    let zeta = derive_zeta(
        &witness.chain_id,
        &state.state_root,
        &old_accumulator_hex,
        &new_accumulator_hex,
        &quotient_commitment,
        &new_balance_commitment_hex,
        state.reserve_addresses.len(),
        &c_x_hex,
        &c_beta_hex,
        &c_y_x_hex,
    );
    let y = old_p.evaluate(zeta);
    let y_prime = new_p.evaluate(zeta);
    let q_zeta = q_poly.evaluate(zeta);
    let r_y = Fr::rand(&mut rng);
    let r_y_prime = Fr::rand(&mut rng);
    let r_q = Fr::rand(&mut rng);
    let c_y = eval_commit(y, r_y);
    let c_y_prime = eval_commit(y_prime, r_y_prime);
    let c_q = eval_commit(q_zeta, r_q);

    let c_y_hex = point_g1_to_hex(&c_y)?;
    let c_y_prime_hex = point_g1_to_hex(&c_y_prime)?;
    let c_q_hex = point_g1_to_hex(&c_q)?;
    let old_opening_poly = old_p.quotient_at(zeta, y)?;
    let new_opening_poly = new_p.quotient_at(zeta, y_prime)?;
    let old_eval_opening = commit_g1(srs, &old_opening_poly)?;
    let new_eval_opening = commit_g1(srs, &new_opening_poly)?;
    let old_eval_opening_proof_hex = prove_committed_opening(
        srs,
        &old_accumulator_hex,
        zeta,
        &c_y_hex,
        y,
        r_y,
        &old_eval_opening,
        "dynamic-poa-insert-old-eval-zkopen",
    )?;
    let new_eval_opening_proof_hex = prove_committed_opening(
        srs,
        &new_accumulator_hex,
        zeta,
        &c_y_prime_hex,
        y_prime,
        r_y_prime,
        &new_eval_opening,
        "dynamic-poa-insert-new-eval-zkopen",
    )?;
    let relation_proof = prove_insert_relation_logic(
        x,
        beta,
        y_x,
        y,
        y_prime,
        q_zeta,
        z_x,
        z_beta,
        witness.balance,
        zeta,
        r_x,
        r_beta,
        r_y_x,
        r_y,
        r_y_prime,
        r_q,
        r_ins,
        &c_x_hex,
        &c_beta_hex,
        &c_y_x_hex,
        &c_y_hex,
        &c_y_prime_hex,
        &c_q_hex,
        &old_balance_commitment_hex,
        &new_balance_commitment_hex,
    )?;
    let next_public_state = PublicState {
        state_root: state.state_root.clone(),
        srs_max_degree: state.srs_max_degree,
        reserve_count: next_reserve_count,
        accumulator_hex: new_accumulator_hex.clone(),
        balance_commitment_hex: new_balance_commitment_hex.clone(),
    };
    let balance_range_proof_hex = prove_threshold(
        &ThresholdStatement {
            public_state: next_public_state,
            threshold: 0,
        },
        &ThresholdWitness {
            asset_total: next_balance_total,
            asset_blind: state.balance_blind + r_ins,
        },
    )?
    .proof_hex;

    let transcript_hex = build_transcript_hex(
        &state.state_root,
        &old_accumulator_hex,
        &new_accumulator_hex,
        &quotient_commitment_hex,
        &new_balance_commitment_hex,
        state.reserve_addresses.len(),
        &c_x_hex,
        &c_beta_hex,
        &c_y_x_hex,
        zeta,
        &c_y_hex,
        &c_y_prime_hex,
        &c_q_hex,
        &ownership_artifact.proof_digest_hex,
        &chain_balance_artifact.proof_digest_hex,
    )?;
    let (eval_value_base, eval_blind_base) = eval_generators();
    let (balance_value_base, balance_blind_base) = balance_generators();
    let sp1_stdin = sp1_host::kzg_insert::build_stdin(
        &witness.chain_id,
        &state.state_root,
        &witness.address,
        witness.balance,
        &witness.ownership,
        &witness.chain_balance_proof,
        x,
        r_x,
        r_ins,
        zeta,
        quotient_salt,
        &q_poly.coeffs,
        quotient_commitment,
        q_zeta,
        r_q,
        eval_value_base,
        eval_blind_base,
        balance_value_base,
        balance_blind_base,
        &c_x,
        &c_q,
        &c_insert_balance,
        &old_accumulator_hex,
        &new_accumulator_hex,
        &old_balance_commitment_hex,
        &new_balance_commitment_hex,
        state.reserve_addresses.len(),
        next_reserve_count,
        &transcript_hex,
    )?;
    let (sp1_proof_hex, sp1_vk_hex, sp1_public_values_hex, sp1_public) =
        sp1_host::kzg_insert::prove(sp1_stdin)?;
    if sp1_public.chain_id != witness.chain_id
        || sp1_public.state_root != state.state_root
        || sp1_public.zeta_le != fr_to_le_bytes(zeta)
        || !sp1_host::kzg_insert::point_matches(&sp1_public.c_x, &c_x)
        || sp1_public.quotient_commitment != quotient_commitment
        || !sp1_host::kzg_insert::point_matches(&sp1_public.c_quotient_eval, &c_q)
        || !sp1_host::kzg_insert::point_matches(&sp1_public.c_balance_delta, &c_insert_balance)
        || sp1_public.transcript_hex != transcript_hex
    {
        return Err("SP1 KZG insert public values do not bind the insertion".to_string());
    }

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
        balance_blind: state.balance_blind + r_ins,
        balance_commitment_hex: new_balance_commitment_hex.clone(),
    };

    let proof = KzgInsertProof {
        scheme: "kzg-nizk-insert-v7-salted-quotient-hash-binary-merkle-bound".to_string(),
        chain_id: witness.chain_id.clone(),
        old_state_root: state.state_root.clone(),
        new_state_root: state.state_root.clone(),
        old_accumulator_hex,
        new_accumulator_hex,
        old_balance_commitment_hex,
        new_balance_commitment_hex,
        reserve_count_before: state.reserve_addresses.len(),
        reserve_count_after: next_reserve_count,
        quotient_commitment_hex,
        c_x_hex,
        c_beta_hex,
        c_y_x_hex,
        c_y_hex,
        c_y_prime_hex,
        c_q_hex,
        zeta,
        old_eval_opening_proof_hex,
        new_eval_opening_proof_hex,
        balance_range_proof_hex,
        relation_bp_proof_hex: relation_proof.bp_proof_hex,
        relation_bp_commitments_hex: relation_proof.bp_commitments_hex,
        relation_link_proof_hex: relation_proof.link_proof_hex,
        ownership_artifact_digest_hex: ownership_artifact.proof_digest_hex,
        chain_balance_artifact_digest_hex: chain_balance_artifact.proof_digest_hex,
        transcript_hex,
        sp1_proof_hex,
        sp1_vk_hex,
        sp1_public_values_hex,
    };

    Ok(KzgInsertResult { next_state, proof })
}

fn validate_insert_chain_id(witness: &KzgInsertWitness) -> Result<(), String> {
    let actual = match &witness.chain_balance_proof {
        ChainBalanceProofInput::Mock { .. } => return Ok(()),
        ChainBalanceProofInput::EthereumAccountProof { chain_id, .. }
        | ChainBalanceProofInput::GenericMerkleProof { chain_id, .. }
        | ChainBalanceProofInput::BinaryMerkleV1 { chain_id, .. }
        | ChainBalanceProofInput::EthereumVerkleBatchMember { chain_id, .. }
        | ChainBalanceProofInput::EthereumVerkleProof { chain_id, .. } => chain_id,
    };
    if actual != &witness.chain_id {
        return Err(format!(
            "insert chain proof chain_id mismatch: expected {}, got {}",
            witness.chain_id, actual
        ));
    }
    Ok(())
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
    srs: &Srs,
    old_state: &PublicState,
    new_state: &PublicState,
    proof: &KzgInsertProof,
) -> Result<(), String> {
    let _ = (srs, old_state, new_state, proof);
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
    if proof.scheme != "kzg-nizk-insert-v7-salted-quotient-hash-binary-merkle-bound" {
        return Err("insert proof is not a production ZK proof".to_string());
    }
    let quotient_commitment = parse_quotient_commitment(&proof.quotient_commitment_hex)?;
    let expected_zeta = derive_zeta(
        &proof.chain_id,
        &proof.old_state_root,
        &proof.old_accumulator_hex,
        &proof.new_accumulator_hex,
        &quotient_commitment,
        &proof.new_balance_commitment_hex,
        proof.reserve_count_before,
        &proof.c_x_hex,
        &proof.c_beta_hex,
        &proof.c_y_x_hex,
    );
    if proof.zeta != expected_zeta {
        return Err("insert Fiat-Shamir challenge mismatch".to_string());
    }
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
    let old_balance = point_g1_from_hex(&proof.old_balance_commitment_hex)?;
    let new_balance = point_g1_from_hex(&proof.new_balance_commitment_hex)?;
    let c_balance_delta = new_balance - old_balance;
    let c_x = point_g1_from_hex(&proof.c_x_hex)?;
    let c_q = point_g1_from_hex(&proof.c_q_hex)?;
    let expected_params_digest = canonical_commitment_params_digest();
    if sp1_public.chain_id != proof.chain_id
        || sp1_public.state_root != proof.old_state_root
        || sp1_public.zeta_le != fr_to_le_bytes(proof.zeta)
        || sp1_public.commitment_params_digest_hex != expected_params_digest
        || !sp1_host::kzg_insert::point_matches(&sp1_public.c_x, &c_x)
        || sp1_public.quotient_commitment != quotient_commitment
        || !sp1_host::kzg_insert::point_matches(&sp1_public.c_quotient_eval, &c_q)
        || !sp1_host::kzg_insert::point_matches(&sp1_public.c_balance_delta, &c_balance_delta)
        || sp1_public.old_accumulator_hex != proof.old_accumulator_hex
        || sp1_public.new_accumulator_hex != proof.new_accumulator_hex
        || sp1_public.old_balance_commitment_hex != proof.old_balance_commitment_hex
        || sp1_public.new_balance_commitment_hex != proof.new_balance_commitment_hex
        || sp1_public.reserve_count_before != proof.reserve_count_before
        || sp1_public.reserve_count_after != proof.reserve_count_after
        || sp1_public.transcript_hex != proof.transcript_hex
    {
        return Err("SP1 KZG insert public statement mismatch".to_string());
    }
    verify_threshold_encoded(
        &ThresholdStatement {
            public_state: new_state.clone(),
            threshold: 0,
        },
        THRESHOLD_PROOF_SCHEME,
        &proof.balance_range_proof_hex,
    )
    .map_err(|err| format!("inserted aggregate balance range proof failed: {err}"))?;
    verify_committed_opening(
        srs,
        &proof.old_accumulator_hex,
        proof.zeta,
        &proof.c_y_hex,
        &proof.old_eval_opening_proof_hex,
        "dynamic-poa-insert-old-eval-zkopen",
    )?;
    verify_committed_opening(
        srs,
        &proof.new_accumulator_hex,
        proof.zeta,
        &proof.c_y_prime_hex,
        &proof.new_eval_opening_proof_hex,
        "dynamic-poa-insert-new-eval-zkopen",
    )?;
    verify_insert_relation_logic(
        proof.zeta,
        &proof.c_x_hex,
        &proof.c_beta_hex,
        &proof.c_y_x_hex,
        &proof.c_y_hex,
        &proof.c_y_prime_hex,
        &proof.c_q_hex,
        &proof.old_balance_commitment_hex,
        &proof.new_balance_commitment_hex,
        &proof.relation_bp_proof_hex,
        &proof.relation_bp_commitments_hex,
        &proof.relation_link_proof_hex,
    )?;
    let expected_transcript = build_transcript_hex(
        &proof.old_state_root,
        &proof.old_accumulator_hex,
        &proof.new_accumulator_hex,
        &proof.quotient_commitment_hex,
        &proof.new_balance_commitment_hex,
        proof.reserve_count_before,
        &proof.c_x_hex,
        &proof.c_beta_hex,
        &proof.c_y_x_hex,
        proof.zeta,
        &proof.c_y_hex,
        &proof.c_y_prime_hex,
        &proof.c_q_hex,
        &proof.ownership_artifact_digest_hex,
        &proof.chain_balance_artifact_digest_hex,
    )?;
    if proof.transcript_hex != expected_transcript {
        return Err("insert transcript mismatch".to_string());
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

#[deprecated(note = "metadata-only verification is not a proof verifier")]
pub fn verify_insert_debug(
    old_state: &PublicState,
    new_state: &PublicState,
    proof: &KzgInsertProof,
) -> Result<(), String> {
    let _ = (old_state, new_state, proof);
    Err("verify_insert_debug was metadata-only and is disabled; use check_insert_metadata_debug explicitly or the production verifier".to_string())
}

pub fn check_insert_metadata_debug(
    old_state: &PublicState,
    new_state: &PublicState,
    proof: &KzgInsertProof,
) -> Result<(), String> {
    verify_insert_state(old_state, new_state, proof)?;
    parse_quotient_commitment(&proof.quotient_commitment_hex)?;
    let expected_transcript = build_transcript_hex(
        &proof.old_state_root,
        &proof.old_accumulator_hex,
        &proof.new_accumulator_hex,
        &proof.quotient_commitment_hex,
        &proof.new_balance_commitment_hex,
        proof.reserve_count_before,
        &proof.c_x_hex,
        &proof.c_beta_hex,
        &proof.c_y_x_hex,
        proof.zeta,
        &proof.c_y_hex,
        &proof.c_y_prime_hex,
        &proof.c_q_hex,
        &proof.ownership_artifact_digest_hex,
        &proof.chain_balance_artifact_digest_hex,
    )?;
    if proof.transcript_hex != expected_transcript {
        return Err("insert transcript mismatch".to_string());
    }
    Ok(())
}

fn derive_zeta(
    chain_id: &str,
    state_root: &str,
    old_accumulator_hex: &str,
    new_accumulator_hex: &str,
    quotient_commitment: &[u8; 32],
    new_balance_commitment_hex: &str,
    reserve_count: usize,
    c_x_hex: &str,
    c_beta_hex: &str,
    c_y_x_hex: &str,
) -> Fr {
    derive_nonzero_scalar(
        "insert-zeta-v2-salted-quotient-hash",
        &[
            chain_id.as_bytes(),
            state_root.as_bytes(),
            old_accumulator_hex.as_bytes(),
            new_accumulator_hex.as_bytes(),
            quotient_commitment,
            new_balance_commitment_hex.as_bytes(),
            reserve_count.to_string().as_bytes(),
            c_x_hex.as_bytes(),
            c_beta_hex.as_bytes(),
            c_y_x_hex.as_bytes(),
        ],
    )
}

fn derive_nonzero_scalar(label: &str, chunks: &[&[u8]]) -> Fr {
    let mut hasher = blake3::Hasher::new();
    hasher.update(label.as_bytes());
    for chunk in chunks {
        hasher.update(chunk);
    }
    let mut scalar = Fr::from_le_bytes_mod_order(hasher.finalize().as_bytes());
    if scalar.is_zero() {
        scalar = Fr::from(37u64);
    }
    scalar
}

fn build_transcript_hex(
    state_root: &str,
    old_accumulator_hex: &str,
    new_accumulator_hex: &str,
    quotient_commitment_hex: &str,
    new_balance_commitment_hex: &str,
    reserve_count: usize,
    c_x_hex: &str,
    c_beta_hex: &str,
    c_y_x_hex: &str,
    zeta: Fr,
    c_y_hex: &str,
    c_y_prime_hex: &str,
    c_q_hex: &str,
    ownership_artifact_digest_hex: &str,
    chain_balance_artifact_digest_hex: &str,
) -> Result<String, String> {
    let count = reserve_count.to_string();
    let zeta_hex = scalar_to_hex(&zeta)?;
    let fields = [
        state_root,
        old_accumulator_hex,
        new_accumulator_hex,
        quotient_commitment_hex,
        new_balance_commitment_hex,
        &count,
        c_x_hex,
        c_beta_hex,
        c_y_x_hex,
        &zeta_hex,
        c_y_hex,
        c_y_prime_hex,
        c_q_hex,
        ownership_artifact_digest_hex,
        chain_balance_artifact_digest_hex,
    ];
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"dynamic-poa-insert-transcript-v2-salted-quotient-hash");
    for (index, field) in fields.iter().enumerate() {
        if index != 0 {
            hasher.update(b"|");
        }
        hasher.update(field.as_bytes());
    }
    Ok(common::crypto::hex_encode(hasher.finalize().as_bytes()))
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

fn parse_quotient_commitment(value: &str) -> Result<[u8; 32], String> {
    hex_decode(value)?
        .try_into()
        .map_err(|_| "insert salted quotient commitment must contain 32 bytes".to_string())
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

fn fr_to_le_bytes(value: Fr) -> [u8; 32] {
    let raw = value.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    let len = raw.len().min(32);
    out[..len].copy_from_slice(&raw[..len]);
    out
}
