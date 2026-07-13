use ark_bls12_381::Fr;
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};

use common::crypto::{hash_to_scalar, point_g1_from_hex, point_g1_to_hex, scalar_to_hex};
use common::encoding::encode_address;
use common::types::{ChainBalanceProofInput, OwnershipWitnessInput, PublicState, StoredState};

use crate::bp::{prove_insert_relation_logic, verify_insert_relation_logic};
use crate::commitment::commit_balance;
use crate::commitment::derive_generator;
use crate::external::{ExternalProofAdapter, ExternalProofArtifact, MockExternalProofAdapter};
use crate::hpoly::{
    commit_hiding_polynomial, prove_hiding_committed_opening, verify_hiding_committed_opening,
};
use crate::kzg::{commit_g1, Srs};
use crate::polynomial::Polynomial;
use crate::zkopen::{eval_commit, prove_committed_opening, verify_committed_opening};

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
        ownership_witness: String,
        chain_balance_witness: String,
    ) -> Self {
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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KzgInsertProof {
    pub scheme: String,
    pub old_state_root: String,
    pub new_state_root: String,
    pub old_accumulator_hex: String,
    pub new_accumulator_hex: String,
    pub old_balance_commitment_hex: String,
    pub new_balance_commitment_hex: String,
    pub reserve_count_before: usize,
    pub reserve_count_after: usize,
    pub c_q_h_hex: String,
    pub c_x_hex: String,
    pub c_beta_hex: String,
    pub c_y_x_hex: String,
    pub c_y_hex: String,
    pub c_y_prime_hex: String,
    pub c_q_hex: String,
    pub zeta: Fr,
    pub old_eval_opening_proof_hex: String,
    pub new_eval_opening_proof_hex: String,
    pub quotient_eval_opening_proof_hex: String,
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
    apply_insert_with_adapter(srs, state, witness, &MockExternalProofAdapter)
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
    if state
        .reserve_addresses
        .iter()
        .any(|addr| addr == &witness.address)
    {
        return Err("inserted address already exists in reserve set".to_string());
    }
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
    let x = encode_address(&witness.address)?;
    let y_x = old_p.evaluate(x);
    if y_x.is_zero() {
        return Err("inserted address is already a root of the accumulator polynomial".to_string());
    }
    let z_x = y_x
        .inverse()
        .ok_or_else(|| "non-zero y_x unexpectedly lacked inverse".to_string())?;

    let beta = derive_nonzero_scalar("insert-beta", &[witness.address.as_bytes()]);
    let z_beta = beta
        .inverse()
        .ok_or_else(|| "non-zero beta unexpectedly lacked inverse".to_string())?;
    let r_x = derive_scalar("insert-r-x", &[witness.address.as_bytes()]);
    let r_beta = derive_scalar("insert-r-beta", &[witness.address.as_bytes()]);
    let r_y_x = derive_scalar("insert-r-y-x", &[witness.address.as_bytes()]);

    let c_x = eval_commit(x, r_x);
    let c_beta = eval_commit(beta, r_beta);
    let c_y_x = eval_commit(y_x, r_y_x);

    let linear = Polynomial::from_coeffs(vec![-x, Fr::one()]);
    let new_p = old_p.mul(&linear).mul_scalar(beta);
    let new_accumulator = commit_g1(srs, &new_p)?;
    let old_accumulator = point_g1_from_hex(&state.accumulator_hex)?;
    if old_accumulator != commit_g1(srs, &old_p)? {
        return Err("old state accumulator does not match polynomial witness".to_string());
    }

    let r_ins = derive_scalar("insert-r-ins", &[witness.address.as_bytes()]);
    let old_balance_commitment = point_g1_from_hex(&state.balance_commitment_hex)?;
    let c_insert_balance = commit_balance(witness.balance, r_ins);
    let new_balance_commitment = old_balance_commitment + c_insert_balance;

    let q_poly = old_p.sub(&Polynomial::constant(y_x)).div_exact(&linear)?;
    let quotient_degree_bound = state.reserve_addresses.len().saturating_sub(1);
    let hiding_q = commit_hiding_polynomial(srs, &q_poly, quotient_degree_bound)?;
    let c_q_h = hiding_q.commitment;

    let old_accumulator_hex = point_g1_to_hex(&old_accumulator)?;
    let new_accumulator_hex = point_g1_to_hex(&new_accumulator)?;
    let old_balance_commitment_hex = state.balance_commitment_hex.clone();
    let new_balance_commitment_hex = point_g1_to_hex(&new_balance_commitment)?;
    let c_q_h_hex = point_g1_to_hex(&c_q_h)?;
    let c_x_hex = point_g1_to_hex(&c_x)?;
    let c_beta_hex = point_g1_to_hex(&c_beta)?;
    let c_y_x_hex = point_g1_to_hex(&c_y_x)?;

    let zeta = derive_zeta(
        &state.state_root,
        &old_accumulator_hex,
        &new_accumulator_hex,
        &c_q_h_hex,
        &new_balance_commitment_hex,
        state.reserve_addresses.len(),
        &c_x_hex,
        &c_beta_hex,
        &c_y_x_hex,
    );
    let y = old_p.evaluate(zeta);
    let y_prime = new_p.evaluate(zeta);
    let q_zeta = q_poly.evaluate(zeta);
    let r_y = derive_scalar("insert-r-y", &[&fr_bytes(y)]);
    let r_y_prime = derive_scalar("insert-r-y-prime", &[&fr_bytes(y_prime)]);
    let r_q = derive_scalar("insert-r-q", &[&fr_bytes(q_zeta)]);
    let c_y = eval_commit(y, r_y);
    let c_y_prime = eval_commit(y_prime, r_y_prime);
    let c_q = eval_commit(q_zeta, r_q);

    if y_prime != beta * y * (zeta - x) {
        return Err("insert relation y' = beta*y*(zeta-x) failed".to_string());
    }
    if y - y_x != q_zeta * (zeta - x) {
        return Err("insert relation y-y_x = q*(zeta-x) failed".to_string());
    }
    if y_x * z_x != Fr::one() || beta * z_beta != Fr::one() {
        return Err("insert inverse relation failed".to_string());
    }

    let c_y_hex = point_g1_to_hex(&c_y)?;
    let c_y_prime_hex = point_g1_to_hex(&c_y_prime)?;
    let c_q_hex = point_g1_to_hex(&c_q)?;
    let old_opening_poly = old_p
        .sub(&Polynomial::constant(y))
        .div_exact(&Polynomial::from_coeffs(vec![-zeta, Fr::one()]))?;
    let new_opening_poly = new_p
        .sub(&Polynomial::constant(y_prime))
        .div_exact(&Polynomial::from_coeffs(vec![-zeta, Fr::one()]))?;
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
    let quotient_eval_opening_proof_hex = prove_hiding_committed_opening(
        srs,
        &c_q_h_hex,
        zeta,
        &c_q_hex,
        q_zeta,
        r_q,
        &q_poly,
        &hiding_q,
        "dynamic-poa-insert-quotient-eval-hzkopen",
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

    let transcript_hex = build_transcript_hex(
        &state.state_root,
        &old_accumulator_hex,
        &new_accumulator_hex,
        &c_q_h_hex,
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
        &derive_generator("eval-v", 0),
        &derive_generator("eval-h", 0),
        &derive_generator("balance-v", 0),
        &derive_generator("balance-h", 0),
        &c_x,
        &c_insert_balance,
        &old_accumulator_hex,
        &new_accumulator_hex,
        &old_balance_commitment_hex,
        &new_balance_commitment_hex,
        state.reserve_addresses.len(),
        state.reserve_addresses.len() + 1,
        &transcript_hex,
    )?;
    let (sp1_proof_hex, sp1_vk_hex, sp1_public_values_hex, sp1_public) =
        sp1_host::kzg_insert::prove(sp1_stdin)?;
    if sp1_public.chain_id != witness.chain_id
        || sp1_public.state_root != state.state_root
        || !sp1_host::kzg_insert::point_matches(&sp1_public.c_x, &c_x)
        || !sp1_host::kzg_insert::point_matches(&sp1_public.c_balance_delta, &c_insert_balance)
        || sp1_public.transcript_hex != transcript_hex
    {
        return Err("SP1 KZG insert public values do not bind the insertion".to_string());
    }

    let mut reserve_addresses = state.reserve_addresses.clone();
    reserve_addresses.push(witness.address.clone());
    let mut reserve_balances = state.reserve_balances.clone();
    reserve_balances.push(witness.balance);
    let next_state = StoredState {
        state_root: state.state_root.clone(),
        srs_max_degree: state.srs_max_degree,
        alpha: state.alpha * beta,
        reserve_addresses,
        reserve_balances,
        masked_polynomial_coeffs: new_p.coeffs,
        accumulator_hex: new_accumulator_hex.clone(),
        balance_total: state
            .balance_total
            .checked_add(witness.balance)
            .ok_or_else(|| "inserted balance total overflow".to_string())?,
        balance_blind: state.balance_blind + r_ins,
        balance_commitment_hex: new_balance_commitment_hex.clone(),
    };

    let proof = KzgInsertProof {
        scheme: "kzg-nizk-insert-v2-hpoly".to_string(),
        old_state_root: state.state_root.clone(),
        new_state_root: state.state_root.clone(),
        old_accumulator_hex,
        new_accumulator_hex,
        old_balance_commitment_hex,
        new_balance_commitment_hex,
        reserve_count_before: state.reserve_addresses.len(),
        reserve_count_after: state.reserve_addresses.len() + 1,
        c_q_h_hex,
        c_x_hex,
        c_beta_hex,
        c_y_x_hex,
        c_y_hex,
        c_y_prime_hex,
        c_q_hex,
        zeta,
        old_eval_opening_proof_hex,
        new_eval_opening_proof_hex,
        quotient_eval_opening_proof_hex,
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
        | ChainBalanceProofInput::BinaryMerkleV1 { chain_id, .. } => chain_id,
    };
    if actual != &witness.chain_id {
        return Err(format!(
            "insert chain proof chain_id mismatch: expected {}, got {}",
            witness.chain_id, actual
        ));
    }
    Ok(())
}

pub fn verify_insert(
    old_state: &PublicState,
    new_state: &PublicState,
    proof: &KzgInsertProof,
) -> Result<(), String> {
    verify_insert_state(old_state, new_state, proof)?;
    Err("production insert verifier requires SRS; use verify_insert_with_srs".to_string())
}

pub fn verify_insert_with_srs(
    srs: &Srs,
    old_state: &PublicState,
    new_state: &PublicState,
    proof: &KzgInsertProof,
) -> Result<(), String> {
    verify_insert_state(old_state, new_state, proof)?;
    if old_state.srs_max_degree != srs.max_degree || new_state.srs_max_degree != srs.max_degree {
        return Err("insert state SRS degree does not match provided SRS".to_string());
    }
    if proof.scheme != "kzg-nizk-insert-v2-hpoly" {
        return Err("insert proof is not a production ZK proof".to_string());
    }
    let sp1_public = sp1_host::kzg_insert::verify(
        &proof.sp1_proof_hex,
        &proof.sp1_vk_hex,
        &proof.sp1_public_values_hex,
    )?;
    let old_balance = point_g1_from_hex(&proof.old_balance_commitment_hex)?;
    let new_balance = point_g1_from_hex(&proof.new_balance_commitment_hex)?;
    let c_balance_delta = new_balance - old_balance;
    let c_x = point_g1_from_hex(&proof.c_x_hex)?;
    if sp1_public.state_root != proof.old_state_root
        || !sp1_host::kzg_insert::point_matches(&sp1_public.c_x, &c_x)
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
    verify_hiding_committed_opening(
        srs,
        &proof.c_q_h_hex,
        proof.zeta,
        &proof.c_q_hex,
        proof.reserve_count_before.saturating_sub(1),
        &proof.quotient_eval_opening_proof_hex,
        "dynamic-poa-insert-quotient-eval-hzkopen",
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
        &proof.c_q_h_hex,
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
    if proof.reserve_count_before != old_state.reserve_count
        || proof.reserve_count_after != new_state.reserve_count
        || proof.reserve_count_after != proof.reserve_count_before + 1
    {
        return Err("insert reserve count mismatch".to_string());
    }
    Ok(())
}

pub fn verify_insert_debug(
    old_state: &PublicState,
    new_state: &PublicState,
    proof: &KzgInsertProof,
) -> Result<(), String> {
    verify_insert_state(old_state, new_state, proof)?;
    let expected_transcript = build_transcript_hex(
        &proof.old_state_root,
        &proof.old_accumulator_hex,
        &proof.new_accumulator_hex,
        &proof.c_q_h_hex,
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

fn derive_scalar(label: &str, chunks: &[&[u8]]) -> Fr {
    let mut bytes = Vec::new();
    for chunk in chunks {
        bytes.extend_from_slice(chunk);
    }
    hash_to_scalar(label, &bytes)
}

fn derive_nonzero_scalar(label: &str, chunks: &[&[u8]]) -> Fr {
    let mut scalar = derive_scalar(label, chunks);
    if scalar.is_zero() {
        scalar = Fr::from(37u64);
    }
    scalar
}

fn derive_zeta(
    state_root: &str,
    old_accumulator_hex: &str,
    new_accumulator_hex: &str,
    c_q_h_hex: &str,
    new_balance_commitment_hex: &str,
    reserve_count: usize,
    c_x_hex: &str,
    c_beta_hex: &str,
    c_y_x_hex: &str,
) -> Fr {
    derive_nonzero_scalar(
        "insert-zeta",
        &[
            state_root.as_bytes(),
            old_accumulator_hex.as_bytes(),
            new_accumulator_hex.as_bytes(),
            c_q_h_hex.as_bytes(),
            new_balance_commitment_hex.as_bytes(),
            reserve_count.to_string().as_bytes(),
            c_x_hex.as_bytes(),
            c_beta_hex.as_bytes(),
            c_y_x_hex.as_bytes(),
        ],
    )
}

fn fr_bytes(value: Fr) -> Vec<u8> {
    value.into_bigint().to_bytes_le()
}

fn build_transcript_hex(
    state_root: &str,
    old_accumulator_hex: &str,
    new_accumulator_hex: &str,
    c_q_h_hex: &str,
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
    let payload = [
        state_root.to_string(),
        old_accumulator_hex.to_string(),
        new_accumulator_hex.to_string(),
        c_q_h_hex.to_string(),
        new_balance_commitment_hex.to_string(),
        reserve_count.to_string(),
        c_x_hex.to_string(),
        c_beta_hex.to_string(),
        c_y_x_hex.to_string(),
        scalar_to_hex(&zeta)?,
        c_y_hex.to_string(),
        c_y_prime_hex.to_string(),
        c_q_hex.to_string(),
        ownership_artifact_digest_hex.to_string(),
        chain_balance_artifact_digest_hex.to_string(),
    ]
    .join("|");
    Ok(common::crypto::hex_encode(
        blake3::hash(payload.as_bytes()).as_bytes(),
    ))
}
