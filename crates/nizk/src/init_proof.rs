use ark_bls12_381::Fr;
use ark_ec::PrimeGroup;
use ark_ff::{BigInteger, PrimeField, Zero};
use common::crypto::{
    hash_bytes, hash_to_scalar, point_g1_from_hex, point_g1_to_hex, scalar_to_hex,
};
use common::types::{
    InitProvingContext, InitReserveWitness, PreparedInitReserveWitness, PublicState, ReserveEntry,
    StoredInitProof, StoredState,
};

use crate::commitment::commit_balance;
use crate::commitment::{commit_linear, derive_generator};
use crate::external::{ExternalProofAdapter, MockExternalProofAdapter};
use crate::kzg::{commit_g1, open as kzg_open, verify_open as verify_kzg_open, Srs};
use crate::polynomial::product_from_roots;

#[derive(Clone, Debug)]
pub struct InitProofResult {
    pub state: StoredState,
    pub proof: StoredInitProof,
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
    if reserve_witnesses.is_empty() {
        return Err("reserve set must not be empty".to_string());
    }
    for witness in reserve_witnesses {
        validate_chain_id(&ctx.chain_id, &witness.chain_balance_proof)?;
    }

    let prepared = reserve_witnesses
        .iter()
        .map(|witness| external.prepare_init_witness(ctx, witness))
        .collect::<Result<Vec<_>, _>>()?;
    let reserve_entries = reserve_witnesses
        .iter()
        .map(|witness| ReserveEntry {
            address: witness.address.clone(),
            balance: witness.balance,
        })
        .collect::<Vec<_>>();
    initialize_core(ctx, &reserve_entries, reserve_witnesses, &prepared, srs)
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
    let prepared = reserve_witnesses
        .iter()
        .map(|witness| external.prepare_init_witness(&ctx, witness))
        .collect::<Result<Vec<_>, _>>()?;
    initialize_core(&ctx, reserve_entries, &reserve_witnesses, &prepared, srs)
}

fn initialize_core(
    ctx: &InitProvingContext,
    reserve_entries: &[ReserveEntry],
    reserve_witnesses: &[InitReserveWitness],
    prepared_witnesses: &[PreparedInitReserveWitness],
    srs: &Srs,
) -> Result<InitProofResult, String> {
    if reserve_entries.is_empty() {
        return Err("reserve set must not be empty".to_string());
    }
    if reserve_entries.len() != prepared_witnesses.len()
        || reserve_entries.len() != reserve_witnesses.len()
    {
        return Err("reserve entries and init witnesses length mismatch".to_string());
    }

    let mut canonical_entries = Vec::with_capacity(reserve_entries.len());
    for ((entry, witness), prepared) in reserve_entries
        .iter()
        .zip(reserve_witnesses.iter())
        .zip(prepared_witnesses.iter())
    {
        if prepared.address != entry.address || prepared.balance != entry.balance {
            return Err("external adapter changed the reserve address or balance".to_string());
        }
        canonical_entries.push((
            common::encoding::encode_address(&entry.address)?,
            entry.clone(),
            witness.clone(),
            prepared.clone(),
        ));
    }
    canonical_entries.sort_by(|left, right| left.0.into_bigint().cmp(&right.0.into_bigint()));

    let mut reserve_addresses = Vec::with_capacity(reserve_entries.len());
    let mut reserve_balances = Vec::with_capacity(reserve_entries.len());
    let mut roots = Vec::with_capacity(reserve_entries.len());
    let mut canonical_witnesses = Vec::with_capacity(reserve_witnesses.len());
    let mut canonical_prepared = Vec::with_capacity(prepared_witnesses.len());
    for (root, entry, witness, prepared) in canonical_entries {
        roots.push(root);
        reserve_addresses.push(entry.address);
        reserve_balances.push(entry.balance);
        canonical_witnesses.push(witness);
        canonical_prepared.push(prepared);
    }
    if !is_strictly_ordered(&roots) {
        return Err("reserve addresses must be canonical and duplicate-free".to_string());
    }

    let canonical_reserve_entries = reserve_addresses
        .iter()
        .zip(reserve_balances.iter())
        .map(|(address, balance)| ReserveEntry {
            address: address.clone(),
            balance: *balance,
        })
        .collect::<Vec<_>>();
    let init_salt = derive_init_salt(&ctx.state_root, &canonical_reserve_entries);
    let init_digest = derive_init_digest(
        &ctx.state_root,
        &reserve_addresses,
        &reserve_balances,
        init_salt,
    )?;
    let ownership_artifact_digest_hex = derive_artifact_bundle_digest(
        "ownership-artifacts",
        canonical_prepared
            .iter()
            .map(|witness| witness.ownership.proof_digest_hex.as_str()),
    );
    let chain_balance_artifact_digest_hex = derive_artifact_bundle_digest(
        "chain-balance-artifacts",
        canonical_prepared
            .iter()
            .map(|witness| witness.chain_balance.proof_digest_hex.as_str()),
    );
    let alpha = derive_alpha(&roots);
    if alpha.is_zero() {
        return Err("derived alpha must be non-zero".to_string());
    }

    let f_s = product_from_roots(&roots);
    let p_s = f_s.mul_scalar(alpha);
    let accumulator = commit_g1(srs, &p_s)?;
    let balance_total = reserve_balances.iter().try_fold(0i128, |sum, balance| {
        sum.checked_add(*balance)
            .ok_or_else(|| "reserve balance total overflow".to_string())
    })?;
    let balance_blind = derive_balance_blind(balance_total, reserve_entries.len());
    let balance_commitment = commit_balance(balance_total, balance_blind);
    let r_shape = derive_shape_blind(&roots, alpha);
    let c_shape = commit_shape(alpha, &roots, r_shape);

    let zeta = derive_zeta(
        &ctx.state_root,
        &init_digest,
        reserve_entries.len(),
        &accumulator,
        &balance_commitment,
        &c_shape,
    )?;
    let p_zeta = p_s.evaluate(zeta);
    let product_zeta = roots.iter().fold(alpha, |acc, root| acc * (zeta - *root));
    let kzg_opening_proof = kzg_open(srs, &p_s, zeta, p_zeta)?;
    let r_y = derive_eval_blind(p_zeta, zeta);
    let c_y = commit_eval(p_zeta, r_y);
    let transcript_hex = build_transcript_hex(
        &ctx.chain_id,
        &ctx.state_root,
        &ctx.session_id,
        reserve_entries.len(),
        &point_g1_to_hex(&accumulator)?,
        &point_g1_to_hex(&balance_commitment)?,
        &point_g1_to_hex(&c_shape)?,
        &point_g1_to_hex(&c_y)?,
        &init_digest,
        &ownership_artifact_digest_hex,
        &chain_balance_artifact_digest_hex,
        zeta,
        p_zeta,
        product_zeta,
    );
    let srs_hash_hex = point_hash_srs(srs)?;
    let init_digest_hex = common::crypto::hex_encode(&init_digest);
    let chain_proof_hex = build_chain_proof_hex(
        &ctx.chain_id,
        &ctx.state_root,
        &ctx.session_id,
        &init_digest_hex,
        &ownership_artifact_digest_hex,
        &chain_balance_artifact_digest_hex,
        reserve_entries.len(),
        balance_total,
    );
    let alg_proof_hex = build_alg_proof_hex(
        &ctx.state_root,
        &point_g1_to_hex(&accumulator)?,
        &point_g1_to_hex(&balance_commitment)?,
        &init_digest_hex,
        zeta,
        p_zeta,
        product_zeta,
        &srs_hash_hex,
    );
    let sp1_stdin = sp1_host::init::build_init_stdin(
        &ctx.chain_id,
        &ctx.state_root,
        &ctx.session_id,
        init_salt,
        alpha,
        zeta,
        p_zeta,
        product_zeta,
        balance_total,
        &init_digest_hex,
        &ownership_artifact_digest_hex,
        &chain_balance_artifact_digest_hex,
        &reserve_addresses,
        &roots,
        &reserve_balances,
        &canonical_witnesses,
    )?;
    let (sp1_proof_hex, sp1_vk_hex, sp1_public_values_hex, _) =
        sp1_host::init::prove_init(sp1_stdin)?;

    let proof = StoredInitProof {
        scheme: "kzg-nizk-init".to_string(),
        mode: "sp1".to_string(),
        chain_id: ctx.chain_id.clone(),
        state_root: ctx.state_root.clone(),
        session_id: ctx.session_id.clone(),
        accumulator_hex: point_g1_to_hex(&accumulator)?,
        balance_commitment_hex: point_g1_to_hex(&balance_commitment)?,
        c_shape_hex: point_g1_to_hex(&c_shape)?,
        c_y_hex: point_g1_to_hex(&c_y)?,
        init_salt,
        init_digest_hex,
        ownership_artifact_digest_hex,
        chain_balance_artifact_digest_hex,
        reserve_count: reserve_entries.len(),
        zeta,
        p_zeta,
        product_zeta,
        r_shape,
        r_y,
        balance_total,
        balance_blind,
        kzg_opening_proof_hex: point_g1_to_hex(&kzg_opening_proof)?,
        sp1_proof_hex,
        sp1_vk_hex,
        sp1_public_values_hex,
        chain_proof_hex,
        alg_proof_hex,
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
        | common::types::ChainBalanceProofInput::BinaryMerkleV1 { chain_id, .. } => chain_id,
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
    if proof.scheme != "mock-nizk-init-boundary" && proof.scheme != "kzg-nizk-init" {
        return Err("unexpected init proof scheme".to_string());
    }
    if proof.mode != "mock-non-zk-native" && proof.mode != "sp1" {
        return Err("unexpected init proof mode".to_string());
    }
    if proof.chain_id.is_empty() {
        return Err("missing chain_id".to_string());
    }
    if proof.session_id.is_empty() {
        return Err("missing session_id".to_string());
    }
    if proof.state_root != state.state_root {
        return Err("init state_root mismatch".to_string());
    }
    if proof.reserve_count != state.reserve_addresses.len() {
        return Err("reserve count mismatch".to_string());
    }
    if proof.accumulator_hex != state.accumulator_hex {
        return Err("accumulator mismatch".to_string());
    }
    if proof.balance_commitment_hex != state.balance_commitment_hex {
        return Err("balance commitment mismatch".to_string());
    }
    if proof.balance_total != state.balance_total || proof.balance_blind != state.balance_blind {
        return Err("balance aggregate mismatch".to_string());
    }
    if proof.srs_hash_hex != point_hash_srs(srs)? {
        return Err("SRS hash mismatch".to_string());
    }

    let roots = state
        .reserve_addresses
        .iter()
        .map(|address| common::encoding::encode_address(address))
        .collect::<Result<Vec<_>, _>>()?;
    let alpha = derive_alpha(&roots);
    if alpha != state.alpha {
        return Err("alpha mismatch".to_string());
    }
    let f_s = product_from_roots(&roots);
    let p_s = f_s.mul_scalar(alpha);
    let accumulator = commit_g1(srs, &p_s)?;
    if point_g1_to_hex(&accumulator)? != proof.accumulator_hex {
        return Err("recomputed accumulator mismatch".to_string());
    }
    if !is_strictly_ordered(&roots) {
        return Err("reserve address encodings are not duplicate-free strict order".to_string());
    }
    let c_shape = commit_shape(alpha, &roots, proof.r_shape);
    if point_g1_to_hex(&c_shape)? != proof.c_shape_hex {
        return Err("shape commitment mismatch".to_string());
    }

    let zeta = proof.zeta;
    let expected_p_zeta = p_s.evaluate(zeta);
    let expected_product_zeta = roots.iter().fold(alpha, |acc, root| acc * (zeta - *root));
    if expected_p_zeta != proof.p_zeta || expected_product_zeta != proof.product_zeta {
        return Err("random evaluation mismatch".to_string());
    }
    if proof.p_zeta != proof.product_zeta {
        return Err("product identity check failed".to_string());
    }
    let c_y = commit_eval(proof.p_zeta, proof.r_y);
    if point_g1_to_hex(&c_y)? != proof.c_y_hex {
        return Err("evaluation commitment mismatch".to_string());
    }
    if !proof.kzg_opening_proof_hex.is_empty() {
        let opening = point_g1_from_hex(&proof.kzg_opening_proof_hex)?;
        if !verify_kzg_open(srs, &accumulator, proof.zeta, proof.p_zeta, &opening)? {
            return Err("init KZG opening verification failed".to_string());
        }
    }

    let expected_digest = derive_init_digest(
        &state.state_root,
        &state.reserve_addresses,
        &state.reserve_balances,
        proof.init_salt,
    )?;
    if common::crypto::hex_encode(&expected_digest) != proof.init_digest_hex {
        return Err("init digest mismatch".to_string());
    }
    let expected_chain_proof = build_chain_proof_hex(
        &proof.chain_id,
        &state.state_root,
        &proof.session_id,
        &proof.init_digest_hex,
        &proof.ownership_artifact_digest_hex,
        &proof.chain_balance_artifact_digest_hex,
        state.reserve_addresses.len(),
        proof.balance_total,
    );
    if expected_chain_proof != proof.chain_proof_hex {
        return Err("init chain proof mismatch".to_string());
    }
    let expected_transcript = build_transcript_hex(
        &proof.chain_id,
        &state.state_root,
        &proof.session_id,
        state.reserve_addresses.len(),
        &state.accumulator_hex,
        &state.balance_commitment_hex,
        &proof.c_shape_hex,
        &proof.c_y_hex,
        &expected_digest,
        &proof.ownership_artifact_digest_hex,
        &proof.chain_balance_artifact_digest_hex,
        zeta,
        expected_p_zeta,
        expected_product_zeta,
    );
    if expected_transcript != proof.transcript_hex {
        return Err("init transcript mismatch".to_string());
    }
    let expected_alg_proof = build_alg_proof_hex(
        &state.state_root,
        &state.accumulator_hex,
        &state.balance_commitment_hex,
        &proof.init_digest_hex,
        zeta,
        expected_p_zeta,
        expected_product_zeta,
        &proof.srs_hash_hex,
    );
    if expected_alg_proof != proof.alg_proof_hex {
        return Err("init algebraic proof mismatch".to_string());
    }

    let balance_total: i128 = state.reserve_balances.iter().sum();
    if balance_total != proof.balance_total {
        return Err("balance total mismatch".to_string());
    }
    let balance_blind = derive_balance_blind(balance_total, state.reserve_addresses.len());
    if balance_blind != proof.balance_blind {
        return Err("balance blind mismatch".to_string());
    }
    let balance_commitment = commit_balance(balance_total, balance_blind);
    if point_g1_to_hex(&balance_commitment)? != proof.balance_commitment_hex {
        return Err("balance commitment recomputation mismatch".to_string());
    }

    Ok(())
}

pub fn verify_init_public_proof(
    srs: &Srs,
    public_state: &PublicState,
    proof: &StoredInitProof,
) -> Result<(), String> {
    if public_state.srs_max_degree != srs.max_degree {
        return Err("state SRS degree does not match provided SRS".to_string());
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
    if proof.scheme != "kzg-nizk-init" {
        return Err("init proof is not a production ZK proof; use verify_init_debug only for transparent local tests".to_string());
    }
    if proof.mode != "sp1" {
        return Err("init proof mode is not sp1".to_string());
    }
    if proof.chain_proof_hex.is_empty()
        || proof.alg_proof_hex.is_empty()
        || proof.kzg_opening_proof_hex.is_empty()
        || proof.sp1_proof_hex.is_empty()
        || proof.sp1_vk_hex.is_empty()
    {
        return Err("missing init proof-system artifact".to_string());
    }
    let accumulator = point_g1_from_hex(&proof.accumulator_hex)?;
    let opening = point_g1_from_hex(&proof.kzg_opening_proof_hex)?;
    if !verify_kzg_open(srs, &accumulator, proof.zeta, proof.p_zeta, &opening)? {
        return Err("init KZG opening verification failed".to_string());
    }
    if proof.p_zeta != proof.product_zeta {
        return Err("init public evaluation/product mismatch".to_string());
    }

    let sp1_public = sp1_host::init::verify_init_proof(proof)?;
    if sp1_public.chain_id != proof.chain_id
        || sp1_public.state_root != proof.state_root
        || sp1_public.session_id != proof.session_id
        || sp1_public.reserve_count != proof.reserve_count
        || sp1_public.init_digest_hex != proof.init_digest_hex
        || sp1_public.ownership_artifact_digest_hex != proof.ownership_artifact_digest_hex
        || sp1_public.chain_balance_artifact_digest_hex != proof.chain_balance_artifact_digest_hex
        || sp1_public.zeta_le != fr_to_le_bytes(proof.zeta)
        || sp1_public.p_zeta_le != fr_to_le_bytes(proof.p_zeta)
        || sp1_public.product_zeta_le != fr_to_le_bytes(proof.product_zeta)
        || sp1_public.balance_total != proof.balance_total
    {
        return Err("init SP1 public values mismatch".to_string());
    }

    let expected_balance_commitment = commit_balance(proof.balance_total, proof.balance_blind);
    if point_g1_to_hex(&expected_balance_commitment)? != proof.balance_commitment_hex {
        return Err("init balance commitment opening mismatch".to_string());
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
        &hex_to_32(&proof.init_digest_hex)?,
        &proof.ownership_artifact_digest_hex,
        &proof.chain_balance_artifact_digest_hex,
        proof.zeta,
        proof.p_zeta,
        proof.product_zeta,
    );
    if expected_transcript != proof.transcript_hex {
        return Err("init transcript mismatch".to_string());
    }
    Ok(())
}

fn derive_init_salt(state_root: &str, reserves: &[ReserveEntry]) -> Fr {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(state_root.as_bytes());
    for entry in reserves {
        bytes.extend_from_slice(entry.address.as_bytes());
        bytes.extend_from_slice(&entry.balance.to_le_bytes());
    }
    let mut salt = hash_to_scalar("init-salt", &bytes);
    if salt.is_zero() {
        salt = Fr::from(31u64);
    }
    salt
}

fn derive_init_digest(
    state_root: &str,
    addresses: &[String],
    balances: &[i128],
    salt: Fr,
) -> Result<[u8; 32], String> {
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    chunks.push(state_root.as_bytes().to_vec());
    chunks.push(scalar_to_hex(&salt)?.into_bytes());
    chunks.push(addresses.len().to_string().into_bytes());
    for (address, balance) in addresses.iter().zip(balances.iter()) {
        chunks.push(address.as_bytes().to_vec());
        chunks.push(balance.to_le_bytes().to_vec());
    }
    let refs = chunks
        .iter()
        .map(|chunk| chunk.as_slice())
        .collect::<Vec<_>>();
    Ok(hash_bytes("init-digest", &refs))
}

fn derive_alpha(encoded_addresses: &[Fr]) -> Fr {
    let mut bytes = Vec::new();
    for address in encoded_addresses {
        bytes.extend_from_slice(&address.into_bigint().to_bytes_le());
    }
    let mut alpha = hash_to_scalar("reserve-alpha", &bytes);
    if alpha.is_zero() {
        alpha = Fr::from(17u64);
    }
    alpha
}

fn derive_balance_blind(balance_total: i128, len: usize) -> Fr {
    let payload = format!("balance-blind:{balance_total}:{len}");
    let mut blind = hash_to_scalar("balance-blind", payload.as_bytes());
    if blind.is_zero() {
        blind = Fr::from(23u64);
    }
    blind
}

fn derive_shape_blind(roots: &[Fr], alpha: Fr) -> Fr {
    let mut bytes = alpha.into_bigint().to_bytes_le();
    for root in roots {
        bytes.extend_from_slice(&root.into_bigint().to_bytes_le());
    }
    let mut blind = hash_to_scalar("shape-blind", &bytes);
    if blind.is_zero() {
        blind = Fr::from(43u64);
    }
    blind
}

fn derive_eval_blind(value: Fr, zeta: Fr) -> Fr {
    let mut bytes = value.into_bigint().to_bytes_le();
    bytes.extend_from_slice(&zeta.into_bigint().to_bytes_le());
    let mut blind = hash_to_scalar("eval-blind", &bytes);
    if blind.is_zero() {
        blind = Fr::from(47u64);
    }
    blind
}

fn commit_shape(alpha: Fr, roots: &[Fr], blind: Fr) -> ark_bls12_381::G1Projective {
    let mut values = Vec::with_capacity(roots.len() + 1);
    values.push(alpha);
    values.extend_from_slice(roots);
    commit_linear(&values, "init-shape-w", "init-shape-h", blind)
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
    state_root: &str,
    init_digest: &[u8; 32],
    reserve_count: usize,
    accumulator: &ark_bls12_381::G1Projective,
    balance_commitment: &ark_bls12_381::G1Projective,
    c_shape: &ark_bls12_381::G1Projective,
) -> Result<Fr, String> {
    let payload = [
        state_root.as_bytes(),
        init_digest,
        &reserve_count.to_le_bytes(),
        point_g1_to_hex(accumulator)?.as_bytes(),
        point_g1_to_hex(balance_commitment)?.as_bytes(),
        point_g1_to_hex(c_shape)?.as_bytes(),
    ]
    .concat();
    let mut zeta = hash_to_scalar("init-zeta", &payload);
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
    init_digest: &[u8; 32],
    ownership_artifact_digest_hex: &str,
    chain_balance_artifact_digest_hex: &str,
    zeta: Fr,
    p_zeta: Fr,
    product_zeta: Fr,
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
        init_digest,
        ownership_artifact_digest_hex.as_bytes(),
        chain_balance_artifact_digest_hex.as_bytes(),
        scalar_to_hex(&zeta).unwrap_or_default().as_bytes(),
        scalar_to_hex(&p_zeta).unwrap_or_default().as_bytes(),
        scalar_to_hex(&product_zeta).unwrap_or_default().as_bytes(),
    ]
    .concat();
    common::crypto::hex_encode(&hash_bytes("init-transcript", &[&payload]))
}

fn point_hash_srs(srs: &Srs) -> Result<String, String> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(srs.max_degree as u64).to_le_bytes());
    for point in &srs.tau_g1_powers {
        bytes.extend_from_slice(&common::crypto::serialize_hex(point)?.into_bytes());
    }
    for point in &srs.tau_g2_powers {
        bytes.extend_from_slice(&common::crypto::serialize_hex(point)?.into_bytes());
    }
    Ok(common::crypto::hex_encode(&hash_bytes(
        "srs-hash",
        &[&bytes],
    )))
}

fn build_chain_proof_hex(
    chain_id: &str,
    state_root: &str,
    session_id: &str,
    init_digest_hex: &str,
    ownership_artifact_digest_hex: &str,
    chain_balance_artifact_digest_hex: &str,
    reserve_count: usize,
    balance_total: i128,
) -> String {
    let payload = [
        chain_id.as_bytes(),
        state_root.as_bytes(),
        session_id.as_bytes(),
        init_digest_hex.as_bytes(),
        ownership_artifact_digest_hex.as_bytes(),
        chain_balance_artifact_digest_hex.as_bytes(),
        reserve_count.to_string().as_bytes(),
        balance_total.to_string().as_bytes(),
    ]
    .concat();
    common::crypto::hex_encode(&hash_bytes("mock-init-chain-proof", &[&payload]))
}

fn build_alg_proof_hex(
    state_root: &str,
    accumulator_hex: &str,
    balance_commitment_hex: &str,
    init_digest_hex: &str,
    zeta: Fr,
    p_zeta: Fr,
    product_zeta: Fr,
    srs_hash_hex: &str,
) -> String {
    let payload = [
        state_root.as_bytes(),
        accumulator_hex.as_bytes(),
        balance_commitment_hex.as_bytes(),
        init_digest_hex.as_bytes(),
        scalar_to_hex(&zeta).unwrap_or_default().as_bytes(),
        scalar_to_hex(&p_zeta).unwrap_or_default().as_bytes(),
        scalar_to_hex(&product_zeta).unwrap_or_default().as_bytes(),
        srs_hash_hex.as_bytes(),
    ]
    .concat();
    common::crypto::hex_encode(&hash_bytes("mock-init-alg-proof", &[&payload]))
}

fn derive_artifact_bundle_digest<'a>(
    label: &str,
    digests: impl Iterator<Item = &'a str>,
) -> String {
    let payload = digests
        .flat_map(|digest| [digest.as_bytes(), b"|".as_slice()])
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    common::crypto::hex_encode(&hash_bytes(label, &[&payload]))
}

fn fr_to_le_bytes(value: Fr) -> [u8; 32] {
    let raw = value.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    let len = raw.len().min(32);
    out[..len].copy_from_slice(&raw[..len]);
    out
}

fn hex_to_32(value: &str) -> Result<[u8; 32], String> {
    let bytes = common::crypto::hex_decode(value)?;
    if bytes.len() != 32 {
        return Err("expected 32-byte hex digest".to_string());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
