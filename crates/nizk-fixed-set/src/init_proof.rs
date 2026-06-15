use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use common::crypto::{hash_bytes, hash_to_scalar, point_g1_to_hex, scalar_to_hex};
use common::types::{
    ChainBalanceProofInput, InitProvingContext, InitReserveWitness, OwnershipWitnessInput, PreparedChainBalanceWitness,
    PreparedInitReserveWitness, PreparedOwnershipWitness, ReserveEntry, StoredInitProof, StoredState,
};

use crate::commitment::commit_balance;
use crate::kzg::{commit_g1, Srs};
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
    if reserve_witnesses.is_empty() {
        return Err("reserve set must not be empty".to_string());
    }

    let prepared = reserve_witnesses
        .iter()
        .map(|witness| prepare_init_witness(ctx, witness))
        .collect::<Result<Vec<_>, _>>()?;
    let reserve_entries = reserve_witnesses
        .iter()
        .map(|witness| ReserveEntry {
            address: witness.address.clone(),
            balance: witness.balance,
        })
        .collect::<Vec<_>>();
    initialize_core(ctx, &reserve_entries, &prepared, srs)
}

pub fn initialize_with_proof(
    reserve_entries: &[ReserveEntry],
    state_root: &str,
    srs: &Srs,
) -> Result<InitProofResult, String> {
    let ctx = InitProvingContext {
        chain_id: "mock-chain".to_string(),
        state_root: state_root.to_string(),
        session_id: "mock-init-session".to_string(),
    };
    let prepared = reserve_entries
        .iter()
        .map(|entry| PreparedInitReserveWitness {
            address: entry.address.clone(),
            balance: entry.balance,
            ownership: PreparedOwnershipWitness {
                scheme: "mock-ownership".to_string(),
                proof_digest_hex: common::crypto::hex_encode(&hash_bytes(
                    "mock-ownership-proof",
                    &[entry.address.as_bytes(), &entry.balance.to_le_bytes()],
                )),
            },
            chain_balance: PreparedChainBalanceWitness {
                scheme: "mock-chain-balance-proof".to_string(),
                proof_digest_hex: common::crypto::hex_encode(&hash_bytes(
                    "mock-chain-balance-proof",
                    &[state_root.as_bytes(), entry.address.as_bytes(), &entry.balance.to_le_bytes()],
                )),
            },
        })
        .collect::<Vec<_>>();
    initialize_core(&ctx, reserve_entries, &prepared, srs)
}

fn initialize_core(
    ctx: &InitProvingContext,
    reserve_entries: &[ReserveEntry],
    prepared_witnesses: &[PreparedInitReserveWitness],
    srs: &Srs,
) -> Result<InitProofResult, String> {
    if reserve_entries.is_empty() {
        return Err("reserve set must not be empty".to_string());
    }
    if reserve_entries.len() != prepared_witnesses.len() {
        return Err("reserve entries and prepared witnesses length mismatch".to_string());
    }

    let mut reserve_addresses = Vec::with_capacity(reserve_entries.len());
    let mut reserve_balances = Vec::with_capacity(reserve_entries.len());
    let mut roots = Vec::with_capacity(reserve_entries.len());
    for entry in reserve_entries {
        reserve_addresses.push(entry.address.clone());
        reserve_balances.push(entry.balance);
        roots.push(common::encoding::encode_address(&entry.address)?);
    }

    let init_salt = derive_init_salt(&ctx.state_root, reserve_entries);
    let init_digest = derive_init_digest(&ctx.state_root, &reserve_addresses, &reserve_balances, init_salt)?;
    let ownership_artifact_digest_hex = derive_artifact_bundle_digest(
        "ownership-artifacts",
        prepared_witnesses
            .iter()
            .map(|witness| witness.ownership.proof_digest_hex.as_str()),
    );
    let chain_balance_artifact_digest_hex = derive_artifact_bundle_digest(
        "chain-balance-artifacts",
        prepared_witnesses
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
    let balance_total: i128 = reserve_balances.iter().sum();
    let balance_blind = derive_balance_blind(balance_total, reserve_entries.len());
    let balance_commitment = commit_balance(balance_total, balance_blind);

    let zeta = derive_zeta(
        &ctx.state_root,
        &init_digest,
        reserve_entries.len(),
        &accumulator,
        &balance_commitment,
    )?;
    let p_zeta = p_s.evaluate(zeta);
    let product_zeta = roots.iter().fold(alpha, |acc, root| acc * (zeta - *root));
    let transcript_hex = build_transcript_hex(
        &ctx.chain_id,
        &ctx.state_root,
        &ctx.session_id,
        reserve_entries.len(),
        &point_g1_to_hex(&accumulator)?,
        &point_g1_to_hex(&balance_commitment)?,
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

    let proof = StoredInitProof {
        scheme: "nizk-fixed-set".to_string(),
        mode: "mock-native".to_string(),
        chain_id: ctx.chain_id.clone(),
        state_root: ctx.state_root.clone(),
        session_id: ctx.session_id.clone(),
        accumulator_hex: point_g1_to_hex(&accumulator)?,
        balance_commitment_hex: point_g1_to_hex(&balance_commitment)?,
        init_salt,
        init_digest_hex,
        ownership_artifact_digest_hex,
        chain_balance_artifact_digest_hex,
        reserve_count: reserve_entries.len(),
        zeta,
        p_zeta,
        product_zeta,
        balance_total,
        balance_blind,
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

pub fn verify_init_proof(
    srs: &Srs,
    state: &StoredState,
    proof: &StoredInitProof,
) -> Result<(), String> {
    if proof.scheme != "nizk-fixed-set" {
        return Err("unexpected init proof scheme".to_string());
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

    let zeta = proof.zeta;
    let expected_p_zeta = p_s.evaluate(zeta);
    let expected_product_zeta = roots.iter().fold(alpha, |acc, root| acc * (zeta - *root));
    if expected_p_zeta != proof.p_zeta || expected_product_zeta != proof.product_zeta {
        return Err("random evaluation mismatch".to_string());
    }
    if proof.p_zeta != proof.product_zeta {
        return Err("product identity check failed".to_string());
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
    let refs = chunks.iter().map(|chunk| chunk.as_slice()).collect::<Vec<_>>();
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

fn derive_zeta(
    state_root: &str,
    init_digest: &[u8; 32],
    reserve_count: usize,
    accumulator: &ark_bls12_381::G1Projective,
    balance_commitment: &ark_bls12_381::G1Projective,
) -> Result<Fr, String> {
    let payload = [
        state_root.as_bytes(),
        init_digest,
        &reserve_count.to_le_bytes(),
        point_g1_to_hex(accumulator)?.as_bytes(),
        point_g1_to_hex(balance_commitment)?.as_bytes(),
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
    Ok(common::crypto::hex_encode(&hash_bytes("srs-hash", &[&bytes])))
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

fn prepare_init_witness(
    ctx: &InitProvingContext,
    witness: &InitReserveWitness,
) -> Result<PreparedInitReserveWitness, String> {
    let ownership = match &witness.ownership {
        OwnershipWitnessInput::MockPrivateKey { mock_private_key } => PreparedOwnershipWitness {
            scheme: "mock-private-key".to_string(),
            proof_digest_hex: common::crypto::hex_encode(&hash_bytes(
                "mock-private-key-ownership",
                &[
                    ctx.chain_id.as_bytes(),
                    ctx.state_root.as_bytes(),
                    ctx.session_id.as_bytes(),
                    witness.address.as_bytes(),
                    mock_private_key.as_bytes(),
                ],
            )),
        },
        OwnershipWitnessInput::EthereumEoaPrivateKeyHex { private_key_hex } => PreparedOwnershipWitness {
            scheme: "ethereum-eoa-secp256k1".to_string(),
            proof_digest_hex: common::crypto::hex_encode(&hash_bytes(
                "ethereum-eoa-private-key-binding",
                &[
                    ctx.chain_id.as_bytes(),
                    ctx.state_root.as_bytes(),
                    ctx.session_id.as_bytes(),
                    witness.address.as_bytes(),
                    private_key_hex.as_bytes(),
                ],
            )),
        },
        OwnershipWitnessInput::ExternalOwnershipProof { scheme, proof_hex } => PreparedOwnershipWitness {
            scheme: scheme.clone(),
            proof_digest_hex: common::crypto::hex_encode(&hash_bytes(
                "external-ownership-proof",
                &[scheme.as_bytes(), proof_hex.as_bytes(), witness.address.as_bytes()],
            )),
        },
    };

    let chain_balance = match &witness.chain_balance_proof {
        ChainBalanceProofInput::Mock { proof_label } => PreparedChainBalanceWitness {
            scheme: "mock-chain-balance-proof".to_string(),
            proof_digest_hex: common::crypto::hex_encode(&hash_bytes(
                "mock-chain-balance-proof",
                &[
                    ctx.chain_id.as_bytes(),
                    ctx.state_root.as_bytes(),
                    witness.address.as_bytes(),
                    &witness.balance.to_le_bytes(),
                    proof_label.as_bytes(),
                ],
            )),
        },
        ChainBalanceProofInput::EthereumAccountProof {
            chain_id,
            block_number,
            block_hash_hex,
            account_proof_rlp_hex,
        } => {
            let mut nodes = account_proof_rlp_hex
                .iter()
                .flat_map(|node| [node.as_bytes(), b"|".as_slice()])
                .flatten()
                .copied()
                .collect::<Vec<_>>();
            nodes.extend_from_slice(chain_id.as_bytes());
            nodes.extend_from_slice(&block_number.to_le_bytes());
            nodes.extend_from_slice(block_hash_hex.as_bytes());
            PreparedChainBalanceWitness {
                scheme: "ethereum-account-proof".to_string(),
                proof_digest_hex: common::crypto::hex_encode(&hash_bytes(
                    "ethereum-account-proof",
                    &[&nodes, witness.address.as_bytes(), &witness.balance.to_le_bytes()],
                )),
            }
        }
        ChainBalanceProofInput::GenericMerkleProof {
            chain_id,
            proof_system,
            proof_payload_hex,
            public_inputs_hex,
        } => PreparedChainBalanceWitness {
            scheme: format!("generic:{proof_system}"),
            proof_digest_hex: common::crypto::hex_encode(&hash_bytes(
                "generic-chain-balance-proof",
                &[
                    chain_id.as_bytes(),
                    proof_system.as_bytes(),
                    witness.address.as_bytes(),
                    &witness.balance.to_le_bytes(),
                    proof_payload_hex.as_bytes(),
                    public_inputs_hex.as_bytes(),
                ],
            )),
        },
    };

    Ok(PreparedInitReserveWitness {
        address: witness.address.clone(),
        balance: witness.balance,
        ownership,
        chain_balance,
    })
}
