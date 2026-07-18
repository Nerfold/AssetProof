use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use ark_bls12_381::{Fr, G1Projective};
use ark_ff::{BigInteger, PrimeField};
use common::crypto::{hex_decode, hex_encode};
use common::types::{
    ChainBalanceProofInput, InitReserveWitness, OwnershipWitnessInput, StoredInitProof,
};
use sp1_programs_common::io::{
    Sp1ChainBalanceProof, Sp1G1Affine, Sp1InitOwnershipEntry, Sp1InitOwnershipPublicValues,
    Sp1InitOwnershipStdin, Sp1OwnershipWitness,
};
use sp1_programs_common::io::{Sp1InitPublicValues, Sp1InitReserveEntry, Sp1InitStdin};
use sp1_sdk::blocking::{ProveRequest, Prover as BlockingProver, ProverClient};
use sp1_sdk::include_elf;
use sp1_sdk::{ProvingKey, SP1ProofWithPublicValues, SP1Stdin};

use crate::proof_mode::{configured_proof_mode, ensure_trusted_vk, ConfiguredProofMode};
use crate::setup::{
    default_setup_dir, ensure_protocol_setups, load_init_ownership_vk, load_init_vk,
};

const INIT_ELF: sp1_sdk::Elf = include_elf!("sp1-init-merkle");
const INIT_OWNERSHIP_ELF: sp1_sdk::Elf = include_elf!("sp1-init-ownership");
const KZG_INSERT_ELF: sp1_sdk::Elf = include_elf!("sp1-kzg-insert");

#[derive(Clone)]
struct Sp1InitContext {
    prover: sp1_sdk::blocking::CpuProver,
    pk: Arc<sp1_sdk::SP1ProvingKey>,
}

static SP1_INIT_CONTEXT: OnceLock<Mutex<Option<Sp1InitContext>>> = OnceLock::new();
static SP1_INIT_OWNERSHIP_CONTEXT: OnceLock<Mutex<Option<Sp1InitContext>>> = OnceLock::new();

pub struct ProvedInitMerkle {
    pub proof_hex: String,
    pub vk_hex: String,
    pub public_values_hex: String,
    pub public: Sp1InitPublicValues,
}

pub struct ProvedInitOwnership {
    pub proof_hex: String,
    pub vk_hex: String,
    pub public_values_hex: String,
    pub public: Sp1InitOwnershipPublicValues,
}

pub fn ensure_sp1_setup(setup_dir: &Path) -> Result<(), String> {
    ensure_protocol_setups(setup_dir, INIT_ELF, INIT_OWNERSHIP_ELF, KZG_INSERT_ELF)
}

pub fn prove_init_ownership(
    ownership_stdin: Sp1InitOwnershipStdin,
) -> Result<ProvedInitOwnership, String> {
    let ownership_ctx = sp1_ownership_context()?;
    let ownership_bundle = run_sp1_proof(&ownership_ctx, &ownership_stdin, "init ownership")?;
    Ok(ProvedInitOwnership {
        proof_hex: serialize_sp1_proof(&ownership_bundle)?,
        vk_hex: serialize_sp1_vk(&ownership_ctx)?,
        public_values_hex: hex_encode(ownership_bundle.public_values.as_slice()),
        public: decode_ownership_public_values(&ownership_bundle),
    })
}

pub fn prove_init_merkle(merkle_stdin: Sp1InitStdin) -> Result<ProvedInitMerkle, String> {
    let merkle_ctx = sp1_context()?;
    let merkle_bundle = run_sp1_proof(&merkle_ctx, &merkle_stdin, "init Merkle")?;
    Ok(ProvedInitMerkle {
        proof_hex: serialize_sp1_proof(&merkle_bundle)?,
        vk_hex: serialize_sp1_vk(&merkle_ctx)?,
        public_values_hex: hex_encode(merkle_bundle.public_values.as_slice()),
        public: decode_public_values(&merkle_bundle),
    })
}

pub fn verify_init_proof(
    proof: &StoredInitProof,
) -> Result<(Sp1InitPublicValues, Sp1InitOwnershipPublicValues), String> {
    if proof.sp1_proof_hex.is_empty()
        || proof.sp1_vk_hex.is_empty()
        || proof.ownership_sp1_proof_hex.is_empty()
        || proof.ownership_sp1_vk_hex.is_empty()
    {
        return Err("missing serialized SP1 init proof artifacts".to_string());
    }
    let merkle_ctx = sp1_context()?;
    let ownership_ctx = sp1_ownership_context()?;
    let merkle_bundle = deserialize_sp1_proof(&proof.sp1_proof_hex)?;
    let ownership_bundle = deserialize_sp1_proof(&proof.ownership_sp1_proof_hex)?;
    if !proof.sp1_public_values_hex.is_empty()
        && proof.sp1_public_values_hex != hex_encode(merkle_bundle.public_values.as_slice())
    {
        return Err("stored SP1 init Merkle public values do not match proof bundle".to_string());
    }
    if !proof.ownership_sp1_public_values_hex.is_empty()
        && proof.ownership_sp1_public_values_hex
            != hex_encode(ownership_bundle.public_values.as_slice())
    {
        return Err(
            "stored SP1 init ownership public values do not match proof bundle".to_string(),
        );
    }
    ensure_trusted_vk(
        &proof.sp1_vk_hex,
        merkle_ctx.pk.verifying_key(),
        hex_decode,
        "init Merkle",
    )?;
    ensure_trusted_vk(
        &proof.ownership_sp1_vk_hex,
        ownership_ctx.pk.verifying_key(),
        hex_decode,
        "init ownership",
    )?;
    merkle_ctx
        .prover
        .verify(&merkle_bundle, merkle_ctx.pk.verifying_key(), None)
        .map_err(|err| format!("sp1 init Merkle verify failed: {err}"))?;
    ownership_ctx
        .prover
        .verify(&ownership_bundle, ownership_ctx.pk.verifying_key(), None)
        .map_err(|err| format!("sp1 init ownership verify failed: {err}"))?;
    Ok((
        decode_public_values(&merkle_bundle),
        decode_ownership_public_values(&ownership_bundle),
    ))
}

pub fn build_init_merkle_stdin(
    chain_id: &str,
    state_root: &str,
    session_id: &str,
    alpha: Fr,
    zeta: Fr,
    p_zeta: Fr,
    product_zeta: Fr,
    balance_total: i128,
    balance_blind: Fr,
    shape_salt: [u8; 32],
    shape_commitment: [u8; 32],
    eval_blind: Fr,
    balance_value_base: &G1Projective,
    balance_blind_base: &G1Projective,
    eval_value_base: &G1Projective,
    eval_blind_base: &G1Projective,
    balance_commitment: &G1Projective,
    eval_commitment: &G1Projective,
    addresses: &[String],
    encoded_addresses: &[Fr],
    balances: &[i128],
    witnesses: &[&InitReserveWitness],
) -> Result<Sp1InitStdin, String> {
    if addresses.len() != encoded_addresses.len()
        || addresses.len() != balances.len()
        || addresses.len() != witnesses.len()
    {
        return Err("init SP1 stdin vector length mismatch".to_string());
    }
    let reserves = addresses
        .iter()
        .zip(encoded_addresses.iter())
        .zip(balances.iter())
        .zip(witnesses.iter())
        .map(|(((address, encoded), balance), witness)| {
            Ok(Sp1InitReserveEntry {
                address: address.clone(),
                encoded_address_le: fr_to_le_bytes(*encoded),
                balance: *balance,
                chain_balance_proof: convert_chain_proof(&witness.chain_balance_proof)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(Sp1InitStdin {
        chain_id: chain_id.to_string(),
        state_root: state_root.to_string(),
        session_id: session_id.to_string(),
        reserve_count: addresses.len(),
        alpha_le: fr_to_le_bytes(alpha),
        zeta_le: fr_to_le_bytes(zeta),
        p_zeta_le: fr_to_le_bytes(p_zeta),
        product_zeta_le: fr_to_le_bytes(product_zeta),
        balance_total,
        balance_blind_le: fr_to_le_bytes(balance_blind),
        shape_salt,
        eval_blind_le: fr_to_le_bytes(eval_blind),
        balance_value_base: crate::kzg_insert::point_to_io(balance_value_base),
        balance_blind_base: crate::kzg_insert::point_to_io(balance_blind_base),
        eval_value_base: crate::kzg_insert::point_to_io(eval_value_base),
        eval_blind_base: crate::kzg_insert::point_to_io(eval_blind_base),
        balance_commitment: crate::kzg_insert::point_to_io(balance_commitment),
        shape_commitment,
        eval_commitment: crate::kzg_insert::point_to_io(eval_commitment),
        commitment_params_digest_hex: commitment_params_digest(
            balance_value_base,
            balance_blind_base,
            eval_value_base,
            eval_blind_base,
        ),
        reserves,
    })
}

pub fn build_init_ownership_stdin(
    chain_id: &str,
    state_root: &str,
    session_id: &str,
    addresses: &[String],
    balances: &[i128],
    witnesses: &[&InitReserveWitness],
) -> Result<Sp1InitOwnershipStdin, String> {
    if addresses.len() != balances.len() || addresses.len() != witnesses.len() {
        return Err("init ownership SP1 stdin vector length mismatch".to_string());
    }
    let reserves = addresses
        .iter()
        .zip(balances.iter())
        .zip(witnesses.iter())
        .map(|((address, balance), witness)| {
            Ok(Sp1InitOwnershipEntry {
                address: address.clone(),
                balance: *balance,
                ownership: convert_ownership(&witness.ownership)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(Sp1InitOwnershipStdin {
        chain_id: chain_id.to_string(),
        state_root: state_root.to_string(),
        session_id: session_id.to_string(),
        reserves,
    })
}

pub fn commitment_params_digest(
    balance_value: &G1Projective,
    balance_blind: &G1Projective,
    eval_value: &G1Projective,
    eval_blind: &G1Projective,
) -> String {
    let points = [balance_value, balance_blind, eval_value, eval_blind]
        .into_iter()
        .map(crate::kzg_insert::point_to_io)
        .collect::<Vec<Sp1G1Affine>>();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"dynamic-poa-init-commitment-params-v2-salted-shape-hash");
    for point in &points {
        hasher.update(&point.x_be);
        hasher.update(&point.y_be);
    }
    hex_encode(hasher.finalize().as_bytes())
}

pub fn shape_commitment(alpha: Fr, roots: &[Fr], salt: &[u8; 32]) -> [u8; 32] {
    sp1_programs_common::io::init_shape_commitment(
        salt,
        &fr_to_le_bytes(alpha),
        roots.len(),
        roots.iter().copied().map(fr_to_le_bytes),
    )
}

pub(crate) fn convert_ownership(
    value: &OwnershipWitnessInput,
) -> Result<Sp1OwnershipWitness, String> {
    match value {
        OwnershipWitnessInput::MockPrivateKey { mock_private_key } => {
            Ok(Sp1OwnershipWitness::MockPrivateKey {
                private_key: mock_private_key.clone(),
            })
        }
        OwnershipWitnessInput::EthereumEoaSignatureHex { signature_hex } => {
            let bytes = hex_decode(signature_hex)?;
            if bytes.len() != 65 {
                return Err("Ethereum ownership signature must contain 65 bytes".to_string());
            }
            let r: [u8; 32] = bytes[..32]
                .try_into()
                .map_err(|_| "invalid Ethereum ownership signature r".to_string())?;
            let s: [u8; 32] = bytes[32..64]
                .try_into()
                .map_err(|_| "invalid Ethereum ownership signature s".to_string())?;
            let recovery_id = match bytes[64] {
                0 | 1 => bytes[64],
                27 | 28 => bytes[64] - 27,
                _ => return Err("Ethereum signature recovery id must be 0/1 or 27/28".to_string()),
            };
            Ok(Sp1OwnershipWitness::EthereumEoaSignature { r, s, recovery_id })
        }
        OwnershipWitnessInput::ExternalOwnershipProof { scheme, .. } => {
            Ok(Sp1OwnershipWitness::UnsupportedExternal {
                scheme: scheme.clone(),
            })
        }
    }
}

pub(crate) fn convert_chain_proof(
    value: &ChainBalanceProofInput,
) -> Result<Sp1ChainBalanceProof, String> {
    match value {
        ChainBalanceProofInput::Mock { proof_label } => Ok(Sp1ChainBalanceProof::MockBinding {
            proof_label: proof_label.clone(),
        }),
        ChainBalanceProofInput::BinaryMerkleV1 {
            leaf_index,
            siblings,
            ..
        } => Ok(Sp1ChainBalanceProof::BinaryMerkleV1 {
            leaf_index: *leaf_index,
            siblings: siblings.clone(),
        }),
        ChainBalanceProofInput::EthereumAccountProof {
            account_proof_rlp_hex,
            ..
        } => Ok(Sp1ChainBalanceProof::EthereumAccountProof {
            nodes: account_proof_rlp_hex
                .iter()
                .map(|node| hex_decode(node))
                .collect::<Result<Vec<_>, _>>()?,
        }),
        ChainBalanceProofInput::GenericMerkleProof { proof_system, .. } => {
            Ok(Sp1ChainBalanceProof::UnsupportedGeneric {
                proof_system: proof_system.clone(),
            })
        }
        ChainBalanceProofInput::EthereumVerkleBatchMember {
            tree_key,
            basic_data,
            ..
        } => Ok(Sp1ChainBalanceProof::EthereumVerkleBatchMember {
            tree_key: *tree_key,
            basic_data: *basic_data,
        }),
        ChainBalanceProofInput::EthereumVerkleProof {
            tree_key,
            basic_data,
            proof,
            ..
        } => Ok(Sp1ChainBalanceProof::EthereumVerkleProof {
            tree_key: *tree_key,
            basic_data: *basic_data,
            proof: proof.clone(),
        }),
    }
}

fn sp1_context() -> Result<Sp1InitContext, String> {
    let slot = SP1_INIT_CONTEXT.get_or_init(|| Mutex::new(None));
    let mut guard = slot
        .lock()
        .map_err(|_| "sp1 init context poisoned".to_string())?;
    if let Some(ctx) = guard.as_ref() {
        return Ok(ctx.clone());
    }
    let setup_dir = default_setup_dir();
    let prover = ProverClient::builder().cpu().build();
    let vk = load_init_vk(&setup_dir, INIT_ELF)?;
    let pk = sp1_sdk::SP1ProvingKey::new(vk, INIT_ELF);
    let ctx = Sp1InitContext {
        prover,
        pk: Arc::new(pk),
    };
    *guard = Some(ctx.clone());
    Ok(ctx)
}

fn sp1_ownership_context() -> Result<Sp1InitContext, String> {
    let slot = SP1_INIT_OWNERSHIP_CONTEXT.get_or_init(|| Mutex::new(None));
    let mut guard = slot
        .lock()
        .map_err(|_| "sp1 init ownership context poisoned".to_string())?;
    if let Some(ctx) = guard.as_ref() {
        return Ok(ctx.clone());
    }
    let setup_dir = default_setup_dir();
    let prover = ProverClient::builder().cpu().build();
    let vk = load_init_ownership_vk(&setup_dir, INIT_OWNERSHIP_ELF)?;
    let pk = sp1_sdk::SP1ProvingKey::new(vk, INIT_OWNERSHIP_ELF);
    let ctx = Sp1InitContext {
        prover,
        pk: Arc::new(pk),
    };
    *guard = Some(ctx.clone());
    Ok(ctx)
}

fn run_sp1_proof<T: serde::Serialize>(
    ctx: &Sp1InitContext,
    stdin_value: &T,
    label: &str,
) -> Result<SP1ProofWithPublicValues, String> {
    let mut stdin = SP1Stdin::new();
    stdin.write(stdin_value);
    let request = ctx.prover.prove(&ctx.pk, stdin);
    let result = match configured_proof_mode()? {
        ConfiguredProofMode::Groth16 => request.groth16().run(),
        ConfiguredProofMode::Plonk => request.plonk().run(),
        ConfiguredProofMode::Compressed => request.compressed().run(),
    };
    result.map_err(|err| format!("sp1 {label} prove failed: {err}"))
}

fn decode_public_values(bundle: &SP1ProofWithPublicValues) -> Sp1InitPublicValues {
    let mut public_values = bundle.public_values.clone();
    public_values.read::<Sp1InitPublicValues>()
}

fn decode_ownership_public_values(
    bundle: &SP1ProofWithPublicValues,
) -> Sp1InitOwnershipPublicValues {
    let mut public_values = bundle.public_values.clone();
    public_values.read::<Sp1InitOwnershipPublicValues>()
}

fn serialize_sp1_proof(bundle: &SP1ProofWithPublicValues) -> Result<String, String> {
    let bytes =
        bincode::serialize(bundle).map_err(|err| format!("serialize sp1 init proof: {err}"))?;
    Ok(hex_encode(&bytes))
}

fn deserialize_sp1_proof(value: &str) -> Result<SP1ProofWithPublicValues, String> {
    let bytes = hex_decode(value)?;
    bincode::deserialize(&bytes).map_err(|err| format!("deserialize sp1 init proof: {err}"))
}

fn serialize_sp1_vk(ctx: &Sp1InitContext) -> Result<String, String> {
    let bytes = bincode::serialize(ctx.pk.verifying_key())
        .map_err(|err| format!("serialize sp1 init vk: {err}"))?;
    Ok(hex_encode(&bytes))
}

fn fr_to_le_bytes(value: Fr) -> [u8; 32] {
    let raw = value.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    let len = raw.len().min(32);
    out[..len].copy_from_slice(&raw[..len]);
    out
}
