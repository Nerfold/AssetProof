use common::crypto::hash_bytes;
use common::types::{
    ChainBalanceProofInput, InitProvingContext, InitReserveWitness, OwnershipWitnessInput,
    PreparedChainBalanceWitness, PreparedInitReserveWitness, PreparedOwnershipWitness, SyncProof,
};

pub trait ExternalProofAdapter {
    fn prepare_init_witness(
        &self,
        ctx: &InitProvingContext,
        witness: &InitReserveWitness,
    ) -> Result<PreparedInitReserveWitness, String>;

    fn verify_insert_ownership(
        &self,
        state_root: &str,
        address: &str,
        artifact: &ExternalProofArtifact,
    ) -> Result<PreparedOwnershipWitness, String>;

    fn verify_insert_balance(
        &self,
        state_root: &str,
        address: &str,
        balance: i128,
        artifact: &ExternalProofArtifact,
    ) -> Result<PreparedChainBalanceWitness, String>;

    fn verify_sync(
        &self,
        old_state_root: &str,
        new_state_root: &str,
        delta_list_commitment_hex: &str,
        proof: &SyncProof,
    ) -> Result<(), String>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalProofArtifact {
    pub scheme: String,
    pub payload_hex: String,
}

impl ExternalProofArtifact {
    pub fn mock(payload: impl Into<String>) -> Self {
        Self {
            scheme: "mock".to_string(),
            payload_hex: payload.into(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MockExternalProofAdapter;

impl ExternalProofAdapter for MockExternalProofAdapter {
    fn prepare_init_witness(
        &self,
        ctx: &InitProvingContext,
        witness: &InitReserveWitness,
    ) -> Result<PreparedInitReserveWitness, String> {
        let ownership = prepare_ownership(ctx, witness)?;
        let chain_balance = prepare_chain_balance(ctx, witness)?;
        Ok(PreparedInitReserveWitness {
            address: witness.address.clone(),
            balance: witness.balance,
            ownership,
            chain_balance,
        })
    }

    fn verify_insert_ownership(
        &self,
        state_root: &str,
        address: &str,
        artifact: &ExternalProofArtifact,
    ) -> Result<PreparedOwnershipWitness, String> {
        if artifact.scheme != "mock" && artifact.scheme != "mock-private-key" {
            return Err("mock adapter received non-mock ownership artifact".to_string());
        }
        if !artifact.payload_hex.is_empty() && !artifact.payload_hex.contains(address) {
            return Err("mock ownership witness rejected".to_string());
        }
        Ok(PreparedOwnershipWitness {
            scheme: "mock-insert-ownership".to_string(),
            proof_digest_hex: hex_hash(
                "mock-insert-ownership",
                &[
                    state_root.as_bytes(),
                    address.as_bytes(),
                    artifact.payload_hex.as_bytes(),
                ],
            ),
        })
    }

    fn verify_insert_balance(
        &self,
        state_root: &str,
        address: &str,
        balance: i128,
        artifact: &ExternalProofArtifact,
    ) -> Result<PreparedChainBalanceWitness, String> {
        if artifact.scheme != "mock" && artifact.scheme != "mock-chain-balance-proof" {
            return Err("mock adapter received non-mock balance artifact".to_string());
        }
        if !artifact.payload_hex.is_empty()
            && !(artifact.payload_hex.contains(state_root)
                && artifact.payload_hex.contains(address)
                || artifact.payload_hex.ends_with(&balance.to_string()))
        {
            return Err("mock chain balance witness rejected".to_string());
        }
        Ok(PreparedChainBalanceWitness {
            scheme: "mock-insert-chain-balance".to_string(),
            proof_digest_hex: hex_hash(
                "mock-insert-chain-balance",
                &[
                    state_root.as_bytes(),
                    address.as_bytes(),
                    &balance.to_le_bytes(),
                    artifact.payload_hex.as_bytes(),
                ],
            ),
        })
    }

    fn verify_sync(
        &self,
        old_state_root: &str,
        new_state_root: &str,
        delta_list_commitment_hex: &str,
        proof: &SyncProof,
    ) -> Result<(), String> {
        if proof.old_state_root != old_state_root || proof.new_state_root != new_state_root {
            return Err("sync proof state root mismatch".to_string());
        }
        if proof.delta_list_commitment_hex != delta_list_commitment_hex {
            return Err("sync proof delta commitment mismatch".to_string());
        }
        match proof.scheme.as_str() {
            "mock-canonical-sync" | "external-canonical-sync" if !proof.proof_hex.is_empty() => {
                Ok(())
            }
            _ => Err("missing accepted canonical Sync proof".to_string()),
        }
    }
}

fn prepare_ownership(
    ctx: &InitProvingContext,
    witness: &InitReserveWitness,
) -> Result<PreparedOwnershipWitness, String> {
    Ok(match &witness.ownership {
        OwnershipWitnessInput::MockPrivateKey { mock_private_key } => PreparedOwnershipWitness {
            scheme: "mock-private-key".to_string(),
            proof_digest_hex: hex_hash(
                "mock-private-key-ownership",
                &[
                    ctx.chain_id.as_bytes(),
                    ctx.state_root.as_bytes(),
                    ctx.session_id.as_bytes(),
                    witness.address.as_bytes(),
                    mock_private_key.as_bytes(),
                ],
            ),
        },
        OwnershipWitnessInput::EthereumEoaPrivateKeyHex { private_key_hex } => {
            PreparedOwnershipWitness {
                scheme: "ethereum-eoa-secp256k1".to_string(),
                proof_digest_hex: hex_hash(
                    "ethereum-eoa-private-key-binding",
                    &[
                        ctx.chain_id.as_bytes(),
                        ctx.state_root.as_bytes(),
                        ctx.session_id.as_bytes(),
                        witness.address.as_bytes(),
                        private_key_hex.as_bytes(),
                    ],
                ),
            }
        }
        OwnershipWitnessInput::ExternalOwnershipProof { scheme, proof_hex } => {
            PreparedOwnershipWitness {
                scheme: scheme.clone(),
                proof_digest_hex: hex_hash(
                    "external-ownership-proof",
                    &[
                        scheme.as_bytes(),
                        proof_hex.as_bytes(),
                        witness.address.as_bytes(),
                    ],
                ),
            }
        }
    })
}

fn prepare_chain_balance(
    ctx: &InitProvingContext,
    witness: &InitReserveWitness,
) -> Result<PreparedChainBalanceWitness, String> {
    Ok(match &witness.chain_balance_proof {
        ChainBalanceProofInput::Mock { proof_label } => PreparedChainBalanceWitness {
            scheme: "mock-chain-balance-proof".to_string(),
            proof_digest_hex: hex_hash(
                "mock-chain-balance-proof",
                &[
                    ctx.chain_id.as_bytes(),
                    ctx.state_root.as_bytes(),
                    witness.address.as_bytes(),
                    &witness.balance.to_le_bytes(),
                    proof_label.as_bytes(),
                ],
            ),
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
                proof_digest_hex: hex_hash(
                    "ethereum-account-proof",
                    &[
                        &nodes,
                        witness.address.as_bytes(),
                        &witness.balance.to_le_bytes(),
                    ],
                ),
            }
        }
        ChainBalanceProofInput::GenericMerkleProof {
            chain_id,
            proof_system,
            proof_payload_hex,
            public_inputs_hex,
        } => PreparedChainBalanceWitness {
            scheme: format!("generic:{proof_system}"),
            proof_digest_hex: hex_hash(
                "generic-chain-balance-proof",
                &[
                    chain_id.as_bytes(),
                    proof_system.as_bytes(),
                    witness.address.as_bytes(),
                    &witness.balance.to_le_bytes(),
                    proof_payload_hex.as_bytes(),
                    public_inputs_hex.as_bytes(),
                ],
            ),
        },
        ChainBalanceProofInput::BinaryMerkleV1 {
            chain_id,
            leaf_index,
            siblings_hex,
        } => {
            let mut path = Vec::new();
            for sibling in siblings_hex {
                path.extend_from_slice(sibling.as_bytes());
                path.push(b'|');
            }
            PreparedChainBalanceWitness {
                scheme: "binary-merkle-v1".to_string(),
                proof_digest_hex: hex_hash(
                    "binary-merkle-v1",
                    &[
                        chain_id.as_bytes(),
                        ctx.state_root.as_bytes(),
                        witness.address.as_bytes(),
                        &witness.balance.to_le_bytes(),
                        &leaf_index.to_le_bytes(),
                        &path,
                    ],
                ),
            }
        }
    })
}

fn hex_hash(label: &str, chunks: &[&[u8]]) -> String {
    common::crypto::hex_encode(&hash_bytes(label, chunks))
}
