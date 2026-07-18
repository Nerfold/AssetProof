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

    fn validate_init_witness(
        &self,
        ctx: &InitProvingContext,
        witness: &InitReserveWitness,
    ) -> Result<(), String> {
        let prepared = self.prepare_init_witness(ctx, witness)?;
        if prepared.address != witness.address || prepared.balance != witness.balance {
            return Err("external adapter changed the reserve address or balance".to_string());
        }
        Ok(())
    }

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

/// Host-side binder for ownership and native chain proofs that are verified
/// inside the SP1 initialization/insert guest. This adapter does not claim to
/// verify those private witnesses outside SP1; it only commits their public
/// artifact labels into the outer transcript.
#[derive(Clone, Debug, Default)]
pub struct Sp1NativeProofAdapter;

#[derive(Clone, Debug)]
pub struct PinnedSyncProofAdapter {
    pub expected_scheme: String,
    pub expected_proof_hex: String,
}

impl ExternalProofAdapter for PinnedSyncProofAdapter {
    fn prepare_init_witness(
        &self,
        _ctx: &InitProvingContext,
        _witness: &InitReserveWitness,
    ) -> Result<PreparedInitReserveWitness, String> {
        Err("pinned Sync adapter cannot prepare initialization witnesses".to_string())
    }

    fn verify_insert_ownership(
        &self,
        _state_root: &str,
        _address: &str,
        _artifact: &ExternalProofArtifact,
    ) -> Result<PreparedOwnershipWitness, String> {
        Err("pinned Sync adapter cannot verify insertion ownership".to_string())
    }

    fn verify_insert_balance(
        &self,
        _state_root: &str,
        _address: &str,
        _balance: i128,
        _artifact: &ExternalProofArtifact,
    ) -> Result<PreparedChainBalanceWitness, String> {
        Err("pinned Sync adapter cannot verify insertion balances".to_string())
    }

    fn verify_sync(
        &self,
        old_state_root: &str,
        new_state_root: &str,
        delta_list_commitment_hex: &str,
        proof: &SyncProof,
    ) -> Result<(), String> {
        if proof.old_state_root != old_state_root
            || proof.new_state_root != new_state_root
            || proof.delta_list_commitment_hex != delta_list_commitment_hex
        {
            return Err("pinned Sync public statement mismatch".to_string());
        }
        if proof.scheme != self.expected_scheme || proof.proof_hex != self.expected_proof_hex {
            return Err("Sync proof is not the transition artifact pinned by policy".to_string());
        }
        if proof.proof_hex.is_empty() {
            return Err("pinned Sync proof must not be empty".to_string());
        }
        Ok(())
    }
}

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
            "mock-canonical-sync" if !proof.proof_hex.is_empty() => Ok(()),
            _ => Err("missing accepted canonical Sync proof".to_string()),
        }
    }
}

impl ExternalProofAdapter for Sp1NativeProofAdapter {
    fn prepare_init_witness(
        &self,
        ctx: &InitProvingContext,
        witness: &InitReserveWitness,
    ) -> Result<PreparedInitReserveWitness, String> {
        Ok(PreparedInitReserveWitness {
            address: witness.address.clone(),
            balance: witness.balance,
            ownership: prepare_ownership(ctx, witness)?,
            chain_balance: prepare_chain_balance(ctx, witness)?,
        })
    }

    fn validate_init_witness(
        &self,
        _ctx: &InitProvingContext,
        witness: &InitReserveWitness,
    ) -> Result<(), String> {
        // The native ownership and chain witnesses are consumed and bound by
        // the two SP1 proofs themselves. Avoid building two unused host-side
        // digest strings per account in the initialization hot path.
        validate_sp1_native_init_types(witness)
    }

    fn verify_insert_ownership(
        &self,
        state_root: &str,
        address: &str,
        artifact: &ExternalProofArtifact,
    ) -> Result<PreparedOwnershipWitness, String> {
        if artifact.scheme != "sp1-native-ownership" {
            return Err("SP1-native insert requires an sp1-native-ownership artifact".to_string());
        }
        Ok(PreparedOwnershipWitness {
            scheme: artifact.scheme.clone(),
            proof_digest_hex: hex_hash(
                "sp1-native-insert-ownership",
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
        if artifact.scheme != "sp1-native-chain-balance" {
            return Err(
                "SP1-native insert requires an sp1-native-chain-balance artifact".to_string(),
            );
        }
        Ok(PreparedChainBalanceWitness {
            scheme: artifact.scheme.clone(),
            proof_digest_hex: hex_hash(
                "sp1-native-insert-chain-balance",
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
        _old_state_root: &str,
        _new_state_root: &str,
        _delta_list_commitment_hex: &str,
        _proof: &SyncProof,
    ) -> Result<(), String> {
        Err("SP1-native witness adapter cannot verify Sync transitions".to_string())
    }
}

fn validate_sp1_native_init_types(witness: &InitReserveWitness) -> Result<(), String> {
    match &witness.ownership {
        OwnershipWitnessInput::EthereumEoaSignatureHex { .. }
        | OwnershipWitnessInput::MockPrivateKey { .. } => {}
        OwnershipWitnessInput::ExternalOwnershipProof { .. } => {
            return Err("unsupported external ownership witness".to_string())
        }
    }
    if matches!(
        &witness.chain_balance_proof,
        ChainBalanceProofInput::GenericMerkleProof { .. }
    ) {
        return Err("unsupported generic chain balance proof".to_string());
    }
    Ok(())
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
        OwnershipWitnessInput::EthereumEoaSignatureHex { signature_hex } => {
            PreparedOwnershipWitness {
                scheme: "ethereum-eoa-ecdsa-recoverable-v1".to_string(),
                proof_digest_hex: hex_hash(
                    "ethereum-eoa-ownership-signature",
                    &[
                        ctx.chain_id.as_bytes(),
                        ctx.state_root.as_bytes(),
                        witness.address.as_bytes(),
                        signature_hex.as_bytes(),
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
            siblings,
        } => {
            let path = siblings.iter().flatten().copied().collect::<Vec<_>>();
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
        ChainBalanceProofInput::EthereumVerkleBatchMember {
            chain_id,
            tree_key,
            basic_data,
        } => PreparedChainBalanceWitness {
            scheme: "ethereum-verkle-batch-member-v1".to_string(),
            proof_digest_hex: hex_hash(
                "ethereum-verkle-batch-member-v1",
                &[
                    chain_id.as_bytes(),
                    ctx.state_root.as_bytes(),
                    witness.address.as_bytes(),
                    &witness.balance.to_le_bytes(),
                    tree_key,
                    basic_data,
                ],
            ),
        },
        ChainBalanceProofInput::EthereumVerkleProof {
            chain_id,
            tree_key,
            basic_data,
            proof,
        } => PreparedChainBalanceWitness {
            scheme: "ethereum-verkle-proof-v1".to_string(),
            proof_digest_hex: hex_hash(
                "ethereum-verkle-proof-v1",
                &[
                    chain_id.as_bytes(),
                    ctx.state_root.as_bytes(),
                    witness.address.as_bytes(),
                    &witness.balance.to_le_bytes(),
                    tree_key,
                    basic_data,
                    proof,
                ],
            ),
        },
    })
}

fn hex_hash(label: &str, chunks: &[&[u8]]) -> String {
    common::crypto::hex_encode(&hash_bytes(label, chunks))
}
