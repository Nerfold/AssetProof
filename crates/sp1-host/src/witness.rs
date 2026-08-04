use common::crypto::hex_decode;
use common::types::{ChainBalanceProofInput, OwnershipWitnessInput};
use sp1_programs_common::io::{Sp1ChainBalanceProof, Sp1OwnershipWitness};

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
