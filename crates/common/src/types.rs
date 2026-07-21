use ark_bls12_381::Fr;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReserveEntry {
    pub address: String,
    pub balance: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitProvingContext {
    pub chain_id: String,
    pub state_root: String,
    pub session_id: String,
    /// Optional shared state-tree proof used to authenticate the entire
    /// ordered reserve prefix without repeating one Merkle path per account.
    pub chain_batch_proof: Option<InitChainBatchProofInput>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InitChainBatchProofInput {
    BinaryMerklePrefixV2 {
        depth: usize,
        suffix_subtrees: Vec<(u32, [u8; 32])>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitReserveWitness {
    pub address: String,
    pub balance: i128,
    pub ownership: OwnershipWitnessInput,
    pub chain_balance_proof: ChainBalanceProofInput,
}

impl InitReserveWitness {
    pub fn mock(address: String, balance: i128, mock_private_key: String) -> Self {
        Self {
            address: address.clone(),
            balance,
            ownership: OwnershipWitnessInput::MockPrivateKey { mock_private_key },
            chain_balance_proof: ChainBalanceProofInput::Mock {
                proof_label: format!("mock-balance-proof:{address}"),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnershipWitnessInput {
    MockPrivateKey {
        mock_private_key: String,
    },
    /// A canonical Ethereum recoverable ECDSA signature encoded as
    /// `r[32] || s[32] || y_parity[1]`. The signed statement is reconstructed
    /// from the protocol operation, chain id, state root, and account address.
    EthereumEoaSignatureHex {
        signature_hex: String,
    },
    ExternalOwnershipProof {
        scheme: String,
        proof_hex: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainBalanceProofInput {
    Mock {
        proof_label: String,
    },
    EthereumAccountProof {
        chain_id: String,
        block_number: u64,
        block_hash_hex: String,
        account_proof_rlp_hex: Vec<String>,
    },
    GenericMerkleProof {
        chain_id: String,
        proof_system: String,
        proof_payload_hex: String,
        public_inputs_hex: String,
    },
    BinaryMerkleV1 {
        chain_id: String,
        leaf_index: u64,
        siblings: Vec<[u8; 32]>,
    },
    /// One key/value opening authenticated by the shared initialization
    /// multiproof in [`EthereumVerkleBatchProofInput`].
    EthereumVerkleBatchMember {
        chain_id: String,
        tree_key: [u8; 32],
        basic_data: [u8; 32],
    },
    /// A self-contained EIP-6800-style Verkle opening. This form is used by
    /// insertion, where only one account is authenticated.
    EthereumVerkleProof {
        chain_id: String,
        tree_key: [u8; 32],
        basic_data: [u8; 32],
        proof: Vec<u8>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthereumVerkleBatchProofInput {
    pub root_commitment: [u8; 32],
    pub proof: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedOwnershipWitness {
    pub scheme: String,
    pub proof_digest_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedChainBalanceWitness {
    pub scheme: String,
    pub proof_digest_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedInitReserveWitness {
    pub address: String,
    pub balance: i128,
    pub ownership: PreparedOwnershipWitness,
    pub chain_balance: PreparedChainBalanceWitness,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delta {
    pub address: String,
    pub delta: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncProof {
    pub scheme: String,
    pub chain_id: String,
    pub old_state_root: String,
    pub new_state_root: String,
    pub delta_list_commitment_hex: String,
    pub proof_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealSrsMeta {
    pub max_degree: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredState {
    pub state_root: String,
    pub srs_max_degree: usize,
    pub alpha: Fr,
    pub reserve_addresses: Vec<String>,
    pub reserve_balances: Vec<i128>,
    pub masked_polynomial_coeffs: Vec<Fr>,
    pub accumulator_hex: String,
    pub balance_total: i128,
    pub balance_blind: Fr,
    pub balance_commitment_hex: String,
}

pub type ProverState = StoredState;

impl StoredState {
    pub fn public_state(&self) -> PublicState {
        PublicState {
            state_root: self.state_root.clone(),
            srs_max_degree: self.srs_max_degree,
            reserve_count: self.reserve_addresses.len(),
            accumulator_hex: self.accumulator_hex.clone(),
            balance_commitment_hex: self.balance_commitment_hex.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicState {
    pub state_root: String,
    pub srs_max_degree: usize,
    pub reserve_count: usize,
    pub accumulator_hex: String,
    pub balance_commitment_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredInitProof {
    pub scheme: String,
    pub mode: String,
    pub chain_id: String,
    pub state_root: String,
    pub session_id: String,
    pub accumulator_hex: String,
    pub balance_commitment_hex: String,
    /// A 32-byte salted BLAKE3 commitment to `(alpha, ordered address roots)`.
    /// The private salt and preimage are checked inside the SP1 initialization proof.
    pub c_shape_hex: String,
    pub c_y_hex: String,
    pub reserve_count: usize,
    pub zeta: Fr,
    pub kzg_opening_proof_hex: String,
    /// Merkle-balance/polynomial SP1 proof.
    pub sp1_proof_hex: String,
    pub sp1_vk_hex: String,
    pub sp1_public_values_hex: String,
    /// Separate ECDSA ownership SP1 proof, bound to the Merkle guest by the
    /// same ordered reserve commitment.
    pub ownership_sp1_proof_hex: String,
    pub ownership_sp1_vk_hex: String,
    pub ownership_sp1_public_values_hex: String,
    pub transcript_hex: String,
    pub srs_hash_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredProof {
    pub old_state_root: String,
    pub new_state_root: String,
    pub delta_list_commitment_hex: String,
    pub c_u_hex: String,
    /// The unique Pedersen commitment D_Y to all hidden KZG evaluations.
    /// MultiZKOpen and the Bulletproof relation consume this same group element.
    pub d_y_hex: String,
    pub c_d_hex: String,
    /// Fiat--Shamir MultiZKOpen proof encoded as canonical binary hex.
    pub multi_zkopen_proof_hex: String,
    pub gate_count: usize,
    pub transcript_hex: String,
    pub bp_proof_hex: String,
    /// Links D_Y and C_U directly to the Bulletproof phase-one witness wires.
    pub committed_input_link_ipa_proof: Vec<u8>,
    pub projection_ipa_proof: Vec<u8>,
    /// Bulletproof proving that the updated aggregate balance commitment opens
    /// to a value in the protocol's accepted nonnegative integer range.
    pub balance_range_proof_hex: String,
}

pub type PublicUpdateProof = StoredProof;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredParallelShardState {
    pub shard_id: usize,
    pub alpha: Fr,
    pub reserve_addresses: Vec<String>,
    pub reserve_balances: Vec<i128>,
    pub masked_polynomial_coeffs: Vec<Fr>,
    pub accumulator_hex: String,
    pub balance_total: i128,
    pub balance_blind: Fr,
    pub balance_commitment_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredParallelState {
    pub state_root: String,
    pub srs_max_degree: usize,
    pub shards: Vec<StoredParallelShardState>,
    pub balance_total: i128,
    pub balance_blind: Fr,
    pub balance_commitment_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredParallelShardProof {
    pub shard_id: usize,
    pub c_u_hex: String,
    pub c_y_hex: String,
    pub eval_proof_hex: String,
    pub r_u: Fr,
    pub rho_y: Fr,
    pub d_value: i128,
    pub gate_count: usize,
    pub bp_proof_hex: String,
    pub bp_commitments_hex: String,
    pub link_proof_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredParallelProof {
    pub old_state_root: String,
    pub new_state_root: String,
    pub shard_proofs: Vec<StoredParallelShardProof>,
    pub c_u_hex: String,
    pub c_d_hex: String,
    pub d_value: i128,
    pub r_u: Fr,
    pub r_d: Fr,
    pub projection_ipa_proof: Vec<u8>,
    pub transcript_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredParallelInitProof {
    pub state_root: String,
    pub shard_proofs: Vec<StoredInitProof>,
    pub balance_total: i128,
    pub balance_blind: Fr,
    pub balance_commitment_hex: String,
    pub transcript_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmtLeafRecord {
    pub address: String,
    pub balance: i128,
    pub salt_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmtNodeRecord {
    pub level: usize,
    pub index: u128,
    pub hash_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredSmtState {
    pub state_root: String,
    pub smt_root_hex: String,
    pub depth: usize,
    pub balance_total: i128,
    pub balance_blind: Fr,
    pub balance_commitment_hex: String,
    pub leaves: Vec<SmtLeafRecord>,
    pub nodes: Vec<SmtNodeRecord>,
    pub nodes_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredSmtInitProof {
    pub scheme: String,
    pub mode: String,
    pub chain_id: String,
    pub state_root: String,
    pub session_id: String,
    pub depth: usize,
    pub smt_root_hex: String,
    pub balance_total: i128,
    pub reserve_count: usize,
    pub reserve_commitment_hex: String,
    pub uses_mock_inputs: bool,
    pub proof_digest_hex: String,
    pub sp1_proof_hex: String,
    pub ownership_sp1_proof_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredSmtProof {
    pub scheme: String,
    pub mode: String,
    pub old_state_root: String,
    pub new_state_root: String,
    pub old_smt_root_hex: String,
    pub new_smt_root_hex: String,
    pub aggregate_delta: i128,
    pub balance_blind_delta: Fr,
    pub old_balance_commitment_hex: String,
    pub new_balance_commitment_hex: String,
    pub proof_digest_hex: String,
    pub transition_commitment_hex: String,
    pub witness_hex: String,
    pub touched_addresses: Vec<String>,
    pub membership_flags: Vec<u8>,
    pub sp1_proof_hex: String,
    pub sp1_vk_hex: String,
    pub sp1_public_values_hex: String,
}
