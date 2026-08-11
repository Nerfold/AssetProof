use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::ethereum_eoa::Keccak256Stream;

pub type Hash = [u8; 32];

/// Commits to the ordered initialization roots before deriving the Fiat--Shamir
/// evaluation point. The salt is a private SP1 witness; only the digest is
/// public. Keeping this encoder in the shared crate prevents host/guest
/// transcript drift without materializing another copy of the root vector.
pub fn init_shape_commitment<I>(
    salt: &Hash,
    alpha_le: &Hash,
    root_count: usize,
    roots_le: I,
) -> Hash
where
    I: IntoIterator<Item = Hash>,
{
    let mut hasher = Keccak256Stream::new();
    hasher.update(b"dynamic-poa-init-shape-salted-keccak-v2");
    hasher.update(salt);
    hasher.update(&(root_count as u64).to_le_bytes());
    hasher.update(alpha_le);

    let mut encoded_count = 0usize;
    for root_le in roots_le {
        hasher.update(&root_le);
        encoded_count += 1;
    }
    assert_eq!(encoded_count, root_count, "shape root count mismatch");

    hasher.finalize()
}

/// Binds the unified initialization witness to its exact ordered
/// `(address, balance)` vector.
pub fn init_reserve_commitment<'a, I>(reserve_count: usize, reserves: I) -> Hash
where
    I: IntoIterator<Item = (&'a str, i128)>,
{
    let mut commitment = InitReserveCommitment::new(reserve_count);
    for (address, balance) in reserves {
        commitment.update(address, balance);
    }
    commitment.finalize()
}

/// Streaming form used by initialization guests to bind each reserve during
/// the validation scan instead of traversing the full witness vector again.
pub struct InitReserveCommitment {
    hasher: Keccak256Stream,
    expected_count: usize,
    encoded_count: usize,
}

impl InitReserveCommitment {
    pub fn new(reserve_count: usize) -> Self {
        let mut hasher = Keccak256Stream::new();
        hasher.update(b"dynamic-poa-init-reserves-keccak-v2");
        hasher.update(&(reserve_count as u64).to_le_bytes());
        Self {
            hasher,
            expected_count: reserve_count,
            encoded_count: 0,
        }
    }

    pub fn update(&mut self, address: &str, balance: i128) {
        self.hasher.update(&(address.len() as u64).to_le_bytes());
        self.hasher.update(address.as_bytes());
        self.hasher.update(&balance.to_le_bytes());
        self.encoded_count += 1;
    }

    pub fn finalize(self) -> Hash {
        assert_eq!(
            self.encoded_count, self.expected_count,
            "reserve count mismatch"
        );
        self.hasher.finalize()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1G1Affine {
    pub x_be: Vec<u8>,
    pub y_be: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sp1SiblingRef {
    Default,
    Frontier(usize),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1DefaultNonMembershipProof {
    pub default_depth: usize,
    pub siblings: Vec<Sp1SiblingRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1CollisionNonMembershipProof {
    pub collision_leaf: Sp1Leaf,
    pub siblings: Vec<Sp1SiblingRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sp1NonMembershipProof {
    Default(Sp1DefaultNonMembershipProof),
    Collision(Sp1CollisionNonMembershipProof),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1Leaf {
    pub key: Hash,
    pub balance: i128,
    pub salt: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1MembershipProof {
    pub siblings: Vec<Sp1SiblingRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sp1AddressProof {
    Membership(Sp1MembershipProof),
    NonMembership(Sp1NonMembershipProof),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1UpdateEntryWitness {
    pub address: String,
    pub key: Hash,
    pub delta: i128,
    pub old_leaf: Option<Sp1Leaf>,
    pub proof: Sp1AddressProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1UpdateStdin {
    pub state_root: String,
    pub new_state_root: String,
    pub depth: usize,
    pub old_smt_root: Hash,
    pub old_balance_total: i128,
    pub old_leaf_count: usize,
    pub transition_salt: Hash,
    pub frontier_hashes: Vec<Hash>,
    pub entries: Vec<Sp1UpdateEntryWitness>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1UpdatePublicValues {
    pub old_state_root: String,
    pub new_state_root: String,
    pub depth: usize,
    pub old_smt_root: Hash,
    pub new_smt_root: Hash,
    pub aggregate_delta: i128,
    pub old_balance_total: i128,
    pub new_balance_total: i128,
    pub old_leaf_count: usize,
    pub new_leaf_count: usize,
    pub transition_commitment: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1InsertStdin {
    pub state_root: String,
    pub new_state_root: String,
    pub depth: usize,
    pub old_smt_root: Hash,
    pub old_balance_total: i128,
    pub old_leaf_count: usize,
    pub frontier_hashes: Vec<Hash>,
    pub address: String,
    pub key: Hash,
    pub balance: i128,
    pub salt: Hash,
    pub transition_salt: Hash,
    pub non_membership_proof: Sp1NonMembershipProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1InsertPublicValues {
    pub old_state_root: String,
    pub new_state_root: String,
    pub depth: usize,
    pub old_smt_root: Hash,
    pub new_smt_root: Hash,
    pub inserted_balance: i128,
    pub old_balance_total: i128,
    pub new_balance_total: i128,
    pub old_leaf_count: usize,
    pub new_leaf_count: usize,
    pub transition_commitment: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1InitReserveEntry {
    pub address: String,
    pub encoded_address_le: [u8; 32],
    pub balance: i128,
    pub ownership: Sp1OwnershipWitness,
    pub chain_balance_proof: Sp1ChainBalanceProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1SmtInitReserveEntry {
    pub address: String,
    pub balance: i128,
    pub chain_balance_proof: Sp1ChainBalanceProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1MerkleSubtree {
    pub level: u32,
    pub root: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1BinaryMerklePrefixProof {
    pub depth: usize,
    pub suffix_subtrees: Vec<Sp1MerkleSubtree>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1InitOwnershipEntry {
    pub address: String,
    pub balance: i128,
    pub ownership: Sp1OwnershipWitness,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1InitOwnershipStdin {
    pub chain_id: String,
    pub state_root: String,
    pub session_id: String,
    pub reserves: Vec<Sp1InitOwnershipEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1InitOwnershipPublicValues {
    pub chain_id: String,
    pub state_root: String,
    pub session_id: String,
    pub reserve_count: usize,
    pub reserve_commitment: Hash,
    pub uses_mock_inputs: bool,
}

/// One private reserve entry for the traditional static PoA baseline.
/// Unlike the dynamic initialization input, this contains no polynomial,
/// KZG, Pedersen, or update-state witness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1StaticInitReserveEntry {
    pub address: String,
    pub address_bytes: [u8; 20],
    pub balance: i128,
    pub ownership: Sp1OwnershipWitness,
    pub chain_balance_proof: Sp1ChainBalanceProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1StaticInitStdin {
    pub chain_id: String,
    pub state_root: String,
    pub session_id: String,
    pub reserves: Vec<Sp1StaticInitReserveEntry>,
    pub merkle_prefix_proof: Option<Sp1BinaryMerklePrefixProof>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1StaticInitPublicValues {
    pub chain_id: String,
    pub state_root: String,
    pub session_id: String,
    pub reserve_count: usize,
    pub reserve_commitment: Hash,
    pub balance_total: i128,
    pub uses_mock_inputs: bool,
}

/// Private input for the isolated Ethereum MPT account-proof benchmark.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1EthereumMptInput {
    pub state_root: Hash,
    pub address: [u8; 20],
    pub expected_balance: i128,
    pub proof_nodes: Vec<Vec<u8>>,
}

/// Private batch input for the isolated Ethereum MPT benchmark.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1EthereumMptBatchInput {
    pub proofs: Vec<Sp1EthereumMptInput>,
}

/// Public output binding every accepted account statement in a batch without
/// committing the much larger MPT witness itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1EthereumMptBatchPublicValues {
    pub statement_digest: Hash,
    pub proof_count: usize,
    pub proof_node_count: usize,
    pub proof_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sp1OwnershipWitness {
    MockPrivateKey {
        private_key: String,
    },
    EthereumEoaSignature {
        r: [u8; 32],
        s: [u8; 32],
        recovery_id: u8,
    },
    UnsupportedExternal {
        scheme: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sp1ChainBalanceProof {
    MockBinding {
        proof_label: String,
    },
    BinaryMerkleV1 {
        leaf_index: u64,
        siblings: Vec<Hash>,
    },
    EthereumAccountProof {
        nodes: Vec<Vec<u8>>,
    },
    EthereumVerkleBatchMember {
        tree_key: Hash,
        basic_data: Hash,
    },
    EthereumVerkleProof {
        tree_key: Hash,
        basic_data: Hash,
        proof: Vec<u8>,
    },
    UnsupportedGeneric {
        proof_system: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1InitStdin {
    pub chain_id: String,
    pub state_root: String,
    pub session_id: String,
    pub reserve_count: usize,
    pub alpha_le: [u8; 32],
    pub zeta_le: [u8; 32],
    pub p_zeta_le: [u8; 32],
    pub product_zeta_le: [u8; 32],
    pub balance_total: i128,
    pub balance_blind_le: [u8; 32],
    pub shape_salt: Hash,
    pub eval_blind_le: [u8; 32],
    pub balance_value_base: Sp1G1Affine,
    pub balance_blind_base: Sp1G1Affine,
    pub eval_value_base: Sp1G1Affine,
    pub eval_blind_base: Sp1G1Affine,
    pub balance_commitment: Sp1G1Affine,
    pub shape_commitment: Hash,
    pub eval_commitment: Sp1G1Affine,
    pub commitment_params_digest_hex: String,
    pub merkle_prefix_proof: Option<Sp1BinaryMerklePrefixProof>,
    pub reserves: Vec<Sp1InitReserveEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1InitPublicValues {
    pub chain_id: String,
    pub state_root: String,
    pub session_id: String,
    pub reserve_count: usize,
    pub reserve_commitment: Hash,
    pub zeta_le: [u8; 32],
    pub balance_commitment: Sp1G1Affine,
    pub shape_commitment: Hash,
    pub eval_commitment: Sp1G1Affine,
    pub commitment_params_digest_hex: String,
    pub uses_mock_inputs: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1SmtInitStdin {
    pub chain_id: String,
    pub state_root: String,
    pub session_id: String,
    pub depth: usize,
    pub reserves: Vec<Sp1SmtInitReserveEntry>,
    pub leaf_salts: Vec<Hash>,
    pub merkle_prefix_proof: Option<Sp1BinaryMerklePrefixProof>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1SmtInitPublicValues {
    pub chain_id: String,
    pub state_root: String,
    pub session_id: String,
    pub depth: usize,
    pub smt_root: Hash,
    pub balance_total: i128,
    pub reserve_count: usize,
    pub reserve_commitment: Hash,
    pub uses_mock_inputs: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1KzgInsertStdin {
    pub chain_id: String,
    pub state_root: String,
    pub address: String,
    pub balance: i128,
    pub ownership: Sp1OwnershipWitness,
    pub chain_balance_proof: Sp1ChainBalanceProof,
    pub encoded_address_le: [u8; 32],
    pub encoded_address_blind_le: [u8; 32],
    pub balance_blind_le: [u8; 32],
    pub eval_value_base: Sp1G1Affine,
    pub eval_blind_base: Sp1G1Affine,
    pub balance_value_base: Sp1G1Affine,
    pub balance_blind_base: Sp1G1Affine,
    pub c_u: Sp1G1Affine,
    pub c_balance: Sp1G1Affine,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1KzgInsertPublicValues {
    pub chain_id: String,
    pub state_root: String,
    pub commitment_params_digest_hex: String,
    pub uses_mock_inputs: bool,
    pub c_u: Sp1G1Affine,
    pub c_balance: Sp1G1Affine,
}

#[cfg(test)]
mod tests {
    use super::{init_reserve_commitment, InitReserveCommitment};

    #[test]
    fn streaming_reserve_commitment_matches_iterator_helper() {
        let reserves = [
            ("0x0000000000000000000000000000000000000001", 17i128),
            ("0x0000000000000000000000000000000000000002", 29i128),
        ];
        let expected = init_reserve_commitment(reserves.len(), reserves.iter().copied());
        let mut streaming = InitReserveCommitment::new(reserves.len());
        for (address, balance) in reserves {
            streaming.update(address, balance);
        }
        assert_eq!(streaming.finalize(), expected);
    }
}
