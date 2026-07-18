use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

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
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"dynamic-poa-init-shape-salted-blake3-v1");
    hasher.update(salt);
    hasher.update(&(root_count as u64).to_le_bytes());
    hasher.update(alpha_le);

    let mut encoded_count = 0usize;
    for root_le in roots_le {
        hasher.update(&root_le);
        encoded_count += 1;
    }
    assert_eq!(encoded_count, root_count, "shape root count mismatch");

    *hasher.finalize().as_bytes()
}

/// Binds the degree-bounded insertion quotient before its Fiat--Shamir
/// evaluation point is derived. The salt and coefficients remain private SP1
/// witnesses; the public digest replaces the linear-size HPolyCom commitment.
pub fn insert_quotient_commitment<I>(
    salt: &Hash,
    coefficient_count: usize,
    coefficients_le: I,
) -> Hash
where
    I: IntoIterator<Item = Hash>,
{
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"dynamic-poa-insert-quotient-salted-blake3-v1");
    hasher.update(salt);
    hasher.update(&(coefficient_count as u64).to_le_bytes());

    let mut encoded_count = 0usize;
    for coefficient_le in coefficients_le {
        hasher.update(&coefficient_le);
        encoded_count += 1;
    }
    assert_eq!(
        encoded_count, coefficient_count,
        "quotient coefficient count mismatch"
    );

    *hasher.finalize().as_bytes()
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
    pub frontier_hashes: Vec<Hash>,
    pub entries: Vec<Sp1UpdateEntryWitness>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1UpdatePublicValues {
    pub old_state_root: String,
    pub new_state_root: String,
    pub old_smt_root: Hash,
    pub new_smt_root: Hash,
    pub aggregate_delta: i128,
    pub old_balance_total: i128,
    pub new_balance_total: i128,
    pub membership_flags: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1InsertStdin {
    pub state_root: String,
    pub new_state_root: String,
    pub depth: usize,
    pub old_smt_root: Hash,
    pub old_balance_total: i128,
    pub frontier_hashes: Vec<Hash>,
    pub key: Hash,
    pub balance: i128,
    pub salt: Hash,
    pub non_membership_proof: Sp1NonMembershipProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1InsertPublicValues {
    pub old_state_root: String,
    pub new_state_root: String,
    pub old_smt_root: Hash,
    pub new_smt_root: Hash,
    pub inserted_balance: i128,
    pub old_balance_total: i128,
    pub new_balance_total: i128,
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
pub struct Sp1EthereumVerkleBatchProof {
    pub proof: Vec<u8>,
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
    pub ethereum_verkle_batch_proof: Option<Sp1EthereumVerkleBatchProof>,
    pub reserves: Vec<Sp1InitReserveEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1InitPublicValues {
    pub chain_id: String,
    pub state_root: String,
    pub session_id: String,
    pub reserve_count: usize,
    pub zeta_le: [u8; 32],
    pub balance_commitment: Sp1G1Affine,
    pub shape_commitment: Hash,
    pub eval_commitment: Sp1G1Affine,
    pub commitment_params_digest_hex: String,
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
    pub balance_blind_delta_le: [u8; 32],
    pub zeta_le: Hash,
    pub quotient_salt: Hash,
    pub quotient_coefficients_le: Vec<Hash>,
    pub quotient_commitment: Hash,
    pub quotient_eval_le: Hash,
    pub quotient_eval_blind_le: Hash,
    pub eval_value_base: Sp1G1Affine,
    pub eval_blind_base: Sp1G1Affine,
    pub balance_value_base: Sp1G1Affine,
    pub balance_blind_base: Sp1G1Affine,
    pub c_x: Sp1G1Affine,
    pub c_quotient_eval: Sp1G1Affine,
    pub c_balance_delta: Sp1G1Affine,
    pub old_accumulator_hex: String,
    pub new_accumulator_hex: String,
    pub old_balance_commitment_hex: String,
    pub new_balance_commitment_hex: String,
    pub reserve_count_before: usize,
    pub reserve_count_after: usize,
    pub transcript_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sp1KzgInsertPublicValues {
    pub chain_id: String,
    pub state_root: String,
    pub zeta_le: Hash,
    pub commitment_params_digest_hex: String,
    pub uses_mock_inputs: bool,
    pub c_x: Sp1G1Affine,
    pub quotient_commitment: Hash,
    pub c_quotient_eval: Sp1G1Affine,
    pub c_balance_delta: Sp1G1Affine,
    pub old_accumulator_hex: String,
    pub new_accumulator_hex: String,
    pub old_balance_commitment_hex: String,
    pub new_balance_commitment_hex: String,
    pub reserve_count_before: usize,
    pub reserve_count_after: usize,
    pub transcript_hex: String,
}
