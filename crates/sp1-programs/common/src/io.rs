use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

pub type Hash = [u8; 32];

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
