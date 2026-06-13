use crate::hash::Hash;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipProof {
    pub siblings: Vec<Hash>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefaultNonMembershipProof {
    pub default_depth: usize,
    pub siblings: Vec<Hash>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollisionNonMembershipProof {
    pub collision_address: String,
    pub collision_balance: i128,
    pub collision_salt: Hash,
    pub siblings: Vec<Hash>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NonMembershipProof {
    Default(DefaultNonMembershipProof),
    Collision(CollisionNonMembershipProof),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddressProof {
    Membership(MembershipProof),
    NonMembership(NonMembershipProof),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SiblingRef {
    Default,
    Frontier(usize),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactMembershipProof {
    pub siblings: Vec<SiblingRef>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactDefaultNonMembershipProof {
    pub default_depth: usize,
    pub siblings: Vec<SiblingRef>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactCollisionNonMembershipProof {
    pub collision_address: String,
    pub collision_balance: i128,
    pub collision_salt: Hash,
    pub siblings: Vec<SiblingRef>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompactNonMembershipProof {
    Default(CompactDefaultNonMembershipProof),
    Collision(CompactCollisionNonMembershipProof),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompactAddressProof {
    Membership(CompactMembershipProof),
    NonMembership(CompactNonMembershipProof),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactProofEntry {
    pub address: String,
    pub proof: CompactAddressProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactMultiproof {
    pub entries: Vec<CompactProofEntry>,
    pub frontier_hashes: Vec<Hash>,
    pub total_sibling_hashes: usize,
}

impl CompactMultiproof {
    pub fn unique_sibling_hashes(&self) -> usize {
        self.frontier_hashes.len()
    }
}
