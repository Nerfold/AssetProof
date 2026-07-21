use crate::hash::{leaf_hash, Hash};
use crate::key::key_for_address;
use common::encoding::normalize_address;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leaf {
    pub address: String,
    pub key: Hash,
    pub balance: i128,
    pub salt: Hash,
}

impl Leaf {
    pub fn new(address: String, balance: i128, salt: Hash) -> Result<Self, String> {
        let address = normalize_address(&address)?;
        let key = key_for_address(&address)?;
        Ok(Self {
            address,
            key,
            balance,
            salt,
        })
    }

    pub fn hash(&self) -> Hash {
        leaf_hash(&self.key, self.balance, &self.salt)
    }
}
