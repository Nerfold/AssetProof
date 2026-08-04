use alloc::vec::Vec;
#[cfg(target_os = "zkvm")]
use alloc::vec;

use crate::ethereum_binary_merkle::{leaf_hash, node_hash};
use crate::io::{
    Hash, Sp1BinaryMerklePrefixProof, Sp1ChainBalanceProof, Sp1InitReserveEntry,
    Sp1SmtInitReserveEntry, Sp1StaticInitReserveEntry,
};

pub trait ChainReserveEntry {
    fn address(&self) -> &str;
    fn address_bytes(&self) -> [u8; 20] {
        decode_address(self.address())
    }
    fn balance(&self) -> i128;
    fn proof(&self) -> &Sp1ChainBalanceProof;
}

impl ChainReserveEntry for Sp1InitReserveEntry {
    fn address(&self) -> &str {
        &self.address
    }

    fn balance(&self) -> i128 {
        self.balance
    }

    fn address_bytes(&self) -> [u8; 20] {
        let mut address = [0u8; 20];
        for (index, byte) in address.iter_mut().enumerate() {
            *byte = self.encoded_address_le[19 - index];
        }
        address
    }

    fn proof(&self) -> &Sp1ChainBalanceProof {
        &self.chain_balance_proof
    }
}

impl ChainReserveEntry for Sp1SmtInitReserveEntry {
    fn address(&self) -> &str {
        &self.address
    }

    fn balance(&self) -> i128 {
        self.balance
    }

    fn proof(&self) -> &Sp1ChainBalanceProof {
        &self.chain_balance_proof
    }
}

impl ChainReserveEntry for Sp1StaticInitReserveEntry {
    fn address(&self) -> &str {
        &self.address
    }

    fn balance(&self) -> i128 {
        self.balance
    }

    fn address_bytes(&self) -> [u8; 20] {
        self.address_bytes
    }

    fn proof(&self) -> &Sp1ChainBalanceProof {
        &self.chain_balance_proof
    }
}

pub fn verify_chain_balance<R: ChainReserveEntry>(
    chain_id: &str,
    expected_root: &Hash,
    reserve: &R,
) {
    match reserve.proof() {
        Sp1ChainBalanceProof::MockBinding { proof_label } => {
            assert_eq!(
                chain_id, "mock-chain",
                "mock state proof used outside mock chain"
            );
            assert_eq!(
                proof_label,
                &alloc::format!("mock-balance-proof:{}", reserve.address()),
                "invalid mock balance proof"
            );
        }
        Sp1ChainBalanceProof::BinaryMerkleV1 {
            leaf_index,
            siblings,
        } => {
            let address = reserve.address_bytes();
            let mut current = leaf_hash(&address, reserve.balance());
            let mut index = *leaf_index;
            for (level, sibling) in siblings.iter().enumerate() {
                current = if index & 1 == 0 {
                    node_hash(level, &current, sibling)
                } else {
                    node_hash(level, sibling, &current)
                };
                index >>= 1;
            }
            assert_eq!(index, 0, "Merkle leaf index exceeds proof depth");
            assert_eq!(
                &current, expected_root,
                "native chain Merkle proof mismatch"
            );
        }
        Sp1ChainBalanceProof::EthereumAccountProof { nodes } => {
            let address = reserve.address_bytes();
            crate::ethereum_mpt::verify_account_balance(
                expected_root,
                &address,
                reserve.balance(),
                nodes,
            )
            .expect("invalid Ethereum account proof");
        }
        Sp1ChainBalanceProof::EthereumVerkleBatchMember { .. }
        | Sp1ChainBalanceProof::EthereumVerkleProof { .. } => {
            panic!("Verkle proofs are disabled in the Merkle initialization guest")
        }
        Sp1ChainBalanceProof::UnsupportedGeneric { .. } => {
            panic!("unsupported generic chain proof verifier")
        }
    }
}

pub fn verify_merkle_prefix<R: ChainReserveEntry>(
    expected_root: &Hash,
    reserves: &[R],
    proof: &Sp1BinaryMerklePrefixProof,
) {
    let mut verifier = BinaryMerklePrefixVerifier::new(expected_root, proof);
    for reserve in reserves {
        verifier.update(reserve);
    }
    verifier.finalize();
}

/// Streaming verifier for a canonical dense-prefix Merkle witness.
///
/// Initialization guests can feed leaves during their existing account scan,
/// avoiding a second O(n) traversal whose only purpose is rebuilding the root.
pub struct BinaryMerklePrefixVerifier<'a> {
    expected_root: Hash,
    proof: &'a Sp1BinaryMerklePrefixProof,
    stack: Vec<Option<Hash>>,
    cursor: u64,
    capacity: u64,
    next_index: u64,
}

impl<'a> BinaryMerklePrefixVerifier<'a> {
    pub fn new(expected_root: &Hash, proof: &'a Sp1BinaryMerklePrefixProof) -> Self {
        assert!(
            proof.depth < u64::BITS as usize,
            "Merkle depth is too large"
        );
        assert!(
            proof.suffix_subtrees.len() <= proof.depth + 1,
            "Merkle prefix contains too many suffix subtrees"
        );
        Self {
            expected_root: *expected_root,
            proof,
            stack: vec![None; proof.depth + 1],
            cursor: 0,
            capacity: 1u64 << proof.depth,
            next_index: 0,
        }
    }

    pub fn update<R: ChainReserveEntry>(&mut self, reserve: &R) {
        assert!(
            self.next_index < self.capacity,
            "reserve prefix exceeds Merkle capacity"
        );
        let Sp1ChainBalanceProof::BinaryMerkleV1 {
            leaf_index,
            siblings,
        } = reserve.proof()
        else {
            panic!("shared Merkle prefix proof requires binary Merkle members")
        };
        assert_eq!(
            *leaf_index, self.next_index,
            "non-canonical Merkle prefix index"
        );
        assert!(
            siblings.is_empty(),
            "prefix member repeated an individual Merkle path"
        );
        append_subtree(
            &mut self.stack,
            &mut self.cursor,
            0,
            leaf_hash(&reserve.address_bytes(), reserve.balance()),
        );
        self.next_index += 1;
    }

    pub fn finalize(mut self) {
        for subtree in &self.proof.suffix_subtrees {
            append_subtree(
                &mut self.stack,
                &mut self.cursor,
                subtree.level as usize,
                subtree.root,
            );
        }
        assert_eq!(
            self.cursor, self.capacity,
            "Merkle prefix proof did not cover the tree"
        );
        assert!(
            self.stack[..self.proof.depth].iter().all(Option::is_none),
            "Merkle prefix proof left an incomplete frontier"
        );
        assert_eq!(
            self.stack[self.proof.depth].expect("missing reconstructed Merkle root"),
            self.expected_root,
            "native chain Merkle prefix proof mismatch"
        );
    }
}

pub fn decode_hash(value: &str) -> Hash {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    assert_eq!(raw.len(), 64, "state root must contain 32 bytes");
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = (hex_nibble(raw.as_bytes()[index * 2]) << 4)
            | hex_nibble(raw.as_bytes()[index * 2 + 1]);
    }
    out
}

pub fn decode_address(address: &str) -> [u8; 20] {
    let raw = address.strip_prefix("0x").unwrap_or(address);
    assert_eq!(raw.len(), 40, "address must contain 20 bytes");
    let mut out = [0u8; 20];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = (hex_nibble(raw.as_bytes()[index * 2]) << 4)
            | hex_nibble(raw.as_bytes()[index * 2 + 1]);
    }
    out
}

fn append_subtree(
    stack: &mut [Option<Hash>],
    cursor: &mut u64,
    mut level: usize,
    mut current: Hash,
) {
    assert!(
        level < stack.len(),
        "Merkle subtree level exceeds tree depth"
    );
    let width = 1u64 << level;
    assert_eq!(*cursor % width, 0, "unaligned Merkle suffix subtree");
    *cursor = cursor.checked_add(width).expect("Merkle cursor overflow");
    loop {
        let Some(left) = stack[level].take() else {
            stack[level] = Some(current);
            return;
        };
        current = node_hash(level, &left, &current);
        level += 1;
        assert!(level < stack.len(), "Merkle prefix exceeded declared depth");
    }
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hex"),
    }
}
