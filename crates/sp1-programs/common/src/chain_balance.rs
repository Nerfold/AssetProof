use alloc::vec;

use crate::ethereum_binary_merkle::{leaf_hash, node_hash};
use crate::io::{
    Hash, Sp1BinaryMerklePrefixProof, Sp1ChainBalanceProof, Sp1InitReserveEntry,
    Sp1SmtInitReserveEntry, Sp1StaticInitReserveEntry,
};

pub trait ChainReserveEntry {
    fn address(&self) -> &str;
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
            let address = decode_address(reserve.address());
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
            let address = decode_address(reserve.address());
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
    assert!(
        proof.depth < usize::BITS as usize,
        "Merkle depth is too large"
    );
    let capacity = 1usize << proof.depth;
    assert!(
        reserves.len() <= capacity,
        "reserve prefix exceeds Merkle capacity"
    );
    assert!(
        proof.suffix_subtrees.len() <= proof.depth + 1,
        "Merkle prefix contains too many suffix subtrees"
    );
    let mut stack = vec![None; proof.depth + 1];
    let mut cursor = 0usize;
    for (expected_index, reserve) in reserves.iter().enumerate() {
        let Sp1ChainBalanceProof::BinaryMerkleV1 {
            leaf_index,
            siblings,
        } = reserve.proof()
        else {
            panic!("shared Merkle prefix proof requires binary Merkle members")
        };
        assert_eq!(
            *leaf_index as usize, expected_index,
            "non-canonical Merkle prefix index"
        );
        assert!(
            siblings.is_empty(),
            "prefix member repeated an individual Merkle path"
        );
        append_subtree(
            &mut stack,
            &mut cursor,
            0,
            leaf_hash(&decode_address(reserve.address()), reserve.balance()),
        );
    }
    for subtree in &proof.suffix_subtrees {
        append_subtree(
            &mut stack,
            &mut cursor,
            subtree.level as usize,
            subtree.root,
        );
    }
    assert_eq!(
        cursor, capacity,
        "Merkle prefix proof did not cover the tree"
    );
    assert!(
        stack[..proof.depth].iter().all(Option::is_none),
        "Merkle prefix proof left an incomplete frontier"
    );
    assert_eq!(
        stack[proof.depth].expect("missing reconstructed Merkle root"),
        *expected_root,
        "native chain Merkle prefix proof mismatch"
    );
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
    cursor: &mut usize,
    mut level: usize,
    mut current: Hash,
) {
    assert!(
        level < stack.len(),
        "Merkle subtree level exceeds tree depth"
    );
    let width = 1usize << level;
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
