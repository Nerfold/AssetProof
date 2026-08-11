use std::array;

use sha3::{Digest, Keccak256};
use sp1_programs_common::ethereum_mpt::verify_account_balance;
use sp1_programs_common::io::Sp1EthereumMptInput;

struct AccountEntry {
    address: [u8; 20],
    balance: i128,
    key: [u8; 64],
    value: Vec<u8>,
}

struct TrieNode {
    encoded: Vec<u8>,
    kind: TrieNodeKind,
}

enum TrieNodeKind {
    Leaf {
        path: Vec<u8>,
    },
    Extension {
        path: Vec<u8>,
        child: Box<TrieNode>,
    },
    Branch {
        children: [Option<Box<TrieNode>>; 16],
    },
}

/// Builds one canonical Ethereum hexary Merkle-Patricia trie and exports one
/// account membership proof per entry. Every returned proof shares the same
/// state root, matching an `eth_getProof` batch at one block.
pub fn synthetic_account_proofs(count: usize) -> Result<Vec<Sp1EthereumMptInput>, String> {
    if count == 0 {
        return Err("Ethereum MPT proof count must be positive".to_string());
    }

    let mut entries = (0..count)
        .map(account_entry)
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_unstable_by(|left, right| left.key.cmp(&right.key));
    if entries.windows(2).any(|pair| pair[0].key == pair[1].key) {
        return Err("deterministic Ethereum fixture produced a duplicate key".to_string());
    }

    let root = build_node(&entries, 0)?;
    let state_root: [u8; 32] = Keccak256::digest(&root.encoded).into();
    let mut proofs = Vec::with_capacity(count);
    for entry in &entries {
        let mut proof_nodes = vec![root.encoded.clone()];
        collect_proof(&root, &entry.key, 0, &mut proof_nodes)?;
        let proof = Sp1EthereumMptInput {
            state_root,
            address: entry.address,
            expected_balance: entry.balance,
            proof_nodes,
        };
        verify_account_balance(
            &proof.state_root,
            &proof.address,
            proof.expected_balance,
            &proof.proof_nodes,
        )
        .map_err(|err| format!("generated invalid Ethereum MPT fixture: {err}"))?;
        proofs.push(proof);
    }
    Ok(proofs)
}

fn account_entry(index: usize) -> Result<AccountEntry, String> {
    let mut hasher = Keccak256::new();
    hasher.update(b"dynamic-poa-ethereum-mpt-account-v2");
    hasher.update((index as u64).to_be_bytes());
    let address_hash = hasher.finalize();
    let address: [u8; 20] = address_hash[12..]
        .try_into()
        .expect("Keccak suffix is a 20-byte address");
    let key_bytes: [u8; 32] = Keccak256::digest(address).into();
    let mut key = [0u8; 64];
    for (offset, byte) in key_bytes.iter().enumerate() {
        key[offset * 2] = byte >> 4;
        key[offset * 2 + 1] = byte & 0x0f;
    }
    let balance = 1_000_000_000_000_000_000i128
        .checked_add(index as i128)
        .ok_or_else(|| "synthetic Ethereum balance overflow".to_string())?;
    Ok(AccountEntry {
        address,
        balance,
        key,
        value: account_rlp(balance as u128),
    })
}

fn build_node(entries: &[AccountEntry], depth: usize) -> Result<TrieNode, String> {
    if entries.is_empty() || depth > 64 {
        return Err("invalid Ethereum trie builder state".to_string());
    }
    if entries.len() == 1 {
        let path = entries[0].key[depth..].to_vec();
        let encoded = rlp_list(&[
            rlp_bytes(&encode_compact_path(&path, true)),
            rlp_bytes(&entries[0].value),
        ]);
        return Ok(TrieNode {
            encoded,
            kind: TrieNodeKind::Leaf { path },
        });
    }

    let mut common_end = depth;
    while common_end < 64
        && entries[0].key[common_end] == entries[entries.len() - 1].key[common_end]
    {
        common_end += 1;
    }
    if common_end > depth {
        let path = entries[0].key[depth..common_end].to_vec();
        let child = Box::new(build_node(entries, common_end)?);
        let encoded = rlp_list(&[
            rlp_bytes(&encode_compact_path(&path, false)),
            node_reference(&child),
        ]);
        return Ok(TrieNode {
            encoded,
            kind: TrieNodeKind::Extension { path, child },
        });
    }
    if depth == 64 {
        return Err("duplicate Ethereum account keys".to_string());
    }

    let mut children: [Option<Box<TrieNode>>; 16] = array::from_fn(|_| None);
    let mut start = 0usize;
    while start < entries.len() {
        let nibble = entries[start].key[depth] as usize;
        let mut end = start + 1;
        while end < entries.len() && entries[end].key[depth] as usize == nibble {
            end += 1;
        }
        children[nibble] = Some(Box::new(build_node(&entries[start..end], depth + 1)?));
        start = end;
    }
    let mut items = (0..17).map(|_| rlp_bytes(&[])).collect::<Vec<_>>();
    for (nibble, child) in children.iter().enumerate() {
        if let Some(child) = child {
            items[nibble] = node_reference(child);
        }
    }
    Ok(TrieNode {
        encoded: rlp_list(&items),
        kind: TrieNodeKind::Branch { children },
    })
}

fn node_reference(node: &TrieNode) -> Vec<u8> {
    if node.encoded.len() < 32 {
        node.encoded.clone()
    } else {
        rlp_bytes(&Keccak256::digest(&node.encoded))
    }
}

fn collect_proof(
    node: &TrieNode,
    key: &[u8; 64],
    depth: usize,
    proof: &mut Vec<Vec<u8>>,
) -> Result<(), String> {
    match &node.kind {
        TrieNodeKind::Leaf { path } => {
            if key.get(depth..) != Some(path.as_slice()) {
                return Err("Ethereum fixture leaf path mismatch".to_string());
            }
            Ok(())
        }
        TrieNodeKind::Extension { path, child } => {
            if key.get(depth..depth + path.len()) != Some(path.as_slice()) {
                return Err("Ethereum fixture extension path mismatch".to_string());
            }
            push_hashed_child(child, proof);
            collect_proof(child, key, depth + path.len(), proof)
        }
        TrieNodeKind::Branch { children } => {
            let nibble = *key
                .get(depth)
                .ok_or_else(|| "Ethereum fixture branch exceeds key length".to_string())?
                as usize;
            let child = children[nibble]
                .as_deref()
                .ok_or_else(|| "Ethereum fixture is missing target branch".to_string())?;
            push_hashed_child(child, proof);
            collect_proof(child, key, depth + 1, proof)
        }
    }
}

fn push_hashed_child(child: &TrieNode, proof: &mut Vec<Vec<u8>>) {
    // Inline nodes are already part of their parent's RLP and must not be
    // duplicated in the eth_getProof-style node list.
    if child.encoded.len() >= 32 {
        proof.push(child.encoded.clone());
    }
}

fn encode_compact_path(nibbles: &[u8], leaf: bool) -> Vec<u8> {
    let odd = nibbles.len() % 2 == 1;
    let flag = if leaf { 2u8 } else { 0u8 };
    let mut out = Vec::with_capacity(1 + nibbles.len() / 2);
    let mut offset = 0usize;
    if odd {
        out.push(((flag + 1) << 4) | nibbles[0]);
        offset = 1;
    } else {
        out.push(flag << 4);
    }
    while offset < nibbles.len() {
        out.push((nibbles[offset] << 4) | nibbles[offset + 1]);
        offset += 2;
    }
    out
}

fn account_rlp(balance: u128) -> Vec<u8> {
    rlp_list(&[
        rlp_bytes(&[]),
        rlp_bytes(&minimal_be(balance)),
        rlp_bytes(&[0x56; 32]),
        rlp_bytes(&[0x78; 32]),
    ])
}

fn minimal_be(value: u128) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let bytes = value.to_be_bytes();
    bytes[bytes
        .iter()
        .position(|byte| *byte != 0)
        .expect("non-zero value")..]
        .to_vec()
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload_len = items.iter().map(Vec::len).sum();
    let mut payload = Vec::with_capacity(payload_len);
    for item in items {
        payload.extend_from_slice(item);
    }
    rlp_with_prefix(0xc0, 0xf7, &payload)
}

fn rlp_bytes(value: &[u8]) -> Vec<u8> {
    if value.len() == 1 && value[0] < 0x80 {
        return value.to_vec();
    }
    rlp_with_prefix(0x80, 0xb7, value)
}

fn rlp_with_prefix(short_base: u8, long_base: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 9);
    if payload.len() < 56 {
        out.push(short_base + payload.len() as u8);
    } else {
        let length = minimal_be(payload.len() as u128);
        out.push(long_base + length.len() as u8);
        out.extend_from_slice(&length);
    }
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Bytes, B256};
    use alloy_trie::{proof::verify_proof, Nibbles};
    use sha3::{Digest, Keccak256};

    use super::{account_rlp, synthetic_account_proofs};

    #[test]
    fn builds_shared_root_valid_ethereum_proofs() {
        for count in [1, 2, 16, 64] {
            let fixtures = synthetic_account_proofs(count).unwrap();
            assert_eq!(fixtures.len(), count);
            let root = fixtures[0].state_root;
            assert!(fixtures.iter().all(|proof| proof.state_root == root));
            assert!(fixtures
                .windows(2)
                .all(|pair| pair[0].address != pair[1].address));

            // Cross-check the first and last paths with an independent,
            // production Ethereum trie implementation.
            for proof in [fixtures.first().unwrap(), fixtures.last().unwrap()] {
                let key = Nibbles::unpack(Keccak256::digest(proof.address));
                let nodes = proof
                    .proof_nodes
                    .iter()
                    .map(|node| Bytes::copy_from_slice(node))
                    .collect::<Vec<_>>();
                verify_proof(
                    B256::from(proof.state_root),
                    key,
                    Some(account_rlp(proof.expected_balance as u128)),
                    &nodes,
                )
                .unwrap();
            }
        }
    }
}
