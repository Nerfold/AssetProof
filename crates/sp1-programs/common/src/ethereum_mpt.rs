use crate::ethereum_eoa::{keccak256, Keccak256Stream};
use crate::io::Sp1EthereumMptInput;
use alloc::vec::Vec;

const MPT_BATCH_DOMAIN: &[u8] = b"DPOA_ETHEREUM_MPT_BATCH_V1";

/// Commits the public account statements accepted by a batch. Proof nodes are
/// excluded because each statement's state root already binds its MPT witness.
/// On SP1 this streaming hash uses the Keccak permutation precompile.
pub fn account_batch_statement_digest(proofs: &[Sp1EthereumMptInput]) -> [u8; 32] {
    let mut digest = Keccak256Stream::new();
    digest.update(MPT_BATCH_DOMAIN);
    digest.update(&(proofs.len() as u64).to_be_bytes());
    for proof in proofs {
        digest.update(&proof.state_root);
        digest.update(&proof.address);
        digest.update(&proof.expected_balance.to_be_bytes());
    }
    digest.finalize()
}

#[derive(Clone, Copy)]
struct RlpItem<'a> {
    raw: &'a [u8],
    payload: &'a [u8],
    is_list: bool,
}

pub fn verify_account_balance(
    state_root: &[u8; 32],
    address: &[u8; 20],
    expected_balance: i128,
    proof_nodes: &[Vec<u8>],
) -> Result<(), &'static str> {
    if expected_balance < 0 || proof_nodes.is_empty() {
        return Err("invalid Ethereum account proof input");
    }
    let key = keccak256(address);
    let mut nibbles = [0u8; 64];
    for (index, byte) in key.iter().enumerate() {
        nibbles[index * 2] = byte >> 4;
        nibbles[index * 2 + 1] = byte & 0x0f;
    }

    let mut proof_index = 0usize;
    let mut node_bytes = proof_nodes[0].as_slice();
    if &keccak256(node_bytes) != state_root {
        return Err("Ethereum state root mismatch");
    }
    let mut path_offset = 0usize;

    loop {
        let node = parse_exact(node_bytes)?;
        if !node.is_list {
            return Err("Ethereum trie node is not an RLP list");
        }
        let mut children = [None; 17];
        let child_count = parse_list_into(node.payload, &mut children)?;
        match child_count {
            17 => {
                if path_offset == nibbles.len() {
                    ensure_proof_consumed(proof_index, proof_nodes.len())?;
                    return verify_account_value(
                        children[16].ok_or("missing Ethereum branch value")?,
                        expected_balance,
                    );
                }
                let child = children[nibbles[path_offset] as usize]
                    .ok_or("missing Ethereum branch child")?;
                path_offset += 1;
                node_bytes = resolve_child(child, proof_nodes, &mut proof_index)?;
            }
            2 => {
                let path = children[0].ok_or("missing compact Ethereum trie path")?;
                let child = children[1].ok_or("missing compact Ethereum trie child")?;
                if path.is_list {
                    return Err("invalid compact Ethereum trie path");
                }
                let (is_leaf, compact_len) =
                    match_compact_path(path.payload, &nibbles[path_offset..])?;
                path_offset += compact_len;
                if is_leaf {
                    if path_offset != nibbles.len() {
                        return Err("Ethereum leaf ended before account key");
                    }
                    ensure_proof_consumed(proof_index, proof_nodes.len())?;
                    return verify_account_value(child, expected_balance);
                }
                node_bytes = resolve_child(child, proof_nodes, &mut proof_index)?;
            }
            _ => return Err("invalid Ethereum trie node arity"),
        }
    }
}

fn resolve_child<'a>(
    child: RlpItem<'a>,
    proof_nodes: &'a [Vec<u8>],
    proof_index: &mut usize,
) -> Result<&'a [u8], &'static str> {
    if child.is_list {
        if child.raw.len() >= 32 {
            return Err("oversized inline Ethereum trie child");
        }
        if proof_nodes
            .get(*proof_index + 1)
            .is_some_and(|node| node.as_slice() == child.raw)
        {
            *proof_index += 1;
            return Ok(proof_nodes[*proof_index].as_slice());
        }
        return Ok(child.raw);
    }
    if child.payload.is_empty() {
        return Err("Ethereum account is absent from the state trie");
    }
    if child.payload.len() == 32 {
        *proof_index += 1;
        let next = proof_nodes
            .get(*proof_index)
            .ok_or("missing Ethereum trie proof node")?;
        if keccak256(next).as_slice() != child.payload {
            return Err("Ethereum trie child hash mismatch");
        }
        return Ok(next);
    }
    Err("invalid Ethereum trie child reference")
}

fn ensure_proof_consumed(index: usize, proof_len: usize) -> Result<(), &'static str> {
    if index.checked_add(1) != Some(proof_len) {
        return Err("unused Ethereum trie proof nodes");
    }
    Ok(())
}

fn verify_account_value(value: RlpItem<'_>, expected_balance: i128) -> Result<(), &'static str> {
    if value.is_list {
        return Err("Ethereum account value must be an RLP byte string");
    }
    let account = parse_exact(value.payload)?;
    if !account.is_list {
        return Err("Ethereum account is not an RLP list");
    }
    let mut fields = [None; 4];
    if parse_list_into(account.payload, &mut fields)? != 4 {
        return Err("invalid Ethereum account RLP");
    }
    let [Some(nonce), Some(balance), Some(storage_root), Some(code_hash)] = fields else {
        return Err("invalid Ethereum account RLP");
    };
    if nonce.is_list || balance.is_list || storage_root.is_list || code_hash.is_list {
        return Err("invalid Ethereum account RLP");
    }
    if storage_root.payload.len() != 32 || code_hash.payload.len() != 32 {
        return Err("invalid Ethereum account roots");
    }
    if decode_u128(nonce.payload)? > u64::MAX as u128 {
        return Err("Ethereum account nonce exceeds u64 range");
    }
    let decoded_balance = decode_u128(balance.payload)?;
    if decoded_balance != expected_balance as u128 {
        return Err("Ethereum account balance mismatch");
    }
    Ok(())
}

/// Checks a hex-prefix compact path directly against the remaining account
/// key. This avoids allocating a temporary nibble vector for every extension
/// or leaf node in the zkVM.
fn match_compact_path(encoded: &[u8], expected: &[u8]) -> Result<(bool, usize), &'static str> {
    if encoded.is_empty() {
        return Err("empty compact Ethereum trie path");
    }
    let flag = encoded[0] >> 4;
    if flag > 3 {
        return Err("invalid compact Ethereum trie flag");
    }
    let odd = flag & 1 == 1;
    if !odd && encoded[0] & 0x0f != 0 {
        return Err("non-canonical compact Ethereum trie path");
    }
    let nibble_len = encoded
        .len()
        .checked_mul(2)
        .and_then(|value| value.checked_sub(if odd { 1 } else { 2 }))
        .ok_or("compact Ethereum trie path length overflow")?;
    let is_leaf = flag & 2 == 2;
    if !is_leaf && nibble_len == 0 {
        return Err("empty Ethereum extension path");
    }
    if nibble_len > expected.len() {
        return Err("Ethereum trie path mismatch");
    }
    let mut matched = 0usize;
    if odd {
        if encoded[0] & 0x0f != expected[matched] {
            return Err("Ethereum trie path mismatch");
        }
        matched += 1;
    }
    for byte in &encoded[1..] {
        if byte >> 4 != expected[matched] || byte & 0x0f != expected[matched + 1] {
            return Err("Ethereum trie path mismatch");
        }
        matched += 2;
    }
    Ok((is_leaf, nibble_len))
}

fn decode_u128(bytes: &[u8]) -> Result<u128, &'static str> {
    if bytes.len() > 16 || bytes.first() == Some(&0) {
        return Err("Ethereum balance is non-canonical or exceeds i128 range");
    }
    let mut out = 0u128;
    for byte in bytes {
        out = (out << 8) | *byte as u128;
    }
    if out > i128::MAX as u128 {
        return Err("Ethereum balance exceeds i128 range");
    }
    Ok(out)
}

/// Parses an RLP list into caller-owned stack storage. Ethereum trie nodes have
/// at most 17 fields and account values have exactly 4, so heap allocation in
/// the hot path is unnecessary.
fn parse_list_into<'a, const N: usize>(
    mut payload: &'a [u8],
    out: &mut [Option<RlpItem<'a>>; N],
) -> Result<usize, &'static str> {
    let mut count = 0usize;
    while !payload.is_empty() {
        if count == N {
            return Err("Ethereum RLP list exceeds expected arity");
        }
        let (item, consumed) = parse_one(payload)?;
        out[count] = Some(item);
        count += 1;
        payload = &payload[consumed..];
    }
    Ok(count)
}

fn parse_exact(input: &[u8]) -> Result<RlpItem<'_>, &'static str> {
    let (item, consumed) = parse_one(input)?;
    if consumed != input.len() {
        return Err("trailing bytes after RLP item");
    }
    Ok(item)
}

fn parse_one(input: &[u8]) -> Result<(RlpItem<'_>, usize), &'static str> {
    let prefix = *input.first().ok_or("truncated RLP")?;
    let (is_list, header, len) = match prefix {
        0x00..=0x7f => (false, 0usize, 1usize),
        0x80..=0xb7 => (false, 1, (prefix - 0x80) as usize),
        0xb8..=0xbf => {
            let len_of_len = (prefix - 0xb7) as usize;
            (false, 1 + len_of_len, parse_length(input, len_of_len)?)
        }
        0xc0..=0xf7 => (true, 1, (prefix - 0xc0) as usize),
        0xf8..=0xff => {
            let len_of_len = (prefix - 0xf7) as usize;
            (true, 1 + len_of_len, parse_length(input, len_of_len)?)
        }
    };
    let total = header.checked_add(len).ok_or("RLP length overflow")?;
    if total > input.len() {
        return Err("truncated RLP payload");
    }
    if header == 1 && !is_list && len == 1 && input[1] < 0x80 {
        return Err("non-canonical single-byte RLP");
    }
    if header > 1 && len < 56 {
        return Err("non-canonical long RLP length");
    }
    let payload = if header == 0 {
        &input[..1]
    } else {
        &input[header..total]
    };
    Ok((
        RlpItem {
            raw: &input[..total],
            payload,
            is_list,
        },
        total,
    ))
}

fn parse_length(input: &[u8], len_of_len: usize) -> Result<usize, &'static str> {
    if input.len() < 1 + len_of_len || input[1] == 0 {
        return Err("invalid RLP length");
    }
    let mut len = 0usize;
    for byte in &input[1..1 + len_of_len] {
        len = len
            .checked_mul(256)
            .and_then(|value| value.checked_add(*byte as usize))
            .ok_or("RLP length overflow")?;
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Digest, Keccak256};

    #[test]
    fn verifies_single_leaf_ethereum_account_proof() {
        let address = [0x11u8; 20];
        let balance = 1_234_567u128;
        let node = account_leaf(&address, balance);
        let root: [u8; 32] = Keccak256::digest(&node).into();

        verify_account_balance(&root, &address, balance as i128, &[node.clone()]).unwrap();
        assert!(
            verify_account_balance(&root, &address, balance as i128 + 1, &[node.clone()]).is_err()
        );

        let mut wrong_root = root;
        wrong_root[0] ^= 1;
        assert!(
            verify_account_balance(&wrong_root, &address, balance as i128, &[node.clone()])
                .is_err()
        );

        let wrong_address = [0x22u8; 20];
        assert!(verify_account_balance(&root, &wrong_address, balance as i128, &[node]).is_err());
    }

    #[test]
    fn verifies_hashed_branch_child() {
        let address = [0xabu8; 20];
        let balance = 42u128;
        let key = Keccak256::digest(address);
        let first_nibble = key[0] >> 4;
        let mut compact_path = Vec::with_capacity(33);
        compact_path.push(0x30 | (key[0] & 0x0f)); // leaf + odd, followed by 63 nibbles
        compact_path.extend_from_slice(&key[1..]);
        let leaf = rlp_list(&[rlp_bytes(&compact_path), rlp_bytes(&account_rlp(balance))]);
        let leaf_hash = Keccak256::digest(&leaf);

        let mut branch_items = (0..17).map(|_| rlp_bytes(&[])).collect::<Vec<_>>();
        branch_items[first_nibble as usize] = rlp_bytes(&leaf_hash);
        let branch = rlp_list(&branch_items);
        let root: [u8; 32] = Keccak256::digest(&branch).into();

        verify_account_balance(&root, &address, balance as i128, &[branch, leaf]).unwrap();
    }

    #[test]
    fn compact_paths_are_checked_without_allocation() {
        assert_eq!(match_compact_path(&[0x20], &[]).unwrap(), (true, 0));
        assert_eq!(
            match_compact_path(&[0x31, 0x23], &[1, 2, 3]).unwrap(),
            (true, 3)
        );
        assert!(match_compact_path(&[0x00], &[]).is_err());
        assert!(match_compact_path(&[0x31, 0x24], &[1, 2, 3]).is_err());
    }

    fn account_leaf(address: &[u8; 20], balance: u128) -> Vec<u8> {
        let key = Keccak256::digest(address);
        let mut compact_path = Vec::with_capacity(33);
        compact_path.push(0x20); // leaf + even nibble count
        compact_path.extend_from_slice(&key);

        let account = account_rlp(balance);
        rlp_list(&[rlp_bytes(&compact_path), rlp_bytes(&account)])
    }

    fn account_rlp(balance: u128) -> Vec<u8> {
        let balance_bytes = minimal_be(balance);
        rlp_list(&[
            rlp_bytes(&[]),
            rlp_bytes(&balance_bytes),
            rlp_bytes(&[0x33; 32]),
            rlp_bytes(&[0x44; 32]),
        ])
    }

    fn minimal_be(value: u128) -> Vec<u8> {
        if value == 0 {
            return Vec::new();
        }
        let bytes = value.to_be_bytes();
        bytes[bytes.iter().position(|byte| *byte != 0).unwrap()..].to_vec()
    }

    fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
        let payload = items.iter().flatten().copied().collect::<Vec<_>>();
        rlp_with_prefix(0xc0, 0xf7, &payload)
    }

    fn rlp_bytes(value: &[u8]) -> Vec<u8> {
        if value.len() == 1 && value[0] < 0x80 {
            return value.to_vec();
        }
        rlp_with_prefix(0x80, 0xb7, value)
    }

    fn rlp_with_prefix(short_base: u8, long_base: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
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
}
