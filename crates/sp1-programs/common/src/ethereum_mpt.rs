use alloc::vec::Vec;
use sha3::{Digest, Keccak256};

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
    let key = Keccak256::digest(address);
    let mut nibbles = [0u8; 64];
    for (index, byte) in key.iter().enumerate() {
        nibbles[index * 2] = byte >> 4;
        nibbles[index * 2 + 1] = byte & 0x0f;
    }

    let mut proof_index = 0usize;
    let mut node_bytes = proof_nodes[0].as_slice();
    if Keccak256::digest(node_bytes).as_slice() != state_root {
        return Err("Ethereum state root mismatch");
    }
    let mut path_offset = 0usize;

    loop {
        let node = parse_exact(node_bytes)?;
        if !node.is_list {
            return Err("Ethereum trie node is not an RLP list");
        }
        let children = parse_list(node.payload)?;
        match children.len() {
            17 => {
                if path_offset == nibbles.len() {
                    return verify_account_value(children[16], expected_balance);
                }
                let child = children[nibbles[path_offset] as usize];
                path_offset += 1;
                node_bytes = resolve_child(child, proof_nodes, &mut proof_index)?;
            }
            2 => {
                if children[0].is_list {
                    return Err("invalid compact Ethereum trie path");
                }
                let (is_leaf, compact) = decode_compact_path(children[0].payload)?;
                if path_offset + compact.len() > nibbles.len()
                    || nibbles[path_offset..path_offset + compact.len()] != compact[..]
                {
                    return Err("Ethereum trie path mismatch");
                }
                path_offset += compact.len();
                if is_leaf {
                    if path_offset != nibbles.len() {
                        return Err("Ethereum leaf ended before account key");
                    }
                    return verify_account_value(children[1], expected_balance);
                }
                node_bytes = resolve_child(children[1], proof_nodes, &mut proof_index)?;
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
        if Keccak256::digest(next).as_slice() != child.payload {
            return Err("Ethereum trie child hash mismatch");
        }
        return Ok(next);
    }
    Err("invalid Ethereum trie child reference")
}

fn verify_account_value(value: RlpItem<'_>, expected_balance: i128) -> Result<(), &'static str> {
    if value.is_list {
        return Err("Ethereum account value must be an RLP byte string");
    }
    let account = parse_exact(value.payload)?;
    if !account.is_list {
        return Err("Ethereum account is not an RLP list");
    }
    let fields = parse_list(account.payload)?;
    if fields.len() != 4 || fields.iter().any(|field| field.is_list) {
        return Err("invalid Ethereum account RLP");
    }
    if fields[2].payload.len() != 32 || fields[3].payload.len() != 32 {
        return Err("invalid Ethereum account roots");
    }
    let balance = decode_u128(fields[1].payload)?;
    if balance != expected_balance as u128 {
        return Err("Ethereum account balance mismatch");
    }
    Ok(())
}

fn decode_compact_path(encoded: &[u8]) -> Result<(bool, Vec<u8>), &'static str> {
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
    let mut out = Vec::with_capacity(encoded.len() * 2);
    if odd {
        out.push(encoded[0] & 0x0f);
    }
    for byte in &encoded[1..] {
        out.push(byte >> 4);
        out.push(byte & 0x0f);
    }
    Ok((flag & 2 == 2, out))
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

fn parse_list(mut payload: &[u8]) -> Result<Vec<RlpItem<'_>>, &'static str> {
    let mut out = Vec::new();
    while !payload.is_empty() {
        let (item, consumed) = parse_one(payload)?;
        out.push(item);
        payload = &payload[consumed..];
    }
    Ok(out)
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
