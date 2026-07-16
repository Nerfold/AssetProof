use std::collections::{BTreeMap, BTreeSet};

use common::crypto::{hash_bytes, hex_encode};
use common::encoding::normalize_address;
use common::types::{Delta, SyncProof};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthereumSyncInput {
    pub chain_id: String,
    pub finalized: bool,
    pub old_state_root: String,
    pub block: EthereumBlockRef,
    pub state_diff: GethStateDiff,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthereumBlockRef {
    pub hash: String,
    pub parent_hash: String,
    pub state_root: String,
    #[serde(default)]
    pub number: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct GethStateDiff {
    #[serde(default)]
    pub pre: BTreeMap<String, GethAccountState>,
    #[serde(default)]
    pub post: BTreeMap<String, GethAccountState>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct GethAccountState {
    #[serde(default)]
    pub balance: Option<String>,
    #[serde(default)]
    pub nonce: Option<u64>,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub storage: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthereumSyncOutput {
    pub chain_id: String,
    pub block_hash: String,
    pub parent_hash: String,
    pub block_number: Option<String>,
    pub old_state_root: String,
    pub new_state_root: String,
    pub addresses: Vec<String>,
    pub deltas: Vec<i128>,
    pub delta_list_commitment_hex: String,
    pub transition_commitment_hex: String,
}

impl EthereumSyncOutput {
    pub fn verify_integrity(&self) -> Result<(), String> {
        if self.addresses.len() != self.deltas.len() {
            return Err("Ethereum Sync address/delta vector length mismatch".to_string());
        }
        let deltas = self.to_deltas();
        let mut previous = None;
        for delta in &deltas {
            let normalized = normalize_address(&delta.address)?;
            if normalized != delta.address {
                return Err("Ethereum Sync address is not canonical".to_string());
            }
            if previous.as_ref().is_some_and(|value| value >= &normalized) {
                return Err("Ethereum Sync addresses are not strictly sorted".to_string());
            }
            previous = Some(normalized);
        }
        if canonical_delta_commitment(&deltas) != self.delta_list_commitment_hex {
            return Err("Ethereum Sync delta commitment mismatch".to_string());
        }
        let expected_transition = transition_commitment(
            &self.chain_id,
            &self.block_hash,
            &self.parent_hash,
            &self.old_state_root,
            &self.new_state_root,
            &self.delta_list_commitment_hex,
        );
        if expected_transition != self.transition_commitment_hex {
            return Err("Ethereum Sync transition commitment mismatch".to_string());
        }
        Ok(())
    }

    pub fn to_deltas(&self) -> Vec<Delta> {
        self.addresses
            .iter()
            .cloned()
            .zip(self.deltas.iter().copied())
            .map(|(address, delta)| Delta { address, delta })
            .collect()
    }

    pub fn to_delta_csv(&self) -> String {
        self.addresses
            .iter()
            .zip(self.deltas.iter())
            .map(|(address, delta)| format!("{address},{delta}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn to_pretty_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self)
            .map_err(|err| format!("serialize Ethereum sync output: {err}"))
    }

    pub fn to_sync_proof(&self) -> SyncProof {
        SyncProof {
            scheme: "external-canonical-sync".to_string(),
            chain_id: self.chain_id.clone(),
            old_state_root: self.old_state_root.clone(),
            new_state_root: self.new_state_root.clone(),
            delta_list_commitment_hex: self.delta_list_commitment_hex.clone(),
            proof_hex: self.transition_commitment_hex.clone(),
        }
    }
}

pub fn synchronize(input: &EthereumSyncInput) -> Result<EthereumSyncOutput, String> {
    if !input.finalized {
        return Err("Ethereum sync input block is not finalized".to_string());
    }
    let chain_id = normalize_quantity(&input.chain_id, "chainId")?;
    let block_hash = normalize_hash(&input.block.hash, "block.hash")?;
    let parent_hash = normalize_hash(&input.block.parent_hash, "block.parentHash")?;
    let old_state_root = normalize_hash(&input.old_state_root, "oldStateRoot")?;
    let new_state_root = normalize_hash(&input.block.state_root, "block.stateRoot")?;
    let block_number = input
        .block
        .number
        .as_deref()
        .map(|value| normalize_quantity(value, "block.number"))
        .transpose()?;

    let pre = normalize_accounts(&input.state_diff.pre, "pre")?;
    let post = normalize_accounts(&input.state_diff.post, "post")?;
    let addresses = pre
        .keys()
        .chain(post.keys())
        .cloned()
        .collect::<BTreeSet<_>>();

    let mut canonical = Vec::new();
    for address in addresses {
        let (old_balance, new_balance) = match (pre.get(&address), post.get(&address)) {
            (Some(old), Some(new)) => match (old.balance.as_deref(), new.balance.as_deref()) {
                (Some(old), Some(new)) => {
                    (Uint256::from_quantity(old)?, Uint256::from_quantity(new)?)
                }
                (Some(old), None) => {
                    let old = Uint256::from_quantity(old)?;
                    (old, old)
                }
                (None, None) => continue,
                (None, Some(_)) => {
                    return Err(format!(
                        "pre account {address} is missing the old balance for a balance change"
                    ));
                }
            },
            (Some(old), None) => (
                parse_required_balance(old, &address, "deleted pre")?,
                Uint256::ZERO,
            ),
            (None, Some(new)) => match new.balance.as_deref() {
                Some(new) => (Uint256::ZERO, Uint256::from_quantity(new)?),
                None => continue,
            },
            (None, None) => continue,
        };
        let delta = signed_delta(old_balance, new_balance)?;
        if delta != 0 {
            canonical.push(Delta { address, delta });
        }
    }

    let delta_list_commitment_hex = canonical_delta_commitment(&canonical);
    let transition_commitment_hex = transition_commitment(
        &chain_id,
        &block_hash,
        &parent_hash,
        &old_state_root,
        &new_state_root,
        &delta_list_commitment_hex,
    );
    Ok(EthereumSyncOutput {
        chain_id,
        block_hash,
        parent_hash,
        block_number,
        old_state_root,
        new_state_root,
        addresses: canonical
            .iter()
            .map(|entry| entry.address.clone())
            .collect(),
        deltas: canonical.iter().map(|entry| entry.delta).collect(),
        delta_list_commitment_hex,
        transition_commitment_hex,
    })
}

fn transition_commitment(
    chain_id: &str,
    block_hash: &str,
    parent_hash: &str,
    old_state_root: &str,
    new_state_root: &str,
    delta_list_commitment_hex: &str,
) -> String {
    hex_encode(&hash_bytes(
        "dynamic-poa-ethereum-sync-transition",
        &[
            chain_id.as_bytes(),
            block_hash.as_bytes(),
            parent_hash.as_bytes(),
            old_state_root.as_bytes(),
            new_state_root.as_bytes(),
            delta_list_commitment_hex.as_bytes(),
        ],
    ))
}

pub fn synchronize_json(input: &str) -> Result<EthereumSyncOutput, String> {
    let parsed: EthereumSyncInput =
        serde_json::from_str(input).map_err(|err| format!("parse Ethereum sync JSON: {err}"))?;
    synchronize(&parsed)
}

pub fn canonical_delta_commitment(deltas: &[Delta]) -> String {
    let mut chunks = Vec::new();
    chunks.push(deltas.len().to_string().into_bytes());
    for delta in deltas {
        chunks.push(delta.address.as_bytes().to_vec());
        chunks.push(delta.delta.to_le_bytes().to_vec());
    }
    let refs = chunks.iter().map(Vec::as_slice).collect::<Vec<_>>();
    hex_encode(&hash_bytes("dynamic-poa-canonical-delta-list", &refs))
}

fn normalize_accounts(
    accounts: &BTreeMap<String, GethAccountState>,
    side: &str,
) -> Result<BTreeMap<String, GethAccountState>, String> {
    let mut out = BTreeMap::new();
    for (address, account) in accounts {
        let normalized = normalize_address(address)?;
        if out.insert(normalized.clone(), account.clone()).is_some() {
            return Err(format!(
                "duplicate {side} account after address normalization: {normalized}"
            ));
        }
    }
    Ok(out)
}

fn parse_required_balance(
    account: &GethAccountState,
    address: &str,
    side: &str,
) -> Result<Uint256, String> {
    let value = account
        .balance
        .as_deref()
        .ok_or_else(|| format!("{side} account {address} is missing balance"))?;
    Uint256::from_quantity(value)
}

fn signed_delta(old: Uint256, new: Uint256) -> Result<i128, String> {
    match new.cmp(&old) {
        std::cmp::Ordering::Equal => Ok(0),
        std::cmp::Ordering::Greater => {
            let magnitude = new.sub(old).to_i128_magnitude()?;
            Ok(magnitude)
        }
        std::cmp::Ordering::Less => {
            let magnitude = old.sub(new).to_i128_magnitude()?;
            Ok(-magnitude)
        }
    }
}

fn normalize_hash(value: &str, field: &str) -> Result<String, String> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    if raw.len() != 64 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{field} must contain 32 hex bytes"));
    }
    Ok(format!("0x{}", raw.to_ascii_lowercase()))
}

fn normalize_quantity(value: &str, field: &str) -> Result<String, String> {
    let raw = value
        .strip_prefix("0x")
        .ok_or_else(|| format!("{field} must be a 0x-prefixed Ethereum quantity"))?;
    if raw.is_empty()
        || !raw.bytes().all(|byte| byte.is_ascii_hexdigit())
        || (raw.len() > 1 && raw.starts_with('0'))
    {
        return Err(format!("invalid Ethereum quantity in {field}"));
    }
    Ok(format!("0x{}", raw.to_ascii_lowercase()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Uint256([u8; 32]);

impl Uint256 {
    const ZERO: Self = Self([0; 32]);

    fn from_quantity(value: &str) -> Result<Self, String> {
        let normalized = normalize_quantity(value, "account.balance")?;
        let raw = &normalized[2..];
        if raw.len() > 64 {
            return Err("Ethereum account balance exceeds 256 bits".to_string());
        }
        let mut out = [0u8; 32];
        let padded = if raw.len() % 2 == 1 {
            format!("0{raw}")
        } else {
            raw.to_string()
        };
        let offset = 32 - padded.len() / 2;
        for (index, chunk) in padded.as_bytes().chunks(2).enumerate() {
            out[offset + index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
        }
        Ok(Self(out))
    }

    fn sub(self, rhs: Self) -> Self {
        debug_assert!(self >= rhs);
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for index in (0..32).rev() {
            let value = self.0[index] as i16 - rhs.0[index] as i16 - borrow;
            if value < 0 {
                out[index] = (value + 256) as u8;
                borrow = 1;
            } else {
                out[index] = value as u8;
                borrow = 0;
            }
        }
        Self(out)
    }

    fn to_i128_magnitude(self) -> Result<i128, String> {
        if self.0[..16].iter().any(|byte| *byte != 0) || self.0[16] & 0x80 != 0 {
            return Err("Ethereum balance delta exceeds protocol i128 range".to_string());
        }
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&self.0[16..]);
        Ok(i128::from_be_bytes(bytes))
    }
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid hex nibble".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const H1: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
    const H2: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
    const H3: &str = "0x3333333333333333333333333333333333333333333333333333333333333333";

    #[test]
    fn emits_sorted_deduplicated_protocol_vectors() {
        let json = format!(
            r#"{{
              "chainId":"0x1",
              "finalized":true,
              "oldStateRoot":"{H1}",
              "block":{{"hash":"{H2}","parentHash":"{H3}","stateRoot":"{H2}","number":"0x10"}},
              "stateDiff":{{
                "pre":{{
                  "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB":{{"balance":"0xa"}},
                  "0x1111111111111111111111111111111111111111":{{"balance":"0x5"}},
                  "0x3333333333333333333333333333333333333333":{{"balance":"0x9"}}
                }},
                "post":{{
                  "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb":{{"balance":"0x7"}},
                  "0x1111111111111111111111111111111111111111":{{"balance":"0x8"}},
                  "0x3333333333333333333333333333333333333333":{{"nonce":2}},
                  "0x2222222222222222222222222222222222222222":{{"balance":"0x4"}}
                }}
              }}
            }}"#
        );
        let output = synchronize_json(&json).unwrap();
        assert_eq!(
            output.addresses,
            vec![
                "0x1111111111111111111111111111111111111111",
                "0x2222222222222222222222222222222222222222",
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ]
        );
        assert_eq!(output.deltas, vec![3, 4, -3]);
        assert_eq!(output.to_deltas().len(), 3);
        assert_eq!(
            output.delta_list_commitment_hex,
            canonical_delta_commitment(&output.to_deltas())
        );
    }

    #[test]
    fn treats_missing_post_account_as_deleted() {
        let input = EthereumSyncInput {
            chain_id: "0x1".to_string(),
            finalized: true,
            old_state_root: H1.to_string(),
            block: EthereumBlockRef {
                hash: H2.to_string(),
                parent_hash: H3.to_string(),
                state_root: H2.to_string(),
                number: None,
            },
            state_diff: GethStateDiff {
                pre: BTreeMap::from([(
                    "0x1111111111111111111111111111111111111111".to_string(),
                    GethAccountState {
                        balance: Some("0x2a".to_string()),
                        ..Default::default()
                    },
                )]),
                post: BTreeMap::new(),
            },
        };
        assert_eq!(synchronize(&input).unwrap().deltas, vec![-42]);
    }

    #[test]
    fn rejects_unfinalized_or_out_of_range_transition() {
        let mut input = EthereumSyncInput {
            chain_id: "0x1".to_string(),
            finalized: false,
            old_state_root: H1.to_string(),
            block: EthereumBlockRef {
                hash: H2.to_string(),
                parent_hash: H3.to_string(),
                state_root: H2.to_string(),
                number: None,
            },
            state_diff: GethStateDiff::default(),
        };
        assert!(synchronize(&input).unwrap_err().contains("not finalized"));
        input.finalized = true;
        input.state_diff.post.insert(
            "0x1111111111111111111111111111111111111111".to_string(),
            GethAccountState {
                balance: Some("0x80000000000000000000000000000000".to_string()),
                ..Default::default()
            },
        );
        assert!(synchronize(&input).unwrap_err().contains("i128"));
    }
}
