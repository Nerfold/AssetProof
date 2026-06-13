use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};

use common::crypto::{hash_to_scalar, point_g1_to_hex};
use common::encoding::encode_address;
use common::types::{ReserveEntry, StoredState};

use crate::commitment::commit_balance;
use crate::kzg::{commit_g1, Srs};
use crate::polynomial::product_from_roots;

#[derive(Clone, Debug)]
pub struct InitResult {
    pub state: StoredState,
}

pub fn initialize(
    reserve_entries: &[ReserveEntry],
    state_root: &str,
    srs: &Srs,
) -> Result<InitResult, String> {
    if reserve_entries.is_empty() {
        return Err("reserve set must not be empty".to_string());
    }

    let mut reserve_addresses = Vec::with_capacity(reserve_entries.len());
    let mut reserve_balances = Vec::with_capacity(reserve_entries.len());
    let mut roots = Vec::with_capacity(reserve_entries.len());
    for entry in reserve_entries {
        reserve_addresses.push(entry.address.clone());
        reserve_balances.push(entry.balance);
        roots.push(encode_address(&entry.address)?);
    }

    let alpha = derive_alpha(&roots);
    if alpha.is_zero() {
        return Err("derived alpha must be non-zero".to_string());
    }

    let f_s = product_from_roots(&roots);
    let p_s = f_s.mul_scalar(alpha);
    let accumulator = commit_g1(srs, &p_s)?;
    let balance_total: i128 = reserve_balances.iter().sum();
    let balance_blind = derive_balance_blind(balance_total, reserve_entries.len());
    let balance_commitment = commit_balance(balance_total, balance_blind);

    Ok(InitResult {
        state: StoredState {
            state_root: state_root.to_string(),
            srs_max_degree: srs.max_degree,
            alpha,
            reserve_addresses,
            reserve_balances,
            masked_polynomial_coeffs: p_s.coeffs,
            accumulator_hex: point_g1_to_hex(&accumulator)?,
            balance_total,
            balance_blind,
            balance_commitment_hex: point_g1_to_hex(&balance_commitment)?,
        },
    })
}

fn derive_alpha(encoded_addresses: &[Fr]) -> Fr {
    let mut bytes = Vec::new();
    for address in encoded_addresses {
        bytes.extend_from_slice(&address.into_bigint().to_bytes_le());
    }
    let mut alpha = hash_to_scalar("reserve-alpha", &bytes);
    if alpha.is_zero() {
        alpha = Fr::from(17u64);
    }
    alpha
}

fn derive_balance_blind(balance_total: i128, len: usize) -> Fr {
    let payload = format!("balance-blind:{balance_total}:{len}");
    let mut blind = hash_to_scalar("balance-blind", payload.as_bytes());
    if blind.is_zero() {
        blind = Fr::from(23u64);
    }
    blind
}
