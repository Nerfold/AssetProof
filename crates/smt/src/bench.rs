use std::time::{Duration, Instant};

use ark_bls12_381::Fr;
use common::crypto::hash_to_scalar;
use common::types::Delta;

use crate::insert::{apply_insert_in_place, build_insert_witness};
use crate::leaf::Leaf;
use crate::state::SmtState;
use crate::update::{apply_update_in_place, build_update_multiproof, build_update_witness};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmtBenchResult {
    pub depth: usize,
    pub num_reserves: usize,
    pub modified_addresses: usize,
    pub init_elapsed: Duration,
    pub multiproof_elapsed: Duration,
    pub witness_elapsed: Duration,
    pub update_elapsed: Duration,
    pub insert_witness_elapsed: Duration,
    pub insert_elapsed: Duration,
    pub frontier_hashes: usize,
    pub total_path_siblings: usize,
    pub aggregate_delta: i128,
    pub post_update_balance_total: i128,
    pub post_insert_balance_total: i128,
}

pub fn run_synthetic_bench(
    depth: usize,
    num_reserves: usize,
    modified_addresses: usize,
) -> Result<SmtBenchResult, String> {
    if modified_addresses > num_reserves {
        return Err(format!(
            "modified-addresses {} cannot exceed num-reserves {}",
            modified_addresses, num_reserves
        ));
    }

    let init_start = Instant::now();
    let state = build_synthetic_smt_state(depth, num_reserves, "smt-bench-root-0")?;
    let init_elapsed = init_start.elapsed();

    let deltas = build_synthetic_smt_member_deltas(modified_addresses);
    let multiproof_start = Instant::now();
    let multiproof = build_update_multiproof(&state, &deltas)?;
    let multiproof_elapsed = multiproof_start.elapsed();

    let blind_delta = hash_to_scalar("smt-bench-update-blind", b"bench-update");
    let witness_start = Instant::now();
    let witness = build_update_witness(&state, &deltas, blind_delta)?;
    let witness_elapsed = witness_start.elapsed();

    let mut update_state = state;
    let update_start = Instant::now();
    let update_proof = apply_update_in_place(&mut update_state, "smt-bench-root-1", &witness)?;
    let update_elapsed = update_start.elapsed();

    let insert_address = format!("0x{:040x}", num_reserves + 1);
    let insert_blind = hash_to_scalar("smt-bench-insert-blind", b"bench-insert");
    let insert_witness_start = Instant::now();
    let insert_witness = build_insert_witness(&update_state, &insert_address, 1, insert_blind)?;
    let insert_witness_elapsed = insert_witness_start.elapsed();

    let post_update_balance_total = update_state.balance_total;
    let insert_start = Instant::now();
    let _insert_proof =
        apply_insert_in_place(&mut update_state, "smt-bench-root-2", &insert_witness)?;
    let insert_elapsed = insert_start.elapsed();

    Ok(SmtBenchResult {
        depth,
        num_reserves,
        modified_addresses,
        init_elapsed,
        multiproof_elapsed,
        witness_elapsed,
        update_elapsed,
        insert_witness_elapsed,
        insert_elapsed,
        frontier_hashes: multiproof.unique_sibling_hashes(),
        total_path_siblings: multiproof.total_sibling_hashes,
        aggregate_delta: update_proof.aggregate_delta,
        post_update_balance_total,
        post_insert_balance_total: update_state.balance_total,
    })
}

fn build_synthetic_smt_state(
    depth: usize,
    num_reserves: usize,
    state_root: &str,
) -> Result<SmtState, String> {
    let mut leaves = Vec::with_capacity(num_reserves);
    for index in 0..num_reserves {
        let address = format!("0x{:040x}", index + 1);
        let balance = 1000 + (index as i128 % 97);
        let salt = SmtState::fresh_salt("smt-bench-init-salt", &address, balance);
        leaves.push(Leaf::new(address, balance, salt)?);
    }
    let blind: Fr = hash_to_scalar("smt-bench-init-blind", state_root.as_bytes());
    SmtState::new(state_root.to_string(), depth, leaves, blind)
}

fn build_synthetic_smt_member_deltas(m: usize) -> Vec<Delta> {
    (0..m)
        .map(|index| Delta {
            address: format!("0x{:040x}", index + 1),
            delta: if index % 2 == 0 { 1 } else { -1 },
        })
        .collect()
}
