#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use sp1_programs_common::chain_balance::{decode_hash, verify_chain_balance, verify_merkle_prefix};
use sp1_programs_common::io::{
    init_reserve_commitment, Hash, Sp1ChainBalanceProof, Sp1SmtInitPublicValues, Sp1SmtInitStdin,
};
use sp1_programs_common::smt::{
    compute_sparse_root, key_hash, leaf_hash, prefix_index, valid_depth,
};
use sp1_zkvm::entrypoint;

entrypoint!(main);

macro_rules! cycle_start {
    ($enabled:expr, $name:literal) => {
        if $enabled {
            println!(concat!("cycle-tracker-report-start: ", $name));
        }
    };
}

macro_rules! cycle_end {
    ($enabled:expr, $name:literal) => {
        if $enabled {
            println!(concat!("cycle-tracker-report-end: ", $name));
        }
    };
}

fn main() {
    let profile: bool = sp1_zkvm::io::read();
    cycle_start!(profile, "input_decode");
    let input: Sp1SmtInitStdin = sp1_zkvm::io::read();
    cycle_end!(profile, "input_decode");
    let public = verify_and_build(input, profile);
    cycle_start!(profile, "public_values_commit");
    sp1_zkvm::io::commit(&public);
    cycle_end!(profile, "public_values_commit");
}

fn verify_and_build(input: Sp1SmtInitStdin, profile: bool) -> Sp1SmtInitPublicValues {
    assert!(valid_depth(input.depth), "SMT depth must be in 1..=128");
    assert!(!input.reserves.is_empty(), "empty reserve set");
    assert_eq!(
        input.reserves.len(),
        input.leaf_salts.len(),
        "reserve/salt vector length mismatch"
    );

    let expected_chain_root = decode_hash(&input.state_root);
    if let Some(prefix_proof) = input.merkle_prefix_proof.as_ref() {
        cycle_start!(profile, "chain_prefix_verify");
        verify_merkle_prefix(&expected_chain_root, &input.reserves, prefix_proof);
        cycle_end!(profile, "chain_prefix_verify");
    }

    let mut leaves = Vec::<(u128, Hash)>::with_capacity(input.reserves.len());
    let mut balance_total = 0i128;
    let mut previous_address: Option<&str> = None;
    let mut uses_mock_inputs = false;

    cycle_start!(profile, "reserve_verify_and_leaf_hash");
    for (reserve, salt) in input.reserves.iter().zip(input.leaf_salts.iter()) {
        assert!(reserve.balance >= 0, "negative reserve balance");
        assert!(
            is_canonical_address(&reserve.address),
            "non-canonical Ethereum address"
        );
        if let Some(previous) = previous_address {
            assert!(
                previous < reserve.address.as_str(),
                "reserve addresses must be sorted and duplicate-free"
            );
        }
        previous_address = Some(&reserve.address);

        uses_mock_inputs |= matches!(
            reserve.chain_balance_proof,
            Sp1ChainBalanceProof::MockBinding { .. }
        );
        if input.merkle_prefix_proof.is_none() {
            verify_chain_balance(&input.chain_id, &expected_chain_root, reserve);
        }

        let key = key_hash(&reserve.address).expect("invalid Ethereum reserve address");
        leaves.push((
            prefix_index(&key, input.depth),
            leaf_hash(&key, reserve.balance, salt),
        ));
        balance_total = balance_total
            .checked_add(reserve.balance)
            .expect("initial balance total overflow");
    }
    cycle_end!(profile, "reserve_verify_and_leaf_hash");

    cycle_start!(profile, "smt_root_build");
    let smt_root = compute_sparse_root(input.depth, leaves);
    cycle_end!(profile, "smt_root_build");

    let reserve_commitment = init_reserve_commitment(
        input.reserves.len(),
        input
            .reserves
            .iter()
            .map(|reserve| (reserve.address.as_str(), reserve.balance)),
    );

    Sp1SmtInitPublicValues {
        chain_id: input.chain_id,
        state_root: input.state_root,
        session_id: input.session_id,
        depth: input.depth,
        smt_root,
        balance_total,
        reserve_count: input.reserves.len(),
        reserve_commitment,
        uses_mock_inputs,
    }
}

fn is_canonical_address(address: &str) -> bool {
    let Some(raw) = address.strip_prefix("0x") else {
        return false;
    };
    raw.len() == 40
        && raw
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}
