use ark_bls12_381::Fr;

use common::types::Delta;
use smt::insert::{apply_insert_with_witness, build_insert_witness};
use smt::leaf::Leaf;
use smt::multiproof::{build_compact_multiproof, expand_compact_multiproof};
use smt::state::SmtState;
use smt::update::{apply_update_with_witness, build_update_witness, verify_update};

fn sample_state() -> SmtState {
    let mut leaves = vec![
        Leaf::new(
            "0x1111111111111111111111111111111111111111".to_string(),
            100,
            SmtState::fresh_salt("test", "0x1111111111111111111111111111111111111111", 100),
        )
        .unwrap(),
        Leaf::new(
            "0x2222222222222222222222222222222222222222".to_string(),
            250,
            SmtState::fresh_salt("test", "0x2222222222222222222222222222222222222222", 250),
        )
        .unwrap(),
    ];
    leaves.sort_by(|a, b| a.address.cmp(&b.address));
    SmtState::new("root-0".to_string(), 32, leaves, Fr::from(7u64)).unwrap()
}

#[test]
fn update_ignores_non_member_and_verifies() {
    let state = sample_state();
    let deltas = vec![
        Delta {
            address: "0x1111111111111111111111111111111111111111".to_string(),
            delta: -10,
        },
        Delta {
            address: "0x3333333333333333333333333333333333333333".to_string(),
            delta: 40,
        },
    ];
    let witness = build_update_witness(&state, &deltas, Fr::from(3u64)).unwrap();
    let result = apply_update_with_witness(&state, "root-1", &witness).unwrap();
    assert_eq!(result.proof.aggregate_delta, -10);
    assert_eq!(result.next_state.balance_total, 340);
    verify_update(&state, &result.next_state, &result.proof).unwrap();
}

#[test]
fn insert_new_member_after_non_member_update() {
    let state = sample_state();
    let witness = build_insert_witness(
        &state,
        "0x3333333333333333333333333333333333333333",
        40,
        Fr::from(9u64),
    )
    .unwrap();
    let result = apply_insert_with_witness(&state, "root-1", &witness).unwrap();
    assert_eq!(result.next_state.balance_total, 390);
    assert_eq!(result.next_state.leaf_count(), 3);
}

#[test]
fn compact_multiproof_reports_shared_siblings() {
    let state = sample_state();
    let addresses = vec![
        "0x1111111111111111111111111111111111111111".to_string(),
        "0x2222222222222222222222222222222222222222".to_string(),
    ];
    let multiproof = build_compact_multiproof(&state.tree(), &addresses).unwrap();
    assert_eq!(multiproof.entries.len(), 2);
    assert!(multiproof.total_sibling_hashes >= multiproof.unique_sibling_hashes());

    let expanded = expand_compact_multiproof(&state.tree(), &multiproof).unwrap();
    let direct = state.tree().proofs_for(&addresses).unwrap();
    assert_eq!(expanded, direct);
}
