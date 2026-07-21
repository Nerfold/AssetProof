use ark_bls12_381::Fr;

use common::types::Delta;
use smt::insert::{apply_insert_with_witness, build_insert_witness, verify_insert};
use smt::key::{key_bit, key_for_address};
use smt::leaf::Leaf;
use smt::multiproof::{build_compact_multiproof, expand_compact_multiproof};
use smt::state::SmtState;
use smt::update::{apply_update_with_witness, build_update_witness, verify_update};

fn sample_state() -> SmtState {
    let mut leaves = vec![
        Leaf::new(
            "0x1111111111111111111111111111111111111111".to_string(),
            100,
            SmtState::mock_salt("test", "0x1111111111111111111111111111111111111111", 100),
        )
        .unwrap(),
        Leaf::new(
            "0x2222222222222222222222222222222222222222".to_string(),
            250,
            SmtState::mock_salt("test", "0x2222222222222222222222222222222222222222", 250),
        )
        .unwrap(),
    ];
    leaves.sort_by(|a, b| a.address.cmp(&b.address));
    SmtState::new("root-0".to_string(), 32, leaves, Fr::from(7u64)).unwrap()
}

#[test]
fn compact_tree_persists_only_branch_frontier() {
    let state = sample_state();
    assert!(
        state.tree().node_count() <= 2 * state.leaf_count(),
        "compact tree stored {} nodes for {} leaves",
        state.tree().node_count(),
        state.leaf_count()
    );
    assert!(state.tree().node_count() < state.depth * state.leaf_count());
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
    verify_insert(&state, &result.next_state, &result.proof).unwrap();
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

#[test]
fn state_rejects_invalid_depth_and_occupied_paths() {
    assert!(SmtState::new("root".to_string(), 0, Vec::new(), Fr::from(1u64)).is_err());
    assert!(SmtState::new("root".to_string(), 129, Vec::new(), Fr::from(1u64)).is_err());

    let first = "0x0000000000000000000000000000000000000001";
    let first_bit = key_bit(&key_for_address(first).unwrap(), 0);
    let collision = (2u64..)
        .map(|value| format!("0x{value:040x}"))
        .find(|address| key_bit(&key_for_address(address).unwrap(), 0) == first_bit)
        .unwrap();
    let leaves = vec![
        Leaf::new(first.to_string(), 1, [1u8; 32]).unwrap(),
        Leaf::new(collision, 2, [2u8; 32]).unwrap(),
    ];
    assert!(SmtState::new("root".to_string(), 1, leaves, Fr::from(1u64)).is_err());
}

#[test]
fn insert_rejects_a_fixed_depth_path_collision() {
    let first = "0x0000000000000000000000000000000000000001";
    let first_bit = key_bit(&key_for_address(first).unwrap(), 0);
    let collision = (2u64..)
        .map(|value| format!("0x{value:040x}"))
        .find(|address| key_bit(&key_for_address(address).unwrap(), 0) == first_bit)
        .unwrap();
    let state = SmtState::new(
        "root".to_string(),
        1,
        vec![Leaf::new(first.to_string(), 1, [1u8; 32]).unwrap()],
        Fr::from(1u64),
    )
    .unwrap();
    let error = build_insert_witness(&state, &collision, 2, Fr::from(2u64)).unwrap_err();
    assert!(error.contains("occupied SMT path"));
}

#[test]
fn leaf_addresses_are_canonicalized() {
    let leaf = Leaf::new(
        "0xABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD".to_string(),
        1,
        [3u8; 32],
    )
    .unwrap();
    assert_eq!(leaf.address, "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd");
}

#[test]
fn shared_guest_root_builder_matches_host_tree() {
    let state = sample_state();
    let leaves = state
        .leaf_records()
        .iter()
        .map(|leaf| (smt::hash::prefix_index(&leaf.key, state.depth), leaf.hash()))
        .collect();
    assert_eq!(
        smt::hash::compute_sparse_root(state.depth, leaves),
        state.smt_root()
    );
}

#[test]
fn persisted_state_round_trip_uses_binary_sidecars() {
    let state = sample_state();
    let path = std::env::temp_dir().join(format!("poa-smt-state-{}.txt", std::process::id()));
    state.persist(&path).unwrap();
    let metadata = std::fs::read_to_string(&path).unwrap();
    assert!(metadata.contains("leaves_path="));
    assert!(metadata.contains("nodes_path="));
    assert!(!metadata.contains("leaf_addresses="));
    let restored = SmtState::from_stored_owned(common::io::read_smt_state(&path).unwrap()).unwrap();
    assert_eq!(restored.public_state(), state.public_state());
    assert_eq!(restored.leaf_records(), state.leaf_records());
    std::fs::remove_file(path.with_extension("leaves.bin")).unwrap();
    std::fs::remove_file(path.with_extension("nodes.bin")).unwrap();
    std::fs::remove_file(path).unwrap();
}
