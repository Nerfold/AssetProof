#![no_main]

extern crate alloc;

use sp1_programs_common::io::{
    init_reserve_commitment, Sp1InitOwnershipPublicValues, Sp1InitOwnershipStdin,
    Sp1OwnershipWitness,
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
    let input: Sp1InitOwnershipStdin = sp1_zkvm::io::read();
    cycle_end!(profile, "input_decode");
    assert!(!input.reserves.is_empty(), "empty reserve set");
    // A single fixed-size Keccak is cheaper than scanning the million-entry
    // vector once merely to decide whether the context will be needed.
    cycle_start!(profile, "ownership_context_hash");
    let ownership_context = (input.chain_id != "mock-chain").then(|| {
        sp1_programs_common::ethereum_eoa::ownership_context_hash(
            sp1_programs_common::ethereum_eoa::OwnershipOperation::Initialization,
            &input.chain_id,
            &input.state_root,
        )
    });
    cycle_end!(profile, "ownership_context_hash");
    let mut uses_mock_inputs = false;

    cycle_start!(profile, "ownership_batch_verify");
    for reserve in &input.reserves {
        assert!(reserve.balance >= 0, "negative reserve balance");
        match &reserve.ownership {
            Sp1OwnershipWitness::MockPrivateKey { private_key } => {
                uses_mock_inputs = true;
                assert_eq!(
                    input.chain_id, "mock-chain",
                    "mock ownership used outside mock chain"
                );
                assert_eq!(
                    private_key,
                    &alloc::format!("mock-private-key:{}", reserve.address),
                    "mock private key does not bind the reserve address"
                );
            }
            Sp1OwnershipWitness::EthereumEoaSignature { r, s, recovery_id } => {
                sp1_programs_common::ethereum_eoa::verify_ownership_signature_with_context(
                    ownership_context
                        .as_ref()
                        .expect("missing Ethereum ownership context"),
                    &reserve.address,
                    r,
                    s,
                    *recovery_id,
                );
            }
            Sp1OwnershipWitness::UnsupportedExternal { .. } => {
                panic!("unsupported external ownership verifier")
            }
        }
    }
    cycle_end!(profile, "ownership_batch_verify");

    cycle_start!(profile, "reserve_commitment");
    let reserve_commitment = init_reserve_commitment(
        input.reserves.len(),
        input
            .reserves
            .iter()
            .map(|reserve| (reserve.address.as_str(), reserve.balance)),
    );
    cycle_end!(profile, "reserve_commitment");
    let public = Sp1InitOwnershipPublicValues {
        chain_id: input.chain_id,
        state_root: input.state_root,
        session_id: input.session_id,
        reserve_count: input.reserves.len(),
        reserve_commitment,
        uses_mock_inputs,
    };
    cycle_start!(profile, "public_values_commit");
    sp1_zkvm::io::commit(&public);
    cycle_end!(profile, "public_values_commit");
}
