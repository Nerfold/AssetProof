#![no_main]

extern crate alloc;

use sp1_programs_common::chain_balance::{decode_hash, verify_chain_balance, verify_merkle_prefix};
use sp1_programs_common::io::{
    init_reserve_commitment, Sp1ChainBalanceProof, Sp1OwnershipWitness, Sp1StaticInitPublicValues,
    Sp1StaticInitStdin,
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
    let input: Sp1StaticInitStdin = sp1_zkvm::io::read();
    cycle_end!(profile, "input_decode");

    let public = verify_static_initialization(input, profile);
    cycle_start!(profile, "public_values_commit");
    sp1_zkvm::io::commit(&public);
    cycle_end!(profile, "public_values_commit");
}

fn verify_static_initialization(
    input: Sp1StaticInitStdin,
    profile: bool,
) -> Sp1StaticInitPublicValues {
    assert!(!input.reserves.is_empty(), "empty reserve set");
    let expected_root = decode_hash(&input.state_root);

    if let Some(prefix_proof) = input.merkle_prefix_proof.as_ref() {
        cycle_start!(profile, "merkle_prefix_verify");
        verify_merkle_prefix(&expected_root, &input.reserves, prefix_proof);
        cycle_end!(profile, "merkle_prefix_verify");
    }

    cycle_start!(profile, "ownership_context_hash");
    let ownership_context = (input.chain_id != "mock-chain").then(|| {
        sp1_programs_common::ethereum_eoa::ownership_context_hash(
            sp1_programs_common::ethereum_eoa::OwnershipOperation::Initialization,
            &input.chain_id,
            &input.state_root,
        )
    });
    cycle_end!(profile, "ownership_context_hash");

    let mut balance_total = 0i128;
    let mut previous_address: Option<&str> = None;
    let mut uses_mock_inputs = false;
    cycle_start!(profile, "input_validation_and_ownership");
    for reserve in &input.reserves {
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

        if input.merkle_prefix_proof.is_none() {
            verify_chain_balance(&input.chain_id, &expected_root, reserve);
        }
        uses_mock_inputs |= matches!(
            reserve.chain_balance_proof,
            Sp1ChainBalanceProof::MockBinding { .. }
        );

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
                    "mock private key does not bind reserve address"
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

        balance_total = balance_total
            .checked_add(reserve.balance)
            .expect("balance total overflow");
    }
    cycle_end!(profile, "input_validation_and_ownership");

    cycle_start!(profile, "reserve_commitment");
    let reserve_commitment = init_reserve_commitment(
        input.reserves.len(),
        input
            .reserves
            .iter()
            .map(|reserve| (reserve.address.as_str(), reserve.balance)),
    );
    cycle_end!(profile, "reserve_commitment");

    Sp1StaticInitPublicValues {
        chain_id: input.chain_id,
        state_root: input.state_root,
        session_id: input.session_id,
        reserve_count: input.reserves.len(),
        reserve_commitment,
        balance_total,
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
