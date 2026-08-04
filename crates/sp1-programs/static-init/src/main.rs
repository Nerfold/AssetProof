#![no_main]

extern crate alloc;

use sp1_programs_common::chain_balance::{
    decode_hash, verify_chain_balance, BinaryMerklePrefixVerifier,
};
use sp1_programs_common::io::{
    InitReserveCommitment, Sp1ChainBalanceProof, Sp1OwnershipWitness, Sp1StaticInitPublicValues,
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
    let mut reserve_commitment = InitReserveCommitment::new(input.reserves.len());
    let mut prefix_verifier = input
        .merkle_prefix_proof
        .as_ref()
        .map(|proof| BinaryMerklePrefixVerifier::new(&expected_root, proof));
    cycle_start!(profile, "input_validation_merkle_ownership_and_commitment");
    for reserve in &input.reserves {
        assert!(reserve.balance >= 0, "negative reserve balance");
        if let Some(previous) = previous_address {
            assert!(
                previous < reserve.address.as_str(),
                "reserve addresses must be sorted and duplicate-free"
            );
        }
        previous_address = Some(&reserve.address);
        assert_eq!(
            reserve.address_bytes,
            decode_canonical_address(&reserve.address),
            "reserve address bytes mismatch"
        );

        if let Some(verifier) = prefix_verifier.as_mut() {
            verifier.update(reserve);
        } else {
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
                sp1_programs_common::ethereum_eoa::verify_ownership_signature_with_context_and_address(
                    ownership_context
                        .as_ref()
                        .expect("missing Ethereum ownership context"),
                    &reserve.address_bytes,
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
        reserve_commitment.update(&reserve.address, reserve.balance);
    }
    if let Some(verifier) = prefix_verifier {
        verifier.finalize();
    }
    let reserve_commitment = reserve_commitment.finalize();
    cycle_end!(profile, "input_validation_merkle_ownership_and_commitment");

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

fn decode_canonical_address(address: &str) -> [u8; 20] {
    let raw = address
        .strip_prefix("0x")
        .expect("canonical address must start with 0x");
    assert_eq!(raw.len(), 40, "canonical address must contain 20 bytes");
    let mut out = [0u8; 20];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = (hex_nibble(raw.as_bytes()[index * 2]) << 4)
            | hex_nibble(raw.as_bytes()[index * 2 + 1]);
    }
    out
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("invalid canonical address hex"),
    }
}
