#![no_main]

use sp1_programs_common::ethereum_mpt::{account_batch_statement_digest, verify_account_balance};
use sp1_programs_common::io::{Sp1EthereumMptBatchInput, Sp1EthereumMptBatchPublicValues};
use sp1_zkvm::entrypoint;

entrypoint!(main);

fn main() {
    let profile: bool = sp1_zkvm::io::read();
    if profile {
        println!("cycle-tracker-report-start: input_decode");
    }
    let input: Sp1EthereumMptBatchInput = sp1_zkvm::io::read();
    if profile {
        println!("cycle-tracker-report-end: input_decode");
        println!("cycle-tracker-report-start: ethereum_mpt_batch_verify");
    }

    assert!(!input.proofs.is_empty(), "empty Ethereum MPT proof batch");
    let mut proof_node_count = 0usize;
    let mut proof_bytes = 0usize;
    for proof in &input.proofs {
        verify_account_balance(
            &proof.state_root,
            &proof.address,
            proof.expected_balance,
            &proof.proof_nodes,
        )
        .expect("invalid Ethereum MPT account proof");
        proof_node_count = proof_node_count
            .checked_add(proof.proof_nodes.len())
            .expect("MPT proof-node count overflow");
        for node in &proof.proof_nodes {
            proof_bytes = proof_bytes
                .checked_add(node.len())
                .expect("MPT proof-byte count overflow");
        }
    }

    if profile {
        println!("cycle-tracker-report-end: ethereum_mpt_batch_verify");
        println!("cycle-tracker-report-start: batch_statement_binding");
    }
    let statement_digest = account_batch_statement_digest(&input.proofs);
    if profile {
        println!("cycle-tracker-report-end: batch_statement_binding");
        println!("cycle-tracker-report-start: public_values_commit");
    }
    let public = Sp1EthereumMptBatchPublicValues {
        statement_digest,
        proof_count: input.proofs.len(),
        proof_node_count,
        proof_bytes,
    };
    sp1_zkvm::io::commit(&public);
    if profile {
        println!("cycle-tracker-report-end: public_values_commit");
    }
}
