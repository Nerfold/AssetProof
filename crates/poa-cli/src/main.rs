use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use ark_bls12_381::Fr;
use ark_ff::Zero;
use common::crypto::{hash_to_scalar, point_g1_to_hex};
use common::io::{
    read_delta_csv, read_init, read_init_witness_csv, read_parallel_init, read_parallel_proof,
    read_parallel_state, read_proof, read_public_state, read_reserve_csv, read_smt_proof,
    read_smt_state, read_srs, read_srs_g1_prefix, read_srs_prefix, read_state, write_init,
    write_parallel_init, write_parallel_proof, write_parallel_state, write_proof,
    write_public_state, write_smt_proof, write_smt_state, write_srs, write_state,
};
use common::types::{Delta, InitProvingContext, StoredParallelState, StoredState};
use mock_chain::generator::{generate_scenario, load_manifest, write_scenario};
use nizk_fixed_set::commitment::commit_balance;
use nizk_fixed_set::external::PinnedSyncProofAdapter;
use nizk_fixed_set::init_proof::initialize_with_proof;
use nizk_fixed_set::kzg::commit_g1;
use nizk_fixed_set::kzg::{Srs, SrsProvenance};
use nizk_fixed_set::parallel::{
    apply_parallel_update, initialize_parallel, verify_parallel_init, verify_parallel_update,
};
use nizk_fixed_set::polynomial::Polynomial;
use nizk_fixed_set::threshold::{
    prove_threshold, verify_threshold, ThresholdProof, ThresholdStatement, ThresholdWitness,
};
use nizk_fixed_set::update::apply_update;
use nizk_fixed_set::verifier::{
    public_state_digest, verify_init_debug, verify_update_debug, verify_update_production,
    ChainPolicy,
};
use serde::Deserialize;
use smt::insert::build_insert_witness;
use smt::leaf::Leaf;
use smt::state::SmtState;
use sp1_host::init::ensure_sp1_setup as ensure_protocol_sp1_setup;
use sp1_host::insert::{build_and_execute_insert, prove_insert, verify_insert_proof};
use sp1_host::setup::default_setup_dir;
use sp1_host::update::{
    build_and_execute_update, build_and_prove_update, ensure_sp1_setup as ensure_smt_sp1_setup,
    verify_update_proof as verify_smt_update_proof,
};

const DEFAULT_SRS_PATH: &str = "params/srs/dev.srs.bin";
const DEFAULT_MOCK_RESERVES_PATH: &str = "data/mock/reserves.csv";
const DEFAULT_INIT_STATE_PATH: &str = "artifacts/states/init-state.txt";
const DEFAULT_INIT_PROOF_PATH: &str = "artifacts/proofs/init-proof.txt";
const DEFAULT_THRESHOLD_PROOF_PATH: &str = "artifacts/proofs/threshold-proof.txt";
const DEFAULT_ETH_DELTAS_PATH: &str = "artifacts/deltas/ethereum.csv";
const DEFAULT_ETH_SYNC_PATH: &str = "artifacts/test-runs/ethereum-sync.json";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerificationPolicyFile {
    expected_chain_id: String,
    finalized_state_roots: Vec<String>,
    last_accepted_state_root: String,
    last_accepted_public_state_digest: String,
    max_update_size: usize,
    pinned_sync_transition_commitment: String,
}

fn main() {
    if let Err(err) = real_main() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    match args[1].as_str() {
        "help" | "--help" | "-h" => print_usage(),
        "help-advanced" => print_advanced_usage(),
        "setup" => quick_setup(&args)?,
        "import-srs" => import_external_srs(&args)?,
        "mock-data" => quick_mock_data(&args)?,
        "prove-init" => quick_prove_init(&args)?,
        "prove-update" => quick_prove_update(&args)?,
        "check-update" => quick_check_update(&args)?,
        "check-update-debug" => quick_check_update_debug(&args)?,
        "state-digest" => {
            if args.len() != 3 {
                return Err("usage: poa-cli state-digest <state.txt>".to_string());
            }
            let path = Path::new(&args[2]);
            let state = read_state(path)?;
            let public_state = read_public_state_or_derive(path, &state)?;
            println!("{}", public_state_digest(&public_state)?);
        }
        "prove-threshold" => quick_prove_threshold(&args)?,
        "check-threshold" => quick_check_threshold(&args)?,
        "eth-sync" => {
            if args.len() != 3 && args.len() != 5 {
                return Err(
                    "usage: poa-cli eth-sync <transition.json> [deltas.csv sync-output.json]"
                        .to_string(),
                );
            }
            ensure_project_layout()?;
            let deltas_path = args
                .get(3)
                .map(String::as_str)
                .unwrap_or(DEFAULT_ETH_DELTAS_PATH);
            let sync_path = args
                .get(4)
                .map(String::as_str)
                .unwrap_or(DEFAULT_ETH_SYNC_PATH);
            let input =
                fs::read_to_string(&args[2]).map_err(|err| format!("read {}: {err}", args[2]))?;
            let output = eth_sync::synchronize_json(&input)?;
            let csv = output.to_delta_csv();
            fs::write(
                deltas_path,
                if csv.is_empty() {
                    csv
                } else {
                    format!("{csv}\n")
                },
            )
            .map_err(|err| format!("write {deltas_path}: {err}"))?;
            fs::write(sync_path, output.to_pretty_json()?)
                .map_err(|err| format!("write {sync_path}: {err}"))?;
            println!(
                "ethereum sync complete: block={}, old_root={}, new_root={}, touched={}, commitment={}, deltas={}, metadata={}",
                output.block_hash,
                output.old_state_root,
                output.new_state_root,
                output.addresses.len(),
                output.delta_list_commitment_hex,
                deltas_path,
                sync_path
            );
        }
        "sp1-setup" => {
            let setup_dir = if args.len() == 3 {
                Path::new(&args[2]).to_path_buf()
            } else if args.len() == 2 {
                default_setup_dir()
            } else {
                return Err("usage: poa-cli sp1-setup [setup-dir]".to_string());
            };
            ensure_protocol_sp1_setup(&setup_dir)?;
            println!(
                "protocol SP1 setup complete (init + KZG insert): {}",
                setup_dir.display()
            );
        }
        "sp1-smt-setup" => {
            let setup_dir = if args.len() == 3 {
                Path::new(&args[2]).to_path_buf()
            } else if args.len() == 2 {
                default_setup_dir()
            } else {
                return Err("usage: poa-cli sp1-smt-setup [setup-dir]".to_string());
            };
            ensure_smt_sp1_setup(&setup_dir)?;
            println!("SMT SP1 setup complete: {}", setup_dir.display());
        }
        "gen-srs" => {
            if args.len() != 4 {
                return Err("usage: poa-cli gen-srs <max-degree> <srs.bin>".to_string());
            }
            let max_degree = args[2]
                .parse::<usize>()
                .map_err(|err| format!("invalid max-degree: {err}"))?;
            let srs = Srs::setup_development(max_degree, b"dynamic-poa-srs");
            write_srs(
                Path::new(&args[3]),
                srs.max_degree,
                &srs.tau_g1_powers,
                &srs.tau_g2_powers,
                &srs.hiding_tau_g1_powers,
            )?;
            write_srs_provenance(Path::new(&args[3]), &srs.provenance)?;
            println!("wrote SRS with max_degree={} to {}", max_degree, args[3]);
        }
        "init" => {
            if args.len() != 7 {
                return Err(
                    "usage: poa-cli init <srs.bin> <reserves.csv> <state-root> <state.txt> <init-proof.txt>"
                        .to_string(),
                );
            }
            let srs = load_srs(Path::new(&args[2]))?;
            let reserves = read_reserve_csv(Path::new(&args[3]))?;
            let init = initialize_with_proof(&reserves, &args[4], &srs)?;
            let state_path = Path::new(&args[5]);
            write_state(state_path, &init.state)?;
            write_public_state(&public_state_path(state_path), &init.state.public_state())?;
            write_init(Path::new(&args[6]), &init.proof)?;
            println!(
                "initialized n={}, balance_total={}, state_root={}",
                init.state.reserve_addresses.len(),
                init.state.balance_total,
                init.state.state_root
            );
        }
        "init-mock-owned" => {
            if args.len() != 9 {
                return Err(
                    "usage: poa-cli init-mock-owned <srs.bin> <init-witness.csv> <chain-id> <state-root> <session-id> <state.txt> <init-proof.txt>"
                        .to_string(),
                );
            }
            let srs = load_srs(Path::new(&args[2]))?;
            let witnesses = read_init_witness_csv(Path::new(&args[3]))?;
            let ctx = InitProvingContext {
                chain_id: args[4].clone(),
                state_root: args[5].clone(),
                session_id: args[6].clone(),
            };
            let init =
                nizk_fixed_set::init_proof::initialize_from_witnesses(&ctx, &witnesses, &srs)?;
            let state_path = Path::new(&args[7]);
            write_state(state_path, &init.state)?;
            write_public_state(&public_state_path(state_path), &init.state.public_state())?;
            write_init(Path::new(&args[8]), &init.proof)?;
            println!(
                "initialized mock-owned n={}, balance_total={}, chain_id={}, state_root={}",
                init.state.reserve_addresses.len(),
                init.state.balance_total,
                ctx.chain_id,
                ctx.state_root
            );
        }
        "prepare-run" => {
            if args.len() != 8 {
                return Err(
                    "usage: poa-cli prepare-run <run-dir> <max-degree> <reserves.csv> <state-root> <state.txt> <init-proof.txt>"
                        .to_string(),
                );
            }
            let run_dir = Path::new(&args[2]);
            fs::create_dir_all(run_dir)
                .map_err(|err| format!("create {}: {err}", run_dir.display()))?;

            let max_degree = args[3]
                .parse::<usize>()
                .map_err(|err| format!("invalid max-degree: {err}"))?;
            let srs_path = run_dir.join("srs.bin");
            if !srs_path.exists() {
                let srs = Srs::setup_development(max_degree, b"dynamic-poa-srs");
                write_srs(
                    &srs_path,
                    srs.max_degree,
                    &srs.tau_g1_powers,
                    &srs.tau_g2_powers,
                    &srs.hiding_tau_g1_powers,
                )?;
                println!("generated srs at {}", srs_path.display());
            } else {
                println!("reusing existing srs at {}", srs_path.display());
            }

            let srs = load_srs(&srs_path)?;
            let reserves = read_reserve_csv(Path::new(&args[4]))?;
            let init = initialize_with_proof(&reserves, &args[5], &srs)?;
            let state_path = Path::new(&args[6]);
            write_state(state_path, &init.state)?;
            write_public_state(&public_state_path(state_path), &init.state.public_state())?;
            write_init(Path::new(&args[7]), &init.proof)?;
            println!(
                "prepared run: state={}, n={}, balance_total={}",
                state_path.display(),
                init.state.reserve_addresses.len(),
                init.state.balance_total
            );
        }
        "prepare-synthetic-run" => {
            if args.len() != 6 {
                return Err(
                    "usage: poa-cli prepare-synthetic-run <run-dir> <degree> <state-root> <state.txt>"
                        .to_string(),
                );
            }
            let run_dir = Path::new(&args[2]);
            fs::create_dir_all(run_dir)
                .map_err(|err| format!("create {}: {err}", run_dir.display()))?;

            let degree = args[3]
                .parse::<usize>()
                .map_err(|err| format!("invalid degree: {err}"))?;
            let srs_path = run_dir.join("srs.bin");
            if !srs_path.exists() {
                let srs = Srs::setup_development(degree, b"dynamic-poa-srs");
                write_srs(
                    &srs_path,
                    srs.max_degree,
                    &srs.tau_g1_powers,
                    &srs.tau_g2_powers,
                    &srs.hiding_tau_g1_powers,
                )?;
                println!("generated srs at {}", srs_path.display());
            } else {
                println!("reusing existing srs at {}", srs_path.display());
            }

            let srs = load_srs(&srs_path)?;
            if srs.max_degree < degree {
                return Err(format!(
                    "existing SRS degree {} is smaller than requested synthetic degree {}",
                    srs.max_degree, degree
                ));
            }
            let mut state = build_synthetic_state(&srs, degree)?;
            state.state_root = args[4].clone();
            let state_path = Path::new(&args[5]);
            write_state(state_path, &state)?;
            write_public_state(&public_state_path(state_path), &state.public_state())?;
            println!(
                "prepared synthetic run: state={}, degree={}, accumulator_bound={}",
                state_path.display(),
                degree,
                srs.max_degree
            );
        }
        "prepare-synthetic-state" => {
            if args.len() != 6 {
                return Err(
                    "usage: poa-cli prepare-synthetic-state <srs.bin> <degree> <state-root> <state.txt>"
                        .to_string(),
                );
            }
            let degree = args[3]
                .parse::<usize>()
                .map_err(|err| format!("invalid degree: {err}"))?;
            let srs = load_srs_g1_prefix(Path::new(&args[2]), degree + 1)?;
            if srs.max_degree < degree {
                return Err(format!(
                    "SRS degree {} is smaller than requested synthetic degree {}",
                    srs.max_degree, degree
                ));
            }
            let mut state = build_synthetic_state(&srs, degree)?;
            state.state_root = args[4].clone();
            let state_path = Path::new(&args[5]);
            write_state(state_path, &state)?;
            write_public_state(&public_state_path(state_path), &state.public_state())?;
            println!(
                "prepared synthetic state: state={}, degree={}, accumulator_bound={}",
                state_path.display(),
                degree,
                srs.max_degree
            );
        }
        "parallel-init" => {
            if args.len() != 8 {
                return Err(
                    "usage: poa-cli parallel-init <srs.bin> <reserves.csv> <state-root> <shards> <state.txt> <init-proof.txt>"
                        .to_string(),
                );
            }
            let srs = load_srs(Path::new(&args[2]))?;
            let reserves = read_reserve_csv(Path::new(&args[3]))?;
            let shards = args[5]
                .parse::<usize>()
                .map_err(|err| format!("invalid shards: {err}"))?;
            let init = initialize_parallel(&reserves, &args[4], &srs, shards)?;
            write_parallel_state(Path::new(&args[6]), &init.state)?;
            write_parallel_init(Path::new(&args[7]), &init.proof)?;
            println!(
                "parallel initialized shards={}, balance_total={}, state_root={}",
                init.state.shards.len(),
                init.state.balance_total,
                init.state.state_root
            );
        }
        "parallel-update" => {
            if args.len() != 8 {
                return Err(
                    "usage: poa-cli parallel-update <srs.bin> <state.txt> <deltas.csv> <new-state-root> <next-state.txt> <proof.txt>"
                        .to_string(),
                );
            }
            let state = read_parallel_state(Path::new(&args[3]))?;
            let deltas = read_delta_csv(Path::new(&args[4]))?;
            let srs = load_srs_for_update(
                Path::new(&args[2]),
                &flatten_parallel_state(&state),
                deltas.len(),
            )?;
            let updated = apply_parallel_update(&srs, &state, &deltas, &args[5])?;
            write_parallel_state(Path::new(&args[6]), &updated.next_state)?;
            write_parallel_proof(Path::new(&args[7]), &updated.proof)?;
            println!(
                "parallel updated shards={}, m={}, aggregate_delta={}",
                updated.next_state.shards.len(),
                deltas.len(),
                updated.proof.d_value
            );
        }
        "parallel-verify" => {
            if args.len() != 8 {
                return Err(
                    "usage: poa-cli parallel-verify <srs.bin> <old-state.txt> <deltas.csv> <new-state.txt> <proof.txt> <init-proof.txt>"
                        .to_string(),
                );
            }
            let old_state = read_parallel_state(Path::new(&args[3]))?;
            let deltas = read_delta_csv(Path::new(&args[4]))?;
            let new_state = read_parallel_state(Path::new(&args[5]))?;
            let proof = read_parallel_proof(Path::new(&args[6]))?;
            let init = read_parallel_init(Path::new(&args[7]))?;
            let srs = load_srs_for_parallel_state(Path::new(&args[2]), &old_state, deltas.len())?;
            verify_parallel_init(&srs, &old_state, &init)?;
            verify_parallel_update(&srs, &old_state, &deltas, &new_state, &proof)?;
            println!(
                "parallel verification passed for shards={}, m={}, new_balance_total={}",
                old_state.shards.len(),
                deltas.len(),
                new_state.balance_total
            );
        }
        "update" => {
            if args.len() != 8 {
                return Err(
                    "usage: poa-cli update <srs.bin> <state.txt> <deltas.csv> <new-state-root> <next-state.txt> <proof.txt>"
                        .to_string(),
                );
            }
            let state = read_state(Path::new(&args[3]))?;
            let deltas = read_delta_csv(Path::new(&args[4]))?;
            let srs = load_srs_for_update(Path::new(&args[2]), &state, deltas.len())?;
            let updated = apply_update(&srs, &state, &deltas, &args[5])?;
            let next_state_path = Path::new(&args[6]);
            write_state(next_state_path, &updated.next_state)?;
            write_public_state(
                &public_state_path(next_state_path),
                &updated.next_state.public_state(),
            )?;
            write_proof(Path::new(&args[7]), &updated.proof)?;
            println!(
                "updated m={}, aggregate_delta={}, gate_count={}",
                deltas.len(),
                updated.aggregate_delta,
                updated.proof.gate_count
            );
        }
        "continue-run" => {
            if args.len() != 7 {
                return Err(
                    "usage: poa-cli continue-run <run-dir> <current-state.txt> <deltas.csv> <new-state-root> <next-state.txt>"
                        .to_string(),
                );
            }
            let run_dir = Path::new(&args[2]);
            let srs_path = run_dir.join("srs.bin");
            if !srs_path.exists() {
                return Err(format!("missing SRS at {}", srs_path.display()));
            }
            let state = read_state(Path::new(&args[3]))?;
            let deltas = read_delta_csv(Path::new(&args[4]))?;
            let srs = load_srs_for_update(&srs_path, &state, deltas.len())?;
            let updated = apply_update(&srs, &state, &deltas, &args[5])?;
            let next_state_path = Path::new(&args[6]);
            write_state(next_state_path, &updated.next_state)?;
            write_public_state(
                &public_state_path(next_state_path),
                &updated.next_state.public_state(),
            )?;
            let proof_path = derive_companion_proof_path(next_state_path)?;
            write_proof(&proof_path, &updated.proof)?;
            println!(
                "continued run: next_state={}, proof={}, m={}, aggregate_delta={}",
                args[6],
                proof_path.display(),
                deltas.len(),
                updated.aggregate_delta
            );
        }
        "continue-synthetic-run" => {
            if args.len() != 7 {
                return Err(
                    "usage: poa-cli continue-synthetic-run <run-dir> <current-state.txt> <modified-addresses> <new-state-root> <next-state.txt>"
                        .to_string(),
                );
            }
            let run_dir = Path::new(&args[2]);
            let srs_path = run_dir.join("srs.bin");
            if !srs_path.exists() {
                return Err(format!("missing SRS at {}", srs_path.display()));
            }
            let state = read_state(Path::new(&args[3]))?;
            let modified = args[4]
                .parse::<usize>()
                .map_err(|err| format!("invalid modified-addresses: {err}"))?;
            let srs = load_srs_for_update(&srs_path, &state, modified)?;
            let deltas = build_synthetic_deltas(modified);
            let updated = apply_update(&srs, &state, &deltas, &args[5])?;
            let next_state_path = Path::new(&args[6]);
            write_state(next_state_path, &updated.next_state)?;
            write_public_state(
                &public_state_path(next_state_path),
                &updated.next_state.public_state(),
            )?;
            let proof_path = derive_companion_proof_path(next_state_path)?;
            write_proof(&proof_path, &updated.proof)?;
            println!(
                "continued synthetic run: next_state={}, proof={}, m={}, aggregate_delta={}",
                args[6],
                proof_path.display(),
                deltas.len(),
                updated.aggregate_delta
            );
        }
        "continue-synthetic-state" => {
            if args.len() != 7 {
                return Err(
                    "usage: poa-cli continue-synthetic-state <srs.bin> <current-state.txt> <modified-addresses> <new-state-root> <next-state.txt>"
                        .to_string(),
                );
            }
            let state = read_state(Path::new(&args[3]))?;
            let modified = args[4]
                .parse::<usize>()
                .map_err(|err| format!("invalid modified-addresses: {err}"))?;
            let srs = load_srs_for_update(Path::new(&args[2]), &state, modified)?;
            let deltas = build_synthetic_deltas(modified);
            let updated = apply_update(&srs, &state, &deltas, &args[5])?;
            let next_state_path = Path::new(&args[6]);
            write_state(next_state_path, &updated.next_state)?;
            write_public_state(
                &public_state_path(next_state_path),
                &updated.next_state.public_state(),
            )?;
            let proof_path = derive_companion_proof_path(next_state_path)?;
            write_proof(&proof_path, &updated.proof)?;
            println!(
                "continued synthetic state: next_state={}, proof={}, m={}, aggregate_delta={}",
                args[6],
                proof_path.display(),
                deltas.len(),
                updated.aggregate_delta
            );
        }
        "verify" => {
            if args.len() != 8 {
                return Err(
                    "usage: poa-cli verify <srs.bin> <old-state.txt> <deltas.csv> <new-state.txt> <proof.txt> <init-proof.txt>"
                        .to_string(),
                );
            }
            let old_state_path = Path::new(&args[3]);
            let old_state = read_state(old_state_path)?;
            let deltas = read_delta_csv(Path::new(&args[4]))?;
            let srs = load_srs_for_init_verify(Path::new(&args[2]), &old_state)?;
            let new_state_path = Path::new(&args[5]);
            let new_state = read_state(new_state_path)?;
            let proof = read_proof(Path::new(&args[6]))?;
            let init_proof = read_init(Path::new(&args[7]))?;
            verify_init_debug(&srs, &old_state, &init_proof)?;
            let verify_srs = load_srs_for_verify(Path::new(&args[2]), deltas.len())?;
            let old_public = read_public_state_or_derive(old_state_path, &old_state)?;
            let new_public = read_public_state_or_derive(new_state_path, &new_state)?;
            verify_update_debug(&verify_srs, &old_public, &deltas, &new_public, &proof)?;
            println!(
                "verification passed for m={}, new_state_root={}",
                deltas.len(),
                new_public.state_root
            );
        }
        "mock-gen" => {
            if args.len() != 8 {
                return Err(
                    "usage: poa-cli mock-gen <out-dir> <num-accounts> <num-reserves> <num-blocks> <txs-per-block> <seed>"
                        .to_string(),
                );
            }
            let out_dir = Path::new(&args[2]);
            let scenario = generate_scenario(
                args[7]
                    .parse::<u64>()
                    .map_err(|err| format!("seed: {err}"))?,
                args[3]
                    .parse::<usize>()
                    .map_err(|err| format!("num-accounts: {err}"))?,
                args[4]
                    .parse::<usize>()
                    .map_err(|err| format!("num-reserves: {err}"))?,
                args[5]
                    .parse::<usize>()
                    .map_err(|err| format!("num-blocks: {err}"))?,
                args[6]
                    .parse::<usize>()
                    .map_err(|err| format!("txs-per-block: {err}"))?,
            )?;
            let manifest_path = write_scenario(out_dir, &scenario)?;
            println!(
                "mock scenario generated at {}, windows={}, initial_root={}",
                manifest_path.display(),
                scenario.windows.len(),
                scenario.initial_root
            );
        }
        "mock-bench" => {
            if args.len() != 5 {
                return Err(
                    "usage: poa-cli mock-bench <srs.bin> <manifest.txt> <report.txt>".to_string(),
                );
            }
            let srs = load_srs(Path::new(&args[2]))?;
            let scenario = load_manifest(Path::new(&args[3]))?;
            let mut report = String::new();
            let init_start = Instant::now();
            let init = initialize_with_proof(&scenario.reserves, &scenario.initial_root, &srs)?;
            let init_elapsed = init_start.elapsed();
            let mut current_state = init.state;
            let mut total_update_micros = 0u128;
            let mut total_verify_micros = 0u128;
            let mut total_m = 0usize;
            let mut total_delta = 0i128;

            report.push_str(&format!(
                "init_micros={}\nwindows={}\n",
                init_elapsed.as_micros(),
                scenario.windows.len()
            ));

            for window in &scenario.windows {
                let update_start = Instant::now();
                let updated = apply_update(&srs, &current_state, &window.deltas, &window.new_root)?;
                total_update_micros += update_start.elapsed().as_micros();

                let verify_start = Instant::now();
                verify_update_debug(
                    &srs,
                    &current_state.public_state(),
                    &window.deltas,
                    &updated.next_state.public_state(),
                    &updated.proof,
                )?;
                total_verify_micros += verify_start.elapsed().as_micros();

                total_m += window.deltas.len();
                total_delta += updated.aggregate_delta;
                report.push_str(&format!(
                    "window_{:04}_m={}\nwindow_{:04}_delta={}\nwindow_{:04}_gate_count={}\n",
                    window.index,
                    window.deltas.len(),
                    window.index,
                    updated.aggregate_delta,
                    window.index,
                    updated.proof.gate_count
                ));
                current_state = updated.next_state;
            }

            report.push_str(&format!(
                "total_update_micros={}\ntotal_verify_micros={}\ntotal_m={}\ntotal_delta={}\nfinal_balance_total={}\n",
                total_update_micros,
                total_verify_micros,
                total_m,
                total_delta,
                current_state.balance_total
            ));
            fs::write(&args[4], report).map_err(|err| format!("write {}: {err}", args[4]))?;
            println!(
                "mock bench complete: windows={}, total_m={}, report={}",
                scenario.windows.len(),
                total_m,
                args[4]
            );
        }
        "synthetic-update-bench" => {
            if !(5..=7).contains(&args.len()) {
                return Err(
                    "usage: poa-cli synthetic-update-bench <srs.bin> <degree> <modified-addresses> [iterations] [warmup]"
                        .to_string(),
                );
            }
            let degree = args[3]
                .parse::<usize>()
                .map_err(|err| format!("invalid degree: {err}"))?;
            let modified = args[4]
                .parse::<usize>()
                .map_err(|err| format!("invalid modified-addresses: {err}"))?;
            let iterations = parse_bench_count(args.get(5), "iterations", 5)?;
            let warmup = parse_bench_count(args.get(6), "warmup", 1)?;

            warn_debug_benchmark();
            let srs_start = Instant::now();
            let srs = load_srs_prefix(Path::new(&args[2]), degree + 1, modified + 1)?;
            let srs_elapsed = srs_start.elapsed();
            eprintln!(
                "phase=setup stage=srs_prefix_load millis={} g1_powers={} g2_powers={}",
                srs_elapsed.as_millis(),
                degree + 1,
                modified + 1
            );

            let state_start = Instant::now();
            let state = build_synthetic_state(&srs, degree)?;
            let deltas = build_synthetic_deltas(modified);
            let state_elapsed = state_start.elapsed();
            eprintln!(
                "phase=setup stage=state_build millis={}",
                state_elapsed.as_millis()
            );

            let result =
                run_update_benchmark(&srs, &state, &deltas, iterations, warmup, "synthetic")?;

            println!("synthetic_degree={degree}");
            println!("modified_addresses={modified}");
            println!("iterations={iterations}");
            println!("warmup={warmup}");
            println!("srs_load_millis={}", srs_elapsed.as_millis());
            println!("state_build_millis={}", state_elapsed.as_millis());
            print_update_benchmark_result(&result);
        }
        "update-bench" => {
            if !(5..=7).contains(&args.len()) {
                return Err(
                    "usage: poa-cli update-bench <srs.bin> <state.txt> <deltas.csv> [iterations] [warmup]"
                        .to_string(),
                );
            }
            let iterations = parse_bench_count(args.get(5), "iterations", 5)?;
            let warmup = parse_bench_count(args.get(6), "warmup", 1)?;
            warn_debug_benchmark();

            let input_start = Instant::now();
            let state = read_state(Path::new(&args[3]))?;
            let deltas = read_delta_csv(Path::new(&args[4]))?;
            let input_elapsed = input_start.elapsed();
            let srs_start = Instant::now();
            let srs = load_srs_for_update(Path::new(&args[2]), &state, deltas.len())?;
            let srs_elapsed = srs_start.elapsed();
            eprintln!(
                "phase=setup stage=input_load millis={}",
                input_elapsed.as_millis()
            );
            eprintln!(
                "phase=setup stage=srs_prefix_load millis={} g1_powers={} g2_powers={}",
                srs_elapsed.as_millis(),
                state.masked_polynomial_coeffs.len(),
                deltas.len() + 1
            );

            let result =
                run_update_benchmark(&srs, &state, &deltas, iterations, warmup, "stored-state")?;
            println!(
                "polynomial_degree={}",
                state.masked_polynomial_coeffs.len() - 1
            );
            println!("modified_addresses={}", deltas.len());
            println!("iterations={iterations}");
            println!("warmup={warmup}");
            println!("input_load_millis={}", input_elapsed.as_millis());
            println!("srs_load_millis={}", srs_elapsed.as_millis());
            print_update_benchmark_result(&result);
        }
        "parallel-synthetic-update-bench" => {
            if args.len() != 6 {
                return Err(
                    "usage: poa-cli parallel-synthetic-update-bench <srs.bin> <degree> <modified-addresses> <shards>"
                        .to_string(),
                );
            }
            let degree = args[3]
                .parse::<usize>()
                .map_err(|err| format!("invalid degree: {err}"))?;
            let modified = args[4]
                .parse::<usize>()
                .map_err(|err| format!("invalid modified-addresses: {err}"))?;
            let shards = args[5]
                .parse::<usize>()
                .map_err(|err| format!("invalid shards: {err}"))?;
            if shards == 0 {
                return Err("shards must be greater than zero".to_string());
            }
            let shard_degree = degree.div_ceil(shards);
            let needed_degree = shard_degree.max(modified);
            let srs = load_srs_prefix(Path::new(&args[2]), needed_degree + 1, modified + 1)?;

            let state_start = Instant::now();
            let state = build_parallel_synthetic_state(&srs, degree, shards)?;
            let deltas = build_synthetic_deltas(modified);
            let state_elapsed = state_start.elapsed();
            eprintln!(
                "stage=parallel_state_complete millis={}",
                state_elapsed.as_millis()
            );

            let update_start = Instant::now();
            let updated =
                apply_parallel_update(&srs, &state, &deltas, "parallel-synthetic-next-root")?;
            let update_elapsed = update_start.elapsed();
            eprintln!(
                "stage=parallel_update_complete millis={}",
                update_elapsed.as_millis()
            );

            let verify_start = Instant::now();
            verify_parallel_update(&srs, &state, &deltas, &updated.next_state, &updated.proof)?;
            let verify_elapsed = verify_start.elapsed();
            eprintln!(
                "stage=parallel_verify_complete millis={}",
                verify_elapsed.as_millis()
            );

            println!("synthetic_degree={degree}");
            println!("modified_addresses={modified}");
            println!("shards={}", state.shards.len());
            println!("shard_degree={shard_degree}");
            println!("state_build_millis={}", state_elapsed.as_millis());
            println!("update_millis={}", update_elapsed.as_millis());
            println!("verify_millis={}", verify_elapsed.as_millis());
            println!("aggregate_delta={}", updated.proof.d_value);
            println!(
                "zero_test_gate_count={}",
                updated
                    .proof
                    .shard_proofs
                    .iter()
                    .map(|proof| proof.gate_count)
                    .sum::<usize>()
            );
            println!("projection_gate_count=0");
            println!(
                "projection_ipa_bytes={}",
                updated.proof.projection_ipa_proof.len()
            );
        }
        "smt-init" => {
            if args.len() != 6 {
                return Err(
                    "usage: poa-cli smt-init <depth> <reserves.csv> <state-root> <state.txt>"
                        .to_string(),
                );
            }
            let depth = args[2]
                .parse::<usize>()
                .map_err(|err| format!("invalid depth: {err}"))?;
            let reserves = read_reserve_csv(Path::new(&args[3]))?;
            let state = build_smt_state_from_reserves(depth, &reserves, &args[4])?;
            write_smt_state(Path::new(&args[5]), &state.to_stored()?)?;
            println!(
                "smt initialized depth={}, n={}, balance_total={}",
                depth,
                state.leaf_count(),
                state.balance_total
            );
        }
        "smt-update" => {
            if args.len() != 7 {
                return Err(
                    "usage: poa-cli smt-update <state.txt> <deltas.csv> <new-state-root> <next-state.txt> <proof.txt>"
                        .to_string(),
                );
            }
            let old_state = SmtState::from_stored(&read_smt_state(Path::new(&args[2]))?)?;
            let deltas = read_delta_csv(Path::new(&args[3]))?;
            let blind_delta = hash_to_scalar("smt-update-blind", args[4].as_bytes());
            let result = build_and_prove_update(&old_state, &deltas, &args[4], blind_delta)?;
            write_smt_state(Path::new(&args[5]), &result.next_state.to_stored()?)?;
            write_smt_proof(Path::new(&args[6]), &result.proof)?;
            println!(
                "smt updated m={}, aggregate_delta={}, new_balance_total={}",
                deltas.len(),
                result.proof.aggregate_delta,
                result.next_state.balance_total
            );
        }
        "smt-update-local" => {
            if args.len() != 7 {
                return Err(
                    "usage: poa-cli smt-update-local <state.txt> <deltas.csv> <new-state-root> <next-state.txt> <proof.txt>"
                        .to_string(),
                );
            }
            let old_state = SmtState::from_stored(&read_smt_state(Path::new(&args[2]))?)?;
            let deltas = read_delta_csv(Path::new(&args[3]))?;
            let blind_delta = hash_to_scalar("smt-update-blind", args[4].as_bytes());
            let witness = smt::update::build_update_witness(&old_state, &deltas, blind_delta)?;
            let result = smt::update::apply_update_with_witness(&old_state, &args[4], &witness)?;
            write_smt_state(Path::new(&args[5]), &result.next_state.to_stored()?)?;
            write_smt_proof(Path::new(&args[6]), &result.proof)?;
            println!(
                "smt locally updated m={}, aggregate_delta={}, new_balance_total={}",
                deltas.len(),
                result.proof.aggregate_delta,
                result.next_state.balance_total
            );
        }
        "smt-update-execute" => {
            if args.len() != 6 {
                return Err(
                    "usage: poa-cli smt-update-execute <state.txt> <deltas.csv> <new-state-root> <next-state.txt>"
                        .to_string(),
                );
            }
            let old_state = SmtState::from_stored(&read_smt_state(Path::new(&args[2]))?)?;
            let deltas = read_delta_csv(Path::new(&args[3]))?;
            let blind_delta = hash_to_scalar("smt-update-blind", args[4].as_bytes());
            let exec = build_and_execute_update(&old_state, &deltas, &args[4], blind_delta)?;
            write_smt_state(Path::new(&args[5]), &exec.next_state.to_stored()?)?;
            println!("smt execute updated m={}", deltas.len());
            println!("update_execute_instructions={}", exec.instruction_count);
            println!("aggregate_delta={}", exec.public_values.aggregate_delta);
            println!("new_balance_total={}", exec.public_values.new_balance_total);
        }
        "smt-verify" => {
            if args.len() != 6 {
                return Err(
                    "usage: poa-cli smt-verify <old-state.txt> <new-state.txt> <proof.txt> <mode>"
                        .to_string(),
                );
            }
            let old_state = SmtState::from_stored(&read_smt_state(Path::new(&args[2]))?)?;
            let new_state = SmtState::from_stored(&read_smt_state(Path::new(&args[3]))?)?;
            let proof = read_smt_proof(Path::new(&args[4]))?;
            match args[5].as_str() {
                "update" => verify_smt_update_proof(&old_state, &new_state, &proof)?,
                "update-local" => smt::update::verify_update(&old_state, &new_state, &proof)?,
                "insert" => verify_insert_proof(&old_state, &new_state, &proof)?,
                other => {
                    return Err(format!(
                        "unknown smt-verify mode {other}, expected update, update-local, or insert"
                    ))
                }
            }
            println!(
                "smt verification passed mode={}, old_root={}, new_root={}",
                args[5], old_state.state_root, new_state.state_root
            );
        }
        "smt-insert" => {
            if args.len() != 8 {
                return Err(
                    "usage: poa-cli smt-insert <state.txt> <address> <balance> <new-state-root> <next-state.txt> <proof.txt>"
                        .to_string(),
                );
            }
            let old_state = SmtState::from_stored(&read_smt_state(Path::new(&args[2]))?)?;
            let balance = args[4]
                .parse::<i128>()
                .map_err(|err| format!("invalid balance: {err}"))?;
            let blind_delta = hash_to_scalar("smt-insert-blind", args[5].as_bytes());
            let witness = build_insert_witness(&old_state, &args[3], balance, blind_delta)?;
            let result = prove_insert(&old_state, &args[5], witness)?;
            write_smt_state(Path::new(&args[6]), &result.next_state.to_stored()?)?;
            write_smt_proof(Path::new(&args[7]), &result.proof)?;
            println!(
                "smt inserted address={}, balance={}, new_balance_total={}",
                args[3], balance, result.next_state.balance_total
            );
        }
        "prepare-smt-run" => {
            if args.len() != 7 {
                return Err(
                    "usage: poa-cli prepare-smt-run <run-dir> <depth> <reserves.csv> <state-root> <state.txt>"
                        .to_string(),
                );
            }
            let run_dir = Path::new(&args[2]);
            fs::create_dir_all(run_dir)
                .map_err(|err| format!("create {}: {err}", run_dir.display()))?;
            let depth = args[3]
                .parse::<usize>()
                .map_err(|err| format!("invalid depth: {err}"))?;
            let reserves = read_reserve_csv(Path::new(&args[4]))?;
            let state = build_smt_state_from_reserves(depth, &reserves, &args[5])?;
            let state_path = run_dir.join("state_0000.txt");
            write_smt_state(&state_path, &state.to_stored()?)?;
            println!(
                "prepared smt run: state={}, depth={}, n={}",
                state_path.display(),
                depth,
                state.leaf_count()
            );
        }
        "smt-synthetic-bench" => {
            if args.len() != 5 {
                return Err(
                    "usage: poa-cli smt-synthetic-bench <depth> <num-reserves> <modified-addresses>"
                        .to_string(),
                );
            }
            let depth = args[2]
                .parse::<usize>()
                .map_err(|err| format!("invalid depth: {err}"))?;
            let num_reserves = args[3]
                .parse::<usize>()
                .map_err(|err| format!("invalid num-reserves: {err}"))?;
            let modified = args[4]
                .parse::<usize>()
                .map_err(|err| format!("invalid modified-addresses: {err}"))?;
            if modified > num_reserves {
                return Err(format!(
                    "modified-addresses {} cannot exceed num-reserves {} for member-update benchmark",
                    modified, num_reserves
                ));
            }

            let init_start = Instant::now();
            let state = build_synthetic_smt_state(depth, num_reserves, "smt-synth-root-0")?;
            let init_elapsed = init_start.elapsed();

            let deltas = build_synthetic_smt_member_deltas(modified);
            let blind_delta = hash_to_scalar("smt-update-blind", b"synth-update");

            let update_start = Instant::now();
            let update_result =
                build_and_prove_update(&state, &deltas, "smt-synth-root-1", blind_delta)?;
            let update_elapsed = update_start.elapsed();

            let verify_start = Instant::now();
            verify_smt_update_proof(&state, &update_result.next_state, &update_result.proof)?;
            let verify_elapsed = verify_start.elapsed();

            let insert_address = format!("0x{:040x}", num_reserves + 1);
            let insert_blind = hash_to_scalar("smt-insert-blind", b"synth-insert");
            let insert_witness =
                build_insert_witness(&update_result.next_state, &insert_address, 1, insert_blind)?;

            let insert_start = Instant::now();
            let insert_result = prove_insert(
                &update_result.next_state,
                "smt-synth-root-2",
                insert_witness,
            )?;
            let insert_elapsed = insert_start.elapsed();

            let insert_verify_start = Instant::now();
            verify_insert_proof(
                &update_result.next_state,
                &insert_result.next_state,
                &insert_result.proof,
            )?;
            let insert_verify_elapsed = insert_verify_start.elapsed();

            println!("depth={depth}");
            println!("num_reserves={num_reserves}");
            println!("modified_addresses={modified}");
            println!("init_millis={}", init_elapsed.as_millis());
            println!("update_millis={}", update_elapsed.as_millis());
            println!("verify_millis={}", verify_elapsed.as_millis());
            println!("insert_millis={}", insert_elapsed.as_millis());
            println!("insert_verify_millis={}", insert_verify_elapsed.as_millis());
            println!("aggregate_delta={}", update_result.proof.aggregate_delta);
            println!(
                "post_update_balance_total={}",
                update_result.next_state.balance_total
            );
            println!(
                "post_insert_balance_total={}",
                insert_result.next_state.balance_total
            );
        }
        "smt-synthetic-execute" => {
            if args.len() != 5 {
                return Err(
                    "usage: poa-cli smt-synthetic-execute <depth> <num-reserves> <modified-addresses>"
                        .to_string(),
                );
            }
            let depth = args[2]
                .parse::<usize>()
                .map_err(|err| format!("invalid depth: {err}"))?;
            let num_reserves = args[3]
                .parse::<usize>()
                .map_err(|err| format!("invalid num-reserves: {err}"))?;
            let modified = args[4]
                .parse::<usize>()
                .map_err(|err| format!("invalid modified-addresses: {err}"))?;
            if modified > num_reserves {
                return Err(format!(
                    "modified-addresses {} cannot exceed num-reserves {} for member-update benchmark",
                    modified, num_reserves
                ));
            }

            let init_start = Instant::now();
            let state = build_synthetic_smt_state(depth, num_reserves, "smt-synth-root-0")?;
            let init_elapsed = init_start.elapsed();

            let deltas = build_synthetic_smt_member_deltas(modified);
            let blind_delta = hash_to_scalar("smt-update-blind", b"synth-update");

            let update_start = Instant::now();
            let update_exec =
                build_and_execute_update(&state, &deltas, "smt-synth-root-1", blind_delta)?;
            let update_elapsed = update_start.elapsed();

            let insert_address = format!("0x{:040x}", num_reserves + 1);
            let insert_blind = hash_to_scalar("smt-insert-blind", b"synth-insert");
            let insert_start = Instant::now();
            let insert_exec = build_and_execute_insert(
                &update_exec.next_state,
                &insert_address,
                1,
                "smt-synth-root-2",
                insert_blind,
            )?;
            let insert_elapsed = insert_start.elapsed();

            println!("depth={depth}");
            println!("num_reserves={num_reserves}");
            println!("modified_addresses={modified}");
            println!("init_millis={}", init_elapsed.as_millis());
            println!("update_execute_millis={}", update_elapsed.as_millis());
            println!(
                "update_execute_instructions={}",
                update_exec.instruction_count
            );
            println!("insert_execute_millis={}", insert_elapsed.as_millis());
            println!(
                "insert_execute_instructions={}",
                insert_exec.instruction_count
            );
            println!(
                "aggregate_delta={}",
                update_exec.public_values.aggregate_delta
            );
            println!(
                "post_update_balance_total={}",
                update_exec.public_values.new_balance_total
            );
            println!(
                "post_insert_balance_total={}",
                insert_exec.public_values.new_balance_total
            );
        }
        "continue-smt-run" => {
            if args.len() != 7 {
                return Err(
                    "usage: poa-cli continue-smt-run <run-dir> <current-state.txt> <deltas.csv> <new-state-root> <next-state.txt>"
                        .to_string(),
                );
            }
            let _run_dir = Path::new(&args[2]);
            let old_state = SmtState::from_stored(&read_smt_state(Path::new(&args[3]))?)?;
            let deltas = read_delta_csv(Path::new(&args[4]))?;
            let blind_delta = hash_to_scalar("smt-update-blind", args[5].as_bytes());
            let result = build_and_prove_update(&old_state, &deltas, &args[5], blind_delta)?;
            write_smt_state(Path::new(&args[6]), &result.next_state.to_stored()?)?;
            let proof_path = derive_companion_proof_path(Path::new(&args[6]))?;
            write_smt_proof(&proof_path, &result.proof)?;
            println!(
                "continued smt run: next_state={}, proof={}, m={}, aggregate_delta={}",
                args[6],
                proof_path.display(),
                deltas.len(),
                result.proof.aggregate_delta
            );
        }
        "continue-smt-local-run" => {
            if args.len() != 7 {
                return Err(
                    "usage: poa-cli continue-smt-local-run <run-dir> <current-state.txt> <deltas.csv> <new-state-root> <next-state.txt>"
                        .to_string(),
                );
            }
            let _run_dir = Path::new(&args[2]);
            let old_state = SmtState::from_stored(&read_smt_state(Path::new(&args[3]))?)?;
            let deltas = read_delta_csv(Path::new(&args[4]))?;
            let blind_delta = hash_to_scalar("smt-update-blind", args[5].as_bytes());
            let witness = smt::update::build_update_witness(&old_state, &deltas, blind_delta)?;
            let result = smt::update::apply_update_with_witness(&old_state, &args[5], &witness)?;
            write_smt_state(Path::new(&args[6]), &result.next_state.to_stored()?)?;
            let proof_path = derive_companion_proof_path(Path::new(&args[6]))?;
            write_smt_proof(&proof_path, &result.proof)?;
            println!(
                "continued smt local run: next_state={}, proof={}, m={}, aggregate_delta={}",
                args[6],
                proof_path.display(),
                deltas.len(),
                result.proof.aggregate_delta
            );
        }
        "continue-smt-execute-run" => {
            if args.len() != 7 {
                return Err(
                    "usage: poa-cli continue-smt-execute-run <run-dir> <current-state.txt> <deltas.csv> <new-state-root> <next-state.txt>"
                        .to_string(),
                );
            }
            let _run_dir = Path::new(&args[2]);
            let old_state = SmtState::from_stored(&read_smt_state(Path::new(&args[3]))?)?;
            let deltas = read_delta_csv(Path::new(&args[4]))?;
            let blind_delta = hash_to_scalar("smt-update-blind", args[5].as_bytes());
            let exec = build_and_execute_update(&old_state, &deltas, &args[5], blind_delta)?;
            write_smt_state(Path::new(&args[6]), &exec.next_state.to_stored()?)?;
            println!(
                "continued smt execute run: next_state={}, m={}",
                args[6],
                deltas.len()
            );
            println!("update_execute_instructions={}", exec.instruction_count);
            println!("aggregate_delta={}", exec.public_values.aggregate_delta);
            println!("new_balance_total={}", exec.public_values.new_balance_total);
        }
        _ => print_usage(),
    }

    Ok(())
}

fn load_srs(path: &Path) -> Result<Srs, String> {
    let (max_degree, tau_g1_powers, tau_g2_powers, _legacy_hiding_tau_g1_powers) = read_srs(path)?;
    let srs = Srs {
        max_degree,
        tau_g1_powers,
        tau_g2_powers,
        hiding_tau_g1_powers: Vec::new(),
        provenance: read_srs_provenance(path)?,
    };
    srs.ensure_complete_layout()?;
    Ok(srs)
}

fn srs_meta_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.meta", path.display()))
}

fn read_srs_provenance(path: &Path) -> Result<SrsProvenance, String> {
    let meta_path = srs_meta_path(path);
    if !meta_path.exists() {
        return Ok(SrsProvenance::Development);
    }
    let raw = fs::read_to_string(&meta_path)
        .map_err(|err| format!("read {}: {err}", meta_path.display()))?;
    let expected_digest = raw
        .lines()
        .find_map(|line| line.strip_prefix("srs_digest_blake3="))
        .unwrap_or_default()
        .trim();
    let actual_digest = file_blake3(path)?;
    if expected_digest.is_empty() || expected_digest != actual_digest {
        return Err(format!(
            "SRS provenance digest mismatch for {}; re-import or regenerate the SRS",
            path.display()
        ));
    }
    let ceremony_id = raw
        .lines()
        .find_map(|line| line.strip_prefix("ceremony_id="))
        .unwrap_or_default()
        .trim();
    if raw
        .lines()
        .any(|line| line == "provenance=external-ceremony")
        && !ceremony_id.is_empty()
    {
        Ok(SrsProvenance::ExternalCeremony {
            ceremony_id: ceremony_id.to_string(),
        })
    } else {
        Ok(SrsProvenance::Development)
    }
}

fn write_srs_provenance(path: &Path, provenance: &SrsProvenance) -> Result<(), String> {
    let meta_path = srs_meta_path(path);
    let digest = file_blake3(path)?;
    let contents = match provenance {
        SrsProvenance::Development => format!(
            "provenance=development\nsrs_digest_blake3={digest}\nwarning=toxic-waste-known-do-not-use-in-production\n"
        ),
        SrsProvenance::ExternalCeremony { ceremony_id } => {
            format!("provenance=external-ceremony\nceremony_id={ceremony_id}\nsrs_digest_blake3={digest}\n")
        }
    };
    fs::write(&meta_path, contents).map_err(|err| format!("write {}: {err}", meta_path.display()))
}

fn file_blake3(path: &Path) -> Result<String, String> {
    let mut file =
        fs::File::open(path).map_err(|err| format!("open {} for digest: {err}", path.display()))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|err| format!("read {} for digest: {err}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn ensure_project_layout() -> Result<(), String> {
    for dir in [
        "data/mock/generated",
        "data/ethereum",
        "params/srs",
        "params/crs",
        "params/sp1",
        "artifacts/states",
        "artifacts/proofs",
        "artifacts/deltas",
        "artifacts/reports",
        "artifacts/benchmarks",
        "artifacts/test-runs",
    ] {
        fs::create_dir_all(dir).map_err(|err| format!("create {dir}: {err}"))?;
    }
    Ok(())
}

fn quick_setup(args: &[String]) -> Result<(), String> {
    if args.len() > 3 {
        return Err("usage: poa-cli setup [max-degree]".to_string());
    }
    ensure_project_layout()?;
    let requested_degree = args
        .get(2)
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|err| format!("max-degree: {err}"))
        })
        .transpose()?
        .unwrap_or(256);
    let mut generation_degree = requested_degree;
    let path = Path::new(DEFAULT_SRS_PATH);
    if path.exists() {
        let (max_degree, tau_g1_powers, tau_g2_powers, hiding_tau_g1_powers) = read_srs(path)?;
        let srs = Srs {
            max_degree,
            tau_g1_powers,
            tau_g2_powers,
            hiding_tau_g1_powers,
            provenance: read_srs_provenance(path)?,
        };
        srs.validate_structure()?;
        generation_degree = generation_degree.max(srs.max_degree);
        let declared_powers = srs
            .max_degree
            .checked_add(1)
            .ok_or_else(|| "declared SRS degree overflow".to_string())?;
        let has_standard_powers = srs.tau_g1_powers.len() == declared_powers
            && srs.tau_g2_powers.len() == declared_powers;
        if srs.max_degree >= requested_degree && has_standard_powers {
            if !srs.hiding_tau_g1_powers.is_empty() {
                let compact_path = path.with_extension("bin.compact.tmp");
                write_srs(
                    &compact_path,
                    srs.max_degree,
                    &srs.tau_g1_powers,
                    &srs.tau_g2_powers,
                    &[],
                )?;
                fs::rename(&compact_path, path).map_err(|err| {
                    format!(
                        "install compacted SRS {} -> {}: {err}",
                        compact_path.display(),
                        path.display()
                    )
                })?;
                write_srs_provenance(path, &srs.provenance)?;
                println!(
                    "removed {} unused legacy hiding-G1 powers from {}",
                    srs.hiding_tau_g1_powers.len(),
                    path.display()
                );
            }
            let provenance = match &srs.provenance {
                SrsProvenance::Development => "development-only",
                SrsProvenance::ExternalCeremony { .. } => "external-ceremony",
            };
            println!(
                "layout ready; reusing {} (degree={}, provenance={})",
                path.display(),
                srs.max_degree,
                provenance
            );
            return Ok(());
        }
        if matches!(srs.provenance, SrsProvenance::ExternalCeremony { .. }) {
            return Err(format!(
                "external ceremony SRS {} is too small/incomplete for degree {}; import a larger ceremony SRS instead of replacing it",
                path.display(), requested_degree
            ));
        }
        println!(
            "upgrading {} from degree {} to {}",
            path.display(),
            srs.max_degree,
            generation_degree
        );
    }
    let srs = Srs::setup_development(generation_degree, b"dynamic-poa-srs");
    write_srs(
        path,
        srs.max_degree,
        &srs.tau_g1_powers,
        &srs.tau_g2_powers,
        &srs.hiding_tau_g1_powers,
    )?;
    write_srs_provenance(path, &srs.provenance)?;
    println!(
        "layout ready; generated DEVELOPMENT-ONLY {} (degree={generation_degree}); production requires `./poa import-srs ...`",
        path.display(),
    );
    Ok(())
}

fn import_external_srs(args: &[String]) -> Result<(), String> {
    if args.len() != 4 && args.len() != 5 {
        return Err(
            "usage: poa-cli import-srs <source.srs.bin> <ceremony-id> [destination.srs.bin]"
                .to_string(),
        );
    }
    ensure_project_layout()?;
    let source = Path::new(&args[2]);
    let ceremony_id = args[3].trim();
    if ceremony_id.is_empty() {
        return Err("ceremony-id must not be empty".to_string());
    }
    let destination = args
        .get(4)
        .map(Path::new)
        .unwrap_or_else(|| Path::new(DEFAULT_SRS_PATH));
    let (max_degree, g1, g2, hiding) = read_srs(source)?;
    let srs = Srs::from_external_ceremony(max_degree, g1, g2, hiding, ceremony_id.to_string())?;
    write_srs(
        destination,
        srs.max_degree,
        &srs.tau_g1_powers,
        &srs.tau_g2_powers,
        &srs.hiding_tau_g1_powers,
    )?;
    write_srs_provenance(destination, &srs.provenance)?;
    println!(
        "validated and imported external ceremony SRS {} -> {} (degree={}, ceremony_id={})",
        source.display(),
        destination.display(),
        srs.max_degree,
        ceremony_id
    );
    Ok(())
}

fn quick_mock_data(args: &[String]) -> Result<(), String> {
    if args.len() != 2 && args.len() != 7 {
        return Err(
            "usage: poa-cli mock-data [num-accounts num-reserves num-blocks txs-per-block seed]"
                .to_string(),
        );
    }
    ensure_project_layout()?;
    let values = if args.len() == 2 {
        (64usize, 8usize, 6usize, 20usize, 42u64)
    } else {
        (
            args[2]
                .parse()
                .map_err(|err| format!("num-accounts: {err}"))?,
            args[3]
                .parse()
                .map_err(|err| format!("num-reserves: {err}"))?,
            args[4]
                .parse()
                .map_err(|err| format!("num-blocks: {err}"))?,
            args[5]
                .parse()
                .map_err(|err| format!("txs-per-block: {err}"))?,
            args[6].parse().map_err(|err| format!("seed: {err}"))?,
        )
    };
    let scenario = generate_scenario(values.4, values.0, values.1, values.2, values.3)?;
    let out = Path::new("data/mock/generated/latest");
    let manifest = write_scenario(out, &scenario)?;
    println!("mock data ready: {}", manifest.display());
    Ok(())
}

fn quick_prove_init(args: &[String]) -> Result<(), String> {
    if args.len() != 3 && args.len() != 4 {
        return Err("usage: poa-cli prove-init <state-root> [reserves.csv]".to_string());
    }
    ensure_project_layout()?;
    let srs = load_srs(Path::new(DEFAULT_SRS_PATH))
        .map_err(|err| format!("{err}; run `cargo run -p poa-cli -- setup` first"))?;
    let reserves_path = args
        .get(3)
        .map(String::as_str)
        .unwrap_or(DEFAULT_MOCK_RESERVES_PATH);
    let reserves = read_reserve_csv(Path::new(reserves_path))?;
    let init = initialize_with_proof(&reserves, &args[2], &srs)?;
    let state_path = Path::new(DEFAULT_INIT_STATE_PATH);
    write_state(state_path, &init.state)?;
    write_public_state(&public_state_path(state_path), &init.state.public_state())?;
    write_init(Path::new(DEFAULT_INIT_PROOF_PATH), &init.proof)?;
    println!(
        "initialization proof ready: state={}, proof={}, n={}, balance_total={}",
        state_path.display(),
        DEFAULT_INIT_PROOF_PATH,
        init.state.reserve_addresses.len(),
        init.state.balance_total
    );
    Ok(())
}

fn quick_prove_update(args: &[String]) -> Result<(), String> {
    if args.len() != 5 {
        return Err(
            "usage: poa-cli prove-update <state.txt> <deltas.csv> <new-state-root>".to_string(),
        );
    }
    ensure_project_layout()?;
    let state_path = Path::new(&args[2]);
    let state = read_state(state_path)?;
    let deltas = read_delta_csv(Path::new(&args[3]))?;
    let srs = load_srs_for_update(Path::new(DEFAULT_SRS_PATH), &state, deltas.len())?;
    let updated = apply_update(&srs, &state, &deltas, &args[4])?;
    let stem = state_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("state");
    let next_path = PathBuf::from(format!("artifacts/states/{stem}-next.txt"));
    let proof_path = PathBuf::from(format!("artifacts/proofs/{stem}-update-proof.txt"));
    write_state(&next_path, &updated.next_state)?;
    write_public_state(
        &public_state_path(&next_path),
        &updated.next_state.public_state(),
    )?;
    write_proof(&proof_path, &updated.proof)?;
    println!(
        "update proof ready: state={}, proof={}, m={}, aggregate_delta={}",
        next_path.display(),
        proof_path.display(),
        deltas.len(),
        updated.aggregate_delta
    );
    Ok(())
}

fn quick_check_update(args: &[String]) -> Result<(), String> {
    if args.len() != 8 {
        return Err(
            "usage: poa-cli check-update <old-state.txt> <deltas.csv> <new-state.txt> <proof.txt> <sync-output.json> <policy.json>".to_string(),
        );
    }
    let old_path = Path::new(&args[2]);
    let new_path = Path::new(&args[4]);
    let old_state = read_state(old_path)?;
    let new_state = read_state(new_path)?;
    let deltas = read_delta_csv(Path::new(&args[3]))?;
    let proof = read_proof(Path::new(&args[5]))?;
    let srs = load_srs_for_verify(Path::new(DEFAULT_SRS_PATH), deltas.len())?;
    let old_public = read_public_state_or_derive(old_path, &old_state)?;
    let new_public = read_public_state_or_derive(new_path, &new_state)?;
    let sync_raw =
        fs::read_to_string(&args[6]).map_err(|err| format!("read {}: {err}", args[6]))?;
    let sync_output: eth_sync::EthereumSyncOutput = serde_json::from_str(&sync_raw)
        .map_err(|err| format!("parse Ethereum Sync output: {err}"))?;
    sync_output.verify_integrity()?;
    if sync_output.to_deltas() != deltas {
        return Err("delta CSV does not match the pinned Ethereum Sync output".to_string());
    }
    let policy_raw =
        fs::read_to_string(&args[7]).map_err(|err| format!("read {}: {err}", args[7]))?;
    let policy_file: VerificationPolicyFile = serde_json::from_str(&policy_raw)
        .map_err(|err| format!("parse verification policy: {err}"))?;
    let sync_proof = sync_output.to_sync_proof();
    let policy = ChainPolicy::production(
        policy_file.expected_chain_id,
        policy_file.finalized_state_roots,
        Some(policy_file.last_accepted_state_root),
        Some(policy_file.last_accepted_public_state_digest),
        policy_file.max_update_size,
    )?;
    let adapter = PinnedSyncProofAdapter {
        expected_scheme: "external-canonical-sync".to_string(),
        expected_proof_hex: policy_file.pinned_sync_transition_commitment,
    };
    verify_update_production(
        &srs,
        &old_public,
        &deltas,
        &new_public,
        &proof,
        &policy,
        &sync_proof,
        &adapter,
    )?;
    println!(
        "update proof valid: m={}, new_state_root={}",
        deltas.len(),
        new_public.state_root
    );
    Ok(())
}

fn quick_check_update_debug(args: &[String]) -> Result<(), String> {
    if args.len() != 6 {
        return Err(
            "usage: poa-cli check-update-debug <old-state.txt> <deltas.csv> <new-state.txt> <proof.txt>"
                .to_string(),
        );
    }
    let old_path = Path::new(&args[2]);
    let new_path = Path::new(&args[4]);
    let old_state = read_state(old_path)?;
    let new_state = read_state(new_path)?;
    let deltas = read_delta_csv(Path::new(&args[3]))?;
    let proof = read_proof(Path::new(&args[5]))?;
    let srs = load_srs_for_verify(Path::new(DEFAULT_SRS_PATH), deltas.len())?;
    verify_update_debug(
        &srs,
        &read_public_state_or_derive(old_path, &old_state)?,
        &deltas,
        &read_public_state_or_derive(new_path, &new_state)?,
        &proof,
    )?;
    println!("debug update proof valid: m={}", deltas.len());
    Ok(())
}

fn quick_prove_threshold(args: &[String]) -> Result<(), String> {
    if args.len() != 4 && args.len() != 5 {
        return Err(
            "usage: poa-cli prove-threshold <state.txt> <threshold> [proof.txt]".to_string(),
        );
    }
    ensure_project_layout()?;
    let state = read_state(Path::new(&args[2]))?;
    let threshold = args[3]
        .parse::<i128>()
        .map_err(|err| format!("invalid threshold: {err}"))?;
    let statement = ThresholdStatement {
        public_state: state.public_state(),
        threshold,
    };
    let proof = prove_threshold(&statement, &ThresholdWitness::from_state(&state))?;
    let proof_path = args
        .get(4)
        .map(String::as_str)
        .unwrap_or(DEFAULT_THRESHOLD_PROOF_PATH);
    write_threshold_proof(Path::new(proof_path), &proof)?;
    println!(
        "threshold proof ready: threshold={}, proof={}, exact_balance_hidden=true",
        threshold, proof_path
    );
    Ok(())
}

fn quick_check_threshold(args: &[String]) -> Result<(), String> {
    if args.len() != 5 {
        return Err(
            "usage: poa-cli check-threshold <public-state.txt> <threshold> <proof.txt>".to_string(),
        );
    }
    let public_state = read_public_state(Path::new(&args[2]))?;
    let threshold = args[3]
        .parse::<i128>()
        .map_err(|err| format!("invalid threshold: {err}"))?;
    let proof = read_threshold_proof(Path::new(&args[4]))?;
    verify_threshold(
        &ThresholdStatement {
            public_state,
            threshold,
        },
        &proof,
    )?;
    println!("threshold proof valid: assets >= {threshold}");
    Ok(())
}

fn write_threshold_proof(path: &Path, proof: &ThresholdProof) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("create {}: {err}", parent.display()))?;
    }
    fs::write(
        path,
        format!("scheme={}\nproof_hex={}\n", proof.scheme, proof.proof_hex),
    )
    .map_err(|err| format!("write {}: {err}", path.display()))
}

fn read_threshold_proof(path: &Path) -> Result<ThresholdProof, String> {
    let content =
        fs::read_to_string(path).map_err(|err| format!("read {}: {err}", path.display()))?;
    let mut scheme = None;
    let mut proof_hex = None;
    for line in content.lines() {
        if let Some((key, value)) = line.split_once('=') {
            match key.trim() {
                "scheme" => scheme = Some(value.trim().to_string()),
                "proof_hex" => proof_hex = Some(value.trim().to_string()),
                _ => {}
            }
        }
    }
    Ok(ThresholdProof {
        scheme: scheme.ok_or_else(|| "threshold proof is missing scheme".to_string())?,
        proof_hex: proof_hex.ok_or_else(|| "threshold proof is missing proof_hex".to_string())?,
    })
}

fn load_srs_g1_prefix(path: &Path, needed_g1_len: usize) -> Result<Srs, String> {
    let (max_degree, tau_g1_powers) = read_srs_g1_prefix(path, needed_g1_len)?;
    Ok(Srs {
        max_degree,
        tau_g1_powers,
        tau_g2_powers: Vec::new(),
        hiding_tau_g1_powers: Vec::new(),
        provenance: read_srs_provenance(path)?,
    })
}

fn load_srs_prefix(path: &Path, needed_g1_len: usize, needed_g2_len: usize) -> Result<Srs, String> {
    let (max_degree, tau_g1_powers, tau_g2_powers) =
        read_srs_prefix(path, needed_g1_len, needed_g2_len)?;
    Ok(Srs {
        max_degree,
        tau_g1_powers,
        tau_g2_powers,
        hiding_tau_g1_powers: Vec::new(),
        provenance: read_srs_provenance(path)?,
    })
}

fn load_srs_for_update(path: &Path, state: &StoredState, modified: usize) -> Result<Srs, String> {
    let needed_g1_len = state.masked_polynomial_coeffs.len();
    let needed_g2_len = modified
        .checked_add(1)
        .ok_or_else(|| "modified-address count overflow".to_string())?;
    load_srs_prefix(path, needed_g1_len, needed_g2_len)
}

#[derive(Debug)]
struct UpdateBenchmarkResult {
    prover_micros: Vec<u128>,
    verifier_micros: Vec<u128>,
    aggregate_delta: i128,
    gate_count: usize,
    proof_artifact_binary_bytes: usize,
}

fn run_update_benchmark(
    srs: &Srs,
    state: &StoredState,
    deltas: &[Delta],
    iterations: usize,
    warmup: usize,
    label: &str,
) -> Result<UpdateBenchmarkResult, String> {
    if iterations == 0 {
        return Err("benchmark iterations must be greater than zero".to_string());
    }

    for index in 0..warmup {
        eprintln!("phase=warmup iteration={}", index + 1);
        let new_root = format!("{label}-warmup-root-{index}");
        let updated = apply_update(srs, state, deltas, &new_root)?;
        verify_update_debug(
            srs,
            &state.public_state(),
            deltas,
            &updated.next_state.public_state(),
            &updated.proof,
        )?;
    }

    let mut prover_micros = Vec::with_capacity(iterations);
    let mut verifier_micros = Vec::with_capacity(iterations);
    let mut aggregate_delta = 0i128;
    let mut gate_count = 0usize;
    let mut proof_artifact_binary_bytes = 0usize;
    for index in 0..iterations {
        let new_root = format!("{label}-measured-root-{index}");
        let prover_start = Instant::now();
        let updated = apply_update(srs, state, deltas, &new_root)?;
        let prover_elapsed = prover_start.elapsed();

        let verifier_start = Instant::now();
        verify_update_debug(
            srs,
            &state.public_state(),
            deltas,
            &updated.next_state.public_state(),
            &updated.proof,
        )?;
        let verifier_elapsed = verifier_start.elapsed();

        let prover_sample = prover_elapsed.as_micros();
        let verifier_sample = verifier_elapsed.as_micros();
        eprintln!(
            "phase=measure iteration={} prover_micros={} verifier_micros={}",
            index + 1,
            prover_sample,
            verifier_sample
        );
        prover_micros.push(prover_sample);
        verifier_micros.push(verifier_sample);
        aggregate_delta = updated.aggregate_delta;
        gate_count = updated.proof.gate_count;
        proof_artifact_binary_bytes = common::io::encode_proof_binary(&updated.proof)?.len();
    }

    Ok(UpdateBenchmarkResult {
        prover_micros,
        verifier_micros,
        aggregate_delta,
        gate_count,
        proof_artifact_binary_bytes,
    })
}

fn print_update_benchmark_result(result: &UpdateBenchmarkResult) {
    let prover = summarize_samples(&result.prover_micros);
    let verifier = summarize_samples(&result.verifier_micros);
    println!("prover_min_micros={}", prover.min);
    println!("prover_median_micros={}", prover.median);
    println!("prover_p95_micros={}", prover.p95);
    println!("prover_mean_micros={}", prover.mean);
    println!("verifier_min_micros={}", verifier.min);
    println!("verifier_median_micros={}", verifier.median);
    println!("verifier_p95_micros={}", verifier.p95);
    println!("verifier_mean_micros={}", verifier.mean);
    println!(
        "proof_artifact_binary_bytes={}",
        result.proof_artifact_binary_bytes
    );
    println!("aggregate_delta={}", result.aggregate_delta);
    println!("gate_count={}", result.gate_count);
}

#[derive(Debug)]
struct SampleSummary {
    min: u128,
    median: u128,
    p95: u128,
    mean: u128,
}

fn summarize_samples(samples: &[u128]) -> SampleSummary {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let p95_index = ((sorted.len() * 95).div_ceil(100)).saturating_sub(1);
    SampleSummary {
        min: sorted[0],
        median: sorted[(sorted.len() - 1) / 2],
        p95: sorted[p95_index],
        mean: sorted.iter().sum::<u128>() / sorted.len() as u128,
    }
}

fn parse_bench_count(value: Option<&String>, name: &str, default: usize) -> Result<usize, String> {
    value
        .map(|raw| {
            raw.parse::<usize>()
                .map_err(|err| format!("invalid {name}: {err}"))
        })
        .transpose()
        .map(|parsed| parsed.unwrap_or(default))
}

fn warn_debug_benchmark() {
    if cfg!(debug_assertions) {
        eprintln!(
            "warning: benchmark is running without compiler optimizations; use `cargo run --release`"
        );
    }
}

fn load_srs_for_parallel_state(
    path: &Path,
    state: &StoredParallelState,
    modified: usize,
) -> Result<Srs, String> {
    let modified_powers = modified
        .checked_add(1)
        .ok_or_else(|| "modified-address count overflow".to_string())?;
    let needed_g1_len = state
        .shards
        .iter()
        .map(|shard| shard.masked_polynomial_coeffs.len())
        .max()
        .unwrap_or(1)
        .max(modified_powers);
    let needed_g2_len = modified_powers;
    load_srs_prefix(path, needed_g1_len, needed_g2_len)
}

fn load_srs_for_verify(path: &Path, modified: usize) -> Result<Srs, String> {
    let needed_len = modified
        .checked_add(1)
        .ok_or_else(|| "modified-address count overflow".to_string())?
        .max(2);
    load_srs_prefix(path, needed_len, needed_len)
}

fn load_srs_for_init_verify(path: &Path, state: &StoredState) -> Result<Srs, String> {
    load_srs_prefix(
        path,
        state.masked_polynomial_coeffs.len(),
        state.masked_polynomial_coeffs.len(),
    )
}

fn flatten_parallel_state(state: &StoredParallelState) -> StoredState {
    let max_coeff_len = state
        .shards
        .iter()
        .map(|shard| shard.masked_polynomial_coeffs.len())
        .max()
        .unwrap_or(1);
    StoredState {
        state_root: state.state_root.clone(),
        srs_max_degree: state.srs_max_degree,
        alpha: Fr::from(1u64),
        reserve_addresses: Vec::new(),
        reserve_balances: Vec::new(),
        masked_polynomial_coeffs: vec![Fr::zero(); max_coeff_len],
        accumulator_hex: String::new(),
        balance_total: state.balance_total,
        balance_blind: state.balance_blind,
        balance_commitment_hex: state.balance_commitment_hex.clone(),
    }
}

fn print_usage() {
    println!("Dynamic PoA daily commands:");
    println!("  ./poa setup [max-degree]");
    println!("  ./poa import-srs <source.srs.bin> <ceremony-id> [destination.srs.bin]");
    println!("  ./poa mock-data [accounts reserves blocks txs-per-block seed]");
    println!("  ./poa eth-sync <transition.json> [deltas.csv sync-output.json]");
    println!("  ./poa prove-init <state-root> [reserves.csv]");
    println!("  ./poa prove-update <state.txt> <deltas.csv> <new-state-root>");
    println!("  ./poa check-update <old-state.txt> <deltas.csv> <new-state.txt> <proof.txt> <sync-output.json> <policy.json>");
    println!("  ./poa check-update-debug <old-state.txt> <deltas.csv> <new-state.txt> <proof.txt>");
    println!("  ./poa state-digest <state.txt>");
    println!("  ./poa prove-threshold <state.txt> <threshold> [proof.txt]");
    println!("  ./poa check-threshold <public-state.txt> <threshold> <proof.txt>");
    println!();
    println!("Run `./poa help-advanced` for explicit paths, SP1, SMT, and benchmarks.");
}

fn print_advanced_usage() {
    println!("advanced commands:");
    println!("  poa-cli sp1-setup [setup-dir]          # protocol init + KZG insert");
    println!("  poa-cli sp1-smt-setup [setup-dir]      # separate SMT implementation");
    println!("  poa-cli gen-srs <max-degree> <srs.bin>");
    println!("  poa-cli init <srs.bin> <reserves.csv> <state-root> <state.txt> <init-proof.txt>");
    println!("  poa-cli init-mock-owned <srs.bin> <init-witness.csv> <chain-id> <state-root> <session-id> <state.txt> <init-proof.txt>");
    println!("  poa-cli prepare-run <run-dir> <max-degree> <reserves.csv> <state-root> <state.txt> <init-proof.txt>");
    println!("  poa-cli prepare-synthetic-run <run-dir> <degree> <state-root> <state.txt>");
    println!("  poa-cli prepare-synthetic-state <srs.bin> <degree> <state-root> <state.txt>");
    println!("  poa-cli parallel-init <srs.bin> <reserves.csv> <state-root> <shards> <state.txt> <init-proof.txt>");
    println!("  poa-cli parallel-update <srs.bin> <state.txt> <deltas.csv> <new-state-root> <next-state.txt> <proof.txt>");
    println!("  poa-cli parallel-verify <srs.bin> <old-state.txt> <deltas.csv> <new-state.txt> <proof.txt> <init-proof.txt>");
    println!("  poa-cli update <srs.bin> <state.txt> <deltas.csv> <new-state-root> <next-state.txt> <proof.txt>");
    println!("  poa-cli continue-run <run-dir> <current-state.txt> <deltas.csv> <new-state-root> <next-state.txt>");
    println!("  poa-cli continue-synthetic-run <run-dir> <current-state.txt> <modified-addresses> <new-state-root> <next-state.txt>");
    println!("  poa-cli continue-synthetic-state <srs.bin> <current-state.txt> <modified-addresses> <new-state-root> <next-state.txt>");
    println!("  poa-cli verify <srs.bin> <old-state.txt> <deltas.csv> <new-state.txt> <proof.txt> <init-proof.txt>");
    println!("  poa-cli mock-gen <out-dir> <num-accounts> <num-reserves> <num-blocks> <txs-per-block> <seed>");
    println!("  poa-cli mock-bench <srs.bin> <manifest.txt> <report.txt>");
    println!("  poa-cli synthetic-update-bench <srs.bin> <degree> <modified-addresses> [iterations] [warmup]");
    println!("  poa-cli update-bench <srs.bin> <state.txt> <deltas.csv> [iterations] [warmup]");
    println!("  poa-cli parallel-synthetic-update-bench <srs.bin> <degree> <modified-addresses> <shards>");
    println!("  poa-cli smt-init <depth> <reserves.csv> <state-root> <state.txt>");
    println!("  poa-cli smt-update <state.txt> <deltas.csv> <new-state-root> <next-state.txt> <proof.txt>");
    println!("  poa-cli smt-update-local <state.txt> <deltas.csv> <new-state-root> <next-state.txt> <proof.txt>");
    println!(
        "  poa-cli smt-update-execute <state.txt> <deltas.csv> <new-state-root> <next-state.txt>"
    );
    println!("  poa-cli smt-insert <state.txt> <address> <balance> <new-state-root> <next-state.txt> <proof.txt>");
    println!("  poa-cli smt-verify <old-state.txt> <new-state.txt> <proof.txt> <mode>");
    println!("  poa-cli prepare-smt-run <run-dir> <depth> <reserves.csv> <state-root> <state.txt>");
    println!("  poa-cli smt-synthetic-bench <depth> <num-reserves> <modified-addresses>");
    println!("  poa-cli smt-synthetic-execute <depth> <num-reserves> <modified-addresses>");
    println!("  poa-cli continue-smt-run <run-dir> <current-state.txt> <deltas.csv> <new-state-root> <next-state.txt>");
    println!("  poa-cli continue-smt-local-run <run-dir> <current-state.txt> <deltas.csv> <new-state-root> <next-state.txt>");
    println!("  poa-cli continue-smt-execute-run <run-dir> <current-state.txt> <deltas.csv> <new-state-root> <next-state.txt>");
}

fn build_synthetic_state(srs: &Srs, degree: usize) -> Result<StoredState, String> {
    let mut coeffs = Vec::with_capacity(degree + 1);
    for index in 0..degree {
        coeffs.push(hash_to_scalar(
            "synthetic-poly",
            &(index as u64).to_le_bytes(),
        ));
    }
    let leading = {
        let scalar = hash_to_scalar("synthetic-poly-leading", &(degree as u64).to_le_bytes());
        if scalar.is_zero() {
            Fr::from(1u64)
        } else {
            scalar
        }
    };
    coeffs.push(leading);

    let poly = Polynomial::from_coeffs(coeffs);
    let accumulator = commit_g1(srs, &poly)?;
    let balance_commitment = commit_balance(0, Fr::zero());

    Ok(StoredState {
        state_root: "synthetic-root".to_string(),
        srs_max_degree: srs.max_degree,
        alpha: Fr::from(1u64),
        reserve_addresses: Vec::new(),
        reserve_balances: Vec::new(),
        masked_polynomial_coeffs: poly.coeffs,
        accumulator_hex: point_g1_to_hex(&accumulator)?,
        balance_total: 0,
        balance_blind: Fr::zero(),
        balance_commitment_hex: point_g1_to_hex(&balance_commitment)?,
    })
}

fn build_parallel_synthetic_state(
    srs: &Srs,
    degree: usize,
    shards: usize,
) -> Result<StoredParallelState, String> {
    let active_shards = shards.max(1);
    let base = degree / active_shards;
    let remainder = degree % active_shards;
    let mut shard_states = Vec::with_capacity(active_shards);
    let mut balance_commitment = commit_balance(0, Fr::zero());

    for shard_id in 0..active_shards {
        let shard_degree = base + usize::from(shard_id < remainder);
        let mut coeffs = Vec::with_capacity(shard_degree + 1);
        for index in 0..shard_degree {
            let payload = format!("{shard_id}:{index}");
            coeffs.push(hash_to_scalar(
                "parallel-synthetic-poly",
                payload.as_bytes(),
            ));
        }
        let leading = {
            let payload = format!("{shard_id}:{shard_degree}");
            let scalar = hash_to_scalar("parallel-synthetic-poly-leading", payload.as_bytes());
            if scalar.is_zero() {
                Fr::from(1u64)
            } else {
                scalar
            }
        };
        coeffs.push(leading);

        let poly = Polynomial::from_coeffs(coeffs);
        let accumulator = commit_g1(srs, &poly)?;
        let shard_balance_commitment = commit_balance(0, Fr::zero());
        balance_commitment += shard_balance_commitment;
        shard_states.push(common::types::StoredParallelShardState {
            shard_id,
            alpha: Fr::from(1u64),
            reserve_addresses: Vec::new(),
            reserve_balances: Vec::new(),
            masked_polynomial_coeffs: poly.coeffs,
            accumulator_hex: point_g1_to_hex(&accumulator)?,
            balance_total: 0,
            balance_blind: Fr::zero(),
            balance_commitment_hex: point_g1_to_hex(&shard_balance_commitment)?,
        });
    }

    Ok(StoredParallelState {
        state_root: "parallel-synthetic-root".to_string(),
        srs_max_degree: srs.max_degree,
        shards: shard_states,
        balance_total: 0,
        balance_blind: Fr::zero(),
        balance_commitment_hex: point_g1_to_hex(&balance_commitment)?,
    })
}

fn derive_companion_proof_path(state_path: &Path) -> Result<std::path::PathBuf, String> {
    let stem = state_path
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("invalid state path {}", state_path.display()))?;
    let mut proof_name = format!("{stem}.proof");
    if let Some(ext) = state_path.extension().and_then(|value| value.to_str()) {
        proof_name.push('.');
        proof_name.push_str(ext);
    }
    Ok(state_path.with_file_name(proof_name))
}

fn public_state_path(state_path: &Path) -> std::path::PathBuf {
    let mut name = state_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("state")
        .to_string();
    name.push_str(".public");
    state_path.with_file_name(name)
}

fn read_public_state_or_derive(
    state_path: &Path,
    prover_state: &StoredState,
) -> Result<common::types::PublicState, String> {
    let public_path = public_state_path(state_path);
    if public_path.exists() {
        read_public_state(&public_path)
    } else {
        Ok(prover_state.public_state())
    }
}

fn build_synthetic_deltas(m: usize) -> Vec<Delta> {
    (0..m)
        .map(|index| Delta {
            address: format!("0x{:040x}", index + 1),
            delta: if index % 2 == 0 { 1 } else { -1 },
        })
        .collect()
}

fn build_smt_state_from_reserves(
    depth: usize,
    reserves: &[common::types::ReserveEntry],
    state_root: &str,
) -> Result<SmtState, String> {
    let mut leaves = Vec::with_capacity(reserves.len());
    for reserve in reserves {
        let salt = SmtState::fresh_salt("smt-init-salt", &reserve.address, reserve.balance);
        leaves.push(Leaf::new(reserve.address.clone(), reserve.balance, salt)?);
    }
    leaves.sort_by(|a, b| a.address.cmp(&b.address));
    let blind = hash_to_scalar("smt-init-blind", state_root.as_bytes());
    SmtState::new(state_root.to_string(), depth, leaves, blind)
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
        let salt = SmtState::fresh_salt("smt-synth-init-salt", &address, balance);
        leaves.push(Leaf::new(address, balance, salt)?);
    }
    let blind = hash_to_scalar("smt-synth-init-blind", state_root.as_bytes());
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
