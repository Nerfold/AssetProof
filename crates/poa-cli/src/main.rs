use std::env;
use std::fs;
use std::path::Path;
use std::time::Instant;

use ark_bls12_381::Fr;
use ark_ff::Zero;
use common::crypto::{hash_to_scalar, point_g1_to_hex};
use common::io::{
    read_delta_csv, read_proof, read_reserve_csv, read_smt_proof, read_smt_state, read_srs, read_srs_g1_prefix,
    read_srs_prefix, read_state, write_proof, write_smt_proof, write_smt_state, write_srs, write_state,
};
use common::types::{Delta, StoredState};
use mock_chain::generator::{generate_scenario, load_manifest, write_scenario};
use nizk_fixed_set::commitment::commit_balance;
use nizk_fixed_set::init::initialize;
use nizk_fixed_set::kzg::commit_g1;
use nizk_fixed_set::kzg::Srs;
use nizk_fixed_set::polynomial::Polynomial;
use nizk_fixed_set::update::apply_update;
use nizk_fixed_set::verifier::verify_update;
use smt::insert::build_insert_witness;
use smt::leaf::Leaf;
use smt::state::SmtState;
use sp1_host::insert::{build_and_execute_insert, prove_insert, verify_insert_proof};
use sp1_host::update::{
    build_and_execute_update, build_and_prove_update, verify_update_proof as verify_smt_update_proof,
};

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
        "gen-srs" => {
            if args.len() != 4 {
                return Err("usage: poa-cli gen-srs <max-degree> <srs.bin>".to_string());
            }
            let max_degree = args[2]
                .parse::<usize>()
                .map_err(|err| format!("invalid max-degree: {err}"))?;
            let srs = Srs::setup(max_degree, b"dynamic-poa-srs");
            write_srs(Path::new(&args[3]), srs.max_degree, &srs.tau_g1_powers, &srs.tau_g2_powers)?;
            println!("wrote SRS with max_degree={} to {}", max_degree, args[3]);
        }
        "init" => {
            if args.len() != 6 {
                return Err("usage: poa-cli init <srs.bin> <reserves.csv> <state-root> <state.txt>".to_string());
            }
            let srs = load_srs(Path::new(&args[2]))?;
            let reserves = read_reserve_csv(Path::new(&args[3]))?;
            let init = initialize(&reserves, &args[4], &srs)?;
            write_state(Path::new(&args[5]), &init.state)?;
            println!(
                "initialized n={}, balance_total={}, state_root={}",
                init.state.reserve_addresses.len(),
                init.state.balance_total,
                init.state.state_root
            );
        }
        "prepare-run" => {
            if args.len() != 7 {
                return Err(
                    "usage: poa-cli prepare-run <run-dir> <max-degree> <reserves.csv> <state-root> <state.txt>"
                        .to_string(),
                );
            }
            let run_dir = Path::new(&args[2]);
            fs::create_dir_all(run_dir).map_err(|err| format!("create {}: {err}", run_dir.display()))?;

            let max_degree = args[3]
                .parse::<usize>()
                .map_err(|err| format!("invalid max-degree: {err}"))?;
            let srs_path = run_dir.join("srs.bin");
            if !srs_path.exists() {
                let srs = Srs::setup(max_degree, b"dynamic-poa-srs");
                write_srs(&srs_path, srs.max_degree, &srs.tau_g1_powers, &srs.tau_g2_powers)?;
                println!("generated srs at {}", srs_path.display());
            } else {
                println!("reusing existing srs at {}", srs_path.display());
            }

            let srs = load_srs(&srs_path)?;
            let reserves = read_reserve_csv(Path::new(&args[4]))?;
            let init = initialize(&reserves, &args[5], &srs)?;
            let state_path = Path::new(&args[6]);
            write_state(state_path, &init.state)?;
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
            fs::create_dir_all(run_dir).map_err(|err| format!("create {}: {err}", run_dir.display()))?;

            let degree = args[3]
                .parse::<usize>()
                .map_err(|err| format!("invalid degree: {err}"))?;
            let srs_path = run_dir.join("srs.bin");
            if !srs_path.exists() {
                let srs = Srs::setup(degree, b"dynamic-poa-srs");
                write_srs(&srs_path, srs.max_degree, &srs.tau_g1_powers, &srs.tau_g2_powers)?;
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
            println!(
                "prepared synthetic state: state={}, degree={}, accumulator_bound={}",
                state_path.display(),
                degree,
                srs.max_degree
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
            write_state(Path::new(&args[6]), &updated.next_state)?;
            write_proof(Path::new(&args[7]), &updated.proof)?;
            println!(
                "updated m={}, aggregate_delta={}, gate_count={}",
                deltas.len(),
                updated.proof.d_value,
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
            write_state(Path::new(&args[6]), &updated.next_state)?;
            let proof_path = derive_companion_proof_path(Path::new(&args[6]))?;
            write_proof(&proof_path, &updated.proof)?;
            println!(
                "continued run: next_state={}, proof={}, m={}, aggregate_delta={}",
                args[6],
                proof_path.display(),
                deltas.len(),
                updated.proof.d_value
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
            write_state(Path::new(&args[6]), &updated.next_state)?;
            let proof_path = derive_companion_proof_path(Path::new(&args[6]))?;
            write_proof(&proof_path, &updated.proof)?;
            println!(
                "continued synthetic run: next_state={}, proof={}, m={}, aggregate_delta={}",
                args[6],
                proof_path.display(),
                deltas.len(),
                updated.proof.d_value
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
            write_state(Path::new(&args[6]), &updated.next_state)?;
            let proof_path = derive_companion_proof_path(Path::new(&args[6]))?;
            write_proof(&proof_path, &updated.proof)?;
            println!(
                "continued synthetic state: next_state={}, proof={}, m={}, aggregate_delta={}",
                args[6],
                proof_path.display(),
                deltas.len(),
                updated.proof.d_value
            );
        }
        "verify" => {
            if args.len() != 7 {
                return Err(
                    "usage: poa-cli verify <srs.bin> <old-state.txt> <deltas.csv> <new-state.txt> <proof.txt>"
                        .to_string(),
                );
            }
            let old_state = read_state(Path::new(&args[3]))?;
            let deltas = read_delta_csv(Path::new(&args[4]))?;
            let srs = load_srs_for_verify(Path::new(&args[2]), deltas.len())?;
            let new_state = read_state(Path::new(&args[5]))?;
            let proof = read_proof(Path::new(&args[6]))?;
            verify_update(&srs, &old_state, &deltas, &new_state, &proof)?;
            println!(
                "verification passed for m={}, new_balance_total={}",
                deltas.len(),
                new_state.balance_total
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
                args[7].parse::<u64>().map_err(|err| format!("seed: {err}"))?,
                args[3].parse::<usize>().map_err(|err| format!("num-accounts: {err}"))?,
                args[4].parse::<usize>().map_err(|err| format!("num-reserves: {err}"))?,
                args[5].parse::<usize>().map_err(|err| format!("num-blocks: {err}"))?,
                args[6].parse::<usize>().map_err(|err| format!("txs-per-block: {err}"))?,
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
                return Err("usage: poa-cli mock-bench <srs.bin> <manifest.txt> <report.txt>".to_string());
            }
            let srs = load_srs(Path::new(&args[2]))?;
            let scenario = load_manifest(Path::new(&args[3]))?;
            let mut report = String::new();
            let init_start = Instant::now();
            let init = initialize(&scenario.reserves, &scenario.initial_root, &srs)?;
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
                verify_update(&srs, &current_state, &window.deltas, &updated.next_state, &updated.proof)?;
                total_verify_micros += verify_start.elapsed().as_micros();

                total_m += window.deltas.len();
                total_delta += updated.proof.d_value;
                report.push_str(&format!(
                    "window_{:04}_m={}\nwindow_{:04}_delta={}\nwindow_{:04}_gate_count={}\n",
                    window.index,
                    window.deltas.len(),
                    window.index,
                    updated.proof.d_value,
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
            if args.len() != 5 {
                return Err(
                    "usage: poa-cli synthetic-update-bench <srs.bin> <degree> <modified-addresses>".to_string(),
                );
            }
            let srs = load_srs(Path::new(&args[2]))?;
            let degree = args[3]
                .parse::<usize>()
                .map_err(|err| format!("invalid degree: {err}"))?;
            let modified = args[4]
                .parse::<usize>()
                .map_err(|err| format!("invalid modified-addresses: {err}"))?;

            let state_start = Instant::now();
            let state = build_synthetic_state(&srs, degree)?;
            let deltas = build_synthetic_deltas(modified);
            let state_elapsed = state_start.elapsed();
            eprintln!("stage=state_complete millis={}", state_elapsed.as_millis());

            let update_start = Instant::now();
            let updated = apply_update(&srs, &state, &deltas, "synthetic-next-root")?;
            let update_elapsed = update_start.elapsed();
            eprintln!("stage=update_complete millis={}", update_elapsed.as_millis());

            let verify_start = Instant::now();
            verify_update(&srs, &state, &deltas, &updated.next_state, &updated.proof)?;
            let verify_elapsed = verify_start.elapsed();
            eprintln!("stage=verify_complete millis={}", verify_elapsed.as_millis());

            println!("synthetic_degree={degree}");
            println!("modified_addresses={modified}");
            println!("state_build_millis={}", state_elapsed.as_millis());
            println!("update_millis={}", update_elapsed.as_millis());
            println!("verify_millis={}", verify_elapsed.as_millis());
            println!("aggregate_delta={}", updated.proof.d_value);
            println!("gate_count={}", updated.proof.gate_count);
        }
        "smt-init" => {
            if args.len() != 6 {
                return Err("usage: poa-cli smt-init <depth> <reserves.csv> <state-root> <state.txt>".to_string());
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
        "smt-verify" => {
            if args.len() != 6 {
                return Err("usage: poa-cli smt-verify <old-state.txt> <new-state.txt> <proof.txt> <mode>".to_string());
            }
            let old_state = SmtState::from_stored(&read_smt_state(Path::new(&args[2]))?)?;
            let new_state = SmtState::from_stored(&read_smt_state(Path::new(&args[3]))?)?;
            let proof = read_smt_proof(Path::new(&args[4]))?;
            match args[5].as_str() {
                "update" => verify_smt_update_proof(&old_state, &new_state, &proof)?,
                "insert" => verify_insert_proof(&old_state, &new_state, &proof)?,
                other => return Err(format!("unknown smt-verify mode {other}, expected update or insert")),
            }
            println!(
                "smt verification passed mode={}, old_root={}, new_root={}",
                args[5],
                old_state.state_root,
                new_state.state_root
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
                args[3],
                balance,
                result.next_state.balance_total
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
            fs::create_dir_all(run_dir).map_err(|err| format!("create {}: {err}", run_dir.display()))?;
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
            let insert_result = prove_insert(&update_result.next_state, "smt-synth-root-2", insert_witness)?;
            let insert_elapsed = insert_start.elapsed();

            let insert_verify_start = Instant::now();
            verify_insert_proof(&update_result.next_state, &insert_result.next_state, &insert_result.proof)?;
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
            println!("post_update_balance_total={}", update_result.next_state.balance_total);
            println!("post_insert_balance_total={}", insert_result.next_state.balance_total);
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
            println!("update_execute_instructions={}", update_exec.instruction_count);
            println!("insert_execute_millis={}", insert_elapsed.as_millis());
            println!("insert_execute_instructions={}", insert_exec.instruction_count);
            println!("aggregate_delta={}", update_exec.public_values.aggregate_delta);
            println!("post_update_balance_total={}", update_exec.public_values.new_balance_total);
            println!("post_insert_balance_total={}", insert_exec.public_values.new_balance_total);
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
        _ => print_usage(),
    }

    Ok(())
}

fn load_srs(path: &Path) -> Result<Srs, String> {
    let (max_degree, tau_g1_powers, tau_g2_powers) = read_srs(path)?;
    Ok(Srs {
        max_degree,
        tau: common::crypto::hash_to_scalar("unused-srs-tau-placeholder", b"loaded-from-file"),
        tau_g1_powers,
        tau_g2_powers,
    })
}

fn load_srs_g1_prefix(path: &Path, needed_g1_len: usize) -> Result<Srs, String> {
    let (max_degree, tau_g1_powers) = read_srs_g1_prefix(path, needed_g1_len)?;
    Ok(Srs {
        max_degree,
        tau: common::crypto::hash_to_scalar("unused-srs-tau-placeholder", b"loaded-from-file"),
        tau_g1_powers,
        tau_g2_powers: Vec::new(),
    })
}

fn load_srs_prefix(path: &Path, needed_g1_len: usize, needed_g2_len: usize) -> Result<Srs, String> {
    let (max_degree, tau_g1_powers, tau_g2_powers) = read_srs_prefix(path, needed_g1_len, needed_g2_len)?;
    Ok(Srs {
        max_degree,
        tau: common::crypto::hash_to_scalar("unused-srs-tau-placeholder", b"loaded-from-file"),
        tau_g1_powers,
        tau_g2_powers,
    })
}

fn load_srs_for_update(path: &Path, state: &StoredState, modified: usize) -> Result<Srs, String> {
    let needed_g1_len = state.masked_polynomial_coeffs.len();
    let needed_g2_len = modified + 1;
    load_srs_prefix(path, needed_g1_len, needed_g2_len)
}

fn load_srs_for_verify(path: &Path, modified: usize) -> Result<Srs, String> {
    let needed_len = modified + 1;
    load_srs_prefix(path, needed_len, needed_len)
}

fn print_usage() {
    println!("usage:");
    println!("  poa-cli gen-srs <max-degree> <srs.bin>");
    println!("  poa-cli init <srs.bin> <reserves.csv> <state-root> <state.txt>");
    println!("  poa-cli prepare-run <run-dir> <max-degree> <reserves.csv> <state-root> <state.txt>");
    println!("  poa-cli prepare-synthetic-run <run-dir> <degree> <state-root> <state.txt>");
    println!("  poa-cli prepare-synthetic-state <srs.bin> <degree> <state-root> <state.txt>");
    println!("  poa-cli update <srs.bin> <state.txt> <deltas.csv> <new-state-root> <next-state.txt> <proof.txt>");
    println!("  poa-cli continue-run <run-dir> <current-state.txt> <deltas.csv> <new-state-root> <next-state.txt>");
    println!("  poa-cli continue-synthetic-run <run-dir> <current-state.txt> <modified-addresses> <new-state-root> <next-state.txt>");
    println!("  poa-cli continue-synthetic-state <srs.bin> <current-state.txt> <modified-addresses> <new-state-root> <next-state.txt>");
    println!("  poa-cli verify <srs.bin> <old-state.txt> <deltas.csv> <new-state.txt> <proof.txt>");
    println!("  poa-cli mock-gen <out-dir> <num-accounts> <num-reserves> <num-blocks> <txs-per-block> <seed>");
    println!("  poa-cli mock-bench <srs.bin> <manifest.txt> <report.txt>");
    println!("  poa-cli synthetic-update-bench <srs.bin> <degree> <modified-addresses>");
    println!("  poa-cli smt-init <depth> <reserves.csv> <state-root> <state.txt>");
    println!("  poa-cli smt-update <state.txt> <deltas.csv> <new-state-root> <next-state.txt> <proof.txt>");
    println!("  poa-cli smt-insert <state.txt> <address> <balance> <new-state-root> <next-state.txt> <proof.txt>");
    println!("  poa-cli smt-verify <old-state.txt> <new-state.txt> <proof.txt> <mode>");
    println!("  poa-cli prepare-smt-run <run-dir> <depth> <reserves.csv> <state-root> <state.txt>");
    println!("  poa-cli smt-synthetic-bench <depth> <num-reserves> <modified-addresses>");
    println!("  poa-cli smt-synthetic-execute <depth> <num-reserves> <modified-addresses>");
    println!("  poa-cli continue-smt-run <run-dir> <current-state.txt> <deltas.csv> <new-state-root> <next-state.txt>");
}

fn build_synthetic_state(srs: &Srs, degree: usize) -> Result<StoredState, String> {
    let mut coeffs = Vec::with_capacity(degree + 1);
    for index in 0..degree {
        coeffs.push(hash_to_scalar("synthetic-poly", &(index as u64).to_le_bytes()));
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
        leaves.push(Leaf::new(
            reserve.address.clone(),
            reserve.balance,
            salt,
        )?);
    }
    leaves.sort_by(|a, b| a.address.cmp(&b.address));
    let blind = hash_to_scalar("smt-init-blind", state_root.as_bytes());
    SmtState::new(state_root.to_string(), depth, leaves, blind)
}

fn build_synthetic_smt_state(depth: usize, num_reserves: usize, state_root: &str) -> Result<SmtState, String> {
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
