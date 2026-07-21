use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use common::io::{read_smt_init_proof, read_smt_state, write_smt_init_proof};
use common::types::{Delta, InitProvingContext};
use poa_bench::{ethereum_fixture, master_fixture_dir, FIXTURE_VERSION};
use smt::state::SmtState;
use sp1_host::setup::default_setup_dir;
use sp1_host::smt_init::{ensure_setup, prove_smt_initialization, verify_smt_initialization};

const SMT_FIXTURE_VERSION: &str = "poseidon-smt-persisted-v1";

fn main() {
    if let Err(err) = run() {
        eprintln!("SMT fixture error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    let fixture_dir = PathBuf::from(required(&args, "--fixture-dir")?);
    let output_dir = PathBuf::from(required(&args, "--output-dir")?);
    let master_n = parse_usize(required(&args, "--master-n")?, "master-n")?;
    let depth = parse_usize(required(&args, "--depth")?, "depth")?;
    let force = args
        .get("--force")
        .map(|value| parse_bool(value, "force"))
        .transpose()?
        .unwrap_or(false);
    let n_sizes = parse_sizes(required(&args, "--n")?, "n")?;
    let m_sizes = parse_sizes(required(&args, "--m")?, "m")?;
    if master_n == 0 || n_sizes.is_empty() || n_sizes.iter().any(|n| *n == 0 || *n > master_n) {
        return Err("master-n must be positive and at least every requested n".to_string());
    }

    let source_dir = master_fixture_dir(&fixture_dir, master_n);
    if !ethereum_fixture::master_accounts_path(&source_dir).is_file() {
        return Err(format!(
            "missing NIZK benchmark fixture {}; run scripts/initialize_benchmark_data.sh first",
            source_dir.display()
        ));
    }
    fs::create_dir_all(&output_dir)
        .map_err(|err| format!("create {}: {err}", output_dir.display()))?;

    println!("Persisted Poseidon SMT initialization");
    println!("  source fixture: {}", source_dir.display());
    println!("  output:         {}", output_dir.display());
    println!("  depth:          {depth}");
    println!("  n sizes:        {n_sizes:?}");
    println!("  m sizes:        {m_sizes:?}");

    ensure_setup(&default_setup_dir())?;
    for n in n_sizes {
        persist_one(
            &source_dir,
            &output_dir,
            master_n,
            n,
            &m_sizes,
            depth,
            force,
        )?;
    }
    Ok(())
}

fn persist_one(
    source_dir: &Path,
    output_dir: &Path,
    master_n: usize,
    n: usize,
    m_sizes: &[usize],
    depth: usize,
    force: bool,
) -> Result<(), String> {
    println!("\n== SMT initialization n={n}, depth={depth} ==");
    let run_dir = output_dir.join(format!("n_{n}"));
    fs::create_dir_all(&run_dir).map_err(|err| format!("create {}: {err}", run_dir.display()))?;
    let state_path = run_dir.join("state-0000.txt");
    let proof_path = run_dir.join("initialization-proof.txt");
    let session_id =
        format!("{SMT_FIXTURE_VERSION}:{FIXTURE_VERSION}:master-{master_n}:n-{n}:depth-{depth}");

    let (source_state_root, insert) = ethereum_fixture::load_insert_fixture(
        source_dir,
        master_n,
        ethereum_fixture::FixtureValidation::None,
    )?;
    let context = InitProvingContext {
        chain_id: ethereum_fixture::CHAIN_ID.to_string(),
        state_root: source_state_root.clone(),
        session_id: session_id.clone(),
        chain_batch_proof: None,
    };

    let reused = !force && state_path.is_file() && proof_path.is_file();
    let state = if reused {
        let state = SmtState::from_stored_owned(read_smt_state(&state_path)?)?;
        let proof = read_smt_init_proof(&proof_path)?;
        verify_smt_initialization(&context, &state.public_state(), &proof)?;
        println!("   reusing verified state and initialization proof");
        state
    } else {
        let fixture = ethereum_fixture::load_init_fixture(
            source_dir,
            master_n,
            n,
            ethereum_fixture::FixtureValidation::None,
        )?;
        if fixture.state_root != source_state_root
            || fixture.insert.address != insert.address
            || fixture.insert.balance != insert.balance
        {
            return Err(
                "initialization and insertion fixtures use different master states".to_string(),
            );
        }
        let proving_context = InitProvingContext {
            chain_batch_proof: Some(fixture.merkle_prefix_proof.clone()),
            ..context.clone()
        };
        let result = prove_smt_initialization(&proving_context, &fixture.witnesses, depth)?;
        result.state.persist(&state_path)?;
        write_smt_init_proof(&proof_path, &result.proof)?;
        println!("   initialization proof generated and persisted");
        result.state
    };

    if state.state_root != source_state_root || state.leaf_count() != n || state.depth != depth {
        return Err("persisted SMT state does not match its source fixture".to_string());
    }

    let insert_path = run_dir.join("insert.csv");
    fs::write(
        &insert_path,
        format!(
            "# source_state_root={}\n{},{}\n",
            source_state_root, insert.address, insert.balance
        ),
    )
    .map_err(|err| format!("write {}: {err}", insert_path.display()))?;

    let mut manifest = vec![
        format!("version={SMT_FIXTURE_VERSION}"),
        format!("source_fixture_version={FIXTURE_VERSION}"),
        format!("source_fixture_dir={}", source_dir.display()),
        format!("master_n={master_n}"),
        format!("n={n}"),
        format!("depth={depth}"),
        format!("chain_id={}", ethereum_fixture::CHAIN_ID),
        format!("state_root={source_state_root}"),
        format!("session_id={session_id}"),
        format!("smt_root={}", smt::state::hex_string(&state.smt_root())),
        format!("balance_total={}", state.balance_total),
        format!("reserve_count={}", state.leaf_count()),
        format!("state_path={}", state_path.display()),
        format!("initialization_proof_path={}", proof_path.display()),
        format!("insert_path={}", insert_path.display()),
        format!("insert_address={}", insert.address),
        format!("insert_balance={}", insert.balance),
        format!("insert_new_state_root={source_state_root}"),
        format!("reused={reused}"),
    ];

    for &m in m_sizes {
        if m > n {
            return Err(format!("m={m} exceeds n={n}"));
        }
        let source_delta = ethereum_fixture::delta_fixture_path(source_dir, n, m);
        let (deltas, new_root, _, _, _) =
            ethereum_fixture::ensure_delta_fixture(&source_delta, &source_state_root, n, m)?;
        let local_delta = run_dir.join(format!("deltas-m-{m}.csv"));
        write_delta_csv(&local_delta, &source_state_root, &new_root, &deltas)?;
        manifest.push(format!("m.{m}.delta_path={}", local_delta.display()));
        manifest.push(format!("m.{m}.new_state_root={new_root}"));
    }
    manifest.push("status=complete".to_string());
    let manifest_path = run_dir.join("manifest.txt");
    fs::write(&manifest_path, manifest.join("\n") + "\n")
        .map_err(|err| format!("write {}: {err}", manifest_path.display()))?;
    println!("   state:    {}", state_path.display());
    println!("   proof:    {}", proof_path.display());
    println!("   manifest: {}", manifest_path.display());
    Ok(())
}

fn write_delta_csv(
    path: &Path,
    old_state_root: &str,
    new_state_root: &str,
    deltas: &[Delta],
) -> Result<(), String> {
    let mut body = format!(
        "old_state_root={old_state_root}\nnew_state_root={new_state_root}\naddress,delta\n"
    );
    for delta in deltas {
        body.push_str(&format!("{},{}\n", delta.address, delta.delta));
    }
    fs::write(path, body).map_err(|err| format!("write {}: {err}", path.display()))
}

fn parse_args() -> Result<BTreeMap<String, String>, String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let mut values = BTreeMap::new();
    let mut index = 0usize;
    while index < args.len() {
        if !args[index].starts_with("--") || index + 1 >= args.len() {
            return Err(format!("expected --key value, got {}", args[index]));
        }
        values.insert(args[index].clone(), args[index + 1].clone());
        index += 2;
    }
    Ok(values)
}

fn required<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, String> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing required argument {key}"))
}

fn parse_usize(value: &str, label: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|err| format!("invalid {label}: {err}"))
}

fn parse_bool(value: &str, label: &str) -> Result<bool, String> {
    match value {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => Err(format!("invalid {label}: expected true or false")),
    }
}

fn parse_sizes(value: &str, label: &str) -> Result<Vec<usize>, String> {
    let mut sizes = value
        .split(',')
        .filter(|item| !item.trim().is_empty())
        .map(|item| parse_usize(item.trim(), label))
        .collect::<Result<Vec<_>, _>>()?;
    sizes.sort_unstable();
    sizes.dedup();
    Ok(sizes)
}
