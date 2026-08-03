use std::collections::BTreeMap;
use std::fs;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use common::crypto::hex_decode;
use common::io::{read_delta_csv, read_smt_state, write_smt_init_proof, write_smt_proof};
use common::types::{Delta, InitProvingContext, InitReserveWitness};
use poa_bench::{ethereum_fixture, master_fixture_dir, FIXTURE_VERSION};
use smt::state::SmtState;
use sp1_host::insert::{build_and_prove_insert_into, verify_insert_proof};
use sp1_host::smt_init::{
    prepare_provers as prepare_init_provers, prove_smt_initialization, verify_smt_initialization,
    SmtInitializationResult,
};
use sp1_host::update::{
    build_and_prove_update_into, prepare_prover as prepare_update_prover, verify_update_proof,
};

fn main() {
    if let Err(err) = run() {
        eprintln!("SMT benchmark error: {err}");
        std::process::exit(1);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    Initialization,
    Insert,
    Update,
}

#[derive(Debug)]
struct Config {
    fixture_dir: PathBuf,
    state_dir: PathBuf,
    output_dir: PathBuf,
    master_n: usize,
    n_sizes: Vec<usize>,
    m_sizes: Vec<usize>,
    depth: usize,
    operations: Vec<Operation>,
    samples: usize,
    warmup: usize,
}

#[derive(Debug)]
struct SampleRecord {
    operation: &'static str,
    n: usize,
    m: usize,
    sample: usize,
    prover: Duration,
    verifier: Duration,
    proof_payload_bytes: usize,
    artifact_bytes: usize,
    proof_encoding: &'static str,
}

#[derive(Debug)]
struct LoadRecord {
    n: usize,
    m: usize,
    phase: &'static str,
    elapsed: Duration,
    bytes: u64,
    reused: bool,
}

#[derive(Clone, Copy, Debug)]
struct Stats {
    min_ms: f64,
    median_ms: f64,
    mean_ms: f64,
    p95_ms: f64,
    stddev_ms: f64,
}

#[derive(Debug)]
struct SummaryRecord {
    operation: &'static str,
    n: usize,
    m: usize,
    input_load: Duration,
    prover: Stats,
    verifier: Stats,
    proof_payload_bytes: usize,
    artifact_bytes: usize,
    proof_encoding: &'static str,
}

fn run() -> Result<(), String> {
    let config = parse_config()?;
    fs::create_dir_all(config.output_dir.join("proof-samples"))
        .map_err(|err| format!("create output directory: {err}"))?;
    require_fixture_manifest(&config)?;
    preflight_persisted_inputs(&config)?;
    write_environment(&config)?;

    println!("Poseidon SMT + SP1 benchmark suite");
    println!("  n sizes: {:?}", config.n_sizes);
    println!("  m sizes: {:?}", config.m_sizes);
    println!("  depth: {}", config.depth);
    println!("  operations: {}", operations_label(&config.operations));
    println!("  samples: {}, warmup: {}", config.samples, config.warmup);
    println!("  output: {}", config.output_dir.display());

    let mut raw = Vec::new();
    let mut loads = prepare_selected_provers(&config)?;
    let mut summaries = Vec::new();
    let source_dir = master_fixture_dir(&config.fixture_dir, config.master_n);

    for &n in &config.n_sizes {
        println!("\n== loading prepared SMT n={n} ==");
        let run_dir = config.state_dir.join(format!("n_{n}"));
        let manifest_path = run_dir.join("manifest.txt");
        require_file(&manifest_path, "persisted SMT manifest")?;
        validate_smt_manifest(&manifest_path, &config, n)?;

        if includes(&config, Operation::Initialization) {
            let started = Instant::now();
            let fixture = ethereum_fixture::load_init_fixture(
                &source_dir,
                config.master_n,
                n,
                ethereum_fixture::FixtureValidation::None,
            )?;
            let elapsed = started.elapsed();
            loads.push(LoadRecord {
                n,
                m: 0,
                phase: "ethereum_initialization_fixture_load",
                elapsed,
                bytes: fixture_init_bytes(&source_dir, n)?,
                reused: true,
            });
            summaries.push(benchmark_initialization(
                &config,
                n,
                &fixture.state_root,
                &fixture.witnesses,
                &fixture.merkle_prefix_proof,
                elapsed,
                &mut raw,
            )?);
        }

        // Initialization deliberately runs without retaining the persisted private SMT.
        // The tree is reconstructed inside the measured initialization operation, while
        // update/insert load their reusable state only after initialization has finished.
        let needs_state =
            includes(&config, Operation::Update) || includes(&config, Operation::Insert);
        let base_state = if needs_state {
            let state_path = run_dir.join("state-0000.txt");
            require_file(&state_path, "persisted SMT state")?;
            let started = Instant::now();
            let state = SmtState::from_stored_owned(read_smt_state(&state_path)?)?;
            let elapsed = started.elapsed();
            if state.depth != config.depth || state.leaf_count() != n {
                return Err(format!(
                    "persisted SMT state n={n} does not match depth={} and leaf count",
                    config.depth
                ));
            }
            loads.push(LoadRecord {
                n,
                m: 0,
                phase: "smt_private_state_load_and_validation",
                elapsed,
                bytes: state_artifact_bytes(&run_dir)?,
                reused: true,
            });
            Some(state)
        } else {
            None
        };

        if includes(&config, Operation::Insert) {
            let state = base_state
                .as_ref()
                .ok_or_else(|| "insert benchmark missing base state".to_string())?;
            let started = Instant::now();
            let (fixture_root, insert) = ethereum_fixture::load_insert_fixture(
                &source_dir,
                config.master_n,
                ethereum_fixture::FixtureValidation::None,
            )?;
            let elapsed = started.elapsed();
            if fixture_root != state.state_root {
                return Err("insert fixture root does not match persisted SMT state".to_string());
            }
            loads.push(LoadRecord {
                n,
                m: 0,
                phase: "ethereum_insert_fixture_load",
                elapsed,
                bytes: fs::metadata(ethereum_fixture::insert_proof_path(&source_dir))
                    .map(|value| value.len())
                    .unwrap_or(0),
                reused: true,
            });
            let new_root = manifest_value(&manifest_path, "insert_new_state_root")?;
            summaries.push(benchmark_insert(
                &config,
                n,
                state,
                &insert.address,
                insert.balance,
                &new_root,
                elapsed,
                &mut raw,
            )?);
        }

        if includes(&config, Operation::Update) {
            let state = base_state
                .as_ref()
                .ok_or_else(|| "update benchmark missing base state".to_string())?;
            for &m in &config.m_sizes {
                if m > n {
                    return Err(format!(
                        "m={m} exceeds n={n}; the persisted fixture currently materializes member updates"
                    ));
                }
                let delta_path = run_dir.join(format!("deltas-m-{m}.csv"));
                require_file(&delta_path, "persisted SMT delta fixture")?;
                let started = Instant::now();
                let deltas = read_delta_csv(&delta_path)?;
                let elapsed = started.elapsed();
                if deltas.len() != m {
                    return Err(format!(
                        "{} contains {} deltas, expected {m}",
                        delta_path.display(),
                        deltas.len()
                    ));
                }
                loads.push(LoadRecord {
                    n,
                    m,
                    phase: "smt_delta_fixture_load",
                    elapsed,
                    bytes: fs::metadata(&delta_path)
                        .map_err(|err| format!("metadata {}: {err}", delta_path.display()))?
                        .len(),
                    reused: true,
                });
                let new_root = manifest_value(&manifest_path, &format!("m.{m}.new_state_root"))?;
                summaries.push(benchmark_update(
                    &config, n, m, state, &deltas, &new_root, elapsed, &mut raw,
                )?);
            }
        }
    }

    write_raw_csv(&config.output_dir.join("raw.csv"), &raw)?;
    write_load_csv(&config.output_dir.join("loading.csv"), &loads)?;
    write_summary_csv(&config.output_dir.join("summary.csv"), &summaries)?;
    write_summary_markdown(&config, &loads, &summaries)?;
    common::profiling::write_reports(&config.output_dir.join("profile"))?;
    println!(
        "\nSMT benchmark complete: {}/summary.md",
        config.output_dir.display()
    );
    Ok(())
}

fn prepare_selected_provers(config: &Config) -> Result<Vec<LoadRecord>, String> {
    println!("\n== preparing reusable SP1 prover contexts outside sample timers ==");
    let mut loads = Vec::new();
    if includes(config, Operation::Initialization) {
        for (guest, elapsed) in prepare_init_provers()? {
            println!("   {guest}: prepare={}", human_duration(elapsed));
            loads.push(LoadRecord {
                n: 0,
                m: 0,
                phase: match guest {
                    "smt-init" => "sp1_prover_prepare_smt_init",
                    "init-ownership" => "sp1_prover_prepare_init_ownership",
                    _ => "sp1_prover_prepare_smt_initialization_guest",
                },
                elapsed,
                bytes: 0,
                reused: false,
            });
        }
    }
    if includes(config, Operation::Update) {
        let elapsed = prepare_update_prover()?;
        println!("   smt-update: prepare={}", human_duration(elapsed));
        loads.push(LoadRecord {
            n: 0,
            m: 0,
            phase: "sp1_prover_prepare_smt_update",
            elapsed,
            bytes: 0,
            reused: false,
        });
    }
    if includes(config, Operation::Insert) {
        let elapsed = sp1_host::insert::prepare_prover()?;
        println!("   smt-insert: prepare={}", human_duration(elapsed));
        loads.push(LoadRecord {
            n: 0,
            m: 0,
            phase: "sp1_prover_prepare_smt_insert",
            elapsed,
            bytes: 0,
            reused: false,
        });
    }
    Ok(loads)
}

#[allow(clippy::too_many_arguments)]
fn benchmark_initialization(
    config: &Config,
    n: usize,
    state_root: &str,
    witnesses: &[InitReserveWitness],
    merkle_prefix_proof: &common::types::InitChainBatchProofInput,
    input_load: Duration,
    raw: &mut Vec<SampleRecord>,
) -> Result<SummaryRecord, String> {
    println!("-- SMT initialization n={n}, depth={}", config.depth);
    for warmup in 0..config.warmup {
        println!("   warmup {}/{}", warmup + 1, config.warmup);
        let context = init_context(
            state_root,
            n,
            &format!("warmup-{warmup}"),
            merkle_prefix_proof,
        );
        let result = prove_smt_initialization(&context, witnesses, config.depth)?;
        verify_smt_initialization(&context, &result.state.public_state(), &result.proof)?;
        black_box(result);
    }

    let mut prover = Vec::with_capacity(config.samples);
    let mut verifier = Vec::with_capacity(config.samples);
    let mut payloads = Vec::with_capacity(config.samples);
    let mut artifacts = Vec::with_capacity(config.samples);
    for sample in 0..config.samples {
        let _profile = profile_context("initialization", n, 0, sample);
        let context = init_context(
            state_root,
            n,
            &format!("sample-{sample}"),
            merkle_prefix_proof,
        );
        let probe_before = common::profiling::probe_overhead();
        let started = Instant::now();
        let result = prove_smt_initialization(&context, witnesses, config.depth)?;
        let with_probe = started.elapsed();
        let probe = common::profiling::probe_overhead().saturating_sub(probe_before);
        let prove_elapsed = with_probe.saturating_sub(probe);

        let verify_started = Instant::now();
        verify_smt_initialization(&context, &result.state.public_state(), &result.proof)?;
        let verify_elapsed = verify_started.elapsed();
        let payload = init_payload_bytes(&result)?;
        let path = config
            .output_dir
            .join("proof-samples")
            .join(format!("smt-init-n-{n}-last.txt"));
        write_smt_init_proof(&path, &result.proof)?;
        let artifact = file_len(&path)? as usize;
        print_sample(
            sample,
            config.samples,
            prove_elapsed,
            verify_elapsed,
            payload,
            artifact,
        );
        raw.push(SampleRecord {
            operation: "initialization",
            n,
            m: 0,
            sample: sample + 1,
            prover: prove_elapsed,
            verifier: verify_elapsed,
            proof_payload_bytes: payload,
            artifact_bytes: artifact,
            proof_encoding: "smt-init-two-sp1-bundles",
        });
        prover.push(prove_elapsed);
        verifier.push(verify_elapsed);
        payloads.push(payload);
        artifacts.push(artifact);
        black_box(result.state);
    }
    Ok(summary(
        "initialization",
        n,
        0,
        input_load,
        &prover,
        &verifier,
        &payloads,
        &artifacts,
        "smt-init-two-sp1-bundles",
    ))
}

#[allow(clippy::too_many_arguments)]
fn benchmark_update(
    config: &Config,
    n: usize,
    m: usize,
    state: &SmtState,
    deltas: &[Delta],
    new_state_root: &str,
    input_load: Duration,
    raw: &mut Vec<SampleRecord>,
) -> Result<SummaryRecord, String> {
    println!("-- SMT update n={n}, m={m}");
    for warmup in 0..config.warmup {
        println!("   warmup {}/{}", warmup + 1, config.warmup);
        let mut next_state = state.clone();
        let proof = build_and_prove_update_into(
            state,
            &mut next_state,
            deltas,
            new_state_root,
            SmtState::random_blind(),
        )?;
        verify_update_proof(state, &next_state, &proof)?;
        black_box((next_state, proof));
    }

    let mut prover = Vec::with_capacity(config.samples);
    let mut verifier = Vec::with_capacity(config.samples);
    let mut payloads = Vec::with_capacity(config.samples);
    let mut artifacts = Vec::with_capacity(config.samples);
    for sample in 0..config.samples {
        let _profile = profile_context("update", n, m, sample);
        let reset_started = Instant::now();
        let mut next_state = state.clone();
        common::profiling::record_phase(
            "smt-update-preparation",
            "sample_state_reset_excluded",
            reset_started.elapsed(),
        );
        let started = Instant::now();
        let proof = build_and_prove_update_into(
            state,
            &mut next_state,
            deltas,
            new_state_root,
            SmtState::random_blind(),
        )?;
        let prove_elapsed = started.elapsed();
        let verify_started = Instant::now();
        verify_update_proof(state, &next_state, &proof)?;
        let verify_elapsed = verify_started.elapsed();
        let payload = hex_decode(&proof.sp1_proof_hex)?.len();
        let path = config
            .output_dir
            .join("proof-samples")
            .join(format!("smt-update-n-{n}-m-{m}-last.txt"));
        write_smt_proof(&path, &proof)?;
        let artifact = file_len(&path)? as usize;
        print_sample(
            sample,
            config.samples,
            prove_elapsed,
            verify_elapsed,
            payload,
            artifact,
        );
        raw.push(SampleRecord {
            operation: "update",
            n,
            m,
            sample: sample + 1,
            prover: prove_elapsed,
            verifier: verify_elapsed,
            proof_payload_bytes: payload,
            artifact_bytes: artifact,
            proof_encoding: "smt-update-sp1-bundle",
        });
        prover.push(prove_elapsed);
        verifier.push(verify_elapsed);
        payloads.push(payload);
        artifacts.push(artifact);
        black_box((next_state, proof));
    }
    Ok(summary(
        "update",
        n,
        m,
        input_load,
        &prover,
        &verifier,
        &payloads,
        &artifacts,
        "smt-update-sp1-bundle",
    ))
}

#[allow(clippy::too_many_arguments)]
fn benchmark_insert(
    config: &Config,
    n: usize,
    state: &SmtState,
    address: &str,
    balance: i128,
    new_state_root: &str,
    input_load: Duration,
    raw: &mut Vec<SampleRecord>,
) -> Result<SummaryRecord, String> {
    println!("-- SMT insert n={n}");
    for warmup in 0..config.warmup {
        println!("   warmup {}/{}", warmup + 1, config.warmup);
        let mut next_state = state.clone();
        let proof = build_and_prove_insert_into(
            state,
            &mut next_state,
            address,
            balance,
            new_state_root,
            SmtState::random_blind(),
        )?;
        verify_insert_proof(state, &next_state, &proof)?;
        black_box((next_state, proof));
    }

    let mut prover = Vec::with_capacity(config.samples);
    let mut verifier = Vec::with_capacity(config.samples);
    let mut payloads = Vec::with_capacity(config.samples);
    let mut artifacts = Vec::with_capacity(config.samples);
    for sample in 0..config.samples {
        let _profile = profile_context("insert", n, 1, sample);
        let reset_started = Instant::now();
        let mut next_state = state.clone();
        common::profiling::record_phase(
            "smt-insert-preparation",
            "sample_state_reset_excluded",
            reset_started.elapsed(),
        );
        let started = Instant::now();
        let proof = build_and_prove_insert_into(
            state,
            &mut next_state,
            address,
            balance,
            new_state_root,
            SmtState::random_blind(),
        )?;
        let prove_elapsed = started.elapsed();
        let verify_started = Instant::now();
        verify_insert_proof(state, &next_state, &proof)?;
        let verify_elapsed = verify_started.elapsed();
        let payload = hex_decode(&proof.sp1_proof_hex)?.len();
        let path = config
            .output_dir
            .join("proof-samples")
            .join(format!("smt-insert-n-{n}-last.txt"));
        write_smt_proof(&path, &proof)?;
        let artifact = file_len(&path)? as usize;
        print_sample(
            sample,
            config.samples,
            prove_elapsed,
            verify_elapsed,
            payload,
            artifact,
        );
        raw.push(SampleRecord {
            operation: "insert",
            n,
            m: 1,
            sample: sample + 1,
            prover: prove_elapsed,
            verifier: verify_elapsed,
            proof_payload_bytes: payload,
            artifact_bytes: artifact,
            proof_encoding: "smt-insert-sp1-bundle",
        });
        prover.push(prove_elapsed);
        verifier.push(verify_elapsed);
        payloads.push(payload);
        artifacts.push(artifact);
        black_box((next_state, proof));
    }
    Ok(summary(
        "insert",
        n,
        1,
        input_load,
        &prover,
        &verifier,
        &payloads,
        &artifacts,
        "smt-insert-sp1-bundle",
    ))
}

fn init_context(
    state_root: &str,
    n: usize,
    suffix: &str,
    proof: &common::types::InitChainBatchProofInput,
) -> InitProvingContext {
    InitProvingContext {
        chain_id: ethereum_fixture::CHAIN_ID.to_string(),
        state_root: state_root.to_string(),
        session_id: format!("smt-benchmark-n-{n}-{suffix}"),
        chain_batch_proof: Some(proof.clone()),
    }
}

fn profile_context(
    operation: &str,
    n: usize,
    m: usize,
    sample: usize,
) -> common::profiling::ContextGuard {
    common::profiling::enter_context(common::profiling::ProfileContext {
        operation: operation.to_string(),
        n,
        m,
        sample: sample + 1,
        run_kind: "measured".to_string(),
    })
}

fn init_payload_bytes(result: &SmtInitializationResult) -> Result<usize, String> {
    Ok(hex_decode(&result.proof.sp1_proof_hex)?
        .len()
        .checked_add(hex_decode(&result.proof.ownership_sp1_proof_hex)?.len())
        .ok_or_else(|| "SMT initialization proof size overflow".to_string())?)
}

fn print_sample(
    sample: usize,
    samples: usize,
    prover: Duration,
    verifier: Duration,
    payload: usize,
    artifact: usize,
) {
    println!(
        "   sample {}/{}: prover={} verifier={} proof-payload={} artifact={}",
        sample + 1,
        samples,
        human_duration(prover),
        human_duration(verifier),
        human_bytes(payload),
        human_bytes(artifact)
    );
}

#[allow(clippy::too_many_arguments)]
fn summary(
    operation: &'static str,
    n: usize,
    m: usize,
    input_load: Duration,
    prover: &[Duration],
    verifier: &[Duration],
    payloads: &[usize],
    artifacts: &[usize],
    proof_encoding: &'static str,
) -> SummaryRecord {
    SummaryRecord {
        operation,
        n,
        m,
        input_load,
        prover: stats(prover),
        verifier: stats(verifier),
        proof_payload_bytes: median_size(payloads),
        artifact_bytes: median_size(artifacts),
        proof_encoding,
    }
}

fn stats(values: &[Duration]) -> Stats {
    let mut millis = values
        .iter()
        .map(|value| value.as_secs_f64() * 1_000.0)
        .collect::<Vec<_>>();
    millis.sort_by(f64::total_cmp);
    let mean = millis.iter().sum::<f64>() / millis.len() as f64;
    let variance = millis
        .iter()
        .map(|value| (value - mean) * (value - mean))
        .sum::<f64>()
        / millis.len() as f64;
    let p95 = ((millis.len() * 95).div_ceil(100)).saturating_sub(1);
    Stats {
        min_ms: millis[0],
        median_ms: millis[(millis.len() - 1) / 2],
        mean_ms: mean,
        p95_ms: millis[p95],
        stddev_ms: variance.sqrt(),
    }
}

fn median_size(values: &[usize]) -> usize {
    let mut values = values.to_vec();
    values.sort_unstable();
    values[(values.len() - 1) / 2]
}

fn write_raw_csv(path: &Path, records: &[SampleRecord]) -> Result<(), String> {
    let mut body = String::from(
        "scheme,operation,n,m,sample,prover_ns,verifier_ns,proof_payload_bytes,artifact_bytes,proof_encoding\n",
    );
    for value in records {
        body.push_str(&format!(
            "smt,{},{},{},{},{},{},{},{},{}\n",
            value.operation,
            value.n,
            value.m,
            value.sample,
            value.prover.as_nanos(),
            value.verifier.as_nanos(),
            value.proof_payload_bytes,
            value.artifact_bytes,
            value.proof_encoding
        ));
    }
    fs::write(path, body).map_err(|err| format!("write {}: {err}", path.display()))
}

fn write_load_csv(path: &Path, records: &[LoadRecord]) -> Result<(), String> {
    let mut body = String::from("scheme,n,m,phase,elapsed_ns,bytes,reused\n");
    for value in records {
        body.push_str(&format!(
            "smt,{},{},{},{},{},{}\n",
            value.n,
            value.m,
            value.phase,
            value.elapsed.as_nanos(),
            value.bytes,
            value.reused
        ));
    }
    fs::write(path, body).map_err(|err| format!("write {}: {err}", path.display()))
}

fn write_summary_csv(path: &Path, records: &[SummaryRecord]) -> Result<(), String> {
    let mut body = String::from(
        "scheme,operation,n,m,input_load_ms,parameter_load_ms,prover_min_ms,prover_median_ms,prover_mean_ms,prover_p95_ms,prover_stddev_ms,verifier_min_ms,verifier_median_ms,verifier_mean_ms,verifier_p95_ms,verifier_stddev_ms,proof_payload_bytes,artifact_bytes,proof_encoding\n",
    );
    for value in records {
        body.push_str(&format!(
            "smt,{},{},{},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{},{},{}\n",
            value.operation,
            value.n,
            value.m,
            duration_ms(value.input_load),
            0.0,
            value.prover.min_ms,
            value.prover.median_ms,
            value.prover.mean_ms,
            value.prover.p95_ms,
            value.prover.stddev_ms,
            value.verifier.min_ms,
            value.verifier.median_ms,
            value.verifier.mean_ms,
            value.verifier.p95_ms,
            value.verifier.stddev_ms,
            value.proof_payload_bytes,
            value.artifact_bytes,
            value.proof_encoding,
        ));
    }
    fs::write(path, body).map_err(|err| format!("write {}: {err}", path.display()))
}

fn write_summary_markdown(
    config: &Config,
    loads: &[LoadRecord],
    summaries: &[SummaryRecord],
) -> Result<(), String> {
    let mut body = format!(
        "# Poseidon SMT + SP1 benchmark report\n\n- scheme: `smt`\n- n sizes: `{:?}`\n- m sizes: `{:?}`\n- SMT depth: `{}`\n- operations: `{}`\n- measured samples: `{}`\n- warmup samples: `{}`\n- SP1 prover: `{}`\n- SP1 proof mode: `{}`\n\n",
        config.n_sizes,
        config.m_sizes,
        config.depth,
        operations_label(&config.operations),
        config.samples,
        config.warmup,
        std::env::var("SP1_PROVER").unwrap_or_else(|_| "cpu".to_string()),
        std::env::var("POA_SP1_PROOF_MODE").unwrap_or_else(|_| "compressed".to_string()),
    );
    body.push_str("`prover` is the online end-to-end protocol boundary. It includes private SMT construction for initialization, witness/multiproof construction for update/insert, host transition computation, stdin serialization/transport, SP1 proving, and returned-public-value checks. It excludes fixture/state loading, process/build time, reusable VK/PK context loading, persistent CUDA worker startup, one-time guest setup, artifact writes, and verification.\n\n");
    body.push_str("## Protocol timings\n\n| operation | n | m | input load | prover median | prover mean | prover p95 | verifier median | verifier mean | verifier p95 | proof payload | persisted artifact | encoding |\n");
    body.push_str("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|\n");
    for value in summaries {
        body.push_str(&format!(
            "| {} | {} | {} | {:.3} ms | {:.3} ms | {:.3} ms | {:.3} ms | {:.3} ms | {:.3} ms | {:.3} ms | {} | {} | {} |\n",
            value.operation,
            value.n,
            value.m,
            duration_ms(value.input_load),
            value.prover.median_ms,
            value.prover.mean_ms,
            value.prover.p95_ms,
            value.verifier.median_ms,
            value.verifier.mean_ms,
            value.verifier.p95_ms,
            human_bytes(value.proof_payload_bytes),
            human_bytes(value.artifact_bytes),
            value.proof_encoding,
        ));
    }
    body.push_str("\n## Preparation and loading\n\n| n | m | phase | elapsed | bytes | reused |\n|---:|---:|---|---:|---:|---|\n");
    for value in loads {
        body.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            value.n,
            value.m,
            value.phase,
            human_duration(value.elapsed),
            human_bytes(value.bytes as usize),
            value.reused,
        ));
    }
    body.push_str("\n## Methodology\n\n- Every measured initialization rebuilds the private host SMT and the `smt-init` guest independently reconstructs the Poseidon root from all leaves; both costs are included. The external mock Ethereum/Keccak tree is a prepared chain fixture and is excluded.\n- Update and insert start independently from the same immutable persisted initialization state. State/delta loading is reported separately.\n- A full-tree clone used only to reset repeated update/insert samples is excluded; witness construction, authenticated-path transition, new-root computation, stdin construction and proving are included. Profile mode records the reset as `sample_state_reset_excluded`.\n- One benchmark process owns one persistent CUDA worker. Selected guests are prepared before warmup and sample timers; per-proof socket serialization and transfer remain in prover latency.\n- Verification runs on CPU with locally trusted VKs and excludes external Sync/finality validation.\n- `proof payload` counts raw serialized SP1 bundle bytes (both split bundles for initialization); `persisted artifact` is the project text format written after the timer.\n- Enable `POA_SP1_PROFILE=1` for host phase records and the extra initialization guest execution probe. Probe time is subtracted from initialization prover samples.\n");
    fs::write(config.output_dir.join("summary.md"), body)
        .map_err(|err| format!("write summary.md: {err}"))
}

fn parse_config() -> Result<Config, String> {
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
    let fixture_dir = PathBuf::from(required(&values, "--fixture-dir")?);
    let state_dir = PathBuf::from(required(&values, "--state-dir")?);
    let output_dir = PathBuf::from(required(&values, "--output")?);
    let master_n = parse_usize(required(&values, "--master-n")?, "master-n")?;
    let n_sizes = parse_sizes(required(&values, "--n")?, "n")?;
    let m_sizes = parse_sizes(required(&values, "--m")?, "m")?;
    let depth = parse_usize(required(&values, "--depth")?, "depth")?;
    let samples = parse_usize(required(&values, "--samples")?, "samples")?;
    let warmup = parse_usize(required(&values, "--warmup")?, "warmup")?;
    let operations = parse_operations(
        values
            .get("--operations")
            .map(String::as_str)
            .unwrap_or("initialization,insert,update"),
    )?;
    if master_n == 0 || samples == 0 || !(1..=128).contains(&depth) {
        return Err("master-n/samples must be positive and depth must be in 1..=128".to_string());
    }
    if n_sizes.is_empty() || m_sizes.is_empty() || n_sizes.iter().any(|n| *n > master_n) {
        return Err("n/m lists must be non-empty and every n must be <= master-n".to_string());
    }
    Ok(Config {
        fixture_dir,
        state_dir,
        output_dir,
        master_n,
        n_sizes,
        m_sizes,
        depth,
        operations,
        samples,
        warmup,
    })
}

fn parse_operations(value: &str) -> Result<Vec<Operation>, String> {
    let value = if value == "all" {
        "initialization,insert,update"
    } else {
        value
    };
    let mut result = Vec::new();
    for name in value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let operation = match name {
            "initialization" | "init" => Operation::Initialization,
            "insert" => Operation::Insert,
            "update" => Operation::Update,
            _ => return Err(format!("unsupported operation {name}")),
        };
        if !result.contains(&operation) {
            result.push(operation);
        }
    }
    if result.is_empty() {
        return Err("at least one operation is required".to_string());
    }
    Ok(result)
}

fn parse_sizes(value: &str, name: &str) -> Result<Vec<usize>, String> {
    let mut result = value
        .split(',')
        .map(|value| parse_usize(value, name))
        .collect::<Result<Vec<_>, _>>()?;
    result.sort_unstable();
    result.dedup();
    if result.iter().any(|value| *value == 0) {
        return Err(format!("{name} values must be positive"));
    }
    Ok(result)
}

fn parse_usize(value: &str, name: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|err| format!("invalid {name} {value}: {err}"))
}

fn required<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, String> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing {key}"))
}

fn includes(config: &Config, operation: Operation) -> bool {
    config.operations.contains(&operation)
}

fn operations_label(operations: &[Operation]) -> String {
    operations
        .iter()
        .map(|value| match value {
            Operation::Initialization => "initialization",
            Operation::Insert => "insert",
            Operation::Update => "update",
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn require_fixture_manifest(config: &Config) -> Result<(), String> {
    let path = config.fixture_dir.join("preparation-manifest.txt");
    require_file(&path, "Ethereum benchmark fixture manifest")?;
    let body =
        fs::read_to_string(&path).map_err(|err| format!("read {}: {err}", path.display()))?;
    if !body
        .lines()
        .any(|line| line == format!("fixture_version={FIXTURE_VERSION}"))
        || !body
            .lines()
            .any(|line| line == format!("master.max_n={}", config.master_n))
    {
        return Err("fixture version or MASTER_N does not match SMT benchmark".to_string());
    }
    Ok(())
}

fn preflight_persisted_inputs(config: &Config) -> Result<(), String> {
    for &n in &config.n_sizes {
        let run_dir = config.state_dir.join(format!("n_{n}"));
        let manifest = run_dir.join("manifest.txt");
        require_file(&manifest, "persisted SMT manifest")?;
        validate_smt_manifest(&manifest, config, n)?;
        if includes(config, Operation::Update) || includes(config, Operation::Insert) {
            require_file(&run_dir.join("state-0000.txt"), "persisted SMT state")?;
        }
        if includes(config, Operation::Insert) {
            require_file(&run_dir.join("insert.csv"), "persisted SMT insert fixture")?;
            let _ = manifest_value(&manifest, "insert_new_state_root")?;
        }
        if includes(config, Operation::Update) {
            for &m in &config.m_sizes {
                if m > n {
                    return Err(format!(
                        "m={m} exceeds n={n}; the persisted fixture currently materializes member updates"
                    ));
                }
                require_file(
                    &run_dir.join(format!("deltas-m-{m}.csv")),
                    "persisted SMT delta fixture",
                )?;
                let _ = manifest_value(&manifest, &format!("m.{m}.new_state_root"))?;
            }
        }
    }
    Ok(())
}

fn validate_smt_manifest(path: &Path, config: &Config, n: usize) -> Result<(), String> {
    for (key, expected) in [
        ("version", "poseidon-smt-persisted-v1".to_string()),
        ("master_n", config.master_n.to_string()),
        ("n", n.to_string()),
        ("depth", config.depth.to_string()),
        ("status", "complete".to_string()),
    ] {
        let actual = manifest_value(path, key)?;
        if actual != expected {
            return Err(format!(
                "{} has {key}={actual}, expected {expected}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn manifest_value(path: &Path, key: &str) -> Result<String, String> {
    let body = fs::read_to_string(path).map_err(|err| format!("read {}: {err}", path.display()))?;
    body.lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")))
        .map(str::to_string)
        .ok_or_else(|| format!("{} is missing {key}", path.display()))
}

fn require_file(path: &Path, label: &str) -> Result<(), String> {
    if !path.is_file() {
        return Err(format!("missing {label}: {}", path.display()));
    }
    Ok(())
}

fn fixture_init_bytes(source_dir: &Path, n: usize) -> Result<u64, String> {
    let mut total = fs::metadata(ethereum_fixture::init_proof_path(source_dir, n))
        .map_err(|err| format!("inspect init proof fixture: {err}"))?
        .len();
    total = total.saturating_add(
        fs::metadata(ethereum_fixture::master_accounts_path(source_dir))
            .map_err(|err| format!("inspect account fixture: {err}"))?
            .len(),
    );
    Ok(total)
}

fn state_artifact_bytes(run_dir: &Path) -> Result<u64, String> {
    let mut total = 0u64;
    for entry in
        fs::read_dir(run_dir).map_err(|err| format!("read {}: {err}", run_dir.display()))?
    {
        let entry = entry.map_err(|err| format!("read state artifact entry: {err}"))?;
        let name = entry.file_name();
        if name.to_string_lossy().starts_with("state-0000") {
            total = total.saturating_add(
                entry
                    .metadata()
                    .map_err(|err| format!("metadata {}: {err}", entry.path().display()))?
                    .len(),
            );
        }
    }
    Ok(total)
}

fn file_len(path: &Path) -> Result<u64, String> {
    fs::metadata(path)
        .map(|value| value.len())
        .map_err(|err| format!("metadata {}: {err}", path.display()))
}

fn write_environment(config: &Config) -> Result<(), String> {
    let mut values = BTreeMap::new();
    values.insert("scheme", "smt".to_string());
    values.insert("fixture_version", FIXTURE_VERSION.to_string());
    values.insert("master_n", config.master_n.to_string());
    values.insert("n_sizes", format!("{:?}", config.n_sizes));
    values.insert("m_sizes", format!("{:?}", config.m_sizes));
    values.insert("smt_depth", config.depth.to_string());
    values.insert("operations", operations_label(&config.operations));
    values.insert("samples", config.samples.to_string());
    values.insert("warmup", config.warmup.to_string());
    values.insert(
        "sp1_prover",
        std::env::var("SP1_PROVER").unwrap_or_else(|_| "cpu".to_string()),
    );
    values.insert(
        "sp1_proof_mode",
        std::env::var("POA_SP1_PROOF_MODE").unwrap_or_else(|_| "compressed".to_string()),
    );
    for key in [
        "SHARD_SIZE",
        "MINIMAL_TRACE_CHUNK_THRESHOLD",
        "TRACE_CHUNK_SLOTS",
        "GAS_TRACE_CHUNK_THRESHOLD",
        "GAS_TRACE_CHUNK_SLOTS",
    ] {
        values.insert(
            key,
            std::env::var(key).unwrap_or_else(|_| "SP1 default".to_string()),
        );
    }
    values.insert("rustc", command_output("rustc", &["--version"]));
    values.insert("git_commit", command_output("git", &["rev-parse", "HEAD"]));
    values.insert("uname", command_output("uname", &["-a"]));
    let body = values
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(config.output_dir.join("environment.txt"), body)
        .map_err(|err| format!("write environment: {err}"))
}

fn command_output(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|value| value.status.success())
        .map(|value| String::from_utf8_lossy(&value.stdout).trim().to_string())
        .unwrap_or_else(|| "unavailable".to_string())
}

fn duration_ms(value: Duration) -> f64 {
    value.as_secs_f64() * 1_000.0
}

fn human_duration(value: Duration) -> String {
    if value.as_secs() >= 60 {
        format!("{:.2} min", value.as_secs_f64() / 60.0)
    } else if value.as_secs() >= 1 {
        format!("{:.3} s", value.as_secs_f64())
    } else {
        format!("{:.3} ms", duration_ms(value))
    }
}

fn human_bytes(value: usize) -> String {
    if value >= 1024 * 1024 {
        format!("{:.2} MiB", value as f64 / (1024.0 * 1024.0))
    } else if value >= 1024 {
        format!("{:.2} KiB", value as f64 / 1024.0)
    } else {
        format!("{value} B")
    }
}
