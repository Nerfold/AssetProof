use std::collections::BTreeMap;
use std::fs;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::EnvFilter;

use common::crypto::hex_decode;
use common::io::{encode_proof_binary, read_srs, read_state, write_init, write_srs, write_state};
use common::types::{
    Delta, InitProvingContext, InitReserveWitness, StoredInitProof, StoredProof, StoredState,
};
use nizk_fixed_set::external::Sp1NativeProofAdapter;
use nizk_fixed_set::init_proof::{
    build_mock_initialized_state, initialize_from_witnesses_with_adapter,
    validate_mock_initialized_state_shape, verify_mock_initialized_state, InitProofResult,
};
use nizk_fixed_set::insert::{
    apply_insert, verify_insert_with_srs_and_policy, KzgInsertProof, KzgInsertWitness,
};
use nizk_fixed_set::kzg::{Srs, SrsProvenance};
use nizk_fixed_set::update::apply_update;
use nizk_fixed_set::verifier::{
    public_state_digest, verify_init_with_policy, verify_update_debug, ChainPolicy,
};
use poa_bench::{ethereum_fixture, master_fixture_dir, FIXTURE_VERSION};

fn main() {
    if let Err(err) = run() {
        eprintln!("benchmark error: {err}");
        std::process::exit(1);
    }
}

#[derive(Debug)]
struct Config {
    mode: RunMode,
    require_existing: bool,
    output_dir: PathBuf,
    srs_dir: PathBuf,
    fixture_dir: PathBuf,
    master_n: usize,
    n_sizes: Vec<usize>,
    m_sizes: Vec<usize>,
    operations: Vec<BenchmarkOperation>,
    samples: usize,
    warmup: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunMode {
    Prepare,
    Benchmark,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BenchmarkOperation {
    Initialization,
    Insert,
    Update,
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

#[derive(Debug)]
struct SummaryRecord {
    operation: &'static str,
    n: usize,
    m: usize,
    input_load: Duration,
    srs_load: Duration,
    prover: Stats,
    verifier: Stats,
    proof_payload_bytes: usize,
    artifact_bytes: usize,
    proof_encoding: &'static str,
}

#[derive(Clone, Copy, Debug)]
struct Stats {
    min_ms: f64,
    median_ms: f64,
    mean_ms: f64,
    p95_ms: f64,
    stddev_ms: f64,
}

fn run() -> Result<(), String> {
    let config = parse_config()?;
    fs::create_dir_all(&config.output_dir)
        .map_err(|err| format!("create {}: {err}", config.output_dir.display()))?;
    fs::create_dir_all(config.output_dir.join("proof-samples"))
        .map_err(|err| format!("create proof samples: {err}"))?;
    fs::create_dir_all(&config.srs_dir)
        .map_err(|err| format!("create {}: {err}", config.srs_dir.display()))?;
    fs::create_dir_all(&config.fixture_dir)
        .map_err(|err| format!("create {}: {err}", config.fixture_dir.display()))?;
    let _tracing_guard = init_sp1_profile_tracing(&config.output_dir)?;

    if config.mode == RunMode::Prepare {
        return prepare_benchmark_inputs(&config);
    }

    write_environment(&config)?;
    let mut samples = Vec::new();
    let mut loads = Vec::new();
    let mut summaries = Vec::new();

    let (max_n, srs_degree, max_g2_degree) = benchmark_srs_spec(&config)?;
    let master_dir = master_fixture_dir(&config.fixture_dir, config.master_n);
    let prepared_srs_path = srs_path(&config.srs_dir, srs_degree, max_g2_degree);
    if config.require_existing {
        require_existing(&prepared_srs_path, "benchmark SRS")?;
    }
    let (srs, srs_load, mut srs_records) =
        prepare_srs(&config.srs_dir, max_n, srs_degree, max_g2_degree)?;
    loads.append(&mut srs_records);

    println!("Dynamic PoA benchmark suite");
    println!("  n sizes: {:?}", config.n_sizes);
    println!("  m sizes: {:?}", config.m_sizes);
    println!("  operations: {}", operations_label(&config.operations));
    println!("  samples: {}, warmup: {}", config.samples, config.warmup);
    println!("  output: {}", config.output_dir.display());

    if includes_operation(&config, BenchmarkOperation::Initialization)
        || includes_operation(&config, BenchmarkOperation::Insert)
    {
        println!("\n== preparing SP1 prover contexts outside sample timers ==");
    }
    if includes_operation(&config, BenchmarkOperation::Initialization) {
        for (guest, elapsed) in sp1_host::init::prepare_provers()? {
            println!("   {guest}: prepare={}", human_duration(elapsed));
            loads.push(LoadRecord {
                n: 0,
                m: 0,
                phase: match guest {
                    "init-merkle" => "sp1_prover_prepare_init_merkle",
                    "init-ownership" => "sp1_prover_prepare_init_ownership",
                    _ => "sp1_prover_prepare_initialization_guest",
                },
                elapsed,
                bytes: 0,
                reused: false,
            });
        }
    }
    if includes_operation(&config, BenchmarkOperation::Insert) {
        let elapsed = sp1_host::kzg_insert::prepare_prover()?;
        println!("   kzg-insert: prepare={}", human_duration(elapsed));
        loads.push(LoadRecord {
            n: 0,
            m: 0,
            phase: "sp1_prover_prepare_kzg_insert",
            elapsed,
            bytes: 0,
            reused: false,
        });
    }

    for &n in &config.n_sizes {
        println!("\n== loading prepared n={n} ==");
        let degree = n
            .checked_add(1)
            .ok_or_else(|| format!("n={n} cannot be represented as an SRS degree"))?;
        if degree > srs.max_degree {
            return Err(format!(
                "n={n} requires SRS degree {degree}, but the shared benchmark SRS has degree {}",
                srs.max_degree
            ));
        }

        let reserve_path = ethereum_fixture::init_proof_path(&master_dir, n);
        let initialized_state_path = mock_initialized_state_path(&master_dir, n);
        let runs_initialization = includes_operation(&config, BenchmarkOperation::Initialization);
        let runs_insert = includes_operation(&config, BenchmarkOperation::Insert);
        if config.require_existing {
            if runs_initialization {
                require_existing(&reserve_path, "Ethereum Merkle initialization fixture")?;
            }
            if runs_initialization || runs_insert {
                require_existing(
                    &ethereum_fixture::master_accounts_path(&master_dir),
                    "master Ethereum account store",
                )?;
            }
            if runs_insert {
                require_existing(
                    &ethereum_fixture::insert_proof_path(&master_dir),
                    "master Ethereum insertion proof",
                )?;
            }
            if !runs_initialization {
                require_existing(&initialized_state_path, "mock initialized polynomial state")?;
            }
        }
        let (fixture, reserve_load) = if runs_initialization {
            let reserve_load_start = Instant::now();
            let fixture = ethereum_fixture::load_init_fixture(
                &master_dir,
                config.master_n,
                n,
                ethereum_fixture::FixtureValidation::None,
            )?;
            let reserve_load = reserve_load_start.elapsed();
            let fixture_bytes = ethereum_fixture::fixture_persisted_bytes(&master_dir, n)?;
            if fixture.witnesses.len() != n {
                return Err(format!(
                    "fixture {} contains {} witnesses, expected {n}",
                    reserve_path.display(),
                    fixture.witnesses.len()
                ));
            }
            loads.push(LoadRecord {
                n,
                m: 0,
                phase: "ethereum_state_fixture_load",
                elapsed: reserve_load,
                bytes: fixture_bytes,
                reused: true,
            });
            (Some(fixture), reserve_load)
        } else {
            (None, Duration::ZERO)
        };

        let base_state = if let Some(fixture) = fixture.as_ref() {
            let (state, init_summary) = benchmark_init(
                &config,
                n,
                &srs,
                &fixture.state_root,
                &fixture.witnesses,
                &fixture.merkle_prefix_proof,
                reserve_load,
                srs_load,
                &mut samples,
            )?;
            summaries.push(init_summary);
            state
        } else {
            let state_load_start = Instant::now();
            let state = read_state(&initialized_state_path)?;
            validate_mock_initialized_state_shape(&srs, &state)?;
            let state_load = state_load_start.elapsed();
            loads.push(LoadRecord {
                n,
                m: 0,
                phase: "mock_initialized_state_load_and_validation",
                elapsed: state_load,
                bytes: file_len(&initialized_state_path)?,
                reused: true,
            });
            println!(
                "-- using persisted mock initialized polynomial n={n}: load+validation={} bytes={}",
                human_duration(state_load),
                human_bytes(file_len(&initialized_state_path)? as usize),
            );
            state
        };
        if let Some(fixture) = fixture.as_ref() {
            ensure_initialized_state_matches_fixture(&base_state, fixture)?;
        } else if base_state.reserve_addresses.len() != n || base_state.reserve_balances.len() != n
        {
            return Err("persisted initialized state does not match requested n".to_string());
        }

        // The initialization witness contains n signatures and proof tags.
        // Retain at most the one small insert witness before running later
        // operations so update/insert peak memory does not include it.
        let insert_from_init = runs_insert
            .then(|| fixture.as_ref().map(|value| value.insert.clone()))
            .flatten();
        drop(fixture);

        if runs_insert {
            let insert_fixture = if let Some(insert) = insert_from_init {
                insert
            } else {
                let insert_load_start = Instant::now();
                let (state_root, insert) = ethereum_fixture::load_insert_fixture(
                    &master_dir,
                    config.master_n,
                    ethereum_fixture::FixtureValidation::None,
                )?;
                if state_root != base_state.state_root {
                    return Err(
                        "insert fixture state root does not match initialized state".to_string()
                    );
                }
                loads.push(LoadRecord {
                    n,
                    m: 0,
                    phase: "ethereum_insert_fixture_load",
                    elapsed: insert_load_start.elapsed(),
                    bytes: file_len(&ethereum_fixture::insert_proof_path(&master_dir))?,
                    reused: true,
                });
                insert
            };
            let insert_summary = benchmark_insert(
                &config,
                n,
                &srs,
                &base_state,
                &insert_fixture,
                srs_load,
                &mut samples,
            )?;
            summaries.push(insert_summary);
        }

        if includes_operation(&config, BenchmarkOperation::Update) {
            for &m in &config.m_sizes {
                if m > n {
                    return Err(format!(
                        "m={m} exceeds n={n}: the NIZK update relation supports non-member \
                         touch-list entries, but the current persisted Ethereum fixture only \
                         materializes n distinct transition accounts"
                    ));
                }
                let delta_path = ethereum_fixture::delta_fixture_path(&master_dir, n, m);
                if config.require_existing {
                    require_existing(&delta_path, "Ethereum Merkle transition fixture")?;
                }
                let (deltas, new_state_root, fixture_time, delta_load, fixture_reused) =
                    ethereum_fixture::ensure_delta_fixture(
                        &delta_path,
                        &base_state.state_root,
                        n,
                        m,
                    )?;
                loads.push(LoadRecord {
                    n,
                    m,
                    phase: "ethereum_transition_fixture_generation",
                    elapsed: fixture_time,
                    bytes: file_len(&delta_path)?,
                    reused: fixture_reused,
                });
                if deltas.len() != m {
                    return Err(format!(
                        "fixture {} contains {} deltas, expected {m}",
                        delta_path.display(),
                        deltas.len()
                    ));
                }
                loads.push(LoadRecord {
                    n,
                    m,
                    phase: "ethereum_transition_fixture_load",
                    elapsed: delta_load,
                    bytes: file_len(&delta_path)?,
                    reused: true,
                });
                summaries.push(benchmark_update(
                    &config,
                    n,
                    m,
                    &srs,
                    &base_state,
                    &deltas,
                    &new_state_root,
                    delta_load,
                    srs_load,
                    &mut samples,
                )?);
            }
        }
    }

    write_raw_csv(&config.output_dir.join("raw.csv"), &samples)?;
    write_load_csv(&config.output_dir.join("loading.csv"), &loads)?;
    write_summary_csv(&config.output_dir.join("summary.csv"), &summaries)?;
    write_summary_markdown(&config, &loads, &summaries)?;
    common::profiling::write_reports(&config.output_dir.join("profile"))?;

    println!("\nbenchmark complete");
    println!(
        "  readable report: {}/summary.md",
        config.output_dir.display()
    );
    println!(
        "  summary CSV:     {}/summary.csv",
        config.output_dir.display()
    );
    println!("  raw samples:     {}/raw.csv", config.output_dir.display());
    println!(
        "  loading times:   {}/loading.csv",
        config.output_dir.display()
    );
    if common::profiling::enabled() {
        println!(
            "  phase profile:   {}/profile/profile.md",
            config.output_dir.display()
        );
        println!(
            "  SP1 span log:     {}/profile/sp1-prover-spans.log",
            config.output_dir.display()
        );
    }
    Ok(())
}

fn init_sp1_profile_tracing(
    output_dir: &Path,
) -> Result<Option<tracing_appender::non_blocking::WorkerGuard>, String> {
    if !common::profiling::enabled() {
        return Ok(None);
    }
    let profile_dir = output_dir.join("profile");
    fs::create_dir_all(&profile_dir)
        .map_err(|err| format!("create {}: {err}", profile_dir.display()))?;
    let appender = tracing_appender::rolling::never(&profile_dir, "sp1-prover-spans.log");
    let (writer, guard) = tracing_appender::non_blocking(appender);
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("sp1_prover=debug,sp1_core_executor=info,sp1_recursion_gnark_ffi=info")
    });
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .with_ansi(false)
        .with_span_events(FmtSpan::CLOSE)
        .try_init()
        .map_err(|err| format!("initialize SP1 profile tracing: {err}"))?;
    Ok(Some(guard))
}

fn prepare_benchmark_inputs(config: &Config) -> Result<(), String> {
    println!("Dynamic PoA benchmark data preparation");
    println!("  n sizes: {:?}", config.n_sizes);
    println!("  m sizes: {:?}", config.m_sizes);
    println!("  fixtures: {}", config.fixture_dir.display());
    println!("  SRS: {}", config.srs_dir.display());

    let mut manifest = vec![
        format!("fixture_version={FIXTURE_VERSION}"),
        format!("n_sizes={:?}", config.n_sizes),
        format!("m_sizes={:?}", config.m_sizes),
    ];
    let (max_n, srs_degree, max_g2_degree) = benchmark_srs_spec(config)?;
    let prepared_srs_path = srs_path(&config.srs_dir, srs_degree, max_g2_degree);

    let master_dir = master_fixture_dir(&config.fixture_dir, config.master_n);
    println!(
        "\n== generating one shared master binary Merkle tree master_n={} ==",
        config.master_n
    );
    let (master_generation, master_reused) = ethereum_fixture::ensure_master_fixture(
        &master_dir,
        config.master_n,
        &config.n_sizes,
        &config.m_sizes,
    )?;
    println!(
        "   master tree: generation={} accounts={} reused={master_reused}",
        human_duration(master_generation),
        human_bytes(file_len(&ethereum_fixture::master_accounts_path(&master_dir))? as usize),
    );
    manifest.push(format!("master.max_n={}", config.master_n));
    manifest.push(format!("master.dir={}", master_dir.display()));
    manifest.push(format!(
        "master.accounts_path={}",
        ethereum_fixture::master_accounts_path(&master_dir).display()
    ));
    manifest.push(format!(
        "master.accounts_bytes={}",
        file_len(&ethereum_fixture::master_accounts_path(&master_dir))?
    ));

    println!("\n== preparing shared update KZG SRS ==");
    let (srs, _, _) = prepare_srs(&config.srs_dir, max_n, srs_degree, max_g2_degree)?;
    manifest.push(format!("srs_path={}", prepared_srs_path.display()));
    manifest.push(format!("srs_max_degree={srs_degree}"));
    manifest.push(format!("srs_max_g2_degree={max_g2_degree}"));
    manifest.push(format!("srs_bytes={}", file_len(&prepared_srs_path)?));

    for &n in &config.n_sizes {
        println!("\n== loading persisted master-tree prefix n={n} ==");
        manifest.push(format!("n.{n}.srs_path={}", prepared_srs_path.display()));
        manifest.push(format!("n.{n}.srs_max_degree={srs_degree}"));

        let init_path = ethereum_fixture::init_proof_path(&master_dir, n);
        let load_start = Instant::now();
        let (state_root, entries) =
            ethereum_fixture::load_reserve_entries(&master_dir, config.master_n, n)?;
        let load = load_start.elapsed();
        println!(
            "   init: generation={} validation={} bytes={} reused=true",
            human_duration(Duration::ZERO),
            human_duration(load),
            human_bytes(ethereum_fixture::fixture_persisted_bytes(&master_dir, n)? as usize),
        );
        manifest.push(format!("n.{n}.state_root={state_root}"));
        manifest.push(format!("n.{n}.init_path={}", init_path.display()));
        manifest.push(format!(
            "n.{n}.input_bytes={}",
            ethereum_fixture::fixture_persisted_bytes(&master_dir, n)?
        ));
        manifest.push(format!(
            "n.{n}.init_merkle_proof_bytes={}",
            file_len(&init_path)?
        ));
        manifest.push(format!(
            "n.{n}.insert_merkle_proof_bytes={}",
            file_len(&ethereum_fixture::insert_proof_path(&master_dir))?
        ));

        let initialized_state_path = mock_initialized_state_path(&master_dir, n);
        let state_prepare_start = Instant::now();
        let state_reused = initialized_state_path.is_file();
        let initialized_state = if state_reused {
            let state = read_state(&initialized_state_path)?;
            verify_mock_initialized_state(&srs, &state)?;
            state
        } else {
            let state = build_mock_initialized_state(&entries, &state_root, &srs)?;
            write_state(&initialized_state_path, &state)?;
            state
        };
        if initialized_state.state_root != state_root
            || initialized_state.reserve_addresses.len() != n
            || initialized_state.reserve_balances.len() != n
        {
            return Err(format!(
                "persisted initialized state for n={n} does not match its fixture"
            ));
        }
        drop(entries);
        println!(
            "   mock initialized polynomial: preparation={} bytes={} reused={state_reused}",
            human_duration(state_prepare_start.elapsed()),
            human_bytes(file_len(&initialized_state_path)? as usize),
        );
        manifest.push(format!(
            "n.{n}.mock_initialized_state_path={}",
            initialized_state_path.display()
        ));
        manifest.push(format!(
            "n.{n}.mock_initialized_state_bytes={}",
            file_len(&initialized_state_path)?
        ));

        for &m in &config.m_sizes {
            if m > n {
                return Err(format!(
                    "m={m} exceeds n={n}: the current persisted Ethereum transition fixture \
                     cannot yet generate more than n distinct touch-list accounts"
                ));
            }
            let delta_path = ethereum_fixture::delta_fixture_path(&master_dir, n, m);
            let (_, new_root, generation, validation, reused) =
                ethereum_fixture::ensure_delta_fixture(&delta_path, &state_root, n, m)?;
            println!(
                "   delta m={m}: generation={} validation={} bytes={} reused={reused}",
                human_duration(generation),
                human_duration(validation),
                human_bytes(file_len(&delta_path)? as usize),
            );
            manifest.push(format!("n.{n}.m.{m}.new_state_root={new_root}"));
            manifest.push(format!("n.{n}.m.{m}.path={}", delta_path.display()));
            manifest.push(format!("n.{n}.m.{m}.bytes={}", file_len(&delta_path)?));
        }
    }
    manifest.push("status=complete".to_string());
    let body = manifest.join("\n") + "\n";
    let report_path = config.output_dir.join("preparation-manifest.txt");
    fs::write(&report_path, &body)
        .map_err(|err| format!("write {}: {err}", report_path.display()))?;
    let fixture_manifest = config.fixture_dir.join("preparation-manifest.txt");
    fs::write(&fixture_manifest, body)
        .map_err(|err| format!("write {}: {err}", fixture_manifest.display()))?;
    println!("\npreparation complete: {}", report_path.display());
    Ok(())
}

fn mock_initialized_state_path(master_dir: &Path, n: usize) -> PathBuf {
    master_dir.join(format!("mock-initialized-state-n-{n}.txt"))
}

fn benchmark_srs_spec(config: &Config) -> Result<(usize, usize, usize), String> {
    let max_n = config.master_n;
    let max_degree = max_n
        .checked_add(1)
        .ok_or_else(|| format!("n={max_n} cannot be represented as an SRS degree"))?;
    let max_g2_degree = config.m_sizes.iter().copied().max().unwrap_or(1).max(1);
    if max_g2_degree > max_degree {
        return Err(format!(
            "maximum update size {max_g2_degree} exceeds benchmark SRS degree {max_degree}; \
             m>n requires an expanded SRS plus a persisted fixture with additional distinct \
             non-member chain accounts"
        ));
    }
    Ok((max_n, max_degree, max_g2_degree))
}

fn srs_path(srs_dir: &Path, degree: usize, max_g2_degree: usize) -> PathBuf {
    srs_dir.join(format!(
        "bench-max-degree-{degree}-g2-degree-{max_g2_degree}.bin"
    ))
}

fn require_existing(path: &Path, label: &str) -> Result<(), String> {
    if path.is_file() {
        Ok(())
    } else {
        Err(format!(
            "missing {label}: {}; run scripts/initialize_benchmark_data.sh first",
            path.display()
        ))
    }
}

fn ensure_initialized_state_matches_fixture(
    state: &StoredState,
    fixture: &ethereum_fixture::EthereumInitFixture,
) -> Result<(), String> {
    if state.state_root != fixture.state_root
        || state.reserve_addresses.len() != fixture.witnesses.len()
        || state.reserve_balances.len() != fixture.witnesses.len()
        || state
            .reserve_addresses
            .iter()
            .zip(&fixture.witnesses)
            .any(|(actual, expected)| actual != &expected.address)
        || state
            .reserve_balances
            .iter()
            .zip(&fixture.witnesses)
            .any(|(actual, expected)| *actual != expected.balance)
    {
        return Err(
            "initialization output does not preserve the canonical Merkle fixture state"
                .to_string(),
        );
    }
    Ok(())
}

fn benchmark_init(
    config: &Config,
    n: usize,
    srs: &Srs,
    state_root: &str,
    witnesses: &[InitReserveWitness],
    merkle_prefix_proof: &common::types::InitChainBatchProofInput,
    input_load: Duration,
    srs_load: Duration,
    raw: &mut Vec<SampleRecord>,
) -> Result<(StoredState, SummaryRecord), String> {
    println!("-- initialization n={n}");
    let policy = ChainPolicy::development(
        ethereum_fixture::CHAIN_ID,
        [state_root.to_string()],
        None,
        None,
        srs.max_degree,
    )?;
    for warmup in 0..config.warmup {
        println!("   warmup {}/{}", warmup + 1, config.warmup);
        let _profile_context =
            common::profiling::enter_context(common::profiling::ProfileContext {
                operation: "initialization".to_string(),
                n,
                m: 0,
                sample: warmup + 1,
                run_kind: "warmup".to_string(),
            });
        let ctx = InitProvingContext {
            chain_id: ethereum_fixture::CHAIN_ID.to_string(),
            state_root: state_root.to_string(),
            session_id: format!("bench-init-{n}-warmup-{warmup}"),
            chain_batch_proof: Some(merkle_prefix_proof.clone()),
        };
        let result =
            initialize_from_witnesses_with_adapter(&ctx, witnesses, srs, &Sp1NativeProofAdapter)?;
        verify_init_with_policy(srs, &result.state.public_state(), &result.proof, &policy)?;
        black_box(result);
    }

    let mut prover_samples = Vec::with_capacity(config.samples);
    let mut verifier_samples = Vec::with_capacity(config.samples);
    let mut proof_payload_sizes = Vec::with_capacity(config.samples);
    let mut artifact_sizes = Vec::with_capacity(config.samples);
    let mut last_result: Option<InitProofResult> = None;
    for sample in 0..config.samples {
        let _profile_context =
            common::profiling::enter_context(common::profiling::ProfileContext {
                operation: "initialization".to_string(),
                n,
                m: 0,
                sample: sample + 1,
                run_kind: "measured".to_string(),
            });
        let probe_before = common::profiling::probe_overhead();
        let prove_start = Instant::now();
        let ctx = InitProvingContext {
            chain_id: ethereum_fixture::CHAIN_ID.to_string(),
            state_root: state_root.to_string(),
            session_id: format!("bench-init-{n}-sample-{sample}"),
            chain_batch_proof: Some(merkle_prefix_proof.clone()),
        };
        let result =
            initialize_from_witnesses_with_adapter(&ctx, witnesses, srs, &Sp1NativeProofAdapter)?;
        let prover_with_probe = prove_start.elapsed();
        let probe_elapsed = common::profiling::probe_overhead().saturating_sub(probe_before);
        let prover = prover_with_probe.saturating_sub(probe_elapsed);
        common::profiling::record_phase("benchmark", "prover_excluding_profile_probe", prover);
        common::profiling::record_phase("profiling", "excluded_guest_execute_probe", probe_elapsed);

        let verify_start = Instant::now();
        verify_init_with_policy(srs, &result.state.public_state(), &result.proof, &policy)?;
        let verifier = verify_start.elapsed();
        common::profiling::record_phase("init-verifier", "total", verifier);

        let proof_path = config
            .output_dir
            .join("proof-samples")
            .join(format!("init-n-{n}-last.txt"));
        write_init(&proof_path, &result.proof)?;
        let proof_payload_bytes = init_proof_payload_bytes(&result.proof)?;
        let artifact_bytes = file_len(&proof_path)? as usize;
        println!(
            "   sample {}/{}: prover={} verifier={} proof-payload={} artifact={}",
            sample + 1,
            config.samples,
            human_duration(prover),
            human_duration(verifier),
            human_bytes(proof_payload_bytes),
            human_bytes(artifact_bytes)
        );
        raw.push(SampleRecord {
            operation: "initialization",
            n,
            m: 0,
            sample: sample + 1,
            prover,
            verifier,
            proof_payload_bytes,
            artifact_bytes,
            proof_encoding: "init-key-value-text-v3",
        });
        prover_samples.push(prover);
        verifier_samples.push(verifier);
        proof_payload_sizes.push(proof_payload_bytes);
        artifact_sizes.push(artifact_bytes);
        last_result = Some(result);
    }
    let result =
        last_result.ok_or_else(|| "initialization produced no measured sample".to_string())?;
    let summary = make_summary(
        "initialization",
        n,
        0,
        input_load,
        srs_load,
        &prover_samples,
        &verifier_samples,
        &proof_payload_sizes,
        &artifact_sizes,
        "init-key-value-text-v4-split-sp1",
    );
    Ok((result.state, summary))
}

fn benchmark_insert(
    config: &Config,
    n: usize,
    srs: &Srs,
    state: &StoredState,
    insert: &ethereum_fixture::EthereumInsertFixture,
    srs_load: Duration,
    raw: &mut Vec<SampleRecord>,
) -> Result<SummaryRecord, String> {
    println!("-- insert n={n}");
    let witness = KzgInsertWitness::ethereum_merkle(
        ethereum_fixture::CHAIN_ID.to_string(),
        insert.address.clone(),
        insert.balance,
        common::crypto::hex_encode(&insert.ownership_signature),
        insert.leaf_index,
        insert.siblings.clone(),
    );
    let policy = ChainPolicy::development(
        ethereum_fixture::CHAIN_ID,
        [state.state_root.clone()],
        Some(state.state_root.clone()),
        Some(public_state_digest(&state.public_state())?),
        srs.max_degree,
    )?;
    for warmup in 0..config.warmup {
        println!("   warmup {}/{}", warmup + 1, config.warmup);
        let _profile_context =
            common::profiling::enter_context(common::profiling::ProfileContext {
                operation: "insert".to_string(),
                n,
                m: 0,
                sample: warmup + 1,
                run_kind: "warmup".to_string(),
            });
        let result = apply_insert(srs, state, &witness)?;
        verify_insert_with_srs_and_policy(
            srs,
            &state.public_state(),
            &result.next_state.public_state(),
            &result.proof,
            &policy,
        )?;
        black_box(result);
    }

    let mut prover_samples = Vec::with_capacity(config.samples);
    let mut verifier_samples = Vec::with_capacity(config.samples);
    let mut proof_payload_sizes = Vec::with_capacity(config.samples);
    let mut artifact_sizes = Vec::with_capacity(config.samples);
    for sample in 0..config.samples {
        let _profile_context =
            common::profiling::enter_context(common::profiling::ProfileContext {
                operation: "insert".to_string(),
                n,
                m: 0,
                sample: sample + 1,
                run_kind: "measured".to_string(),
            });
        let probe_before = common::profiling::probe_overhead();
        let prove_start = Instant::now();
        let result = apply_insert(srs, state, &witness)?;
        let prover_with_probe = prove_start.elapsed();
        let probe_elapsed = common::profiling::probe_overhead().saturating_sub(probe_before);
        let prover = prover_with_probe.saturating_sub(probe_elapsed);
        common::profiling::record_phase("benchmark", "prover_excluding_profile_probe", prover);
        common::profiling::record_phase("profiling", "excluded_guest_execute_probe", probe_elapsed);

        let verify_start = Instant::now();
        verify_insert_with_srs_and_policy(
            srs,
            &state.public_state(),
            &result.next_state.public_state(),
            &result.proof,
            &policy,
        )?;
        let verifier = verify_start.elapsed();
        common::profiling::record_phase("insert-verifier", "total", verifier);

        let encoded = encode_insert_proof_text(&result.proof)?;
        let proof_payload_bytes = insert_proof_payload_bytes(&result.proof)?;
        let artifact_bytes = encoded.len();
        let proof_path = config
            .output_dir
            .join("proof-samples")
            .join(format!("insert-n-{n}-last.txt"));
        fs::write(&proof_path, encoded)
            .map_err(|err| format!("write {}: {err}", proof_path.display()))?;
        println!(
            "   sample {}/{}: prover={} verifier={} proof-payload={} artifact={}",
            sample + 1,
            config.samples,
            human_duration(prover),
            human_duration(verifier),
            human_bytes(proof_payload_bytes),
            human_bytes(artifact_bytes)
        );
        raw.push(SampleRecord {
            operation: "insert",
            n,
            m: 1,
            sample: sample + 1,
            prover,
            verifier,
            proof_payload_bytes,
            artifact_bytes,
            proof_encoding: "insert-key-value-text-v2",
        });
        prover_samples.push(prover);
        verifier_samples.push(verifier);
        proof_payload_sizes.push(proof_payload_bytes);
        artifact_sizes.push(artifact_bytes);
        black_box(result.next_state);
    }
    Ok(make_summary(
        "insert",
        n,
        1,
        Duration::ZERO,
        srs_load,
        &prover_samples,
        &verifier_samples,
        &proof_payload_sizes,
        &artifact_sizes,
        "insert-key-value-text-v2",
    ))
}

#[allow(clippy::too_many_arguments)]
fn benchmark_update(
    config: &Config,
    n: usize,
    m: usize,
    srs: &Srs,
    state: &StoredState,
    deltas: &[Delta],
    new_state_root: &str,
    input_load: Duration,
    srs_load: Duration,
    raw: &mut Vec<SampleRecord>,
) -> Result<SummaryRecord, String> {
    println!("-- update n={n}, m={m}");
    for warmup in 0..config.warmup {
        println!("   warmup {}/{}", warmup + 1, config.warmup);
        let result = apply_update(srs, state, deltas, new_state_root)?;
        verify_update_debug(
            srs,
            &state.public_state(),
            deltas,
            &result.next_state.public_state(),
            &result.proof,
        )?;
        black_box(result);
    }

    let mut prover_samples = Vec::with_capacity(config.samples);
    let mut verifier_samples = Vec::with_capacity(config.samples);
    let mut proof_payload_sizes = Vec::with_capacity(config.samples);
    let mut artifact_sizes = Vec::with_capacity(config.samples);
    for sample in 0..config.samples {
        let prove_start = Instant::now();
        let result = apply_update(srs, state, deltas, new_state_root)?;
        let prover = prove_start.elapsed();

        let verify_start = Instant::now();
        verify_update_debug(
            srs,
            &state.public_state(),
            deltas,
            &result.next_state.public_state(),
            &result.proof,
        )?;
        let verifier = verify_start.elapsed();

        let encoded = encode_proof_binary(&result.proof)?;
        let proof_payload_bytes = update_proof_payload_bytes(&result.proof)?;
        let artifact_bytes = encoded.len();
        let proof_path = config
            .output_dir
            .join("proof-samples")
            .join(format!("update-n-{n}-m-{m}-last.bin"));
        fs::write(&proof_path, encoded)
            .map_err(|err| format!("write {}: {err}", proof_path.display()))?;
        println!(
            "   sample {}/{}: prover={} verifier={} proof-payload={} artifact={}",
            sample + 1,
            config.samples,
            human_duration(prover),
            human_duration(verifier),
            human_bytes(proof_payload_bytes),
            human_bytes(artifact_bytes)
        );
        raw.push(SampleRecord {
            operation: "update",
            n,
            m,
            sample: sample + 1,
            prover,
            verifier,
            proof_payload_bytes,
            artifact_bytes,
            proof_encoding: "DPOAUPD6-multizkopen-binary",
        });
        prover_samples.push(prover);
        verifier_samples.push(verifier);
        proof_payload_sizes.push(proof_payload_bytes);
        artifact_sizes.push(artifact_bytes);
        black_box(result.next_state);
    }
    Ok(make_summary(
        "update",
        n,
        m,
        input_load,
        srs_load,
        &prover_samples,
        &verifier_samples,
        &proof_payload_sizes,
        &artifact_sizes,
        "DPOAUPD6-multizkopen-binary",
    ))
}

fn prepare_srs(
    srs_dir: &Path,
    n: usize,
    degree: usize,
    max_g2_degree: usize,
) -> Result<(Srs, Duration, Vec<LoadRecord>), String> {
    let path = srs_path(srs_dir, degree, max_g2_degree);
    let mut records = Vec::new();
    let generated_srs = if !path.exists() {
        println!("   generating shared SRS: G1 degree={degree}, G2 degree={max_g2_degree}");
        let setup_start = Instant::now();
        let srs = Srs::setup_development_with_g2_degree(
            degree,
            max_g2_degree,
            format!("dynamic-poa-benchmark-srs-v2-{degree}").as_bytes(),
        );
        let setup_elapsed = setup_start.elapsed();
        let write_start = Instant::now();
        let temporary_path = path.with_extension("bin.tmp");
        write_srs(
            &temporary_path,
            srs.max_degree,
            &srs.tau_g1_powers,
            &srs.tau_g2_powers,
            &srs.hiding_tau_g1_powers,
        )?;
        fs::rename(&temporary_path, &path).map_err(|err| {
            format!(
                "install generated SRS {} -> {}: {err}",
                temporary_path.display(),
                path.display()
            )
        })?;
        let write_elapsed = write_start.elapsed();
        records.push(LoadRecord {
            n,
            m: 0,
            phase: "srs_generation",
            elapsed: setup_elapsed,
            bytes: file_len(&path)?,
            reused: false,
        });
        records.push(LoadRecord {
            n,
            m: 0,
            phase: "srs_write",
            elapsed: write_elapsed,
            bytes: file_len(&path)?,
            reused: false,
        });
        Some(srs)
    } else {
        None
    };

    let generated_now = generated_srs.is_some();
    let (srs, load_elapsed, legacy_hiding_tau_g1_powers) = if let Some(srs) = generated_srs {
        (srs, Duration::ZERO, Vec::new())
    } else {
        let load_start = Instant::now();
        let (max_degree, tau_g1_powers, tau_g2_powers, legacy_hiding_tau_g1_powers) =
            read_srs(&path)?;
        (
            Srs {
                max_degree,
                tau_g1_powers,
                tau_g2_powers,
                hiding_tau_g1_powers: Vec::new(),
                provenance: SrsProvenance::Development,
            },
            load_start.elapsed(),
            legacy_hiding_tau_g1_powers,
        )
    };
    let needed_powers = degree
        .checked_add(1)
        .ok_or_else(|| "benchmark SRS degree overflow".to_string())?;
    let needed_g2_powers = max_g2_degree
        .checked_add(1)
        .ok_or_else(|| "benchmark G2 SRS degree overflow".to_string())?;
    if srs.max_degree != degree
        || srs.tau_g1_powers.len() < needed_powers
        || srs.tau_g2_powers.len() < needed_g2_powers
    {
        return Err(format!(
            "benchmark SRS {} is incomplete for G1 degree {degree} and G2 degree {max_g2_degree}",
            path.display()
        ));
    }
    if !legacy_hiding_tau_g1_powers.is_empty() {
        let compact_path = path.with_extension("bin.compact.tmp");
        write_srs(
            &compact_path,
            srs.max_degree,
            &srs.tau_g1_powers,
            &srs.tau_g2_powers,
            &[],
        )?;
        fs::rename(&compact_path, &path).map_err(|err| {
            format!(
                "install compacted benchmark SRS {} -> {}: {err}",
                compact_path.display(),
                path.display()
            )
        })?;
        println!(
            "   removed {} unused legacy hiding-G1 powers from {}",
            legacy_hiding_tau_g1_powers.len(),
            path.display()
        );
    }
    records.push(LoadRecord {
        n,
        m: 0,
        phase: "srs_load",
        elapsed: load_elapsed,
        bytes: file_len(&path)?,
        reused: !generated_now,
    });
    Ok((srs, load_elapsed, records))
}

#[allow(clippy::too_many_arguments)]
fn make_summary(
    operation: &'static str,
    n: usize,
    m: usize,
    input_load: Duration,
    srs_load: Duration,
    prover_samples: &[Duration],
    verifier_samples: &[Duration],
    proof_payload_sizes: &[usize],
    artifact_sizes: &[usize],
    proof_encoding: &'static str,
) -> SummaryRecord {
    let mut payloads = proof_payload_sizes.to_vec();
    payloads.sort_unstable();
    let mut artifacts = artifact_sizes.to_vec();
    artifacts.sort_unstable();
    SummaryRecord {
        operation,
        n,
        m,
        input_load,
        srs_load,
        prover: stats(prover_samples),
        verifier: stats(verifier_samples),
        proof_payload_bytes: payloads[(payloads.len() - 1) / 2],
        artifact_bytes: artifacts[(artifacts.len() - 1) / 2],
        proof_encoding,
    }
}

fn stats(samples: &[Duration]) -> Stats {
    let mut millis = samples
        .iter()
        .map(|duration| duration.as_secs_f64() * 1_000.0)
        .collect::<Vec<_>>();
    millis.sort_by(f64::total_cmp);
    let mean = millis.iter().sum::<f64>() / millis.len() as f64;
    let variance = millis
        .iter()
        .map(|sample| {
            let delta = sample - mean;
            delta * delta
        })
        .sum::<f64>()
        / millis.len() as f64;
    let p95_index = ((millis.len() * 95).div_ceil(100)).saturating_sub(1);
    Stats {
        min_ms: millis[0],
        median_ms: millis[(millis.len() - 1) / 2],
        mean_ms: mean,
        p95_ms: millis[p95_index],
        stddev_ms: variance.sqrt(),
    }
}

fn write_raw_csv(path: &Path, records: &[SampleRecord]) -> Result<(), String> {
    let mut body = String::from(
        "scheme,operation,n,m,sample,prover_ns,verifier_ns,proof_payload_bytes,artifact_bytes,proof_encoding\n",
    );
    for record in records {
        body.push_str(&format!(
            "nizk,{},{},{},{},{},{},{},{},{}\n",
            record.operation,
            record.n,
            record.m,
            record.sample,
            record.prover.as_nanos(),
            record.verifier.as_nanos(),
            record.proof_payload_bytes,
            record.artifact_bytes,
            record.proof_encoding
        ));
    }
    fs::write(path, body).map_err(|err| format!("write {}: {err}", path.display()))
}

fn write_load_csv(path: &Path, records: &[LoadRecord]) -> Result<(), String> {
    let mut body = String::from("scheme,n,m,phase,elapsed_ns,bytes,reused\n");
    for record in records {
        body.push_str(&format!(
            "nizk,{},{},{},{},{},{}\n",
            record.n,
            record.m,
            record.phase,
            record.elapsed.as_nanos(),
            record.bytes,
            record.reused
        ));
    }
    fs::write(path, body).map_err(|err| format!("write {}: {err}", path.display()))
}

fn write_summary_csv(path: &Path, records: &[SummaryRecord]) -> Result<(), String> {
    let mut body = String::from(
        "scheme,operation,n,m,input_load_ms,parameter_load_ms,prover_min_ms,prover_median_ms,prover_mean_ms,prover_p95_ms,prover_stddev_ms,verifier_min_ms,verifier_median_ms,verifier_mean_ms,verifier_p95_ms,verifier_stddev_ms,proof_payload_bytes,artifact_bytes,proof_encoding\n",
    );
    for record in records {
        body.push_str(&format!(
            "nizk,{},{},{},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{},{},{}\n",
            record.operation,
            record.n,
            record.m,
            duration_ms(record.input_load),
            duration_ms(record.srs_load),
            record.prover.min_ms,
            record.prover.median_ms,
            record.prover.mean_ms,
            record.prover.p95_ms,
            record.prover.stddev_ms,
            record.verifier.min_ms,
            record.verifier.median_ms,
            record.verifier.mean_ms,
            record.verifier.p95_ms,
            record.verifier.stddev_ms,
            record.proof_payload_bytes,
            record.artifact_bytes,
            record.proof_encoding,
        ));
    }
    fs::write(path, body).map_err(|err| format!("write {}: {err}", path.display()))
}

fn write_summary_markdown(
    config: &Config,
    loads: &[LoadRecord],
    summaries: &[SummaryRecord],
) -> Result<(), String> {
    let mut body = String::new();
    body.push_str("# Dynamic PoA benchmark report\n\n");
    body.push_str(&format!(
        "- n sizes: `{:?}`\n- m sizes: `{:?}`\n- operations: `{}`\n- measured samples: `{}`\n- warmup samples: `{}`\n- SP1 prover: `{}`\n- SP1 proof mode: `{}`\n\n",
        config.n_sizes,
        config.m_sizes,
        operations_label(&config.operations),
        config.samples,
        config.warmup,
        std::env::var("SP1_PROVER").unwrap_or_else(|_| "cpu".to_string()),
        std::env::var("POA_SP1_PROOF_MODE").unwrap_or_else(|_| "groth16".to_string())
    ));
    body.push_str(
        "Prover and verifier columns exclude fixture generation, CSV parsing, SRS generation/loading, reusable prover/program setup, output-artifact serialization, and report I/O. Each operation uses the same prepared state and already-prepared proving program for all measured repetitions.\n\n",
    );
    body.push_str("## Protocol timings\n\n");
    body.push_str("| operation | n | m | input load | SRS load | prover median | prover mean | prover p95 | verifier median | verifier mean | verifier p95 | proof payload | persisted artifact | encoding |\n");
    body.push_str("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|\n");
    for record in summaries {
        body.push_str(&format!(
            "| {} | {} | {} | {:.3} ms | {:.3} ms | {:.3} ms | {:.3} ms | {:.3} ms | {:.3} ms | {:.3} ms | {:.3} ms | {} | {} | {} |\n",
            record.operation,
            record.n,
            record.m,
            duration_ms(record.input_load),
            duration_ms(record.srs_load),
            record.prover.median_ms,
            record.prover.mean_ms,
            record.prover.p95_ms,
            record.verifier.median_ms,
            record.verifier.mean_ms,
            record.verifier.p95_ms,
            human_bytes(record.proof_payload_bytes),
            human_bytes(record.artifact_bytes),
            record.proof_encoding,
        ));
    }
    body.push_str("\nStandard deviations and per-sample nanosecond values are available in `summary.csv` and `raw.csv`.\n\n");
    body.push_str("## Data and parameter preparation\n\n");
    body.push_str("| n | m | phase | elapsed | bytes | reused |\n");
    body.push_str("|---:|---:|---|---:|---:|---|\n");
    for record in loads {
        body.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            record.n,
            record.m,
            record.phase,
            human_duration(record.elapsed),
            human_bytes(record.bytes as usize),
            record.reused,
        ));
    }
    body.push_str("\n## Methodology notes\n\n");
    body.push_str("- The release binary is compiled before the benchmark process starts.\n");
    body.push_str("- SP1 verification-key artifacts are prepared by the wrapper script. Runtime prover/VK contexts for every selected guest are preloaded before warmups and measured samples. With CUDA, this also starts one persistent worker and setups each guest ELF exactly once. These wall-clock preparation costs are reported in the preparation table and excluded from prover samples.\n");
    body.push_str("- CUDA prover samples are end-to-end host wall times after preload, so they include the local Unix-socket request/response and its transport encoding; this is intentionally retained as observable proving latency.\n");
    body.push_str("- KZG ceremony and power-sequence validation belong to setup/import. Runtime loading authenticates the fixed SRS artifact; proof verification does not scan SRS powers.\n");
    body.push_str("- All n sizes use prefixes of one persisted max-n Ethereum account store and one fixed-height Keccak-Merkle tree under a shared root; the tree is not rebuilt per n.\n");
    body.push_str("- Initialization uses valid secp256k1 EOA witnesses and one compact shared-prefix Merkle proof. Ownership and Merkle/polynomial checks run in separate SP1 guests and are joined by a common ordered reserve commitment.\n");
    body.push_str("- Initialization verification uses a development policy because the benchmark SRS is deterministic.\n");
    body.push_str("- Insert authenticates an additional EOA against the same binary Merkle root with a self-contained path.\n");
    body.push_str("- Update verification uses the debug verifier and excludes canonical Sync/finality verification.\n");
    body.push_str("- Update-only mode loads a persisted, structurally valid initialized root polynomial and KZG/balance commitments; it skips only the initialization proof and excludes that state loading/validation from prover time.\n");
    body.push_str("- Proof payload counts canonical binary cryptographic proof components and excludes the public statement/VK. Persisted artifact size records the project's current text or binary file format. Both are measured after the timer.\n");
    body.push_str("- Ethereum keys, balances, deltas, binary Merkle roots, and proofs are deterministically generated outside SP1; fixture preparation is excluded from prover time.\n");
    body.push_str("- Merkle and large salted witness commitments use SP1's Keccak permutation syscall; ECDSA uses the patched k256 precompiles and BLS12-381 commitment checks use SP1 BLS add/double syscalls.\n");

    let path = config.output_dir.join("summary.md");
    fs::write(&path, body).map_err(|err| format!("write {}: {err}", path.display()))
}

fn write_environment(config: &Config) -> Result<(), String> {
    let mut values = BTreeMap::new();
    values.insert("fixture_version", FIXTURE_VERSION.to_string());
    values.insert("scheme", "nizk".to_string());
    values.insert("mode", format!("{:?}", config.mode));
    values.insert("require_existing", config.require_existing.to_string());
    values.insert("os", std::env::consts::OS.to_string());
    values.insert("arch", std::env::consts::ARCH.to_string());
    values.insert(
        "available_parallelism",
        std::thread::available_parallelism()
            .map(|value| value.get().to_string())
            .unwrap_or_else(|_| "unknown".to_string()),
    );
    values.insert(
        "sp1_prover",
        std::env::var("SP1_PROVER").unwrap_or_else(|_| "cpu".to_string()),
    );
    values.insert(
        "sp1_proof_mode",
        std::env::var("POA_SP1_PROOF_MODE").unwrap_or_else(|_| "groth16".to_string()),
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
    values.insert("n_sizes", format!("{:?}", config.n_sizes));
    values.insert("m_sizes", format!("{:?}", config.m_sizes));
    values.insert("operations", operations_label(&config.operations));
    values.insert("master_n", config.master_n.to_string());
    values.insert("samples", config.samples.to_string());
    values.insert("warmup", config.warmup.to_string());
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
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|| "unavailable".to_string())
}

fn encode_insert_proof_text(proof: &KzgInsertProof) -> Result<String, String> {
    Ok([
        format!("scheme={}", proof.scheme),
        format!("chain_id={}", proof.chain_id),
        format!("old_state_root={}", proof.old_state_root),
        format!("new_state_root={}", proof.new_state_root),
        format!("old_accumulator_hex={}", proof.old_accumulator_hex),
        format!("new_accumulator_hex={}", proof.new_accumulator_hex),
        format!(
            "old_balance_commitment_hex={}",
            proof.old_balance_commitment_hex
        ),
        format!(
            "new_balance_commitment_hex={}",
            proof.new_balance_commitment_hex
        ),
        format!("reserve_count_before={}", proof.reserve_count_before),
        format!("reserve_count_after={}", proof.reserve_count_after),
        format!("c_u_hex={}", proof.c_u_hex),
        format!("c_y_hex={}", proof.c_y_hex),
        format!("c_balance_hex={}", proof.c_balance_hex),
        format!("d_hex={}", proof.d_hex),
        format!("strong_zkopen_proof_hex={}", proof.strong_zkopen_proof_hex),
        format!("nonzero_proof_hex={}", proof.nonzero_proof_hex),
        format!("transcript_hex={}", proof.transcript_hex),
        format!("sp1_proof_hex={}", proof.sp1_proof_hex),
        format!("sp1_vk_hex={}", proof.sp1_vk_hex),
        format!("sp1_public_values_hex={}", proof.sp1_public_values_hex),
    ]
    .join("\n"))
}

fn init_proof_payload_bytes(proof: &StoredInitProof) -> Result<usize, String> {
    decoded_payload_bytes(&[
        &proof.kzg_opening_proof_hex,
        &proof.sp1_proof_hex,
        &proof.ownership_sp1_proof_hex,
        &proof.transcript_hex,
    ])
}

fn insert_proof_payload_bytes(proof: &KzgInsertProof) -> Result<usize, String> {
    decoded_payload_bytes(&[
        &proof.strong_zkopen_proof_hex,
        &proof.nonzero_proof_hex,
        &proof.transcript_hex,
        &proof.sp1_proof_hex,
    ])
}

fn update_proof_payload_bytes(proof: &StoredProof) -> Result<usize, String> {
    let decoded = decoded_payload_bytes(&[
        &proof.multi_zkopen_proof_hex,
        &proof.transcript_hex,
        &proof.bp_proof_hex,
        &proof.balance_range_proof_hex,
    ])?;
    decoded
        .checked_add(proof.committed_input_link_ipa_proof.len())
        .and_then(|value| value.checked_add(proof.projection_ipa_proof.len()))
        .ok_or_else(|| "update proof payload size overflow".to_string())
}

fn decoded_payload_bytes(parts: &[&str]) -> Result<usize, String> {
    parts.iter().try_fold(0usize, |total, value| {
        total
            .checked_add(hex_decode(value)?.len())
            .ok_or_else(|| "proof payload size overflow".to_string())
    })
}

fn parse_config() -> Result<Config, String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let mut values = BTreeMap::<String, String>::new();
    let mut index = 0usize;
    while index < args.len() {
        let key = args[index].clone();
        if !key.starts_with("--") || index + 1 >= args.len() {
            return Err(format!("expected --key value, got {key}"));
        }
        values.insert(key, args[index + 1].clone());
        index += 2;
    }
    let mode = match values.get("--mode").map(String::as_str) {
        None | Some("benchmark") => RunMode::Benchmark,
        Some("prepare") => RunMode::Prepare,
        Some(value) => {
            return Err(format!(
                "unsupported --mode {value}; use prepare or benchmark"
            ))
        }
    };
    let require_existing = values
        .get("--require-existing")
        .map(|value| parse_bool(value, "--require-existing"))
        .transpose()?
        .unwrap_or(false);
    let output_dir = PathBuf::from(required(&values, "--output")?);
    let srs_dir = PathBuf::from(required(&values, "--srs-dir")?);
    let fixture_dir = PathBuf::from(required(&values, "--fixture-dir")?);
    let n_sizes = parse_sizes(required(&values, "--n")?, "n")?;
    let m_sizes = parse_sizes(required(&values, "--m")?, "m")?;
    let operations = parse_operations(
        values
            .get("--operations")
            .map(String::as_str)
            .unwrap_or("initialization,insert,update"),
    )?;
    let master_n = values
        .get("--master-n")
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|err| format!("master-n: {err}"))
        })
        .transpose()?
        .unwrap_or_else(|| n_sizes.iter().copied().max().unwrap_or(0));
    let samples = required(&values, "--samples")?
        .parse::<usize>()
        .map_err(|err| format!("samples: {err}"))?;
    let warmup = required(&values, "--warmup")?
        .parse::<usize>()
        .map_err(|err| format!("warmup: {err}"))?;
    if samples == 0 {
        return Err("samples must be greater than zero".to_string());
    }
    if n_sizes.is_empty() || m_sizes.is_empty() {
        return Err("n and m size lists must not be empty".to_string());
    }
    if master_n == 0 || n_sizes.iter().any(|&n| n > master_n) {
        return Err("master-n must be positive and at least max(n)".to_string());
    }
    Ok(Config {
        mode,
        require_existing,
        output_dir,
        srs_dir,
        fixture_dir,
        master_n,
        n_sizes,
        m_sizes,
        operations,
        samples,
        warmup,
    })
}

fn parse_operations(raw: &str) -> Result<Vec<BenchmarkOperation>, String> {
    let expanded = if raw == "all" {
        "initialization,insert,update"
    } else {
        raw
    };
    let mut operations = Vec::new();
    for name in expanded
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        let operation = match name {
            "initialization" | "init" => BenchmarkOperation::Initialization,
            "insert" => BenchmarkOperation::Insert,
            "update" => BenchmarkOperation::Update,
            _ => {
                return Err(format!(
                    "unsupported benchmark operation {name}; use initialization, insert, update, or all"
                ))
            }
        };
        if !operations.contains(&operation) {
            operations.push(operation);
        }
    }
    if operations.is_empty() {
        return Err("benchmark operations must not be empty".to_string());
    }
    Ok(operations)
}

fn includes_operation(config: &Config, operation: BenchmarkOperation) -> bool {
    config.operations.contains(&operation)
}

fn operations_label(operations: &[BenchmarkOperation]) -> String {
    operations
        .iter()
        .map(|operation| match operation {
            BenchmarkOperation::Initialization => "initialization",
            BenchmarkOperation::Insert => "insert",
            BenchmarkOperation::Update => "update",
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn parse_bool(value: &str, name: &str) -> Result<bool, String> {
    match value {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(format!("{name} must be true or false")),
    }
}

fn required<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, String> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing {key}"))
}

fn parse_sizes(raw: &str, name: &str) -> Result<Vec<usize>, String> {
    let mut values = raw
        .split(',')
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|err| format!("invalid {name} size {value}: {err}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    values.sort_unstable();
    values.dedup();
    if values.iter().any(|value| *value == 0) {
        return Err(format!("{name} sizes must be greater than zero"));
    }
    Ok(values)
}

fn file_len(path: &Path) -> Result<u64, String> {
    fs::metadata(path)
        .map(|metadata| metadata.len())
        .map_err(|err| format!("metadata {}: {err}", path.display()))
}

fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn human_duration(duration: Duration) -> String {
    if duration.as_secs() >= 60 {
        format!("{:.2} min", duration.as_secs_f64() / 60.0)
    } else if duration.as_secs() >= 1 {
        format!("{:.3} s", duration.as_secs_f64())
    } else {
        format!("{:.3} ms", duration_ms(duration))
    }
}

fn human_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.2} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

#[allow(dead_code)]
fn _type_checks(_: &StoredInitProof, _: &StoredProof) {}
