use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::hint::black_box;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use common::crypto::scalar_to_hex;
use common::io::{
    encode_proof_binary, read_delta_csv, read_reserve_csv, read_srs, write_init, write_srs,
};
use common::types::{Delta, ReserveEntry, StoredInitProof, StoredProof, StoredState};
use nizk_fixed_set::init_proof::{initialize_with_proof, InitProofResult};
use nizk_fixed_set::insert::{
    apply_insert, verify_insert_with_srs, KzgInsertProof, KzgInsertWitness,
};
use nizk_fixed_set::kzg::Srs;
use nizk_fixed_set::update::apply_update;
use nizk_fixed_set::verifier::{verify_init, verify_update};

const FIXTURE_VERSION: &str = "deterministic-account-delta-v1";

fn main() {
    if let Err(err) = run() {
        eprintln!("benchmark error: {err}");
        std::process::exit(1);
    }
}

#[derive(Debug)]
struct Config {
    output_dir: PathBuf,
    srs_dir: PathBuf,
    fixture_dir: PathBuf,
    n_sizes: Vec<usize>,
    m_sizes: Vec<usize>,
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
    proof_bytes: usize,
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
    proof_bytes: usize,
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

    write_environment(&config)?;
    let mut samples = Vec::new();
    let mut loads = Vec::new();
    let mut summaries = Vec::new();

    println!("Dynamic PoA benchmark suite");
    println!("  n sizes: {:?}", config.n_sizes);
    println!("  m sizes: {:?}", config.m_sizes);
    println!("  samples: {}, warmup: {}", config.samples, config.warmup);
    println!("  output: {}", config.output_dir.display());

    for &n in &config.n_sizes {
        println!("\n== preparing n={n} ==");
        let degree = n
            .checked_add(1)
            .ok_or_else(|| format!("n={n} cannot be represented as an SRS degree"))?;
        let (srs, srs_load, mut srs_records) = prepare_srs(&config.srs_dir, n, degree)?;
        loads.append(&mut srs_records);

        let reserve_path = config
            .fixture_dir
            .join(format!("n_{n}"))
            .join("reserves.csv");
        let (fixture_time, fixture_reused) = ensure_reserve_fixture(&reserve_path, n)?;
        loads.push(LoadRecord {
            n,
            m: 0,
            phase: "reserve_fixture_generation",
            elapsed: fixture_time,
            bytes: file_len(&reserve_path)?,
            reused: fixture_reused,
        });
        let load_start = Instant::now();
        let reserves = read_reserve_csv(&reserve_path)?;
        let reserve_load = load_start.elapsed();
        if reserves.len() != n {
            return Err(format!(
                "fixture {} contains {} reserves, expected {n}",
                reserve_path.display(),
                reserves.len()
            ));
        }
        loads.push(LoadRecord {
            n,
            m: 0,
            phase: "reserve_csv_load",
            elapsed: reserve_load,
            bytes: file_len(&reserve_path)?,
            reused: true,
        });

        let (base_state, init_summary) = benchmark_init(
            &config,
            n,
            &srs,
            &reserves,
            reserve_load,
            srs_load,
            &mut samples,
        )?;
        summaries.push(init_summary);
        drop(reserves);

        let insert_summary =
            benchmark_insert(&config, n, &srs, &base_state, srs_load, &mut samples)?;
        summaries.push(insert_summary);

        for &m in &config.m_sizes {
            if m > n {
                return Err(format!("m={m} cannot exceed n={n}"));
            }
            let delta_path = config
                .fixture_dir
                .join(format!("n_{n}"))
                .join(format!("deltas_m_{m}.csv"));
            let (fixture_time, fixture_reused) = ensure_delta_fixture(&delta_path, n, m)?;
            loads.push(LoadRecord {
                n,
                m,
                phase: "delta_fixture_generation",
                elapsed: fixture_time,
                bytes: file_len(&delta_path)?,
                reused: fixture_reused,
            });
            let load_start = Instant::now();
            let deltas = read_delta_csv(&delta_path)?;
            let delta_load = load_start.elapsed();
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
                phase: "delta_csv_load",
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
                delta_load,
                srs_load,
                &mut samples,
            )?);
        }
    }

    write_raw_csv(&config.output_dir.join("raw.csv"), &samples)?;
    write_load_csv(&config.output_dir.join("loading.csv"), &loads)?;
    write_summary_csv(&config.output_dir.join("summary.csv"), &summaries)?;
    write_summary_markdown(&config, &loads, &summaries)?;

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
    Ok(())
}

fn benchmark_init(
    config: &Config,
    n: usize,
    srs: &Srs,
    reserves: &[ReserveEntry],
    input_load: Duration,
    srs_load: Duration,
    raw: &mut Vec<SampleRecord>,
) -> Result<(StoredState, SummaryRecord), String> {
    println!("-- initialization n={n}");
    for warmup in 0..config.warmup {
        println!("   warmup {}/{}", warmup + 1, config.warmup);
        let result =
            initialize_with_proof(reserves, &format!("bench-init-{n}-warmup-{warmup}"), srs)?;
        verify_init(srs, &result.state.public_state(), &result.proof)?;
        black_box(result);
    }

    let mut prover_samples = Vec::with_capacity(config.samples);
    let mut verifier_samples = Vec::with_capacity(config.samples);
    let mut proof_sizes = Vec::with_capacity(config.samples);
    let mut last_result: Option<InitProofResult> = None;
    for sample in 0..config.samples {
        let prove_start = Instant::now();
        let result =
            initialize_with_proof(reserves, &format!("bench-init-{n}-sample-{sample}"), srs)?;
        let prover = prove_start.elapsed();

        let verify_start = Instant::now();
        verify_init(srs, &result.state.public_state(), &result.proof)?;
        let verifier = verify_start.elapsed();

        let proof_path = config
            .output_dir
            .join("proof-samples")
            .join(format!("init-n-{n}-last.txt"));
        write_init(&proof_path, &result.proof)?;
        let proof_bytes = file_len(&proof_path)? as usize;
        println!(
            "   sample {}/{}: prover={} verifier={} proof={}",
            sample + 1,
            config.samples,
            human_duration(prover),
            human_duration(verifier),
            human_bytes(proof_bytes)
        );
        raw.push(SampleRecord {
            operation: "initialization",
            n,
            m: 0,
            sample: sample + 1,
            prover,
            verifier,
            proof_bytes,
            proof_encoding: "init-key-value-text-v3",
        });
        prover_samples.push(prover);
        verifier_samples.push(verifier);
        proof_sizes.push(proof_bytes);
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
        &proof_sizes,
        "init-key-value-text-v3",
    );
    Ok((result.state, summary))
}

fn benchmark_insert(
    config: &Config,
    n: usize,
    srs: &Srs,
    state: &StoredState,
    srs_load: Duration,
    raw: &mut Vec<SampleRecord>,
) -> Result<SummaryRecord, String> {
    println!("-- insert n={n}");
    let address = mock_address(n + 1);
    let witness = KzgInsertWitness::mock(
        address.clone(),
        10_000,
        format!("benchmark-owner:{address}"),
        format!("benchmark-balance:{address}"),
    );
    for warmup in 0..config.warmup {
        println!("   warmup {}/{}", warmup + 1, config.warmup);
        let result = apply_insert(srs, state, &witness)?;
        verify_insert_with_srs(
            srs,
            &state.public_state(),
            &result.next_state.public_state(),
            &result.proof,
        )?;
        black_box(result);
    }

    let mut prover_samples = Vec::with_capacity(config.samples);
    let mut verifier_samples = Vec::with_capacity(config.samples);
    let mut proof_sizes = Vec::with_capacity(config.samples);
    for sample in 0..config.samples {
        let prove_start = Instant::now();
        let result = apply_insert(srs, state, &witness)?;
        let prover = prove_start.elapsed();

        let verify_start = Instant::now();
        verify_insert_with_srs(
            srs,
            &state.public_state(),
            &result.next_state.public_state(),
            &result.proof,
        )?;
        let verifier = verify_start.elapsed();

        let encoded = encode_insert_proof_text(&result.proof)?;
        let proof_bytes = encoded.len();
        let proof_path = config
            .output_dir
            .join("proof-samples")
            .join(format!("insert-n-{n}-last.txt"));
        fs::write(&proof_path, encoded)
            .map_err(|err| format!("write {}: {err}", proof_path.display()))?;
        println!(
            "   sample {}/{}: prover={} verifier={} proof={}",
            sample + 1,
            config.samples,
            human_duration(prover),
            human_duration(verifier),
            human_bytes(proof_bytes)
        );
        raw.push(SampleRecord {
            operation: "insert",
            n,
            m: 1,
            sample: sample + 1,
            prover,
            verifier,
            proof_bytes,
            proof_encoding: "insert-key-value-text-v2",
        });
        prover_samples.push(prover);
        verifier_samples.push(verifier);
        proof_sizes.push(proof_bytes);
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
        &proof_sizes,
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
    input_load: Duration,
    srs_load: Duration,
    raw: &mut Vec<SampleRecord>,
) -> Result<SummaryRecord, String> {
    println!("-- update n={n}, m={m}");
    for warmup in 0..config.warmup {
        println!("   warmup {}/{}", warmup + 1, config.warmup);
        let result = apply_update(
            srs,
            state,
            deltas,
            &format!("bench-update-{n}-{m}-warmup-{warmup}"),
        )?;
        verify_update(
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
    let mut proof_sizes = Vec::with_capacity(config.samples);
    for sample in 0..config.samples {
        let prove_start = Instant::now();
        let result = apply_update(
            srs,
            state,
            deltas,
            &format!("bench-update-{n}-{m}-sample-{sample}"),
        )?;
        let prover = prove_start.elapsed();

        let verify_start = Instant::now();
        verify_update(
            srs,
            &state.public_state(),
            deltas,
            &result.next_state.public_state(),
            &result.proof,
        )?;
        let verifier = verify_start.elapsed();

        let encoded = encode_proof_binary(&result.proof)?;
        let proof_bytes = encoded.len();
        let proof_path = config
            .output_dir
            .join("proof-samples")
            .join(format!("update-n-{n}-m-{m}-last.bin"));
        fs::write(&proof_path, encoded)
            .map_err(|err| format!("write {}: {err}", proof_path.display()))?;
        println!(
            "   sample {}/{}: prover={} verifier={} proof={}",
            sample + 1,
            config.samples,
            human_duration(prover),
            human_duration(verifier),
            human_bytes(proof_bytes)
        );
        raw.push(SampleRecord {
            operation: "update",
            n,
            m,
            sample: sample + 1,
            prover,
            verifier,
            proof_bytes,
            proof_encoding: "DPOAUPD3-binary",
        });
        prover_samples.push(prover);
        verifier_samples.push(verifier);
        proof_sizes.push(proof_bytes);
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
        &proof_sizes,
        "DPOAUPD3-binary",
    ))
}

fn prepare_srs(
    srs_dir: &Path,
    n: usize,
    degree: usize,
) -> Result<(Srs, Duration, Vec<LoadRecord>), String> {
    let path = srs_dir.join(format!("bench-degree-{degree}.bin"));
    let mut records = Vec::new();
    if !path.exists() {
        println!("   generating SRS degree={degree}");
        let setup_start = Instant::now();
        let srs = Srs::setup(
            degree,
            format!("dynamic-poa-benchmark-srs-{degree}").as_bytes(),
        );
        let setup_elapsed = setup_start.elapsed();
        let write_start = Instant::now();
        write_srs(
            &path,
            srs.max_degree,
            &srs.tau_g1_powers,
            &srs.tau_g2_powers,
            &srs.hiding_tau_g1_powers,
        )?;
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
        drop(srs);
    }

    let load_start = Instant::now();
    let (max_degree, tau_g1_powers, tau_g2_powers, hiding_tau_g1_powers) = read_srs(&path)?;
    let load_elapsed = load_start.elapsed();
    if max_degree < degree
        || tau_g1_powers.len() < degree + 1
        || tau_g2_powers.len() < degree + 1
        || hiding_tau_g1_powers.len() < degree + 1
    {
        return Err(format!(
            "benchmark SRS {} is incomplete for degree {degree}",
            path.display()
        ));
    }
    records.push(LoadRecord {
        n,
        m: 0,
        phase: "srs_load",
        elapsed: load_elapsed,
        bytes: file_len(&path)?,
        reused: true,
    });
    Ok((
        Srs {
            max_degree,
            tau_g1_powers,
            tau_g2_powers,
            hiding_tau_g1_powers,
        },
        load_elapsed,
        records,
    ))
}

fn ensure_reserve_fixture(path: &Path, n: usize) -> Result<(Duration, bool), String> {
    if path.exists() {
        return Ok((Duration::ZERO, true));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("create {}: {err}", parent.display()))?;
    }
    let start = Instant::now();
    let file = File::create(path).map_err(|err| format!("create {}: {err}", path.display()))?;
    let mut writer = BufWriter::new(file);
    for index in 0..n {
        let address = mock_address(index);
        let balance = 5_000_i128 + (index % 45_000) as i128;
        writeln!(writer, "{address},{balance}")
            .map_err(|err| format!("write {}: {err}", path.display()))?;
    }
    writer
        .flush()
        .map_err(|err| format!("flush {}: {err}", path.display()))?;
    fs::write(
        path.with_extension("meta"),
        format!("version={FIXTURE_VERSION}\nn={n}\n"),
    )
    .map_err(|err| format!("write reserve metadata: {err}"))?;
    Ok((start.elapsed(), false))
}

fn ensure_delta_fixture(path: &Path, n: usize, m: usize) -> Result<(Duration, bool), String> {
    if path.exists() {
        return Ok((Duration::ZERO, true));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("create {}: {err}", parent.display()))?;
    }
    let start = Instant::now();
    let file = File::create(path).map_err(|err| format!("create {}: {err}", path.display()))?;
    let mut writer = BufWriter::new(file);
    for index in 0..m {
        let address = mock_address(index);
        let delta = if index % 2 == 0 { 1 } else { -1 };
        writeln!(writer, "{address},{delta}")
            .map_err(|err| format!("write {}: {err}", path.display()))?;
    }
    writer
        .flush()
        .map_err(|err| format!("flush {}: {err}", path.display()))?;
    fs::write(
        path.with_extension("meta"),
        format!("version={FIXTURE_VERSION}\nn={n}\nm={m}\n"),
    )
    .map_err(|err| format!("write delta metadata: {err}"))?;
    Ok((start.elapsed(), false))
}

fn mock_address(index: usize) -> String {
    format!("0x{:040x}", index + 1)
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
    proof_sizes: &[usize],
    proof_encoding: &'static str,
) -> SummaryRecord {
    let mut sizes = proof_sizes.to_vec();
    sizes.sort_unstable();
    SummaryRecord {
        operation,
        n,
        m,
        input_load,
        srs_load,
        prover: stats(prover_samples),
        verifier: stats(verifier_samples),
        proof_bytes: sizes[(sizes.len() - 1) / 2],
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
    let mut body =
        String::from("operation,n,m,sample,prover_ns,verifier_ns,proof_bytes,proof_encoding\n");
    for record in records {
        body.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            record.operation,
            record.n,
            record.m,
            record.sample,
            record.prover.as_nanos(),
            record.verifier.as_nanos(),
            record.proof_bytes,
            record.proof_encoding
        ));
    }
    fs::write(path, body).map_err(|err| format!("write {}: {err}", path.display()))
}

fn write_load_csv(path: &Path, records: &[LoadRecord]) -> Result<(), String> {
    let mut body = String::from("n,m,phase,elapsed_ns,bytes,reused\n");
    for record in records {
        body.push_str(&format!(
            "{},{},{},{},{},{}\n",
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
        "operation,n,m,input_load_ms,srs_load_ms,prover_min_ms,prover_median_ms,prover_mean_ms,prover_p95_ms,prover_stddev_ms,verifier_min_ms,verifier_median_ms,verifier_mean_ms,verifier_p95_ms,verifier_stddev_ms,proof_bytes,proof_encoding\n",
    );
    for record in records {
        body.push_str(&format!(
            "{},{},{},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{},{}\n",
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
            record.proof_bytes,
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
        "- n sizes: `{:?}`\n- m sizes: `{:?}`\n- measured samples: `{}`\n- warmup samples: `{}`\n- SP1 proof mode: `{}`\n\n",
        config.n_sizes,
        config.m_sizes,
        config.samples,
        config.warmup,
        std::env::var("POA_SP1_PROOF_MODE").unwrap_or_else(|_| "groth16".to_string())
    ));
    body.push_str(
        "Prover and verifier columns exclude fixture generation, CSV parsing, SRS generation/loading, proof serialization, and report I/O. Each operation uses the same prepared state for all measured repetitions.\n\n",
    );
    body.push_str("## Protocol timings\n\n");
    body.push_str("| operation | n | m | input load | SRS load | prover median | prover mean | prover p95 | verifier median | verifier mean | verifier p95 | proof size | encoding |\n");
    body.push_str("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|\n");
    for record in summaries {
        body.push_str(&format!(
            "| {} | {} | {} | {:.3} ms | {:.3} ms | {:.3} ms | {:.3} ms | {:.3} ms | {:.3} ms | {:.3} ms | {:.3} ms | {} | {} |\n",
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
            human_bytes(record.proof_bytes),
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
    body.push_str("- SP1 setup is performed by the wrapper script before timing.\n");
    body.push_str("- Initialization verification uses the public production verifier.\n");
    body.push_str("- Insert verification uses the SRS-aware production verifier.\n");
    body.push_str("- Update verification uses the production committed-opening verifier.\n");
    body.push_str(
        "- Proof size is measured after the timer using the labeled artifact encoding.\n",
    );
    body.push_str("- The deterministic mock addresses are not Ethereum accounts or MPT proofs.\n");

    let path = config.output_dir.join("summary.md");
    fs::write(&path, body).map_err(|err| format!("write {}: {err}", path.display()))
}

fn write_environment(config: &Config) -> Result<(), String> {
    let mut values = BTreeMap::new();
    values.insert("fixture_version", FIXTURE_VERSION.to_string());
    values.insert("os", std::env::consts::OS.to_string());
    values.insert("arch", std::env::consts::ARCH.to_string());
    values.insert(
        "available_parallelism",
        std::thread::available_parallelism()
            .map(|value| value.get().to_string())
            .unwrap_or_else(|_| "unknown".to_string()),
    );
    values.insert(
        "sp1_proof_mode",
        std::env::var("POA_SP1_PROOF_MODE").unwrap_or_else(|_| "groth16".to_string()),
    );
    values.insert("rustc", command_output("rustc", &["--version"]));
    values.insert("git_commit", command_output("git", &["rev-parse", "HEAD"]));
    values.insert("uname", command_output("uname", &["-a"]));
    values.insert("n_sizes", format!("{:?}", config.n_sizes));
    values.insert("m_sizes", format!("{:?}", config.m_sizes));
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
        format!("c_q_h_hex={}", proof.c_q_h_hex),
        format!("c_x_hex={}", proof.c_x_hex),
        format!("c_beta_hex={}", proof.c_beta_hex),
        format!("c_y_x_hex={}", proof.c_y_x_hex),
        format!("c_y_hex={}", proof.c_y_hex),
        format!("c_y_prime_hex={}", proof.c_y_prime_hex),
        format!("c_q_hex={}", proof.c_q_hex),
        format!("zeta={}", scalar_to_hex(&proof.zeta)?),
        format!(
            "old_eval_opening_proof_hex={}",
            proof.old_eval_opening_proof_hex
        ),
        format!(
            "new_eval_opening_proof_hex={}",
            proof.new_eval_opening_proof_hex
        ),
        format!(
            "quotient_eval_opening_proof_hex={}",
            proof.quotient_eval_opening_proof_hex
        ),
        format!("relation_bp_proof_hex={}", proof.relation_bp_proof_hex),
        format!(
            "relation_bp_commitments_hex={}",
            proof.relation_bp_commitments_hex
        ),
        format!("relation_link_proof_hex={}", proof.relation_link_proof_hex),
        format!(
            "ownership_artifact_digest_hex={}",
            proof.ownership_artifact_digest_hex
        ),
        format!(
            "chain_balance_artifact_digest_hex={}",
            proof.chain_balance_artifact_digest_hex
        ),
        format!("transcript_hex={}", proof.transcript_hex),
        format!("sp1_proof_hex={}", proof.sp1_proof_hex),
        format!("sp1_vk_hex={}", proof.sp1_vk_hex),
        format!("sp1_public_values_hex={}", proof.sp1_public_values_hex),
    ]
    .join("\n"))
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
    let output_dir = PathBuf::from(required(&values, "--output")?);
    let srs_dir = PathBuf::from(required(&values, "--srs-dir")?);
    let fixture_dir = PathBuf::from(required(&values, "--fixture-dir")?);
    let n_sizes = parse_sizes(required(&values, "--n")?, "n")?;
    let m_sizes = parse_sizes(required(&values, "--m")?, "m")?;
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
    Ok(Config {
        output_dir,
        srs_dir,
        fixture_dir,
        n_sizes,
        m_sizes,
        samples,
        warmup,
    })
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
