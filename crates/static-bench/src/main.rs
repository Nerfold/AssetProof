use std::collections::BTreeMap;
use std::fs;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::crypto::hex_decode;
use common::types::{InitProvingContext, InitReserveWitness};
use poa_bench::{ethereum_fixture, master_fixture_dir, FIXTURE_VERSION};
use sp1_host::setup::default_setup_dir;
use sp1_host::static_init::{
    ensure_setup, prepare_prover, prove_static_initialization, verify_static_initialization,
    StaticInitProof,
};

#[derive(Debug)]
struct Config {
    fixture_dir: PathBuf,
    output_dir: PathBuf,
    master_n: usize,
    n_sizes: Vec<usize>,
    samples: usize,
    warmup: usize,
}

#[derive(Debug)]
struct SampleRecord {
    n: usize,
    sample: usize,
    prover: Duration,
    verifier: Duration,
    proof_payload_bytes: usize,
    artifact_bytes: usize,
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
    n: usize,
    input_load: Duration,
    prover: Stats,
    verifier: Stats,
    proof_payload_bytes: usize,
    artifact_bytes: usize,
}

#[derive(Debug)]
struct LoadRecord {
    n: usize,
    phase: &'static str,
    elapsed: Duration,
    bytes: u64,
    reused: bool,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("static baseline benchmark error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let config = parse_config()?;
    preflight(&config)?;
    fs::create_dir_all(config.output_dir.join("proof-samples"))
        .map_err(|err| format!("create output directory: {err}"))?;
    write_environment(&config)?;

    println!("Traditional static PoA SP1 baseline");
    println!("  n sizes: {:?}", config.n_sizes);
    println!("  samples: {}, warmup: {}", config.samples, config.warmup);
    println!("  output: {}", config.output_dir.display());
    println!("  KZG/polynomial state: disabled");

    let mut loads = Vec::new();
    println!("\n== preparing static SP1 prover outside sample timers ==");
    let setup_started = Instant::now();
    ensure_setup(&default_setup_dir())?;
    loads.push(LoadRecord {
        n: 0,
        phase: "sp1_vk_setup_or_reuse",
        elapsed: setup_started.elapsed(),
        bytes: 0,
        reused: false,
    });
    let prepare_elapsed = prepare_prover()?;
    println!(
        "   static-init: prepare={}",
        human_duration(prepare_elapsed)
    );
    loads.push(LoadRecord {
        n: 0,
        phase: "sp1_prover_prepare_static_init",
        elapsed: prepare_elapsed,
        bytes: 0,
        reused: false,
    });

    let source_dir = master_fixture_dir(&config.fixture_dir, config.master_n);
    let mut raw = Vec::new();
    let mut summaries = Vec::new();
    for &n in &config.n_sizes {
        println!("\n== loading prepared Ethereum fixture n={n} ==");
        let started = Instant::now();
        let fixture = ethereum_fixture::load_init_fixture(
            &source_dir,
            config.master_n,
            n,
            ethereum_fixture::FixtureValidation::None,
        )?;
        let load_elapsed = started.elapsed();
        loads.push(LoadRecord {
            n,
            phase: "ethereum_static_fixture_load",
            elapsed: load_elapsed,
            bytes: fixture_bytes(&source_dir, n)?,
            reused: true,
        });
        summaries.push(benchmark_n(
            &config,
            n,
            &fixture.state_root,
            &fixture.witnesses,
            &fixture.merkle_prefix_proof,
            load_elapsed,
            &mut raw,
        )?);
    }

    write_raw_csv(&config.output_dir.join("raw.csv"), &raw)?;
    write_loading_csv(&config.output_dir.join("loading.csv"), &loads)?;
    write_summary_csv(&config.output_dir.join("summary.csv"), &summaries)?;
    write_summary_markdown(&config, &loads, &summaries)?;
    common::profiling::write_reports(&config.output_dir.join("profile"))?;
    println!(
        "\nstatic baseline complete: {}/summary.md",
        config.output_dir.display()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn benchmark_n(
    config: &Config,
    n: usize,
    state_root: &str,
    witnesses: &[InitReserveWitness],
    merkle_prefix_proof: &common::types::InitChainBatchProofInput,
    input_load: Duration,
    raw: &mut Vec<SampleRecord>,
) -> Result<SummaryRecord, String> {
    println!("-- static initialization n={n}");
    for warmup in 0..config.warmup {
        println!("   warmup {}/{}", warmup + 1, config.warmup);
        let _profile = profile_context(n, warmup, "warmup");
        let context = proving_context(
            state_root,
            n,
            &format!("warmup-{warmup}"),
            merkle_prefix_proof,
        );
        let (proof, _) = prove_static_initialization(&context, witnesses)?;
        verify_static_initialization(&context, n, &proof)?;
        black_box(proof);
    }

    let mut prover = Vec::with_capacity(config.samples);
    let mut verifier = Vec::with_capacity(config.samples);
    let mut payloads = Vec::with_capacity(config.samples);
    let mut artifacts = Vec::with_capacity(config.samples);
    for sample in 0..config.samples {
        let _profile = profile_context(n, sample, "measured");
        let context = proving_context(
            state_root,
            n,
            &format!("sample-{sample}"),
            merkle_prefix_proof,
        );
        let probe_before = common::profiling::probe_overhead();
        let started = Instant::now();
        let (proof, public) = prove_static_initialization(&context, witnesses)?;
        let with_probe = started.elapsed();
        let probe = common::profiling::probe_overhead().saturating_sub(probe_before);
        let prove_elapsed = with_probe.saturating_sub(probe);
        common::profiling::record_phase(
            "benchmark",
            "prover_excluding_profile_probe",
            prove_elapsed,
        );
        common::profiling::record_phase("profiling", "excluded_guest_execute_probe", probe);

        let verify_started = Instant::now();
        let verified = verify_static_initialization(&context, n, &proof)?;
        let verify_elapsed = verify_started.elapsed();
        if verified != public {
            return Err("static proof public values changed during verification".to_string());
        }
        let payload = hex_decode(&proof.proof_hex)?.len();
        let path = config
            .output_dir
            .join("proof-samples")
            .join(format!("static-init-n-{n}-last.txt"));
        write_proof(&path, &proof)?;
        let artifact = fs::metadata(&path)
            .map_err(|err| format!("metadata {}: {err}", path.display()))?
            .len() as usize;
        println!(
            "   sample {}/{}: prover={} verifier={} proof-payload={} artifact={}",
            sample + 1,
            config.samples,
            human_duration(prove_elapsed),
            human_duration(verify_elapsed),
            human_bytes(payload),
            human_bytes(artifact),
        );
        raw.push(SampleRecord {
            n,
            sample: sample + 1,
            prover: prove_elapsed,
            verifier: verify_elapsed,
            proof_payload_bytes: payload,
            artifact_bytes: artifact,
        });
        prover.push(prove_elapsed);
        verifier.push(verify_elapsed);
        payloads.push(payload);
        artifacts.push(artifact);
        black_box((proof, public));
    }

    Ok(SummaryRecord {
        n,
        input_load,
        prover: stats(&prover),
        verifier: stats(&verifier),
        proof_payload_bytes: median_size(&payloads),
        artifact_bytes: median_size(&artifacts),
    })
}

fn proving_context(
    state_root: &str,
    n: usize,
    suffix: &str,
    merkle_prefix_proof: &common::types::InitChainBatchProofInput,
) -> InitProvingContext {
    InitProvingContext {
        chain_id: ethereum_fixture::CHAIN_ID.to_string(),
        state_root: state_root.to_string(),
        session_id: format!("static-baseline-n-{n}-{suffix}"),
        chain_batch_proof: Some(merkle_prefix_proof.clone()),
    }
}

fn profile_context(n: usize, sample: usize, run_kind: &str) -> common::profiling::ContextGuard {
    common::profiling::enter_context(common::profiling::ProfileContext {
        operation: "static-initialization".to_string(),
        n,
        m: 0,
        sample: sample + 1,
        run_kind: run_kind.to_string(),
    })
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
    let master_n = parse_usize(required(&values, "--master-n")?, "master-n")?;
    let n_sizes = parse_sizes(required(&values, "--n")?)?;
    let samples = parse_usize(required(&values, "--samples")?, "samples")?;
    let warmup = parse_usize(required(&values, "--warmup")?, "warmup")?;
    if master_n == 0 || samples == 0 || n_sizes.iter().any(|n| *n > master_n) {
        return Err(
            "master-n/samples must be positive and every n must be <= master-n".to_string(),
        );
    }
    Ok(Config {
        fixture_dir: PathBuf::from(required(&values, "--fixture-dir")?),
        output_dir: PathBuf::from(required(&values, "--output")?),
        master_n,
        n_sizes,
        samples,
        warmup,
    })
}

fn preflight(config: &Config) -> Result<(), String> {
    let manifest = config.fixture_dir.join("preparation-manifest.txt");
    let body = fs::read_to_string(&manifest)
        .map_err(|err| format!("read fixture manifest {}: {err}", manifest.display()))?;
    if !body
        .lines()
        .any(|line| line == format!("fixture_version={FIXTURE_VERSION}"))
        || !body
            .lines()
            .any(|line| line == format!("master.max_n={}", config.master_n))
    {
        return Err("fixture version or MASTER_N does not match static benchmark".to_string());
    }
    let source_dir = master_fixture_dir(&config.fixture_dir, config.master_n);
    for &n in &config.n_sizes {
        require_file(&ethereum_fixture::init_proof_path(&source_dir, n))?;
    }
    require_file(&ethereum_fixture::master_accounts_path(&source_dir))
}

fn require_file(path: &Path) -> Result<(), String> {
    if !path.is_file() {
        return Err(format!(
            "missing static benchmark input: {}",
            path.display()
        ));
    }
    Ok(())
}

fn required<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, String> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing {key}"))
}

fn parse_usize(value: &str, name: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|err| format!("invalid {name} {value}: {err}"))
}

fn parse_sizes(value: &str) -> Result<Vec<usize>, String> {
    let mut values = value
        .split(',')
        .map(|value| parse_usize(value, "n"))
        .collect::<Result<Vec<_>, _>>()?;
    values.sort_unstable();
    values.dedup();
    if values.is_empty() || values.iter().any(|value| *value == 0) {
        return Err("n values must be non-empty and positive".to_string());
    }
    Ok(values)
}

fn fixture_bytes(source_dir: &Path, n: usize) -> Result<u64, String> {
    let accounts = fs::metadata(ethereum_fixture::master_accounts_path(source_dir))
        .map_err(|err| format!("inspect account fixture: {err}"))?
        .len();
    let proof = fs::metadata(ethereum_fixture::init_proof_path(source_dir, n))
        .map_err(|err| format!("inspect Merkle fixture: {err}"))?
        .len();
    Ok(accounts.saturating_add(proof))
}

fn write_proof(path: &Path, proof: &StaticInitProof) -> Result<(), String> {
    fs::write(
        path,
        format!(
            "scheme=static-poa-init-sp1-v1\nproof_digest_hex={}\nproof_hex={}\n",
            proof.proof_digest_hex, proof.proof_hex
        ),
    )
    .map_err(|err| format!("write {}: {err}", path.display()))
}

fn write_raw_csv(path: &Path, values: &[SampleRecord]) -> Result<(), String> {
    let mut body = String::from("scheme,operation,n,m,sample,prover_ns,verifier_ns,proof_payload_bytes,artifact_bytes,proof_encoding\n");
    for value in values {
        body.push_str(&format!(
            "static-baseline,initialization,{},{},{},{},{},{},{},static-init-sp1-bundle\n",
            value.n,
            0,
            value.sample,
            value.prover.as_nanos(),
            value.verifier.as_nanos(),
            value.proof_payload_bytes,
            value.artifact_bytes,
        ));
    }
    fs::write(path, body).map_err(|err| format!("write {}: {err}", path.display()))
}

fn write_loading_csv(path: &Path, values: &[LoadRecord]) -> Result<(), String> {
    let mut body = String::from("scheme,n,m,phase,elapsed_ns,bytes,reused\n");
    for value in values {
        body.push_str(&format!(
            "static-baseline,{},0,{},{},{},{}\n",
            value.n,
            value.phase,
            value.elapsed.as_nanos(),
            value.bytes,
            value.reused,
        ));
    }
    fs::write(path, body).map_err(|err| format!("write {}: {err}", path.display()))
}

fn write_summary_csv(path: &Path, values: &[SummaryRecord]) -> Result<(), String> {
    let mut body = String::from("scheme,operation,n,m,input_load_ms,parameter_load_ms,prover_min_ms,prover_median_ms,prover_mean_ms,prover_p95_ms,prover_stddev_ms,verifier_min_ms,verifier_median_ms,verifier_mean_ms,verifier_p95_ms,verifier_stddev_ms,proof_payload_bytes,artifact_bytes,proof_encoding\n");
    for value in values {
        body.push_str(&format!(
            "static-baseline,initialization,{},0,{:.6},0.0,{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{},{},static-init-sp1-bundle\n",
            value.n,
            value.input_load.as_secs_f64() * 1000.0,
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
        ));
    }
    fs::write(path, body).map_err(|err| format!("write {}: {err}", path.display()))
}

fn write_summary_markdown(
    config: &Config,
    loads: &[LoadRecord],
    values: &[SummaryRecord],
) -> Result<(), String> {
    let mut body = String::from("# Traditional static PoA SP1 baseline\n\n");
    body.push_str("This baseline proves only account input validity, Ethereum ownership, nonnegative balances, and chain-state Merkle membership. It constructs no address polynomial, KZG accumulator/digest, KZG opening, evaluation commitment, or updateable local state.\n\n");
    body.push_str("| n | prover median | verifier median | proof payload | artifact |\n|---:|---:|---:|---:|---:|\n");
    for value in values {
        body.push_str(&format!(
            "| {} | {:.3} ms | {:.3} ms | {} | {} |\n",
            value.n,
            value.prover.median_ms,
            value.verifier.median_ms,
            human_bytes(value.proof_payload_bytes),
            human_bytes(value.artifact_bytes),
        ));
    }
    body.push_str(
        "\n## Excluded preparation\n\n| n | phase | elapsed | bytes |\n|---:|---|---:|---:|\n",
    );
    for value in loads {
        body.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            value.n,
            value.phase,
            human_duration(value.elapsed),
            human_bytes(value.bytes as usize),
        ));
    }
    body.push_str("\n## Methodology\n\n- Mock fixture generation, file loading, Cargo build, VK setup, CUDA worker startup/guest upload and disk writes are excluded from prover samples.\n- Stdin construction, CUDA/network transport, the complete single-guest SP1 proof and assembly of its protocol proof bundle are included.\n- Verification is measured separately with the locally trusted static-init VK.\n- POA_SP1_PROFILE=1 adds one execute-only diagnostic probe and subtracts it from measured prover time.\n");
    body.push_str(&format!(
        "\nEnvironment: n={:?}, samples={}, warmup={}, prover={}, mode={}\n",
        config.n_sizes,
        config.samples,
        config.warmup,
        std::env::var("SP1_PROVER").unwrap_or_else(|_| "cpu".to_string()),
        std::env::var("POA_SP1_PROOF_MODE").unwrap_or_else(|_| "compressed".to_string()),
    ));
    fs::write(config.output_dir.join("summary.md"), body)
        .map_err(|err| format!("write summary.md: {err}"))
}

fn write_environment(config: &Config) -> Result<(), String> {
    let body = format!(
        "scheme=static-baseline\nfixture_version={}\nmaster_n={}\nn_sizes={:?}\nsamples={}\nwarmup={}\nsp1_prover={}\nsp1_mode={}\nprofile={}\n",
        FIXTURE_VERSION,
        config.master_n,
        config.n_sizes,
        config.samples,
        config.warmup,
        std::env::var("SP1_PROVER").unwrap_or_else(|_| "cpu".to_string()),
        std::env::var("POA_SP1_PROOF_MODE").unwrap_or_else(|_| "compressed".to_string()),
        std::env::var("POA_SP1_PROFILE").unwrap_or_else(|_| "0".to_string()),
    );
    fs::write(config.output_dir.join("environment.txt"), body)
        .map_err(|err| format!("write environment.txt: {err}"))
}

fn stats(values: &[Duration]) -> Stats {
    let mut millis = values
        .iter()
        .map(|value| value.as_secs_f64() * 1000.0)
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

fn human_duration(value: Duration) -> String {
    if value.as_secs() >= 60 {
        format!("{:.2} min", value.as_secs_f64() / 60.0)
    } else if value.as_secs() >= 1 {
        format!("{:.3} s", value.as_secs_f64())
    } else {
        format!("{:.3} ms", value.as_secs_f64() * 1000.0)
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
