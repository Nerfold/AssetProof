mod fixture;

use std::collections::BTreeMap;
use std::fs;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sp1_host::standalone::StandaloneProgram;
use sp1_programs_common::ethereum_mpt::account_batch_statement_digest;
use sp1_programs_common::io::{Sp1EthereumMptBatchInput, Sp1EthereumMptBatchPublicValues};
use sp1_sdk::{include_elf, SP1ProofWithPublicValues, SP1PublicValues, SP1Stdin};

const ELF: sp1_sdk::Elf = include_elf!("sp1-ethereum-mpt-bench");
const GUEST: &str = "ethereum-mpt-account-proof";

#[derive(Debug)]
struct Config {
    counts: Vec<usize>,
    samples: usize,
    warmup: usize,
    output: PathBuf,
    prove: bool,
}

#[derive(Debug)]
struct ResultRow {
    count: usize,
    nodes: usize,
    input_bytes: usize,
    proof_bytes: usize,
    execute_mean: Duration,
    cycles: u64,
    syscalls: u64,
    input_decode_cycles: u64,
    mpt_verify_cycles: u64,
    batch_binding_cycles: u64,
    public_commit_cycles: u64,
    prove_mean: Option<Duration>,
    verify_mean: Option<Duration>,
    sp1_proof_bytes: Option<usize>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Ethereum MPT SP1 benchmark error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let config = parse_config()?;
    fs::create_dir_all(&config.output)
        .map_err(|err| format!("create {}: {err}", config.output.display()))?;
    println!("Ethereum MPT account-proof SP1 benchmark");
    println!("  proof counts: {:?}", config.counts);
    println!("  samples: {}, warmup: {}", config.samples, config.warmup);
    println!("  prover: {}", env("SP1_PROVER", "cpu"));
    println!("  proof mode: {}", env("POA_SP1_PROOF_MODE", "compressed"));
    println!("  prove: {}", config.prove);
    println!("  output: {}", config.output.display());

    println!("\n== preparing standalone SP1 guest outside sample timers ==");
    let (program, preparation) = StandaloneProgram::prepare(ELF, GUEST, config.prove)?;
    println!(
        "   executor prepare: {}",
        human_duration(preparation.executor_prepare)
    );
    println!("   CPU setup: {}", human_duration(preparation.cpu_setup));
    println!(
        "   backend prepare: {}",
        human_duration(preparation.backend_prepare)
    );

    let max_count = *config
        .counts
        .last()
        .ok_or_else(|| "empty MPT proof-count list".to_string())?;
    let mut rows = Vec::new();
    let fixture_started = Instant::now();
    let master = fixture::synthetic_account_proofs(max_count)?;
    println!(
        "\n== generated one {max_count}-account Ethereum MPT and all membership proofs in {} (excluded) ==",
        human_duration(fixture_started.elapsed())
    );

    // Process largest-to-smallest and truncate in place. This keeps only
    // one copy of the potentially large witness in host memory.
    let mut input = Sp1EthereumMptBatchInput { proofs: master };
    for &count in config.counts.iter().rev() {
        input.proofs.truncate(count);
        let input_bytes = bincode::serialized_size(&input)
            .map_err(|err| format!("measure input: {err}"))? as usize;
        let nodes = input
            .proofs
            .iter()
            .map(|proof| proof.proof_nodes.len())
            .sum::<usize>();
        let proof_bytes = input
            .proofs
            .iter()
            .flat_map(|proof| &proof.proof_nodes)
            .map(Vec::len)
            .sum::<usize>();
        let expected_public = Sp1EthereumMptBatchPublicValues {
            statement_digest: account_batch_statement_digest(&input.proofs),
            proof_count: count,
            proof_node_count: nodes,
            proof_bytes,
        };
        // Serialize the large nested witness once per batch size. Each SP1
        // request still needs its own owned stdin buffer, but cloning the
        // encoded bytes avoids repeated serde traversal and RLP-vector
        // allocation on the host.
        let stdin_template = stdin(false, &input);
        let profile_stdin = stdin(true, &input);
        println!(
            "\n-- proofs={count}, nodes={nodes} ({:.2}/proof), MPT-witness={} --",
            nodes as f64 / count as f64,
            human_bytes(proof_bytes)
        );

        for _ in 0..config.warmup {
            let execution = program.execute(stdin_template.clone())?;
            validate_public_values(execution.public_values, &expected_public)?;
        }
        let mut execute_samples = Vec::with_capacity(config.samples);
        let mut cycles = None;
        let mut syscalls = None;
        for _ in 0..config.samples {
            let execution = program.execute(stdin_template.clone())?;
            validate_public_values(execution.public_values, &expected_public)?;
            if cycles
                .replace(execution.cycles)
                .is_some_and(|old| old != execution.cycles)
                || syscalls
                    .replace(execution.syscalls)
                    .is_some_and(|old| old != execution.syscalls)
            {
                return Err(format!(
                    "non-deterministic SP1 execution report for {count} MPT proofs"
                ));
            }
            execute_samples.push(execution.elapsed);
        }
        let execute_mean = mean_duration(&execute_samples)
            .ok_or_else(|| "missing SP1 execute samples".to_string())?;
        let cycles = cycles.expect("samples are non-empty");
        let syscalls = syscalls.expect("samples are non-empty");
        println!(
            "   execute mean={} cycles={} syscalls={}",
            human_duration(execute_mean),
            cycles,
            syscalls
        );

        // The profile execution is separate from all timed samples.
        let profile = program.execute(profile_stdin)?;
        validate_public_values(profile.public_values, &expected_public)?;
        let input_decode_cycles = phase_cycles(&profile.phase_cycles, "input_decode")?;
        let mpt_verify_cycles = phase_cycles(&profile.phase_cycles, "ethereum_mpt_batch_verify")?;
        let batch_binding_cycles = phase_cycles(&profile.phase_cycles, "batch_statement_binding")?;
        let public_commit_cycles = phase_cycles(&profile.phase_cycles, "public_values_commit")?;
        println!(
            "   MPT verification core={mpt_verify_cycles} cycles ({:.1} cycles/proof)",
            mpt_verify_cycles as f64 / count as f64
        );
        if env("POA_SP1_PROFILE", "0") == "1" {
            println!("   phase profile (excluded from all measurements):");
            for (phase, phase_cycles) in profile.phase_cycles {
                println!("      {phase}: {phase_cycles} cycles");
            }
        }

        let mut prove_samples = Vec::new();
        let mut verify_samples = Vec::new();
        let mut last_proof_size = None;
        if config.prove {
            for index in 0..config.warmup {
                println!("   proof warmup {}/{}", index + 1, config.warmup);
                let proof = program.prove(stdin_template.clone())?;
                program.verify(&proof)?;
                validate_bundle(&proof, &expected_public)?;
                black_box(proof);
            }
            for index in 0..config.samples {
                let proof_stdin = stdin_template.clone();
                let prove_started = Instant::now();
                let proof = program.prove(proof_stdin)?;
                let prove_elapsed = prove_started.elapsed();
                let verify_started = Instant::now();
                program.verify(&proof)?;
                let verify_elapsed = verify_started.elapsed();
                validate_bundle(&proof, &expected_public)?;
                let encoded = bincode::serialize(&proof)
                    .map_err(|err| format!("serialize SP1 proof: {err}"))?;
                println!(
                    "   sample {}/{}: prove={} verify={} proof={}",
                    index + 1,
                    config.samples,
                    human_duration(prove_elapsed),
                    human_duration(verify_elapsed),
                    human_bytes(encoded.len())
                );
                prove_samples.push(prove_elapsed);
                verify_samples.push(verify_elapsed);
                last_proof_size = Some(encoded.len());
                black_box(proof);
            }
        }
        rows.push(ResultRow {
            count,
            nodes,
            input_bytes,
            proof_bytes,
            execute_mean,
            cycles,
            syscalls,
            input_decode_cycles,
            mpt_verify_cycles,
            batch_binding_cycles,
            public_commit_cycles,
            prove_mean: mean_duration(&prove_samples),
            verify_mean: mean_duration(&verify_samples),
            sp1_proof_bytes: last_proof_size,
        });
    }

    rows.sort_by_key(|row| row.count);
    write_results(&config.output, &rows, preparation)?;
    println!("\nSummary: {}/summary.md", config.output.display());
    Ok(())
}

fn stdin(profile: bool, input: &Sp1EthereumMptBatchInput) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(&profile);
    stdin.write(input);
    stdin
}

fn validate_bundle(
    proof: &SP1ProofWithPublicValues,
    expected: &Sp1EthereumMptBatchPublicValues,
) -> Result<(), String> {
    validate_public_values(proof.public_values.clone(), expected)
}

fn validate_public_values(
    mut values: SP1PublicValues,
    expected: &Sp1EthereumMptBatchPublicValues,
) -> Result<(), String> {
    let public = values.read::<Sp1EthereumMptBatchPublicValues>();
    if &public != expected {
        return Err("unexpected Ethereum MPT guest public values".to_string());
    }
    Ok(())
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
    let counts = parse_positive_list(
        values.get("--counts").map(String::as_str).unwrap_or("1"),
        "proof count",
    )?;
    let samples = parse_usize(
        values.get("--samples").map(String::as_str).unwrap_or("3"),
        "samples",
    )?;
    let warmup = parse_usize(
        values.get("--warmup").map(String::as_str).unwrap_or("1"),
        "warmup",
    )?;
    let prove = match values.get("--prove").map(String::as_str).unwrap_or("1") {
        "1" | "true" => true,
        "0" | "false" => false,
        value => return Err(format!("--prove must be 0/1 or false/true, got {value}")),
    };
    if samples == 0 {
        return Err("samples must be positive".to_string());
    }
    Ok(Config {
        counts,
        samples,
        warmup,
        output: PathBuf::from(
            values
                .get("--output")
                .map(String::as_str)
                .unwrap_or("artifacts/benchmarks/ethereum-mpt-sp1"),
        ),
        prove,
    })
}

fn parse_positive_list(value: &str, label: &str) -> Result<Vec<usize>, String> {
    let mut values = value
        .split(',')
        .map(|item| parse_usize(item, label))
        .collect::<Result<Vec<_>, _>>()?;
    values.sort_unstable();
    values.dedup();
    if values.is_empty() || values.contains(&0) {
        return Err(format!("{label}s must be positive"));
    }
    Ok(values)
}

fn phase_cycles(phases: &BTreeMap<String, u64>, name: &str) -> Result<u64, String> {
    phases
        .get(name)
        .copied()
        .ok_or_else(|| format!("SP1 execution report is missing phase {name}"))
}

fn parse_usize(value: &str, label: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|err| format!("invalid {label} {value}: {err}"))
}

fn write_results(
    output: &Path,
    rows: &[ResultRow],
    preparation: sp1_host::standalone::StandalonePreparation,
) -> Result<(), String> {
    let mut csv = String::from(
        "proof_count,proof_nodes,proof_nodes_per_account,input_bytes,mpt_proof_bytes,execute_mean_ms,total_cycles,syscalls,input_decode_cycles,mpt_verify_cycles,mpt_verify_cycles_per_proof,batch_binding_cycles,public_commit_cycles,prove_mean_ms,verify_mean_ms,sp1_proof_bytes\n",
    );
    let mut markdown = String::from(
        "# Ethereum MPT account-proof verification in SP1\n\nThis benchmark verifies account membership proofs exported from one synthetic Ethereum hexary Merkle-Patricia trie, so every statement shares one state root. It contains address hashing, canonical RLP/MPT verification, balance comparison, a Keccak commitment to the accepted public statements, and public-value commitment. Fixture generation, guest setup, backend preparation, and the separate phase-profile execution are excluded.\n\n| proofs | proof nodes | nodes/account | MPT witness | execute mean | MPT cycles/proof | total cycles | prove mean | verify mean | SP1 proof |\n|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n",
    );
    for row in rows {
        csv.push_str(&format!(
            "{},{},{},{},{},{:.6},{},{},{},{},{},{},{},{},{},{}\n",
            row.count,
            row.nodes,
            row.nodes as f64 / row.count as f64,
            row.input_bytes,
            row.proof_bytes,
            row.execute_mean.as_secs_f64() * 1000.0,
            row.cycles,
            row.syscalls,
            row.input_decode_cycles,
            row.mpt_verify_cycles,
            row.mpt_verify_cycles as f64 / row.count as f64,
            row.batch_binding_cycles,
            row.public_commit_cycles,
            optional_ms(row.prove_mean),
            optional_ms(row.verify_mean),
            row.sp1_proof_bytes
                .map(|value| value.to_string())
                .unwrap_or_default(),
        ));
        markdown.push_str(&format!(
            "| {} | {} | {:.2} | {} | {} | {:.1} | {} | {} | {} | {} |\n",
            row.count,
            row.nodes,
            row.nodes as f64 / row.count as f64,
            human_bytes(row.proof_bytes),
            human_duration(row.execute_mean),
            row.mpt_verify_cycles as f64 / row.count as f64,
            row.cycles,
            optional_duration(row.prove_mean),
            optional_duration(row.verify_mean),
            row.sp1_proof_bytes
                .map(human_bytes)
                .unwrap_or_else(|| "-".to_string()),
        ));
    }
    markdown.push_str(&format!(
        "\n## Excluded preparation\n\n- reference executor preparation: {}\n- CPU setup: {}\n- selected backend preparation: {}\n- prover: `{}`\n- proof mode: `{}`\n",
        human_duration(preparation.executor_prepare),
        human_duration(preparation.cpu_setup),
        human_duration(preparation.backend_prepare),
        env("SP1_PROVER", "cpu"),
        env("POA_SP1_PROOF_MODE", "compressed"),
    ));
    fs::write(output.join("summary.csv"), csv)
        .map_err(|err| format!("write summary.csv: {err}"))?;
    fs::write(output.join("summary.md"), markdown).map_err(|err| format!("write summary.md: {err}"))
}

fn mean_duration(values: &[Duration]) -> Option<Duration> {
    if values.is_empty() {
        return None;
    }
    Some(Duration::from_secs_f64(
        values.iter().map(Duration::as_secs_f64).sum::<f64>() / values.len() as f64,
    ))
}

fn optional_ms(value: Option<Duration>) -> String {
    value
        .map(|duration| format!("{:.6}", duration.as_secs_f64() * 1000.0))
        .unwrap_or_default()
}

fn optional_duration(value: Option<Duration>) -> String {
    value.map(human_duration).unwrap_or_else(|| "-".to_string())
}

fn env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
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
