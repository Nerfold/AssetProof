use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use poa_bench::{ethereum_fixture, master_fixture_dir, FIXTURE_VERSION};

fn main() {
    if let Err(err) = run() {
        eprintln!("static baseline fixture error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    let fixture_dir = PathBuf::from(required(&args, "--fixture-dir")?);
    let master_n = parse_usize(required(&args, "--master-n")?, "master-n")?;
    let n_sizes = parse_sizes(required(&args, "--n")?)?;
    if master_n == 0 || n_sizes.iter().any(|n| *n == 0 || *n > master_n) {
        return Err("master-n must be positive and at least every requested n".to_string());
    }

    let source_dir = master_fixture_dir(&fixture_dir, master_n);
    println!("Traditional static PoA fixture preparation");
    println!("  master n: {master_n}");
    println!("  n sizes:  {n_sizes:?}");
    println!("  output:   {}", fixture_dir.display());
    println!("  SRS/KZG/delta/SMT: disabled");
    let (elapsed, reused) =
        ethereum_fixture::ensure_master_fixture(&source_dir, master_n, &n_sizes, &[])?;
    fs::create_dir_all(&fixture_dir)
        .map_err(|err| format!("create {}: {err}", fixture_dir.display()))?;
    fs::write(
        fixture_dir.join("preparation-manifest.txt"),
        format!(
            "fixture_version={FIXTURE_VERSION}\nmaster.max_n={master_n}\nmaster.dir={}\nn_sizes={n_sizes:?}\nmode=static-baseline-only\nstatus=complete\n",
            source_dir.display(),
        ),
    )
    .map_err(|err| format!("write static fixture manifest: {err}"))?;
    println!(
        "static fixture complete: elapsed={:.3}s reused={reused}",
        elapsed.as_secs_f64()
    );
    Ok(())
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
    if values.is_empty() {
        return Err("at least one n is required".to_string());
    }
    Ok(values)
}
