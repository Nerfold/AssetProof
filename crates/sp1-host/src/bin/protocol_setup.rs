use std::path::PathBuf;

use sp1_host::init::{ensure_sp1_setup, ensure_sp1_setup_components};
use sp1_host::setup::default_setup_dir;

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let setup_dir = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(default_setup_dir);
    if args.next().is_some() {
        return Err("usage: ./poa sp1-setup [setup-dir]".to_string());
    }
    let components =
        std::env::var("POA_SP1_SETUP_COMPONENTS").unwrap_or_else(|_| "all".to_string());
    let include_init = components == "all" || components.split(',').any(|value| value == "init");
    let include_insert =
        components == "all" || components.split(',').any(|value| value == "insert");
    if !include_init && !include_insert {
        return Err("POA_SP1_SETUP_COMPONENTS must contain init, insert, or all".to_string());
    }
    if components == "all" {
        ensure_sp1_setup(&setup_dir)?;
    } else {
        ensure_sp1_setup_components(&setup_dir, include_init, include_insert)?;
    }
    println!(
        "protocol SP1 setup complete (components={components}): {}",
        setup_dir.display(),
    );
    Ok(())
}
