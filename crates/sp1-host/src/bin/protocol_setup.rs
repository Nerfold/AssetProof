use std::path::PathBuf;

use sp1_host::init::ensure_sp1_setup;
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
    ensure_sp1_setup(&setup_dir)?;
    println!(
        "protocol SP1 setup complete (init Merkle + init ownership + KZG insert): {}",
        setup_dir.display()
    );
    Ok(())
}
