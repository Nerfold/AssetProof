use std::fs;
use std::path::{Path, PathBuf};

use common::crypto::hash_bytes;
use serde::{Deserialize, Serialize};
use sp1_sdk::blocking::Prover as BlockingProver;
use sp1_sdk::Elf;
use sp1_sdk::ProvingKey;
use sp1_sdk::SP1VerifyingKey;

use crate::prover_backend::shared_cpu_prover;

const UPDATE_ELF_NAME: &str = "smt-update";
const INSERT_ELF_NAME: &str = "smt-insert";
const SMT_INIT_ELF_NAME: &str = "smt-init";
const INIT_ELF_NAME: &str = "init";
const INIT_OWNERSHIP_ELF_NAME: &str = "init-ownership";
const KZG_INSERT_ELF_NAME: &str = "kzg-insert";

#[derive(Clone, Serialize, Deserialize)]
struct StoredSp1Setup {
    elf_name: String,
    elf_digest: [u8; 32],
    vk: SP1VerifyingKey,
}

pub fn default_setup_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("POA_SP1_SETUP_DIR") {
        return PathBuf::from(path);
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("sp1-host must live under the workspace crates directory")
        .join("params/sp1")
}

pub fn ensure_protocol_setups(
    setup_dir: &Path,
    init_elf: Elf,
    init_ownership_elf: Elf,
    kzg_insert_elf: Elf,
) -> Result<(), String> {
    ensure_setup_file(setup_dir, INIT_ELF_NAME, init_elf)?;
    ensure_setup_file(setup_dir, INIT_OWNERSHIP_ELF_NAME, init_ownership_elf)?;
    ensure_setup_file(setup_dir, KZG_INSERT_ELF_NAME, kzg_insert_elf)?;
    Ok(())
}

pub fn ensure_protocol_setup_components(
    setup_dir: &Path,
    init_elf: Option<Elf>,
    init_ownership_elf: Option<Elf>,
    kzg_insert_elf: Option<Elf>,
) -> Result<(), String> {
    if let Some(elf) = init_elf {
        ensure_setup_file(setup_dir, INIT_ELF_NAME, elf)?;
    }
    if let Some(elf) = init_ownership_elf {
        ensure_setup_file(setup_dir, INIT_OWNERSHIP_ELF_NAME, elf)?;
    }
    if let Some(elf) = kzg_insert_elf {
        ensure_setup_file(setup_dir, KZG_INSERT_ELF_NAME, elf)?;
    }
    Ok(())
}

pub fn ensure_smt_setups(
    setup_dir: &Path,
    init_elf: Elf,
    ownership_elf: Elf,
    update_elf: Elf,
    insert_elf: Elf,
) -> Result<(), String> {
    ensure_setup_file(setup_dir, SMT_INIT_ELF_NAME, init_elf)?;
    ensure_setup_file(setup_dir, INIT_OWNERSHIP_ELF_NAME, ownership_elf)?;
    ensure_setup_file(setup_dir, UPDATE_ELF_NAME, update_elf)?;
    ensure_setup_file(setup_dir, INSERT_ELF_NAME, insert_elf)?;
    Ok(())
}

pub fn ensure_smt_init_setups(
    setup_dir: &Path,
    init_elf: Elf,
    ownership_elf: Elf,
) -> Result<(), String> {
    ensure_setup_file(setup_dir, SMT_INIT_ELF_NAME, init_elf)?;
    ensure_setup_file(setup_dir, INIT_OWNERSHIP_ELF_NAME, ownership_elf)?;
    Ok(())
}

pub fn load_smt_init_vk(setup_dir: &Path, init_elf: Elf) -> Result<SP1VerifyingKey, String> {
    load_setup_file(setup_dir, SMT_INIT_ELF_NAME, init_elf)
}

pub fn load_kzg_insert_vk(setup_dir: &Path, elf: Elf) -> Result<SP1VerifyingKey, String> {
    load_setup_file(setup_dir, KZG_INSERT_ELF_NAME, elf)
}

pub fn load_update_vk(setup_dir: &Path, update_elf: Elf) -> Result<SP1VerifyingKey, String> {
    load_setup_file(setup_dir, UPDATE_ELF_NAME, update_elf)
}

pub fn load_insert_vk(setup_dir: &Path, insert_elf: Elf) -> Result<SP1VerifyingKey, String> {
    load_setup_file(setup_dir, INSERT_ELF_NAME, insert_elf)
}

pub fn load_init_vk(setup_dir: &Path, init_elf: Elf) -> Result<SP1VerifyingKey, String> {
    load_setup_file(setup_dir, INIT_ELF_NAME, init_elf)
}

pub fn load_init_ownership_vk(
    setup_dir: &Path,
    init_ownership_elf: Elf,
) -> Result<SP1VerifyingKey, String> {
    load_setup_file(setup_dir, INIT_OWNERSHIP_ELF_NAME, init_ownership_elf)
}

fn ensure_setup_file(setup_dir: &Path, elf_name: &str, elf: Elf) -> Result<(), String> {
    fs::create_dir_all(setup_dir)
        .map_err(|err| format!("create setup dir {}: {err}", setup_dir.display()))?;
    let path = setup_file_path(setup_dir, elf_name);
    let digest = elf_digest(&elf);

    if path.exists() {
        let stored = read_setup_file(&path)?;
        if stored.elf_digest == digest {
            println!("SP1 setup [{elf_name}]: reusing {}", path.display());
            return Ok(());
        }
        println!("SP1 setup [{elf_name}]: ELF changed, regenerating...");
    } else {
        println!("SP1 setup [{elf_name}]: generating...");
    }

    let prover = shared_cpu_prover();
    let pk = prover
        .setup(elf)
        .map_err(|err| format!("sp1 setup failed for {elf_name}: {err}"))?;
    let stored = StoredSp1Setup {
        elf_name: elf_name.to_string(),
        elf_digest: digest,
        vk: pk.verifying_key().clone(),
    };
    write_setup_file(&path, &stored)?;
    println!("SP1 setup [{elf_name}]: wrote {}", path.display());
    Ok(())
}

fn load_setup_file(setup_dir: &Path, elf_name: &str, elf: Elf) -> Result<SP1VerifyingKey, String> {
    let path = setup_file_path(setup_dir, elf_name);
    let setup_command = if matches!(
        elf_name,
        SMT_INIT_ELF_NAME | UPDATE_ELF_NAME | INSERT_ELF_NAME
    ) {
        "sp1-smt-setup"
    } else {
        "sp1-setup"
    };
    if !path.exists() {
        return Err(format!(
            "missing SP1 setup artifact {}. Run `./poa {setup_command} {}` first.",
            path.display(),
            setup_dir.display()
        ));
    }
    let stored = read_setup_file(&path)?;
    let digest = elf_digest(&elf);
    if stored.elf_digest != digest {
        return Err(format!(
            "stale SP1 setup artifact {} for {}. Re-run `./poa {setup_command} {}`.",
            path.display(),
            elf_name,
            setup_dir.display()
        ));
    }
    Ok(stored.vk)
}

fn setup_file_path(setup_dir: &Path, elf_name: &str) -> PathBuf {
    setup_dir.join(format!("{elf_name}.bin"))
}

fn elf_digest(elf: &Elf) -> [u8; 32] {
    hash_bytes("sp1-elf-digest", &[elf.as_ref()])
}

fn read_setup_file(path: &Path) -> Result<StoredSp1Setup, String> {
    let bytes = fs::read(path).map_err(|err| format!("read {}: {err}", path.display()))?;
    bincode::deserialize(&bytes).map_err(|err| format!("deserialize {}: {err}", path.display()))
}

fn write_setup_file(path: &Path, stored: &StoredSp1Setup) -> Result<(), String> {
    let bytes =
        bincode::serialize(stored).map_err(|err| format!("serialize {}: {err}", path.display()))?;
    fs::write(path, bytes).map_err(|err| format!("write {}: {err}", path.display()))
}
