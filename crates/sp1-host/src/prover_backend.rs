use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sp1_sdk::blocking::{CpuProver, ProveRequest, Prover as BlockingProver};
use sp1_sdk::{Elf, ProvingKey, SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin};

use crate::proof_mode::ConfiguredProofMode;

/// Boundary between protocol orchestration and proof generation.
///
/// The in-process backend intentionally remains CPU-only. SP1 6.2's network
/// feature links a newer native `blst` than the Bulletproof dependency used by
/// the protocol. The network adapter therefore belongs in an isolated worker
/// process with its own Cargo dependency graph.
#[derive(Clone)]
pub(crate) enum ProofGenerator {
    Cpu,
    Network { worker: PathBuf },
}

impl ProofGenerator {
    pub(crate) fn from_env() -> Result<Self, String> {
        match std::env::var("SP1_PROVER")
            .unwrap_or_else(|_| "cpu".to_string())
            .to_ascii_lowercase()
            .as_str()
        {
            "cpu" | "local" => Ok(Self::Cpu),
            "network" => Ok(Self::Network {
                worker: network_worker_path(),
            }),
            value => Err(format!(
                "unsupported SP1_PROVER {value}; expected cpu or network"
            )),
        }
    }

    pub(crate) fn prove(
        &self,
        cpu: &CpuProver,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        mode: ConfiguredProofMode,
        guest: &str,
    ) -> Result<SP1ProofWithPublicValues, String> {
        match self {
            Self::Cpu => run_cpu(cpu, pk, stdin, mode, guest),
            Self::Network { worker } => run_network_worker(worker, cpu, pk, stdin, mode, guest),
        }
    }
}

const REQUEST_MAGIC: &[u8; 8] = b"POANET01";
const RESPONSE_MAGIC: &[u8; 8] = b"POARES01";
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn network_worker_path() -> PathBuf {
    std::env::var_os("POA_SP1_NETWORK_WORKER")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .and_then(Path::parent)
                .expect("sp1-host must be inside the repository")
                .join("tools/sp1-network-worker/target/release/sp1-network-worker")
        })
}

fn run_network_worker(
    worker: &Path,
    verifier: &CpuProver,
    pk: &SP1ProvingKey,
    stdin: SP1Stdin,
    mode: ConfiguredProofMode,
    guest: &str,
) -> Result<SP1ProofWithPublicValues, String> {
    if std::env::var_os("NETWORK_PRIVATE_KEY").is_none() {
        return Err("NETWORK_PRIVATE_KEY is required for SP1 Network proving".to_string());
    }
    if !worker.is_file() {
        return Err(format!(
            "SP1 Network worker not found at {}. Run `./poa sp1-network-build` first or set POA_SP1_NETWORK_WORKER.",
            worker.display()
        ));
    }

    let temp = PrivateRequestDir::new()?;
    let request_path = temp.path.join("request.bin");
    let response_path = temp.path.join("response.bin");
    write_request(&request_path, pk.elf(), &stdin, mode, guest)?;

    let status = Command::new(worker)
        .arg("prove")
        .arg(&request_path)
        .arg(&response_path)
        .status()
        .map_err(|err| format!("start SP1 Network worker {}: {err}", worker.display()))?;
    if !status.success() && !response_path.is_file() {
        return Err(format!("SP1 Network worker exited with {status}"));
    }
    let proof = read_response(&response_path, guest)?;
    verifier
        .verify(&proof, pk.verifying_key(), None)
        .map_err(|err| {
            format!("SP1 {guest} Network proof failed local trusted-VK verification: {err}")
        })?;
    Ok(proof)
}

fn write_request(
    path: &Path,
    elf: &Elf,
    stdin: &SP1Stdin,
    mode: ConfiguredProofMode,
    guest: &str,
) -> Result<(), String> {
    let elf_bytes: &[u8] = match elf {
        Elf::Static(bytes) => bytes,
        Elf::Dynamic(bytes) => bytes,
    };
    let stdin_bytes =
        bincode::serialize(stdin).map_err(|err| format!("serialize SP1 Network stdin: {err}"))?;
    let mode = match mode {
        ConfiguredProofMode::Compressed => 0u8,
        ConfiguredProofMode::Groth16 => 1u8,
        ConfiguredProofMode::Plonk => 2u8,
    };

    let mut file = create_private_file(path)?;
    file.write_all(REQUEST_MAGIC)
        .and_then(|_| file.write_all(&[mode]))
        .and_then(|_| write_len_prefixed(&mut file, guest.as_bytes()))
        .and_then(|_| write_len_prefixed(&mut file, elf_bytes))
        .and_then(|_| write_len_prefixed(&mut file, &stdin_bytes))
        .and_then(|_| file.flush())
        .map_err(|err| format!("write SP1 Network request {}: {err}", path.display()))
}

fn read_response(path: &Path, guest: &str) -> Result<SP1ProofWithPublicValues, String> {
    let mut file = fs::File::open(path)
        .map_err(|err| format!("open SP1 Network response {}: {err}", path.display()))?;
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic)
        .map_err(|err| format!("read SP1 Network response header: {err}"))?;
    if &magic != RESPONSE_MAGIC {
        return Err("invalid SP1 Network worker response header".to_string());
    }
    let mut status = [0u8; 1];
    file.read_exact(&mut status)
        .map_err(|err| format!("read SP1 Network response status: {err}"))?;
    let payload = read_len_prefixed(&mut file, 1usize << 34)?;
    if status[0] != 0 {
        return Err(format!(
            "SP1 {guest} Network prove failed: {}",
            String::from_utf8_lossy(&payload)
        ));
    }
    bincode::deserialize(&payload)
        .map_err(|err| format!("deserialize SP1 {guest} Network proof: {err}"))
}

fn write_len_prefixed(writer: &mut impl Write, bytes: &[u8]) -> std::io::Result<()> {
    writer.write_all(&(bytes.len() as u64).to_le_bytes())?;
    writer.write_all(bytes)
}

fn read_len_prefixed(reader: &mut impl Read, max: usize) -> Result<Vec<u8>, String> {
    let mut len = [0u8; 8];
    reader
        .read_exact(&mut len)
        .map_err(|err| format!("read length-prefixed payload: {err}"))?;
    let len = usize::try_from(u64::from_le_bytes(len))
        .map_err(|_| "SP1 Network payload length does not fit this platform".to_string())?;
    if len > max {
        return Err(format!("SP1 Network payload exceeds {max} bytes"));
    }
    let mut bytes = vec![0u8; len];
    reader
        .read_exact(&mut bytes)
        .map_err(|err| format!("read length-prefixed payload body: {err}"))?;
    Ok(bytes)
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> Result<fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| format!("create private file {}: {err}", path.display()))
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> Result<fs::File, String> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|err| format!("create private file {}: {err}", path.display()))
}

struct PrivateRequestDir {
    path: PathBuf,
}

impl PrivateRequestDir {
    fn new() -> Result<Self, String> {
        let id = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| format!("read system time for SP1 Network request: {err}"))?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "poa-sp1-network-{}-{timestamp}-{id}",
            std::process::id(),
        ));
        fs::create_dir(&path)
            .map_err(|err| format!("create private SP1 Network request dir: {err}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .map_err(|err| format!("secure SP1 Network request dir: {err}"))?;
        }
        Ok(Self { path })
    }
}

impl Drop for PrivateRequestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn run_cpu(
    prover: &CpuProver,
    pk: &SP1ProvingKey,
    stdin: SP1Stdin,
    mode: ConfiguredProofMode,
    guest: &str,
) -> Result<SP1ProofWithPublicValues, String> {
    let request = prover.prove(pk, stdin);
    let result = match mode {
        ConfiguredProofMode::Groth16 => request.groth16().run(),
        ConfiguredProofMode::Plonk => request.plonk().run(),
        ConfiguredProofMode::Compressed => request.compressed().run(),
    };
    result.map_err(|err| format!("SP1 {guest} CPU prove failed: {err}"))
}
