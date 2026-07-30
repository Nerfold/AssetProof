use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use sp1_sdk::blocking::{CpuProver, ProveRequest, Prover as BlockingProver, ProverClient};
use sp1_sdk::{Elf, ProvingKey, SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin};

use crate::proof_mode::ConfiguredProofMode;

/// Boundary between protocol orchestration and proof generation.
///
/// The in-process backend intentionally remains CPU-only. Optional Network and
/// CUDA dependency graphs live in isolated worker processes so ordinary builds
/// do not require cloud credentials, Linux/x86_64, or a GPU runtime.
#[derive(Clone)]
pub(crate) enum ProofGenerator {
    Cpu,
    Cuda {
        client: Arc<Mutex<CudaWorkerClient>>,
    },
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
            "cuda" | "gpu" => Ok(Self::Cuda {
                client: shared_cuda_client(),
            }),
            "network" => Ok(Self::Network {
                worker: network_worker_path(),
            }),
            value => Err(format!(
                "unsupported SP1_PROVER {value}; expected cpu, cuda, or network"
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
            Self::Cuda { client } => {
                // Non-benchmark callers retain lazy setup semantics. The benchmark
                // explicitly calls `prepare` before starting any sample timer.
                self.prepare(pk, guest)?;
                let proof = client
                    .lock()
                    .map_err(|_| "SP1 CUDA worker lock poisoned".to_string())?
                    .prove(stdin, mode, guest)?;
                Ok(proof)
            }
            Self::Network { worker } => run_network_worker(worker, pk, stdin, mode, guest),
        }
    }

    /// Starts the persistent CUDA worker and uploads/setups this guest program.
    ///
    /// The returned wall-clock duration is intended to be recorded as setup
    /// overhead outside benchmark sample timers. Repeated calls for the same
    /// guest return zero.
    pub(crate) fn prepare(
        &self,
        pk: &SP1ProvingKey,
        guest: &str,
    ) -> Result<Duration, String> {
        match self {
            Self::Cuda { client } => client
                .lock()
                .map_err(|_| "SP1 CUDA worker lock poisoned".to_string())?
                .prepare(pk.elf(), guest),
            Self::Cpu | Self::Network { .. } => Ok(Duration::ZERO),
        }
    }
}

// Kept stable for compatibility with already-built external workers.
const REQUEST_MAGIC: &[u8; 8] = b"POANET01";
const RESPONSE_MAGIC: &[u8; 8] = b"POARES01";
const CUDA_REQUEST_MAGIC: &[u8; 8] = b"POACUD02";
const CUDA_RESPONSE_MAGIC: &[u8; 8] = b"POACUR02";
const CUDA_PREPARE: u8 = 0;
const CUDA_PROVE: u8 = 1;
const CUDA_WORKER_VERSION: &str = "poa-sp1-cuda-worker-v3-direct";
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);
static CUDA_CLIENT: OnceLock<Arc<Mutex<CudaWorkerClient>>> = OnceLock::new();
static CPU_PROVER: OnceLock<CpuProver> = OnceLock::new();

pub(crate) fn shared_cpu_prover() -> CpuProver {
    CPU_PROVER
        .get_or_init(|| ProverClient::builder().cpu().build())
        .clone()
}

fn repository_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("sp1-host must be inside the repository")
}

fn cuda_worker_path() -> PathBuf {
    std::env::var_os("POA_SP1_CUDA_WORKER")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            repository_root().join("tools/sp1-cuda-worker/target/release/sp1-cuda-worker")
        })
}

fn shared_cuda_client() -> Arc<Mutex<CudaWorkerClient>> {
    CUDA_CLIENT
        .get_or_init(|| Arc::new(Mutex::new(CudaWorkerClient::new(cuda_worker_path()))))
        .clone()
}

fn network_worker_path() -> PathBuf {
    std::env::var_os("POA_SP1_NETWORK_WORKER")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            repository_root().join("tools/sp1-network-worker/target/release/sp1-network-worker")
        })
}

fn run_network_worker(
    worker: &Path,
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
    run_external_worker(worker, "Network", pk, stdin, mode, guest)
}

pub(crate) struct CudaWorkerClient {
    worker: PathBuf,
    process: Option<CudaWorkerProcess>,
    prepared_guests: std::collections::BTreeSet<String>,
}

impl CudaWorkerClient {
    fn new(worker: PathBuf) -> Self {
        Self {
            worker,
            process: None,
            prepared_guests: std::collections::BTreeSet::new(),
        }
    }

    fn prepare(&mut self, elf: &Elf, guest: &str) -> Result<Duration, String> {
        if self.prepared_guests.contains(guest) {
            return Ok(Duration::ZERO);
        }
        let started = Instant::now();
        let process = self.process()?;
        let elf_bytes: &[u8] = match elf {
            Elf::Static(bytes) => bytes,
            Elf::Dynamic(bytes) => bytes,
        };
        process
            .stream
            .write_all(CUDA_REQUEST_MAGIC)
            .and_then(|_| process.stream.write_all(&[CUDA_PREPARE]))
            .and_then(|_| write_len_prefixed(&mut process.stream, guest.as_bytes()))
            .and_then(|_| write_len_prefixed(&mut process.stream, elf_bytes))
            .and_then(|_| process.stream.flush())
            .map_err(|err| format!("send SP1 CUDA setup request for {guest}: {err}"))?;
        let payload = read_cuda_response(&mut process.stream, guest, "setup")?;
        if !payload.is_empty() {
            return Err(format!(
                "SP1 CUDA setup for {guest} returned an unexpected payload"
            ));
        }
        self.prepared_guests.insert(guest.to_string());
        Ok(started.elapsed())
    }

    fn prove(
        &mut self,
        stdin: SP1Stdin,
        mode: ConfiguredProofMode,
        guest: &str,
    ) -> Result<SP1ProofWithPublicValues, String> {
        if !self.prepared_guests.contains(guest) {
            return Err(format!(
                "SP1 CUDA guest {guest} was not prepared before proving"
            ));
        }
        let stdin_bytes =
            bincode::serialize(&stdin).map_err(|err| format!("serialize SP1 CUDA stdin: {err}"))?;
        let mode = proof_mode_byte(mode);
        let process = self.process()?;
        process
            .stream
            .write_all(CUDA_REQUEST_MAGIC)
            .and_then(|_| process.stream.write_all(&[CUDA_PROVE, mode]))
            .and_then(|_| write_len_prefixed(&mut process.stream, guest.as_bytes()))
            .and_then(|_| write_len_prefixed(&mut process.stream, &stdin_bytes))
            .and_then(|_| process.stream.flush())
            .map_err(|err| format!("send SP1 CUDA prove request for {guest}: {err}"))?;
        let payload = read_cuda_response(&mut process.stream, guest, "prove")?;
        let proof: sp1_sdk::ProofFromNetwork = bincode::deserialize(&payload)
            .map_err(|err| format!("deserialize SP1 {guest} CUDA proof: {err}"))?;
        Ok(proof.into())
    }

    #[cfg(unix)]
    fn process(&mut self) -> Result<&mut CudaWorkerProcess, String> {
        if self.process.is_none() {
            if !self.worker.is_file() {
                return Err(format!(
                    "SP1 CUDA worker not found at {}. Run `./poa sp1-cuda-build` first or set POA_SP1_CUDA_WORKER.",
                    self.worker.display()
                ));
            }
            validate_cuda_worker(&self.worker)?;
            let session = PrivateRequestDir::new("cuda-session")?;
            let socket_path = session.path.join("worker.sock");
            let mut child = Command::new(&self.worker)
                .arg("serve")
                .arg(&socket_path)
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|err| {
                    format!(
                        "start persistent SP1 CUDA worker {}: {err}",
                        self.worker.display()
                    )
                })?;
            let stream = connect_cuda_socket(&socket_path, &mut child)?;
            self.process = Some(CudaWorkerProcess {
                child,
                stream,
                _session: session,
            });
        }
        self.process
            .as_mut()
            .ok_or_else(|| "SP1 CUDA worker failed to start".to_string())
    }

    #[cfg(not(unix))]
    fn process(&mut self) -> Result<&mut CudaWorkerProcess, String> {
        Err("SP1 CUDA proving requires a Unix host".to_string())
    }
}

fn validate_cuda_worker(worker: &Path) -> Result<(), String> {
    let output = Command::new(worker)
        .arg("protocol-version")
        .output()
        .map_err(|err| format!("inspect SP1 CUDA worker {}: {err}", worker.display()))?;
    let version = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() || version.trim() != CUDA_WORKER_VERSION {
        return Err(format!(
            "SP1 CUDA worker {} is stale or incompatible (found {:?}, expected {}). \
             Run `./poa sp1-cuda-build` again.",
            worker.display(),
            version.trim(),
            CUDA_WORKER_VERSION
        ));
    }
    Ok(())
}

#[cfg(unix)]
struct CudaWorkerProcess {
    child: Child,
    stream: UnixStream,
    _session: PrivateRequestDir,
}

#[cfg(not(unix))]
struct CudaWorkerProcess;

#[cfg(unix)]
impl Drop for CudaWorkerProcess {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(unix)]
fn connect_cuda_socket(socket_path: &Path, child: &mut Child) -> Result<UnixStream, String> {
    let started = Instant::now();
    loop {
        match UnixStream::connect(socket_path) {
            Ok(stream) => return Ok(stream),
            Err(connect_err) => {
                if let Some(status) = child
                    .try_wait()
                    .map_err(|err| format!("poll SP1 CUDA worker: {err}"))?
                {
                    return Err(format!(
                        "SP1 CUDA worker exited with {status} before opening its control socket"
                    ));
                }
                if started.elapsed() >= Duration::from_secs(30) {
                    return Err(format!(
                        "timed out connecting to SP1 CUDA worker socket {}: {connect_err}",
                        socket_path.display()
                    ));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
}

fn read_cuda_response(
    reader: &mut impl Read,
    guest: &str,
    operation: &str,
) -> Result<Vec<u8>, String> {
    let mut magic = [0u8; 8];
    reader
        .read_exact(&mut magic)
        .map_err(|err| format!("read SP1 CUDA {operation} response header: {err}"))?;
    if &magic != CUDA_RESPONSE_MAGIC {
        return Err(format!("invalid SP1 CUDA {operation} response header"));
    }
    let mut status = [0u8; 1];
    reader
        .read_exact(&mut status)
        .map_err(|err| format!("read SP1 CUDA {operation} response status: {err}"))?;
    let payload = read_len_prefixed(reader, 1usize << 34)?;
    if status[0] != 0 {
        return Err(format!(
            "SP1 {guest} CUDA {operation} failed: {}",
            String::from_utf8_lossy(&payload)
        ));
    }
    Ok(payload)
}

fn proof_mode_byte(mode: ConfiguredProofMode) -> u8 {
    match mode {
        ConfiguredProofMode::Compressed => 0,
        ConfiguredProofMode::Groth16 => 1,
        ConfiguredProofMode::Plonk => 2,
    }
}

fn run_external_worker(
    worker: &Path,
    backend: &str,
    pk: &SP1ProvingKey,
    stdin: SP1Stdin,
    mode: ConfiguredProofMode,
    guest: &str,
) -> Result<SP1ProofWithPublicValues, String> {
    let temp = PrivateRequestDir::new(&backend.to_ascii_lowercase())?;
    let request_path = temp.path.join("request.bin");
    let response_path = temp.path.join("response.bin");
    write_request(&request_path, pk.elf(), &stdin, mode, guest)?;

    let status = Command::new(worker)
        .arg("prove")
        .arg(&request_path)
        .arg(&response_path)
        .status()
        .map_err(|err| format!("start SP1 {backend} worker {}: {err}", worker.display()))?;
    if !status.success() && !response_path.is_file() {
        return Err(format!("SP1 {backend} worker exited with {status}"));
    }
    read_response(&response_path, backend, guest)
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
        bincode::serialize(stdin).map_err(|err| format!("serialize SP1 worker stdin: {err}"))?;
    let mode = proof_mode_byte(mode);

    let mut file = create_private_file(path)?;
    file.write_all(REQUEST_MAGIC)
        .and_then(|_| file.write_all(&[mode]))
        .and_then(|_| write_len_prefixed(&mut file, guest.as_bytes()))
        .and_then(|_| write_len_prefixed(&mut file, elf_bytes))
        .and_then(|_| write_len_prefixed(&mut file, &stdin_bytes))
        .and_then(|_| file.flush())
        .map_err(|err| format!("write SP1 worker request {}: {err}", path.display()))
}

fn read_response(
    path: &Path,
    backend: &str,
    guest: &str,
) -> Result<SP1ProofWithPublicValues, String> {
    let mut file = fs::File::open(path)
        .map_err(|err| format!("open SP1 {backend} response {}: {err}", path.display()))?;
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic)
        .map_err(|err| format!("read SP1 {backend} response header: {err}"))?;
    if &magic != RESPONSE_MAGIC {
        return Err(format!("invalid SP1 {backend} worker response header"));
    }
    let mut status = [0u8; 1];
    file.read_exact(&mut status)
        .map_err(|err| format!("read SP1 {backend} response status: {err}"))?;
    let payload = read_len_prefixed(&mut file, 1usize << 34)?;
    if status[0] != 0 {
        return Err(format!(
            "SP1 {guest} {backend} prove failed: {}",
            String::from_utf8_lossy(&payload)
        ));
    }
    bincode::deserialize(&payload)
        .map_err(|err| format!("deserialize SP1 {guest} {backend} proof: {err}"))
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
    fn new(backend: &str) -> Result<Self, String> {
        let id = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| format!("read system time for SP1 worker request: {err}"))?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "poa-sp1-{backend}-{}-{timestamp}-{id}",
            std::process::id(),
        ));
        fs::create_dir(&path)
            .map_err(|err| format!("create private SP1 worker request dir: {err}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .map_err(|err| format!("secure SP1 worker request dir: {err}"))?;
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
