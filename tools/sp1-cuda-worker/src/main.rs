use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::time::{Duration, Instant};

use sp1_core_machine::riscv::RiscvAir;
use sp1_cuda::CudaProvingKey;
use sp1_prover_types::network_base_types::ProofMode;
use sp1_sdk::{Elf, SP1Context, SP1ProofWithPublicValues, SP1Stdin};

// Private control protocol shared with crates/sp1-host. It is deliberately
// separate from the file protocol used by the Network worker.
const REQUEST_MAGIC: &[u8; 8] = b"POACUD02";
const RESPONSE_MAGIC: &[u8; 8] = b"POACUR02";
const PREPARE: u8 = 0;
const PROVE: u8 = 1;

fn main() {
    if let Err(err) = run() {
        eprintln!("sp1-cuda-worker: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 3 || args[1] != "serve" {
        return Err("usage: sp1-cuda-worker serve <control.sock>".to_string());
    }
    serve(Path::new(&args[2]))
}

fn serve(socket_path: &Path) -> Result<(), String> {
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    return Err("SP1 CUDA proving requires Linux x86_64".to_string());

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let listener = UnixListener::bind(socket_path)
            .map_err(|err| format!("bind control socket {}: {err}", socket_path.display()))?;
        let (mut stream, _) = listener
            .accept()
            .map_err(|err| format!("accept control connection: {err}"))?;

        let device = match std::env::var("POA_SP1_CUDA_DEVICE") {
            Ok(value) => value
                .parse::<u32>()
                .map_err(|err| format!("invalid POA_SP1_CUDA_DEVICE {value}: {err}"))?,
            Err(std::env::VarError::NotPresent) => 0,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err("POA_SP1_CUDA_DEVICE is not valid UTF-8".to_string())
            }
        };
        eprintln!("initializing persistent SP1 CUDA server client on device {device}");
        let gpu_server_path = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .map(|home| home.join(".sp1/bin/sp1-gpu-server"));
        match gpu_server_path {
            Some(path) if path.is_file() => {
                eprintln!("using SP1 GPU server binary {}", path.display())
            }
            Some(path) => eprintln!(
                "SP1 GPU server binary is missing at {}; SP1 will download it before connecting",
                path.display()
            ),
            None => eprintln!("HOME is unset; SP1 GPU server initialization will fail"),
        }
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|err| format!("create CUDA worker runtime: {err}"))?;
        let connect_started = Instant::now();
        let client = runtime
            .block_on(async {
                tokio::time::timeout(
                    Duration::from_secs(600),
                    sp1_cuda::CudaProver::new_with_id(device),
                )
                .await
            })
            .map_err(|_| {
                "timed out after 600s downloading, starting, or connecting to sp1-gpu-server"
                    .to_string()
            })?
            .map_err(|err| format!("initialize CUDA server client: {err}"))?;
        eprintln!(
            "persistent SP1 CUDA server client ready in {:.3}s",
            connect_started.elapsed().as_secs_f64()
        );
        let mut keys = BTreeMap::<String, CudaProvingKey>::new();

        let result = (|| {
            loop {
                let command = match read_command(&mut stream)? {
                    Some(command) => command,
                    None => return Ok(()),
                };
                let result = match command {
                    PREPARE => handle_prepare(&mut stream, &runtime, &client, &mut keys),
                    PROVE => handle_prove(&mut stream, &runtime, &client, &keys),
                    value => Err(format!("unsupported CUDA worker command {value}")),
                };
                write_response(&mut stream, result)?;
            }
        })();

        // CudaProvingKey and CudaClient use tokio tasks in Drop. Entering the
        // runtime here keeps graceful worker shutdown well-defined.
        let runtime_guard = runtime.enter();
        drop(keys);
        drop(client);
        drop(runtime_guard);
        result
    }
}

fn read_command(reader: &mut impl Read) -> Result<Option<u8>, String> {
    let mut magic = [0u8; 8];
    match reader.read_exact(&mut magic) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(format!("read request header: {err}")),
    }
    if &magic != REQUEST_MAGIC {
        return Err("invalid request header".to_string());
    }
    let mut command = [0u8; 1];
    reader
        .read_exact(&mut command)
        .map_err(|err| format!("read request command: {err}"))?;
    Ok(Some(command[0]))
}

fn handle_prepare(
    reader: &mut impl Read,
    runtime: &tokio::runtime::Runtime,
    client: &sp1_cuda::CudaProver,
    keys: &mut BTreeMap<String, CudaProvingKey>,
) -> Result<Vec<u8>, String> {
    let guest = read_guest(reader)?;
    let elf = read_len_prefixed(reader, 1usize << 31)?;
    if keys.contains_key(&guest) {
        return Ok(Vec::new());
    }

    eprintln!("setting up SP1 CUDA guest {guest}");
    let started = Instant::now();
    let pk = runtime
        .block_on(client.setup_with_machine(Elf::from(elf), RiscvAir::machine()))
        .map_err(|err| format!("CUDA setup for {guest}: {err}"))?;
    keys.insert(guest.clone(), pk);
    eprintln!(
        "SP1 CUDA guest {guest} setup complete in {:.3}s",
        started.elapsed().as_secs_f64()
    );
    Ok(Vec::new())
}

fn handle_prove(
    reader: &mut impl Read,
    runtime: &tokio::runtime::Runtime,
    client: &sp1_cuda::CudaProver,
    keys: &BTreeMap<String, CudaProvingKey>,
) -> Result<Vec<u8>, String> {
    let mut mode = [0u8; 1];
    reader
        .read_exact(&mut mode)
        .map_err(|err| format!("read proof mode: {err}"))?;
    let guest = read_guest(reader)?;
    let stdin_bytes = read_len_prefixed(reader, 1usize << 34)?;
    let stdin: SP1Stdin = bincode::deserialize(&stdin_bytes)
        .map_err(|err| format!("deserialize SP1 stdin: {err}"))?;
    let pk = keys
        .get(&guest)
        .ok_or_else(|| format!("CUDA guest {guest} has not been prepared"))?;

    eprintln!("generating SP1 CUDA proof for {guest}");
    let started = Instant::now();
    let proof_mode = match mode[0] {
        0 => ProofMode::Compressed,
        1 => ProofMode::Groth16,
        2 => ProofMode::Plonk,
        value => return Err(format!("unsupported proof mode byte {value}")),
    };
    let proof: SP1ProofWithPublicValues = runtime
        .block_on(client.prove_with_mode(pk, stdin, SP1Context::default(), proof_mode))
        .map_err(|err| format!("CUDA prove for {guest}: {err}"))?
        .into();
    eprintln!(
        "SP1 CUDA proof for {guest} complete in {:.3}s",
        started.elapsed().as_secs_f64()
    );
    bincode::serialize(&proof).map_err(|err| format!("serialize proof: {err}"))
}

fn read_guest(reader: &mut impl Read) -> Result<String, String> {
    String::from_utf8(read_len_prefixed(reader, 1024)?)
        .map_err(|err| format!("invalid guest name: {err}"))
}

fn write_response(
    writer: &mut impl Write,
    result: Result<Vec<u8>, String>,
) -> Result<(), String> {
    let (status, payload) = match result {
        Ok(payload) => (0u8, payload),
        Err(err) => (1u8, err.into_bytes()),
    };
    writer
        .write_all(RESPONSE_MAGIC)
        .and_then(|_| writer.write_all(&[status]))
        .and_then(|_| write_len_prefixed(writer, &payload))
        .and_then(|_| writer.flush())
        .map_err(|err| format!("write CUDA worker response: {err}"))
}

fn write_len_prefixed(writer: &mut impl Write, bytes: &[u8]) -> std::io::Result<()> {
    writer.write_all(&(bytes.len() as u64).to_le_bytes())?;
    writer.write_all(bytes)
}

fn read_len_prefixed(reader: &mut impl Read, max: usize) -> Result<Vec<u8>, String> {
    let mut len = [0u8; 8];
    reader
        .read_exact(&mut len)
        .map_err(|err| format!("read payload length: {err}"))?;
    let len = usize::try_from(u64::from_le_bytes(len))
        .map_err(|_| "payload length does not fit this platform".to_string())?;
    if len > max {
        return Err(format!("payload exceeds {max} bytes"));
    }
    let mut bytes = vec![0u8; len];
    reader
        .read_exact(&mut bytes)
        .map_err(|err| format!("read payload: {err}"))?;
    Ok(bytes)
}
