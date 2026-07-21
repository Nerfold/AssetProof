use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
use sp1_sdk::{Elf, SP1ProofWithPublicValues, SP1Stdin};

const REQUEST_MAGIC: &[u8; 8] = b"POANET01";
const RESPONSE_MAGIC: &[u8; 8] = b"POARES01";

struct Request {
    mode: u8,
    guest: String,
    elf: Vec<u8>,
    stdin: SP1Stdin,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("sp1-network-worker: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 4 || args[1] != "prove" {
        return Err("usage: sp1-network-worker prove <request.bin> <response.bin>".to_string());
    }
    let response_path = Path::new(&args[3]);
    let result = read_request(Path::new(&args[2])).and_then(prove);
    write_response(response_path, result)
}

fn read_request(path: &Path) -> Result<Request, String> {
    let mut file =
        fs::File::open(path).map_err(|err| format!("open request {}: {err}", path.display()))?;
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic)
        .map_err(|err| format!("read request header: {err}"))?;
    if &magic != REQUEST_MAGIC {
        return Err("invalid request header".to_string());
    }
    let mut mode = [0u8; 1];
    file.read_exact(&mut mode)
        .map_err(|err| format!("read proof mode: {err}"))?;
    let guest = String::from_utf8(read_len_prefixed(&mut file, 1024)?)
        .map_err(|err| format!("invalid guest name: {err}"))?;
    let elf = read_len_prefixed(&mut file, 1usize << 31)?;
    let stdin_bytes = read_len_prefixed(&mut file, 1usize << 34)?;
    let stdin = bincode::deserialize(&stdin_bytes)
        .map_err(|err| format!("deserialize SP1 stdin: {err}"))?;
    Ok(Request {
        mode: mode[0],
        guest,
        elf,
        stdin,
    })
}

fn prove(request: Request) -> Result<SP1ProofWithPublicValues, String> {
    if std::env::var_os("NETWORK_PRIVATE_KEY").is_none() {
        return Err("NETWORK_PRIVATE_KEY is not set".to_string());
    }
    eprintln!("submitting private SP1 Network proof for {}", request.guest);
    let client = ProverClient::builder().network().build();
    let pk = client
        .setup(Elf::from(request.elf))
        .map_err(|err| format!("network setup: {err}"))?;
    let skip_simulation = std::env::var("POA_SP1_NETWORK_SKIP_SIMULATION")
        .map(|value| !matches!(value.to_ascii_lowercase().as_str(), "0" | "false" | "no"))
        .unwrap_or(true);
    let proof = client
        .prove(&pk, request.stdin)
        .private_stdin(true)
        .skip_simulation(skip_simulation);
    match request.mode {
        0 => proof.compressed().run(),
        1 => proof.groth16().run(),
        2 => proof.plonk().run(),
        value => return Err(format!("unsupported proof mode byte {value}")),
    }
    .map_err(|err| format!("network prove: {err}"))
}

fn write_response(
    path: &Path,
    result: Result<SP1ProofWithPublicValues, String>,
) -> Result<(), String> {
    let (status, payload) = match result {
        Ok(proof) => (
            0u8,
            bincode::serialize(&proof).map_err(|err| format!("serialize proof: {err}"))?,
        ),
        Err(err) => (1u8, err.into_bytes()),
    };
    let mut file = create_private_file(path)?;
    file.write_all(RESPONSE_MAGIC)
        .and_then(|_| file.write_all(&[status]))
        .and_then(|_| write_len_prefixed(&mut file, &payload))
        .and_then(|_| file.flush())
        .map_err(|err| format!("write response {}: {err}", path.display()))
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

#[cfg(unix)]
fn create_private_file(path: &Path) -> Result<fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| format!("create response {}: {err}", path.display()))
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> Result<fs::File, String> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|err| format!("create response {}: {err}", path.display()))
}
