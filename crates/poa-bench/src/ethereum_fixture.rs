use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::crypto::hex_encode;
use common::types::{
    ChainBalanceProofInput, Delta, EthereumVerkleBatchProofInput, InitReserveWitness,
    OwnershipWitnessInput,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use sha3::{Digest, Keccak256};
use verkle_spec::Hasher as VerkleKeyHasher;
use verkle_trie::database::memory_db::MemoryDb;
use verkle_trie::{proof::VerkleProof, DefaultConfig, Element, Trie, TrieTrait};

pub const CHAIN_ID: &str = "benchmark-ethereum-eip6800-verkle-v3-master";

const ACCOUNT_MAGIC: &[u8; 8] = b"DPOAVKMA";
const PROOF_MAGIC: &[u8; 8] = b"DPOAVKMP";
const VERSION: u32 = 3;
const PUBLIC_KEY_BYTES: usize = 65;
const ACCOUNT_RECORD_BYTES: u64 = (32 + PUBLIC_KEY_BYTES + 20 + 16 + 32 + 32) as u64;
const ACCOUNT_HEADER_BYTES: u64 = 8 + 4 + 8 + 32;

pub struct EthereumInitFixture {
    pub state_root: String,
    pub witnesses: Vec<InitReserveWitness>,
    pub verkle_proof: EthereumVerkleBatchProofInput,
    pub insert: EthereumInsertFixture,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureValidation {
    None,
    Proofs,
    Full,
}

#[derive(Clone)]
pub struct EthereumInsertFixture {
    pub address: String,
    pub balance: i128,
    pub private_key: [u8; 32],
    pub tree_key: [u8; 32],
    pub basic_data: [u8; 32],
    pub proof: Vec<u8>,
}

#[derive(Clone)]
struct AccountRecord {
    private_key: [u8; 32],
    public_key: [u8; PUBLIC_KEY_BYTES],
    address: [u8; 20],
    balance: i128,
    tree_key: [u8; 32],
    basic_data: [u8; 32],
}

struct Eip6800PedersenHasher;

impl VerkleKeyHasher for Eip6800PedersenHasher {}

pub fn ensure_master_fixture(
    dir: &Path,
    max_n: usize,
    n_sizes: &[usize],
    m_sizes: &[usize],
) -> Result<(Duration, bool), String> {
    validate_requested_sizes(max_n, n_sizes, m_sizes)?;
    fs::create_dir_all(dir).map_err(|err| format!("create {}: {err}", dir.display()))?;
    if master_artifacts_exist(dir, n_sizes, m_sizes) {
        return Ok((Duration::ZERO, true));
    }
    let manifest_path = master_manifest_path(dir);
    if manifest_path.exists() {
        fs::remove_file(&manifest_path)
            .map_err(|err| format!("invalidate {}: {err}", manifest_path.display()))?;
    }

    let generation_start = Instant::now();
    let seed = fixture_seed(max_n);
    // One extra chain account is present in the state tree but excluded from
    // every reserve prefix. All benchmark sizes share this same insertion item.
    let mut accounts = (0..=max_n)
        .map(|index| derive_account(&seed, index))
        .collect::<Result<Vec<_>, _>>()?;
    accounts.sort_unstable_by(|left, right| left.address.cmp(&right.address));

    let mut trie = build_verkle_trie(
        accounts
            .iter()
            .map(|account| (account.tree_key, account.basic_data)),
    )?;
    let root_commitment = trie.root_commitment().to_bytes();
    write_master_accounts(dir, max_n, &root_commitment, &accounts)?;

    for &n in &canonical_sizes(n_sizes) {
        let proof = trie
            .create_verkle_proof(accounts[..n].iter().map(|account| account.tree_key))
            .map_err(|err| format!("create initialization Verkle multiproof for n={n}: {err}"))?;
        let mut proof_bytes = Vec::new();
        proof.write(&mut proof_bytes).map_err(|err| {
            format!("serialize initialization Verkle multiproof for n={n}: {err}")
        })?;
        write_proof_artifact(
            &init_proof_path(dir, n),
            max_n,
            n,
            &root_commitment,
            &proof_bytes,
        )?;
    }

    let insert_proof = trie
        .create_verkle_proof(std::iter::once(accounts[max_n].tree_key))
        .map_err(|err| format!("create insertion Verkle proof: {err}"))?;
    let mut insert_proof_bytes = Vec::new();
    insert_proof
        .write(&mut insert_proof_bytes)
        .map_err(|err| format!("serialize insertion Verkle proof: {err}"))?;
    write_proof_artifact(
        &insert_proof_path(dir),
        max_n,
        max_n,
        &root_commitment,
        &insert_proof_bytes,
    )?;

    for &n in &canonical_sizes(n_sizes) {
        generate_delta_artifacts(
            dir,
            max_n,
            n,
            m_sizes,
            &root_commitment,
            &accounts,
            &mut trie,
        )?;
    }
    drop(trie);
    write_master_manifest(dir, max_n, n_sizes, m_sizes, &root_commitment)?;
    let generation = generation_start.elapsed();

    Ok((generation, false))
}

pub fn load_init_fixture(
    dir: &Path,
    max_n: usize,
    n: usize,
    validation: FixtureValidation,
) -> Result<EthereumInitFixture, String> {
    if n == 0 || n > max_n {
        return Err(format!(
            "reserve prefix n={n} is outside master size {max_n}"
        ));
    }
    let (root_commitment, witnesses, candidate) =
        read_master_account_prefix(dir, max_n, n, validation == FixtureValidation::Full)?;
    let init_proof = read_proof_artifact(&init_proof_path(dir, n), max_n, n, &root_commitment)?;
    let insert_proof =
        read_proof_artifact(&insert_proof_path(dir), max_n, max_n, &root_commitment)?;
    let fixture = EthereumInitFixture {
        state_root: hex_encode(&root_commitment),
        witnesses,
        verkle_proof: EthereumVerkleBatchProofInput {
            root_commitment,
            proof: init_proof,
        },
        insert: EthereumInsertFixture {
            address: format!("0x{}", hex_encode(&candidate.address)),
            balance: candidate.balance,
            private_key: candidate.private_key,
            tree_key: candidate.tree_key,
            basic_data: candidate.basic_data,
            proof: insert_proof,
        },
    };
    if validation != FixtureValidation::None {
        verify_fixture_proofs(&fixture)?;
    }
    Ok(fixture)
}

pub fn ensure_delta_fixture(
    path: &Path,
    fixture: &EthereumInitFixture,
    m: usize,
) -> Result<(Vec<Delta>, String, Duration, Duration, bool), String> {
    if m > fixture.witnesses.len() {
        return Err(format!(
            "m={m} exceeds reserve count {}",
            fixture.witnesses.len()
        ));
    }
    if !path.exists() {
        return Err(format!(
            "missing persisted master-tree delta fixture {}; rerun benchmark data initialization",
            path.display()
        ));
    }
    let load_start = Instant::now();
    let (loaded_deltas, loaded_old_root, loaded_root) = read_delta_fixture(path)?;
    validate_delta_fixture(fixture, m, &loaded_deltas, &loaded_old_root, &loaded_root)?;
    Ok((
        loaded_deltas,
        loaded_root,
        Duration::ZERO,
        load_start.elapsed(),
        true,
    ))
}

fn build_verkle_trie(
    items: impl Iterator<Item = ([u8; 32], [u8; 32])>,
) -> Result<impl TrieTrait, String> {
    let db = MemoryDb::new();
    let mut trie = Trie::new(DefaultConfig::new(db));
    trie.insert(items);
    Ok(trie)
}

fn validate_requested_sizes(
    max_n: usize,
    n_sizes: &[usize],
    m_sizes: &[usize],
) -> Result<(), String> {
    if max_n == 0 || n_sizes.is_empty() {
        return Err("Verkle benchmark requires at least one reserve size".to_string());
    }
    for &n in n_sizes {
        if n == 0 || n > max_n {
            return Err(format!("reserve size n={n} is outside master size {max_n}"));
        }
        for &m in m_sizes {
            if m == 0 {
                return Err("update fixture size m must be greater than zero".to_string());
            }
            if m > n {
                return Err(format!("update size m={m} exceeds reserve prefix n={n}"));
            }
        }
    }
    Ok(())
}

fn canonical_sizes(values: &[usize]) -> Vec<usize> {
    values
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn master_artifacts_exist(dir: &Path, n_sizes: &[usize], m_sizes: &[usize]) -> bool {
    master_accounts_path(dir).is_file()
        && insert_proof_path(dir).is_file()
        && master_manifest_path(dir).is_file()
        && n_sizes.iter().all(|&n| init_proof_path(dir, n).is_file())
        && n_sizes.iter().all(|&n| {
            m_sizes
                .iter()
                .all(|&m| delta_fixture_path(dir, n, m).is_file())
        })
}

fn generate_delta_artifacts(
    dir: &Path,
    max_n: usize,
    n: usize,
    m_sizes: &[usize],
    base_root: &[u8; 32],
    accounts: &[AccountRecord],
    trie: &mut impl TrieTrait,
) -> Result<(), String> {
    let targets = canonical_sizes(m_sizes);
    let Some(&max_m) = targets.last() else {
        return Ok(());
    };
    if max_m > n {
        return Err(format!(
            "update size m={max_m} exceeds reserve prefix n={n}"
        ));
    }
    let (offset, step) = permutation_parameters(n);
    let mut balances = accounts[..n]
        .iter()
        .map(|account| account.balance)
        .collect::<Vec<_>>();
    let mut changed_indices = Vec::with_capacity(max_m);
    let mut deltas = Vec::with_capacity(max_m);
    let target_set = targets.iter().copied().collect::<BTreeSet<_>>();
    for ordinal in 0..max_m {
        let index = (offset + ordinal * step) % n;
        let old_balance = balances[index];
        let delta = deterministic_delta(n, ordinal, old_balance);
        let new_balance = old_balance
            .checked_add(delta)
            .ok_or_else(|| "benchmark delta overflowed balance".to_string())?;
        if new_balance < 0 {
            return Err("benchmark delta made a balance negative".to_string());
        }
        balances[index] = new_balance;
        changed_indices.push(index);
        deltas.push(Delta {
            address: format!("0x{}", hex_encode(&accounts[index].address)),
            delta,
        });
        trie.insert(std::iter::once((
            accounts[index].tree_key,
            eip6800_basic_data(new_balance),
        )));
        let m = ordinal + 1;
        if target_set.contains(&m) {
            let new_root = trie.root_commitment().to_bytes();
            let mut canonical_deltas = deltas.clone();
            canonical_deltas.sort_unstable_by(|left, right| left.address.cmp(&right.address));
            write_delta_artifact(
                &delta_fixture_path(dir, n, m),
                max_n,
                n,
                m,
                base_root,
                &new_root,
                &canonical_deltas,
            )?;
        }
    }
    for index in changed_indices {
        trie.insert(std::iter::once((
            accounts[index].tree_key,
            accounts[index].basic_data,
        )));
    }
    if trie.root_commitment().to_bytes() != *base_root {
        return Err(format!(
            "restoring delta scenario n={n} did not recover master Verkle root"
        ));
    }
    Ok(())
}

fn write_delta_artifact(
    path: &Path,
    max_n: usize,
    n: usize,
    m: usize,
    old_root: &[u8; 32],
    new_root: &[u8; 32],
    deltas: &[Delta],
) -> Result<(), String> {
    let file = File::create(path).map_err(|err| format!("create {}: {err}", path.display()))?;
    let mut writer = BufWriter::new(file);
    writeln!(writer, "# version=ethereum-eip6800-verkle-v3-master")
        .map_err(|err| format!("write {}: {err}", path.display()))?;
    writeln!(writer, "# master_n={max_n}")
        .map_err(|err| format!("write {}: {err}", path.display()))?;
    writeln!(writer, "# n={n}").map_err(|err| format!("write {}: {err}", path.display()))?;
    writeln!(writer, "# m={m}").map_err(|err| format!("write {}: {err}", path.display()))?;
    writeln!(writer, "# old_state_root={}", hex_encode(old_root))
        .map_err(|err| format!("write {}: {err}", path.display()))?;
    writeln!(writer, "# new_state_root={}", hex_encode(new_root))
        .map_err(|err| format!("write {}: {err}", path.display()))?;
    for delta in deltas {
        writeln!(writer, "{},{}", delta.address, delta.delta)
            .map_err(|err| format!("write {}: {err}", path.display()))?;
    }
    writer
        .flush()
        .map_err(|err| format!("flush {}: {err}", path.display()))
}

fn write_master_manifest(
    dir: &Path,
    max_n: usize,
    n_sizes: &[usize],
    m_sizes: &[usize],
    root: &[u8; 32],
) -> Result<(), String> {
    let path = master_manifest_path(dir);
    let body = format!(
        "version=ethereum-eip6800-verkle-v3-master\nmax_n={max_n}\nn_sizes={:?}\nm_sizes={:?}\nstate_root={}\naccounts_path={}\nstatus=complete\n",
        canonical_sizes(n_sizes),
        canonical_sizes(m_sizes),
        hex_encode(root),
        master_accounts_path(dir).display(),
    );
    fs::write(&path, body).map_err(|err| format!("write {}: {err}", path.display()))
}

fn file_len(path: &Path) -> Result<u64, String> {
    fs::metadata(path)
        .map(|metadata| metadata.len())
        .map_err(|err| format!("stat {}: {err}", path.display()))
}

fn verify_fixture_proofs(fixture: &EthereumInitFixture) -> Result<(), String> {
    let canonical_root = hex_encode(&fixture.verkle_proof.root_commitment);
    if fixture
        .state_root
        .strip_prefix("0x")
        .unwrap_or(&fixture.state_root)
        != canonical_root
    {
        return Err("fixture state root does not match its Banderwagon commitment".to_string());
    }
    let root = Element::from_bytes(&fixture.verkle_proof.root_commitment)
        .ok_or_else(|| "fixture contains an invalid Banderwagon root commitment".to_string())?;
    let mut keys = Vec::with_capacity(fixture.witnesses.len());
    let mut values = Vec::with_capacity(fixture.witnesses.len());
    for witness in &fixture.witnesses {
        let (tree_key, basic_data) = witness_verkle_opening(witness)?;
        if basic_data != eip6800_basic_data(witness.balance) {
            return Err(format!(
                "fixture basic-data balance mismatch for {}",
                witness.address
            ));
        }
        keys.push(tree_key);
        values.push(Some(basic_data));
    }
    let proof = VerkleProof::read(fixture.verkle_proof.proof.as_slice())
        .map_err(|err| format!("decode initialization Verkle multiproof: {err}"))?;
    let (valid, _) = proof.check(keys, values, root);
    if !valid {
        return Err("initialization Verkle multiproof does not match fixture root".to_string());
    }

    let insert_root = Element::from_bytes(&fixture.verkle_proof.root_commitment)
        .ok_or_else(|| "fixture contains an invalid Banderwagon root commitment".to_string())?;
    let insert_proof = VerkleProof::read(fixture.insert.proof.as_slice())
        .map_err(|err| format!("decode insertion Verkle proof: {err}"))?;
    let (valid, _) = insert_proof.check(
        vec![fixture.insert.tree_key],
        vec![Some(fixture.insert.basic_data)],
        insert_root,
    );
    if !valid {
        return Err("insertion Verkle proof does not match fixture root".to_string());
    }
    if fixture
        .witnesses
        .iter()
        .any(|witness| witness.address == fixture.insert.address)
    {
        return Err("insertion account is already in the reserve set".to_string());
    }
    Ok(())
}

fn witness_verkle_opening(witness: &InitReserveWitness) -> Result<([u8; 32], [u8; 32]), String> {
    match &witness.chain_balance_proof {
        ChainBalanceProofInput::EthereumVerkleBatchMember {
            chain_id,
            tree_key,
            basic_data,
        } if chain_id == CHAIN_ID => Ok((*tree_key, *basic_data)),
        _ => Err(format!(
            "{} is not an Ethereum Verkle batch member",
            witness.address
        )),
    }
}

fn validate_delta_fixture(
    fixture: &EthereumInitFixture,
    m: usize,
    deltas: &[Delta],
    old_root: &str,
    new_root: &str,
) -> Result<(), String> {
    if old_root.strip_prefix("0x").unwrap_or(old_root)
        != fixture
            .state_root
            .strip_prefix("0x")
            .unwrap_or(&fixture.state_root)
    {
        return Err("delta fixture old root does not match initialization fixture".to_string());
    }
    if deltas.len() != m {
        return Err(format!(
            "delta fixture contains {} entries, expected {m}",
            deltas.len()
        ));
    }
    if deltas
        .windows(2)
        .any(|pair| pair[0].address >= pair[1].address)
    {
        return Err("delta fixture is not canonical and duplicate-free".to_string());
    }
    let raw_root = new_root.strip_prefix("0x").unwrap_or(new_root);
    if raw_root.len() != 64 || !raw_root.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("delta fixture contains an invalid persisted Verkle root".to_string());
    }
    Ok(())
}

pub fn master_accounts_path(dir: &Path) -> PathBuf {
    dir.join("accounts.bin")
}

pub fn init_proof_path(dir: &Path, n: usize) -> PathBuf {
    dir.join(format!("init-multiproof-n-{n}.bin"))
}

pub fn insert_proof_path(dir: &Path) -> PathBuf {
    dir.join("insert-proof.bin")
}

pub fn delta_fixture_path(dir: &Path, n: usize, m: usize) -> PathBuf {
    dir.join(format!("deltas-n-{n}-m-{m}.csv"))
}

pub fn master_manifest_path(dir: &Path) -> PathBuf {
    dir.join("master-manifest.txt")
}

pub fn fixture_persisted_bytes(dir: &Path, n: usize) -> Result<u64, String> {
    let account_prefix = ACCOUNT_HEADER_BYTES
        .checked_add(
            (n as u64)
                .checked_mul(ACCOUNT_RECORD_BYTES)
                .ok_or_else(|| "account prefix byte size overflow".to_string())?,
        )
        .and_then(|value| value.checked_add(ACCOUNT_RECORD_BYTES))
        .ok_or_else(|| "fixture byte size overflow".to_string())?;
    Ok(account_prefix + file_len(&init_proof_path(dir, n))? + file_len(&insert_proof_path(dir))?)
}

fn write_master_accounts(
    dir: &Path,
    max_n: usize,
    root_commitment: &[u8; 32],
    accounts: &[AccountRecord],
) -> Result<(), String> {
    if accounts.len() != max_n + 1 {
        return Err(
            "master fixture must contain max_n reserves plus one insertion account".to_string(),
        );
    }
    let path = master_accounts_path(dir);
    let file = File::create(&path).map_err(|err| format!("create {}: {err}", path.display()))?;
    let mut writer = BufWriter::new(file);
    writer
        .write_all(ACCOUNT_MAGIC)
        .map_err(io_error(&path, "write account magic"))?;
    writer
        .write_all(&VERSION.to_le_bytes())
        .map_err(io_error(&path, "write account version"))?;
    writer
        .write_all(&(max_n as u64).to_le_bytes())
        .map_err(io_error(&path, "write master reserve count"))?;
    writer
        .write_all(root_commitment)
        .map_err(io_error(&path, "write root commitment"))?;
    for account in accounts {
        write_account(&mut writer, &path, account)?;
    }
    writer.flush().map_err(io_error(&path, "flush accounts"))
}

fn write_account(
    writer: &mut impl Write,
    path: &Path,
    account: &AccountRecord,
) -> Result<(), String> {
    writer
        .write_all(&account.private_key)
        .map_err(io_error(path, "write private key"))?;
    writer
        .write_all(&account.public_key)
        .map_err(io_error(path, "write public key"))?;
    writer
        .write_all(&account.address)
        .map_err(io_error(path, "write address"))?;
    writer
        .write_all(&account.balance.to_le_bytes())
        .map_err(io_error(path, "write balance"))?;
    writer
        .write_all(&account.tree_key)
        .map_err(io_error(path, "write Verkle tree key"))?;
    writer
        .write_all(&account.basic_data)
        .map_err(io_error(path, "write EIP-6800 basic data"))
}

fn read_master_account_prefix(
    dir: &Path,
    expected_max_n: usize,
    n: usize,
    validate_cryptography: bool,
) -> Result<([u8; 32], Vec<InitReserveWitness>, AccountRecord), String> {
    let path = master_accounts_path(dir);
    let expected_bytes = ACCOUNT_HEADER_BYTES
        .checked_add(
            ((expected_max_n + 1) as u64)
                .checked_mul(ACCOUNT_RECORD_BYTES)
                .ok_or_else(|| "master account byte size overflow".to_string())?,
        )
        .ok_or_else(|| "master account file size overflow".to_string())?;
    if file_len(&path)? != expected_bytes {
        return Err(format!(
            "master account file {} has an unexpected size",
            path.display()
        ));
    }
    let file = File::open(&path).map_err(|err| format!("open {}: {err}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut magic = [0u8; 8];
    reader
        .read_exact(&mut magic)
        .map_err(io_error(&path, "read account magic"))?;
    if &magic != ACCOUNT_MAGIC {
        return Err(format!(
            "{} is not a master Verkle account store",
            path.display()
        ));
    }
    let version = read_u32(&mut reader, &path)?;
    if version != VERSION {
        return Err(format!(
            "unsupported master Verkle fixture version {version}"
        ));
    }
    let max_n = read_u64(&mut reader, &path)? as usize;
    if max_n != expected_max_n {
        return Err(format!(
            "master reserve count {max_n}, expected {expected_max_n}"
        ));
    }
    let mut root_commitment = [0u8; 32];
    reader
        .read_exact(&mut root_commitment)
        .map_err(io_error(&path, "read root commitment"))?;
    let mut witnesses = Vec::with_capacity(n);
    let mut previous_address = None;
    for index in 0..n {
        let account = read_account(&mut reader, &path)?;
        if validate_cryptography {
            validate_account(&account)
                .map_err(|err| format!("master account {index} is invalid: {err}"))?;
        }
        if previous_address.is_some_and(|previous| previous >= account.address) {
            return Err("master account prefix is not canonical and duplicate-free".to_string());
        }
        previous_address = Some(account.address);
        witnesses.push(init_witness(&account));
    }
    let candidate_offset = ACCOUNT_HEADER_BYTES
        .checked_add(
            (max_n as u64)
                .checked_mul(ACCOUNT_RECORD_BYTES)
                .ok_or_else(|| "insertion account offset overflow".to_string())?,
        )
        .ok_or_else(|| "insertion account offset overflow".to_string())?;
    reader
        .seek(SeekFrom::Start(candidate_offset))
        .map_err(io_error(&path, "seek insertion account"))?;
    let candidate = read_account(&mut reader, &path)?;
    if validate_cryptography {
        validate_account(&candidate)
            .map_err(|err| format!("insertion account is invalid: {err}"))?;
    }
    if previous_address.is_some_and(|address| address >= candidate.address) {
        return Err("insertion account is not outside the reserve prefix".to_string());
    }
    Ok((root_commitment, witnesses, candidate))
}

fn write_proof_artifact(
    path: &Path,
    max_n: usize,
    selected_n: usize,
    root_commitment: &[u8; 32],
    proof: &[u8],
) -> Result<(), String> {
    let file = File::create(path).map_err(|err| format!("create {}: {err}", path.display()))?;
    let mut writer = BufWriter::new(file);
    writer
        .write_all(PROOF_MAGIC)
        .map_err(io_error(path, "write proof magic"))?;
    writer
        .write_all(&VERSION.to_le_bytes())
        .map_err(io_error(path, "write proof version"))?;
    writer
        .write_all(&(max_n as u64).to_le_bytes())
        .map_err(io_error(path, "write proof max_n"))?;
    writer
        .write_all(&(selected_n as u64).to_le_bytes())
        .map_err(io_error(path, "write proof n"))?;
    writer
        .write_all(root_commitment)
        .map_err(io_error(path, "write proof root"))?;
    write_blob(&mut writer, proof, path, "Verkle proof")?;
    writer.flush().map_err(io_error(path, "flush Verkle proof"))
}

fn read_proof_artifact(
    path: &Path,
    expected_max_n: usize,
    expected_n: usize,
    expected_root: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|err| format!("open {}: {err}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut magic = [0u8; 8];
    reader
        .read_exact(&mut magic)
        .map_err(io_error(path, "read proof magic"))?;
    if &magic != PROOF_MAGIC {
        return Err(format!(
            "{} is not a master Verkle proof artifact",
            path.display()
        ));
    }
    if read_u32(&mut reader, path)? != VERSION
        || read_u64(&mut reader, path)? as usize != expected_max_n
        || read_u64(&mut reader, path)? as usize != expected_n
    {
        return Err(format!("{} Verkle proof metadata mismatch", path.display()));
    }
    let mut root = [0u8; 32];
    reader
        .read_exact(&mut root)
        .map_err(io_error(path, "read proof root"))?;
    if &root != expected_root {
        return Err(format!("{} Verkle proof root mismatch", path.display()));
    }
    read_blob(&mut reader, path, "Verkle proof")
}

fn read_account(reader: &mut impl Read, path: &Path) -> Result<AccountRecord, String> {
    let mut private_key = [0u8; 32];
    let mut public_key = [0u8; PUBLIC_KEY_BYTES];
    let mut address = [0u8; 20];
    let mut balance = [0u8; 16];
    let mut tree_key = [0u8; 32];
    let mut basic_data = [0u8; 32];
    reader
        .read_exact(&mut private_key)
        .map_err(io_error(path, "read private key"))?;
    reader
        .read_exact(&mut public_key)
        .map_err(io_error(path, "read public key"))?;
    reader
        .read_exact(&mut address)
        .map_err(io_error(path, "read address"))?;
    reader
        .read_exact(&mut balance)
        .map_err(io_error(path, "read balance"))?;
    reader
        .read_exact(&mut tree_key)
        .map_err(io_error(path, "read Verkle tree key"))?;
    reader
        .read_exact(&mut basic_data)
        .map_err(io_error(path, "read EIP-6800 basic data"))?;
    Ok(AccountRecord {
        private_key,
        public_key,
        address,
        balance: i128::from_le_bytes(balance),
        tree_key,
        basic_data,
    })
}

fn init_witness(account: &AccountRecord) -> InitReserveWitness {
    let address = format!("0x{}", hex_encode(&account.address));
    InitReserveWitness {
        address,
        balance: account.balance,
        ownership: OwnershipWitnessInput::EthereumEoaPrivateKeyHex {
            private_key_hex: hex_encode(&account.private_key),
        },
        chain_balance_proof: ChainBalanceProofInput::EthereumVerkleBatchMember {
            chain_id: CHAIN_ID.to_string(),
            tree_key: account.tree_key,
            basic_data: account.basic_data,
        },
    }
}

fn validate_account(account: &AccountRecord) -> Result<(), String> {
    let (public_key, address) = public_key_and_address(&account.private_key)?;
    if public_key != account.public_key || address != account.address {
        return Err("secp256k1 public key/address mismatch".to_string());
    }
    if account.balance < 0 {
        return Err("negative balance".to_string());
    }
    if account.tree_key != eip6800_basic_data_key(&account.address) {
        return Err("EIP-6800 tree key mismatch".to_string());
    }
    if account.basic_data != eip6800_basic_data(account.balance) {
        return Err("EIP-6800 basic-data value mismatch".to_string());
    }
    Ok(())
}

fn derive_account(seed: &[u8; 32], index: usize) -> Result<AccountRecord, String> {
    let mut counter = 0u64;
    let private_key = loop {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"dpoa-benchmark-ethereum-private-key-v2");
        hasher.update(seed);
        hasher.update(&(index as u64).to_le_bytes());
        hasher.update(&counter.to_le_bytes());
        let candidate = *hasher.finalize().as_bytes();
        if SecretKey::from_slice(&candidate).is_ok() {
            break candidate;
        }
        counter = counter
            .checked_add(1)
            .ok_or_else(|| "private-key derivation counter overflow".to_string())?;
    };
    let (public_key, address) = public_key_and_address(&private_key)?;
    let mut balance_hasher = blake3::Hasher::new();
    balance_hasher.update(b"dpoa-benchmark-ethereum-balance-v2");
    balance_hasher.update(seed);
    balance_hasher.update(&(index as u64).to_le_bytes());
    let digest = balance_hasher.finalize();
    let mut word = [0u8; 8];
    word.copy_from_slice(&digest.as_bytes()[..8]);
    let balance = 1_000_000i128 + (u64::from_le_bytes(word) % 1_000_000_000_000) as i128;
    Ok(AccountRecord {
        private_key,
        public_key,
        address,
        balance,
        tree_key: eip6800_basic_data_key(&address),
        basic_data: eip6800_basic_data(balance),
    })
}

fn public_key_and_address(
    private_key: &[u8; 32],
) -> Result<([u8; PUBLIC_KEY_BYTES], [u8; 20]), String> {
    let secret = SecretKey::from_slice(private_key)
        .map_err(|err| format!("invalid secp256k1 private key: {err}"))?;
    let encoded = secret.public_key().to_encoded_point(false);
    let public_key: [u8; PUBLIC_KEY_BYTES] = encoded
        .as_bytes()
        .try_into()
        .map_err(|_| "unexpected secp256k1 public-key length".to_string())?;
    let digest = Keccak256::digest(&public_key[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&digest[12..]);
    Ok((public_key, address))
}

fn eip6800_basic_data_key(address: &[u8; 20]) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[12..32].copy_from_slice(address);
    let hash = <Eip6800PedersenHasher as VerkleKeyHasher>::hash64(input);
    let mut key = *hash.as_fixed_bytes();
    key[31] = 0;
    key
}

fn eip6800_basic_data(balance: i128) -> [u8; 32] {
    let mut value = [0u8; 32];
    value[16..32].copy_from_slice(&(balance as u128).to_be_bytes());
    value
}

fn read_delta_fixture(path: &Path) -> Result<(Vec<Delta>, String, String), String> {
    let input =
        fs::read_to_string(path).map_err(|err| format!("read {}: {err}", path.display()))?;
    let mut new_root = None;
    let mut old_root = None;
    let mut deltas = Vec::new();
    for (line_no, raw) in input.lines().enumerate() {
        let line = raw.trim();
        if let Some(value) = line.strip_prefix("# new_state_root=") {
            new_root = Some(value.to_string());
            continue;
        }
        if let Some(value) = line.strip_prefix("# old_state_root=") {
            old_root = Some(value.to_string());
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (address, delta) = line
            .split_once(',')
            .ok_or_else(|| format!("invalid delta fixture line {}", line_no + 1))?;
        deltas.push(Delta {
            address: address.to_string(),
            delta: delta
                .parse::<i128>()
                .map_err(|err| format!("invalid delta line {}: {err}", line_no + 1))?,
        });
    }
    Ok((
        deltas,
        old_root.ok_or_else(|| format!("{} has no old state root", path.display()))?,
        new_root.ok_or_else(|| format!("{} has no new state root", path.display()))?,
    ))
}

fn fixture_seed(n: usize) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"dpoa-benchmark-ethereum-verkle-master-seed-v3");
    hasher.update(&(n as u64).to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn permutation_parameters(n: usize) -> (usize, usize) {
    let seed = fixture_seed(n ^ 0x4450_4f41usize);
    let offset = u64::from_le_bytes(seed[..8].try_into().expect("eight bytes")) as usize % n;
    let mut step =
        (u64::from_le_bytes(seed[8..16].try_into().expect("eight bytes")) as usize % n).max(1);
    while gcd(step, n) != 1 {
        step += 1;
        if step == n {
            step = 1;
        }
    }
    (offset, step)
}

fn deterministic_delta(n: usize, ordinal: usize, balance: i128) -> i128 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"dpoa-benchmark-ethereum-delta-v2");
    hasher.update(&(n as u64).to_le_bytes());
    hasher.update(&(ordinal as u64).to_le_bytes());
    let digest = hasher.finalize();
    let mut word = [0u8; 8];
    word.copy_from_slice(&digest.as_bytes()[..8]);
    let magnitude = 1 + (u64::from_le_bytes(word) % 100_000) as i128;
    if digest.as_bytes()[8] & 1 == 0 {
        magnitude
    } else {
        -magnitude.min(balance)
    }
}

fn gcd(mut left: usize, mut right: usize) -> usize {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

fn write_blob(
    writer: &mut impl Write,
    bytes: &[u8],
    path: &Path,
    label: &'static str,
) -> Result<(), String> {
    writer
        .write_all(&(bytes.len() as u64).to_le_bytes())
        .map_err(io_error(path, label))?;
    writer.write_all(bytes).map_err(io_error(path, label))
}

fn read_blob(reader: &mut impl Read, path: &Path, label: &'static str) -> Result<Vec<u8>, String> {
    let len = read_u64(reader, path)? as usize;
    let mut bytes = vec![0u8; len];
    reader
        .read_exact(&mut bytes)
        .map_err(io_error(path, label))?;
    Ok(bytes)
}

fn read_u32(reader: &mut impl Read, path: &Path) -> Result<u32, String> {
    let mut bytes = [0u8; 4];
    reader
        .read_exact(&mut bytes)
        .map_err(io_error(path, "read u32"))?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(reader: &mut impl Read, path: &Path) -> Result<u64, String> {
    let mut bytes = [0u8; 8];
    reader
        .read_exact(&mut bytes)
        .map_err(io_error(path, "read u64"))?;
    Ok(u64::from_le_bytes(bytes))
}

fn io_error<'a>(
    path: &'a Path,
    action: &'static str,
) -> impl FnOnce(std::io::Error) -> String + 'a {
    move |err| format!("{action} {}: {err}", path.display())
}
