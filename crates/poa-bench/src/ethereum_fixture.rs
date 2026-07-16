use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
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

pub const CHAIN_ID: &str = "benchmark-ethereum-eip6800-verkle-v2";

const MAGIC: &[u8; 8] = b"DPOAVKL1";
const VERSION: u32 = 2;
const PUBLIC_KEY_BYTES: usize = 65;

pub struct EthereumInitFixture {
    pub state_root: String,
    pub witnesses: Vec<InitReserveWitness>,
    pub verkle_proof: EthereumVerkleBatchProofInput,
    pub insert: EthereumInsertFixture,
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

pub fn ensure_init_fixture(
    path: &Path,
    n: usize,
) -> Result<(EthereumInitFixture, Duration, Duration, bool), String> {
    if path.exists() {
        let start = Instant::now();
        let fixture = read_init_fixture(path, n)?;
        return Ok((fixture, Duration::ZERO, start.elapsed(), true));
    }
    if n == 0 {
        return Err("Verkle benchmark requires at least one reserve".to_string());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("create {}: {err}", parent.display()))?;
    }

    let start = Instant::now();
    let seed = fixture_seed(n);
    // The extra account is present in the Ethereum state tree but absent from
    // the reserve set. It is used by the insertion benchmark.
    let mut accounts = (0..=n)
        .map(|index| derive_account(&seed, index))
        .collect::<Result<Vec<_>, _>>()?;
    accounts.sort_unstable_by(|left, right| left.address.cmp(&right.address));

    let trie = build_verkle_trie(
        accounts
            .iter()
            .map(|account| (account.tree_key, account.basic_data)),
    )?;
    let root_commitment = trie.root_commitment().to_bytes();
    let init_keys = accounts[..n]
        .iter()
        .map(|account| account.tree_key)
        .collect::<Vec<_>>();
    let init_proof = trie
        .create_verkle_proof(init_keys.iter().copied())
        .map_err(|err| format!("create initialization Verkle multiproof: {err}"))?;
    let mut init_proof_bytes = Vec::new();
    init_proof
        .write(&mut init_proof_bytes)
        .map_err(|err| format!("serialize initialization Verkle multiproof: {err}"))?;

    let insert_proof = trie
        .create_verkle_proof(std::iter::once(accounts[n].tree_key))
        .map_err(|err| format!("create insertion Verkle proof: {err}"))?;
    let mut insert_proof_bytes = Vec::new();
    insert_proof
        .write(&mut insert_proof_bytes)
        .map_err(|err| format!("serialize insertion Verkle proof: {err}"))?;
    // Make the peak-memory lifetime explicit before serializing the fixture.
    drop(trie);

    write_fixture(
        path,
        n,
        &root_commitment,
        &init_proof_bytes,
        &insert_proof_bytes,
        &accounts,
    )?;
    let generation = start.elapsed();
    let load_start = Instant::now();
    let fixture = read_init_fixture(path, n)?;
    Ok((fixture, generation, load_start.elapsed(), false))
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
    if path.exists() {
        let start = Instant::now();
        let (deltas, old_root, new_root) = read_delta_fixture(path)?;
        validate_delta_fixture(fixture, m, &deltas, &old_root, &new_root)?;
        return Ok((deltas, new_root, Duration::ZERO, start.elapsed(), true));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("create {}: {err}", parent.display()))?;
    }

    let start = Instant::now();
    let (updates, updated_balances) = deterministic_transition(fixture, m)?;
    let new_root = transition_root(fixture, &updated_balances)?;
    let file = File::create(path).map_err(|err| format!("create {}: {err}", path.display()))?;
    let mut writer = BufWriter::new(file);
    writeln!(writer, "# version=ethereum-eip6800-verkle-v2")
        .map_err(|err| format!("write {}: {err}", path.display()))?;
    writeln!(writer, "# n={}", fixture.witnesses.len())
        .map_err(|err| format!("write {}: {err}", path.display()))?;
    writeln!(writer, "# m={m}").map_err(|err| format!("write {}: {err}", path.display()))?;
    writeln!(writer, "# old_state_root={}", fixture.state_root)
        .map_err(|err| format!("write {}: {err}", path.display()))?;
    writeln!(writer, "# new_state_root={new_root}")
        .map_err(|err| format!("write {}: {err}", path.display()))?;
    for delta in &updates {
        writeln!(writer, "{},{}", delta.address, delta.delta)
            .map_err(|err| format!("write {}: {err}", path.display()))?;
    }
    writer
        .flush()
        .map_err(|err| format!("flush {}: {err}", path.display()))?;
    let generation = start.elapsed();
    let load_start = Instant::now();
    let (loaded_deltas, loaded_old_root, loaded_root) = read_delta_fixture(path)?;
    if loaded_deltas != updates || loaded_old_root != fixture.state_root || loaded_root != new_root
    {
        return Err("persisted delta fixture does not round-trip".to_string());
    }
    Ok((
        loaded_deltas,
        loaded_root,
        generation,
        load_start.elapsed(),
        false,
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

fn deterministic_transition(
    fixture: &EthereumInitFixture,
    m: usize,
) -> Result<(Vec<Delta>, Vec<i128>), String> {
    let n = fixture.witnesses.len();
    let (offset, step) = permutation_parameters(n);
    let mut updated_balances = fixture
        .witnesses
        .iter()
        .map(|witness| witness.balance)
        .collect::<Vec<_>>();
    let mut updates = Vec::with_capacity(m);
    for ordinal in 0..m {
        let index = (offset + ordinal * step) % n;
        let balance = updated_balances[index];
        let delta = deterministic_delta(n, ordinal, balance);
        updated_balances[index] = balance
            .checked_add(delta)
            .ok_or_else(|| "benchmark delta overflowed balance".to_string())?;
        if updated_balances[index] < 0 {
            return Err("benchmark delta made a balance negative".to_string());
        }
        updates.push(Delta {
            address: fixture.witnesses[index].address.clone(),
            delta,
        });
    }
    updates.sort_unstable_by(|left, right| left.address.cmp(&right.address));
    Ok((updates, updated_balances))
}

fn transition_root(
    fixture: &EthereumInitFixture,
    updated_balances: &[i128],
) -> Result<String, String> {
    if updated_balances.len() != fixture.witnesses.len() {
        return Err("transition balance vector length mismatch".to_string());
    }
    let items = fixture
        .witnesses
        .iter()
        .zip(updated_balances.iter())
        .map(|(witness, balance)| account_item(&witness.address, *balance))
        .chain(std::iter::once(Ok((
            fixture.insert.tree_key,
            fixture.insert.basic_data,
        ))))
        .collect::<Result<Vec<_>, String>>()?;
    let trie = build_verkle_trie(items.into_iter())?;
    Ok(hex_encode(&trie.root_commitment().to_bytes()))
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
    let (expected, updated_balances) = deterministic_transition(fixture, m)?;
    if deltas != expected {
        return Err("delta fixture does not match the deterministic transition".to_string());
    }
    let expected_root = transition_root(fixture, &updated_balances)?;
    if new_root.strip_prefix("0x").unwrap_or(new_root) != expected_root {
        return Err("delta fixture new root does not match the rebuilt Verkle tree".to_string());
    }
    Ok(())
}

fn write_fixture(
    path: &Path,
    reserve_count: usize,
    root_commitment: &[u8; 32],
    init_proof: &[u8],
    insert_proof: &[u8],
    accounts: &[AccountRecord],
) -> Result<(), String> {
    if accounts.len() != reserve_count + 1 {
        return Err("fixture must contain exactly one insertion account".to_string());
    }
    let file = File::create(path).map_err(|err| format!("create {}: {err}", path.display()))?;
    let mut writer = BufWriter::new(file);
    writer
        .write_all(MAGIC)
        .map_err(io_error(path, "write magic"))?;
    writer
        .write_all(&VERSION.to_le_bytes())
        .map_err(io_error(path, "write version"))?;
    writer
        .write_all(&(reserve_count as u64).to_le_bytes())
        .map_err(io_error(path, "write reserve count"))?;
    writer
        .write_all(root_commitment)
        .map_err(io_error(path, "write root commitment"))?;
    write_blob(&mut writer, init_proof, path, "initialization proof")?;
    write_blob(&mut writer, insert_proof, path, "insertion proof")?;
    for account in accounts {
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
            .map_err(io_error(path, "write EIP-6800 basic data"))?;
    }
    writer.flush().map_err(io_error(path, "flush fixture"))
}

fn read_init_fixture(path: &Path, expected_n: usize) -> Result<EthereumInitFixture, String> {
    let file = File::open(path).map_err(|err| format!("open {}: {err}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut magic = [0u8; 8];
    reader
        .read_exact(&mut magic)
        .map_err(io_error(path, "read magic"))?;
    if &magic != MAGIC {
        return Err(format!(
            "{} is not an EIP-6800 Verkle fixture",
            path.display()
        ));
    }
    let version = read_u32(&mut reader, path)?;
    if version != VERSION {
        return Err(format!("unsupported Verkle fixture version {version}"));
    }
    let n = read_u64(&mut reader, path)? as usize;
    if n != expected_n {
        return Err(format!("fixture reserve count {n}, expected {expected_n}"));
    }
    let mut root_commitment = [0u8; 32];
    reader
        .read_exact(&mut root_commitment)
        .map_err(io_error(path, "read root commitment"))?;
    let init_proof = read_blob(&mut reader, path, "initialization proof")?;
    let insert_proof = read_blob(&mut reader, path, "insertion proof")?;

    let mut accounts = Vec::with_capacity(n + 1);
    for index in 0..=n {
        let account = read_account(&mut reader, path)?;
        validate_account(&account)
            .map_err(|err| format!("fixture account {index} is invalid: {err}"))?;
        accounts.push(account);
    }
    if !accounts
        .windows(2)
        .all(|pair| pair[0].address < pair[1].address)
    {
        return Err("fixture accounts are not canonical and duplicate-free".to_string());
    }

    let witnesses = accounts[..n].iter().map(init_witness).collect::<Vec<_>>();
    let candidate = &accounts[n];
    let insert = EthereumInsertFixture {
        address: format!("0x{}", hex_encode(&candidate.address)),
        balance: candidate.balance,
        private_key: candidate.private_key,
        tree_key: candidate.tree_key,
        basic_data: candidate.basic_data,
        proof: insert_proof,
    };
    let fixture = EthereumInitFixture {
        state_root: hex_encode(&root_commitment),
        witnesses,
        verkle_proof: EthereumVerkleBatchProofInput {
            root_commitment,
            proof: init_proof,
        },
        insert,
    };
    verify_fixture_proofs(&fixture)?;
    Ok(fixture)
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

fn account_item(address: &str, balance: i128) -> Result<([u8; 32], [u8; 32]), String> {
    let address = decode_address(address)?;
    if balance < 0 {
        return Err("negative Ethereum benchmark balance".to_string());
    }
    Ok((
        eip6800_basic_data_key(&address),
        eip6800_basic_data(balance),
    ))
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

fn decode_address(value: &str) -> Result<[u8; 20], String> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    if raw.len() != 40 {
        return Err(format!("Ethereum address must contain 20 bytes: {value}"));
    }
    let mut out = [0u8; 20];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&raw[index * 2..index * 2 + 2], 16)
            .map_err(|err| format!("invalid Ethereum address: {err}"))?;
    }
    Ok(out)
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
    hasher.update(b"dpoa-benchmark-ethereum-verkle-fixture-seed-v1");
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
