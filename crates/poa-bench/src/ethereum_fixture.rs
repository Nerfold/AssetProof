use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::crypto::{hex_decode, hex_encode};
use common::types::{
    ChainBalanceProofInput, Delta, InitChainBatchProofInput, InitReserveWitness,
    OwnershipWitnessInput, ReserveEntry,
};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use rayon::prelude::*;
use sha3::{Digest, Keccak256};
use sp1_programs_common::ethereum_binary_merkle::{empty_leaf_hash, leaf_hash, node_hash};
use sp1_programs_common::ethereum_eoa::{
    ownership_context_hash, ownership_digest_from_context, OwnershipOperation,
};

pub const CHAIN_ID: &str = "0x1";
const VERSION_NAME: &str = "ethereum-keccak-merkle-prefix-v2-ecdsa";
const VERSION: u32 = 2;
const ACCOUNT_MAGIC: &[u8; 8] = b"DPMERK02";
const PROOF_MAGIC: &[u8; 8] = b"DPPREF02";
const ACCOUNT_HEADER_BYTES: u64 = 8 + 4 + 8 + 4 + 32;
const ACCOUNT_RECORD_BYTES: u64 = 32 + 65 + 20 + 16 + 65;
const OWNERSHIP_SIGNATURE_BYTES: usize = 65;

type Hash = [u8; 32];

#[derive(Clone)]
pub struct EthereumInitFixture {
    pub state_root: String,
    pub witnesses: Vec<InitReserveWitness>,
    pub merkle_prefix_proof: InitChainBatchProofInput,
    pub insert: EthereumInsertFixture,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureValidation {
    None,
    Full,
}

#[derive(Clone)]
pub struct EthereumInsertFixture {
    pub address: String,
    pub balance: i128,
    pub ownership_signature: [u8; OWNERSHIP_SIGNATURE_BYTES],
    pub leaf_index: u64,
    pub siblings: Vec<Hash>,
}

#[derive(Clone)]
struct AccountRecord {
    private_key: [u8; 32],
    public_key: [u8; 65],
    address: [u8; 20],
    balance: i128,
    ownership_signature: [u8; OWNERSHIP_SIGNATURE_BYTES],
}

/// Runtime view used by proving. Private/public keys remain in the persisted
/// master store for reproducibility and full fixture validation, but retaining
/// them for every account would waste roughly 97 MB per million entries.
struct LoadedAccount {
    address: [u8; 20],
    balance: i128,
    ownership_signature: [u8; OWNERSHIP_SIGNATURE_BYTES],
}

impl From<AccountRecord> for LoadedAccount {
    fn from(value: AccountRecord) -> Self {
        Self {
            address: value.address,
            balance: value.balance,
            ownership_signature: value.ownership_signature,
        }
    }
}

struct BinaryMerkleTree {
    layers: Vec<Vec<Hash>>,
}

impl BinaryMerkleTree {
    fn build(accounts: &[AccountRecord]) -> Result<Self, String> {
        if accounts.is_empty() {
            return Err("Merkle tree requires at least one account".to_string());
        }
        let capacity = accounts.len().next_power_of_two();
        let mut leaves = Vec::with_capacity(capacity);
        leaves.par_extend(
            accounts
                .par_iter()
                .map(|account| leaf_hash(&account.address, account.balance)),
        );
        leaves.par_extend(
            (accounts.len()..capacity)
                .into_par_iter()
                .map(empty_leaf_hash),
        );
        let mut layers = vec![leaves];
        let mut level = 0usize;
        while layers.last().map_or(0, Vec::len) > 1 {
            let previous = layers.last().expect("Merkle layer exists");
            let next = previous
                .par_chunks_exact(2)
                .map(|pair| node_hash(level, &pair[0], &pair[1]))
                .collect();
            layers.push(next);
            level += 1;
        }
        Ok(Self { layers })
    }

    fn depth(&self) -> usize {
        self.layers.len() - 1
    }

    fn root(&self) -> Hash {
        self.layers[self.depth()][0]
    }

    fn proof(&self, leaf_index: usize) -> Result<Vec<Hash>, String> {
        if leaf_index >= self.layers[0].len() {
            return Err("Merkle proof index is outside tree capacity".to_string());
        }
        let mut index = leaf_index;
        let mut siblings = Vec::with_capacity(self.depth());
        for level in 0..self.depth() {
            siblings.push(self.layers[level][index ^ 1]);
            index >>= 1;
        }
        Ok(siblings)
    }

    fn suffix_subtrees(&self, mut start: usize) -> Result<Vec<(u32, Hash)>, String> {
        let capacity = self.layers[0].len();
        if start > capacity {
            return Err("Merkle prefix exceeds tree capacity".to_string());
        }
        let mut out = Vec::with_capacity(self.depth());
        while start < capacity {
            let remaining = capacity - start;
            let alignment_level = start.trailing_zeros() as usize;
            let remaining_level = (usize::BITS - 1 - remaining.leading_zeros()) as usize;
            let level = alignment_level.min(remaining_level).min(self.depth());
            out.push((level as u32, self.layers[level][start >> level]));
            start += 1usize << level;
        }
        Ok(out)
    }

    fn set_account_balance(&mut self, index: usize, address: &[u8; 20], balance: i128) {
        self.layers[0][index] = leaf_hash(address, balance);
        let mut node_index = index;
        for level in 0..self.depth() {
            let parent = node_index >> 1;
            let left = self.layers[level][parent * 2];
            let right = self.layers[level][parent * 2 + 1];
            self.layers[level + 1][parent] = node_hash(level, &left, &right);
            node_index = parent;
        }
    }
}

pub fn ensure_master_fixture(
    dir: &Path,
    max_n: usize,
    n_sizes: &[usize],
    m_sizes: &[usize],
) -> Result<(Duration, bool), String> {
    validate_requested_sizes(max_n, n_sizes, m_sizes)?;
    fs::create_dir_all(dir).map_err(|err| format!("create {}: {err}", dir.display()))?;
    if master_artifacts_exist(dir, max_n, n_sizes, m_sizes) {
        return Ok((Duration::ZERO, true));
    }

    let start = Instant::now();
    let seed = fixture_seed(max_n);
    let mut accounts = (0..=max_n)
        .into_par_iter()
        .map(|index| derive_account(&seed, index))
        .collect::<Result<Vec<_>, _>>()?;
    accounts.sort_unstable_by(|left, right| left.address.cmp(&right.address));
    let mut tree = BinaryMerkleTree::build(&accounts)?;
    let root = tree.root();
    let state_root = hex_encode(&root);
    let init_context =
        ownership_context_hash(OwnershipOperation::Initialization, CHAIN_ID, &state_root);
    let insert_context = ownership_context_hash(OwnershipOperation::Insert, CHAIN_ID, &state_root);
    accounts
        .par_iter_mut()
        .enumerate()
        .try_for_each(|(index, account)| {
            let context = if index == max_n {
                &insert_context
            } else {
                &init_context
            };
            account.ownership_signature = sign_ownership(account, context)?;
            Ok::<_, String>(())
        })?;
    write_master_accounts(dir, max_n, tree.depth(), &root, &accounts)?;

    for &n in &canonical_sizes(n_sizes) {
        write_prefix_proof(
            &init_proof_path(dir, n),
            max_n,
            n,
            tree.depth(),
            &root,
            &tree.suffix_subtrees(n)?,
        )?;
    }
    write_merkle_proofs(
        &insert_proof_path(dir),
        max_n,
        1,
        tree.depth(),
        &root,
        std::iter::once((max_n, tree.proof(max_n)?)),
    )?;

    for &n in &canonical_sizes(n_sizes) {
        generate_delta_artifacts(dir, n, m_sizes, &root, &accounts, &mut tree)?;
    }
    write_master_manifest(dir, max_n, tree.depth(), n_sizes, m_sizes, &root)?;
    Ok((start.elapsed(), false))
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
    let (root, depth, accounts, candidate) =
        read_master_account_prefix(dir, max_n, n, validation == FixtureValidation::Full)?;
    let suffix_subtrees = read_prefix_proof(&init_proof_path(dir, n), max_n, n, depth, &root)?;
    let witnesses = accounts
        .into_iter()
        .enumerate()
        .map(|(leaf_index, account)| init_witness(account, leaf_index as u64, Vec::new()))
        .collect::<Vec<_>>();
    let insert_proofs = read_merkle_proofs(&insert_proof_path(dir), max_n, 1, depth, &root)?;
    let (insert_index, insert_siblings) = insert_proofs
        .into_iter()
        .next()
        .ok_or_else(|| "missing insertion Merkle proof".to_string())?;
    let fixture = EthereumInitFixture {
        state_root: hex_encode(&root),
        witnesses,
        merkle_prefix_proof: InitChainBatchProofInput::BinaryMerklePrefixV2 {
            depth,
            suffix_subtrees,
        },
        insert: EthereumInsertFixture {
            address: format!("0x{}", hex_encode(&candidate.address)),
            balance: candidate.balance,
            ownership_signature: candidate.ownership_signature,
            leaf_index: insert_index,
            siblings: insert_siblings,
        },
    };
    if validation != FixtureValidation::None {
        verify_fixture_proofs(&fixture)?;
    }
    Ok(fixture)
}

pub fn ensure_delta_fixture(
    path: &Path,
    state_root: &str,
    reserve_count: usize,
    m: usize,
) -> Result<(Vec<Delta>, String, Duration, Duration, bool), String> {
    if m > reserve_count {
        return Err(format!(
            "m={m} exceeds reserve count {reserve_count}: this persisted fixture contains only \
             reserve-member transition accounts; the update proof relation itself also supports \
             distinct non-member touch-list entries"
        ));
    }
    if !path.is_file() {
        return Err(format!(
            "missing persisted Merkle transition fixture {}; rerun benchmark data initialization",
            path.display()
        ));
    }
    let start = Instant::now();
    let (deltas, old_root, new_root) = read_delta_fixture(path)?;
    if deltas.len() != m || old_root != state_root {
        return Err("persisted delta fixture does not match requested state".to_string());
    }
    Ok((deltas, new_root, Duration::ZERO, start.elapsed(), true))
}

pub fn load_insert_fixture(
    dir: &Path,
    max_n: usize,
    validation: FixtureValidation,
) -> Result<(String, EthereumInsertFixture), String> {
    let (root, depth, accounts, candidate) =
        read_master_account_prefix(dir, max_n, 0, validation == FixtureValidation::Full)?;
    debug_assert!(accounts.is_empty());
    let proofs = read_merkle_proofs(&insert_proof_path(dir), max_n, 1, depth, &root)?;
    let (leaf_index, siblings) = proofs
        .into_iter()
        .next()
        .ok_or_else(|| "missing insertion Merkle proof".to_string())?;
    let fixture = EthereumInsertFixture {
        address: format!("0x{}", hex_encode(&candidate.address)),
        balance: candidate.balance,
        ownership_signature: candidate.ownership_signature,
        leaf_index,
        siblings,
    };
    if validation != FixtureValidation::None {
        verify_merkle_proof(
            &root,
            &fixture.address,
            fixture.balance,
            fixture.leaf_index,
            &fixture.siblings,
        )?;
    }
    Ok((hex_encode(&root), fixture))
}

/// Loads only the fields needed to materialize the persisted initialized
/// polynomial.  Preparation does not need signatures, private keys, public
/// keys, or Merkle proof objects at this stage.
pub fn load_reserve_entries(
    dir: &Path,
    expected_max_n: usize,
    n: usize,
) -> Result<(String, Vec<ReserveEntry>), String> {
    if n == 0 || n > expected_max_n {
        return Err(format!(
            "reserve prefix n={n} is outside master size {expected_max_n}"
        ));
    }
    let path = master_accounts_path(dir);
    let expected = ACCOUNT_HEADER_BYTES + (expected_max_n as u64 + 1) * ACCOUNT_RECORD_BYTES;
    if fs::metadata(&path).map_err(io_error(&path, "stat"))?.len() != expected {
        return Err("master Merkle account store has unexpected size".to_string());
    }
    let mut reader = BufReader::new(File::open(&path).map_err(io_error(&path, "open"))?);
    let mut magic = [0u8; 8];
    reader
        .read_exact(&mut magic)
        .map_err(io_error(&path, "read magic"))?;
    let version = read_u32(&mut reader, &path)?;
    let max_n = read_u64(&mut reader, &path)? as usize;
    let _depth = read_u32(&mut reader, &path)?;
    let mut root = [0u8; 32];
    reader
        .read_exact(&mut root)
        .map_err(io_error(&path, "read root"))?;
    if &magic != ACCOUNT_MAGIC || version != VERSION || max_n != expected_max_n {
        return Err("unsupported master Merkle account store".to_string());
    }

    let mut entries = Vec::with_capacity(n);
    let mut previous = None;
    let mut discarded_keys = [0u8; 32 + 65];
    let mut discarded_signature = [0u8; 65];
    for _ in 0..n {
        let mut address = [0u8; 20];
        let mut balance = [0u8; 16];
        reader
            .read_exact(&mut discarded_keys)
            .map_err(io_error(&path, "read account keys"))?;
        reader
            .read_exact(&mut address)
            .map_err(io_error(&path, "read address"))?;
        reader
            .read_exact(&mut balance)
            .map_err(io_error(&path, "read balance"))?;
        reader
            .read_exact(&mut discarded_signature)
            .map_err(io_error(&path, "read signature"))?;
        if previous.is_some_and(|value| value >= address) {
            return Err("master account prefix is not canonical".to_string());
        }
        previous = Some(address);
        entries.push(ReserveEntry {
            address: format!("0x{}", hex_encode(&address)),
            balance: i128::from_le_bytes(balance),
        });
    }
    Ok((hex_encode(&root), entries))
}

fn generate_delta_artifacts(
    dir: &Path,
    n: usize,
    m_sizes: &[usize],
    base_root: &Hash,
    accounts: &[AccountRecord],
    tree: &mut BinaryMerkleTree,
) -> Result<(), String> {
    let targets = canonical_sizes(m_sizes);
    let Some(&max_m) = targets.last() else {
        return Ok(());
    };
    let (offset, step) = permutation_parameters(n);
    let mut updates = Vec::with_capacity(max_m);
    for ordinal in 0..max_m {
        let index = (offset + ordinal * step) % n;
        // The permutation visits every index exactly once before wrapping at
        // n, and fixture validation requires max_m <= n.  Reading the original
        // account directly avoids another O(n) balance allocation.
        let old_balance = accounts[index].balance;
        let new_balance = old_balance
            .checked_add(deterministic_delta(n, ordinal, old_balance))
            .ok_or_else(|| "benchmark delta overflowed balance".to_string())?;
        let delta = new_balance - old_balance;
        if new_balance < 0 {
            return Err("benchmark delta made a balance negative".to_string());
        }
        tree.set_account_balance(index, &accounts[index].address, new_balance);
        updates.push((index, delta));
        if targets.binary_search(&(ordinal + 1)).is_ok() {
            let mut deltas = updates
                .iter()
                .map(|(account_index, delta)| Delta {
                    address: format!("0x{}", hex_encode(&accounts[*account_index].address)),
                    delta: *delta,
                })
                .collect::<Vec<_>>();
            deltas.sort_by(|left, right| left.address.cmp(&right.address));
            write_delta_fixture(
                &delta_fixture_path(dir, n, ordinal + 1),
                &hex_encode(base_root),
                &hex_encode(&tree.root()),
                &deltas,
            )?;
        }
    }
    for (index, _) in updates {
        tree.set_account_balance(index, &accounts[index].address, accounts[index].balance);
    }
    if &tree.root() != base_root {
        return Err("failed to restore Merkle tree after delta generation".to_string());
    }
    Ok(())
}

fn write_master_accounts(
    dir: &Path,
    max_n: usize,
    depth: usize,
    root: &Hash,
    accounts: &[AccountRecord],
) -> Result<(), String> {
    let path = master_accounts_path(dir);
    let mut writer = BufWriter::new(File::create(&path).map_err(io_error(&path, "create"))?);
    writer
        .write_all(ACCOUNT_MAGIC)
        .map_err(io_error(&path, "write magic"))?;
    writer
        .write_all(&VERSION.to_le_bytes())
        .map_err(io_error(&path, "write version"))?;
    writer
        .write_all(&(max_n as u64).to_le_bytes())
        .map_err(io_error(&path, "write max_n"))?;
    writer
        .write_all(&(depth as u32).to_le_bytes())
        .map_err(io_error(&path, "write depth"))?;
    writer
        .write_all(root)
        .map_err(io_error(&path, "write root"))?;
    for account in accounts {
        writer
            .write_all(&account.private_key)
            .map_err(io_error(&path, "write private key"))?;
        writer
            .write_all(&account.public_key)
            .map_err(io_error(&path, "write public key"))?;
        writer
            .write_all(&account.address)
            .map_err(io_error(&path, "write address"))?;
        writer
            .write_all(&account.balance.to_le_bytes())
            .map_err(io_error(&path, "write balance"))?;
        writer
            .write_all(&account.ownership_signature)
            .map_err(io_error(&path, "write signature"))?;
    }
    writer.flush().map_err(io_error(&path, "flush"))
}

fn read_master_account_prefix(
    dir: &Path,
    expected_max_n: usize,
    n: usize,
    validate_crypto: bool,
) -> Result<(Hash, usize, Vec<LoadedAccount>, LoadedAccount), String> {
    let path = master_accounts_path(dir);
    let expected = ACCOUNT_HEADER_BYTES + (expected_max_n as u64 + 1) * ACCOUNT_RECORD_BYTES;
    if fs::metadata(&path).map_err(io_error(&path, "stat"))?.len() != expected {
        return Err("master Merkle account store has unexpected size".to_string());
    }
    let mut reader = BufReader::new(File::open(&path).map_err(io_error(&path, "open"))?);
    let mut magic = [0u8; 8];
    reader
        .read_exact(&mut magic)
        .map_err(io_error(&path, "read magic"))?;
    if &magic != ACCOUNT_MAGIC || read_u32(&mut reader, &path)? != VERSION {
        return Err("unsupported master Merkle account store".to_string());
    }
    let max_n = read_u64(&mut reader, &path)? as usize;
    let depth = read_u32(&mut reader, &path)? as usize;
    if max_n != expected_max_n {
        return Err(format!(
            "master reserve count {max_n}, expected {expected_max_n}"
        ));
    }
    let mut root = [0u8; 32];
    reader
        .read_exact(&mut root)
        .map_err(io_error(&path, "read root"))?;
    let state_root = hex_encode(&root);
    let init_context =
        ownership_context_hash(OwnershipOperation::Initialization, CHAIN_ID, &state_root);
    let insert_context = ownership_context_hash(OwnershipOperation::Insert, CHAIN_ID, &state_root);
    let mut accounts = Vec::with_capacity(n);
    let mut previous = None;
    for index in 0..n {
        let account = if validate_crypto {
            let account = read_account(&mut reader, &path)?;
            validate_account(&account, &init_context)
                .map_err(|err| format!("account {index}: {err}"))?;
            account.into()
        } else {
            read_loaded_account(&mut reader, &path)?
        };
        if previous.is_some_and(|value| value >= account.address) {
            return Err("master account prefix is not canonical".to_string());
        }
        previous = Some(account.address);
        accounts.push(account);
    }
    reader
        .seek(SeekFrom::Start(
            ACCOUNT_HEADER_BYTES + expected_max_n as u64 * ACCOUNT_RECORD_BYTES,
        ))
        .map_err(io_error(&path, "seek insert account"))?;
    let candidate = if validate_crypto {
        let account = read_account(&mut reader, &path)?;
        validate_account(&account, &insert_context)?;
        account.into()
    } else {
        read_loaded_account(&mut reader, &path)?
    };
    Ok((root, depth, accounts, candidate))
}

fn read_loaded_account(reader: &mut impl Read, path: &Path) -> Result<LoadedAccount, String> {
    // Consume but do not retain private/public keys during ordinary proving.
    let mut keys = [0u8; 32 + 65];
    let mut address = [0u8; 20];
    let mut balance = [0u8; 16];
    let mut ownership_signature = [0u8; 65];
    reader
        .read_exact(&mut keys)
        .map_err(io_error(path, "read account keys"))?;
    reader
        .read_exact(&mut address)
        .map_err(io_error(path, "read address"))?;
    reader
        .read_exact(&mut balance)
        .map_err(io_error(path, "read balance"))?;
    reader
        .read_exact(&mut ownership_signature)
        .map_err(io_error(path, "read signature"))?;
    Ok(LoadedAccount {
        address,
        balance: i128::from_le_bytes(balance),
        ownership_signature,
    })
}

fn read_account(reader: &mut impl Read, path: &Path) -> Result<AccountRecord, String> {
    let mut private_key = [0u8; 32];
    let mut public_key = [0u8; 65];
    let mut address = [0u8; 20];
    let mut balance = [0u8; 16];
    let mut ownership_signature = [0u8; 65];
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
        .read_exact(&mut ownership_signature)
        .map_err(io_error(path, "read signature"))?;
    Ok(AccountRecord {
        private_key,
        public_key,
        address,
        balance: i128::from_le_bytes(balance),
        ownership_signature,
    })
}

fn write_prefix_proof(
    path: &Path,
    max_n: usize,
    prefix_count: usize,
    depth: usize,
    root: &Hash,
    suffix_subtrees: &[(u32, Hash)],
) -> Result<(), String> {
    let mut writer = BufWriter::new(File::create(path).map_err(io_error(path, "create prefix"))?);
    writer
        .write_all(PROOF_MAGIC)
        .map_err(io_error(path, "write prefix magic"))?;
    writer
        .write_all(&VERSION.to_le_bytes())
        .map_err(io_error(path, "write prefix version"))?;
    writer
        .write_all(&(max_n as u64).to_le_bytes())
        .map_err(io_error(path, "write prefix max_n"))?;
    writer
        .write_all(&(prefix_count as u64).to_le_bytes())
        .map_err(io_error(path, "write prefix count"))?;
    writer
        .write_all(&(depth as u32).to_le_bytes())
        .map_err(io_error(path, "write prefix depth"))?;
    writer
        .write_all(root)
        .map_err(io_error(path, "write prefix root"))?;
    writer
        .write_all(&(suffix_subtrees.len() as u32).to_le_bytes())
        .map_err(io_error(path, "write suffix count"))?;
    for (level, hash) in suffix_subtrees {
        writer
            .write_all(&level.to_le_bytes())
            .map_err(io_error(path, "write suffix level"))?;
        writer
            .write_all(hash)
            .map_err(io_error(path, "write suffix root"))?;
    }
    writer.flush().map_err(io_error(path, "flush prefix"))
}

fn read_prefix_proof(
    path: &Path,
    expected_max_n: usize,
    expected_count: usize,
    expected_depth: usize,
    expected_root: &Hash,
) -> Result<Vec<(u32, Hash)>, String> {
    let mut reader = BufReader::new(File::open(path).map_err(io_error(path, "open prefix"))?);
    let mut magic = [0u8; 8];
    reader
        .read_exact(&mut magic)
        .map_err(io_error(path, "read prefix magic"))?;
    let version = read_u32(&mut reader, path)?;
    let max_n = read_u64(&mut reader, path)? as usize;
    let count = read_u64(&mut reader, path)? as usize;
    let depth = read_u32(&mut reader, path)? as usize;
    let mut root = [0u8; 32];
    reader
        .read_exact(&mut root)
        .map_err(io_error(path, "read prefix root"))?;
    if &magic != PROOF_MAGIC
        || version != VERSION
        || max_n != expected_max_n
        || count != expected_count
        || depth != expected_depth
        || root != *expected_root
    {
        return Err(format!("invalid Merkle prefix artifact {}", path.display()));
    }
    let suffix_count = read_u32(&mut reader, path)? as usize;
    if suffix_count > depth + 1 {
        return Err("Merkle prefix contains too many suffix subtrees".to_string());
    }
    let mut suffix = Vec::with_capacity(suffix_count);
    for _ in 0..suffix_count {
        let level = read_u32(&mut reader, path)?;
        let mut hash = [0u8; 32];
        reader
            .read_exact(&mut hash)
            .map_err(io_error(path, "read suffix root"))?;
        suffix.push((level, hash));
    }
    Ok(suffix)
}

fn write_merkle_proofs(
    path: &Path,
    max_n: usize,
    proof_count: usize,
    depth: usize,
    root: &Hash,
    proofs: impl Iterator<Item = (usize, Vec<Hash>)>,
) -> Result<(), String> {
    let mut writer = BufWriter::new(File::create(path).map_err(io_error(path, "create proof"))?);
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
        .write_all(&(proof_count as u64).to_le_bytes())
        .map_err(io_error(path, "write proof count"))?;
    writer
        .write_all(&(depth as u32).to_le_bytes())
        .map_err(io_error(path, "write proof depth"))?;
    writer
        .write_all(root)
        .map_err(io_error(path, "write proof root"))?;
    let mut written = 0usize;
    for (index, siblings) in proofs {
        if siblings.len() != depth {
            return Err("Merkle proof depth mismatch".to_string());
        }
        writer
            .write_all(&(index as u64).to_le_bytes())
            .map_err(io_error(path, "write leaf index"))?;
        for sibling in siblings {
            writer
                .write_all(&sibling)
                .map_err(io_error(path, "write sibling"))?;
        }
        written += 1;
    }
    if written != proof_count {
        return Err("Merkle proof count mismatch".to_string());
    }
    writer.flush().map_err(io_error(path, "flush proof"))
}

fn read_merkle_proofs(
    path: &Path,
    expected_max_n: usize,
    expected_count: usize,
    expected_depth: usize,
    expected_root: &Hash,
) -> Result<Vec<(u64, Vec<Hash>)>, String> {
    let mut reader = BufReader::new(File::open(path).map_err(io_error(path, "open proof"))?);
    let mut magic = [0u8; 8];
    reader
        .read_exact(&mut magic)
        .map_err(io_error(path, "read proof magic"))?;
    let version = read_u32(&mut reader, path)?;
    let max_n = read_u64(&mut reader, path)? as usize;
    let count = read_u64(&mut reader, path)? as usize;
    let depth = read_u32(&mut reader, path)? as usize;
    let mut root = [0u8; 32];
    reader
        .read_exact(&mut root)
        .map_err(io_error(path, "read proof root"))?;
    if &magic != PROOF_MAGIC
        || version != VERSION
        || max_n != expected_max_n
        || count != expected_count
        || depth != expected_depth
        || root != *expected_root
    {
        return Err(format!("invalid Merkle proof artifact {}", path.display()));
    }
    let mut proofs = Vec::with_capacity(count);
    for _ in 0..count {
        let index = read_u64(&mut reader, path)?;
        let mut siblings = Vec::with_capacity(depth);
        for _ in 0..depth {
            let mut sibling = [0u8; 32];
            reader
                .read_exact(&mut sibling)
                .map_err(io_error(path, "read sibling"))?;
            siblings.push(sibling);
        }
        proofs.push((index, siblings));
    }
    Ok(proofs)
}

fn init_witness(
    account: LoadedAccount,
    leaf_index: u64,
    siblings: Vec<Hash>,
) -> InitReserveWitness {
    let address = format!("0x{}", hex_encode(&account.address));
    InitReserveWitness {
        address,
        balance: account.balance,
        ownership: OwnershipWitnessInput::EthereumEoaSignatureHex {
            signature_hex: hex_encode(&account.ownership_signature),
        },
        chain_balance_proof: ChainBalanceProofInput::BinaryMerkleV1 {
            chain_id: CHAIN_ID.to_string(),
            leaf_index,
            siblings,
        },
    }
}

fn verify_fixture_proofs(fixture: &EthereumInitFixture) -> Result<(), String> {
    let expected_root = decode_hash(&fixture.state_root)?;
    verify_prefix_proof(
        &expected_root,
        &fixture.witnesses,
        &fixture.merkle_prefix_proof,
    )?;
    verify_merkle_proof(
        &expected_root,
        &fixture.insert.address,
        fixture.insert.balance,
        fixture.insert.leaf_index,
        &fixture.insert.siblings,
    )
}

fn verify_merkle_proof(
    root: &Hash,
    address: &str,
    balance: i128,
    leaf_index: u64,
    siblings: &[Hash],
) -> Result<(), String> {
    let address = decode_address(address)?;
    let mut current = leaf_hash(&address, balance);
    let mut index = leaf_index;
    for (level, sibling) in siblings.iter().enumerate() {
        current = if index & 1 == 0 {
            node_hash(level, &current, sibling)
        } else {
            node_hash(level, sibling, &current)
        };
        index >>= 1;
    }
    if index != 0 || current != *root {
        return Err("binary Merkle proof mismatch".to_string());
    }
    Ok(())
}

fn verify_prefix_proof(
    root: &Hash,
    witnesses: &[InitReserveWitness],
    proof: &InitChainBatchProofInput,
) -> Result<(), String> {
    let InitChainBatchProofInput::BinaryMerklePrefixV2 {
        depth,
        suffix_subtrees,
    } = proof;
    if *depth >= usize::BITS as usize {
        return Err("Merkle prefix depth is too large".to_string());
    }
    let capacity = 1usize << depth;
    let mut stack = vec![None; depth + 1];
    let mut cursor = 0usize;
    for (expected_index, witness) in witnesses.iter().enumerate() {
        let ChainBalanceProofInput::BinaryMerkleV1 {
            leaf_index,
            siblings,
            ..
        } = &witness.chain_balance_proof
        else {
            return Err("Merkle prefix contains a non-binary member".to_string());
        };
        if *leaf_index as usize != expected_index || !siblings.is_empty() {
            return Err("Merkle prefix member repeated or reordered a path".to_string());
        }
        let address = decode_address(&witness.address)?;
        append_subtree(
            &mut stack,
            &mut cursor,
            0,
            leaf_hash(&address, witness.balance),
        )?;
    }
    for (level, hash) in suffix_subtrees {
        append_subtree(&mut stack, &mut cursor, *level as usize, *hash)?;
    }
    if cursor != capacity
        || stack[..*depth].iter().any(Option::is_some)
        || stack[*depth] != Some(*root)
    {
        return Err("binary Merkle prefix proof mismatch".to_string());
    }
    Ok(())
}

fn append_subtree(
    stack: &mut [Option<Hash>],
    cursor: &mut usize,
    mut level: usize,
    mut current: Hash,
) -> Result<(), String> {
    if level >= stack.len() {
        return Err("Merkle suffix level exceeds depth".to_string());
    }
    let width = 1usize << level;
    if *cursor % width != 0 {
        return Err("unaligned Merkle suffix subtree".to_string());
    }
    *cursor = cursor
        .checked_add(width)
        .ok_or_else(|| "Merkle cursor overflow".to_string())?;
    loop {
        let Some(left) = stack[level].take() else {
            stack[level] = Some(current);
            return Ok(());
        };
        current = node_hash(level, &left, &current);
        level += 1;
        if level >= stack.len() {
            return Err("Merkle prefix exceeded declared depth".to_string());
        }
    }
}

fn decode_address(value: &str) -> Result<[u8; 20], String> {
    hex_decode(value.strip_prefix("0x").unwrap_or(value))?
        .try_into()
        .map_err(|_| "Ethereum address must contain 20 bytes".to_string())
}

fn derive_account(seed: &Hash, index: usize) -> Result<AccountRecord, String> {
    let mut counter = 0u64;
    let private_key = loop {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"dpoa-benchmark-ethereum-private-key-merkle-v1");
        hasher.update(seed);
        hasher.update(&(index as u64).to_le_bytes());
        hasher.update(&counter.to_le_bytes());
        let candidate = *hasher.finalize().as_bytes();
        if SecretKey::from_slice(&candidate).is_ok() {
            break candidate;
        }
        counter += 1;
    };
    let (public_key, address) = public_key_and_address(&private_key)?;
    let mut balance_hasher = blake3::Hasher::new();
    balance_hasher.update(b"dpoa-benchmark-ethereum-balance-merkle-v1");
    balance_hasher.update(seed);
    balance_hasher.update(&(index as u64).to_le_bytes());
    let balance_bytes = balance_hasher.finalize();
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&balance_bytes.as_bytes()[..8]);
    let balance = 1_000_000i128 + (u64::from_le_bytes(raw) % 1_000_000_000) as i128;
    Ok(AccountRecord {
        private_key,
        public_key,
        address,
        balance,
        ownership_signature: [0u8; 65],
    })
}

fn public_key_and_address(private_key: &[u8; 32]) -> Result<([u8; 65], [u8; 20]), String> {
    let secret = SecretKey::from_slice(private_key).map_err(|err| format!("private key: {err}"))?;
    let encoded = secret.public_key().to_encoded_point(false);
    let public_key: [u8; 65] = encoded
        .as_bytes()
        .try_into()
        .map_err(|_| "uncompressed public key must contain 65 bytes".to_string())?;
    let digest = Keccak256::digest(&public_key[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&digest[12..]);
    Ok((public_key, address))
}

fn sign_ownership(account: &AccountRecord, context: &Hash) -> Result<[u8; 65], String> {
    let key = SigningKey::from_slice(&account.private_key)
        .map_err(|err| format!("ownership signing key: {err}"))?;
    let address = format!("0x{}", hex_encode(&account.address));
    let digest = ownership_digest_from_context(context, &address);
    let (signature, recovery_id) = key
        .sign_prehash_recoverable(&digest)
        .map_err(|err| format!("sign ownership: {err}"))?;
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&signature.to_bytes());
    out[64] = recovery_id.to_byte();
    Ok(out)
}

fn validate_account(account: &AccountRecord, context: &Hash) -> Result<(), String> {
    let (public_key, address) = public_key_and_address(&account.private_key)?;
    if public_key != account.public_key || address != account.address || account.balance < 0 {
        return Err("Ethereum account key/address/balance mismatch".to_string());
    }
    let signature = Signature::from_slice(&account.ownership_signature[..64])
        .map_err(|err| format!("ownership signature: {err}"))?;
    let recovery_id = RecoveryId::from_byte(account.ownership_signature[64])
        .ok_or_else(|| "invalid recovery id".to_string())?;
    let digest =
        ownership_digest_from_context(context, &format!("0x{}", hex_encode(&account.address)));
    let recovered = VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id)
        .map_err(|err| format!("recover ownership key: {err}"))?;
    if recovered.to_encoded_point(false).as_bytes() != account.public_key {
        return Err("ownership signature recovered wrong public key".to_string());
    }
    Ok(())
}

fn fixture_seed(max_n: usize) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"dynamic-poa-ethereum-merkle-master-fixture-v1");
    hasher.update(&(max_n as u64).to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn deterministic_delta(n: usize, ordinal: usize, old_balance: i128) -> i128 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"dynamic-poa-merkle-delta-v1");
    hasher.update(&(n as u64).to_le_bytes());
    hasher.update(&(ordinal as u64).to_le_bytes());
    let raw = u64::from_le_bytes(hasher.finalize().as_bytes()[..8].try_into().unwrap());
    let magnitude = 1 + (raw % 10_000) as i128;
    if raw & 1 == 0 || old_balance <= magnitude {
        magnitude
    } else {
        -magnitude
    }
}

fn permutation_parameters(n: usize) -> (usize, usize) {
    let offset = n / 3;
    let mut step = (n / 2).max(1) | 1;
    while gcd(step, n) != 1 {
        step += 2;
    }
    (offset, step)
}

fn gcd(mut left: usize, mut right: usize) -> usize {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

fn canonical_sizes(values: &[usize]) -> Vec<usize> {
    values
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn validate_requested_sizes(
    max_n: usize,
    n_sizes: &[usize],
    m_sizes: &[usize],
) -> Result<(), String> {
    if max_n == 0 || n_sizes.is_empty() {
        return Err("Merkle benchmark requires a non-empty reserve set".to_string());
    }
    for &n in n_sizes {
        if n == 0 || n > max_n {
            return Err(format!("n={n} is outside master size {max_n}"));
        }
        if m_sizes.iter().any(|m| *m == 0 || *m > n) {
            return Err(format!(
                "persisted Ethereum transition fixture size must be in 1..={n}; m>n needs an \
                 expanded chain-account pool containing distinct non-members"
            ));
        }
    }
    Ok(())
}

fn master_artifacts_exist(dir: &Path, max_n: usize, n_sizes: &[usize], m_sizes: &[usize]) -> bool {
    fs::read_to_string(master_manifest_path(dir)).is_ok_and(|body| {
        body.lines()
            .any(|line| line == format!("version={VERSION_NAME}"))
            && body.lines().any(|line| line == format!("max_n={max_n}"))
    }) && master_accounts_path(dir).is_file()
        && insert_proof_path(dir).is_file()
        && n_sizes.iter().all(|n| init_proof_path(dir, *n).is_file())
        && n_sizes.iter().all(|n| {
            m_sizes
                .iter()
                .all(|m| delta_fixture_path(dir, *n, *m).is_file())
        })
}

fn write_master_manifest(
    dir: &Path,
    max_n: usize,
    depth: usize,
    n_sizes: &[usize],
    m_sizes: &[usize],
    root: &Hash,
) -> Result<(), String> {
    let body = format!(
        "version={VERSION_NAME}\nmax_n={max_n}\ndepth={depth}\nn_sizes={:?}\nm_sizes={:?}\nstate_root={}\nstatus=complete\n",
        canonical_sizes(n_sizes),
        canonical_sizes(m_sizes),
        hex_encode(root)
    );
    fs::write(master_manifest_path(dir), body).map_err(|err| format!("write manifest: {err}"))
}

fn write_delta_fixture(
    path: &Path,
    old_root: &str,
    new_root: &str,
    deltas: &[Delta],
) -> Result<(), String> {
    let mut body = format!("old_state_root={old_root}\nnew_state_root={new_root}\naddress,delta\n");
    for delta in deltas {
        body.push_str(&format!("{},{}\n", delta.address, delta.delta));
    }
    fs::write(path, body).map_err(|err| format!("write {}: {err}", path.display()))
}

fn read_delta_fixture(path: &Path) -> Result<(Vec<Delta>, String, String), String> {
    let body = fs::read_to_string(path).map_err(|err| format!("read {}: {err}", path.display()))?;
    let mut lines = body.lines();
    let old_root = lines
        .next()
        .and_then(|line| line.strip_prefix("old_state_root="))
        .ok_or_else(|| "missing old root".to_string())?
        .to_string();
    let new_root = lines
        .next()
        .and_then(|line| line.strip_prefix("new_state_root="))
        .ok_or_else(|| "missing new root".to_string())?
        .to_string();
    if lines.next() != Some("address,delta") {
        return Err("invalid delta CSV header".to_string());
    }
    let deltas = lines
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (address, delta) = line
                .split_once(',')
                .ok_or_else(|| "invalid delta row".to_string())?;
            Ok(Delta {
                address: address.to_string(),
                delta: delta
                    .parse::<i128>()
                    .map_err(|err| format!("delta: {err}"))?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok((deltas, old_root, new_root))
}

fn decode_hash(value: &str) -> Result<Hash, String> {
    hex_decode(value)?
        .try_into()
        .map_err(|_| "hash must contain 32 bytes".to_string())
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

fn io_error<'a>(path: &'a Path, action: &'static str) -> impl Fn(std::io::Error) -> String + 'a {
    move |err| format!("{action} {}: {err}", path.display())
}

pub fn init_proof_path(dir: &Path, n: usize) -> PathBuf {
    dir.join(format!("init-merkle-proofs-n-{n}.bin"))
}

pub fn insert_proof_path(dir: &Path) -> PathBuf {
    dir.join("insert-merkle-proof.bin")
}

pub fn delta_fixture_path(dir: &Path, n: usize, m: usize) -> PathBuf {
    dir.join(format!("deltas-n-{n}-m-{m}.csv"))
}

pub fn master_accounts_path(dir: &Path) -> PathBuf {
    dir.join("accounts.bin")
}

pub fn master_manifest_path(dir: &Path) -> PathBuf {
    dir.join("master-manifest.txt")
}

pub fn fixture_persisted_bytes(dir: &Path, n: usize) -> Result<u64, String> {
    [
        master_accounts_path(dir),
        init_proof_path(dir, n),
        insert_proof_path(dir),
    ]
    .into_iter()
    .try_fold(0u64, |sum, path| {
        Ok(sum + fs::metadata(&path).map_err(io_error(&path, "stat"))?.len())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethereum_merkle_fixture_round_trip() {
        let dir = std::env::temp_dir().join(format!(
            "poa-merkle-fixture-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let (elapsed, reused) = ensure_master_fixture(&dir, 8, &[3, 5, 8], &[2]).unwrap();
        assert!(!reused);
        assert!(!elapsed.is_zero());

        for n in [3, 5] {
            let prefix = load_init_fixture(&dir, 8, n, FixtureValidation::Full).unwrap();
            assert_eq!(prefix.witnesses.len(), n);
        }
        let fixture = load_init_fixture(&dir, 8, 8, FixtureValidation::Full).unwrap();
        assert_eq!(fixture.witnesses.len(), 8);
        assert!(fixture.witnesses.iter().all(|witness| matches!(
            &witness.chain_balance_proof,
            ChainBalanceProofInput::BinaryMerkleV1 { siblings, .. } if siblings.is_empty()
        )));
        assert!(fs::metadata(init_proof_path(&dir, 8)).unwrap().len() < 1024);
        assert_eq!(fixture.insert.leaf_index, 8);
        assert_eq!(fixture.insert.siblings.len(), 4);
        let (insert_root, insert) = load_insert_fixture(&dir, 8, FixtureValidation::Full).unwrap();
        assert_eq!(insert_root, fixture.state_root);
        assert_eq!(insert.address, fixture.insert.address);
        let delta_path = delta_fixture_path(&dir, 8, 2);
        let (deltas, new_root, _, _, reused) =
            ensure_delta_fixture(&delta_path, &fixture.state_root, fixture.witnesses.len(), 2)
                .unwrap();
        assert!(reused);
        assert_eq!(deltas.len(), 2);
        assert_ne!(new_root, fixture.state_root);

        fs::remove_dir_all(&dir).unwrap();
    }
}
