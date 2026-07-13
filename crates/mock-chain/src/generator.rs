use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use common::crypto::hex_encode;
use common::encoding::normalize_address;
use common::types::{Delta, ReserveEntry};

#[derive(Clone, Debug)]
pub struct MockScenario {
    pub seed: u64,
    pub num_accounts: usize,
    pub num_reserves: usize,
    pub num_blocks: usize,
    pub txs_per_block: usize,
    pub initial_root: String,
    pub reserves: Vec<ReserveEntry>,
    pub windows: Vec<MockWindow>,
}

#[derive(Clone, Debug)]
pub struct MockWindow {
    pub index: usize,
    pub old_root: String,
    pub new_root: String,
    pub deltas: Vec<Delta>,
}

pub fn generate_scenario(
    seed: u64,
    num_accounts: usize,
    num_reserves: usize,
    num_blocks: usize,
    txs_per_block: usize,
) -> Result<MockScenario, String> {
    if num_reserves == 0 || num_reserves > num_accounts {
        return Err("num_reserves must be in 1..=num_accounts".to_string());
    }

    let mut rng = StdRng::seed_from_u64(seed);
    let mut addresses = Vec::with_capacity(num_accounts);
    let mut balances = Vec::with_capacity(num_accounts);
    for _ in 0..num_accounts {
        addresses.push(random_address(&mut rng)?);
        balances.push(rng.gen_range(5_000_i128..50_000_i128));
    }

    let mut reserve_indices = Vec::new();
    while reserve_indices.len() < num_reserves {
        let candidate = rng.gen_range(0..num_accounts);
        if !reserve_indices.contains(&candidate) {
            reserve_indices.push(candidate);
        }
    }
    reserve_indices.sort_unstable();

    let reserves = reserve_indices
        .iter()
        .map(|index| ReserveEntry {
            address: addresses[*index].clone(),
            balance: balances[*index],
        })
        .collect::<Vec<_>>();

    let initial_root = compute_state_root(&addresses, &balances);
    let mut windows = Vec::with_capacity(num_blocks);
    let mut current_root = initial_root.clone();

    for block_index in 0..num_blocks {
        let mut delta_map = BTreeMap::<String, i128>::new();
        for _ in 0..txs_per_block {
            let sender = pick_funded_sender(&mut rng, &balances)?;
            let mut receiver = rng.gen_range(0..num_accounts);
            while receiver == sender {
                receiver = rng.gen_range(0..num_accounts);
            }

            let max_amount = balances[sender].min(1_000);
            if max_amount <= 0 {
                continue;
            }
            let amount = rng.gen_range(1_i128..=max_amount);
            balances[sender] -= amount;
            balances[receiver] += amount;
            *delta_map.entry(addresses[sender].clone()).or_insert(0) -= amount;
            *delta_map.entry(addresses[receiver].clone()).or_insert(0) += amount;
        }

        let new_root = compute_state_root(&addresses, &balances);
        let deltas = delta_map
            .into_iter()
            .filter_map(|(address, delta)| (delta != 0).then_some(Delta { address, delta }))
            .collect::<Vec<_>>();
        windows.push(MockWindow {
            index: block_index + 1,
            old_root: current_root.clone(),
            new_root: new_root.clone(),
            deltas,
        });
        current_root = new_root;
    }

    Ok(MockScenario {
        seed,
        num_accounts,
        num_reserves,
        num_blocks,
        txs_per_block,
        initial_root,
        reserves,
        windows,
    })
}

pub fn write_scenario(output_dir: &Path, scenario: &MockScenario) -> Result<PathBuf, String> {
    fs::create_dir_all(output_dir)
        .map_err(|err| format!("create {}: {err}", output_dir.display()))?;
    let windows_dir = output_dir.join("windows");
    fs::create_dir_all(&windows_dir)
        .map_err(|err| format!("create {}: {err}", windows_dir.display()))?;
    clear_generated_windows(&windows_dir)?;

    write_reserves_csv(&output_dir.join("reserves.csv"), &scenario.reserves)?;
    for window in &scenario.windows {
        let window_path = windows_dir.join(format!("window_{:04}.csv", window.index));
        write_deltas_csv(&window_path, &window.deltas)?;
        let meta_path = windows_dir.join(format!("window_{:04}.meta", window.index));
        fs::write(
            &meta_path,
            format!(
                "old_root={}\nnew_root={}\n",
                window.old_root, window.new_root
            ),
        )
        .map_err(|err| format!("write {}: {err}", meta_path.display()))?;
    }

    let manifest_path = output_dir.join("manifest.txt");
    fs::write(
        &manifest_path,
        format!(
            "seed={}\nnum_accounts={}\nnum_reserves={}\nnum_blocks={}\ntxs_per_block={}\ninitial_root={}\n",
            scenario.seed,
            scenario.num_accounts,
            scenario.num_reserves,
            scenario.num_blocks,
            scenario.txs_per_block,
            scenario.initial_root
        ),
    )
    .map_err(|err| format!("write {}: {err}", manifest_path.display()))?;
    Ok(manifest_path)
}

fn clear_generated_windows(windows_dir: &Path) -> Result<(), String> {
    for entry in
        fs::read_dir(windows_dir).map_err(|err| format!("read {}: {err}", windows_dir.display()))?
    {
        let entry = entry.map_err(|err| format!("read {} entry: {err}", windows_dir.display()))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let generated = name.starts_with("window_")
            && matches!(
                path.extension().and_then(|value| value.to_str()),
                Some("csv" | "meta")
            );
        if generated {
            fs::remove_file(&path).map_err(|err| format!("remove {}: {err}", path.display()))?;
        }
    }
    Ok(())
}

pub fn load_manifest(manifest_path: &Path) -> Result<MockScenario, String> {
    let input = fs::read_to_string(manifest_path)
        .map_err(|err| format!("read {}: {err}", manifest_path.display()))?;
    let mut seed = None;
    let mut num_accounts = None;
    let mut num_reserves = None;
    let mut num_blocks = None;
    let mut txs_per_block = None;
    let mut initial_root = None;
    for line in input.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "seed" => seed = Some(value.parse::<u64>().map_err(|err| format!("seed: {err}"))?),
            "num_accounts" => {
                num_accounts = Some(
                    value
                        .parse::<usize>()
                        .map_err(|err| format!("num_accounts: {err}"))?,
                )
            }
            "num_reserves" => {
                num_reserves = Some(
                    value
                        .parse::<usize>()
                        .map_err(|err| format!("num_reserves: {err}"))?,
                )
            }
            "num_blocks" => {
                num_blocks = Some(
                    value
                        .parse::<usize>()
                        .map_err(|err| format!("num_blocks: {err}"))?,
                )
            }
            "txs_per_block" => {
                txs_per_block = Some(
                    value
                        .parse::<usize>()
                        .map_err(|err| format!("txs_per_block: {err}"))?,
                )
            }
            "initial_root" => initial_root = Some(value.to_string()),
            _ => {}
        }
    }

    let base_dir = manifest_path
        .parent()
        .ok_or_else(|| format!("manifest has no parent: {}", manifest_path.display()))?;
    let reserves = common::io::read_reserve_csv(&base_dir.join("reserves.csv"))?;
    let windows_dir = base_dir.join("windows");
    let mut windows = Vec::new();
    let mut index = 1usize;
    loop {
        let csv_path = windows_dir.join(format!("window_{:04}.csv", index));
        let meta_path = windows_dir.join(format!("window_{:04}.meta", index));
        if !csv_path.exists() {
            break;
        }
        let deltas = common::io::read_delta_csv(&csv_path)?;
        let meta = fs::read_to_string(&meta_path)
            .map_err(|err| format!("read {}: {err}", meta_path.display()))?;
        let mut old_root = String::new();
        let mut new_root = String::new();
        for line in meta.lines() {
            if let Some((key, value)) = line.split_once('=') {
                match key {
                    "old_root" => old_root = value.to_string(),
                    "new_root" => new_root = value.to_string(),
                    _ => {}
                }
            }
        }
        windows.push(MockWindow {
            index,
            old_root,
            new_root,
            deltas,
        });
        index += 1;
    }

    Ok(MockScenario {
        seed: seed.ok_or_else(|| "manifest missing seed".to_string())?,
        num_accounts: num_accounts.ok_or_else(|| "manifest missing num_accounts".to_string())?,
        num_reserves: num_reserves.ok_or_else(|| "manifest missing num_reserves".to_string())?,
        num_blocks: num_blocks.ok_or_else(|| "manifest missing num_blocks".to_string())?,
        txs_per_block: txs_per_block.ok_or_else(|| "manifest missing txs_per_block".to_string())?,
        initial_root: initial_root.ok_or_else(|| "manifest missing initial_root".to_string())?,
        reserves,
        windows,
    })
}

fn random_address(rng: &mut StdRng) -> Result<String, String> {
    let mut bytes = [0u8; 20];
    rng.fill(&mut bytes);
    normalize_address(&format!("0x{}", hex_encode(&bytes)))
}

fn compute_state_root(addresses: &[String], balances: &[i128]) -> String {
    let mut hasher = blake3::Hasher::new();
    for (address, balance) in addresses.iter().zip(balances.iter()) {
        hasher.update(address.as_bytes());
        hasher.update(&balance.to_le_bytes());
    }
    hex_encode(hasher.finalize().as_bytes())
}

fn pick_funded_sender(rng: &mut StdRng, balances: &[i128]) -> Result<usize, String> {
    let funded = balances
        .iter()
        .enumerate()
        .filter_map(|(index, balance)| (*balance > 0).then_some(index))
        .collect::<Vec<_>>();
    if funded.is_empty() {
        return Err("no funded sender available".to_string());
    }
    Ok(funded[rng.gen_range(0..funded.len())])
}

fn write_reserves_csv(path: &Path, reserves: &[ReserveEntry]) -> Result<(), String> {
    let body = reserves
        .iter()
        .map(|entry| format!("{},{}", entry.address, entry.balance))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(path, body).map_err(|err| format!("write {}: {err}", path.display()))
}

fn write_deltas_csv(path: &Path, deltas: &[Delta]) -> Result<(), String> {
    let body = deltas
        .iter()
        .map(|delta| format!("{},{}", delta.address, delta.delta))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(path, body).map_err(|err| format!("write {}: {err}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{generate_scenario, write_scenario};

    #[test]
    fn rewriting_scenario_removes_stale_generated_windows_only() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("poa-mock-chain-{nonce}"));

        let larger = generate_scenario(7, 8, 2, 3, 2).unwrap();
        write_scenario(&dir, &larger).unwrap();
        fs::write(dir.join("windows/keep.txt"), "keep").unwrap();

        let smaller = generate_scenario(7, 8, 2, 1, 2).unwrap();
        write_scenario(&dir, &smaller).unwrap();

        assert!(dir.join("windows/window_0001.csv").exists());
        assert!(!dir.join("windows/window_0002.csv").exists());
        assert!(!dir.join("windows/window_0003.meta").exists());
        assert!(dir.join("windows/keep.txt").exists());

        fs::remove_dir_all(dir).unwrap();
    }
}
