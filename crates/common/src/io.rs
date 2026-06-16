use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use ark_bls12_381::{Fr, G1Affine, G2Affine};

use crate::crypto::{
    read_scalar_vec_csv, read_srs_binary, read_srs_g1_prefix_binary, read_srs_prefix_binary, read_u8_vec_csv,
    scalar_from_hex, scalar_to_hex,
    write_scalar_vec_csv, write_srs_binary, write_string_vec_csv, write_u8_vec_csv,
};
use crate::encoding::normalize_address;
use crate::types::{
    Delta, InitReserveWitness, ReserveEntry, SmtLeafRecord, StoredInitProof, StoredProof, StoredSmtProof,
    StoredParallelInitProof, StoredParallelProof, StoredParallelShardProof, StoredParallelShardState,
    StoredParallelState, StoredSmtState, StoredState,
};

pub fn read_reserve_csv(path: &Path) -> Result<Vec<ReserveEntry>, String> {
    let input = fs::read_to_string(path).map_err(|err| format!("read {}: {err}", path.display()))?;
    let mut entries = Vec::new();
    for (line_no, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<_> = line.split(',').map(|part| part.trim()).collect();
        if parts.len() != 2 {
            return Err(format!("invalid reserve csv line {}: {line}", line_no + 1));
        }
        let address = normalize_address(parts[0])?;
        let balance = parts[1]
            .parse::<i128>()
            .map_err(|err| format!("invalid balance on line {}: {err}", line_no + 1))?;
        entries.push(ReserveEntry { address, balance });
    }
    Ok(entries)
}

pub fn read_init_witness_csv(path: &Path) -> Result<Vec<InitReserveWitness>, String> {
    let input = fs::read_to_string(path).map_err(|err| format!("read {}: {err}", path.display()))?;
    let mut entries = Vec::new();
    for (line_no, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<_> = line.split(',').map(|part| part.trim()).collect();
        if parts.len() != 3 {
            return Err(format!(
                "invalid init witness csv line {}: expected address,balance,mock_private_key",
                line_no + 1
            ));
        }
        let address = normalize_address(parts[0])?;
        let balance = parts[1]
            .parse::<i128>()
            .map_err(|err| format!("invalid balance on line {}: {err}", line_no + 1))?;
        entries.push(InitReserveWitness::mock(
            address,
            balance,
            parts[2].to_string(),
        ));
    }
    Ok(entries)
}

pub fn read_delta_csv(path: &Path) -> Result<Vec<Delta>, String> {
    let input = fs::read_to_string(path).map_err(|err| format!("read {}: {err}", path.display()))?;
    let mut merged = BTreeMap::<String, i128>::new();
    for (line_no, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<_> = line.split(',').map(|part| part.trim()).collect();
        if parts.len() != 2 {
            return Err(format!("invalid delta csv line {}: {line}", line_no + 1));
        }
        let address = normalize_address(parts[0])?;
        let delta = parts[1]
            .parse::<i128>()
            .map_err(|err| format!("invalid delta on line {}: {err}", line_no + 1))?;
        *merged.entry(address).or_insert(0) += delta;
    }

    let mut deltas = Vec::new();
    for (address, delta) in merged {
        if delta != 0 {
            deltas.push(Delta { address, delta });
        }
    }
    Ok(deltas)
}

pub fn write_state(path: &Path, state: &StoredState) -> Result<(), String> {
    let mut lines = Vec::new();
    lines.push(format!("state_root={}", state.state_root));
    lines.push(format!("srs_max_degree={}", state.srs_max_degree));
    lines.push(format!("alpha={}", scalar_to_hex(&state.alpha)?));
    lines.push(format!(
        "reserve_addresses={}",
        write_string_vec_csv(&state.reserve_addresses)
    ));
    lines.push(format!(
        "reserve_balances={}",
        state.reserve_balances
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    ));
    lines.push(format!(
        "masked_polynomial_coeffs={}",
        write_scalar_vec_csv(&state.masked_polynomial_coeffs)?
    ));
    lines.push(format!("accumulator_hex={}", state.accumulator_hex));
    lines.push(format!("balance_total={}", state.balance_total));
    lines.push(format!("balance_blind={}", scalar_to_hex(&state.balance_blind)?));
    lines.push(format!("balance_commitment_hex={}", state.balance_commitment_hex));
    fs::write(path, lines.join("\n")).map_err(|err| format!("write {}: {err}", path.display()))
}

pub fn read_state(path: &Path) -> Result<StoredState, String> {
    let kv = read_key_value_file(path)?;
    let state_root = req_string(&kv, "state_root")?;
    let srs_max_degree = req_usize(&kv, "srs_max_degree")?;
    let alpha = req_scalar(&kv, "alpha")?;
    let reserve_addresses = req_csv_strings(&kv, "reserve_addresses")?;
    let reserve_balances = req_csv_i128(&kv, "reserve_balances")?;
    let masked_polynomial_coeffs = req_scalar_vec(&kv, "masked_polynomial_coeffs")?;
    let accumulator_hex = req_string(&kv, "accumulator_hex")?;
    let balance_total = req_i128(&kv, "balance_total")?;
    let balance_blind = req_scalar(&kv, "balance_blind")?;
    let balance_commitment_hex = req_string(&kv, "balance_commitment_hex")?;

    if reserve_addresses.len() != reserve_balances.len() {
        return Err("reserve_addresses and reserve_balances length mismatch".to_string());
    }

    Ok(StoredState {
        state_root,
        srs_max_degree,
        alpha,
        reserve_addresses,
        reserve_balances,
        masked_polynomial_coeffs,
        accumulator_hex,
        balance_total,
        balance_blind,
        balance_commitment_hex,
    })
}

pub fn write_proof(path: &Path, proof: &StoredProof) -> Result<(), String> {
    let mut lines = Vec::new();
    lines.push(format!("old_state_root={}", proof.old_state_root));
    lines.push(format!("new_state_root={}", proof.new_state_root));
    lines.push(format!("c_u_hex={}", proof.c_u_hex));
    lines.push(format!("c_y_hex={}", proof.c_y_hex));
    lines.push(format!("c_d_hex={}", proof.c_d_hex));
    lines.push(format!("eval_proof_hex={}", proof.eval_proof_hex));
    lines.push(format!("d_value={}", proof.d_value));
    lines.push(format!("r_u={}", scalar_to_hex(&proof.r_u)?));
    lines.push(format!("rho_y={}", scalar_to_hex(&proof.rho_y)?));
    lines.push(format!("r_d={}", scalar_to_hex(&proof.r_d)?));
    lines.push(format!("y_values={}", write_scalar_vec_csv(&proof.y_values)?));
    lines.push(format!("u_values={}", write_u8_vec_csv(&proof.u_values)));
    lines.push(format!("z_values={}", write_scalar_vec_csv(&proof.z_values)?));
    lines.push(format!("w_values={}", write_scalar_vec_csv(&proof.w_values)?));
    lines.push(format!("gate_count={}", proof.gate_count));
    lines.push(format!("transcript_hex={}", proof.transcript_hex));
    lines.push(format!("bp_proof_hex={}", proof.bp_proof_hex));
    lines.push(format!("bp_commitments_hex={}", proof.bp_commitments_hex));
    lines.push(format!("link_proof_hex={}", proof.link_proof_hex));
    fs::write(path, lines.join("\n")).map_err(|err| format!("write {}: {err}", path.display()))
}

pub fn write_init_proof(path: &Path, proof: &StoredInitProof) -> Result<(), String> {
    let mut lines = Vec::new();
    lines.push(format!("scheme={}", proof.scheme));
    lines.push(format!("mode={}", proof.mode));
    lines.push(format!("chain_id={}", proof.chain_id));
    lines.push(format!("state_root={}", proof.state_root));
    lines.push(format!("session_id={}", proof.session_id));
    lines.push(format!("accumulator_hex={}", proof.accumulator_hex));
    lines.push(format!(
        "balance_commitment_hex={}",
        proof.balance_commitment_hex
    ));
    lines.push(format!("init_salt={}", scalar_to_hex(&proof.init_salt)?));
    lines.push(format!("init_digest_hex={}", proof.init_digest_hex));
    lines.push(format!(
        "ownership_artifact_digest_hex={}",
        proof.ownership_artifact_digest_hex
    ));
    lines.push(format!(
        "chain_balance_artifact_digest_hex={}",
        proof.chain_balance_artifact_digest_hex
    ));
    lines.push(format!("reserve_count={}", proof.reserve_count));
    lines.push(format!("zeta={}", scalar_to_hex(&proof.zeta)?));
    lines.push(format!("p_zeta={}", scalar_to_hex(&proof.p_zeta)?));
    lines.push(format!(
        "product_zeta={}",
        scalar_to_hex(&proof.product_zeta)?
    ));
    lines.push(format!("balance_total={}", proof.balance_total));
    lines.push(format!(
        "balance_blind={}",
        scalar_to_hex(&proof.balance_blind)?
    ));
    lines.push(format!("chain_proof_hex={}", proof.chain_proof_hex));
    lines.push(format!("alg_proof_hex={}", proof.alg_proof_hex));
    lines.push(format!("transcript_hex={}", proof.transcript_hex));
    lines.push(format!("srs_hash_hex={}", proof.srs_hash_hex));
    fs::write(path, lines.join("\n")).map_err(|err| format!("write {}: {err}", path.display()))
}

pub fn write_init(path: &Path, proof: &StoredInitProof) -> Result<(), String> {
    write_init_proof(path, proof)
}

pub fn read_init_proof(path: &Path) -> Result<StoredInitProof, String> {
    let kv = read_key_value_file(path)?;
    Ok(StoredInitProof {
        scheme: req_string(&kv, "scheme")?,
        mode: req_string(&kv, "mode")?,
        chain_id: kv.get("chain_id").cloned().unwrap_or_else(|| "mock-chain".to_string()),
        state_root: req_string(&kv, "state_root")?,
        session_id: kv
            .get("session_id")
            .cloned()
            .unwrap_or_else(|| "legacy-init-session".to_string()),
        accumulator_hex: req_string(&kv, "accumulator_hex")?,
        balance_commitment_hex: req_string(&kv, "balance_commitment_hex")?,
        init_salt: req_scalar(&kv, "init_salt")?,
        init_digest_hex: req_string(&kv, "init_digest_hex")?,
        ownership_artifact_digest_hex: kv
            .get("ownership_artifact_digest_hex")
            .cloned()
            .unwrap_or_default(),
        chain_balance_artifact_digest_hex: kv
            .get("chain_balance_artifact_digest_hex")
            .cloned()
            .unwrap_or_default(),
        reserve_count: req_usize(&kv, "reserve_count")?,
        zeta: req_scalar(&kv, "zeta")?,
        p_zeta: req_scalar(&kv, "p_zeta")?,
        product_zeta: req_scalar(&kv, "product_zeta")?,
        balance_total: req_i128(&kv, "balance_total")?,
        balance_blind: req_scalar(&kv, "balance_blind")?,
        chain_proof_hex: kv.get("chain_proof_hex").cloned().unwrap_or_default(),
        alg_proof_hex: kv.get("alg_proof_hex").cloned().unwrap_or_default(),
        transcript_hex: req_string(&kv, "transcript_hex")?,
        srs_hash_hex: req_string(&kv, "srs_hash_hex")?,
    })
}

pub fn read_init(path: &Path) -> Result<StoredInitProof, String> {
    read_init_proof(path)
}

pub fn read_proof(path: &Path) -> Result<StoredProof, String> {
    let kv = read_key_value_file(path)?;
    Ok(StoredProof {
        old_state_root: req_string(&kv, "old_state_root")?,
        new_state_root: req_string(&kv, "new_state_root")?,
        c_u_hex: req_string(&kv, "c_u_hex")?,
        c_y_hex: req_string(&kv, "c_y_hex")?,
        c_d_hex: req_string(&kv, "c_d_hex")?,
        eval_proof_hex: req_string(&kv, "eval_proof_hex")?,
        d_value: req_i128(&kv, "d_value")?,
        r_u: req_scalar(&kv, "r_u")?,
        rho_y: req_scalar(&kv, "rho_y")?,
        r_d: req_scalar(&kv, "r_d")?,
        y_values: req_scalar_vec(&kv, "y_values")?,
        u_values: req_u8_vec(&kv, "u_values")?,
        z_values: req_scalar_vec(&kv, "z_values")?,
        w_values: req_scalar_vec(&kv, "w_values")?,
        gate_count: req_usize(&kv, "gate_count")?,
        transcript_hex: req_string(&kv, "transcript_hex")?,
        bp_proof_hex: req_string(&kv, "bp_proof_hex")?,
        bp_commitments_hex: req_string(&kv, "bp_commitments_hex")?,
        link_proof_hex: req_string(&kv, "link_proof_hex")?,
    })
}

pub fn write_parallel_state(path: &Path, state: &StoredParallelState) -> Result<(), String> {
    let mut lines = Vec::new();
    lines.push(format!("state_root={}", state.state_root));
    lines.push(format!("srs_max_degree={}", state.srs_max_degree));
    lines.push(format!("shard_count={}", state.shards.len()));
    lines.push(format!(
        "shard_ids={}",
        state
            .shards
            .iter()
            .map(|shard| shard.shard_id.to_string())
            .collect::<Vec<_>>()
            .join(",")
    ));
    lines.push(format!(
        "shard_alphas={}",
        write_scalar_vec_csv(&state.shards.iter().map(|shard| shard.alpha).collect::<Vec<_>>())?
    ));
    lines.push(format!(
        "shard_reserve_addresses={}",
        state
            .shards
            .iter()
            .map(|shard| write_string_vec_csv(&shard.reserve_addresses))
            .collect::<Vec<_>>()
            .join("||")
    ));
    lines.push(format!(
        "shard_reserve_balances={}",
        state
            .shards
            .iter()
            .map(|shard| {
                shard
                    .reserve_balances
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .collect::<Vec<_>>()
            .join("||")
    ));
    lines.push(format!(
        "shard_masked_polynomial_coeffs={}",
        state
            .shards
            .iter()
            .map(|shard| write_scalar_vec_csv(&shard.masked_polynomial_coeffs))
            .collect::<Result<Vec<_>, _>>()?
            .join("||")
    ));
    lines.push(format!(
        "shard_accumulator_hexes={}",
        state
            .shards
            .iter()
            .map(|shard| shard.accumulator_hex.clone())
            .collect::<Vec<_>>()
            .join(",")
    ));
    lines.push(format!(
        "shard_balance_totals={}",
        state
            .shards
            .iter()
            .map(|shard| shard.balance_total.to_string())
            .collect::<Vec<_>>()
            .join(",")
    ));
    lines.push(format!(
        "shard_balance_blinds={}",
        write_scalar_vec_csv(&state.shards.iter().map(|shard| shard.balance_blind).collect::<Vec<_>>())?
    ));
    lines.push(format!(
        "shard_balance_commitment_hexes={}",
        state
            .shards
            .iter()
            .map(|shard| shard.balance_commitment_hex.clone())
            .collect::<Vec<_>>()
            .join(",")
    ));
    lines.push(format!("balance_total={}", state.balance_total));
    lines.push(format!("balance_blind={}", scalar_to_hex(&state.balance_blind)?));
    lines.push(format!("balance_commitment_hex={}", state.balance_commitment_hex));
    fs::write(path, lines.join("\n")).map_err(|err| format!("write {}: {err}", path.display()))
}

pub fn read_parallel_state(path: &Path) -> Result<StoredParallelState, String> {
    let kv = read_key_value_file(path)?;
    let state_root = req_string(&kv, "state_root")?;
    let srs_max_degree = req_usize(&kv, "srs_max_degree")?;
    let shard_count = req_usize(&kv, "shard_count")?;
    let shard_ids = req_csv_usize(&kv, "shard_ids")?;
    let shard_alphas = req_scalar_vec(&kv, "shard_alphas")?;
    let shard_addresses = req_sharded_strings(&kv, "shard_reserve_addresses")?;
    let shard_balances = req_sharded_i128(&kv, "shard_reserve_balances")?;
    let shard_coeffs = req_sharded_scalars(&kv, "shard_masked_polynomial_coeffs")?;
    let shard_accumulators = req_csv_strings(&kv, "shard_accumulator_hexes")?;
    let shard_balance_totals = req_csv_i128(&kv, "shard_balance_totals")?;
    let shard_balance_blinds = req_scalar_vec(&kv, "shard_balance_blinds")?;
    let shard_balance_commitments = req_csv_strings(&kv, "shard_balance_commitment_hexes")?;

    if shard_ids.len() != shard_count
        || shard_alphas.len() != shard_count
        || shard_addresses.len() != shard_count
        || shard_balances.len() != shard_count
        || shard_coeffs.len() != shard_count
        || shard_accumulators.len() != shard_count
        || shard_balance_totals.len() != shard_count
        || shard_balance_blinds.len() != shard_count
        || shard_balance_commitments.len() != shard_count
    {
        return Err("parallel state shard vector length mismatch".to_string());
    }

    let mut shards = Vec::with_capacity(shard_count);
    for index in 0..shard_count {
        if shard_addresses[index].len() != shard_balances[index].len() {
            return Err(format!("parallel state shard {index} address/balance length mismatch"));
        }
        shards.push(StoredParallelShardState {
            shard_id: shard_ids[index],
            alpha: shard_alphas[index],
            reserve_addresses: shard_addresses[index].clone(),
            reserve_balances: shard_balances[index].clone(),
            masked_polynomial_coeffs: shard_coeffs[index].clone(),
            accumulator_hex: shard_accumulators[index].clone(),
            balance_total: shard_balance_totals[index],
            balance_blind: shard_balance_blinds[index],
            balance_commitment_hex: shard_balance_commitments[index].clone(),
        });
    }

    Ok(StoredParallelState {
        state_root,
        srs_max_degree,
        shards,
        balance_total: req_i128(&kv, "balance_total")?,
        balance_blind: req_scalar(&kv, "balance_blind")?,
        balance_commitment_hex: req_string(&kv, "balance_commitment_hex")?,
    })
}

pub fn write_parallel_init(
    path: &Path,
    proof: &StoredParallelInitProof,
) -> Result<(), String> {
    let mut lines = Vec::new();
    lines.push(format!("state_root={}", proof.state_root));
    lines.push(format!("shard_count={}", proof.shard_proofs.len()));
    lines.push(format!(
        "shard_init_proofs_hex={}",
        proof
            .shard_proofs
            .iter()
            .map(encode_stored_init_proof)
            .collect::<Result<Vec<_>, _>>()?
            .join("||")
    ));
    lines.push(format!("balance_total={}", proof.balance_total));
    lines.push(format!("balance_blind={}", scalar_to_hex(&proof.balance_blind)?));
    lines.push(format!("balance_commitment_hex={}", proof.balance_commitment_hex));
    lines.push(format!("transcript_hex={}", proof.transcript_hex));
    fs::write(path, lines.join("\n")).map_err(|err| format!("write {}: {err}", path.display()))
}

pub fn read_parallel_init(path: &Path) -> Result<StoredParallelInitProof, String> {
    let kv = read_key_value_file(path)?;
    let shard_count = req_usize(&kv, "shard_count")?;
    let encoded = split_shards(&req_string(&kv, "shard_init_proofs_hex")?);
    if encoded.len() != shard_count {
        return Err("parallel init proof shard vector length mismatch".to_string());
    }
    let shard_proofs = encoded
        .iter()
        .map(|item| decode_stored_init_proof(item))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(StoredParallelInitProof {
        state_root: req_string(&kv, "state_root")?,
        shard_proofs,
        balance_total: req_i128(&kv, "balance_total")?,
        balance_blind: req_scalar(&kv, "balance_blind")?,
        balance_commitment_hex: req_string(&kv, "balance_commitment_hex")?,
        transcript_hex: req_string(&kv, "transcript_hex")?,
    })
}

pub fn write_parallel_proof(path: &Path, proof: &StoredParallelProof) -> Result<(), String> {
    let mut lines = Vec::new();
    lines.push(format!("old_state_root={}", proof.old_state_root));
    lines.push(format!("new_state_root={}", proof.new_state_root));
    lines.push(format!("shard_count={}", proof.shard_proofs.len()));
    lines.push(format!(
        "shard_ids={}",
        proof
            .shard_proofs
            .iter()
            .map(|shard| shard.shard_id.to_string())
            .collect::<Vec<_>>()
            .join(",")
    ));
    lines.push(format!(
        "shard_proofs_hex={}",
        proof
            .shard_proofs
            .iter()
            .map(encode_parallel_shard_proof)
            .collect::<Result<Vec<_>, _>>()?
            .join("||")
    ));
    lines.push(format!("c_u_hex={}", proof.c_u_hex));
    lines.push(format!("c_d_hex={}", proof.c_d_hex));
    lines.push(format!("d_value={}", proof.d_value));
    lines.push(format!("r_u={}", scalar_to_hex(&proof.r_u)?));
    lines.push(format!("r_d={}", scalar_to_hex(&proof.r_d)?));
    lines.push(format!(
        "projection_bp_proof_hex={}",
        proof.projection_bp_proof_hex
    ));
    lines.push(format!(
        "projection_bp_commitments_hex={}",
        proof.projection_bp_commitments_hex
    ));
    lines.push(format!(
        "projection_link_proof_hex={}",
        proof.projection_link_proof_hex
    ));
    lines.push(format!("transcript_hex={}", proof.transcript_hex));
    fs::write(path, lines.join("\n")).map_err(|err| format!("write {}: {err}", path.display()))
}

pub fn read_parallel_proof(path: &Path) -> Result<StoredParallelProof, String> {
    let kv = read_key_value_file(path)?;
    let shard_count = req_usize(&kv, "shard_count")?;
    let shard_ids = req_csv_usize(&kv, "shard_ids")?;
    let shard_proofs = req_string(&kv, "shard_proofs_hex")?;
    let encoded_proofs = split_shards(&shard_proofs);
    if shard_ids.len() != shard_count || encoded_proofs.len() != shard_count {
        return Err("parallel proof shard vector length mismatch".to_string());
    }

    let mut proofs = Vec::with_capacity(shard_count);
    for (shard_id, encoded) in shard_ids.into_iter().zip(encoded_proofs) {
        let mut proof = decode_parallel_shard_proof(&encoded)?;
        proof.shard_id = shard_id;
        proofs.push(proof);
    }

    Ok(StoredParallelProof {
        old_state_root: req_string(&kv, "old_state_root")?,
        new_state_root: req_string(&kv, "new_state_root")?,
        shard_proofs: proofs,
        c_u_hex: req_string(&kv, "c_u_hex")?,
        c_d_hex: req_string(&kv, "c_d_hex")?,
        d_value: req_i128(&kv, "d_value")?,
        r_u: req_scalar(&kv, "r_u")?,
        r_d: req_scalar(&kv, "r_d")?,
        projection_bp_proof_hex: req_string(&kv, "projection_bp_proof_hex")?,
        projection_bp_commitments_hex: req_string(&kv, "projection_bp_commitments_hex")?,
        projection_link_proof_hex: req_string(&kv, "projection_link_proof_hex")?,
        transcript_hex: req_string(&kv, "transcript_hex")?,
    })
}

pub fn write_smt_state(path: &Path, state: &StoredSmtState) -> Result<(), String> {
    let mut lines = Vec::new();
    lines.push(format!("state_root={}", state.state_root));
    lines.push(format!("smt_root_hex={}", state.smt_root_hex));
    lines.push(format!("depth={}", state.depth));
    lines.push(format!("balance_total={}", state.balance_total));
    lines.push(format!("balance_blind={}", scalar_to_hex(&state.balance_blind)?));
    lines.push(format!("balance_commitment_hex={}", state.balance_commitment_hex));
    let leaf_addresses = state
        .leaves
        .iter()
        .map(|leaf| leaf.address.clone())
        .collect::<Vec<_>>();
    let leaf_balances = state
        .leaves
        .iter()
        .map(|leaf| leaf.balance.to_string())
        .collect::<Vec<_>>();
    let leaf_salts = state
        .leaves
        .iter()
        .map(|leaf| leaf.salt_hex.clone())
        .collect::<Vec<_>>();
    lines.push(format!("leaf_addresses={}", write_string_vec_csv(&leaf_addresses)));
    lines.push(format!("leaf_balances={}", leaf_balances.join(",")));
    lines.push(format!("leaf_salts={}", leaf_salts.join(",")));
    fs::write(path, lines.join("\n")).map_err(|err| format!("write {}: {err}", path.display()))
}

pub fn read_smt_state(path: &Path) -> Result<StoredSmtState, String> {
    let kv = read_key_value_file(path)?;
    let addresses = req_csv_strings(&kv, "leaf_addresses")?;
    let balances = req_csv_i128(&kv, "leaf_balances")?;
    let salts = req_csv_strings(&kv, "leaf_salts")?;
    if addresses.len() != balances.len() || addresses.len() != salts.len() {
        return Err("SMT leaf vectors length mismatch".to_string());
    }

    let mut leaves = Vec::with_capacity(addresses.len());
    for ((address, balance), salt_hex) in addresses.into_iter().zip(balances).zip(salts) {
        leaves.push(SmtLeafRecord {
            address,
            balance,
            salt_hex,
        });
    }

    Ok(StoredSmtState {
        state_root: req_string(&kv, "state_root")?,
        smt_root_hex: req_string(&kv, "smt_root_hex")?,
        depth: req_usize(&kv, "depth")?,
        balance_total: req_i128(&kv, "balance_total")?,
        balance_blind: req_scalar(&kv, "balance_blind")?,
        balance_commitment_hex: req_string(&kv, "balance_commitment_hex")?,
        leaves,
    })
}

pub fn write_smt_proof(path: &Path, proof: &StoredSmtProof) -> Result<(), String> {
    let mut lines = Vec::new();
    lines.push(format!("scheme={}", proof.scheme));
    lines.push(format!("mode={}", proof.mode));
    lines.push(format!("old_state_root={}", proof.old_state_root));
    lines.push(format!("new_state_root={}", proof.new_state_root));
    lines.push(format!("old_smt_root_hex={}", proof.old_smt_root_hex));
    lines.push(format!("new_smt_root_hex={}", proof.new_smt_root_hex));
    lines.push(format!("aggregate_delta={}", proof.aggregate_delta));
    lines.push(format!(
        "balance_blind_delta={}",
        scalar_to_hex(&proof.balance_blind_delta)?
    ));
    lines.push(format!(
        "old_balance_commitment_hex={}",
        proof.old_balance_commitment_hex
    ));
    lines.push(format!(
        "new_balance_commitment_hex={}",
        proof.new_balance_commitment_hex
    ));
    lines.push(format!("proof_digest_hex={}", proof.proof_digest_hex));
    lines.push(format!("witness_hex={}", proof.witness_hex));
    lines.push(format!(
        "touched_addresses={}",
        write_string_vec_csv(&proof.touched_addresses)
    ));
    lines.push(format!(
        "membership_flags={}",
        write_u8_vec_csv(&proof.membership_flags)
    ));
    lines.push(format!("sp1_proof_hex={}", proof.sp1_proof_hex));
    lines.push(format!("sp1_vk_hex={}", proof.sp1_vk_hex));
    lines.push(format!(
        "sp1_public_values_hex={}",
        proof.sp1_public_values_hex
    ));
    fs::write(path, lines.join("\n")).map_err(|err| format!("write {}: {err}", path.display()))
}

pub fn read_smt_proof(path: &Path) -> Result<StoredSmtProof, String> {
    let kv = read_key_value_file(path)?;
    Ok(StoredSmtProof {
        scheme: req_string(&kv, "scheme")?,
        mode: req_string(&kv, "mode")?,
        old_state_root: req_string(&kv, "old_state_root")?,
        new_state_root: req_string(&kv, "new_state_root")?,
        old_smt_root_hex: req_string(&kv, "old_smt_root_hex")?,
        new_smt_root_hex: req_string(&kv, "new_smt_root_hex")?,
        aggregate_delta: req_i128(&kv, "aggregate_delta")?,
        balance_blind_delta: req_scalar(&kv, "balance_blind_delta")?,
        old_balance_commitment_hex: req_string(&kv, "old_balance_commitment_hex")?,
        new_balance_commitment_hex: req_string(&kv, "new_balance_commitment_hex")?,
        proof_digest_hex: req_string(&kv, "proof_digest_hex")?,
        witness_hex: req_string(&kv, "witness_hex")?,
        touched_addresses: req_csv_strings(&kv, "touched_addresses")?,
        membership_flags: req_u8_vec(&kv, "membership_flags")?,
        sp1_proof_hex: kv.get("sp1_proof_hex").cloned().unwrap_or_default(),
        sp1_vk_hex: kv.get("sp1_vk_hex").cloned().unwrap_or_default(),
        sp1_public_values_hex: kv
            .get("sp1_public_values_hex")
            .cloned()
            .unwrap_or_default(),
    })
}

pub fn write_srs(
    path: &Path,
    max_degree: usize,
    tau_g1_powers: &[G1Affine],
    tau_g2_powers: &[G2Affine],
) -> Result<(), String> {
    let mut file = fs::File::create(path).map_err(|err| format!("create {}: {err}", path.display()))?;
    write_srs_binary(&mut file, max_degree, tau_g1_powers, tau_g2_powers)
}

pub fn read_srs(path: &Path) -> Result<(usize, Vec<G1Affine>, Vec<G2Affine>), String> {
    let mut file = fs::File::open(path).map_err(|err| format!("open {}: {err}", path.display()))?;
    read_srs_binary(&mut file)
}

pub fn read_srs_g1_prefix(path: &Path, needed_g1_len: usize) -> Result<(usize, Vec<G1Affine>), String> {
    let mut file = fs::File::open(path).map_err(|err| format!("open {}: {err}", path.display()))?;
    read_srs_g1_prefix_binary(&mut file, needed_g1_len)
}

pub fn read_srs_prefix(
    path: &Path,
    needed_g1_len: usize,
    needed_g2_len: usize,
) -> Result<(usize, Vec<G1Affine>, Vec<G2Affine>), String> {
    let mut file = fs::File::open(path).map_err(|err| format!("open {}: {err}", path.display()))?;
    read_srs_prefix_binary(&mut file, needed_g1_len, needed_g2_len)
}

fn read_key_value_file(path: &Path) -> Result<BTreeMap<String, String>, String> {
    let input = fs::read_to_string(path).map_err(|err| format!("read {}: {err}", path.display()))?;
    let mut kv = BTreeMap::<String, String>::new();
    for (line_no, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("invalid line {} in {}: {line}", line_no + 1, path.display()));
        };
        kv.insert(key.to_string(), value.to_string());
    }
    Ok(kv)
}

fn req_string(kv: &BTreeMap<String, String>, key: &str) -> Result<String, String> {
    kv.get(key)
        .cloned()
        .ok_or_else(|| format!("missing key {key}"))
}

fn req_usize(kv: &BTreeMap<String, String>, key: &str) -> Result<usize, String> {
    req_string(kv, key)?
        .parse::<usize>()
        .map_err(|err| format!("invalid usize for {key}: {err}"))
}

fn req_i128(kv: &BTreeMap<String, String>, key: &str) -> Result<i128, String> {
    req_string(kv, key)?
        .parse::<i128>()
        .map_err(|err| format!("invalid i128 for {key}: {err}"))
}

fn req_csv_strings(kv: &BTreeMap<String, String>, key: &str) -> Result<Vec<String>, String> {
    let raw = req_string(kv, key)?;
    if raw.is_empty() {
        Ok(Vec::new())
    } else {
        Ok(raw.split(',').map(|value| value.to_string()).collect())
    }
}

fn req_csv_i128(kv: &BTreeMap<String, String>, key: &str) -> Result<Vec<i128>, String> {
    let raw = req_string(kv, key)?;
    if raw.is_empty() {
        Ok(Vec::new())
    } else {
        raw.split(',')
            .map(|item| item.parse::<i128>().map_err(|err| format!("invalid {key}: {err}")))
            .collect()
    }
}

fn req_csv_usize(kv: &BTreeMap<String, String>, key: &str) -> Result<Vec<usize>, String> {
    let raw = req_string(kv, key)?;
    if raw.is_empty() {
        Ok(Vec::new())
    } else {
        raw.split(',')
            .map(|item| item.parse::<usize>().map_err(|err| format!("invalid {key}: {err}")))
            .collect()
    }
}

fn req_sharded_strings(kv: &BTreeMap<String, String>, key: &str) -> Result<Vec<Vec<String>>, String> {
    let raw = req_string(kv, key)?;
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    raw.split("||")
        .map(|chunk| {
            if chunk.is_empty() {
                Ok(Vec::new())
            } else {
                Ok(chunk.split(',').map(|value| value.to_string()).collect())
            }
        })
        .collect()
}

fn req_sharded_i128(kv: &BTreeMap<String, String>, key: &str) -> Result<Vec<Vec<i128>>, String> {
    let raw = req_string(kv, key)?;
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    raw.split("||")
        .map(|chunk| {
            if chunk.is_empty() {
                Ok(Vec::new())
            } else {
                chunk
                    .split(',')
                    .map(|item| item.parse::<i128>().map_err(|err| format!("invalid {key}: {err}")))
                    .collect()
            }
        })
        .collect()
}

fn req_sharded_scalars(kv: &BTreeMap<String, String>, key: &str) -> Result<Vec<Vec<Fr>>, String> {
    let raw = req_string(kv, key)?;
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    raw.split("||")
        .map(|chunk| read_scalar_vec_csv(chunk))
        .collect()
}

fn split_shards(raw: &str) -> Vec<String> {
    if raw.is_empty() {
        Vec::new()
    } else {
        raw.split("||").map(|value| value.to_string()).collect()
    }
}

fn encode_parallel_shard_proof(proof: &StoredParallelShardProof) -> Result<String, String> {
    let mut lines = Vec::new();
    lines.push(format!("shard_id={}", proof.shard_id));
    lines.push(format!("c_u_hex={}", proof.c_u_hex));
    lines.push(format!("c_y_hex={}", proof.c_y_hex));
    lines.push(format!("eval_proof_hex={}", proof.eval_proof_hex));
    lines.push(format!("r_u={}", scalar_to_hex(&proof.r_u)?));
    lines.push(format!("rho_y={}", scalar_to_hex(&proof.rho_y)?));
    lines.push(format!("d_value={}", proof.d_value));
    lines.push(format!("gate_count={}", proof.gate_count));
    lines.push(format!("bp_proof_hex={}", proof.bp_proof_hex));
    lines.push(format!("bp_commitments_hex={}", proof.bp_commitments_hex));
    lines.push(format!("link_proof_hex={}", proof.link_proof_hex));
    Ok(lines.join(";"))
}

fn decode_parallel_shard_proof(raw: &str) -> Result<StoredParallelShardProof, String> {
    let mut kv = BTreeMap::<String, String>::new();
    for item in raw.split(';') {
        if item.is_empty() {
            continue;
        }
        let Some((key, value)) = item.split_once('=') else {
            return Err(format!("invalid encoded parallel shard proof segment: {item}"));
        };
        kv.insert(key.to_string(), value.to_string());
    }
    Ok(StoredParallelShardProof {
        shard_id: req_usize(&kv, "shard_id")?,
        c_u_hex: req_string(&kv, "c_u_hex")?,
        c_y_hex: req_string(&kv, "c_y_hex")?,
        eval_proof_hex: req_string(&kv, "eval_proof_hex")?,
        r_u: req_scalar(&kv, "r_u")?,
        rho_y: req_scalar(&kv, "rho_y")?,
        d_value: req_i128(&kv, "d_value")?,
        gate_count: req_usize(&kv, "gate_count")?,
        bp_proof_hex: req_string(&kv, "bp_proof_hex")?,
        bp_commitments_hex: req_string(&kv, "bp_commitments_hex")?,
        link_proof_hex: req_string(&kv, "link_proof_hex")?,
    })
}

fn encode_stored_init_proof(proof: &StoredInitProof) -> Result<String, String> {
    let mut lines = Vec::new();
    lines.push(format!("scheme={}", proof.scheme));
    lines.push(format!("mode={}", proof.mode));
    lines.push(format!("chain_id={}", proof.chain_id));
    lines.push(format!("state_root={}", proof.state_root));
    lines.push(format!("session_id={}", proof.session_id));
    lines.push(format!("accumulator_hex={}", proof.accumulator_hex));
    lines.push(format!("balance_commitment_hex={}", proof.balance_commitment_hex));
    lines.push(format!("init_salt={}", scalar_to_hex(&proof.init_salt)?));
    lines.push(format!("init_digest_hex={}", proof.init_digest_hex));
    lines.push(format!(
        "ownership_artifact_digest_hex={}",
        proof.ownership_artifact_digest_hex
    ));
    lines.push(format!(
        "chain_balance_artifact_digest_hex={}",
        proof.chain_balance_artifact_digest_hex
    ));
    lines.push(format!("reserve_count={}", proof.reserve_count));
    lines.push(format!("zeta={}", scalar_to_hex(&proof.zeta)?));
    lines.push(format!("p_zeta={}", scalar_to_hex(&proof.p_zeta)?));
    lines.push(format!("product_zeta={}", scalar_to_hex(&proof.product_zeta)?));
    lines.push(format!("balance_total={}", proof.balance_total));
    lines.push(format!("balance_blind={}", scalar_to_hex(&proof.balance_blind)?));
    lines.push(format!("chain_proof_hex={}", proof.chain_proof_hex));
    lines.push(format!("alg_proof_hex={}", proof.alg_proof_hex));
    lines.push(format!("transcript_hex={}", proof.transcript_hex));
    lines.push(format!("srs_hash_hex={}", proof.srs_hash_hex));
    Ok(lines.join(";"))
}

fn decode_stored_init_proof(raw: &str) -> Result<StoredInitProof, String> {
    let mut kv = BTreeMap::<String, String>::new();
    for item in raw.split(';') {
        if item.is_empty() {
            continue;
        }
        let Some((key, value)) = item.split_once('=') else {
            return Err(format!("invalid encoded init proof segment: {item}"));
        };
        kv.insert(key.to_string(), value.to_string());
    }

    Ok(StoredInitProof {
        scheme: req_string(&kv, "scheme")?,
        mode: req_string(&kv, "mode")?,
        chain_id: req_string(&kv, "chain_id")?,
        state_root: req_string(&kv, "state_root")?,
        session_id: req_string(&kv, "session_id")?,
        accumulator_hex: req_string(&kv, "accumulator_hex")?,
        balance_commitment_hex: req_string(&kv, "balance_commitment_hex")?,
        init_salt: req_scalar(&kv, "init_salt")?,
        init_digest_hex: req_string(&kv, "init_digest_hex")?,
        ownership_artifact_digest_hex: req_string(&kv, "ownership_artifact_digest_hex")?,
        chain_balance_artifact_digest_hex: req_string(&kv, "chain_balance_artifact_digest_hex")?,
        reserve_count: req_usize(&kv, "reserve_count")?,
        zeta: req_scalar(&kv, "zeta")?,
        p_zeta: req_scalar(&kv, "p_zeta")?,
        product_zeta: req_scalar(&kv, "product_zeta")?,
        balance_total: req_i128(&kv, "balance_total")?,
        balance_blind: req_scalar(&kv, "balance_blind")?,
        chain_proof_hex: kv.get("chain_proof_hex").cloned().unwrap_or_default(),
        alg_proof_hex: kv.get("alg_proof_hex").cloned().unwrap_or_default(),
        transcript_hex: req_string(&kv, "transcript_hex")?,
        srs_hash_hex: req_string(&kv, "srs_hash_hex")?,
    })
}

fn req_scalar(kv: &BTreeMap<String, String>, key: &str) -> Result<Fr, String> {
    scalar_from_hex(&req_string(kv, key)?)
}

fn req_scalar_vec(kv: &BTreeMap<String, String>, key: &str) -> Result<Vec<Fr>, String> {
    read_scalar_vec_csv(&req_string(kv, key)?)
}

fn req_u8_vec(kv: &BTreeMap<String, String>, key: &str) -> Result<Vec<u8>, String> {
    read_u8_vec_csv(&req_string(kv, key)?)
}
