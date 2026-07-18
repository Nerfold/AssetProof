use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use ark_bls12_381::{Fr, G1Affine, G2Affine};

use crate::crypto::{
    hex_decode, hex_encode, read_scalar_vec_csv, read_srs_binary_with_hiding,
    read_srs_g1_prefix_binary, read_srs_prefix_binary, read_u8_vec_csv, scalar_from_hex,
    scalar_to_hex, write_scalar_vec_csv, write_srs_binary_with_hiding, write_string_vec_csv,
    write_u8_vec_csv,
};
use crate::encoding::normalize_address;
use crate::types::{
    Delta, InitReserveWitness, PublicState, ReserveEntry, SmtLeafRecord, SmtNodeRecord,
    StoredInitProof, StoredParallelInitProof, StoredParallelProof, StoredParallelShardProof,
    StoredParallelShardState, StoredParallelState, StoredProof, StoredSmtProof, StoredSmtState,
    StoredState,
};

pub fn read_reserve_csv(path: &Path) -> Result<Vec<ReserveEntry>, String> {
    let input =
        fs::read_to_string(path).map_err(|err| format!("read {}: {err}", path.display()))?;
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
    let input =
        fs::read_to_string(path).map_err(|err| format!("read {}: {err}", path.display()))?;
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
    let input =
        fs::read_to_string(path).map_err(|err| format!("read {}: {err}", path.display()))?;
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
        let total = merged.entry(address).or_insert(0);
        *total = total
            .checked_add(delta)
            .ok_or_else(|| format!("merged delta overflowed i128 on line {}", line_no + 1))?;
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
        state
            .reserve_balances
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
    lines.push(format!(
        "balance_blind={}",
        scalar_to_hex(&state.balance_blind)?
    ));
    lines.push(format!(
        "balance_commitment_hex={}",
        state.balance_commitment_hex
    ));
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

pub fn write_public_state(path: &Path, state: &PublicState) -> Result<(), String> {
    let mut lines = Vec::new();
    lines.push(format!("state_root={}", state.state_root));
    lines.push(format!("srs_max_degree={}", state.srs_max_degree));
    lines.push(format!("reserve_count={}", state.reserve_count));
    lines.push(format!("accumulator_hex={}", state.accumulator_hex));
    lines.push(format!(
        "balance_commitment_hex={}",
        state.balance_commitment_hex
    ));
    fs::write(path, lines.join("\n")).map_err(|err| format!("write {}: {err}", path.display()))
}

pub fn read_public_state(path: &Path) -> Result<PublicState, String> {
    let kv = read_key_value_file(path)?;
    Ok(PublicState {
        state_root: req_string(&kv, "state_root")?,
        srs_max_degree: req_usize(&kv, "srs_max_degree")?,
        reserve_count: req_usize(&kv, "reserve_count")?,
        accumulator_hex: req_string(&kv, "accumulator_hex")?,
        balance_commitment_hex: req_string(&kv, "balance_commitment_hex")?,
    })
}

pub fn write_proof(path: &Path, proof: &StoredProof) -> Result<(), String> {
    let bytes = encode_proof_binary(proof)?;
    fs::write(path, bytes).map_err(|err| format!("write {}: {err}", path.display()))
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
    lines.push(format!("c_shape_hex={}", proof.c_shape_hex));
    lines.push(format!("c_y_hex={}", proof.c_y_hex));
    lines.push(format!("reserve_count={}", proof.reserve_count));
    lines.push(format!("zeta={}", scalar_to_hex(&proof.zeta)?));
    lines.push(format!(
        "kzg_opening_proof_hex={}",
        proof.kzg_opening_proof_hex
    ));
    lines.push(format!("sp1_proof_hex={}", proof.sp1_proof_hex));
    lines.push(format!("sp1_vk_hex={}", proof.sp1_vk_hex));
    lines.push(format!(
        "sp1_public_values_hex={}",
        proof.sp1_public_values_hex
    ));
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
        chain_id: kv
            .get("chain_id")
            .cloned()
            .unwrap_or_else(|| "mock-chain".to_string()),
        state_root: req_string(&kv, "state_root")?,
        session_id: kv
            .get("session_id")
            .cloned()
            .unwrap_or_else(|| "legacy-init-session".to_string()),
        accumulator_hex: req_string(&kv, "accumulator_hex")?,
        balance_commitment_hex: req_string(&kv, "balance_commitment_hex")?,
        c_shape_hex: kv.get("c_shape_hex").cloned().unwrap_or_default(),
        c_y_hex: kv.get("c_y_hex").cloned().unwrap_or_default(),
        reserve_count: req_usize(&kv, "reserve_count")?,
        zeta: req_scalar(&kv, "zeta")?,
        kzg_opening_proof_hex: kv.get("kzg_opening_proof_hex").cloned().unwrap_or_default(),
        sp1_proof_hex: kv.get("sp1_proof_hex").cloned().unwrap_or_default(),
        sp1_vk_hex: kv.get("sp1_vk_hex").cloned().unwrap_or_default(),
        sp1_public_values_hex: kv.get("sp1_public_values_hex").cloned().unwrap_or_default(),
        transcript_hex: req_string(&kv, "transcript_hex")?,
        srs_hash_hex: req_string(&kv, "srs_hash_hex")?,
    })
}

pub fn read_init(path: &Path) -> Result<StoredInitProof, String> {
    read_init_proof(path)
}

pub fn read_proof(path: &Path) -> Result<StoredProof, String> {
    let bytes = fs::read(path).map_err(|err| format!("read {}: {err}", path.display()))?;
    decode_proof_binary(&bytes)
}

const UPDATE_PROOF_MAGIC: &[u8; 8] = b"DPOAUPD6";

pub fn encode_proof_binary(proof: &StoredProof) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    out.extend_from_slice(UPDATE_PROOF_MAGIC);
    put_bytes(&mut out, proof.old_state_root.as_bytes())?;
    put_bytes(&mut out, proof.new_state_root.as_bytes())?;
    put_hex(&mut out, &proof.delta_list_commitment_hex)?;
    put_hex(&mut out, &proof.c_u_hex)?;
    put_hex(&mut out, &proof.d_y_hex)?;
    put_hex(&mut out, &proof.c_d_hex)?;
    put_hex(&mut out, &proof.multi_zkopen_proof_hex)?;
    put_u64(&mut out, proof.gate_count as u64);
    put_hex(&mut out, &proof.transcript_hex)?;
    put_hex(&mut out, &proof.bp_proof_hex)?;
    put_bytes(&mut out, &proof.committed_input_link_ipa_proof)?;
    put_bytes(&mut out, &proof.projection_ipa_proof)?;
    put_bytes(&mut out, proof.balance_range_proof_hex.as_bytes())?;
    Ok(out)
}

fn decode_proof_binary(bytes: &[u8]) -> Result<StoredProof, String> {
    if !bytes.starts_with(UPDATE_PROOF_MAGIC) {
        return Err(
            "unsupported update proof format; regenerate the proof with the MultiZKOpen update protocol".to_string(),
        );
    }
    let mut input = BinaryReader::new(&bytes[UPDATE_PROOF_MAGIC.len()..]);
    let old_state_root = input.string()?;
    let new_state_root = input.string()?;
    let delta_list_commitment_hex = input.hex()?;
    let c_u_hex = input.hex()?;
    let d_y_hex = input.hex()?;
    let c_d_hex = input.hex()?;
    let multi_zkopen_proof_hex = input.hex()?;
    let gate_count = usize::try_from(input.u64()?)
        .map_err(|_| "update proof gate count does not fit usize".to_string())?;
    let transcript_hex = input.hex()?;
    let bp_proof_hex = input.hex()?;
    let committed_input_link_ipa_proof = input.bytes()?.to_vec();
    let projection_ipa_proof = input.bytes()?.to_vec();
    let balance_range_proof_hex = input.string()?;
    input.finish()?;
    Ok(StoredProof {
        old_state_root,
        new_state_root,
        delta_list_commitment_hex,
        c_u_hex,
        d_y_hex,
        c_d_hex,
        multi_zkopen_proof_hex,
        gate_count,
        transcript_hex,
        bp_proof_hex,
        committed_input_link_ipa_proof,
        projection_ipa_proof,
        balance_range_proof_hex,
    })
}

fn put_u32(out: &mut Vec<u8>, value: usize) -> Result<(), String> {
    let value = u32::try_from(value).map_err(|_| "proof field exceeds u32 length".to_string())?;
    out.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_bytes(out: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    put_u32(out, value.len())?;
    out.extend_from_slice(value);
    Ok(())
}

fn put_hex(out: &mut Vec<u8>, value: &str) -> Result<(), String> {
    put_bytes(out, &hex_decode(value)?)
}

struct BinaryReader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> BinaryReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| "update proof length overflow".to_string())?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or_else(|| "truncated update proof".to_string())?;
        self.offset = end;
        Ok(value)
    }

    fn u32(&mut self) -> Result<usize, String> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| "invalid update proof u32".to_string())?;
        Ok(u32::from_le_bytes(bytes) as usize)
    }

    fn u64(&mut self) -> Result<u64, String> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| "invalid update proof u64".to_string())?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn bytes(&mut self) -> Result<&'a [u8], String> {
        let len = self.u32()?;
        self.take(len)
    }

    fn string(&mut self) -> Result<String, String> {
        String::from_utf8(self.bytes()?.to_vec())
            .map_err(|_| "update proof contains invalid UTF-8".to_string())
    }

    fn hex(&mut self) -> Result<String, String> {
        Ok(hex_encode(self.bytes()?))
    }

    fn finish(&self) -> Result<(), String> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err("trailing bytes in update proof".to_string())
        }
    }
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
        write_scalar_vec_csv(
            &state
                .shards
                .iter()
                .map(|shard| shard.alpha)
                .collect::<Vec<_>>()
        )?
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
        write_scalar_vec_csv(
            &state
                .shards
                .iter()
                .map(|shard| shard.balance_blind)
                .collect::<Vec<_>>()
        )?
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
    lines.push(format!(
        "balance_blind={}",
        scalar_to_hex(&state.balance_blind)?
    ));
    lines.push(format!(
        "balance_commitment_hex={}",
        state.balance_commitment_hex
    ));
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
            return Err(format!(
                "parallel state shard {index} address/balance length mismatch"
            ));
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

pub fn write_parallel_init(path: &Path, proof: &StoredParallelInitProof) -> Result<(), String> {
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
    lines.push(format!(
        "balance_blind={}",
        scalar_to_hex(&proof.balance_blind)?
    ));
    lines.push(format!(
        "balance_commitment_hex={}",
        proof.balance_commitment_hex
    ));
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
        "projection_ipa_proof_hex={}",
        hex_encode(&proof.projection_ipa_proof)
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
        projection_ipa_proof: hex_decode(&req_string(&kv, "projection_ipa_proof_hex")?)?,
        transcript_hex: req_string(&kv, "transcript_hex")?,
    })
}

pub fn write_smt_state(path: &Path, state: &StoredSmtState) -> Result<(), String> {
    let mut lines = Vec::new();
    lines.push(format!("state_root={}", state.state_root));
    lines.push(format!("smt_root_hex={}", state.smt_root_hex));
    lines.push(format!("depth={}", state.depth));
    lines.push(format!("balance_total={}", state.balance_total));
    lines.push(format!(
        "balance_blind={}",
        scalar_to_hex(&state.balance_blind)?
    ));
    lines.push(format!(
        "balance_commitment_hex={}",
        state.balance_commitment_hex
    ));
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
    lines.push(format!(
        "leaf_addresses={}",
        write_string_vec_csv(&leaf_addresses)
    ));
    lines.push(format!("leaf_balances={}", leaf_balances.join(",")));
    lines.push(format!("leaf_salts={}", leaf_salts.join(",")));
    if !state.nodes.is_empty() {
        let nodes_path = path.with_extension("nodes.bin");
        write_smt_nodes_file(&nodes_path, &state.nodes)?;
        lines.push(format!("node_count={}", state.nodes.len()));
        lines.push(format!(
            "nodes_path={}",
            nodes_path
                .file_name()
                .and_then(|v| v.to_str())
                .unwrap_or("state.nodes.bin")
        ));
    }
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
    let (nodes, nodes_path) = if let Some(raw_path) = kv.get("nodes_path") {
        let nodes_path = path.with_extension("nodes.bin");
        let nodes = read_smt_nodes_file(&nodes_path)?;
        if let Some(expected) = kv.get("node_count") {
            let expected = expected
                .parse::<usize>()
                .map_err(|err| format!("invalid node_count: {err}"))?;
            if expected != nodes.len() {
                return Err("SMT node_count does not match nodes_path".to_string());
            }
        }
        (nodes, raw_path.clone())
    } else if let Some(raw) = kv.get("nodes_hex") {
        let nodes = decode_smt_nodes(raw)?;
        if let Some(expected) = kv.get("node_count") {
            let expected = expected
                .parse::<usize>()
                .map_err(|err| format!("invalid node_count: {err}"))?;
            if expected != nodes.len() {
                return Err("SMT node_count does not match nodes_hex".to_string());
            }
        }
        (nodes, String::new())
    } else {
        (Vec::new(), String::new())
    };

    Ok(StoredSmtState {
        state_root: req_string(&kv, "state_root")?,
        smt_root_hex: req_string(&kv, "smt_root_hex")?,
        depth: req_usize(&kv, "depth")?,
        balance_total: req_i128(&kv, "balance_total")?,
        balance_blind: req_scalar(&kv, "balance_blind")?,
        balance_commitment_hex: req_string(&kv, "balance_commitment_hex")?,
        leaves,
        nodes,
        nodes_path,
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
        sp1_public_values_hex: kv.get("sp1_public_values_hex").cloned().unwrap_or_default(),
    })
}

pub fn write_srs(
    path: &Path,
    max_degree: usize,
    tau_g1_powers: &[G1Affine],
    tau_g2_powers: &[G2Affine],
    hiding_tau_g1_powers: &[G1Affine],
) -> Result<(), String> {
    let mut file =
        fs::File::create(path).map_err(|err| format!("create {}: {err}", path.display()))?;
    write_srs_binary_with_hiding(
        &mut file,
        max_degree,
        tau_g1_powers,
        tau_g2_powers,
        hiding_tau_g1_powers,
    )
}

pub fn read_srs(
    path: &Path,
) -> Result<(usize, Vec<G1Affine>, Vec<G2Affine>, Vec<G1Affine>), String> {
    let mut file = fs::File::open(path).map_err(|err| format!("open {}: {err}", path.display()))?;
    read_srs_binary_with_hiding(&mut file)
}

pub fn read_srs_g1_prefix(
    path: &Path,
    needed_g1_len: usize,
) -> Result<(usize, Vec<G1Affine>), String> {
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
    let input =
        fs::read_to_string(path).map_err(|err| format!("read {}: {err}", path.display()))?;
    let mut kv = BTreeMap::<String, String>::new();
    for (line_no, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!(
                "invalid line {} in {}: {line}",
                line_no + 1,
                path.display()
            ));
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
            .map(|item| {
                item.parse::<i128>()
                    .map_err(|err| format!("invalid {key}: {err}"))
            })
            .collect()
    }
}

fn req_csv_usize(kv: &BTreeMap<String, String>, key: &str) -> Result<Vec<usize>, String> {
    let raw = req_string(kv, key)?;
    if raw.is_empty() {
        Ok(Vec::new())
    } else {
        raw.split(',')
            .map(|item| {
                item.parse::<usize>()
                    .map_err(|err| format!("invalid {key}: {err}"))
            })
            .collect()
    }
}

fn req_sharded_strings(
    kv: &BTreeMap<String, String>,
    key: &str,
) -> Result<Vec<Vec<String>>, String> {
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
                    .map(|item| {
                        item.parse::<i128>()
                            .map_err(|err| format!("invalid {key}: {err}"))
                    })
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

fn decode_smt_nodes(raw: &str) -> Result<Vec<SmtNodeRecord>, String> {
    let bytes = hex_decode(raw)?;
    decode_smt_nodes_bytes(&bytes)
}

fn write_smt_nodes_file(path: &Path, nodes: &[SmtNodeRecord]) -> Result<(), String> {
    let bytes = encode_smt_nodes_bytes(nodes)?;
    fs::write(path, bytes).map_err(|err| format!("write {}: {err}", path.display()))
}

fn read_smt_nodes_file(path: &Path) -> Result<Vec<SmtNodeRecord>, String> {
    let bytes = fs::read(path).map_err(|err| format!("read {}: {err}", path.display()))?;
    decode_smt_nodes_bytes(&bytes)
}

fn encode_smt_nodes_bytes(nodes: &[SmtNodeRecord]) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(8 + nodes.len() * 50);
    bytes.extend_from_slice(&(nodes.len() as u64).to_le_bytes());
    for node in nodes {
        if node.level > u16::MAX as usize {
            return Err(format!("SMT node level {} exceeds u16", node.level));
        }
        let hash = hex_decode(&node.hash_hex)?;
        if hash.len() != 32 {
            return Err(format!(
                "SMT node hash must be 32 bytes, got {}",
                hash.len()
            ));
        }
        bytes.extend_from_slice(&(node.level as u16).to_le_bytes());
        bytes.extend_from_slice(&node.index.to_le_bytes());
        bytes.extend_from_slice(&hash);
    }
    Ok(bytes)
}

fn decode_smt_nodes_bytes(bytes: &[u8]) -> Result<Vec<SmtNodeRecord>, String> {
    if bytes.len() < 8 {
        return Err("SMT nodes payload too short".to_string());
    }
    let mut cursor = 0usize;
    let mut count_bytes = [0u8; 8];
    count_bytes.copy_from_slice(&bytes[cursor..cursor + 8]);
    cursor += 8;
    let count = u64::from_le_bytes(count_bytes) as usize;
    let expected = 8 + count * 50;
    if bytes.len() != expected {
        return Err(format!(
            "SMT nodes payload length mismatch: expected {expected}, got {}",
            bytes.len()
        ));
    }

    let mut nodes = Vec::with_capacity(count);
    for _ in 0..count {
        let mut level_bytes = [0u8; 2];
        level_bytes.copy_from_slice(&bytes[cursor..cursor + 2]);
        cursor += 2;
        let level = u16::from_le_bytes(level_bytes) as usize;

        let mut index_bytes = [0u8; 16];
        index_bytes.copy_from_slice(&bytes[cursor..cursor + 16]);
        cursor += 16;
        let index = u128::from_le_bytes(index_bytes);

        let hash_hex = hex_encode(&bytes[cursor..cursor + 32]);
        cursor += 32;
        nodes.push(SmtNodeRecord {
            level,
            index,
            hash_hex,
        });
    }
    Ok(nodes)
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
            return Err(format!(
                "invalid encoded parallel shard proof segment: {item}"
            ));
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
    lines.push(format!(
        "balance_commitment_hex={}",
        proof.balance_commitment_hex
    ));
    lines.push(format!("c_shape_hex={}", proof.c_shape_hex));
    lines.push(format!("c_y_hex={}", proof.c_y_hex));
    lines.push(format!("reserve_count={}", proof.reserve_count));
    lines.push(format!("zeta={}", scalar_to_hex(&proof.zeta)?));
    lines.push(format!(
        "kzg_opening_proof_hex={}",
        proof.kzg_opening_proof_hex
    ));
    lines.push(format!("sp1_proof_hex={}", proof.sp1_proof_hex));
    lines.push(format!("sp1_vk_hex={}", proof.sp1_vk_hex));
    lines.push(format!(
        "sp1_public_values_hex={}",
        proof.sp1_public_values_hex
    ));
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
        c_shape_hex: kv.get("c_shape_hex").cloned().unwrap_or_default(),
        c_y_hex: kv.get("c_y_hex").cloned().unwrap_or_default(),
        reserve_count: req_usize(&kv, "reserve_count")?,
        zeta: req_scalar(&kv, "zeta")?,
        kzg_opening_proof_hex: kv.get("kzg_opening_proof_hex").cloned().unwrap_or_default(),
        sp1_proof_hex: kv.get("sp1_proof_hex").cloned().unwrap_or_default(),
        sp1_vk_hex: kv.get("sp1_vk_hex").cloned().unwrap_or_default(),
        sp1_public_values_hex: kv.get("sp1_public_values_hex").cloned().unwrap_or_default(),
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

#[cfg(test)]
mod init_privacy_tests {
    use ark_bls12_381::Fr;

    use super::{decode_proof_binary, encode_proof_binary, encode_stored_init_proof};
    use crate::types::{StoredInitProof, StoredProof};

    #[test]
    fn public_init_proof_encoding_omits_private_openings() {
        let proof = StoredInitProof {
            scheme: "kzg-nizk-init-v6-zkopen-salted-shape-hash-mock-bound".to_string(),
            mode: "sp1".to_string(),
            chain_id: "0x1".to_string(),
            state_root: "root".to_string(),
            session_id: "session".to_string(),
            accumulator_hex: "acc".to_string(),
            balance_commitment_hex: "balance".to_string(),
            c_shape_hex: "shape".to_string(),
            c_y_hex: "eval".to_string(),
            reserve_count: 2,
            zeta: Fr::from(3u64),
            kzg_opening_proof_hex: "open".to_string(),
            sp1_proof_hex: String::new(),
            sp1_vk_hex: String::new(),
            sp1_public_values_hex: String::new(),
            transcript_hex: "transcript".to_string(),
            srs_hash_hex: "srs".to_string(),
        };
        let encoded = encode_stored_init_proof(&proof).unwrap();
        for private_key in [
            "balance_total=",
            "balance_blind=",
            "r_shape=",
            "r_y=",
            "alpha=",
            "product_zeta=",
            "p_zeta=",
            "init_salt=",
            "init_digest_hex=",
        ] {
            assert!(!encoded.contains(private_key), "leaked {private_key}");
        }
    }

    #[test]
    fn update_multizkopen_binary_round_trip_includes_balance_range_proof() {
        let proof = StoredProof {
            old_state_root: "old".to_string(),
            new_state_root: "new".to_string(),
            delta_list_commitment_hex: "00".to_string(),
            c_u_hex: "01".to_string(),
            d_y_hex: "02".to_string(),
            c_d_hex: "03".to_string(),
            multi_zkopen_proof_hex: "04".to_string(),
            gate_count: 2,
            transcript_hex: "09".to_string(),
            bp_proof_hex: "0a".to_string(),
            committed_input_link_ipa_proof: vec![14],
            projection_ipa_proof: vec![16],
            balance_range_proof_hex: "crange:v1:128:aa,bb:cc".to_string(),
        };
        let encoded = encode_proof_binary(&proof).unwrap();
        assert!(encoded.starts_with(b"DPOAUPD6"));
        assert_eq!(decode_proof_binary(&encoded).unwrap(), proof);
    }
}
