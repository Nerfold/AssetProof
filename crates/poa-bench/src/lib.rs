pub mod ethereum_fixture;

use common::crypto::hex_decode;

pub const FIXTURE_VERSION: &str = "ethereum-keccak-fixed32-merkle-prefix-v3-ecdsa";

pub fn master_fixture_dir(fixture_dir: &std::path::Path, master_n: usize) -> std::path::PathBuf {
    fixture_dir
        .join(format!("master_n_{master_n}"))
        .join(FIXTURE_VERSION)
}

/// Returns the decoded cryptographic payload size of a `zkopen:v2` proof.
///
/// The protocol encoding is a tagged, colon-separated envelope rather than a
/// single hexadecimal string. Benchmark payload accounting deliberately omits
/// the textual tag, version and separators.
pub fn zkopen_proof_payload_bytes(encoded: &str) -> Result<usize, String> {
    let parts = encoded.split(':').collect::<Vec<_>>();
    if parts.len() != 7 || parts[0] != "zkopen" || parts[1] != "v2" {
        return Err("invalid ZKOpen proof encoding".to_string());
    }
    decoded_hex_payload_bytes(&parts[2..])
}

/// Returns the decoded cryptographic payload size of a `crange:v1` proof.
///
/// The public bit length is metadata, while the limb commitments and range
/// proof are the actual proof payload counted by the benchmark.
pub fn committed_range_proof_payload_bytes(encoded: &str) -> Result<usize, String> {
    let parts = encoded.split(':').collect::<Vec<_>>();
    if parts.len() != 5 || parts[0] != "crange" || parts[1] != "v1" {
        return Err("invalid committed range proof encoding".to_string());
    }
    parts[2]
        .parse::<usize>()
        .map_err(|err| format!("invalid range bit length: {err}"))?;

    let mut total = 0usize;
    if !parts[3].is_empty() {
        total = decoded_hex_payload_bytes(&parts[3].split(',').collect::<Vec<_>>())?;
    }
    checked_payload_add(total, hex_decode(parts[4])?.len())
}

fn decoded_hex_payload_bytes(parts: &[&str]) -> Result<usize, String> {
    parts.iter().try_fold(0usize, |total, value| {
        checked_payload_add(total, hex_decode(value)?.len())
    })
}

fn checked_payload_add(lhs: usize, rhs: usize) -> Result<usize, String> {
    lhs.checked_add(rhs)
        .ok_or_else(|| "proof payload size overflow".to_string())
}

#[cfg(test)]
mod tests {
    use super::{committed_range_proof_payload_bytes, zkopen_proof_payload_bytes};

    #[test]
    fn counts_tagged_zkopen_payload() {
        let encoded = "zkopen:v2:00:0102:03:0405:06";
        assert_eq!(zkopen_proof_payload_bytes(encoded).unwrap(), 7);
    }

    #[test]
    fn rejects_non_hex_zkopen_field() {
        let encoded = "zkopen:v2:zz:0102:03:0405:06";
        assert!(zkopen_proof_payload_bytes(encoded).is_err());
    }

    #[test]
    fn counts_tagged_committed_range_payload() {
        let encoded = "crange:v1:128:00,0102:030405";
        assert_eq!(committed_range_proof_payload_bytes(encoded).unwrap(), 6);
    }

    #[test]
    fn counts_committed_range_payload_without_limbs() {
        let encoded = "crange:v1:128::030405";
        assert_eq!(committed_range_proof_payload_bytes(encoded).unwrap(), 3);
    }
}
