use std::env;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConfiguredProofMode {
    Groth16,
    Plonk,
    Compressed,
}

pub(crate) fn configured_proof_mode() -> Result<ConfiguredProofMode, String> {
    match env::var("POA_SP1_PROOF_MODE")
        .unwrap_or_else(|_| "groth16".to_string())
        .to_ascii_lowercase()
        .as_str()
    {
        "groth16" => Ok(ConfiguredProofMode::Groth16),
        "plonk" => Ok(ConfiguredProofMode::Plonk),
        "compressed" => Ok(ConfiguredProofMode::Compressed),
        value => Err(format!(
            "unsupported POA_SP1_PROOF_MODE {value}; expected groth16, plonk, or compressed"
        )),
    }
}

#[cfg(feature = "protocol-sp1")]
pub(crate) fn ensure_trusted_vk<T: serde::Serialize>(
    stored_vk_hex: &str,
    trusted_vk: &T,
    decode_hex: impl FnOnce(&str) -> Result<Vec<u8>, String>,
    label: &str,
) -> Result<(), String> {
    if stored_vk_hex.is_empty() {
        return Err(format!("missing serialized SP1 {label} verifying key"));
    }
    let supplied = decode_hex(stored_vk_hex)?;
    let trusted = bincode::serialize(trusted_vk)
        .map_err(|err| format!("serialize trusted SP1 {label} verifying key: {err}"))?;
    if supplied != trusted {
        return Err(format!(
            "SP1 {label} verifying key does not match the locally trusted setup"
        ));
    }
    Ok(())
}
