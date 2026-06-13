use ark_bls12_381::Fr;
use ark_ff::PrimeField;

pub fn encode_address(address: &str) -> Result<Fr, String> {
    let normalized = normalize_address(address)?;
    let raw = normalized.strip_prefix("0x").unwrap_or(&normalized);
    let mut bytes = [0u8; 20];
    for (index, chunk) in raw.as_bytes().chunks(2).enumerate() {
        let high = from_hex_nibble(chunk[0])?;
        let low = from_hex_nibble(chunk[1])?;
        bytes[index] = (high << 4) | low;
    }
    Ok(Fr::from_be_bytes_mod_order(&bytes))
}

pub fn normalize_address(address: &str) -> Result<String, String> {
    let trimmed = address.trim();
    let raw = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if raw.len() != 40 {
        return Err(format!("address must have 40 hex chars: {address}"));
    }

    for (index, ch) in raw.bytes().enumerate() {
        match ch {
            b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => {}
            _ => return Err(format!("invalid hex at position {index} in {address}")),
        }
    }

    Ok(format!("0x{}", raw.to_ascii_lowercase()))
}

fn from_hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex nibble: {}", byte as char)),
    }
}
