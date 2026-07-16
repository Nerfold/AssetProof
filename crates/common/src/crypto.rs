use std::fmt::Write;
use std::io::{Read, Seek, SeekFrom, Write as IoWrite};

use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub fn scalar_from_u64(value: u64) -> Fr {
    Fr::from(value)
}

pub fn scalar_from_i128(value: i128) -> Fr {
    if value >= 0 {
        Fr::from(value as u128)
    } else {
        -Fr::from(value.unsigned_abs())
    }
}

pub fn scalar_to_hex(value: &Fr) -> Result<String, String> {
    serialize_hex(value)
}

pub fn scalar_from_hex(hex: &str) -> Result<Fr, String> {
    deserialize_hex::<Fr>(hex)
}

pub fn point_g1_to_hex(value: &G1Projective) -> Result<String, String> {
    serialize_hex(&value.into_affine())
}

pub fn point_g1_from_hex(hex: &str) -> Result<G1Projective, String> {
    Ok(deserialize_hex::<G1Affine>(hex)?.into())
}

pub fn point_g2_to_hex(value: &G2Projective) -> Result<String, String> {
    serialize_hex(&value.into_affine())
}

pub fn point_g2_from_hex(hex: &str) -> Result<G2Projective, String> {
    Ok(deserialize_hex::<G2Affine>(hex)?.into())
}

pub fn g1_mul_generator(scalar: &Fr) -> G1Projective {
    G1Projective::generator().mul_bigint(scalar.into_bigint())
}

pub fn g2_mul_generator(scalar: &Fr) -> G2Projective {
    G2Projective::generator().mul_bigint(scalar.into_bigint())
}

pub fn hash_to_scalar(label: &str, data: &[u8]) -> Fr {
    let mut hasher = blake3::Hasher::new();
    hasher.update(label.as_bytes());
    hasher.update(data);
    let digest = hasher.finalize();
    Fr::from_le_bytes_mod_order(digest.as_bytes())
}

pub fn hash_bytes(label: &str, chunks: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(label.as_bytes());
    for chunk in chunks {
        hasher.update(chunk);
    }
    *hasher.finalize().as_bytes()
}

pub fn derive_generator(label: &str, index: usize) -> G1Projective {
    let scalar = hash_to_scalar(label, index.to_string().as_bytes());
    g1_mul_generator(&scalar)
}

pub fn commit_balance(value: i128, blind: Fr) -> G1Projective {
    let v = derive_generator("balance-v", 0);
    let h = derive_generator("balance-h", 0);
    v.mul_bigint(scalar_from_i128(value).into_bigint()) + h.mul_bigint(blind.into_bigint())
}

pub fn serialize_hex<T: CanonicalSerialize>(value: &T) -> Result<String, String> {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .map_err(|err| format!("serialize: {err}"))?;
    Ok(hex_encode(&bytes))
}

pub fn deserialize_hex<T: CanonicalDeserialize>(hex: &str) -> Result<T, String> {
    let bytes = hex_decode(hex)?;
    let mut slice: &[u8] = &bytes;
    T::deserialize_compressed(&mut slice).map_err(|err| format!("deserialize: {err}"))
}

pub fn write_scalar_vec_csv(values: &[Fr]) -> Result<String, String> {
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        out.push(scalar_to_hex(value)?);
    }
    Ok(out.join(","))
}

pub fn read_scalar_vec_csv(raw: &str) -> Result<Vec<Fr>, String> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    raw.split(',').map(scalar_from_hex).collect()
}

pub fn write_u8_vec_csv(values: &[u8]) -> String {
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

pub fn read_u8_vec_csv(raw: &str) -> Result<Vec<u8>, String> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    raw.split(',')
        .map(|item| {
            item.parse::<u8>()
                .map_err(|err| format!("invalid u8: {err}"))
        })
        .collect()
}

pub fn write_string_vec_csv(values: &[String]) -> String {
    values.join(",")
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    let raw = hex.trim();
    if raw.len() % 2 != 0 {
        return Err("hex length must be even".to_string());
    }

    let mut out = Vec::with_capacity(raw.len() / 2);
    let bytes = raw.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let high = from_hex_nibble(bytes[index])?;
        let low = from_hex_nibble(bytes[index + 1])?;
        out.push((high << 4) | low);
        index += 2;
    }
    Ok(out)
}

pub fn write_srs_binary<W: IoWrite>(
    writer: &mut W,
    max_degree: usize,
    tau_g1_powers: &[G1Affine],
    tau_g2_powers: &[G2Affine],
) -> Result<(), String> {
    let encoded_max_degree = u64::try_from(max_degree)
        .map_err(|_| "SRS max_degree does not fit the binary format".to_string())?;
    let encoded_g1_len = u64::try_from(tau_g1_powers.len())
        .map_err(|_| "SRS G1 length does not fit the binary format".to_string())?;
    let encoded_g2_len = u64::try_from(tau_g2_powers.len())
        .map_err(|_| "SRS G2 length does not fit the binary format".to_string())?;
    writer
        .write_all(&encoded_max_degree.to_le_bytes())
        .map_err(|err| format!("write srs degree: {err}"))?;
    writer
        .write_all(&encoded_g1_len.to_le_bytes())
        .map_err(|err| format!("write srs g1 len: {err}"))?;
    for point in tau_g1_powers {
        let mut bytes = Vec::new();
        point
            .serialize_compressed(&mut bytes)
            .map_err(|err| format!("write srs g1 point: {err}"))?;
        writer
            .write_all(&bytes)
            .map_err(|err| format!("write srs g1 bytes: {err}"))?;
    }
    writer
        .write_all(&encoded_g2_len.to_le_bytes())
        .map_err(|err| format!("write srs g2 len: {err}"))?;
    for point in tau_g2_powers {
        let mut bytes = Vec::new();
        point
            .serialize_compressed(&mut bytes)
            .map_err(|err| format!("write srs g2 point: {err}"))?;
        writer
            .write_all(&bytes)
            .map_err(|err| format!("write srs g2 bytes: {err}"))?;
    }
    Ok(())
}

pub fn write_srs_binary_with_hiding<W: IoWrite>(
    writer: &mut W,
    max_degree: usize,
    tau_g1_powers: &[G1Affine],
    tau_g2_powers: &[G2Affine],
    hiding_tau_g1_powers: &[G1Affine],
) -> Result<(), String> {
    write_srs_binary(writer, max_degree, tau_g1_powers, tau_g2_powers)?;
    let encoded_hiding_len = u64::try_from(hiding_tau_g1_powers.len())
        .map_err(|_| "hiding SRS G1 length does not fit the binary format".to_string())?;
    writer
        .write_all(&encoded_hiding_len.to_le_bytes())
        .map_err(|err| format!("write hiding srs g1 len: {err}"))?;
    for point in hiding_tau_g1_powers {
        let mut bytes = Vec::new();
        point
            .serialize_compressed(&mut bytes)
            .map_err(|err| format!("write hiding srs g1 point: {err}"))?;
        writer
            .write_all(&bytes)
            .map_err(|err| format!("write hiding srs g1 bytes: {err}"))?;
    }
    Ok(())
}

pub fn read_srs_binary<R: Read>(
    reader: &mut R,
) -> Result<(usize, Vec<G1Affine>, Vec<G2Affine>), String> {
    let max_degree = usize::try_from(read_u64(reader)?)
        .map_err(|_| "SRS max_degree does not fit this platform".to_string())?;
    let max_len = max_degree
        .checked_add(1)
        .ok_or_else(|| "SRS max_degree overflow".to_string())?;
    let g1_len = usize::try_from(read_u64(reader)?)
        .map_err(|_| "SRS G1 length does not fit this platform".to_string())?;
    if g1_len > max_len {
        return Err("SRS G1 length exceeds declared max_degree".to_string());
    }
    let mut tau_g1_powers = Vec::new();
    tau_g1_powers
        .try_reserve_exact(g1_len)
        .map_err(|err| format!("reserve SRS G1 powers: {err}"))?;
    for _ in 0..g1_len {
        let mut bytes = vec![0u8; G1Affine::identity().compressed_size()];
        reader
            .read_exact(&mut bytes)
            .map_err(|err| format!("read srs g1 bytes: {err}"))?;
        tau_g1_powers.push(
            G1Affine::deserialize_compressed(&bytes[..])
                .map_err(|err| format!("read srs g1 point: {err}"))?,
        );
    }
    let g2_len = usize::try_from(read_u64(reader)?)
        .map_err(|_| "SRS G2 length does not fit this platform".to_string())?;
    if g2_len > max_len {
        return Err("SRS G2 length exceeds declared max_degree".to_string());
    }
    let mut tau_g2_powers = Vec::new();
    tau_g2_powers
        .try_reserve_exact(g2_len)
        .map_err(|err| format!("reserve SRS G2 powers: {err}"))?;
    for _ in 0..g2_len {
        let mut bytes = vec![0u8; G2Affine::identity().compressed_size()];
        reader
            .read_exact(&mut bytes)
            .map_err(|err| format!("read srs g2 bytes: {err}"))?;
        tau_g2_powers.push(
            G2Affine::deserialize_compressed(&bytes[..])
                .map_err(|err| format!("read srs g2 point: {err}"))?,
        );
    }
    Ok((max_degree, tau_g1_powers, tau_g2_powers))
}

pub fn read_srs_binary_with_hiding<R: Read>(
    reader: &mut R,
) -> Result<(usize, Vec<G1Affine>, Vec<G2Affine>, Vec<G1Affine>), String> {
    let (max_degree, tau_g1_powers, tau_g2_powers) = read_srs_binary(reader)?;
    let mut len_bytes = [0u8; 8];
    match reader
        .read(&mut len_bytes[..1])
        .map_err(|err| format!("read hiding srs marker: {err}"))?
    {
        0 => {
            return Ok((max_degree, tau_g1_powers, tau_g2_powers, Vec::new()));
        }
        1 => reader
            .read_exact(&mut len_bytes[1..])
            .map_err(|err| format!("read hiding srs g1 len: {err}"))?,
        _ => unreachable!(),
    }
    let len = usize::try_from(u64::from_le_bytes(len_bytes))
        .map_err(|_| "hiding SRS G1 length does not fit this platform".to_string())?;
    let max_len = max_degree
        .checked_add(1)
        .ok_or_else(|| "SRS max_degree overflow".to_string())?;
    if len > max_len {
        return Err("hiding SRS G1 length exceeds declared max_degree".to_string());
    }
    let mut hiding_tau_g1_powers = Vec::new();
    hiding_tau_g1_powers
        .try_reserve_exact(len)
        .map_err(|err| format!("reserve hiding SRS G1 powers: {err}"))?;
    for _ in 0..len {
        let mut bytes = vec![0u8; G1Affine::identity().compressed_size()];
        reader
            .read_exact(&mut bytes)
            .map_err(|err| format!("read hiding srs g1 bytes: {err}"))?;
        hiding_tau_g1_powers.push(
            G1Affine::deserialize_compressed(&bytes[..])
                .map_err(|err| format!("read hiding srs g1 point: {err}"))?,
        );
    }
    Ok((
        max_degree,
        tau_g1_powers,
        tau_g2_powers,
        hiding_tau_g1_powers,
    ))
}

pub fn read_srs_g1_prefix_binary<R: Read + Seek>(
    reader: &mut R,
    needed_g1_len: usize,
) -> Result<(usize, Vec<G1Affine>), String> {
    let max_degree = usize::try_from(read_u64(reader)?)
        .map_err(|_| "SRS max_degree does not fit this platform".to_string())?;
    let g1_len = usize::try_from(read_u64(reader)?)
        .map_err(|_| "SRS G1 length does not fit this platform".to_string())?;
    let max_len = max_degree
        .checked_add(1)
        .ok_or_else(|| "SRS max_degree overflow".to_string())?;
    if g1_len > max_len {
        return Err("SRS G1 length exceeds declared max_degree".to_string());
    }
    if needed_g1_len > g1_len {
        return Err(format!(
            "requested {} G1 powers but SRS only stores {}",
            needed_g1_len, g1_len
        ));
    }

    let g1_point_size = G1Affine::identity().compressed_size() as i64;
    let mut tau_g1_powers = Vec::new();
    tau_g1_powers
        .try_reserve_exact(needed_g1_len)
        .map_err(|err| format!("reserve SRS G1 prefix: {err}"))?;
    for _ in 0..needed_g1_len {
        let mut bytes = vec![0u8; g1_point_size as usize];
        reader
            .read_exact(&mut bytes)
            .map_err(|err| format!("read srs g1 bytes: {err}"))?;
        tau_g1_powers.push(
            G1Affine::deserialize_compressed(&bytes[..])
                .map_err(|err| format!("read srs g1 point: {err}"))?,
        );
    }

    let remaining_g1 = g1_len - needed_g1_len;
    if remaining_g1 > 0 {
        let byte_offset = remaining_g1
            .checked_mul(g1_point_size as usize)
            .and_then(|offset| i64::try_from(offset).ok())
            .ok_or_else(|| "SRS G1 tail offset overflow".to_string())?;
        reader
            .seek(SeekFrom::Current(byte_offset))
            .map_err(|err| format!("skip srs g1 tail: {err}"))?;
    }

    Ok((max_degree, tau_g1_powers))
}

pub fn read_srs_prefix_binary<R: Read + Seek>(
    reader: &mut R,
    needed_g1_len: usize,
    needed_g2_len: usize,
) -> Result<(usize, Vec<G1Affine>, Vec<G2Affine>), String> {
    let max_degree = usize::try_from(read_u64(reader)?)
        .map_err(|_| "SRS max_degree does not fit this platform".to_string())?;
    let g1_len = usize::try_from(read_u64(reader)?)
        .map_err(|_| "SRS G1 length does not fit this platform".to_string())?;
    let max_len = max_degree
        .checked_add(1)
        .ok_or_else(|| "SRS max_degree overflow".to_string())?;
    if g1_len > max_len {
        return Err("SRS G1 length exceeds declared max_degree".to_string());
    }
    if needed_g1_len > g1_len {
        return Err(format!(
            "requested {} G1 powers but SRS only stores {}",
            needed_g1_len, g1_len
        ));
    }

    let g1_point_size = G1Affine::identity().compressed_size() as i64;
    let mut tau_g1_powers = Vec::new();
    tau_g1_powers
        .try_reserve_exact(needed_g1_len)
        .map_err(|err| format!("reserve SRS G1 prefix: {err}"))?;
    for _ in 0..needed_g1_len {
        let mut bytes = vec![0u8; g1_point_size as usize];
        reader
            .read_exact(&mut bytes)
            .map_err(|err| format!("read srs g1 bytes: {err}"))?;
        tau_g1_powers.push(
            G1Affine::deserialize_compressed(&bytes[..])
                .map_err(|err| format!("read srs g1 point: {err}"))?,
        );
    }

    let remaining_g1 = g1_len - needed_g1_len;
    if remaining_g1 > 0 {
        let byte_offset = remaining_g1
            .checked_mul(g1_point_size as usize)
            .and_then(|offset| i64::try_from(offset).ok())
            .ok_or_else(|| "SRS G1 tail offset overflow".to_string())?;
        reader
            .seek(SeekFrom::Current(byte_offset))
            .map_err(|err| format!("skip srs g1 tail: {err}"))?;
    }

    let g2_len = usize::try_from(read_u64(reader)?)
        .map_err(|_| "SRS G2 length does not fit this platform".to_string())?;
    if g2_len > max_len {
        return Err("SRS G2 length exceeds declared max_degree".to_string());
    }
    if needed_g2_len > g2_len {
        return Err(format!(
            "requested {} G2 powers but SRS only stores {}",
            needed_g2_len, g2_len
        ));
    }

    let g2_point_size = G2Affine::identity().compressed_size() as usize;
    let mut tau_g2_powers = Vec::new();
    tau_g2_powers
        .try_reserve_exact(needed_g2_len)
        .map_err(|err| format!("reserve SRS G2 prefix: {err}"))?;
    for _ in 0..needed_g2_len {
        let mut bytes = vec![0u8; g2_point_size];
        reader
            .read_exact(&mut bytes)
            .map_err(|err| format!("read srs g2 bytes: {err}"))?;
        tau_g2_powers.push(
            G2Affine::deserialize_compressed(&bytes[..])
                .map_err(|err| format!("read srs g2 point: {err}"))?,
        );
    }

    Ok((max_degree, tau_g1_powers, tau_g2_powers))
}

fn read_u64<R: Read>(reader: &mut R) -> Result<u64, String> {
    let mut bytes = [0u8; 8];
    reader
        .read_exact(&mut bytes)
        .map_err(|err| format!("read u64: {err}"))?;
    Ok(u64::from_le_bytes(bytes))
}

fn from_hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex nibble: {}", byte as char)),
    }
}

#[cfg(test)]
mod srs_encoding_tests {
    use std::io::Cursor;

    use ark_bls12_381::{Fr, G1Projective, G2Projective};
    use ark_ec::{CurveGroup, PrimeGroup};

    use super::{read_srs_binary_with_hiding, write_srs_binary_with_hiding};

    #[test]
    fn extended_srs_roundtrip_preserves_hiding_powers() {
        let g1 = vec![
            G1Projective::generator().into_affine(),
            (G1Projective::generator() * Fr::from(2u64)).into_affine(),
        ];
        let g2 = vec![
            G2Projective::generator().into_affine(),
            (G2Projective::generator() * Fr::from(2u64)).into_affine(),
        ];
        let hiding = vec![
            (G1Projective::generator() * Fr::from(3u64)).into_affine(),
            (G1Projective::generator() * Fr::from(6u64)).into_affine(),
        ];
        let mut encoded = Vec::new();
        write_srs_binary_with_hiding(&mut encoded, 1, &g1, &g2, &hiding).unwrap();
        let decoded = read_srs_binary_with_hiding(&mut Cursor::new(encoded)).unwrap();
        assert_eq!(decoded, (1, g1, g2, hiding));
    }
}
