use alloc::vec::Vec;

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

const OWNERSHIP_DOMAIN: &[u8] = b"DPOA_ETHEREUM_EOA_OWNERSHIP_V1";
const PERSONAL_SIGN_32_PREFIX: &[u8] = b"\x19Ethereum Signed Message:\n32";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OwnershipOperation {
    Initialization = 1,
    Insert = 2,
}

/// Returns the EIP-191 `personal_sign` prehash for one ownership statement.
///
/// The signed 32-byte message is itself a domain-separated hash of the
/// operation, chain id, state root, and account address. Consequently a
/// signature for initialization cannot be replayed as an insertion signature,
/// or against a different chain snapshot.
pub fn ownership_digest(
    operation: OwnershipOperation,
    chain_id: &str,
    state_root: &str,
    address: &str,
) -> [u8; 32] {
    let context_hash = ownership_context_hash(operation, chain_id, state_root);
    ownership_digest_from_context(&context_hash, address)
}

/// Returns the exact 32-byte message that a real Ethereum wallet should sign
/// with `personal_sign`.
pub fn ownership_statement_hash(
    operation: OwnershipOperation,
    chain_id: &str,
    state_root: &str,
    address: &str,
) -> [u8; 32] {
    let context_hash = ownership_context_hash(operation, chain_id, state_root);
    ownership_statement_hash_from_context(&context_hash, address)
}

/// Hashes the statement fields shared by every account in one protocol run.
/// Initialization computes this once, rather than repeating a Keccak for all
/// `n` reserve entries.
pub fn ownership_context_hash(
    operation: OwnershipOperation,
    chain_id: &str,
    state_root: &str,
) -> [u8; 32] {
    let state_root = decode_fixed_hex::<32>(state_root, "state root");

    let mut context = Vec::with_capacity(OWNERSHIP_DOMAIN.len() + 1 + 4 + chain_id.len() + 32);
    context.extend_from_slice(OWNERSHIP_DOMAIN);
    context.push(operation as u8);
    context.extend_from_slice(&(chain_id.len() as u32).to_be_bytes());
    context.extend_from_slice(chain_id.as_bytes());
    context.extend_from_slice(&state_root);
    keccak256(&context)
}

pub fn ownership_digest_from_context(context_hash: &[u8; 32], address: &str) -> [u8; 32] {
    let address = decode_fixed_hex::<20>(address, "Ethereum address");
    ownership_digest_from_context_and_address(context_hash, &address)
}

pub fn ownership_digest_from_context_and_address(
    context_hash: &[u8; 32],
    address: &[u8; 20],
) -> [u8; 32] {
    let statement_hash = ownership_statement_hash_from_context_and_address(context_hash, address);

    let mut personal_sign_input = [0u8; PERSONAL_SIGN_32_PREFIX.len() + 32];
    personal_sign_input[..PERSONAL_SIGN_32_PREFIX.len()].copy_from_slice(PERSONAL_SIGN_32_PREFIX);
    personal_sign_input[PERSONAL_SIGN_32_PREFIX.len()..].copy_from_slice(&statement_hash);
    keccak256(&personal_sign_input)
}

pub fn ownership_statement_hash_from_context(context_hash: &[u8; 32], address: &str) -> [u8; 32] {
    let address = decode_fixed_hex::<20>(address, "Ethereum address");
    ownership_statement_hash_from_context_and_address(context_hash, &address)
}

pub fn ownership_statement_hash_from_context_and_address(
    context_hash: &[u8; 32],
    address: &[u8; 20],
) -> [u8; 32] {
    // Hash a fixed-width statement so every account needs only two Keccak
    // permutations after the shared context has been constructed.
    let mut statement = [0u8; 64];
    statement[..32].copy_from_slice(context_hash);
    statement[44..].copy_from_slice(address);
    keccak256(&statement)
}

/// Verifies a canonical Ethereum recoverable signature and binds its recovered
/// public key to `address`.
///
/// On the SP1 target the patched `k256` implementation routes secp256k1 field
/// and curve operations through SP1 precompiles. `keccak256` below likewise
/// uses SP1's Keccak permutation syscall.
pub fn verify_ownership_signature(
    operation: OwnershipOperation,
    chain_id: &str,
    state_root: &str,
    address: &str,
    r: &[u8; 32],
    s: &[u8; 32],
    recovery_id: u8,
) {
    let context_hash = ownership_context_hash(operation, chain_id, state_root);
    verify_ownership_signature_with_context(&context_hash, address, r, s, recovery_id);
}

pub fn verify_ownership_signature_with_context(
    context_hash: &[u8; 32],
    address: &str,
    r: &[u8; 32],
    s: &[u8; 32],
    recovery_id: u8,
) {
    let address_bytes = decode_fixed_hex::<20>(address, "Ethereum address");
    verify_ownership_signature_with_context_and_address(
        context_hash,
        &address_bytes,
        r,
        s,
        recovery_id,
    );
}

pub fn verify_ownership_signature_with_context_and_address(
    context_hash: &[u8; 32],
    address: &[u8; 20],
    r: &[u8; 32],
    s: &[u8; 32],
    recovery_id: u8,
) {
    assert!(
        recovery_id <= 1,
        "Ethereum recovery id must be y parity 0 or 1"
    );
    let signature = Signature::from_scalars(*r, *s).expect("invalid ECDSA signature");
    assert!(
        signature.normalize_s().is_none(),
        "non-canonical high-s Ethereum signature"
    );
    let recovery_id = RecoveryId::from_byte(recovery_id).expect("invalid ECDSA recovery id");
    let digest = ownership_digest_from_context_and_address(context_hash, address);
    let verifying_key = VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id)
        .expect("ECDSA public-key recovery failed");
    let public_key = verifying_key.to_encoded_point(false);
    let encoded = public_key.as_bytes();
    assert_eq!(encoded.len(), 65, "invalid recovered public-key length");
    assert_eq!(
        encoded[0], 0x04,
        "recovered public key is not uncompressed SEC1"
    );

    let public_key_hash = keccak256(&encoded[1..]);
    assert_eq!(
        &public_key_hash[12..],
        address.as_slice(),
        "ECDSA signature does not own address"
    );
}

pub fn keccak256(input: &[u8]) -> [u8; 32] {
    #[cfg(target_os = "zkvm")]
    {
        keccak256_sp1(input)
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        use sha3::{Digest, Keccak256};
        Keccak256::digest(input).into()
    }
}

/// Incremental Keccak-256 with the same SP1 permutation syscall as
/// [`keccak256`].  Large protocol vectors can therefore be committed without
/// first allocating one contiguous encoded buffer and without executing a
/// software hash inside the zkVM.
#[cfg(target_os = "zkvm")]
pub struct Keccak256Stream {
    state: [u64; 25],
    buffer: [u8; 136],
    buffer_len: usize,
}

#[cfg(not(target_os = "zkvm"))]
pub struct Keccak256Stream(sha3::Keccak256);

impl Keccak256Stream {
    pub fn new() -> Self {
        #[cfg(target_os = "zkvm")]
        {
            Self {
                state: [0u64; 25],
                buffer: [0u8; 136],
                buffer_len: 0,
            }
        }
        #[cfg(not(target_os = "zkvm"))]
        {
            use sha3::Digest;
            Self(sha3::Keccak256::new())
        }
    }

    #[allow(unused_mut)]
    pub fn update(&mut self, mut input: &[u8]) {
        #[cfg(target_os = "zkvm")]
        {
            const RATE: usize = 136;
            while !input.is_empty() {
                let count = core::cmp::min(RATE - self.buffer_len, input.len());
                self.buffer[self.buffer_len..self.buffer_len + count]
                    .copy_from_slice(&input[..count]);
                self.buffer_len += count;
                input = &input[count..];
                if self.buffer_len == RATE {
                    absorb_keccak_block(&mut self.state, &self.buffer);
                    self.buffer.fill(0);
                    self.buffer_len = 0;
                }
            }
        }
        #[cfg(not(target_os = "zkvm"))]
        {
            use sha3::Digest;
            self.0.update(input);
        }
    }

    #[allow(unused_mut)]
    pub fn finalize(mut self) -> [u8; 32] {
        #[cfg(target_os = "zkvm")]
        {
            const RATE: usize = 136;
            self.buffer[self.buffer_len] ^= 0x01;
            self.buffer[RATE - 1] ^= 0x80;
            absorb_keccak_block(&mut self.state, &self.buffer);
            let mut digest = [0u8; 32];
            for (index, lane) in self.state[..4].iter().enumerate() {
                digest[index * 8..(index + 1) * 8].copy_from_slice(&lane.to_le_bytes());
            }
            digest
        }
        #[cfg(not(target_os = "zkvm"))]
        {
            use sha3::Digest;
            self.0.finalize().into()
        }
    }
}

impl Default for Keccak256Stream {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "zkvm")]
fn absorb_keccak_block(state: &mut [u64; 25], block: &[u8; 136]) {
    for (index, byte) in block.iter().enumerate() {
        state[index / 8] ^= (*byte as u64) << ((index % 8) * 8);
    }
    unsafe {
        sp1_lib::syscall_keccak_permute(state);
    }
}

#[cfg(target_os = "zkvm")]
fn keccak256_sp1(input: &[u8]) -> [u8; 32] {
    const RATE: usize = 136;
    let mut state = [0u64; 25];
    let mut offset = 0usize;
    while input.len() - offset >= RATE {
        for (index, byte) in input[offset..offset + RATE].iter().enumerate() {
            state[index / 8] ^= (*byte as u64) << ((index % 8) * 8);
        }
        unsafe {
            sp1_lib::syscall_keccak_permute(&mut state);
        }
        offset += RATE;
    }

    let remaining = &input[offset..];
    for (index, byte) in remaining.iter().enumerate() {
        state[index / 8] ^= (*byte as u64) << ((index % 8) * 8);
    }
    state[remaining.len() / 8] ^= 0x01u64 << ((remaining.len() % 8) * 8);
    state[(RATE - 1) / 8] ^= 0x80u64 << (((RATE - 1) % 8) * 8);
    unsafe {
        sp1_lib::syscall_keccak_permute(&mut state);
    }

    let mut digest = [0u8; 32];
    for (index, lane) in state[..4].iter().enumerate() {
        digest[index * 8..(index + 1) * 8].copy_from_slice(&lane.to_le_bytes());
    }
    digest
}

fn decode_fixed_hex<const N: usize>(value: &str, label: &str) -> [u8; N] {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    assert_eq!(raw.len(), N * 2, "{label} must contain {N} bytes");
    let mut out = [0u8; N];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = (hex_nibble(raw.as_bytes()[index * 2]) << 4)
            | hex_nibble(raw.as_bytes()[index * 2 + 1]);
    }
    out
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hexadecimal character"),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_fixed_hex, keccak256, ownership_context_hash, ownership_digest,
        ownership_digest_from_context_and_address, verify_ownership_signature,
        verify_ownership_signature_with_context_and_address, Keccak256Stream, OwnershipOperation,
    };
    use k256::ecdsa::SigningKey;

    const ADDRESS: &str = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf";
    const STATE_ROOT: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn streaming_keccak_matches_one_shot_across_rate_boundaries() {
        let input = (0..600).map(|index| index as u8).collect::<Vec<_>>();
        for chunks in [1usize, 17, 135, 136, 137, 271] {
            let mut stream = Keccak256Stream::new();
            for chunk in input.chunks(chunks) {
                stream.update(chunk);
            }
            assert_eq!(stream.finalize(), keccak256(&input));
        }
    }

    #[test]
    fn recovers_ethereum_owner_and_binds_context() {
        let mut private_key = [0u8; 32];
        private_key[31] = 1;
        let signing_key = SigningKey::from_slice(&private_key).unwrap();
        let digest = ownership_digest(OwnershipOperation::Initialization, "1", STATE_ROOT, ADDRESS);
        let context = ownership_context_hash(OwnershipOperation::Initialization, "1", STATE_ROOT);
        let address = decode_fixed_hex::<20>(ADDRESS, "address");
        assert_eq!(
            digest,
            ownership_digest_from_context_and_address(&context, &address)
        );
        let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&digest).unwrap();
        let bytes = signature.to_bytes();
        let r: [u8; 32] = bytes[..32].try_into().unwrap();
        let s: [u8; 32] = bytes[32..].try_into().unwrap();

        verify_ownership_signature(
            OwnershipOperation::Initialization,
            "1",
            STATE_ROOT,
            ADDRESS,
            &r,
            &s,
            recovery_id.to_byte(),
        );
        verify_ownership_signature_with_context_and_address(
            &context,
            &address,
            &r,
            &s,
            recovery_id.to_byte(),
        );

        let wrong_operation = std::panic::catch_unwind(|| {
            verify_ownership_signature(
                OwnershipOperation::Insert,
                "1",
                STATE_ROOT,
                ADDRESS,
                &r,
                &s,
                recovery_id.to_byte(),
            )
        });
        assert!(wrong_operation.is_err());
    }
}
