//! Multi-source entropy combiner (spec Errata E.5)
//!
//! Combines OS CSPRNG + environmental noise to ensure no single
//! entropy source compromise is sufficient. In production, a
//! dedicated hardware RNG would be added as a third source.

use sha2::{Sha512, Digest};

/// Combine multiple entropy sources per spec E.5.
/// Returns 32 bytes of combined entropy.
///
/// Sources:
/// 1. OS CSPRNG (getrandom → /dev/urandom → RDRAND)
/// 2. Environmental noise (time, thread ID)
/// 3. XOR combination ensures independence
pub fn combined_entropy() -> [u8; 32] {
    // Source 1: OS CSPRNG
    let mut os_entropy = [0u8; 32];
    getrandom::getrandom(&mut os_entropy).expect("OS entropy source must be available");

    // Source 2: Environmental noise
    let time_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let thread_id = format!("{:?}", std::thread::current().id());

    // Combine via hash
    let mut hasher = Sha512::new();
    hasher.update(b"MILNET-ENTROPY-COMBINER-v1");
    hasher.update(os_entropy);
    hasher.update(time_ns.to_le_bytes());
    hasher.update(thread_id.as_bytes());
    // In production: add dedicated_hardware_rng bytes here
    let hash = hasher.finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(&hash[..32]);

    // XOR with OS entropy for defense in depth
    for i in 0..32 {
        result[i] ^= os_entropy[i];
    }

    result
}

/// Generate a 32-byte nonce using combined entropy.
pub fn generate_nonce() -> [u8; 32] {
    combined_entropy()
}

/// Generate a 64-byte key using combined entropy (two rounds).
pub fn generate_key_64() -> [u8; 64] {
    let mut key = [0u8; 64];
    let a = combined_entropy();
    let b = combined_entropy();
    key[..32].copy_from_slice(&a);
    key[32..].copy_from_slice(&b);
    key
}
