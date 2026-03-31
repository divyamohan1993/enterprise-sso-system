//! Log pseudonymization — replaces sensitive identifiers with HMAC-based
//! pseudonyms before they reach log output.
//!
//! In a military deployment where logs may be exfiltrated from a compromised
//! host, raw user IDs and email addresses in log messages enable an attacker
//! to correlate identities across systems.  This module produces deterministic
//! but irreversible pseudonyms using HMAC-SHA256 keyed by the master KEK,
//! so the same input always maps to the same pseudonym (enabling log
//! correlation by operators who hold the KEK) while being opaque to anyone
//! who does not.
#![forbid(unsafe_code)]

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::OnceLock;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Domain separation tag for log pseudonyms — ensures these HMACs cannot
/// collide with HMACs produced for other purposes (e.g. SHARD auth, CSRF).
const LOG_PSEUDONYM_DOMAIN: &[u8] = b"MILNET-LOG-PSEUDONYM-v1";

/// Cached HMAC key derived from master KEK (computed once on first use).
static PSEUDONYM_KEY: OnceLock<[u8; 32]> = OnceLock::new();

fn pseudonym_key() -> &'static [u8; 32] {
    PSEUDONYM_KEY.get_or_init(|| {
        // In test mode, the master KEK may not be available (it calls
        // process::exit if MILNET_MASTER_KEK is not set).  Use a fixed
        // test-only key so pseudonym tests can run without a real KEK.
        let kek = if cfg!(test) || std::env::var("MILNET_DEV_MODE").as_deref() == Ok("1") {
            match std::env::var("MILNET_MASTER_KEK") {
                Ok(hex) if hex.len() >= 64 => {
                    crate::sealed_keys::cached_master_kek()
                }
                _ => {
                    // Dev/test fallback: deterministic key for log pseudonyms.
                    // This is NOT used in production (KEK is always available).
                    static DEV_KEY: [u8; 32] = [
                        0x4D, 0x49, 0x4C, 0x4E, 0x45, 0x54, 0x2D, 0x4C,
                        0x4F, 0x47, 0x2D, 0x50, 0x53, 0x45, 0x55, 0x44,
                        0x4F, 0x4E, 0x59, 0x4D, 0x2D, 0x44, 0x45, 0x56,
                        0x2D, 0x4B, 0x45, 0x59, 0x21, 0x21, 0x21, 0x21,
                    ];
                    &DEV_KEY
                }
            }
        } else {
            crate::sealed_keys::cached_master_kek()
        };
        let hk = hkdf::Hkdf::<Sha256>::new(Some(LOG_PSEUDONYM_DOMAIN), kek);
        let mut okm = [0u8; 32];
        hk.expand(b"log-pseudonym-hmac-key", &mut okm)
            .unwrap_or_else(|_| {
                okm.copy_from_slice(kek);
            });
        okm
    })
}

/// Produce a short hex pseudonym for a UUID (first 8 bytes of HMAC = 16 hex chars).
/// Deterministic: same UUID always yields the same pseudonym.
pub fn pseudonym_uuid(id: Uuid) -> String {
    let key = pseudonym_key();
    let mut mac = HmacSha256::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC-SHA256 accepts any key length"));
    mac.update(b"uuid:");
    mac.update(id.as_bytes());
    let result = mac.finalize().into_bytes();
    hex::encode(&result[..8])
}

/// Produce a short hex pseudonym for an email address.
pub fn pseudonym_email(email: &str) -> String {
    let key = pseudonym_key();
    let mut mac = HmacSha256::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC-SHA256 accepts any key length"));
    mac.update(b"email:");
    mac.update(email.as_bytes());
    let result = mac.finalize().into_bytes();
    hex::encode(&result[..8])
}

/// Produce a short hex pseudonym for an arbitrary string identifier.
pub fn pseudonym_str(tag: &str, value: &str) -> String {
    let key = pseudonym_key();
    let mut mac = HmacSha256::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC-SHA256 accepts any key length"));
    mac.update(tag.as_bytes());
    mac.update(b":");
    mac.update(value.as_bytes());
    let result = mac.finalize().into_bytes();
    hex::encode(&result[..8])
}
