//! Log pseudonymization — replaces sensitive identifiers with HMAC-based
//! pseudonyms before they reach log output.
//!
//! In a military deployment where logs may be exfiltrated from a compromised
//! host, raw user IDs and email addresses in log messages enable an attacker
//! to correlate identities across systems.  This module produces deterministic
//! but irreversible pseudonyms using HMAC-SHA512 keyed by the master KEK,
//! so the same input always maps to the same pseudonym (enabling log
//! correlation by operators who hold the KEK) while being opaque to anyone
//! who does not.
#![forbid(unsafe_code)]

use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::sync::OnceLock;
use uuid::Uuid;

type HmacSha512 = Hmac<Sha512>;

/// Domain separation tag for log pseudonyms — ensures these HMACs cannot
/// collide with HMACs produced for other purposes (e.g. SHARD auth, CSRF).
const LOG_PSEUDONYM_DOMAIN: &[u8] = b"MILNET-LOG-PSEUDONYM-v1";

/// Cached HMAC key derived from master KEK (computed once on first use).
static PSEUDONYM_KEY: OnceLock<[u8; 32]> = OnceLock::new();

fn pseudonym_key() -> &'static [u8; 32] {
    PSEUDONYM_KEY.get_or_init(|| {
        let kek = crate::sealed_keys::cached_master_kek();
        let hk = hkdf::Hkdf::<Sha512>::new(Some(LOG_PSEUDONYM_DOMAIN), kek);
        let mut okm = [0u8; 32];
        // X-V — Invariant: HKDF-SHA512-Expand of 32 bytes is mathematically
        // infallible per RFC 5869 §2.3 (32 ≤ 255 × HashLen = 16 320 with
        // HashLen=64). The pre-fix `unwrap_or_else(|_| copy_from_slice(kek))`
        // was unreachable today, but if a future hkdf bump ever changed the
        // bound it would silently use the master KEK as the pseudonym HMAC
        // key — defeating pseudonymisation entirely (anyone who can observe
        // many `(plaintext, pseudonym)` pairs could probe the KEK directly).
        // Replace the silent fallback with `expect` so any failure is a
        // loud panic, surfaced in tests, not a silent privacy regression.
        hk.expand(b"log-pseudonym-hmac-key", &mut okm)
            .expect(
                "HKDF-SHA512 expand of 32 bytes is infallible per RFC 5869 \
                 §2.3 — input never empty under construction invariants",
            );
        okm
    })
}

/// Produce a hex pseudonym for a UUID (first 16 bytes of HMAC-SHA512 = 32 hex chars).
/// Deterministic: same UUID always yields the same pseudonym.
/// CNSA 2.0 Level 5: HMAC-SHA512 (upgraded from HMAC-SHA256).
pub fn pseudonym_uuid(id: Uuid) -> String {
    let key = pseudonym_key();
    let mut mac = HmacSha512::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC-SHA512 accepts any key length"));
    mac.update(b"uuid:");
    mac.update(id.as_bytes());
    let result = mac.finalize().into_bytes();
    hex::encode(&result[..16])
}

/// Produce a hex pseudonym for an email address (first 16 bytes = 32 hex chars).
/// CNSA 2.0 Level 5: HMAC-SHA512 (upgraded from HMAC-SHA256).
pub fn pseudonym_email(email: &str) -> String {
    let key = pseudonym_key();
    let mut mac = HmacSha512::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC-SHA512 accepts any key length"));
    mac.update(b"email:");
    mac.update(email.as_bytes());
    let result = mac.finalize().into_bytes();
    hex::encode(&result[..16])
}

/// Produce a hex pseudonym for an arbitrary string identifier (first 16 bytes = 32 hex chars).
/// CNSA 2.0 Level 5: HMAC-SHA512 (upgraded from HMAC-SHA256).
pub fn pseudonym_str(tag: &str, value: &str) -> String {
    let key = pseudonym_key();
    let mut mac = HmacSha512::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC-SHA512 accepts any key length"));
    mac.update(tag.as_bytes());
    mac.update(b":");
    mac.update(value.as_bytes());
    let result = mac.finalize().into_bytes();
    hex::encode(&result[..16])
}

/// Produce a hex pseudonym for an IP address (first 16 bytes = 32 hex chars).
/// Preserves the ability to correlate log entries from the same IP without
/// exposing the actual address.
/// CNSA 2.0 Level 5: HMAC-SHA512.
pub fn pseudonym_ip(ip: &str) -> String {
    let key = pseudonym_key();
    let mut mac = HmacSha512::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC-SHA512 accepts any key length"));
    mac.update(b"ip:");
    mac.update(ip.as_bytes());
    let result = mac.finalize().into_bytes();
    hex::encode(&result[..16])
}
