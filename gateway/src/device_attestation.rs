//! GW-ATTEST: signed device attestation assertion validation.
//!
//! The gateway previously accepted `device_attestation_age_secs: Option<f64>`
//! from the client as a plain integer and forwarded it unchanged. A malicious
//! client could simply claim `Some(0.0)` to pass any downstream freshness
//! check. This module replaces that with a PQ-signed assertion:
//!
//! - `issued_at_secs` is authenticated by an ML-DSA-87 signature over the
//!   canonical serialization.
//! - `nonce` is verified against a per-session challenge derived from the
//!   X-Wing session key via HKDF with domain separator
//!   `MILNET-ATTEST-NONCE-v1`. This binds the attestation to the current
//!   session and prevents replay across sessions.
//! - `signer_id` must match a trusted attestation pubkey loaded from
//!   `MILNET_DEVICE_ATTEST_TRUST_DIR` (one `*.pub` file per signer).
//! - Age is checked against `MILNET_DEVICE_ATTESTATION_MAX_AGE_SECS`
//!   (default 300). Assertions older than that are rejected.
//!
//! Fail-closed: any validation error returns `Err(AttestError)` and the
//! caller rejects the auth request. Only the validated `issued_at_secs`
//! integer is forwarded downstream — never the raw struct.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

/// Env var: directory of trusted signer public keys. Each file `<name>.pub`
/// contains the raw ML-DSA-87 verifying key bytes; the file stem is the
/// `signer_id` the assertion must match.
pub const ENV_TRUST_DIR: &str = "MILNET_DEVICE_ATTEST_TRUST_DIR";

/// Env var: maximum acceptable attestation age in seconds. Default 300.
pub const ENV_MAX_AGE: &str = "MILNET_DEVICE_ATTESTATION_MAX_AGE_SECS";

/// Default max attestation age (5 minutes).
pub const DEFAULT_MAX_AGE_SECS: u64 = 300;

/// Domain separator for the per-session attestation nonce HKDF.
pub const NONCE_HKDF_LABEL: &[u8] = b"MILNET-ATTEST-NONCE-v1";

/// Signed assertion sent by the client inside `AuthRequest`.
///
/// Wire format (postcard): fixed fields + variable-length `quote` and
/// `signature`. The signature covers `signer_id || issued_at_secs || nonce
/// || quote` (see `canonical_message`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceAttestationAssertion {
    /// Opaque TPM quote bytes (platform-configuration register values,
    /// attestation key certificate chain, etc.). Gateway does not parse
    /// this — it is forwarded opaque to whatever service consumes the
    /// attestation downstream; the signature covers it for integrity.
    pub quote: Vec<u8>,
    /// 32-byte challenge nonce supplied by the gateway at session start.
    /// Must match `derive_session_nonce(session_key)`.
    pub nonce: [u8; 32],
    /// Unix epoch seconds when the assertion was produced on the device.
    pub issued_at_secs: u64,
    /// Identifier of the signing key. Must match a `<signer_id>.pub` file
    /// in the trust directory.
    pub signer_id: String,
    /// ML-DSA-87 (tagged) signature over `canonical_message()`.
    pub signature: Vec<u8>,
}

/// Validation failure modes — each is a distinct reject path with its
/// own negative test in `gateway/tests/device_attestation_test.rs`.
#[derive(Debug, PartialEq, Eq)]
pub enum AttestError {
    /// `issued_at_secs` is older than `MILNET_DEVICE_ATTESTATION_MAX_AGE_SECS`.
    Stale { age_secs: u64, max_age_secs: u64 },
    /// `nonce` does not match the session-bound challenge.
    WrongNonce,
    /// Signature verification failed.
    BadSignature,
    /// `signer_id` is not present in the trust store.
    UnknownSigner(String),
    /// Trust store is missing or empty — fail-closed.
    TrustStoreUnavailable,
    /// System clock read failed (should be impossible).
    ClockFailure,
}

impl std::fmt::Display for AttestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttestError::Stale { age_secs, max_age_secs } => write!(
                f,
                "device attestation stale: {age_secs}s > {max_age_secs}s"
            ),
            AttestError::WrongNonce => write!(f, "device attestation nonce mismatch"),
            AttestError::BadSignature => write!(f, "device attestation signature invalid"),
            AttestError::UnknownSigner(id) => write!(f, "device attestation unknown signer: {id}"),
            AttestError::TrustStoreUnavailable => {
                write!(f, "device attestation trust store unavailable — fail-closed")
            }
            AttestError::ClockFailure => write!(f, "system clock unavailable — fail-closed"),
        }
    }
}

impl std::error::Error for AttestError {}

/// Build the canonical byte string the signer commits to. Length-prefixed
/// fields prevent ambiguity across variable-length inputs.
pub fn canonical_message(a: &DeviceAttestationAssertion) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        NONCE_HKDF_LABEL.len() + 8 + 32 + a.signer_id.len() + a.quote.len() + 32,
    );
    buf.extend_from_slice(b"MILNET-ATTEST-SIGN-v1\0");
    // signer_id (len-prefixed)
    buf.extend_from_slice(&(a.signer_id.len() as u32).to_be_bytes());
    buf.extend_from_slice(a.signer_id.as_bytes());
    // issued_at_secs
    buf.extend_from_slice(&a.issued_at_secs.to_be_bytes());
    // nonce
    buf.extend_from_slice(&a.nonce);
    // quote (len-prefixed)
    buf.extend_from_slice(&(a.quote.len() as u32).to_be_bytes());
    buf.extend_from_slice(&a.quote);
    buf
}

/// Derive the per-session attestation nonce from the X-Wing session key.
///
/// `session_key` is the shared secret established via X-Wing KEM between
/// the client and gateway. HKDF-SHA512 is simulated as SHA-512 over
/// `label || session_key` truncated to 32 bytes, consistent with the
/// other HKDF-ish helpers in this crate (e.g., `common::key_hierarchy`).
pub fn derive_session_nonce(session_key: &[u8]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(NONCE_HKDF_LABEL);
    h.update([0u8]); // label terminator
    h.update(session_key);
    let digest = h.finalize();
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&digest[..32]);
    nonce
}

/// Read `MILNET_DEVICE_ATTESTATION_MAX_AGE_SECS` once and cache.
fn max_age_secs() -> u64 {
    static CACHE: OnceLock<u64> = OnceLock::new();
    *CACHE.get_or_init(|| {
        std::env::var(ENV_MAX_AGE)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX_AGE_SECS)
    })
}

/// Trust store: maps `signer_id` → raw verifying-key bytes. Lazily loaded
/// from `MILNET_DEVICE_ATTEST_TRUST_DIR` on first use.
fn trust_store() -> &'static HashMap<String, Vec<u8>> {
    static CACHE: OnceLock<HashMap<String, Vec<u8>>> = OnceLock::new();
    CACHE.get_or_init(load_trust_store)
}

fn load_trust_store() -> HashMap<String, Vec<u8>> {
    let mut out = HashMap::new();
    let Some(dir) = std::env::var_os(ENV_TRUST_DIR) else {
        return out;
    };
    let path = PathBuf::from(dir);
    if !path.is_dir() {
        return out;
    }
    let Ok(entries) = fs::read_dir(&path) else {
        return out;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) != Some("pub") {
            continue;
        }
        let Some(stem) = p.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if let Ok(bytes) = fs::read(&p) {
            out.insert(stem.to_string(), bytes);
        }
    }
    out
}

/// Test helper: install an explicit trust store. Gated behind
/// `cfg(any(test, debug_assertions))` so a release build with
/// `debug_assertions = false` cannot use it to bypass the filesystem
/// trust path. Integration tests in `gateway/tests/` compile in dev
/// profile and therefore can reach this symbol.
#[cfg(any(test, debug_assertions))]
pub fn test_install_trust_store(entries: HashMap<String, Vec<u8>>) {
    // `set` fails on second call; tests that re-install overwrite via
    // interior mutation of the contained HashMap would be nicer but the
    // OnceLock semantics suffice for the negative tests we have.
    let _ = TEST_TRUST_OVERRIDE.set(entries);
}

#[cfg(any(test, debug_assertions))]
static TEST_TRUST_OVERRIDE: OnceLock<HashMap<String, Vec<u8>>> = OnceLock::new();

fn active_trust_store() -> &'static HashMap<String, Vec<u8>> {
    #[cfg(any(test, debug_assertions))]
    {
        if let Some(o) = TEST_TRUST_OVERRIDE.get() {
            return o;
        }
    }
    trust_store()
}

/// Validate a `DeviceAttestationAssertion` against the current session and
/// trust store. Returns the validated `issued_at_secs` on success — that is
/// the only value that should be forwarded downstream.
///
/// Fail-closed: any error path rejects.
pub fn validate_assertion(
    assertion: &DeviceAttestationAssertion,
    session_key: &[u8],
) -> Result<u64, AttestError> {
    // 1. Nonce binding.
    let expected_nonce = derive_session_nonce(session_key);
    if !constant_time_eq(&assertion.nonce, &expected_nonce) {
        return Err(AttestError::WrongNonce);
    }

    // 2. Freshness.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| AttestError::ClockFailure)?;
    let max = max_age_secs();
    // Future-dated assertions are also rejected (clock skew or forgery).
    let age = now.saturating_sub(assertion.issued_at_secs);
    if assertion.issued_at_secs > now.saturating_add(max) || age > max {
        return Err(AttestError::Stale {
            age_secs: age,
            max_age_secs: max,
        });
    }

    // 3. Signer lookup.
    let store = active_trust_store();
    if store.is_empty() {
        return Err(AttestError::TrustStoreUnavailable);
    }
    let vk_bytes = store
        .get(&assertion.signer_id)
        .ok_or_else(|| AttestError::UnknownSigner(assertion.signer_id.clone()))?;

    // 4. Signature.
    let msg = canonical_message(assertion);
    if !crypto::pq_sign::pq_verify_raw_from_bytes(vk_bytes, &msg, &assertion.signature) {
        return Err(AttestError::BadSignature);
    }

    Ok(assertion.issued_at_secs)
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Test-only helper to produce a signed assertion for the negative-test
/// suite. Gated on `debug_assertions` so release builds cannot use it.
/// Lives in the library so integration tests reuse the exact canonical
/// message builder without re-implementing it.
#[cfg(any(test, debug_assertions))]
pub fn sign_for_test(
    quote: Vec<u8>,
    nonce: [u8; 32],
    issued_at_secs: u64,
    signer_id: String,
    signing_key: &crypto::pq_sign::PqSigningKey,
) -> DeviceAttestationAssertion {
    let mut a = DeviceAttestationAssertion {
        quote,
        nonce,
        issued_at_secs,
        signer_id,
        signature: Vec::new(),
    };
    let msg = canonical_message(&a);
    a.signature = crypto::pq_sign::pq_sign_raw(signing_key, &msg);
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_message_stable() {
        let a = DeviceAttestationAssertion {
            quote: vec![1, 2, 3],
            nonce: [7u8; 32],
            issued_at_secs: 1_700_000_000,
            signer_id: "dev-tpm-1".into(),
            signature: vec![],
        };
        let m1 = canonical_message(&a);
        let m2 = canonical_message(&a);
        assert_eq!(m1, m2);
        // Mutating a field changes the message.
        let mut a2 = a.clone();
        a2.issued_at_secs += 1;
        assert_ne!(canonical_message(&a2), m1);
    }

    #[test]
    fn derive_session_nonce_is_deterministic_and_key_dependent() {
        let k1 = b"session-key-a";
        let k2 = b"session-key-b";
        assert_eq!(derive_session_nonce(k1), derive_session_nonce(k1));
        assert_ne!(derive_session_nonce(k1), derive_session_nonce(k2));
    }
}
