//! TOTP (Time-based One-Time Password) implementation per RFC 6238.
//!
//! Supports SHA-512 (CNSA 2.0) for new enrollments. SHA-256 is legacy-only.
//! New enrollments default to SHA-512 via `MILNET_TOTP_ALGORITHM` env var.
//! SHA-1 has been REMOVED -- cryptographically broken and prohibited.
//! SHA-256 is rejected for new enrollments (only SHA-512+ allowed).
//! `MILNET_TOTP_MIN_ALGORITHM` env var controls minimum (default: "sha512").
//! In military mode (`MILNET_MILITARY_DEPLOYMENT`), SHA-256 is rejected even for verification.

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use std::collections::HashMap;
use std::sync::Mutex;

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// TOTP hash algorithm selection per RFC 6238.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpAlgorithm {
    /// SHA-1 — REMOVED. Any use returns an error. Retained only so legacy
    /// configurations can be deserialized and rejected with a clear message.
    #[deprecated(note = "SHA-1 is cryptographically broken and prohibited for MILNET. Use Sha512.")]
    Sha1,
    /// SHA-256 — recommended for new enrollments.
    Sha256,
    /// SHA-512 — CNSA 2.0 compliant.
    Sha512,
}

impl TotpAlgorithm {
    /// Parse from string (case-insensitive). Returns None for unrecognized values.
    /// SHA-1 is recognized but returns the deprecated Sha1 variant so callers
    /// can detect and reject it with a clear error.
    #[allow(deprecated)]
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "sha1" | "sha-1" => Some(Self::Sha1),
            "sha256" | "sha-256" => Some(Self::Sha256),
            "sha512" | "sha-512" => Some(Self::Sha512),
            _ => None,
        }
    }

    /// Return the algorithm string for otpauth:// URIs.
    #[allow(deprecated)]
    pub fn otpauth_name(&self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }

    /// HMAC output length in bytes for this algorithm.
    #[allow(dead_code, deprecated)]
    fn hmac_output_len(&self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

/// Read the default TOTP algorithm from `MILNET_TOTP_ALGORITHM` env var.
///
/// SECURITY: Defaults to SHA-512 (CNSA 2.0 compliant) if unset or unrecognized.
/// SHA-1 is REJECTED unconditionally — it has been removed from MILNET.
#[allow(deprecated)]
pub fn default_totp_algorithm() -> TotpAlgorithm {
    let algo = std::env::var("MILNET_TOTP_ALGORITHM")
        .ok()
        .and_then(|v| TotpAlgorithm::from_str_loose(&v))
        .unwrap_or(TotpAlgorithm::Sha512);

    // SECURITY: Block SHA-1 and SHA-256 for new enrollments -- only SHA-512+ is acceptable.
    if algo == TotpAlgorithm::Sha1 {
        tracing::error!(
            "SECURITY: MILNET_TOTP_ALGORITHM=SHA1 is PROHIBITED for new enrollments. \
             Overriding to SHA-512 (CNSA 2.0). Remove SHA-1 configuration immediately."
        );
        return TotpAlgorithm::Sha512;
    }

    if algo == TotpAlgorithm::Sha256 {
        tracing::error!(
            "SECURITY: MILNET_TOTP_ALGORITHM=SHA256 is REJECTED for new enrollments. \
             Only SHA-512+ is permitted. Overriding to SHA-512 (CNSA 2.0)."
        );
        return TotpAlgorithm::Sha512;
    }

    algo
}

/// Returns true if the given algorithm string represents a legacy/deprecated algorithm.
///
/// SECURITY: Legacy algorithms must not be used for new enrollments.
/// Existing tokens using these algorithms should be migrated urgently.
pub fn is_legacy_algorithm(algo: &str) -> bool {
    matches!(algo.to_lowercase().as_str(), "sha1" | "sha-1" | "sha256" | "sha-256")
}

/// Global TOTP used-code cache — prevents replay within a time window.
/// Per RFC 6238 Section 5.2: "The verifier MUST NOT accept the second attempt."
/// Keyed by (user_secret_fingerprint, code, time_step) to prevent cross-user collisions.
/// Entries are evicted after 2 minutes (4 time steps) to bound memory.
static TOTP_USED_CODES: std::sync::OnceLock<Mutex<TotpUsedCodeCache>> = std::sync::OnceLock::new();

struct TotpUsedCodeCache {
    /// Maps (secret_fingerprint_u64, time_step, code) -> true
    used: HashMap<(u64, u64, u32), bool>,
    last_cleanup: u64,
}

impl TotpUsedCodeCache {
    fn new() -> Self {
        Self { used: HashMap::new(), last_cleanup: 0 }
    }

    fn is_used(&mut self, secret_fp: u64, time: u64, code: u32) -> bool {
        let step = time / TIME_STEP;
        // Cleanup old entries every 60 seconds
        if time > self.last_cleanup + 60 {
            self.used.retain(|&(_, s, _), _| s + 4 >= step);
            self.last_cleanup = time;
        }
        self.used.contains_key(&(secret_fp, step, code))
    }

    fn mark_used(&mut self, secret_fp: u64, time: u64, code: u32) {
        let step = time / TIME_STEP;
        self.used.insert((secret_fp, step, code), true);
    }
}

fn totp_used_cache() -> &'static Mutex<TotpUsedCodeCache> {
    TOTP_USED_CODES.get_or_init(|| Mutex::new(TotpUsedCodeCache::new()))
}

/// Compute a fast fingerprint of the TOTP secret for cache keying.
/// Not cryptographic — just for HashMap key differentiation.
fn secret_fingerprint(secret: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    secret.hash(&mut hasher);
    hasher.finish()
}

/// Minimum acceptable algorithm for new TOTP enrollments.
///
/// SECURITY: Only SHA-512+ is permitted for new enrollments.
/// SHA-256 is legacy-only. Configurable via `MILNET_TOTP_MIN_ALGORITHM`.
pub const TOTP_MIN_ALGORITHM: &str = "SHA512";

/// Returns the minimum algorithm for new enrollments from env or default.
/// Only SHA-512+ is acceptable for new enrollments.
#[allow(deprecated)]
pub fn min_enrollment_algorithm() -> TotpAlgorithm {
    let algo_str = std::env::var("MILNET_TOTP_MIN_ALGORITHM")
        .unwrap_or_else(|_| "sha512".to_string());
    match TotpAlgorithm::from_str_loose(&algo_str) {
        Some(TotpAlgorithm::Sha512) => TotpAlgorithm::Sha512,
        _ => {
            // Only SHA-512+ is valid as minimum. Override anything weaker.
            TotpAlgorithm::Sha512
        }
    }
}

/// Returns true if we are in military deployment mode.
pub fn is_military_deployment() -> bool {
    std::env::var("MILNET_MILITARY_DEPLOYMENT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Validate that an algorithm is acceptable for NEW enrollments.
/// Only SHA-512+ is allowed. SHA-1 and SHA-256 are rejected.
///
/// Returns Ok(()) if acceptable, Err with reason if not.
#[allow(deprecated)]
pub fn validate_enrollment_algorithm(algorithm: TotpAlgorithm) -> Result<(), String> {
    match algorithm {
        TotpAlgorithm::Sha1 => {
            Err("SHA-1 is cryptographically broken and PROHIBITED for new TOTP enrollments. Use SHA-512.".to_string())
        }
        TotpAlgorithm::Sha256 => {
            Err("SHA-256 is rejected for new TOTP enrollments. Only SHA-512+ is permitted per MILNET policy. Set MILNET_TOTP_MIN_ALGORITHM to override.".to_string())
        }
        TotpAlgorithm::Sha512 => Ok(()),
    }
}

// ── Brute-force rate limiting ──────────────────────────────────────────

/// Configuration for TOTP rate limiting thresholds.
#[derive(Debug, Clone)]
pub struct TotpRateLimitConfig {
    /// Failures before warning-level lockout (default: 5)
    pub warn_threshold: u32,
    /// Failures before critical-level lockout (default: 10)
    pub critical_threshold: u32,
    /// Window in seconds to count failures (default: 300 = 5 min)
    pub window_secs: u64,
    /// Lockout duration in seconds for warning level (default: 900 = 15 min)
    pub warn_lockout_secs: u64,
    /// Lockout duration in seconds for critical level (default: 3600 = 1 hour)
    pub critical_lockout_secs: u64,
}

impl Default for TotpRateLimitConfig {
    fn default() -> Self {
        Self {
            warn_threshold: std::env::var("MILNET_TOTP_WARN_THRESHOLD")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(5),
            critical_threshold: std::env::var("MILNET_TOTP_CRITICAL_THRESHOLD")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(10),
            window_secs: std::env::var("MILNET_TOTP_RATE_WINDOW_SECS")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(300),
            warn_lockout_secs: std::env::var("MILNET_TOTP_WARN_LOCKOUT_SECS")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(900),
            critical_lockout_secs: std::env::var("MILNET_TOTP_CRITICAL_LOCKOUT_SECS")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(3600),
        }
    }
}

/// Per-user failure tracking entry.
#[derive(Debug, Clone)]
struct UserFailureRecord {
    /// Timestamps of recent failures (monotonic instants converted to unix-like offsets)
    failure_times: Vec<u64>,
    /// If locked out, when does it expire (unix timestamp)
    lockout_until: Option<u64>,
    /// Current lockout level for SIEM reporting
    lockout_level: LockoutLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockoutLevel {
    None,
    Warning,
    Critical,
}

/// Thread-safe TOTP brute-force rate limiter.
pub struct TotpRateLimiter {
    config: TotpRateLimitConfig,
    users: Mutex<HashMap<String, UserFailureRecord>>,
}

static GLOBAL_RATE_LIMITER: std::sync::OnceLock<TotpRateLimiter> = std::sync::OnceLock::new();

/// Get or initialize the global rate limiter.
pub fn global_rate_limiter() -> &'static TotpRateLimiter {
    GLOBAL_RATE_LIMITER.get_or_init(|| TotpRateLimiter::new(TotpRateLimitConfig::default()))
}

impl TotpRateLimiter {
    /// Create a new rate limiter with the given config.
    pub fn new(config: TotpRateLimitConfig) -> Self {
        Self {
            config,
            users: Mutex::new(HashMap::new()),
        }
    }

    /// Check if a user is currently locked out.
    /// Returns Ok(()) if allowed, Err with message if locked out.
    pub fn check_allowed(&self, user_id: &str, now_unix: u64) -> Result<(), String> {
        let users = self.users.lock().map_err(|_| "Rate limiter lock poisoned".to_string())?;
        if let Some(record) = users.get(user_id) {
            if let Some(until) = record.lockout_until {
                if now_unix < until {
                    let remaining = until - now_unix;
                    return Err(format!(
                        "TOTP locked out for user. {} seconds remaining. Level: {:?}",
                        remaining, record.lockout_level
                    ));
                }
            }
        }
        Ok(())
    }

    /// Record a failed TOTP attempt for a user.
    /// Returns the lockout level triggered (if any).
    pub fn record_failure(&self, user_id: &str, now_unix: u64) -> LockoutLevel {
        let mut users = match self.users.lock() {
            Ok(u) => u,
            Err(_) => return LockoutLevel::None,
        };

        let record = users.entry(user_id.to_string()).or_insert_with(|| UserFailureRecord {
            failure_times: Vec::new(),
            lockout_until: None,
            lockout_level: LockoutLevel::None,
        });

        // Clear expired lockout
        if let Some(until) = record.lockout_until {
            if now_unix >= until {
                record.lockout_until = None;
                record.lockout_level = LockoutLevel::None;
                record.failure_times.clear();
            }
        }

        record.failure_times.push(now_unix);

        // Prune failures outside the window
        let window_start = now_unix.saturating_sub(self.config.window_secs);
        record.failure_times.retain(|&t| t >= window_start);

        let count = record.failure_times.len() as u32;

        if count >= self.config.critical_threshold {
            record.lockout_until = Some(now_unix + self.config.critical_lockout_secs);
            record.lockout_level = LockoutLevel::Critical;
            tracing::error!(
                user_id = user_id,
                failure_count = count,
                lockout_secs = self.config.critical_lockout_secs,
                "SIEM CRITICAL: TOTP brute force detected. {} failures in {} seconds. \
                 User locked out for {} seconds.",
                count, self.config.window_secs, self.config.critical_lockout_secs
            );
            LockoutLevel::Critical
        } else if count >= self.config.warn_threshold {
            record.lockout_until = Some(now_unix + self.config.warn_lockout_secs);
            record.lockout_level = LockoutLevel::Warning;
            tracing::warn!(
                user_id = user_id,
                failure_count = count,
                lockout_secs = self.config.warn_lockout_secs,
                "SIEM WARNING: TOTP repeated failures. {} failures in {} seconds. \
                 User locked out for {} seconds.",
                count, self.config.window_secs, self.config.warn_lockout_secs
            );
            LockoutLevel::Warning
        } else {
            LockoutLevel::None
        }
    }

    /// Record a successful TOTP verification. Resets the failure counter.
    pub fn record_success(&self, user_id: &str) {
        if let Ok(mut users) = self.users.lock() {
            users.remove(user_id);
        }
    }
}

/// Rate-limited TOTP verification wrapper.
///
/// Checks rate limits before verification, records failures/successes,
/// and enforces algorithm policy for legacy vs new enrollments.
///
/// For legacy SHA-256 users: verification works but emits SIEM WARNING.
/// In military mode: SHA-256 is rejected even for legacy verification.
#[allow(deprecated)]
pub fn verify_totp_rate_limited(
    user_id: &str,
    secret: &[u8],
    code: &str,
    time: u64,
    window: u32,
    algorithm: TotpAlgorithm,
    rate_limiter: &TotpRateLimiter,
) -> Result<bool, String> {
    // Check lockout first
    rate_limiter.check_allowed(user_id, time)?;

    // Algorithm policy enforcement
    match algorithm {
        TotpAlgorithm::Sha1 => {
            rate_limiter.record_failure(user_id, time);
            return Err("SHA-1 is prohibited for all TOTP operations".to_string());
        }
        TotpAlgorithm::Sha256 => {
            if is_military_deployment() {
                rate_limiter.record_failure(user_id, time);
                tracing::error!(
                    user_id = user_id,
                    "SIEM CRITICAL: SHA-256 TOTP verification REJECTED in military deployment mode. \
                     User must re-enroll with SHA-512."
                );
                return Err(
                    "SHA-256 TOTP is rejected in military deployment mode. Re-enroll with SHA-512.".to_string()
                );
            }
            // Legacy SHA-256: allow but warn
            tracing::warn!(
                user_id = user_id,
                "SIEM WARNING: Legacy SHA-256 TOTP verification for user. \
                 Migration to SHA-512 (CNSA 2.0) is required."
            );
        }
        TotpAlgorithm::Sha512 => { /* OK */ }
    }

    let result = verify_totp_with_algorithm(secret, code, time, window, algorithm);

    if result {
        rate_limiter.record_success(user_id);
        Ok(true)
    } else {
        rate_limiter.record_failure(user_id, time);
        Ok(false)
    }
}

/// Time step in seconds (RFC 6238 default).
const TIME_STEP: u64 = 30;

/// Number of TOTP digits.
const TOTP_DIGITS: u32 = 6;

/// Generate a 32-byte random secret for TOTP enrollment.
///
/// Returns a `Zeroizing<[u8; 32]>` — the secret is automatically erased
/// from memory when dropped, preventing post-use forensic recovery.
pub fn generate_secret() -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
    let mut secret = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::getrandom(secret.as_mut())
        .map_err(|e| format!("CSPRNG entropy failure during TOTP secret generation: {e}"))?;
    Ok(secret)
}

/// Compute HMAC for TOTP using the specified algorithm.
/// Returns the full HMAC output bytes.
///
/// SECURITY: SHA-1 is rejected unconditionally. It is cryptographically broken
/// and prohibited for all MILNET operations.
#[allow(deprecated)]
fn hmac_totp(algorithm: TotpAlgorithm, secret: &[u8], counter_bytes: &[u8; 8]) -> Result<Vec<u8>, String> {
    match algorithm {
        TotpAlgorithm::Sha1 => {
            tracing::error!(
                "SECURITY: SHA-1 TOTP computation REJECTED. SHA-1 is cryptographically \
                 broken and has been removed from MILNET. Migrate all TOTP enrollments \
                 to SHA-512 (CNSA 2.0) immediately."
            );
            Err("SHA-1 is prohibited for MILNET TOTP — migrate to SHA-512".to_string())
        }
        TotpAlgorithm::Sha256 => {
            let mut mac = HmacSha256::new_from_slice(secret)
                .map_err(|_| "HMAC-SHA256 key initialization failed".to_string())?;
            mac.update(counter_bytes);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        TotpAlgorithm::Sha512 => {
            let mut mac = HmacSha512::new_from_slice(secret)
                .map_err(|_| "HMAC-SHA512 key initialization failed".to_string())?;
            mac.update(counter_bytes);
            Ok(mac.finalize().into_bytes().to_vec())
        }
    }
}

/// Generate a 6-digit TOTP code for the given secret and unix timestamp.
///
/// Implements HOTP (RFC 4226) with time-based counter per RFC 6238.
/// Uses dynamic truncation to extract a 6-digit code from the HMAC result.
/// Uses SHA-512 (CNSA 2.0 compliant).
pub fn generate_totp(secret: &[u8], time: u64) -> String {
    generate_totp_with_algorithm(secret, time, TotpAlgorithm::Sha512)
}

/// Generate a 6-digit TOTP code using the specified hash algorithm.
///
/// Implements HOTP (RFC 4226) with time-based counter per RFC 6238.
/// Dynamic truncation offset is taken from the last byte of the HMAC output,
/// which works correctly for all hash sizes per RFC 6238 Section 1.2.
///
/// SECURITY: SHA-1 is rejected and returns "000000".
#[allow(deprecated)]
pub fn generate_totp_with_algorithm(secret: &[u8], time: u64, algorithm: TotpAlgorithm) -> String {
    let counter = time / TIME_STEP;
    let counter_bytes = counter.to_be_bytes();

    // HMAC accepts any key length per RFC 2104; this should never fail.
    let result = match hmac_totp(algorithm, secret, &counter_bytes) {
        Ok(v) => v,
        Err(_) => return "000000".to_string(),
    };

    // Dynamic truncation per RFC 4226 Section 5.4
    // Offset is derived from the last byte of the HMAC output regardless of hash size.
    let last_byte_idx = result.len() - 1;
    let offset = (result[last_byte_idx] & 0x0F) as usize;
    let binary = ((result[offset] as u32 & 0x7F) << 24)
        | ((result[offset + 1] as u32) << 16)
        | ((result[offset + 2] as u32) << 8)
        | (result[offset + 3] as u32);

    let otp = binary % 10u32.pow(TOTP_DIGITS);
    format!("{:0width$}", otp, width = TOTP_DIGITS as usize)
}

/// Verify a TOTP code against the given secret and time, checking +/- window steps.
/// Uses SHA-512 (CNSA 2.0 compliant).
///
/// Uses constant-time comparison to prevent timing side-channels on the code value.
/// Per RFC 6238 Section 5.2, each code can only be used once -- replay within the
/// same time step is rejected via a global used-code cache.
pub fn verify_totp(secret: &[u8], code: &str, time: u64, window: u32) -> bool {
    verify_totp_with_algorithm(secret, code, time, window, TotpAlgorithm::Sha512)
}

/// Verify a TOTP code using the specified hash algorithm.
///
/// Uses constant-time comparison to prevent timing side-channels on the code value.
/// Per RFC 6238 Section 5.2, each code can only be used once — replay within the
/// same time step is rejected via a global used-code cache.
///
/// SECURITY: SHA-1 is REJECTED unconditionally -- returns `false` and logs an error.
#[allow(deprecated)]
pub fn verify_totp_with_algorithm(
    secret: &[u8],
    code: &str,
    time: u64,
    window: u32,
    algorithm: TotpAlgorithm,
) -> bool {
    use subtle::ConstantTimeEq;

    // SECURITY: SHA-1 is cryptographically broken and REJECTED for all verification.
    // Users with SHA-1 enrollments MUST re-enroll with SHA-512.
    if algorithm == TotpAlgorithm::Sha1 {
        tracing::error!(
            "SECURITY: SHA-1 TOTP verification REFUSED. SHA-1 is cryptographically \
             broken and has been removed from MILNET. The user MUST re-enroll with \
             SHA-512 (CNSA 2.0). This is NOT a warning — the token is REJECTED."
        );
        return false;
    }

    // Enforce maximum window to prevent callers from degrading security
    let window = window.min(2);

    let code_num: u32 = match code.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };

    let fp = secret_fingerprint(secret);

    // Check if this exact code was already used for this secret in this time step
    if let Ok(mut cache) = totp_used_cache().lock() {
        if cache.is_used(fp, time, code_num) {
            return false; // RFC 6238 §5.2: reject second attempt
        }
    }

    let mut result = 0u8;
    for i in 0..=(window * 2) {
        let check_time = if i <= window {
            time.wrapping_sub((window as u64 - i as u64) * TIME_STEP)
        } else {
            time + (i as u64 - window as u64) * TIME_STEP
        };
        let expected = generate_totp_with_algorithm(secret, check_time, algorithm);
        // Accumulate match results in constant time
        result |= code.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8();
    }

    if result == 1 {
        // Mark this code as used so it cannot be replayed
        if let Ok(mut cache) = totp_used_cache().lock() {
            cache.mark_used(fp, time, code_num);
        }
        true
    } else {
        false
    }
}

/// Migrate a user from a legacy TOTP algorithm to SHA-512 (CNSA 2.0).
///
/// Returns the new secret. The caller is responsible for:
/// 1. Storing the new secret in the user's record
/// 2. Presenting a new QR code for re-enrollment
/// 3. Verifying the user can produce a valid code before finalizing
///
/// The old secret should be kept until the user confirms the new enrollment,
/// then securely erased.
///
/// SECURITY: Upgraded from SHA-256 to SHA-512 target to comply with CNSA 2.0.
pub fn migrate_to_sha256() -> Result<(zeroize::Zeroizing<[u8; 32]>, TotpAlgorithm), String> {
    let secret = generate_secret()?;
    tracing::info!("TOTP migration: generated new SHA-512 (CNSA 2.0) secret for re-enrollment");
    Ok((secret, TotpAlgorithm::Sha512))
}

/// Build an otpauth:// URI for QR code generation.
///
/// SECURITY: Uses SHA-512 (CNSA 2.0) for new enrollments. SHA-1 is no longer
/// available through this function. Use `secret_to_otpauth_uri_with_algorithm`
/// directly only for legacy migration scenarios.
pub fn secret_to_otpauth_uri(secret: &[u8], issuer: &str, account: &str) -> String {
    secret_to_otpauth_uri_with_algorithm(secret, issuer, account, TotpAlgorithm::Sha512)
}

/// Build an otpauth:// URI for QR code generation with specified algorithm.
pub fn secret_to_otpauth_uri_with_algorithm(
    secret: &[u8],
    issuer: &str,
    account: &str,
    algorithm: TotpAlgorithm,
) -> String {
    let encoded_secret = encode_base32(secret);
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm={}&digits=6&period=30",
        issuer, account, encoded_secret, issuer, algorithm.otpauth_name()
    )
}

/// RFC 4648 Base32 encoding (no padding).
pub fn encode_base32(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits_left: u32 = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let index = ((buffer >> bits_left) & 0x1F) as usize;
            result.push(ALPHABET[index] as char);
        }
    }
    if bits_left > 0 {
        let index = ((buffer << (5 - bits_left)) & 0x1F) as usize;
        result.push(ALPHABET[index] as char);
    }
    result
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    /// generate_totp now uses SHA-512. Verify round-trip works.
    #[test]
    fn test_generate_totp_sha512_roundtrip() {
        let secret = b"1234567890123456789012345678901234567890123456789012345678901234";
        let time = 59u64;
        let code = generate_totp(secret, time);
        assert_eq!(code.len(), 6);
        assert!(verify_totp(secret, &code, time, 0));
    }

    /// SHA-1 TOTP is REJECTED — generate returns "000000" (HMAC error fallback).
    #[test]
    fn test_sha1_generate_rejected() {
        let secret = b"12345678901234567890";
        let code = generate_totp_with_algorithm(secret, 59, TotpAlgorithm::Sha1);
        assert_eq!(code, "000000", "SHA-1 TOTP must be rejected");
    }

    /// SHA-1 TOTP verification is REJECTED — always returns false.
    #[test]
    fn test_sha1_verify_rejected() {
        let secret = b"12345678901234567890";
        // "287082" was the old RFC 6238 SHA-1 test vector — must be rejected now
        assert!(!verify_totp_with_algorithm(secret, "287082", 59, 0, TotpAlgorithm::Sha1));
    }

    #[test]
    fn test_verify_totp_exact() {
        let secret = b"1234567890123456789012345678901234567890123456789012345678901234";
        // Use a distinct time step from other tests so the replay-prevention cache
        // does not reject the code when tests run in the same process.
        let time = 1_000_059u64;
        let code = generate_totp(secret, time);
        assert!(verify_totp(secret, &code, time, 0));
    }

    #[test]
    fn test_verify_totp_with_window() {
        let secret = b"1234567890123456789012345678901234567890123456789012345678901234";
        let time = 59u64;
        let code = generate_totp(secret, time);
        // verify at time=89 (step 2) with window=1
        assert!(verify_totp(secret, &code, 89, 1));
    }

    #[test]
    fn test_verify_totp_wrong_code() {
        let secret = b"1234567890123456789012345678901234567890123456789012345678901234";
        assert!(!verify_totp(secret, "000000", 59, 1));
    }

    #[test]
    fn test_generate_secret_is_random() {
        let s1 = generate_secret().unwrap();
        let s2 = generate_secret().unwrap();
        assert_ne!(*s1, *s2);
    }

    #[test]
    fn test_encode_base32() {
        // Known test: "Hello!" -> "JBSWY3DPEE"
        // Actually let's use a simpler known vector
        assert_eq!(encode_base32(b""), "");
        assert_eq!(encode_base32(b"f"), "MY");
        assert_eq!(encode_base32(b"fo"), "MZXQ");
        assert_eq!(encode_base32(b"foo"), "MZXW6");
        assert_eq!(encode_base32(b"foob"), "MZXW6YQ");
        assert_eq!(encode_base32(b"fooba"), "MZXW6YTB");
        assert_eq!(encode_base32(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn test_otpauth_uri() {
        let secret = b"12345678901234567890";
        let uri = secret_to_otpauth_uri(secret, "MILNET", "user@example.com");
        assert!(uri.starts_with("otpauth://totp/MILNET:user@example.com?"));
        // SECURITY: New enrollments use SHA-512 (CNSA 2.0), not SHA-1
        assert!(uri.contains("algorithm=SHA512"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }

    // ── SHA-256 / SHA-512 TOTP tests ────────────────────────────────────

    #[test]
    fn test_totp_sha256_roundtrip() {
        let secret = b"12345678901234567890123456789012";
        let time = 59u64;
        let code = generate_totp_with_algorithm(secret, time, TotpAlgorithm::Sha256);
        assert_eq!(code.len(), 6);
        assert!(verify_totp_with_algorithm(secret, &code, time, 0, TotpAlgorithm::Sha256));
    }

    #[test]
    fn test_totp_sha512_roundtrip() {
        let secret = b"1234567890123456789012345678901234567890123456789012345678901234";
        let time = 59u64;
        let code = generate_totp_with_algorithm(secret, time, TotpAlgorithm::Sha512);
        assert_eq!(code.len(), 6);
        assert!(verify_totp_with_algorithm(secret, &code, time, 0, TotpAlgorithm::Sha512));
    }

    #[test]
    fn test_sha256_differs_from_sha512() {
        let secret = b"1234567890123456789012345678901234567890123456789012345678901234";
        let time = 59u64;
        let sha256_code = generate_totp_with_algorithm(secret, time, TotpAlgorithm::Sha256);
        let sha512_code = generate_totp_with_algorithm(secret, time, TotpAlgorithm::Sha512);
        // Different algorithms should (overwhelmingly likely) produce different codes
        assert_ne!(sha256_code, sha512_code, "SHA-256 and SHA-512 TOTP codes should differ (probabilistic)");
    }

    #[test]
    fn test_otpauth_uri_with_sha256() {
        let secret = b"12345678901234567890";
        let uri = secret_to_otpauth_uri_with_algorithm(secret, "MILNET", "user@example.com", TotpAlgorithm::Sha256);
        assert!(uri.contains("algorithm=SHA256"));
    }

    #[test]
    fn test_otpauth_uri_with_sha512() {
        let secret = b"12345678901234567890";
        let uri = secret_to_otpauth_uri_with_algorithm(secret, "MILNET", "user@example.com", TotpAlgorithm::Sha512);
        assert!(uri.contains("algorithm=SHA512"));
    }

    #[test]
    fn test_default_algorithm_is_sha512() {
        // SECURITY: When env var is not set, default should be SHA-512 (CNSA 2.0)
        std::env::remove_var("MILNET_TOTP_ALGORITHM");
        assert_eq!(default_totp_algorithm(), TotpAlgorithm::Sha512);
    }

    #[test]
    fn test_migrate_to_sha512() {
        let (secret, algo) = migrate_to_sha256().unwrap();
        // SECURITY: Migration target is now SHA-512 (CNSA 2.0)
        assert_eq!(algo, TotpAlgorithm::Sha512);
        assert_ne!(*secret, [0u8; 32], "migrated secret must not be all zeros");
    }

    #[test]
    fn test_is_legacy_algorithm() {
        assert!(is_legacy_algorithm("sha1"));
        assert!(is_legacy_algorithm("SHA-1"));
        assert!(is_legacy_algorithm("SHA1"));
        assert!(is_legacy_algorithm("sha256"));
        assert!(is_legacy_algorithm("SHA-256"));
        assert!(!is_legacy_algorithm("SHA-512"));
        assert!(!is_legacy_algorithm("md5")); // not legacy, just unsupported
    }

    #[test]
    fn test_sha1_blocked_for_new_enrollments() {
        // SECURITY: Even if explicitly configured, SHA-1 is overridden to SHA-512
        std::env::set_var("MILNET_TOTP_ALGORITHM", "sha1");
        let algo = default_totp_algorithm();
        assert_eq!(algo, TotpAlgorithm::Sha512, "SHA-1 must be blocked for new enrollments");
        std::env::remove_var("MILNET_TOTP_ALGORITHM");
    }

    #[test]
    fn test_sha256_blocked_for_new_enrollments() {
        std::env::set_var("MILNET_TOTP_ALGORITHM", "sha256");
        let algo = default_totp_algorithm();
        assert_eq!(algo, TotpAlgorithm::Sha512, "SHA-256 must be blocked for new enrollments");
        std::env::remove_var("MILNET_TOTP_ALGORITHM");
    }

    // ── Enrollment algorithm validation tests ──────────────────────────

    #[test]
    fn test_validate_enrollment_sha512_ok() {
        assert!(validate_enrollment_algorithm(TotpAlgorithm::Sha512).is_ok());
    }

    #[test]
    fn test_validate_enrollment_sha256_rejected() {
        let err = validate_enrollment_algorithm(TotpAlgorithm::Sha256);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("SHA-256 is rejected"));
    }

    #[test]
    fn test_validate_enrollment_sha1_rejected() {
        let err = validate_enrollment_algorithm(TotpAlgorithm::Sha1);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("SHA-1"));
    }

    #[test]
    fn test_min_enrollment_algorithm_default() {
        std::env::remove_var("MILNET_TOTP_MIN_ALGORITHM");
        assert_eq!(min_enrollment_algorithm(), TotpAlgorithm::Sha512);
    }

    #[test]
    fn test_min_enrollment_algorithm_rejects_weak() {
        std::env::set_var("MILNET_TOTP_MIN_ALGORITHM", "sha256");
        // SHA-256 is too weak, should override to SHA-512
        assert_eq!(min_enrollment_algorithm(), TotpAlgorithm::Sha512);
        std::env::remove_var("MILNET_TOTP_MIN_ALGORITHM");
    }

    // ── Rate limiter tests ─────────────────────────────────────────────

    #[test]
    fn test_rate_limiter_allows_initial() {
        let rl = TotpRateLimiter::new(TotpRateLimitConfig::default());
        assert!(rl.check_allowed("user1", 1000).is_ok());
    }

    #[test]
    fn test_rate_limiter_warn_lockout_at_5_failures() {
        let config = TotpRateLimitConfig {
            warn_threshold: 5,
            critical_threshold: 10,
            window_secs: 300,
            warn_lockout_secs: 900,
            critical_lockout_secs: 3600,
        };
        let rl = TotpRateLimiter::new(config);
        let now = 1_000_000u64;

        for i in 0..4 {
            let level = rl.record_failure("user1", now + i);
            assert_eq!(level, LockoutLevel::None);
        }
        let level = rl.record_failure("user1", now + 4);
        assert_eq!(level, LockoutLevel::Warning);

        // Now locked out
        let err = rl.check_allowed("user1", now + 5);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("locked out"));

        // After lockout expires
        assert!(rl.check_allowed("user1", now + 901).is_ok());
    }

    #[test]
    fn test_rate_limiter_critical_lockout_at_10_failures() {
        let config = TotpRateLimitConfig {
            warn_threshold: 5,
            critical_threshold: 10,
            window_secs: 300,
            warn_lockout_secs: 900,
            critical_lockout_secs: 3600,
        };
        let rl = TotpRateLimiter::new(config);
        let now = 2_000_000u64;

        // Push past warn into critical (need fresh failures after lockout clears)
        // Record 10 failures rapidly
        for i in 0..10 {
            rl.record_failure("user2", now + i);
        }

        let err = rl.check_allowed("user2", now + 11);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("locked out"));

        // Still locked after 900s (warn would have expired, but critical is 3600)
        let err = rl.check_allowed("user2", now + 1000);
        assert!(err.is_err());

        // Unlocked after 3600s
        assert!(rl.check_allowed("user2", now + 3601).is_ok());
    }

    #[test]
    fn test_rate_limiter_success_resets_counter() {
        let config = TotpRateLimitConfig {
            warn_threshold: 5,
            critical_threshold: 10,
            window_secs: 300,
            warn_lockout_secs: 900,
            critical_lockout_secs: 3600,
        };
        let rl = TotpRateLimiter::new(config);
        let now = 3_000_000u64;

        // 4 failures, then success
        for i in 0..4 {
            rl.record_failure("user3", now + i);
        }
        rl.record_success("user3");

        // Counter reset, 4 more failures should not trigger lockout
        for i in 0..4 {
            let level = rl.record_failure("user3", now + 10 + i);
            assert_eq!(level, LockoutLevel::None);
        }
    }

    #[test]
    fn test_rate_limiter_failures_outside_window_ignored() {
        let config = TotpRateLimitConfig {
            warn_threshold: 5,
            critical_threshold: 10,
            window_secs: 300,
            warn_lockout_secs: 900,
            critical_lockout_secs: 3600,
        };
        let rl = TotpRateLimiter::new(config);

        // 4 failures at t=0
        for i in 0..4 {
            rl.record_failure("user4", 4_000_000 + i);
        }
        // 1 failure at t=301 (outside window, old ones pruned)
        let level = rl.record_failure("user4", 4_000_301);
        assert_eq!(level, LockoutLevel::None, "Old failures outside window should be pruned");
    }

    #[test]
    fn test_rate_limiter_independent_users() {
        let config = TotpRateLimitConfig {
            warn_threshold: 5,
            critical_threshold: 10,
            window_secs: 300,
            warn_lockout_secs: 900,
            critical_lockout_secs: 3600,
        };
        let rl = TotpRateLimiter::new(config);
        let now = 5_000_000u64;

        // Lock out userA
        for i in 0..5 {
            rl.record_failure("userA", now + i);
        }
        assert!(rl.check_allowed("userA", now + 6).is_err());

        // userB unaffected
        assert!(rl.check_allowed("userB", now + 6).is_ok());
    }

    // ── verify_totp_rate_limited tests ─────────────────────────────────

    #[test]
    fn test_verify_rate_limited_sha512_success() {
        let rl = TotpRateLimiter::new(TotpRateLimitConfig::default());
        let secret = b"1234567890123456789012345678901234567890123456789012345678901234";
        let time = 6_000_059u64;
        let code = generate_totp(secret, time);

        let result = verify_totp_rate_limited("rl_user1", secret, &code, time, 0, TotpAlgorithm::Sha512, &rl);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_rate_limited_sha256_legacy_allowed() {
        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
        let rl = TotpRateLimiter::new(TotpRateLimitConfig::default());
        let secret = b"12345678901234567890123456789012";
        let time = 7_000_059u64;
        let code = generate_totp_with_algorithm(secret, time, TotpAlgorithm::Sha256);

        let result = verify_totp_rate_limited("rl_user2", secret, &code, time, 0, TotpAlgorithm::Sha256, &rl);
        assert!(result.is_ok(), "Legacy SHA-256 verification should be allowed in non-military mode");
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_rate_limited_sha256_rejected_military() {
        std::env::set_var("MILNET_MILITARY_DEPLOYMENT", "true");
        let rl = TotpRateLimiter::new(TotpRateLimitConfig::default());
        let secret = b"12345678901234567890123456789012";
        let time = 8_000_059u64;
        let code = generate_totp_with_algorithm(secret, time, TotpAlgorithm::Sha256);

        let result = verify_totp_rate_limited("rl_user3", secret, &code, time, 0, TotpAlgorithm::Sha256, &rl);
        assert!(result.is_err(), "SHA-256 must be rejected in military mode");
        assert!(result.unwrap_err().contains("military deployment"));
        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
    }

    #[test]
    fn test_verify_rate_limited_sha1_always_rejected() {
        let rl = TotpRateLimiter::new(TotpRateLimitConfig::default());
        let secret = b"12345678901234567890";
        let time = 9_000_059u64;

        let result = verify_totp_rate_limited("rl_user4", secret, "000000", time, 0, TotpAlgorithm::Sha1, &rl);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("SHA-1"));
    }

    #[test]
    fn test_verify_rate_limited_lockout_after_failures() {
        let config = TotpRateLimitConfig {
            warn_threshold: 3,
            critical_threshold: 6,
            window_secs: 300,
            warn_lockout_secs: 60,
            critical_lockout_secs: 120,
        };
        let rl = TotpRateLimiter::new(config);
        let secret = b"1234567890123456789012345678901234567890123456789012345678901234";
        let time = 10_000_059u64;

        // 3 wrong codes
        for _ in 0..3 {
            let result = verify_totp_rate_limited("rl_user5", secret, "999999", time, 0, TotpAlgorithm::Sha512, &rl);
            assert!(result.is_ok()); // no error, just false
        }

        // Now locked out -- even correct code should fail
        let code = generate_totp(secret, time);
        let result = verify_totp_rate_limited("rl_user5", secret, &code, time, 0, TotpAlgorithm::Sha512, &rl);
        assert!(result.is_err(), "Should be locked out after threshold failures");
    }

    #[test]
    fn test_algorithm_from_str() {
        // SHA-1 is still parseable (so configs can be detected and rejected)
        assert_eq!(TotpAlgorithm::from_str_loose("sha1"), Some(TotpAlgorithm::Sha1));
        assert_eq!(TotpAlgorithm::from_str_loose("SHA-256"), Some(TotpAlgorithm::Sha256));
        assert_eq!(TotpAlgorithm::from_str_loose("sha512"), Some(TotpAlgorithm::Sha512));
        assert_eq!(TotpAlgorithm::from_str_loose("md5"), None);
    }

    // ── TOTP replay prevention tests (RFC 6238 §5.2) ───────────────────

    #[test]
    fn test_totp_replay_prevention() {
        // Use a unique secret so the cache doesn't interfere with other tests
        let mut secret = [0u8; 64];
        getrandom::getrandom(&mut secret).unwrap();
        let time = 1_700_000_000u64; // fixed timestamp
        let code = generate_totp(&secret, time);

        // First use should succeed
        assert!(verify_totp(&secret, &code, time, 0), "first use should succeed");
        // Second use of the same code in the same time step MUST fail
        assert!(!verify_totp(&secret, &code, time, 0), "replay MUST be rejected (RFC 6238 §5.2)");
    }

    #[test]
    fn test_totp_window_capped_at_2() {
        // Even if caller passes window=10, it should be capped at 2
        let secret = b"1234567890123456789012345678901234567890123456789012345678901234";
        // Code for time=59 (step 1), try to verify at a time far away with window=10
        // Window is capped at 2, so this should NOT match step 1 from step 10+
        let code = generate_totp(secret, 59);
        // At step 10 (time=300), window=2 covers steps 8-12, not step 1
        assert!(!verify_totp(secret, &code, 300, 10));
    }

    #[test]
    fn test_totp_different_secrets_independent_replay() {
        let mut s1 = [0u8; 64];
        let mut s2 = [0u8; 64];
        getrandom::getrandom(&mut s1).unwrap();
        getrandom::getrandom(&mut s2).unwrap();
        let time = 1_700_001_000u64;

        let code1 = generate_totp(&s1, time);
        let code2 = generate_totp(&s2, time);

        // Using code1 for s1 should not affect s2
        assert!(verify_totp(&s1, &code1, time, 0));
        if code1 == code2 {
            // Same code, different secret — each has its own replay tracking
            assert!(verify_totp(&s2, &code2, time, 0));
        }
    }
}
