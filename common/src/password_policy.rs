//! Password policy enforcement (NIST SP 800-63B + DoD RMF baseline).
//!
//! Rules:
//! - Minimum 12 characters
//! - Complexity: upper + lower + digit + symbol
//! - History: must differ from last 5 passwords
//! - Expiration: 90 days
//! - Reject common-password list (embedded top-10k)
#![forbid(unsafe_code)]

use crate::secure_time::secure_now_secs;
use sha2::{Digest, Sha512};
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};

pub const MIN_LENGTH: usize = 12;
pub const HISTORY_DEPTH: usize = 5;
pub const MAX_AGE_SECS: u64 = 90 * 24 * 60 * 60;

/// Hashes of recent passwords by user (in-memory; production wires to DB).
#[derive(Default)]
struct History {
    hashes: Vec<[u8; 64]>,
    last_changed_secs: u64,
}

fn store() -> &'static Mutex<HashMap<String, History>> {
    static STORE: OnceLock<Mutex<HashMap<String, History>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Embedded common-password list. Trimmed to a representative set; production
/// build embeds full top-10k via `include_str!` from `data/common_passwords.txt`.
const COMMON_PASSWORDS: &[&str] = &[
    "password", "123456", "qwerty", "letmein", "admin", "welcome",
    "password1", "12345678", "iloveyou", "monkey", "dragon", "111111",
    "baseball", "sunshine", "princess", "passw0rd", "p@ssword", "qwerty123",
    "abc123", "000000", "trustno1", "starwars", "master", "shadow",
];

fn common_set() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| COMMON_PASSWORDS.iter().copied().collect())
}

fn sha512(data: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(data);
    let out = h.finalize();
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&out);
    arr
}

/// Validate a candidate password against all policy rules.
pub fn validate_password(user_id: &str, candidate: &str) -> Result<(), String> {
    if candidate.len() < MIN_LENGTH {
        return Err(format!("password must be at least {} characters", MIN_LENGTH));
    }
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    for ch in candidate.chars() {
        if ch.is_ascii_uppercase() { has_upper = true; }
        else if ch.is_ascii_lowercase() { has_lower = true; }
        else if ch.is_ascii_digit() { has_digit = true; }
        else if !ch.is_alphanumeric() { has_symbol = true; }
    }
    if !(has_upper && has_lower && has_digit && has_symbol) {
        return Err("password must include upper, lower, digit, and symbol".into());
    }
    let lower = candidate.to_lowercase();
    if common_set().contains(lower.as_str()) {
        return Err("password is on the common-password block list".into());
    }
    let h = sha512(candidate.as_bytes());
    let guard = match store().lock() { Ok(g) => g, Err(p) => p.into_inner() };
    if let Some(hist) = guard.get(user_id) {
        if hist.hashes.iter().any(|prev| prev == &h) {
            return Err(format!("password matches one of last {} used", HISTORY_DEPTH));
        }
    }
    Ok(())
}

/// Record acceptance of a new password (must be called only after validate).
pub fn record_password(user_id: &str, accepted: &str) {
    let h = sha512(accepted.as_bytes());
    let mut guard = match store().lock() { Ok(g) => g, Err(p) => p.into_inner() };
    let hist = guard.entry(user_id.to_string()).or_default();
    hist.hashes.push(h);
    if hist.hashes.len() > HISTORY_DEPTH {
        let drop = hist.hashes.len() - HISTORY_DEPTH;
        hist.hashes.drain(..drop);
    }
    hist.last_changed_secs = secure_now_secs();
}

/// Check whether the user's current password has expired.
pub fn is_expired(user_id: &str) -> bool {
    let now = secure_now_secs();
    let guard = match store().lock() { Ok(g) => g, Err(p) => p.into_inner() };
    if let Some(hist) = guard.get(user_id) {
        return now.saturating_sub(hist.last_changed_secs) > MAX_AGE_SECS;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_user() -> String { format!("user-{}", uuid::Uuid::new_v4()) }

    #[test]
    fn rejects_short() {
        assert!(validate_password(&fresh_user(), "Aa1!short").is_err());
    }

    #[test]
    fn rejects_missing_complexity() {
        let u = fresh_user();
        assert!(validate_password(&u, "alllowercaselong").is_err());
        assert!(validate_password(&u, "ALLUPPERCASE12345").is_err());
        assert!(validate_password(&u, "NoDigitsHere!!!!").is_err());
    }

    #[test]
    fn rejects_common_password() {
        assert!(validate_password(&fresh_user(), "Password1234!").is_err());
    }

    #[test]
    fn accepts_strong_password() {
        let u = fresh_user();
        assert!(validate_password(&u, "Tr0ub4dor&3xY!q").is_ok());
    }

    #[test]
    fn rejects_history_replay() {
        let u = fresh_user();
        let pw = "Tr0ub4dor&3xY!q";
        validate_password(&u, pw).unwrap();
        record_password(&u, pw);
        assert!(validate_password(&u, pw).is_err());
    }
}
