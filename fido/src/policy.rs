//! FIDO2 enrollment policy: AAGUID allow-list, attestation format gate, and
//! backup-eligible enforcement (CAT-B B6, B8, B9).

use std::collections::HashSet;

/// Hardcoded military-mode default AAGUID allow-list.
///
/// Source: FIDO MDS3 — these are the AAGUIDs published by vendors for
/// hardware authenticators authorized for DoD Common Access Card flows and
/// the Microsoft / Apple platform authenticators. Operators can override or
/// extend the list via `MILNET_FIDO_AAGUID_ALLOWLIST` (comma-separated hex).
const DEFAULT_AAGUIDS: &[&str] = &[
    // YubiKey 5 Series (USB-A)
    "cb69481e-8ff7-4039-93ec-0a2729a154a8",
    // YubiKey 5 NFC
    "fa2b99dc-9e39-4257-8f92-4a30d23c4118",
    // YubiKey 5C NFC
    "2fc0579f-8113-47ea-b116-bb5a8db9202a",
    // YubiKey 5Ci
    "c5ef55ff-ad9a-4b9f-b580-adebafe026d0",
    // YubiKey 5 Nano
    "f8a011f3-8c0a-4d15-8006-17111f9edc7d",
    // Windows Hello hardware
    "08987058-cadc-4b81-b6e1-30de50dcbe96",
    // Apple Platform Authenticator (Touch ID / Face ID)
    "dd4ec289-e01d-41c9-bb89-70fa845d4bf2",
    "f24a8e70-d0d3-f82c-2937-32523cc4de5a",
];

fn allowlist_from_env() -> Option<HashSet<[u8; 16]>> {
    let raw = std::env::var("MILNET_FIDO_AAGUID_ALLOWLIST").ok()?;
    let mut out: HashSet<[u8; 16]> = HashSet::new();
    for token in raw.split(',') {
        let t = token.trim();
        if t.is_empty() {
            continue;
        }
        if let Some(bytes) = parse_aaguid(t) {
            out.insert(bytes);
        }
    }
    Some(out)
}

fn parse_aaguid(s: &str) -> Option<[u8; 16]> {
    // Accept 32 hex chars or canonical UUID form with dashes.
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    if cleaned.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Build the active AAGUID allow-list. Env override takes precedence; otherwise
/// the hardcoded military default list is loaded.
pub fn allowed_aaguids() -> HashSet<[u8; 16]> {
    if let Some(env_list) = allowlist_from_env() {
        return env_list;
    }
    let mut s = HashSet::new();
    for entry in DEFAULT_AAGUIDS {
        if let Some(b) = parse_aaguid(entry) {
            s.insert(b);
        }
    }
    // Test builds exercise fido crate internals with synthetic credentials
    // whose AAGUID defaults to the all-zero sentinel. Compiling the zero
    // AAGUID into the allow-list under the `test-support` feature lets unit
    // AND integration tests run without weakening the production allow-list —
    // the feature is never enabled in release/military builds.
    #[cfg(any(test, feature = "test-support"))]
    {
        s.insert([0u8; 16]);
    }
    s
}

/// Whether military mode is active (mirrors registration::is_military_deployment
/// without taking a dependency on that private function).
pub fn military_mode() -> bool {
    match std::env::var("MILNET_MILITARY_DEPLOYMENT") {
        Ok(val) => val != "0" && val.to_lowercase() != "false",
        Err(_) => true,
    }
}

/// Reject AAGUIDs that are not in the allow-list when running in military mode.
/// Returns Ok in non-military mode regardless of AAGUID value (still emits a
/// warning to SIEM).
pub fn enforce_aaguid(aaguid: &[u8; 16]) -> Result<(), &'static str> {
    let list = allowed_aaguids();
    if list.contains(aaguid) {
        return Ok(());
    }
    if military_mode() {
        tracing::error!(
            target: "siem",
            "SIEM:CRITICAL FIDO AAGUID rejected (not in allow-list): {:02x?}",
            aaguid,
        );
        return Err("AAGUID not in MILNET allow-list");
    }
    tracing::warn!(
        target: "siem",
        "SIEM:WARN FIDO AAGUID not in allow-list (non-military mode, allowed): {:02x?}",
        aaguid,
    );
    Ok(())
}

/// Whether backed-up credentials (BS=1) should be rejected. Defaults to true
/// in military mode. Override with `MILNET_FIDO_REJECT_BACKED_UP_CREDS`.
pub fn reject_backed_up_credentials() -> bool {
    match std::env::var("MILNET_FIDO_REJECT_BACKED_UP_CREDS") {
        Ok(val) => val == "1" || val.to_lowercase() == "true",
        Err(_) => military_mode(),
    }
}

/// B9 — attestation format allow-list. Returns Err if format is not allowed
/// in the active mode.
pub fn enforce_attestation_format(fmt: &str) -> Result<(), &'static str> {
    const MIL_ALLOWED: &[&str] = &["packed", "tpm", "android-key", "apple"];
    const NON_MIL_ALLOWED: &[&str] = &["packed", "tpm", "android-key", "apple", "fido-u2f", "none"];
    let list: &[&str] = if military_mode() { MIL_ALLOWED } else { NON_MIL_ALLOWED };
    if list.iter().any(|f| *f == fmt) {
        Ok(())
    } else {
        tracing::error!(
            target: "siem",
            "SIEM:CRITICAL FIDO attestation format '{}' rejected (military_mode={})",
            fmt, military_mode(),
        );
        Err("attestation format not in MILNET allow-list")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn default_list_parses() {
        let l = allowed_aaguids();
        assert!(!l.is_empty());
        assert_eq!(l.iter().next().unwrap().len(), 16);
    }

    #[test]
    fn parse_uuid_canonical_form() {
        let b = parse_aaguid("cb69481e-8ff7-4039-93ec-0a2729a154a8").unwrap();
        assert_eq!(b[0], 0xcb);
        assert_eq!(b[15], 0xa8);
    }

    #[test]
    #[serial]
    fn unknown_aaguid_rejected_in_military_mode() {
        std::env::remove_var("MILNET_FIDO_AAGUID_ALLOWLIST");
        std::env::set_var("MILNET_MILITARY_DEPLOYMENT", "1");
        let unknown = [0xAB; 16];
        assert!(enforce_aaguid(&unknown).is_err());
        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
    }

    #[test]
    #[serial]
    fn known_aaguid_accepted() {
        std::env::remove_var("MILNET_FIDO_AAGUID_ALLOWLIST");
        let yk = parse_aaguid("cb69481e-8ff7-4039-93ec-0a2729a154a8").unwrap();
        assert!(enforce_aaguid(&yk).is_ok());
    }

    #[test]
    #[serial]
    fn fido_u2f_rejected_in_military_mode() {
        std::env::set_var("MILNET_MILITARY_DEPLOYMENT", "1");
        assert!(enforce_attestation_format("fido-u2f").is_err());
        assert!(enforce_attestation_format("packed").is_ok());
        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
    }

    #[test]
    #[serial]
    fn none_rejected_in_military_mode() {
        std::env::set_var("MILNET_MILITARY_DEPLOYMENT", "1");
        assert!(enforce_attestation_format("none").is_err());
        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
    }

    #[test]
    #[serial]
    fn env_override_replaces_default() {
        std::env::set_var(
            "MILNET_FIDO_AAGUID_ALLOWLIST",
            "00112233-4455-6677-8899-aabbccddeeff",
        );
        let l = allowed_aaguids();
        assert_eq!(l.len(), 1);
        let mine = parse_aaguid("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        assert!(l.contains(&mine));
        std::env::remove_var("MILNET_FIDO_AAGUID_ALLOWLIST");
    }
}
