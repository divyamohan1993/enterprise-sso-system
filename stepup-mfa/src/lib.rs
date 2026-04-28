//! Step-up MFA enforcement (J6).
//!
//! A pure decision engine: given a request URL/method and the timestamp of
//! the user's last MFA assertion, decide whether the operation is allowed
//! or whether a fresh MFA proof is required. Wireable into any HTTP layer.
//!
//! ## Token rebinding (audit-fix)
//!
//! Step-up MFA used to be a *soft* decision: the orchestrator would lift a
//! per-session `last_mfa_at` flag and the verifier accepted any token whose
//! session carried the flag. A pre-MFA-stolen token therefore authorised
//! post-MFA critical operations because the token itself never carried the
//! step-up assertion.
//!
//! [`MfaAssertedClaim`] and [`new_mfa_asserted_claim`] are the rebinding
//! primitives a caller MUST use after a successful step-up: the orchestrator
//! computes a short-lived (60s by default) claim, signs the bearer's session
//! id + freshness window into it, and the verifier rejects any
//! `Critical`-sensitivity request unless the bound claim is present and
//! still fresh.
#![forbid(unsafe_code)]

use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sensitivity {
    Low,
    Medium,
    High,
    Critical,
}

impl Sensitivity {
    pub fn freshness_secs(self) -> i64 {
        match self {
            Sensitivity::Low => i64::MAX,
            Sensitivity::Medium => 30 * 60,
            Sensitivity::High => 5 * 60,
            Sensitivity::Critical => 60,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub method: String,
    pub path_regex: Regex,
    pub sensitivity: Sensitivity,
}

#[derive(Debug, Default, Clone)]
pub struct SensitivityMap {
    pub rules: Vec<Rule>,
    pub default: Option<Sensitivity>,
}

impl SensitivityMap {
    pub fn classify(&self, method: &str, path: &str) -> Sensitivity {
        for r in &self.rules {
            if r.method.eq_ignore_ascii_case(method) && r.path_regex.is_match(path) {
                return r.sensitivity;
            }
        }
        self.default.unwrap_or(Sensitivity::Low)
    }

    pub fn add(&mut self, method: &str, path_pattern: &str, s: Sensitivity) -> Result<(), regex::Error> {
        self.rules.push(Rule {
            method: method.into(),
            path_regex: Regex::new(path_pattern)?,
            sensitivity: s,
        });
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    RequireFreshMfa { max_age_secs: i64 },
}

pub fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Maximum lifetime of an `mfa_asserted` claim (token rebinding window).
pub const MFA_ASSERTED_TTL_SECS: i64 = 60;

const MFA_ASSERTED_DOMAIN: &[u8] = b"MILNET-MFA-ASSERTED-v1";

fn sensitivity_byte(s: Sensitivity) -> u8 {
    match s {
        Sensitivity::Low => 0x01,
        Sensitivity::Medium => 0x02,
        Sensitivity::High => 0x03,
        Sensitivity::Critical => 0x04,
    }
}

fn compute_binding_tag(session_id: &[u8; 32], asserted_at: i64, s: Sensitivity) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(MFA_ASSERTED_DOMAIN);
    h.update(session_id);
    h.update(asserted_at.to_be_bytes());
    h.update([sensitivity_byte(s)]);
    let out = h.finalize();
    let mut tag = [0u8; 64];
    tag.copy_from_slice(&out);
    tag
}

/// Bound MFA assertion attached to a freshly minted token after a
/// successful step-up. The claim is bound to (session_id, asserted_at, sensitivity)
/// so it cannot be replayed onto a sibling session or after expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MfaAssertedClaim {
    pub session_id: [u8; 32],
    pub asserted_at: i64,
    pub for_sensitivity: Sensitivity,
    pub binding_tag: [u8; 64],
}

/// Construct an `mfa_asserted` claim. The orchestrator MUST embed this in
/// a freshly minted, short-TTL token; the previous token (the one that
/// triggered the step-up) MUST be revoked atomically.
pub fn new_mfa_asserted_claim(session_id: [u8; 32], s: Sensitivity) -> MfaAssertedClaim {
    let asserted_at = now_secs();
    let binding_tag = compute_binding_tag(&session_id, asserted_at, s);
    MfaAssertedClaim {
        session_id,
        asserted_at,
        for_sensitivity: s,
        binding_tag,
    }
}

/// Verify an `mfa_asserted` claim against the session id and required
/// sensitivity. Constant-time and TTL-bounded.
pub fn verify_mfa_asserted_claim(
    claim: &MfaAssertedClaim,
    expected_session_id: &[u8; 32],
    required: Sensitivity,
) -> bool {
    if sensitivity_byte(claim.for_sensitivity) < sensitivity_byte(required) {
        return false;
    }
    let now = now_secs();
    if now - claim.asserted_at > MFA_ASSERTED_TTL_SECS {
        return false;
    }
    if claim.session_id.ct_eq(expected_session_id).unwrap_u8() != 1 {
        return false;
    }
    let recomputed = compute_binding_tag(
        &claim.session_id,
        claim.asserted_at,
        claim.for_sensitivity,
    );
    claim.binding_tag.ct_eq(&recomputed).unwrap_u8() == 1
}

pub fn decide(map: &SensitivityMap, method: &str, path: &str, last_mfa_at: Option<i64>) -> Decision {
    let s = map.classify(method, path);
    let max_age = s.freshness_secs();
    if max_age == i64::MAX {
        return Decision::Allow;
    }
    match last_mfa_at {
        Some(t) if now_secs() - t <= max_age => Decision::Allow,
        _ => Decision::RequireFreshMfa { max_age_secs: max_age },
    }
}

#[cfg(test)]
mod stepup_rebinding_tests {
    use super::*;

    fn fresh_session_id(seed: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = seed;
        id
    }

    #[test]
    fn fresh_claim_verifies_for_same_or_stronger_sensitivity() {
        let sid = fresh_session_id(1);
        let claim = new_mfa_asserted_claim(sid, Sensitivity::Critical);
        assert!(verify_mfa_asserted_claim(&claim, &sid, Sensitivity::Critical));
        assert!(verify_mfa_asserted_claim(&claim, &sid, Sensitivity::High));
        assert!(verify_mfa_asserted_claim(&claim, &sid, Sensitivity::Medium));
    }

    #[test]
    fn weaker_claim_does_not_authorise_stronger_op() {
        let sid = fresh_session_id(2);
        let claim = new_mfa_asserted_claim(sid, Sensitivity::High);
        assert!(!verify_mfa_asserted_claim(&claim, &sid, Sensitivity::Critical));
    }

    #[test]
    fn claim_for_other_session_rejected() {
        let sid_a = fresh_session_id(3);
        let sid_b = fresh_session_id(4);
        let claim = new_mfa_asserted_claim(sid_a, Sensitivity::Critical);
        assert!(!verify_mfa_asserted_claim(&claim, &sid_b, Sensitivity::Critical));
    }

    #[test]
    fn tampered_claim_rejected() {
        let sid = fresh_session_id(5);
        let mut claim = new_mfa_asserted_claim(sid, Sensitivity::Critical);
        claim.asserted_at += 100;
        assert!(!verify_mfa_asserted_claim(&claim, &sid, Sensitivity::Critical));
    }

    #[test]
    fn expired_claim_rejected() {
        let sid = fresh_session_id(6);
        let old = now_secs() - (MFA_ASSERTED_TTL_SECS + 5);
        let binding_tag = compute_binding_tag(&sid, old, Sensitivity::Critical);
        let claim = MfaAssertedClaim {
            session_id: sid,
            asserted_at: old,
            for_sensitivity: Sensitivity::Critical,
            binding_tag,
        };
        assert!(!verify_mfa_asserted_claim(&claim, &sid, Sensitivity::Critical));
    }
}
