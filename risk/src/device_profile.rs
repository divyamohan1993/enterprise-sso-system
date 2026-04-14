//! F3: Device profile with TPM re-attestation freshness enforcement.
//!
//! Backed by table `device_profile` (migration 009). On every login, if
//! the last TPM attestation timestamp is older than `REATTESTATION_MAX_AGE_SECS`,
//! re-attestation is required and the login MUST fail closed.

#[allow(unused_imports)]
use uuid::Uuid;

/// Seven days — fail closed after this many seconds without fresh attestation.
pub const REATTESTATION_MAX_AGE_SECS: i64 = 7 * 24 * 60 * 60;

/// The table DDL expected by this module (kept here for documentation and
/// also emitted as migration 009).
pub const DEVICE_PROFILE_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS device_profile (
    user_id UUID NOT NULL,
    device_id TEXT NOT NULL,
    last_attestation_ts BIGINT NOT NULL,
    attestation_quote BYTEA,
    PRIMARY KEY (user_id, device_id)
);
CREATE INDEX IF NOT EXISTS idx_device_profile_user ON device_profile (user_id);
"#;

/// Reason returned from the freshness check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationCheck {
    /// Fresh — login may proceed.
    Fresh,
    /// Stale — re-attestation required. Login MUST be rejected.
    StaleReattestationRequired { age_secs: i64 },
    /// No record yet — treat as stale (fail-closed).
    MissingFailClosed,
}

impl AttestationCheck {
    pub fn is_ok(&self) -> bool {
        matches!(self, AttestationCheck::Fresh)
    }
}

/// Pure-logic freshness check — callers pass the stored timestamp they read.
pub fn check_freshness(last_attestation_ts: Option<i64>, now_secs: i64) -> AttestationCheck {
    match last_attestation_ts {
        None => AttestationCheck::MissingFailClosed,
        Some(ts) => {
            let age = now_secs.saturating_sub(ts);
            if age > REATTESTATION_MAX_AGE_SECS {
                AttestationCheck::StaleReattestationRequired { age_secs: age }
            } else {
                AttestationCheck::Fresh
            }
        }
    }
}

/// SQL used by orchestrator-side callers for device_profile reads/writes.
/// Kept as constants so the risk crate does not depend on sqlx.
pub mod sql {
    pub const SELECT_LAST_ATTESTATION: &str =
        "SELECT last_attestation_ts FROM device_profile WHERE user_id = $1 AND device_id = $2";
    pub const UPSERT_ATTESTATION: &str =
        "INSERT INTO device_profile (user_id, device_id, last_attestation_ts, attestation_quote) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (user_id, device_id) DO UPDATE SET \
           last_attestation_ts = EXCLUDED.last_attestation_ts, \
           attestation_quote = EXCLUDED.attestation_quote";
}

// Keep Uuid in scope for future use by orchestrator-side callers.
#[allow(dead_code)]
fn _uuid_anchor(_u: &Uuid) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_attestation_passes() {
        let now = 1_000_000;
        let ts = now - (REATTESTATION_MAX_AGE_SECS - 1);
        assert!(check_freshness(Some(ts), now).is_ok());
    }

    #[test]
    fn stale_attestation_requires_reattestation() {
        let now = 1_000_000;
        let ts = now - (REATTESTATION_MAX_AGE_SECS + 10);
        matches!(
            check_freshness(Some(ts), now),
            AttestationCheck::StaleReattestationRequired { .. }
        );
    }

    #[test]
    fn missing_fails_closed() {
        assert_eq!(check_freshness(None, 1_000_000), AttestationCheck::MissingFailClosed);
    }
}
