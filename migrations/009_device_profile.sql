-- Migration 009: device_profile table for F3 TPM re-attestation freshness.
-- On every login, if (now - last_attestation_ts) > 7 days, re-attestation
-- is required. Failing closed on missing rows is enforced in code.

CREATE TABLE IF NOT EXISTS device_profile (
    user_id             UUID NOT NULL,
    device_id           TEXT NOT NULL,
    last_attestation_ts BIGINT NOT NULL,
    attestation_quote   BYTEA,
    PRIMARY KEY (user_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_device_profile_user ON device_profile (user_id);
CREATE INDEX IF NOT EXISTS idx_device_profile_stale
    ON device_profile (last_attestation_ts);
