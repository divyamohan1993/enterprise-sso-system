-- Migration 007: Add encrypted data column for audit log entries
--
-- The plaintext data TEXT column may contain PII in event details.
-- This migration adds an encrypted_data BYTEA column for defense-in-depth.

BEGIN;

ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS data_encrypted BYTEA;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS data_kek_version INTEGER DEFAULT 1;

-- Encrypt all existing plaintext rows in-place using envelope encryption.
-- This batch update relies on the application-side envelope encryption function
-- `audit_envelope_encrypt(plaintext, kek_version)` (registered via PL/pgSQL or
-- pg-extension at deploy-time) which performs AES-256-GCM with the active KEK.
-- The migration is hard-required: deploy fails if function is not registered.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_proc WHERE proname = 'audit_envelope_encrypt'
    ) THEN
        RAISE EXCEPTION 'audit_envelope_encrypt function not registered. Migration 007 requires the envelope encryption function to be installed before running. See deploy/kubernetes/external-secrets/README.md.';
    END IF;
END $$;

UPDATE audit_log
SET data_encrypted = audit_envelope_encrypt(data::bytea, 1),
    data_kek_version = 1,
    data = NULL
WHERE data IS NOT NULL AND data_encrypted IS NULL;

-- HARD-REQUIRED constraint: plaintext data column MUST be NULL.
-- After this migration completes, no new row may carry plaintext audit payload.
ALTER TABLE audit_log ADD CONSTRAINT audit_data_no_plaintext
    CHECK (data IS NULL);

COMMIT;
