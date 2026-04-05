-- Migration 007: Add encrypted data column for audit log entries
--
-- The plaintext data TEXT column may contain PII in event details.
-- This migration adds an encrypted_data BYTEA column for defense-in-depth.

BEGIN;

ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS data_encrypted BYTEA;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS data_kek_version INTEGER DEFAULT 1;

-- Note: Existing data migration (encrypting historical plaintext) must be
-- performed by the application layer using the current KEK. A background
-- task should encrypt all rows where data IS NOT NULL AND data_encrypted IS NULL.

COMMIT;
