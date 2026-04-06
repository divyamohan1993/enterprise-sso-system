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

-- Enforce that new audit entries MUST use encrypted data column.
-- Plaintext data column is retained for backward compatibility during migration
-- but new inserts must set it to NULL.
ALTER TABLE audit_log ADD CONSTRAINT audit_data_encrypted_required
    CHECK (data IS NULL OR data_encrypted IS NOT NULL);

-- After background migration completes, this constraint can be tightened to:
-- ALTER TABLE audit_log ADD CONSTRAINT audit_data_no_plaintext CHECK (data IS NULL);

COMMIT;
