-- Migration 006: Nullify plaintext PII columns after encryption migration
-- SECURITY: Plaintext username and email columns were retained in migration 005
-- for backward compatibility during rolling deployment. This migration removes
-- the plaintext data now that all reads use the encrypted columns.
--
-- This is a one-way migration: plaintext data is permanently removed.
-- Ensure all application instances are running migration-005-compatible code
-- before applying this migration.

-- Step 1: Nullify plaintext values where encrypted versions exist
UPDATE users SET username = 'REDACTED' WHERE username_encrypted IS NOT NULL AND username != 'REDACTED';
UPDATE users SET email = 'REDACTED' WHERE email_encrypted IS NOT NULL AND email != 'REDACTED';

-- Step 2: Drop the NOT NULL constraint on username (it was VARCHAR(255) NOT NULL)
ALTER TABLE users ALTER COLUMN username DROP NOT NULL;

-- Step 3: Set remaining non-redacted values to NULL (safety net)
UPDATE users SET username = NULL WHERE username_encrypted IS NOT NULL;
UPDATE users SET email = NULL WHERE email_encrypted IS NOT NULL;

-- Step 4: Drop the plaintext unique index on email
DROP INDEX IF EXISTS users_email_unique;

-- Step 5: Add a check constraint to prevent new plaintext data from being inserted
-- (defense-in-depth: application code should never write to these columns)
ALTER TABLE users ADD CONSTRAINT chk_no_plaintext_username
    CHECK (username IS NULL OR username = 'REDACTED');
ALTER TABLE users ADD CONSTRAINT chk_no_plaintext_email
    CHECK (email IS NULL OR email = 'REDACTED');
