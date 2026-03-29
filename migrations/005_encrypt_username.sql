-- Migration 005: Encrypt username field and add blind index
--
-- SECURITY: Previously username and email were stored in plaintext,
-- making them exfiltrable with database-only access. This migration
-- adds encrypted columns and blind index columns (HMAC-SHA256) so that
-- lookups can be performed without decryption.
--
-- After migration, the application layer encrypts usernames before INSERT
-- and decrypts after SELECT. The plaintext columns are retained for
-- backward compatibility during rolling deployment but will be nullified
-- by the application after re-encryption.

BEGIN;

-- Add encrypted username column (envelope-encrypted BYTEA)
ALTER TABLE users ADD COLUMN IF NOT EXISTS username_encrypted BYTEA;

-- Add blind index for username lookups without decryption
-- HMAC-SHA256(blind_index_key, "MILNET-USERNAME-BLIND-v1" || username)
ALTER TABLE users ADD COLUMN IF NOT EXISTS username_hash BYTEA;

-- Index on blind hash for efficient lookups
CREATE INDEX IF NOT EXISTS users_username_hash_idx
    ON users (username_hash) WHERE username_hash IS NOT NULL;

-- Add comment explaining the security model
COMMENT ON COLUMN users.username_encrypted IS
    'AES-256-GCM envelope-encrypted username. Decrypt with table KEK.';
COMMENT ON COLUMN users.username_hash IS
    'HMAC-SHA256 blind index for username lookups without decryption.';

COMMIT;
