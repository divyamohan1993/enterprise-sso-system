-- Migration 012: per-user session revocation watermark (F3) on the LIVE path.
--
-- Adds `users.tokens_not_before` — a "not-before" instant in EPOCH SECONDS.
-- The live auth path (auth_middleware + /oauth/userinfo in the admin service)
-- DENIES any token whose issued-at (`created_at`) is <= this value, so a
-- revocation bites an ALREADY-ISSUED token immediately, not only at TTL. A
-- revoke (duress, admin action) UPSERTs `tokens_not_before = now`; a later
-- re-auth issues a token with a newer issued-at and is unaffected. NULL means
-- "no revocation recorded".
--
-- CROSS-NODE PROPAGATION is the shared database itself: every service node
-- connects to this one Postgres, so node A's write is visible to node B's
-- auth_middleware on the next request. No custom cluster transport, no signed
-- broadcast, no per-node identity needed — the DB write is already
-- authenticated by the admin RBAC path that performed the revoke.
--
-- Monotonic upsert pattern used by the application (never moves backward):
--   UPDATE users
--      SET tokens_not_before = GREATEST(COALESCE(tokens_not_before, 0), $now)
--    WHERE id = $user_id;

ALTER TABLE users ADD COLUMN IF NOT EXISTS tokens_not_before BIGINT;

-- No separate index: the watermark is read by `WHERE id = $1` (the users PK),
-- which already fetches the row on the hot path, so the read is free.
