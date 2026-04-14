-- Migration 011: dpop_replay_cache for F15 — DPoP jti replay persistence.
-- The in-memory cache is kept as an L1 for hot-path reads; this table is
-- the durable L2 so process restarts do not open a replay window.

CREATE TABLE IF NOT EXISTS dpop_replay_cache (
    jkt_hash BYTEA NOT NULL,
    jti      TEXT NOT NULL,
    exp      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (jkt_hash, jti)
);

CREATE INDEX IF NOT EXISTS idx_dpop_replay_exp ON dpop_replay_cache (exp);

-- TTL: entries are eligible for deletion 60 seconds after `exp`. A periodic
-- janitor runs `DELETE FROM dpop_replay_cache WHERE exp < NOW() - INTERVAL '60 seconds'`.
