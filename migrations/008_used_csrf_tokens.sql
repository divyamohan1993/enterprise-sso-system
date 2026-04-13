-- E3 fix: persist used CSRF tokens to the database so that single-use
-- semantics survive process restarts and apply across replicas.
-- The atomic UNIQUE constraint on token_hex provides the check-and-insert
-- primitive: a duplicate insert raises 23505 (unique_violation), which the
-- application code interprets as "token replayed".
--
-- The token TTL is 60 seconds; rows older than that are pruned by a
-- background task. We index by created_at to make the prune cheap.

CREATE TABLE IF NOT EXISTS used_csrf_tokens (
    token_hex     TEXT        NOT NULL PRIMARY KEY,
    created_at    BIGINT      NOT NULL
);

CREATE INDEX IF NOT EXISTS used_csrf_tokens_created_at_idx
    ON used_csrf_tokens (created_at);
