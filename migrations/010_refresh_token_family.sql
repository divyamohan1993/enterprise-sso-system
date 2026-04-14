-- Migration 010: refresh_token_family table for F6 logout revocation.
-- On logout, every refresh token in a family is set to revoked=true so
-- that a stolen family is neutralized as soon as the legitimate user
-- terminates any session.

CREATE TABLE IF NOT EXISTS refresh_token_family (
    token_id    UUID PRIMARY KEY,
    family_id   UUID NOT NULL,
    user_id     UUID NOT NULL,
    issued_at   BIGINT NOT NULL,
    expires_at  BIGINT NOT NULL,
    revoked     BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_refresh_family_family
    ON refresh_token_family (family_id);
CREATE INDEX IF NOT EXISTS idx_refresh_family_user
    ON refresh_token_family (user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_family_live
    ON refresh_token_family (user_id) WHERE revoked = FALSE;
