-- Super admin registry for multi-person ceremony support.
-- Each super admin gets a unique API key derived from the master KEK + their ID.
-- Created during initial setup; N super admins can be registered.
--
-- SECURITY: This table is FROZEN after initial setup.
-- - INSERT: blocked by trigger after freeze (except via unanimous ceremony)
-- - UPDATE: blocked unconditionally by trigger (no modifications ever)
-- - DELETE: allowed (only way to remove a compromised admin)
-- Even a PostgreSQL superuser cannot bypass these triggers without
-- explicitly dropping them first (which is logged by pg_audit).
--
-- `last_used` is NOT stored here — it is DERIVED from the immutable
-- super_admin_audit_log (prevents forgery).

CREATE TABLE IF NOT EXISTS super_admins (
    id          UUID PRIMARY KEY,
    label       VARCHAR(255) NOT NULL,
    key_hash    BYTEA NOT NULL,
    region      VARCHAR(255),
    created_at  BIGINT NOT NULL,
    UNIQUE(label)
);

-- Audit log for every operation on super_admins (including access attempts).
-- This table is append-only: no UPDATE, no DELETE (enforced by trigger).
-- `last_used` for any admin is: SELECT MAX(event_time) FROM super_admin_audit_log
--   WHERE admin_id = ? AND operation = 'ACCESS_GRANTED'
CREATE TABLE IF NOT EXISTS super_admin_audit_log (
    id          BIGSERIAL PRIMARY KEY,
    event_time  TIMESTAMPTZ NOT NULL DEFAULT now(),
    operation   VARCHAR(20) NOT NULL,
    admin_id    UUID,
    admin_label VARCHAR(255),
    detail      TEXT,
    source_ip   VARCHAR(45),
    node_id     VARCHAR(255)
);

-- Index for fast last_used derivation: O(1) with index scan
CREATE INDEX IF NOT EXISTS idx_sa_audit_admin_op
    ON super_admin_audit_log (admin_id, operation, event_time DESC);

-- View for convenient last_used lookup (derived from immutable audit log)
CREATE OR REPLACE VIEW super_admin_last_used AS
SELECT
    sa.id AS admin_id,
    sa.label,
    sa.region,
    sa.created_at,
    (SELECT MAX(al.event_time) FROM super_admin_audit_log al
     WHERE al.admin_id = sa.id AND al.operation = 'ACCESS_GRANTED') AS last_used
FROM super_admins sa;

-- ═══════════════════════════════════════════════════════════════════════════
-- Freeze flag: once set to true, INSERT on super_admins is blocked.
-- Can be temporarily unlocked via unanimous ceremony (all admins approve).
-- ═══════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS super_admins_frozen (
    frozen BOOLEAN NOT NULL DEFAULT false
);
INSERT INTO super_admins_frozen (frozen) VALUES (false) ON CONFLICT DO NOTHING;

-- ═══════════════════════════════════════════════════════════════════════════
-- TRIGGER: Block UPDATE on super_admins (unconditional — no modifications)
-- ═══════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION block_super_admin_update() RETURNS trigger AS $$
BEGIN
    INSERT INTO super_admin_audit_log (operation, admin_id, admin_label, detail)
    VALUES ('UPDATE_BLOCKED', OLD.id, OLD.label,
            'UPDATE attempted on frozen super_admins table — DENIED');
    RAISE EXCEPTION 'SECURITY VIOLATION: UPDATE on super_admins table is forbidden. This table is immutable. Only DELETE is permitted to remove compromised admins.';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_block_super_admin_update ON super_admins;
CREATE TRIGGER trg_block_super_admin_update
    BEFORE UPDATE ON super_admins
    FOR EACH ROW EXECUTE FUNCTION block_super_admin_update();

-- ═══════════════════════════════════════════════════════════════════════════
-- TRIGGER: Block INSERT on super_admins when frozen (unless ceremony unlocks)
-- ═══════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION block_super_admin_insert_after_setup() RETURNS trigger AS $$
DECLARE
    is_frozen BOOLEAN;
BEGIN
    SELECT frozen INTO is_frozen FROM super_admins_frozen LIMIT 1;
    IF is_frozen THEN
        INSERT INTO super_admin_audit_log (operation, admin_label, detail)
        VALUES ('INSERT_BLOCKED', NEW.label,
                'INSERT attempted on frozen super_admins table — DENIED.');
        RAISE EXCEPTION 'SECURITY VIOLATION: INSERT on super_admins table is frozen. Use unanimous ceremony to add new admins.';
    END IF;
    INSERT INTO super_admin_audit_log (operation, admin_id, admin_label, detail)
    VALUES ('INSERT', NEW.id, NEW.label, 'Super admin created');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_block_super_admin_insert ON super_admins;
CREATE TRIGGER trg_block_super_admin_insert
    BEFORE INSERT ON super_admins
    FOR EACH ROW EXECUTE FUNCTION block_super_admin_insert_after_setup();

-- Freeze the table after initial setup.
CREATE OR REPLACE FUNCTION freeze_super_admins() RETURNS void AS $$
BEGIN
    UPDATE super_admins_frozen SET frozen = true;
    INSERT INTO super_admin_audit_log (operation, detail)
    VALUES ('FREEZE', 'super_admins table frozen after initial setup');
END;
$$ LANGUAGE plpgsql;

-- Temporarily unfreeze for adding a new admin via unanimous ceremony.
-- Re-freeze MUST be called immediately after the insert.
CREATE OR REPLACE FUNCTION unfreeze_super_admins_for_ceremony() RETURNS void AS $$
BEGIN
    UPDATE super_admins_frozen SET frozen = false;
    INSERT INTO super_admin_audit_log (operation, detail)
    VALUES ('UNFREEZE', 'Table temporarily unfrozen for unanimous ceremony admin creation');
END;
$$ LANGUAGE plpgsql;

-- ═══════════════════════════════════════════════════════════════════════════
-- TRIGGER: Log DELETE on super_admins (allowed but logged immutably)
-- ═══════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION log_super_admin_delete() RETURNS trigger AS $$
BEGIN
    INSERT INTO super_admin_audit_log (operation, admin_id, admin_label, detail)
    VALUES ('DELETE', OLD.id, OLD.label,
            'Super admin DELETED — compromised or decommissioned');
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_log_super_admin_delete ON super_admins;
CREATE TRIGGER trg_log_super_admin_delete
    BEFORE DELETE ON super_admins
    FOR EACH ROW EXECUTE FUNCTION log_super_admin_delete();

-- ═══════════════════════════════════════════════════════════════════════════
-- TRIGGER: Protect the audit log itself — no UPDATE, no DELETE, no TRUNCATE
-- ═══════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION block_audit_log_modify() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'SECURITY VIOLATION: super_admin_audit_log is append-only. No UPDATE or DELETE permitted.';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_block_audit_log_update ON super_admin_audit_log;
CREATE TRIGGER trg_block_audit_log_update
    BEFORE UPDATE ON super_admin_audit_log
    FOR EACH ROW EXECUTE FUNCTION block_audit_log_modify();

DROP TRIGGER IF EXISTS trg_block_audit_log_delete ON super_admin_audit_log;
CREATE TRIGGER trg_block_audit_log_delete
    BEFORE DELETE ON super_admin_audit_log
    FOR EACH ROW EXECUTE FUNCTION block_audit_log_modify();

REVOKE TRUNCATE ON super_admin_audit_log FROM PUBLIC;
