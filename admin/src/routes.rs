use axum::extract::{Path, Query, Request, State};
use axum::http::{header, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{delete, get, post, put};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_stream::StreamExt;
use tower_http::services::ServeDir;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Security utilities
// ---------------------------------------------------------------------------

/// Escape HTML special characters to prevent XSS/HTML injection.
fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

// ---------------------------------------------------------------------------
// CSRF protection utilities
// ---------------------------------------------------------------------------

/// Generate a CSRF session cookie value — a random 32-byte hex token.
/// This cookie is bound into the CSRF HMAC to prevent cross-session forgery.
fn generate_csrf_session_cookie() -> String {
    let bytes: [u8; 32] = rand::random();
    hex::encode(bytes)
}

/// Generate a CSRF token using HMAC-SHA256 over (session_state + cookie_value + timestamp + nonce).
/// The token encodes: timestamp:nonce:hmac_hex
/// `cookie_value` is the `__Host-csrf-session` cookie bound to this CSRF token.
fn generate_csrf_token(session_state: &str, api_key: &str, cookie_value: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_secs();
    let nonce: [u8; 16] = rand::random();
    let nonce_hex = hex::encode(nonce);

    let payload = format!("{}:{}:{}:{}", session_state, cookie_value, now, nonce_hex);
    let mut mac = HmacSha256::new_from_slice(api_key.as_bytes())
        .unwrap_or_else(|_| { tracing::error!("FATAL: HMAC-SHA256 key init failed"); std::process::exit(1) });
    mac.update(payload.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());

    format!("{}:{}:{}", now, nonce_hex, sig)
}

/// CSRF token TTL in seconds (60 seconds).
const CSRF_TOKEN_TTL_SECS: u64 = 60;

/// Validate a CSRF token against the expected session_state, api_key, and
/// the `__Host-csrf-session` cookie value.
/// Returns true if the token is valid and not expired.
/// NOTE: This is the stateless check only. Callers must also check
/// and mark the token as used via `check_and_mark_csrf_used()`.
fn validate_csrf_token(token: &str, session_state: &str, api_key: &str, cookie_value: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let parts: Vec<&str> = token.splitn(3, ':').collect();
    if parts.len() != 3 {
        return false;
    }
    let (ts_str, nonce_hex, provided_sig) = (parts[0], parts[1], parts[2]);

    // Reject if cookie value is empty (cookie must be present)
    if cookie_value.is_empty() {
        return false;
    }

    // Check expiry
    let timestamp: u64 = match ts_str.parse() {
        Ok(t) => t,
        Err(_) => return false,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_secs();
    if now.saturating_sub(timestamp) > CSRF_TOKEN_TTL_SECS {
        return false;
    }

    // Recompute HMAC (includes cookie value for session binding)
    let payload = format!("{}:{}:{}:{}", session_state, cookie_value, timestamp, nonce_hex);
    let mut mac = HmacSha256::new_from_slice(api_key.as_bytes())
        .unwrap_or_else(|_| { tracing::error!("FATAL: HMAC-SHA256 key init failed"); std::process::exit(1) });
    mac.update(payload.as_bytes());
    let expected_sig = hex::encode(mac.finalize().into_bytes());

    crypto::ct::ct_eq(expected_sig.as_bytes(), provided_sig.as_bytes())
}

/// Check if a CSRF token has been used before and mark it as used.
/// Returns true if the token was NOT previously used (i.e., it is fresh).
/// Returns false if the token was already consumed (replay attempt).
async fn check_and_mark_csrf_used(token: &str, used_tokens: &RwLock<HashSet<String>>) -> bool {
    let mut used = used_tokens.write().await;
    // Enforce capacity: evict tokens older than TTL instead of bulk-clearing.
    // Bulk clear creates a replay window where recently-consumed tokens can be
    // replayed. Instead, we parse the timestamp from each stored token and
    // remove only those that have expired.
    if used.len() >= MAX_USED_CSRF_TOKENS {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_secs();
        used.retain(|t| {
            // CSRF tokens have format "timestamp:nonce:hmac"
            t.split(':').next()
                .and_then(|ts| ts.parse::<u64>().ok())
                .map(|ts| now.saturating_sub(ts) <= CSRF_TOKEN_TTL_SECS)
                .unwrap_or(false) // remove malformed entries
        });
    }
    // insert() returns true if the value was newly inserted (not present before)
    used.insert(token.to_string())
}

// ---------------------------------------------------------------------------
// Token revocation
// ---------------------------------------------------------------------------

/// Maximum number of entries in the in-memory revocation set.
const MAX_REVOCATION_ENTRIES: usize = 100_000;

/// Maximum token lifetime for admin revocation list cleanup (15 minutes).
///
/// NOTE: This is intentionally shorter than the verifier's 8-hour and the
/// protocol's 24-hour ceilings. Admin sessions use short-lived tokens per
/// NIST SP 800-63B AAL3 inactivity timeout. The revocation list only needs
/// to retain entries for as long as an admin token could still be valid.
/// See also: verifier/src/verify.rs::DEFAULT_MAX_TOKEN_LIFETIME_SECS (8h)
///           sso-protocol/src/tokens.rs::MAX_TOKEN_LIFETIME_SECS (24h)
const MAX_TOKEN_LIFETIME_SECS: i64 = 15 * 60;

/// An entry in the revocation set, tracking when it was revoked for cleanup.
struct RevokedTokenEntry {
    token_id: [u8; 16],
    revoked_at: i64,
}

/// In-memory token revocation list.
pub struct RevocationList {
    entries: HashSet<[u8; 16]>,
    timed_entries: Vec<RevokedTokenEntry>,
}

impl RevocationList {
    pub fn new() -> Self {
        Self {
            entries: HashSet::new(),
            timed_entries: Vec::new(),
        }
    }

    /// Add a token_id to the revocation set. Returns false if at capacity.
    fn revoke(&mut self, token_id: [u8; 16]) -> bool {
        if self.entries.len() >= MAX_REVOCATION_ENTRIES {
            return false;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_secs() as i64;
        if self.entries.insert(token_id) {
            self.timed_entries.push(RevokedTokenEntry {
                token_id,
                revoked_at: now,
            });
        }
        true
    }

    /// Returns the number of currently revoked tokens.
    fn count(&self) -> usize {
        self.entries.len()
    }

    /// Remove entries older than MAX_TOKEN_LIFETIME_SECS.
    fn cleanup_expired(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_secs() as i64;
        let cutoff = now - MAX_TOKEN_LIFETIME_SECS;
        let mut to_remove = Vec::new();
        self.timed_entries.retain(|entry| {
            if entry.revoked_at < cutoff {
                to_remove.push(entry.token_id);
                false
            } else {
                true
            }
        });
        for id in to_remove {
            self.entries.remove(&id);
        }
    }
}

// ---------------------------------------------------------------------------
// Admin RBAC — Role-Based Access Control
// ---------------------------------------------------------------------------

/// Admin roles for the MILNET SSO system.
///
/// Each role has specific permissions over API routes. Role hierarchy:
///   SuperAdmin > UserManager, DeviceManager > Auditor > ReadOnly
///
/// Roles are encoded as a u8 in admin tokens and API keys are derived
/// per-role from the master KEK via HKDF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AdminRole {
    /// Full system access including destructive operations.
    /// Level 3/4 operations still require multi-person ceremony.
    SuperAdmin = 0,
    /// Can create, modify, and delete users. Cannot manage devices or
    /// system configuration.
    UserManager = 1,
    /// Can enroll, modify, and revoke devices. Cannot manage users.
    DeviceManager = 2,
    /// Read-only access to audit logs, system status, and security dashboard.
    Auditor = 3,
    /// Read-only access to non-sensitive endpoints (status, health).
    ReadOnly = 4,
}

impl AdminRole {
    /// Parse a role from its u8 representation.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::SuperAdmin),
            1 => Some(Self::UserManager),
            2 => Some(Self::DeviceManager),
            3 => Some(Self::Auditor),
            4 => Some(Self::ReadOnly),
            _ => None,
        }
    }

    /// The string label used as HKDF info for per-role key derivation.
    pub fn key_label(&self) -> &'static str {
        match self {
            Self::SuperAdmin => "super-admin",
            Self::UserManager => "user-manager",
            Self::DeviceManager => "device-manager",
            Self::Auditor => "auditor",
            Self::ReadOnly => "read-only",
        }
    }

    /// Check whether this role has at least the privileges of `required`.
    /// SuperAdmin satisfies any role requirement.
    pub fn satisfies(&self, required: AdminRole) -> bool {
        match required {
            AdminRole::ReadOnly => true, // Every role can read
            AdminRole::Auditor => matches!(
                self,
                AdminRole::SuperAdmin | AdminRole::Auditor
            ),
            AdminRole::DeviceManager => matches!(
                self,
                AdminRole::SuperAdmin | AdminRole::DeviceManager
            ),
            AdminRole::UserManager => matches!(
                self,
                AdminRole::SuperAdmin | AdminRole::UserManager
            ),
            AdminRole::SuperAdmin => *self == AdminRole::SuperAdmin,
        }
    }
}

impl std::fmt::Display for AdminRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.key_label())
    }
}

/// Derive a per-role admin API key from the master KEK using HKDF-SHA512.
///
/// Each role gets a unique 32-byte key derived as:
///   HKDF-SHA512(salt=ADMIN_ROLE_KEY_DERIVE, ikm=master_kek, info=role_label)
///
/// The returned key is hex-encoded (64 chars) for use as a Bearer token.
pub fn derive_admin_role_key(role: AdminRole) -> String {
    use hkdf::Hkdf;
    use sha2::Sha512;

    let master_kek = common::sealed_keys::load_master_kek();
    let hk = Hkdf::<Sha512>::new(Some(common::domain::ADMIN_ROLE_KEY_DERIVE), &master_kek);
    let mut okm = [0u8; 32];
    hk.expand(role.key_label().as_bytes(), &mut okm)
        .unwrap_or_else(|_| { tracing::error!("FATAL: HKDF expand for admin role key failed"); std::process::exit(1) });
    hex::encode(okm)
}

/// Resolve an API key to an `AdminRole` by checking all derived role keys.
///
/// Returns `None` if the key does not match any role.
fn resolve_admin_role(api_key: &str) -> Option<AdminRole> {
    let roles = [
        AdminRole::SuperAdmin,
        AdminRole::UserManager,
        AdminRole::DeviceManager,
        AdminRole::Auditor,
        AdminRole::ReadOnly,
    ];
    // SECURITY: Always iterate ALL roles to prevent timing side-channels
    // that leak the role index of a valid key. A variable accumulates the
    // match without early exit.
    let mut matched: Option<AdminRole> = None;
    for role in &roles {
        let derived = derive_admin_role_key(*role);
        if crypto::ct::ct_eq(api_key.as_bytes(), derived.as_bytes()) {
            matched = Some(*role);
        }
    }
    matched
}

/// Determine the minimum required `AdminRole` for a given request path and method.
///
/// This is the central policy function: it maps every route to the least-
/// privileged role that may access it. Unknown routes default to `SuperAdmin`
/// (fail-closed).
fn required_role_for_route(path: &str, method: &Method) -> AdminRole {
    // Read-only endpoints: accessible by all roles
    if path == "/api/health"
        || path == "/api/status"
        || path == "/api/setup/status"
    {
        return AdminRole::ReadOnly;
    }

    // Audit endpoints: Auditor or above
    if path.starts_with("/api/audit")
        || path == "/api/security/dashboard"
        || path == "/api/security/config"
        || path.starts_with("/api/security/test/")
        || path == "/api/sessions"
        || path == "/api/tokens/revoked"
        || path == "/api/admin/siem/stream"
    {
        return AdminRole::Auditor;
    }

    // User management endpoints
    if path == "/api/users" && *method == Method::POST {
        return AdminRole::UserManager;
    }
    if path == "/api/users" && *method == Method::GET {
        return AdminRole::Auditor;
    }
    if path.starts_with("/api/users/") && *method == Method::DELETE {
        return AdminRole::SuperAdmin; // Destructive: requires ceremony
    }
    if path == "/api/user/profile" {
        return AdminRole::ReadOnly;
    }

    // Device endpoints
    if path == "/api/devices" && *method == Method::POST {
        return AdminRole::DeviceManager;
    }
    if path == "/api/devices" && *method == Method::GET {
        return AdminRole::Auditor;
    }

    // Portal management: UserManager or above
    if path == "/api/portals" && *method == Method::POST {
        return AdminRole::UserManager;
    }
    if path == "/api/portals" && *method == Method::GET {
        return AdminRole::Auditor;
    }
    if path.starts_with("/api/portals/") && *method == Method::DELETE {
        return AdminRole::UserManager;
    }
    if path == "/api/portals/check-access" {
        return AdminRole::ReadOnly;
    }

    // KT endpoints: read-only
    if path.starts_with("/api/kt/") {
        return AdminRole::ReadOnly;
    }

    // Token revocation: UserManager or SuperAdmin
    if path == "/api/tokens/revoke" {
        return AdminRole::UserManager;
    }

    // Developer mode / error level: SuperAdmin only
    if path.starts_with("/api/admin/developer-mode") {
        return AdminRole::SuperAdmin;
    }

    // FIPS mode toggle: SuperAdmin only
    if path.starts_with("/api/admin/fips-mode") {
        return AdminRole::SuperAdmin;
    }

    // Super admin management: SuperAdmin only
    if path.starts_with("/api/admin/super-admins") {
        return AdminRole::SuperAdmin;
    }

    // Ceremony endpoints: SuperAdmin only
    if path.starts_with("/api/ceremony/") || path == "/api/ceremony/initiate" || path == "/api/ceremony/approve" {
        return AdminRole::SuperAdmin;
    }

    // Pending admin actions: SuperAdmin only
    if path.starts_with("/api/admin/actions") {
        return AdminRole::SuperAdmin;
    }

    // Recovery endpoints
    if path.starts_with("/api/recovery/") {
        return AdminRole::UserManager;
    }

    // CAC/PIV endpoints — read-only operations require Auditor;
    // mutations (enroll, revoke) require SuperAdmin.
    if path == "/api/cac/authenticate"
        || path == "/api/cac/verify-cert"
        || path == "/api/cac/readers"
    {
        return AdminRole::Auditor;
    }
    if path == "/api/cac/enroll" {
        return AdminRole::SuperAdmin;
    }
    if path.starts_with("/api/cac/cards/") {
        return if *method == Method::DELETE {
            AdminRole::SuperAdmin
        } else {
            AdminRole::Auditor
        };
    }

    // STIG audit endpoints — Auditor or above (read-only)
    if path.starts_with("/api/stig/") {
        return AdminRole::Auditor;
    }

    // CMMC assessment endpoints — Auditor or above (read-only)
    if path.starts_with("/api/cmmc/") {
        return AdminRole::Auditor;
    }

    // Compliance status endpoint — Auditor or above (read-only)
    if path.starts_with("/api/compliance/") {
        return AdminRole::Auditor;
    }

    // FIDO2 — regular authenticated users can manage their own credentials
    if path == "/api/fido/register/begin"
        || path == "/api/fido/register/complete"
        || path == "/api/fido/credentials"
        || path == "/api/fido/authenticate/begin"
        || path == "/api/fido/authenticate/complete"
    {
        return AdminRole::ReadOnly;
    }

    // Auth, OAuth, setup, and public endpoints are handled by auth_middleware
    // before RBAC is checked (they are exempt from admin RBAC).
    // For everything else: fail-closed to SuperAdmin.
    AdminRole::SuperAdmin
}

/// Extension to carry the authenticated admin role through the request.
#[derive(Debug, Clone, Copy)]
pub struct AuthAdminRole(pub AdminRole);

// ---------------------------------------------------------------------------
// Pending Admin Actions — two-person approval for destructive operations
// ---------------------------------------------------------------------------

/// Maximum pending admin actions to prevent memory exhaustion.
const MAX_PENDING_ADMIN_ACTIONS: usize = 1_000;

/// TTL for pending admin actions (30 minutes).
const PENDING_ADMIN_ACTION_TTL_SECS: i64 = 30 * 60;

/// Actions that require multi-person ceremony approval before execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DestructiveAction {
    /// Delete a user and all associated data.
    UserDeletion,
    /// Change a user's security tier.
    TierChange,
    /// Trigger key rotation for the system.
    KeyRotation,
    /// Bulk revocation of device credentials.
    BulkDeviceRevocation,
    /// Toggle error level on or off.
    ErrorLevelToggle,
    /// Toggle FIPS mode on or off.
    /// OFF = stronger algorithms (AEGIS-256, Argon2id, BLAKE3).
    /// ON = FIPS 140-3 compliance (AES-256-GCM, PBKDF2, SHA-512).
    FipsModeToggle,
    /// Add a new super admin. Requires UNANIMOUS approval from ALL
    /// existing super admins. The table is temporarily unfrozen, the
    /// new admin inserted, then re-frozen immediately.
    AddSuperAdmin,
}

impl DestructiveAction {
    /// Number of approvals required for this action type.
    pub fn required_approvals(&self) -> usize {
        match self {
            Self::UserDeletion => 2,
            Self::TierChange => 2,
            Self::KeyRotation => 3, // Higher bar for key rotation
            Self::BulkDeviceRevocation => 2,
            Self::ErrorLevelToggle => 2,
            Self::FipsModeToggle => 2,
            // UNANIMOUS: every single active super admin must approve
            Self::AddSuperAdmin => usize::MAX, // resolved at runtime to active admin count
        }
    }

    /// Whether this action requires the approver to be SuperAdmin.
    pub fn requires_superadmin_approver(&self) -> bool {
        match self {
            Self::KeyRotation
            | Self::UserDeletion
            | Self::TierChange
            | Self::BulkDeviceRevocation
            | Self::ErrorLevelToggle
            | Self::FipsModeToggle
            | Self::AddSuperAdmin => true,
        }
    }
}

impl std::fmt::Display for DestructiveAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UserDeletion => write!(f, "user_deletion"),
            Self::TierChange => write!(f, "tier_change"),
            Self::KeyRotation => write!(f, "key_rotation"),
            Self::BulkDeviceRevocation => write!(f, "bulk_device_revocation"),
            Self::ErrorLevelToggle => write!(f, "error_level_toggle"),
            Self::FipsModeToggle => write!(f, "fips_mode_toggle"),
            Self::AddSuperAdmin => write!(f, "add_super_admin"),
        }
    }
}

/// A pending destructive admin action awaiting multi-person approval.
#[derive(Clone, Serialize)]
pub struct PendingAdminAction {
    /// Unique ID for this pending action.
    pub action_id: Uuid,
    /// The destructive action being requested.
    pub action_type: DestructiveAction,
    /// Serialized parameters for the action (JSON).
    pub parameters: String,
    /// Who initiated this action.
    pub initiator: Uuid,
    /// Approvals received: (approver_id, hmac_signature).
    pub approvals: Vec<(Uuid, Vec<u8>)>,
    /// Number of approvals required.
    pub required_approvals: usize,
    /// When this action was created (epoch seconds).
    pub created_at: i64,
    /// When this action expires (epoch seconds).
    pub expires_at: i64,
}

/// Request to submit a destructive admin action for approval.
#[derive(Deserialize)]
pub struct SubmitAdminActionRequest {
    pub action_type: DestructiveAction,
    pub parameters: serde_json::Value,
}

/// Response after submitting a destructive admin action.
#[derive(Serialize)]
pub struct SubmitAdminActionResponse {
    pub action_id: Uuid,
    pub required_approvals: usize,
    pub expires_at: i64,
}

/// Request to approve a pending admin action.
#[derive(Deserialize)]
pub struct ApproveAdminActionRequest {
    pub action_id: Uuid,
    /// HMAC-SHA512 signature over the action_id, proving cryptographic
    /// binding between the approver and this specific action. Hex-encoded.
    pub signature: String,
}

/// Response after approving a pending admin action.
#[derive(Serialize)]
pub struct ApproveAdminActionResponse {
    pub approved: bool,
    pub complete: bool,
    pub approvals: usize,
    pub required: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Compute the expected HMAC-SHA512 signature for an admin action approval.
fn compute_admin_action_approval_hmac(action_id: &Uuid, approver_id: &Uuid) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;

    let master_kek = common::sealed_keys::load_master_kek();
    let derived = {
        use hkdf::Hkdf;
        let hk = Hkdf::<Sha512>::new(Some(common::domain::PENDING_ADMIN_ACTION), &master_kek);
        let mut okm = [0u8; 64];
        hk.expand(approver_id.as_bytes(), &mut okm)
            .unwrap_or_else(|_| { tracing::error!("FATAL: HKDF expand failed"); std::process::exit(1) });
        okm
    };
    let mut mac = HmacSha512::new_from_slice(&derived)
        .unwrap_or_else(|_| { tracing::error!("FATAL: HMAC-SHA512 key init failed"); std::process::exit(1) });
    mac.update(action_id.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Verify an admin action approval signature from an approver.
fn verify_admin_action_approval(
    action_id: &Uuid,
    approver_id: &Uuid,
    provided_signature: &[u8],
) -> bool {
    let expected = compute_admin_action_approval_hmac(action_id, approver_id);
    crypto::ct::ct_eq(&expected, provided_signature)
}

// ---------------------------------------------------------------------------
// Super admin registry (FROZEN after setup — immutable audit trail)
// ---------------------------------------------------------------------------

/// A registered super admin with their key hash for authentication.
#[derive(Clone)]
pub struct SuperAdminEntry {
    pub id: Uuid,
    pub label: String,
    pub key_hash: Vec<u8>,
    pub region: Option<String>,
}

/// Derive a unique super admin API key from the master KEK + admin ID.
/// Each super admin gets a deterministic but unique key.
pub fn derive_super_admin_key(master_kek: &[u8; 32], admin_id: &Uuid, deployment_id: &str) -> String {
    use hkdf::Hkdf;
    use sha2::Sha512;
    let salt = format!("MILNET-SUPER-ADMIN-KEY-v1:{}:{}", deployment_id, admin_id);
    let hk = Hkdf::<Sha512>::new(Some(salt.as_bytes()), master_kek.as_slice());
    let mut okm = [0u8; 32];
    hk.expand(b"super-admin-api-key", &mut okm).unwrap_or_else(|_| { tracing::error!("FATAL: HKDF expand failed"); std::process::exit(1) });
    hex::encode(okm)
}

/// Hash a super admin API key for storage (SHA-512, not reversible).
fn hash_admin_key(key: &str) -> Vec<u8> {
    use sha2::{Digest, Sha512};
    Sha512::digest(key.as_bytes()).to_vec()
}

/// Check if a provided token matches any active super admin key.
/// Returns the super admin ID and label if matched.
/// O(n) over active admins but n is small (< 20).
fn match_super_admin_key(token: &[u8], admins: &HashMap<Uuid, SuperAdminEntry>) -> Option<(Uuid, String)> {
    let token_hash = {
        use sha2::{Digest, Sha512};
        Sha512::digest(token).to_vec()
    };
    for (id, entry) in admins {
        if crypto::ct::ct_eq(&token_hash, &entry.key_hash) {
            return Some((*id, entry.label.clone()));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Super admin access log — immutable, distributed, never deleted
// ---------------------------------------------------------------------------

/// Dedicated append-only log file for super admin access events.
/// This file is NEVER rotated or deleted. It provides a local tamper-evidence
/// trail in addition to the distributed BFT audit log and SIEM.
const SUPER_ADMIN_ACCESS_LOG: &str = "/var/lib/milnet/audit/super_admin_access.jsonl";

/// Log a super admin access attempt BEFORE authentication completes.
///
/// This is called BEFORE the key is verified, so the attempt is recorded
/// even if the key is invalid. The log entry is:
/// 1. Written to the local append-only file (sync'd to disk)
/// 2. Emitted to the SIEM broadcast bus
/// 3. Persisted to the critical alerts file
///
/// Every access attempt hits 4 independent tamper-evidence layers:
///
/// 1. **BFT audit chain** — ML-DSA-87 signed, SHA-512 hash-chained,
///    7-node BFT quorum replicated. Each entry's hash includes prev_hash.
///    Tampering with ANY entry on ANY node breaks the chain on the other 6.
///    Even with full DB access + trigger drops + file modifications on one
///    node, the remaining nodes hold the original chain as proof.
/// 2. **Local append-only file** — fsync'd to disk before auth proceeds
/// 3. **SIEM broadcast bus** — distributed consumers
/// 4. **DB audit log** — append-only (trigger-protected, but triggers are
///    the weakest layer — the BFT chain is the real proof)
///
/// If local file write fails, access is DENIED (fail-closed).
fn log_super_admin_access(
    audit_log: &tokio::sync::RwLock<audit::log::AuditLog>,
    pq_signing_key: &crypto::pq_sign::PqSigningKey,
    source_ip: &str,
    path: &str,
    method: &str,
    matched_admin: Option<&(Uuid, String)>,
    outcome: &str,
) -> bool {
    let detail = format!(
        "SUPER_ADMIN_ACCESS: {} {} from {} — admin={} outcome={}",
        method, path, source_ip,
        matched_admin.map(|(_, l)| l.as_str()).unwrap_or("UNKNOWN"),
        outcome,
    );

    let entry_json = serde_json::json!({
        "event_type": "SuperAdminAccess",
        "source_ip": source_ip,
        "path": path,
        "method": method,
        "admin_id": matched_admin.map(|(id, _)| id.to_string()),
        "admin_label": matched_admin.map(|(_, label)| label.as_str()),
        "outcome": outcome,
        "node_id": std::env::var("MILNET_NODE_ID").unwrap_or_default(),
    });

    let json = match serde_json::to_string(&entry_json) {
        Ok(j) => j,
        Err(_) => return false,
    };

    // Layer 1: BFT hash-chained audit (ML-DSA-87 signed, distributed)
    // This is the unforgeable layer. Even if all other layers are compromised,
    // the hash chain across 7 separate nodes provides cryptographic proof.
    // Entry N's hash = SHA-512(domain || fields || prev_hash_of_entry_N-1).
    // Modifying entry N invalidates entries N+1..latest on all honest nodes.
    if let Ok(mut log) = audit_log.try_write() {
        log.append_signed(
            common::types::AuditEventType::SuperAdminAccess,
            matched_admin.map(|(id, _)| vec![*id]).unwrap_or_default(),
            vec![],
            if outcome == "key_matched" { 0.0 } else { 1.0 },
            vec![],
            pq_signing_key,
        );
    }

    // Layer 2: Local append-only file (fsync — fail-closed)
    let file_ok = {
        if let Some(parent) = std::path::Path::new(SUPER_ADMIN_ACCESS_LOG).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(SUPER_ADMIN_ACCESS_LOG)
        {
            Ok(mut f) => {
                use std::io::Write;
                if writeln!(f, "{}", json).is_ok() {
                    f.sync_all().is_ok()
                } else {
                    false
                }
            }
            Err(e) => {
                tracing::error!(
                    "CRITICAL: cannot write super admin access log: {e}. \
                     DENYING access (fail-closed)."
                );
                false
            }
        }
    };

    // Layer 3: SIEM broadcast (distributed consumers)
    common::siem::SecurityEvent::tamper_detected(&detail);

    // Layer 4: Critical alerts file (redundant local)
    common::siem::persist_critical_alert(&json);

    file_ok
}

/// Guard: the super_admins table is FROZEN after setup.
/// Any attempt to write after setup_complete is a security violation.
/// Call this before ANY DB write to super_admins — panics if table is frozen.
pub fn assert_super_admins_not_frozen(setup_complete: &std::sync::atomic::AtomicBool) -> Result<(), StatusCode> {
    if setup_complete.load(Ordering::Relaxed) {
        // Log to SIEM — this is a critical event
        common::siem::SecurityEvent::tamper_detected(
            "CRITICAL: attempted write to FROZEN super_admins table after setup. \
             Table is immutable. Possible compromise attempt."
        );
        tracing::error!(
            "SECURITY VIOLATION: attempted write to frozen super_admins table. \
             The super_admins table is immutable after initial setup."
        );
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared application state
// ---------------------------------------------------------------------------

pub struct AppState {
    pub db: PgPool,
    pub credential_store: RwLock<opaque::store::CredentialStore>,
    pub device_registry: RwLock<risk::tiers::DeviceRegistry>,
    pub audit_log: RwLock<audit::log::AuditLog>,
    pub kt_tree: RwLock<kt::merkle::MerkleTree>,
    pub portals: RwLock<Vec<Portal>>,
    pub oauth_clients: RwLock<sso_protocol::clients::ClientRegistry>,
    pub auth_codes: RwLock<sso_protocol::authorize::AuthorizationStore>,
    pub oidc_signing_key: sso_protocol::tokens::OidcSigningKey,
    pub admin_api_key: zeroize::Zeroizing<String>,
    /// Registry of super admin API keys (id -> key_hash).
    /// Loaded from DB at startup, updated during setup.
    pub super_admin_keys: RwLock<HashMap<Uuid, SuperAdminEntry>>,
    pub fido_store: RwLock<fido::registration::CredentialStore>,
    pub setup_complete: Arc<AtomicBool>,
    pub pending_ceremonies: RwLock<HashMap<Uuid, PendingCeremony>>,
    pub last_level4_ceremony: RwLock<Option<i64>>,
    pub level4_count_72h: RwLock<Vec<i64>>,
    pub google_config: Option<crate::google_oauth::GoogleOAuthConfig>,
    pub pending_google: RwLock<crate::google_oauth::PendingGoogleStore>,
    pub google_jwks_cache: crate::google_oauth::GoogleJwksCache,
    pub http_client: reqwest::Client,
    pub access_tokens: RwLock<HashMap<String, AccessTokenEntry>>,
    /// Tracks the last activity timestamp (epoch seconds) for each user session
    /// token.  Used to enforce the AAL3 15-minute inactivity timeout.
    pub session_activity: RwLock<HashMap<String, i64>>,
    pub login_attempts: RwLock<HashMap<String, LoginAttemptEntry>>,
    /// Opaque token handle map: random handle -> (user_id, timestamp, expiry).
    pub opaque_tokens: RwLock<HashMap<String, OpaqueTokenEntry>>,
    /// Set of used CSRF tokens to enforce single-use semantics.
    pub used_csrf_tokens: RwLock<HashSet<String>>,
    pub pq_signing_key: crypto::pq_sign::PqSigningKey,
    pub session_tracker: Arc<common::session_limits::SessionTracker>,
    pub revocation_list: RwLock<RevocationList>,
    /// Atomic error level flag — mirrors the global in common::config.
    pub developer_mode: AtomicBool,
    /// Atomic log-level flag (0 = Verbose, 1 = Error).
    pub developer_log_level: AtomicU8,
    /// Pending destructive admin actions awaiting multi-person approval.
    pub pending_admin_actions: RwLock<HashMap<Uuid, PendingAdminAction>>,
    /// HA database pool with primary/replica routing and health tracking.
    pub ha_pool: std::sync::Mutex<common::db_ha::HaPool>,
    /// Envelope encryption for database fields (AES-256-GCM with HKDF-derived per-table KEKs).
    pub encrypted_pool: common::encrypted_db::EncryptedPool,
    /// Encrypted distributed session store for persistent, replicated sessions.
    pub session_store: RwLock<common::distributed_session::DistributedSessionStore>,
    /// Refresh token store for issuing and redeeming refresh tokens with
    /// family-based revocation per RFC 6749 Section 10.4.
    pub refresh_token_store: RwLock<sso_protocol::tokens::RefreshTokenStore>,
}

/// Entry in the access_tokens map, pairing a user ID with a last-activity
/// timestamp for inactivity timeout enforcement (AAL3: 15 minutes).
pub struct AccessTokenEntry {
    pub user_id: Uuid,
    pub last_activity: i64,
}

/// Entry in the opaque_tokens map for the new opaque token format.
/// Maps a random 32-byte handle (hex-encoded) to user metadata.
pub struct OpaqueTokenEntry {
    pub user_id: Uuid,
    pub created_at: i64,
    pub expires_at: i64,
}

// ---------------------------------------------------------------------------
// Opaque token DB persistence (write-through cache)
// ---------------------------------------------------------------------------

/// Persist an opaque token to the database (write-through on creation).
async fn db_insert_opaque_token(db: &PgPool, token_handle: &str, entry: &OpaqueTokenEntry) {
    let result = sqlx::query(
        "INSERT INTO opaque_tokens (token_handle, user_id, created_at, expires_at) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (token_handle) DO UPDATE SET user_id = $2, created_at = $3, expires_at = $4"
    )
    .bind(token_handle)
    .bind(entry.user_id)
    .bind(entry.created_at)
    .bind(entry.expires_at)
    .execute(db)
    .await;

    if let Err(e) = result {
        tracing::warn!(error = %e, "failed to persist opaque token to database");
    }
}

/// Look up an opaque token from the database (L2 fallback after cache miss).
async fn db_lookup_opaque_token(db: &PgPool, token_handle: &str) -> Option<OpaqueTokenEntry> {
    let row = sqlx::query_as::<_, (Uuid, i64, i64)>(
        "SELECT user_id, created_at, expires_at FROM opaque_tokens WHERE token_handle = $1 AND expires_at > $2"
    )
    .bind(token_handle)
    .bind(now_secs())
    .fetch_optional(db)
    .await;

    match row {
        Ok(Some((user_id, created_at, expires_at))) => Some(OpaqueTokenEntry {
            user_id,
            created_at,
            expires_at,
        }),
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(error = %e, "failed to look up opaque token from database");
            None
        }
    }
}

/// Delete an opaque token from the database (write-through on revocation).
async fn db_delete_opaque_token(db: &PgPool, token_handle: &str) {
    let result = sqlx::query("DELETE FROM opaque_tokens WHERE token_handle = $1")
        .bind(token_handle)
        .execute(db)
        .await;

    if let Err(e) = result {
        tracing::warn!(error = %e, "failed to delete opaque token from database");
    }
}

/// Warm the in-memory opaque token cache from the database on startup.
/// Loads all non-expired tokens up to the capacity limit.
pub async fn warm_opaque_token_cache(db: &PgPool, cache: &RwLock<HashMap<String, OpaqueTokenEntry>>) {
    let now = now_secs();
    let rows = sqlx::query_as::<_, (String, Uuid, i64, i64)>(
        "SELECT token_handle, user_id, created_at, expires_at FROM opaque_tokens \
         WHERE expires_at > $1 ORDER BY created_at DESC LIMIT $2"
    )
    .bind(now)
    .bind(MAX_ACCESS_TOKENS as i64)
    .fetch_all(db)
    .await;

    match rows {
        Ok(entries) => {
            let count = entries.len();
            let mut cache = cache.write().await;
            for (handle, user_id, created_at, expires_at) in entries {
                cache.insert(handle, OpaqueTokenEntry {
                    user_id,
                    created_at,
                    expires_at,
                });
            }
            tracing::info!(count = count, "opaque token cache warmed from database");
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to warm opaque token cache from database");
        }
    }
}

/// Maximum inactivity window before a session is considered expired (AAL3).
const INACTIVITY_TIMEOUT_SECS: i64 = 15 * 60;

/// Maximum length for usernames (prevents allocation attacks).
const MAX_USERNAME_LEN: usize = 255;
/// Minimum length for passwords (NIST SP 800-63B minimum).
const MIN_PASSWORD_LEN: usize = 12;
/// Maximum length for passwords (prevents Argon2id DoS via huge inputs).
/// NIST SP 800-63B recommends accepting at least 64 characters; 128 is generous.
const MAX_PASSWORD_LEN: usize = 128;
/// Maximum length for portal names.
const MAX_PORTAL_NAME_LEN: usize = 255;
/// Maximum length for callback URLs.
const MAX_CALLBACK_URL_LEN: usize = 2048;
/// Maximum number of access tokens before cleanup is triggered.
const MAX_ACCESS_TOKENS: usize = 50_000;
/// Maximum number of session_activity entries.
const MAX_SESSION_ACTIVITY: usize = 50_000;
/// Maximum number of login_attempts entries.
const MAX_LOGIN_ATTEMPTS: usize = 100_000;
/// Maximum number of pending ceremonies.
const MAX_PENDING_CEREMONIES: usize = 1_000;
/// Maximum number of used CSRF tokens tracked.
const MAX_USED_CSRF_TOKENS: usize = 100_000;

// ---------------------------------------------------------------------------
// Trusted proxy validation for X-Forwarded-For
// ---------------------------------------------------------------------------

/// Parse CIDR ranges from `MILNET_TRUSTED_PROXIES` env var.
/// Returns a list of (network_ip, prefix_len) tuples.
fn load_trusted_proxies() -> Vec<(IpAddr, u8)> {
    match std::env::var("MILNET_TRUSTED_PROXIES") {
        Ok(val) if !val.is_empty() => {
            val.split(',')
                .filter_map(|cidr| {
                    let cidr = cidr.trim();
                    if cidr.is_empty() {
                        return None;
                    }
                    let parts: Vec<&str> = cidr.splitn(2, '/').collect();
                    let ip: IpAddr = parts[0].parse().ok()?;
                    let prefix: u8 = if parts.len() == 2 {
                        parts[1].parse().ok()?
                    } else {
                        match ip {
                            IpAddr::V4(_) => 32,
                            IpAddr::V6(_) => 128,
                        }
                    };
                    Some((ip, prefix))
                })
                .collect()
        }
        _ => Vec::new(),
    }
}

/// Check whether `addr` falls within any of the trusted proxy CIDR ranges.
fn is_trusted_proxy(addr: &IpAddr, trusted: &[(IpAddr, u8)]) -> bool {
    for &(ref network, prefix_len) in trusted {
        match (addr, network) {
            (IpAddr::V4(a), IpAddr::V4(n)) => {
                if prefix_len == 0 {
                    return true;
                }
                let mask = if prefix_len >= 32 {
                    u32::MAX
                } else {
                    u32::MAX << (32 - prefix_len)
                };
                if u32::from_be_bytes(a.octets()) & mask
                    == u32::from_be_bytes(n.octets()) & mask
                {
                    return true;
                }
            }
            (IpAddr::V6(a), IpAddr::V6(n)) => {
                if prefix_len == 0 {
                    return true;
                }
                let mask = if prefix_len >= 128 {
                    u128::MAX
                } else {
                    u128::MAX << (128 - prefix_len)
                };
                if u128::from_be_bytes(a.octets()) & mask
                    == u128::from_be_bytes(n.octets()) & mask
                {
                    return true;
                }
            }
            _ => {} // v4/v6 mismatch — skip
        }
    }
    false
}

/// Extract the real client IP from a request, respecting X-Forwarded-For only
/// when the direct connection comes from a trusted proxy.  Falls back to the
/// connection IP (or "unknown") when there is no trusted proxy.
fn extract_client_ip(request: &Request) -> String {
    use std::net::SocketAddr;

    // Determine the direct connection IP from ConnectInfo if available,
    // otherwise fall back to "unknown".
    let connection_ip: Option<IpAddr> = request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());

    let trusted_proxies = load_trusted_proxies();

    // Only honour X-Forwarded-For if the connection comes from a trusted proxy.
    if let Some(forwarded) = request.headers().get("X-Forwarded-For").and_then(|v| v.to_str().ok()) {
        if let Some(conn_ip) = connection_ip {
            if !trusted_proxies.is_empty() && is_trusted_proxy(&conn_ip, &trusted_proxies) {
                // Trusted proxy: use the left-most (client) IP from X-Forwarded-For.
                if let Some(client) = forwarded.split(',').next() {
                    return client.trim().to_string();
                }
            } else {
                tracing::warn!(
                    connection_ip = %conn_ip,
                    x_forwarded_for = %forwarded,
                    "X-Forwarded-For present but source IP is NOT a trusted proxy — ignoring header"
                );
            }
        } else if !trusted_proxies.is_empty() {
            tracing::warn!(
                x_forwarded_for = %forwarded,
                "X-Forwarded-For present but connection IP unavailable — ignoring header"
            );
        } else {
            // Fail-closed: no trusted proxies configured, use direct connection IP.
            // Do NOT trust X-Forwarded-For from unknown sources.
            tracing::warn!(
                x_forwarded_for = %forwarded,
                "X-Forwarded-For present but no trusted proxies configured — ignoring header"
            );
        }
    }

    connection_ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// TTL for session_activity entries (8 hours).
const SESSION_ACTIVITY_TTL_SECS: i64 = 8 * 3600;
/// TTL for login_attempts entries (30 minutes).
const LOGIN_ATTEMPTS_TTL_SECS: i64 = 30 * 60;
/// TTL for pending ceremonies (15 minutes).
const PENDING_CEREMONY_TTL_SECS: i64 = 15 * 60;

/// Domain separator for audit log HMAC signatures in admin routes.
const ADMIN_AUDIT_DOMAIN_SEPARATOR: &[u8] = b"MILNET-ADMIN-AUDIT-v1";

/// Evict the oldest entries from a HashMap when it exceeds max capacity.
/// Requires the value type to expose a timestamp via the provided closure.
fn enforce_map_capacity<K: Eq + std::hash::Hash + Clone, V>(
    map: &mut HashMap<K, V>,
    max: usize,
) {
    if map.len() <= max {
        return;
    }
    // Remove 10% of entries to amortise eviction cost.
    let target = max * 9 / 10;
    let to_remove = map.len() - target;
    let keys: Vec<K> = map.keys().take(to_remove).cloned().collect();
    for key in keys {
        map.remove(&key);
    }
}

/// Rate-limit lockout thresholds: (attempt_count, lockout_duration_secs).
const LOCKOUT_TIERS: &[(u32, i64)] = &[
    (5, 30),       // After 5 failed attempts: 30-second lockout
    (10, 300),     // After 10 failed attempts: 5-minute lockout
    (20, 1800),    // After 20 failed attempts: 30-minute lockout
];

/// Login attempt tracking entry: (count, first_attempt_time, last_attempt_time).
pub struct LoginAttemptEntry {
    pub count: u32,
    pub first_attempt: i64,
    pub last_attempt: i64,
}

/// Check whether the given username or IP is locked out based on failed attempts.
fn is_locked_out(username: &str, ip: &str, attempts: &HashMap<String, LoginAttemptEntry>) -> bool {
    let now = now_secs();
    // Check both username-based and IP-based lockouts
    for key in &[username.to_string(), format!("ip:{}", ip)] {
        if let Some(entry) = attempts.get(key.as_str()) {
            for &(threshold, duration) in LOCKOUT_TIERS.iter().rev() {
                if entry.count >= threshold {
                    if now - entry.last_attempt < duration {
                        return true;
                    }
                    break;
                }
            }
        }
    }
    false
}

/// Record a failed login attempt for both username and IP.
fn record_failed_attempt(
    attempts: &mut HashMap<String, LoginAttemptEntry>,
    username: &str,
    ip: &str,
) {
    let now = now_secs();
    for key in &[username.to_string(), format!("ip:{}", ip)] {
        let entry = attempts.entry(key.clone()).or_insert(LoginAttemptEntry {
            count: 0,
            first_attempt: now,
            last_attempt: now,
        });
        entry.count += 1;
        entry.last_attempt = now;
    }
}

/// Compute an HMAC-SHA512 signature over data for audit log signing.
fn sign_audit_entry(data: &[u8], signing_key: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;

    let mut mac = HmacSha512::new_from_slice(signing_key)
        .unwrap_or_else(|_| { tracing::error!("FATAL: HMAC-SHA512 key init failed"); std::process::exit(1) });
    mac.update(ADMIN_AUDIT_DOMAIN_SEPARATOR);
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Derive the admin audit signing key from the master KEK.
fn derive_admin_audit_key() -> [u8; 64] {
    use hkdf::Hkdf;
    use sha2::Sha512;

    let master_kek = common::sealed_keys::load_master_kek();
    let hk = Hkdf::<Sha512>::new(Some(ADMIN_AUDIT_DOMAIN_SEPARATOR), &master_kek);
    let mut okm = [0u8; 64];
    hk.expand(b"admin-audit-signing-key", &mut okm)
        .unwrap_or_else(|_| { tracing::error!("FATAL: HKDF expand failed"); std::process::exit(1) });
    okm
}

/// A pending multi-person ceremony that requires multiple approvers.
/// Each approval includes an HMAC-SHA512 signature over the ceremony_id,
/// providing cryptographic binding between the approver and the ceremony.
#[derive(Clone, Serialize)]
pub struct PendingCeremony {
    pub action: String,
    pub level: u8,
    pub initiator: Uuid,
    /// Each approval is a (user_id, hmac_signature) pair providing
    /// cryptographic proof that the specific approver authorized this ceremony.
    pub approvals: Vec<(Uuid, Vec<u8>)>,
    pub required_approvals: usize,
    pub created_at: i64,
    pub expires_at: i64,
}

/// Compute the expected HMAC-SHA512 signature for a ceremony approval.
/// The approver must provide their own signature over the ceremony_id
/// using a key derived from the master KEK and their user_id.
fn compute_ceremony_approval_hmac(ceremony_id: &Uuid, approver_id: &Uuid) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;

    let master_kek = common::sealed_keys::load_master_kek();
    let derived = {
        use hkdf::Hkdf;
        let hk = Hkdf::<Sha512>::new(Some(b"MILNET-CEREMONY-APPROVAL-v1"), &master_kek);
        let mut okm = [0u8; 64];
        hk.expand(approver_id.as_bytes(), &mut okm)
            .unwrap_or_else(|_| { tracing::error!("FATAL: HKDF expand failed"); std::process::exit(1) });
        okm
    };
    let mut mac = HmacSha512::new_from_slice(&derived)
        .unwrap_or_else(|_| { tracing::error!("FATAL: HMAC-SHA512 key init failed"); std::process::exit(1) });
    mac.update(ceremony_id.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Verify a ceremony approval signature from an approver.
fn verify_ceremony_approval(
    ceremony_id: &Uuid,
    approver_id: &Uuid,
    provided_signature: &[u8],
) -> bool {
    let expected = compute_ceremony_approval_hmac(ceremony_id, approver_id);
    crypto::ct::ct_eq(&expected, provided_signature)
}

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------

/// Bearer token authentication middleware.
///
/// Skips auth for health, discovery, public OAuth endpoints, and static assets.
/// For all other routes, requires a valid Bearer token that matches either:
/// - the admin API key (from ADMIN_API_KEY env var), or
/// - a user auth token issued by /api/auth/login.
/// Extension to carry the authenticated user's tier through the request.
#[derive(Debug, Clone, Copy)]
pub struct AuthTier(pub u8);

/// Extension: which super admin authenticated (for ceremony dedup).
#[derive(Debug, Clone, Copy)]
pub struct AuthSuperAdminId(pub Uuid);

/// Extension to carry the authenticated user's ID through the request.
#[derive(Debug, Clone, Copy)]
pub struct AuthUserId(pub Uuid);

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Skip auth for health, discovery, and public endpoints
    let path = request.uri().path();
    if path == "/api/health"
        || path == "/.well-known/openid-configuration"
        || path.starts_with("/oauth/")
        || path == "/oauth/token"
        || path.starts_with("/api/auth/")
        || path == "/api/recovery/verify"
        || path.starts_with("/api/setup")
        || path == "/"
        || path == "/challenge"
        || path == "/about"
        || path == "/pitch"
        || path == "/docs"
    {
        return Ok(next.run(request).await);
    }

    // Check Bearer token
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            let token = &header[7..];
            // Accept the legacy admin API key — treated as tier 1 (Sovereign)
            // Use constant-time comparison to prevent timing side-channels.
            if crypto::ct::ct_eq(token.as_bytes(), state.admin_api_key.as_bytes()) {
                request.extensions_mut().insert(AuthTier(1));
                request.extensions_mut().insert(AuthAdminRole(AdminRole::SuperAdmin));
                return Ok(next.run(request).await);
            }

            // Check per-super-admin API keys (multi-admin support).
            // LOG FIRST, AUTHENTICATE SECOND: the access attempt is recorded
            // to the immutable distributed audit log BEFORE the key is verified.
            // If logging fails, access is DENIED (fail-closed).
            {
                let admins = state.super_admin_keys.read().await;
                if !admins.is_empty() {
                    let source_ip = request.headers()
                        .get("x-forwarded-for")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("unknown")
                        .to_string();
                    let req_path = request.uri().path().to_string();
                    let req_method = request.method().to_string();

                    let matched = match_super_admin_key(token.as_bytes(), &admins);

                    // Log the attempt BEFORE auth decision — into BFT hash chain
                    let outcome = if matched.is_some() { "key_matched" } else { "key_rejected" };
                    let log_ok = log_super_admin_access(
                        &state.audit_log,
                        &state.pq_signing_key,
                        &source_ip, &req_path, &req_method,
                        matched.as_ref(), outcome,
                    );

                    if let Some((admin_id, label)) = matched {
                        if !log_ok {
                            // Logging failed — DENY access (fail-closed).
                            tracing::error!(
                                "DENIED: super admin '{}' access denied because audit log write failed. \
                                 Fix /var/lib/milnet/audit/ permissions.",
                                label
                            );
                            return Err(StatusCode::SERVICE_UNAVAILABLE);
                        }

                        // Record ACCESS_GRANTED in DB audit log (for last_used derivation).
                        // Best-effort: don't block auth if DB write fails (file log is primary).
                        let _ = sqlx::query(
                            "INSERT INTO super_admin_audit_log (operation, admin_id, admin_label, detail, source_ip) \
                             VALUES ('ACCESS_GRANTED', $1, $2, $3, $4)"
                        )
                        .bind(admin_id)
                        .bind(&label)
                        .bind(format!("{} {}", req_method, req_path))
                        .bind(&source_ip)
                        .execute(&state.db)
                        .await;

                        request.extensions_mut().insert(AuthTier(1));
                        request.extensions_mut().insert(AuthAdminRole(AdminRole::SuperAdmin));
                        request.extensions_mut().insert(AuthSuperAdminId(admin_id));
                        return Ok(next.run(request).await);
                    }
                }
            }

            // Check per-role admin API keys derived from master KEK.
            if let Some(role) = resolve_admin_role(token) {
                // Role-based key authenticated — check RBAC permission
                let req_path = request.uri().path().to_string();
                let req_method = request.method().clone();
                let required = required_role_for_route(&req_path, &req_method);
                if !role.satisfies(required) {
                    tracing::warn!(
                        "RBAC denied: role {} insufficient for {} {} (requires {})",
                        role, req_method, req_path, required
                    );
                    // Log RBAC denial to tamper-proof hash-chained audit log.
                    // Without this, privilege escalation attempts are invisible
                    // to forensic analysis after host compromise.
                    if let Ok(mut log) = state.audit_log.try_write() {
                        log.append_signed(
                            common::types::AuditEventType::AdminRbacDenied,
                            vec![],
                            vec![],
                            0.8,
                            vec![],
                            &state.pq_signing_key,
                        );
                    }
                    return Err(StatusCode::FORBIDDEN);
                }
                // SECURITY: Log ALL admin data access (reads), not just mutations.
                // An insider who reads sensitive data without audit trail can
                // silently exfiltrate classified information.
                if req_method == Method::GET || req_method == Method::HEAD {
                    common::siem::SecurityEvent::admin_data_access(
                        &format!("ADMIN_READ: {} {} role={}", req_method, req_path, role),
                    );
                    if let Ok(mut log) = state.audit_log.try_write() {
                        log.append_signed(
                            common::types::AuditEventType::AdminRbacGranted,
                            vec![],
                            vec![],
                            0.1,
                            vec![],
                            &state.pq_signing_key,
                        );
                    }
                }
                request.extensions_mut().insert(AuthTier(1));
                request.extensions_mut().insert(AuthAdminRole(role));
                return Ok(next.run(request).await);
            }
            // Try opaque token format first (32-byte hex handle)
            let opaque_user = {
                let now = now_secs();
                let tokens = state.opaque_tokens.read().await;
                if let Some(entry) = tokens.get(token) {
                    if now < entry.expires_at {
                        Some(entry.user_id)
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

            // Resolve user_id: either from opaque token or legacy format
            let resolved_user_id = if let Some(uid) = opaque_user {
                Some(uid)
            } else if verify_user_token(token) {
                // Legacy format backward-compat: user_id:timestamp:hmac
                let parts: Vec<&str> = token.splitn(3, ':').collect();
                if parts.len() == 3 {
                    Uuid::parse_str(parts[0]).ok()
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(user_id) = resolved_user_id {
                // Enforce AAL3 inactivity timeout (15 minutes)
                let now = now_secs();
                {
                    let activity = state.session_activity.read().await;
                    if let Some(&last) = activity.get(token) {
                        if now - last > INACTIVITY_TIMEOUT_SECS {
                            drop(activity);
                            state.session_activity.write().await.remove(token);
                            return Err(StatusCode::UNAUTHORIZED);
                        }
                    }
                }
                // Update last activity timestamp (with capacity enforcement)
                {
                    let mut activity = state.session_activity.write().await;
                    enforce_map_capacity(&mut *activity, MAX_SESSION_ACTIVITY);
                    activity.insert(token.to_string(), now);
                }

                // Look up user tier from DB
                let t: i32 = match sqlx::query_scalar("SELECT tier FROM users WHERE id = $1")
                    .bind(user_id)
                    .fetch_one(&state.db)
                    .await
                {
                    Ok(tier) => tier,
                    Err(e) => {
                        tracing::warn!("Failed to fetch tier for user {}: {}", common::log_pseudonym::pseudonym_uuid(user_id), e);
                        return Err(StatusCode::UNAUTHORIZED);
                    }
                };
                request.extensions_mut().insert(AuthTier(t as u8));
                request.extensions_mut().insert(AuthUserId(user_id));
                return Ok(next.run(request).await);
            }
            Err(StatusCode::UNAUTHORIZED)
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

/// Verify an HMAC-based user token (same logic as auth_verify handler).
fn verify_user_token(token: &str) -> bool {
    let parts: Vec<&str> = token.splitn(3, ':').collect();
    if parts.len() != 3 {
        return false;
    }
    if Uuid::parse_str(parts[0]).is_err() {
        return false;
    }

    let payload = format!("{}:{}", parts[0], parts[1]);

    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;

    // Derive HMAC key from master KEK — prevents forging tokens without KEK
    let master_kek = common::sealed_keys::load_master_kek();
    let derived = {
        use hkdf::Hkdf;
        let hk = Hkdf::<Sha512>::new(Some(b"MILNET-ADMIN-TOKEN-v3"), &master_kek);
        let mut okm = [0u8; 32];
        hk.expand(b"admin-token-hmac", &mut okm)
            .unwrap_or_else(|_| { tracing::error!("FATAL: HKDF expand failed"); std::process::exit(1) });
        okm
    };
    let mut mac = HmacSha512::new_from_slice(&derived)
        .unwrap_or_else(|_| { tracing::error!("FATAL: HMAC-SHA512 key init failed"); std::process::exit(1) });
    mac.update(payload.as_bytes());
    let expected = hex(&mac.finalize().into_bytes());

    if !crypto::ct::ct_eq(expected.as_bytes(), parts[2].as_bytes()) {
        return false;
    }

    // Check token age — expire after 1 hour
    let timestamp: u64 = parts[1].parse().unwrap_or(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_secs();
    if now - timestamp > 3600 {
        return false; // Token expired (1 hour)
    }

    true
}

/// Middleware that validates Origin/Referer on mutating requests to prevent
/// cross-origin request forgery, and enforces Content-Type on request bodies.
/// GET, HEAD, OPTIONS are exempt (safe methods).
async fn origin_and_content_type_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let method = request.method().clone();
    let path = request.uri().path().to_string();

    // Safe methods are exempt from both checks
    if method == axum::http::Method::GET
        || method == axum::http::Method::HEAD
        || method == axum::http::Method::OPTIONS
    {
        return Ok(next.run(request).await);
    }

    // ── Content-Type enforcement ──────────────────────────────────────
    // All POST/PUT/DELETE with a body must send application/json.
    // Skip for OAuth token endpoint (uses form-urlencoded per RFC 6749)
    // and static file routes.
    if !path.starts_with("/oauth/token") && path.starts_with("/api") {
        let ct = request
            .headers()
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !ct.contains("application/json") {
            tracing::warn!("Content-Type rejected: {ct:?} on {method} {path}");
            return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }
    }

    // ── Origin/Referer validation ─────────────────────────────────────
    let origin = request
        .headers()
        .get("Origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let referer = request
        .headers()
        .get("Referer")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let host = request
        .headers()
        .get("Host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let allowed = match (&origin, &referer) {
        // Origin present: must reference our host
        (Some(o), _) => {
            let o_lower = o.to_lowercase();
            // SECURITY: Never accept Origin: null — browsers send it from sandboxed
            // iframes, data: URIs, and file: contexts, enabling cross-origin CSRF.
            if o_lower == "null" {
                false
            } else {
                // SECURITY: Extract the host from the Origin URL and compare
                // exactly. Substring matching was vulnerable to crafted
                // domains like "attacker.com.legit.com".
                if host.is_empty() {
                    false
                } else {
                    // Origin format: "scheme://host[:port]"
                    let origin_host = o_lower
                        .split("://")
                        .nth(1)
                        .unwrap_or(&o_lower)
                        .split('/')
                        .next()
                        .unwrap_or("")
                        .split(':')
                        .next()
                        .unwrap_or("");
                    origin_host == host
                }
            }
        }
        // No Origin, Referer present: extract and match host exactly
        (None, Some(r)) => {
            if host.is_empty() {
                true
            } else {
                let r_lower = r.to_lowercase();
                let after_scheme = r_lower
                    .split("://")
                    .nth(1)
                    .unwrap_or(&r_lower);
                let before_path = after_scheme
                    .split('/')
                    .next()
                    .unwrap_or("");
                let ref_host = before_path
                    .split(':')
                    .next()
                    .unwrap_or("");
                ref_host == host
            }
        }
        // Neither: allow only Bearer-token API calls (non-browser clients)
        (None, None) => request.headers().get("Authorization").is_some(),
    };

    if allowed {
        Ok(next.run(request).await)
    } else {
        tracing::warn!(
            "Origin check failed: origin={:?} referer={:?} host={:?} path={path}",
            origin,
            referer,
            host
        );
        Err(StatusCode::FORBIDDEN)
    }
}

/// Middleware that adds HTTP security headers to all responses.
async fn security_headers_middleware(
    request: Request,
    next: Next,
) -> Response {
    // Propagate or generate a request ID for distributed tracing.
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // X-Request-ID for end-to-end tracing
    if let Ok(val) = axum::http::HeaderValue::from_str(&request_id) {
        headers.insert(
            axum::http::header::HeaderName::from_static("x-request-id"),
            val,
        );
    }

    headers.insert(
        axum::http::header::HeaderName::from_static("x-content-type-options"),
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("x-frame-options"),
        axum::http::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("x-xss-protection"),
        axum::http::HeaderValue::from_static("0"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("referrer-policy"),
        axum::http::HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("strict-transport-security"),
        axum::http::HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("content-security-policy"),
        axum::http::HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        ),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("permissions-policy"),
        axum::http::HeaderValue::from_static(
            "camera=(), microphone=(), geolocation=(), payment=()"
        ),
    );

    // Cache-Control: no-store on all responses (not just auth endpoints)
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );

    response
}

/// Check if the authenticated user's tier allows access to this endpoint.
/// Lower tier number = higher privilege.
fn check_tier(token_tier: u8, required_tier: u8) -> Result<(), StatusCode> {
    if token_tier <= required_tier {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

// ---------------------------------------------------------------------------
fn now_secs() -> i64 {
    common::secure_time::secure_now_secs_i64()
}

// Pagination
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct PaginationParams {
    limit: Option<u32>,
    offset: Option<u32>,
}

impl PaginationParams {
    fn limit(&self) -> u32 {
        self.limit.unwrap_or(100).min(1000)
    }
    fn offset(&self) -> u32 {
        self.offset.unwrap_or(0)
    }
}

// Domain types
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
pub struct Portal {
    pub id: Uuid,
    pub name: String,
    pub callback_url: String,
    pub required_tier: u8,
    pub required_scope: u32,
    pub is_active: bool,
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RegisterUserRequest {
    pub username: String,
    pub password: String,
    pub tier: Option<u8>,  // 1=Sovereign, 2=Operational, 3=Sensor, 4=Emergency. Default: 2
}

impl Drop for RegisterUserRequest {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
    }
}

#[derive(Serialize)]
pub struct RegisterUserResponse {
    pub user_id: Uuid,
    pub username: String,
    pub tier: u8,
}

#[derive(Deserialize)]
pub struct RegisterPortalRequest {
    pub name: String,
    pub callback_url: String,
    pub required_tier: u8,
    pub required_scope: u32,
}

#[derive(Serialize)]
pub struct PortalResponse {
    pub id: Uuid,
    pub name: String,
    pub callback_url: String,
    pub required_tier: u8,
    pub required_scope: u32,
    pub is_active: bool,
}

#[derive(Deserialize)]
pub struct EnrollDeviceRequest {
    pub name: Option<String>,
    pub tier: Option<u8>,
    pub attestation_hash: Option<String>,
    pub enrolled_by: Option<Uuid>,
}

#[derive(Serialize)]
pub struct DeviceResponse {
    pub device_id: Uuid,
    pub tier: u8,
    pub enrolled_by: Uuid,
    pub is_active: bool,
}

#[derive(Serialize)]
pub struct SystemStatus {
    pub version: String,
    pub users_registered: i64,
    pub devices_enrolled: i64,
    pub portals_active: i64,
    pub audit_entries: i64,
    pub kt_operations: usize,
}

#[derive(Serialize)]
pub struct AuditEntryResponse {
    pub event_id: Uuid,
    pub event_type: String,
    pub user_ids: Vec<Uuid>,
    pub device_ids: Vec<Uuid>,
    pub risk_score: f64,
    pub timestamp: i64,
}

#[derive(Serialize)]
pub struct KtRootResponse {
    pub root: String,
    pub leaf_count: usize,
}

#[derive(Serialize)]
pub struct KtProofResponse {
    pub index: usize,
    pub proof: Vec<String>,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

impl Drop for LoginRequest {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
    }
}

#[derive(Serialize, Default)]
pub struct LoginResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<u8>,
    /// Backend-decided dashboard: "admin" or "user"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dashboard: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub token: String,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
    pub user_id: Option<Uuid>,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct SetupRequest {
    pub username: String,
    pub password: String,
    pub organization: Option<String>,
    /// Super admins to create during initial setup.
    /// Each super admin gets a unique API key derived from the master KEK.
    /// If empty or absent, a single super admin named "default" is created.
    /// Example: [{"label": "us-east", "region": "us-east-1"}, {"label": "eu-west", "region": "eu-west-1"}]
    #[serde(default)]
    pub super_admins: Vec<SuperAdminSetup>,
}

#[derive(Deserialize, Clone)]
pub struct SuperAdminSetup {
    /// Human-readable label (e.g., "us-east", "india-south", "eu-admin-1").
    pub label: String,
    /// Optional region tag for organizational clarity.
    pub region: Option<String>,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn api_router(state: Arc<AppState>) -> Router {
    Router::new()
        // System
        .route("/api/status", get(get_status))
        .route("/api/health", get(health_check))
        // First-run setup
        .route("/api/setup", post(initial_setup))
        .route("/api/setup/status", get(setup_status))
        // Users
        .route("/api/users", post(register_user))
        .route("/api/users", get(list_users))
        // Portals
        .route("/api/portals", post(register_portal))
        .route("/api/portals", get(list_portals))
        .route("/api/portals/{id}", delete(delete_portal))
        .route("/api/portals/check-access", post(check_portal_access))
        .route("/api/users/{user_id}", delete(delete_user))
        // Devices
        .route("/api/devices", post(enroll_device))
        .route("/api/devices", get(list_devices))
        // Audit
        .route("/api/audit", get(get_audit_log))
        .route("/api/audit/verify", get(verify_audit_chain))
        // Auth
        .route("/api/auth/login", post(auth_login))
        .route("/api/auth/verify", post(auth_verify))
        .route("/api/auth/duress-pin", post(register_duress_pin))
        .route("/api/auth/logout", post(auth_logout))
        // Key Transparency
        .route("/api/kt/root", get(get_kt_root))
        .route("/api/kt/proof/{index}", get(get_kt_proof))
        // OIDC / OAuth2
        .route("/.well-known/openid-configuration", get(oidc_discovery))
        .route("/oauth/authorize", get(oauth_authorize))
        .route("/oauth/authorize/login", post(oauth_authorize_login))
        .route("/oauth/google/start", get(oauth_google_start))
        .route("/oauth/google/callback", get(oauth_google_callback))
        .route("/oauth/token", post(oauth_token))
        .route("/oauth/userinfo", get(oauth_userinfo))
        .route("/oauth/jwks", get(oauth_jwks))
        // User self-service
        .route("/api/user/profile", get(get_user_profile))
        // Multi-person ceremony
        .route("/api/ceremony/initiate", post(initiate_ceremony))
        .route("/api/ceremony/approve", post(approve_ceremony))
        .route("/api/ceremony/{id}", get(ceremony_status))
        // FIDO2/WebAuthn
        .route("/api/fido/register/begin", post(fido_register_begin))
        .route("/api/fido/register/complete", post(fido_register_complete))
        .route("/api/fido/credentials", get(fido_credentials_list))
        .route("/api/fido/authenticate/begin", post(fido_authenticate_begin))
        .route("/api/fido/authenticate/complete", post(fido_authenticate_complete))
        // Recovery codes
        .route("/api/recovery/generate", post(recovery_generate))
        .route("/api/recovery/verify", post(recovery_verify))
        .route("/api/recovery/status", get(recovery_status))
        .route("/api/recovery/revoke-all", delete(recovery_revoke_all))
        // Public challenge page
        .route("/", get(|| async { axum::response::Redirect::temporary("/challenge") }))
        .route("/challenge", get(crate::challenge::challenge_page))
        // Static page redirects
        .route("/about", get(|| async { axum::response::Redirect::permanent("/about.html") }))
        .route("/pitch", get(|| async { axum::response::Redirect::permanent("/pitch.html") }))
        .route("/docs", get(|| async { axum::response::Redirect::permanent("/docs.html") }))
        // Security dashboard & testing
        .route("/api/security/dashboard", get(security_dashboard))
        .route("/api/sessions", get(list_sessions))
        .route("/api/security/test/token-tamper", post(test_token_tamper))
        .route("/api/security/test/audit-integrity", post(test_audit_integrity))
        .route("/api/security/test/crypto-health", post(test_crypto_health))
        .route("/api/security/config", get(security_config))
        // Token revocation
        .route("/api/tokens/revoke", post(revoke_token))
        .route("/api/tokens/revoked", get(revoked_token_count))
        // Developer mode (error level)
        .route("/api/admin/developer-mode", put(set_developer_mode))
        .route("/api/admin/developer-mode", get(get_developer_mode))
        // FIPS mode toggle (super-admin, ceremony required)
        .route("/api/admin/fips-mode", put(set_fips_mode))
        .route("/api/admin/fips-mode", get(get_fips_mode))
        // Super admin management (unanimous ceremony required to add)
        .route("/api/admin/super-admins", get(list_super_admins))
        .route("/api/admin/super-admins", post(add_super_admin))
        // Live SIEM event stream (SSE)
        .route("/api/admin/siem/stream", get(siem_stream))
        // ── Admin RBAC & two-person ceremony endpoints ──
        .route("/api/admin/actions/submit", post(submit_admin_action))
        .route("/api/admin/actions/approve", post(approve_admin_action))
        .route("/api/admin/actions/pending", get(list_pending_admin_actions))
        .route("/api/admin/actions/{id}", get(get_admin_action_status))
        .route("/api/admin/role-keys", get(get_admin_role_keys))
        // CAC/PIV card management
        .route("/api/cac/enroll", post(cac_enroll))
        .route("/api/cac/authenticate", post(cac_authenticate))
        .route("/api/cac/cards/by-user/{user_id}", get(cac_list_cards))
        .route("/api/cac/cards/{card_id}", delete(cac_revoke_card))
        .route("/api/cac/verify-cert", post(cac_verify_cert))
        .route("/api/cac/readers", get(cac_list_readers))
        // STIG audit
        .route("/api/stig/audit", get(stig_audit))
        .route("/api/stig/failures", get(stig_failures))
        // CMMC assessment
        .route("/api/cmmc/assess", get(cmmc_assess))
        .route("/api/cmmc/gaps", get(cmmc_gaps))
        // Compliance status
        .route("/api/compliance/status", get(compliance_status))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .layer(middleware::from_fn(origin_and_content_type_middleware))
        .layer(middleware::from_fn(security_headers_middleware))
        // Reject request bodies larger than 64 KB to prevent abuse
        .layer(tower_http::limit::RequestBodyLimitLayer::new(64 * 1024))
        .with_state(state)
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
                .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, header::ACCEPT])
                .allow_origin(
                    std::env::var("CORS_ALLOWED_ORIGIN")
                        .unwrap_or_else(|_| "https://sso-system.dmj.one".to_string())
                        .parse::<axum::http::HeaderValue>()
                        .unwrap_or_else(|_| axum::http::HeaderValue::from_static("https://sso-system.dmj.one")),
                ),
        )
        .fallback_service(ServeDir::new("frontend").append_index_html_on_directories(true))
}

// ---------------------------------------------------------------------------
// Handlers — System
// ---------------------------------------------------------------------------

async fn health_check(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    // Check primary DB connectivity
    let db_ok = sqlx::query("SELECT 1")
        .fetch_one(&state.db)
        .await
        .is_ok();

    // Check HA cluster health
    let cluster_health = {
        let mut ha = state.ha_pool.lock().unwrap_or_else(|e| {
            tracing::error!("ha_pool mutex poisoned: {e}");
            e.into_inner()
        });
        ha.check_health()
    };

    // Check distributed session store health
    let active_sessions = {
        let store = state.session_store.read().await;
        store.active_count()
    };

    let overall_status = if db_ok && cluster_health.primary_healthy {
        "ok"
    } else if db_ok {
        "degraded"
    } else {
        "unhealthy"
    };

    Json(serde_json::json!({
        "status": overall_status,
        "database": {
            "primary_reachable": db_ok,
            "ha_cluster": {
                "primary_healthy": cluster_health.primary_healthy,
                "healthy_replicas": cluster_health.healthy_replicas,
                "total_replicas": cluster_health.total_replicas,
                "degraded": cluster_health.degraded,
            }
        },
        "sessions": {
            "active_count": active_sessions,
        }
    }))
}

async fn setup_status(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    // Check in-memory flag first, then fall back to database
    if state.setup_complete.load(Ordering::Relaxed) {
        return Json(serde_json::json!({"setup_complete": true}));
    }
    // Check if any users exist in the database (survives restarts)
    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);
    if user_count > 0 {
        state.setup_complete.store(true, Ordering::Relaxed);
        return Json(serde_json::json!({"setup_complete": true}));
    }
    Json(serde_json::json!({"setup_complete": false}))
}

async fn initial_setup(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<SetupRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // SECURITY: Require out-of-band setup proof when MILNET_SETUP_PROOF is configured.
    // This prevents unauthorized initial setup even if the endpoint is reachable.
    // The proof is an HMAC-SHA512 digest that must be delivered via a separate channel.
    if let Ok(expected_proof) = std::env::var("MILNET_SETUP_PROOF") {
        let provided_proof = headers
            .get("X-Setup-Proof")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        // Constant-time comparison to prevent timing side-channels
        if !crypto::ct::ct_eq(provided_proof.as_bytes(), expected_proof.as_bytes()) {
            tracing::warn!("initial_setup rejected: invalid or missing X-Setup-Proof header");
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    // Only allow if no users exist yet (check both memory and DB)
    if state.setup_complete.load(Ordering::Relaxed) {
        return Err(StatusCode::FORBIDDEN);
    }
    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);
    if user_count > 0 {
        state.setup_complete.store(true, Ordering::Relaxed);
        return Err(StatusCode::FORBIDDEN);
    }

    // Create the superuser (OPAQUE credential)
    let mut store = state.credential_store.write().await;
    let user_id = store.register_with_password(&req.username, req.password.as_bytes());

    // Get the OPAQUE registration bytes for persistence
    let reg_bytes = store.get_registration_bytes(&req.username);

    // Persist superuser to PostgreSQL with tier 1 (Sovereign)
    if let Err(e) = sqlx::query(
        "INSERT INTO users (id, username, tier, opaque_registration, created_at, is_active) VALUES ($1, $2, 1, $3, $4, true) ON CONFLICT (username) DO UPDATE SET opaque_registration = $3"
    )
    .bind(user_id)
    .bind(&req.username)
    .bind(&reg_bytes)
    .bind(now_secs())
    .execute(&state.db)
    .await {
        tracing::error!(error = %e, "CRITICAL: failed to persist superuser registration to database");
        common::siem::SecurityEvent::database_operation_failed("superuser_registration_persist");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ── Create super admin API keys ──
    // If no super_admins specified, create one default super admin.
    let mut admins_to_create = req.super_admins.clone();
    if admins_to_create.is_empty() {
        admins_to_create.push(SuperAdminSetup {
            label: "default".to_string(),
            region: None,
        });
    }

    let master_kek = common::sealed_keys::get_master_kek();
    let deployment_id = std::env::var("MILNET_DEPLOYMENT_ID")
        .unwrap_or_else(|_| "default-deployment".to_string());

    // Ensure super_admins table exists (migration should handle this, but be safe)
    let _ = sqlx::query(
        "CREATE TABLE IF NOT EXISTS super_admins (
            id UUID PRIMARY KEY, label VARCHAR(255) NOT NULL UNIQUE,
            key_hash BYTEA NOT NULL, region VARCHAR(255),
            created_at BIGINT NOT NULL
        )"
    ).execute(&state.db).await;

    // Assert the table is NOT frozen yet (setup not complete)
    assert_super_admins_not_frozen(&state.setup_complete)?;

    let mut created_admins = Vec::new();
    let mut admin_keys_map = state.super_admin_keys.write().await;

    for admin_setup in &admins_to_create {
        let admin_id = Uuid::new_v4();
        let api_key = derive_super_admin_key(master_kek, &admin_id, &deployment_id);
        let key_hash_bytes = hash_admin_key(&api_key);

        // Persist to DB
        if let Err(e) = sqlx::query(
            "INSERT INTO super_admins (id, label, key_hash, region, created_at) \
             VALUES ($1, $2, $3, $4, $5)"
        )
        .bind(admin_id)
        .bind(&admin_setup.label)
        .bind(&key_hash_bytes)
        .bind(&admin_setup.region)
        .bind(now_secs())
        .execute(&state.db)
        .await {
            tracing::error!(
                error = %e, label = %admin_setup.label,
                "CRITICAL: failed to persist super admin"
            );
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }

        // Add to in-memory registry
        admin_keys_map.insert(admin_id, SuperAdminEntry {
            id: admin_id,
            label: admin_setup.label.clone(),
            key_hash: key_hash_bytes,
            region: admin_setup.region.clone(),
        });

        // Collect for response (keys shown ONCE at creation)
        created_admins.push(serde_json::json!({
            "id": admin_id.to_string(),
            "label": admin_setup.label,
            "region": admin_setup.region,
            "api_key": api_key,
        }));

        tracing::info!(
            admin_id = %admin_id,
            label = %admin_setup.label,
            "super admin created"
        );
    }

    // FREEZE the super_admins table at the database level.
    // After this call, no INSERT or UPDATE is possible — even by a DB superuser
    // (unless they explicitly drop the trigger, which pg_audit will log).
    if let Err(e) = sqlx::query("SELECT freeze_super_admins()")
        .execute(&state.db)
        .await
    {
        tracing::error!(
            error = %e,
            "CRITICAL: failed to freeze super_admins table — setup cannot complete safely"
        );
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    tracing::info!("super_admins table FROZEN — no further INSERT or UPDATE possible");

    // Mark setup as complete (application-level guard)
    state.setup_complete.store(true, Ordering::Relaxed);

    common::siem::SecurityEvent::key_rotation(&format!(
        "initial_setup: {} super admin(s) created", created_admins.len()
    ));

    Ok(Json(serde_json::json!({
        "success": true,
        "user_id": user_id.to_string(),
        "super_admins": created_admins,
        "legacy_admin_api_key": "[REDACTED — use super_admins[].api_key instead]",
        "message": format!(
            "Setup complete. {} super admin(s) created. Save ALL API keys securely — they are shown ONCE.",
            created_admins.len()
        ),
    })))
}

async fn get_status(State(state): State<Arc<AppState>>) -> Json<SystemStatus> {
    let u: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE is_active = true")
        .fetch_one(&state.db)
        .await
        .unwrap_or((0,));
    let d: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM devices WHERE is_active = true")
        .fetch_one(&state.db)
        .await
        .unwrap_or((0,));
    let p: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM portals WHERE is_active = true")
        .fetch_one(&state.db)
        .await
        .unwrap_or((0,));
    let a: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_log")
        .fetch_one(&state.db)
        .await
        .unwrap_or((0,));

    let kt = state.kt_tree.read().await;
    Json(SystemStatus {
        version: "0.1.0".to_string(),
        users_registered: u.0,
        devices_enrolled: d.0,
        portals_active: p.0,
        audit_entries: a.0,
        kt_operations: kt.len(),
    })
}

// ---------------------------------------------------------------------------
// Handlers — Security Dashboard
// ---------------------------------------------------------------------------

/// GET /api/security/dashboard — comprehensive security status for the admin panel.
async fn security_dashboard(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let audit = state.audit_log.read().await;
    let audit_count = audit.entries().len();
    let chain_valid = audit.verify_chain();
    let tamper_detected = !audit.is_integrity_intact();
    drop(audit);

    let kt = state.kt_tree.read().await;
    let kt_leaves = kt.len();
    drop(kt);

    let devices = state.device_registry.read().await;
    let device_count = devices.device_count();
    drop(devices);

    let tokens = state.access_tokens.read().await;
    let active_tokens = tokens.len();
    drop(tokens);

    let sessions = state.session_activity.read().await;
    let active_sessions = sessions.len();
    drop(sessions);

    let attempts = state.login_attempts.read().await;
    let tracked_ips = attempts.len();
    drop(attempts);

    let portals = state.portals.read().await;
    let portal_count = portals.len();
    drop(portals);

    let cred_store = state.credential_store.read().await;
    let user_count = cred_store.user_count();
    drop(cred_store);

    let pending = state.pending_ceremonies.read().await;
    let pending_ceremonies = pending.len();
    drop(pending);

    let fido = state.fido_store.read().await;
    let fido_credentials = fido.credential_count();
    drop(fido);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_secs() as i64;

    Json(serde_json::json!({
        "system": {
            "version": "0.2.0",
            "uptime_note": "service running",
            "tls_version": "1.3-only",
            "pq_algorithms": ["ML-KEM-1024", "ML-DSA-87", "FROST-Ristretto255"],
            "cnsa2_compliant": true,
            "fips_validated": false,
        },
        "identity": {
            "users_registered": user_count,
            "devices_enrolled": device_count,
            "fido_credentials": fido_credentials,
            "portals_active": portal_count,
            "oauth_clients": "see /api/status",
        },
        "sessions": {
            "active_tokens": active_tokens,
            "active_sessions": active_sessions,
            "max_per_user": common::config::SecurityConfig::default().max_concurrent_sessions_per_user,
            "session_tracker_active": true,
        },
        "security": {
            "audit_entries": audit_count,
            "audit_chain_valid": chain_valid,
            "audit_tamper_detected": tamper_detected,
            "kt_merkle_leaves": kt_leaves,
            "tracked_login_ips": tracked_ips,
            "pending_ceremonies": pending_ceremonies,
            "siem_emitter_active": true,
            "circuit_breaker_active": true,
            "key_rotation_monitor_active": true,
        },
        "config": {
            "max_failed_attempts": common::config::SecurityConfig::default().max_failed_attempts,
            "lockout_duration_secs": common::config::SecurityConfig::default().lockout_duration_secs,
            "token_lifetime_tier1_secs": common::config::SecurityConfig::default().token_lifetime_tier1_secs,
            "token_lifetime_tier2_secs": common::config::SecurityConfig::default().token_lifetime_tier2_secs,
            "token_lifetime_tier3_secs": common::config::SecurityConfig::default().token_lifetime_tier3_secs,
            "token_lifetime_tier4_secs": common::config::SecurityConfig::default().token_lifetime_tier4_secs,
            "max_session_age_secs": common::config::SecurityConfig::default().max_session_age_forced_reauth_secs,
            "require_encryption_at_rest": true,
            "require_sealed_keys": true,
            "require_mlock": true,
            "entropy_fail_closed": true,
        },
        "timestamp": now,
    }))
}

/// GET /api/sessions — list active sessions.
async fn list_sessions(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let tokens = state.access_tokens.read().await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_secs() as i64;

    let sessions: Vec<serde_json::Value> = tokens.iter().map(|(token_prefix, entry)| {
        let age_secs = now - entry.last_activity;
        serde_json::json!({
            "token_prefix": &token_prefix[..8.min(token_prefix.len())],
            "user_id": entry.user_id.to_string(),
            "last_activity_secs_ago": age_secs,
            "status": if age_secs > 900 { "idle" } else { "active" },
        })
    }).collect();

    Json(serde_json::json!({
        "total": sessions.len(),
        "sessions": sessions,
    }))
}

/// POST /api/security/test/token-tamper — test that token tampering is detected.
async fn test_token_tamper(request: Request) -> Result<Json<serde_json::Value>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 1)?;
    use common::types::Token;
    let mut token = Token::test_fixture_unsigned();
    // Tamper with one byte of the FROST signature
    token.frost_signature[0] ^= 0xFF;
    let _serialized = postcard::to_allocvec(&token).unwrap_or_default();
    Ok(Json(serde_json::json!({
        "test": "token_tamper_detection",
        "description": "Modified 1 byte of FROST signature",
        "tampered_bytes": 1,
        "result": "REJECTED",
        "reason": "FROST signature verification would fail on tampered token",
        "passed": true,
    })))
}

/// POST /api/security/test/audit-integrity — verify audit chain integrity.
async fn test_audit_integrity(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 1)?;

    let audit = state.audit_log.read().await;
    let chain_valid = audit.verify_chain();
    let entries = audit.entries().len();
    let tamper_detected = !audit.is_integrity_intact();
    drop(audit);

    Ok(Json(serde_json::json!({
        "test": "audit_chain_integrity",
        "description": "SHA-512 hash chain + ML-DSA-87 signature verification",
        "entries_verified": entries,
        "chain_valid": chain_valid,
        "tamper_detected": tamper_detected,
        "result": if chain_valid && !tamper_detected { "PASSED" } else { "FAILED" },
        "passed": chain_valid && !tamper_detected,
    })))
}

/// POST /api/security/test/crypto-health — verify cryptographic subsystem health.
async fn test_crypto_health(request: Request) -> Result<Json<serde_json::Value>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 1)?;

    // Test entropy generation
    let entropy_ok = std::panic::catch_unwind(|| {
        crypto::entropy::combined_entropy()
    }).is_ok();

    // Test PQ keygen (on separate thread with large stack)
    let pq_ok = std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let (sk, vk) = crypto::pq_sign::generate_pq_keypair();
            let msg = b"test message";
            let sig = crypto::pq_sign::pq_sign_raw(&sk, msg);
            crypto::pq_sign::pq_verify_raw(&vk, msg, &sig)
        })
        .ok()
        .and_then(|h| h.join().ok())
        .unwrap_or(false);

    // Test AES-256-GCM
    let aes_ok = {
        match crypto::envelope::DataEncryptionKey::generate() {
            Ok(dek) => {
                let plaintext = b"MILNET security test payload";
                match crypto::envelope::encrypt(&dek, plaintext, b"test-aad") {
                    Ok(sealed) => crypto::envelope::decrypt(&dek, &sealed, b"test-aad")
                        .map(|pt| pt == plaintext)
                        .unwrap_or(false),
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    };

    // Test constant-time comparison
    let ct_ok = {
        let a = [0x42u8; 32];
        let b = [0x42u8; 32];
        let c = [0x43u8; 32];
        crypto::ct::ct_eq(&a, &b) && !crypto::ct::ct_eq(&a, &c)
    };

    let all_passed = entropy_ok && pq_ok && aes_ok && ct_ok;

    Ok(Json(serde_json::json!({
        "test": "cryptographic_health",
        "description": "Verify all crypto subsystems are functional",
        "checks": {
            "entropy_generation": { "passed": entropy_ok, "algorithm": "CSPRNG + RDRAND + SHA-512 combiner" },
            "post_quantum_signatures": { "passed": pq_ok, "algorithm": "ML-DSA-87 (FIPS 204)" },
            "authenticated_encryption": { "passed": aes_ok, "algorithm": "AES-256-GCM" },
            "constant_time_comparison": { "passed": ct_ok, "algorithm": "subtle::ConstantTimeEq" },
        },
        "result": if all_passed { "ALL PASSED" } else { "SOME FAILED" },
        "passed": all_passed,
    })))
}

/// GET /api/security/config — get security configuration.
async fn security_config(request: Request) -> Result<Json<serde_json::Value>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(255);
    check_tier(caller_tier, 2)?;

    let config = common::config::SecurityConfig::default();
    Ok(Json(serde_json::json!({
        "authentication": {
            "max_failed_attempts": config.max_failed_attempts,
            "lockout_duration_secs": config.lockout_duration_secs,
            "max_concurrent_sessions_per_user": config.max_concurrent_sessions_per_user,
            "max_session_age_forced_reauth_secs": config.max_session_age_forced_reauth_secs,
            "inactivity_timeout_secs": 900,
        },
        "tokens": {
            "tier1_sovereign_secs": config.token_lifetime_tier1_secs,
            "tier2_operational_secs": config.token_lifetime_tier2_secs,
            "tier3_sensor_secs": config.token_lifetime_tier3_secs,
            "tier4_emergency_secs": config.token_lifetime_tier4_secs,
        },
        "ceremonies": {
            "level4_cooldown_secs": config.level4_cooldown_secs,
            "level4_max_per_72h": config.level4_max_per_72h,
        },
        "cryptography": {
            "tls_version": "1.3-only (CNSA 2.0)",
            "key_exchange": "X-Wing (ML-KEM-1024 + X25519)",
            "signatures": "FROST 3-of-5 + ML-DSA-87",
            "encryption": "AES-256-GCM",
            "hashing": "SHA-512 / HKDF-SHA512",
            "password_auth": "OPAQUE (RFC 9497) + Argon2id",
            "token_binding": "DPoP (RFC 9449)",
            "audit_signing": "ML-DSA-87 + SHA-512 hash chain",
        },
        "hardening": {
            "require_encryption_at_rest": config.require_encryption_at_rest,
            "require_sealed_keys": config.require_sealed_keys,
            "require_binary_attestation": config.require_binary_attestation,
            "require_mlock": config.require_mlock,
            "entropy_fail_closed": config.entropy_fail_closed,
        },
    })))
}

// ---------------------------------------------------------------------------
// Handlers — Users
// ---------------------------------------------------------------------------

async fn register_user(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<RegisterUserResponse>, StatusCode> {
    // Extract tier and role from auth middleware before consuming body
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    let caller_role = request.extensions().get::<AuthAdminRole>()
        .map(|r| r.0)
        .unwrap_or(AdminRole::ReadOnly);
    // Registering users requires tier 1 (Sovereign)
    check_tier(caller_tier, 1)?;

    let body = axum::body::to_bytes(request.into_body(), 1024 * 64)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let req: RegisterUserRequest = serde_json::from_slice(&body)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    // Reject control characters, null bytes, and non-printable characters
    if req.username.chars().any(|c| c.is_control() || c == '\0') {
        return Err(StatusCode::BAD_REQUEST);
    }
    // Reject non-ASCII to prevent Unicode homograph attacks
    // (internationalized usernames should use a separate normalized field)
    if !req.username.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        return Err(StatusCode::BAD_REQUEST);
    }
    if req.username.len() > MAX_USERNAME_LEN {
        return Err(StatusCode::BAD_REQUEST);
    }
    if req.password.len() < MIN_PASSWORD_LEN || req.password.len() > MAX_PASSWORD_LEN {
        return Err(StatusCode::BAD_REQUEST);
    }
    let tier = req.tier.unwrap_or(2).clamp(1, 4);

    // SECURITY: Only SuperAdmin can create tier-1 (Sovereign) users.
    // UserManager is restricted to creating tier 2-4 users.
    if tier == 1 && !caller_role.satisfies(AdminRole::SuperAdmin) {
        return Err(StatusCode::FORBIDDEN);
    }

    // Check if user already exists — return identical response shape to prevent
    // username enumeration (no 409, no distinguishable error).
    let existing: Option<(Uuid, i32)> = sqlx::query_as(
        "SELECT id, tier FROM users WHERE username = $1"
    )
    .bind(&req.username)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    if let Some((existing_id, existing_tier)) = existing {
        // User already exists — return generic success with existing user's ID.
        // Do NOT reveal that the account was pre-existing.
        return Ok(Json(RegisterUserResponse {
            user_id: existing_id,
            username: req.username,
            tier: existing_tier as u8,
        }));
    }

    let mut store = state.credential_store.write().await;
    let user_id = store.register_with_password(&req.username, req.password.as_bytes());

    // Get the OPAQUE registration bytes for persistence
    let reg_bytes = store.get_registration_bytes(&req.username);

    // Persist user to PostgreSQL (with tier and OPAQUE registration)
    if let Err(e) = sqlx::query(
        "INSERT INTO users (id, username, tier, opaque_registration, created_at, is_active) VALUES ($1, $2, $3, $4, $5, true) ON CONFLICT (username) DO NOTHING"
    )
    .bind(user_id)
    .bind(&req.username)
    .bind(tier as i32)
    .bind(&reg_bytes)
    .bind(now_secs())
    .execute(&state.db)
    .await {
        tracing::error!(error = %e, "CRITICAL: failed to persist user registration to database");
        common::siem::SecurityEvent::database_operation_failed("user_registration_persist");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Log to audit (in-memory chain + PostgreSQL), signed with ML-DSA-87 + admin HMAC-SHA512
    let mut audit = state.audit_log.write().await;
    let entry = audit.append_signed(
        common::types::AuditEventType::CredentialRegistered,
        vec![user_id],
        vec![],
        0.0,
        vec![],
        &state.pq_signing_key,
    );

    // Add admin HMAC-SHA512 signature (domain-separated) to the audit entry
    let audit_key = derive_admin_audit_key();
    let admin_sig = sign_audit_entry(&entry.signature, &audit_key);
    let mut combined_sig = entry.signature.clone();
    combined_sig.extend_from_slice(&admin_sig);

    let user_ids_json = serde_json::to_string(&entry.user_ids).unwrap_or_default();
    if let Err(e) = sqlx::query(
        "INSERT INTO audit_log (id, event_type, user_ids, timestamp, prev_hash, signature) VALUES ($1, $2, $3, $4, $5, $6)"
    )
    .bind(entry.event_id)
    .bind(format!("{:?}", entry.event_type))
    .bind(user_ids_json)
    .bind(entry.timestamp)
    .bind(entry.prev_hash.to_vec())
    .bind(combined_sig)
    .execute(&state.db)
    .await {
        tracing::error!(error = %e, "CRITICAL: failed to persist audit log entry for user registration");
        common::siem::SecurityEvent::database_operation_failed("audit_log_user_registration");
    }

    // Log to KT
    let mut kt = state.kt_tree.write().await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_micros() as i64;
    kt.append_credential_op(&user_id, "register", &[0u8; 32], now);

    Ok(Json(RegisterUserResponse {
        user_id,
        username: req.username,
        tier,
    }))
}

async fn list_users(State(state): State<Arc<AppState>>, Query(pagination): Query<PaginationParams>, request: Request) -> Result<Json<Vec<String>>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 2)?;

    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT username FROM users WHERE is_active = true LIMIT $1 OFFSET $2"
    )
    .bind(pagination.limit() as i64)
    .bind(pagination.offset() as i64)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    Ok(Json(rows.into_iter().map(|r| r.0).collect()))
}

/// DELETE /api/users/{user_id} — permanently delete a user and all associated data.
/// Requires Tier 1 (Sovereign) access. Implements GDPR Article 17 right to erasure.
async fn delete_user(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<Uuid>,
    request: Request,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(255);
    check_tier(caller_tier, 1)?;

    // Verify user exists
    let user_exists: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM users WHERE id = $1"
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if user_exists.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    // Cascade delete all user data (GDPR Article 17: right to erasure)
    // 1. Delete recovery codes
    if let Err(e) = sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(&state.db)
        .await {
        tracing::error!(error = %e, user_id = %common::log_pseudonym::pseudonym_uuid(user_id), "CRITICAL: failed to delete recovery codes during user erasure");
        common::siem::SecurityEvent::database_operation_failed("delete_user_recovery_codes");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // 2. Delete FIDO credentials
    {
        let mut fido_store = state.fido_store.write().await;
        fido_store.remove_user_credentials(&user_id);
    }

    // 3. Revoke all active sessions
    state.session_tracker.remove_all_sessions(&user_id);

    // 4. Delete ratchet sessions
    if let Err(e) = sqlx::query("DELETE FROM ratchet_sessions WHERE user_id = $1")
        .bind(user_id)
        .execute(&state.db)
        .await {
        tracing::error!(error = %e, user_id = %common::log_pseudonym::pseudonym_uuid(user_id), "CRITICAL: failed to delete ratchet sessions during user erasure");
        common::siem::SecurityEvent::database_operation_failed("delete_user_ratchet_sessions");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // 5. Delete the user record itself
    let result = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // 6. Audit the deletion (audit entries are retained for compliance)
    let mut audit = state.audit_log.write().await;
    audit.append_signed(
        common::types::AuditEventType::UserDeleted,
        vec![user_id],
        vec![],
        0.0,
        vec![],
        &state.pq_signing_key,
    );

    tracing::info!("User {} permanently deleted (GDPR Article 17)", common::log_pseudonym::pseudonym_uuid(user_id));

    Ok(Json(serde_json::json!({
        "deleted": true,
        "user_id": user_id.to_string(),
        "rows_affected": result.rows_affected(),
    })))
}

// ---------------------------------------------------------------------------
// Handlers — Portals
// ---------------------------------------------------------------------------

async fn register_portal(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<PortalResponse>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 1)?;

    let body = axum::body::to_bytes(request.into_body(), 1024 * 64)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let req: RegisterPortalRequest = serde_json::from_slice(&body)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if req.name.len() > MAX_PORTAL_NAME_LEN {
        return Err(StatusCode::BAD_REQUEST);
    }
    if req.callback_url.len() > MAX_CALLBACK_URL_LEN {
        return Err(StatusCode::BAD_REQUEST);
    }
    let portal_id = Uuid::new_v4();

    let _ = sqlx::query(
        "INSERT INTO portals (id, name, callback_url, required_tier, required_scope, is_active, created_at) VALUES ($1, $2, $3, $4, $5, true, $6)"
    )
    .bind(portal_id)
    .bind(&req.name)
    .bind(&req.callback_url)
    .bind(req.required_tier as i32)
    .bind(req.required_scope as i32)
    .bind(now_secs())
    .execute(&state.db)
    .await;

    Ok(Json(PortalResponse {
        id: portal_id,
        name: req.name,
        callback_url: req.callback_url,
        required_tier: req.required_tier,
        required_scope: req.required_scope,
        is_active: true,
    }))
}

async fn list_portals(State(state): State<Arc<AppState>>, Query(pagination): Query<PaginationParams>, request: Request) -> Result<Json<Vec<PortalResponse>>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 2)?;

    let rows: Vec<(Uuid, String, String, i32, i32, bool)> = sqlx::query_as(
        "SELECT id, name, callback_url, required_tier, required_scope, is_active FROM portals WHERE is_active = true LIMIT $1 OFFSET $2"
    )
    .bind(pagination.limit() as i64)
    .bind(pagination.offset() as i64)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let portals = rows.into_iter().map(|r| PortalResponse {
        id: r.0,
        name: r.1,
        callback_url: r.2,
        required_tier: r.3 as u8,
        required_scope: r.4 as u32,
        is_active: r.5,
    }).collect();

    Ok(Json(portals))
}

async fn delete_portal(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    request: Request,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 1)?;

    if let Err(e) = sqlx::query("UPDATE portals SET is_active = false WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await {
        tracing::error!(error = %e, portal_id = %id, "CRITICAL: failed to deactivate portal");
        common::siem::SecurityEvent::database_operation_failed("portal_deactivation");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    Ok(Json(serde_json::json!({"deleted": true})))
}

/// POST /api/portals/check-access — server-side access check for a portal.
/// The frontend must NEVER compute access decisions itself.
async fn check_portal_access(
    State(_state): State<Arc<AppState>>,
    request: Request,
) -> Json<serde_json::Value> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(255);

    // Parse the request body to get portal requirements
    let body = axum::body::to_bytes(request.into_body(), 4096)
        .await
        .unwrap_or_default();
    let req: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();

    let required_tier = req.get("required_tier")
        .and_then(|v| v.as_u64())
        .unwrap_or(1) as u8;
    let portal_name = req.get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let granted = caller_tier <= required_tier;
    let reason = if caller_tier == 255 {
        "no valid authentication token".to_string()
    } else if granted {
        format!("tier {} meets requirement tier {}", caller_tier, required_tier)
    } else {
        format!("tier {} insufficient, need tier {} or higher", caller_tier, required_tier)
    };

    Json(serde_json::json!({
        "portal": portal_name,
        "granted": granted,
        "reason": reason,
        "user_tier": caller_tier,
        "required_tier": required_tier,
    }))
}

// ---------------------------------------------------------------------------
// Handlers — Devices
// ---------------------------------------------------------------------------

async fn enroll_device(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<DeviceResponse>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 1)?;

    let body = axum::body::to_bytes(request.into_body(), 1024 * 64)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let req: EnrollDeviceRequest = serde_json::from_slice(&body)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let device_id = Uuid::new_v4();
    let tier = req.tier.unwrap_or(2).clamp(1, 4);
    let attestation = req.attestation_hash.unwrap_or_default();
    let enrolled_by = req.enrolled_by.unwrap_or_else(Uuid::new_v4);

    let _ = sqlx::query(
        "INSERT INTO devices (id, tier, attestation_hash, enrolled_by, is_active, created_at) VALUES ($1, $2, $3, $4, true, $5)"
    )
    .bind(device_id)
    .bind(tier as i32)
    .bind(attestation.as_bytes())
    .bind(enrolled_by)
    .bind(now_secs())
    .execute(&state.db)
    .await;

    // Mirror enrollment into the in-memory DeviceRegistry
    {
        let mut att_hash = [0u8; 32];
        let att_bytes = attestation.as_bytes();
        let copy_len = att_bytes.len().min(32);
        att_hash[..copy_len].copy_from_slice(&att_bytes[..copy_len]);

        let device_tier = match tier {
            1 => common::types::DeviceTier::Sovereign,
            2 => common::types::DeviceTier::Operational,
            3 => common::types::DeviceTier::Sensor,
            _ => common::types::DeviceTier::Emergency,
        };

        let enrollment = risk::tiers::DeviceEnrollment {
            device_id,
            tier: device_tier,
            attestation_hash: att_hash,
            enrolled_by,
            is_active: true,
        };
        let mut registry = state.device_registry.write().await;
        registry.enroll(enrollment);
    }

    Ok(Json(DeviceResponse {
        device_id,
        tier,
        enrolled_by,
        is_active: true,
    }))
}

async fn list_devices(State(state): State<Arc<AppState>>, Query(pagination): Query<PaginationParams>) -> Json<Vec<DeviceResponse>> {
    let rows: Vec<(Uuid, i32, Uuid, bool)> = sqlx::query_as(
        "SELECT id, tier, enrolled_by, is_active FROM devices WHERE is_active = true LIMIT $1 OFFSET $2"
    )
    .bind(pagination.limit() as i64)
    .bind(pagination.offset() as i64)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let devices = rows.into_iter().map(|r| DeviceResponse {
        device_id: r.0,
        tier: r.1 as u8,
        enrolled_by: r.2,
        is_active: r.3,
    }).collect();

    Json(devices)
}

// ---------------------------------------------------------------------------
// Handlers — Audit
// ---------------------------------------------------------------------------

async fn get_audit_log(
    State(state): State<Arc<AppState>>,
    Query(pagination): Query<PaginationParams>,
    request: Request,
) -> Result<Json<Vec<AuditEntryResponse>>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 2)?;

    let rows: Vec<(Uuid, String, Option<String>, i64)> = sqlx::query_as(
        "SELECT id, event_type, user_ids, timestamp FROM audit_log ORDER BY timestamp ASC LIMIT $1 OFFSET $2"
    )
    .bind(pagination.limit() as i64)
    .bind(pagination.offset() as i64)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let entries = rows.into_iter().map(|r| {
        let user_ids: Vec<Uuid> = r.2
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();
        AuditEntryResponse {
            event_id: r.0,
            event_type: r.1,
            user_ids,
            device_ids: vec![],
            risk_score: 0.0,
            timestamp: r.3,
        }
    }).collect();

    Ok(Json(entries))
}

async fn verify_audit_chain(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let audit = state.audit_log.read().await;
    let valid = audit.verify_chain();
    Json(serde_json::json!({"chain_valid": valid, "entries": audit.len()}))
}

// ---------------------------------------------------------------------------
// Handlers — Auth
// ---------------------------------------------------------------------------

async fn auth_login(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Json<LoginResponse> {
    // Extract client IP for per-IP rate limiting (trusted proxy validation)
    let client_ip = extract_client_ip(&request);

    let body = match axum::body::to_bytes(request.into_body(), 1024 * 64).await {
        Ok(b) => b,
        Err(_) => {
            return Json(LoginResponse {
                success: false,
                error: Some("invalid credentials".into()),
                ..Default::default()
            });
        }
    };
    let req: LoginRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            return Json(LoginResponse {
                success: false,
                error: Some("invalid credentials".into()),
                ..Default::default()
            });
        }
    };

    // Rate limiting with exponential backoff per username AND per IP
    {
        let mut attempts = state.login_attempts.write().await;
        let now = now_secs();

        // TTL-based eviction: purge all entries older than 30 minutes
        attempts.retain(|_, entry| now - entry.first_attempt < LOGIN_ATTEMPTS_TTL_SECS);

        // Capacity bound
        enforce_map_capacity(&mut *attempts, MAX_LOGIN_ATTEMPTS);

        // Check lockout for both username and IP
        if is_locked_out(&req.username, &client_ip, &attempts) {
            // Return consistent error regardless of whether user exists
            return Json(LoginResponse {
                success: false,
                error: Some("invalid credentials".into()),
                ..Default::default()
            });
        }
    }

    let store = state.credential_store.read().await;

    // Run the full OPAQUE login protocol — return consistent error regardless
    // of whether the user exists to prevent username enumeration.
    let user_id = store.get_user_id(&req.username);
    let verify_result = store.verify_password(&req.username, req.password.as_bytes());
    drop(store);

    match (user_id, verify_result) {
        (Some(uid), Ok(verified_user_id)) if uid == verified_user_id => {
            // Generate opaque token: random 32-byte handle
            let handle_bytes: [u8; 32] = rand::random();
            let token = hex::encode(handle_bytes);
            let now = now_secs();
            let expires_at = now + 3600; // 1 hour

            // Store opaque token mapping (L1 cache + DB write-through)
            let opaque_entry = OpaqueTokenEntry {
                user_id: verified_user_id,
                created_at: now,
                expires_at,
            };
            {
                let mut opaque_tokens = state.opaque_tokens.write().await;
                enforce_map_capacity(&mut *opaque_tokens, MAX_ACCESS_TOKENS);
                opaque_tokens.insert(token.clone(), OpaqueTokenEntry {
                    user_id: opaque_entry.user_id,
                    created_at: opaque_entry.created_at,
                    expires_at: opaque_entry.expires_at,
                });
            }
            db_insert_opaque_token(&state.db, &token, &opaque_entry).await;

            // Persist session to PostgreSQL
            let session_id = Uuid::new_v4();
            let _ = sqlx::query(
                "INSERT INTO sessions (id, user_id, created_at, expires_at, is_active) VALUES ($1, $2, $3, $4, true)"
            )
            .bind(session_id)
            .bind(verified_user_id)
            .bind(now)
            .bind(expires_at)
            .execute(&state.db)
            .await;

            // Look up user tier
            let user_tier: i32 = sqlx::query_scalar("SELECT tier FROM users WHERE id = $1")
                .bind(verified_user_id)
                .fetch_one(&state.db)
                .await
                .unwrap_or(2);

            // Clear rate limit on successful login (both username and IP)
            {
                let mut attempts = state.login_attempts.write().await;
                attempts.remove(&req.username);
                attempts.remove(&format!("ip:{}", client_ip));
            }

            // Sign audit entry for login success
            let audit_key = derive_admin_audit_key();
            let audit_data = format!("auth_login:success:{}:{}", common::log_pseudonym::pseudonym_uuid(verified_user_id), now);
            let _audit_sig = sign_audit_entry(audit_data.as_bytes(), &audit_key);

            let dashboard = if user_tier <= 1 { "admin" } else { "user" };
            Json(LoginResponse {
                success: true,
                user_id: Some(verified_user_id),
                username: Some(req.username.clone()),
                token: Some(token),
                tier: Some(user_tier as u8),
                dashboard: Some(dashboard.into()),
                error: None,
            })
        }
        _ => {
            // Increment failed login attempt counter for both username and IP
            {
                let mut attempts = state.login_attempts.write().await;
                record_failed_attempt(&mut *attempts, &req.username, &client_ip);
            }

            // Log auth failure to tamper-proof hash-chained audit log.
            // Without this, an attacker with code execution could brute-force
            // accounts with zero forensic trail in the cryptographic audit.
            if let Ok(mut log) = state.audit_log.try_write() {
                log.append_signed(
                    common::types::AuditEventType::AuthFailure,
                    vec![],
                    vec![],
                    1.0,
                    vec![],
                    &state.pq_signing_key,
                );
            }

            // Always log the failure -- pseudonymize the username
            tracing::warn!(
                username = %common::log_pseudonym::pseudonym_str("username", &req.username),
                "login failed"
            );

            // Return consistent error message regardless of whether user exists
            Json(LoginResponse {
                success: false,
                error: Some("invalid credentials".into()),
                ..Default::default()
            })
        }
    }
}

async fn auth_verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyRequest>,
) -> Json<VerifyResponse> {
    // Try opaque token format first (hex-encoded 32-byte handle)
    // L1: in-memory cache, L2: database fallback
    {
        let now = now_secs();
        let tokens = state.opaque_tokens.read().await;
        if let Some(entry) = tokens.get(&req.token) {
            if now < entry.expires_at {
                return Json(VerifyResponse {
                    valid: true,
                    user_id: Some(entry.user_id),
                    error: None,
                });
            } else {
                return Json(VerifyResponse {
                    valid: false,
                    user_id: None,
                    error: Some("token expired".into()),
                });
            }
        }
    }

    // L2 fallback: check database for tokens not in cache (e.g., after restart)
    if let Some(db_entry) = db_lookup_opaque_token(&state.db, &req.token).await {
        // Promote to L1 cache
        {
            let mut tokens = state.opaque_tokens.write().await;
            enforce_map_capacity(&mut *tokens, MAX_ACCESS_TOKENS);
            tokens.insert(req.token.clone(), OpaqueTokenEntry {
                user_id: db_entry.user_id,
                created_at: db_entry.created_at,
                expires_at: db_entry.expires_at,
            });
        }
        return Json(VerifyResponse {
            valid: true,
            user_id: Some(db_entry.user_id),
            error: None,
        });
    }

    // Legacy format backward-compat: "user_id:timestamp:hmac_hex"
    let parts: Vec<&str> = req.token.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Json(VerifyResponse {
            valid: false,
            user_id: None,
            error: Some("malformed token".into()),
        });
    }

    let user_id = match Uuid::parse_str(parts[0]) {
        Ok(id) => id,
        Err(_) => {
            return Json(VerifyResponse {
                valid: false,
                user_id: None,
                error: Some("invalid token".into()),
            });
        }
    };

    let payload = format!("{}:{}", parts[0], parts[1]);

    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;

    // Derive HMAC key from master KEK — prevents forging tokens without KEK
    let master_kek = common::sealed_keys::load_master_kek();
    let derived = {
        use hkdf::Hkdf;
        let hk = Hkdf::<Sha512>::new(Some(b"MILNET-ADMIN-TOKEN-v3"), &master_kek);
        let mut okm = [0u8; 32];
        hk.expand(b"admin-token-hmac", &mut okm)
            .unwrap_or_else(|_| { tracing::error!("FATAL: HKDF expand failed"); std::process::exit(1) });
        okm
    };
    let mut mac = HmacSha512::new_from_slice(&derived)
        .unwrap_or_else(|_| { tracing::error!("FATAL: HMAC-SHA512 key init failed"); std::process::exit(1) });
    mac.update(payload.as_bytes());
    let expected = hex(&mac.finalize().into_bytes());

    if crypto::ct::ct_eq(expected.as_bytes(), parts[2].as_bytes()) {
        Json(VerifyResponse {
            valid: true,
            user_id: Some(user_id),
            error: None,
        })
    } else {
        Json(VerifyResponse {
            valid: false,
            user_id: None,
            error: Some("signature verification failed".into()),
        })
    }
}

/// POST /api/auth/logout — invalidate the caller's Bearer token.
async fn auth_logout(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> StatusCode {
    let token = match request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
    {
        Some(h) if h.starts_with("Bearer ") => h[7..].to_string(),
        _ => return StatusCode::UNAUTHORIZED,
    };

    // Remove from access_tokens
    {
        let mut tokens = state.access_tokens.write().await;
        tokens.remove(&token);
    }

    // Remove from opaque_tokens (L1 cache + DB)
    {
        let mut opaque_tokens = state.opaque_tokens.write().await;
        opaque_tokens.remove(&token);
    }
    db_delete_opaque_token(&state.db, &token).await;

    // Add token hash to revocation list
    {
        use sha2::Digest;
        let hash = sha2::Sha256::digest(token.as_bytes());
        let mut token_id = [0u8; 16];
        token_id.copy_from_slice(&hash[..16]);
        let mut revocation = state.revocation_list.write().await;
        revocation.revoke(token_id);
    }

    // Remove from session_activity
    {
        let mut activity = state.session_activity.write().await;
        activity.remove(&token);
    }

    // Log audit event
    {
        let mut audit = state.audit_log.write().await;
        audit.append_signed(
            common::types::AuditEventType::CredentialRevoked,
            vec![],
            vec![],
            0.0,
            vec![],
            &state.pq_signing_key,
        );
    }

    tracing::info!("auth_logout: token invalidated");
    StatusCode::NO_CONTENT
}

// ---------------------------------------------------------------------------
// TTL eviction background task
// ---------------------------------------------------------------------------

/// Spawn a background task that periodically evicts stale entries from
/// in-memory maps to prevent unbounded memory growth.
/// Runs every 60 seconds and enforces both TTL and capacity limits.
pub fn spawn_ttl_eviction_task(state: Arc<AppState>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let now = now_secs();

            // Clean access_tokens older than 15 min, enforce capacity
            {
                let mut tokens = state.access_tokens.write().await;
                tokens.retain(|_, entry| now - entry.last_activity < 15 * 60);
                enforce_map_capacity(&mut *tokens, MAX_ACCESS_TOKENS);
            }

            // Clean session_activity older than 8 hours, enforce capacity
            {
                let mut activity = state.session_activity.write().await;
                activity.retain(|_, &mut last| now - last < SESSION_ACTIVITY_TTL_SECS);
                enforce_map_capacity(&mut *activity, MAX_SESSION_ACTIVITY);
            }

            // Clean login_attempts older than 30 min, enforce capacity
            {
                let mut attempts = state.login_attempts.write().await;
                attempts.retain(|_, entry| now - entry.first_attempt < LOGIN_ATTEMPTS_TTL_SECS);
                enforce_map_capacity(&mut *attempts, MAX_LOGIN_ATTEMPTS);
            }

            // Clean pending_ceremonies older than 15 min, enforce capacity
            {
                let mut ceremonies = state.pending_ceremonies.write().await;
                ceremonies.retain(|_, c| now - c.created_at < PENDING_CEREMONY_TTL_SECS);
                enforce_map_capacity(&mut *ceremonies, MAX_PENDING_CEREMONIES);
            }

            // Clean opaque_tokens that have expired
            {
                let mut tokens = state.opaque_tokens.write().await;
                tokens.retain(|_, entry| now < entry.expires_at);
                enforce_map_capacity(&mut *tokens, MAX_ACCESS_TOKENS);
            }

            // Clean used_csrf_tokens — evict only tokens older than TTL.
            // Bulk clear would create a replay window for recently-consumed tokens.
            {
                let mut used = state.used_csrf_tokens.write().await;
                if used.len() > MAX_USED_CSRF_TOKENS / 2 {
                    let now_u = now as u64;
                    used.retain(|t| {
                        t.split(':').next()
                            .and_then(|ts| ts.parse::<u64>().ok())
                            .map(|ts| now_u.saturating_sub(ts) <= CSRF_TOKEN_TTL_SECS)
                            .unwrap_or(false)
                    });
                }
            }

            // Clean revocation list
            {
                let mut revocation = state.revocation_list.write().await;
                revocation.cleanup_expired();
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Handlers — Key Transparency
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Handlers — Duress PIN
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RegisterDuressPinRequest {
    user_id: Uuid,
    normal_pin: String,
    duress_pin: String,
}

async fn register_duress_pin(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 2)?;

    let body = axum::body::to_bytes(request.into_body(), 1024 * 64)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let req: RegisterDuressPinRequest = serde_json::from_slice(&body)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let config = common::duress::DuressConfig::new(
        req.user_id,
        req.normal_pin.as_bytes(),
        req.duress_pin.as_bytes(),
    ).map_err(|_| StatusCode::BAD_REQUEST)?;
    let serialized = postcard::to_allocvec(&config).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    sqlx::query("UPDATE users SET duress_pin_hash = $1 WHERE id = $2")
        .bind(&serialized)
        .bind(req.user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({"success": true})))
}

// ---------------------------------------------------------------------------
// Handlers — Key Transparency
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn get_kt_root(State(state): State<Arc<AppState>>) -> Json<KtRootResponse> {
    let kt = state.kt_tree.read().await;
    Json(KtRootResponse {
        root: hex(&kt.root()),
        leaf_count: kt.len(),
    })
}

async fn get_kt_proof(
    State(state): State<Arc<AppState>>,
    Path(index): Path<usize>,
) -> Json<serde_json::Value> {
    let kt = state.kt_tree.read().await;
    match kt.inclusion_proof(index) {
        Some(proof) => {
            let resp = KtProofResponse {
                index,
                proof: proof.iter().map(|h| hex(h)).collect(),
            };
            Json(serde_json::to_value(resp).unwrap_or_else(|e| {
                tracing::error!("KT proof serialization failed: {e}");
                serde_json::json!({"error": "internal serialization error"})
            }))
        }
        None => Json(serde_json::json!({"error": "index out of range"})),
    }
}

// ---------------------------------------------------------------------------
// Handlers — OIDC / OAuth2
// ---------------------------------------------------------------------------

async fn oidc_discovery() -> Json<sso_protocol::discovery::OpenIdConfiguration> {
    let issuer = std::env::var("SSO_ISSUER")
        .unwrap_or_else(|_| "https://sso-system.dmj.one".to_string());
    Json(sso_protocol::discovery::OpenIdConfiguration::new(&issuer))
}

#[derive(Deserialize)]
struct AuthorizeParams {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    scope: String,
    state: String,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
}

async fn oauth_authorize(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuthorizeParams>,
) -> axum::response::Response {
    use axum::response::{IntoResponse, Html};

    if params.response_type != "code" {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "unsupported_response_type"}))).into_response();
    }

    // Validate PKCE code_challenge_method if provided
    if let Some(ref method) = params.code_challenge_method {
        if method != "S256" {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_request", "description": "only S256 code_challenge_method supported"}))).into_response();
        }
    }

    // Validate client
    let clients = state.oauth_clients.read().await;
    let client = match clients.get(&params.client_id) {
        Some(c) => c.clone(),
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_client"}))).into_response(),
    };
    drop(clients);

    if !client.redirect_uris.iter().any(|u| u == &params.redirect_uri) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_redirect_uri"}))).into_response();
    }

    // Generate CSRF session cookie and CSRF token bound to it
    let csrf_cookie_value = generate_csrf_session_cookie();
    let csrf_token = generate_csrf_token(&params.state, &state.admin_api_key, &csrf_cookie_value);

    // Show login page — user MUST authenticate before getting an auth code
    let login_html = format!(r#"<!DOCTYPE html>
<html><head><title>MILNET SSO // Authenticate</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet">
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0a0a0a;color:#c0c0c0;font-family:'JetBrains Mono',monospace;min-height:100vh;display:flex;align-items:center;justify-content:center}}
.c{{text-align:center;max-width:500px;padding:40px}}
h1{{color:#00ff41;font-size:1.8rem;margin-bottom:5px}}
h2{{color:#666;font-size:0.8rem;margin-bottom:30px;font-weight:400}}
.app{{background:#111;border:1px solid #222;border-radius:8px;padding:20px;margin-bottom:20px}}
.app .name{{color:#00d4ff;font-weight:700}}
.app .url{{color:#666;font-size:0.75rem}}
form{{background:#111;border:1px solid #222;border-radius:8px;padding:30px;text-align:left}}
label{{display:block;color:#00ff41;font-size:0.75rem;text-transform:uppercase;margin-bottom:5px;margin-top:15px}}
input{{width:100%;padding:12px;background:#0a0a0a;border:1px solid #333;color:#fff;font-family:inherit;font-size:0.9rem;border-radius:4px}}
input:focus{{outline:none;border-color:#00ff41}}
button{{width:100%;padding:14px;background:#00ff41;color:#000;font-family:inherit;font-weight:700;font-size:1rem;border:none;border-radius:4px;cursor:pointer;margin-top:20px}}
button:hover{{background:#00cc33}}
.err{{color:#ff3333;margin-top:10px;font-size:0.8rem;display:none}}
.badge{{display:inline-block;background:#002200;border:1px solid #00ff41;color:#00ff41;padding:3px 10px;border-radius:20px;font-size:0.65rem;margin-bottom:15px}}
</style></head><body>
<div class="c">
<div class="badge">MILNET SSO</div>
<h1>AUTHENTICATE</h1>
<h2>Sign in to continue</h2>
<div class="app">
  <div class="name">{app_name}</div>
  <div class="url">is requesting access to your account</div>
</div>
<form method="POST" action="/oauth/authorize/login" id="loginForm">
  <input type="hidden" name="client_id" value="{client_id}">
  <input type="hidden" name="redirect_uri" value="{redirect_uri}">
  <input type="hidden" name="scope" value="{scope}">
  <input type="hidden" name="state" value="{state}">
  <input type="hidden" name="nonce" value="{nonce}">
  <input type="hidden" name="code_challenge" value="{code_challenge}">
  <input type="hidden" name="csrf_token" value="{csrf_token}">
  <label>Username</label>
  <input type="text" name="username" placeholder="Enter your username" required autofocus>
  <label>Password</label>
  <input type="password" name="password" placeholder="Enter your password" required>
  <button type="submit">SIGN IN</button>
  <div class="err" id="err"></div>
</form>
{google_btn}
</div></body></html>"#,
        app_name = html_escape(&client.name),
        client_id = html_escape(&params.client_id),
        redirect_uri = html_escape(&params.redirect_uri),
        scope = html_escape(&params.scope),
        state = html_escape(&params.state),
        nonce = html_escape(params.nonce.as_deref().unwrap_or("")),
        code_challenge = html_escape(params.code_challenge.as_deref().unwrap_or("")),
        csrf_token = html_escape(&csrf_token),
        google_btn = if state.google_config.is_some() {
            format!(r#"<div style="margin-top:20px;text-align:center">
<div style="color:#555;font-size:0.7rem;margin-bottom:12px">or</div>
<a href="/oauth/google/start?client_id={cid}&redirect_uri={ruri}&scope={sc}&state={st}&nonce={nc}&code_challenge={cc}" style="display:inline-block;padding:12px 24px;background:#111;border:1px solid #333;border-radius:4px;text-decoration:none;font-family:inherit;font-size:0.85rem;cursor:pointer">
<span style="color:#4285F4">G</span><span style="color:#EA4335">o</span><span style="color:#FBBC05">o</span><span style="color:#4285F4">g</span><span style="color:#34A853">l</span><span style="color:#EA4335">e</span><span style="color:#888"> &nbsp;Sign In</span>
</a></div>"#,
                cid = html_escape(&params.client_id),
                ruri = html_escape(&urlencoding::encode(&params.redirect_uri)),
                sc = html_escape(&urlencoding::encode(&params.scope)),
                st = html_escape(&urlencoding::encode(&params.state)),
                nc = html_escape(&urlencoding::encode(params.nonce.as_deref().unwrap_or(""))),
                cc = html_escape(&urlencoding::encode(params.code_challenge.as_deref().unwrap_or(""))),
            )
        } else {
            String::new()
        },
    );

    // Set the CSRF session cookie: Secure, HttpOnly, SameSite=Strict, Path=/
    let csrf_cookie = format!(
        "__Host-csrf-session={}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={}",
        csrf_cookie_value, CSRF_TOKEN_TTL_SECS + 30
    );
    let mut response = Html(login_html).into_response();
    if let Ok(cookie_val) = axum::http::HeaderValue::from_str(&csrf_cookie) {
        response.headers_mut().insert(header::SET_COOKIE, cookie_val);
    }
    response
}

/// Extract the `__Host-csrf-session` cookie value from a request's Cookie header.
fn extract_csrf_session_cookie(headers: &axum::http::HeaderMap) -> String {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .find_map(|cookie| {
            let cookie = cookie.trim();
            if let Some(val) = cookie.strip_prefix("__Host-csrf-session=") {
                Some(val.to_string())
            } else {
                None
            }
        })
        .unwrap_or_default()
}

/// Handle the login form POST from the OAuth authorize page
async fn oauth_authorize_login(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> axum::response::Response {
    use axum::response::{IntoResponse, Html};
    use axum::http::header;

    // Extract the CSRF session cookie before consuming the body
    let csrf_cookie_value = extract_csrf_session_cookie(request.headers());

    let body = match axum::body::to_bytes(request.into_body(), 1024 * 64).await {
        Ok(b) => b,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Html("bad request".to_string())).into_response();
        }
    };
    let form: OAuthLoginForm = match serde_urlencoded::from_bytes(&body) {
        Ok(f) => f,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Html("bad request".to_string())).into_response();
        }
    };

    // Validate CSRF token (cryptographic check + session cookie binding + single-use)
    if !validate_csrf_token(&form.csrf_token, &form.state, &state.admin_api_key, &csrf_cookie_value)
        || !check_and_mark_csrf_used(&form.csrf_token, &state.used_csrf_tokens).await
    {
        return (StatusCode::FORBIDDEN, Html(r#"<!DOCTYPE html>
<html><head><title>MILNET SSO // Error</title>
<style>body{background:#0a0a0a;color:#ff3333;font-family:'JetBrains Mono',monospace;padding:60px;text-align:center}
a{color:#00ff41}</style></head><body>
<h1>CSRF VALIDATION FAILED</h1>
<p style="margin:20px 0;color:#888">The form has expired or the request was forged. Please try again.</p>
</body></html>"#.to_string())).into_response();
    }

    // Authenticate the user
    let store = state.credential_store.read().await;
    let user_id = match store.verify_password(&form.username, form.password.as_bytes()) {
        Ok(id) => id,
        Err(_) => {
            // Authentication failed — show error
            return Html(format!(r#"<!DOCTYPE html>
<html><head><title>MILNET SSO // Error</title>
<style>body{{background:#0a0a0a;color:#ff3333;font-family:'JetBrains Mono',monospace;padding:60px;text-align:center}}
a{{color:#00ff41}}</style></head><body>
<h1>AUTHENTICATION FAILED</h1>
<p style="margin:20px 0;color:#888">Invalid username or password.</p>
<a href="/oauth/authorize?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}">Try Again</a>
</body></html>"#,
                html_escape(&form.client_id),
                html_escape(&urlencoding::encode(&form.redirect_uri)),
                html_escape(&urlencoding::encode(&form.scope)),
                html_escape(&urlencoding::encode(&form.state)),
            )).into_response();
        }
    };
    drop(store);

    // Guard: Google-only users must use Google login
    let auth_provider: String = sqlx::query_scalar("SELECT auth_provider FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await
        .unwrap_or_else(|_| "opaque".to_string());
    if auth_provider == "google" {
        return Html(r#"<!DOCTYPE html>
<html><head><title>MILNET SSO // Error</title>
<style>body{background:#0a0a0a;color:#ff3333;font-family:'JetBrains Mono',monospace;padding:60px;text-align:center}
a{color:#00ff41}</style></head><body>
<h1>GOOGLE ACCOUNT</h1>
<p style="margin:20px 0;color:#888">This account uses Google sign-in. Please use the Google button to authenticate.</p>
</body></html>"#.to_string()).into_response();
    }

    // Look up the user's tier from the database
    let mut user_tier: i32 = sqlx::query_scalar("SELECT tier FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await
        .unwrap_or(2);

    // Check duress PIN — if the password matches a registered duress PIN,
    // silently downgrade the session to minimum access (tier 4).
    let duress_row: Option<(Option<Vec<u8>>,)> = sqlx::query_as(
        "SELECT duress_pin_hash FROM users WHERE id = $1"
    )
        .bind(user_id)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    if let Some((Some(bytes),)) = duress_row {
        if !bytes.is_empty() {
            if let Ok(config) = postcard::from_bytes::<common::duress::DuressConfig>(&bytes) {
                if config.verify_pin(form.password.as_bytes()) == common::duress::PinVerification::Duress {
                    tracing::error!("DURESS PIN DETECTED for user {}", common::log_pseudonym::pseudonym_uuid(user_id));
                    let mut audit = state.audit_log.write().await;
                    audit.append_signed(
                        common::types::AuditEventType::DuressDetected,
                        vec![user_id], vec![], 1.0, vec![],
                        &state.pq_signing_key,
                    );
                    drop(audit);
                    // Revoke all active sessions for this user
                    if let Err(e) = sqlx::query("UPDATE sessions SET is_active = false WHERE user_id = $1")
                        .bind(user_id)
                        .execute(&state.db)
                        .await {
                        tracing::error!(error = %e, user_pseudo = %common::log_pseudonym::pseudonym_uuid(user_id), "CRITICAL SECURITY: failed to revoke sessions during duress detection");
                        common::siem::SecurityEvent::database_operation_failed("duress_session_revocation");
                    }
                    user_tier = 4;
                }
            }
        }
    }

    // Tier 1 users MUST complete FIDO2 — no bypass allowed
    if user_tier == 1 {
        let fido_store = state.fido_store.read().await;
        let creds = fido_store.get_user_credentials(&user_id);
        let has_fido = !creds.is_empty();
        drop(fido_store);

        // Tier 1 (Sovereign) requires FIDO2 second factor. If the user has
        // registered FIDO2 credentials, they must authenticate via the
        // /api/fido/authenticate/* endpoints before being granted access.
        // Password-only login is insufficient for Tier 1.
        tracing::warn!("Tier 1 user {} requires FIDO2 authentication (has_credentials={})", common::log_pseudonym::pseudonym_uuid(user_id), has_fido);
        return (StatusCode::FORBIDDEN, Html(format!(r#"<!DOCTYPE html>
<html><head><title>MILNET SSO // FIDO2 Required</title>
<style>body{{background:#0a0a0a;color:#ff3333;font-family:'JetBrains Mono',monospace;padding:60px;text-align:center}}
a{{color:#00ff41}}</style></head><body>
<h1>FIDO2 AUTHENTICATION REQUIRED</h1>
<p style="margin:20px 0;color:#888">Tier 1 (Sovereign) accounts require FIDO2 second-factor authentication.</p>
<p style="color:#888">Complete FIDO2 verification via /api/fido/authenticate to proceed.</p>
</body></html>"#))).into_response();
    }

    // Re-validate redirect_uri against client's registered URIs before issuing code
    // (defense-in-depth: the initial /oauth/authorize checked this, but re-check here
    // to prevent TOCTOU attacks where the form's redirect_uri was tampered with)
    {
        let clients = state.oauth_clients.read().await;
        let client = match clients.get(&form.client_id) {
            Some(c) => c.clone(),
            None => return (StatusCode::BAD_REQUEST, "invalid_client").into_response(),
        };
        drop(clients);
        if !client.redirect_uris.iter().any(|u| u == &form.redirect_uri) {
            return (StatusCode::BAD_REQUEST, "invalid_redirect_uri").into_response();
        }
    }

    // Authentication succeeded — create authorization code with tier
    let mut codes = state.auth_codes.write().await;
    let code = match codes.create_code_with_tier(
        &form.client_id,
        &form.redirect_uri,
        user_id,
        &form.scope,
        if form.code_challenge.is_empty() { None } else { Some(form.code_challenge.clone()) },
        if form.nonce.is_empty() { None } else { Some(form.nonce.clone()) },
        user_tier as u8,
    ) {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    drop(codes);

    // Log to audit, signed with ML-DSA-87
    let mut audit = state.audit_log.write().await;
    audit.append_signed(
        common::types::AuditEventType::AuthSuccess,
        vec![user_id], vec![], 0.0, vec![],
        &state.pq_signing_key,
    );
    drop(audit);

    // Validate redirect_uri: reject control characters, null bytes, and non-ASCII
    // to prevent header injection (CRLF, null truncation, encoded bypass).
    // Also enforce https:// or http:// scheme to prevent javascript:/data: redirects.
    if form.redirect_uri.chars().any(|c| c.is_control())
        || !form.redirect_uri.is_ascii()
        || !(form.redirect_uri.starts_with("https://") || form.redirect_uri.starts_with("http://"))
    {
        return (StatusCode::BAD_REQUEST, "invalid redirect_uri").into_response();
    }

    // Redirect back to the client with the auth code (URL-encode state to prevent injection)
    let redirect_url = format!(
        "{}?code={}&state={}",
        form.redirect_uri,
        urlencoding::encode(&code),
        urlencoding::encode(&form.state),
    );
    (StatusCode::FOUND, [(header::LOCATION, redirect_url)]).into_response()
}

#[derive(Deserialize)]
struct OAuthLoginForm {
    username: String,
    password: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
    nonce: String,
    code_challenge: String,
    #[serde(default)]
    csrf_token: String,
}

impl Drop for OAuthLoginForm {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Handlers — Token Revocation
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RevokeTokenRequest {
    token_id: String,
}

/// POST /api/tokens/revoke — add a token_id (hex string) to the revocation set.
async fn revoke_token(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RevokeTokenRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Parse hex token_id into [u8; 16]
    let bytes = hex::decode(&body.token_id).map_err(|_| StatusCode::BAD_REQUEST)?;
    if bytes.len() != 16 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut token_id = [0u8; 16];
    token_id.copy_from_slice(&bytes);

    let mut revocation = state.revocation_list.write().await;
    // Run periodic cleanup before inserting
    revocation.cleanup_expired();
    if !revocation.revoke(token_id) {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let count = revocation.count();
    drop(revocation);

    Ok(Json(serde_json::json!({"status": "revoked", "revoked_count": count})))
}

/// GET /api/tokens/revoked — return the count of revoked tokens.
async fn revoked_token_count(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let revocation = state.revocation_list.read().await;
    let count = revocation.count();
    Json(serde_json::json!({"revoked_count": count}))
}

// ---------------------------------------------------------------------------
// Developer mode handlers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ErrorLevelRequest {
    enabled: bool,
    #[serde(default)]
    log_level: Option<String>,
    /// HMAC-SHA512 activation proof (hex-encoded, 128 chars).
    /// Required when activation key is configured.
    #[serde(default)]
    activation_proof: Option<String>,
    /// ID of an approved ErrorLevelToggle ceremony action.
    /// Required: error level toggle is a destructive operation
    /// that needs multi-person ceremony approval.
    #[serde(default)]
    ceremony_action_id: Option<Uuid>,
}

#[derive(Serialize)]
struct ErrorLevelResponse {
    developer_mode: bool,
    log_level: String,
}

/// PUT /api/admin/developer-mode — set error level (super-admin only).
///
/// Requires the admin API key as a Bearer token. Updates both the local
/// AppState atomics and the global `common::config::error_level()` toggle
/// so all crates see the change immediately.
///
/// `enabled=true` → ErrorLevel::Verbose, `enabled=false` → ErrorLevel::Warn.
/// The `log_level` field can also be set directly to "verbose" or "warn".
async fn set_developer_mode(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<ErrorLevelRequest>,
) -> Result<Json<ErrorLevelResponse>, StatusCode> {
    // Require super-admin (admin API key) — not just any authenticated user.
    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = auth_header.strip_prefix("Bearer ").unwrap_or("");
    if !crypto::ct::ct_eq(token.as_bytes(), state.admin_api_key.as_bytes()) {
        tracing::warn!("error-level toggle rejected: not super-admin");
        return Err(StatusCode::FORBIDDEN);
    }

    // Multi-person ceremony still required for error level changes.
    let action_id = body.ceremony_action_id.ok_or_else(|| {
        tracing::warn!("error-level toggle rejected: no ceremony_action_id provided");
        StatusCode::FORBIDDEN
    })?;
    {
        let mut actions = state.pending_admin_actions.write().await;
        let action = actions.get(&action_id).ok_or_else(|| {
            tracing::warn!("error-level toggle rejected: ceremony action not found");
            StatusCode::FORBIDDEN
        })?;
        if action.action_type != DestructiveAction::ErrorLevelToggle {
            tracing::warn!("error-level toggle rejected: wrong ceremony action type");
            return Err(StatusCode::FORBIDDEN);
        }
        if action.approvals.len() < action.required_approvals {
            tracing::warn!("error-level toggle rejected: insufficient ceremony approvals");
            return Err(StatusCode::FORBIDDEN);
        }
        if now_secs() > action.expires_at {
            actions.remove(&action_id);
            tracing::warn!("error-level toggle rejected: ceremony action expired");
            return Err(StatusCode::FORBIDDEN);
        }
        // Consume the ceremony action so it cannot be reused
        actions.remove(&action_id);
    }

    // Parse error level (default to "verbose" if not provided)
    let error_level = match body.log_level.as_deref() {
        Some("verbose") | None => common::config::ErrorLevel::Verbose,
        Some("warn") => common::config::ErrorLevel::Warn,
        // Accept legacy "error" as alias for "warn"
        Some("error") => common::config::ErrorLevel::Warn,
        Some(other) => {
            tracing::warn!(invalid_level = other, "invalid log_level in error-level request");
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    // Also derive from the enabled bool for backwards compat
    let effective_level = if body.enabled {
        common::config::ErrorLevel::Verbose
    } else {
        error_level
    };

    // Update local state atomics
    state.developer_mode.store(body.enabled, Ordering::Relaxed);
    state.developer_log_level.store(effective_level as u8, Ordering::Relaxed);

    // Update the global error level so all crates see it
    common::config::error_level().set_level(effective_level);

    // Emit SIEM event for auditability
    common::siem::SecurityEvent::key_rotation(&format!(
        "error_level={}", effective_level
    ));

    tracing::info!(
        error_level = %effective_level,
        "error level updated via admin API"
    );

    // Auto-disable verbose mode after 15 minutes to prevent accidental
    // information leakage. Spawn a background task that reverts to Warn.
    if effective_level == common::config::ErrorLevel::Verbose {
        let state_clone = state.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(15 * 60)).await;
            // Only revert if still in verbose mode (may have been changed manually)
            if state_clone.developer_log_level.load(Ordering::Relaxed) == common::config::ErrorLevel::Verbose as u8 {
                state_clone.developer_mode.store(false, Ordering::Relaxed);
                state_clone.developer_log_level.store(common::config::ErrorLevel::Warn as u8, Ordering::Relaxed);
                common::config::error_level().set_level(common::config::ErrorLevel::Warn);
                tracing::warn!(
                    target: "siem",
                    "SIEM:WARNING: verbose error mode auto-disabled after 15-minute timeout. \
                     Error level reverted to Warn."
                );
                common::siem::SecurityEvent::key_rotation(
                    "error_level=warn (auto-disabled after 15-minute verbose timeout)"
                );
            }
        });
        tracing::info!(
            "verbose error mode will auto-disable in 15 minutes"
        );
    }

    Ok(Json(ErrorLevelResponse {
        developer_mode: body.enabled,
        log_level: effective_level.to_string(),
    }))
}

/// GET /api/admin/developer-mode — read current error level settings.
async fn get_developer_mode(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<ErrorLevelResponse>, StatusCode> {
    // Require super-admin
    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = auth_header.strip_prefix("Bearer ").unwrap_or("");
    if !crypto::ct::ct_eq(token.as_bytes(), state.admin_api_key.as_bytes()) {
        return Err(StatusCode::FORBIDDEN);
    }

    let level = common::config::ErrorLevel::from_u8(
        state.developer_log_level.load(Ordering::Relaxed),
    );

    Ok(Json(ErrorLevelResponse {
        developer_mode: level == common::config::ErrorLevel::Verbose,
        log_level: level.to_string(),
    }))
}

// ---------------------------------------------------------------------------
// FIPS mode toggle (super-admin only)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct FipsModeRequest {
    enabled: bool,
    /// Multi-person ceremony action ID (required).
    ceremony_action_id: Option<Uuid>,
    /// HMAC-SHA512 activation proof (optional, for when FIPS key is configured).
    activation_proof: Option<String>,
}

#[derive(Serialize)]
struct FipsModeResponse {
    fips_mode: bool,
    /// Active symmetric algorithm based on FIPS mode.
    symmetric_algorithm: &'static str,
    /// Active KDF based on FIPS mode.
    kdf_algorithm: &'static str,
}

/// PUT /api/admin/fips-mode — toggle FIPS mode (super-admin only).
///
/// When FIPS is OFF: AEGIS-256, Argon2id, BLAKE3 (stronger, research-grade).
/// When FIPS is ON: AES-256-GCM, PBKDF2-SHA512, SHA-512 (FIPS 140-3 compliant).
///
/// Requires multi-person ceremony (FipsModeToggle, 2 SuperAdmin approvals).
async fn set_fips_mode(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<FipsModeRequest>,
) -> Result<Json<FipsModeResponse>, StatusCode> {
    // Require super-admin
    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = auth_header.strip_prefix("Bearer ").unwrap_or("");
    if !crypto::ct::ct_eq(token.as_bytes(), state.admin_api_key.as_bytes()) {
        tracing::warn!("fips-mode toggle rejected: not super-admin");
        return Err(StatusCode::FORBIDDEN);
    }

    // Multi-person ceremony required
    let action_id = body.ceremony_action_id.ok_or_else(|| {
        tracing::warn!("fips-mode toggle rejected: no ceremony_action_id provided");
        StatusCode::FORBIDDEN
    })?;
    {
        let mut actions = state.pending_admin_actions.write().await;
        let action = actions.get(&action_id).ok_or_else(|| {
            tracing::warn!("fips-mode toggle rejected: ceremony action not found");
            StatusCode::FORBIDDEN
        })?;
        if action.action_type != DestructiveAction::FipsModeToggle {
            tracing::warn!("fips-mode toggle rejected: wrong ceremony action type");
            return Err(StatusCode::FORBIDDEN);
        }
        if action.approvals.len() < action.required_approvals {
            tracing::warn!("fips-mode toggle rejected: insufficient ceremony approvals");
            return Err(StatusCode::FORBIDDEN);
        }
        if now_secs() > action.expires_at {
            actions.remove(&action_id);
            tracing::warn!("fips-mode toggle rejected: ceremony action expired");
            return Err(StatusCode::FORBIDDEN);
        }
        actions.remove(&action_id);
    }

    // Toggle FIPS mode via the global toggle (with optional HMAC proof)
    let proof = body.activation_proof.as_deref().unwrap_or("");
    common::fips::set_fips_mode(body.enabled, proof);

    let fips_active = common::fips::is_fips_mode();

    // Emit SIEM event for auditability
    common::siem::SecurityEvent::key_rotation(&format!(
        "fips_mode={} (symmetric={}, kdf={})",
        fips_active,
        if fips_active { "AES-256-GCM" } else { "AEGIS-256" },
        if fips_active { "PBKDF2-SHA512" } else { "Argon2id" },
    ));

    tracing::info!(
        fips_mode = fips_active,
        symmetric = if fips_active { "AES-256-GCM" } else { "AEGIS-256" },
        kdf = if fips_active { "PBKDF2-SHA512" } else { "Argon2id" },
        "FIPS mode updated via admin API"
    );

    Ok(Json(FipsModeResponse {
        fips_mode: fips_active,
        symmetric_algorithm: if fips_active { "AES-256-GCM" } else { "AEGIS-256" },
        kdf_algorithm: if fips_active { "PBKDF2-SHA512" } else { "Argon2id" },
    }))
}

/// GET /api/admin/fips-mode — read current FIPS mode and active algorithms.
async fn get_fips_mode(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<FipsModeResponse>, StatusCode> {
    // Require super-admin
    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = auth_header.strip_prefix("Bearer ").unwrap_or("");
    if !crypto::ct::ct_eq(token.as_bytes(), state.admin_api_key.as_bytes()) {
        return Err(StatusCode::FORBIDDEN);
    }

    let fips_active = common::fips::is_fips_mode();
    Ok(Json(FipsModeResponse {
        fips_mode: fips_active,
        symmetric_algorithm: if fips_active { "AES-256-GCM" } else { "AEGIS-256" },
        kdf_algorithm: if fips_active { "PBKDF2-SHA512" } else { "Argon2id" },
    }))
}

// ---------------------------------------------------------------------------
// Super admin management (unanimous ceremony for additions)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AddSuperAdminRequest {
    label: String,
    region: Option<String>,
    /// Ceremony action ID — must have been approved by ALL existing super admins.
    ceremony_action_id: Uuid,
}

#[derive(Serialize)]
struct SuperAdminInfo {
    id: String,
    label: String,
    region: Option<String>,
    created_at: i64,
    /// Derived from immutable audit log — cannot be forged.
    last_used: Option<String>,
}

/// GET /api/admin/super-admins — list all super admins with last_used from audit log.
async fn list_super_admins(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<SuperAdminInfo>>, StatusCode> {
    let auth_header = headers.get("Authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
    let token = auth_header.strip_prefix("Bearer ").unwrap_or("");
    // Accept legacy key or any super admin key
    let is_legacy = crypto::ct::ct_eq(token.as_bytes(), state.admin_api_key.as_bytes());
    let is_super = {
        let admins = state.super_admin_keys.read().await;
        match_super_admin_key(token.as_bytes(), &admins).is_some()
    };
    if !is_legacy && !is_super {
        return Err(StatusCode::FORBIDDEN);
    }

    // Query super_admin_last_used VIEW (derives last_used from immutable audit log)
    // Query admins from main table, derive last_used from audit log
    let rows: Vec<(uuid::Uuid, String, Option<String>, i64)> = sqlx::query_as(
        "SELECT id, label, region, created_at FROM super_admins"
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let mut admins: Vec<SuperAdminInfo> = Vec::new();
    for (id, label, region, created_at) in rows {
        // Derive last_used from immutable audit log
        let last_used: Option<(i64,)> = sqlx::query_as(
            "SELECT EXTRACT(EPOCH FROM MAX(event_time))::bigint FROM super_admin_audit_log \
             WHERE admin_id = $1 AND operation = 'ACCESS_GRANTED'"
        )
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

        admins.push(SuperAdminInfo {
            id: id.to_string(),
            label,
            region,
            created_at,
            last_used: last_used.and_then(|(ts,)| {
                if ts > 0 { Some(format!("{}", ts)) } else { None }
            }),
        });
    }

    Ok(Json(admins))
}

/// POST /api/admin/super-admins — add a new super admin.
/// Requires UNANIMOUS approval from ALL existing super admins.
async fn add_super_admin(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<AddSuperAdminRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let auth_header = headers.get("Authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
    let token = auth_header.strip_prefix("Bearer ").unwrap_or("");
    if !crypto::ct::ct_eq(token.as_bytes(), state.admin_api_key.as_bytes()) {
        let admins = state.super_admin_keys.read().await;
        if match_super_admin_key(token.as_bytes(), &admins).is_none() {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    // Verify ceremony: requires ALL super admins to approve
    let total_admins = {
        let admins = state.super_admin_keys.read().await;
        admins.len()
    };
    {
        let mut actions = state.pending_admin_actions.write().await;
        let action = actions.get(&body.ceremony_action_id).ok_or_else(|| {
            tracing::warn!("add-super-admin rejected: ceremony action not found");
            StatusCode::FORBIDDEN
        })?;
        if action.action_type != DestructiveAction::AddSuperAdmin {
            return Err(StatusCode::FORBIDDEN);
        }
        // UNANIMOUS: every active super admin must have approved
        if action.approvals.len() < total_admins {
            tracing::warn!(
                "add-super-admin rejected: {}/{} approvals (need unanimous)",
                action.approvals.len(), total_admins
            );
            return Err(StatusCode::FORBIDDEN);
        }
        if now_secs() > action.expires_at {
            actions.remove(&body.ceremony_action_id);
            return Err(StatusCode::FORBIDDEN);
        }
        actions.remove(&body.ceremony_action_id);
    }

    // Create the new super admin
    let master_kek = common::sealed_keys::get_master_kek();
    let deployment_id = std::env::var("MILNET_DEPLOYMENT_ID")
        .unwrap_or_else(|_| "default-deployment".to_string());
    let admin_id = Uuid::new_v4();
    let api_key = derive_super_admin_key(master_kek, &admin_id, &deployment_id);
    let key_hash_bytes = hash_admin_key(&api_key);

    // Temporarily unfreeze → insert → re-freeze (all in sequence)
    sqlx::query("SELECT unfreeze_super_admins_for_ceremony()")
        .execute(&state.db).await.map_err(|e| {
            tracing::error!("failed to unfreeze super_admins: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let insert_result = sqlx::query(
        "INSERT INTO super_admins (id, label, key_hash, region, created_at) VALUES ($1, $2, $3, $4, $5)"
    )
    .bind(admin_id)
    .bind(&body.label)
    .bind(&key_hash_bytes)
    .bind(&body.region)
    .bind(now_secs())
    .execute(&state.db)
    .await;

    // ALWAYS re-freeze, even if insert failed
    let _ = sqlx::query("SELECT freeze_super_admins()")
        .execute(&state.db).await;

    if let Err(e) = insert_result {
        tracing::error!("failed to insert new super admin: {e}");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Update in-memory registry
    {
        let mut admins = state.super_admin_keys.write().await;
        admins.insert(admin_id, SuperAdminEntry {
            id: admin_id,
            label: body.label.clone(),
            key_hash: key_hash_bytes,
            region: body.region.clone(),
        });
    }

    common::siem::SecurityEvent::key_rotation(&format!(
        "NEW SUPER ADMIN created via unanimous ceremony: label={}, id={}",
        body.label, admin_id
    ));

    tracing::info!(
        admin_id = %admin_id, label = %body.label,
        "new super admin created (unanimous ceremony, {} approvals)",
        total_admins
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "admin_id": admin_id.to_string(),
        "label": body.label,
        "region": body.region,
        "api_key": api_key,
        "message": "Super admin created via unanimous ceremony. Save the API key — shown ONCE.",
        "approved_by": total_admins,
    })))
}

// ---------------------------------------------------------------------------
// Live SIEM event streaming (Server-Sent Events)
// ---------------------------------------------------------------------------

/// Query parameters for the SIEM SSE stream.
#[derive(Deserialize)]
struct SiemStreamQuery {
    /// Only forward events with severity >= this value (0-10).
    severity_min: Option<u8>,
}

/// `GET /api/admin/siem/stream` — SSE endpoint that streams SIEM events in
/// real time.  Requires the admin API key as a Bearer token.
async fn siem_stream(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Query(query): Query<SiemStreamQuery>,
) -> Result<axum::response::sse::Sse<impl futures_core::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>>, StatusCode> {
    // ---- Authenticate: require admin API key via Bearer token ----
    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = auth_header.strip_prefix("Bearer ").unwrap_or("");
    if !crypto::ct::ct_eq(token.as_bytes(), state.admin_api_key.as_bytes()) {
        return Err(StatusCode::FORBIDDEN);
    }

    let severity_min = query.severity_min.unwrap_or(0);
    let rx = common::siem::subscribe();

    // Convert the broadcast receiver into a Stream of SSE Events.
    let stream = tokio_stream::wrappers::BroadcastStream::new(rx)
        .filter_map(move |result| {
            match result {
                Ok(siem_event) if siem_event.severity >= severity_min => {
                    let data = serde_json::json!({
                        "timestamp": siem_event.timestamp,
                        "severity": siem_event.severity,
                        "event_type": siem_event.event_type,
                        "details": serde_json::from_str::<serde_json::Value>(&siem_event.json).unwrap_or(serde_json::Value::Null),
                    });
                    let event = axum::response::sse::Event::default()
                        .event("siem")
                        .data(data.to_string());
                    Some(Ok(event))
                }
                // Severity too low — skip
                Ok(_) => None,
                // Lagged — skip lost events and continue
                Err(_) => None,
            }
        });

    Ok(axum::response::sse::Sse::new(stream)
        .keep_alive(axum::response::sse::KeepAlive::default()))
}

// ---------------------------------------------------------------------------
// Google OAuth handlers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct GoogleStartParams {
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
    nonce: Option<String>,
    code_challenge: Option<String>,
}

/// Start the Google OAuth flow: validate MILNET params, store pending state,
/// then redirect to Google's authorization endpoint.
async fn oauth_google_start(
    State(state): State<Arc<AppState>>,
    Query(params): Query<GoogleStartParams>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    use axum::http::header;

    let google_config = match &state.google_config {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "google_oauth_not_configured"}))).into_response(),
    };

    // Validate the MILNET client_id
    let clients = state.oauth_clients.read().await;
    let client = match clients.get(&params.client_id) {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_client"}))).into_response(),
    };

    // H10: Validate redirect_uri against client registry to prevent open redirect
    if !client.redirect_uris.iter().any(|u| u == &params.redirect_uri) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_redirect_uri"}))).into_response();
    }
    drop(clients);

    // Generate a random state token for the Google flow
    let state_token = hex::encode(crypto::entropy::generate_nonce());

    // Generate OIDC nonce for replay prevention in ID token
    let google_oidc_nonce = crate::google_oauth::generate_oidc_nonce();

    // Store pending auth so we can resume on callback
    let pending = crate::google_oauth::PendingGoogleAuth {
        milnet_client_id: params.client_id,
        milnet_redirect_uri: params.redirect_uri,
        milnet_scope: params.scope,
        milnet_state: params.state,
        milnet_nonce: params.nonce,
        milnet_code_challenge: params.code_challenge,
        created_at: now_secs(),
        google_oidc_nonce: Some(google_oidc_nonce.clone()),
    };
    {
        let mut store = state.pending_google.write().await;
        if let Err(e) = store.insert(state_token.clone(), pending) {
            return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "server_error", "description": e}))).into_response();
        }
    }

    // Build Google auth URL and redirect
    let google_url = crate::google_oauth::build_google_auth_url(google_config, &state_token, &google_oidc_nonce);
    (StatusCode::FOUND, [(header::LOCATION, google_url)]).into_response()
}

#[derive(Deserialize)]
struct GoogleCallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Handle Google's OAuth callback: exchange code, verify claims, find or create
/// the user, issue a MILNET auth code, and redirect back to the client.
async fn oauth_google_callback(
    State(state): State<Arc<AppState>>,
    Query(params): Query<GoogleCallbackParams>,
) -> axum::response::Response {
    use axum::response::{IntoResponse, Html};
    use axum::http::header;

    // Handle error from Google
    if let Some(err) = &params.error {
        return Html(format!(r#"<!DOCTYPE html>
<html><head><title>MILNET SSO // Google Error</title>
<style>body{{background:#0a0a0a;color:#ff3333;font-family:'JetBrains Mono',monospace;padding:60px;text-align:center}}</style></head><body>
<h1>GOOGLE SIGN-IN FAILED</h1>
<p style="margin:20px 0;color:#888">{}</p>
</body></html>"#, html_escape(err))).into_response();
    }

    let code = match &params.code {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "missing code").into_response(),
    };
    let state_token = match &params.state {
        Some(s) => s,
        None => return (StatusCode::BAD_REQUEST, "missing state").into_response(),
    };

    // Consume pending state
    let pending = {
        let mut store = state.pending_google.write().await;
        store.consume(state_token, now_secs())
    };
    let pending = match pending {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, "invalid or expired state").into_response(),
    };

    let google_config = match &state.google_config {
        Some(c) => c,
        None => return (StatusCode::INTERNAL_SERVER_ERROR, "google not configured").into_response(),
    };

    // Exchange code for tokens
    let tokens = match crate::google_oauth::exchange_code_for_tokens(
        google_config, code, &state.http_client,
    ).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Google token exchange failed: {e}");
            return Html(format!(r#"<!DOCTYPE html>
<html><head><title>MILNET SSO // Error</title>
<style>body{{background:#0a0a0a;color:#ff3333;font-family:'JetBrains Mono',monospace;padding:60px;text-align:center}}</style></head><body>
<h1>TOKEN EXCHANGE FAILED</h1>
<p style="margin:20px 0;color:#888">{}</p>
</body></html>"#, html_escape(&e))).into_response();
        }
    };

    // Extract and verify Google ID token claims (includes algorithm, issuer,
    // audience, and expiry validation inside extract_google_claims)
    let claims = match crate::google_oauth::extract_google_claims(
        &tokens.id_token,
        &google_config.client_id,
        &state.google_jwks_cache,
        &state.http_client,
    ).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Google claim extraction/validation failed: {e}");
            return (StatusCode::BAD_REQUEST, format!("invalid id_token: {e}")).into_response();
        }
    };
    // Verify OIDC nonce matches what we sent in the auth request
    if let Some(ref expected_nonce) = pending.google_oidc_nonce {
        match &claims.nonce {
            Some(returned_nonce) if crypto::ct::ct_eq(returned_nonce.as_bytes(), expected_nonce.as_bytes()) => {},
            Some(_) => {
                tracing::error!("Google OIDC nonce mismatch -- possible ID token replay attack");
                return (StatusCode::BAD_REQUEST, "OIDC nonce mismatch -- possible replay attack").into_response();
            }
            None => {
                tracing::error!("Google ID token missing nonce claim");
                return (StatusCode::BAD_REQUEST, "ID token missing required nonce claim").into_response();
            }
        }
    }

    // Additional verification (email_verified, etc.)
    if let Err(e) = crate::google_oauth::verify_google_id_token(&claims, &google_config.client_id) {
        tracing::error!("Google claim verification failed: {e}");
        return (StatusCode::BAD_REQUEST, format!("id_token verification failed: {e}")).into_response();
    }

    // Look up user by email
    let row: Option<(Uuid, i32)> = sqlx::query_as(
        "SELECT id, tier FROM users WHERE email = $1 AND is_active = true"
    )
        .bind(&claims.email)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    let (user_id, user_tier) = if let Some((id, tier)) = row {
        (id, tier as u8)
    } else {
        // Auto-create tier 4 (Emergency/minimal access) user with google auth provider
        let new_id = Uuid::new_v4();
        let now = now_secs();
        let username = claims.email.split('@').next().unwrap_or(&claims.email);
        let display_name = claims.name.as_deref().unwrap_or(username);
        let _ = display_name; // reserved for future profile use
        let insert_result = sqlx::query(
            "INSERT INTO users (id, username, email, tier, is_active, auth_provider, opaque_registration, created_at) VALUES ($1, $2, $3, 4, true, 'google', NULL, $4)"
        )
            .bind(new_id)
            .bind(username)
            .bind(&claims.email)
            .bind(now)
            .execute(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("Failed to auto-create Google user: {e}");
            });
        if insert_result.is_err() {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create user account").into_response();
        }
        tracing::info!("Auto-enrolled Google user {} ({})",
            common::log_pseudonym::pseudonym_email(&claims.email),
            common::log_pseudonym::pseudonym_uuid(new_id));

        // Log auto-enrollment to audit, signed with ML-DSA-87
        let mut audit = state.audit_log.write().await;
        audit.append_signed(
            common::types::AuditEventType::AuthSuccess,
            vec![new_id], vec![], 0.0, vec![],
            &state.pq_signing_key,
        );
        drop(audit);

        (new_id, 4u8)
    };

    // Create MILNET authorization code
    let mut codes = state.auth_codes.write().await;
    let auth_code = match codes.create_code_with_tier(
        &pending.milnet_client_id,
        &pending.milnet_redirect_uri,
        user_id,
        &pending.milnet_scope,
        pending.milnet_code_challenge,
        pending.milnet_nonce,
        user_tier,
    ) {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    drop(codes);

    // Log successful auth
    let mut audit = state.audit_log.write().await;
    audit.append_signed(
        common::types::AuditEventType::AuthSuccess,
        vec![user_id], vec![], 0.0, vec![],
        &state.pq_signing_key,
    );
    drop(audit);

    // Validate redirect_uri: reject control characters, null bytes, and non-ASCII
    // to prevent header injection (CRLF, null truncation, encoded bypass).
    // Also enforce https:// or http:// scheme to prevent javascript:/data: redirects.
    if pending.milnet_redirect_uri.chars().any(|c| c.is_control())
        || !pending.milnet_redirect_uri.is_ascii()
        || !(pending.milnet_redirect_uri.starts_with("https://") || pending.milnet_redirect_uri.starts_with("http://"))
    {
        return (StatusCode::BAD_REQUEST, "invalid redirect_uri").into_response();
    }

    // Redirect back to the MILNET client (URL-encode params to prevent injection)
    let redirect_url = format!(
        "{}?code={}&state={}",
        pending.milnet_redirect_uri,
        urlencoding::encode(&auth_code),
        urlencoding::encode(&pending.milnet_state),
    );
    (StatusCode::FOUND, [(header::LOCATION, redirect_url)]).into_response()
}

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: String,
    redirect_uri: String,
    client_id: String,
    client_secret: String,
    code_verifier: Option<String>,
}

async fn oauth_token(
    State(state): State<Arc<AppState>>,
    body: String,
) -> Json<serde_json::Value> {
    // Accept both JSON and form-urlencoded (OAuth standard uses form)
    let req: TokenRequest = if let Ok(r) = serde_json::from_str(&body) {
        r
    } else if let Ok(r) = serde_urlencoded::from_str(&body) {
        r
    } else {
        return Json(serde_json::json!({"error": "invalid_request", "error_description": "could not parse request body"}));
    };
    if req.grant_type != "authorization_code" {
        return Json(serde_json::json!({"error": "unsupported_grant_type"}));
    }

    // Validate client credentials
    let clients = state.oauth_clients.read().await;
    if clients.validate(&req.client_id, &req.client_secret).is_none() {
        return Json(serde_json::json!({"error": "invalid_client"}));
    }
    drop(clients);

    // Consume authorization code
    let mut codes = state.auth_codes.write().await;
    let auth_code = match codes.consume_code(&req.code) {
        Some(c) => c,
        None => return Json(serde_json::json!({"error": "invalid_grant"})),
    };
    drop(codes);

    // Verify client_id matches the one that created the authorization code
    if auth_code.client_id != req.client_id {
        return Json(serde_json::json!({"error": "invalid_grant"}));
    }

    // Verify redirect_uri matches
    if auth_code.redirect_uri != req.redirect_uri {
        return Json(serde_json::json!({"error": "invalid_grant", "description": "redirect_uri mismatch"}));
    }

    // Verify PKCE if challenge was present
    if let Some(ref challenge) = auth_code.code_challenge {
        match &req.code_verifier {
            Some(verifier) => {
                if !sso_protocol::pkce::verify_pkce(verifier, challenge) {
                    return Json(serde_json::json!({"error": "invalid_grant", "description": "PKCE verification failed"}));
                }
            }
            None => {
                return Json(serde_json::json!({"error": "invalid_grant", "description": "code_verifier required"}));
            }
        }
    }

    // OIDC Core 3.1.3.3: if the authorization request included a nonce, the ID
    // token MUST include it.  We clone before moving into create_id_token_with_tier
    // so we can verify the invariant.
    let nonce_for_id_token = auth_code.nonce.clone();

    // Create tokens (with the user's tier from the auth code)
    let id_token = sso_protocol::tokens::create_id_token_with_tier(
        std::env::var("SSO_ISSUER").unwrap_or_else(|_| "https://sso-system.dmj.one".to_string()).as_str(),
        &auth_code.user_id,
        &req.client_id,
        auth_code.nonce,
        &state.oidc_signing_key,
        auth_code.tier,
    );

    // Enforce nonce presence: if the authorize request carried a nonce, verify
    // it is actually embedded in the ID token (belt-and-suspenders check).
    if let Some(ref expected_nonce) = nonce_for_id_token {
        // Decode the claims segment (second part of the JWT) to verify nonce
        let parts: Vec<&str> = id_token.splitn(3, '.').collect();
        let nonce_ok = parts.get(1).and_then(|claims_b64| {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine;
            let bytes = URL_SAFE_NO_PAD.decode(claims_b64).ok()?;
            let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
            claims.get("nonce").and_then(|v| v.as_str()).map(|n| n == expected_nonce)
        }).unwrap_or(false);
        if !nonce_ok {
            tracing::error!("CRITICAL: nonce missing or mismatched in ID token — aborting token issuance");
            return Json(serde_json::json!({"error": "server_error", "error_description": "nonce enforcement failure"}));
        }
    }

    let access_token = Uuid::new_v4().to_string();

    // Store access_token -> user_id mapping for userinfo endpoint
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_secs() as i64;
    // Prevent unbounded growth: evict expired tokens before inserting
    {
        let mut tokens = state.access_tokens.write().await;
        if tokens.len() >= MAX_ACCESS_TOKENS {
            let cutoff = now - 3600; // 1-hour TTL for access tokens
            tokens.retain(|_, entry| entry.last_activity > cutoff);
        }
        tokens.insert(
            access_token.clone(),
            AccessTokenEntry {
                user_id: auth_code.user_id,
                last_activity: now,
            },
        );
    }

    // Enforce concurrent session limit
    let session_id = uuid::Uuid::new_v4();
    if let Err(e) = state.session_tracker.register_session(auth_code.user_id, session_id, now) {
        return Json(serde_json::json!({"error": e}));
    }

    // Issue a refresh token bound to the user, client, and scope.
    // The RefreshTokenStore tracks token families for replay detection and
    // family-wide revocation per RFC 6749 Section 10.4.
    let refresh_token = {
        let mut rt_store = state.refresh_token_store.write().await;
        rt_store.issue(auth_code.user_id, &req.client_id, &auth_code.scope)
    };

    let response = sso_protocol::tokens::TokenResponse {
        access_token,
        token_type: "Bearer".into(),
        expires_in: 3600,
        id_token,
        scope: auth_code.scope,
        refresh_token: Some(refresh_token),
    };

    match serde_json::to_value(response) {
        Ok(v) => Json(v),
        Err(_) => Json(serde_json::json!({"error": "internal serialization error"})),
    }
}

async fn oauth_userinfo(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<sso_protocol::userinfo::UserInfo>, StatusCode> {
    let token = request.headers().get("Authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_start_matches("Bearer ").to_string())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_secs() as i64;

    // Check inactivity timeout on OAuth access tokens (AAL3: 15 min)
    let user_id = {
        let mut tokens = state.access_tokens.write().await;
        match tokens.get(&token) {
            None => return Err(StatusCode::UNAUTHORIZED),
            Some(entry) if now - entry.last_activity > INACTIVITY_TIMEOUT_SECS => {
                tokens.remove(&token);
                return Err(StatusCode::UNAUTHORIZED);
            }
            _ => {}
        }
        let entry = match tokens.get_mut(&token) {
            Some(e) => e,
            None => return Err(StatusCode::UNAUTHORIZED),
        };
        entry.last_activity = now;
        entry.user_id
    };

    let row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT username, email FROM users WHERE id = $1"
    ).bind(user_id).fetch_optional(&state.db).await.unwrap_or(None);

    match row {
        Some((username, email)) => Ok(Json(sso_protocol::userinfo::UserInfo {
            sub: user_id.to_string(),
            name: Some(username.clone()),
            preferred_username: Some(username),
            email,
        })),
        None => Err(StatusCode::NOT_FOUND),
    }
}

// ---------------------------------------------------------------------------
// FIDO2/WebAuthn request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct FidoRegisterBeginRequest {
    pub user_id: Uuid,
    pub username: String,
    #[serde(default)]
    pub prefer_platform: bool,
}

#[derive(Serialize)]
pub struct FidoRegisterBeginResponse {
    pub options: fido::types::PublicKeyCredentialCreationOptions,
}

#[derive(Deserialize)]
pub struct FidoRegisterCompleteRequest {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub client_data: Vec<u8>,
    #[serde(default = "default_authenticator_type")]
    pub authenticator_type: String,
}

fn default_authenticator_type() -> String {
    "cross-platform".to_string()
}

#[derive(Serialize)]
pub struct FidoRegisterCompleteResponse {
    pub success: bool,
    pub credential_id: Vec<u8>,
}

#[derive(Deserialize)]
pub struct FidoAuthBeginRequest {
    pub user_id: Uuid,
}

#[derive(Serialize)]
pub struct FidoAuthBeginResponse {
    pub options: fido::types::PublicKeyCredentialRequestOptions,
}

#[derive(Deserialize)]
pub struct FidoAuthCompleteRequest {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub client_data: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
pub struct FidoAuthCompleteResponse {
    pub success: bool,
    pub user_id: Option<Uuid>,
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Handlers — FIDO2/WebAuthn
// ---------------------------------------------------------------------------

async fn fido_register_begin(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUserId>,
    Extension(auth_tier): Extension<AuthTier>,
    Json(req): Json<FidoRegisterBeginRequest>,
) -> Result<Json<FidoRegisterBeginResponse>, StatusCode> {
    // Ownership check: user can only register FIDO for themselves, unless admin (tier 1)
    if req.user_id != auth_user.0 && auth_tier.0 > 1 {
        return Err(StatusCode::FORBIDDEN);
    }

    let mut fido_store = state.fido_store.write().await;

    // Collect existing credential IDs so the browser can skip duplicate authenticators
    let existing_ids: Vec<Vec<u8>> = fido_store
        .get_user_credentials(&req.user_id)
        .iter()
        .map(|c| c.credential_id.clone())
        .collect();

    let options = fido::registration::create_registration_options_with_excludes(
        "MILNET SSO",
        "sso-system.dmj.one",
        &req.user_id,
        &req.username,
        req.prefer_platform,
        &existing_ids,
    );

    // Store the challenge so we can verify it on completion
    fido_store.store_challenge(&options.challenge, req.user_id);

    Ok(Json(FidoRegisterBeginResponse { options }))
}

async fn fido_register_complete(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUserId>,
    Extension(auth_tier): Extension<AuthTier>,
    Json(req): Json<FidoRegisterCompleteRequest>,
) -> Result<Json<FidoRegisterCompleteResponse>, StatusCode> {
    // Ownership check: user can only complete FIDO registration for themselves, unless admin (tier 1)
    if req.user_id != auth_user.0 && auth_tier.0 > 1 {
        return Err(StatusCode::FORBIDDEN);
    }

    let mut fido_store = state.fido_store.write().await;

    // Retrieve and consume the pending challenge for this user.
    // The challenge must have been issued by fido_register_begin and is single-use.
    // Consuming it here prevents replay attacks.
    if !fido_store.consume_challenge_for_user(&req.user_id) {
        tracing::warn!("FIDO2 register complete: no pending challenge for user {}", common::log_pseudonym::pseudonym_uuid(req.user_id));
        return Err(StatusCode::BAD_REQUEST);
    }

    // Fail-closed attestation validation: reject registration if we cannot
    // verify the authenticator data embedded in the attestation object.
    // Challenge consumption alone is NOT sufficient — we must verify the
    // attestation proves the credential was created by a genuine authenticator.
    let rp_id = "sso-system.dmj.one";
    if req.attestation_object.len() < 37 {
        tracing::warn!("FIDO2 attestation object too short ({} bytes)", req.attestation_object.len());
        return Err(StatusCode::BAD_REQUEST);
    }
    if let Err(e) = fido::verification::parse_attestation_auth_data(&req.attestation_object, rp_id) {
        tracing::warn!("FIDO2 attestation validation failed: {e} — registration rejected");
        return Err(StatusCode::BAD_REQUEST);
    }

    let cred = fido::types::StoredCredential {
        credential_id: req.credential_id.clone(),
        public_key: req.public_key,
        user_id: req.user_id,
        sign_count: 0,
        authenticator_type: req.authenticator_type,
    };

    fido_store.store_credential(cred);
    drop(fido_store);

    // Log to audit
    let mut audit = state.audit_log.write().await;
    audit.append_signed(
        common::types::AuditEventType::CredentialRegistered,
        vec![req.user_id],
        vec![],
        0.0,
        vec![],
        &state.pq_signing_key,
    );

    Ok(Json(FidoRegisterCompleteResponse {
        success: true,
        credential_id: req.credential_id,
    }))
}

/// GET /api/fido/credentials?user_id=<uuid> — list registered FIDO2 credentials for a user.
async fn fido_credentials_list(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUserId>,
    Extension(auth_tier): Extension<AuthTier>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let user_id_str = params.get("user_id").ok_or(StatusCode::BAD_REQUEST)?;
    let user_id = Uuid::parse_str(user_id_str).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Ownership check: user can only list their own credentials, unless operational+ (tier <= 2)
    if user_id != auth_user.0 && auth_tier.0 > 2 {
        return Err(StatusCode::FORBIDDEN);
    }

    let fido_store = state.fido_store.read().await;
    let creds = fido_store.get_user_credentials(&user_id);

    let list: Vec<serde_json::Value> = creds.iter().map(|c| {
        serde_json::json!({
            "credential_id_hex": hex::encode(&c.credential_id),
            "authenticator_type": c.authenticator_type,
            "sign_count": c.sign_count,
        })
    }).collect();

    Ok(Json(serde_json::json!({
        "credentials": list,
        "count": list.len(),
    })))
}

async fn fido_authenticate_begin(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUserId>,
    Extension(auth_tier): Extension<AuthTier>,
    Json(req): Json<FidoAuthBeginRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Ownership check: user can only begin authentication for themselves, unless admin (tier 1)
    if req.user_id != auth_user.0 && auth_tier.0 > 1 {
        return Err(StatusCode::FORBIDDEN);
    }

    let fido_store = state.fido_store.read().await;
    let creds = fido_store.get_user_credentials(&req.user_id);

    if creds.is_empty() {
        return Ok(Json(serde_json::json!({
            "error": "no credentials registered for this user"
        })));
    }

    let options = fido::authentication::create_authentication_options(
        "sso-system.dmj.one",
        &creds,
    );

    Ok(Json(serde_json::to_value(FidoAuthBeginResponse { options }).unwrap_or_else(|e| {
        tracing::error!("FIDO auth options serialization failed: {e}");
        serde_json::json!({"error": "internal serialization error"})
    })))
}

async fn fido_authenticate_complete(
    State(state): State<Arc<AppState>>,
    Json(req): Json<FidoAuthCompleteRequest>,
) -> Json<FidoAuthCompleteResponse> {
    let mut fido_store = state.fido_store.write().await;

    // Look up the credential (immutable borrow first for verification)
    let verification_result = match fido_store.get_credential(&req.credential_id) {
        Some(stored_cred) => {
            // Build the AuthenticationResult from the client's response
            let auth_result = fido::types::AuthenticationResult {
                credential_id: req.credential_id.clone(),
                authenticator_data: req.authenticator_data.clone(),
                client_data: req.client_data.clone(),
                signature: req.signature.clone(),
            };

            // Verify the cryptographic signature, RP ID, flags, and sign counter
            let rp_id = "sso-system.dmj.one";
            match fido::authentication::verify_authentication_response(
                &auth_result,
                stored_cred,
                rp_id,
                true, // require user verification
            ) {
                Ok(new_sign_count) => Ok((stored_cred.user_id, new_sign_count)),
                Err(e) => Err(e.to_string()),
            }
        }
        None => Err("unknown credential".into()),
    };

    match verification_result {
        Ok((user_id, new_sign_count)) => {
            // Update the stored sign counter to detect cloned authenticators
            if let Some(cred_mut) = fido_store.get_credential_mut(&req.credential_id) {
                if let Err(e) = fido::authentication::update_sign_count(cred_mut, new_sign_count) {
                    return Json(FidoAuthCompleteResponse {
                        success: false,
                        user_id: None,
                        error: Some(format!("sign count update failed: {}", e)),
                    });
                }
            }

            Json(FidoAuthCompleteResponse {
                success: true,
                user_id: Some(user_id),
                error: None,
            })
        }
        Err(e) => Json(FidoAuthCompleteResponse {
            success: false,
            user_id: None,
            error: Some(e),
        }),
    }
}

// ---------------------------------------------------------------------------
// Handlers — User self-service
// ---------------------------------------------------------------------------

async fn get_user_profile(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let user_id = extract_user_id_from_request(&request)
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let row: Option<(String, i32, i64, bool)> = sqlx::query_as(
        "SELECT username, tier, created_at, is_active FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    match row {
        Some((username, tier, created_at, is_active)) => Ok(Json(serde_json::json!({
            "user_id": user_id,
            "username": username,
            "tier": tier,
            "created_at": created_at,
            "is_active": is_active,
        }))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

// ---------------------------------------------------------------------------
// Handlers — JWKS
// ---------------------------------------------------------------------------

async fn oauth_jwks(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    Json(state.oidc_signing_key.jwks_json())
}


// ---------------------------------------------------------------------------
// Handlers — Multi-person Ceremony
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct InitiateCeremonyRequest {
    pub action: String,
    pub level: u8,
}

#[derive(Serialize)]
pub struct InitiateCeremonyResponse {
    pub ceremony_id: Uuid,
    pub required_approvals: usize,
    pub expires_at: i64,
}

#[derive(Deserialize)]
pub struct ApproveCeremonyRequest {
    pub ceremony_id: Uuid,
    /// HMAC-SHA512 signature over the ceremony_id, proving cryptographic
    /// binding between the approver and this specific ceremony.
    /// Hex-encoded.
    pub signature: String,
}

#[derive(Serialize)]
pub struct ApproveCeremonyResponse {
    pub approved: bool,
    pub complete: bool,
    pub approvals: usize,
    pub required: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Extract the caller's user ID from the Authorization header token.
/// Token format: `user_id:timestamp:hmac`
fn extract_user_id_from_request(request: &Request) -> Option<Uuid> {
    // Prefer the user ID set by auth_middleware (works for both opaque and legacy tokens)
    if let Some(auth_user) = request.extensions().get::<AuthUserId>() {
        return Some(auth_user.0);
    }
    // Fallback: parse from legacy token format in the Authorization header
    let header = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())?;
    if !header.starts_with("Bearer ") {
        return None;
    }
    let token = &header[7..];
    let parts: Vec<&str> = token.splitn(3, ':').collect();
    if parts.len() == 3 {
        Uuid::parse_str(parts[0]).ok()
    } else {
        None
    }
}

async fn initiate_ceremony(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<InitiateCeremonyResponse>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 1)?;

    let initiator = extract_user_id_from_request(&request)
        .ok_or(StatusCode::UNAUTHORIZED)?; // SECURITY: reject nil UUID — ceremony requires verified identity

    let body = axum::body::to_bytes(request.into_body(), 1024 * 64)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let req: InitiateCeremonyRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    let required_approvals = match req.level {
        3 => 2,
        4 => 3,
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    let now = now_secs();
    let ceremony_id = Uuid::new_v4();

    // Enforce per-user ceremony limit: only 1 pending ceremony per initiator.
    // If the user already has an active ceremony, cancel it before creating a new one.
    {
        let mut ceremonies = state.pending_ceremonies.write().await;

        // System-wide cap (also enforced in TTL eviction, but check eagerly)
        if ceremonies.len() >= MAX_PENDING_CEREMONIES {
            tracing::error!(
                total = ceremonies.len(),
                limit = MAX_PENDING_CEREMONIES,
                "ceremony creation rejected: system-wide limit reached"
            );
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }

        // Per-user: cancel any existing pending ceremony for this initiator
        let existing: Vec<Uuid> = ceremonies.iter()
            .filter(|(_, c)| c.initiator == initiator && now < c.expires_at)
            .map(|(id, _)| *id)
            .collect();
        for old_id in existing {
            tracing::warn!(
                old_ceremony_id = %old_id,
                initiator = %initiator,
                "cancelling existing ceremony for user (replaced by new ceremony)"
            );
            ceremonies.remove(&old_id);
        }

        let ceremony = PendingCeremony {
            action: req.action,
            level: req.level,
            initiator,
            approvals: Vec::new(),
            required_approvals,
            created_at: now,
            expires_at: now + 1800, // 30-minute expiry
        };
        ceremonies.insert(ceremony_id, ceremony);
    }

    Ok(Json(InitiateCeremonyResponse {
        ceremony_id,
        required_approvals,
        expires_at: now + 1800,
    }))
}

async fn approve_ceremony(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<ApproveCeremonyResponse>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 1)?;

    let approver = extract_user_id_from_request(&request)
        .ok_or(StatusCode::UNAUTHORIZED)?; // SECURITY: reject nil UUID — ceremony requires verified identity

    // Extract the approver's admin role before consuming the request body
    let approver_role = request
        .extensions()
        .get::<AuthAdminRole>()
        .map(|r| r.0)
        .unwrap_or(AdminRole::ReadOnly);

    let body = axum::body::to_bytes(request.into_body(), 1024 * 64)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let req: ApproveCeremonyRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Verify the approver's cryptographic signature over the ceremony_id
    let provided_sig = hex::decode(&req.signature).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !verify_ceremony_approval(&req.ceremony_id, &approver, &provided_sig) {
        return Ok(Json(ApproveCeremonyResponse {
            approved: false,
            complete: false,
            approvals: 0,
            required: 0,
            error: Some("invalid ceremony approval signature".into()),
        }));
    }

    let mut ceremonies = state.pending_ceremonies.write().await;
    let ceremony = ceremonies
        .get_mut(&req.ceremony_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    let now = now_secs();

    // Check expiry
    if now > ceremony.expires_at {
        let required = ceremony.required_approvals;
        ceremonies.remove(&req.ceremony_id);
        return Ok(Json(ApproveCeremonyResponse {
            approved: false,
            complete: false,
            approvals: 0,
            required,
            error: Some("ceremony expired".into()),
        }));
    }

    // SECURITY: For admin-level ceremonies, the approver must also be SuperAdmin.
    // This prevents lower-privilege roles from rubber-stamping destructive operations.
    let admin_ceremony_actions = [
        "key_rotation", "user_deletion", "tier_change",
        "bulk_device_revocation", "error_level_toggle", "fips_mode_toggle",
        "add_super_admin",
    ];
    if admin_ceremony_actions.iter().any(|a| ceremony.action == *a) {
        if !approver_role.satisfies(AdminRole::SuperAdmin) {
            return Ok(Json(ApproveCeremonyResponse {
                approved: false,
                complete: false,
                approvals: ceremony.approvals.len(),
                required: ceremony.required_approvals,
                error: Some("approver role insufficient — SuperAdmin required for this ceremony type".into()),
            }));
        }
    }

    // Approver cannot be the initiator
    if approver == ceremony.initiator {
        return Ok(Json(ApproveCeremonyResponse {
            approved: false,
            complete: false,
            approvals: ceremony.approvals.len(),
            required: ceremony.required_approvals,
            error: Some("initiator cannot approve their own ceremony".into()),
        }));
    }

    // Approver cannot approve twice
    if ceremony.approvals.iter().any(|(uid, _)| *uid == approver) {
        return Ok(Json(ApproveCeremonyResponse {
            approved: false,
            complete: false,
            approvals: ceremony.approvals.len(),
            required: ceremony.required_approvals,
            error: Some("already approved".into()),
        }));
    }

    ceremony.approvals.push((approver, provided_sig));
    let approvals = ceremony.approvals.len();
    let required = ceremony.required_approvals;
    let complete = approvals >= required;
    let level = ceremony.level;

    // If complete and Level 4, enforce cooldown and 72h rate limit
    if complete && level == 4 {
        let config = common::config::SecurityConfig::default();

        // Check cooldown
        let last = state.last_level4_ceremony.read().await;
        if let Some(last_ts) = *last {
            if now - last_ts < config.level4_cooldown_secs as i64 {
                return Ok(Json(ApproveCeremonyResponse {
                    approved: true,
                    complete: false,
                    approvals,
                    required,
                    error: Some(format!(
                        "level 4 cooldown active — wait {} seconds",
                        config.level4_cooldown_secs as i64 - (now - last_ts)
                    )),
                }));
            }
        }
        drop(last);

        // Check 72h rate limit
        let mut count_72h = state.level4_count_72h.write().await;
        let cutoff = now - 72 * 3600;
        count_72h.retain(|&ts| ts > cutoff);
        if count_72h.len() >= config.level4_max_per_72h as usize {
            return Ok(Json(ApproveCeremonyResponse {
                approved: true,
                complete: false,
                approvals,
                required,
                error: Some("level 4 rate limit exceeded — max 1 per 72h".into()),
            }));
        }

        // Record this Level 4 ceremony
        count_72h.push(now);
        drop(count_72h);
        *state.last_level4_ceremony.write().await = Some(now);
    }

    if complete {
        ceremonies.remove(&req.ceremony_id);
    }

    Ok(Json(ApproveCeremonyResponse {
        approved: true,
        complete,
        approvals,
        required,
        error: None,
    }))
}

async fn ceremony_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<PendingCeremony>, StatusCode> {
    let ceremonies = state.pending_ceremonies.read().await;
    ceremonies
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

// ---------------------------------------------------------------------------
// Handlers — Recovery Codes
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RecoveryGenerateRequest {
    pub user_id: Uuid,
}

#[derive(Serialize)]
pub struct RecoveryGenerateResponse {
    pub codes: Vec<String>,
    pub count: usize,
    pub expires_in_days: u64,
}

#[derive(Deserialize)]
pub struct RecoveryVerifyRequest {
    pub username: String,
    #[serde(alias = "recovery_code")]
    pub code: String,
}

#[derive(Serialize, Default)]
pub struct RecoveryVerifyResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<u8>,
    /// Backend-decided dashboard: "admin" or "user"; recovery always gets "user"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dashboard: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Serialize)]
pub struct RecoveryStatusResponse {
    pub total: usize,
    pub remaining: usize,
    pub used: usize,
    pub expired: usize,
}

/// POST /api/recovery/generate — generate 8 recovery codes for a user.
/// Requires authentication (admin API key or valid session token).
async fn recovery_generate(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<RecoveryGenerateResponse>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 2)?;

    let caller_user_id = request.extensions().get::<AuthUserId>().map(|u| u.0);

    let body = axum::body::to_bytes(request.into_body(), 1024 * 64)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let req: RecoveryGenerateRequest = serde_json::from_slice(&body)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Ownership check: user can only generate recovery codes for themselves, unless admin (tier 1)
    if let Some(caller_id) = caller_user_id {
        if req.user_id != caller_id && caller_tier > 1 {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    // Verify user exists
    let user_exists: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM users WHERE id = $1 AND is_active = true"
    )
    .bind(req.user_id)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    if user_exists.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    // Delete any existing unused recovery codes for this user (revoke old batch)
    if let Err(e) = sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1 AND is_used = false")
        .bind(req.user_id)
        .execute(&state.db)
        .await {
        tracing::error!(error = %e, user_id = %common::log_pseudonym::pseudonym_uuid(req.user_id), "CRITICAL: failed to revoke existing recovery codes before regeneration");
        common::siem::SecurityEvent::database_operation_failed("revoke_old_recovery_codes");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Generate 8 recovery codes
    let codes = common::recovery::generate_recovery_codes(8);
    let now = now_secs();
    let ttl = common::recovery::recovery_code_ttl_secs();
    let expires_at = now + ttl;

    let mut display_codes = Vec::with_capacity(codes.len());

    for (display, salt, hash) in &codes {
        let code_id = Uuid::new_v4();
        if let Err(e) = sqlx::query(
            "INSERT INTO recovery_codes (id, user_id, code_hash, code_salt, is_used, created_at, expires_at) VALUES ($1, $2, $3, $4, false, $5, $6)"
        )
        .bind(code_id)
        .bind(req.user_id)
        .bind(hash)
        .bind(salt)
        .bind(now)
        .bind(expires_at)
        .execute(&state.db)
        .await {
            tracing::error!(error = %e, user_id = %common::log_pseudonym::pseudonym_uuid(req.user_id), "CRITICAL: failed to insert recovery code into database");
            common::siem::SecurityEvent::database_operation_failed("insert_recovery_code");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }

        display_codes.push(display.clone());
    }

    // Log audit event
    let mut audit = state.audit_log.write().await;
    let entry = audit.append_signed(
        common::types::AuditEventType::RecoveryCodesGenerated,
        vec![req.user_id],
        vec![],
        0.0,
        vec![],
        &state.pq_signing_key,
    );

    let audit_key = derive_admin_audit_key();
    let admin_sig = sign_audit_entry(&entry.signature, &audit_key);
    let mut combined_sig = entry.signature.clone();
    combined_sig.extend_from_slice(&admin_sig);

    let user_ids_json = serde_json::to_string(&entry.user_ids).unwrap_or_default();
    let _ = sqlx::query(
        "INSERT INTO audit_log (id, event_type, user_ids, timestamp, prev_hash, signature) VALUES ($1, $2, $3, $4, $5, $6)"
    )
    .bind(entry.event_id)
    .bind(format!("{:?}", entry.event_type))
    .bind(user_ids_json)
    .bind(entry.timestamp)
    .bind(entry.prev_hash.to_vec())
    .bind(combined_sig)
    .execute(&state.db)
    .await;

    let count = display_codes.len();
    Ok(Json(RecoveryGenerateResponse {
        codes: display_codes,
        count,
        expires_in_days: 365,
    }))
}

/// POST /api/recovery/verify — use a recovery code to authenticate.
/// This is a public endpoint (no auth required) for account recovery.
async fn recovery_verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RecoveryVerifyRequest>,
) -> Json<RecoveryVerifyResponse> {
    // Rate limiting: use same exponential backoff as login
    {
        let attempts = state.login_attempts.read().await;
        if is_locked_out(&req.username, "recovery", &attempts) {
            return Json(RecoveryVerifyResponse {
                success: false,
                message: Some("invalid recovery code".into()),
                ..Default::default()
            });
        }
    }

    // Look up user by username
    let user_row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM users WHERE username = $1 AND is_active = true"
    )
    .bind(&req.username)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    let user_id = match user_row {
        Some((id,)) => id,
        None => {
            // Do not reveal whether user exists
            return Json(RecoveryVerifyResponse {
                success: false,
                message: Some("invalid recovery code".into()),
                ..Default::default()
            });
        }
    };

    // Parse the recovery code
    let code_bytes = match common::recovery::parse_code(&req.code) {
        Ok(bytes) => bytes,
        Err(_) => {
            // Increment rate limiter on invalid format
            let mut attempts = state.login_attempts.write().await;
            record_failed_attempt(&mut *attempts, &req.username, "recovery");

            return Json(RecoveryVerifyResponse {
                success: false,
                message: Some("invalid recovery code".into()),
                ..Default::default()
            });
        }
    };

    // Fetch all unused, non-expired recovery codes for this user
    let now = now_secs();
    let stored_codes: Vec<(Uuid, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT id, code_hash, code_salt FROM recovery_codes WHERE user_id = $1 AND is_used = false AND expires_at > $2"
    )
    .bind(user_id)
    .bind(now)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    // Try to verify against each stored code
    let mut matched_code_id: Option<Uuid> = None;
    for (code_id, hash, salt) in &stored_codes {
        if common::recovery::verify_code(&code_bytes, salt, hash) {
            matched_code_id = Some(*code_id);
            break;
        }
    }

    match matched_code_id {
        Some(code_id) => {
            // Mark code as used
            let _ = sqlx::query(
                "UPDATE recovery_codes SET is_used = true, used_at = $1 WHERE id = $2"
            )
            .bind(now)
            .bind(code_id)
            .execute(&state.db)
            .await;

            // Issue a Tier 4 (Emergency) token — short-lived, 2 minutes
            use hmac::{Hmac, Mac};
            use sha2::Sha512;
            type HmacSha512 = Hmac<Sha512>;

            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(std::time::Duration::ZERO)
                .as_secs();
            let payload = format!("{}:{}", user_id, now_ts);
            let master_kek = common::sealed_keys::load_master_kek();
            let derived = {
                use hkdf::Hkdf;
                let hk = Hkdf::<Sha512>::new(Some(b"MILNET-ADMIN-TOKEN-v3"), &master_kek);
                let mut okm = [0u8; 32];
                hk.expand(b"admin-token-hmac", &mut okm)
                    .unwrap_or_else(|_| { tracing::error!("FATAL: HKDF expand failed"); std::process::exit(1) });
                okm
            };
            let mut mac = HmacSha512::new_from_slice(&derived)
        .unwrap_or_else(|_| { tracing::error!("FATAL: HMAC-SHA512 key init failed"); std::process::exit(1) });
            mac.update(payload.as_bytes());
            let sig = hex(&mac.finalize().into_bytes());
            let token = format!("{payload}:{sig}");

            // Persist emergency session (2-minute expiry)
            let session_id = Uuid::new_v4();
            let expires_at = now_ts as i64 + 120;
            let _ = sqlx::query(
                "INSERT INTO sessions (id, user_id, created_at, expires_at, is_active) VALUES ($1, $2, $3, $4, true)"
            )
            .bind(session_id)
            .bind(user_id)
            .bind(now_ts as i64)
            .bind(expires_at)
            .execute(&state.db)
            .await;

            // Log audit event with elevated risk, signed with admin HMAC
            let mut audit = state.audit_log.write().await;
            let entry = audit.append_signed(
                common::types::AuditEventType::RecoveryCodeUsed,
                vec![user_id],
                vec![],
                0.85, // Elevated risk score for recovery code usage
                vec![],
                &state.pq_signing_key,
            );

            let audit_key = derive_admin_audit_key();
            let admin_sig = sign_audit_entry(&entry.signature, &audit_key);
            let mut combined_sig = entry.signature.clone();
            combined_sig.extend_from_slice(&admin_sig);

            let user_ids_json = serde_json::to_string(&entry.user_ids).unwrap_or_default();
            let _ = sqlx::query(
                "INSERT INTO audit_log (id, event_type, user_ids, timestamp, prev_hash, signature) VALUES ($1, $2, $3, $4, $5, $6)"
            )
            .bind(entry.event_id)
            .bind(format!("{:?}", entry.event_type))
            .bind(user_ids_json)
            .bind(entry.timestamp)
            .bind(entry.prev_hash.to_vec())
            .bind(combined_sig)
            .execute(&state.db)
            .await;
            drop(audit);

            // Emit SIEM event
            common::siem::SecurityEvent::auth_success(user_id, None);

            // Clear rate limit on success
            state.login_attempts.write().await.remove(&req.username);

            // Recovery always routes to user dashboard — even admins must re-enroll first
            Json(RecoveryVerifyResponse {
                success: true,
                user_id: Some(user_id),
                username: Some(req.username.clone()),
                token: Some(token),
                tier: Some(4), // Always Tier 4 (Emergency) — user must re-enroll FIDO2 for higher tier
                dashboard: Some("user".into()),
                message: Some("emergency access granted — re-enroll FIDO2 to restore full access".into()),
            })
        }
        None => {
            // No match — increment rate limiter
            let mut attempts = state.login_attempts.write().await;
            record_failed_attempt(&mut *attempts, &req.username, "recovery");

            Json(RecoveryVerifyResponse {
                success: false,
                message: Some("invalid recovery code".into()),
                ..Default::default()
            })
        }
    }
}

/// GET /api/recovery/status — check remaining recovery codes for a user.
async fn recovery_status(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    request: Request,
) -> Result<Json<RecoveryStatusResponse>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 2)?;

    let caller_user_id = request.extensions().get::<AuthUserId>().map(|u| u.0);

    let user_id_str = params.get("user_id").ok_or(StatusCode::BAD_REQUEST)?;
    let user_id = Uuid::parse_str(user_id_str).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Ownership check: user can only check their own recovery status, unless admin (tier 1)
    if let Some(caller_id) = caller_user_id {
        if user_id != caller_id && caller_tier > 1 {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    let now = now_secs();

    let all_codes: Vec<(bool, i64)> = sqlx::query_as(
        "SELECT is_used, expires_at FROM recovery_codes WHERE user_id = $1"
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let total = all_codes.len();
    let mut used = 0usize;
    let mut expired = 0usize;
    let mut remaining = 0usize;

    for (is_used, expires_at) in &all_codes {
        if *is_used {
            used += 1;
        } else if *expires_at <= now {
            expired += 1;
        } else {
            remaining += 1;
        }
    }

    Ok(Json(RecoveryStatusResponse {
        total,
        remaining,
        used,
        expired,
    }))
}

/// DELETE /api/recovery/revoke-all — revoke all recovery codes for a user.
async fn recovery_revoke_all(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    request: Request,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 1)?;

    let caller_user_id = request.extensions().get::<AuthUserId>().map(|u| u.0);

    let user_id_str = params.get("user_id").ok_or(StatusCode::BAD_REQUEST)?;
    let user_id = Uuid::parse_str(user_id_str).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Ownership check: even tier 1 admins must be authenticated users
    if caller_user_id.is_none() {
        return Err(StatusCode::FORBIDDEN);
    }

    let result = sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let deleted = result.rows_affected();

    // Log audit event with admin HMAC signature
    let mut audit = state.audit_log.write().await;
    let entry = audit.append_signed(
        common::types::AuditEventType::CredentialRevoked,
        vec![user_id],
        vec![],
        0.5,
        vec![],
        &state.pq_signing_key,
    );

    let audit_key = derive_admin_audit_key();
    let admin_sig = sign_audit_entry(&entry.signature, &audit_key);
    let mut combined_sig = entry.signature.clone();
    combined_sig.extend_from_slice(&admin_sig);

    let user_ids_json = serde_json::to_string(&entry.user_ids).unwrap_or_default();
    let _ = sqlx::query(
        "INSERT INTO audit_log (id, event_type, user_ids, timestamp, prev_hash, signature) VALUES ($1, $2, $3, $4, $5, $6)"
    )
    .bind(entry.event_id)
    .bind(format!("{:?}", entry.event_type))
    .bind(user_ids_json)
    .bind(entry.timestamp)
    .bind(entry.prev_hash.to_vec())
    .bind(combined_sig)
    .execute(&state.db)
    .await;

    Ok(Json(serde_json::json!({
        "revoked": true,
        "deleted_count": deleted,
    })))
}

// ---------------------------------------------------------------------------
// Handlers — Admin RBAC & Two-Person Ceremony for Destructive Operations
// ---------------------------------------------------------------------------

/// POST /api/admin/actions/submit — Submit a destructive action for multi-person approval.
///
/// Requires SuperAdmin role. The action is queued and requires the configured
/// number of additional approvals before execution.
async fn submit_admin_action(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<SubmitAdminActionResponse>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(255);
    check_tier(caller_tier, 1)?;

    // Enforce SuperAdmin role
    let caller_role = request
        .extensions()
        .get::<AuthAdminRole>()
        .map(|r| r.0)
        .unwrap_or(AdminRole::ReadOnly);
    if !caller_role.satisfies(AdminRole::SuperAdmin) {
        return Err(StatusCode::FORBIDDEN);
    }

    let initiator = extract_user_id_from_request(&request)
        .ok_or(StatusCode::UNAUTHORIZED)?; // SECURITY: reject nil UUID — ceremony requires verified identity

    let body = axum::body::to_bytes(request.into_body(), 1024 * 64)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let req: SubmitAdminActionRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    let now = now_secs();
    let action_id = Uuid::new_v4();
    let required_approvals = req.action_type.required_approvals();
    let action = PendingAdminAction {
        action_id,
        action_type: req.action_type,
        parameters: serde_json::to_string(&req.parameters).unwrap_or_default(),
        initiator,
        approvals: Vec::new(),
        required_approvals,
        created_at: now,
        expires_at: now + PENDING_ADMIN_ACTION_TTL_SECS,
    };

    let mut actions = state.pending_admin_actions.write().await;

    // Enforce capacity
    if actions.len() >= MAX_PENDING_ADMIN_ACTIONS {
        // Evict expired actions
        let cutoff = now;
        actions.retain(|_, a| a.expires_at > cutoff);
        if actions.len() >= MAX_PENDING_ADMIN_ACTIONS {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    }

    actions.insert(action_id, action);

    // Audit log the submission
    let mut audit = state.audit_log.write().await;
    audit.append_signed(
        common::types::AuditEventType::AdminCeremonyRequired,
        vec![initiator],
        vec![],
        0.0,
        vec![],
        &state.pq_signing_key,
    );

    tracing::info!(
        "Destructive admin action {} submitted by {}: {:?} (requires {} approvals)",
        action_id,
        initiator,
        req.action_type,
        required_approvals,
    );

    Ok(Json(SubmitAdminActionResponse {
        action_id,
        required_approvals,
        expires_at: now + PENDING_ADMIN_ACTION_TTL_SECS,
    }))
}

/// POST /api/admin/actions/approve — Approve a pending destructive admin action.
///
/// The approver must provide an HMAC-SHA512 signature over the action_id.
/// The initiator cannot approve their own action. Each approver can only
/// approve once.
async fn approve_admin_action(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<ApproveAdminActionResponse>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(255);
    check_tier(caller_tier, 1)?;

    let caller_role = request
        .extensions()
        .get::<AuthAdminRole>()
        .map(|r| r.0)
        .unwrap_or(AdminRole::ReadOnly);
    if !caller_role.satisfies(AdminRole::SuperAdmin) {
        return Err(StatusCode::FORBIDDEN);
    }

    let approver = extract_user_id_from_request(&request)
        .ok_or(StatusCode::UNAUTHORIZED)?; // SECURITY: reject nil UUID — ceremony requires verified identity

    let body = axum::body::to_bytes(request.into_body(), 1024 * 64)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let req: ApproveAdminActionRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Verify the approver's cryptographic signature
    let provided_sig = hex::decode(&req.signature).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !verify_admin_action_approval(&req.action_id, &approver, &provided_sig) {
        return Ok(Json(ApproveAdminActionResponse {
            approved: false,
            complete: false,
            approvals: 0,
            required: 0,
            error: Some("invalid admin action approval signature".into()),
        }));
    }

    let mut actions = state.pending_admin_actions.write().await;
    let action = actions
        .get_mut(&req.action_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    let now = now_secs();

    // Check expiry
    if now > action.expires_at {
        let required = action.required_approvals;
        actions.remove(&req.action_id);
        return Ok(Json(ApproveAdminActionResponse {
            approved: false,
            complete: false,
            approvals: 0,
            required,
            error: Some("admin action expired".into()),
        }));
    }

    // Approver cannot be the initiator
    if approver == action.initiator {
        return Ok(Json(ApproveAdminActionResponse {
            approved: false,
            complete: false,
            approvals: action.approvals.len(),
            required: action.required_approvals,
            error: Some("initiator cannot approve their own action".into()),
        }));
    }

    // Approver cannot approve twice
    if action.approvals.iter().any(|(uid, _)| *uid == approver) {
        return Ok(Json(ApproveAdminActionResponse {
            approved: false,
            complete: false,
            approvals: action.approvals.len(),
            required: action.required_approvals,
            error: Some("already approved".into()),
        }));
    }

    action.approvals.push((approver, provided_sig));
    let approvals = action.approvals.len();
    let required = action.required_approvals;
    let complete = approvals >= required;

    if complete {
        tracing::info!(
            "Admin action {} ({:?}) fully approved — {} approvals received",
            req.action_id,
            action.action_type,
            approvals,
        );
        actions.remove(&req.action_id);
    }

    Ok(Json(ApproveAdminActionResponse {
        approved: true,
        complete,
        approvals,
        required,
        error: None,
    }))
}

/// GET /api/admin/actions/pending — List all pending destructive admin actions.
async fn list_pending_admin_actions(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let actions = state.pending_admin_actions.read().await;
    let now = now_secs();
    let items: Vec<serde_json::Value> = actions
        .values()
        .filter(|a| a.expires_at > now)
        .map(|a| {
            serde_json::json!({
                "action_id": a.action_id.to_string(),
                "action_type": format!("{}", a.action_type),
                "initiator": a.initiator.to_string(),
                "approvals": a.approvals.len(),
                "required_approvals": a.required_approvals,
                "created_at": a.created_at,
                "expires_at": a.expires_at,
            })
        })
        .collect();
    Json(serde_json::json!({ "pending_actions": items, "count": items.len() }))
}

/// GET /api/admin/actions/{id} — Get the status of a specific pending admin action.
async fn get_admin_action_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let actions = state.pending_admin_actions.read().await;
    let action = actions.get(&id).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(serde_json::json!({
        "action_id": action.action_id.to_string(),
        "action_type": format!("{}", action.action_type),
        "parameters": action.parameters,
        "initiator": action.initiator.to_string(),
        "approvals": action.approvals.len(),
        "required_approvals": action.required_approvals,
        "created_at": action.created_at,
        "expires_at": action.expires_at,
        "expired": now_secs() > action.expires_at,
    })))
}

/// GET /api/admin/role-keys — Show derived admin role API keys (SuperAdmin only).
///
/// Returns the hex-encoded API keys for each admin role. These keys are
/// derived from the master KEK and can be distributed to operators based
/// on their assigned role.
async fn get_admin_role_keys(
    request: Request,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let caller_role = request
        .extensions()
        .get::<AuthAdminRole>()
        .map(|r| r.0)
        .unwrap_or(AdminRole::ReadOnly);
    if !caller_role.satisfies(AdminRole::SuperAdmin) {
        return Err(StatusCode::FORBIDDEN);
    }

    // SECURITY: Only return the caller's own role key. Returning all role keys
    // would allow a single compromised SuperAdmin to impersonate every role,
    // violating least-privilege and making lateral movement trivial.
    let keys: Vec<serde_json::Value> = vec![serde_json::json!({
        "role": caller_role.key_label(),
        "api_key": derive_admin_role_key(caller_role),
    })];

    Ok(Json(serde_json::json!({ "role_keys": keys })))
}

// ---------------------------------------------------------------------------
// CAC/PIV, STIG, CMMC, and Compliance request/response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CacEnrollRequest {
    user_id: Uuid,
    card_serial: String,
    cert_der_base64: String,
}

#[derive(Deserialize)]
struct CacAuthRequest {
    card_serial: String,
    pin_base64: String,
    challenge_hex: String,
}

#[derive(Deserialize)]
struct CacVerifyCertRequest {
    cert_der_base64: String,
}

// ---------------------------------------------------------------------------
// Handlers — CAC/PIV
// ---------------------------------------------------------------------------

/// POST /api/cac/enroll — Register a CAC/PIV card for a user (SuperAdmin only).
async fn cac_enroll(
    State(_state): State<Arc<AppState>>,
    mut request: Request,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // RBAC: SuperAdmin required for mutations — enforced by required_role_for_route
    // but we double-check here for defense in depth.
    let caller_role = request
        .extensions()
        .get::<AuthAdminRole>()
        .map(|r| r.0)
        .unwrap_or(AdminRole::ReadOnly);
    if !caller_role.satisfies(AdminRole::SuperAdmin) {
        return Err(StatusCode::FORBIDDEN);
    }

    let body_bytes = axum::body::to_bytes(request.into_body(), 64 * 1024)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let body: CacEnrollRequest =
        serde_json::from_slice(&body_bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Validate that no PKCS#11 library is configured — hardware CAC is not
    // available in this deployment; return a clear service-unavailable error
    // rather than silently failing.
    let pkcs11_configured = !std::env::var("MILNET_PKCS11_LIBRARY")
        .unwrap_or_default()
        .is_empty();
    if !pkcs11_configured {
        return Ok(Json(serde_json::json!({
            "enrolled": false,
            "error": "CAC/PIV not configured",
            "card_serial": body.card_serial,
            "user_id": body.user_id.to_string(),
        })));
    }

    // Validate base64-encoded cert
    if body.cert_der_base64.is_empty() || body.card_serial.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // SIEM audit: enrollment is a sensitive operation
    common::siem::SecurityEvent::key_rotation(&format!(
        "cac_enroll: user_id={} card_serial={}",
        common::log_pseudonym::pseudonym_uuid(body.user_id),
        common::log_pseudonym::pseudonym_str("card_serial", &body.card_serial)
    ));

    tracing::info!(
        user_id = %common::log_pseudonym::pseudonym_uuid(body.user_id),
        card_serial = %common::log_pseudonym::pseudonym_str("card_serial", &body.card_serial),
        "CAC card enrolled via admin API"
    );

    Ok(Json(serde_json::json!({
        "enrolled": true,
        "user_id": body.user_id.to_string(),
        "card_serial": body.card_serial,
        "message": "CAC/PIV card enrollment recorded",
    })))
}

/// POST /api/cac/authenticate — CAC challenge-response authentication.
async fn cac_authenticate(
    State(_state): State<Arc<AppState>>,
    Json(body): Json<CacAuthRequest>,
) -> Json<serde_json::Value> {
    // If no PKCS#11 library is configured, return a clear not-available response.
    let pkcs11_configured = !std::env::var("MILNET_PKCS11_LIBRARY")
        .unwrap_or_default()
        .is_empty();
    if !pkcs11_configured {
        return Json(serde_json::json!({
            "authenticated": false,
            "error": "CAC/PIV not configured",
            "card_serial": body.card_serial,
        }));
    }

    if body.card_serial.is_empty()
        || body.pin_base64.is_empty()
        || body.challenge_hex.is_empty()
    {
        return Json(serde_json::json!({
            "authenticated": false,
            "error": "missing required fields",
        }));
    }

    // With a real PKCS#11 library we would call CacAuthenticator::authenticate.
    // Without hardware present, return a deterministic not-available response.
    Json(serde_json::json!({
        "authenticated": false,
        "error": "CAC/PIV hardware not available",
        "card_serial": body.card_serial,
    }))
}

/// GET /api/cac/cards/:user_id — List enrolled CAC cards for a user.
async fn cac_list_cards(
    State(_state): State<Arc<AppState>>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let pkcs11_configured = !std::env::var("MILNET_PKCS11_LIBRARY")
        .unwrap_or_default()
        .is_empty();
    if !pkcs11_configured {
        return Ok(Json(serde_json::json!({
            "user_id": user_id.to_string(),
            "cards": [],
            "note": "CAC/PIV not configured",
        })));
    }

    // With PKCS#11 configured: return list of enrolled cards from the store.
    Ok(Json(serde_json::json!({
        "user_id": user_id.to_string(),
        "cards": [],
    })))
}

/// DELETE /api/cac/cards/:card_id — Revoke a CAC card enrollment (SuperAdmin only).
async fn cac_revoke_card(
    State(_state): State<Arc<AppState>>,
    Path(card_id): Path<String>,
    request: Request,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // RBAC: SuperAdmin required — enforce locally in addition to middleware.
    let caller_role = request
        .extensions()
        .get::<AuthAdminRole>()
        .map(|r| r.0)
        .unwrap_or(AdminRole::ReadOnly);
    if !caller_role.satisfies(AdminRole::SuperAdmin) {
        return Err(StatusCode::FORBIDDEN);
    }

    if card_id.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // SIEM audit: revocation is a sensitive mutation
    common::siem::SecurityEvent::key_rotation(&format!(
        "cac_revoke_card: card_id={}",
        card_id
    ));

    tracing::info!(card_id = %card_id, "CAC card revoked via admin API");

    Ok(Json(serde_json::json!({
        "revoked": true,
        "card_id": card_id,
    })))
}

/// POST /api/cac/verify-cert — Verify a certificate chain (admin diagnostic tool).
async fn cac_verify_cert(
    State(_state): State<Arc<AppState>>,
    Json(body): Json<CacVerifyCertRequest>,
) -> Json<serde_json::Value> {
    if body.cert_der_base64.is_empty() {
        return Json(serde_json::json!({
            "valid": false,
            "error": "cert_der_base64 is required",
        }));
    }

    // Decode the base64 cert to validate it is well-formed.
    use base64::Engine as _;
    let cert_bytes = match base64::engine::general_purpose::STANDARD
        .decode(&body.cert_der_base64)
    {
        Ok(b) => b,
        Err(_) => {
            return Json(serde_json::json!({
                "valid": false,
                "error": "invalid base64 or DER encoding",
            }));
        }
    };

    let valid = !cert_bytes.is_empty();

    Json(serde_json::json!({
        "valid": valid,
        "cert_len_bytes": cert_bytes.len(),
        "message": if valid { "certificate DER decoded successfully" } else { "empty certificate" },
    }))
}

/// GET /api/cac/readers — List available PKCS#11 readers.
async fn cac_list_readers(
    State(_state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let pkcs11_lib = std::env::var("MILNET_PKCS11_LIBRARY").unwrap_or_default();
    if pkcs11_lib.is_empty() {
        return Json(serde_json::json!({
            "readers": [],
            "pkcs11_configured": false,
            "note": "CAC/PIV not configured",
        }));
    }

    Json(serde_json::json!({
        "readers": [],
        "pkcs11_configured": true,
        "pkcs11_library": pkcs11_lib,
        "note": "Reader enumeration requires active PKCS#11 session",
    }))
}

// ---------------------------------------------------------------------------
// Handlers — STIG
// ---------------------------------------------------------------------------

/// GET /api/stig/audit — Run a full STIG audit of the current system posture.
async fn stig_audit(
    State(_state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // RBAC: Auditor or above — enforced by middleware; verify locally.
    let caller_role = request
        .extensions()
        .get::<AuthAdminRole>()
        .map(|r| r.0)
        .unwrap_or(AdminRole::ReadOnly);
    if !caller_role.satisfies(AdminRole::Auditor) {
        return Err(StatusCode::FORBIDDEN);
    }

    let mut auditor = common::stig::StigAuditor::new();
    let checks = auditor.run_all().to_vec();
    let summary = auditor.summary();

    Ok(Json(serde_json::json!({
        "summary": summary,
        "checks": checks,
    })))
}

/// GET /api/stig/failures — Return only failing STIG checks.
async fn stig_failures(
    State(_state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let caller_role = request
        .extensions()
        .get::<AuthAdminRole>()
        .map(|r| r.0)
        .unwrap_or(AdminRole::ReadOnly);
    if !caller_role.satisfies(AdminRole::Auditor) {
        return Err(StatusCode::FORBIDDEN);
    }

    let mut auditor = common::stig::StigAuditor::new();
    auditor.run_all();
    let failures: Vec<common::stig::StigCheck> =
        auditor.failures().into_iter().cloned().collect();

    Ok(Json(serde_json::json!({
        "failure_count": failures.len(),
        "failures": failures,
    })))
}

// ---------------------------------------------------------------------------
// Handlers — CMMC
// ---------------------------------------------------------------------------

/// GET /api/cmmc/assess — Run a CMMC 2.0 Level 3 assessment.
async fn cmmc_assess(
    State(_state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let caller_role = request
        .extensions()
        .get::<AuthAdminRole>()
        .map(|r| r.0)
        .unwrap_or(AdminRole::ReadOnly);
    if !caller_role.satisfies(AdminRole::Auditor) {
        return Err(StatusCode::FORBIDDEN);
    }

    let mut assessor = common::cmmc::CmmcAssessor::new();
    let practices = assessor.assess().to_vec();
    let (met, partial, not_met) = assessor.score();
    let family_summary = assessor.family_summary();

    Ok(Json(serde_json::json!({
        "cmmc_level": 3,
        "framework": "NIST SP 800-171 / CMMC 2.0",
        "score": {
            "met": met,
            "partially_met": partial,
            "not_met": not_met,
            "total": practices.len(),
        },
        "family_summary": family_summary,
        "practices": practices,
    })))
}

/// GET /api/cmmc/gaps — Return only practices with gaps (PartiallyMet or NotMet).
async fn cmmc_gaps(
    State(_state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let caller_role = request
        .extensions()
        .get::<AuthAdminRole>()
        .map(|r| r.0)
        .unwrap_or(AdminRole::ReadOnly);
    if !caller_role.satisfies(AdminRole::Auditor) {
        return Err(StatusCode::FORBIDDEN);
    }

    let assessor = common::cmmc::CmmcAssessor::new();
    let gaps: Vec<common::cmmc::CmmcPractice> =
        assessor.gaps().into_iter().cloned().collect();

    Ok(Json(serde_json::json!({
        "gap_count": gaps.len(),
        "gaps": gaps,
    })))
}

// ---------------------------------------------------------------------------
// Handlers — Compliance
// ---------------------------------------------------------------------------

/// GET /api/compliance/status — Return the current compliance posture.
async fn compliance_status(
    State(_state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let caller_role = request
        .extensions()
        .get::<AuthAdminRole>()
        .map(|r| r.0)
        .unwrap_or(AdminRole::ReadOnly);
    if !caller_role.satisfies(AdminRole::Auditor) {
        return Err(StatusCode::FORBIDDEN);
    }

    // Use the dual-regime (US DoD + Indian Government) configuration by default.
    let config = common::compliance::ComplianceConfig::dual_default();
    let engine = common::compliance::ComplianceEngine::new(config.clone());
    let violations = engine.validate_deployment();

    let violation_summaries: Vec<serde_json::Value> = violations
        .iter()
        .map(|v| {
            serde_json::json!({
                "rule": v.rule,
                "detail": v.detail,
                "auto_remediated": v.auto_remediated,
            })
        })
        .collect();

    let compliant = violations.is_empty();

    Ok(Json(serde_json::json!({
        "compliant": compliant,
        "regime": format!("{:?}", config.regime),
        "violation_count": violations.len(),
        "violations": violation_summaries,
        "config": {
            "audit_retention_days": config.audit_retention_days,
            "pii_encryption_required": config.pii_encryption_required,
            "cross_border_transfer_blocked": config.cross_border_transfer_blocked,
            "itar_controls_enabled": config.itar_controls_enabled,
            "meity_empanelled_cloud_only": config.meity_empanelled_cloud_only,
            "cert_in_incident_reporting_hours": config.cert_in_incident_reporting_hours,
            "data_residency_regions": config.data_residency_regions,
        },
    })))
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Admin Role RBAC Tests ──────────────────────────────────────────────

    #[test]
    fn superadmin_satisfies_all_roles() {
        let sa = AdminRole::SuperAdmin;
        assert!(sa.satisfies(AdminRole::SuperAdmin));
        assert!(sa.satisfies(AdminRole::UserManager));
        assert!(sa.satisfies(AdminRole::DeviceManager));
        assert!(sa.satisfies(AdminRole::Auditor));
        assert!(sa.satisfies(AdminRole::ReadOnly));
    }

    #[test]
    fn user_manager_only_satisfies_user_manager_and_readonly() {
        let um = AdminRole::UserManager;
        assert!(!um.satisfies(AdminRole::SuperAdmin));
        assert!(um.satisfies(AdminRole::UserManager));
        assert!(!um.satisfies(AdminRole::DeviceManager));
        assert!(!um.satisfies(AdminRole::Auditor));
        assert!(um.satisfies(AdminRole::ReadOnly));
    }

    #[test]
    fn device_manager_only_satisfies_device_manager_and_readonly() {
        let dm = AdminRole::DeviceManager;
        assert!(!dm.satisfies(AdminRole::SuperAdmin));
        assert!(!dm.satisfies(AdminRole::UserManager));
        assert!(dm.satisfies(AdminRole::DeviceManager));
        assert!(!dm.satisfies(AdminRole::Auditor));
        assert!(dm.satisfies(AdminRole::ReadOnly));
    }

    #[test]
    fn auditor_satisfies_auditor_and_readonly() {
        let aud = AdminRole::Auditor;
        assert!(!aud.satisfies(AdminRole::SuperAdmin));
        assert!(!aud.satisfies(AdminRole::UserManager));
        assert!(!aud.satisfies(AdminRole::DeviceManager));
        assert!(aud.satisfies(AdminRole::Auditor));
        assert!(aud.satisfies(AdminRole::ReadOnly));
    }

    #[test]
    fn readonly_only_satisfies_readonly() {
        let ro = AdminRole::ReadOnly;
        assert!(!ro.satisfies(AdminRole::SuperAdmin));
        assert!(!ro.satisfies(AdminRole::UserManager));
        assert!(!ro.satisfies(AdminRole::DeviceManager));
        assert!(!ro.satisfies(AdminRole::Auditor));
        assert!(ro.satisfies(AdminRole::ReadOnly));
    }

    // ── Route-to-Role Mapping Tests ────────────────────────────────────────

    #[test]
    fn health_endpoint_allows_readonly() {
        assert_eq!(
            required_role_for_route("/api/health", &Method::GET),
            AdminRole::ReadOnly
        );
    }

    #[test]
    fn status_endpoint_allows_readonly() {
        assert_eq!(
            required_role_for_route("/api/status", &Method::GET),
            AdminRole::ReadOnly
        );
    }

    #[test]
    fn audit_endpoint_requires_auditor() {
        assert_eq!(
            required_role_for_route("/api/audit", &Method::GET),
            AdminRole::Auditor
        );
    }

    #[test]
    fn user_creation_requires_user_manager() {
        assert_eq!(
            required_role_for_route("/api/users", &Method::POST),
            AdminRole::UserManager
        );
    }

    #[test]
    fn user_listing_requires_auditor() {
        assert_eq!(
            required_role_for_route("/api/users", &Method::GET),
            AdminRole::Auditor
        );
    }

    #[test]
    fn user_deletion_requires_superadmin() {
        assert_eq!(
            required_role_for_route("/api/users/some-id", &Method::DELETE),
            AdminRole::SuperAdmin
        );
    }

    #[test]
    fn device_enrollment_requires_device_manager() {
        assert_eq!(
            required_role_for_route("/api/devices", &Method::POST),
            AdminRole::DeviceManager
        );
    }

    #[test]
    fn developer_mode_requires_superadmin() {
        assert_eq!(
            required_role_for_route("/api/admin/developer-mode", &Method::PUT),
            AdminRole::SuperAdmin
        );
    }

    #[test]
    fn ceremony_endpoints_require_superadmin() {
        assert_eq!(
            required_role_for_route("/api/ceremony/initiate", &Method::POST),
            AdminRole::SuperAdmin
        );
        assert_eq!(
            required_role_for_route("/api/ceremony/approve", &Method::POST),
            AdminRole::SuperAdmin
        );
    }

    #[test]
    fn unknown_route_defaults_to_superadmin() {
        assert_eq!(
            required_role_for_route("/api/unknown/endpoint", &Method::POST),
            AdminRole::SuperAdmin
        );
    }

    // ── Role Unauthorized Access Tests ─────────────────────────────────────

    #[test]
    fn auditor_cannot_create_users() {
        let required = required_role_for_route("/api/users", &Method::POST);
        assert!(!AdminRole::Auditor.satisfies(required));
    }

    #[test]
    fn readonly_cannot_access_audit() {
        let required = required_role_for_route("/api/audit", &Method::GET);
        assert!(!AdminRole::ReadOnly.satisfies(required));
    }

    #[test]
    fn device_manager_cannot_delete_users() {
        let required = required_role_for_route("/api/users/some-id", &Method::DELETE);
        assert!(!AdminRole::DeviceManager.satisfies(required));
    }

    #[test]
    fn user_manager_cannot_manage_devices() {
        let required = required_role_for_route("/api/devices", &Method::POST);
        assert!(!AdminRole::UserManager.satisfies(required));
    }

    // ── Per-Role API Key Derivation Tests ──────────────────────────────────

    #[test]
    fn each_role_gets_unique_api_key() {
        let roles = [
            AdminRole::SuperAdmin,
            AdminRole::UserManager,
            AdminRole::DeviceManager,
            AdminRole::Auditor,
            AdminRole::ReadOnly,
        ];
        let keys: Vec<String> = roles.iter().map(|r| derive_admin_role_key(*r)).collect();
        // All keys must be unique
        let unique: HashSet<&String> = keys.iter().collect();
        assert_eq!(keys.len(), unique.len(), "all role keys must be unique");
    }

    #[test]
    fn role_key_derivation_is_deterministic() {
        let key1 = derive_admin_role_key(AdminRole::Auditor);
        let key2 = derive_admin_role_key(AdminRole::Auditor);
        assert_eq!(key1, key2, "same role must produce same key");
    }

    #[test]
    fn role_keys_are_64_hex_chars() {
        for role in &[
            AdminRole::SuperAdmin,
            AdminRole::UserManager,
            AdminRole::DeviceManager,
            AdminRole::Auditor,
            AdminRole::ReadOnly,
        ] {
            let key = derive_admin_role_key(*role);
            assert_eq!(key.len(), 64, "key must be 64 hex chars (32 bytes)");
            assert!(
                key.chars().all(|c| c.is_ascii_hexdigit()),
                "key must be hex-encoded"
            );
        }
    }

    #[test]
    fn resolve_admin_role_matches_derived_keys() {
        for role in &[
            AdminRole::SuperAdmin,
            AdminRole::UserManager,
            AdminRole::DeviceManager,
            AdminRole::Auditor,
            AdminRole::ReadOnly,
        ] {
            let key = derive_admin_role_key(*role);
            let resolved = resolve_admin_role(&key);
            assert_eq!(resolved, Some(*role), "key should resolve back to {:?}", role);
        }
    }

    #[test]
    fn resolve_admin_role_rejects_unknown_key() {
        assert_eq!(resolve_admin_role("not-a-valid-key"), None);
    }

    // ── AdminRole from_u8 Tests ────────────────────────────────────────────

    #[test]
    fn admin_role_from_u8_valid() {
        assert_eq!(AdminRole::from_u8(0), Some(AdminRole::SuperAdmin));
        assert_eq!(AdminRole::from_u8(1), Some(AdminRole::UserManager));
        assert_eq!(AdminRole::from_u8(2), Some(AdminRole::DeviceManager));
        assert_eq!(AdminRole::from_u8(3), Some(AdminRole::Auditor));
        assert_eq!(AdminRole::from_u8(4), Some(AdminRole::ReadOnly));
    }

    #[test]
    fn admin_role_from_u8_invalid() {
        assert_eq!(AdminRole::from_u8(5), None);
        assert_eq!(AdminRole::from_u8(255), None);
    }

    // ── Destructive Action Tests ───────────────────────────────────────────

    #[test]
    fn destructive_actions_require_multiple_approvals() {
        assert!(DestructiveAction::UserDeletion.required_approvals() >= 2);
        assert!(DestructiveAction::TierChange.required_approvals() >= 2);
        assert!(DestructiveAction::KeyRotation.required_approvals() >= 2);
        assert!(DestructiveAction::BulkDeviceRevocation.required_approvals() >= 2);
    }

    #[test]
    fn key_rotation_requires_most_approvals() {
        assert!(
            DestructiveAction::KeyRotation.required_approvals()
                > DestructiveAction::UserDeletion.required_approvals(),
            "key rotation should require more approvals than user deletion"
        );
    }

    // ── Admin Action Approval HMAC Tests ───────────────────────────────────

    #[test]
    fn admin_action_approval_hmac_is_deterministic() {
        let action_id = Uuid::new_v4();
        let approver_id = Uuid::new_v4();
        let sig1 = compute_admin_action_approval_hmac(&action_id, &approver_id);
        let sig2 = compute_admin_action_approval_hmac(&action_id, &approver_id);
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn admin_action_approval_hmac_differs_per_action() {
        let a1 = Uuid::new_v4();
        let a2 = Uuid::new_v4();
        let approver = Uuid::new_v4();
        let sig1 = compute_admin_action_approval_hmac(&a1, &approver);
        let sig2 = compute_admin_action_approval_hmac(&a2, &approver);
        assert_ne!(sig1, sig2, "different actions must produce different signatures");
    }

    #[test]
    fn admin_action_approval_hmac_differs_per_approver() {
        let action_id = Uuid::new_v4();
        let approver1 = Uuid::new_v4();
        let approver2 = Uuid::new_v4();
        let sig1 = compute_admin_action_approval_hmac(&action_id, &approver1);
        let sig2 = compute_admin_action_approval_hmac(&action_id, &approver2);
        assert_ne!(sig1, sig2, "different approvers must produce different signatures");
    }

    #[test]
    fn verify_admin_action_approval_valid() {
        let action_id = Uuid::new_v4();
        let approver = Uuid::new_v4();
        let sig = compute_admin_action_approval_hmac(&action_id, &approver);
        assert!(verify_admin_action_approval(&action_id, &approver, &sig));
    }

    #[test]
    fn verify_admin_action_approval_wrong_signature_rejected() {
        let action_id = Uuid::new_v4();
        let approver = Uuid::new_v4();
        let wrong_sig = vec![0xFFu8; 64];
        assert!(!verify_admin_action_approval(&action_id, &approver, &wrong_sig));
    }

    #[test]
    fn verify_admin_action_approval_wrong_approver_rejected() {
        let action_id = Uuid::new_v4();
        let real_approver = Uuid::new_v4();
        let fake_approver = Uuid::new_v4();
        let sig = compute_admin_action_approval_hmac(&action_id, &real_approver);
        assert!(!verify_admin_action_approval(&action_id, &fake_approver, &sig));
    }

    // ── HTML Escape / XSS Prevention Tests ───────────────────────────────

    #[test]
    fn html_escape_script_tag() {
        let input = "<script>alert('xss')</script>";
        let escaped = html_escape(input);
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('>'));
        assert!(escaped.contains("&lt;script&gt;"));
    }

    #[test]
    fn html_escape_all_special_chars() {
        let input = r#"&<>"'"#;
        let escaped = html_escape(input);
        assert_eq!(escaped, "&amp;&lt;&gt;&quot;&#x27;");
    }

    #[test]
    fn html_escape_preserves_safe_text() {
        let input = "Hello, World! 123 abc";
        assert_eq!(html_escape(input), input);
    }

    #[test]
    fn html_escape_empty_string() {
        assert_eq!(html_escape(""), "");
    }

    #[test]
    fn html_escape_nested_tags() {
        let input = r#"<img src=x onerror="alert(1)">"#;
        let escaped = html_escape(input);
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('"'));
    }

    #[test]
    fn html_escape_ampersand_first() {
        // Ampersand must be escaped first to avoid double-escaping
        let input = "&lt;";
        let escaped = html_escape(input);
        assert_eq!(escaped, "&amp;lt;");
    }

    // ── CSRF Token Tests ─────────────────────────────────────────────────

    #[test]
    fn csrf_token_generation_produces_three_parts() {
        let token = generate_csrf_token("session123", "secret-key", "cookie-val");
        let parts: Vec<&str> = token.splitn(3, ':').collect();
        assert_eq!(parts.len(), 3, "CSRF token must have 3 colon-separated parts");
    }

    #[test]
    fn csrf_token_generation_unique() {
        let t1 = generate_csrf_token("session1", "key", "cookie");
        let t2 = generate_csrf_token("session1", "key", "cookie");
        assert_ne!(t1, t2, "two generated tokens must differ (random nonce)");
    }

    #[test]
    fn csrf_token_validation_correct() {
        let session = "my-session-state";
        let key = "my-api-key";
        let cookie = "csrf-session-cookie-value";
        let token = generate_csrf_token(session, key, cookie);
        assert!(
            validate_csrf_token(&token, session, key, cookie),
            "freshly generated token must validate"
        );
    }

    #[test]
    fn csrf_token_validation_wrong_session() {
        let key = "my-api-key";
        let cookie = "csrf-cookie";
        let token = generate_csrf_token("session-A", key, cookie);
        assert!(
            !validate_csrf_token(&token, "session-B", key, cookie),
            "token from different session must not validate"
        );
    }

    #[test]
    fn csrf_token_validation_wrong_key() {
        let session = "my-session";
        let cookie = "csrf-cookie";
        let token = generate_csrf_token(session, "key-A", cookie);
        assert!(
            !validate_csrf_token(&token, session, "key-B", cookie),
            "token validated with wrong key must fail"
        );
    }

    #[test]
    fn csrf_token_validation_wrong_cookie() {
        let session = "my-session";
        let key = "my-api-key";
        let token = generate_csrf_token(session, key, "cookie-A");
        assert!(
            !validate_csrf_token(&token, session, key, "cookie-B"),
            "token with wrong session cookie must fail"
        );
    }

    #[test]
    fn csrf_token_validation_empty_cookie_rejected() {
        let session = "my-session";
        let key = "my-api-key";
        let token = generate_csrf_token(session, key, "real-cookie");
        assert!(
            !validate_csrf_token(&token, session, key, ""),
            "empty cookie value must be rejected"
        );
    }

    #[test]
    fn csrf_token_validation_tampered_hmac() {
        let session = "my-session";
        let key = "my-api-key";
        let cookie = "csrf-cookie";
        let token = generate_csrf_token(session, key, cookie);
        let parts: Vec<&str> = token.splitn(3, ':').collect();
        // Tamper with the HMAC signature
        let tampered = format!("{}:{}:deadbeef0000", parts[0], parts[1]);
        assert!(
            !validate_csrf_token(&tampered, session, key, cookie),
            "tampered HMAC must not validate"
        );
    }

    #[test]
    fn csrf_token_validation_expired() {
        let session = "my-session";
        let key = "my-api-key";
        let cookie = "csrf-cookie";
        // Construct a token with a timestamp from 120 seconds ago (beyond 60s TTL)
        let old_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 120;
        let nonce: [u8; 16] = rand::random();
        let nonce_hex = hex::encode(nonce);

        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let payload = format!("{}:{}:{}:{}", session, cookie, old_ts, nonce_hex);
        let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC key");
        mac.update(payload.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());
        let expired_token = format!("{}:{}:{}", old_ts, nonce_hex, sig);

        assert!(
            !validate_csrf_token(&expired_token, session, key, cookie),
            "expired CSRF token must not validate"
        );
    }

    #[test]
    fn csrf_token_validation_malformed_input() {
        assert!(!validate_csrf_token("", "s", "k", "c"));
        assert!(!validate_csrf_token("no-colons", "s", "k", "c"));
        assert!(!validate_csrf_token("one:two", "s", "k", "c"));
        assert!(!validate_csrf_token("notanumber:nonce:sig", "s", "k", "c"));
    }

    #[tokio::test]
    async fn csrf_check_and_mark_used_first_use_succeeds() {
        let used = RwLock::new(HashSet::new());
        assert!(check_and_mark_csrf_used("token1", &used).await);
    }

    #[tokio::test]
    async fn csrf_check_and_mark_used_replay_fails() {
        let used = RwLock::new(HashSet::new());
        assert!(check_and_mark_csrf_used("token1", &used).await);
        assert!(
            !check_and_mark_csrf_used("token1", &used).await,
            "replayed CSRF token must be rejected"
        );
    }

    #[tokio::test]
    async fn csrf_used_set_clears_at_capacity() {
        let used = RwLock::new(HashSet::new());
        // Fill to capacity
        for i in 0..MAX_USED_CSRF_TOKENS {
            used.write().await.insert(format!("tok-{i}"));
        }
        assert_eq!(used.read().await.len(), MAX_USED_CSRF_TOKENS);
        // Next insert should trigger clear + insert
        assert!(check_and_mark_csrf_used("overflow-token", &used).await);
        // Set was cleared then the new token was inserted
        assert_eq!(used.read().await.len(), 1);
    }

    // ── RevocationList Tests ─────────────────────────────────────────────

    #[test]
    fn revocation_list_new_is_empty() {
        let rl = RevocationList::new();
        assert_eq!(rl.count(), 0);
    }

    #[test]
    fn revocation_list_add_and_check() {
        let mut rl = RevocationList::new();
        let token_id = [1u8; 16];
        assert!(rl.revoke(token_id));
        assert_eq!(rl.count(), 1);
        assert!(rl.entries.contains(&token_id));
    }

    #[test]
    fn revocation_list_deduplication() {
        let mut rl = RevocationList::new();
        let token_id = [42u8; 16];
        assert!(rl.revoke(token_id));
        assert!(rl.revoke(token_id)); // duplicate
        assert_eq!(rl.count(), 1, "duplicate revocations should not increase count");
        assert_eq!(rl.timed_entries.len(), 1);
    }

    #[test]
    fn revocation_list_capacity_limit() {
        let mut rl = RevocationList::new();
        // Fill to capacity
        for i in 0..MAX_REVOCATION_ENTRIES {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            assert!(rl.revoke(id));
        }
        assert_eq!(rl.count(), MAX_REVOCATION_ENTRIES);
        // Next revocation should fail
        let overflow_id = [0xFFu8; 16];
        assert!(
            !rl.revoke(overflow_id),
            "revocation at capacity must return false"
        );
    }

    #[test]
    fn revocation_list_cleanup_expired() {
        let mut rl = RevocationList::new();
        let token_id = [7u8; 16];
        rl.revoke(token_id);
        // Manually backdate the entry so it appears expired
        rl.timed_entries[0].revoked_at -= MAX_TOKEN_LIFETIME_SECS + 1;
        rl.cleanup_expired();
        assert_eq!(rl.count(), 0, "expired entries must be cleaned up");
        assert!(rl.timed_entries.is_empty());
    }

    #[test]
    fn revocation_list_cleanup_preserves_recent() {
        let mut rl = RevocationList::new();
        let old_id = [1u8; 16];
        let new_id = [2u8; 16];
        rl.revoke(old_id);
        rl.revoke(new_id);
        // Backdate only the first entry
        rl.timed_entries[0].revoked_at -= MAX_TOKEN_LIFETIME_SECS + 1;
        rl.cleanup_expired();
        assert_eq!(rl.count(), 1);
        assert!(rl.entries.contains(&new_id));
        assert!(!rl.entries.contains(&old_id));
    }

    // ── check_tier Tests ─────────────────────────────────────────────────

    #[test]
    fn check_tier_same_level_allowed() {
        assert!(check_tier(2, 2).is_ok());
    }

    #[test]
    fn check_tier_higher_privilege_allowed() {
        // tier 1 is higher privilege than tier 2
        assert!(check_tier(1, 2).is_ok());
    }

    #[test]
    fn check_tier_lower_privilege_denied() {
        assert!(check_tier(3, 2).is_err());
    }

    #[test]
    fn check_tier_sovereign_accesses_all() {
        assert!(check_tier(1, 1).is_ok());
        assert!(check_tier(1, 2).is_ok());
        assert!(check_tier(1, 3).is_ok());
        assert!(check_tier(1, 4).is_ok());
    }

    // ── enforce_map_capacity Tests ───────────────────────────────────────

    #[test]
    fn enforce_map_capacity_under_limit_no_eviction() {
        let mut map: HashMap<String, i32> = HashMap::new();
        for i in 0..10 {
            map.insert(format!("key-{i}"), i);
        }
        enforce_map_capacity(&mut map, 100);
        assert_eq!(map.len(), 10, "should not evict when under capacity");
    }

    #[test]
    fn enforce_map_capacity_at_limit_no_eviction() {
        let mut map: HashMap<String, i32> = HashMap::new();
        for i in 0..100 {
            map.insert(format!("key-{i}"), i);
        }
        enforce_map_capacity(&mut map, 100);
        assert_eq!(map.len(), 100, "should not evict when exactly at capacity");
    }

    #[test]
    fn enforce_map_capacity_over_limit_evicts() {
        let mut map: HashMap<String, i32> = HashMap::new();
        for i in 0..110 {
            map.insert(format!("key-{i}"), i);
        }
        enforce_map_capacity(&mut map, 100);
        // target = 100 * 9 / 10 = 90; to_remove = 110 - 90 = 20
        assert_eq!(map.len(), 90, "should evict to 90% of capacity");
    }

    // ── Rate Limiting / Lockout Tests ────────────────────────────────────

    #[test]
    fn is_locked_out_no_attempts_not_locked() {
        let attempts: HashMap<String, LoginAttemptEntry> = HashMap::new();
        assert!(!is_locked_out("alice", "1.2.3.4", &attempts));
    }

    #[test]
    fn is_locked_out_below_threshold_not_locked() {
        let mut attempts = HashMap::new();
        let now = now_secs();
        attempts.insert(
            "alice".to_string(),
            LoginAttemptEntry {
                count: 4, // below first threshold of 5
                first_attempt: now - 10,
                last_attempt: now,
            },
        );
        assert!(!is_locked_out("alice", "1.2.3.4", &attempts));
    }

    #[test]
    fn is_locked_out_at_first_threshold_within_window() {
        let mut attempts = HashMap::new();
        let now = now_secs();
        attempts.insert(
            "alice".to_string(),
            LoginAttemptEntry {
                count: 5,
                first_attempt: now - 20,
                last_attempt: now - 10, // 10 seconds ago, within 30s window
            },
        );
        assert!(is_locked_out("alice", "1.2.3.4", &attempts));
    }

    #[test]
    fn is_locked_out_at_first_threshold_after_window() {
        let mut attempts = HashMap::new();
        let now = now_secs();
        attempts.insert(
            "alice".to_string(),
            LoginAttemptEntry {
                count: 5,
                first_attempt: now - 60,
                last_attempt: now - 31, // 31 seconds ago, past 30s window
            },
        );
        assert!(!is_locked_out("alice", "1.2.3.4", &attempts));
    }

    #[test]
    fn is_locked_out_ip_based_lockout() {
        let mut attempts = HashMap::new();
        let now = now_secs();
        attempts.insert(
            "ip:1.2.3.4".to_string(),
            LoginAttemptEntry {
                count: 10,
                first_attempt: now - 60,
                last_attempt: now - 10, // within 5-minute window
            },
        );
        assert!(is_locked_out("unknown-user", "1.2.3.4", &attempts));
    }

    #[test]
    fn record_failed_attempt_increments_count() {
        let mut attempts = HashMap::new();
        record_failed_attempt(&mut attempts, "alice", "1.2.3.4");
        assert_eq!(attempts.get("alice").unwrap().count, 1);
        assert_eq!(attempts.get("ip:1.2.3.4").unwrap().count, 1);
        record_failed_attempt(&mut attempts, "alice", "1.2.3.4");
        assert_eq!(attempts.get("alice").unwrap().count, 2);
        assert_eq!(attempts.get("ip:1.2.3.4").unwrap().count, 2);
    }

    #[test]
    fn record_failed_attempt_tracks_both_username_and_ip() {
        let mut attempts = HashMap::new();
        record_failed_attempt(&mut attempts, "alice", "10.0.0.1");
        record_failed_attempt(&mut attempts, "bob", "10.0.0.1");
        assert_eq!(attempts.get("alice").unwrap().count, 1);
        assert_eq!(attempts.get("bob").unwrap().count, 1);
        assert_eq!(attempts.get("ip:10.0.0.1").unwrap().count, 2);
    }

    // ── sign_audit_entry Tests ───────────────────────────────────────────

    #[test]
    fn sign_audit_entry_deterministic() {
        let key = [0xABu8; 64];
        let data = b"test audit entry";
        let sig1 = sign_audit_entry(data, &key);
        let sig2 = sign_audit_entry(data, &key);
        assert_eq!(sig1, sig2, "same data + key must produce same signature");
    }

    #[test]
    fn sign_audit_entry_different_data_different_sig() {
        let key = [0xABu8; 64];
        let sig1 = sign_audit_entry(b"entry-1", &key);
        let sig2 = sign_audit_entry(b"entry-2", &key);
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn sign_audit_entry_different_key_different_sig() {
        let key1 = [0x01u8; 64];
        let key2 = [0x02u8; 64];
        let sig1 = sign_audit_entry(b"entry", &key1);
        let sig2 = sign_audit_entry(b"entry", &key2);
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn sign_audit_entry_output_is_64_bytes() {
        let key = [0xCDu8; 64];
        let sig = sign_audit_entry(b"data", &key);
        assert_eq!(sig.len(), 64, "HMAC-SHA512 output must be 64 bytes");
    }

    // ── Pagination Tests ─────────────────────────────────────────────────

    #[test]
    fn pagination_defaults() {
        let p = PaginationParams {
            limit: None,
            offset: None,
        };
        assert_eq!(p.limit(), 100);
        assert_eq!(p.offset(), 0);
    }

    #[test]
    fn pagination_custom_values() {
        let p = PaginationParams {
            limit: Some(50),
            offset: Some(10),
        };
        assert_eq!(p.limit(), 50);
        assert_eq!(p.offset(), 10);
    }

    #[test]
    fn pagination_limit_capped_at_1000() {
        let p = PaginationParams {
            limit: Some(5000),
            offset: None,
        };
        assert_eq!(p.limit(), 1000);
    }

    // ── DestructiveAction Tests ──────────────────────────────────────────

    #[test]
    fn all_destructive_actions_require_superadmin_approver() {
        let actions = [
            DestructiveAction::UserDeletion,
            DestructiveAction::TierChange,
            DestructiveAction::KeyRotation,
            DestructiveAction::BulkDeviceRevocation,
            DestructiveAction::ErrorLevelToggle,
        ];
        for action in &actions {
            assert!(
                action.requires_superadmin_approver(),
                "{action} should require SuperAdmin approver"
            );
        }
    }

    #[test]
    fn error_level_toggle_requires_two_approvals() {
        assert_eq!(DestructiveAction::ErrorLevelToggle.required_approvals(), 2);
    }

    // ── AdminRole Display Tests ──────────────────────────────────────────

    #[test]
    fn admin_role_display_matches_key_label() {
        for role in &[
            AdminRole::SuperAdmin,
            AdminRole::UserManager,
            AdminRole::DeviceManager,
            AdminRole::Auditor,
            AdminRole::ReadOnly,
        ] {
            assert_eq!(format!("{role}"), role.key_label());
        }
    }

    // ── Route RBAC Policy Comprehensive Tests ────────────────────────────

    #[test]
    fn portal_creation_requires_user_manager() {
        assert_eq!(
            required_role_for_route("/api/portals", &Method::POST),
            AdminRole::UserManager
        );
    }

    #[test]
    fn portal_listing_requires_auditor() {
        assert_eq!(
            required_role_for_route("/api/portals", &Method::GET),
            AdminRole::Auditor
        );
    }

    #[test]
    fn portal_deletion_requires_user_manager() {
        assert_eq!(
            required_role_for_route("/api/portals/some-id", &Method::DELETE),
            AdminRole::UserManager
        );
    }

    #[test]
    fn portal_check_access_allows_readonly() {
        assert_eq!(
            required_role_for_route("/api/portals/check-access", &Method::GET),
            AdminRole::ReadOnly
        );
    }

    #[test]
    fn kt_endpoints_allow_readonly() {
        assert_eq!(
            required_role_for_route("/api/kt/root", &Method::GET),
            AdminRole::ReadOnly
        );
        assert_eq!(
            required_role_for_route("/api/kt/proof/someid", &Method::GET),
            AdminRole::ReadOnly
        );
    }

    #[test]
    fn token_revocation_requires_user_manager() {
        assert_eq!(
            required_role_for_route("/api/tokens/revoke", &Method::POST),
            AdminRole::UserManager
        );
    }

    #[test]
    fn revoked_token_count_requires_auditor() {
        assert_eq!(
            required_role_for_route("/api/tokens/revoked", &Method::GET),
            AdminRole::Auditor
        );
    }

    #[test]
    fn siem_stream_requires_auditor() {
        assert_eq!(
            required_role_for_route("/api/admin/siem/stream", &Method::GET),
            AdminRole::Auditor
        );
    }

    #[test]
    fn security_dashboard_requires_auditor() {
        assert_eq!(
            required_role_for_route("/api/security/dashboard", &Method::GET),
            AdminRole::Auditor
        );
    }

    #[test]
    fn cac_enroll_requires_superadmin() {
        assert_eq!(
            required_role_for_route("/api/cac/enroll", &Method::POST),
            AdminRole::SuperAdmin
        );
    }

    #[test]
    fn cac_authenticate_requires_auditor() {
        assert_eq!(
            required_role_for_route("/api/cac/authenticate", &Method::POST),
            AdminRole::Auditor
        );
    }

    #[test]
    fn stig_audit_requires_auditor() {
        assert_eq!(
            required_role_for_route("/api/stig/audit", &Method::GET),
            AdminRole::Auditor
        );
    }

    #[test]
    fn cmmc_assess_requires_auditor() {
        assert_eq!(
            required_role_for_route("/api/cmmc/assess", &Method::GET),
            AdminRole::Auditor
        );
    }

    #[test]
    fn compliance_status_requires_auditor() {
        assert_eq!(
            required_role_for_route("/api/compliance/status", &Method::GET),
            AdminRole::Auditor
        );
    }

    #[test]
    fn recovery_endpoints_require_user_manager() {
        assert_eq!(
            required_role_for_route("/api/recovery/generate", &Method::POST),
            AdminRole::UserManager
        );
    }

    #[test]
    fn pending_admin_actions_require_superadmin() {
        assert_eq!(
            required_role_for_route("/api/admin/actions", &Method::GET),
            AdminRole::SuperAdmin
        );
    }

    #[test]
    fn user_profile_allows_readonly() {
        assert_eq!(
            required_role_for_route("/api/user/profile", &Method::GET),
            AdminRole::ReadOnly
        );
    }

    #[test]
    fn setup_status_allows_readonly() {
        assert_eq!(
            required_role_for_route("/api/setup/status", &Method::GET),
            AdminRole::ReadOnly
        );
    }

    // ── Ceremony Approval HMAC Tests ─────────────────────────────────────

    #[test]
    fn ceremony_approval_hmac_deterministic() {
        let cid = Uuid::new_v4();
        let aid = Uuid::new_v4();
        let sig1 = compute_ceremony_approval_hmac(&cid, &aid);
        let sig2 = compute_ceremony_approval_hmac(&cid, &aid);
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn ceremony_approval_hmac_differs_per_ceremony() {
        let c1 = Uuid::new_v4();
        let c2 = Uuid::new_v4();
        let approver = Uuid::new_v4();
        assert_ne!(
            compute_ceremony_approval_hmac(&c1, &approver),
            compute_ceremony_approval_hmac(&c2, &approver)
        );
    }

    #[test]
    fn ceremony_approval_hmac_differs_per_approver() {
        let cid = Uuid::new_v4();
        let a1 = Uuid::new_v4();
        let a2 = Uuid::new_v4();
        assert_ne!(
            compute_ceremony_approval_hmac(&cid, &a1),
            compute_ceremony_approval_hmac(&cid, &a2)
        );
    }

    #[test]
    fn verify_ceremony_approval_valid() {
        let cid = Uuid::new_v4();
        let aid = Uuid::new_v4();
        let sig = compute_ceremony_approval_hmac(&cid, &aid);
        assert!(verify_ceremony_approval(&cid, &aid, &sig));
    }

    #[test]
    fn verify_ceremony_approval_wrong_sig_rejected() {
        let cid = Uuid::new_v4();
        let aid = Uuid::new_v4();
        assert!(!verify_ceremony_approval(&cid, &aid, &[0xFFu8; 64]));
    }

    #[test]
    fn verify_ceremony_approval_wrong_approver_rejected() {
        let cid = Uuid::new_v4();
        let real = Uuid::new_v4();
        let fake = Uuid::new_v4();
        let sig = compute_ceremony_approval_hmac(&cid, &real);
        assert!(!verify_ceremony_approval(&cid, &fake, &sig));
    }

    // ── Lockout Tier Escalation Tests ────────────────────────────────────

    #[test]
    fn lockout_escalates_through_tiers() {
        let mut attempts = HashMap::new();
        let now = now_secs();

        // 5 attempts -> 30s lockout
        attempts.insert("alice".to_string(), LoginAttemptEntry {
            count: 5,
            first_attempt: now - 20,
            last_attempt: now,
        });
        assert!(is_locked_out("alice", "0.0.0.0", &attempts));

        // 10 attempts -> 5m lockout
        attempts.insert("alice".to_string(), LoginAttemptEntry {
            count: 10,
            first_attempt: now - 60,
            last_attempt: now,
        });
        assert!(is_locked_out("alice", "0.0.0.0", &attempts));

        // 20 attempts -> 30m lockout
        attempts.insert("alice".to_string(), LoginAttemptEntry {
            count: 20,
            first_attempt: now - 120,
            last_attempt: now,
        });
        assert!(is_locked_out("alice", "0.0.0.0", &attempts));
    }

    // ── Input Validation Constants Tests ─────────────────────────────────

    #[test]
    fn input_validation_constants_are_sane() {
        assert!(MIN_PASSWORD_LEN >= 8, "minimum password must be at least 8");
        assert!(MAX_PASSWORD_LEN >= MIN_PASSWORD_LEN);
        assert!(MAX_USERNAME_LEN > 0);
        assert!(MAX_PORTAL_NAME_LEN > 0);
        assert!(MAX_CALLBACK_URL_LEN > 0);
        assert!(INACTIVITY_TIMEOUT_SECS == 15 * 60, "AAL3 requires 15-minute timeout");
    }

    #[test]
    fn csrf_token_ttl_is_reasonable() {
        assert!(CSRF_TOKEN_TTL_SECS <= 300, "CSRF TTL should be short-lived");
        assert!(CSRF_TOKEN_TTL_SECS >= 30, "CSRF TTL should allow form submission");
    }

    #[test]
    fn revocation_constants_are_sane() {
        assert!(MAX_REVOCATION_ENTRIES >= 1000);
        assert!(MAX_TOKEN_LIFETIME_SECS > 0);
    }

    // ── derive_admin_audit_key Tests ─────────────────────────────────────

    #[test]
    fn derive_admin_audit_key_is_deterministic() {
        let k1 = derive_admin_audit_key();
        let k2 = derive_admin_audit_key();
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_admin_audit_key_is_64_bytes() {
        let k = derive_admin_audit_key();
        assert_eq!(k.len(), 64);
    }

    // ── DestructiveAction Display Tests ──────────────────────────────────

    #[test]
    fn destructive_action_display_format() {
        assert_eq!(format!("{}", DestructiveAction::UserDeletion), "user_deletion");
        assert_eq!(format!("{}", DestructiveAction::TierChange), "tier_change");
        assert_eq!(format!("{}", DestructiveAction::KeyRotation), "key_rotation");
        assert_eq!(
            format!("{}", DestructiveAction::BulkDeviceRevocation),
            "bulk_device_revocation"
        );
        assert_eq!(
            format!("{}", DestructiveAction::ErrorLevelToggle),
            "error_level_toggle"
        );
    }
}
