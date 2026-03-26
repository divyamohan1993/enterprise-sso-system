//! Delegated Administration for the MILNET SSO system.
//!
//! Provides:
//! - Admin hierarchy: GlobalAdmin > TenantAdmin > UserManager > ReadOnly
//! - TenantAdmin role: manage users within own tenant only
//! - Delegated permissions: user CRUD, device management, MFA enrollment, policy management
//! - Scope enforcement: all operations filtered by tenant_id
//! - Audit logging for all delegated admin actions
//! - Admin invitation workflow
//! - Admin activity dashboard data
//! - Rate limiting per admin
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

use crate::multi_tenancy::TenantId;
use crate::siem::SecurityEvent;

// ── Admin Role Hierarchy ────────────────────────────────────────────────────

/// Admin role levels (ordered by privilege, highest first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AdminRole {
    /// Read-only access to dashboards and reports within scope.
    ReadOnly = 0,
    /// Can manage individual users within assigned tenant.
    UserManager = 1,
    /// Full admin of a single tenant (users, devices, MFA, policies).
    TenantAdmin = 2,
    /// Global system administrator with unrestricted access.
    GlobalAdmin = 3,
}

impl AdminRole {
    /// Return the human-readable label for this role.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::UserManager => "user_manager",
            Self::TenantAdmin => "tenant_admin",
            Self::GlobalAdmin => "global_admin",
        }
    }

    /// Parse a role from its string representation.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "read_only" => Some(Self::ReadOnly),
            "user_manager" => Some(Self::UserManager),
            "tenant_admin" => Some(Self::TenantAdmin),
            "global_admin" => Some(Self::GlobalAdmin),
            _ => None,
        }
    }

    /// Check if this role has at least the given privilege level.
    pub fn has_at_least(&self, required: AdminRole) -> bool {
        (*self as u8) >= (required as u8)
    }
}

impl std::fmt::Display for AdminRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ── Delegated Permissions ───────────────────────────────────────────────────

/// Fine-grained permissions that can be delegated to admin roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    /// Create new users.
    UserCreate,
    /// Read/list users.
    UserRead,
    /// Update user properties.
    UserUpdate,
    /// Delete/deactivate users.
    UserDelete,
    /// Manage user devices.
    DeviceManage,
    /// Enroll MFA for users.
    MfaEnroll,
    /// Reset MFA for users.
    MfaReset,
    /// Manage tenant policies.
    PolicyManage,
    /// View policies (read-only).
    PolicyRead,
    /// Manage admin roles (invite, revoke).
    AdminManage,
    /// View audit logs.
    AuditRead,
    /// Export audit logs.
    AuditExport,
    /// View dashboards and reports.
    DashboardRead,
    /// Manage tenant configuration.
    TenantConfigManage,
    /// Manage sessions (view, revoke).
    SessionManage,
}

impl Permission {
    /// Return the string key for this permission.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UserCreate => "user:create",
            Self::UserRead => "user:read",
            Self::UserUpdate => "user:update",
            Self::UserDelete => "user:delete",
            Self::DeviceManage => "device:manage",
            Self::MfaEnroll => "mfa:enroll",
            Self::MfaReset => "mfa:reset",
            Self::PolicyManage => "policy:manage",
            Self::PolicyRead => "policy:read",
            Self::AdminManage => "admin:manage",
            Self::AuditRead => "audit:read",
            Self::AuditExport => "audit:export",
            Self::DashboardRead => "dashboard:read",
            Self::TenantConfigManage => "tenant_config:manage",
            Self::SessionManage => "session:manage",
        }
    }
}

/// Return the default permissions for a given admin role.
pub fn default_permissions(role: AdminRole) -> Vec<Permission> {
    match role {
        AdminRole::ReadOnly => vec![
            Permission::UserRead,
            Permission::PolicyRead,
            Permission::AuditRead,
            Permission::DashboardRead,
        ],
        AdminRole::UserManager => vec![
            Permission::UserCreate,
            Permission::UserRead,
            Permission::UserUpdate,
            Permission::UserDelete,
            Permission::DeviceManage,
            Permission::MfaEnroll,
            Permission::MfaReset,
            Permission::PolicyRead,
            Permission::AuditRead,
            Permission::DashboardRead,
            Permission::SessionManage,
        ],
        AdminRole::TenantAdmin => vec![
            Permission::UserCreate,
            Permission::UserRead,
            Permission::UserUpdate,
            Permission::UserDelete,
            Permission::DeviceManage,
            Permission::MfaEnroll,
            Permission::MfaReset,
            Permission::PolicyManage,
            Permission::PolicyRead,
            Permission::AdminManage,
            Permission::AuditRead,
            Permission::AuditExport,
            Permission::DashboardRead,
            Permission::TenantConfigManage,
            Permission::SessionManage,
        ],
        AdminRole::GlobalAdmin => vec![
            Permission::UserCreate,
            Permission::UserRead,
            Permission::UserUpdate,
            Permission::UserDelete,
            Permission::DeviceManage,
            Permission::MfaEnroll,
            Permission::MfaReset,
            Permission::PolicyManage,
            Permission::PolicyRead,
            Permission::AdminManage,
            Permission::AuditRead,
            Permission::AuditExport,
            Permission::DashboardRead,
            Permission::TenantConfigManage,
            Permission::SessionManage,
        ],
    }
}

// ── Admin Identity ──────────────────────────────────────────────────────────

/// Represents an admin user with role and scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminIdentity {
    /// Admin user ID.
    pub user_id: Uuid,
    /// Admin role.
    pub role: AdminRole,
    /// Tenant scope (None for GlobalAdmin = all tenants).
    pub tenant_id: Option<TenantId>,
    /// Explicit permission overrides (beyond role defaults).
    pub extra_permissions: Vec<Permission>,
    /// Permissions explicitly denied (override role defaults).
    pub denied_permissions: Vec<Permission>,
    /// Display name.
    pub display_name: String,
    /// Email address.
    pub email: String,
    /// Whether the admin account is active.
    pub active: bool,
    /// When the admin was created (epoch seconds).
    pub created_at: i64,
    /// Last activity timestamp (epoch seconds).
    pub last_active_at: Option<i64>,
}

impl AdminIdentity {
    /// Check if this admin has a specific permission.
    pub fn has_permission(&self, perm: Permission) -> bool {
        if !self.active {
            return false;
        }
        // Denied permissions always take precedence
        if self.denied_permissions.contains(&perm) {
            return false;
        }
        // Check explicit grants first, then role defaults
        if self.extra_permissions.contains(&perm) {
            return true;
        }
        default_permissions(self.role).contains(&perm)
    }

    /// Check if this admin can operate on the given tenant.
    pub fn can_access_tenant(&self, target_tenant: &TenantId) -> bool {
        if !self.active {
            return false;
        }
        match self.role {
            AdminRole::GlobalAdmin => true, // Global admins can access any tenant
            _ => {
                // Non-global admins can only access their assigned tenant
                self.tenant_id
                    .as_ref()
                    .map(|t| t == target_tenant)
                    .unwrap_or(false)
            }
        }
    }

    /// Get the effective set of permissions for this admin.
    pub fn effective_permissions(&self) -> Vec<Permission> {
        if !self.active {
            return Vec::new();
        }
        let mut perms = default_permissions(self.role);
        for p in &self.extra_permissions {
            if !perms.contains(p) {
                perms.push(*p);
            }
        }
        perms.retain(|p| !self.denied_permissions.contains(p));
        perms
    }
}

// ── Scope Enforcement ───────────────────────────────────────────────────────

/// Scope-enforced operation context.
///
/// All delegated admin operations MUST go through this context
/// to ensure tenant isolation and permission checks.
pub struct AdminOperationContext {
    /// The admin performing the operation.
    pub admin: AdminIdentity,
    /// Target tenant ID for the operation.
    pub target_tenant: TenantId,
    /// Source IP of the admin request.
    pub source_ip: Option<String>,
    /// Request ID for audit correlation.
    pub request_id: String,
}

impl AdminOperationContext {
    /// Create a new operation context with scope validation.
    pub fn new(
        admin: AdminIdentity,
        target_tenant: TenantId,
        source_ip: Option<String>,
    ) -> Result<Self, String> {
        if !admin.active {
            return Err("admin account is deactivated".to_string());
        }

        if !admin.can_access_tenant(&target_tenant) {
            SecurityEvent::delegated_admin_scope_violation(
                &admin.user_id,
                &target_tenant,
                admin.tenant_id.as_ref(),
            );
            return Err(format!(
                "admin '{}' does not have access to tenant '{}'",
                admin.user_id, target_tenant
            ));
        }

        Ok(Self {
            admin,
            target_tenant,
            source_ip,
            request_id: Uuid::new_v4().to_string(),
        })
    }

    /// Require a specific permission for the current operation.
    pub fn require_permission(&self, perm: Permission) -> Result<(), String> {
        if !self.admin.has_permission(perm) {
            SecurityEvent::delegated_admin_permission_denied(
                &self.admin.user_id,
                perm.as_str(),
                &self.target_tenant,
            );
            return Err(format!(
                "admin '{}' lacks permission '{}'",
                self.admin.user_id,
                perm.as_str()
            ));
        }
        Ok(())
    }

    /// Require that the admin has at least the given role level.
    pub fn require_role(&self, minimum_role: AdminRole) -> Result<(), String> {
        if !self.admin.role.has_at_least(minimum_role) {
            return Err(format!(
                "operation requires at least '{}' role, admin has '{}'",
                minimum_role, self.admin.role
            ));
        }
        Ok(())
    }

    /// Log an admin action for audit.
    pub fn audit_log(&self, action: &str, target: &str, detail: Option<&str>) {
        SecurityEvent::delegated_admin_action(
            &self.admin.user_id,
            &self.admin.role,
            &self.target_tenant,
            action,
            target,
            detail,
            self.source_ip.as_deref(),
        );
    }
}

// ── Admin Invitation ────────────────────────────────────────────────────────

/// Status of an admin invitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvitationStatus {
    /// Invitation sent, awaiting acceptance.
    Pending,
    /// Invitation accepted and admin account created.
    Accepted,
    /// Invitation expired.
    Expired,
    /// Invitation revoked by an admin.
    Revoked,
}

impl std::fmt::Display for InvitationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Accepted => write!(f, "accepted"),
            Self::Expired => write!(f, "expired"),
            Self::Revoked => write!(f, "revoked"),
        }
    }
}

/// An invitation for a new admin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminInvitation {
    /// Invitation ID.
    pub id: String,
    /// Invitee email address.
    pub email: String,
    /// Assigned role.
    pub role: AdminRole,
    /// Target tenant (None for GlobalAdmin).
    pub tenant_id: Option<TenantId>,
    /// Who sent the invitation.
    pub invited_by: Uuid,
    /// Invitation token (sent to invitee).
    #[serde(skip_serializing)]
    pub token: String,
    /// Status.
    pub status: InvitationStatus,
    /// Creation timestamp.
    pub created_at: i64,
    /// Expiry timestamp (48 hours from creation by default).
    pub expires_at: i64,
}

// ── Admin Rate Limiter ──────────────────────────────────────────────────────

/// Per-admin rate limiter.
struct AdminRateLimiter {
    /// Map of admin user ID -> (action count in current window, window start).
    windows: HashMap<Uuid, (u32, i64)>,
}

impl AdminRateLimiter {
    fn new() -> Self {
        Self {
            windows: HashMap::new(),
        }
    }

    /// Check if the admin is within rate limits.
    /// Returns true if allowed, false if rate-limited.
    fn check(&mut self, admin_id: &Uuid, limit_per_minute: u32) -> bool {
        let now = now_epoch();
        let window_start = now - (now % 60);

        let entry = self
            .windows
            .entry(*admin_id)
            .or_insert((0, window_start));

        if entry.1 < window_start {
            *entry = (0, window_start);
        }

        if entry.0 >= limit_per_minute {
            return false;
        }

        entry.0 += 1;
        true
    }

    /// Evict stale entries.
    fn evict_stale(&mut self) {
        let cutoff = now_epoch() - 120;
        self.windows.retain(|_, (_, start)| *start > cutoff);
    }
}

// ── Admin Activity Dashboard ────────────────────────────────────────────────

/// Summary of an admin's recent activity for the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminActivitySummary {
    /// Admin user ID.
    pub admin_id: Uuid,
    /// Admin display name.
    pub display_name: String,
    /// Admin role.
    pub role: AdminRole,
    /// Total actions in the reporting period.
    pub total_actions: u64,
    /// Actions broken down by type.
    pub actions_by_type: HashMap<String, u64>,
    /// Last action timestamp.
    pub last_action_at: Option<i64>,
    /// Scope violations count.
    pub scope_violations: u64,
    /// Permission denials count.
    pub permission_denials: u64,
}

/// Aggregated dashboard data for all admins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminDashboardData {
    /// Total admins.
    pub total_admins: u64,
    /// Active admins (active in last 24h).
    pub active_admins_24h: u64,
    /// Pending invitations.
    pub pending_invitations: u64,
    /// Per-admin activity summaries.
    pub admin_activities: Vec<AdminActivitySummary>,
    /// Breakdown by role.
    pub admins_by_role: HashMap<String, u64>,
    /// Recent scope violations.
    pub recent_violations: u64,
}

// ── Delegated Admin Store ───────────────────────────────────────────────────

/// In-memory store for delegated admin management.
/// In production, this would be backed by a database.
pub struct DelegatedAdminStore {
    /// Registered admins keyed by user ID.
    admins: RwLock<HashMap<Uuid, AdminIdentity>>,
    /// Pending invitations keyed by invitation ID.
    invitations: RwLock<HashMap<String, AdminInvitation>>,
    /// Rate limiter.
    rate_limiter: RwLock<AdminRateLimiter>,
    /// Audit log (recent entries, bounded).
    audit_log: RwLock<Vec<AdminAuditEntry>>,
    /// Default rate limit per admin (actions per minute).
    default_rate_limit: u32,
    /// Maximum audit log entries to keep.
    max_audit_entries: usize,
}

/// An admin audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminAuditEntry {
    /// Entry ID.
    pub id: String,
    /// Admin user ID.
    pub admin_id: Uuid,
    /// Admin role.
    pub role: AdminRole,
    /// Tenant scope.
    pub tenant_id: TenantId,
    /// Action performed.
    pub action: String,
    /// Target entity (e.g., user ID, policy ID).
    pub target: String,
    /// Additional detail.
    pub detail: Option<String>,
    /// Source IP.
    pub source_ip: Option<String>,
    /// Timestamp (epoch seconds).
    pub timestamp: i64,
    /// Whether the action succeeded.
    pub success: bool,
}

impl DelegatedAdminStore {
    /// Create a new delegated admin store.
    pub fn new() -> Self {
        Self {
            admins: RwLock::new(HashMap::new()),
            invitations: RwLock::new(HashMap::new()),
            rate_limiter: RwLock::new(AdminRateLimiter::new()),
            audit_log: RwLock::new(Vec::new()),
            default_rate_limit: 120, // 120 actions/min
            max_audit_entries: 50_000,
        }
    }

    // ── Admin CRUD ──────────────────────────────────────────────────────

    /// Register a new admin (typically called after invitation acceptance).
    pub fn register_admin(&self, admin: AdminIdentity) -> Result<(), String> {
        let mut admins = self
            .admins
            .write()
            .map_err(|_| "admins lock poisoned".to_string())?;

        if admins.len() >= 10_000 {
            return Err("maximum admin count exceeded".to_string());
        }

        if admins.contains_key(&admin.user_id) {
            return Err(format!("admin '{}' already registered", admin.user_id));
        }

        // Validate: non-GlobalAdmin must have a tenant
        if admin.role != AdminRole::GlobalAdmin && admin.tenant_id.is_none() {
            return Err("non-GlobalAdmin must be scoped to a tenant".to_string());
        }

        let uid = admin.user_id;
        let role = admin.role;
        admins.insert(uid, admin);

        SecurityEvent::delegated_admin_registered(&uid, &role);
        Ok(())
    }

    /// Get an admin by user ID.
    pub fn get_admin(&self, user_id: &Uuid) -> Result<Option<AdminIdentity>, String> {
        let admins = self
            .admins
            .read()
            .map_err(|_| "admins lock poisoned".to_string())?;
        Ok(admins.get(user_id).cloned())
    }

    /// List all admins, optionally filtered by tenant.
    pub fn list_admins(&self, tenant_filter: Option<&TenantId>) -> Result<Vec<AdminIdentity>, String> {
        let admins = self
            .admins
            .read()
            .map_err(|_| "admins lock poisoned".to_string())?;

        let result: Vec<_> = admins
            .values()
            .filter(|a| {
                tenant_filter
                    .map(|t| a.tenant_id.as_ref() == Some(t) || a.role == AdminRole::GlobalAdmin)
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        Ok(result)
    }

    /// Update an admin's role (requires higher privilege).
    pub fn update_admin_role(
        &self,
        ctx: &AdminOperationContext,
        target_user_id: &Uuid,
        new_role: AdminRole,
    ) -> Result<(), String> {
        ctx.require_permission(Permission::AdminManage)?;

        // Cannot promote to a role higher than your own
        if new_role > ctx.admin.role {
            return Err(format!(
                "cannot promote to '{}' (your role: '{}')",
                new_role, ctx.admin.role
            ));
        }

        let mut admins = self
            .admins
            .write()
            .map_err(|_| "admins lock poisoned".to_string())?;

        let target = admins
            .get_mut(target_user_id)
            .ok_or_else(|| format!("admin '{}' not found", target_user_id))?;

        // Cannot modify an admin with higher or equal role (unless GlobalAdmin)
        if target.role >= ctx.admin.role && ctx.admin.role != AdminRole::GlobalAdmin {
            return Err("cannot modify an admin with equal or higher privilege".to_string());
        }

        let old_role = target.role;
        target.role = new_role;
        target.updated_at_epoch(now_epoch());

        ctx.audit_log(
            "role_update",
            &target_user_id.to_string(),
            Some(&format!("{} -> {}", old_role, new_role)),
        );

        Ok(())
    }

    /// Deactivate an admin account.
    pub fn deactivate_admin(
        &self,
        ctx: &AdminOperationContext,
        target_user_id: &Uuid,
    ) -> Result<(), String> {
        ctx.require_permission(Permission::AdminManage)?;

        let mut admins = self
            .admins
            .write()
            .map_err(|_| "admins lock poisoned".to_string())?;

        let target = admins
            .get_mut(target_user_id)
            .ok_or_else(|| format!("admin '{}' not found", target_user_id))?;

        if target.role >= ctx.admin.role && ctx.admin.role != AdminRole::GlobalAdmin {
            return Err("cannot deactivate an admin with equal or higher privilege".to_string());
        }

        target.active = false;

        ctx.audit_log("admin_deactivated", &target_user_id.to_string(), None);
        Ok(())
    }

    // ── Invitation Workflow ─────────────────────────────────────────────

    /// Create an admin invitation.
    pub fn create_invitation(
        &self,
        ctx: &AdminOperationContext,
        email: &str,
        role: AdminRole,
        tenant_id: Option<TenantId>,
    ) -> Result<AdminInvitation, String> {
        ctx.require_permission(Permission::AdminManage)?;

        // Cannot invite to a role higher than your own
        if role > ctx.admin.role {
            return Err(format!(
                "cannot invite with role '{}' (your role: '{}')",
                role, ctx.admin.role
            ));
        }

        if email.is_empty() || !email.contains('@') {
            return Err("invalid email address".to_string());
        }

        let mut invitations = self
            .invitations
            .write()
            .map_err(|_| "invitations lock poisoned".to_string())?;

        // Check for duplicate pending invitation
        if invitations
            .values()
            .any(|i| i.email == email && i.status == InvitationStatus::Pending)
        {
            return Err(format!(
                "pending invitation already exists for '{}'",
                email
            ));
        }

        // Bound invitations
        if invitations.len() >= 1_000 {
            // Evict expired
            let now = now_epoch();
            invitations.retain(|_, i| {
                i.status == InvitationStatus::Pending && i.expires_at > now
            });
        }

        let now = now_epoch();
        let invitation = AdminInvitation {
            id: Uuid::new_v4().to_string(),
            email: email.to_string(),
            role,
            tenant_id,
            invited_by: ctx.admin.user_id,
            token: generate_invitation_token(),
            status: InvitationStatus::Pending,
            created_at: now,
            expires_at: now + 48 * 3600, // 48 hours
        };

        let result = invitation.clone();
        invitations.insert(invitation.id.clone(), invitation);

        ctx.audit_log(
            "admin_invited",
            email,
            Some(&format!("role={} invitation_id={}", role, result.id)),
        );

        Ok(result)
    }

    /// Accept an invitation and create the admin account.
    pub fn accept_invitation(
        &self,
        invitation_id: &str,
        token: &str,
        user_id: Uuid,
        display_name: &str,
    ) -> Result<AdminIdentity, String> {
        let mut invitations = self
            .invitations
            .write()
            .map_err(|_| "invitations lock poisoned".to_string())?;

        let invitation = invitations
            .get_mut(invitation_id)
            .ok_or("invitation not found")?;

        if invitation.status != InvitationStatus::Pending {
            return Err(format!(
                "invitation is no longer pending (status: {})",
                invitation.status
            ));
        }

        if invitation.expires_at < now_epoch() {
            invitation.status = InvitationStatus::Expired;
            return Err("invitation has expired".to_string());
        }

        // Constant-time token comparison
        // Constant-time token comparison
        use subtle::ConstantTimeEq;
        if !bool::from(invitation.token.as_bytes().ct_eq(token.as_bytes())) {
            return Err("invalid invitation token".to_string());
        }

        invitation.status = InvitationStatus::Accepted;

        let admin = AdminIdentity {
            user_id,
            role: invitation.role,
            tenant_id: invitation.tenant_id,
            extra_permissions: Vec::new(),
            denied_permissions: Vec::new(),
            display_name: display_name.to_string(),
            email: invitation.email.clone(),
            active: true,
            created_at: now_epoch(),
            last_active_at: None,
        };

        // Register the admin (drop invitations lock first to avoid deadlock)
        let admin_clone = admin.clone();
        drop(invitations);
        self.register_admin(admin_clone)?;

        Ok(admin)
    }

    /// Revoke a pending invitation.
    pub fn revoke_invitation(
        &self,
        ctx: &AdminOperationContext,
        invitation_id: &str,
    ) -> Result<(), String> {
        ctx.require_permission(Permission::AdminManage)?;

        let mut invitations = self
            .invitations
            .write()
            .map_err(|_| "invitations lock poisoned".to_string())?;

        let invitation = invitations
            .get_mut(invitation_id)
            .ok_or("invitation not found")?;

        if invitation.status != InvitationStatus::Pending {
            return Err("can only revoke pending invitations".to_string());
        }

        invitation.status = InvitationStatus::Revoked;

        ctx.audit_log("invitation_revoked", invitation_id, None);
        Ok(())
    }

    /// List invitations, optionally filtered by status.
    pub fn list_invitations(
        &self,
        status_filter: Option<InvitationStatus>,
    ) -> Result<Vec<AdminInvitation>, String> {
        let invitations = self
            .invitations
            .read()
            .map_err(|_| "invitations lock poisoned".to_string())?;

        let result: Vec<_> = invitations
            .values()
            .filter(|i| status_filter.map(|s| i.status == s).unwrap_or(true))
            .cloned()
            .collect();
        Ok(result)
    }

    // ── Rate Limiting ───────────────────────────────────────────────────

    /// Check if an admin action is within rate limits.
    pub fn check_rate_limit(&self, admin_id: &Uuid) -> Result<(), String> {
        let mut rl = self
            .rate_limiter
            .write()
            .map_err(|_| "rate limiter lock poisoned".to_string())?;

        if !rl.check(admin_id, self.default_rate_limit) {
            SecurityEvent::admin_rate_limited(admin_id);
            return Err(format!(
                "admin '{}' rate limit exceeded ({}/min)",
                admin_id, self.default_rate_limit
            ));
        }

        // Periodic cleanup
        if rl.windows.len() > 1000 {
            rl.evict_stale();
        }

        Ok(())
    }

    // ── Audit Log ───────────────────────────────────────────────────────

    /// Record an admin audit entry.
    pub fn record_audit(
        &self,
        admin_id: Uuid,
        role: AdminRole,
        tenant_id: TenantId,
        action: &str,
        target: &str,
        detail: Option<&str>,
        source_ip: Option<&str>,
        success: bool,
    ) -> Result<(), String> {
        let mut log = self
            .audit_log
            .write()
            .map_err(|_| "audit log lock poisoned".to_string())?;

        if log.len() >= self.max_audit_entries {
            let quarter = log.len() / 4;
            log.drain(0..quarter); // Remove oldest 25%
        }

        log.push(AdminAuditEntry {
            id: Uuid::new_v4().to_string(),
            admin_id,
            role,
            tenant_id,
            action: action.to_string(),
            target: target.to_string(),
            detail: detail.map(|s| s.to_string()),
            source_ip: source_ip.map(|s| s.to_string()),
            timestamp: now_epoch(),
            success,
        });

        Ok(())
    }

    /// Get recent audit entries for a specific admin.
    pub fn get_audit_entries(
        &self,
        admin_id: Option<&Uuid>,
        tenant_id: Option<&TenantId>,
        limit: usize,
    ) -> Result<Vec<AdminAuditEntry>, String> {
        let log = self
            .audit_log
            .read()
            .map_err(|_| "audit log lock poisoned".to_string())?;

        let filtered: Vec<_> = log
            .iter()
            .rev()
            .filter(|e| {
                admin_id.map(|id| &e.admin_id == id).unwrap_or(true)
                    && tenant_id.map(|t| &e.tenant_id == t).unwrap_or(true)
            })
            .take(limit)
            .cloned()
            .collect();
        Ok(filtered)
    }

    // ── Dashboard Data ──────────────────────────────────────────────────

    /// Build dashboard data for admin activity overview.
    pub fn build_dashboard_data(
        &self,
        tenant_filter: Option<&TenantId>,
    ) -> Result<AdminDashboardData, String> {
        let admins = self
            .admins
            .read()
            .map_err(|_| "admins lock poisoned".to_string())?;
        let invitations = self
            .invitations
            .read()
            .map_err(|_| "invitations lock poisoned".to_string())?;
        let log = self
            .audit_log
            .read()
            .map_err(|_| "audit log lock poisoned".to_string())?;

        let now = now_epoch();
        let day_ago = now - 86400;

        let filtered_admins: Vec<_> = admins
            .values()
            .filter(|a| {
                tenant_filter
                    .map(|t| a.tenant_id.as_ref() == Some(t) || a.role == AdminRole::GlobalAdmin)
                    .unwrap_or(true)
            })
            .collect();

        let mut admins_by_role = HashMap::new();
        for admin in &filtered_admins {
            *admins_by_role
                .entry(admin.role.as_str().to_string())
                .or_insert(0u64) += 1;
        }

        let active_24h = filtered_admins
            .iter()
            .filter(|a| a.last_active_at.map(|t| t > day_ago).unwrap_or(false))
            .count() as u64;

        let pending_invitations = invitations
            .values()
            .filter(|i| i.status == InvitationStatus::Pending)
            .count() as u64;

        // Count recent violations from audit log
        let recent_violations = log
            .iter()
            .rev()
            .take_while(|e| e.timestamp > day_ago)
            .filter(|e| !e.success)
            .count() as u64;

        // Build per-admin activity summaries
        let mut admin_activities = Vec::new();
        for admin in &filtered_admins {
            let mut actions_by_type = HashMap::new();
            let mut total = 0u64;
            let mut last_action = None;
            for entry in log.iter().rev() {
                if entry.admin_id == admin.user_id && entry.timestamp > day_ago {
                    total += 1;
                    *actions_by_type
                        .entry(entry.action.clone())
                        .or_insert(0u64) += 1;
                    if last_action.is_none() {
                        last_action = Some(entry.timestamp);
                    }
                }
            }

            admin_activities.push(AdminActivitySummary {
                admin_id: admin.user_id,
                display_name: admin.display_name.clone(),
                role: admin.role,
                total_actions: total,
                actions_by_type,
                last_action_at: last_action,
                scope_violations: 0,
                permission_denials: 0,
            });
        }

        Ok(AdminDashboardData {
            total_admins: filtered_admins.len() as u64,
            active_admins_24h: active_24h,
            pending_invitations,
            admin_activities,
            admins_by_role,
            recent_violations,
        })
    }
}

impl Default for DelegatedAdminStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── AdminIdentity helper ────────────────────────────────────────────────────

impl AdminIdentity {
    /// Update the last-modified timestamp.
    fn updated_at_epoch(&mut self, _epoch: i64) {
        self.last_active_at = Some(now_epoch());
    }
}

// ── SIEM Event Extensions ───────────────────────────────────────────────────

impl SecurityEvent {
    /// Emit a delegated admin scope violation event.
    pub fn delegated_admin_scope_violation(
        admin_id: &Uuid,
        target_tenant: &TenantId,
        admin_tenant: Option<&TenantId>,
    ) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "delegated_admin",
            action: "scope_violation",
            severity: crate::siem::Severity::High,
            outcome: "failure",
            user_id: Some(*admin_id),
            source_ip: None,
            detail: Some(format!(
                "admin attempted cross-tenant access: target={} admin_tenant={:?}",
                target_tenant, admin_tenant
            )),
        };
        event.emit();
    }

    /// Emit a delegated admin permission denied event.
    pub fn delegated_admin_permission_denied(
        admin_id: &Uuid,
        permission: &str,
        tenant_id: &TenantId,
    ) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "delegated_admin",
            action: "permission_denied",
            severity: crate::siem::Severity::Medium,
            outcome: "failure",
            user_id: Some(*admin_id),
            source_ip: None,
            detail: Some(format!(
                "permission denied: perm={} tenant={}",
                permission, tenant_id
            )),
        };
        event.emit();
    }

    /// Emit a delegated admin action event.
    pub fn delegated_admin_action(
        admin_id: &Uuid,
        role: &AdminRole,
        tenant_id: &TenantId,
        action: &str,
        target: &str,
        detail: Option<&str>,
        source_ip: Option<&str>,
    ) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "delegated_admin",
            action: "admin_action",
            severity: crate::siem::Severity::Info,
            outcome: "success",
            user_id: Some(*admin_id),
            source_ip: source_ip.map(|s| s.to_string()),
            detail: Some(format!(
                "role={} tenant={} action={} target={} detail={:?}",
                role, tenant_id, action, target, detail
            )),
        };
        event.emit();
    }

    /// Emit a delegated admin registered event.
    pub fn delegated_admin_registered(user_id: &Uuid, role: &AdminRole) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "delegated_admin",
            action: "admin_registered",
            severity: crate::siem::Severity::Medium,
            outcome: "success",
            user_id: Some(*user_id),
            source_ip: None,
            detail: Some(format!("admin registered with role: {}", role)),
        };
        event.emit();
    }

    /// Emit an admin rate limited event.
    pub fn admin_rate_limited(admin_id: &Uuid) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "delegated_admin",
            action: "rate_limited",
            severity: crate::siem::Severity::Notice,
            outcome: "failure",
            user_id: Some(*admin_id),
            source_ip: None,
            detail: Some("admin action rate limit exceeded".to_string()),
        };
        event.emit();
    }
}

// ── Utility Functions ───────────────────────────────────────────────────────

/// Get the current time as Unix epoch seconds.
fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Generate a random invitation token (64 hex characters).
fn generate_invitation_token() -> String {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).expect("getrandom failed");
    hex::encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tenant() -> TenantId {
        TenantId::new()
    }

    fn make_global_admin() -> AdminIdentity {
        AdminIdentity {
            user_id: Uuid::new_v4(),
            role: AdminRole::GlobalAdmin,
            tenant_id: None,
            extra_permissions: Vec::new(),
            denied_permissions: Vec::new(),
            display_name: "Global Admin".to_string(),
            email: "global@milnet.mil".to_string(),
            active: true,
            created_at: now_epoch(),
            last_active_at: None,
        }
    }

    fn make_tenant_admin(tenant_id: TenantId) -> AdminIdentity {
        AdminIdentity {
            user_id: Uuid::new_v4(),
            role: AdminRole::TenantAdmin,
            tenant_id: Some(tenant_id),
            extra_permissions: Vec::new(),
            denied_permissions: Vec::new(),
            display_name: "Tenant Admin".to_string(),
            email: "tenant@milnet.mil".to_string(),
            active: true,
            created_at: now_epoch(),
            last_active_at: None,
        }
    }

    #[test]
    fn test_role_hierarchy() {
        assert!(AdminRole::GlobalAdmin.has_at_least(AdminRole::TenantAdmin));
        assert!(AdminRole::GlobalAdmin.has_at_least(AdminRole::GlobalAdmin));
        assert!(AdminRole::TenantAdmin.has_at_least(AdminRole::UserManager));
        assert!(!AdminRole::UserManager.has_at_least(AdminRole::TenantAdmin));
        assert!(!AdminRole::ReadOnly.has_at_least(AdminRole::UserManager));
    }

    #[test]
    fn test_default_permissions() {
        let perms = default_permissions(AdminRole::ReadOnly);
        assert!(perms.contains(&Permission::UserRead));
        assert!(!perms.contains(&Permission::UserCreate));

        let perms = default_permissions(AdminRole::TenantAdmin);
        assert!(perms.contains(&Permission::UserCreate));
        assert!(perms.contains(&Permission::PolicyManage));
        assert!(perms.contains(&Permission::AdminManage));
    }

    #[test]
    fn test_admin_permission_check() {
        let tenant = make_tenant();
        let admin = make_tenant_admin(tenant);
        assert!(admin.has_permission(Permission::UserCreate));
        assert!(admin.has_permission(Permission::PolicyManage));
    }

    #[test]
    fn test_denied_permission_override() {
        let tenant = make_tenant();
        let mut admin = make_tenant_admin(tenant);
        admin.denied_permissions = vec![Permission::UserDelete];
        assert!(!admin.has_permission(Permission::UserDelete));
        assert!(admin.has_permission(Permission::UserCreate)); // Other perms still work
    }

    #[test]
    fn test_tenant_scope_enforcement() {
        let tenant_a = make_tenant();
        let tenant_b = make_tenant();
        let admin = make_tenant_admin(tenant_a);

        assert!(admin.can_access_tenant(&tenant_a));
        assert!(!admin.can_access_tenant(&tenant_b));

        let global = make_global_admin();
        assert!(global.can_access_tenant(&tenant_a));
        assert!(global.can_access_tenant(&tenant_b));
    }

    #[test]
    fn test_operation_context_scope_check() {
        let tenant_a = make_tenant();
        let tenant_b = make_tenant();
        let admin = make_tenant_admin(tenant_a);

        let ctx = AdminOperationContext::new(admin.clone(), tenant_a, None);
        assert!(ctx.is_ok());

        let ctx = AdminOperationContext::new(admin, tenant_b, None);
        assert!(ctx.is_err());
    }

    #[test]
    fn test_inactive_admin_blocked() {
        let tenant = make_tenant();
        let mut admin = make_tenant_admin(tenant);
        admin.active = false;

        assert!(!admin.has_permission(Permission::UserRead));
        assert!(!admin.can_access_tenant(&tenant));
        assert!(AdminOperationContext::new(admin, tenant, None).is_err());
    }

    #[test]
    fn test_admin_store_crud() {
        let store = DelegatedAdminStore::new();
        let tenant = make_tenant();
        let admin = make_tenant_admin(tenant);
        let uid = admin.user_id;

        store.register_admin(admin).unwrap();
        let found = store.get_admin(&uid).unwrap();
        assert!(found.is_some());

        let list = store.list_admins(None).unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn test_non_global_admin_requires_tenant() {
        let store = DelegatedAdminStore::new();
        let admin = AdminIdentity {
            user_id: Uuid::new_v4(),
            role: AdminRole::TenantAdmin,
            tenant_id: None, // Missing!
            extra_permissions: Vec::new(),
            denied_permissions: Vec::new(),
            display_name: "Bad".to_string(),
            email: "bad@milnet.mil".to_string(),
            active: true,
            created_at: now_epoch(),
            last_active_at: None,
        };
        assert!(store.register_admin(admin).is_err());
    }

    #[test]
    fn test_rate_limiter() {
        let mut rl = AdminRateLimiter::new();
        let uid = Uuid::new_v4();
        for _ in 0..5 {
            assert!(rl.check(&uid, 5));
        }
        assert!(!rl.check(&uid, 5)); // Exceeded
    }

    #[test]
    fn test_role_from_str() {
        assert_eq!(AdminRole::from_str("global_admin"), Some(AdminRole::GlobalAdmin));
        assert_eq!(AdminRole::from_str("tenant_admin"), Some(AdminRole::TenantAdmin));
        assert_eq!(AdminRole::from_str("user_manager"), Some(AdminRole::UserManager));
        assert_eq!(AdminRole::from_str("read_only"), Some(AdminRole::ReadOnly));
        assert_eq!(AdminRole::from_str("invalid"), None);
    }

    #[test]
    fn test_effective_permissions() {
        let tenant = make_tenant();
        let mut admin = make_tenant_admin(tenant);
        let base_count = admin.effective_permissions().len();

        // Add extra permission (no duplicates)
        admin.extra_permissions = vec![Permission::UserCreate]; // Already in defaults
        assert_eq!(admin.effective_permissions().len(), base_count);

        // Deny one permission
        admin.denied_permissions = vec![Permission::UserDelete];
        assert_eq!(admin.effective_permissions().len(), base_count - 1);
        assert!(!admin.effective_permissions().contains(&Permission::UserDelete));
    }
}
