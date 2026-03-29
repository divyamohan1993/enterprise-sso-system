//! Multi-tenant isolation for the MILNET SSO system.
//!
//! Provides comprehensive tenant isolation including:
//! - Per-tenant encryption key derivation (HKDF-SHA512)
//! - Constant-time tenant ID comparison to prevent timing side-channels
//! - Thread-local tenant context for request-scoped query scoping
//! - Audit segregation with cross-tenant access denial
//! - Quota management (users, devices)
//! - Tenant lifecycle management (create, suspend, decommission)
//!
//! All database queries, audit logs, and API responses MUST be scoped
//! through the [`TenantContext`] to guarantee isolation.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::sync::RwLock;

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::compliance::ComplianceRegime;

// ── Domain separation label for tenant KEK derivation ───────────────────────

/// Domain separation string used in HKDF tenant key derivation.
const TENANT_KEK_DOMAIN: &str = "MILNET-TENANT-KEK-v1";

// ── TenantId ────────────────────────────────────────────────────────────────

/// Strongly-typed tenant identifier wrapping a UUID.
///
/// Equality comparison is constant-time to prevent timing-based
/// tenant enumeration attacks.
#[derive(Debug, Clone, Copy, Hash, Serialize, Deserialize)]
pub struct TenantId(Uuid);

impl TenantId {
    /// Create a new random tenant ID.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Wrap an existing UUID as a TenantId.
    pub fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    /// Return the inner UUID.
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    /// Return the raw bytes of the underlying UUID.
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl Default for TenantId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Constant-time equality to prevent timing side-channel attacks.
impl PartialEq for TenantId {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

impl Eq for TenantId {}

// ── TenantStatus ────────────────────────────────────────────────────────────

/// Lifecycle status of a tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TenantStatus {
    /// Tenant is fully operational.
    Active,
    /// Tenant is suspended — authentication and data access are blocked.
    Suspended,
    /// Tenant data is being purged; no new operations allowed.
    Decommissioning,
    /// Tenant has been fully removed. Record kept for audit trail only.
    Decommissioned,
}

impl fmt::Display for TenantStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "ACTIVE"),
            Self::Suspended => write!(f, "SUSPENDED"),
            Self::Decommissioning => write!(f, "DECOMMISSIONING"),
            Self::Decommissioned => write!(f, "DECOMMISSIONED"),
        }
    }
}

// ── ComplianceRegime extension for multi-tenancy ────────────────────────────

/// Tenant-level compliance regime.
///
/// Extends the base [`ComplianceRegime`] with a `Commercial` variant
/// for tenants that do not fall under government regulations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TenantComplianceRegime {
    /// US Department of Defense (DISA STIG / ITAR).
    UsDod,
    /// Indian Government (CERT-In / DPDP Act / MEITY).
    IndianGovt,
    /// Commercial — no specific government compliance regime.
    Commercial,
    /// Dual regime: union of US DoD and Indian Government requirements.
    Dual,
}

impl TenantComplianceRegime {
    /// Convert to the base [`ComplianceRegime`] used elsewhere in the system.
    /// Commercial tenants map to `None` since they have no government regime.
    pub fn to_base_regime(&self) -> Option<ComplianceRegime> {
        match self {
            Self::UsDod => Some(ComplianceRegime::UsDod),
            Self::IndianGovt => Some(ComplianceRegime::IndianGovt),
            Self::Dual => Some(ComplianceRegime::Dual),
            Self::Commercial => None,
        }
    }
}

// ── Tenant ──────────────────────────────────────────────────────────────────

/// A tenant in the MILNET SSO system.
///
/// Each tenant is a fully isolated unit with its own encryption keys,
/// compliance regime, data residency constraints, and resource quotas.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    /// Unique identifier for this tenant.
    pub tenant_id: TenantId,
    /// Human-readable name (e.g. "INDOPACOM Joint Task Force").
    pub name: String,
    /// URL-safe slug identifier (e.g. "indopacom-jtf").
    pub slug: String,
    /// Current lifecycle status.
    pub status: TenantStatus,
    /// Unix timestamp (microseconds) when the tenant was created.
    pub created_at: i64,
    /// Compliance regime governing this tenant's data handling.
    pub compliance_regime: TenantComplianceRegime,
    /// GCP/AWS region where this tenant's data must reside.
    pub data_residency_region: String,
    /// Maximum number of users permitted under this tenant.
    pub max_users: u64,
    /// Maximum number of devices permitted under this tenant.
    pub max_devices: u64,
    /// Feature flags enabled for this tenant.
    pub feature_flags: Vec<String>,
    /// Cloud KMS key resource name for tenant-specific encryption.
    pub encryption_key_id: String,
}

impl Tenant {
    /// Check whether the tenant is in an operational state.
    pub fn is_active(&self) -> bool {
        self.status == TenantStatus::Active
    }
}

// ── TenantIsolation trait ───────────────────────────────────────────────────

/// Trait implemented by all entities that belong to a specific tenant.
///
/// Used to enforce tenant scoping at compile time — any struct that
/// implements this trait can be validated against the current tenant context.
pub trait TenantIsolation {
    /// Return the tenant ID this entity belongs to.
    fn tenant_id(&self) -> &TenantId;
}

impl TenantIsolation for Tenant {
    fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

// ── TenantContext (thread-local request scoping) ────────────────────────────

thread_local! {
    /// Thread-local storage for the current tenant ID.
    /// Visible within the crate so that `tenant_middleware::TenantGuard` can
    /// set and clear the context directly.
    pub(crate) static CURRENT_TENANT: RefCell<Option<TenantId>> = const { RefCell::new(None) };
}

/// Thread-local tenant context for request-scoped isolation.
///
/// All database queries, audit log entries, and API responses should
/// check the current tenant context to ensure proper scoping.
pub struct TenantContext;

impl TenantContext {
    /// Execute a closure within the scope of a specific tenant.
    ///
    /// The tenant ID is set for the duration of `f` and restored
    /// to its previous value afterward (supports nested scoping).
    ///
    /// # Example
    /// ```ignore
    /// TenantContext::with_tenant(tenant_id, || {
    ///     // All DB queries here are scoped to tenant_id
    ///     db.query_users()?;
    /// });
    /// ```
    pub fn with_tenant<F, R>(tenant_id: TenantId, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let previous = CURRENT_TENANT.with(|c| c.borrow().clone());
        CURRENT_TENANT.with(|c| {
            *c.borrow_mut() = Some(tenant_id);
        });
        let result = f();
        CURRENT_TENANT.with(|c| {
            *c.borrow_mut() = previous;
        });
        result
    }

    /// Get the current tenant ID, if set.
    pub fn current_tenant_id() -> Option<TenantId> {
        CURRENT_TENANT.with(|c| *c.borrow())
    }

    /// Get the current tenant ID or return an error.
    pub fn require_tenant() -> Result<TenantId, TenantError> {
        Self::current_tenant_id().ok_or(TenantError::NoTenantContext)
    }
}

// ── TenantError ─────────────────────────────────────────────────────────────

/// Errors related to multi-tenant operations.
#[derive(Debug, thiserror::Error)]
pub enum TenantError {
    /// No tenant context is set for the current request.
    #[error("no tenant context set — all operations require a tenant scope")]
    NoTenantContext,

    /// The referenced tenant was not found.
    #[error("tenant not found: {0}")]
    TenantNotFound(TenantId),

    /// The tenant is not in an active state.
    #[error("tenant {id} is {status} — operation requires Active status")]
    TenantNotActive { id: TenantId, status: TenantStatus },

    /// Cross-tenant access was attempted and denied.
    #[error("cross-tenant access denied: {from} -> {to}")]
    CrossTenantAccessDenied { from: TenantId, to: TenantId },

    /// Tenant IDs do not match (constant-time comparison failed).
    #[error("tenant ID mismatch — isolation boundary violated")]
    TenantMismatch,

    /// Resource quota exceeded.
    #[error("quota exceeded for tenant {tenant_id}: {resource} (limit: {limit}, current: {current})")]
    QuotaExceeded {
        tenant_id: TenantId,
        resource: String,
        limit: u64,
        current: u64,
    },

    /// The tenant slug is invalid (not URL-safe).
    #[error("invalid tenant slug: {0}")]
    InvalidSlug(String),

    /// A tenant with the same slug already exists.
    #[error("tenant slug already exists: {0}")]
    DuplicateSlug(String),

    /// Tenant status transition is not allowed.
    #[error("invalid status transition: {from} -> {to}")]
    InvalidStatusTransition {
        from: TenantStatus,
        to: TenantStatus,
    },

    /// Internal error (e.g., lock poisoning).
    #[error("internal error: {0}")]
    InternalError(String),
}

// ── TenantAuditFilter ───────────────────────────────────────────────────────

/// Ensures audit queries are always scoped to a single tenant.
///
/// Cross-tenant audit access is explicitly denied and triggers a
/// SIEM security event on any attempt.
pub struct TenantAuditFilter {
    tenant_id: TenantId,
}

impl TenantAuditFilter {
    /// Create a new audit filter scoped to the given tenant.
    pub fn new(tenant_id: TenantId) -> Self {
        Self { tenant_id }
    }

    /// Validate that an audit query targets only the scoped tenant.
    ///
    /// Returns `Ok(())` if the query tenant matches, or an error
    /// (and emits a SIEM event) if cross-tenant audit access is attempted.
    pub fn validate_audit_access(&self, query_tenant_id: &TenantId) -> Result<(), TenantError> {
        if assert_same_tenant(&self.tenant_id, query_tenant_id).is_ok() {
            Ok(())
        } else {
            // Emit SIEM event for cross-tenant audit access attempt
            tracing::error!(
                event = "CROSS_TENANT_AUDIT_ACCESS_ATTEMPT",
                scoped_tenant = %self.tenant_id,
                attempted_tenant = %query_tenant_id,
                severity = "CRITICAL",
                "Cross-tenant audit access attempt detected — SIEM alert raised"
            );
            Err(TenantError::CrossTenantAccessDenied {
                from: self.tenant_id,
                to: *query_tenant_id,
            })
        }
    }

    /// Return the tenant ID this filter is scoped to.
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

// ── Cross-tenant protection ─────────────────────────────────────────────────

/// Assert that two tenant IDs are identical using constant-time comparison.
///
/// Returns `Ok(())` if they match, or `Err(TenantError::TenantMismatch)` otherwise.
/// This prevents timing side-channel attacks that could leak tenant identity.
pub fn assert_same_tenant(a: &TenantId, b: &TenantId) -> Result<(), TenantError> {
    if a.as_bytes().ct_eq(b.as_bytes()).into() {
        Ok(())
    } else {
        Err(TenantError::TenantMismatch)
    }
}

// ── Tenant encryption (HKDF-SHA512 KEK derivation) ─────────────────────────

/// Derive a per-tenant Key Encryption Key (KEK) from the master KEK using HKDF-SHA512.
///
/// The derivation uses domain separation with the label
/// `MILNET-TENANT-KEK-v1:{tenant_id}` to ensure each tenant's key
/// is cryptographically independent.
///
/// # Arguments
/// - `tenant_id` — the tenant whose KEK to derive
/// - `master_kek` — the 256-bit master key encryption key (from HSM/sealed storage)
///
/// # Returns
/// A 256-bit per-tenant KEK suitable for wrapping data encryption keys.
pub fn derive_tenant_kek(tenant_id: TenantId, master_kek: &[u8; 32]) -> Result<[u8; 32], String> {
    let hk = Hkdf::<Sha512>::new(Some(TENANT_KEK_DOMAIN.as_bytes()), master_kek);
    let info = format!("{}:{}", TENANT_KEK_DOMAIN, tenant_id);
    let mut okm = [0u8; 32];
    hk.expand(info.as_bytes(), &mut okm)
        .map_err(|_| "HKDF-SHA512 tenant KEK derivation failed".to_string())?;
    Ok(okm)
}

// ── Resource usage tracking ─────────────────────────────────────────────────

/// Current resource usage counters for a tenant.
#[derive(Debug, Clone, Default)]
struct ResourceUsage {
    current_users: u64,
    current_devices: u64,
}

// ── TenantManager ───────────────────────────────────────────────────────────

/// Central manager for tenant lifecycle, quotas, and isolation enforcement.
///
/// Thread-safe via internal `RwLock`. In production, the backing store
/// would be the encrypted database; this in-memory implementation provides
/// the enforcement logic.
pub struct TenantManager {
    tenants: RwLock<HashMap<TenantId, Tenant>>,
    slugs: RwLock<HashMap<String, TenantId>>,
    usage: RwLock<HashMap<TenantId, ResourceUsage>>,
}

impl TenantManager {
    /// Create a new, empty tenant manager.
    pub fn new() -> Self {
        Self {
            tenants: RwLock::new(HashMap::new()),
            slugs: RwLock::new(HashMap::new()),
            usage: RwLock::new(HashMap::new()),
        }
    }

    /// Register a new tenant.
    ///
    /// Validates the slug format and uniqueness before inserting.
    /// Returns the tenant ID on success.
    pub fn create_tenant(&self, tenant: Tenant) -> Result<TenantId, TenantError> {
        // Validate slug: must be non-empty, lowercase alphanumeric + hyphens
        if tenant.slug.is_empty()
            || !tenant
                .slug
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(TenantError::InvalidSlug(tenant.slug.clone()));
        }

        let mut slugs = self.slugs.write().map_err(|_| TenantError::InternalError("lock poisoned — potential state corruption".to_string()))?;
        if slugs.contains_key(&tenant.slug) {
            return Err(TenantError::DuplicateSlug(tenant.slug.clone()));
        }

        let id = tenant.tenant_id;
        slugs.insert(tenant.slug.clone(), id);
        drop(slugs);

        self.usage
            .write()
            .map_err(|_| TenantError::InternalError("lock poisoned — potential state corruption".to_string()))?
            .insert(id, ResourceUsage::default());
        self.tenants.write().map_err(|_| TenantError::InternalError("lock poisoned — potential state corruption".to_string()))?.insert(id, tenant);

        tracing::info!(tenant_id = %id, "tenant created");
        Ok(id)
    }

    /// Look up a tenant by ID.
    pub fn get_tenant(&self, id: TenantId) -> Result<Option<Tenant>, TenantError> {
        let guard = self.tenants.read().map_err(|_| TenantError::InternalError("lock poisoned — potential state corruption".to_string()))?;
        Ok(guard.get(&id).cloned())
    }

    /// Suspend a tenant, blocking all authentication and data access.
    pub fn suspend_tenant(&self, id: TenantId, reason: &str) -> Result<(), TenantError> {
        let mut tenants = self.tenants.write().map_err(|_| TenantError::InternalError("lock poisoned — potential state corruption".to_string()))?;
        let tenant = tenants
            .get_mut(&id)
            .ok_or(TenantError::TenantNotFound(id))?;

        if tenant.status != TenantStatus::Active {
            return Err(TenantError::InvalidStatusTransition {
                from: tenant.status,
                to: TenantStatus::Suspended,
            });
        }

        tenant.status = TenantStatus::Suspended;
        tracing::warn!(
            tenant_id = %id,
            reason = reason,
            event = "TENANT_SUSPENDED",
            "tenant suspended"
        );
        Ok(())
    }

    /// Reactivate a previously suspended tenant.
    pub fn reactivate_tenant(&self, id: TenantId) -> Result<(), TenantError> {
        let mut tenants = self.tenants.write().map_err(|_| TenantError::InternalError("lock poisoned — potential state corruption".to_string()))?;
        let tenant = tenants
            .get_mut(&id)
            .ok_or(TenantError::TenantNotFound(id))?;

        if tenant.status != TenantStatus::Suspended {
            return Err(TenantError::InvalidStatusTransition {
                from: tenant.status,
                to: TenantStatus::Active,
            });
        }

        tenant.status = TenantStatus::Active;
        tracing::info!(tenant_id = %id, event = "TENANT_REACTIVATED", "tenant reactivated");
        Ok(())
    }

    /// Begin decommissioning a tenant. This is a terminal transition.
    pub fn decommission_tenant(&self, id: TenantId, reason: &str) -> Result<(), TenantError> {
        let mut tenants = self.tenants.write().map_err(|_| TenantError::InternalError("lock poisoned — potential state corruption".to_string()))?;
        let tenant = tenants
            .get_mut(&id)
            .ok_or(TenantError::TenantNotFound(id))?;

        match tenant.status {
            TenantStatus::Active | TenantStatus::Suspended => {
                tenant.status = TenantStatus::Decommissioning;
                tracing::warn!(
                    tenant_id = %id,
                    reason = reason,
                    event = "TENANT_DECOMMISSIONING",
                    "tenant decommissioning initiated"
                );
                Ok(())
            }
            other => Err(TenantError::InvalidStatusTransition {
                from: other,
                to: TenantStatus::Decommissioning,
            }),
        }
    }

    /// Mark a decommissioning tenant as fully decommissioned.
    pub fn finalize_decommission(&self, id: TenantId) -> Result<(), TenantError> {
        let mut tenants = self.tenants.write().map_err(|_| TenantError::InternalError("lock poisoned — potential state corruption".to_string()))?;
        let tenant = tenants
            .get_mut(&id)
            .ok_or(TenantError::TenantNotFound(id))?;

        if tenant.status != TenantStatus::Decommissioning {
            return Err(TenantError::InvalidStatusTransition {
                from: tenant.status,
                to: TenantStatus::Decommissioned,
            });
        }

        tenant.status = TenantStatus::Decommissioned;
        tracing::info!(
            tenant_id = %id,
            event = "TENANT_DECOMMISSIONED",
            "tenant fully decommissioned"
        );
        Ok(())
    }

    /// List all tenants.
    pub fn list_tenants(&self) -> Result<Vec<Tenant>, TenantError> {
        let guard = self.tenants.read().map_err(|_| TenantError::InternalError("lock poisoned — potential state corruption".to_string()))?;
        Ok(guard.values().cloned().collect())
    }

    /// Update the user and device quotas for a tenant.
    pub fn update_quota(
        &self,
        id: TenantId,
        max_users: u64,
        max_devices: u64,
    ) -> Result<(), TenantError> {
        let mut tenants = self.tenants.write().map_err(|_| TenantError::InternalError("lock poisoned — potential state corruption".to_string()))?;
        let tenant = tenants
            .get_mut(&id)
            .ok_or(TenantError::TenantNotFound(id))?;
        tenant.max_users = max_users;
        tenant.max_devices = max_devices;
        tracing::info!(
            tenant_id = %id,
            max_users = max_users,
            max_devices = max_devices,
            "tenant quotas updated"
        );
        Ok(())
    }

    /// Check whether a tenant is within quota for a given resource.
    ///
    /// Supported resources: `"users"`, `"devices"`.
    /// Returns `Ok(true)` if under quota, `Ok(false)` if at/over quota.
    pub fn check_quota(&self, id: TenantId, resource: &str) -> Result<bool, TenantError> {
        let tenants = self.tenants.read().map_err(|_| TenantError::InternalError("lock poisoned — potential state corruption".to_string()))?;
        let tenant = tenants.get(&id).ok_or(TenantError::TenantNotFound(id))?;
        let usage = self.usage.read().map_err(|_| TenantError::InternalError("lock poisoned — potential state corruption".to_string()))?;
        let counters = usage.get(&id).ok_or(TenantError::TenantNotFound(id))?;

        match resource {
            "users" => Ok(counters.current_users < tenant.max_users),
            "devices" => Ok(counters.current_devices < tenant.max_devices),
            _ => Ok(true), // Unknown resources are not quota-limited
        }
    }

    /// Increment a resource counter for a tenant, failing if quota is exceeded.
    pub fn increment_usage(
        &self,
        id: TenantId,
        resource: &str,
    ) -> Result<(), TenantError> {
        let tenants = self.tenants.read().map_err(|_| TenantError::InternalError("lock poisoned — potential state corruption".to_string()))?;
        let tenant = tenants.get(&id).ok_or(TenantError::TenantNotFound(id))?;

        if !tenant.is_active() {
            return Err(TenantError::TenantNotActive {
                id,
                status: tenant.status,
            });
        }

        let mut usage = self.usage.write().map_err(|_| TenantError::InternalError("lock poisoned — potential state corruption".to_string()))?;
        let counters = usage.get_mut(&id).ok_or(TenantError::TenantNotFound(id))?;

        match resource {
            "users" => {
                if counters.current_users >= tenant.max_users {
                    return Err(TenantError::QuotaExceeded {
                        tenant_id: id,
                        resource: resource.to_string(),
                        limit: tenant.max_users,
                        current: counters.current_users,
                    });
                }
                counters.current_users += 1;
            }
            "devices" => {
                if counters.current_devices >= tenant.max_devices {
                    return Err(TenantError::QuotaExceeded {
                        tenant_id: id,
                        resource: resource.to_string(),
                        limit: tenant.max_devices,
                        current: counters.current_devices,
                    });
                }
                counters.current_devices += 1;
            }
            _ => {} // Unknown resources pass through
        }
        Ok(())
    }

    /// Finalize decommission with cascade deletion of all tenant data.
    ///
    /// This is the in-memory counterpart; the actual database cascade
    /// deletion is performed by [`crate::db::TenantAwarePool::cascade_delete_tenant_data`].
    /// After calling this method, the tenant status transitions to Decommissioned
    /// and all in-memory usage counters / slug mappings are purged.
    pub fn finalize_decommission_with_purge(&self, id: TenantId) -> Result<(), TenantError> {
        let mut tenants = self.tenants.write().map_err(|_| TenantError::InternalError("lock poisoned — potential state corruption".to_string()))?;
        let tenant = tenants
            .get_mut(&id)
            .ok_or(TenantError::TenantNotFound(id))?;

        if tenant.status != TenantStatus::Decommissioning {
            return Err(TenantError::InvalidStatusTransition {
                from: tenant.status,
                to: TenantStatus::Decommissioned,
            });
        }

        // Remove slug mapping
        let slug = tenant.slug.clone();
        let mut slugs = self.slugs.write().map_err(|_| TenantError::InternalError("lock poisoned — potential state corruption".to_string()))?;
        slugs.remove(&slug);
        drop(slugs);

        // Remove usage counters
        let mut usage = self.usage.write().map_err(|_| TenantError::InternalError("lock poisoned — potential state corruption".to_string()))?;
        usage.remove(&id);
        drop(usage);

        // Mark as decommissioned (keep record for audit trail)
        tenant.status = TenantStatus::Decommissioned;

        tracing::info!(
            tenant_id = %id,
            event = "TENANT_DECOMMISSIONED_WITH_PURGE",
            "tenant fully decommissioned — all data purged"
        );

        // Emit SIEM event
        let event = crate::siem::SiemEvent {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
            severity: 8,
            event_type: "TENANT_DECOMMISSIONED_WITH_PURGE".to_string(),
            json: format!(
                r#"{{"event":"TENANT_DECOMMISSIONED_WITH_PURGE","tenant_id":"{}","slug":"{}"}}"#,
                id, slug
            ),
        };
        crate::siem::broadcast_event(&event);

        Ok(())
    }

    /// Get the Cloud KMS key reference for a tenant.
    pub fn get_tenant_encryption_key_id(
        &self,
        id: TenantId,
    ) -> Result<String, TenantError> {
        let tenants = self.tenants.read().map_err(|_| TenantError::InternalError("lock poisoned — potential state corruption".to_string()))?;
        let tenant = tenants.get(&id).ok_or(TenantError::TenantNotFound(id))?;
        Ok(tenant.encryption_key_id.clone())
    }

    /// Validate cross-tenant access. Default policy: DENY ALL.
    ///
    /// Cross-tenant access is never permitted in the MILNET system.
    /// Any attempt is logged as a critical SIEM event.
    pub fn validate_cross_tenant_access(
        &self,
        from: TenantId,
        to: TenantId,
    ) -> Result<(), TenantError> {
        // Same tenant is allowed
        if assert_same_tenant(&from, &to).is_ok() {
            return Ok(());
        }

        tracing::error!(
            event = "CROSS_TENANT_ACCESS_ATTEMPT",
            from_tenant = %from,
            to_tenant = %to,
            severity = "CRITICAL",
            "Cross-tenant access attempt denied — SIEM alert raised"
        );

        Err(TenantError::CrossTenantAccessDenied { from, to })
    }
}

impl Default for TenantManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Per-tenant rate limiting configuration ───────────────────────────────

/// Rate limiting parameters for a tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantRateLimitConfig {
    /// Maximum sustained requests per second.
    pub rps: u32,
    /// Maximum burst size (token bucket capacity).
    pub burst: u32,
}

impl Default for TenantRateLimitConfig {
    fn default() -> Self {
        Self {
            rps: 1000,
            burst: 2000,
        }
    }
}

// ── Per-tenant policy configuration ─────────────────────────────────────

/// Security and operational policies configurable per tenant.
///
/// These override system-wide defaults and allow tenants with different
/// compliance requirements to have appropriately strict controls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantPolicy {
    /// Session timeout in seconds. Default: 3600 (1 hour).
    pub session_timeout_secs: i64,
    /// Maximum concurrent sessions per user. Default: 5.
    pub max_sessions_per_user: u32,
    /// Minimum password length. Default: 12.
    pub password_min_length: u32,
    /// Whether MFA is required for all users in this tenant. Default: true.
    pub mfa_required: bool,
    /// Allowed authentication methods (e.g. ["opaque", "fido", "cac"]).
    pub allowed_auth_methods: Vec<String>,
    /// IP allowlist (CIDR notation). Empty = allow all.
    pub ip_allowlist: Vec<String>,
    /// Whether to enforce data residency constraints. Default: true.
    pub enforce_data_residency: bool,
}

impl Default for TenantPolicy {
    fn default() -> Self {
        Self {
            session_timeout_secs: 3600,
            max_sessions_per_user: 5,
            password_min_length: 12,
            mfa_required: true,
            allowed_auth_methods: vec![
                "opaque".to_string(),
                "fido".to_string(),
                "cac".to_string(),
            ],
            ip_allowlist: Vec::new(),
            enforce_data_residency: true,
        }
    }
}

impl TenantPolicy {
    /// Check if an authentication method is allowed for this tenant.
    pub fn is_auth_method_allowed(&self, method: &str) -> bool {
        self.allowed_auth_methods.iter().any(|m| m == method)
    }

    /// Check if an IP address is within the allowlist.
    /// Returns `true` if the allowlist is empty (allow all) or if the IP matches.
    pub fn is_ip_allowed(&self, ip: &str) -> bool {
        if self.ip_allowlist.is_empty() {
            return true;
        }
        self.ip_allowlist.iter().any(|entry| {
            if let Some(slash_pos) = entry.find('/') {
                // CIDR notation: parse network address and prefix length
                let network_str = &entry[..slash_pos];
                let prefix_len: u32 = match entry[slash_pos + 1..].parse() {
                    Ok(p) => p,
                    Err(_) => return false,
                };
                // Parse both as IPv4 octets for comparison
                let net_octets: Vec<u8> = network_str
                    .split('.')
                    .filter_map(|s| s.parse().ok())
                    .collect();
                let ip_octets: Vec<u8> = ip
                    .split('.')
                    .filter_map(|s| s.parse().ok())
                    .collect();
                if net_octets.len() != 4 || ip_octets.len() != 4 || prefix_len > 32 {
                    return false;
                }
                let net_u32 = u32::from_be_bytes([net_octets[0], net_octets[1], net_octets[2], net_octets[3]]);
                let ip_u32 = u32::from_be_bytes([ip_octets[0], ip_octets[1], ip_octets[2], ip_octets[3]]);
                let mask = if prefix_len == 0 { 0u32 } else { !0u32 << (32 - prefix_len) };
                (net_u32 & mask) == (ip_u32 & mask)
            } else {
                // Exact match
                ip == entry
            }
        })
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tenant(slug: &str) -> Tenant {
        Tenant {
            tenant_id: TenantId::new(),
            name: format!("Test Tenant {}", slug),
            slug: slug.to_string(),
            status: TenantStatus::Active,
            created_at: 1700000000_000000,
            compliance_regime: TenantComplianceRegime::UsDod,
            data_residency_region: "us-central1".to_string(),
            max_users: 100,
            max_devices: 500,
            feature_flags: vec!["mfa".to_string(), "cac".to_string()],
            encryption_key_id: "projects/milnet/locations/global/keyRings/tenants/cryptoKeys/tenant-key".to_string(),
        }
    }

    // ── TenantId tests ──────────────────────────────────────────────────

    #[test]
    fn tenant_id_equality_is_constant_time() {
        let id1 = TenantId::new();
        let id2 = TenantId::from_uuid(*id1.as_uuid());
        assert_eq!(id1, id2);
    }

    #[test]
    fn tenant_id_inequality() {
        let id1 = TenantId::new();
        let id2 = TenantId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn tenant_id_display() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let id = TenantId::from_uuid(uuid);
        assert_eq!(id.to_string(), "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn tenant_id_serde_roundtrip() {
        let id = TenantId::new();
        let json = serde_json::to_string(&id).unwrap();
        let deserialized: TenantId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, deserialized);
    }

    // ── TenantContext tests ─────────────────────────────────────────────

    #[test]
    fn tenant_context_scoped_execution() {
        let id = TenantId::new();
        assert!(TenantContext::current_tenant_id().is_none());

        let captured = TenantContext::with_tenant(id, || {
            TenantContext::current_tenant_id()
        });

        assert_eq!(captured, Some(id));
        // After scope, context is restored
        assert!(TenantContext::current_tenant_id().is_none());
    }

    #[test]
    fn tenant_context_nested_scoping() {
        let outer = TenantId::new();
        let inner = TenantId::new();

        TenantContext::with_tenant(outer, || {
            assert_eq!(TenantContext::current_tenant_id(), Some(outer));

            TenantContext::with_tenant(inner, || {
                assert_eq!(TenantContext::current_tenant_id(), Some(inner));
            });

            // Outer scope restored
            assert_eq!(TenantContext::current_tenant_id(), Some(outer));
        });
    }

    #[test]
    fn tenant_context_require_tenant_fails_without_context() {
        // Clear any leftover state
        assert!(TenantContext::require_tenant().is_err());
    }

    // ── TenantManager lifecycle tests ───────────────────────────────────

    #[test]
    fn create_and_retrieve_tenant() {
        let mgr = TenantManager::new();
        let tenant = make_tenant("alpha-team");
        let id = tenant.tenant_id;
        mgr.create_tenant(tenant).unwrap();

        let retrieved = mgr.get_tenant(id).unwrap();
        assert_eq!(retrieved.slug, "alpha-team");
        assert_eq!(retrieved.status, TenantStatus::Active);
    }

    #[test]
    fn duplicate_slug_rejected() {
        let mgr = TenantManager::new();
        let t1 = make_tenant("bravo");
        mgr.create_tenant(t1).unwrap();

        let t2 = make_tenant("bravo");
        let result = mgr.create_tenant(t2);
        assert!(matches!(result, Err(TenantError::DuplicateSlug(_))));
    }

    #[test]
    fn invalid_slug_rejected() {
        let mgr = TenantManager::new();
        let mut t = make_tenant("valid");
        t.slug = "INVALID_SLUG!".to_string();
        assert!(matches!(mgr.create_tenant(t), Err(TenantError::InvalidSlug(_))));
    }

    #[test]
    fn suspend_and_reactivate_tenant() {
        let mgr = TenantManager::new();
        let tenant = make_tenant("charlie");
        let id = tenant.tenant_id;
        mgr.create_tenant(tenant).unwrap();

        mgr.suspend_tenant(id, "security review").unwrap();
        assert_eq!(mgr.get_tenant(id).unwrap().status, TenantStatus::Suspended);

        mgr.reactivate_tenant(id).unwrap();
        assert_eq!(mgr.get_tenant(id).unwrap().status, TenantStatus::Active);
    }

    #[test]
    fn cannot_suspend_non_active_tenant() {
        let mgr = TenantManager::new();
        let tenant = make_tenant("delta");
        let id = tenant.tenant_id;
        mgr.create_tenant(tenant).unwrap();

        mgr.suspend_tenant(id, "test").unwrap();
        // Cannot suspend an already-suspended tenant
        assert!(matches!(
            mgr.suspend_tenant(id, "again"),
            Err(TenantError::InvalidStatusTransition { .. })
        ));
    }

    #[test]
    fn decommission_lifecycle() {
        let mgr = TenantManager::new();
        let tenant = make_tenant("echo");
        let id = tenant.tenant_id;
        mgr.create_tenant(tenant).unwrap();

        mgr.decommission_tenant(id, "end of contract").unwrap();
        assert_eq!(
            mgr.get_tenant(id).unwrap().status,
            TenantStatus::Decommissioning
        );

        mgr.finalize_decommission(id).unwrap();
        assert_eq!(
            mgr.get_tenant(id).unwrap().status,
            TenantStatus::Decommissioned
        );
    }

    #[test]
    fn list_tenants_returns_all() {
        let mgr = TenantManager::new();
        mgr.create_tenant(make_tenant("foxtrot")).unwrap();
        mgr.create_tenant(make_tenant("golf")).unwrap();
        mgr.create_tenant(make_tenant("hotel")).unwrap();

        assert_eq!(mgr.list_tenants().len(), 3);
    }

    // ── Quota tests ─────────────────────────────────────────────────────

    #[test]
    fn quota_check_and_increment() {
        let mgr = TenantManager::new();
        let mut tenant = make_tenant("india");
        tenant.max_users = 2;
        tenant.max_devices = 1;
        let id = tenant.tenant_id;
        mgr.create_tenant(tenant).unwrap();

        // Under quota
        assert!(mgr.check_quota(id, "users").unwrap());
        mgr.increment_usage(id, "users").unwrap();
        mgr.increment_usage(id, "users").unwrap();

        // At quota
        assert!(!mgr.check_quota(id, "users").unwrap());
        assert!(matches!(
            mgr.increment_usage(id, "users"),
            Err(TenantError::QuotaExceeded { .. })
        ));
    }

    #[test]
    fn update_quota() {
        let mgr = TenantManager::new();
        let tenant = make_tenant("juliet");
        let id = tenant.tenant_id;
        mgr.create_tenant(tenant).unwrap();

        mgr.update_quota(id, 200, 1000).unwrap();
        let updated = mgr.get_tenant(id).unwrap();
        assert_eq!(updated.max_users, 200);
        assert_eq!(updated.max_devices, 1000);
    }

    // ── Cross-tenant protection tests ───────────────────────────────────

    #[test]
    fn assert_same_tenant_passes_for_identical() {
        let id = TenantId::new();
        assert!(assert_same_tenant(&id, &id).is_ok());
    }

    #[test]
    fn assert_same_tenant_fails_for_different() {
        let a = TenantId::new();
        let b = TenantId::new();
        assert!(matches!(
            assert_same_tenant(&a, &b),
            Err(TenantError::TenantMismatch)
        ));
    }

    #[test]
    fn cross_tenant_access_denied_by_default() {
        let mgr = TenantManager::new();
        let t1 = make_tenant("kilo");
        let t2 = make_tenant("lima");
        let id1 = t1.tenant_id;
        let id2 = t2.tenant_id;
        mgr.create_tenant(t1).unwrap();
        mgr.create_tenant(t2).unwrap();

        assert!(matches!(
            mgr.validate_cross_tenant_access(id1, id2),
            Err(TenantError::CrossTenantAccessDenied { .. })
        ));

        // Same tenant access is allowed
        assert!(mgr.validate_cross_tenant_access(id1, id1).is_ok());
    }

    // ── Audit filter tests ──────────────────────────────────────────────

    #[test]
    fn audit_filter_allows_same_tenant() {
        let id = TenantId::new();
        let filter = TenantAuditFilter::new(id);
        assert!(filter.validate_audit_access(&id).is_ok());
    }

    #[test]
    fn audit_filter_denies_cross_tenant() {
        let id1 = TenantId::new();
        let id2 = TenantId::new();
        let filter = TenantAuditFilter::new(id1);
        assert!(matches!(
            filter.validate_audit_access(&id2),
            Err(TenantError::CrossTenantAccessDenied { .. })
        ));
    }

    // ── Encryption key derivation tests ─────────────────────────────────

    #[test]
    fn derive_tenant_kek_deterministic() {
        let id = TenantId::from_uuid(
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
        );
        let master = [0xABu8; 32];
        let kek1 = derive_tenant_kek(id, &master);
        let kek2 = derive_tenant_kek(id, &master);
        assert_eq!(kek1, kek2);
    }

    #[test]
    fn derive_tenant_kek_differs_per_tenant() {
        let master = [0xCDu8; 32];
        let id1 = TenantId::new();
        let id2 = TenantId::new();
        let kek1 = derive_tenant_kek(id1, &master);
        let kek2 = derive_tenant_kek(id2, &master);
        assert_ne!(kek1, kek2);
    }

    #[test]
    fn derive_tenant_kek_differs_per_master() {
        let id = TenantId::new();
        let master1 = [0x01u8; 32];
        let master2 = [0x02u8; 32];
        let kek1 = derive_tenant_kek(id, &master1);
        let kek2 = derive_tenant_kek(id, &master2);
        assert_ne!(kek1, kek2);
    }

    #[test]
    fn get_tenant_encryption_key_id() {
        let mgr = TenantManager::new();
        let tenant = make_tenant("mike");
        let id = tenant.tenant_id;
        let expected_key = tenant.encryption_key_id.clone();
        mgr.create_tenant(tenant).unwrap();

        let key_id = mgr.get_tenant_encryption_key_id(id).unwrap();
        assert_eq!(key_id, expected_key);
    }

    // ── TenantIsolation trait test ──────────────────────────────────────

    #[test]
    fn tenant_implements_isolation_trait() {
        let tenant = make_tenant("november");
        let id = tenant.tenant_id;
        let trait_id: &TenantId = TenantIsolation::tenant_id(&tenant);
        assert_eq!(*trait_id, id);
    }

    // ── TenantComplianceRegime conversion test ──────────────────────────

    #[test]
    fn compliance_regime_conversion() {
        assert_eq!(
            TenantComplianceRegime::UsDod.to_base_regime(),
            Some(ComplianceRegime::UsDod)
        );
        assert_eq!(
            TenantComplianceRegime::IndianGovt.to_base_regime(),
            Some(ComplianceRegime::IndianGovt)
        );
        assert_eq!(
            TenantComplianceRegime::Dual.to_base_regime(),
            Some(ComplianceRegime::Dual)
        );
        assert_eq!(TenantComplianceRegime::Commercial.to_base_regime(), None);
    }

    // ── Suspended tenant cannot increment usage ─────────────────────────

    #[test]
    fn suspended_tenant_cannot_increment_usage() {
        let mgr = TenantManager::new();
        let tenant = make_tenant("oscar");
        let id = tenant.tenant_id;
        mgr.create_tenant(tenant).unwrap();
        mgr.suspend_tenant(id, "review").unwrap();

        assert!(matches!(
            mgr.increment_usage(id, "users"),
            Err(TenantError::TenantNotActive { .. })
        ));
    }

    // ── CIDR IP allowlist tests (security-critical) ─────────────────────

    fn make_policy_with_ip_allowlist(ips: Vec<&str>) -> TenantPolicy {
        TenantPolicy {
            ip_allowlist: ips.into_iter().map(String::from).collect(),
            ..TenantPolicy::default()
        }
    }

    #[test]
    fn cidr_allowlist_exact_match() {
        let pol = make_policy_with_ip_allowlist(vec!["10.0.0.5"]);
        assert!(pol.is_ip_allowed("10.0.0.5"));
        assert!(!pol.is_ip_allowed("10.0.0.6"));
    }

    #[test]
    fn cidr_allowlist_24_subnet() {
        let pol = make_policy_with_ip_allowlist(vec!["192.168.1.0/24"]);
        assert!(pol.is_ip_allowed("192.168.1.0"));
        assert!(pol.is_ip_allowed("192.168.1.1"));
        assert!(pol.is_ip_allowed("192.168.1.255"));
        assert!(!pol.is_ip_allowed("192.168.2.0"));
        assert!(!pol.is_ip_allowed("10.0.0.1"));
    }

    #[test]
    fn cidr_allowlist_16_subnet() {
        let pol = make_policy_with_ip_allowlist(vec!["10.10.0.0/16"]);
        assert!(pol.is_ip_allowed("10.10.0.1"));
        assert!(pol.is_ip_allowed("10.10.255.255"));
        assert!(!pol.is_ip_allowed("10.11.0.1"));
    }

    #[test]
    fn cidr_allowlist_32_single_host() {
        let pol = make_policy_with_ip_allowlist(vec!["10.0.0.1/32"]);
        assert!(pol.is_ip_allowed("10.0.0.1"));
        assert!(!pol.is_ip_allowed("10.0.0.2"));
    }

    #[test]
    fn cidr_allowlist_rejects_random_ip_with_slash() {
        // The old buggy code accepted ANY IP when CIDR notation was present.
        // This test ensures that is fixed.
        let pol = make_policy_with_ip_allowlist(vec!["10.0.0.0/24"]);
        assert!(!pol.is_ip_allowed("192.168.100.50"));
        assert!(!pol.is_ip_allowed("1.2.3.4"));
        assert!(!pol.is_ip_allowed("255.255.255.255"));
    }

    #[test]
    fn cidr_allowlist_empty_allows_all() {
        let pol = make_policy_with_ip_allowlist(vec![]);
        assert!(pol.is_ip_allowed("1.2.3.4"));
        assert!(pol.is_ip_allowed("255.255.255.255"));
    }

    #[test]
    fn cidr_allowlist_mixed_entries() {
        let pol = make_policy_with_ip_allowlist(vec!["10.0.0.5", "192.168.0.0/16"]);
        assert!(pol.is_ip_allowed("10.0.0.5"));
        assert!(pol.is_ip_allowed("192.168.1.100"));
        assert!(!pol.is_ip_allowed("10.0.0.6"));
        assert!(!pol.is_ip_allowed("172.16.0.1"));
    }

    #[test]
    fn cidr_allowlist_invalid_cidr_rejects() {
        let pol = make_policy_with_ip_allowlist(vec!["not-a-cidr/24"]);
        assert!(!pol.is_ip_allowed("10.0.0.1"));
    }

    #[test]
    fn cidr_allowlist_zero_prefix_matches_all() {
        let pol = make_policy_with_ip_allowlist(vec!["0.0.0.0/0"]);
        assert!(pol.is_ip_allowed("10.0.0.1"));
        assert!(pol.is_ip_allowed("192.168.1.1"));
        assert!(pol.is_ip_allowed("255.255.255.255"));
    }
}
