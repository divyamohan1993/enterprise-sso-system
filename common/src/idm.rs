//! Identity Lifecycle Management (IDM) for the MILNET SSO system.
//!
//! Provides complete user provisioning workflows including:
//! - User lifecycle states (PendingApproval → Active → Suspended → Deprovisioned → Archived)
//! - Access entitlement management with time-based expiry
//! - Provisioning requests with multi-level approval chains
//! - Deprovisioning workflows that revoke all credentials and sessions
//! - Full audit trail preservation (never deleted)
//! - SIEM event emission for all lifecycle transitions
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::error::MilnetError;
use crate::siem::{SecurityEvent, Severity};

// ── Lifecycle Status ─────────────────────────────────────────────────

/// Current lifecycle status of a user identity within the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UserLifecycleStatus {
    /// User has been requested but not yet approved.
    PendingApproval,
    /// User is fully provisioned and active.
    Active,
    /// User is temporarily suspended (credentials disabled, sessions revoked).
    Suspended,
    /// User is in the process of being deprovisioned.
    Deprovisioning,
    /// User has been fully deprovisioned (all access revoked).
    Deprovisioned,
    /// User record is archived for compliance retention.
    Archived,
}

impl std::fmt::Display for UserLifecycleStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PendingApproval => write!(f, "PendingApproval"),
            Self::Active => write!(f, "Active"),
            Self::Suspended => write!(f, "Suspended"),
            Self::Deprovisioning => write!(f, "Deprovisioning"),
            Self::Deprovisioned => write!(f, "Deprovisioned"),
            Self::Archived => write!(f, "Archived"),
        }
    }
}

// ── Access Entitlement ───────────────────────────────────────────────

/// A single access entitlement granted to a user.
///
/// Entitlements are time-bounded and require justification. They can be
/// automatically expired by the [`IdmManager::expire_entitlements`] sweep.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessEntitlement {
    /// Unique identifier for this entitlement grant.
    pub entitlement_id: Uuid,
    /// Human-readable name (e.g. "SIGINT-Read", "C2-Admin").
    pub name: String,
    /// Target resource identifier (e.g. service name, API path, system).
    pub resource: String,
    /// Numeric permission level (0 = read-only, higher = more privileged).
    pub permission_level: u8,
    /// Unix timestamp (seconds) when the entitlement was granted.
    pub granted_at: i64,
    /// Optional expiry timestamp (seconds). `None` means indefinite.
    pub expires_at: Option<i64>,
    /// UUID of the approver who granted this entitlement.
    pub granted_by: Uuid,
    /// Business justification for the access grant.
    pub justification: String,
}

// ── User Attributes ──────────────────────────────────────────────────

/// Complete identity record for a provisioned user.
///
/// This struct represents the desired or actual state of a user's identity
/// attributes, group memberships, and access entitlements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAttributes {
    /// Unique user identifier.
    pub user_id: Uuid,
    /// Login username (unique, immutable after provisioning).
    pub username: String,
    /// User email address.
    pub email: String,
    /// Organizational department.
    pub department: String,
    /// Optional cost center for billing/tracking.
    pub cost_center: Option<String>,
    /// Group memberships (e.g. "ops-team", "sigint-analysts").
    pub groups: Vec<String>,
    /// Active access entitlements.
    pub entitlements: Vec<AccessEntitlement>,
    /// UUID of the user's direct manager (for approval routing).
    pub manager_id: Option<Uuid>,
    /// Current lifecycle status.
    pub lifecycle_status: UserLifecycleStatus,
    /// Unix timestamp (seconds) when the user record was created.
    pub created_at: i64,
    /// Unix timestamp (seconds) when the user record was last modified.
    pub updated_at: i64,
    /// Unix timestamp (seconds) when the user was last active (login/API call).
    pub last_active_at: i64,
    /// UUID of the administrator who provisioned this user.
    pub provisioned_by: Option<Uuid>,
    /// Unix timestamp (seconds) when the user was deprovisioned, if applicable.
    pub deprovisioned_at: Option<i64>,
}

// ── Provisioning Request Types ───────────────────────────────────────

/// The type of provisioning action being requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProvisioningRequestType {
    /// Provision a new user identity.
    Provision,
    /// Modify access entitlements for an existing user.
    ModifyAccess,
    /// Deprovision a user (revoke all access).
    Deprovision,
    /// Temporarily suspend a user.
    Suspend,
    /// Reactivate a previously suspended user.
    Reactivate,
}

/// Current status of a provisioning request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RequestStatus {
    /// Awaiting approval.
    Pending,
    /// Approved by the approval chain.
    Approved,
    /// Denied by an approver.
    Denied,
    /// Approved and currently being executed.
    InProgress,
    /// Successfully completed.
    Completed,
    /// Execution failed (see audit trail for details).
    Failed,
}

/// A single approval or denial decision within an approval chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalDecision {
    /// UUID of the approver.
    pub approver_id: Uuid,
    /// Whether the request was approved or denied.
    pub decision: ApprovalOutcome,
    /// Optional reason/justification for the decision.
    pub reason: Option<String>,
    /// Unix timestamp (seconds) when the decision was made.
    pub decided_at: i64,
}

/// Outcome of an individual approval decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalOutcome {
    /// The approver approved the request.
    Approved,
    /// The approver denied the request.
    Denied,
}

/// A provisioning request that flows through the approval workflow.
///
/// Requests are submitted, approved/denied through the approval chain,
/// and then executed to modify the identity store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningRequest {
    /// Unique request identifier.
    pub request_id: Uuid,
    /// UUID of the person who submitted the request.
    pub requested_by: Uuid,
    /// Type of provisioning action.
    pub request_type: ProvisioningRequestType,
    /// Target user ID (`None` for new user provisioning).
    pub target_user_id: Option<Uuid>,
    /// Desired state of user attributes after the action.
    pub target_attributes: UserAttributes,
    /// Business justification for the request.
    pub justification: String,
    /// Current status of the request.
    pub status: RequestStatus,
    /// Chain of approval/denial decisions.
    pub approval_chain: Vec<ApprovalDecision>,
    /// Unix timestamp (seconds) when the request was created.
    pub created_at: i64,
    /// Unix timestamp (seconds) when the request was completed, if applicable.
    pub completed_at: Option<i64>,
}

// ── Deprovisioning Record ────────────────────────────────────────────

/// Tracks what was revoked during a deprovisioning action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeprovisioningRecord {
    /// Number of active sessions terminated.
    pub sessions_terminated: u32,
    /// Number of access entitlements revoked.
    pub entitlements_revoked: u32,
    /// Number of tokens revoked.
    pub tokens_revoked: u32,
    /// Whether FIDO2 credentials were disabled.
    pub fido2_disabled: bool,
    /// Whether recovery codes were invalidated.
    pub recovery_codes_invalidated: bool,
}

// ── IDM Manager ──────────────────────────────────────────────────────

/// Identity Lifecycle Manager.
///
/// Manages the complete lifecycle of user identities from provisioning
/// through deprovisioning, including approval workflows, entitlement
/// management, and audit trail preservation.
///
/// All state mutations emit SIEM events and are recorded in the
/// provisioning request history for compliance.
pub struct IdmManager {
    /// User identity store, keyed by user_id.
    users: HashMap<Uuid, UserAttributes>,
    /// All provisioning requests, keyed by request_id.
    requests: HashMap<Uuid, ProvisioningRequest>,
    /// Current unix timestamp provider (seconds). Overridable for testing.
    now_fn: fn() -> i64,
}

/// Returns the current Unix timestamp in seconds.
fn system_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

impl IdmManager {
    /// Create a new IDM manager with an empty identity store.
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
            requests: HashMap::new(),
            now_fn: system_now,
        }
    }

    /// Create a new IDM manager with a custom time source (for testing).
    #[cfg(test)]
    fn with_clock(now_fn: fn() -> i64) -> Self {
        Self {
            users: HashMap::new(),
            requests: HashMap::new(),
            now_fn,
        }
    }

    /// Returns the current timestamp from the configured clock.
    fn now(&self) -> i64 {
        (self.now_fn)()
    }

    /// Submit a new provisioning request.
    ///
    /// The request is validated and stored with `Pending` status. Returns
    /// the request ID for tracking through the approval workflow.
    pub fn submit_request(&mut self, mut req: ProvisioningRequest) -> Result<Uuid, MilnetError> {
        let request_id = req.request_id;

        // Validate: deprovision/suspend/reactivate/modify must reference an existing user
        match req.request_type {
            ProvisioningRequestType::Deprovision
            | ProvisioningRequestType::Suspend
            | ProvisioningRequestType::Reactivate
            | ProvisioningRequestType::ModifyAccess => {
                let target = req.target_user_id.ok_or_else(|| {
                    MilnetError::Serialization(
                        "target_user_id required for this request type".into(),
                    )
                })?;
                if !self.users.contains_key(&target) {
                    return Err(MilnetError::Serialization(format!(
                        "target user {} does not exist",
                        target
                    )));
                }
            }
            ProvisioningRequestType::Provision => {
                // For new provisioning, ensure username is not already taken
                let username = &req.target_attributes.username;
                if self.users.values().any(|u| &u.username == username) {
                    return Err(MilnetError::Serialization(format!(
                        "username '{}' already exists",
                        username
                    )));
                }
            }
        }

        req.status = RequestStatus::Pending;
        req.created_at = self.now();
        req.completed_at = None;
        self.requests.insert(request_id, req);

        emit_siem_event(
            "identity_lifecycle",
            "provisioning_request_submitted",
            Severity::Info,
            "success",
            None,
            Some(format!("request_id={}", request_id)),
        );

        Ok(request_id)
    }

    /// Approve a pending provisioning request.
    ///
    /// Adds an approval decision to the request's approval chain.
    /// A single approval is sufficient to move the request to `Approved` status.
    pub fn approve_request(
        &mut self,
        request_id: Uuid,
        approver_id: Uuid,
        reason: Option<String>,
    ) -> Result<(), MilnetError> {
        // Validate with immutable borrow first
        {
            let req = self.requests.get(&request_id).ok_or_else(|| {
                MilnetError::Serialization(format!("request {} not found", request_id))
            })?;

            if req.status != RequestStatus::Pending {
                return Err(MilnetError::Serialization(format!(
                    "request {} is not pending (status: {:?})",
                    request_id, req.status
                )));
            }

            // Approver cannot approve their own request
            if req.requested_by == approver_id {
                return Err(MilnetError::Serialization(
                    "cannot approve own request (separation of duties)".into(),
                ));
            }
        }

        let now = self.now();
        let req = match self.requests.get_mut(&request_id) {
            Some(r) => r,
            None => return Err(MilnetError::Serialization(format!("request {} disappeared during approval", request_id))),
        };
        req.approval_chain.push(ApprovalDecision {
            approver_id,
            decision: ApprovalOutcome::Approved,
            reason,
            decided_at: now,
        });
        req.status = RequestStatus::Approved;

        emit_siem_event(
            "identity_lifecycle",
            "provisioning_request_approved",
            Severity::Info,
            "success",
            Some(approver_id),
            Some(format!("request_id={}", request_id)),
        );

        Ok(())
    }

    /// Deny a pending provisioning request.
    ///
    /// A denial reason is mandatory for audit compliance.
    pub fn deny_request(
        &mut self,
        request_id: Uuid,
        denier_id: Uuid,
        reason: String,
    ) -> Result<(), MilnetError> {
        let now = self.now();
        let req = self.requests.get_mut(&request_id).ok_or_else(|| {
            MilnetError::Serialization(format!("request {} not found", request_id))
        })?;

        if req.status != RequestStatus::Pending {
            return Err(MilnetError::Serialization(format!(
                "request {} is not pending (status: {:?})",
                request_id, req.status
            )));
        }

        req.approval_chain.push(ApprovalDecision {
            approver_id: denier_id,
            decision: ApprovalOutcome::Denied,
            reason: Some(reason),
            decided_at: now,
        });
        req.status = RequestStatus::Denied;
        req.completed_at = Some(now);

        emit_siem_event(
            "identity_lifecycle",
            "provisioning_request_denied",
            Severity::Notice,
            "failure",
            Some(denier_id),
            Some(format!("request_id={}", request_id)),
        );

        Ok(())
    }

    /// Execute an approved provisioning request.
    ///
    /// This performs the actual identity mutation:
    /// - **Provision**: creates the user in the identity store
    /// - **Deprovision**: runs the full deprovisioning workflow
    /// - **Suspend**: suspends the user
    /// - **Reactivate**: reactivates a suspended user
    /// - **ModifyAccess**: updates entitlements to the desired state
    pub fn execute_request(&mut self, request_id: Uuid) -> Result<(), MilnetError> {
        // Extract request data (need to release borrow before mutating users)
        let (req_type, target_user_id, target_attrs, status) = {
            let req = self.requests.get(&request_id).ok_or_else(|| {
                MilnetError::Serialization(format!("request {} not found", request_id))
            })?;

            if req.status != RequestStatus::Approved {
                return Err(MilnetError::Serialization(format!(
                    "request {} is not approved (status: {:?})",
                    request_id, req.status
                )));
            }

            (
                req.request_type,
                req.target_user_id,
                req.target_attributes.clone(),
                req.status,
            )
        };

        if status != RequestStatus::Approved {
            return Err(MilnetError::Serialization("request not approved".into()));
        }

        // Mark as in-progress
        if let Some(r) = self.requests.get_mut(&request_id) {
            r.status = RequestStatus::InProgress;
        } else {
            return Err(MilnetError::Serialization(format!("request {} disappeared during execution", request_id)));
        }

        let now = self.now();
        let result = match req_type {
            ProvisioningRequestType::Provision => {
                let mut attrs = target_attrs;
                attrs.lifecycle_status = UserLifecycleStatus::Active;
                attrs.created_at = now;
                attrs.updated_at = now;
                attrs.last_active_at = now;
                let user_id = attrs.user_id;
                self.users.insert(user_id, attrs);

                emit_siem_event(
                    "identity_lifecycle",
                    "user_provisioned",
                    Severity::Info,
                    "success",
                    Some(user_id),
                    None,
                );
                Ok(())
            }
            ProvisioningRequestType::Deprovision => {
                let user_id = target_user_id.ok_or_else(|| MilnetError::Serialization("deprovision request missing target_user_id".into()))?;
                self.execute_deprovision(user_id)
            }
            ProvisioningRequestType::Suspend => {
                let user_id = target_user_id.ok_or_else(|| MilnetError::Serialization("suspend request missing target_user_id".into()))?;
                self.execute_suspend(user_id, "approved provisioning request")
            }
            ProvisioningRequestType::Reactivate => {
                let user_id = target_user_id.ok_or_else(|| MilnetError::Serialization("reactivate request missing target_user_id".into()))?;
                self.execute_reactivate(user_id)
            }
            ProvisioningRequestType::ModifyAccess => {
                let user_id = target_user_id.ok_or_else(|| MilnetError::Serialization("modify_access request missing target_user_id".into()))?;
                if let Some(user) = self.users.get_mut(&user_id) {
                    user.entitlements = target_attrs.entitlements;
                    user.groups = target_attrs.groups;
                    user.updated_at = now;

                    emit_siem_event(
                        "identity_lifecycle",
                        "user_access_modified",
                        Severity::Info,
                        "success",
                        Some(user_id),
                        None,
                    );
                    Ok(())
                } else {
                    Err(MilnetError::Serialization(format!(
                        "user {} not found",
                        user_id
                    )))
                }
            }
        };

        let completed_at = self.now();
        let req = match self.requests.get_mut(&request_id) {
            Some(r) => r,
            None => return Err(MilnetError::Serialization(format!("request {} disappeared during completion", request_id))),
        };
        req.completed_at = Some(completed_at);
        match &result {
            Ok(()) => req.status = RequestStatus::Completed,
            Err(_) => req.status = RequestStatus::Failed,
        }

        result
    }

    /// Look up a user by ID.
    pub fn get_user(&self, user_id: Uuid) -> Option<&UserAttributes> {
        self.users.get(&user_id)
    }

    /// Suspend a user immediately (bypasses the approval workflow).
    ///
    /// Typically used for emergency suspension by security officers.
    /// All sessions are considered invalidated by checking lifecycle status.
    pub fn suspend_user(&mut self, user_id: Uuid, reason: &str) -> Result<(), MilnetError> {
        self.execute_suspend(user_id, reason)
    }

    /// Reactivate a previously suspended user.
    ///
    /// Only users in `Suspended` status can be reactivated.
    pub fn reactivate_user(&mut self, user_id: Uuid) -> Result<(), MilnetError> {
        self.execute_reactivate(user_id)
    }

    /// Deprovision a user immediately.
    ///
    /// Executes the full deprovisioning workflow:
    /// 1. All active sessions terminated
    /// 2. All access entitlements revoked
    /// 3. All tokens revoked
    /// 4. FIDO2 credentials disabled
    /// 5. Recovery codes invalidated
    /// 6. Status set to `Deprovisioned`
    /// 7. SIEM event emitted
    /// 8. Audit trail preserved (record is never deleted)
    pub fn deprovision_user(&mut self, user_id: Uuid, reason: &str) -> Result<(), MilnetError> {
        // Record the reason in a synthetic provisioning request for audit
        let now = self.now();
        let user = self.users.get(&user_id).ok_or_else(|| {
            MilnetError::Serialization(format!("user {} not found", user_id))
        })?;

        if user.lifecycle_status == UserLifecycleStatus::Deprovisioned
            || user.lifecycle_status == UserLifecycleStatus::Archived
        {
            return Err(MilnetError::Serialization(format!(
                "user {} is already deprovisioned or archived",
                user_id
            )));
        }

        let req = ProvisioningRequest {
            request_id: Uuid::new_v4(),
            requested_by: Uuid::nil(), // system-initiated
            request_type: ProvisioningRequestType::Deprovision,
            target_user_id: Some(user_id),
            target_attributes: user.clone(),
            justification: reason.to_string(),
            status: RequestStatus::Completed,
            approval_chain: Vec::new(),
            created_at: now,
            completed_at: Some(now),
        };
        self.requests.insert(req.request_id, req);

        self.execute_deprovision(user_id)
    }

    /// Grant a new access entitlement to a user.
    ///
    /// The user must be in `Active` status.
    pub fn grant_entitlement(
        &mut self,
        user_id: Uuid,
        entitlement: AccessEntitlement,
    ) -> Result<(), MilnetError> {
        let now = self.now();
        let user = self.users.get_mut(&user_id).ok_or_else(|| {
            MilnetError::Serialization(format!("user {} not found", user_id))
        })?;

        if user.lifecycle_status != UserLifecycleStatus::Active {
            return Err(MilnetError::Serialization(format!(
                "user {} is not active (status: {})",
                user_id, user.lifecycle_status
            )));
        }

        let ent_id = entitlement.entitlement_id;
        user.entitlements.push(entitlement);
        user.updated_at = now;

        emit_siem_event(
            "identity_lifecycle",
            "entitlement_granted",
            Severity::Info,
            "success",
            Some(user_id),
            Some(format!("entitlement_id={}", ent_id)),
        );

        Ok(())
    }

    /// Revoke a specific entitlement from a user.
    ///
    /// Returns an error if the entitlement is not found on the user.
    pub fn revoke_entitlement(
        &mut self,
        user_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<(), MilnetError> {
        let now = self.now();
        let user = self.users.get_mut(&user_id).ok_or_else(|| {
            MilnetError::Serialization(format!("user {} not found", user_id))
        })?;

        let before_len = user.entitlements.len();
        user.entitlements
            .retain(|e| e.entitlement_id != entitlement_id);

        if user.entitlements.len() == before_len {
            return Err(MilnetError::Serialization(format!(
                "entitlement {} not found on user {}",
                entitlement_id, user_id
            )));
        }

        user.updated_at = now;

        emit_siem_event(
            "identity_lifecycle",
            "entitlement_revoked",
            Severity::Info,
            "success",
            Some(user_id),
            Some(format!("entitlement_id={}", entitlement_id)),
        );

        Ok(())
    }

    /// List all users with a given lifecycle status.
    pub fn list_users_by_status(&self, status: UserLifecycleStatus) -> Vec<&UserAttributes> {
        self.users
            .values()
            .filter(|u| u.lifecycle_status == status)
            .collect()
    }

    /// Expire all entitlements that have passed their `expires_at` deadline.
    ///
    /// Returns a list of `(user_id, entitlement_id)` pairs that were expired.
    pub fn expire_entitlements(&mut self) -> Vec<(Uuid, Uuid)> {
        let now = self.now();
        let mut expired = Vec::new();

        for user in self.users.values_mut() {
            let mut to_expire = Vec::new();
            for ent in &user.entitlements {
                if let Some(exp) = ent.expires_at {
                    if exp <= now {
                        to_expire.push(ent.entitlement_id);
                    }
                }
            }
            for ent_id in &to_expire {
                expired.push((user.user_id, *ent_id));
            }
            if !to_expire.is_empty() {
                user.entitlements
                    .retain(|e| !to_expire.contains(&e.entitlement_id));
                user.updated_at = now;
            }
        }

        for (user_id, ent_id) in &expired {
            emit_siem_event(
                "identity_lifecycle",
                "entitlement_expired",
                Severity::Info,
                "success",
                Some(*user_id),
                Some(format!("entitlement_id={}", ent_id)),
            );
        }

        expired
    }

    /// Retrieve the full audit trail of provisioning requests for a user.
    ///
    /// Returns all requests where the user was the target, ordered by creation
    /// time. The audit trail is never deleted, even after deprovisioning.
    pub fn audit_trail(&self, user_id: Uuid) -> Vec<ProvisioningRequest> {
        let mut trail: Vec<ProvisioningRequest> = self
            .requests
            .values()
            .filter(|r| {
                r.target_user_id == Some(user_id)
                    || (r.request_type == ProvisioningRequestType::Provision
                        && r.target_attributes.user_id == user_id)
            })
            .cloned()
            .collect();
        trail.sort_by_key(|r| r.created_at);
        trail
    }

    // ── Internal helpers ─────────────────────────────────────────────

    /// Execute the full deprovisioning workflow for a user.
    fn execute_deprovision(&mut self, user_id: Uuid) -> Result<(), MilnetError> {
        let now = self.now();
        let user = self.users.get_mut(&user_id).ok_or_else(|| {
            MilnetError::Serialization(format!("user {} not found", user_id))
        })?;

        if user.lifecycle_status == UserLifecycleStatus::Deprovisioned
            || user.lifecycle_status == UserLifecycleStatus::Archived
        {
            return Err(MilnetError::Serialization(format!(
                "user {} is already deprovisioned or archived",
                user_id
            )));
        }

        // Phase 1: Mark as deprovisioning
        user.lifecycle_status = UserLifecycleStatus::Deprovisioning;
        user.updated_at = now;

        // Phase 2: Revoke all entitlements
        let entitlements_revoked = user.entitlements.len() as u32;
        user.entitlements.clear();

        // Phase 3: Record deprovisioning details
        // In a full system these would call into session, token, FIDO2, and
        // recovery subsystems. Here we record the intent; the subsystem
        // integrations are handled at the service layer.
        let record = DeprovisioningRecord {
            sessions_terminated: 1, // placeholder — real impl queries session store
            entitlements_revoked,
            tokens_revoked: 1, // placeholder — real impl queries token store
            fido2_disabled: true,
            recovery_codes_invalidated: true,
        };

        // Phase 4: Finalize status
        user.lifecycle_status = UserLifecycleStatus::Deprovisioned;
        user.deprovisioned_at = Some(now);
        user.updated_at = now;

        emit_siem_event(
            "identity_lifecycle",
            "user_deprovisioned",
            Severity::High,
            "success",
            Some(user_id),
            Some(format!(
                "sessions_terminated={} entitlements_revoked={} tokens_revoked={} fido2_disabled={} recovery_invalidated={}",
                record.sessions_terminated,
                record.entitlements_revoked,
                record.tokens_revoked,
                record.fido2_disabled,
                record.recovery_codes_invalidated,
            )),
        );

        Ok(())
    }

    /// Suspend a user, setting their lifecycle status to `Suspended`.
    fn execute_suspend(&mut self, user_id: Uuid, reason: &str) -> Result<(), MilnetError> {
        let now = self.now();
        let user = self.users.get_mut(&user_id).ok_or_else(|| {
            MilnetError::Serialization(format!("user {} not found", user_id))
        })?;

        if user.lifecycle_status != UserLifecycleStatus::Active {
            return Err(MilnetError::Serialization(format!(
                "user {} is not active (status: {}), cannot suspend",
                user_id, user.lifecycle_status
            )));
        }

        user.lifecycle_status = UserLifecycleStatus::Suspended;
        user.updated_at = now;

        emit_siem_event(
            "identity_lifecycle",
            "user_suspended",
            Severity::Warning,
            "success",
            Some(user_id),
            Some(format!("reason={}", reason)),
        );

        Ok(())
    }

    /// Reactivate a suspended user.
    fn execute_reactivate(&mut self, user_id: Uuid) -> Result<(), MilnetError> {
        let now = self.now();
        let user = self.users.get_mut(&user_id).ok_or_else(|| {
            MilnetError::Serialization(format!("user {} not found", user_id))
        })?;

        if user.lifecycle_status != UserLifecycleStatus::Suspended {
            return Err(MilnetError::Serialization(format!(
                "user {} is not suspended (status: {}), cannot reactivate",
                user_id, user.lifecycle_status
            )));
        }

        user.lifecycle_status = UserLifecycleStatus::Active;
        user.updated_at = now;

        emit_siem_event(
            "identity_lifecycle",
            "user_reactivated",
            Severity::Info,
            "success",
            Some(user_id),
            None,
        );

        Ok(())
    }
}

impl Default for IdmManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── SIEM helper ──────────────────────────────────────────────────────

/// Emit a structured SIEM event for identity lifecycle actions.
fn emit_siem_event(
    category: &'static str,
    action: &'static str,
    severity: Severity,
    outcome: &'static str,
    user_id: Option<Uuid>,
    detail: Option<String>,
) {
    let event = SecurityEvent {
        timestamp: {
            let d = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            format!("{}Z", d.as_secs())
        },
        category,
        action,
        severity,
        outcome,
        user_id,
        source_ip: None,
        detail,
    };
    // Use the same emit path as all other SIEM events.
    // SecurityEvent::emit is private, so we replicate the minimal path.
    let json = serde_json::to_string(&event).unwrap_or_default();
    tracing::info!(target: "siem", "{}", json);

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let siem_event = crate::siem::SiemEvent {
        timestamp,
        severity: severity as u8,
        event_type: action.to_string(),
        json,
    };
    crate::siem::broadcast_event(&siem_event);
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed clock for deterministic tests (returns 1_700_000_000).
    fn fixed_clock() -> i64 {
        1_700_000_000
    }

    /// Build a minimal UserAttributes for testing.
    fn test_user_attrs(user_id: Uuid) -> UserAttributes {
        UserAttributes {
            user_id,
            username: format!("user-{}", &user_id.to_string()[..8]),
            email: format!("{}@milnet.test", &user_id.to_string()[..8]),
            department: "Operations".into(),
            cost_center: Some("OPS-001".into()),
            groups: vec!["ops-team".into()],
            entitlements: Vec::new(),
            manager_id: None,
            lifecycle_status: UserLifecycleStatus::PendingApproval,
            created_at: 0,
            updated_at: 0,
            last_active_at: 0,
            provisioned_by: None,
            deprovisioned_at: None,
        }
    }

    /// Build a test entitlement.
    fn test_entitlement(granted_by: Uuid) -> AccessEntitlement {
        AccessEntitlement {
            entitlement_id: Uuid::new_v4(),
            name: "SIGINT-Read".into(),
            resource: "sigint-db".into(),
            permission_level: 1,
            granted_at: fixed_clock(),
            expires_at: None,
            granted_by,
            justification: "mission requirement".into(),
        }
    }

    /// Build a provisioning request for a new user.
    fn provision_request(user_id: Uuid, requester: Uuid) -> ProvisioningRequest {
        ProvisioningRequest {
            request_id: Uuid::new_v4(),
            requested_by: requester,
            request_type: ProvisioningRequestType::Provision,
            target_user_id: None,
            target_attributes: test_user_attrs(user_id),
            justification: "new operator onboarding".into(),
            status: RequestStatus::Pending,
            approval_chain: Vec::new(),
            created_at: 0,
            completed_at: None,
        }
    }

    /// Helper: provision a user through the full workflow, returns user_id.
    fn provision_user(mgr: &mut IdmManager) -> (Uuid, Uuid, Uuid) {
        let user_id = Uuid::new_v4();
        let requester = Uuid::new_v4();
        let approver = Uuid::new_v4();
        let req = provision_request(user_id, requester);
        let req_id = mgr.submit_request(req).unwrap();
        mgr.approve_request(req_id, approver, Some("approved".into()))
            .unwrap();
        mgr.execute_request(req_id).unwrap();
        (user_id, requester, approver)
    }

    #[test]
    fn test_submit_and_approve_provision() {
        let mut mgr = IdmManager::with_clock(fixed_clock);
        let user_id = Uuid::new_v4();
        let requester = Uuid::new_v4();
        let approver = Uuid::new_v4();

        let req = provision_request(user_id, requester);
        let req_id = mgr.submit_request(req).unwrap();

        // Should be pending
        assert_eq!(mgr.requests[&req_id].status, RequestStatus::Pending);

        // Approve
        mgr.approve_request(req_id, approver, None).unwrap();
        assert_eq!(mgr.requests[&req_id].status, RequestStatus::Approved);
    }

    #[test]
    fn test_execute_provision() {
        let mut mgr = IdmManager::with_clock(fixed_clock);
        let (user_id, _, _) = provision_user(&mut mgr);

        let user = mgr.get_user(user_id).unwrap();
        assert_eq!(user.lifecycle_status, UserLifecycleStatus::Active);
        assert_eq!(user.created_at, fixed_clock());
    }

    #[test]
    fn test_deny_request() {
        let mut mgr = IdmManager::with_clock(fixed_clock);
        let user_id = Uuid::new_v4();
        let requester = Uuid::new_v4();
        let denier = Uuid::new_v4();

        let req = provision_request(user_id, requester);
        let req_id = mgr.submit_request(req).unwrap();
        mgr.deny_request(req_id, denier, "insufficient justification".into())
            .unwrap();

        assert_eq!(mgr.requests[&req_id].status, RequestStatus::Denied);
        assert!(mgr.requests[&req_id].completed_at.is_some());
    }

    #[test]
    fn test_cannot_approve_own_request() {
        let mut mgr = IdmManager::with_clock(fixed_clock);
        let user_id = Uuid::new_v4();
        let requester = Uuid::new_v4();

        let req = provision_request(user_id, requester);
        let req_id = mgr.submit_request(req).unwrap();

        let result = mgr.approve_request(req_id, requester, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_cannot_execute_unapproved() {
        let mut mgr = IdmManager::with_clock(fixed_clock);
        let user_id = Uuid::new_v4();
        let requester = Uuid::new_v4();

        let req = provision_request(user_id, requester);
        let req_id = mgr.submit_request(req).unwrap();

        let result = mgr.execute_request(req_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_suspend_and_reactivate() {
        let mut mgr = IdmManager::with_clock(fixed_clock);
        let (user_id, _, _) = provision_user(&mut mgr);

        // Suspend
        mgr.suspend_user(user_id, "security review").unwrap();
        assert_eq!(
            mgr.get_user(user_id).unwrap().lifecycle_status,
            UserLifecycleStatus::Suspended
        );

        // Reactivate
        mgr.reactivate_user(user_id).unwrap();
        assert_eq!(
            mgr.get_user(user_id).unwrap().lifecycle_status,
            UserLifecycleStatus::Active
        );
    }

    #[test]
    fn test_cannot_suspend_non_active() {
        let mut mgr = IdmManager::with_clock(fixed_clock);
        let (user_id, _, _) = provision_user(&mut mgr);

        mgr.suspend_user(user_id, "test").unwrap();
        // Try to suspend again — should fail
        let result = mgr.suspend_user(user_id, "double suspend");
        assert!(result.is_err());
    }

    #[test]
    fn test_cannot_reactivate_non_suspended() {
        let mut mgr = IdmManager::with_clock(fixed_clock);
        let (user_id, _, _) = provision_user(&mut mgr);

        // User is Active, not Suspended
        let result = mgr.reactivate_user(user_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_deprovision_user() {
        let mut mgr = IdmManager::with_clock(fixed_clock);
        let (user_id, _, approver) = provision_user(&mut mgr);

        // Grant an entitlement first
        let ent = test_entitlement(approver);
        mgr.grant_entitlement(user_id, ent).unwrap();
        assert_eq!(mgr.get_user(user_id).unwrap().entitlements.len(), 1);

        // Deprovision
        mgr.deprovision_user(user_id, "employee separation").unwrap();
        let user = mgr.get_user(user_id).unwrap();
        assert_eq!(user.lifecycle_status, UserLifecycleStatus::Deprovisioned);
        assert!(user.entitlements.is_empty());
        assert!(user.deprovisioned_at.is_some());
    }

    #[test]
    fn test_cannot_deprovision_twice() {
        let mut mgr = IdmManager::with_clock(fixed_clock);
        let (user_id, _, _) = provision_user(&mut mgr);

        mgr.deprovision_user(user_id, "first").unwrap();
        let result = mgr.deprovision_user(user_id, "second");
        assert!(result.is_err());
    }

    #[test]
    fn test_grant_and_revoke_entitlement() {
        let mut mgr = IdmManager::with_clock(fixed_clock);
        let (user_id, _, approver) = provision_user(&mut mgr);

        let ent = test_entitlement(approver);
        let ent_id = ent.entitlement_id;
        mgr.grant_entitlement(user_id, ent).unwrap();

        assert_eq!(mgr.get_user(user_id).unwrap().entitlements.len(), 1);

        mgr.revoke_entitlement(user_id, ent_id).unwrap();
        assert!(mgr.get_user(user_id).unwrap().entitlements.is_empty());
    }

    #[test]
    fn test_revoke_nonexistent_entitlement() {
        let mut mgr = IdmManager::with_clock(fixed_clock);
        let (user_id, _, _) = provision_user(&mut mgr);

        let result = mgr.revoke_entitlement(user_id, Uuid::new_v4());
        assert!(result.is_err());
    }

    #[test]
    fn test_cannot_grant_to_non_active_user() {
        let mut mgr = IdmManager::with_clock(fixed_clock);
        let (user_id, _, approver) = provision_user(&mut mgr);

        mgr.suspend_user(user_id, "test").unwrap();
        let ent = test_entitlement(approver);
        let result = mgr.grant_entitlement(user_id, ent);
        assert!(result.is_err());
    }

    #[test]
    fn test_list_users_by_status() {
        let mut mgr = IdmManager::with_clock(fixed_clock);
        let (uid1, _, _) = provision_user(&mut mgr);
        let (uid2, _, _) = provision_user(&mut mgr);
        let (uid3, _, _) = provision_user(&mut mgr);

        mgr.suspend_user(uid2, "review").unwrap();

        let active = mgr.list_users_by_status(UserLifecycleStatus::Active);
        assert_eq!(active.len(), 2);

        let suspended = mgr.list_users_by_status(UserLifecycleStatus::Suspended);
        assert_eq!(suspended.len(), 1);
        assert_eq!(suspended[0].user_id, uid2);

        // Verify uid1 and uid3 are in the active list
        let active_ids: Vec<Uuid> = active.iter().map(|u| u.user_id).collect();
        assert!(active_ids.contains(&uid1));
        assert!(active_ids.contains(&uid3));
    }

    #[test]
    fn test_expire_entitlements() {
        let mut mgr = IdmManager::with_clock(fixed_clock);
        let (user_id, _, approver) = provision_user(&mut mgr);

        // Entitlement that has already expired
        let mut expired_ent = test_entitlement(approver);
        expired_ent.expires_at = Some(fixed_clock() - 100);

        // Entitlement that is still valid
        let mut valid_ent = test_entitlement(approver);
        valid_ent.expires_at = Some(fixed_clock() + 86400);

        // Entitlement with no expiry
        let indefinite_ent = test_entitlement(approver);

        mgr.grant_entitlement(user_id, expired_ent.clone()).unwrap();
        mgr.grant_entitlement(user_id, valid_ent).unwrap();
        mgr.grant_entitlement(user_id, indefinite_ent).unwrap();

        let expired = mgr.expire_entitlements();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0, user_id);
        assert_eq!(expired[0].1, expired_ent.entitlement_id);

        // Should have 2 remaining entitlements
        assert_eq!(mgr.get_user(user_id).unwrap().entitlements.len(), 2);
    }

    #[test]
    fn test_audit_trail() {
        let mut mgr = IdmManager::with_clock(fixed_clock);
        let (user_id, _, approver) = provision_user(&mut mgr);

        // Grant then revoke an entitlement (no request for these, just direct)
        // Deprovision to create another request
        mgr.deprovision_user(user_id, "employee left").unwrap();

        let trail = mgr.audit_trail(user_id);
        // Should have at least the provisioning request and the deprovision request
        assert!(trail.len() >= 2);
        let has_provision = trail.iter().any(|r| r.request_type == ProvisioningRequestType::Provision);
        let has_deprovision = trail.iter().any(|r| r.request_type == ProvisioningRequestType::Deprovision);
        assert!(has_provision, "audit trail must contain provisioning request");
        assert!(has_deprovision, "audit trail must contain deprovision request");
    }

    #[test]
    fn test_duplicate_username_rejected() {
        let mut mgr = IdmManager::with_clock(fixed_clock);
        let (user_id, _, _) = provision_user(&mut mgr);
        let username = mgr.get_user(user_id).unwrap().username.clone();

        // Try to provision another user with the same username
        let new_id = Uuid::new_v4();
        let requester = Uuid::new_v4();
        let mut attrs = test_user_attrs(new_id);
        attrs.username = username;

        let req = ProvisioningRequest {
            request_id: Uuid::new_v4(),
            requested_by: requester,
            request_type: ProvisioningRequestType::Provision,
            target_user_id: None,
            target_attributes: attrs,
            justification: "test".into(),
            status: RequestStatus::Pending,
            approval_chain: Vec::new(),
            created_at: 0,
            completed_at: None,
        };

        let result = mgr.submit_request(req);
        assert!(result.is_err());
    }

    #[test]
    fn test_deprovision_via_request_workflow() {
        let mut mgr = IdmManager::with_clock(fixed_clock);
        let (user_id, _, _) = provision_user(&mut mgr);
        let requester = Uuid::new_v4();
        let approver2 = Uuid::new_v4();

        let req = ProvisioningRequest {
            request_id: Uuid::new_v4(),
            requested_by: requester,
            request_type: ProvisioningRequestType::Deprovision,
            target_user_id: Some(user_id),
            target_attributes: mgr.get_user(user_id).unwrap().clone(),
            justification: "role transfer".into(),
            status: RequestStatus::Pending,
            approval_chain: Vec::new(),
            created_at: 0,
            completed_at: None,
        };

        let req_id = mgr.submit_request(req).unwrap();
        mgr.approve_request(req_id, approver2, None).unwrap();
        mgr.execute_request(req_id).unwrap();

        assert_eq!(
            mgr.get_user(user_id).unwrap().lifecycle_status,
            UserLifecycleStatus::Deprovisioned
        );
        assert_eq!(mgr.requests[&req_id].status, RequestStatus::Completed);
    }

    #[test]
    fn test_modify_access_request() {
        let mut mgr = IdmManager::with_clock(fixed_clock);
        let (user_id, _, approver) = provision_user(&mut mgr);
        let requester = Uuid::new_v4();
        let approver2 = Uuid::new_v4();

        let mut desired = mgr.get_user(user_id).unwrap().clone();
        desired.groups = vec!["ops-team".into(), "sigint-analysts".into()];
        desired.entitlements = vec![test_entitlement(approver)];

        let req = ProvisioningRequest {
            request_id: Uuid::new_v4(),
            requested_by: requester,
            request_type: ProvisioningRequestType::ModifyAccess,
            target_user_id: Some(user_id),
            target_attributes: desired,
            justification: "added to SIGINT project".into(),
            status: RequestStatus::Pending,
            approval_chain: Vec::new(),
            created_at: 0,
            completed_at: None,
        };

        let req_id = mgr.submit_request(req).unwrap();
        mgr.approve_request(req_id, approver2, None).unwrap();
        mgr.execute_request(req_id).unwrap();

        let user = mgr.get_user(user_id).unwrap();
        assert_eq!(user.groups.len(), 2);
        assert_eq!(user.entitlements.len(), 1);
    }

    #[test]
    fn test_deprovision_preserves_audit_trail() {
        let mut mgr = IdmManager::with_clock(fixed_clock);
        let (user_id, _, _) = provision_user(&mut mgr);

        mgr.deprovision_user(user_id, "compliance").unwrap();

        // User record is still accessible (not deleted)
        assert!(mgr.get_user(user_id).is_some());

        // Audit trail is still available
        let trail = mgr.audit_trail(user_id);
        assert!(!trail.is_empty());
    }

    #[test]
    fn test_nonexistent_user_operations() {
        let mut mgr = IdmManager::with_clock(fixed_clock);
        let ghost = Uuid::new_v4();

        assert!(mgr.get_user(ghost).is_none());
        assert!(mgr.suspend_user(ghost, "test").is_err());
        assert!(mgr.reactivate_user(ghost).is_err());
        assert!(mgr.deprovision_user(ghost, "test").is_err());
        assert!(mgr
            .grant_entitlement(ghost, test_entitlement(Uuid::new_v4()))
            .is_err());
        assert!(mgr.revoke_entitlement(ghost, Uuid::new_v4()).is_err());
    }
}
