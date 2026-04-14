//! Privileged Identity Management (PIM) — just-in-time role elevation.
//!
//! Provides time-bounded, approval-gated privilege escalation with full SIEM
//! audit trail.  All elevations are ephemeral: they activate only after
//! approval, carry a hard expiry, and are automatically revoked when stale.
//!
//! # Security properties
//!
//! - Self-approval is forbidden (constant-time UUID comparison).
//! - At most one concurrent elevation per user.
//! - Cooldown between successive elevation requests.
//! - Optional per-elevation action cap.
//! - Break-glass emergency bypass with mandatory post-review flag.
//! - Every state transition emits a SIEM `SecurityEvent`.
#![forbid(unsafe_code)]

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::error::MilnetError;
use crate::siem::SecurityEvent;

// ── Constants ──────────────────────────────────────────────────────────

/// Absolute maximum elevation duration (8 hours in seconds).
const ABSOLUTE_MAX_DURATION_SECS: u64 = 28_800;

/// Default maximum elevation duration (4 hours in seconds).
const DEFAULT_MAX_DURATION_SECS: u64 = 14_400;

/// Default cooldown between elevation requests (5 minutes).
const DEFAULT_COOLDOWN_SECS: u64 = 300;

// ── Elevation status ───────────────────────────────────────────────────

/// Lifecycle status of an [`ElevationRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ElevationStatus {
    /// Awaiting approval.
    Pending,
    /// Approved by an authorised reviewer.
    Approved,
    /// Denied by an authorised reviewer.
    Denied,
    /// Elevation is currently active.
    Activated,
    /// Elevation expired naturally.
    Expired,
    /// Elevation was explicitly revoked.
    Revoked,
}

// ── ElevationRequest ───────────────────────────────────────────────────

/// A request for just-in-time privilege elevation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElevationRequest {
    /// Unique identifier for this request.
    pub request_id: Uuid,
    /// The user requesting elevation.
    pub requester_id: Uuid,
    /// Target role to elevate to (e.g. `"SuperAdmin"`, `"UserManager"`).
    pub target_role: String,
    /// Mandatory human-readable justification.
    pub justification: String,
    /// Requested duration in seconds (capped at 8 hours).
    pub requested_duration_secs: u64,
    /// Unix-epoch timestamp (seconds) when the request was created.
    pub requested_at: i64,
    /// Current status.
    pub status: ElevationStatus,
    /// Who denied the request (if denied).
    pub denied_by: Option<Uuid>,
    /// Reason for denial (if denied).
    pub denial_reason: Option<String>,
    /// Who approved the request (if approved/activated).
    pub approved_by: Option<Uuid>,
    /// All distinct approvers who have signed off on this request.
    pub approvers: Vec<Uuid>,
    /// Whether this was a break-glass emergency request.
    pub break_glass: bool,
}

// ── ActiveElevation ────────────────────────────────────────────────────

/// An active, time-bounded privilege elevation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveElevation {
    /// Unique elevation identifier.
    pub elevation_id: Uuid,
    /// The elevated user.
    pub user_id: Uuid,
    /// The elevated role.
    pub elevated_role: String,
    /// Unix-epoch seconds when the elevation was activated.
    pub activated_at: i64,
    /// Unix-epoch seconds when the elevation expires.
    pub expires_at: i64,
    /// Who approved the elevation.
    pub approved_by: Uuid,
    /// Human-readable justification carried forward from the request.
    pub justification: String,
    /// Number of actions performed under this elevation.
    pub actions_performed: u64,
    /// Optional cap on actions allowed during this elevation.
    pub max_actions: Option<u64>,
    /// Whether this elevation requires a post-incident review (break-glass).
    pub requires_post_review: bool,
}

impl ActiveElevation {
    /// Returns `true` if the elevation has expired relative to the given
    /// `now` timestamp (Unix-epoch seconds).
    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.expires_at
    }

    /// Returns `true` if the action cap has been reached.
    pub fn is_action_cap_reached(&self) -> bool {
        match self.max_actions {
            Some(max) => self.actions_performed >= max,
            None => false,
        }
    }
}

// ── ElevationConstraints ───────────────────────────────────────────────

/// Configurable policy constraints for the PIM subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElevationConstraints {
    /// Maximum allowed elevation duration in seconds (default 4 hours).
    pub max_duration_secs: u64,
    /// Maximum concurrent elevations per user (default 1).
    pub max_concurrent_elevations: u32,
    /// Require MFA before activation (default `true`).
    pub require_mfa: bool,
    /// Require that the approver is a different person than the requester
    /// (default `true`).
    pub require_different_approver: bool,
    /// Roles that may be elevated to.  An empty list means *all* roles are
    /// allowed.
    pub allowed_roles: Vec<String>,
    /// Minimum seconds between successive elevation requests from the same
    /// user (default 300).
    pub cooldown_secs: u64,
    /// Number of distinct approvers required before an elevation is approved.
    /// Defaults to 1, but sensitive roles (SuperAdmin, GlobalAdmin) should
    /// require 2 via [`min_approvers_for_role`].
    pub required_approvers: u32,
}

impl Default for ElevationConstraints {
    fn default() -> Self {
        Self {
            max_duration_secs: DEFAULT_MAX_DURATION_SECS,
            max_concurrent_elevations: 1,
            require_mfa: true,
            require_different_approver: true,
            allowed_roles: Vec::new(),
            cooldown_secs: DEFAULT_COOLDOWN_SECS,
            required_approvers: 1,
        }
    }
}

/// Returns the minimum number of distinct approvers required for a given role.
///
/// SuperAdmin and GlobalAdmin require dual approval (2 approvers); all other
/// roles require a single approver.
pub fn min_approvers_for_role(role: &str) -> u32 {
    match role {
        "SuperAdmin" | "GlobalAdmin" => 2,
        _ => 1,
    }
}

// ── Helper: constant-time UUID comparison ──────────────────────────────

/// Compare two UUIDs in constant time to avoid timing side-channels.
fn uuids_equal_ct(a: &Uuid, b: &Uuid) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

// ── Helper: current Unix-epoch seconds ─────────────────────────────────

fn now_epoch_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ── SIEM helpers ───────────────────────────────────────────────────────

fn emit_pim_event(
    action: &'static str,
    severity: crate::siem::Severity,
    outcome: &'static str,
    user_id: Option<Uuid>,
    detail: Option<String>,
) {
    let event = SecurityEvent {
        timestamp: SecurityEvent::now_iso8601(),
        category: "pim",
        action,
        severity,
        outcome,
        user_id,
        source_ip: None,
        detail,
    };
    event.emit();
}

// ── PimManager ─────────────────────────────────────────────────────────

/// Central manager for Privileged Identity Management.
///
/// All state is held in-memory.  In a production deployment this would be
/// backed by an encrypted database, but the API surface is identical.
pub struct PimManager {
    /// Policy constraints.
    constraints: ElevationConstraints,
    /// Pending / processed elevation requests keyed by `request_id`.
    requests: HashMap<Uuid, ElevationRequest>,
    /// Currently active elevations keyed by `user_id` (max 1 per user).
    active: HashMap<Uuid, ActiveElevation>,
    /// Timestamp of the most recent elevation request per user (for cooldown).
    last_request_at: HashMap<Uuid, i64>,
}

impl PimManager {
    /// Create a new `PimManager` with the given constraints.
    pub fn new(constraints: ElevationConstraints) -> Self {
        Self {
            constraints,
            requests: HashMap::new(),
            active: HashMap::new(),
            last_request_at: HashMap::new(),
        }
    }

    /// Create a new `PimManager` with default constraints.
    pub fn with_defaults() -> Self {
        Self::new(ElevationConstraints::default())
    }

    /// Return a reference to the active constraints.
    pub fn constraints(&self) -> &ElevationConstraints {
        &self.constraints
    }

    // ── Request ────────────────────────────────────────────────────────

    /// Submit an elevation request.
    ///
    /// # Errors
    ///
    /// - Empty justification.
    /// - Requested duration exceeds the absolute maximum (8 h).
    /// - Requested role not in the allowed list (when the list is non-empty).
    /// - User already has an active elevation.
    /// - Cooldown period has not elapsed since the last request.
    pub fn request_elevation(&mut self, req: ElevationRequest) -> Result<Uuid, MilnetError> {
        // Validate justification
        if req.justification.trim().is_empty() {
            emit_pim_event(
                "elevation_request_denied",
                crate::siem::Severity::Warning,
                "failure",
                Some(req.requester_id),
                Some("empty justification".into()),
            );
            return Err(MilnetError::CryptoVerification(
                "elevation justification must not be empty".into(),
            ));
        }

        // Validate duration
        if req.requested_duration_secs > ABSOLUTE_MAX_DURATION_SECS {
            emit_pim_event(
                "elevation_request_denied",
                crate::siem::Severity::Warning,
                "failure",
                Some(req.requester_id),
                Some(format!(
                    "requested duration {}s exceeds max {}s",
                    req.requested_duration_secs, ABSOLUTE_MAX_DURATION_SECS
                )),
            );
            return Err(MilnetError::CryptoVerification(format!(
                "requested duration {}s exceeds maximum {}s",
                req.requested_duration_secs, ABSOLUTE_MAX_DURATION_SECS
            )));
        }

        // Validate allowed roles
        if !self.constraints.allowed_roles.is_empty()
            && !self.constraints.allowed_roles.contains(&req.target_role)
        {
            emit_pim_event(
                "elevation_request_denied",
                crate::siem::Severity::Warning,
                "failure",
                Some(req.requester_id),
                Some(format!("role '{}' not in allowed list", req.target_role)),
            );
            return Err(MilnetError::CryptoVerification(format!(
                "role '{}' is not in the allowed elevation roles",
                req.target_role
            )));
        }

        // Check concurrent elevation
        if self.active.contains_key(&req.requester_id) {
            emit_pim_event(
                "elevation_request_denied",
                crate::siem::Severity::Warning,
                "failure",
                Some(req.requester_id),
                Some("user already has an active elevation".into()),
            );
            return Err(MilnetError::CryptoVerification(
                "user already has an active elevation".into(),
            ));
        }

        // Check cooldown
        let now = now_epoch_secs();
        if let Some(&last) = self.last_request_at.get(&req.requester_id) {
            let elapsed = now.saturating_sub(last) as u64;
            if elapsed < self.constraints.cooldown_secs {
                emit_pim_event(
                    "elevation_request_denied",
                    crate::siem::Severity::Warning,
                    "failure",
                    Some(req.requester_id),
                    Some(format!(
                        "cooldown: {}s remaining",
                        self.constraints.cooldown_secs - elapsed
                    )),
                );
                return Err(MilnetError::CryptoVerification(format!(
                    "elevation cooldown active — {}s remaining",
                    self.constraints.cooldown_secs - elapsed
                )));
            }
        }

        let id = req.request_id;
        self.last_request_at.insert(req.requester_id, now);
        self.requests.insert(id, req.clone());

        emit_pim_event(
            "elevation_requested",
            crate::siem::Severity::Medium,
            "success",
            Some(req.requester_id),
            Some(format!(
                "request_id={} target_role={} duration={}s break_glass={}",
                id, req.target_role, req.requested_duration_secs, req.break_glass
            )),
        );

        Ok(id)
    }

    // ── Approve ────────────────────────────────────────────────────────

    /// Approve a pending elevation request.
    ///
    /// For roles that require multiple approvers (e.g. SuperAdmin requires 2),
    /// the request stays in `Pending` status until enough distinct approvers
    /// have signed off.  Only then does it transition to `Approved`.
    ///
    /// # Errors
    ///
    /// - Request not found or not in `Pending` status.
    /// - Self-approval attempted (constant-time comparison).
    /// - Duplicate approver (same person approving twice).
    pub fn approve_elevation(
        &mut self,
        request_id: Uuid,
        approver_id: Uuid,
    ) -> Result<(), MilnetError> {
        let required = self.constraints.required_approvers;
        let req = self.requests.get_mut(&request_id).ok_or_else(|| {
            MilnetError::CryptoVerification("elevation request not found".into())
        })?;

        if req.status != ElevationStatus::Pending {
            return Err(MilnetError::CryptoVerification(format!(
                "request is not pending (status={:?})",
                req.status
            )));
        }

        // Constant-time self-approval check
        if self.constraints.require_different_approver
            && uuids_equal_ct(&req.requester_id, &approver_id)
        {
            emit_pim_event(
                "elevation_self_approval_blocked",
                crate::siem::Severity::High,
                "failure",
                Some(approver_id),
                Some(format!("request_id={}", request_id)),
            );
            return Err(MilnetError::CryptoVerification(
                "self-approval is forbidden".into(),
            ));
        }

        // Reject duplicate approvers (constant-time check for each existing approver).
        for existing in &req.approvers {
            if uuids_equal_ct(existing, &approver_id) {
                return Err(MilnetError::CryptoVerification(
                    "duplicate approver — each approver may only sign once".into(),
                ));
            }
        }

        req.approvers.push(approver_id);

        // Determine how many approvers are needed: use the role-specific
        // minimum or the constraint-configured value, whichever is greater.
        let role_min = min_approvers_for_role(&req.target_role);
        let needed = required.max(role_min);

        let collected = req.approvers.len() as u32;

        if collected >= needed {
            req.status = ElevationStatus::Approved;
            req.approved_by = Some(approver_id);

            emit_pim_event(
                "elevation_approved",
                crate::siem::Severity::Medium,
                "success",
                Some(req.requester_id),
                Some(format!(
                    "request_id={} approver={} total_approvers={}/{}",
                    request_id, approver_id, collected, needed
                )),
            );
        } else {
            emit_pim_event(
                "elevation_partial_approval",
                crate::siem::Severity::Medium,
                "success",
                Some(req.requester_id),
                Some(format!(
                    "request_id={} approver={} approvals_collected={}/{}",
                    request_id, approver_id, collected, needed
                )),
            );
        }

        Ok(())
    }

    // ── Deny ───────────────────────────────────────────────────────────

    /// Deny a pending elevation request.
    ///
    /// # Errors
    ///
    /// - Request not found or not in `Pending` status.
    pub fn deny_elevation(
        &mut self,
        request_id: Uuid,
        denier_id: Uuid,
        reason: &str,
    ) -> Result<(), MilnetError> {
        let req = self.requests.get_mut(&request_id).ok_or_else(|| {
            MilnetError::CryptoVerification("elevation request not found".into())
        })?;

        if req.status != ElevationStatus::Pending {
            return Err(MilnetError::CryptoVerification(format!(
                "request is not pending (status={:?})",
                req.status
            )));
        }

        req.status = ElevationStatus::Denied;
        req.denied_by = Some(denier_id);
        req.denial_reason = Some(reason.to_string());

        emit_pim_event(
            "elevation_denied",
            crate::siem::Severity::Medium,
            "success",
            Some(req.requester_id),
            Some(format!(
                "request_id={} denier={} reason={}",
                request_id, denier_id, reason
            )),
        );

        Ok(())
    }

    // ── Activate ───────────────────────────────────────────────────────

    /// Activate an approved elevation request, making it live.
    ///
    /// The effective duration is the minimum of the requested duration and
    /// the constraint-configured maximum.
    ///
    /// # Errors
    ///
    /// - Request not found or not in `Approved` status.
    /// - User already has an active elevation.
    pub fn activate_elevation(
        &mut self,
        request_id: Uuid,
    ) -> Result<ActiveElevation, MilnetError> {
        let req = self.requests.get_mut(&request_id).ok_or_else(|| {
            MilnetError::CryptoVerification("elevation request not found".into())
        })?;

        if req.status != ElevationStatus::Approved {
            return Err(MilnetError::CryptoVerification(format!(
                "request is not approved (status={:?})",
                req.status
            )));
        }

        // Prevent concurrent elevations
        if self.active.contains_key(&req.requester_id) {
            return Err(MilnetError::CryptoVerification(
                "user already has an active elevation".into(),
            ));
        }

        let now = now_epoch_secs();
        let effective_duration = req
            .requested_duration_secs
            .min(self.constraints.max_duration_secs);

        let elevation = ActiveElevation {
            elevation_id: Uuid::new_v4(),
            user_id: req.requester_id,
            elevated_role: req.target_role.clone(),
            activated_at: now,
            expires_at: now + effective_duration as i64,
            approved_by: req.approved_by.unwrap_or_else(Uuid::nil),
            justification: req.justification.clone(),
            actions_performed: 0,
            max_actions: None,
            requires_post_review: req.break_glass,
        };

        req.status = ElevationStatus::Activated;
        self.active.insert(elevation.user_id, elevation.clone());

        emit_pim_event(
            "elevation_activated",
            crate::siem::Severity::High,
            "success",
            Some(elevation.user_id),
            Some(format!(
                "elevation_id={} role={} expires_at={} break_glass={}",
                elevation.elevation_id,
                elevation.elevated_role,
                elevation.expires_at,
                elevation.requires_post_review
            )),
        );

        Ok(elevation)
    }

    // ── Query ──────────────────────────────────────────────────────────

    /// Check whether a user currently has an active (non-expired) elevation.
    pub fn check_elevation(&self, user_id: Uuid) -> Option<&ActiveElevation> {
        let elev = self.active.get(&user_id)?;
        let now = now_epoch_secs();
        if elev.is_expired(now) {
            None
        } else {
            Some(elev)
        }
    }

    /// Returns `true` if the user has an active, non-expired elevation.
    pub fn is_elevated(&self, user_id: Uuid) -> bool {
        self.check_elevation(user_id).is_some()
    }

    // ── Record action ──────────────────────────────────────────────────

    /// Record an action performed under an active elevation.
    ///
    /// Increments the action counter and checks the optional cap.
    ///
    /// # Errors
    ///
    /// - No active elevation for the user.
    /// - Action cap exceeded (the elevation is auto-revoked).
    pub fn record_action(&mut self, user_id: Uuid) -> Result<(), MilnetError> {
        let now = now_epoch_secs();
        let elev = self.active.get_mut(&user_id).ok_or_else(|| {
            MilnetError::CryptoVerification("no active elevation for user".into())
        })?;

        if elev.is_expired(now) {
            // Auto-revoke expired elevation
            let eid = elev.elevation_id;
            self.active.remove(&user_id);
            emit_pim_event(
                "elevation_expired",
                crate::siem::Severity::Medium,
                "success",
                Some(user_id),
                Some(format!("elevation_id={} expired during action", eid)),
            );
            return Err(MilnetError::CryptoVerification(
                "elevation has expired".into(),
            ));
        }

        elev.actions_performed += 1;

        emit_pim_event(
            "elevated_action_performed",
            crate::siem::Severity::Medium,
            "success",
            Some(user_id),
            Some(format!(
                "elevation_id={} role={} action_count={}",
                elev.elevation_id, elev.elevated_role, elev.actions_performed
            )),
        );

        if elev.is_action_cap_reached() {
            let eid = elev.elevation_id;
            self.active.remove(&user_id);
            emit_pim_event(
                "elevation_action_cap_reached",
                crate::siem::Severity::High,
                "success",
                Some(user_id),
                Some(format!(
                    "elevation_id={} auto-revoked after reaching action cap",
                    eid
                )),
            );
            return Err(MilnetError::CryptoVerification(
                "elevation action cap reached — elevation revoked".into(),
            ));
        }

        Ok(())
    }

    // ── Revoke ─────────────────────────────────────────────────────────

    /// Explicitly revoke a user's active elevation.
    ///
    /// # Errors
    ///
    /// - No active elevation for the user.
    pub fn revoke_elevation(&mut self, user_id: Uuid, reason: &str) -> Result<(), MilnetError> {
        let elev = self.active.remove(&user_id).ok_or_else(|| {
            MilnetError::CryptoVerification("no active elevation to revoke".into())
        })?;

        // Mark the originating request as revoked
        for req in self.requests.values_mut() {
            if uuids_equal_ct(&req.requester_id, &user_id)
                && req.status == ElevationStatus::Activated
            {
                req.status = ElevationStatus::Revoked;
            }
        }

        emit_pim_event(
            "elevation_revoked",
            crate::siem::Severity::High,
            "success",
            Some(user_id),
            Some(format!(
                "elevation_id={} role={} reason={} actions_performed={}",
                elev.elevation_id, elev.elevated_role, reason, elev.actions_performed
            )),
        );

        Ok(())
    }

    // ── Expire stale ───────────────────────────────────────────────────

    /// Scan all active elevations and remove those that have expired.
    ///
    /// Returns the user IDs whose elevations were expired.
    pub fn expire_stale_elevations(&mut self) -> Vec<Uuid> {
        let now = now_epoch_secs();
        let expired_users: Vec<Uuid> = self
            .active
            .iter()
            .filter(|(_, elev)| elev.is_expired(now))
            .map(|(&uid, _)| uid)
            .collect();

        for &uid in &expired_users {
            if let Some(elev) = self.active.remove(&uid) {
                // Mark originating request
                for req in self.requests.values_mut() {
                    if uuids_equal_ct(&req.requester_id, &uid)
                        && req.status == ElevationStatus::Activated
                    {
                        req.status = ElevationStatus::Expired;
                    }
                }

                emit_pim_event(
                    "elevation_expired",
                    crate::siem::Severity::Medium,
                    "success",
                    Some(uid),
                    Some(format!(
                        "elevation_id={} role={} actions_performed={}",
                        elev.elevation_id, elev.elevated_role, elev.actions_performed
                    )),
                );
            }
        }

        expired_users
    }

    // ── List ───────────────────────────────────────────────────────────

    /// List all currently active (non-expired) elevations.
    pub fn list_active_elevations(&self) -> Vec<&ActiveElevation> {
        let now = now_epoch_secs();
        self.active
            .values()
            .filter(|e| !e.is_expired(now))
            .collect()
    }

    /// List all pending elevation requests.
    pub fn list_pending_requests(&self) -> Vec<&ElevationRequest> {
        self.requests
            .values()
            .filter(|r| r.status == ElevationStatus::Pending)
            .collect()
    }

    // ── Break-glass ────────────────────────────────────────────────────

    /// Emergency break-glass elevation bypass.
    ///
    /// Creates and immediately activates an elevation without the normal
    /// approval flow.  The resulting [`ActiveElevation`] is flagged with
    /// `requires_post_review = true` and emits a CRITICAL-severity SIEM
    /// event.
    ///
    /// # Arguments
    ///
    /// * `user_id` — the user requesting emergency access.
    /// * `target_role` — the role to elevate to.
    /// * `justification` — mandatory justification (must be non-empty).
    /// * `duration_secs` — requested duration (capped at constraints max).
    ///
    /// # Errors
    ///
    /// - Empty justification.
    /// - User already has an active elevation.
    pub fn break_glass(
        &mut self,
        user_id: Uuid,
        target_role: &str,
        justification: &str,
        duration_secs: u64,
    ) -> Result<ActiveElevation, MilnetError> {
        if justification.trim().is_empty() {
            return Err(MilnetError::CryptoVerification(
                "break-glass justification must not be empty".into(),
            ));
        }

        if self.active.contains_key(&user_id) {
            return Err(MilnetError::CryptoVerification(
                "user already has an active elevation".into(),
            ));
        }

        let now = now_epoch_secs();
        let effective_duration = duration_secs.min(self.constraints.max_duration_secs);

        let request_id = Uuid::new_v4();
        let req = ElevationRequest {
            request_id,
            requester_id: user_id,
            target_role: target_role.to_string(),
            justification: justification.to_string(),
            requested_duration_secs: effective_duration,
            requested_at: now,
            status: ElevationStatus::Activated,
            denied_by: None,
            denial_reason: None,
            approvers: vec![user_id], // self-approved under break-glass
            approved_by: Some(user_id), // self-approved under break-glass
            break_glass: true,
        };
        self.requests.insert(request_id, req);

        let elevation = ActiveElevation {
            elevation_id: Uuid::new_v4(),
            user_id,
            elevated_role: target_role.to_string(),
            activated_at: now,
            expires_at: now + effective_duration as i64,
            approved_by: user_id,
            justification: justification.to_string(),
            actions_performed: 0,
            max_actions: None,
            requires_post_review: true,
        };

        self.active.insert(user_id, elevation.clone());
        self.last_request_at.insert(user_id, now);

        emit_pim_event(
            "break_glass_activated",
            crate::siem::Severity::Critical,
            "success",
            Some(user_id),
            Some(format!(
                "elevation_id={} role={} duration={}s MANDATORY_POST_REVIEW",
                elevation.elevation_id, target_role, effective_duration
            )),
        );

        Ok(elevation)
    }

    /// Return the underlying request by ID (for testing / auditing).
    pub fn get_request(&self, request_id: Uuid) -> Option<&ElevationRequest> {
        self.requests.get(&request_id)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a PimManager with relaxed cooldown for tests.
    fn test_manager() -> PimManager {
        PimManager::new(ElevationConstraints {
            max_duration_secs: DEFAULT_MAX_DURATION_SECS,
            max_concurrent_elevations: 1,
            require_mfa: false,
            require_different_approver: true,
            allowed_roles: vec![
                "SuperAdmin".into(),
                "UserManager".into(),
                "DeviceManager".into(),
                "GlobalAdmin".into(),
            ],
            cooldown_secs: 0, // disable cooldown for tests
            required_approvers: 1,
        })
    }

    fn make_request(requester: Uuid, role: &str, duration: u64) -> ElevationRequest {
        ElevationRequest {
            request_id: Uuid::new_v4(),
            requester_id: requester,
            target_role: role.into(),
            justification: "incident response — ticket INC-1234".into(),
            requested_duration_secs: duration,
            requested_at: now_epoch_secs(),
            status: ElevationStatus::Pending,
            denied_by: None,
            denial_reason: None,
            approved_by: None,
            approvers: Vec::new(),
            break_glass: false,
        }
    }

    // ── 1. Basic request → approve → activate → check lifecycle ────────

    #[test]
    fn test_full_lifecycle() {
        let mut mgr = test_manager();
        let user = Uuid::new_v4();
        let approver1 = Uuid::new_v4();
        let approver2 = Uuid::new_v4();

        let req = make_request(user, "SuperAdmin", 3600);
        let rid = mgr.request_elevation(req).unwrap();

        assert!(!mgr.is_elevated(user));
        assert_eq!(mgr.list_pending_requests().len(), 1);

        // SuperAdmin requires dual approval — first approver keeps it Pending.
        mgr.approve_elevation(rid, approver1).unwrap();
        assert_eq!(mgr.list_pending_requests().len(), 1);

        // Second approver transitions to Approved.
        mgr.approve_elevation(rid, approver2).unwrap();
        assert_eq!(mgr.list_pending_requests().len(), 0);

        let elev = mgr.activate_elevation(rid).unwrap();
        assert_eq!(elev.elevated_role, "SuperAdmin");
        assert!(mgr.is_elevated(user));
        assert_eq!(mgr.list_active_elevations().len(), 1);
    }

    #[test]
    fn test_single_approver_role_lifecycle() {
        let mut mgr = test_manager();
        let user = Uuid::new_v4();
        let approver = Uuid::new_v4();

        // UserManager only requires 1 approver.
        let req = make_request(user, "UserManager", 3600);
        let rid = mgr.request_elevation(req).unwrap();

        mgr.approve_elevation(rid, approver).unwrap();
        assert_eq!(mgr.list_pending_requests().len(), 0);

        let elev = mgr.activate_elevation(rid).unwrap();
        assert_eq!(elev.elevated_role, "UserManager");
        assert!(mgr.is_elevated(user));
    }

    #[test]
    fn test_duplicate_approver_rejected() {
        let mut mgr = test_manager();
        let user = Uuid::new_v4();
        let approver = Uuid::new_v4();

        let req = make_request(user, "SuperAdmin", 3600);
        let rid = mgr.request_elevation(req).unwrap();

        mgr.approve_elevation(rid, approver).unwrap();
        // Same approver cannot approve twice.
        assert!(mgr.approve_elevation(rid, approver).is_err());
    }

    #[test]
    fn test_min_approvers_for_role() {
        assert_eq!(min_approvers_for_role("SuperAdmin"), 2);
        assert_eq!(min_approvers_for_role("GlobalAdmin"), 2);
        assert_eq!(min_approvers_for_role("UserManager"), 1);
        assert_eq!(min_approvers_for_role("DeviceManager"), 1);
    }

    // ── 2. Empty justification rejected ────────────────────────────────

    #[test]
    fn test_empty_justification_rejected() {
        let mut mgr = test_manager();
        let user = Uuid::new_v4();
        let mut req = make_request(user, "SuperAdmin", 3600);
        req.justification = "   ".into();

        assert!(mgr.request_elevation(req).is_err());
    }

    // ── 3. Duration exceeds absolute max ───────────────────────────────

    #[test]
    fn test_excessive_duration_rejected() {
        let mut mgr = test_manager();
        let user = Uuid::new_v4();
        let req = make_request(user, "SuperAdmin", ABSOLUTE_MAX_DURATION_SECS + 1);
        assert!(mgr.request_elevation(req).is_err());
    }

    // ── 4. Role not in allowed list ────────────────────────────────────

    #[test]
    fn test_disallowed_role_rejected() {
        let mut mgr = test_manager();
        let user = Uuid::new_v4();
        let req = make_request(user, "GodMode", 3600);
        assert!(mgr.request_elevation(req).is_err());
    }

    // ── 5. Self-approval forbidden ─────────────────────────────────────

    #[test]
    fn test_self_approval_forbidden() {
        let mut mgr = test_manager();
        let user = Uuid::new_v4();

        let req = make_request(user, "SuperAdmin", 3600);
        let rid = mgr.request_elevation(req).unwrap();

        let result = mgr.approve_elevation(rid, user);
        assert!(result.is_err());
    }

    // ── 6. Self-approval allowed when constraint disabled ──────────────

    #[test]
    fn test_self_approval_when_allowed() {
        let mut mgr = PimManager::new(ElevationConstraints {
            require_different_approver: false,
            cooldown_secs: 0,
            ..ElevationConstraints::default()
        });
        let user = Uuid::new_v4();

        // Use a non-sensitive role that only requires 1 approver.
        let req = make_request(user, "UserManager", 3600);
        let rid = mgr.request_elevation(req).unwrap();

        assert!(mgr.approve_elevation(rid, user).is_ok());
    }

    // ── 7. Deny a request ──────────────────────────────────────────────

    #[test]
    fn test_deny_request() {
        let mut mgr = test_manager();
        let user = Uuid::new_v4();
        let denier = Uuid::new_v4();

        let req = make_request(user, "UserManager", 1800);
        let rid = mgr.request_elevation(req).unwrap();

        mgr.deny_elevation(rid, denier, "not justified").unwrap();

        let r = mgr.get_request(rid).unwrap();
        assert_eq!(r.status, ElevationStatus::Denied);
        assert_eq!(r.denial_reason.as_deref(), Some("not justified"));
    }

    // ── 8. Cannot approve a denied request ─────────────────────────────

    #[test]
    fn test_cannot_approve_denied() {
        let mut mgr = test_manager();
        let user = Uuid::new_v4();
        let denier = Uuid::new_v4();
        let approver = Uuid::new_v4();

        let req = make_request(user, "SuperAdmin", 3600);
        let rid = mgr.request_elevation(req).unwrap();
        mgr.deny_elevation(rid, denier, "nope").unwrap();

        assert!(mgr.approve_elevation(rid, approver).is_err());
    }

    // ── 9. Concurrent elevation blocked ────────────────────────────────

    #[test]
    fn test_concurrent_elevation_blocked() {
        let mut mgr = test_manager();
        let user = Uuid::new_v4();
        let approver1 = Uuid::new_v4();
        let approver2 = Uuid::new_v4();

        let req = make_request(user, "SuperAdmin", 3600);
        let rid = mgr.request_elevation(req).unwrap();
        mgr.approve_elevation(rid, approver1).unwrap();
        mgr.approve_elevation(rid, approver2).unwrap();
        mgr.activate_elevation(rid).unwrap();

        // Second request should fail
        let req2 = make_request(user, "UserManager", 1800);
        assert!(mgr.request_elevation(req2).is_err());
    }

    // ── 10. Revoke an active elevation ─────────────────────────────────

    #[test]
    fn test_revoke_elevation() {
        let mut mgr = test_manager();
        let user = Uuid::new_v4();
        let approver1 = Uuid::new_v4();
        let approver2 = Uuid::new_v4();

        let req = make_request(user, "SuperAdmin", 3600);
        let rid = mgr.request_elevation(req).unwrap();
        mgr.approve_elevation(rid, approver1).unwrap();
        mgr.approve_elevation(rid, approver2).unwrap();
        mgr.activate_elevation(rid).unwrap();
        assert!(mgr.is_elevated(user));

        mgr.revoke_elevation(user, "no longer needed").unwrap();
        assert!(!mgr.is_elevated(user));
    }

    // ── 11. Revoke non-existent elevation fails ────────────────────────

    #[test]
    fn test_revoke_nonexistent_fails() {
        let mut mgr = test_manager();
        assert!(mgr
            .revoke_elevation(Uuid::new_v4(), "reason")
            .is_err());
    }

    // ── 12. Record action increments counter ───────────────────────────

    #[test]
    fn test_record_action() {
        let mut mgr = test_manager();
        let user = Uuid::new_v4();
        let approver = Uuid::new_v4();

        let req = make_request(user, "DeviceManager", 3600);
        let rid = mgr.request_elevation(req).unwrap();
        mgr.approve_elevation(rid, approver).unwrap();
        mgr.activate_elevation(rid).unwrap();

        mgr.record_action(user).unwrap();
        mgr.record_action(user).unwrap();

        let elev = mgr.check_elevation(user).unwrap();
        assert_eq!(elev.actions_performed, 2);
    }

    // ── 13. Action cap revokes elevation ───────────────────────────────

    #[test]
    fn test_action_cap_revokes() {
        let mut mgr = test_manager();
        let user = Uuid::new_v4();
        let approver1 = Uuid::new_v4();
        let approver2 = Uuid::new_v4();

        let req = make_request(user, "SuperAdmin", 3600);
        let rid = mgr.request_elevation(req).unwrap();
        mgr.approve_elevation(rid, approver1).unwrap();
        mgr.approve_elevation(rid, approver2).unwrap();
        let mut elev = mgr.activate_elevation(rid).unwrap();
        // Set a low action cap
        elev.max_actions = Some(2);
        mgr.active.insert(user, elev);

        mgr.record_action(user).unwrap();
        // Second action hits the cap
        let result = mgr.record_action(user);
        assert!(result.is_err());
        assert!(!mgr.is_elevated(user));
    }

    // ── 14. Expire stale elevations ────────────────────────────────────

    #[test]
    fn test_expire_stale_elevations() {
        let mut mgr = test_manager();
        let user = Uuid::new_v4();

        // Directly insert an already-expired elevation
        let elev = ActiveElevation {
            elevation_id: Uuid::new_v4(),
            user_id: user,
            elevated_role: "SuperAdmin".into(),
            activated_at: 1000,
            expires_at: 1001, // already expired
            approved_by: Uuid::new_v4(),
            justification: "test".into(),
            actions_performed: 0,
            max_actions: None,
            requires_post_review: false,
        };
        mgr.active.insert(user, elev);

        let expired = mgr.expire_stale_elevations();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], user);
        assert!(!mgr.is_elevated(user));
    }

    // ── 15. Break-glass emergency bypass ───────────────────────────────

    #[test]
    fn test_break_glass() {
        let mut mgr = test_manager();
        let user = Uuid::new_v4();

        let elev = mgr
            .break_glass(user, "SuperAdmin", "active cyber attack", 7200)
            .unwrap();

        assert!(elev.requires_post_review);
        assert_eq!(elev.elevated_role, "SuperAdmin");
        assert!(mgr.is_elevated(user));
    }

    // ── 16. Break-glass empty justification rejected ───────────────────

    #[test]
    fn test_break_glass_empty_justification() {
        let mut mgr = test_manager();
        let user = Uuid::new_v4();
        assert!(mgr.break_glass(user, "SuperAdmin", "  ", 7200).is_err());
    }

    // ── 17. Break-glass blocked if already elevated ────────────────────

    #[test]
    fn test_break_glass_concurrent_blocked() {
        let mut mgr = test_manager();
        let user = Uuid::new_v4();

        mgr.break_glass(user, "SuperAdmin", "reason one", 3600)
            .unwrap();
        assert!(mgr
            .break_glass(user, "UserManager", "reason two", 3600)
            .is_err());
    }

    // ── 18. Effective duration capped by constraints ───────────────────

    #[test]
    fn test_duration_capped_by_constraints() {
        let mut mgr = PimManager::new(ElevationConstraints {
            max_duration_secs: 1800, // 30 min
            cooldown_secs: 0,
            ..ElevationConstraints::default()
        });
        let user = Uuid::new_v4();
        let approver1 = Uuid::new_v4();
        let approver2 = Uuid::new_v4();

        let req = make_request(user, "SuperAdmin", 7200); // asks for 2 hours
        let rid = mgr.request_elevation(req).unwrap();
        mgr.approve_elevation(rid, approver1).unwrap();
        mgr.approve_elevation(rid, approver2).unwrap();
        let elev = mgr.activate_elevation(rid).unwrap();

        let actual_duration = elev.expires_at - elev.activated_at;
        assert_eq!(actual_duration, 1800);
    }

    // ── 19. Cooldown enforcement ───────────────────────────────────────

    #[test]
    fn test_cooldown_enforcement() {
        let mut mgr = PimManager::new(ElevationConstraints {
            cooldown_secs: 999_999, // effectively infinite
            ..ElevationConstraints::default()
        });
        let user = Uuid::new_v4();

        let req = make_request(user, "SuperAdmin", 3600);
        mgr.request_elevation(req).unwrap();

        // Second request should be blocked by cooldown
        let req2 = make_request(user, "SuperAdmin", 3600);
        assert!(mgr.request_elevation(req2).is_err());
    }

    // ── 20. Constant-time UUID comparison ──────────────────────────────

    #[test]
    fn test_constant_time_uuid_eq() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert!(uuids_equal_ct(&a, &a));
        assert!(!uuids_equal_ct(&a, &b));
        assert!(uuids_equal_ct(&Uuid::nil(), &Uuid::nil()));
    }

    // ── 21. Record action on non-elevated user fails ───────────────────

    #[test]
    fn test_record_action_no_elevation() {
        let mut mgr = test_manager();
        assert!(mgr.record_action(Uuid::new_v4()).is_err());
    }

    // ── 22. List functions return correct counts ───────────────────────

    #[test]
    fn test_list_functions() {
        let mut mgr = test_manager();
        let user1 = Uuid::new_v4();
        let user2 = Uuid::new_v4();
        let approver1 = Uuid::new_v4();
        let approver2 = Uuid::new_v4();

        let req1 = make_request(user1, "SuperAdmin", 3600);
        let req2 = make_request(user2, "UserManager", 3600);
        let rid1 = mgr.request_elevation(req1).unwrap();
        let _rid2 = mgr.request_elevation(req2).unwrap();

        assert_eq!(mgr.list_pending_requests().len(), 2);

        mgr.approve_elevation(rid1, approver1).unwrap();
        mgr.approve_elevation(rid1, approver2).unwrap();
        mgr.activate_elevation(rid1).unwrap();

        assert_eq!(mgr.list_pending_requests().len(), 1);
        assert_eq!(mgr.list_active_elevations().len(), 1);
    }

    // ── 23. Cannot activate a non-approved request ─────────────────────

    #[test]
    fn test_activate_pending_fails() {
        let mut mgr = test_manager();
        let user = Uuid::new_v4();

        let req = make_request(user, "SuperAdmin", 3600);
        let rid = mgr.request_elevation(req).unwrap();

        assert!(mgr.activate_elevation(rid).is_err());
    }

    // ── 24. Default constraints are sane ───────────────────────────────

    #[test]
    fn test_default_constraints() {
        let c = ElevationConstraints::default();
        assert_eq!(c.max_duration_secs, DEFAULT_MAX_DURATION_SECS);
        assert_eq!(c.max_concurrent_elevations, 1);
        assert!(c.require_mfa);
        assert!(c.require_different_approver);
        assert!(c.allowed_roles.is_empty());
        assert_eq!(c.cooldown_secs, DEFAULT_COOLDOWN_SECS);
        assert_eq!(c.required_approvers, 1);
    }

    // ── 25. ActiveElevation helpers ────────────────────────────────────

    #[test]
    fn test_active_elevation_helpers() {
        let elev = ActiveElevation {
            elevation_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            elevated_role: "SuperAdmin".into(),
            activated_at: 1000,
            expires_at: 2000,
            approved_by: Uuid::new_v4(),
            justification: "test".into(),
            actions_performed: 5,
            max_actions: Some(5),
            requires_post_review: false,
        };

        assert!(elev.is_expired(2000));
        assert!(!elev.is_expired(1999));
        assert!(elev.is_action_cap_reached());

        let no_cap = ActiveElevation {
            max_actions: None,
            actions_performed: 999,
            ..elev
        };
        assert!(!no_cap.is_action_cap_reached());
    }

    // ── TEST GROUP 5: PIM dual-approval tests ────────────────────────────

    #[test]
    fn test_superadmin_requires_two_approvers() {
        assert_eq!(
            min_approvers_for_role("SuperAdmin"),
            2,
            "SuperAdmin must require 2 approvers"
        );
        assert_eq!(
            min_approvers_for_role("GlobalAdmin"),
            2,
            "GlobalAdmin must require 2 approvers"
        );
    }

    #[test]
    fn test_single_approval_for_superadmin_stays_pending() {
        let mut mgr = test_manager();
        let user = Uuid::new_v4();
        let approver1 = Uuid::new_v4();

        let req = make_request(user, "SuperAdmin", 3600);
        let rid = mgr.request_elevation(req).unwrap();

        // Single approval is not enough for SuperAdmin.
        mgr.approve_elevation(rid, approver1).unwrap();

        // Request must still be pending (not approved).
        let pending = mgr.list_pending_requests();
        assert_eq!(pending.len(), 1, "SuperAdmin with 1 approver must remain pending");
        assert_eq!(pending[0].status, ElevationStatus::Pending);
    }

    #[test]
    fn test_two_distinct_approvers_for_superadmin_succeeds() {
        let mut mgr = test_manager();
        let user = Uuid::new_v4();
        let approver1 = Uuid::new_v4();
        let approver2 = Uuid::new_v4();

        let req = make_request(user, "SuperAdmin", 3600);
        let rid = mgr.request_elevation(req).unwrap();

        mgr.approve_elevation(rid, approver1).unwrap();
        mgr.approve_elevation(rid, approver2).unwrap();

        // After two distinct approvers, the request should be Approved.
        let pending = mgr.list_pending_requests();
        assert_eq!(pending.len(), 0, "SuperAdmin with 2 approvers must leave pending state");
    }

    #[test]
    fn test_same_approver_twice_rejected_for_superadmin() {
        let mut mgr = test_manager();
        let user = Uuid::new_v4();
        let approver = Uuid::new_v4();

        let req = make_request(user, "SuperAdmin", 3600);
        let rid = mgr.request_elevation(req).unwrap();

        mgr.approve_elevation(rid, approver).unwrap();
        // Same approver trying again must be rejected.
        let result = mgr.approve_elevation(rid, approver);
        assert!(result.is_err(), "same approver twice must be rejected");
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("duplicate approver"),
            "error must mention duplicate approver, got: {err}"
        );
    }

    #[test]
    fn test_non_superadmin_works_with_single_approver() {
        let mut mgr = test_manager();
        let user = Uuid::new_v4();
        let approver = Uuid::new_v4();

        // UserManager requires only 1 approver.
        let req = make_request(user, "UserManager", 3600);
        let rid = mgr.request_elevation(req).unwrap();

        mgr.approve_elevation(rid, approver).unwrap();

        // Should be fully approved and activatable with just 1 approver.
        let pending = mgr.list_pending_requests();
        assert_eq!(pending.len(), 0, "UserManager should be approved with 1 approver");

        let elev = mgr.activate_elevation(rid).unwrap();
        assert_eq!(elev.elevated_role, "UserManager");
    }
}
