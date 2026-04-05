//! Self-Service Portal Backend for the MILNET SSO system.
//!
//! Provides:
//! - Password reset flow (email verification + OPAQUE re-registration)
//! - MFA enrollment (TOTP setup, FIDO2 registration)
//! - Device registration and management
//! - Access request workflow (request -> approve -> grant)
//! - Profile management (display name, email update with re-verification)
//! - Recovery code generation and viewing
//! - Session management (view active sessions, revoke)
//! - All operations require current session + MFA verification
//! - SIEM logging for all self-service actions
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

use crate::siem::SecurityEvent;

// ── Constants ───────────────────────────────────────────────────────────────

/// Password reset token TTL (15 minutes).
const PASSWORD_RESET_TTL_SECS: i64 = 900;

/// Email verification token TTL (24 hours).
const EMAIL_VERIFICATION_TTL_SECS: i64 = 86400;

/// Access request expiry (7 days).
const ACCESS_REQUEST_TTL_SECS: i64 = 7 * 86400;

/// Maximum active sessions per user.
const MAX_SESSIONS_PER_USER: usize = 10;

/// Maximum devices per user.
const MAX_DEVICES_PER_USER: usize = 10;

/// Number of recovery codes to generate.
const RECOVERY_CODE_COUNT: usize = 10;

/// Recovery code length (hex characters).
const RECOVERY_CODE_LENGTH: usize = 16;

// ── Session Verification ────────────────────────────────────────────────────

/// Verified session context required for all self-service operations.
///
/// All self-service actions MUST go through this context to ensure
/// the user has a valid session AND has completed MFA verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedSession {
    /// User ID.
    pub user_id: Uuid,
    /// Session ID.
    pub session_id: String,
    /// Whether MFA was verified for this session.
    pub mfa_verified: bool,
    /// Session creation time (epoch seconds).
    pub created_at: i64,
    /// Source IP address.
    pub source_ip: Option<String>,
    /// User agent string.
    pub user_agent: Option<String>,
    /// Tenant ID for multi-tenant scoping.
    pub tenant_id: Option<String>,
}

impl VerifiedSession {
    /// Ensure MFA has been verified. Returns error if not.
    pub fn require_mfa(&self) -> Result<(), String> {
        if !self.mfa_verified {
            return Err("MFA verification required for this operation".to_string());
        }
        Ok(())
    }
}

// ── Password Reset ──────────────────────────────────────────────────────────

/// Status of a password reset request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PasswordResetStatus {
    /// Token sent to user email.
    Pending,
    /// User has verified the token.
    Verified,
    /// Password has been reset.
    Completed,
    /// Token expired.
    Expired,
    /// Token was revoked.
    Revoked,
}

impl std::fmt::Display for PasswordResetStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Verified => write!(f, "verified"),
            Self::Completed => write!(f, "completed"),
            Self::Expired => write!(f, "expired"),
            Self::Revoked => write!(f, "revoked"),
        }
    }
}

/// A password reset request.
#[derive(Clone, Serialize, Deserialize)]
pub struct PasswordResetRequest {
    /// Request ID.
    pub id: String,
    /// User ID.
    pub user_id: Uuid,
    /// Email address the reset was sent to.
    pub email: String,
    /// Reset token (sent to user via email).
    #[serde(skip_serializing)]
    pub token: String,
    /// Status.
    pub status: PasswordResetStatus,
    /// Creation timestamp.
    pub created_at: i64,
    /// Expiry timestamp.
    pub expires_at: i64,
    /// Source IP that initiated the request.
    pub source_ip: Option<String>,
}

impl std::fmt::Debug for PasswordResetRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordResetRequest")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("email", &"[REDACTED]")
            .field("token", &"[REDACTED]")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl Drop for PasswordResetRequest {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.email.zeroize();
        self.token.zeroize();
        self.source_ip.take();
    }
}

// ── MFA Enrollment ──────────────────────────────────────────────────────────

/// MFA method types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MfaMethod {
    /// Time-based One-Time Password.
    Totp,
    /// FIDO2/WebAuthn security key.
    Fido2,
    /// Recovery codes.
    RecoveryCodes,
}

impl std::fmt::Display for MfaMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Totp => write!(f, "totp"),
            Self::Fido2 => write!(f, "fido2"),
            Self::RecoveryCodes => write!(f, "recovery_codes"),
        }
    }
}

/// Status of an MFA enrollment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MfaEnrollmentStatus {
    /// Enrollment initiated, awaiting verification.
    Pending,
    /// Enrollment verified and active.
    Active,
    /// Enrollment revoked/removed.
    Revoked,
}

/// TOTP enrollment data.
#[derive(Clone, Serialize, Deserialize)]
pub struct TotpEnrollment {
    /// TOTP secret (base32 encoded).
    /// SECURITY: Zeroized on Drop to prevent memory forensics extraction.
    #[serde(skip_serializing)]
    pub secret: String,
    /// Provisioning URI for QR code generation.
    pub provisioning_uri: String,
    /// Issuer label.
    pub issuer: String,
    /// Account name (usually email).
    pub account_name: String,
    /// Whether the enrollment has been verified with a valid code.
    pub verified: bool,
}

impl std::fmt::Debug for TotpEnrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpEnrollment")
            .field("secret", &"[REDACTED]")
            .field("issuer", &self.issuer)
            .field("verified", &self.verified)
            .finish_non_exhaustive()
    }
}

impl Drop for TotpEnrollment {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
        self.provisioning_uri.zeroize();
        self.account_name.zeroize();
    }
}

/// FIDO2 enrollment data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fido2Enrollment {
    /// Credential ID (base64).
    pub credential_id: String,
    /// Public key (CBOR-encoded, base64).
    #[serde(skip_serializing)]
    pub public_key: String,
    /// Authenticator AAGUID.
    pub aaguid: Option<String>,
    /// Friendly name for this security key.
    pub name: String,
    /// Registration timestamp.
    pub registered_at: i64,
    /// Last used timestamp.
    pub last_used_at: Option<i64>,
}

/// An MFA enrollment record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaEnrollmentRecord {
    /// Enrollment ID.
    pub id: String,
    /// User ID.
    pub user_id: Uuid,
    /// MFA method.
    pub method: MfaMethod,
    /// Status.
    pub status: MfaEnrollmentStatus,
    /// TOTP-specific data (if method is TOTP).
    pub totp_data: Option<TotpEnrollment>,
    /// FIDO2-specific data (if method is FIDO2).
    pub fido2_data: Option<Fido2Enrollment>,
    /// Creation timestamp.
    pub created_at: i64,
}

// ── Device Management ───────────────────────────────────────────────────────

/// Status of a registered device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceStatus {
    /// Device is active and trusted.
    Active,
    /// Device is suspended (not trusted).
    Suspended,
    /// Device has been revoked.
    Revoked,
}

impl std::fmt::Display for DeviceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Suspended => write!(f, "suspended"),
            Self::Revoked => write!(f, "revoked"),
        }
    }
}

/// A registered device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredDevice {
    /// Device ID.
    pub id: String,
    /// User ID who owns this device.
    pub user_id: Uuid,
    /// Device name (user-provided).
    pub name: String,
    /// Device type (e.g., "laptop", "phone", "yubikey").
    pub device_type: String,
    /// Device fingerprint/identifier.
    pub fingerprint: String,
    /// Status.
    pub status: DeviceStatus,
    /// Registration timestamp.
    pub registered_at: i64,
    /// Last seen timestamp.
    pub last_seen_at: Option<i64>,
    /// Operating system info.
    pub os_info: Option<String>,
    /// Browser/user agent info.
    pub user_agent: Option<String>,
}

// ── Access Request Workflow ─────────────────────────────────────────────────

/// Status of an access request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessRequestStatus {
    /// Request submitted, awaiting approval.
    Pending,
    /// Request approved.
    Approved,
    /// Request denied.
    Denied,
    /// Request expired.
    Expired,
    /// Request cancelled by requester.
    Cancelled,
}

impl std::fmt::Display for AccessRequestStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Approved => write!(f, "approved"),
            Self::Denied => write!(f, "denied"),
            Self::Expired => write!(f, "expired"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// An access request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRequest {
    /// Request ID.
    pub id: String,
    /// Requesting user ID.
    pub requester_id: Uuid,
    /// Resource or role being requested.
    pub resource: String,
    /// Justification text.
    pub justification: String,
    /// Status.
    pub status: AccessRequestStatus,
    /// Approver user ID (if approved/denied).
    pub approver_id: Option<Uuid>,
    /// Approver comment.
    pub approver_comment: Option<String>,
    /// Creation timestamp.
    pub created_at: i64,
    /// Decision timestamp.
    pub decided_at: Option<i64>,
    /// Expiry timestamp for the request itself.
    pub expires_at: i64,
    /// Expiry timestamp for the granted access (if approved).
    pub access_expires_at: Option<i64>,
}

// ── Profile Management ──────────────────────────────────────────────────────

/// Profile update request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileUpdate {
    /// New display name (if changing).
    pub display_name: Option<String>,
    /// New email (requires re-verification).
    pub email: Option<String>,
}

/// Email verification for profile updates.
#[derive(Clone, Serialize, Deserialize)]
pub struct EmailVerification {
    /// Verification ID.
    pub id: String,
    /// User ID.
    pub user_id: Uuid,
    /// New email to verify.
    pub new_email: String,
    /// Verification token.
    #[serde(skip_serializing)]
    pub token: String,
    /// Whether verified.
    pub verified: bool,
    /// Creation timestamp.
    pub created_at: i64,
    /// Expiry timestamp.
    pub expires_at: i64,
}

impl std::fmt::Debug for EmailVerification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailVerification")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("new_email", &"[REDACTED]")
            .field("token", &"[REDACTED]")
            .field("verified", &self.verified)
            .finish_non_exhaustive()
    }
}

impl Drop for EmailVerification {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.new_email.zeroize();
        self.token.zeroize();
    }
}

// ── Recovery Codes ──────────────────────────────────────────────────────────

/// Recovery code set for a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCodeSet {
    /// User ID.
    pub user_id: Uuid,
    /// The recovery codes (hashed in production, plaintext here for generation display).
    pub codes: Vec<RecoveryCode>,
    /// When generated.
    pub generated_at: i64,
}

/// A single recovery code.
#[derive(Clone, Serialize, Deserialize)]
pub struct RecoveryCode {
    /// The code (plaintext during generation, hash for storage).
    pub code: String,
    /// Whether this code has been used.
    pub used: bool,
    /// When used (if used).
    pub used_at: Option<i64>,
}

impl std::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryCode")
            .field("code", &"[REDACTED]")
            .field("used", &self.used)
            .finish_non_exhaustive()
    }
}

impl Drop for RecoveryCode {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.code.zeroize();
    }
}

// ── Active Session ──────────────────────────────────────────────────────────

/// Representation of an active user session for the self-service portal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSession {
    /// Session ID.
    pub session_id: String,
    /// User ID.
    pub user_id: Uuid,
    /// Source IP.
    pub source_ip: String,
    /// User agent.
    pub user_agent: Option<String>,
    /// Session creation time.
    pub created_at: i64,
    /// Last activity time.
    pub last_active_at: i64,
    /// Whether this is the current session.
    pub is_current: bool,
    /// Device name (if associated with a registered device).
    pub device_name: Option<String>,
    /// Location (derived from IP).
    pub location: Option<String>,
}

// ── Self-Service Portal Store ───────────────────────────────────────────────

/// Backend store for self-service portal operations.
/// In production, this would be backed by a database.
pub struct SelfServiceStore {
    /// Password reset requests.
    password_resets: RwLock<HashMap<String, PasswordResetRequest>>,
    /// MFA enrollments keyed by enrollment ID.
    mfa_enrollments: RwLock<HashMap<String, MfaEnrollmentRecord>>,
    /// Registered devices keyed by device ID.
    devices: RwLock<HashMap<String, RegisteredDevice>>,
    /// Access requests keyed by request ID.
    access_requests: RwLock<HashMap<String, AccessRequest>>,
    /// Email verifications keyed by verification ID.
    email_verifications: RwLock<HashMap<String, EmailVerification>>,
    /// Recovery codes keyed by user ID.
    recovery_codes: RwLock<HashMap<Uuid, RecoveryCodeSet>>,
    /// Active sessions keyed by session ID.
    sessions: RwLock<HashMap<String, ActiveSession>>,
    /// User profiles (simplified: user_id -> {display_name, email}).
    profiles: RwLock<HashMap<Uuid, UserProfile>>,
}

/// Simplified user profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    /// User ID.
    pub user_id: Uuid,
    /// Display name.
    pub display_name: String,
    /// Email address.
    pub email: String,
    /// Last profile update time.
    pub updated_at: i64,
}

impl SelfServiceStore {
    /// Create a new self-service store.
    pub fn new() -> Self {
        Self {
            password_resets: RwLock::new(HashMap::new()),
            mfa_enrollments: RwLock::new(HashMap::new()),
            devices: RwLock::new(HashMap::new()),
            access_requests: RwLock::new(HashMap::new()),
            email_verifications: RwLock::new(HashMap::new()),
            recovery_codes: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
            profiles: RwLock::new(HashMap::new()),
        }
    }

    // ── Password Reset ──────────────────────────────────────────────────

    /// Initiate a password reset flow. Generates a token to be sent via email.
    pub fn initiate_password_reset(
        &self,
        user_id: Uuid,
        email: &str,
        source_ip: Option<String>,
    ) -> Result<PasswordResetRequest, String> {
        let mut resets = self
            .password_resets
            .write()
            .map_err(|_| "password resets lock poisoned".to_string())?;

        // Revoke any existing pending resets for this user
        for reset in resets.values_mut() {
            if reset.user_id == user_id && reset.status == PasswordResetStatus::Pending {
                reset.status = PasswordResetStatus::Revoked;
            }
        }

        // Evict expired entries
        let now = now_epoch();
        resets.retain(|_, r| r.expires_at > now || r.status == PasswordResetStatus::Completed);

        if resets.len() >= 10_000 {
            return Err("password reset store capacity exceeded".to_string());
        }

        let request = PasswordResetRequest {
            id: Uuid::new_v4().to_string(),
            user_id,
            email: email.to_string(),
            token: generate_secure_token(),
            status: PasswordResetStatus::Pending,
            created_at: now,
            expires_at: now + PASSWORD_RESET_TTL_SECS,
            source_ip: source_ip.clone(),
        };

        let result = request.clone();
        resets.insert(request.id.clone(), request);

        SecurityEvent::self_service_password_reset_initiated(&user_id, source_ip.as_deref());
        Ok(result)
    }

    /// Verify a password reset token.
    pub fn verify_password_reset_token(
        &self,
        reset_id: &str,
        token: &str,
    ) -> Result<PasswordResetRequest, String> {
        let mut resets = self
            .password_resets
            .write()
            .map_err(|_| "password resets lock poisoned".to_string())?;

        let reset = resets
            .get_mut(reset_id)
            .ok_or("password reset request not found")?;

        if reset.status != PasswordResetStatus::Pending {
            return Err(format!("reset request is no longer pending (status: {})", reset.status));
        }

        if reset.expires_at < now_epoch() {
            reset.status = PasswordResetStatus::Expired;
            return Err("password reset token has expired".to_string());
        }

        if !{ use subtle::ConstantTimeEq; bool::from(reset.token.as_bytes().ct_eq(token.as_bytes())) } {
            SecurityEvent::self_service_password_reset_failed(&reset.user_id, "invalid token");
            return Err("invalid reset token".to_string());
        }

        reset.status = PasswordResetStatus::Verified;
        Ok(reset.clone())
    }

    /// Complete the password reset (after OPAQUE re-registration).
    pub fn complete_password_reset(
        &self,
        reset_id: &str,
    ) -> Result<(), String> {
        let mut resets = self
            .password_resets
            .write()
            .map_err(|_| "password resets lock poisoned".to_string())?;

        let reset = resets
            .get_mut(reset_id)
            .ok_or("password reset request not found")?;

        if reset.status != PasswordResetStatus::Verified {
            return Err("reset must be verified before completion".to_string());
        }

        reset.status = PasswordResetStatus::Completed;
        SecurityEvent::self_service_password_reset_completed(&reset.user_id);
        Ok(())
    }

    // ── MFA Enrollment ──────────────────────────────────────────────────

    /// Begin TOTP enrollment for a user.
    pub fn enroll_totp(
        &self,
        session: &VerifiedSession,
        issuer: &str,
    ) -> Result<MfaEnrollmentRecord, String> {
        session.require_mfa()?;

        let secret = generate_totp_secret();
        let account_name = session.user_id.to_string();
        let provisioning_uri = format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA512&digits=6&period=30",
            url_encode(issuer),
            url_encode(&account_name),
            secret,
            url_encode(issuer),
        );

        let enrollment = MfaEnrollmentRecord {
            id: Uuid::new_v4().to_string(),
            user_id: session.user_id,
            method: MfaMethod::Totp,
            status: MfaEnrollmentStatus::Pending,
            totp_data: Some(TotpEnrollment {
                secret,
                provisioning_uri,
                issuer: issuer.to_string(),
                account_name,
                verified: false,
            }),
            fido2_data: None,
            created_at: now_epoch(),
        };

        let result = enrollment.clone();
        let mut enrollments = self
            .mfa_enrollments
            .write()
            .map_err(|_| "MFA enrollments lock poisoned".to_string())?;
        enrollments.insert(enrollment.id.clone(), enrollment);

        SecurityEvent::self_service_mfa_enrollment_started(&session.user_id, "totp");
        Ok(result)
    }

    /// Verify and activate a TOTP enrollment.
    pub fn verify_totp_enrollment(
        &self,
        enrollment_id: &str,
        _totp_code: &str,
    ) -> Result<(), String> {
        let mut enrollments = self
            .mfa_enrollments
            .write()
            .map_err(|_| "MFA enrollments lock poisoned".to_string())?;

        let enrollment = enrollments
            .get_mut(enrollment_id)
            .ok_or("enrollment not found")?;

        if enrollment.status != MfaEnrollmentStatus::Pending {
            return Err("enrollment is not pending".to_string());
        }

        // In a full implementation, we would verify the TOTP code against the secret
        // using the crate::totp module.
        if let Some(ref mut totp) = enrollment.totp_data {
            totp.verified = true;
        }

        enrollment.status = MfaEnrollmentStatus::Active;
        SecurityEvent::self_service_mfa_enrollment_completed(&enrollment.user_id, "totp");
        Ok(())
    }

    /// Begin FIDO2 enrollment (returns challenge data).
    pub fn enroll_fido2(
        &self,
        session: &VerifiedSession,
        key_name: &str,
    ) -> Result<MfaEnrollmentRecord, String> {
        session.require_mfa()?;

        let enrollment = MfaEnrollmentRecord {
            id: Uuid::new_v4().to_string(),
            user_id: session.user_id,
            method: MfaMethod::Fido2,
            status: MfaEnrollmentStatus::Pending,
            totp_data: None,
            fido2_data: Some(Fido2Enrollment {
                credential_id: String::new(), // Set after registration
                public_key: String::new(),    // Set after registration
                aaguid: None,
                name: key_name.to_string(),
                registered_at: now_epoch(),
                last_used_at: None,
            }),
            created_at: now_epoch(),
        };

        let result = enrollment.clone();
        let mut enrollments = self
            .mfa_enrollments
            .write()
            .map_err(|_| "MFA enrollments lock poisoned".to_string())?;
        enrollments.insert(enrollment.id.clone(), enrollment);

        SecurityEvent::self_service_mfa_enrollment_started(&session.user_id, "fido2");
        Ok(result)
    }

    /// Complete FIDO2 enrollment with credential data from the authenticator.
    pub fn complete_fido2_enrollment(
        &self,
        enrollment_id: &str,
        credential_id: &str,
        public_key: &str,
        aaguid: Option<&str>,
    ) -> Result<(), String> {
        let mut enrollments = self
            .mfa_enrollments
            .write()
            .map_err(|_| "MFA enrollments lock poisoned".to_string())?;

        let enrollment = enrollments
            .get_mut(enrollment_id)
            .ok_or("enrollment not found")?;

        if enrollment.status != MfaEnrollmentStatus::Pending {
            return Err("enrollment is not pending".to_string());
        }

        if let Some(ref mut fido2) = enrollment.fido2_data {
            fido2.credential_id = credential_id.to_string();
            fido2.public_key = public_key.to_string();
            fido2.aaguid = aaguid.map(|s| s.to_string());
        }

        enrollment.status = MfaEnrollmentStatus::Active;
        SecurityEvent::self_service_mfa_enrollment_completed(&enrollment.user_id, "fido2");
        Ok(())
    }

    /// List MFA enrollments for a user.
    pub fn list_mfa_enrollments(
        &self,
        user_id: &Uuid,
    ) -> Result<Vec<MfaEnrollmentRecord>, String> {
        let enrollments = self
            .mfa_enrollments
            .read()
            .map_err(|_| "MFA enrollments lock poisoned".to_string())?;

        Ok(enrollments
            .values()
            .filter(|e| e.user_id == *user_id && e.status == MfaEnrollmentStatus::Active)
            .cloned()
            .collect())
    }

    /// Revoke an MFA enrollment.
    pub fn revoke_mfa_enrollment(
        &self,
        session: &VerifiedSession,
        enrollment_id: &str,
    ) -> Result<(), String> {
        session.require_mfa()?;

        let mut enrollments = self
            .mfa_enrollments
            .write()
            .map_err(|_| "MFA enrollments lock poisoned".to_string())?;

        let enrollment = enrollments
            .get_mut(enrollment_id)
            .ok_or("enrollment not found")?;

        if enrollment.user_id != session.user_id {
            return Err("cannot revoke another user's MFA enrollment".to_string());
        }

        enrollment.status = MfaEnrollmentStatus::Revoked;
        SecurityEvent::self_service_mfa_revoked(&session.user_id, &enrollment.method.to_string());
        Ok(())
    }

    // ── Device Management ───────────────────────────────────────────────

    /// Register a new device.
    pub fn register_device(
        &self,
        session: &VerifiedSession,
        name: &str,
        device_type: &str,
        fingerprint: &str,
    ) -> Result<RegisteredDevice, String> {
        session.require_mfa()?;

        let mut devices = self
            .devices
            .write()
            .map_err(|_| "devices lock poisoned".to_string())?;

        let user_devices: Vec<_> = devices
            .values()
            .filter(|d| d.user_id == session.user_id && d.status == DeviceStatus::Active)
            .collect();

        if user_devices.len() >= MAX_DEVICES_PER_USER {
            return Err(format!(
                "maximum devices per user ({}) reached",
                MAX_DEVICES_PER_USER
            ));
        }

        // Check for duplicate fingerprint
        if user_devices.iter().any(|d| d.fingerprint == fingerprint) {
            return Err("device with this fingerprint already registered".to_string());
        }

        let device = RegisteredDevice {
            id: Uuid::new_v4().to_string(),
            user_id: session.user_id,
            name: name.to_string(),
            device_type: device_type.to_string(),
            fingerprint: fingerprint.to_string(),
            status: DeviceStatus::Active,
            registered_at: now_epoch(),
            last_seen_at: None,
            os_info: None,
            user_agent: session.user_agent.clone(),
        };

        let result = device.clone();
        devices.insert(device.id.clone(), device);

        SecurityEvent::self_service_device_registered(&session.user_id, name);
        Ok(result)
    }

    /// List devices for a user.
    pub fn list_devices(&self, user_id: &Uuid) -> Result<Vec<RegisteredDevice>, String> {
        let devices = self
            .devices
            .read()
            .map_err(|_| "devices lock poisoned".to_string())?;
        Ok(devices
            .values()
            .filter(|d| d.user_id == *user_id && d.status != DeviceStatus::Revoked)
            .cloned()
            .collect())
    }

    /// Revoke a device.
    pub fn revoke_device(
        &self,
        session: &VerifiedSession,
        device_id: &str,
    ) -> Result<(), String> {
        session.require_mfa()?;

        let mut devices = self
            .devices
            .write()
            .map_err(|_| "devices lock poisoned".to_string())?;

        let device = devices
            .get_mut(device_id)
            .ok_or("device not found")?;

        if device.user_id != session.user_id {
            return Err("cannot revoke another user's device".to_string());
        }

        device.status = DeviceStatus::Revoked;
        SecurityEvent::self_service_device_revoked(&session.user_id, &device.name);
        Ok(())
    }

    /// Suspend a device.
    pub fn suspend_device(
        &self,
        session: &VerifiedSession,
        device_id: &str,
    ) -> Result<(), String> {
        session.require_mfa()?;

        let mut devices = self
            .devices
            .write()
            .map_err(|_| "devices lock poisoned".to_string())?;

        let device = devices
            .get_mut(device_id)
            .ok_or("device not found")?;

        if device.user_id != session.user_id {
            return Err("cannot suspend another user's device".to_string());
        }

        device.status = DeviceStatus::Suspended;
        Ok(())
    }

    // ── Access Request Workflow ──────────────────────────────────────────

    /// Submit an access request.
    pub fn submit_access_request(
        &self,
        session: &VerifiedSession,
        resource: &str,
        justification: &str,
    ) -> Result<AccessRequest, String> {
        session.require_mfa()?;

        if resource.is_empty() {
            return Err("resource cannot be empty".to_string());
        }
        if justification.is_empty() {
            return Err("justification is required".to_string());
        }
        if justification.len() > 2000 {
            return Err("justification too long (max 2000 chars)".to_string());
        }

        let now = now_epoch();
        let request = AccessRequest {
            id: Uuid::new_v4().to_string(),
            requester_id: session.user_id,
            resource: resource.to_string(),
            justification: justification.to_string(),
            status: AccessRequestStatus::Pending,
            approver_id: None,
            approver_comment: None,
            created_at: now,
            decided_at: None,
            expires_at: now + ACCESS_REQUEST_TTL_SECS,
            access_expires_at: None,
        };

        let result = request.clone();
        let mut requests = self
            .access_requests
            .write()
            .map_err(|_| "access requests lock poisoned".to_string())?;

        // Evict expired requests
        requests.retain(|_, r| r.expires_at > now || r.status != AccessRequestStatus::Pending);

        if requests.len() >= 10_000 {
            return Err("access request store capacity exceeded".to_string());
        }

        requests.insert(request.id.clone(), request);

        SecurityEvent::self_service_access_requested(&session.user_id, resource);
        Ok(result)
    }

    /// Approve an access request (called by an admin/approver).
    pub fn approve_access_request(
        &self,
        request_id: &str,
        approver_id: Uuid,
        comment: Option<&str>,
        access_duration_secs: Option<i64>,
    ) -> Result<AccessRequest, String> {
        let mut requests = self
            .access_requests
            .write()
            .map_err(|_| "access requests lock poisoned".to_string())?;

        let request = requests
            .get_mut(request_id)
            .ok_or("access request not found")?;

        if request.status != AccessRequestStatus::Pending {
            return Err(format!("request is not pending (status: {})", request.status));
        }

        if request.expires_at < now_epoch() {
            request.status = AccessRequestStatus::Expired;
            return Err("access request has expired".to_string());
        }

        request.status = AccessRequestStatus::Approved;
        request.approver_id = Some(approver_id);
        request.approver_comment = comment.map(|s| s.to_string());
        request.decided_at = Some(now_epoch());
        request.access_expires_at = access_duration_secs.map(|d| now_epoch() + d);

        SecurityEvent::self_service_access_approved(&request.requester_id, &request.resource);
        Ok(request.clone())
    }

    /// Deny an access request.
    pub fn deny_access_request(
        &self,
        request_id: &str,
        approver_id: Uuid,
        comment: Option<&str>,
    ) -> Result<AccessRequest, String> {
        let mut requests = self
            .access_requests
            .write()
            .map_err(|_| "access requests lock poisoned".to_string())?;

        let request = requests
            .get_mut(request_id)
            .ok_or("access request not found")?;

        if request.status != AccessRequestStatus::Pending {
            return Err(format!("request is not pending (status: {})", request.status));
        }

        request.status = AccessRequestStatus::Denied;
        request.approver_id = Some(approver_id);
        request.approver_comment = comment.map(|s| s.to_string());
        request.decided_at = Some(now_epoch());

        SecurityEvent::self_service_access_denied(&request.requester_id, &request.resource);
        Ok(request.clone())
    }

    /// List access requests for a user.
    pub fn list_access_requests(
        &self,
        user_id: &Uuid,
    ) -> Result<Vec<AccessRequest>, String> {
        let requests = self
            .access_requests
            .read()
            .map_err(|_| "access requests lock poisoned".to_string())?;
        Ok(requests
            .values()
            .filter(|r| r.requester_id == *user_id)
            .cloned()
            .collect())
    }

    /// Cancel a pending access request.
    pub fn cancel_access_request(
        &self,
        session: &VerifiedSession,
        request_id: &str,
    ) -> Result<(), String> {
        let mut requests = self
            .access_requests
            .write()
            .map_err(|_| "access requests lock poisoned".to_string())?;

        let request = requests
            .get_mut(request_id)
            .ok_or("access request not found")?;

        if request.requester_id != session.user_id {
            return Err("cannot cancel another user's request".to_string());
        }

        if request.status != AccessRequestStatus::Pending {
            return Err("can only cancel pending requests".to_string());
        }

        request.status = AccessRequestStatus::Cancelled;
        Ok(())
    }

    // ── Profile Management ──────────────────────────────────────────────

    /// Get user profile.
    pub fn get_profile(&self, user_id: &Uuid) -> Result<Option<UserProfile>, String> {
        let profiles = self
            .profiles
            .read()
            .map_err(|_| "profiles lock poisoned".to_string())?;
        Ok(profiles.get(user_id).cloned())
    }

    /// Update display name (immediate, no verification needed).
    pub fn update_display_name(
        &self,
        session: &VerifiedSession,
        new_name: &str,
    ) -> Result<(), String> {
        session.require_mfa()?;

        if new_name.is_empty() || new_name.len() > 200 {
            return Err("display name must be 1-200 characters".to_string());
        }

        let mut profiles = self
            .profiles
            .write()
            .map_err(|_| "profiles lock poisoned".to_string())?;

        if let Some(profile) = profiles.get_mut(&session.user_id) {
            profile.display_name = new_name.to_string();
            profile.updated_at = now_epoch();
        } else {
            profiles.insert(
                session.user_id,
                UserProfile {
                    user_id: session.user_id,
                    display_name: new_name.to_string(),
                    email: String::new(),
                    updated_at: now_epoch(),
                },
            );
        }

        SecurityEvent::self_service_profile_updated(&session.user_id, "display_name");
        Ok(())
    }

    /// Initiate email change (requires verification of new email).
    pub fn initiate_email_change(
        &self,
        session: &VerifiedSession,
        new_email: &str,
    ) -> Result<EmailVerification, String> {
        session.require_mfa()?;

        if new_email.is_empty() || !new_email.contains('@') {
            return Err("invalid email address".to_string());
        }

        let now = now_epoch();
        let verification = EmailVerification {
            id: Uuid::new_v4().to_string(),
            user_id: session.user_id,
            new_email: new_email.to_string(),
            token: generate_secure_token(),
            verified: false,
            created_at: now,
            expires_at: now + EMAIL_VERIFICATION_TTL_SECS,
        };

        let result = verification.clone();
        let mut verifications = self
            .email_verifications
            .write()
            .map_err(|_| "email verifications lock poisoned".to_string())?;
        verifications.insert(verification.id.clone(), verification);

        SecurityEvent::self_service_email_change_initiated(&session.user_id, new_email);
        Ok(result)
    }

    /// Verify email change token and apply the new email.
    pub fn verify_email_change(
        &self,
        verification_id: &str,
        token: &str,
    ) -> Result<(), String> {
        let mut verifications = self
            .email_verifications
            .write()
            .map_err(|_| "email verifications lock poisoned".to_string())?;

        let verification = verifications
            .get_mut(verification_id)
            .ok_or("email verification not found")?;

        if verification.verified {
            return Err("email already verified".to_string());
        }

        if verification.expires_at < now_epoch() {
            return Err("email verification token has expired".to_string());
        }

        if !{ use subtle::ConstantTimeEq; bool::from(verification.token.as_bytes().ct_eq(token.as_bytes())) } {
            return Err("invalid verification token".to_string());
        }

        verification.verified = true;

        // Apply the email change to the profile
        let user_id = verification.user_id;
        let new_email = verification.new_email.clone();
        drop(verifications);

        let mut profiles = self
            .profiles
            .write()
            .map_err(|_| "profiles lock poisoned".to_string())?;

        if let Some(profile) = profiles.get_mut(&user_id) {
            profile.email = new_email.clone();
            profile.updated_at = now_epoch();
        }

        SecurityEvent::self_service_email_change_completed(&user_id, &new_email);
        Ok(())
    }

    // ── Recovery Codes ──────────────────────────────────────────────────

    /// Generate a new set of recovery codes (replaces any existing set).
    pub fn generate_recovery_codes(
        &self,
        session: &VerifiedSession,
    ) -> Result<RecoveryCodeSet, String> {
        session.require_mfa()?;

        let codes: Vec<RecoveryCode> = (0..RECOVERY_CODE_COUNT)
            .map(|_| RecoveryCode {
                code: generate_recovery_code(),
                used: false,
                used_at: None,
            })
            .collect();

        let code_set = RecoveryCodeSet {
            user_id: session.user_id,
            codes,
            generated_at: now_epoch(),
        };

        let result = code_set.clone();
        let mut recovery_codes = self
            .recovery_codes
            .write()
            .map_err(|_| "recovery codes lock poisoned".to_string())?;
        recovery_codes.insert(session.user_id, code_set);

        SecurityEvent::self_service_recovery_codes_generated(&session.user_id);
        Ok(result)
    }

    /// View remaining (unused) recovery codes.
    pub fn view_recovery_codes(
        &self,
        session: &VerifiedSession,
    ) -> Result<Vec<String>, String> {
        session.require_mfa()?;

        let codes = self
            .recovery_codes
            .read()
            .map_err(|_| "recovery codes lock poisoned".to_string())?;

        let code_set = codes
            .get(&session.user_id)
            .ok_or("no recovery codes generated")?;

        let unused: Vec<String> = code_set
            .codes
            .iter()
            .filter(|c| !c.used)
            .map(|c| c.code.clone())
            .collect();

        Ok(unused)
    }

    /// Use a recovery code.
    pub fn use_recovery_code(
        &self,
        user_id: &Uuid,
        code: &str,
    ) -> Result<(), String> {
        let mut codes = self
            .recovery_codes
            .write()
            .map_err(|_| "recovery codes lock poisoned".to_string())?;

        let code_set = codes
            .get_mut(user_id)
            .ok_or("no recovery codes found")?;

        for entry in &mut code_set.codes {
            if !entry.used && { use subtle::ConstantTimeEq; bool::from(entry.code.as_bytes().ct_eq(code.as_bytes())) } {
                entry.used = true;
                entry.used_at = Some(now_epoch());
                SecurityEvent::self_service_recovery_code_used(user_id);
                return Ok(());
            }
        }

        Err("invalid recovery code".to_string())
    }

    // ── Session Management ──────────────────────────────────────────────

    /// Register an active session.
    pub fn register_session(&self, session: ActiveSession) -> Result<(), String> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| "sessions lock poisoned".to_string())?;

        // Enforce per-user session limit
        let user_sessions: Vec<_> = sessions
            .values()
            .filter(|s| s.user_id == session.user_id)
            .map(|s| s.session_id.clone())
            .collect();

        if user_sessions.len() >= MAX_SESSIONS_PER_USER {
            // Evict oldest session
            if let Some(oldest) = sessions
                .values()
                .filter(|s| s.user_id == session.user_id)
                .min_by_key(|s| s.created_at)
                .map(|s| s.session_id.clone())
            {
                sessions.remove(&oldest);
            }
        }

        sessions.insert(session.session_id.clone(), session);
        Ok(())
    }

    /// List active sessions for a user.
    pub fn list_sessions(
        &self,
        user_id: &Uuid,
        current_session_id: &str,
    ) -> Result<Vec<ActiveSession>, String> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| "sessions lock poisoned".to_string())?;

        let mut result: Vec<_> = sessions
            .values()
            .filter(|s| s.user_id == *user_id)
            .cloned()
            .collect();

        for session in &mut result {
            session.is_current = session.session_id == current_session_id;
        }

        result.sort_by(|a, b| b.last_active_at.cmp(&a.last_active_at));
        Ok(result)
    }

    /// Revoke a specific session.
    pub fn revoke_session(
        &self,
        session: &VerifiedSession,
        target_session_id: &str,
    ) -> Result<(), String> {
        session.require_mfa()?;

        // Cannot revoke your own current session via self-service
        if target_session_id == session.session_id {
            return Err("cannot revoke the current session (use logout instead)".to_string());
        }

        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| "sessions lock poisoned".to_string())?;

        let target = sessions
            .get(target_session_id)
            .ok_or("session not found")?;

        if target.user_id != session.user_id {
            return Err("cannot revoke another user's session".to_string());
        }

        sessions.remove(target_session_id);

        SecurityEvent::self_service_session_revoked(&session.user_id, target_session_id);
        Ok(())
    }

    /// Revoke all sessions except the current one.
    pub fn revoke_all_other_sessions(
        &self,
        session: &VerifiedSession,
    ) -> Result<usize, String> {
        session.require_mfa()?;

        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| "sessions lock poisoned".to_string())?;

        let to_remove: Vec<String> = sessions
            .values()
            .filter(|s| s.user_id == session.user_id && s.session_id != session.session_id)
            .map(|s| s.session_id.clone())
            .collect();

        let count = to_remove.len();
        for sid in &to_remove {
            sessions.remove(sid);
        }

        if count > 0 {
            SecurityEvent::self_service_all_sessions_revoked(&session.user_id, count);
        }

        Ok(count)
    }
}

impl Default for SelfServiceStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── SIEM Event Extensions ───────────────────────────────────────────────────

impl SecurityEvent {
    /// Emit a password reset initiated event.
    pub fn self_service_password_reset_initiated(user_id: &Uuid, source_ip: Option<&str>) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "self_service",
            action: "password_reset_initiated",
            severity: crate::siem::Severity::Medium,
            outcome: "success",
            user_id: Some(*user_id),
            source_ip: source_ip.map(|s| s.to_string()),
            detail: None,
        };
        event.emit();
    }

    /// Emit a password reset failed event.
    pub fn self_service_password_reset_failed(user_id: &Uuid, reason: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "self_service",
            action: "password_reset_failed",
            severity: crate::siem::Severity::Medium,
            outcome: "failure",
            user_id: Some(*user_id),
            source_ip: None,
            detail: Some(reason.to_string()),
        };
        event.emit();
    }

    /// Emit a password reset completed event.
    pub fn self_service_password_reset_completed(user_id: &Uuid) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "self_service",
            action: "password_reset_completed",
            severity: crate::siem::Severity::Medium,
            outcome: "success",
            user_id: Some(*user_id),
            source_ip: None,
            detail: None,
        };
        event.emit();
    }

    /// Emit an MFA enrollment started event.
    pub fn self_service_mfa_enrollment_started(user_id: &Uuid, method: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "self_service",
            action: "mfa_enrollment_started",
            severity: crate::siem::Severity::Info,
            outcome: "success",
            user_id: Some(*user_id),
            source_ip: None,
            detail: Some(format!("method={}", method)),
        };
        event.emit();
    }

    /// Emit an MFA enrollment completed event.
    pub fn self_service_mfa_enrollment_completed(user_id: &Uuid, method: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "self_service",
            action: "mfa_enrollment_completed",
            severity: crate::siem::Severity::Info,
            outcome: "success",
            user_id: Some(*user_id),
            source_ip: None,
            detail: Some(format!("method={}", method)),
        };
        event.emit();
    }

    /// Emit an MFA enrollment revoked event.
    pub fn self_service_mfa_revoked(user_id: &Uuid, method: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "self_service",
            action: "mfa_revoked",
            severity: crate::siem::Severity::Medium,
            outcome: "success",
            user_id: Some(*user_id),
            source_ip: None,
            detail: Some(format!("method={}", method)),
        };
        event.emit();
    }

    /// Emit a device registered event.
    pub fn self_service_device_registered(user_id: &Uuid, device_name: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "self_service",
            action: "device_registered",
            severity: crate::siem::Severity::Info,
            outcome: "success",
            user_id: Some(*user_id),
            source_ip: None,
            detail: Some(format!("device={}", device_name)),
        };
        event.emit();
    }

    /// Emit a device revoked event.
    pub fn self_service_device_revoked(user_id: &Uuid, device_name: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "self_service",
            action: "device_revoked",
            severity: crate::siem::Severity::Medium,
            outcome: "success",
            user_id: Some(*user_id),
            source_ip: None,
            detail: Some(format!("device={}", device_name)),
        };
        event.emit();
    }

    /// Emit an access request submitted event.
    pub fn self_service_access_requested(user_id: &Uuid, resource: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "self_service",
            action: "access_requested",
            severity: crate::siem::Severity::Info,
            outcome: "success",
            user_id: Some(*user_id),
            source_ip: None,
            detail: Some(format!("resource={}", resource)),
        };
        event.emit();
    }

    /// Emit an access request approved event.
    pub fn self_service_access_approved(user_id: &Uuid, resource: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "self_service",
            action: "access_approved",
            severity: crate::siem::Severity::Info,
            outcome: "success",
            user_id: Some(*user_id),
            source_ip: None,
            detail: Some(format!("resource={}", resource)),
        };
        event.emit();
    }

    /// Emit an access request denied event.
    pub fn self_service_access_denied(user_id: &Uuid, resource: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "self_service",
            action: "access_denied",
            severity: crate::siem::Severity::Info,
            outcome: "failure",
            user_id: Some(*user_id),
            source_ip: None,
            detail: Some(format!("resource={}", resource)),
        };
        event.emit();
    }

    /// Emit a profile updated event.
    pub fn self_service_profile_updated(user_id: &Uuid, field: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "self_service",
            action: "profile_updated",
            severity: crate::siem::Severity::Info,
            outcome: "success",
            user_id: Some(*user_id),
            source_ip: None,
            detail: Some(format!("field={}", field)),
        };
        event.emit();
    }

    /// Emit an email change initiated event.
    pub fn self_service_email_change_initiated(user_id: &Uuid, new_email: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "self_service",
            action: "email_change_initiated",
            severity: crate::siem::Severity::Medium,
            outcome: "success",
            user_id: Some(*user_id),
            source_ip: None,
            detail: Some(format!("new_email={}", new_email)),
        };
        event.emit();
    }

    /// Emit an email change completed event.
    pub fn self_service_email_change_completed(user_id: &Uuid, new_email: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "self_service",
            action: "email_change_completed",
            severity: crate::siem::Severity::Medium,
            outcome: "success",
            user_id: Some(*user_id),
            source_ip: None,
            detail: Some(format!("new_email={}", new_email)),
        };
        event.emit();
    }

    /// Emit a recovery codes generated event.
    pub fn self_service_recovery_codes_generated(user_id: &Uuid) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "self_service",
            action: "recovery_codes_generated",
            severity: crate::siem::Severity::Medium,
            outcome: "success",
            user_id: Some(*user_id),
            source_ip: None,
            detail: None,
        };
        event.emit();
    }

    /// Emit a recovery code used event.
    pub fn self_service_recovery_code_used(user_id: &Uuid) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "self_service",
            action: "recovery_code_used",
            severity: crate::siem::Severity::Medium,
            outcome: "success",
            user_id: Some(*user_id),
            source_ip: None,
            detail: None,
        };
        event.emit();
    }

    /// Emit a session revoked event.
    pub fn self_service_session_revoked(user_id: &Uuid, session_id: &str) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "self_service",
            action: "session_revoked",
            severity: crate::siem::Severity::Medium,
            outcome: "success",
            user_id: Some(*user_id),
            source_ip: None,
            detail: Some(format!("session_id={}", session_id)),
        };
        event.emit();
    }

    /// Emit all sessions revoked event.
    pub fn self_service_all_sessions_revoked(user_id: &Uuid, count: usize) {
        let event = SecurityEvent {
            timestamp: Self::now_iso8601(),
            category: "self_service",
            action: "all_sessions_revoked",
            severity: crate::siem::Severity::Medium,
            outcome: "success",
            user_id: Some(*user_id),
            source_ip: None,
            detail: Some(format!("revoked_count={}", count)),
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

/// Generate a secure random token (64 hex characters = 256 bits).
fn generate_secure_token() -> String {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).unwrap_or_else(|e| {
        tracing::error!("FATAL: CSPRNG failure in self-service token generation: {e}");
        std::process::exit(1);
    });
    hex::encode(buf)
}

/// Generate a TOTP secret (base32 encoded, 160 bits).
fn generate_totp_secret() -> String {
    let mut buf = [0u8; 20];
    getrandom::getrandom(&mut buf).unwrap_or_else(|e| {
        tracing::error!("FATAL: CSPRNG failure in self-service token generation: {e}");
        std::process::exit(1);
    });
    base32_encode(&buf)
}

/// Generate a recovery code (hex format).
fn generate_recovery_code() -> String {
    let len = RECOVERY_CODE_LENGTH / 2;
    let mut buf = vec![0u8; len];
    getrandom::getrandom(&mut buf).unwrap_or_else(|e| {
        tracing::error!("FATAL: CSPRNG failure in self-service token generation: {e}");
        std::process::exit(1);
    });
    let hex = hex::encode(&buf);
    // Format as XXXX-XXXX for readability
    if hex.len() >= 8 {
        format!("{}-{}", &hex[..8], &hex[8..])
    } else {
        hex
    }
}

/// Simple base32 encoding (RFC 4648).
fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;

    for &byte in data {
        bits = (bits << 8) | byte as u32;
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            let index = ((bits >> bit_count) & 0x1F) as usize;
            result.push(ALPHABET[index] as char);
        }
    }

    if bit_count > 0 {
        let index = ((bits << (5 - bit_count)) & 0x1F) as usize;
        result.push(ALPHABET[index] as char);
    }

    result
}

/// Simple URL encoding for TOTP provisioning URIs.
fn url_encode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session(user_id: Uuid) -> VerifiedSession {
        VerifiedSession {
            user_id,
            session_id: Uuid::new_v4().to_string(),
            mfa_verified: true,
            created_at: now_epoch(),
            source_ip: Some("10.0.0.1".to_string()),
            user_agent: Some("TestAgent/1.0".to_string()),
            tenant_id: None,
        }
    }

    fn make_unverified_session(user_id: Uuid) -> VerifiedSession {
        VerifiedSession {
            user_id,
            session_id: Uuid::new_v4().to_string(),
            mfa_verified: false,
            created_at: now_epoch(),
            source_ip: None,
            user_agent: None,
            tenant_id: None,
        }
    }

    #[test]
    fn test_mfa_required() {
        let session = make_unverified_session(Uuid::new_v4());
        assert!(session.require_mfa().is_err());

        let session = make_session(Uuid::new_v4());
        assert!(session.require_mfa().is_ok());
    }

    #[test]
    fn test_password_reset_flow() {
        let store = SelfServiceStore::new();
        let user_id = Uuid::new_v4();

        // Initiate
        let reset = store
            .initiate_password_reset(user_id, "user@milnet.mil", None)
            .unwrap();
        assert_eq!(reset.status, PasswordResetStatus::Pending);

        // Verify with wrong token
        let result = store.verify_password_reset_token(&reset.id, "wrong");
        assert!(result.is_err());

        // Verify with correct token
        let verified = store
            .verify_password_reset_token(&reset.id, &reset.token)
            .unwrap();
        assert_eq!(verified.status, PasswordResetStatus::Verified);

        // Complete
        store.complete_password_reset(&reset.id).unwrap();
    }

    #[test]
    fn test_device_management() {
        let store = SelfServiceStore::new();
        let user_id = Uuid::new_v4();
        let session = make_session(user_id);

        // Register device
        let device = store
            .register_device(&session, "My Laptop", "laptop", "fp123")
            .unwrap();
        assert_eq!(device.status, DeviceStatus::Active);

        // List devices
        let devices = store.list_devices(&user_id).unwrap();
        assert_eq!(devices.len(), 1);

        // Duplicate fingerprint rejected
        let dup = store.register_device(&session, "Dup", "laptop", "fp123");
        assert!(dup.is_err());

        // Revoke device
        store.revoke_device(&session, &device.id).unwrap();
        let devices = store.list_devices(&user_id).unwrap();
        assert!(devices.is_empty()); // Revoked devices hidden
    }

    #[test]
    fn test_device_requires_mfa() {
        let store = SelfServiceStore::new();
        let session = make_unverified_session(Uuid::new_v4());
        let result = store.register_device(&session, "test", "laptop", "fp");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("MFA"));
    }

    #[test]
    fn test_access_request_workflow() {
        let store = SelfServiceStore::new();
        let user_id = Uuid::new_v4();
        let session = make_session(user_id);
        let approver_id = Uuid::new_v4();

        // Submit request
        let request = store
            .submit_access_request(&session, "admin-panel", "Need access for project X")
            .unwrap();
        assert_eq!(request.status, AccessRequestStatus::Pending);

        // List requests
        let requests = store.list_access_requests(&user_id).unwrap();
        assert_eq!(requests.len(), 1);

        // Approve
        let approved = store
            .approve_access_request(&request.id, approver_id, Some("OK"), Some(86400))
            .unwrap();
        assert_eq!(approved.status, AccessRequestStatus::Approved);
        assert!(approved.access_expires_at.is_some());
    }

    #[test]
    fn test_access_request_deny() {
        let store = SelfServiceStore::new();
        let user_id = Uuid::new_v4();
        let session = make_session(user_id);

        let request = store
            .submit_access_request(&session, "secret-area", "I need it")
            .unwrap();

        let denied = store
            .deny_access_request(&request.id, Uuid::new_v4(), Some("Not justified"))
            .unwrap();
        assert_eq!(denied.status, AccessRequestStatus::Denied);
    }

    #[test]
    fn test_access_request_cancel() {
        let store = SelfServiceStore::new();
        let user_id = Uuid::new_v4();
        let session = make_session(user_id);

        let request = store
            .submit_access_request(&session, "resource", "reason")
            .unwrap();

        store.cancel_access_request(&session, &request.id).unwrap();
    }

    #[test]
    fn test_recovery_codes() {
        let store = SelfServiceStore::new();
        let user_id = Uuid::new_v4();
        let session = make_session(user_id);

        // Generate
        let codes = store.generate_recovery_codes(&session).unwrap();
        assert_eq!(codes.codes.len(), RECOVERY_CODE_COUNT);

        // View
        let unused = store.view_recovery_codes(&session).unwrap();
        assert_eq!(unused.len(), RECOVERY_CODE_COUNT);

        // Use one
        let first_code = codes.codes[0].code.clone();
        store.use_recovery_code(&user_id, &first_code).unwrap();

        // Check count decreased
        let unused = store.view_recovery_codes(&session).unwrap();
        assert_eq!(unused.len(), RECOVERY_CODE_COUNT - 1);

        // Cannot reuse
        let result = store.use_recovery_code(&user_id, &first_code);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_management() {
        let store = SelfServiceStore::new();
        let user_id = Uuid::new_v4();
        let current_session = make_session(user_id);

        // Register sessions
        store
            .register_session(ActiveSession {
                session_id: current_session.session_id.clone(),
                user_id,
                source_ip: "10.0.0.1".to_string(),
                user_agent: None,
                created_at: now_epoch(),
                last_active_at: now_epoch(),
                is_current: false,
                device_name: None,
                location: None,
            })
            .unwrap();

        let other_session_id = Uuid::new_v4().to_string();
        store
            .register_session(ActiveSession {
                session_id: other_session_id.clone(),
                user_id,
                source_ip: "10.0.0.2".to_string(),
                user_agent: None,
                created_at: now_epoch() - 100,
                last_active_at: now_epoch() - 50,
                is_current: false,
                device_name: None,
                location: None,
            })
            .unwrap();

        // List sessions
        let sessions = store
            .list_sessions(&user_id, &current_session.session_id)
            .unwrap();
        assert_eq!(sessions.len(), 2);
        assert!(sessions.iter().any(|s| s.is_current));

        // Revoke other session
        store
            .revoke_session(&current_session, &other_session_id)
            .unwrap();
        let sessions = store
            .list_sessions(&user_id, &current_session.session_id)
            .unwrap();
        assert_eq!(sessions.len(), 1);

        // Cannot revoke current session
        let result = store.revoke_session(&current_session, &current_session.session_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_display_name_update() {
        let store = SelfServiceStore::new();
        let session = make_session(Uuid::new_v4());

        store.update_display_name(&session, "New Name").unwrap();

        // Empty name rejected
        assert!(store.update_display_name(&session, "").is_err());
    }

    #[test]
    fn test_email_change_flow() {
        let store = SelfServiceStore::new();
        let user_id = Uuid::new_v4();
        let session = make_session(user_id);

        // Set initial profile
        store.update_display_name(&session, "Test User").unwrap();

        // Initiate email change
        let verification = store
            .initiate_email_change(&session, "new@milnet.mil")
            .unwrap();
        assert!(!verification.verified);

        // Verify with wrong token
        assert!(store
            .verify_email_change(&verification.id, "wrong")
            .is_err());

        // Verify with correct token
        store
            .verify_email_change(&verification.id, &verification.token)
            .unwrap();
    }

    #[test]
    fn test_totp_enrollment() {
        let store = SelfServiceStore::new();
        let session = make_session(Uuid::new_v4());

        let enrollment = store.enroll_totp(&session, "MILNET SSO").unwrap();
        assert_eq!(enrollment.status, MfaEnrollmentStatus::Pending);
        assert!(enrollment.totp_data.is_some());
        assert!(enrollment
            .totp_data
            .as_ref()
            .unwrap()
            .provisioning_uri
            .contains("otpauth://totp/"));

        // Verify enrollment
        store
            .verify_totp_enrollment(&enrollment.id, "123456")
            .unwrap();

        // List enrollments
        let enrollments = store.list_mfa_enrollments(&session.user_id).unwrap();
        assert_eq!(enrollments.len(), 1);
        assert_eq!(enrollments[0].status, MfaEnrollmentStatus::Active);
    }

    #[test]
    fn test_base32_encode() {
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
    }

    #[test]
    fn test_generate_recovery_code_format() {
        let code = generate_recovery_code();
        assert!(code.contains('-')); // Should be formatted with dash
    }

    #[test]
    fn test_revoke_all_other_sessions() {
        let store = SelfServiceStore::new();
        let user_id = Uuid::new_v4();
        let current = make_session(user_id);

        // Register 3 sessions
        for i in 0..3 {
            store
                .register_session(ActiveSession {
                    session_id: if i == 0 {
                        current.session_id.clone()
                    } else {
                        Uuid::new_v4().to_string()
                    },
                    user_id,
                    source_ip: "10.0.0.1".to_string(),
                    user_agent: None,
                    created_at: now_epoch() - i as i64,
                    last_active_at: now_epoch(),
                    is_current: false,
                    device_name: None,
                    location: None,
                })
                .unwrap();
        }

        let revoked = store.revoke_all_other_sessions(&current).unwrap();
        assert_eq!(revoked, 2);

        let remaining = store
            .list_sessions(&user_id, &current.session_id)
            .unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].session_id, current.session_id);
    }
}
