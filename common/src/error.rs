use thiserror::Error;

/// Unified error type for the MILNET SSO system.
#[derive(Error, Debug)]
pub enum MilnetError {
    #[error("cryptographic verification failed: {0}")]
    CryptoVerification(String),

    #[error("receipt chain integrity error: {0}")]
    ReceiptChain(String),

    #[error("token has expired")]
    TokenExpired,

    #[error("insufficient device tier: required {required}, actual {actual}")]
    InsufficientTier { required: u8, actual: u8 },

    #[error("ceremony replay detected")]
    CeremonyReplay,

    #[error("threshold quorum not met")]
    QuorumNotMet,

    #[error("shard transport error: {0}")]
    Shard(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("audit subsystem unavailable")]
    AuditUnavailable,

    // ── Military hardening errors ──

    #[error("envelope encryption failed: {0}")]
    EnvelopeEncryption(String),

    #[error("envelope decryption failed: {0}")]
    EnvelopeDecryption(String),

    #[error("key seal/unseal failed: {0}")]
    KeySeal(String),

    #[error("entropy health check failed: {0}")]
    EntropyHealth(String),

    #[error("binary attestation failed: {0}")]
    AttestationFailure(String),

    #[error("secure memory error: {0}")]
    SecureMemory(String),

    #[error("production mode violation: {0}")]
    ProductionViolation(String),

    #[error("session limit exceeded: max {max} concurrent sessions")]
    SessionLimitExceeded { max: u32 },

    #[error("forced re-authentication required")]
    ForcedReauth,

    #[error("canary violation — possible memory corruption")]
    CanaryViolation,

    #[error("capacity exceeded: {0}")]
    CapacityExceeded(String),

    #[error("user already registered: {0}")]
    AlreadyRegistered(String),

    #[error("OIDC nonce mismatch")]
    OidcNonceMismatch,

    #[error("corrupted KEK share — reconstructed key does not match expected commitment (X-C: silent slot poisoning rejected)")]
    CorruptedKekShare,

    #[error("KEK reconstruction failed: {0}")]
    KekReconstruction(String),

    #[error("OS entropy unavailable — refusing to fall back to deterministic randomness (X-U)")]
    EntropyExhausted,
}

impl MilnetError {
    /// Return a user-facing message appropriate for the current developer
    /// mode setting.
    ///
    /// - In developer mode: includes the full error chain plus guidance.
    /// - In production:     returns a generic safe message.
    pub fn to_response_message(&self) -> String {
        crate::error_response::sanitize(&self.to_string())
    }

    /// Return an actionable description of what the caller should do.
    ///
    /// This is always safe to show externally — it never leaks internals.
    pub fn caller_guidance(&self) -> &'static str {
        match self {
            MilnetError::CryptoVerification(_) => {
                "Retry the operation. If the error persists, re-authenticate."
            }
            MilnetError::ReceiptChain(_) => {
                "Restart the authentication ceremony from step 1."
            }
            MilnetError::TokenExpired => {
                "Your session has expired. Please log in again."
            }
            MilnetError::InsufficientTier { .. } => {
                "Your device does not meet the required security tier for this action."
            }
            MilnetError::CeremonyReplay => {
                "This ceremony has already been used. Start a new one."
            }
            MilnetError::QuorumNotMet => {
                "Not enough approvers have signed. Wait for additional approvals."
            }
            MilnetError::Shard(_) => {
                "An internal communication error occurred. Try again shortly."
            }
            MilnetError::Serialization(_) => {
                "Invalid request format. Check the request body and try again."
            }
            MilnetError::AuditUnavailable => {
                "The audit subsystem is temporarily unavailable. Operations are paused for safety."
            }
            MilnetError::EnvelopeEncryption(_) | MilnetError::EnvelopeDecryption(_) => {
                "A data protection error occurred. Contact your administrator."
            }
            MilnetError::KeySeal(_) => {
                "Key management error. Contact your administrator."
            }
            MilnetError::EntropyHealth(_) => {
                "System entropy is degraded. The system will resume when hardware RNG recovers."
            }
            MilnetError::AttestationFailure(_) => {
                "Binary integrity check failed. The system cannot start until resolved."
            }
            MilnetError::SecureMemory(_) => {
                "Secure memory allocation failed. Contact your administrator."
            }
            MilnetError::ProductionViolation(_) => {
                "A required production security setting is misconfigured."
            }
            MilnetError::SessionLimitExceeded { .. } => {
                "You have too many active sessions. Log out of another session first."
            }
            MilnetError::ForcedReauth => {
                "Your session requires re-authentication. Please log in again."
            }
            MilnetError::CanaryViolation => {
                "Memory integrity check failed. Contact your administrator immediately."
            }
            MilnetError::CapacityExceeded(_) => {
                "The system has reached its user capacity. Contact your administrator."
            }
            MilnetError::AlreadyRegistered(_) => {
                "This username is already registered. Use re-registration if authorized."
            }
            MilnetError::OidcNonceMismatch => {
                "Authentication failed due to a security check. Please try again."
            }
        }
    }
}
