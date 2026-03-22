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
}
