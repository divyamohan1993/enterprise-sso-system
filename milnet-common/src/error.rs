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
}
