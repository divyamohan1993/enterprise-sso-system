//! SAML 2.0 Service Provider consumer.
//!
//! Strict Response → Assertion pipeline with exclusive C14N, enveloped
//! XML-DSig verification, replay protection, and full XSW/XXE hardening.
#![forbid(unsafe_code)]

pub mod trust;
pub mod time;
pub mod replay_cache;
pub mod request_cache;
pub mod dom;
pub mod c14n;
pub mod dsig;
pub mod validate;

use std::collections::BTreeMap;

pub use replay_cache::ReplayCache;
pub use request_cache::RequestCache;
pub use validate::{consume_response, ValidationConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SamlError {
    #[error("base64 decode failed")]
    Base64,
    #[error("XML parse error")]
    Xml,
    #[error("unsigned assertion rejected")]
    UnsignedRejected,
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("audience restriction mismatch")]
    AudienceMismatch,
    #[error("assertion expired (NotOnOrAfter reached)")]
    Expired,
    #[error("assertion not yet valid (NotBefore in future)")]
    NotYetValid,
    #[error("timestamp failed strict ISO-8601 parse")]
    TimestampParse,
    #[error("configured clock skew exceeds policy cap")]
    ClockSkewExceeded,
    #[error("Status was not Success")]
    StatusNotSuccess,
    #[error("issuer not in trust store")]
    UnknownIssuer,
    #[error("Destination did not match ACS URL")]
    DestinationMismatch,
    #[error("assertion cardinality violation")]
    AssertionCardinality,
    #[error("assertion ID confusion (XSW)")]
    AssertionIdConfusion,
    #[error("signature cardinality violation")]
    SignatureCardinality,
    #[error("signature Reference URI does not match assertion ID")]
    SignatureReferenceMismatch,
    #[error("canonicalization algorithm forbidden")]
    CanonicalizationAlgorithmForbidden,
    #[error("signature algorithm forbidden")]
    SignatureAlgorithmForbidden,
    #[error("digest algorithm forbidden")]
    DigestAlgorithmForbidden,
    #[error("digest mismatch")]
    DigestMismatch,
    #[error("transform chain forbidden")]
    TransformForbidden,
    #[error("X.509 certificate parse failed")]
    CertificateParse,
    #[error("pinned public key type unsupported for this signature alg")]
    PublicKeyUnsupported,
    #[error("subject cardinality violation")]
    SubjectCardinality,
    #[error("SubjectConfirmation Method not bearer")]
    SubjectConfirmationMethod,
    #[error("SubjectConfirmationData Recipient mismatch")]
    SubjectConfirmationRecipient,
    #[error("SubjectConfirmationData expired")]
    SubjectConfirmationExpired,
    #[error("InResponseTo missing or mismatched")]
    InResponseToMismatch,
    #[error("assertion ID replay detected")]
    Replay,
    #[error("XML size limit exceeded")]
    SizeExceeded,
    #[error("XML depth limit exceeded")]
    DepthExceeded,
    #[error("DOCTYPE forbidden")]
    DoctypeForbidden,
    #[error("entity reference forbidden")]
    EntityForbidden,
    #[error("processing instruction forbidden")]
    ProcessingInstructionForbidden,
    #[error("internal invariant violation")]
    Internal,
}

#[derive(Debug, Clone)]
pub struct SamlAssertion {
    pub assertion_id: String,
    pub issuer: String,
    pub subject: String,
    pub audience: String,
    pub destination: String,
    pub in_response_to: String,
    pub not_before: i64,
    pub not_on_or_after: i64,
    pub session_not_on_or_after: Option<i64>,
    pub authn_instant: Option<i64>,
    pub authn_context_class_ref: Option<String>,
    pub attributes: BTreeMap<String, Vec<String>>,
}
