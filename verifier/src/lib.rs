#![forbid(unsafe_code)]
//! verifier: Credential Verifier (O(1) token verification).

pub mod messages;
pub mod verify;

pub use messages::{RatchetState, RevokeRequest, RevokeResponse, VerifierMessage, VerifyRequest, VerifyResponse};
pub use verify::{
    verify_token, verify_token_bound, verify_token_full, verify_token_with_dpop,
    verify_token_with_ratchet, verify_token_with_revocation,
};
