#![forbid(unsafe_code)]
//! verifier: Credential Verifier (O(1) token verification).

pub mod messages;
pub mod verify;

pub use messages::{VerifyRequest, VerifyResponse};
pub use verify::verify_token;
