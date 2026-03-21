#![forbid(unsafe_code)]
//! sso-opaque: T-OPAQUE Password Service.
//!
//! Provides simulated OPAQUE password authentication with ceremony receipt issuance.

pub mod messages;
pub mod service;
pub mod store;
