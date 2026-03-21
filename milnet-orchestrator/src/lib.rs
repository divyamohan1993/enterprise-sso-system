#![forbid(unsafe_code)]
//! milnet-orchestrator: Auth Orchestrator (ceremony routing).
//!
//! Coordinates Gateway, OPAQUE, and TSS services through a ceremony
//! state machine to produce threshold-signed authentication tokens.

pub mod ceremony;
pub mod messages;
pub mod service;
