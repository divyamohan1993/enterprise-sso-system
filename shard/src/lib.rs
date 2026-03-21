#![forbid(unsafe_code)]
//! shard: SHARD inter-process communication protocol.
//!
//! Implements the secure, authenticated IPC protocol used for
//! communication between MILNET SSO microservices.

pub mod protocol;
pub mod tls;
pub mod tls_transport;
pub mod transport;
