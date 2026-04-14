#![forbid(unsafe_code)]
//! audit: Hash-chained append-only audit log.

pub mod bft;
pub mod blockchain;
pub mod log;
pub mod throttle;

pub use log::{AuditError, audit_write_or_die};
