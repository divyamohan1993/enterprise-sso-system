#![forbid(unsafe_code)]
//! common: Shared types for the MILNET SSO system.
//!
//! Provides core domain types including Token, Receipt, DeviceTier,
//! ActionLevel, and other foundational structures used across all crates.

pub mod actions;
pub mod config;
pub mod db;
pub mod domain;
pub mod duress;
pub mod error;
pub mod network;
pub mod revocation;
pub mod types;
pub mod persistence;
pub mod shared_keys;
pub mod witness;

// ── Military hardening modules ──
pub mod cnsa2;
pub mod encrypted_db;
pub mod sealed_keys;

// ── Platform integrity and measured boot ──
pub mod platform_integrity;
pub mod measured_boot;
pub mod startup_checks;

// ── Classification and cross-domain guard ──
pub mod classification;
pub mod cross_domain;

// ── Security infrastructure ──
pub mod session_limits;
pub mod circuit_breaker;
pub mod siem;
pub mod key_rotation;
pub mod retry;
pub mod health;
pub mod recovery;
pub mod totp;
pub mod backup;

// ── Developer mode & error response sanitisation ──
pub mod error_response;

// ── FIPS mode runtime toggle ──
pub mod fips;

// ── Observability & incident response ──
pub mod structured_logging;
pub mod metrics;
pub mod incident_response;

// ── CAC/PIV smart card authentication ──
pub mod cac;
pub mod cac_auth;

// ── Compliance and data residency ──
pub mod compliance;
pub mod data_residency;

// ── STIG/CIS benchmark auditor ──
pub mod stig;
