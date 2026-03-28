#![deny(unsafe_code)]
//! common: Shared types for the MILNET SSO system.
//!
//! Provides core domain types including Token, Receipt, DeviceTier,
//! ActionLevel, and other foundational structures used across all crates.

pub mod actions;
pub mod config;
pub mod db;
pub mod domain;
pub mod sync;
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
#[allow(unsafe_code)]
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

// ── CMMC 2.0 assessment and SIEM webhook integration ──
pub mod cmmc;
pub mod siem_webhook;

// ── Searchable Symmetric Encryption (blind index for zero-trust DB) ──
pub mod sse;

// ── Reproducible build manifest and binary integrity verification ──
pub mod build_manifest;

// ── Authenticated time, DNS security, BMC hardening, physical security ──
pub mod secure_time;
pub mod dns_security;
pub mod bmc_hardening;
pub mod physical_security;

// ── Session recording & certificate lifecycle ──
pub mod session_recording;
pub mod cert_lifecycle;

// ── Database HA and distributed sessions ──
pub mod db_ha;
pub mod distributed_session;

// ── Distributed consensus, cluster coordination, and auto-healing ──
pub mod raft;
pub mod cluster;
pub mod cluster_roles;
pub mod auto_heal;
pub mod binary_attestation_mesh;
pub mod code_healing;
pub mod threshold_kek;

// ── Privileged Identity Management (just-in-time elevation) ──
pub mod pim;

// ── Device lifecycle management ──
pub mod device_lifecycle;

// ── Conditional access policy engine ──
pub mod conditional_access;

// ── Multi-tenant isolation ──
pub mod multi_tenancy;
pub mod tenant_middleware;

// ── Identity Lifecycle Management ──
pub mod idm;

// ── Continuous Access Evaluation ──
pub mod cae;

// ── SCIM 2.0 provisioning server ──
pub mod scim;

// ── FedRAMP compliance evidence auto-generation ──
pub mod fedramp_evidence;

// ── Automated STIG scanner with CI/CD integration ──
pub mod stig_scanner;

// ── SOC 2 Type II evidence collector ──
pub mod soc2_evidence;

// ── FIPS 140-3 validation abstraction layer ──
pub mod fips_validation;

// ── FIPS 140-3 CMVP submission tracker dashboard ──
pub mod fips_tracker;

// ── Common Criteria (ISO/IEC 15408) Security Target ──
pub mod common_criteria;

// ── Encrypted audit metadata ──
pub mod encrypted_audit;

// ── SAML 2.0 Identity Provider ──
pub mod saml;

// ── Webhook / Event Streaming ──
pub mod event_streaming;

// ── Delegated Administration ──
pub mod delegated_admin;

// ── Self-Service Portal ──
pub mod self_service;

// ── Service discovery, distributed locks, persistent sessions ──
pub mod service_discovery;
pub mod distributed_lock;
pub mod persistent_session;

// ── OCSP/CRL revocation checking ──
pub mod ocsp_crl;

// ── Anti-lateral-movement guard ──
pub mod lateral_movement_guard;

// ── External witness cosigner and distributed CA ──
pub mod external_witness;
pub mod distributed_ca;

// ── Secret ceremony, stealth detection, quarantine, and auto-response ──
pub mod secret_ceremony;
pub mod stealth_detection;
pub mod quarantine;
pub mod auto_response;
