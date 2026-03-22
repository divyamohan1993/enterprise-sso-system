#![forbid(unsafe_code)]
//! opaque: T-OPAQUE Password Service.
//!
//! SECURITY: This service is the SOLE holder of the receipt signing key.
//! The key is generated (or loaded from HSM) inside `opaque::service::run()`
//! and never leaves this process. The orchestrator forwards receipts to the
//! TSS without re-signing.

use opaque::store::CredentialStore;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Platform integrity: vTPM check, process hardening, self-attestation, monitor
    let (_platform_report, _monitor_handle, _monitor) =
        common::startup_checks::run_platform_checks(crypto::memguard::harden_process);

    let store = CredentialStore::new();
    if let Err(e) = opaque::service::run(store).await {
        eprintln!("OPAQUE service error: {e}");
        std::process::exit(1);
    }
}
