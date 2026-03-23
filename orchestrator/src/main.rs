#![forbid(unsafe_code)]
//! orchestrator: Auth Orchestrator entry point.

use crypto::entropy::generate_key_64;
use orchestrator::service::OrchestratorService;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Platform integrity: vTPM check, process hardening, self-attestation, monitor
    let (_platform_report, _monitor_handle, _monitor) =
        common::startup_checks::run_platform_checks(crypto::memguard::harden_process);

    let opaque_addr = std::env::var("OPAQUE_ADDR").unwrap_or_else(|_| "127.0.0.1:9102".into());
    let tss_addr = std::env::var("TSS_ADDR").unwrap_or_else(|_| "127.0.0.1:9103".into());
    let listen_addr = std::env::var("ORCH_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:9101".into());

    // In production these would be loaded from an HSM / sealed config.
    let hmac_key = generate_key_64();

    // SECURITY: No receipt_signing_key — receipts are signed solely by the
    // OPAQUE service and forwarded to the TSS without re-signing.
    // mTLS client credentials are auto-generated at construction time.
    let service = OrchestratorService::new(hmac_key, opaque_addr, tss_addr);

    tracing::info!("Starting orchestrator on {listen_addr} (mTLS)");
    if let Err(e) = service.run(&listen_addr).await {
        tracing::error!("Orchestrator exited with error: {e}");
        std::process::exit(1);
    }
}
