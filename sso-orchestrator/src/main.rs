#![forbid(unsafe_code)]
//! sso-orchestrator: Auth Orchestrator entry point.

use sso_crypto::entropy::generate_key_64;
use sso_orchestrator::service::OrchestratorService;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let opaque_addr = std::env::var("OPAQUE_ADDR").unwrap_or_else(|_| "127.0.0.1:9102".into());
    let tss_addr = std::env::var("TSS_ADDR").unwrap_or_else(|_| "127.0.0.1:9103".into());
    let listen_addr = std::env::var("ORCH_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:9101".into());

    // In production these would be loaded from an HSM / sealed config.
    let hmac_key = generate_key_64();
    let receipt_signing_key = generate_key_64();

    let service = OrchestratorService::new(hmac_key, opaque_addr, tss_addr, receipt_signing_key);

    tracing::info!("Starting orchestrator on {listen_addr}");
    if let Err(e) = service.run(&listen_addr).await {
        tracing::error!("Orchestrator exited with error: {e}");
        std::process::exit(1);
    }
}
