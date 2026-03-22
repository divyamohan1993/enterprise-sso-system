#![forbid(unsafe_code)]
//! gateway binary entry point.

use gateway::server::GatewayServer;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Platform integrity: vTPM check, process hardening, self-attestation, monitor
    let (_platform_report, _monitor_handle, _monitor) =
        common::startup_checks::run_platform_checks(crypto::memguard::harden_process);

    let port = std::env::var("GATEWAY_PORT").unwrap_or_else(|_| "9100".into());
    let is_production = std::env::var("MILNET_PRODUCTION").is_ok();
    // In production, default to loopback; override with GATEWAY_BIND_ADDR if needed.
    let default_bind = if is_production { "127.0.0.1" } else { "0.0.0.0" };
    let bind_addr = std::env::var("GATEWAY_BIND_ADDR").unwrap_or_else(|_| default_bind.to_string());

    if bind_addr == "0.0.0.0" {
        tracing::warn!("WARNING: Binding to all interfaces (0.0.0.0). Use a TLS-terminating reverse proxy in production.");
        if is_production {
            tracing::warn!("MILNET_PRODUCTION is set but binding to 0.0.0.0 — set GATEWAY_BIND_ADDR=127.0.0.1 for loopback-only.");
        }
    }

    let addr = format!("{bind_addr}:{port}");

    let server = GatewayServer::bind(&addr, 4)
        .await
        .expect("failed to bind gateway");

    tracing::info!("Gateway listening on {addr}");
    server.run().await.expect("gateway server error");
}
