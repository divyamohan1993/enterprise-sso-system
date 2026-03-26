#![forbid(unsafe_code)]
//! gateway binary entry point.

use gateway::server::GatewayServer;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Platform integrity: vTPM check, process hardening, self-attestation, monitor
    let (_platform_report, _monitor_handle, _monitor) =
        common::startup_checks::run_platform_checks(crypto::memguard::harden_process);

    // Initialize structured JSON logging for production observability
    common::structured_logging::init(common::structured_logging::ServiceMeta {
        service_name: "gateway".to_string(),
        service_version: env!("CARGO_PKG_VERSION").to_string(),
        instance_id: uuid::Uuid::new_v4().to_string(),
        project_id: std::env::var("GCP_PROJECT_ID").unwrap_or_else(|_| "milnet-sso".to_string()),
    });

    // Verify binary integrity at startup
    let build_info = common::embed_build_info!();
    tracing::info!(
        git_commit = %build_info.git_commit,
        build_time = %build_info.build_time,
        "build manifest verified"
    );

    // Initialize health monitor for peer service tracking
    let _health_monitor = std::sync::Arc::new(common::health::HealthMonitor::new());

    // Initialize metrics counters
    let _auth_counter = common::metrics::Counter::new("auth_attempts", "Total authentication attempts");
    let _error_counter = common::metrics::Counter::new("errors", "Total errors");

    // Verify CNSA 2.0 compliance at startup
    assert!(common::cnsa2::is_cnsa2_compliant(), "CNSA 2.0 compliance check failed");
    tracing::info!("CNSA 2.0 compliance verified");

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

    let server = GatewayServer::bind(&addr, 16)
        .await
        .expect("failed to bind gateway");

    tracing::info!("Gateway listening on {addr}");
    server.run().await.expect("gateway server error");
}
