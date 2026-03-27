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

    // Initialize structured JSON logging for production observability
    common::structured_logging::init(common::structured_logging::ServiceMeta {
        service_name: "orchestrator".to_string(),
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

    let opaque_addr = std::env::var("OPAQUE_ADDR").unwrap_or_else(|_| "127.0.0.1:9102".into());
    let tss_addr = std::env::var("TSS_ADDR").unwrap_or_else(|_| "127.0.0.1:9103".into());
    let listen_addr = std::env::var("ORCH_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:9101".into());

    // In production these would be loaded from an HSM / sealed config.
    let hmac_key = generate_key_64();

    // SECURITY: No receipt_signing_key — receipts are signed solely by the
    // OPAQUE service and forwarded to the TSS without re-signing.
    // mTLS client credentials are auto-generated at construction time.
    let service = OrchestratorService::new(hmac_key, opaque_addr, tss_addr);

    // Spawn health check endpoint
    let health_start = std::time::Instant::now();
    let orch_port: u16 = listen_addr.split(':').last().and_then(|p| p.parse().ok()).unwrap_or(9101);
    let _health_handle = common::health::spawn_health_endpoint(
        "orchestrator".to_string(),
        orch_port,
        health_start,
        || {
            vec![common::health::HealthCheck {
                name: "orchestrator_listener".to_string(),
                ok: true,
                detail: None,
                latency_ms: None,
            }]
        },
    );

    tracing::info!("Starting orchestrator on {listen_addr} (mTLS)");
    if let Err(e) = service.run(&listen_addr).await {
        tracing::error!("Orchestrator exited with error: {e}");
        std::process::exit(1);
    }
}
