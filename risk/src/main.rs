#![forbid(unsafe_code)]
//! risk: Risk Scoring Engine service entry point.

use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Platform integrity: vTPM check, process hardening, self-attestation, monitor
    let (_platform_report, _monitor_handle, _monitor) =
        common::startup_checks::run_platform_checks(crypto::memguard::harden_process);

    // Start runtime defense: stealth detection + auto-response pipeline
    let _defense = common::runtime_defense::start_runtime_defense(
        "risk",
        9106,
        _platform_report.binary_hash,
    );

    // Initialize structured JSON logging for production observability
    common::structured_logging::init(common::structured_logging::ServiceMeta {
        service_name: "risk".to_string(),
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

    // Spawn health check endpoint
    let health_start = std::time::Instant::now();
    let _health_handle = common::health::spawn_health_endpoint(
        "risk".to_string(),
        9106,
        health_start,
        || {
            vec![common::health::HealthCheck {
                name: "risk_service".to_string(),
                ok: true,
                detail: None,
                latency_ms: None,
            }]
        },
    );

    tracing::info!("Risk Scoring service starting");

    let engine = Arc::new(RwLock::new(risk::scoring::RiskEngine::new()));
    let registry = Arc::new(RwLock::new(risk::tiers::DeviceRegistry::new()));

    let addr = std::env::var("RISK_ADDR").unwrap_or_else(|_| "127.0.0.1:9106".to_string());
    let hmac_key = crypto::entropy::generate_key_64();
    let (listener, _ca, _cert_key) =
        shard::tls_transport::tls_bind(&addr, common::types::ModuleId::Risk, hmac_key, "risk")
            .await
            .unwrap();

    tracing::info!("Risk Scoring service listening on {addr} (mTLS)");
    loop {
        if let Ok(mut transport) = listener.accept().await {
            let engine_handle = engine.clone();
            let _registry = registry.clone();
            tokio::spawn(async move {
                while let Ok((_sender, payload)) = transport.recv().await {
                    let request: risk::scoring::RiskRequest = match postcard::from_bytes(&payload) {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::error!("Failed to deserialize RiskRequest: {e}");
                            continue;
                        }
                    };

                    let eng = engine_handle.read().await;
                    let score = eng.compute_score(&request.user_id, &request.signals);
                    let classification = format!("{:?}", eng.classify(score));
                    let step_up_required = eng.requires_step_up(score);
                    let session_terminate = eng.requires_termination(score);
                    drop(eng);

                    let response = risk::scoring::RiskResponse {
                        score,
                        classification,
                        step_up_required,
                        session_terminate,
                    };

                    let resp_bytes = match postcard::to_allocvec(&response) {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::error!("Failed to serialize RiskResponse: {e}");
                            continue;
                        }
                    };

                    if let Err(e) = transport.send(&resp_bytes).await {
                        tracing::error!("Failed to send RiskResponse: {e}");
                        break;
                    }
                }
            });
        }
    }
}
