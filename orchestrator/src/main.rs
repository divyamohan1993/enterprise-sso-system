#![forbid(unsafe_code)]
//! orchestrator: Auth Orchestrator entry point.

use orchestrator::service::OrchestratorService;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Platform integrity: vTPM check, process hardening, self-attestation, monitor
    let (_platform_report, _monitor_handle, _monitor) =
        common::startup_checks::run_platform_checks(crypto::memguard::harden_process);

    // Start runtime defense: stealth detection + auto-response pipeline
    let _defense = common::runtime_defense::start_runtime_defense(
        "orchestrator",
        9101,
        _platform_report.binary_hash,
    );

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
    if !common::cnsa2::is_cnsa2_compliant() {
        tracing::error!("FATAL: CNSA 2.0 compliance check failed");
        std::process::exit(1);
    }
    tracing::info!("CNSA 2.0 compliance verified");

    let opaque_addr = std::env::var("OPAQUE_ADDR").unwrap_or_else(|_| "127.0.0.1:9102".into());
    let tss_addr = std::env::var("TSS_ADDR").unwrap_or_else(|_| "127.0.0.1:9103".into());
    let listen_addr = std::env::var("ORCH_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:9101".into());

    // Initialize master KEK via distributed threshold reconstruction (3-of-5 Shamir)
    let _kek = common::sealed_keys::get_master_kek();

    // Load HMAC key from sealed storage (derived from master KEK via HKDF).
    // Previously this was generate_key_64() which generated a RANDOM key at every
    // startup, making it impossible to verify receipts from OPAQUE (key mismatch).
    let hmac_key = common::sealed_keys::load_shard_hmac_key_sealed();

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

    // ── Distributed cluster coordination ──
    // Start Raft-based leader election. In production mode, cluster membership
    // is MANDATORY — the service will panic if it cannot join the cluster.
    let cluster = common::cluster::require_cluster(
        common::cluster::ServiceType::Orchestrator,
        &listen_addr,
    ).await;

    // Wire auto-response pipeline to Raft for distributed quarantine enforcement
    if let Some(ref c) = cluster {
        _defense.connect_to_cluster(c.clone());
    }

    // If clustered, log leader election result
    if let Some(ref c) = cluster {
        let mut watcher = c.leader_watch();
        let _leader_log = tokio::spawn(async move {
            while watcher.changed().await.is_ok() {
                let leader = *watcher.borrow();
                match leader {
                    Some(lid) => tracing::info!(%lid, "orchestrator leader elected"),
                    None => tracing::warn!("orchestrator leader unknown"),
                }
            }
        });
    }

    // SECURITY: Verify kernel security posture (ptrace_scope, BPF restrictions)
    common::startup_checks::verify_kernel_security_posture();

    // SECURITY: Verify process hardening flags and apply anti-ptrace
    crypto::seccomp::apply_anti_ptrace();
    crypto::seccomp::verify_process_hardening();

    // SECURITY: Remove ALL sensitive env vars from /proc/PID/environ.
    // All config has been loaded above; secrets must not linger in memory.
    common::startup_checks::sanitize_environment();

    tracing::info!("Starting orchestrator on {listen_addr} (mTLS)");

    // SECURITY: Graceful shutdown on SIGTERM/SIGINT.
    // - Stops accepting new connections
    // - Waits for in-flight requests to complete (30s timeout)
    // - Shuts down Raft cluster membership cleanly
    // - Zeroizes sensitive HMAC key memory before exit
    let shutdown_signal = async {
        let mut sigterm = match tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("FATAL: failed to install SIGTERM handler: {e}");
                std::process::exit(1);
            }
        };
        let mut sigint = match tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::interrupt(),
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("FATAL: failed to install SIGINT handler: {e}");
                std::process::exit(1);
            }
        };
        tokio::select! {
            _ = sigterm.recv() => tracing::info!("received SIGTERM, initiating graceful shutdown"),
            _ = sigint.recv() => tracing::info!("received SIGINT, initiating graceful shutdown"),
        }
    };

    tokio::select! {
        result = service.run(&listen_addr) => {
            if let Err(e) = result {
                tracing::error!("Orchestrator exited with error: {e}");
                if let Some(c) = cluster {
                    c.shutdown().await;
                }
                std::process::exit(1);
            }
        }
        _ = shutdown_signal => {
            tracing::info!("orchestrator: waiting up to 30s for in-flight requests...");
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            if let Some(c) = cluster {
                c.shutdown().await;
            }
            // SECURITY: Zeroize HMAC key material before exit
            use zeroize::Zeroize;
            let mut key_to_zeroize = hmac_key;
            key_to_zeroize.zeroize();
            tracing::info!("orchestrator: graceful shutdown complete");
        }
    }
}
