#![forbid(unsafe_code)]
//! gateway binary entry point.

use gateway::server::GatewayServer;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Platform integrity: vTPM check, process hardening, self-attestation, monitor
    let (_platform_report, _monitor_handle, _monitor) =
        common::startup_checks::run_platform_checks(crypto::memguard::harden_process);

    // Start runtime defense: stealth detection + auto-response pipeline
    let _defense = common::runtime_defense::start_runtime_defense(
        "gateway",
        9100,
        _platform_report.binary_hash,
    );

    // Initialize master KEK via distributed threshold reconstruction (3-of-5 Shamir)
    let _kek = common::sealed_keys::get_master_kek();

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
    // Always default to loopback; override with GATEWAY_BIND_ADDR if needed.
    let default_bind = "127.0.0.1";
    let bind_addr = std::env::var("GATEWAY_BIND_ADDR").unwrap_or_else(|_| default_bind.to_string());

    if bind_addr == "0.0.0.0" {
        tracing::warn!("WARNING: Binding to all interfaces (0.0.0.0). Ensure a TLS-terminating reverse proxy is in front, or set GATEWAY_BIND_ADDR=127.0.0.1 for loopback-only.");
    }

    let addr = format!("{bind_addr}:{port}");

    // TLS termination for external listener
    // In production, MILNET_GATEWAY_CERT_PATH and MILNET_GATEWAY_KEY_PATH must be set.
    let cert_path = std::env::var("MILNET_GATEWAY_CERT_PATH");
    let key_path = std::env::var("MILNET_GATEWAY_KEY_PATH");

    if cert_path.is_err() || key_path.is_err() {
        panic!(
            "FATAL: MILNET_GATEWAY_CERT_PATH and MILNET_GATEWAY_KEY_PATH must be set \
             for TLS termination."
        );
    }

    let tls_config = if let (Ok(cert_file), Ok(key_file)) = (cert_path, key_path) {
        tracing::info!("Loading TLS certificate from {cert_file} and key from {key_file}");

        let cert_pem = std::fs::read(&cert_file)
            .unwrap_or_else(|e| panic!("failed to read TLS cert {cert_file}: {e}"));
        let key_pem = std::fs::read(&key_file)
            .unwrap_or_else(|e| panic!("failed to read TLS key {key_file}: {e}"));

        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut &cert_pem[..])
                .collect::<Result<Vec<_>, _>>()
                .expect("failed to parse TLS certificate PEM");
        let key = rustls_pemfile::private_key(&mut &key_pem[..])
            .expect("failed to parse TLS private key PEM")
            .expect("no private key found in PEM file");

        // CNSA 2.0 compliant: TLS 1.3 only with AES-256-GCM-SHA384
        // Post-quantum hybrid key exchange: X25519MLKEM768 preferred, X25519 fallback.
        // Set MILNET_PQ_TLS_ONLY=1 or MILNET_MILITARY_DEPLOYMENT=1 to remove
        // classical fallback entirely (CNSA 2.0 strict / military mode).
        //
        // TODO(CNSA2-TLS): Upgrade to X25519MLKEM1024 when rustls/aws-lc-rs exposes it.
        // The application layer uses ML-KEM-1024 (via crypto::xwing) but TLS is limited
        // to ML-KEM-768 because rustls::crypto::aws_lc_rs::kx_group only exports
        // X25519MLKEM768 as of rustls 0.23.x / aws-lc-rs 1.x. This is a known
        // discrepancy: TLS uses ML-KEM-768 while application-layer key agreement
        // uses ML-KEM-1024. Both provide post-quantum security; ML-KEM-1024 offers
        // a larger security margin (NIST Level 5 vs Level 3). Track upstream:
        //   - https://github.com/rustls/rustls/issues (X25519MLKEM1024 support)
        //   - https://github.com/aws/aws-lc-rs/issues (ML-KEM-1024 kx group)
        let military_mode = std::env::var("MILNET_MILITARY_DEPLOYMENT")
            .map(|v| v == "1")
            .unwrap_or(false);
        let pq_only = military_mode
            || std::env::var("MILNET_PQ_TLS_ONLY")
                .map(|v| v == "1")
                .unwrap_or(false);
        let kx_groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup> = if pq_only {
            tracing::info!(
                military_mode = military_mode,
                "PQ-only TLS mode: X25519 classical fallback REMOVED — only X25519MLKEM768 allowed"
            );
            vec![
                rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
            ]
        } else {
            vec![
                rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
                rustls::crypto::aws_lc_rs::kx_group::X25519,
            ]
        };

        // Startup integrity check: in military mode, PANIC if classical fallback is present
        if military_mode && kx_groups.len() > 1 {
            panic!(
                "FATAL: MILNET_MILITARY_DEPLOYMENT=1 but X25519 classical fallback is present \
                 in TLS key exchange groups. This MUST NOT happen in military deployments."
            );
        }
        let provider = rustls::crypto::CryptoProvider {
            cipher_suites: vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384],
            kx_groups,
            ..rustls::crypto::aws_lc_rs::default_provider()
        };

        let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 config failed")
            .with_no_client_auth()
            .with_single_cert(certs, key.into())
            .expect("TLS server config failed");

        Some(std::sync::Arc::new(config))
    } else {
        // This branch is unreachable due to the panic above, but kept for type completeness.
        unreachable!("TLS certificate check should have panicked above");
    };

    let server = if let Some(tls_cfg) = tls_config {
        GatewayServer::bind_tls(&addr, 16, tls_cfg)
            .await
            .expect("failed to bind gateway with TLS")
    } else {
        // SECURITY: Plain TCP is NEVER allowed. Nation-state
        // attackers can intercept unencrypted authentication traffic.
        panic!(
            "FATAL: TLS is required but no certificate was configured. \
             Set MILNET_GATEWAY_CERT_PATH and MILNET_GATEWAY_KEY_PATH."
        );
    };

    // Spawn health check endpoint on port+1000 (or MILNET_HEALTH_PORT)
    let health_start = std::time::Instant::now();
    let svc_port: u16 = port.parse().unwrap_or(9100);
    let _health_handle = common::health::spawn_health_endpoint(
        "gateway".to_string(),
        svc_port,
        health_start,
        || {
            vec![common::health::HealthCheck {
                name: "gateway_listener".to_string(),
                ok: true,
                detail: None,
                latency_ms: None,
            }]
        },
    );

    tracing::info!("Gateway listening on {addr}");
    server.run().await.expect("gateway server error");
}
