#![forbid(unsafe_code)]
//! opaque: T-OPAQUE Password Service.
//!
//! SECURITY: This service is the SOLE holder of the receipt signing key.
//! The key is generated (or loaded from HSM) inside `opaque::service::run()`
//! and never leaves this process.
//!
//! Supports two modes:
//! - **single** (default): single-server OPAQUE.
//! - **threshold**: 2-of-3 distributed OPAQUE — **NOT production-ready**.
//!   The threshold OPRF combiner and the cross-server key ceremony are not
//!   correctly implemented (a 2026-04-30 audit found the XOR-of-HMACs combiner
//!   is not a Shamir-based PRF, and no orchestrator drives the protocol
//!   end-to-end). Threshold mode therefore refuses to start; see
//!   `run_threshold_mode` and `opaque::threshold` for the full rationale.

use opaque::store::CredentialStore;

#[tokio::main]
async fn main() {
    // MUST be first: harden process before any allocation that could hold a secret.
    crypto::process_harden::harden_early();
    // Structured logging init
    tracing_subscriber::fmt::init();

    // Anchor monotonic time before any crypto/auth operations.
    common::secure_time::init_time_anchor();

    // Platform integrity: vTPM check, process hardening, self-attestation, monitor
    let (_platform_report, _monitor_handle, _monitor) =
        common::startup_checks::run_platform_checks(crypto::memguard::harden_process);

    // Start runtime defense: stealth detection + auto-response pipeline
    let _defense = common::runtime_defense::start_runtime_defense(
        "opaque",
        9102,
        _platform_report.binary_hash,
    );

    // Initialize master KEK via distributed threshold reconstruction (3-of-5 Shamir)
    let _kek = common::sealed_keys::get_master_kek();

    // STIG compliance audit (best-effort — log warnings, do not block startup)
    match common::startup_checks::run_stig_audit() {
        Ok(summary) => tracing::info!("STIG audit passed: {:?}", summary),
        Err(failures) => tracing::warn!("STIG audit had {} failures", failures.len()),
    }

    // Default is single-server OPAQUE. Threshold mode is gated off (see
    // run_threshold_mode) until the distributed OPRF construction is correct.
    let opaque_mode = std::env::var("MILNET_OPAQUE_MODE")
        .unwrap_or_else(|_| "single".to_string());

    // Spawn health check endpoint
    let health_start = std::time::Instant::now();
    let _health_handle = common::health::spawn_health_endpoint(
        "opaque".to_string(),
        9102,
        health_start,
        || {
            vec![common::health::HealthCheck {
                name: "opaque_service".to_string(),
                ok: true,
                detail: None,
                latency_ms: None,
            }]
        },
    );

    // ── Distributed cluster coordination ──
    // In production mode, cluster membership is MANDATORY — panics if unavailable.
    let opaque_addr = std::env::var("MILNET_OPAQUE_ADDR").unwrap_or_else(|_| "127.0.0.1:9102".into());
    let _cluster = common::cluster::require_cluster(
        common::cluster::ServiceType::Opaque,
        &opaque_addr,
    ).await;

    // Log leader elections
    if let Some(ref node) = _cluster {
        let mut watcher = node.leader_watch();
        tokio::spawn(async move {
            while watcher.changed().await.is_ok() {
                if let Some(lid) = *watcher.borrow() {
                    tracing::info!(%lid, "OPAQUE leader elected — this node coordinates threshold fan-out");
                }
            }
        });
    }

    // Wire auto-response pipeline to Raft for distributed quarantine enforcement
    if let Some(ref c) = _cluster {
        _defense.connect_to_cluster(c.clone());
    }

    // SECURITY: Remove ALL sensitive env vars from /proc/PID/environ IMMEDIATELY
    // after the last env var read. Secrets must not linger in the process environment
    // any longer than necessary to prevent leakage via /proc/PID/environ or
    // child process inheritance.
    common::startup_checks::sanitize_environment();

    // SECURITY: Verify kernel security posture (ptrace_scope, BPF restrictions)
    common::startup_checks::verify_kernel_security_posture();

    // SECURITY: Verify process hardening flags and apply anti-ptrace
    crypto::seccomp::apply_anti_ptrace();
    crypto::seccomp::verify_process_hardening();

    // SECURITY: Graceful shutdown on SIGTERM/SIGINT.
    // - Stops accepting new OPAQUE protocol requests
    // - Waits for in-flight requests to complete (30s timeout)
    // - Shuts down Raft cluster membership cleanly
    // - Zeroizes OPRF key shares before exit
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

    let service_future = async {
        let result = match opaque_mode.as_str() {
            "threshold" => run_threshold_mode().await,
            "single" => {
                tracing::warn!("Running in SINGLE-SERVER mode (dev/test only — NOT for production)");
                let store = CredentialStore::new();
                opaque::service::run(store).await
            }
            other => {
                eprintln!("Unknown MILNET_OPAQUE_MODE: '{other}' (expected 'threshold' or 'single')");
                std::process::exit(1);
            }
        };

        if let Err(e) = result {
            eprintln!("OPAQUE service error: {e}");
            std::process::exit(1);
        }
    };

    tokio::select! {
        _ = service_future => {}
        _ = shutdown_signal => {
            tracing::info!("opaque: waiting up to 30s for in-flight OPAQUE requests...");
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            if let Some(c) = _cluster {
                c.shutdown().await;
            }
            tracing::info!("opaque: graceful shutdown complete");
        }
    }
}

/// Threshold mode (2-of-3 distributed OPAQUE) — **disabled, fail-closed**.
///
/// # Why this refuses to start
///
/// A 2026-04-30 security audit found threshold OPAQUE non-functional and
/// cryptographically unsound as shipped:
///
/// * `opaque::threshold::combine_evaluations_for_input` XORs independent
///   `HMAC(share_i, input)` values. That is **not** a Shamir-based threshold
///   PRF — different server subsets produce different "OPRF outputs", so a
///   user who registered with servers {1,2} cannot log in via {2,3}.
/// * Each of the 3 server processes here independently called
///   `generate_threshold_oprf_key(2,3)`, producing **three unrelated master
///   keys**. There is no key ceremony distributing one coherent split.
/// * No orchestrator consumes `OpaqueResponse::ThresholdPartialEval`, so the
///   2-round threshold protocol is never actually driven end-to-end.
///
/// A correct fix requires a real distributed OPRF (e.g. a DH-OPRF with
/// Lagrange-in-the-exponent over ristretto255) plus a key-distribution
/// ceremony and an orchestrator — a multi-component subsystem that is out of
/// scope for the current hardening pass. Per the project security posture
/// ("fail closed, security wins"), threshold mode refuses to start rather
/// than authenticate users against a broken construction. Run single-server
/// mode (the default) until distributed OPAQUE is correctly implemented.
async fn run_threshold_mode() -> Result<(), Box<dyn std::error::Error>> {
    tracing::error!(
        target: "siem",
        category = "security",
        severity = "CRITICAL",
        action = "opaque_threshold_mode_disabled",
        "FATAL: MILNET_OPAQUE_MODE=threshold is disabled. The distributed \
         OPRF construction was found unsound and non-functional end-to-end \
         (2026-04-30 audit) and has not yet been correctly reimplemented. \
         Refusing to start. Use MILNET_OPAQUE_MODE=single."
    );
    Err("threshold OPAQUE mode is disabled (fail-closed): the distributed \
         OPRF construction is not production-ready — use single mode"
        .into())
}
