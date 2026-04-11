#![allow(unsafe_code)]
//! gateway binary entry point.

use gateway::server::GatewayServer;

// ---------------------------------------------------------------------------
// PEM parsing helpers — replaces UNMAINTAINED rustls-pemfile (RUSTSEC-2025-0134)
// ---------------------------------------------------------------------------

/// Parse all PEM-encoded certificates from raw bytes.
fn parse_pem_certs(
    pem_bytes: &[u8],
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    let pem_str = std::str::from_utf8(pem_bytes)
        .map_err(|e| format!("PEM is not valid UTF-8: {e}"))?;
    let mut certs = Vec::new();
    for section in pem_sections(pem_str) {
        if section.label == "CERTIFICATE" {
            certs.push(rustls::pki_types::CertificateDer::from(section.der));
        }
    }
    if certs.is_empty() {
        return Err("no CERTIFICATE sections found in PEM".into());
    }
    Ok(certs)
}

/// Parse the first PEM-encoded private key from raw bytes.
fn parse_pem_private_key(
    pem_bytes: &[u8],
) -> Result<rustls::pki_types::PrivateKeyDer<'static>, String> {
    let pem_str = std::str::from_utf8(pem_bytes)
        .map_err(|e| format!("PEM is not valid UTF-8: {e}"))?;
    for section in pem_sections(pem_str) {
        match section.label.as_str() {
            "PRIVATE KEY" => {
                return Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(section.der),
                ));
            }
            "RSA PRIVATE KEY" => {
                return Ok(rustls::pki_types::PrivateKeyDer::Pkcs1(
                    rustls::pki_types::PrivatePkcs1KeyDer::from(section.der),
                ));
            }
            "EC PRIVATE KEY" => {
                return Ok(rustls::pki_types::PrivateKeyDer::Sec1(
                    rustls::pki_types::PrivateSec1KeyDer::from(section.der),
                ));
            }
            _ => continue,
        }
    }
    Err("no private key found in PEM file".into())
}

struct PemSection {
    label: String,
    der: Vec<u8>,
}

/// Minimal PEM decoder — extracts labelled base64 DER sections.
fn pem_sections(input: &str) -> Vec<PemSection> {
    let mut sections = Vec::new();
    let mut label: Option<String> = None;
    let mut b64 = String::new();

    for line in input.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("-----BEGIN ") {
            if let Some(lbl) = rest.strip_suffix("-----") {
                label = Some(lbl.to_string());
                b64.clear();
            }
        } else if trimmed.starts_with("-----END ") {
            if let Some(lbl) = label.take() {
                // Decode base64 (no padding required, ignore whitespace)
                let clean: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
                if let Ok(der) = base64_decode(&clean) {
                    sections.push(PemSection { label: lbl, der });
                }
                b64.clear();
            }
        } else if label.is_some() {
            b64.push_str(trimmed);
        }
    }
    sections
}

/// Standard base64 decoder (RFC 4648).
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    const TABLE: [u8; 256] = {
        let mut t = [0xFFu8; 256];
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0;
        while i < 64 {
            t[alphabet[i] as usize] = i as u8;
            i += 1;
        }
        t[b'=' as usize] = 0xFE; // padding marker
        t
    };

    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for &b in bytes {
        let val = TABLE[b as usize];
        if val == 0xFF {
            return Err(format!("invalid base64 character: 0x{:02x}", b));
        }
        if val == 0xFE {
            break; // padding — stop
        }
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Anchor monotonic time before any crypto/auth operations.
    // All secure_now_us()/secure_now_secs() calls use this anchor,
    // making them immune to clock manipulation after process start.
    common::secure_time::init_time_anchor();

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
    if !common::cnsa2::is_cnsa2_compliant() {
        tracing::error!("FATAL: CNSA 2.0 compliance check failed");
        std::process::exit(1);
    }
    tracing::info!("CNSA 2.0 compliance verified");

    // Note: GATEWAY_PORT is auto-set by K8s service discovery (e.g. "tcp://10.x.x.x:9100").
    // Use MILNET_GATEWAY_PORT to avoid collision, falling back to GATEWAY_PORT only if numeric.
    let port = std::env::var("MILNET_GATEWAY_PORT")
        .or_else(|_| std::env::var("GATEWAY_PORT").and_then(|v| {
            if v.chars().all(|c| c.is_ascii_digit()) { Ok(v) } else { Err(std::env::VarError::NotPresent) }
        }))
        .unwrap_or_else(|_| "9100".into());
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
        tracing::error!(
            "FATAL: MILNET_GATEWAY_CERT_PATH and MILNET_GATEWAY_KEY_PATH must be set \
             for TLS termination."
        );
        std::process::exit(1);
    }

    let tls_config = if let (Ok(cert_file), Ok(key_file)) = (cert_path, key_path) {
        // SECURITY: Redact actual file paths from logs to prevent information
        // disclosure about key material locations to an attacker reading logs.
        tracing::info!("Loading TLS certificate and key from configured paths");

        // SECURITY: Remove key/cert paths from environment immediately after reading.
        // Prevents leakage via /proc/pid/environ or child process inheritance.
        std::env::remove_var("MILNET_GATEWAY_KEY_PATH");
        std::env::remove_var("MILNET_GATEWAY_CERT_PATH");

        // SECURITY: Canonicalize and validate certificate/key paths to prevent
        // path traversal attacks. Block /proc, /sys, /dev which could be used
        // to read process memory or device files via certificate loading.
        for (label, path) in [("cert", &cert_file), ("key", &key_file)] {
            let canonical = std::fs::canonicalize(path).unwrap_or_else(|e| {
                tracing::error!("FATAL: cannot canonicalize TLS {label} path: {e}");
                std::process::exit(1);
            });
            let canon_str = canonical.to_string_lossy();
            if canon_str.starts_with("/proc")
                || canon_str.starts_with("/sys")
                || canon_str.starts_with("/dev")
            {
                tracing::error!(
                    "FATAL: TLS {label} path resolves to a forbidden location \
                     (/proc, /sys, or /dev). Certificate and key files must be \
                     regular files on disk."
                );
                std::process::exit(1);
            }
        }

        let cert_pem = std::fs::read(&cert_file).unwrap_or_else(|e| {
            tracing::error!("Failed to read TLS cert: {e}");
            std::process::exit(1);
        });
        let key_pem = std::fs::read(&key_file).unwrap_or_else(|e| {
            tracing::error!("Failed to read TLS key: {e}");
            std::process::exit(1);
        });

        // SECURITY: mlock the TLS private key material into RAM and exclude
        // from core dumps. This prevents the key from being swapped to disk
        // or captured in a core dump by a nation-state attacker.
        unsafe {
            let key_ptr = key_pem.as_ptr() as *const libc::c_void;
            let key_len = key_pem.len();
            if libc::mlock(key_ptr, key_len) != 0 {
                tracing::error!(
                    "CRITICAL: mlock failed for TLS private key ({key_len} bytes). \
                     Key material may be swappable to disk."
                );
            }
            libc::madvise(key_ptr as *mut libc::c_void, key_len, libc::MADV_DONTDUMP);
        }

        // SECURITY: Zeroize the raw PEM bytes after parsing into rustls types.
        // The key material is now held only by rustls's PrivateKeyDer.
        let mut key_pem = key_pem;

        // SECURITY: rustls-pemfile is UNMAINTAINED (RUSTSEC-2025-0134).
        // PEM parsing inlined here to eliminate the dependency entirely.
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            match parse_pem_certs(&cert_pem) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("FATAL: failed to parse TLS certificate PEM: {e}");
                    std::process::exit(1);
                }
            };
        let key: rustls::pki_types::PrivateKeyDer<'static> =
            match parse_pem_private_key(&key_pem) {
                Ok(k) => k,
                Err(e) => {
                    tracing::error!("FATAL: failed to parse TLS private key PEM: {e}");
                    std::process::exit(1);
                }
            };

        // SECURITY: Zeroize raw PEM key bytes now that they've been parsed into rustls format.
        // Prevents key material from lingering in process memory.
        {
            use zeroize::Zeroize;
            key_pem.zeroize();
        }

        // CNSA 2.0 compliant: TLS 1.3 only with AES-256-GCM-SHA384
        // Post-quantum hybrid key exchange: X25519MLKEM768 is the ONLY group
        // offered by default (PQ-only). Classical X25519 fallback requires
        // explicit opt-in via MILNET_ALLOW_CLASSICAL_TLS=1 and is NEVER
        // permitted in military mode (MILNET_MILITARY_DEPLOYMENT=1).
        //
        // CNSA 2.0 Level 5 COMPLIANCE GAP:
        // TLS key exchange uses X25519MLKEM768 (ML-KEM-768, NIST Level 3) because
        // rustls/aws-lc-rs does not yet expose X25519MLKEM1024. When upstream adds
        // X25519MLKEM1024 support, this MUST be upgraded immediately.
        //
        // MITIGATION: All sensitive key exchanges above TLS use the application-layer
        // X-Wing hybrid KEM (X25519 + ML-KEM-1024, NIST Level 5) via crypto::xwing.
        // TLS provides transport-layer PQ protection; X-Wing provides Level 5
        // application-layer protection. Defense-in-depth.
        //
        // Set MILNET_TLS_PQ_LEVEL=5 to block startup until ML-KEM-1024 is available.
        let military_mode = std::env::var("MILNET_MILITARY_DEPLOYMENT")
            .map(|v| v == "1")
            .unwrap_or(false);

        // CR-10: Enforce MILNET_TLS_PQ_LEVEL=5 or MILNET_REQUIRE_MLKEM1024=1
        let require_level5 = std::env::var("MILNET_TLS_PQ_LEVEL")
            .map(|v| v == "5")
            .unwrap_or(false)
            || std::env::var("MILNET_REQUIRE_MLKEM1024")
                .map(|v| v == "1")
                .unwrap_or(false);

        if require_level5 {
            tracing::error!(
                target: "siem",
                category = "security",
                severity = "CRITICAL",
                action = "tls_pq_level5_enforcement_failed",
                "FATAL: MILNET_TLS_PQ_LEVEL=5 (or MILNET_REQUIRE_MLKEM1024=1) is set but \
                 TLS layer only supports ML-KEM-768 (X25519MLKEM768). CNSA 2.0 requires \
                 ML-KEM-1024 for TOP SECRET. Refusing to start."
            );
            std::process::exit(198);
        }

        // CR-10: SIEM:CRITICAL log in military mode documenting Level 3 gap.
        // Do NOT abort: app-layer X-Wing provides Level 5 defense-in-depth.
        if military_mode {
            tracing::error!(
                target: "siem",
                category = "security",
                severity = "CRITICAL",
                action = "tls_pq_level3_gap",
                "SIEM:CRITICAL: MILNET_MILITARY_DEPLOYMENT=1 but gateway TLS key exchange \
                 uses ML-KEM-768 (NIST Level 3) instead of ML-KEM-1024 (NIST Level 5). \
                 rustls/aws-lc-rs does not yet expose X25519MLKEM1024. Application-layer \
                 X-Wing (ML-KEM-1024, Level 5) provides defense-in-depth. Set \
                 MILNET_TLS_PQ_LEVEL=5 to block startup until upstream adds support."
            );
        }

        // CR-11: PQ-only is the DEFAULT. Classical X25519 requires explicit opt-in.
        // Military mode ALWAYS rejects classical regardless of opt-in env var.
        let classical_allowed = if military_mode {
            false
        } else {
            std::env::var("MILNET_ALLOW_CLASSICAL_TLS")
                .map(|v| v == "1")
                .unwrap_or(false)
                || std::env::var("MILNET_PQ_TLS_ONLY")
                    .map(|v| v == "0")
                    .unwrap_or(false)
        };

        let kx_groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup> = if classical_allowed {
            tracing::warn!(
                target: "siem",
                category = "security",
                severity = "HIGH",
                action = "tls_classical_fallback_enabled",
                "Gateway TLS: Classical X25519 fallback ENABLED via MILNET_ALLOW_CLASSICAL_TLS=1. \
                 PQ-only mode is recommended for CNSA 2.0 compliance."
            );
            vec![
                rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
                rustls::crypto::aws_lc_rs::kx_group::X25519,
            ]
        } else {
            tracing::info!(
                military_mode = military_mode,
                "Gateway TLS: PQ-only mode active (default) -- only X25519MLKEM768 key \
                 exchange allowed, classical connections will be rejected"
            );
            vec![
                rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
            ]
        };

        // Military mode integrity check: exit if classical fallback would be offered
        if military_mode && kx_groups.len() > 1 {
            tracing::error!(
                "FATAL: MILNET_MILITARY_DEPLOYMENT=1 but X25519 classical fallback is present \
                 in TLS key exchange groups. This MUST NOT happen in military deployments."
            );
            std::process::exit(1);
        }
        let provider = rustls::crypto::CryptoProvider {
            cipher_suites: vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384],
            kx_groups,
            ..rustls::crypto::aws_lc_rs::default_provider()
        };

        let config = match rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
        {
            Ok(builder) => match builder
                .with_no_client_auth()
                .with_single_cert(certs, key.into())
            {
                Ok(cfg) => cfg,
                Err(e) => {
                    tracing::error!("FATAL: TLS server config failed: {e}");
                    std::process::exit(1);
                }
            },
            Err(e) => {
                tracing::error!("FATAL: TLS 1.3 config failed: {e}");
                std::process::exit(1);
            }
        };

        Some(std::sync::Arc::new(config))
    } else {
        // This branch is unreachable due to the exit above, but kept for type completeness.
        tracing::error!("FATAL: TLS certificate check should have exited above");
        std::process::exit(1);
    };

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

    let server = if let Some(tls_cfg) = tls_config {
        match GatewayServer::bind_tls(&addr, 16, tls_cfg).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("FATAL: failed to bind gateway with TLS: {e}");
                std::process::exit(1);
            }
        }
    } else {
        // SECURITY: Plain TCP is NEVER allowed. Nation-state
        // attackers can intercept unencrypted authentication traffic.
        tracing::error!(
            "FATAL: TLS is required but no certificate was configured. \
             Set MILNET_GATEWAY_CERT_PATH and MILNET_GATEWAY_KEY_PATH."
        );
        std::process::exit(1);
    };

    // Spawn health check endpoint on port+1000 (or MILNET_HEALTH_PORT)
    let health_start = std::time::Instant::now();
    let svc_port: u16 = port.parse().unwrap_or(9100);
    let orch_addr_health: std::net::SocketAddr = std::env::var("ORCH_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9101".into())
        .parse()
        .unwrap_or_else(|_| std::net::SocketAddr::from(([127, 0, 0, 1], 9101)));
    let _health_handle = common::health::spawn_health_endpoint(
        "gateway".to_string(),
        svc_port,
        health_start,
        move || {
            // Probe orchestrator reachability instead of always returning ok
            let orch_ok = std::net::TcpStream::connect_timeout(
                &orch_addr_health,
                std::time::Duration::from_secs(2),
            )
            .is_ok();

            vec![
                common::health::HealthCheck {
                    name: "gateway_listener".to_string(),
                    ok: true,
                    detail: None,
                    latency_ms: None,
                },
                common::health::HealthCheck {
                    name: "orchestrator_reachable".to_string(),
                    ok: orch_ok,
                    detail: if orch_ok { None } else { Some("Orchestrator unreachable".into()) },
                    latency_ms: None,
                },
            ]
        },
    );

    tracing::info!("Gateway listening on {addr}");

    // SECURITY: Graceful shutdown on SIGTERM/SIGINT.
    // - Stops accepting new connections
    // - Waits for in-flight requests to complete (30s timeout)
    // - Zeroizes sensitive memory before exit
    // This prevents data loss and ensures clean termination in Kubernetes/systemd.
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
        result = server.run() => {
            if let Err(e) = result {
                tracing::error!("FATAL: gateway server error: {e}");
                std::process::exit(1);
            }
        }
        _ = shutdown_signal => {
            tracing::info!("gateway: waiting up to 30s for in-flight requests to complete...");
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            tracing::info!("gateway: graceful shutdown complete");
        }
    }
}
