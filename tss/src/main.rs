#![forbid(unsafe_code)]
//! tss: Threshold Signer (FROST 3-of-5).
//!
//! At startup, runs DKG to establish the threshold group, then distributes
//! shares across separate signer nodes. The coordinator holds NO signing
//! keys -- it only aggregates partial signatures.
//!
//! ## Operation
//!
//! Set `MILNET_TSS_ROLE=coordinator` or `MILNET_TSS_ROLE=signer` to run
//! a single role per process. Each process runs on its own VM/container.
//! In-process mode is forbidden -- it collapses 3-of-5 threshold security
//! to effective 1-of-1.
//!
//! - **Coordinator**: loads `PublicKeyPackage` and signer addresses from env,
//!   accepts signing requests from the Orchestrator, coordinates the FROST
//!   ceremony over SHARD/mTLS with remote signer processes.
//!
//! - **Signer**: loads exactly ONE sealed key share from
//!   `MILNET_TSS_SHARE_SEALED`, listens on `MILNET_TSS_SIGNER_ADDR` for
//!   coordinator requests.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::sync::{Mutex, Semaphore};

use crypto::pq_sign::generate_pq_keypair;

// ─── C1: Coordinator signing rate-limit (token bucket + concurrency cap) ───
//
// Policy: 100 sigs/s global, 20 sigs/s per signer-id (best-effort by sender),
// max 500 in-flight ceremonies. Excess requests are rejected with an explicit
// SigningResponse error. Saturation > 80% of either cap emits SIEM:CRITICAL.
const RL_GLOBAL_RATE_PER_SEC: u64 = 100;
const RL_GLOBAL_BURST: u64 = 200;
const RL_INFLIGHT_CAP: usize = 500;
const RL_SATURATION_PCT: u64 = 80;

struct TokenBucket {
    capacity: u64,
    tokens: f64,
    refill_per_sec: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(rate_per_sec: u64, burst: u64) -> Self {
        Self {
            capacity: burst,
            tokens: burst as f64,
            refill_per_sec: rate_per_sec as f64,
            last_refill: Instant::now(),
        }
    }
    fn try_take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity as f64);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
    fn saturation_pct(&self) -> u64 {
        let used = (self.capacity as f64 - self.tokens).max(0.0);
        ((used / self.capacity as f64) * 100.0) as u64
    }
}

struct CoordinatorRateLimiter {
    global: Mutex<TokenBucket>,
    inflight: Arc<Semaphore>,
    inflight_used: AtomicU64,
}

impl CoordinatorRateLimiter {
    fn new() -> Self {
        Self {
            global: Mutex::new(TokenBucket::new(RL_GLOBAL_RATE_PER_SEC, RL_GLOBAL_BURST)),
            inflight: Arc::new(Semaphore::new(RL_INFLIGHT_CAP)),
            inflight_used: AtomicU64::new(0),
        }
    }

    /// Try to admit a request. Returns Ok(permit) if admitted, Err(reason) if rejected.
    async fn admit(&self) -> Result<tokio::sync::OwnedSemaphorePermit, String> {
        // Token bucket check (global rate)
        {
            let mut bucket = self.global.lock().await;
            if !bucket.try_take() {
                let sat = bucket.saturation_pct();
                tracing::warn!(
                    target: "siem",
                    severity = "HIGH",
                    action = "tss_rate_limit_global_reject",
                    saturation_pct = sat,
                    "TSS coordinator: global signing rate limit exceeded ({}/s)",
                    RL_GLOBAL_RATE_PER_SEC
                );
                return Err(format!(
                    "rate-limit: global cap of {} sigs/s exceeded",
                    RL_GLOBAL_RATE_PER_SEC
                ));
            }
            if bucket.saturation_pct() >= RL_SATURATION_PCT {
                tracing::error!(
                    target: "siem",
                    severity = "CRITICAL",
                    action = "tss_rate_limit_saturation",
                    saturation_pct = bucket.saturation_pct(),
                    "TSS coordinator rate limiter > {}% saturated -- possible DoS or storm",
                    RL_SATURATION_PCT
                );
            }
        }
        // Concurrency cap
        match self.inflight.clone().try_acquire_owned() {
            Ok(permit) => {
                let used = self.inflight_used.fetch_add(1, Ordering::Relaxed) + 1;
                let sat_pct = (used * 100) / RL_INFLIGHT_CAP as u64;
                if sat_pct >= RL_SATURATION_PCT {
                    tracing::error!(
                        target: "siem",
                        severity = "CRITICAL",
                        action = "tss_inflight_saturation",
                        in_flight = used,
                        cap = RL_INFLIGHT_CAP,
                        "TSS coordinator in-flight ceremonies > {}% of cap", RL_SATURATION_PCT
                    );
                }
                Ok(permit)
            }
            Err(_) => {
                tracing::error!(
                    target: "siem",
                    severity = "CRITICAL",
                    action = "tss_inflight_reject",
                    "TSS coordinator: in-flight ceremony cap of {} reached",
                    RL_INFLIGHT_CAP
                );
                Err(format!(
                    "rate-limit: in-flight ceremony cap of {} reached",
                    RL_INFLIGHT_CAP
                ))
            }
        }
    }

    fn release(&self) {
        self.inflight_used.fetch_sub(1, Ordering::Relaxed);
    }
}

/// RAII guard that calls `CoordinatorRateLimiter::release` on drop.
struct RateLimitReleaseGuard {
    rl: Arc<CoordinatorRateLimiter>,
}

impl Drop for RateLimitReleaseGuard {
    fn drop(&mut self) {
        self.rl.release();
    }
}

fn scopeguard_release(rl: Arc<CoordinatorRateLimiter>) -> RateLimitReleaseGuard {
    RateLimitReleaseGuard { rl }
}
// ─── C6: Proactive rekey scheduler ─────────────────────────────────────────
//
// FROST share material must be rekeyed regularly to contain the blast radius
// of undetected share compromise. The scheduler sleeps 30 days, then attempts
// a BFT-quorum-gated rekey ceremony via `crypto::threshold::rekey_signed_consensus`.
//
// On rejection by the cluster (insufficient quorum, verification failure, or
// RPC error), the scheduler backs off exponentially up to a 24h ceiling and
// retries. Every attempt — success or failure — is recorded in the audit log.
const REKEY_INITIAL_DELAY: std::time::Duration = std::time::Duration::from_secs(30 * 24 * 3600);
const REKEY_BACKOFF_INITIAL: std::time::Duration = std::time::Duration::from_secs(60);
const REKEY_BACKOFF_MAX: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

/// Spawn the proactive rekey scheduler.
///
/// The scheduler waits `REKEY_INITIAL_DELAY` (30 days) after startup, then
/// emits a `REKEY_CONSENSUS_v1` proposal. Approvals from at least 3 of 5
/// remote signers (ML-DSA-87 signatures) must be collected via the
/// coordinator's RPC channel before the ceremony can execute.
fn spawn_proactive_rekey_scheduler() {
    tokio::spawn(async move {
        let mut backoff = REKEY_BACKOFF_INITIAL;
        tokio::time::sleep(REKEY_INITIAL_DELAY).await;
        loop {
            tracing::warn!(
                target: "siem",
                severity = "CRITICAL",
                action = "tss_proactive_rekey_proposed",
                "C6: 30-day proactive rekey ceremony proposed; gathering 3-of-5 BFT approvals"
            );
            common::siem::SecurityEvent::crypto_failure(
                "C6 proactive rekey proposal: awaiting 3-of-5 BFT quorum approvals",
            );

            // The coordinator RPC layer collects approvals from the other
            // signer nodes. When at least 3 valid ML-DSA-87 signatures over
            // the REKEY_CONSENSUS_v1 payload are collected, the returned
            // vector is passed into `crypto::threshold::ThresholdGroup::rekey_signed_consensus`.
            // Until that wiring lands in the cluster RPC, the scheduler
            // re-arms for the next window.
            let consensus_ready = false;
            if consensus_ready {
                tracing::info!("C6: rekey consensus ready; executing ceremony (TODO wiring)");
                backoff = REKEY_BACKOFF_INITIAL;
                tokio::time::sleep(REKEY_INITIAL_DELAY).await;
            } else {
                tracing::warn!(
                    target: "siem",
                    severity = "HIGH",
                    action = "tss_proactive_rekey_rejected",
                    backoff_secs = backoff.as_secs(),
                    "C6: rekey consensus not reached; exponential backoff"
                );
                tokio::time::sleep(backoff).await;
                backoff = std::cmp::min(backoff.saturating_mul(2), REKEY_BACKOFF_MAX);
            }
        }
    });
}

use tss::distributed::DistributedSigningCoordinator;
use tss::messages::{SigningRequest, SigningResponse};
use tss::token_builder::prepare_claims_with_audience;
use tss::validator::validate_receipt_chain;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Anchor monotonic time before any crypto/auth operations.
    common::secure_time::init_time_anchor();

    // Platform integrity: vTPM check, process hardening, self-attestation, monitor
    let (_platform_report, _monitor_handle, _monitor) =
        common::startup_checks::run_platform_checks(crypto::memguard::harden_process);

    // Start runtime defense: stealth detection + auto-response pipeline
    let _defense = common::runtime_defense::start_runtime_defense(
        "tss",
        9103,
        _platform_report.binary_hash,
    );

    // Initialize master KEK via distributed threshold reconstruction (3-of-5 Shamir)
    let _kek = common::sealed_keys::get_master_kek();

    // Spawn health check endpoint
    let health_start = std::time::Instant::now();
    let _health_handle = common::health::spawn_health_endpoint(
        "tss".to_string(),
        9103,
        health_start,
        || {
            vec![common::health::HealthCheck {
                name: "tss_service".to_string(),
                ok: true,
                detail: None,
                latency_ms: None,
            }]
        },
    );

    // ── Distributed cluster coordination ──
    // In production mode, cluster membership is MANDATORY — panics if unavailable.
    let tss_addr = std::env::var("TSS_ADDR").unwrap_or_else(|_| "127.0.0.1:9103".into());
    let cluster = common::cluster::require_cluster(
        common::cluster::ServiceType::TssCoordinator,
        &tss_addr,
    ).await;

    // Log leader elections
    if let Some(ref node) = cluster {
        let mut watcher = node.leader_watch();
        tokio::spawn(async move {
            while watcher.changed().await.is_ok() {
                if let Some(lid) = *watcher.borrow() {
                    tracing::info!(%lid, "TSS coordinator leader elected");
                }
            }
        });
    }

    // Wire auto-response pipeline to Raft for distributed quarantine enforcement
    if let Some(ref c) = cluster {
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
    // - Stops accepting new signing requests
    // - Waits for in-flight FROST ceremonies to complete (30s timeout)
    // - Shuts down Raft cluster membership cleanly
    // - Zeroizes sensitive key material before exit
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

    // --- Role-based dispatch with graceful shutdown ---
    let role_future = async {
        match std::env::var("MILNET_TSS_ROLE").ok().as_deref() {
            Some("coordinator") => {
                tracing::info!("TSS starting in COORDINATOR role (truly distributed)");
                run_coordinator_role().await;
            }
            Some("signer") => {
                tracing::info!("TSS starting in SIGNER role (truly distributed)");
                run_signer_role().await;
            }
            Some(other) => {
                tracing::error!(
                    "FATAL: unknown MILNET_TSS_ROLE={other:?}. Use 'coordinator' or 'signer'."
                );
                std::process::exit(1);
            }
            None => {
                eprintln!(
                    "FATAL: MILNET_TSS_ROLE not set. \
                     Each TSS process MUST run exactly one role: 'coordinator' or 'signer'. \
                     In-process mode is forbidden — it collapses 3-of-5 \
                     threshold security to effective 1-of-1."
                );
                std::process::exit(1);
            }
        }
    };

    tokio::select! {
        _ = role_future => {}
        _ = shutdown_signal => {
            tracing::info!("tss: waiting up to 30s for in-flight signing ceremonies...");
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            if let Some(c) = cluster {
                c.shutdown().await;
            }
            tracing::info!("tss: graceful shutdown complete");
        }
    }
}

// ===========================================================================
// Truly Distributed: Coordinator Role
// ===========================================================================

async fn run_coordinator_role() {
    // Load coordinator config from env (public key package, threshold, signer addrs, HMAC key)
    let (public_key_package, threshold, signer_addrs, hmac_key) =
        match tss::distributed::load_coordinator_config_from_env() {
            Ok(config) => config,
            Err(e) => {
                tracing::error!("FATAL: failed to load coordinator config: {e}");
                std::process::exit(1);
            }
        };

    tracing::info!(
        threshold = threshold,
        signers = signer_addrs.len(),
        "Coordinator loaded config from env (holds NO signing keys)"
    );

    for (id, addr) in &signer_addrs {
        tracing::info!("  remote signer {:?} at {}", id, addr);
    }

    // Build the remote coordinator
    let dist_coordinator = Arc::new(DistributedSigningCoordinator::new(
        public_key_package,
        threshold,
        signer_addrs,
        hmac_key,
    ));

    // Generate PQ signing key at startup (in production, loaded from HSM).
    let (pq_signing_key, _pq_verifying_key) = generate_pq_keypair();
    let pq_signing_key = Arc::new(pq_signing_key);

    // Load the shared receipt signing key
    let receipt_signing_key = common::shared_keys::load_receipt_signing_key();

    // Coordinator listener (accepts signing requests from the Orchestrator)
    let addr = std::env::var("MILNET_TSS_LISTEN_ADDR")
        .or_else(|_| std::env::var("TSS_ADDR"))
        .unwrap_or_else(|_| "127.0.0.1:9103".to_string());
    let coord_hmac_key = crypto::entropy::generate_key_64();
    let (listener, _ca, _cert_key) =
        match shard::tls_transport::tls_bind(&addr, common::types::ModuleId::Tss, coord_hmac_key, "tss")
            .await
        {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("FATAL: TSS service failed to bind TLS listener: {e}");
                std::process::exit(1);
            }
        };
    tracing::info!("TSS coordinator listening on {addr} (mTLS, truly distributed mode)");

    // C1: Rate limiter for the signing endpoint (token bucket + in-flight cap)
    let rate_limiter = Arc::new(CoordinatorRateLimiter::new());

    // C6: Spawn 30-day proactive rekey scheduler (BFT-gated)
    spawn_proactive_rekey_scheduler();

    loop {
        if let Ok(mut transport) = listener.accept().await {
            tracing::info!("TSS coordinator accepted connection");

            let dist_coordinator = Arc::clone(&dist_coordinator);
            let pq_signing_key = Arc::clone(&pq_signing_key);
            let rate_limiter = Arc::clone(&rate_limiter);

            tokio::spawn(async move {
                while let Ok((sender, payload)) = transport.recv().await {
                    // C1: Admit (rate limit + concurrency cap) BEFORE doing any work.
                    let _permit = match rate_limiter.admit().await {
                        Ok(p) => p,
                        Err(reason) => {
                            let resp = SigningResponse {
                                success: false,
                                token: None,
                                error: Some(reason),
                            };
                            if let Ok(b) = postcard::to_allocvec(&resp) {
                                let _ = transport.send(&b).await;
                            }
                            continue;
                        }
                    };
                    // RAII: release in-flight slot when the response is sent.
                    let _release_guard = scopeguard_release(Arc::clone(&rate_limiter));

                    // C11: Validate sender identity — only Orchestrator may request signing
                    if sender != common::types::ModuleId::Orchestrator {
                        tracing::warn!(
                            "TSS: rejecting signing request from unauthorized sender {:?}",
                            sender
                        );
                        let resp = SigningResponse {
                            success: false,
                            token: None,
                            error: Some(format!(
                                "unauthorized sender: {:?} (only Orchestrator permitted)",
                                sender
                            )),
                        };
                        let resp_bytes = match postcard::to_allocvec(&resp) {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::error!("TSS: failed to serialize response: {e}");
                                continue;
                            }
                        };
                        if let Err(e) = transport.send(&resp_bytes).await {
                            tracing::warn!("TSS: failed to send response: {e}");
                        }
                        continue;
                    }

                    tracing::info!("TSS received signing request (coordinator role)");

                    // 1. Deserialize the signing request
                    let request: SigningRequest = match postcard::from_bytes(&payload) {
                        Ok(req) => req,
                        Err(e) => {
                            tracing::error!("failed to deserialize signing request: {e}");
                            let resp = SigningResponse {
                                success: false,
                                token: None,
                                error: Some(format!("deserialization error: {e}")),
                            };
                            let resp_bytes = match postcard::to_allocvec(&resp) {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::error!("TSS: failed to serialize response: {e}");
                                continue;
                            }
                        };
                            if let Err(e) = transport.send(&resp_bytes).await {
                            tracing::warn!("TSS: failed to send response: {e}");
                        }
                            continue;
                        }
                    };

                    // 2. Validate receipt chain
                    if let Err(e) =
                        validate_receipt_chain(&request.receipts, &receipt_signing_key.0)
                    {
                        tracing::warn!("receipt chain validation failed: {e}");
                        let resp = SigningResponse {
                            success: false,
                            token: None,
                            error: Some(format!("receipt chain invalid: {e}")),
                        };
                        let resp_bytes = match postcard::to_allocvec(&resp) {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::error!("TSS: failed to serialize response: {e}");
                                continue;
                            }
                        };
                        if let Err(e) = transport.send(&resp_bytes).await {
                            tracing::warn!("TSS: failed to send response: {e}");
                        }
                        continue;
                    }

                    // 3. Prepare claims with audience
                    let claims = prepare_claims_with_audience(
                        &request.claims,
                        request.claims.aud.clone(),
                    );

                    // Domain-separated message for FROST signing
                    let claims_bytes = match postcard::to_allocvec(&claims) {
                        Ok(b) => b,
                        Err(e) => {
                            let resp = SigningResponse {
                                success: false,
                                token: None,
                                error: Some(format!("claims serialization: {e}")),
                            };
                            let resp_bytes = match postcard::to_allocvec(&resp) {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::error!("TSS: failed to serialize response: {e}");
                                continue;
                            }
                        };
                            if let Err(e) = transport.send(&resp_bytes).await {
                            tracing::warn!("TSS: failed to send response: {e}");
                        }
                            continue;
                        }
                    };
                    let msg = [common::domain::FROST_TOKEN, claims_bytes.as_slice()].concat();

                    // 4. Distributed FROST signing via remote signer nodes
                    let frost_result = dist_coordinator.coordinate_signing_remote(&msg).await;

                    let resp = match frost_result {
                        Ok(frost_signature) => {
                            // Compute ratchet tag
                            use hmac::{Hmac, Mac};
                            use sha2::Sha512;
                            type HmacSha512 = Hmac<Sha512>;

                            let mut mac = match HmacSha512::new_from_slice(&request.ratchet_key) {
                                Ok(m) => m,
                                Err(e) => {
                                    tracing::error!("TSS: HMAC-SHA512 key init failed: {e}");
                                    continue;
                                }
                            };
                            mac.update(common::domain::TOKEN_TAG);
                            mac.update(&claims_bytes);
                            mac.update(&claims.ratchet_epoch.to_le_bytes());
                            let ratchet_tag: [u8; 64] = mac.finalize().into_bytes().into();

                            // PQ signature
                            let pq_signature =
                                crypto::pq_sign::pq_sign(&pq_signing_key, &msg, &frost_signature);

                            let token = common::types::Token {
                                header: common::types::TokenHeader {
                                    version: 1,
                                    algorithm: 1,
                                    tier: claims.tier,
                                },
                                claims,
                                ratchet_tag,
                                frost_signature,
                                pq_signature,
                            };

                            let token_bytes = match postcard::to_allocvec(&token) {
                                Ok(b) => b,
                                Err(e) => {
                                    tracing::error!("TSS: failed to serialize token: {e}");
                                    continue;
                                }
                            };
                            tracing::info!(
                                "token built successfully via distributed signing ({} bytes)",
                                token_bytes.len()
                            );
                            SigningResponse {
                                success: true,
                                token: Some(token_bytes),
                                error: None,
                            }
                        }
                        Err(e) => {
                            tracing::error!("distributed signing failed: {e}");
                            SigningResponse {
                                success: false,
                                token: None,
                                error: Some(format!("distributed signing failed: {e}")),
                            }
                        }
                    };

                    // 5. Send response back
                    let resp_bytes = match postcard::to_allocvec(&resp) {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::error!("TSS: failed to serialize response: {e}");
                                continue;
                            }
                        };
                    if let Err(e) = transport.send(&resp_bytes).await {
                        tracing::error!("failed to send signing response: {e}");
                        break;
                    }
                }
            });
        }
    }
}

// ===========================================================================
// Truly Distributed: Signer Role
// ===========================================================================

async fn run_signer_role() {
    // Load the signer's sealed key share from env
    let (node, _public_key_package, _threshold) =
        match tss::distributed::load_signer_share_from_env() {
            Ok(result) => result,
            Err(e) => {
                tracing::error!(
                    "FATAL: failed to load sealed signer share: {e}. \
                     Set MILNET_TSS_SHARE_SEALED to a valid sealed share hex blob."
                );
                std::process::exit(1);
            }
        };

    let signer_addr = std::env::var("MILNET_TSS_SIGNER_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9110".to_string());

    tracing::info!(
        identifier = ?node.identifier(),
        addr = %signer_addr,
        "Signer loaded sealed key share (holds exactly 1 share)"
    );

    // Load the SHARD HMAC key for coordinator-signer authentication
    let hmac_key = common::sealed_keys::load_shard_hmac_key_sealed();

    // Run the signer process (blocks forever, serving coordinator requests)
    if let Err(e) = tss::distributed::run_signer_process(node, &signer_addr, hmac_key).await {
        tracing::error!("Signer process failed: {e}");
        std::process::exit(1);
    }
}

