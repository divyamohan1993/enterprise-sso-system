//! Service health checking with liveness probes and peer monitoring.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Health status of a service
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

/// Tracks health of peer services
pub struct HealthMonitor {
    peers: Mutex<HashMap<String, PeerHealth>>,
    _check_interval: Duration,
    unhealthy_threshold: Duration,
    degraded_threshold: Duration,
}

struct PeerHealth {
    last_seen: Instant,
    consecutive_failures: u32,
    status: HealthStatus,
    avg_response_ms: f64,
    response_count: u64,
}

impl HealthMonitor {
    pub fn new() -> Self {
        Self {
            peers: Mutex::new(HashMap::new()),
            _check_interval: Duration::from_secs(10),
            unhealthy_threshold: Duration::from_secs(30),
            degraded_threshold: Duration::from_secs(15),
        }
    }

    /// Record a successful interaction with a peer
    pub fn record_success(&self, peer: &str, response_time_ms: f64) {
        let mut peers = crate::sync::siem_lock(&self.peers, "health::record_success");
        let health = peers.entry(peer.to_string()).or_insert_with(|| PeerHealth {
            last_seen: Instant::now(),
            consecutive_failures: 0,
            status: HealthStatus::Healthy,
            avg_response_ms: 0.0,
            response_count: 0,
        });
        health.last_seen = Instant::now();
        health.consecutive_failures = 0;
        health.response_count += 1;
        // Exponential moving average
        let alpha = 0.3;
        health.avg_response_ms = alpha * response_time_ms + (1.0 - alpha) * health.avg_response_ms;
        health.status = HealthStatus::Healthy;
    }

    /// Record a failed interaction with a peer
    pub fn record_failure(&self, peer: &str) {
        let mut peers = crate::sync::siem_lock(&self.peers, "health::record_failure");
        let health = peers.entry(peer.to_string()).or_insert_with(|| PeerHealth {
            last_seen: Instant::now(),
            consecutive_failures: 0,
            status: HealthStatus::Unknown,
            avg_response_ms: 0.0,
            response_count: 0,
        });
        health.consecutive_failures += 1;
        if health.consecutive_failures >= 3 {
            health.status = HealthStatus::Unhealthy;
        } else {
            health.status = HealthStatus::Degraded;
        }
    }

    /// Get current health status of a peer
    pub fn peer_status(&self, peer: &str) -> HealthStatus {
        let peers = crate::sync::siem_lock(&self.peers, "health::peer_status");
        match peers.get(peer) {
            Some(health) => {
                let elapsed = health.last_seen.elapsed();
                if elapsed > self.unhealthy_threshold {
                    HealthStatus::Unhealthy
                } else if elapsed > self.degraded_threshold {
                    HealthStatus::Degraded
                } else {
                    health.status
                }
            }
            None => HealthStatus::Unknown,
        }
    }

    /// Get summary of all peers
    pub fn all_statuses(&self) -> HashMap<String, HealthStatus> {
        let peers = crate::sync::siem_lock(&self.peers, "health::all_statuses");
        peers.iter().map(|(k, v)| {
            let elapsed = v.last_seen.elapsed();
            let status = if elapsed > self.unhealthy_threshold {
                HealthStatus::Unhealthy
            } else if elapsed > self.degraded_threshold {
                HealthStatus::Degraded
            } else {
                v.status
            };
            (k.clone(), status)
        }).collect()
    }

    /// Check if enough peers are healthy for the system to operate
    pub fn has_quorum(&self, required: usize) -> bool {
        let statuses = self.all_statuses();
        let healthy_count = statuses.values()
            .filter(|s| **s == HealthStatus::Healthy || **s == HealthStatus::Degraded)
            .count();
        healthy_count >= required
    }

    /// Evict peers that haven't been seen within `max_idle`.
    /// Returns the number of peers removed.
    pub fn evict_dead_peers(&self, max_idle: Duration) -> usize {
        let mut peers = crate::sync::siem_lock(&self.peers, "health::evict_dead_peers");
        let before = peers.len();
        peers.retain(|peer_name, health| {
            let dominated = health.last_seen.elapsed() <= max_idle;
            if !dominated {
                tracing::warn!(
                    peer = %peer_name,
                    idle_secs = health.last_seen.elapsed().as_secs(),
                    "evicting dead peer from health monitor"
                );
            }
            dominated
        });
        before - peers.len()
    }

    /// Spawn a background task that periodically evicts peers not seen in 5 minutes.
    pub fn spawn_peer_eviction_task(monitor: std::sync::Arc<Self>) {
        tokio::spawn(async move {
            const EVICTION_INTERVAL: Duration = Duration::from_secs(60);
            const DEAD_PEER_THRESHOLD: Duration = Duration::from_secs(300); // 5 minutes
            loop {
                tokio::time::sleep(EVICTION_INTERVAL).await;
                let removed = monitor.evict_dead_peers(DEAD_PEER_THRESHOLD);
                if removed > 0 {
                    tracing::info!(
                        removed = removed,
                        "health monitor: evicted dead peers"
                    );
                }
            }
        });
    }
}

impl Default for HealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Structured health check endpoint support
// ---------------------------------------------------------------------------

/// Individual health check result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthCheck {
    /// Name of the check (e.g., "database", "peer_tss", "cert_validity").
    pub name: String,
    /// Whether this check passed.
    pub ok: bool,
    /// Human-readable detail (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Latency of the check in milliseconds (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
}

/// Structured health response returned by `/healthz` endpoints.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthResponse {
    /// Overall status: "healthy", "degraded", or "unhealthy".
    pub status: String,
    /// Individual check results.
    pub checks: Vec<HealthCheck>,
    /// Service name.
    pub service: String,
    /// Uptime in seconds.
    pub uptime_secs: u64,
}

impl HealthResponse {
    /// Compute overall status from individual checks.
    pub fn from_checks(service: &str, checks: Vec<HealthCheck>, start_time: std::time::Instant) -> Self {
        let all_ok = checks.iter().all(|c| c.ok);
        let any_ok = checks.iter().any(|c| c.ok);
        let status = if all_ok {
            "healthy"
        } else if any_ok {
            "degraded"
        } else {
            "unhealthy"
        };

        Self {
            status: status.to_string(),
            checks,
            service: service.to_string(),
            uptime_secs: start_time.elapsed().as_secs(),
        }
    }

    /// Serialize to JSON bytes.
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_else(|_| b"{\"status\":\"unhealthy\"}".to_vec())
    }
}

/// Check database connectivity by running `SELECT 1`.
pub async fn check_db(pool: &sqlx::PgPool) -> HealthCheck {
    let start = std::time::Instant::now();
    match sqlx::query("SELECT 1").execute(pool).await {
        Ok(_) => HealthCheck {
            name: "database".to_string(),
            ok: true,
            detail: None,
            latency_ms: Some(start.elapsed().as_millis() as u64),
        },
        Err(e) => HealthCheck {
            name: "database".to_string(),
            ok: false,
            detail: Some(format!("connection failed: {e}")),
            latency_ms: Some(start.elapsed().as_millis() as u64),
        },
    }
}

/// Check peer reachability from the HealthMonitor.
pub fn check_peers(monitor: &HealthMonitor, required_peers: &[&str]) -> Vec<HealthCheck> {
    required_peers
        .iter()
        .map(|peer| {
            let status = monitor.peer_status(peer);
            HealthCheck {
                name: format!("peer_{}", peer),
                ok: status == HealthStatus::Healthy || status == HealthStatus::Degraded,
                detail: Some(format!("{:?}", status)),
                latency_ms: None,
            }
        })
        .collect()
}

/// Rate limiter state for the health endpoint.
///
/// Uses a simple token-bucket approach: tracks request count per second
/// and rejects requests exceeding the limit.
struct HealthRateLimiter {
    /// Request count in the current second window.
    count: AtomicU32,
    /// Epoch second of the current window (seconds since `start`).
    window_epoch: AtomicU64,
}

impl HealthRateLimiter {
    const MAX_REQUESTS_PER_SECOND: u32 = 100;

    fn new() -> Self {
        Self {
            count: AtomicU32::new(0),
            window_epoch: AtomicU64::new(0),
        }
    }

    /// Try to acquire a rate-limit token. Returns `true` if allowed.
    fn try_acquire(&self, now_secs: u64) -> bool {
        let current_window = self.window_epoch.load(Ordering::Acquire);
        if now_secs != current_window {
            // New window — reset counter
            self.window_epoch.store(now_secs, Ordering::Release);
            self.count.store(1, Ordering::Release);
            return true;
        }
        let prev = self.count.fetch_add(1, Ordering::Acquire);
        prev < Self::MAX_REQUESTS_PER_SECOND
    }
}

/// Cached health check result to avoid per-request DB queries.
struct CachedHealth {
    response: Mutex<Option<(Instant, Vec<u8>, u16)>>,
}

impl CachedHealth {
    const CACHE_TTL: Duration = Duration::from_secs(5);

    fn new() -> Self {
        Self {
            response: Mutex::new(None),
        }
    }

    /// Get cached response if fresh, or None if stale/missing.
    fn get(&self) -> Option<(Vec<u8>, u16)> {
        let guard = crate::sync::siem_lock(&self.response, "health::cached_get");
        if let Some((ts, body, status)) = guard.as_ref() {
            if ts.elapsed() < Self::CACHE_TTL {
                return Some((body.clone(), *status));
            }
        }
        None
    }

    /// Store a new cached response.
    fn set(&self, body: Vec<u8>, status: u16) {
        let mut guard = crate::sync::siem_lock(&self.response, "health::cached_set");
        *guard = Some((Instant::now(), body, status));
    }
}

/// Spawn a lightweight TCP-based `/healthz` endpoint on a dedicated port.
///
/// Each service should call this at startup with a closure that produces
/// the current health checks.  The health port is `service_port + 1000`
/// unless overridden by `MILNET_HEALTH_PORT`.
///
/// Hardening measures:
/// - Rate limit: max 100 requests/second (across all IPs)
/// - Caching: health check results cached for 5 seconds
/// - HTTP 503 for degraded and unhealthy status
/// - Concurrency limit: max 50 simultaneous connections
///
/// The server responds to any TCP connection with an HTTP/1.1 response
/// containing the JSON health payload, then closes the connection.
pub fn spawn_health_endpoint<F>(
    service_name: String,
    service_port: u16,
    start_time: std::time::Instant,
    check_fn: F,
) -> tokio::task::JoinHandle<()>
where
    F: Fn() -> Vec<HealthCheck> + Send + Sync + 'static,
{
    let health_port = std::env::var("MILNET_HEALTH_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or_else(|| service_port.saturating_add(1000));

    // Read bearer token for health endpoint authentication at startup.
    let health_token: Option<String> = std::env::var("MILNET_HEALTH_TOKEN").ok().filter(|t| !t.is_empty());

    tokio::spawn(async move {
        // SECURITY: Bind to configurable address. When MILNET_HEALTH_TOKEN is set
        // (authenticated health checks), default to 0.0.0.0 for K8s probe access.
        // Otherwise default to 127.0.0.1 (localhost only) to prevent unauthenticated
        // health info exposure.
        let bind_addr = std::env::var("MILNET_HEALTH_BIND_ADDR")
            .unwrap_or_else(|_| {
                if std::env::var("MILNET_HEALTH_TOKEN").is_ok() {
                    "0.0.0.0".to_string()
                } else {
                    "127.0.0.1".to_string()
                }
            });
        let addr = format!("{bind_addr}:{health_port}");
        let listener = match tokio::net::TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(
                    service = %service_name,
                    port = health_port,
                    error = %e,
                    "Failed to bind health endpoint — health checks unavailable"
                );
                return;
            }
        };

        tracing::info!(
            service = %service_name,
            addr = %addr,
            "Health endpoint listening on /healthz (localhost only)"
        );

        let rate_limiter = HealthRateLimiter::new();
        let cache = CachedHealth::new();
        let concurrent = AtomicU32::new(0);
        const MAX_CONCURRENT: u32 = 50;

        loop {
            let (mut stream, peer) = match listener.accept().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!("Health endpoint accept error: {e}");
                    continue;
                }
            };

            // Connection limit check
            let current = concurrent.fetch_add(1, Ordering::Acquire);
            if current >= MAX_CONCURRENT {
                concurrent.fetch_sub(1, Ordering::Release);
                // 503 with connection limit message
                let msg = b"HTTP/1.1 503 Service Unavailable\r\n\
                    Content-Type: text/plain\r\n\
                    Content-Length: 25\r\n\
                    Connection: close\r\n\
                    \r\n\
                    connection limit exceeded";
                use tokio::io::AsyncWriteExt;
                let _ = stream.write_all(msg).await;
                let _ = stream.shutdown().await;
                continue;
            }

            // Bearer token authentication check.
            // If MILNET_HEALTH_TOKEN is set, require it in the Authorization header.
            // If not set, only loopback connections are allowed (already enforced by
            // binding to 127.0.0.1, but we double-check the peer address).
            if let Some(ref required_token) = health_token {
                // Read the HTTP request to extract the Authorization header.
                let mut req_buf = vec![0u8; 4096];
                use tokio::io::AsyncReadExt;
                let n = match tokio::time::timeout(
                    Duration::from_secs(2),
                    stream.read(&mut req_buf),
                )
                .await
                {
                    Ok(Ok(n)) => n,
                    _ => {
                        concurrent.fetch_sub(1, Ordering::Release);
                        continue;
                    }
                };
                let req_str = String::from_utf8_lossy(&req_buf[..n]);
                let authorized = req_str.lines().any(|line| {
                    if let Some(value) = line.strip_prefix("Authorization: Bearer ") {
                        use subtle::ConstantTimeEq;
                        let a = value.trim().as_bytes();
                        let b = required_token.as_bytes();
                        let len_eq: subtle::Choice = (a.len() as u64).ct_eq(&(b.len() as u64));
                        let min_len = std::cmp::min(a.len(), b.len());
                        let content_eq: subtle::Choice = a[..min_len].ct_eq(&b[..min_len]);
                        bool::from(len_eq & content_eq)
                    } else {
                        false
                    }
                });
                if !authorized {
                    concurrent.fetch_sub(1, Ordering::Release);
                    let msg = b"HTTP/1.1 401 Unauthorized\r\n\
                        Content-Type: text/plain\r\n\
                        Content-Length: 12\r\n\
                        Connection: close\r\n\
                        \r\n\
                        unauthorized";
                    use tokio::io::AsyncWriteExt;
                    let _ = stream.write_all(msg).await;
                    let _ = stream.shutdown().await;
                    continue;
                }
            } else {
                // No token configured. Verify peer is loopback (defense in depth).
                let is_loopback = peer.ip().is_loopback();
                if !is_loopback {
                    concurrent.fetch_sub(1, Ordering::Release);
                    let msg = b"HTTP/1.1 403 Forbidden\r\n\
                        Content-Type: text/plain\r\n\
                        Content-Length: 9\r\n\
                        Connection: close\r\n\
                        \r\n\
                        forbidden";
                    use tokio::io::AsyncWriteExt;
                    let _ = stream.write_all(msg).await;
                    let _ = stream.shutdown().await;
                    continue;
                }
            }

            // Rate limit check
            let now_secs = start_time.elapsed().as_secs();
            if !rate_limiter.try_acquire(now_secs) {
                concurrent.fetch_sub(1, Ordering::Release);
                let msg = b"HTTP/1.1 429 Too Many Requests\r\n\
                    Content-Type: text/plain\r\n\
                    Content-Length: 19\r\n\
                    Connection: close\r\n\
                    Retry-After: 1\r\n\
                    \r\n\
                    rate limit exceeded";
                use tokio::io::AsyncWriteExt;
                let _ = stream.write_all(msg).await;
                let _ = stream.shutdown().await;
                continue;
            }

            // Serve from cache or compute fresh
            let (body, status_code) = if let Some(cached) = cache.get() {
                cached
            } else {
                let checks = check_fn();
                let response = HealthResponse::from_checks(&service_name, checks, start_time);
                let body = response.to_json();
                // Return 503 for degraded and unhealthy
                let status_code: u16 = if response.status == "healthy" {
                    200
                } else {
                    503
                };
                cache.set(body.clone(), status_code);
                (body, status_code)
            };

            let status_text = if status_code == 200 { "OK" } else { "Service Unavailable" };
            let http_response = format!(
                "HTTP/1.1 {} {}\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 Cache-Control: no-store\r\n\
                 \r\n",
                status_code,
                status_text,
                body.len()
            );

            use tokio::io::AsyncWriteExt;
            let _ = stream.write_all(http_response.as_bytes()).await;
            let _ = stream.write_all(&body).await;
            let _ = stream.shutdown().await;

            concurrent.fetch_sub(1, Ordering::Release);
        }
    })
}

/// Check mTLS certificate validity (time until rotation needed).
pub fn check_cert_validity(
    module_name: &str,
    issued_at: std::time::Instant,
    lifetime_hours: u64,
) -> HealthCheck {
    let age_secs = issued_at.elapsed().as_secs();
    let lifetime_secs = lifetime_hours * 3600;
    let remaining_secs = lifetime_secs.saturating_sub(age_secs);
    let threshold_secs = (lifetime_secs as f64 * 0.8) as u64;

    if age_secs < threshold_secs {
        HealthCheck {
            name: format!("cert_{}", module_name),
            ok: true,
            detail: Some(format!("{}h remaining", remaining_secs / 3600)),
            latency_ms: None,
        }
    } else if remaining_secs > 0 {
        HealthCheck {
            name: format!("cert_{}", module_name),
            ok: true,
            detail: Some(format!(
                "rotation threshold reached — {}h remaining",
                remaining_secs / 3600
            )),
            latency_ms: None,
        }
    } else {
        HealthCheck {
            name: format!("cert_{}", module_name),
            ok: false,
            detail: Some("certificate EXPIRED".to_string()),
            latency_ms: None,
        }
    }
}
