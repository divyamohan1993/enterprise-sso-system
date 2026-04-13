//! Distributed rate limiting with Redis-backed sliding window.
//!
//! Provides a Redis-backed rate limiter using the sliding window log algorithm
//! with atomic Lua scripts. Falls back to local in-memory rate limiting when
//! Redis is unavailable, ensuring the gateway never fails open.
//!
//! # Configuration
//!
//! - `MILNET_RATE_LIMIT_REDIS_URL`: Redis connection URL (e.g., `redis://redis:6379`)
//! - `MILNET_RATE_LIMIT_PER_IP`: Max requests per IP per window (default: 100)
//! - `MILNET_RATE_LIMIT_PER_USER`: Max requests per user per window (default: 50)
//! - `MILNET_RATE_LIMIT_WINDOW_SECS`: Window duration in seconds (default: 60)
//! - `MILNET_RATE_LIMIT_BURST`: Token bucket burst size (default: 20)
//!
//! # Algorithm
//!
//! Uses a hybrid approach:
//! 1. **Sliding window counter** in Redis for distributed state
//! 2. **Token bucket** for burst control with configurable refill rate
//! 3. **Local fallback** using in-memory HashMap when Redis is down

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// Result of a rate limit check.
#[derive(Debug, Clone)]
pub struct RateLimitResult {
    /// Whether the request is allowed.
    pub allowed: bool,
    /// Remaining requests in the current window.
    pub remaining: u64,
    /// Seconds until the rate limit window resets.
    pub reset_after_secs: u64,
    /// Seconds to wait before retrying (0 if allowed).
    pub retry_after_secs: u64,
}

/// Configuration for the distributed rate limiter.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per IP per window.
    pub per_ip_limit: u64,
    /// Maximum requests per authenticated user per window.
    pub per_user_limit: u64,
    /// Window duration in seconds.
    pub window_secs: u64,
    /// Token bucket burst size (max tokens accumulated).
    pub burst_size: u64,
    /// Token refill rate (tokens per second).
    pub refill_rate: f64,
    /// Redis connection URL (None = local-only mode).
    pub redis_url: Option<String>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            per_ip_limit: 100,
            per_user_limit: 50,
            window_secs: 60,
            burst_size: 20,
            refill_rate: 1.667, // 100 tokens per minute
            redis_url: None,
        }
    }
}

impl RateLimitConfig {
    /// Validate configuration invariants. Panics on invalid config to
    /// fail fast at startup rather than produce NaN/Infinity at runtime.
    pub fn validate(&self) {
        assert!(
            self.refill_rate > 0.0 && self.refill_rate.is_finite(),
            "SECURITY: refill_rate must be a positive finite number, got: {}",
            self.refill_rate,
        );
        assert!(
            self.window_secs > 0,
            "SECURITY: window_secs must be > 0, got: {}",
            self.window_secs,
        );
        assert!(
            self.burst_size > 0,
            "SECURITY: burst_size must be > 0, got: {}",
            self.burst_size,
        );
    }

    /// Load configuration from environment variables.
    pub fn from_env() -> Self {
        let redis_url = std::env::var("MILNET_RATE_LIMIT_REDIS_URL").ok();
        let per_ip_limit = std::env::var("MILNET_RATE_LIMIT_PER_IP")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);
        let per_user_limit = std::env::var("MILNET_RATE_LIMIT_PER_USER")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(50);
        let window_secs = std::env::var("MILNET_RATE_LIMIT_WINDOW_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);
        let burst_size = std::env::var("MILNET_RATE_LIMIT_BURST")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(20);

        let refill_rate = per_ip_limit as f64 / window_secs as f64;

        let config = Self {
            per_ip_limit,
            per_user_limit,
            window_secs,
            burst_size,
            refill_rate,
            redis_url,
        };
        config.validate();
        config
    }
}

/// Redis Lua script for atomic sliding window rate limiting.
///
/// KEYS[1] = rate limit key
/// ARGV[1] = current timestamp (milliseconds)
/// ARGV[2] = window size (milliseconds)
/// ARGV[3] = max requests
///
/// Returns: [allowed (0/1), remaining, reset_after_ms]
const SLIDING_WINDOW_LUA: &str = r#"
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])

-- Remove entries outside the sliding window
local window_start = now - window
redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

-- Count current entries in the window
local count = redis.call('ZCARD', key)

if count < limit then
    -- Add the current request timestamp as both score and member
    -- Use a unique member to avoid dedup (timestamp + random suffix)
    local member = now .. ':' .. math.random(1000000)
    redis.call('ZADD', key, now, member)
    redis.call('PEXPIRE', key, window)
    local remaining = limit - count - 1
    return {1, remaining, window}
else
    -- Get the oldest entry to calculate reset time
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local reset_after = 0
    if #oldest > 0 then
        reset_after = tonumber(oldest[2]) + window - now
        if reset_after < 0 then reset_after = 0 end
    end
    return {0, 0, reset_after}
end
"#;

/// Token bucket Lua script for burst control.
///
/// KEYS[1] = bucket key
/// ARGV[1] = current timestamp (seconds, float)
/// ARGV[2] = burst size (max tokens)
/// ARGV[3] = refill rate (tokens per second)
/// ARGV[4] = tokens to consume (usually 1)
///
/// Returns: [allowed (0/1), tokens_remaining]
const TOKEN_BUCKET_LUA: &str = r#"
local key = KEYS[1]
local now = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local rate = tonumber(ARGV[3])
local consume = tonumber(ARGV[4])

local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens = tonumber(bucket[1])
local last_refill = tonumber(bucket[2])

if tokens == nil then
    -- Initialize bucket
    tokens = burst
    last_refill = now
end

-- Refill tokens based on elapsed time
local elapsed = now - last_refill
local refill = elapsed * rate
tokens = math.min(burst, tokens + refill)

if tokens >= consume then
    tokens = tokens - consume
    redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
    redis.call('EXPIRE', key, math.ceil(burst / rate) + 1)
    return {1, math.floor(tokens)}
else
    redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
    redis.call('EXPIRE', key, math.ceil(burst / rate) + 1)
    return {0, math.floor(tokens)}
end
"#;

/// Local fallback rate limit entry.
struct LocalEntry {
    /// Number of requests in the current window.
    count: u64,
    /// Window start time.
    window_start: Instant,
    /// Token bucket: current tokens.
    tokens: f64,
    /// Token bucket: last refill time.
    last_refill: Instant,
}

/// Distributed rate limiter with Redis backend and local fallback.
///
/// When Redis is unavailable, local fallback applies a **conservative divisor**
/// to account for multiple gateway instances that each maintain independent
/// state. This prevents an attacker from distributing requests across N
/// gateways to bypass the global limit.
pub struct DistributedRateLimiter {
    config: RateLimitConfig,
    /// Redis client (None if Redis is not configured or connection failed).
    redis_client: Option<Arc<Mutex<RedisClient>>>,
    /// Local fallback state.
    local_state: Arc<Mutex<HashMap<String, LocalEntry>>>,
    /// Whether Redis is currently healthy.
    redis_healthy: Arc<std::sync::atomic::AtomicBool>,
    /// Whether Redis is required in this deployment mode.
    pub redis_required: bool,
    /// Conservative divisor for local fallback limits. Each gateway instance
    /// gets `limit / degraded_limit_divisor` when Redis is down. Set to
    /// the expected number of gateway instances (e.g., 10 for a 10-instance MIG).
    /// Default: 10 (conservative — better to over-restrict than under-restrict).
    pub degraded_limit_divisor: u64,
    /// Counter for the number of times degraded mode has been activated.
    /// Useful for monitoring/alerting on persistent Redis failures.
    pub degraded_mode_activations: Arc<AtomicU64>,
    /// E7 fix: timestamp (epoch seconds) when Redis first became unhealthy.
    /// 0 = currently healthy. Once outage exceeds REDIS_OUTAGE_FAIL_CLOSED_SECS,
    /// the gateway transitions to fail-closed: ALL non-whitelisted traffic
    /// rejected until Redis recovers.
    pub redis_unhealthy_since: Arc<AtomicU64>,
}

/// E7: After Redis has been unavailable for this many seconds, the gateway
/// transitions from "degraded local fallback" to fail-closed (deny-all).
/// 30 seconds is short enough to limit attacker exploitation but long enough
/// that brief Redis blips don't black-hole the service.
pub const REDIS_OUTAGE_FAIL_CLOSED_SECS: u64 = 30;

/// E7: Local token bucket rate (req/s per IP) used while Redis is degraded.
/// Hard-capped at 10 req/s per IP regardless of normal Redis-backed limit
/// to constrain attacker amplification when the global counter is unavailable.
pub const REDIS_DEGRADED_LOCAL_RPS_PER_IP: u64 = 10;

/// Minimal Redis client wrapper.
///
/// In production, this would use a connection pool (e.g., `deadpool-redis`
/// or `bb8-redis`). For this implementation, we define the interface and
/// provide the atomic Lua script execution contract.
pub struct RedisClient {
    url: String,
    connected: bool,
    /// Raw TCP stream to Redis (RESP protocol). When TLS is enabled
    /// (MILNET_REDIS_TLS=1), this is wrapped in a TLS connector.
    stream: Option<RedisStream>,
    /// Last reconnection attempt time for exponential backoff.
    last_reconnect_attempt: Option<Instant>,
    /// Current backoff duration for reconnection (1s, 2s, 4s, ... max 30s).
    reconnect_backoff: Duration,
}

/// Abstraction over plain TCP and TLS-wrapped TCP streams for Redis.
pub enum RedisStream {
    Plain(tokio::net::TcpStream),
    Tls(tokio_rustls::client::TlsStream<tokio::net::TcpStream>),
}

impl RedisClient {
    /// Connect to Redis via raw TCP (or TLS if MILNET_REDIS_TLS=1) using RESP protocol.
    /// No external Redis crate needed -- we speak RESP directly.
    pub async fn connect(url: &str) -> Result<Self, String> {
        use tokio::net::TcpStream;

        // Parse redis://host:port or host:port
        let addr = url
            .trim_start_matches("redis://")
            .trim_start_matches("rediss://")
            .split('/')
            .next()
            .unwrap_or("127.0.0.1:6379");

        let host = addr.split(':').next().unwrap_or("127.0.0.1");

        info!("connecting to Redis rate limit backend: {}", addr);

        let tcp_stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("Redis connect to {}: {}", addr, e))?;

        // Wrap in TLS if MILNET_REDIS_TLS=1
        let use_tls = std::env::var("MILNET_REDIS_TLS")
            .map(|v| v == "1")
            .unwrap_or(false);

        let stream = if use_tls {
            let mut root_store = rustls::RootCertStore::empty();
            // Load CA cert from MILNET_REDIS_CA_CERT or MILNET_CA_CERT env var
            let ca_path = std::env::var("MILNET_REDIS_CA_CERT")
                .or_else(|_| std::env::var("MILNET_CA_CERT"))
                .ok();
            if let Some(ref path) = ca_path {
                let ca_der = std::fs::read(path)
                    .map_err(|e| format!("read Redis CA cert {}: {}", path, e))?;
                let cert = rustls::pki_types::CertificateDer::from(ca_der);
                root_store.add(cert)
                    .map_err(|e| format!("add Redis CA cert: {e}"))?;
                info!("Redis TLS: loaded CA from {}", path);
            }
            let tls_config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
            let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
                .map_err(|e| format!("invalid Redis TLS server name '{}': {}", host, e))?;
            let tls_stream = connector
                .connect(server_name, tcp_stream)
                .await
                .map_err(|e| format!("Redis TLS handshake to {}: {}", addr, e))?;
            info!("Redis TLS connection established to {}", addr);
            RedisStream::Tls(tls_stream)
        } else {
            RedisStream::Plain(tcp_stream)
        };

        let mut client = Self {
            url: url.to_string(),
            connected: true,
            stream: Some(stream),
            last_reconnect_attempt: None,
            reconnect_backoff: Duration::from_secs(1),
        };

        // Verify connection with PING
        client.ping().await?;

        // AUTH if MILNET_REDIS_PASSWORD is set
        if let Ok(password) = std::env::var("MILNET_REDIS_PASSWORD") {
            // SECURITY: Overwrite env var with zeros then remove IMMEDIATELY after reading.
            // NOTE: On Linux, /proc/PID/environ is an immutable snapshot from execve.
            // std::env::remove_var() only removes from libc's environ pointer -- it does
            // NOT erase the original /proc/PID/environ content. A root attacker can always
            // read the initial environment. For true protection, pass secrets via fd passing.
            let zeros = "0".repeat(password.len());
            std::env::set_var("MILNET_REDIS_PASSWORD", &zeros);
            std::env::remove_var("MILNET_REDIS_PASSWORD");

            if !password.is_empty() {
                let response = client.resp_command(&["AUTH", &password]).await?;
                if !response.contains("+OK") {
                    return Err(format!("Redis AUTH failed: {}", response.trim()));
                }
                info!("Redis AUTH successful");
            }
        }

        info!("Redis rate limit backend connected: {}", addr);

        Ok(client)
    }

    /// Attempt reconnection with exponential backoff (1s, 2s, 4s, ... max 30s).
    /// Returns Ok(()) if reconnection succeeds, Err if too soon or failed.
    pub async fn try_reconnect(&mut self) -> Result<(), String> {
        let now = Instant::now();
        if let Some(last) = self.last_reconnect_attempt {
            if now.duration_since(last) < self.reconnect_backoff {
                return Err("reconnect backoff not elapsed".into());
            }
        }
        self.last_reconnect_attempt = Some(now);

        let url = self.url.clone();
        match Self::connect(&url).await {
            Ok(new_client) => {
                self.connected = new_client.connected;
                self.stream = new_client.stream;
                self.reconnect_backoff = Duration::from_secs(1); // Reset backoff on success
                info!("Redis reconnection successful");
                Ok(())
            }
            Err(e) => {
                // Exponential backoff: double up to 30s
                self.reconnect_backoff = (self.reconnect_backoff * 2).min(Duration::from_secs(30));
                Err(format!("Redis reconnection failed: {e}"))
            }
        }
    }

    /// Send a RESP command and read a complete RESP response.
    ///
    /// Reads in a loop until a complete RESP response is received (terminated
    /// by \r\n), with a max buffer of 64 KiB to prevent unbounded reads.
    async fn resp_command(&mut self, args: &[&str]) -> Result<String, String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const MAX_RESP_BUFFER: usize = 64 * 1024;

        let stream = self.stream.as_mut().ok_or("Redis not connected")?;

        // Build RESP array: *N\r\n$len\r\narg\r\n...
        let mut cmd = format!("*{}\r\n", args.len());
        for arg in args {
            cmd.push_str(&format!("${}\r\n{}\r\n", arg.len(), arg));
        }

        match stream {
            RedisStream::Plain(s) => {
                s.write_all(cmd.as_bytes())
                    .await
                    .map_err(|e| format!("Redis write: {e}"))?;
            }
            RedisStream::Tls(s) => {
                s.write_all(cmd.as_bytes())
                    .await
                    .map_err(|e| format!("Redis TLS write: {e}"))?;
            }
        }

        // Read response in a loop until we have a complete RESP value
        // (ends with \r\n). Cap at MAX_RESP_BUFFER to prevent unbounded reads.
        let mut buf = Vec::with_capacity(4096);
        let mut tmp = [0u8; 4096];
        loop {
            let n = match stream {
                RedisStream::Plain(s) => s
                    .read(&mut tmp)
                    .await
                    .map_err(|e| format!("Redis read: {e}"))?,
                RedisStream::Tls(s) => s
                    .read(&mut tmp)
                    .await
                    .map_err(|e| format!("Redis TLS read: {e}"))?,
            };
            if n == 0 {
                self.connected = false;
                return Err("Redis connection closed".into());
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() > MAX_RESP_BUFFER {
                self.connected = false;
                return Err(format!(
                    "Redis response exceeded {} byte limit",
                    MAX_RESP_BUFFER
                ));
            }
            // A complete RESP response ends with \r\n
            if buf.len() >= 2 && buf[buf.len() - 2] == b'\r' && buf[buf.len() - 1] == b'\n' {
                break;
            }
        }

        let response = String::from_utf8_lossy(&buf).to_string();
        Ok(response)
    }

    /// Execute the sliding window rate limit check via EVAL.
    pub async fn sliding_window_check(
        &mut self,
        key: &str,
        now_ms: u64,
        window_ms: u64,
        limit: u64,
    ) -> Result<(bool, u64, u64), String> {
        if !self.connected {
            return Err("Redis not connected".into());
        }

        let now_str = now_ms.to_string();
        let window_str = window_ms.to_string();
        let limit_str = limit.to_string();

        let response = self
            .resp_command(&[
                "EVAL",
                SLIDING_WINDOW_LUA,
                "1",
                key,
                &now_str,
                &window_str,
                &limit_str,
            ])
            .await?;

        // Parse RESP array response: *3\r\n:allowed\r\n:count\r\n:remaining\r\n
        let values: Vec<i64> = response
            .lines()
            .filter(|l| l.starts_with(':'))
            .filter_map(|l| l[1..].trim().parse().ok())
            .collect();

        if values.len() >= 3 {
            Ok((values[0] == 1, values[1] as u64, values[2] as u64))
        } else {
            Err(format!("unexpected Redis response: {}", response.trim()))
        }
    }

    /// Execute the token bucket rate limit check via EVAL.
    pub async fn token_bucket_check(
        &mut self,
        key: &str,
        now_secs: f64,
        burst: u64,
        rate: f64,
        consume: u64,
    ) -> Result<(bool, u64), String> {
        if !self.connected {
            return Err("Redis not connected".into());
        }

        let now_str = now_secs.to_string();
        let burst_str = burst.to_string();
        let rate_str = rate.to_string();
        let consume_str = consume.to_string();

        let response = self
            .resp_command(&[
                "EVAL",
                TOKEN_BUCKET_LUA,
                "1",
                key,
                &now_str,
                &burst_str,
                &rate_str,
                &consume_str,
            ])
            .await?;

        let values: Vec<i64> = response
            .lines()
            .filter(|l| l.starts_with(':'))
            .filter_map(|l| l[1..].trim().parse().ok())
            .collect();

        if values.len() >= 2 {
            Ok((values[0] == 1, values[1] as u64))
        } else {
            Err(format!("unexpected Redis response: {}", response.trim()))
        }
    }

    /// Health check ping — sends PING, expects +PONG.
    pub async fn ping(&mut self) -> Result<(), String> {
        let response = self.resp_command(&["PING"]).await?;
        if response.contains("PONG") {
            Ok(())
        } else {
            Err(format!("Redis PING failed: {}", response.trim()))
        }
    }
}

impl DistributedRateLimiter {
    /// Create a new distributed rate limiter from configuration.
    pub async fn new(config: RateLimitConfig) -> Self {
        let mlp_mode = std::env::var("MILNET_MLP_MODE_ACK").map(|v| v == "1").unwrap_or(false);
        let redis_required = std::env::var("MILNET_RATE_LIMIT_REDIS_REQUIRED")
            .map(|v| v == "1")
            .unwrap_or(!mlp_mode);

        let redis_client = if let Some(ref url) = config.redis_url {
            match RedisClient::connect(url).await {
                Ok(client) => {
                    info!("Redis rate limit backend connected");
                    Some(Arc::new(Mutex::new(client)))
                }
                Err(e) => {
                    if redis_required && !mlp_mode {
                        error!("SIEM:CRITICAL Redis rate limit backend REQUIRED but unavailable: {e}");
                    } else {
                        warn!("Redis rate limit backend unavailable, using local fallback: {e}");
                    }
                    None
                }
            }
        } else {
            if redis_required && !mlp_mode {
                error!("SIEM:CRITICAL No Redis URL configured but redis required");
            } else if mlp_mode {
                warn!("SIEM:SECURITY MLP mode: local-only rate limiting enabled without Redis");
            } else {
                debug!("No Redis URL configured, using local-only rate limiting");
            }
            None
        };

        let redis_healthy = Arc::new(std::sync::atomic::AtomicBool::new(
            redis_client.is_some(),
        ));

        let degraded_limit_divisor = std::env::var("MILNET_RATE_LIMIT_DEGRADED_DIVISOR")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10u64)
            .max(1);

        Self {
            config,
            redis_client,
            local_state: Arc::new(Mutex::new(HashMap::new())),
            redis_healthy,
            redis_required,
            degraded_limit_divisor,
            degraded_mode_activations: Arc::new(AtomicU64::new(0)),
            redis_unhealthy_since: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Create a rate limiter from environment variables.
    pub async fn from_env() -> Self {
        Self::new(RateLimitConfig::from_env()).await
    }

    /// Check rate limit for an IP address.
    ///
    /// Tries Redis first; falls back to local if Redis is unavailable.
    pub async fn check_ip(&self, ip: IpAddr) -> RateLimitResult {
        let key = format!("rl:ip:{ip}");
        self.check_rate_limit(&key, self.config.per_ip_limit).await
    }

    /// Check rate limit for an authenticated user.
    pub async fn check_user(&self, user_id: &str) -> RateLimitResult {
        let key = format!("rl:user:{user_id}");
        self.check_rate_limit(&key, self.config.per_user_limit).await
    }

    /// Check both IP and burst rate limits.
    ///
    /// Returns the most restrictive result (denied if either denies).
    pub async fn check_ip_with_burst(&self, ip: IpAddr) -> RateLimitResult {
        let window_result = self.check_ip(ip).await;
        if !window_result.allowed {
            return window_result;
        }

        let burst_result = self.check_burst(&format!("rl:burst:{ip}")).await;
        if !burst_result.allowed {
            return burst_result;
        }

        // Return the more restrictive remaining count
        RateLimitResult {
            allowed: true,
            remaining: window_result.remaining.min(burst_result.remaining),
            reset_after_secs: window_result.reset_after_secs,
            retry_after_secs: 0,
        }
    }

    /// E7: Returns true if the gateway should fail-closed (deny ALL) because
    /// Redis has been down longer than REDIS_OUTAGE_FAIL_CLOSED_SECS.
    fn should_fail_closed(&self) -> bool {
        let since = self.redis_unhealthy_since.load(std::sync::atomic::Ordering::Relaxed);
        if since == 0 {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now.saturating_sub(since) >= REDIS_OUTAGE_FAIL_CLOSED_SECS
    }

    /// E7: Mark Redis healthy — clears the outage timer.
    fn mark_redis_healthy(&self) {
        self.redis_healthy.store(true, std::sync::atomic::Ordering::Relaxed);
        self.redis_unhealthy_since.store(0, std::sync::atomic::Ordering::Relaxed);
    }

    /// E7: Mark Redis unhealthy — starts the outage timer if not already running.
    fn mark_redis_unhealthy(&self) {
        self.redis_healthy.store(false, std::sync::atomic::Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Only set if currently 0 (don't reset an existing timer)
        let _ = self.redis_unhealthy_since.compare_exchange(
            0, now,
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Internal: perform the rate limit check with Redis fallback.
    async fn check_rate_limit(&self, key: &str, limit: u64) -> RateLimitResult {
        // E7: fail-closed if Redis has been down longer than the threshold.
        if self.should_fail_closed() {
            error!(
                key = key,
                "SIEM:CRITICAL rate limit FAIL-CLOSED: Redis outage > {}s, denying request",
                REDIS_OUTAGE_FAIL_CLOSED_SECS
            );
            common::siem::SecurityEvent::tamper_detected(
                "Gateway rate limit fail-closed: Redis outage exceeded threshold"
            );
            return RateLimitResult {
                allowed: false,
                remaining: 0,
                reset_after_secs: REDIS_OUTAGE_FAIL_CLOSED_SECS,
                retry_after_secs: REDIS_OUTAGE_FAIL_CLOSED_SECS,
            };
        }
        // Try Redis first
        if self.redis_healthy.load(std::sync::atomic::Ordering::Relaxed) {
            if let Some(ref redis) = self.redis_client {
                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let window_ms = self.config.window_secs * 1000;

                let mut client = redis.lock().await;
                match client.sliding_window_check(key, now_ms, window_ms, limit).await {
                    Ok((allowed, remaining, reset_after_ms)) => {
                        return RateLimitResult {
                            allowed,
                            remaining,
                            reset_after_secs: reset_after_ms / 1000,
                            retry_after_secs: if allowed { 0 } else { reset_after_ms / 1000 },
                        };
                    }
                    Err(e) => {
                        warn!("Redis rate limit check failed, falling back to local: {e}");
                        self.mark_redis_unhealthy();
                        // Spawn background reconnection with exponential backoff
                        let redis_clone = redis.clone();
                        let healthy_clone = self.redis_healthy.clone();
                        let unhealthy_since_clone = self.redis_unhealthy_since.clone();
                        tokio::spawn(async move {
                            let mut client = redis_clone.lock().await;
                            match client.try_reconnect().await {
                                Ok(()) => {
                                    healthy_clone
                                        .store(true, std::sync::atomic::Ordering::Relaxed);
                                    unhealthy_since_clone
                                        .store(0, std::sync::atomic::Ordering::Relaxed);
                                    info!("Redis rate limit backend reconnected");
                                }
                                Err(e) => {
                                    debug!("Redis reconnection deferred: {e}");
                                }
                            }
                        });
                    }
                }
            }
        }

        // E7: hard cap on degraded local fallback. The previous formula
        // (limit/2 or limit/divisor) could still allow ~1000 r/s if the
        // configured per_ip_limit was 2000. The new cap is min(prev, 10/window)
        // for IP-scoped keys to cap attacker amplification regardless of config.
        let mut degraded_limit = if self.redis_required {
            (limit / 2).max(1)
        } else {
            (limit / self.degraded_limit_divisor).max(1)
        };
        if key.starts_with("rl:ip:") {
            let cap = REDIS_DEGRADED_LOCAL_RPS_PER_IP.saturating_mul(self.config.window_secs).max(1);
            degraded_limit = degraded_limit.min(cap);
        }
        let activations = self.degraded_mode_activations.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        let severity = if self.redis_required { "CRITICAL" } else { "SECURITY" };
        warn!(
            key = key,
            degraded_limit = degraded_limit,
            normal_limit = limit,
            redis_required = self.redis_required,
            total_activations = activations,
            "SIEM:{} rate limit degraded mode -- Redis unavailable, stricter local limits ({}/{})",
            severity, degraded_limit, limit
        );
        self.check_local(key, degraded_limit).await
    }

    /// Local in-memory rate limiting (fallback when Redis is unavailable).
    async fn check_local(&self, key: &str, limit: u64) -> RateLimitResult {
        let mut state = self.local_state.lock().await;
        let now = Instant::now();
        let window = Duration::from_secs(self.config.window_secs);

        // Evict oldest entries if map exceeds limit
        const MAX_LOCAL_ENTRIES: usize = 10_000;
        if state.len() > MAX_LOCAL_ENTRIES {
            // Remove entries older than 60 seconds
            let cutoff = now - Duration::from_secs(60);
            state.retain(|_, entry| entry.window_start > cutoff);
        }

        let entry = state.entry(key.to_string()).or_insert_with(|| LocalEntry {
            count: 0,
            window_start: now,
            tokens: self.config.burst_size as f64,
            last_refill: now,
        });

        // Reset window if expired
        if now.duration_since(entry.window_start) >= window {
            entry.count = 0;
            entry.window_start = now;
        }

        entry.count += 1;

        if entry.count <= limit {
            let remaining = limit - entry.count;
            let reset_after = window
                .checked_sub(now.duration_since(entry.window_start))
                .unwrap_or_default()
                .as_secs();
            RateLimitResult {
                allowed: true,
                remaining,
                reset_after_secs: reset_after,
                retry_after_secs: 0,
            }
        } else {
            let reset_after = window
                .checked_sub(now.duration_since(entry.window_start))
                .unwrap_or_default()
                .as_secs();
            // Undo the count increment for denied requests
            entry.count -= 1;
            RateLimitResult {
                allowed: false,
                remaining: 0,
                reset_after_secs: reset_after,
                retry_after_secs: reset_after,
            }
        }
    }

    /// Token bucket burst check.
    async fn check_burst(&self, key: &str) -> RateLimitResult {
        // Try Redis first
        if self.redis_healthy.load(std::sync::atomic::Ordering::Relaxed) {
            if let Some(ref redis) = self.redis_client {
                let now_secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs_f64();

                let mut client = redis.lock().await;
                match client
                    .token_bucket_check(
                        key,
                        now_secs,
                        self.config.burst_size,
                        self.config.refill_rate,
                        1,
                    )
                    .await
                {
                    Ok((allowed, remaining)) => {
                        let burst_retry = if allowed {
                            0u64
                        } else {
                            let v = (1.0 / self.config.refill_rate).ceil();
                            if v.is_nan() || v.is_infinite() || v < 0.0 { 1 } else { v as u64 }
                        };
                        return RateLimitResult {
                            allowed,
                            remaining,
                            reset_after_secs: burst_retry,
                            retry_after_secs: burst_retry,
                        };
                    }
                    Err(e) => {
                        debug!("Redis burst check failed, using local: {e}");
                    }
                }
            }
        }

        // Local token bucket fallback
        self.check_local_burst(key).await
    }

    /// Local token bucket implementation.
    async fn check_local_burst(&self, key: &str) -> RateLimitResult {
        let mut state = self.local_state.lock().await;
        let now = Instant::now();

        let entry = state.entry(key.to_string()).or_insert_with(|| LocalEntry {
            count: 0,
            window_start: now,
            tokens: self.config.burst_size as f64,
            last_refill: now,
        });

        // Refill tokens based on elapsed time
        let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
        let refill = elapsed * self.config.refill_rate;
        entry.tokens = (entry.tokens + refill).min(self.config.burst_size as f64);
        entry.last_refill = now;

        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            RateLimitResult {
                allowed: true,
                remaining: entry.tokens.floor() as u64,
                reset_after_secs: 0,
                retry_after_secs: 0,
            }
        } else {
            // SECURITY: guard against NaN/Infinity from floating-point division.
            // If refill_rate is somehow zero or denormal, default to 1 second.
            let mut retry_after = ((1.0 - entry.tokens) / self.config.refill_rate).ceil();
            if retry_after.is_nan() || retry_after.is_infinite() || retry_after < 0.0 {
                retry_after = 1.0; // Safe default: 1 second
            }
            let retry_after = retry_after as u64;
            RateLimitResult {
                allowed: false,
                remaining: 0,
                reset_after_secs: retry_after,
                retry_after_secs: retry_after,
            }
        }
    }

    /// Periodically clean up expired local state entries.
    ///
    /// Should be spawned as a background task.
    pub async fn cleanup_loop(&self) {
        let window = Duration::from_secs(self.config.window_secs * 2);
        loop {
            tokio::time::sleep(Duration::from_secs(self.config.window_secs)).await;
            let mut state = self.local_state.lock().await;
            let now = Instant::now();
            state.retain(|_, entry| now.duration_since(entry.window_start) < window);
            debug!("rate limit cleanup: {} active entries", state.len());
        }
    }

    /// Background task to periodically check Redis health and reconnect.
    pub async fn health_check_loop(&self) {
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            if let Some(ref redis) = self.redis_client {
                let mut client = redis.lock().await;
                match client.ping().await {
                    Ok(()) => {
                        if !self.redis_healthy.load(std::sync::atomic::Ordering::Relaxed) {
                            info!("Redis rate limit backend recovered");
                            self.redis_healthy
                                .store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    Err(e) => {
                        if self.redis_healthy.load(std::sync::atomic::Ordering::Relaxed) {
                            warn!("Redis rate limit backend unhealthy: {e}");
                            self.redis_healthy
                                .store(false, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }
            }
        }
    }

    pub fn is_redis_required(&self) -> bool { self.redis_required }
    pub fn is_redis_healthy(&self) -> bool { self.redis_healthy.load(std::sync::atomic::Ordering::Relaxed) }

    /// Export local counters for gossip-based sync when Redis is unavailable.
    pub async fn export_local_counters(&self) -> Vec<(String, u64)> {
        let state = self.local_state.lock().await;
        let now = Instant::now();
        let window = Duration::from_secs(self.config.window_secs);
        state.iter()
            .filter(|(_, entry)| now.duration_since(entry.window_start) < window)
            .map(|(key, entry)| (key.clone(), entry.count))
            .collect()
    }

    /// Merge peer counters received via gossip (uses max to prevent bypass).
    pub async fn merge_peer_counters(&self, peer_counters: &[(String, u64)]) {
        let mut state = self.local_state.lock().await;
        let now = Instant::now();
        for (key, peer_count) in peer_counters {
            let entry = state.entry(key.clone()).or_insert_with(|| LocalEntry {
                count: 0, window_start: now,
                tokens: self.config.burst_size as f64, last_refill: now,
            });
            entry.count = entry.count.max(*peer_count);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Helper: create a limiter with no Redis (local-only mode).
    // =========================================================================
    async fn local_limiter(per_ip: u64, per_user: u64, window: u64, burst: u64) -> DistributedRateLimiter {
        let mut limiter = DistributedRateLimiter::new(RateLimitConfig {
            per_ip_limit: per_ip,
            per_user_limit: per_user,
            window_secs: window,
            burst_size: burst,
            refill_rate: per_ip as f64 / window as f64,
            redis_url: None,
        })
        .await;
        limiter.degraded_limit_divisor = 1;
        limiter.redis_required = false;
        limiter
    }

    // =========================================================================
    // 1. Rate limit enforcement — verify requests rejected after threshold
    // =========================================================================

    #[tokio::test]
    async fn ip_rate_limit_allows_exactly_up_to_limit() {
        let limiter = local_limiter(5, 100, 60, 100).await;
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        for i in 0..5 {
            let result = limiter.check_ip(ip).await;
            assert!(result.allowed, "request {i} should be allowed (within limit)");
            assert_eq!(result.remaining, 4 - i as u64, "remaining should decrement");
            assert_eq!(result.retry_after_secs, 0, "retry_after should be 0 for allowed requests");
        }
    }

    #[tokio::test]
    async fn ip_rate_limit_rejects_after_threshold() {
        let limiter = local_limiter(3, 100, 60, 100).await;
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Exhaust the limit
        for _ in 0..3 {
            let result = limiter.check_ip(ip).await;
            assert!(result.allowed);
        }

        // 4th request: must be rejected
        let result = limiter.check_ip(ip).await;
        assert!(!result.allowed, "4th request must be denied after limit of 3");
        assert_eq!(result.remaining, 0, "remaining must be 0 when denied");
        assert!(result.retry_after_secs > 0, "retry_after must be > 0 when denied");

        // 5th request: still rejected
        let result = limiter.check_ip(ip).await;
        assert!(!result.allowed, "5th request must also be denied");
    }

    #[tokio::test]
    async fn denied_requests_do_not_increment_counter() {
        // Verify that denied requests do not consume additional capacity.
        // After the window resets, the counter should be back to 0, not
        // inflated by the denied attempts.
        let limiter = local_limiter(2, 100, 60, 100).await;
        let ip: IpAddr = "10.0.0.2".parse().unwrap();

        // Exhaust limit
        limiter.check_ip(ip).await;
        limiter.check_ip(ip).await;

        // Attempt 100 denied requests
        for _ in 0..100 {
            let r = limiter.check_ip(ip).await;
            assert!(!r.allowed);
        }

        // Manually reset the window by manipulating local state
        {
            let mut state = limiter.local_state.lock().await;
            let key = format!("rl:ip:{ip}");
            if let Some(entry) = state.get_mut(&key) {
                // Simulate window expiry by backdating window_start
                entry.window_start = Instant::now() - Duration::from_secs(61);
            }
        }

        // After window reset, should be allowed again (counter was 2, not 102)
        let result = limiter.check_ip(ip).await;
        assert!(result.allowed, "after window reset, request should be allowed");
        assert_eq!(result.remaining, 1, "remaining should be limit - 1 after reset");
    }

    #[tokio::test]
    async fn rate_limit_result_fields_are_consistent() {
        let limiter = local_limiter(1, 100, 60, 100).await;
        let ip: IpAddr = "10.0.0.3".parse().unwrap();

        // First request (allowed)
        let r = limiter.check_ip(ip).await;
        assert!(r.allowed);
        assert_eq!(r.remaining, 0); // 1 allowed, 0 remaining
        assert_eq!(r.retry_after_secs, 0);
        // reset_after_secs should be <= window duration
        assert!(r.reset_after_secs <= 60);

        // Second request (denied)
        let r = limiter.check_ip(ip).await;
        assert!(!r.allowed);
        assert_eq!(r.remaining, 0);
        assert!(r.retry_after_secs > 0);
        assert!(r.reset_after_secs > 0);
        assert_eq!(r.retry_after_secs, r.reset_after_secs, "retry_after should equal reset_after for window limiter");
    }

    // =========================================================================
    // 2. Sliding window expiry — verify limits reset after window
    // =========================================================================

    #[tokio::test]
    async fn window_expiry_resets_counter() {
        // Use a very short window (1 second) to test expiry without sleeping
        let limiter = local_limiter(2, 100, 1, 100).await;
        let ip: IpAddr = "172.16.0.1".parse().unwrap();

        // Exhaust the limit
        limiter.check_ip(ip).await;
        limiter.check_ip(ip).await;
        let r = limiter.check_ip(ip).await;
        assert!(!r.allowed, "should be denied at limit");

        // Simulate window expiry
        {
            let mut state = limiter.local_state.lock().await;
            let key = format!("rl:ip:{ip}");
            if let Some(entry) = state.get_mut(&key) {
                entry.window_start = Instant::now() - Duration::from_secs(2);
            }
        }

        // After window expires, counter resets
        let r = limiter.check_ip(ip).await;
        assert!(r.allowed, "after window expiry, request should be allowed");
        assert_eq!(r.remaining, 1, "remaining should be limit-1 after fresh window");
    }

    #[tokio::test]
    async fn window_expiry_with_real_sleep() {
        // Use a 1-second window and actually sleep to verify real-time behavior
        let limiter = local_limiter(1, 100, 1, 100).await;
        let ip: IpAddr = "172.16.0.2".parse().unwrap();

        let r = limiter.check_ip(ip).await;
        assert!(r.allowed);

        let r = limiter.check_ip(ip).await;
        assert!(!r.allowed, "should be denied after 1 request");

        // Sleep past the window
        tokio::time::sleep(Duration::from_millis(1100)).await;

        let r = limiter.check_ip(ip).await;
        assert!(r.allowed, "after sleeping past window, request should be allowed");
    }

    #[tokio::test]
    async fn multiple_ips_have_independent_windows() {
        let limiter = local_limiter(2, 100, 60, 100).await;
        let ip_a: IpAddr = "10.1.1.1".parse().unwrap();
        let ip_b: IpAddr = "10.1.1.2".parse().unwrap();

        // Exhaust IP-A
        limiter.check_ip(ip_a).await;
        limiter.check_ip(ip_a).await;
        let r = limiter.check_ip(ip_a).await;
        assert!(!r.allowed, "IP-A should be denied");

        // IP-B should be completely unaffected
        let r = limiter.check_ip(ip_b).await;
        assert!(r.allowed, "IP-B should be allowed (independent counter)");
        assert_eq!(r.remaining, 1);

        let r = limiter.check_ip(ip_b).await;
        assert!(r.allowed);

        let r = limiter.check_ip(ip_b).await;
        assert!(!r.allowed, "IP-B should be denied after its own limit");
    }

    // =========================================================================
    // 3. Redis fallback — verify local rate limiting when Redis unavailable
    // =========================================================================

    #[tokio::test]
    async fn redis_fallback_when_no_redis_configured() {
        // When redis_url is None, should use local limiter without errors
        let limiter = local_limiter(3, 100, 60, 100).await;

        assert!(
            limiter.redis_client.is_none(),
            "no Redis client should be created when URL is None"
        );
        assert!(
            !limiter.redis_healthy.load(std::sync::atomic::Ordering::Relaxed),
            "redis_healthy should be false when no Redis"
        );

        // Should still work correctly via local fallback
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let r = limiter.check_ip(ip).await;
        assert!(r.allowed, "local fallback should work");
    }

    #[tokio::test]
    async fn redis_fallback_when_redis_url_provided_but_stub() {
        // When a Redis URL is provided but Redis isn't running, the connection
        // fails and the limiter falls back to local rate limiting.
        let mut limiter = DistributedRateLimiter::new(RateLimitConfig {
            per_ip_limit: 3,
            per_user_limit: 2,
            window_secs: 60,
            burst_size: 10,
            refill_rate: 1.0,
            redis_url: Some("redis://127.0.0.1:63799".to_string()), // non-existent port
        })
        .await;
        limiter.degraded_limit_divisor = 1;
        limiter.redis_required = false;

        // Redis client should be None (connection failed to non-existent port)
        assert!(
            limiter.redis_client.is_none(),
            "Redis client should be None when connection fails"
        );

        // Should fall back to local rate limiting
        let ip: IpAddr = "10.0.0.5".parse().unwrap();

        // All 3 should be allowed via local fallback
        for i in 0..3 {
            let r = limiter.check_ip(ip).await;
            assert!(r.allowed, "request {i} should be allowed via local fallback");
        }

        // 4th should be denied via local fallback
        let r = limiter.check_ip(ip).await;
        assert!(!r.allowed, "4th request should be denied via local fallback");
    }

    #[tokio::test]
    async fn redis_health_flag_transitions_on_failure() {
        // When Redis is unreachable, the health flag should reflect this.
        let mut limiter = DistributedRateLimiter::new(RateLimitConfig {
            per_ip_limit: 50,
            per_user_limit: 50,
            window_secs: 60,
            burst_size: 100,
            refill_rate: 1.0,
            redis_url: Some("redis://127.0.0.1:63799".to_string()), // non-existent
        })
        .await;
        limiter.degraded_limit_divisor = 1; // no divisor for test
        limiter.redis_required = false;

        // Connection failed, so redis_healthy should be false
        assert!(
            !limiter.redis_healthy.load(std::sync::atomic::Ordering::Relaxed),
            "should be unhealthy when Redis connection fails"
        );

        // Rate limiting still works via local fallback
        let ip: IpAddr = "10.0.0.6".parse().unwrap();
        let r = limiter.check_ip(ip).await;
        assert!(r.allowed, "local fallback should still allow requests");

        // Subsequent calls should skip Redis entirely (go straight to local)
        // This is a performance optimization — no lock contention on Redis mutex
        let r = limiter.check_ip(ip).await;
        assert!(r.allowed, "should still work via local fallback after Redis marked down");
    }

    #[tokio::test]
    async fn local_fallback_enforces_limits_correctly_after_redis_fails() {
        let mut limiter = DistributedRateLimiter::new(RateLimitConfig {
            per_ip_limit: 2,
            per_user_limit: 2,
            window_secs: 60,
            burst_size: 100,
            refill_rate: 1.0,
            redis_url: Some("redis://localhost:6379".to_string()),
        })
        .await;
        limiter.degraded_limit_divisor = 1;
        limiter.redis_required = false;

        let ip: IpAddr = "10.0.0.7".parse().unwrap();

        // These will fail Redis and fall back to local
        let r1 = limiter.check_ip(ip).await;
        assert!(r1.allowed);
        let r2 = limiter.check_ip(ip).await;
        assert!(r2.allowed);
        let r3 = limiter.check_ip(ip).await;
        assert!(!r3.allowed, "local fallback must enforce the limit of 2");
    }

    // =========================================================================
    // 4. Per-IP and per-user limits independently
    // =========================================================================

    #[tokio::test]
    async fn per_user_limit_is_independent_of_ip_limit() {
        let limiter = local_limiter(100, 2, 60, 100).await;

        // User limit is 2; IP limit is 100
        let r = limiter.check_user("alice").await;
        assert!(r.allowed);
        assert_eq!(r.remaining, 1);

        let r = limiter.check_user("alice").await;
        assert!(r.allowed);
        assert_eq!(r.remaining, 0);

        let r = limiter.check_user("alice").await;
        assert!(!r.allowed, "3rd user request should be denied (limit=2)");

        // IP check should be completely unaffected by user limit
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let r = limiter.check_ip(ip).await;
        assert!(r.allowed, "IP check should be independent of user limit");
        assert_eq!(r.remaining, 99);
    }

    #[tokio::test]
    async fn different_users_have_independent_limits() {
        let limiter = local_limiter(100, 2, 60, 100).await;

        // Exhaust alice's limit
        limiter.check_user("alice").await;
        limiter.check_user("alice").await;
        let r = limiter.check_user("alice").await;
        assert!(!r.allowed, "alice should be denied");

        // bob should be completely unaffected
        let r = limiter.check_user("bob").await;
        assert!(r.allowed, "bob should be allowed (independent counter)");
        assert_eq!(r.remaining, 1);

        // charlie too
        let r = limiter.check_user("charlie").await;
        assert!(r.allowed, "charlie should be allowed");
    }

    #[tokio::test]
    async fn per_ip_and_per_user_use_different_key_namespaces() {
        // Verify that an IP "10.0.0.1" and a user "10.0.0.1" do not collide
        let limiter = local_limiter(1, 1, 60, 100).await;

        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Exhaust IP limit
        let r = limiter.check_ip(ip).await;
        assert!(r.allowed);
        let r = limiter.check_ip(ip).await;
        assert!(!r.allowed, "IP should be denied");

        // User with the same string representation should be independent
        let r = limiter.check_user("10.0.0.1").await;
        assert!(r.allowed, "user '10.0.0.1' should be independent of IP 10.0.0.1");
    }

    #[tokio::test]
    async fn user_limit_respects_window_expiry() {
        let limiter = local_limiter(100, 2, 1, 100).await;

        limiter.check_user("alice").await;
        limiter.check_user("alice").await;
        let r = limiter.check_user("alice").await;
        assert!(!r.allowed, "alice should be denied at limit");

        // Simulate window expiry
        {
            let mut state = limiter.local_state.lock().await;
            let key = "rl:user:alice".to_string();
            if let Some(entry) = state.get_mut(&key) {
                entry.window_start = Instant::now() - Duration::from_secs(2);
            }
        }

        let r = limiter.check_user("alice").await;
        assert!(r.allowed, "alice should be allowed after window expiry");
    }

    // =========================================================================
    // 5. Token bucket / burst control
    // =========================================================================

    #[tokio::test]
    async fn burst_allows_up_to_burst_size_then_denies() {
        let mut limiter = DistributedRateLimiter::new(RateLimitConfig {
            per_ip_limit: 1000,
            per_user_limit: 1000,
            window_secs: 60,
            burst_size: 3,
            refill_rate: 0.1, // very slow refill: 0.1 tokens/sec
            redis_url: None,
        })
        .await;
        limiter.degraded_limit_divisor = 1;
        limiter.redis_required = false;

        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Should allow exactly burst_size requests
        for i in 0..3 {
            let r = limiter.check_ip_with_burst(ip).await;
            assert!(r.allowed, "burst request {i} should be allowed");
        }

        // 4th request: bucket empty, slow refill means it is denied
        let r = limiter.check_ip_with_burst(ip).await;
        assert!(!r.allowed, "post-burst request should be denied");
        assert!(r.retry_after_secs > 0, "should indicate retry delay");
    }

    #[tokio::test]
    async fn burst_refills_over_time() {
        let mut limiter = DistributedRateLimiter::new(RateLimitConfig {
            per_ip_limit: 1000,
            per_user_limit: 1000,
            window_secs: 60,
            burst_size: 2,
            refill_rate: 10.0, // fast refill: 10 tokens/sec
            redis_url: None,
        })
        .await;
        limiter.degraded_limit_divisor = 1;
        limiter.redis_required = false;

        let ip: IpAddr = "10.0.0.8".parse().unwrap();

        // Exhaust burst
        limiter.check_ip_with_burst(ip).await;
        limiter.check_ip_with_burst(ip).await;
        let r = limiter.check_ip_with_burst(ip).await;
        assert!(!r.allowed, "burst exhausted");

        // Wait for refill (at 10 tokens/sec, 200ms should give ~2 tokens)
        tokio::time::sleep(Duration::from_millis(250)).await;

        let r = limiter.check_ip_with_burst(ip).await;
        assert!(r.allowed, "burst should have refilled after waiting");
    }

    #[tokio::test]
    async fn combined_check_denied_by_window_limit_even_with_burst_available() {
        // Window limit = 2, burst = 100. After 2 requests, window denies
        // even though burst tokens are still available.
        let mut limiter = DistributedRateLimiter::new(RateLimitConfig {
            per_ip_limit: 2,
            per_user_limit: 100,
            window_secs: 60,
            burst_size: 100,
            refill_rate: 1.0,
            redis_url: None,
        })
        .await;
        limiter.degraded_limit_divisor = 1;
        limiter.redis_required = false;

        let ip: IpAddr = "10.0.0.9".parse().unwrap();

        limiter.check_ip_with_burst(ip).await;
        limiter.check_ip_with_burst(ip).await;

        // Window limit (2) is exhausted; burst (100) still has tokens
        // check_ip_with_burst checks window first, so it should deny
        let r = limiter.check_ip_with_burst(ip).await;
        assert!(!r.allowed, "window limit should deny even when burst is available");
    }

    // =========================================================================
    // 6. Configuration
    // =========================================================================

    #[tokio::test]
    async fn config_from_defaults() {
        let config = RateLimitConfig::default();
        assert_eq!(config.per_ip_limit, 100);
        assert_eq!(config.per_user_limit, 50);
        assert_eq!(config.window_secs, 60);
        assert_eq!(config.burst_size, 20);
        assert!(config.redis_url.is_none());
        // refill_rate = 100/60 ~= 1.667
        assert!((config.refill_rate - 1.667).abs() < 0.001);
    }

    #[tokio::test]
    async fn config_from_env_uses_defaults_when_unset() {
        // Ensure no MILNET_RATE_LIMIT_* env vars are set for this test
        // (they typically aren't in CI)
        let config = RateLimitConfig::from_env();
        assert_eq!(config.per_ip_limit, 100);
        assert_eq!(config.per_user_limit, 50);
        assert_eq!(config.window_secs, 60);
        assert_eq!(config.burst_size, 20);
        assert!(config.redis_url.is_none());
    }

    #[tokio::test]
    async fn limiter_from_env_creates_local_only() {
        let limiter = DistributedRateLimiter::from_env().await;
        // Without MILNET_RATE_LIMIT_REDIS_URL, should be local-only
        assert!(limiter.redis_client.is_none());
    }

    // =========================================================================
    // 7. Edge cases
    // =========================================================================

    #[tokio::test]
    async fn limit_of_one_allows_exactly_one() {
        let limiter = local_limiter(1, 1, 60, 100).await;
        let ip: IpAddr = "10.0.0.10".parse().unwrap();

        let r = limiter.check_ip(ip).await;
        assert!(r.allowed);
        assert_eq!(r.remaining, 0);

        let r = limiter.check_ip(ip).await;
        assert!(!r.allowed);
    }

    #[tokio::test]
    async fn ipv6_addresses_work() {
        let limiter = local_limiter(3, 100, 60, 100).await;
        let ip: IpAddr = "2001:db8::1".parse().unwrap();

        let r = limiter.check_ip(ip).await;
        assert!(r.allowed);
        assert_eq!(r.remaining, 2);

        let ip2: IpAddr = "2001:db8::2".parse().unwrap();
        let r = limiter.check_ip(ip2).await;
        assert!(r.allowed, "different IPv6 should be independent");
        assert_eq!(r.remaining, 2);
    }

    #[tokio::test]
    async fn localhost_ipv4_and_ipv6_are_independent() {
        let limiter = local_limiter(1, 100, 60, 100).await;
        let v4: IpAddr = "127.0.0.1".parse().unwrap();
        let v6: IpAddr = "::1".parse().unwrap();

        let r = limiter.check_ip(v4).await;
        assert!(r.allowed);
        let r = limiter.check_ip(v4).await;
        assert!(!r.allowed, "IPv4 localhost exhausted");

        // IPv6 localhost should be independent
        let r = limiter.check_ip(v6).await;
        assert!(r.allowed, "IPv6 localhost should be independent of IPv4");
    }

    // =========================================================================
    // 8. Degraded mode — verify conservative limits when Redis is down
    // =========================================================================

    #[tokio::test]
    async fn degraded_mode_applies_divisor_to_limits() {
        // With per_ip_limit=100 and divisor=10, local fallback allows only 10.
        let mut limiter = DistributedRateLimiter::new(RateLimitConfig {
            per_ip_limit: 100,
            per_user_limit: 50,
            window_secs: 60,
            burst_size: 200,
            refill_rate: 1.0,
            redis_url: None,
        })
        .await;
        limiter.degraded_limit_divisor = 10;
        limiter.redis_required = false;

        let ip: IpAddr = "10.99.0.1".parse().unwrap();

        // Should allow exactly 10 (100 / 10)
        for i in 0..10 {
            let r = limiter.check_ip(ip).await;
            assert!(r.allowed, "degraded request {i} should be allowed (limit=10)");
        }
        // 11th should be denied
        let r = limiter.check_ip(ip).await;
        assert!(!r.allowed, "11th request should be denied in degraded mode (limit=10)");
    }

    #[tokio::test]
    async fn degraded_divisor_never_allows_zero() {
        // Even with divisor > limit, at least 1 request should be allowed
        let mut limiter = DistributedRateLimiter::new(RateLimitConfig {
            per_ip_limit: 3,
            per_user_limit: 3,
            window_secs: 60,
            burst_size: 100,
            refill_rate: 1.0,
            redis_url: None,
        })
        .await;
        limiter.degraded_limit_divisor = 100; // 3/100 = 0, but .max(1) → 1
        limiter.redis_required = false;

        let ip: IpAddr = "10.99.0.2".parse().unwrap();
        let r = limiter.check_ip(ip).await;
        assert!(r.allowed, "at least 1 request must be allowed (max(1))");

        let r = limiter.check_ip(ip).await;
        assert!(!r.allowed, "2nd request denied with effective limit of 1");
    }

    #[tokio::test]
    async fn empty_username_is_a_valid_key() {
        let limiter = local_limiter(100, 1, 60, 100).await;

        let r = limiter.check_user("").await;
        assert!(r.allowed);
        let r = limiter.check_user("").await;
        assert!(!r.allowed, "empty username should still be rate limited");

        // Non-empty user should be independent
        let r = limiter.check_user("notempty").await;
        assert!(r.allowed);
    }

    #[tokio::test]
    async fn concurrent_requests_from_same_ip_are_serialized() {
        // Verify that concurrent access does not cause data races or
        // allow more requests than the limit.
        let limiter = Arc::new(local_limiter(10, 100, 60, 100).await);
        let ip: IpAddr = "10.0.0.20".parse().unwrap();

        let mut handles = Vec::new();
        for _ in 0..20 {
            let lim = limiter.clone();
            handles.push(tokio::spawn(async move { lim.check_ip(ip).await }));
        }

        let mut allowed = 0;
        let mut denied = 0;
        for h in handles {
            let r = h.await.unwrap();
            if r.allowed {
                allowed += 1;
            } else {
                denied += 1;
            }
        }

        assert_eq!(allowed, 10, "exactly 10 should be allowed (limit=10)");
        assert_eq!(denied, 10, "exactly 10 should be denied");
    }
}
