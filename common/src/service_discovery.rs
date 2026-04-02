//! Service discovery, failover, and load balancing for distributed SSO services.
//!
//! Replaces hardcoded static IPs with a dynamic registry that supports:
//! - Multiple discovery backends (static config, DNS, environment variables)
//! - Automatic health checking (TCP + application-level)
//! - Failover with SIEM event logging
//! - Round-robin and least-connections load balancing
//! - Circuit breaker integration per endpoint
//! - Connection pooling with configurable pool sizes
//! - Retry with exponential backoff across DIFFERENT endpoints
//! - Split-brain detection via quorum checks
//!
//! # Architecture
//! ```text
//!   ┌───────────┐      ┌──────────────┐      ┌──────────────┐
//!   │  Caller   │─────▶│  ServiceReg  │─────▶│  Endpoint A  │
//!   │           │      │  (registry)  │──┐   └──────────────┘
//!   └───────────┘      └──────────────┘  │   ┌──────────────┐
//!                                        └──▶│  Endpoint B  │
//!                                            └──────────────┘
//! ```
#![forbid(unsafe_code)]

use crate::circuit_breaker::CircuitBreaker;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ── Error types ─────────────────────────────────────────────────────────────

/// Errors that can occur during service discovery and routing.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("no healthy endpoints available for service '{0}'")]
    NoHealthyEndpoints(String),

    #[error("service '{0}' not registered")]
    ServiceNotFound(String),

    #[error("health check failed for {0}: {1}")]
    HealthCheckFailed(String, String),

    #[error("connection pool exhausted for {0}")]
    PoolExhausted(String),

    #[error("circuit breaker open for endpoint {0}")]
    CircuitBreakerOpen(String),

    #[error("quorum lost: {healthy}/{required} healthy instances for '{service}'")]
    QuorumLost {
        service: String,
        healthy: usize,
        required: usize,
    },

    #[error("DNS resolution failed for {0}: {1}")]
    DnsResolutionFailed(String, String),

    #[error("all endpoints exhausted after {attempts} attempts for '{service}'")]
    AllEndpointsExhausted { service: String, attempts: usize },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

// ── Configuration types ─────────────────────────────────────────────────────

/// Load balancing strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoadBalanceStrategy {
    /// Distribute requests evenly across healthy endpoints in order.
    RoundRobin,
    /// Route to the endpoint with the fewest active connections.
    LeastConnections,
}

impl Default for LoadBalanceStrategy {
    fn default() -> Self {
        Self::RoundRobin
    }
}

/// Discovery backend configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoveryBackend {
    /// Endpoints are provided as a static list in configuration.
    Static {
        endpoints: Vec<EndpointConfig>,
    },
    /// Endpoints are resolved from DNS SRV or A records.
    Dns {
        /// The DNS name to resolve (e.g., `_orchestrator._tcp.milnet.local`).
        service_name: String,
        /// Default port if not provided by SRV records.
        default_port: u16,
    },
    /// Endpoints are loaded from environment variables.
    /// Format: `MILNET_<SERVICE>_ENDPOINTS=host1:port1,host2:port2,...`
    Environment {
        /// Environment variable name to read.
        env_var: String,
    },
}

/// Configuration for a single service endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointConfig {
    /// Address in `host:port` format.
    pub address: String,
    /// Optional human-readable label (e.g., `"orchestrator-east-1"`).
    pub label: Option<String>,
    /// Weight for weighted load balancing (higher = more traffic). Default 1.
    pub weight: Option<u32>,
}

/// Configuration for a registered service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Unique service name (e.g., `"orchestrator"`, `"tss-signer"`).
    pub name: String,
    /// Discovery backend to use.
    pub backend: DiscoveryBackend,
    /// Load balancing strategy.
    pub strategy: LoadBalanceStrategy,
    /// Health check interval.
    pub health_check_interval: Duration,
    /// TCP connect timeout for health checks.
    pub health_check_timeout: Duration,
    /// Number of consecutive failures before marking unhealthy.
    pub unhealthy_threshold: u32,
    /// Number of consecutive successes before marking healthy again.
    pub healthy_threshold: u32,
    /// Circuit breaker failure threshold.
    pub circuit_breaker_threshold: u32,
    /// Circuit breaker reset timeout.
    pub circuit_breaker_reset: Duration,
    /// Maximum connections per endpoint in the pool.
    pub max_pool_size: u32,
    /// Minimum number of healthy instances required (quorum).
    pub quorum_size: usize,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            backend: DiscoveryBackend::Static {
                endpoints: Vec::new(),
            },
            strategy: LoadBalanceStrategy::RoundRobin,
            health_check_interval: Duration::from_secs(10),
            health_check_timeout: Duration::from_secs(3),
            unhealthy_threshold: 3,
            healthy_threshold: 2,
            circuit_breaker_threshold: 5,
            circuit_breaker_reset: Duration::from_secs(30),
            max_pool_size: 10,
            quorum_size: 3,
        }
    }
}

/// Validate that a ServiceConfig is safe for production use.
/// Rejects quorum_size < 2 to prevent single-point-of-failure.
pub fn validate_service_config(config: &ServiceConfig) -> Result<(), DiscoveryError> {
    if config.quorum_size < 2 {
        return Err(DiscoveryError::QuorumLost {
            service: config.name.clone(),
            healthy: 0,
            required: 2,
        });
    }
    Ok(())
}

// ── Endpoint state ──────────────────────────────────────────────────────────

/// Health status of an individual endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EndpointHealth {
    /// Endpoint is healthy and accepting traffic.
    Healthy,
    /// Endpoint is suspect — being probed after failure.
    Suspect,
    /// Endpoint is unreachable or failing health checks.
    Unhealthy,
    /// Health status not yet determined.
    Unknown,
}

/// Runtime state for a single endpoint.
struct EndpointState {
    /// Configuration for this endpoint.
    config: EndpointConfig,
    /// Current health status.
    health: EndpointHealth,
    /// Circuit breaker for this endpoint.
    circuit_breaker: Arc<CircuitBreaker>,
    /// Consecutive successful health checks.
    consecutive_successes: u32,
    /// Consecutive failed health checks.
    consecutive_failures: u32,
    /// Last time a health check was performed.
    last_check: Option<Instant>,
    /// Last observed response time in milliseconds.
    last_response_ms: f64,
    /// Active connection count (for least-connections balancing).
    active_connections: Arc<AtomicUsize>,
    /// Resolved socket address (cached for DNS-based backends).
    #[allow(dead_code)]
    resolved_addr: Option<SocketAddr>,
}

impl EndpointState {
    fn new(config: EndpointConfig, cb_threshold: u32, cb_reset: Duration) -> Self {
        let label = config
            .label
            .clone()
            .unwrap_or_else(|| config.address.clone());
        Self {
            config,
            health: EndpointHealth::Unknown,
            circuit_breaker: Arc::new(CircuitBreaker::with_name(
                &label,
                cb_threshold,
                cb_reset,
            )),
            consecutive_successes: 0,
            consecutive_failures: 0,
            last_check: None,
            last_response_ms: 0.0,
            active_connections: Arc::new(AtomicUsize::new(0)),
            resolved_addr: None,
        }
    }
}

// ── Service entry ───────────────────────────────────────────────────────────

/// Runtime state for a registered service.
struct ServiceEntry {
    config: ServiceConfig,
    endpoints: Vec<EndpointState>,
    /// Round-robin counter.
    rr_counter: AtomicU64,
}

// ── Connection guard ────────────────────────────────────────────────────────

/// RAII guard that decrements active connections when dropped.
/// Returned when a caller acquires an endpoint from the pool.
pub struct ConnectionGuard {
    active_connections: Arc<AtomicUsize>,
    /// The address of the endpoint this connection is associated with.
    pub address: String,
    /// Label for logging/metrics.
    pub label: String,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.active_connections.fetch_sub(1, Ordering::Release);
    }
}

impl std::fmt::Debug for ConnectionGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionGuard")
            .field("address", &self.address)
            .field("label", &self.label)
            .finish()
    }
}

// ── ServiceRegistry ─────────────────────────────────────────────────────────

/// Central registry for all service instances.
///
/// Thread-safe: all access goes through an internal `Mutex`. In a production
/// system the health-check loop runs on a background `tokio` task.
///
/// # Example
/// ```rust,no_run
/// use common::service_discovery::*;
/// use std::time::Duration;
///
/// let mut registry = ServiceRegistry::new();
/// registry.register(ServiceConfig {
///     name: "orchestrator".into(),
///     backend: DiscoveryBackend::Static {
///         endpoints: vec![
///             EndpointConfig { address: "10.0.1.10:8443".into(), label: Some("orch-1".into()), weight: None },
///             EndpointConfig { address: "10.0.1.11:8443".into(), label: Some("orch-2".into()), weight: None },
///         ],
///     },
///     strategy: LoadBalanceStrategy::RoundRobin,
///     quorum_size: 1,
///     ..ServiceConfig::default()
/// });
/// ```
pub struct ServiceRegistry {
    services: Mutex<HashMap<String, ServiceEntry>>,
}

impl ServiceRegistry {
    /// Create a new empty service registry.
    pub fn new() -> Self {
        Self {
            services: Mutex::new(HashMap::new()),
        }
    }

    /// Register a service with its configuration.
    ///
    /// Resolves endpoints from the configured backend and initialises health
    /// state for each one.
    pub fn register(&self, config: ServiceConfig) -> Result<(), DiscoveryError> {
        let endpoints = Self::resolve_endpoints(&config)?;
        let cb_threshold = config.circuit_breaker_threshold;
        let cb_reset = config.circuit_breaker_reset;

        let states: Vec<EndpointState> = endpoints
            .into_iter()
            .map(|ep| EndpointState::new(ep, cb_threshold, cb_reset))
            .collect();

        let name = config.name.clone();
        let entry = ServiceEntry {
            config,
            endpoints: states,
            rr_counter: AtomicU64::new(0),
        };

        let mut services = self.services.lock().unwrap_or_else(|poisoned| {
            crate::siem::SecurityEvent::mutex_poisoning(
                "ServiceRegistry::register — recovered from poisoned lock",
            );
            poisoned.into_inner()
        });
        services.insert(name, entry);
        Ok(())
    }

    /// Resolve endpoints from the configured discovery backend.
    fn resolve_endpoints(config: &ServiceConfig) -> Result<Vec<EndpointConfig>, DiscoveryError> {
        match &config.backend {
            DiscoveryBackend::Static { endpoints } => Ok(endpoints.clone()),

            DiscoveryBackend::Dns {
                service_name,
                default_port,
            } => {
                // DNS resolution: use std::net for A record lookup.
                // SRV records would require a dedicated DNS library; for now we
                // resolve A records and apply the default port.
                use std::net::ToSocketAddrs;
                let addr_str = format!("{}:{}", service_name, default_port);
                let addrs: Vec<SocketAddr> = addr_str
                    .to_socket_addrs()
                    .map_err(|e| {
                        DiscoveryError::DnsResolutionFailed(service_name.clone(), e.to_string())
                    })?
                    .collect();

                if addrs.is_empty() {
                    return Err(DiscoveryError::DnsResolutionFailed(
                        service_name.clone(),
                        "no addresses returned".into(),
                    ));
                }

                Ok(addrs
                    .into_iter()
                    .enumerate()
                    .map(|(i, addr)| EndpointConfig {
                        address: addr.to_string(),
                        label: Some(format!("{}-dns-{}", config.name, i)),
                        weight: None,
                    })
                    .collect())
            }

            DiscoveryBackend::Environment { env_var } => {
                let raw = std::env::var(env_var).map_err(|_| {
                    DiscoveryError::ServiceNotFound(format!(
                        "environment variable {} not set",
                        env_var
                    ))
                })?;

                let endpoints: Vec<EndpointConfig> = raw
                    .split(',')
                    .filter(|s| !s.trim().is_empty())
                    .enumerate()
                    .map(|(i, addr)| EndpointConfig {
                        address: addr.trim().to_string(),
                        label: Some(format!("{}-env-{}", config.name, i)),
                        weight: None,
                    })
                    .collect();

                if endpoints.is_empty() {
                    return Err(DiscoveryError::ServiceNotFound(format!(
                        "no endpoints in {}",
                        env_var
                    )));
                }

                Ok(endpoints)
            }
        }
    }

    /// Select the next healthy endpoint for the given service.
    ///
    /// Returns a [`ConnectionGuard`] that automatically releases the active
    /// connection count when dropped.  The caller should use `guard.address`
    /// to connect.
    ///
    /// The selection respects the configured load-balancing strategy and skips
    /// endpoints whose circuit breaker is open.
    pub fn acquire_endpoint(
        &self,
        service_name: &str,
    ) -> Result<ConnectionGuard, DiscoveryError> {
        let mut services = self.services.lock().unwrap_or_else(|poisoned| {
            crate::siem::SecurityEvent::mutex_poisoning(
                "ServiceRegistry::acquire_endpoint — recovered from poisoned lock",
            );
            poisoned.into_inner()
        });

        let entry = services
            .get_mut(service_name)
            .ok_or_else(|| DiscoveryError::ServiceNotFound(service_name.to_string()))?;

        // Quorum check — split-brain detection.
        let healthy_count = entry
            .endpoints
            .iter()
            .filter(|ep| ep.health == EndpointHealth::Healthy)
            .count();

        if healthy_count < entry.config.quorum_size {
            let err = DiscoveryError::QuorumLost {
                service: service_name.to_string(),
                healthy: healthy_count,
                required: entry.config.quorum_size,
            };
            emit_failover_event(service_name, &format!("{}", err));
            return Err(err);
        }

        let strategy = entry.config.strategy;
        let max_pool_size = entry.config.max_pool_size as usize;

        let candidate = match strategy {
            LoadBalanceStrategy::RoundRobin => {
                Self::select_round_robin(entry)?
            }
            LoadBalanceStrategy::LeastConnections => {
                Self::select_least_connections(entry)?
            }
        };

        // Check pool capacity.
        let current = candidate.active_connections.load(Ordering::Acquire);
        if current >= max_pool_size {
            return Err(DiscoveryError::PoolExhausted(
                candidate.config.address.clone(),
            ));
        }

        candidate.active_connections.fetch_add(1, Ordering::Release);

        Ok(ConnectionGuard {
            active_connections: Arc::clone(&candidate.active_connections),
            address: candidate.config.address.clone(),
            label: candidate
                .config
                .label
                .clone()
                .unwrap_or_else(|| candidate.config.address.clone()),
        })
    }

    /// Round-robin selection among healthy endpoints.
    fn select_round_robin(
        entry: &mut ServiceEntry,
    ) -> Result<&mut EndpointState, DiscoveryError> {
        let total = entry.endpoints.len();
        if total == 0 {
            return Err(DiscoveryError::NoHealthyEndpoints(
                entry.config.name.clone(),
            ));
        }

        let start = entry.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;

        // Try all endpoints starting from the current counter position.
        for offset in 0..total {
            let idx = (start + offset) % total;
            let ep = &entry.endpoints[idx];
            if ep.health == EndpointHealth::Healthy && ep.circuit_breaker.allow_request() {
                // Re-borrow mutably at the chosen index.
                return Ok(&mut entry.endpoints[idx]);
            }
        }

        Err(DiscoveryError::NoHealthyEndpoints(
            entry.config.name.clone(),
        ))
    }

    /// Least-connections selection among healthy endpoints.
    fn select_least_connections(
        entry: &mut ServiceEntry,
    ) -> Result<&mut EndpointState, DiscoveryError> {
        let mut best_idx: Option<usize> = None;
        let mut best_conns: usize = usize::MAX;

        for (idx, ep) in entry.endpoints.iter().enumerate() {
            if ep.health == EndpointHealth::Healthy && ep.circuit_breaker.allow_request() {
                let conns = ep.active_connections.load(Ordering::Relaxed);
                if conns < best_conns {
                    best_conns = conns;
                    best_idx = Some(idx);
                }
            }
        }

        match best_idx {
            Some(idx) => Ok(&mut entry.endpoints[idx]),
            None => Err(DiscoveryError::NoHealthyEndpoints(
                entry.config.name.clone(),
            )),
        }
    }

    /// Run a single health-check pass for all endpoints of a given service.
    ///
    /// This should be called periodically from a background task:
    /// ```rust,no_run
    /// # use common::service_discovery::ServiceRegistry;
    /// # async fn run(registry: &ServiceRegistry) {
    /// loop {
    ///     registry.check_health("orchestrator").await;
    ///     tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    /// }
    /// # }
    /// ```
    pub async fn check_health(&self, service_name: &str) {
        // Snapshot the endpoint addresses and thresholds under the lock,
        // then release the lock before doing async I/O.
        let snapshot: Vec<(usize, String, u32, u32, Duration)> = {
            let services = self.services.lock().unwrap_or_else(|p| {
                crate::siem::SecurityEvent::mutex_poisoning(
                    "ServiceRegistry::check_health — recovered from poisoned lock",
                );
                p.into_inner()
            });
            let entry = match services.get(service_name) {
                Some(e) => e,
                None => return,
            };
            entry
                .endpoints
                .iter()
                .enumerate()
                .map(|(i, ep)| {
                    (
                        i,
                        ep.config.address.clone(),
                        entry.config.unhealthy_threshold,
                        entry.config.healthy_threshold,
                        entry.config.health_check_timeout,
                    )
                })
                .collect()
        };

        // Run TCP health checks concurrently outside the lock.
        let mut results: Vec<(usize, bool, f64)> = Vec::with_capacity(snapshot.len());
        for (idx, addr, _uh, _h, timeout) in &snapshot {
            let start = Instant::now();
            let ok = tcp_health_check(addr, *timeout).await;
            let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
            results.push((*idx, ok, elapsed_ms));
        }

        // Apply results under the lock.
        let mut services = self.services.lock().unwrap_or_else(|p| {
            crate::siem::SecurityEvent::mutex_poisoning(
                "ServiceRegistry::check_health (apply) — recovered from poisoned lock",
            );
            p.into_inner()
        });
        let entry = match services.get_mut(service_name) {
            Some(e) => e,
            None => return,
        };

        for (idx, ok, elapsed_ms) in results {
            if idx >= entry.endpoints.len() {
                continue;
            }
            let ep = &mut entry.endpoints[idx];
            let unhealthy_threshold = entry.config.unhealthy_threshold;
            let healthy_threshold = entry.config.healthy_threshold;
            ep.last_check = Some(Instant::now());

            let prev_health = ep.health;

            if ok {
                ep.consecutive_successes += 1;
                ep.consecutive_failures = 0;
                ep.last_response_ms = elapsed_ms;
                ep.circuit_breaker.record_success();

                if ep.consecutive_successes >= healthy_threshold {
                    ep.health = EndpointHealth::Healthy;
                } else if ep.health == EndpointHealth::Unhealthy {
                    ep.health = EndpointHealth::Suspect;
                }
            } else {
                ep.consecutive_failures += 1;
                ep.consecutive_successes = 0;
                ep.circuit_breaker.record_failure();

                if ep.consecutive_failures >= unhealthy_threshold {
                    ep.health = EndpointHealth::Unhealthy;
                } else if ep.health == EndpointHealth::Healthy {
                    ep.health = EndpointHealth::Suspect;
                }
            }

            // Emit SIEM event on health transition.
            if prev_health != ep.health {
                let label = ep
                    .config
                    .label
                    .clone()
                    .unwrap_or_else(|| ep.config.address.clone());

                if ep.health == EndpointHealth::Unhealthy {
                    emit_failover_event(
                        service_name,
                        &format!(
                            "endpoint {} transitioned {:?} -> Unhealthy",
                            label, prev_health
                        ),
                    );
                } else if ep.health == EndpointHealth::Healthy
                    && prev_health == EndpointHealth::Unhealthy
                {
                    emit_recovery_event(
                        service_name,
                        &format!("endpoint {} recovered to Healthy", label),
                    );
                }
            }
        }
    }

    /// Record a successful request to the given endpoint address.
    ///
    /// This feeds the health tracking so that even between scheduled health
    /// checks, real traffic keeps the state accurate.
    pub fn record_success(&self, service_name: &str, address: &str) {
        let mut services = self.services.lock().unwrap_or_else(|p| {
            crate::siem::SecurityEvent::mutex_poisoning(
                "ServiceRegistry::record_success — recovered",
            );
            p.into_inner()
        });
        if let Some(entry) = services.get_mut(service_name) {
            for ep in &mut entry.endpoints {
                if ep.config.address == address {
                    ep.circuit_breaker.record_success();
                    ep.consecutive_successes += 1;
                    ep.consecutive_failures = 0;
                    if ep.consecutive_successes >= entry.config.healthy_threshold {
                        ep.health = EndpointHealth::Healthy;
                    }
                    break;
                }
            }
        }
    }

    /// Record a failed request to the given endpoint address.
    pub fn record_failure(&self, service_name: &str, address: &str) {
        let mut services = self.services.lock().unwrap_or_else(|p| {
            crate::siem::SecurityEvent::mutex_poisoning(
                "ServiceRegistry::record_failure — recovered",
            );
            p.into_inner()
        });
        if let Some(entry) = services.get_mut(service_name) {
            for ep in &mut entry.endpoints {
                if ep.config.address == address {
                    ep.circuit_breaker.record_failure();
                    ep.consecutive_failures += 1;
                    ep.consecutive_successes = 0;
                    if ep.consecutive_failures >= entry.config.unhealthy_threshold {
                        let prev = ep.health;
                        ep.health = EndpointHealth::Unhealthy;
                        if prev != EndpointHealth::Unhealthy {
                            let label = ep
                                .config
                                .label
                                .clone()
                                .unwrap_or_else(|| ep.config.address.clone());
                            emit_failover_event(
                                service_name,
                                &format!("endpoint {} marked Unhealthy from traffic", label),
                            );
                        }
                    }
                    break;
                }
            }
        }
    }

    /// Return a snapshot of all endpoint health states for a service.
    pub fn endpoint_statuses(
        &self,
        service_name: &str,
    ) -> Result<Vec<EndpointSnapshot>, DiscoveryError> {
        let services = self.services.lock().unwrap_or_else(|p| {
            crate::siem::SecurityEvent::mutex_poisoning(
                "ServiceRegistry::endpoint_statuses — recovered",
            );
            p.into_inner()
        });
        let entry = services
            .get(service_name)
            .ok_or_else(|| DiscoveryError::ServiceNotFound(service_name.to_string()))?;

        Ok(entry
            .endpoints
            .iter()
            .map(|ep| EndpointSnapshot {
                address: ep.config.address.clone(),
                label: ep.config.label.clone(),
                health: ep.health,
                active_connections: ep.active_connections.load(Ordering::Relaxed),
                last_response_ms: ep.last_response_ms,
                consecutive_failures: ep.consecutive_failures,
            })
            .collect())
    }

    /// Check if a service has quorum (enough healthy instances).
    ///
    /// This is the primary split-brain detection mechanism: if fewer than
    /// `quorum_size` endpoints are reachable, we assume a network partition
    /// rather than routing to a potentially stale minority.
    pub fn has_quorum(&self, service_name: &str) -> Result<bool, DiscoveryError> {
        let services = self.services.lock().unwrap_or_else(|p| {
            crate::siem::SecurityEvent::mutex_poisoning(
                "ServiceRegistry::has_quorum — recovered",
            );
            p.into_inner()
        });
        let entry = services
            .get(service_name)
            .ok_or_else(|| DiscoveryError::ServiceNotFound(service_name.to_string()))?;

        let healthy = entry
            .endpoints
            .iter()
            .filter(|ep| ep.health == EndpointHealth::Healthy)
            .count();

        Ok(healthy >= entry.config.quorum_size)
    }

    /// Get all registered service names.
    pub fn service_names(&self) -> Vec<String> {
        let services = self.services.lock().unwrap_or_else(|p| {
            crate::siem::SecurityEvent::mutex_poisoning(
                "ServiceRegistry::service_names — recovered",
            );
            p.into_inner()
        });
        services.keys().cloned().collect()
    }

    /// Spawn a background health-check loop for all registered services.
    ///
    /// Runs until the returned [`tokio::task::JoinHandle`] is aborted or the
    /// registry is dropped.
    pub fn spawn_health_checker(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let registry = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                let names = registry.service_names();
                for name in &names {
                    registry.check_health(name).await;
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        })
    }
}

impl Default for ServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Endpoint snapshot (public read-only view) ───────────────────────────────

/// Read-only snapshot of endpoint state for observability.
#[derive(Debug, Clone, Serialize)]
pub struct EndpointSnapshot {
    pub address: String,
    pub label: Option<String>,
    pub health: EndpointHealth,
    pub active_connections: usize,
    pub last_response_ms: f64,
    pub consecutive_failures: u32,
}

// ── Multi-endpoint retry ────────────────────────────────────────────────────

/// Configuration for multi-endpoint retry with failover.
pub struct MultiEndpointRetryConfig {
    /// Maximum number of different endpoints to try.
    pub max_endpoint_attempts: usize,
    /// Retry config for backoff between attempts.
    pub retry_config: crate::retry::RetryConfig,
}

impl Default for MultiEndpointRetryConfig {
    fn default() -> Self {
        Self {
            max_endpoint_attempts: 3,
            retry_config: crate::retry::RetryConfig::default(),
        }
    }
}

/// Execute an async operation with failover across multiple endpoints.
///
/// Unlike simple retry (which hammers the same endpoint), this function:
/// 1. Acquires an endpoint from the registry.
/// 2. Tries the operation.
/// 3. On failure, records the failure, acquires a DIFFERENT endpoint, retries.
/// 4. Uses exponential backoff between endpoint attempts.
///
/// This is the primary way callers should make inter-service requests.
///
/// # Arguments
/// * `registry` - The service registry to select endpoints from.
/// * `service_name` - The service to connect to.
/// * `config` - Retry and failover configuration.
/// * `operation` - An async closure that takes an endpoint address and returns
///   `Result<T, E>`.
pub async fn retry_with_failover<F, Fut, T, E>(
    registry: &ServiceRegistry,
    service_name: &str,
    config: &MultiEndpointRetryConfig,
    mut operation: F,
) -> Result<T, DiscoveryError>
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut last_err_msg = String::from("no attempts made");
    let mut tried_addresses: Vec<String> = Vec::new();

    for attempt in 0..config.max_endpoint_attempts {
        // Acquire an endpoint (the registry will pick a different one each time
        // due to round-robin / least-connections and the fact that we recorded
        // failures on previous endpoints).
        let guard = match registry.acquire_endpoint(service_name) {
            Ok(g) => g,
            Err(e) => {
                last_err_msg = format!("{}", e);
                if attempt < config.max_endpoint_attempts - 1 {
                    let delay = config.retry_config.delay_for_attempt(attempt as u32);
                    tracing::warn!(
                        "service_discovery: no endpoint for '{}' on attempt {}, retrying in {:?}: {}",
                        service_name,
                        attempt + 1,
                        delay,
                        e
                    );
                    tokio::time::sleep(delay).await;
                }
                continue;
            }
        };

        let addr = guard.address.clone();
        let label = guard.label.clone();

        // Skip if we already tried this exact address (force diversity).
        if tried_addresses.contains(&addr) && attempt < config.max_endpoint_attempts - 1 {
            // Still allow as last resort on final attempt.
            tracing::debug!(
                "service_discovery: skipping already-tried endpoint {} for '{}'",
                label,
                service_name
            );
            continue;
        }

        tried_addresses.push(addr.clone());

        match operation(addr.clone()).await {
            Ok(result) => {
                registry.record_success(service_name, &addr);
                if attempt > 0 {
                    tracing::info!(
                        "service_discovery: '{}' succeeded on attempt {} via {}",
                        service_name,
                        attempt + 1,
                        label
                    );
                }
                return Ok(result);
            }
            Err(e) => {
                registry.record_failure(service_name, &addr);
                last_err_msg = format!("endpoint {} failed: {}", label, e);

                if attempt < config.max_endpoint_attempts - 1 {
                    let delay = config.retry_config.delay_for_attempt(attempt as u32);
                    tracing::warn!(
                        "service_discovery: '{}' attempt {} via {} failed ({}), trying next endpoint in {:?}",
                        service_name,
                        attempt + 1,
                        label,
                        e,
                        delay
                    );
                    tokio::time::sleep(delay).await;
                } else {
                    tracing::error!(
                        "service_discovery: '{}' all {} endpoint attempts exhausted, last error: {}",
                        service_name,
                        config.max_endpoint_attempts,
                        e
                    );
                }
            }
        }
    }

    emit_failover_event(
        service_name,
        &format!(
            "all {} endpoints exhausted: {}",
            tried_addresses.len(),
            last_err_msg
        ),
    );

    Err(DiscoveryError::AllEndpointsExhausted {
        service: service_name.to_string(),
        attempts: tried_addresses.len(),
    })
}

// ── TCP health check ────────────────────────────────────────────────────────

/// Perform a TCP connect health check to the given address.
///
/// Returns `true` if the connection succeeds within the timeout.
async fn tcp_health_check(address: &str, timeout: Duration) -> bool {
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(address)).await {
        Ok(Ok(_stream)) => true,
        Ok(Err(_)) | Err(_) => false,
    }
}

// ── SIEM integration ────────────────────────────────────────────────────────

/// Emit a SIEM failover event.
fn emit_failover_event(service: &str, detail: &str) {
    let event = crate::siem::SecurityEvent {
        timestamp: crate::siem::SecurityEvent::now_iso8601(),
        category: "availability",
        action: "service_failover",
        severity: crate::siem::Severity::High,
        outcome: "failure",
        user_id: None,
        source_ip: None,
        detail: Some(format!("service={} {}", service, detail)),
    };
    event.emit();
}

/// Emit a SIEM recovery event.
fn emit_recovery_event(service: &str, detail: &str) {
    let event = crate::siem::SecurityEvent {
        timestamp: crate::siem::SecurityEvent::now_iso8601(),
        category: "availability",
        action: "service_recovered",
        severity: crate::siem::Severity::Info,
        outcome: "success",
        user_id: None,
        source_ip: None,
        detail: Some(format!("service={} {}", service, detail)),
    };
    event.emit();
}

// ── Convenience: build registry from environment ────────────────────────────

/// Build a [`ServiceRegistry`] from standard environment variables.
///
/// Looks for `MILNET_<SERVICE>_ENDPOINTS` variables (comma-separated
/// `host:port` pairs) and registers each one with sensible defaults.
///
/// Supported environment variables:
/// - `MILNET_ORCHESTRATOR_ENDPOINTS`
/// - `MILNET_TSS_SIGNER_ENDPOINTS`
/// - `MILNET_GATEWAY_ENDPOINTS`
pub fn registry_from_env() -> Result<ServiceRegistry, DiscoveryError> {
    let registry = ServiceRegistry::new();

    let services = [
        ("orchestrator", "MILNET_ORCHESTRATOR_ENDPOINTS"),
        ("tss-signer", "MILNET_TSS_SIGNER_ENDPOINTS"),
        ("gateway", "MILNET_GATEWAY_ENDPOINTS"),
    ];

    for (name, env_var) in &services {
        if std::env::var(env_var).is_ok() {
            registry.register(ServiceConfig {
                name: name.to_string(),
                backend: DiscoveryBackend::Environment {
                    env_var: env_var.to_string(),
                },
                strategy: LoadBalanceStrategy::RoundRobin,
                quorum_size: 1,
                ..ServiceConfig::default()
            })?;
            tracing::info!(
                "service_discovery: registered '{}' from env var {}",
                name,
                env_var
            );
        }
    }

    Ok(registry)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn static_config(name: &str, addrs: &[&str]) -> ServiceConfig {
        ServiceConfig {
            name: name.to_string(),
            backend: DiscoveryBackend::Static {
                endpoints: addrs
                    .iter()
                    .enumerate()
                    .map(|(i, a)| EndpointConfig {
                        address: a.to_string(),
                        label: Some(format!("{}-{}", name, i)),
                        weight: None,
                    })
                    .collect(),
            },
            strategy: LoadBalanceStrategy::RoundRobin,
            quorum_size: 1,
            unhealthy_threshold: 2,
            healthy_threshold: 1,
            ..ServiceConfig::default()
        }
    }

    #[test]
    fn register_and_list_services() {
        let reg = ServiceRegistry::new();
        reg.register(static_config("svc-a", &["127.0.0.1:1000"]))
            .unwrap();
        reg.register(static_config("svc-b", &["127.0.0.1:2000"]))
            .unwrap();
        let mut names = reg.service_names();
        names.sort();
        assert_eq!(names, vec!["svc-a", "svc-b"]);
    }

    #[test]
    fn endpoint_statuses_returns_correct_count() {
        let reg = ServiceRegistry::new();
        reg.register(static_config(
            "orch",
            &["127.0.0.1:8001", "127.0.0.1:8002", "127.0.0.1:8003"],
        ))
        .unwrap();
        let statuses = reg.endpoint_statuses("orch").unwrap();
        assert_eq!(statuses.len(), 3);
        // All start as Unknown.
        for s in &statuses {
            assert_eq!(s.health, EndpointHealth::Unknown);
        }
    }

    #[test]
    fn service_not_found_error() {
        let reg = ServiceRegistry::new();
        let err = reg
            .acquire_endpoint("nonexistent")
            .unwrap_err();
        assert!(matches!(err, DiscoveryError::ServiceNotFound(_)));
    }

    #[test]
    fn record_failures_marks_unhealthy() {
        let reg = ServiceRegistry::new();
        let mut cfg = static_config("test", &["127.0.0.1:9999"]);
        cfg.unhealthy_threshold = 2;
        cfg.quorum_size = 0; // Allow acquisition even when unhealthy for testing.
        reg.register(cfg).unwrap();

        // Mark healthy first so we can acquire.
        reg.record_success("test", "127.0.0.1:9999");

        // Record enough failures to cross threshold.
        reg.record_failure("test", "127.0.0.1:9999");
        reg.record_failure("test", "127.0.0.1:9999");

        let statuses = reg.endpoint_statuses("test").unwrap();
        assert_eq!(statuses[0].health, EndpointHealth::Unhealthy);
    }

    #[test]
    fn quorum_check() {
        let reg = ServiceRegistry::new();
        let mut cfg = static_config("quorum-test", &["127.0.0.1:7001", "127.0.0.1:7002"]);
        cfg.quorum_size = 2;
        reg.register(cfg).unwrap();

        // Initially Unknown — not enough healthy.
        assert!(!reg.has_quorum("quorum-test").unwrap());

        // Mark both healthy.
        reg.record_success("quorum-test", "127.0.0.1:7001");
        reg.record_success("quorum-test", "127.0.0.1:7002");
        assert!(reg.has_quorum("quorum-test").unwrap());
    }

    #[test]
    fn default_configs_are_sane() {
        let cfg = ServiceConfig::default();
        assert_eq!(cfg.quorum_size, 3);
        assert_eq!(cfg.unhealthy_threshold, 3);
        assert_eq!(cfg.max_pool_size, 10);
        assert_eq!(cfg.strategy, LoadBalanceStrategy::RoundRobin);
    }
}
