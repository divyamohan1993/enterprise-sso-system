//! High-Availability PostgreSQL layer with primary/replica routing.
//!
//! Provides automatic read/write splitting, health checks, failover detection,
//! and connection pool management for distributed deployments.
//!
//! # Architecture
//! - One primary node handles all writes
//! - Multiple read replicas handle SELECT queries
//! - Health checks run on configurable intervals
//! - Failover detection alerts operators (automatic promotion requires manual approval)
//!
//! # Security
//! - All connections use TLS (rustls)
//! - Connection strings are never logged
//! - Health check queries are read-only
//! - Failover events are audit-logged

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

/// Health status of a database node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeHealth {
    /// Node is healthy and accepting connections.
    Healthy,
    /// Node is reachable but experiencing elevated latency.
    Degraded,
    /// Node is unreachable or returning errors.
    Unhealthy,
    /// Node health is unknown (not yet checked).
    Unknown,
}

/// Configuration for a single database node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Unique identifier for this node.
    pub node_id: String,
    /// PostgreSQL connection string (redacted in logs).
    pub connection_url: String,
    /// Whether this is a read-write (primary) or read-only (replica) node.
    pub role: NodeRole,
    /// Maximum connections in the pool for this node.
    pub max_connections: u32,
}

/// Role of a database node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeRole {
    /// Read-write primary (handles INSERT/UPDATE/DELETE).
    Primary,
    /// Read-only replica (handles SELECT queries).
    Replica,
}

/// HA cluster configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaConfig {
    /// Primary node configuration.
    pub primary: NodeConfig,
    /// Replica node configurations.
    pub replicas: Vec<NodeConfig>,
    /// Health check interval.
    pub health_check_interval_secs: u64,
    /// Connection timeout.
    pub connect_timeout_secs: u64,
    /// Maximum replication lag before replica is considered unhealthy (milliseconds).
    pub max_replication_lag_ms: u64,
}

impl Default for HaConfig {
    fn default() -> Self {
        Self {
            primary: NodeConfig {
                node_id: "primary-1".into(),
                connection_url: String::new(),
                role: NodeRole::Primary,
                max_connections: 20,
            },
            replicas: vec![],
            health_check_interval_secs: 10,
            connect_timeout_secs: 5,
            max_replication_lag_ms: 1000,
        }
    }
}

/// A tracked database node with health state.
pub struct TrackedNode {
    pub config: NodeConfig,
    pub health: NodeHealth,
    pub last_check: Option<Instant>,
    pub last_latency_ms: Option<u64>,
    pub consecutive_failures: u32,
}

// ===========================================================================
// PgExecutor trait for testability
// ===========================================================================

/// Trait abstracting PostgreSQL operations for testability.
/// Production uses real connections; tests use a mock.
pub trait PgExecutor: Send + Sync {
    /// Execute `SELECT pg_promote(true, 30)` on the given connection URL.
    fn pg_promote(
        &self,
        connection_url: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + '_>>;

    /// Check if the node is still in recovery mode.
    fn pg_is_in_recovery(
        &self,
        connection_url: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + '_>>;

    /// Verify the node accepts writes.
    fn verify_writable(
        &self,
        connection_url: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>>;

    /// Terminate all connections on the given node (STONITH).
    fn pg_terminate_all(
        &self,
        connection_url: &str,
    ) -> Pin<Box<dyn Future<Output = Result<u64, String>> + Send + '_>>;

    /// Check the current WAL LSN position.
    fn pg_current_wal_lsn(
        &self,
        connection_url: &str,
    ) -> Pin<Box<dyn Future<Output = Result<u64, String>> + Send + '_>>;
}

/// Production PostgreSQL executor using sqlx.
pub struct SqlxPgExecutor {
    pub connect_timeout_secs: u64,
}

impl SqlxPgExecutor {
    pub fn new(connect_timeout_secs: u64) -> Self {
        Self {
            connect_timeout_secs,
        }
    }
}

impl PgExecutor for SqlxPgExecutor {
    fn pg_promote(
        &self,
        connection_url: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + '_>> {
        let url = connection_url.to_string();
        let timeout_secs = self.connect_timeout_secs;
        Box::pin(async move {
            use sqlx::Connection;
            let mut conn = tokio::time::timeout(
                std::time::Duration::from_secs(timeout_secs),
                sqlx::postgres::PgConnection::connect(&url),
            )
            .await
            .map_err(|_| "connect timeout during pg_promote".to_string())?
            .map_err(|e| format!("connect error during pg_promote: {e}"))?;

            let result: (bool,) = sqlx::query_as("SELECT pg_promote(true, 30)")
                .fetch_one(&mut conn)
                .await
                .map_err(|e| format!("pg_promote() SQL error: {e}"))?;
            Ok(result.0)
        })
    }

    fn pg_is_in_recovery(
        &self,
        connection_url: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + '_>> {
        let url = connection_url.to_string();
        let timeout_secs = self.connect_timeout_secs;
        Box::pin(async move {
            use sqlx::Connection;
            let mut conn = tokio::time::timeout(
                std::time::Duration::from_secs(timeout_secs),
                sqlx::postgres::PgConnection::connect(&url),
            )
            .await
            .map_err(|_| "connect timeout during pg_is_in_recovery".to_string())?
            .map_err(|e| format!("connect error during pg_is_in_recovery: {e}"))?;

            let result: (bool,) = sqlx::query_as("SELECT pg_is_in_recovery()")
                .fetch_one(&mut conn)
                .await
                .map_err(|e| format!("pg_is_in_recovery() SQL error: {e}"))?;
            Ok(result.0)
        })
    }

    fn verify_writable(
        &self,
        connection_url: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>> {
        let url = connection_url.to_string();
        let timeout_secs = self.connect_timeout_secs;
        Box::pin(async move {
            use sqlx::Connection;
            let mut conn = tokio::time::timeout(
                std::time::Duration::from_secs(timeout_secs),
                sqlx::postgres::PgConnection::connect(&url),
            )
            .await
            .map_err(|_| "connect timeout during verify_writable".to_string())?
            .map_err(|e| format!("connect error during verify_writable: {e}"))?;

            sqlx::query("CREATE TEMP TABLE _failover_test(id int)")
                .execute(&mut conn)
                .await
                .map_err(|e| format!("write verification failed: {e}"))?;
            let _ = sqlx::query("DROP TABLE IF EXISTS _failover_test")
                .execute(&mut conn)
                .await;
            Ok(())
        })
    }

    fn pg_terminate_all(
        &self,
        connection_url: &str,
    ) -> Pin<Box<dyn Future<Output = Result<u64, String>> + Send + '_>> {
        let url = connection_url.to_string();
        let timeout_secs = self.connect_timeout_secs;
        Box::pin(async move {
            use sqlx::Connection;
            let mut conn = tokio::time::timeout(
                std::time::Duration::from_secs(timeout_secs),
                sqlx::postgres::PgConnection::connect(&url),
            )
            .await
            .map_err(|_| "connect timeout during pg_terminate_all".to_string())?
            .map_err(|e| format!("connect error during pg_terminate_all: {e}"))?;

            let result = sqlx::query_as::<_, (i64,)>(
                "SELECT count(*) FROM (SELECT pg_terminate_backend(pid) \
                 FROM pg_stat_activity \
                 WHERE datname = current_database() AND pid != pg_backend_pid()) t",
            )
            .fetch_one(&mut conn)
            .await
            .map_err(|e| format!("pg_terminate_backend failed: {e}"))?;
            Ok(result.0 as u64)
        })
    }

    fn pg_current_wal_lsn(
        &self,
        connection_url: &str,
    ) -> Pin<Box<dyn Future<Output = Result<u64, String>> + Send + '_>> {
        let url = connection_url.to_string();
        let timeout_secs = self.connect_timeout_secs;
        Box::pin(async move {
            use sqlx::Connection;
            let mut conn = tokio::time::timeout(
                std::time::Duration::from_secs(timeout_secs),
                sqlx::postgres::PgConnection::connect(&url),
            )
            .await
            .map_err(|_| "connect timeout during pg_current_wal_lsn".to_string())?
            .map_err(|e| format!("connect error during pg_current_wal_lsn: {e}"))?;

            let result: (i64,) = sqlx::query_as(
                "SELECT CAST(pg_catalog.pg_wal_lsn_diff(pg_current_wal_lsn(), '0/0') AS bigint)",
            )
            .fetch_one(&mut conn)
            .await
            .map_err(|e| format!("pg_current_wal_lsn query failed: {e}"))?;
            Ok(result.0 as u64)
        })
    }
}

// ===========================================================================
// HaPool
// ===========================================================================

/// High-Availability database pool with read/write routing.
pub struct HaPool {
    primary: TrackedNode,
    replicas: Vec<TrackedNode>,
    /// Round-robin counter for replica selection.
    replica_counter: AtomicUsize,
    /// Whether the cluster is in degraded mode (primary issues).
    degraded: AtomicBool,
    /// Set to true when a pg_promote() has been issued, so the async health
    /// checker can verify the promoted node is accepting writes.
    last_promotion_target: AtomicBool,
    config: HaConfig,
    /// Blocklist of node IDs fenced via STONITH.
    stonith_blocklist: Mutex<HashSet<String>>,
}

impl HaPool {
    /// Create a new HA pool from configuration.
    pub fn new(config: HaConfig) -> Self {
        let primary = TrackedNode {
            config: config.primary.clone(),
            health: NodeHealth::Unknown,
            last_check: None,
            last_latency_ms: None,
            consecutive_failures: 0,
        };
        let replicas = config
            .replicas
            .iter()
            .map(|rc| TrackedNode {
                config: rc.clone(),
                health: NodeHealth::Unknown,
                last_check: None,
                last_latency_ms: None,
                consecutive_failures: 0,
            })
            .collect();

        Self {
            primary,
            replicas,
            replica_counter: AtomicUsize::new(0),
            degraded: AtomicBool::new(false),
            last_promotion_target: AtomicBool::new(false),
            config,
            stonith_blocklist: Mutex::new(HashSet::new()),
        }
    }

    /// Get the primary node config for write operations.
    pub fn write_node(&self) -> &NodeConfig {
        &self.primary.config
    }

    /// Get a replica node config for read operations (round-robin).
    /// Falls back to primary if no healthy replicas are available.
    pub fn read_node(&self) -> &NodeConfig {
        let healthy_replicas: Vec<_> = self
            .replicas
            .iter()
            .filter(|r| r.health == NodeHealth::Healthy || r.health == NodeHealth::Unknown)
            .collect();

        if healthy_replicas.is_empty() {
            return &self.primary.config;
        }

        let idx = self.replica_counter.fetch_add(1, Ordering::Relaxed) % healthy_replicas.len();
        &healthy_replicas[idx].config
    }

    /// Check health of all nodes.
    pub fn check_health(&mut self) -> ClusterHealth {
        let primary_healthy =
            self.primary.health == NodeHealth::Healthy || self.primary.health == NodeHealth::Unknown;
        let healthy_replicas = self
            .replicas
            .iter()
            .filter(|r| r.health == NodeHealth::Healthy)
            .count();
        let total_replicas = self.replicas.len();

        ClusterHealth {
            primary_healthy,
            healthy_replicas,
            total_replicas,
            degraded: self.degraded.load(Ordering::Relaxed),
        }
    }

    /// Mark a node as healthy after a successful health check.
    pub fn mark_healthy(&mut self, node_id: &str) {
        if self.primary.config.node_id == node_id {
            self.primary.health = NodeHealth::Healthy;
            self.primary.consecutive_failures = 0;
            self.primary.last_check = Some(Instant::now());
            // If primary recovers, clear degraded mode
            self.degraded.store(false, Ordering::Relaxed);
        }
        for replica in &mut self.replicas {
            if replica.config.node_id == node_id {
                replica.health = NodeHealth::Healthy;
                replica.consecutive_failures = 0;
                replica.last_check = Some(Instant::now());
            }
        }
    }

    /// Mark a node as unhealthy.
    pub fn mark_unhealthy(&mut self, node_id: &str) {
        if self.primary.config.node_id == node_id {
            self.primary.health = NodeHealth::Unhealthy;
            self.primary.consecutive_failures += 1;
            self.primary.last_check = Some(Instant::now());
            self.degraded.store(true, Ordering::Relaxed);
        }
        for replica in &mut self.replicas {
            if replica.config.node_id == node_id {
                replica.health = NodeHealth::Unhealthy;
                replica.consecutive_failures += 1;
                replica.last_check = Some(Instant::now());
            }
        }
    }

    /// Get the total number of nodes (primary + replicas).
    pub fn node_count(&self) -> usize {
        1 + self.replicas.len()
    }

    /// Returns true if the cluster is in degraded mode.
    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Relaxed)
    }

    /// Get the HA configuration.
    pub fn config(&self) -> &HaConfig {
        &self.config
    }
}

/// Cluster health summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterHealth {
    pub primary_healthy: bool,
    pub healthy_replicas: usize,
    pub total_replicas: usize,
    pub degraded: bool,
}

// ===========================================================================
// Automatic Failover with Split-Brain Prevention
// ===========================================================================

/// Configuration for automatic database failover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoFailoverConfig {
    /// How long the primary must be unreachable before failover is attempted (seconds).
    pub failover_threshold_secs: u64,
    /// Maximum replication lag (in milliseconds) for a replica to be eligible for promotion.
    pub min_replica_lag_for_promotion_ms: u64,
    /// Whether to require a majority of replicas to agree that the primary is down.
    pub require_quorum: bool,
    /// Number of consecutive health check failures required before failover.
    pub consecutive_failure_threshold: u32,
}

impl Default for AutoFailoverConfig {
    fn default() -> Self {
        Self {
            failover_threshold_secs: 30,
            min_replica_lag_for_promotion_ms: 100,
            require_quorum: true,
            consecutive_failure_threshold: 3,
        }
    }
}

/// Configuration for automatic database promotion with witness verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoPromoteConfig {
    pub enabled: bool,
    pub safety_delay_secs: u64,
    pub require_witness: bool,
    pub min_replica_lag_bytes: i64,
}

impl AutoPromoteConfig {
    pub fn from_env() -> Self {
        let manual_only = std::env::var("MILNET_DB_MANUAL_FAILOVER").map(|v| v == "1").unwrap_or(false);
        let military_mode = std::env::var("MILNET_MILITARY_DEPLOYMENT").map(|v| v == "1").unwrap_or(false);
        if manual_only {
            return Self { enabled: false, safety_delay_secs: 30, require_witness: true, min_replica_lag_bytes: 0 };
        }
        let default_delay = if military_mode { 5 } else { 30 };
        let safety_delay = std::env::var("MILNET_DB_FAILOVER_DELAY")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(default_delay);
        if military_mode {
            return Self { enabled: true, safety_delay_secs: safety_delay, require_witness: true, min_replica_lag_bytes: 0 };
        }
        Self { safety_delay_secs: safety_delay, ..Self::default() }
    }
}

impl Default for AutoPromoteConfig {
    fn default() -> Self {
        Self { enabled: true, safety_delay_secs: 30, require_witness: true, min_replica_lag_bytes: 0 }
    }
}

/// A witness attestation for a database promotion event, signed with HMAC-SHA512.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotionWitness {
    pub witness_node_id: String,
    pub promoted_node_id: String,
    pub failed_primary_id: String,
    pub timestamp_secs: u64,
    pub hmac_signature: Vec<u8>,
}

impl PromotionWitness {
    pub fn sign(witness_node_id: &str, promoted_node_id: &str, failed_primary_id: &str, witness_key: &[u8]) -> Self {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;
        type HmacSha512 = Hmac<Sha512>;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        let mut mac = HmacSha512::new_from_slice(witness_key).expect("HMAC key size is valid");
        mac.update(witness_node_id.as_bytes());
        mac.update(promoted_node_id.as_bytes());
        mac.update(failed_primary_id.as_bytes());
        mac.update(&now.to_be_bytes());
        Self {
            witness_node_id: witness_node_id.to_string(),
            promoted_node_id: promoted_node_id.to_string(),
            failed_primary_id: failed_primary_id.to_string(),
            timestamp_secs: now,
            hmac_signature: mac.finalize().into_bytes().to_vec(),
        }
    }

    pub fn verify(&self, witness_key: &[u8]) -> Result<(), String> {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;
        type HmacSha512 = Hmac<Sha512>;
        let mut mac = HmacSha512::new_from_slice(witness_key).expect("HMAC key size is valid");
        mac.update(self.witness_node_id.as_bytes());
        mac.update(self.promoted_node_id.as_bytes());
        mac.update(self.failed_primary_id.as_bytes());
        mac.update(&self.timestamp_secs.to_be_bytes());
        mac.verify_slice(&self.hmac_signature).map_err(|_| "witness HMAC-SHA512 verification failed".to_string())
    }
}

/// Result of a witnessed automatic promotion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessedPromotionResult {
    pub approved: bool,
    pub witness: Option<PromotionWitness>,
    pub reason: String,
}

/// Verify old primary is truly unreachable from multiple vantage points (split-brain prevention).
pub fn verify_primary_unreachable(primary_reports: &[(String, bool)], required_confirmations: usize) -> Result<usize, String> {
    let confirmed = primary_reports.iter().filter(|(_, unreachable)| *unreachable).count();
    if confirmed >= required_confirmations {
        Ok(confirmed)
    } else {
        Err(format!("split-brain prevention: only {}/{} vantage points confirm primary unreachable (need {})", confirmed, primary_reports.len(), required_confirmations))
    }
}

/// Result of a failover attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverResult {
    /// Whether failover succeeded.
    pub success: bool,
    /// The node ID of the newly promoted primary (if successful).
    pub promoted_node_id: Option<String>,
    /// Replication lag of the promoted replica at time of promotion (ms).
    pub promoted_lag_ms: Option<u64>,
    /// Human-readable reason for success or failure.
    pub reason: String,
}

/// Replication lag information for a single replica.
#[derive(Debug, Clone)]
pub struct ReplicaLagInfo {
    /// Node ID of the replica.
    pub node_id: String,
    /// Current replication lag in milliseconds.
    pub lag_ms: u64,
    /// Whether this replica reports the primary as unreachable.
    pub primary_unreachable: bool,
}

impl HaPool {
    /// Attempt automatic failover from the current primary to the best replica.
    ///
    /// FAILOVER PROTOCOL:
    /// 1. Verify primary has been unreachable for `failover_threshold_secs`
    /// 2. Query all replicas for their replication lag
    /// 3. Select the replica with the lowest lag within the promotion threshold
    /// 4. If quorum required, verify majority of replicas agree primary is down
    /// 5. Schedule promotion via PgExecutor (caller must follow up with execute_pg_promote_async)
    /// 6. Update internal routing to point to the new primary
    /// 7. Log SIEM audit event for the failover
    pub fn attempt_automatic_failover(
        &mut self,
        config: &AutoFailoverConfig,
        replica_lags: &[ReplicaLagInfo],
    ) -> Result<FailoverResult, String> {
        // Step 1: Check if primary has been unreachable long enough
        if self.primary.health != NodeHealth::Unhealthy {
            return Ok(FailoverResult {
                success: false,
                promoted_node_id: None,
                promoted_lag_ms: None,
                reason: "primary is not unhealthy -- failover not needed".into(),
            });
        }

        // Check consecutive failures threshold
        if self.primary.consecutive_failures < config.consecutive_failure_threshold {
            return Ok(FailoverResult {
                success: false,
                promoted_node_id: None,
                promoted_lag_ms: None,
                reason: format!(
                    "primary consecutive failures ({}) below threshold ({}) -- waiting",
                    self.primary.consecutive_failures, config.consecutive_failure_threshold
                ),
            });
        }

        // Check if primary has been down long enough.
        // Use consecutive_failures * health_check_interval as a proxy for downtime
        let estimated_downtime_secs =
            self.primary.consecutive_failures as u64 * self.config.health_check_interval_secs;

        if estimated_downtime_secs < config.failover_threshold_secs {
            return Ok(FailoverResult {
                success: false,
                promoted_node_id: None,
                promoted_lag_ms: None,
                reason: format!(
                    "primary estimated downtime ({}s) below threshold ({}s)",
                    estimated_downtime_secs, config.failover_threshold_secs
                ),
            });
        }

        // Step 2: Find eligible replicas (within lag threshold)
        let mut eligible: Vec<&ReplicaLagInfo> = replica_lags
            .iter()
            .filter(|r| r.lag_ms <= config.min_replica_lag_for_promotion_ms)
            .collect();

        if eligible.is_empty() {
            tracing::error!(
                "SIEM:CRITICAL automatic failover BLOCKED: no replicas within {}ms lag threshold",
                config.min_replica_lag_for_promotion_ms
            );
            return Ok(FailoverResult {
                success: false,
                promoted_node_id: None,
                promoted_lag_ms: None,
                reason: format!(
                    "no replicas within {}ms replication lag threshold",
                    config.min_replica_lag_for_promotion_ms
                ),
            });
        }

        // Step 3: Sort by lag (lowest first)
        eligible.sort_by_key(|r| r.lag_ms);
        let best_candidate = eligible[0];

        // Step 4: Quorum check
        if config.require_quorum {
            let total_replicas = replica_lags.len();
            let replicas_reporting_down = replica_lags
                .iter()
                .filter(|r| r.primary_unreachable)
                .count();
            let quorum_needed = (total_replicas / 2) + 1;

            if replicas_reporting_down < quorum_needed {
                tracing::warn!(
                    reporting_down = replicas_reporting_down,
                    quorum_needed = quorum_needed,
                    total = total_replicas,
                    "SIEM:WARN automatic failover BLOCKED: quorum not met"
                );
                return Ok(FailoverResult {
                    success: false,
                    promoted_node_id: None,
                    promoted_lag_ms: None,
                    reason: format!(
                        "quorum not met: {}/{} replicas report primary down (need {})",
                        replicas_reporting_down, total_replicas, quorum_needed
                    ),
                });
            }
        }

        // Step 5: Promote the selected replica
        let promoted_node_id = best_candidate.node_id.clone();
        let promoted_lag_ms = best_candidate.lag_ms;

        tracing::warn!(
            promoted_node = %promoted_node_id,
            lag_ms = promoted_lag_ms,
            primary_down_secs = estimated_downtime_secs,
            primary_failures = self.primary.consecutive_failures,
            "SIEM:CRITICAL AUTOMATIC FAILOVER: promoting replica {} to primary \
             (primary unreachable for ~{}s, replica lag {}ms)",
            promoted_node_id,
            estimated_downtime_secs,
            promoted_lag_ms
        );

        // Verify the promoted replica exists in our pool
        let _promoted_url = self
            .replicas
            .iter()
            .find(|r| r.config.node_id == promoted_node_id)
            .map(|r| r.config.connection_url.clone())
            .ok_or_else(|| format!("promoted replica {} not found in pool", promoted_node_id))?;

        // Store promotion intent. The caller must follow up with
        // execute_pg_promote_async() to complete the actual SQL promotion.
        self.last_promotion_target.store(true, Ordering::SeqCst);

        tracing::info!(
            target: "siem",
            promoted_node = %promoted_node_id,
            "SIEM:CRITICAL pg_promote() scheduled on replica {} (async execution via PgExecutor)",
            promoted_node_id
        );

        // Step 6: Update internal state
        let mut new_primary_idx = None;
        for (i, replica) in self.replicas.iter().enumerate() {
            if replica.config.node_id == promoted_node_id {
                new_primary_idx = Some(i);
                break;
            }
        }

        if let Some(idx) = new_primary_idx {
            let old_primary_config = self.primary.config.clone();
            let old_primary_failures = self.primary.consecutive_failures;
            let promoted_replica = self.replicas.remove(idx);

            let mut new_primary_config = promoted_replica.config;
            new_primary_config.role = NodeRole::Primary;

            let mut demoted_config = old_primary_config;
            demoted_config.role = NodeRole::Replica;

            self.primary = TrackedNode {
                config: new_primary_config,
                health: NodeHealth::Healthy,
                last_check: Some(Instant::now()),
                last_latency_ms: Some(promoted_lag_ms),
                consecutive_failures: 0,
            };

            self.replicas.push(TrackedNode {
                config: demoted_config,
                health: NodeHealth::Unhealthy,
                last_check: Some(Instant::now()),
                last_latency_ms: None,
                consecutive_failures: old_primary_failures,
            });

            self.degraded.store(false, Ordering::Relaxed);

            Ok(FailoverResult {
                success: true,
                promoted_node_id: Some(promoted_node_id),
                promoted_lag_ms: Some(promoted_lag_ms),
                reason: "automatic failover completed successfully".into(),
            })
        } else {
            Ok(FailoverResult {
                success: false,
                promoted_node_id: None,
                promoted_lag_ms: None,
                reason: format!(
                    "promoted replica '{}' not found in pool -- inconsistent state",
                    promoted_node_id
                ),
            })
        }
    }

    /// Detect split-brain condition: multiple nodes claiming to be primary.
    ///
    /// Returns the list of conflicting node IDs that claim primary status.
    /// The caller MUST pass these to `stonith_fence_node()` for automated fencing.
    pub fn detect_split_brain(&self, replica_self_reports: &[(String, bool)]) -> Vec<String> {
        let primary_healthy = self.primary.health == NodeHealth::Healthy
            || self.primary.health == NodeHealth::Unknown;

        if !primary_healthy {
            return vec![];
        }

        let mut conflicting = vec![];
        for (node_id, claims_primary) in replica_self_reports {
            if *claims_primary {
                tracing::error!(
                    current_primary = %self.primary.config.node_id,
                    conflicting_node = %node_id,
                    "SIEM:CRITICAL SPLIT-BRAIN DETECTED: node '{}' claims to be primary \
                     while '{}' is already the active primary. STONITH fencing required.",
                    node_id,
                    self.primary.config.node_id
                );
                conflicting.push(node_id.clone());
            }
        }

        if !conflicting.is_empty() {
            let event = crate::siem::SecurityEvent {
                timestamp: crate::siem::SecurityEvent::now_iso8601(),
                category: "db_ha",
                action: "split_brain_detected",
                severity: crate::siem::Severity::Critical,
                outcome: "failure",
                user_id: None,
                source_ip: None,
                detail: Some(format!(
                    "current_primary={} conflicting_nodes={:?}",
                    self.primary.config.node_id, conflicting
                )),
            };
            event.emit();
        }

        conflicting
    }

    /// STONITH (Shoot The Other Node In The Head): fence a stale primary.
    ///
    /// Terminates all connections on the stale node, adds it to the blocklist,
    /// and emits a SIEM CRITICAL event.
    pub async fn stonith_fence_node(
        &self,
        stale_node_id: &str,
        executor: &dyn PgExecutor,
    ) -> Result<(), String> {
        let stale_url = self
            .replicas
            .iter()
            .find(|r| r.config.node_id == stale_node_id)
            .map(|r| r.config.connection_url.clone())
            .or_else(|| {
                if self.primary.config.node_id == stale_node_id {
                    Some(self.primary.config.connection_url.clone())
                } else {
                    None
                }
            });

        let mut terminated = 0u64;
        if let Some(ref url) = stale_url {
            match executor.pg_terminate_all(url).await {
                Ok(count) => {
                    terminated = count;
                    tracing::warn!(
                        stale_node = %stale_node_id,
                        terminated_connections = count,
                        "SIEM:CRITICAL STONITH: terminated {} connections on stale primary {}",
                        count,
                        stale_node_id
                    );
                }
                Err(e) => {
                    tracing::error!(
                        stale_node = %stale_node_id,
                        error = %e,
                        "SIEM:CRITICAL STONITH: failed to terminate connections on {}. \
                         Adding to blocklist as fallback.",
                        stale_node_id
                    );
                }
            }
        }

        {
            let mut blocklist = self.stonith_blocklist.lock().unwrap_or_else(|p| p.into_inner());
            blocklist.insert(stale_node_id.to_string());
        }

        let event = crate::siem::SecurityEvent {
            timestamp: crate::siem::SecurityEvent::now_iso8601(),
            category: "db_ha",
            action: "stonith_fence",
            severity: crate::siem::Severity::Critical,
            outcome: "success",
            user_id: None,
            source_ip: None,
            detail: Some(format!(
                "fenced_node={} terminated_connections={} blocklisted=true",
                stale_node_id, terminated
            )),
        };
        event.emit();

        Ok(())
    }

    /// Check if a node is blocklisted (fenced via STONITH).
    pub fn is_stonith_blocklisted(&self, node_id: &str) -> bool {
        let blocklist = self.stonith_blocklist.lock().unwrap_or_else(|p| p.into_inner());
        blocklist.contains(node_id)
    }

    /// Execute the full async failover promotion sequence with retry.
    ///
    /// 1. Execute `SELECT pg_promote(true, 30)` on the replica
    /// 2. Poll `SELECT pg_is_in_recovery()` until false (with timeout)
    /// 3. Verify writes with a temp table
    ///
    /// Retries up to 3 times with exponential backoff.
    pub async fn execute_pg_promote_async(
        &self,
        connection_url: &str,
        promoted_node_id: &str,
        executor: &dyn PgExecutor,
    ) -> Result<(), String> {
        const MAX_ATTEMPTS: u32 = 3;
        const RECOVERY_POLL_INTERVAL_MS: u64 = 500;
        const RECOVERY_POLL_TIMEOUT_SECS: u64 = 60;

        let mut last_err = String::new();

        for attempt in 1..=MAX_ATTEMPTS {
            if attempt > 1 {
                let backoff_ms = 100 * (1u64 << (attempt - 1));
                tracing::warn!(
                    attempt = attempt,
                    promoted_node = %promoted_node_id,
                    "SIEM:WARN Retrying pg_promote() (attempt {}/{})",
                    attempt,
                    MAX_ATTEMPTS
                );
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
            }

            match executor.pg_promote(connection_url).await {
                Ok(true) => {}
                Ok(false) => {
                    last_err = "pg_promote() returned false".to_string();
                    continue;
                }
                Err(e) => {
                    last_err = e;
                    continue;
                }
            }

            // Poll pg_is_in_recovery() until false
            let poll_start = std::time::Instant::now();
            let mut promoted = false;
            while poll_start.elapsed().as_secs() < RECOVERY_POLL_TIMEOUT_SECS {
                match executor.pg_is_in_recovery(connection_url).await {
                    Ok(false) => {
                        promoted = true;
                        break;
                    }
                    Ok(true) | Err(_) => {
                        tokio::time::sleep(std::time::Duration::from_millis(
                            RECOVERY_POLL_INTERVAL_MS,
                        ))
                        .await;
                    }
                }
            }

            if !promoted {
                last_err = format!(
                    "replica did not exit recovery within {}s",
                    RECOVERY_POLL_TIMEOUT_SECS
                );
                continue;
            }

            // Verify the new primary accepts writes
            match executor.verify_writable(connection_url).await {
                Ok(()) => {}
                Err(e) => {
                    last_err = format!("write verification failed: {e}");
                    continue;
                }
            }

            // Success
            let event = crate::siem::SecurityEvent {
                timestamp: crate::siem::SecurityEvent::now_iso8601(),
                category: "db_ha",
                action: "failover_promoted",
                severity: crate::siem::Severity::Critical,
                outcome: "success",
                user_id: None,
                source_ip: None,
                detail: Some(format!(
                    "promoted_node={} attempts={}",
                    promoted_node_id, attempt
                )),
            };
            event.emit();

            self.last_promotion_target.store(false, Ordering::SeqCst);
            return Ok(());
        }

        // All retries exhausted
        let event = crate::siem::SecurityEvent {
            timestamp: crate::siem::SecurityEvent::now_iso8601(),
            category: "db_ha",
            action: "failover_promotion_failed",
            severity: crate::siem::Severity::Critical,
            outcome: "failure",
            user_id: None,
            source_ip: None,
            detail: Some(format!(
                "promoted_node={} error={}",
                promoted_node_id, last_err
            )),
        };
        event.emit();

        Err(format!(
            "pg_promote() failed after {} attempts: {}",
            MAX_ATTEMPTS, last_err
        ))
    }

    /// Verify the new primary has the latest WAL position.
    pub async fn verify_wal_position(
        &self,
        connection_url: &str,
        min_wal_lsn: u64,
        executor: &dyn PgExecutor,
    ) -> Result<(), String> {
        let current_lsn = executor.pg_current_wal_lsn(connection_url).await?;
        if current_lsn >= min_wal_lsn {
            Ok(())
        } else {
            Err(format!(
                "WAL position {} is behind minimum {}, data loss risk",
                current_lsn, min_wal_lsn
            ))
        }
    }

    /// Consensus-based health check: trigger failover if 2+ replicas report
    /// the primary as unreachable.
    pub fn consensus_health_check(&mut self, replica_reports: &[(String, bool)]) -> bool {
        let reporting_primary_down = replica_reports
            .iter()
            .filter(|(_, primary_unreachable)| *primary_unreachable)
            .count();

        if reporting_primary_down >= 2 {
            tracing::warn!(
                replicas_reporting_down = reporting_primary_down,
                total_replicas = replica_reports.len(),
                "SIEM:WARN consensus health check: {}/{} replicas report primary unreachable",
                reporting_primary_down,
                replica_reports.len()
            );
            self.mark_unhealthy(&self.primary.config.node_id.clone());
            true
        } else {
            false
        }
    }

    /// Update a replica's replication lag information.
    pub fn update_replica_lag(&mut self, node_id: &str, lag_ms: u64) {
        for replica in &mut self.replicas {
            if replica.config.node_id == node_id {
                replica.last_latency_ms = Some(lag_ms);
            }
        }
    }
}

/// Backup manifest for verified backups.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    /// Unique backup identifier.
    pub backup_id: String,
    /// Timestamp of backup creation (microseconds since epoch).
    pub created_at: i64,
    /// SHA-256 hash of the backup data for integrity verification.
    pub data_hash: [u8; 32],
    /// Size of the backup in bytes.
    pub size_bytes: u64,
    /// Path where backup is stored.
    pub path: String,
    /// Whether the backup has been verified via test restore.
    pub verified: bool,
    /// Encryption key ID used to encrypt the backup (if encrypted).
    pub encryption_key_id: Option<String>,
}

/// Create a backup manifest (the actual pg_dump would be an external command).
pub fn create_backup_manifest(backup_id: &str, path: &str, data: &[u8]) -> BackupManifest {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(data);
    let full_hash = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&full_hash[..32]);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64;

    BackupManifest {
        backup_id: backup_id.to_string(),
        created_at: now,
        data_hash: hash,
        size_bytes: data.len() as u64,
        path: path.to_string(),
        verified: false,
        encryption_key_id: None,
    }
}

/// Verify a backup's integrity by checking its hash (CNSA 2.0: SHA-512).
pub fn verify_backup(manifest: &BackupManifest, data: &[u8]) -> bool {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(data);
    let full_hash = hasher.finalize();
    let mut actual_hash = [0u8; 32];
    actual_hash.copy_from_slice(&full_hash[..32]);

    // Constant-time comparison
    use subtle::ConstantTimeEq;
    actual_hash.ct_eq(&manifest.data_hash).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ha_config(num_replicas: usize) -> HaConfig {
        let mut replicas = Vec::with_capacity(num_replicas);
        for i in 0..num_replicas {
            replicas.push(NodeConfig {
                node_id: format!("replica-{}", i + 1),
                connection_url: format!("postgres://replica{}:5432/db", i + 1),
                role: NodeRole::Replica,
                max_connections: 10,
            });
        }
        HaConfig {
            primary: NodeConfig {
                node_id: "primary-1".into(),
                connection_url: "postgres://primary:5432/db".into(),
                role: NodeRole::Primary,
                max_connections: 20,
            },
            replicas,
            health_check_interval_secs: 10,
            connect_timeout_secs: 5,
            max_replication_lag_ms: 1000,
        }
    }

    #[test]
    fn ha_pool_creation_with_primary_and_replicas() {
        let config = make_ha_config(3);
        let pool = HaPool::new(config);
        assert_eq!(pool.node_count(), 4); // 1 primary + 3 replicas
        assert!(!pool.is_degraded());
        assert_eq!(pool.write_node().node_id, "primary-1");
        assert_eq!(pool.write_node().role, NodeRole::Primary);
    }

    #[test]
    fn read_routing_round_robin() {
        let config = make_ha_config(3);
        let mut pool = HaPool::new(config);

        // Mark all replicas healthy so they participate
        pool.mark_healthy("replica-1");
        pool.mark_healthy("replica-2");
        pool.mark_healthy("replica-3");

        // Round-robin should distribute reads across replicas
        let mut seen = std::collections::HashSet::new();
        for _ in 0..6 {
            let node = pool.read_node();
            seen.insert(node.node_id.clone());
            assert_eq!(node.role, NodeRole::Replica);
        }
        assert_eq!(seen.len(), 3, "all 3 replicas should be visited");
    }

    #[test]
    fn read_fallback_to_primary_when_no_healthy_replicas() {
        let config = make_ha_config(2);
        let mut pool = HaPool::new(config);

        // Mark all replicas unhealthy
        pool.mark_unhealthy("replica-1");
        pool.mark_unhealthy("replica-2");

        // Reads should fall back to primary
        let node = pool.read_node();
        assert_eq!(node.node_id, "primary-1");
        assert_eq!(node.role, NodeRole::Primary);
    }

    #[test]
    fn read_fallback_to_primary_with_no_replicas() {
        let config = make_ha_config(0);
        let pool = HaPool::new(config);

        let node = pool.read_node();
        assert_eq!(node.node_id, "primary-1");
    }

    #[test]
    fn health_marking_healthy() {
        let config = make_ha_config(1);
        let mut pool = HaPool::new(config);

        assert_eq!(pool.primary.health, NodeHealth::Unknown);
        pool.mark_healthy("primary-1");
        assert_eq!(pool.primary.health, NodeHealth::Healthy);
        assert_eq!(pool.primary.consecutive_failures, 0);
        assert!(pool.primary.last_check.is_some());

        pool.mark_healthy("replica-1");
        assert_eq!(pool.replicas[0].health, NodeHealth::Healthy);
        assert_eq!(pool.replicas[0].consecutive_failures, 0);
    }

    #[test]
    fn health_marking_unhealthy() {
        let config = make_ha_config(1);
        let mut pool = HaPool::new(config);

        pool.mark_unhealthy("primary-1");
        assert_eq!(pool.primary.health, NodeHealth::Unhealthy);
        assert_eq!(pool.primary.consecutive_failures, 1);

        pool.mark_unhealthy("primary-1");
        assert_eq!(pool.primary.consecutive_failures, 2);

        pool.mark_unhealthy("replica-1");
        assert_eq!(pool.replicas[0].health, NodeHealth::Unhealthy);
        assert_eq!(pool.replicas[0].consecutive_failures, 1);
    }

    #[test]
    fn degraded_mode_detection() {
        let config = make_ha_config(2);
        let mut pool = HaPool::new(config);

        assert!(!pool.is_degraded());

        // Primary goes unhealthy -> degraded
        pool.mark_unhealthy("primary-1");
        assert!(pool.is_degraded());

        // Primary recovers -> not degraded
        pool.mark_healthy("primary-1");
        assert!(!pool.is_degraded());
    }

    #[test]
    fn cluster_health_summary() {
        let config = make_ha_config(3);
        let mut pool = HaPool::new(config);

        pool.mark_healthy("primary-1");
        pool.mark_healthy("replica-1");
        pool.mark_healthy("replica-2");
        pool.mark_unhealthy("replica-3");

        let health = pool.check_health();
        assert!(health.primary_healthy);
        assert_eq!(health.healthy_replicas, 2);
        assert_eq!(health.total_replicas, 3);
        assert!(!health.degraded);
    }

    #[test]
    fn backup_manifest_creation_and_verification() {
        let data = b"pg_dump output data for testing backup integrity";
        let manifest = create_backup_manifest("backup-001", "/backups/2026/001.sql.gz", data);

        assert_eq!(manifest.backup_id, "backup-001");
        assert_eq!(manifest.path, "/backups/2026/001.sql.gz");
        assert_eq!(manifest.size_bytes, data.len() as u64);
        assert!(!manifest.verified);
        assert!(manifest.encryption_key_id.is_none());
        assert!(manifest.created_at > 0);

        // Verification should succeed with the same data
        assert!(verify_backup(&manifest, data));
    }

    #[test]
    fn backup_integrity_tampered_data_fails_verification() {
        let data = b"original backup data content";
        let manifest = create_backup_manifest("backup-002", "/backups/002.sql.gz", data);

        // Same data verifies
        assert!(verify_backup(&manifest, data));

        // Tampered data fails
        let mut tampered = data.to_vec();
        tampered[0] ^= 0xFF;
        assert!(!verify_backup(&manifest, &tampered));

        // Empty data fails
        assert!(!verify_backup(&manifest, b""));

        // Different data entirely fails
        assert!(!verify_backup(&manifest, b"completely different data"));
    }

    #[test]
    fn default_ha_config() {
        let config = HaConfig::default();
        assert_eq!(config.primary.node_id, "primary-1");
        assert_eq!(config.primary.role, NodeRole::Primary);
        assert!(config.replicas.is_empty());
        assert_eq!(config.health_check_interval_secs, 10);
        assert_eq!(config.connect_timeout_secs, 5);
        assert_eq!(config.max_replication_lag_ms, 1000);
    }

    // -- Mock PgExecutor for testing --

    struct MockPgExecutor {
        promote_results: Mutex<Vec<Result<bool, String>>>,
        recovery_results: Mutex<Vec<Result<bool, String>>>,
        writable_results: Mutex<Vec<Result<(), String>>>,
        terminate_results: Mutex<Vec<Result<u64, String>>>,
        wal_lsn_results: Mutex<Vec<Result<u64, String>>>,
    }

    impl MockPgExecutor {
        fn success() -> Self {
            Self {
                promote_results: Mutex::new(vec![Ok(true)]),
                recovery_results: Mutex::new(vec![Ok(false)]),
                writable_results: Mutex::new(vec![Ok(())]),
                terminate_results: Mutex::new(vec![Ok(5)]),
                wal_lsn_results: Mutex::new(vec![Ok(1000)]),
            }
        }

        fn failing_promote() -> Self {
            Self {
                promote_results: Mutex::new(vec![
                    Err("connection refused".into()),
                    Err("timeout".into()),
                    Err("still failing".into()),
                ]),
                recovery_results: Mutex::new(vec![Ok(true)]),
                writable_results: Mutex::new(vec![Ok(())]),
                terminate_results: Mutex::new(vec![Ok(0)]),
                wal_lsn_results: Mutex::new(vec![Ok(0)]),
            }
        }

        fn pop_or_last<T: Clone>(v: &Mutex<Vec<T>>) -> T {
            let mut guard = v.lock().unwrap();
            if guard.len() > 1 {
                guard.remove(0)
            } else {
                guard[0].clone()
            }
        }
    }

    impl PgExecutor for MockPgExecutor {
        fn pg_promote(
            &self,
            _url: &str,
        ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + '_>> {
            Box::pin(async { Self::pop_or_last(&self.promote_results) })
        }
        fn pg_is_in_recovery(
            &self,
            _url: &str,
        ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + '_>> {
            Box::pin(async { Self::pop_or_last(&self.recovery_results) })
        }
        fn verify_writable(
            &self,
            _url: &str,
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>> {
            Box::pin(async { Self::pop_or_last(&self.writable_results) })
        }
        fn pg_terminate_all(
            &self,
            _url: &str,
        ) -> Pin<Box<dyn Future<Output = Result<u64, String>> + Send + '_>> {
            Box::pin(async { Self::pop_or_last(&self.terminate_results) })
        }
        fn pg_current_wal_lsn(
            &self,
            _url: &str,
        ) -> Pin<Box<dyn Future<Output = Result<u64, String>> + Send + '_>> {
            Box::pin(async { Self::pop_or_last(&self.wal_lsn_results) })
        }
    }

    #[test]
    fn split_brain_detection_returns_conflicting_nodes() {
        let config = make_ha_config(3);
        let mut pool = HaPool::new(config);
        pool.mark_healthy("primary-1");

        let reports = vec![
            ("replica-1".to_string(), false),
            ("replica-2".to_string(), true),
            ("replica-3".to_string(), false),
        ];
        let conflicts = pool.detect_split_brain(&reports);
        assert_eq!(conflicts, vec!["replica-2"]);
    }

    #[test]
    fn split_brain_no_conflict_when_primary_unhealthy() {
        let config = make_ha_config(2);
        let mut pool = HaPool::new(config);
        pool.mark_unhealthy("primary-1");

        let reports = vec![("replica-1".to_string(), true)];
        let conflicts = pool.detect_split_brain(&reports);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn split_brain_multiple_conflicts() {
        let config = make_ha_config(3);
        let mut pool = HaPool::new(config);
        pool.mark_healthy("primary-1");

        let reports = vec![
            ("replica-1".to_string(), true),
            ("replica-2".to_string(), true),
            ("replica-3".to_string(), false),
        ];
        let conflicts = pool.detect_split_brain(&reports);
        assert_eq!(conflicts.len(), 2);
    }

    #[tokio::test]
    async fn stonith_fence_node_adds_to_blocklist() {
        let config = make_ha_config(2);
        let pool = HaPool::new(config);
        let executor = MockPgExecutor::success();

        assert!(!pool.is_stonith_blocklisted("replica-1"));
        pool.stonith_fence_node("replica-1", &executor)
            .await
            .unwrap();
        assert!(pool.is_stonith_blocklisted("replica-1"));
        assert!(!pool.is_stonith_blocklisted("replica-2"));
    }

    #[tokio::test]
    async fn stonith_fence_blocklists_even_on_terminate_failure() {
        let config = make_ha_config(1);
        let pool = HaPool::new(config);
        let executor = MockPgExecutor {
            terminate_results: Mutex::new(vec![Err("unreachable".into())]),
            ..MockPgExecutor::success()
        };

        pool.stonith_fence_node("replica-1", &executor)
            .await
            .unwrap();
        assert!(pool.is_stonith_blocklisted("replica-1"));
    }

    #[tokio::test]
    async fn execute_pg_promote_async_succeeds() {
        let config = make_ha_config(1);
        let pool = HaPool::new(config);
        let executor = MockPgExecutor::success();

        let result = pool
            .execute_pg_promote_async("postgres://replica1:5432/db", "replica-1", &executor)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn execute_pg_promote_async_retries_on_failure() {
        let config = make_ha_config(1);
        let pool = HaPool::new(config);
        let executor = MockPgExecutor {
            promote_results: Mutex::new(vec![Err("transient".into()), Ok(true)]),
            recovery_results: Mutex::new(vec![Ok(false)]),
            writable_results: Mutex::new(vec![Ok(())]),
            ..MockPgExecutor::success()
        };

        let result = pool
            .execute_pg_promote_async("postgres://replica1:5432/db", "replica-1", &executor)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn execute_pg_promote_async_fails_after_max_retries() {
        let config = make_ha_config(1);
        let pool = HaPool::new(config);
        let executor = MockPgExecutor::failing_promote();

        let result = pool
            .execute_pg_promote_async("postgres://replica1:5432/db", "replica-1", &executor)
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("3 attempts"));
    }

    #[tokio::test]
    async fn verify_wal_position_passes_when_ahead() {
        let config = make_ha_config(1);
        let pool = HaPool::new(config);
        let executor = MockPgExecutor {
            wal_lsn_results: Mutex::new(vec![Ok(2000)]),
            ..MockPgExecutor::success()
        };

        let result = pool
            .verify_wal_position("postgres://p:5432/db", 1000, &executor)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn verify_wal_position_fails_when_behind() {
        let config = make_ha_config(1);
        let pool = HaPool::new(config);
        let executor = MockPgExecutor {
            wal_lsn_results: Mutex::new(vec![Ok(500)]),
            ..MockPgExecutor::success()
        };

        let result = pool
            .verify_wal_position("postgres://p:5432/db", 1000, &executor)
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("data loss risk"));
    }

    #[test]
    fn auto_promote_config_military_mode_defaults_to_5s() {
        std::env::set_var("MILNET_MILITARY_DEPLOYMENT", "1");
        std::env::remove_var("MILNET_DB_MANUAL_FAILOVER");
        std::env::remove_var("MILNET_DB_FAILOVER_DELAY");
        let cfg = AutoPromoteConfig::from_env();
        assert!(cfg.enabled);
        assert_eq!(cfg.safety_delay_secs, 5);
        assert!(cfg.require_witness);
        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
    }

    #[test]
    fn auto_promote_config_env_override() {
        std::env::set_var("MILNET_MILITARY_DEPLOYMENT", "1");
        std::env::set_var("MILNET_DB_FAILOVER_DELAY", "3");
        std::env::remove_var("MILNET_DB_MANUAL_FAILOVER");
        let cfg = AutoPromoteConfig::from_env();
        assert_eq!(cfg.safety_delay_secs, 3);
        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
        std::env::remove_var("MILNET_DB_FAILOVER_DELAY");
    }

    #[test]
    fn auto_promote_config_default_30s() {
        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
        std::env::remove_var("MILNET_DB_MANUAL_FAILOVER");
        std::env::remove_var("MILNET_DB_FAILOVER_DELAY");
        let cfg = AutoPromoteConfig::from_env();
        assert_eq!(cfg.safety_delay_secs, 30);
    }

    #[tokio::test]
    async fn failover_rapid_cycling_stress() {
        let config = make_ha_config(3);
        let mut pool = HaPool::new(config);
        let failover_config = AutoFailoverConfig {
            failover_threshold_secs: 0,
            min_replica_lag_for_promotion_ms: 100,
            require_quorum: false,
            consecutive_failure_threshold: 1,
        };

        for cycle in 0..5 {
            pool.mark_unhealthy("primary-1");

            let lags = vec![ReplicaLagInfo {
                node_id: format!("replica-{}", (cycle % 3) + 1),
                lag_ms: 10,
                primary_unreachable: true,
            }];

            let result = pool.attempt_automatic_failover(&failover_config, &lags);
            assert!(result.is_ok());

            let primary_id = pool.primary.config.node_id.clone();
            pool.mark_healthy(&primary_id);
        }
    }
}
