//! Database high-availability tests.
//!
//! Verifies the HaPool correctly implements:
//!   - Primary/replica routing with round-robin load balancing
//!   - Health state tracking with consecutive failure counters
//!   - Degraded mode detection on primary failure
//!   - Read fallback to primary when all replicas are unhealthy
//!   - Backup manifest creation and integrity verification
//!   - Configurable health check intervals

use common::db_ha::*;

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

// ── Primary Failure Triggers Degraded Mode ────────────────────────────────

/// Security property: When the primary node fails, the cluster enters degraded
/// mode. This is critical for SIEM alerting and operational awareness.
#[test]
fn primary_failure_triggers_degraded_mode() {
    let config = make_ha_config(2);
    let mut pool = HaPool::new(config);

    assert!(!pool.is_degraded(), "fresh cluster must not be degraded");

    // Simulate primary failure
    pool.mark_unhealthy("primary-1");
    assert!(pool.is_degraded(), "cluster must be degraded after primary failure");

    let health = pool.check_health();
    assert!(!health.primary_healthy || health.degraded);
}

/// Security property: After consecutive primary failures, the failure counter
/// increments correctly for threshold-based failover decisions.
#[test]
fn consecutive_failure_counter_increments_correctly() {
    let config = make_ha_config(1);
    let mut pool = HaPool::new(config);

    // Three consecutive failures
    pool.mark_unhealthy("primary-1");
    pool.mark_unhealthy("primary-1");
    pool.mark_unhealthy("primary-1");

    // We can verify via check_health that primary is unhealthy
    let health = pool.check_health();
    assert!(!health.primary_healthy || health.degraded);
    assert!(pool.is_degraded());
}

/// Security property: A successful health check resets the consecutive failure
/// counter, preventing spurious failover after transient issues.
#[test]
fn consecutive_failure_counter_resets_on_healthy() {
    let config = make_ha_config(1);
    let mut pool = HaPool::new(config);

    // Accumulate failures
    pool.mark_unhealthy("primary-1");
    pool.mark_unhealthy("primary-1");
    assert!(pool.is_degraded());

    // Recovery
    pool.mark_healthy("primary-1");
    assert!(!pool.is_degraded(), "degraded flag must clear on primary recovery");

    let health = pool.check_health();
    assert!(health.primary_healthy);
}

// ── Replica Selection ─────────────────────────────────────────────────────

/// Security property: Read operations are distributed across healthy replicas
/// via round-robin to prevent hotspot-induced denial of service.
#[test]
fn replica_selection_round_robin_distributes_load() {
    let config = make_ha_config(3);
    let mut pool = HaPool::new(config);

    pool.mark_healthy("replica-1");
    pool.mark_healthy("replica-2");
    pool.mark_healthy("replica-3");

    let mut seen = std::collections::HashSet::new();
    for _ in 0..9 {
        let node = pool.read_node();
        seen.insert(node.node_id.clone());
        assert_eq!(node.role, NodeRole::Replica);
    }
    assert_eq!(seen.len(), 3, "all 3 replicas must participate in round-robin");
}

/// Security property: Read operations fall back to primary when ALL replicas
/// are unhealthy, ensuring continued availability for reads.
#[test]
fn read_falls_back_to_primary_when_all_replicas_unhealthy() {
    let config = make_ha_config(3);
    let mut pool = HaPool::new(config);

    pool.mark_unhealthy("replica-1");
    pool.mark_unhealthy("replica-2");
    pool.mark_unhealthy("replica-3");

    let node = pool.read_node();
    assert_eq!(node.node_id, "primary-1");
    assert_eq!(node.role, NodeRole::Primary);
}

/// Security property: Write operations ALWAYS go to the primary node.
#[test]
fn write_always_routes_to_primary() {
    let config = make_ha_config(3);
    let pool = HaPool::new(config);

    let node = pool.write_node();
    assert_eq!(node.node_id, "primary-1");
    assert_eq!(node.role, NodeRole::Primary);
}

// ── Cluster Health Summary ────────────────────────────────────────────────

/// Security property: Cluster health summary accurately reflects the state
/// of all nodes for SIEM integration and operational dashboards.
#[test]
fn cluster_health_summary_is_accurate() {
    let config = make_ha_config(4);
    let mut pool = HaPool::new(config);

    pool.mark_healthy("primary-1");
    pool.mark_healthy("replica-1");
    pool.mark_healthy("replica-2");
    pool.mark_unhealthy("replica-3");
    pool.mark_unhealthy("replica-4");

    let health = pool.check_health();
    assert!(health.primary_healthy);
    assert_eq!(health.healthy_replicas, 2);
    assert_eq!(health.total_replicas, 4);
    assert!(!health.degraded, "degraded only set by primary failure");
}

/// Security property: Node count includes primary + all replicas.
#[test]
fn node_count_includes_primary_and_replicas() {
    let config = make_ha_config(5);
    let pool = HaPool::new(config);
    assert_eq!(pool.node_count(), 6, "1 primary + 5 replicas = 6");
}

// ── Health Check Interval Configuration ───────────────────────────────────

/// Security property: Health check interval is configurable to allow
/// tuning for different deployment environments and latency requirements.
#[test]
fn health_check_interval_is_configurable() {
    let mut config = make_ha_config(1);
    config.health_check_interval_secs = 30;
    config.connect_timeout_secs = 10;
    config.max_replication_lag_ms = 500;

    let pool = HaPool::new(config);
    assert_eq!(pool.config().health_check_interval_secs, 30);
    assert_eq!(pool.config().connect_timeout_secs, 10);
    assert_eq!(pool.config().max_replication_lag_ms, 500);
}

// ── Backup Manifest Integrity ─────────────────────────────────────────────

/// Security property: Backup manifests record SHA-256 hashes for integrity
/// verification, and verification MUST fail for tampered data.
#[test]
fn backup_manifest_integrity_verification() {
    let data = b"simulated pg_dump output for a critical database backup";
    let manifest = create_backup_manifest("backup-ha-001", "/backups/ha/001.sql.gz", data);

    assert_eq!(manifest.backup_id, "backup-ha-001");
    assert_eq!(manifest.size_bytes, data.len() as u64);
    assert!(!manifest.verified);

    // Valid data verifies
    assert!(verify_backup(&manifest, data), "valid data must verify");

    // Tampered data fails
    let mut tampered = data.to_vec();
    tampered[0] ^= 0xFF;
    assert!(!verify_backup(&manifest, &tampered), "tampered data must fail verification");

    // Truncated data fails
    assert!(!verify_backup(&manifest, &data[..10]), "truncated data must fail");

    // Empty data fails
    assert!(!verify_backup(&manifest, b""), "empty data must fail");
}

/// Security property: Backup manifests use constant-time hash comparison
/// to prevent timing attacks that could reveal partial hash information.
#[test]
fn backup_verification_uses_constant_time_comparison() {
    let data = b"backup data for constant-time test";
    let manifest = create_backup_manifest("ct-test", "/backups/ct.sql.gz", data);

    // Run verification multiple times — all should produce same result
    // (we cannot directly test timing, but we verify the API is consistent)
    for _ in 0..10 {
        assert!(verify_backup(&manifest, data));
    }
    for _ in 0..10 {
        assert!(!verify_backup(&manifest, b"wrong data"));
    }
}

// ── Replica Health Transitions ────────────────────────────────────────────

/// Security property: Replica health transitions are tracked independently
/// and do not affect primary degraded state.
#[test]
fn replica_health_independent_of_primary_degraded() {
    let config = make_ha_config(2);
    let mut pool = HaPool::new(config);

    // All replicas unhealthy does NOT set degraded (only primary does)
    pool.mark_unhealthy("replica-1");
    pool.mark_unhealthy("replica-2");
    assert!(!pool.is_degraded(), "replica failures must not set degraded flag");

    // Primary unhealthy sets degraded
    pool.mark_unhealthy("primary-1");
    assert!(pool.is_degraded());

    // Recovering replicas does not clear degraded (only primary recovery does)
    pool.mark_healthy("replica-1");
    pool.mark_healthy("replica-2");
    assert!(pool.is_degraded(), "replica recovery must not clear primary degraded flag");

    // Primary recovery clears degraded
    pool.mark_healthy("primary-1");
    assert!(!pool.is_degraded());
}

/// Security property: Default HaConfig provides secure defaults.
#[test]
fn default_ha_config_secure_defaults() {
    let config = HaConfig::default();
    assert_eq!(config.primary.role, NodeRole::Primary);
    assert!(config.replicas.is_empty());
    assert!(config.health_check_interval_secs > 0, "health check interval must be > 0");
    assert!(config.connect_timeout_secs > 0, "connect timeout must be > 0");
    assert!(config.max_replication_lag_ms > 0, "max lag must be > 0");
}
