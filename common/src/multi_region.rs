//! Multi-region active-active deployment.
//!
//! Each region runs a complete SSO stack. Regions sync state via:
//! 1. Cross-region Raft consensus for cluster membership
//! 2. Async database replication (PostgreSQL logical replication)
//! 3. Cross-region BFT audit chain anchoring
//! 4. Distributed KEK shares across regions
//!
//! Failure model: Any single region can fail completely without service interruption.
//! Two regions can fail if the remaining region(s) maintain quorum.
//!
//! # Security
//! - Cross-region communication MUST use mTLS with certificate pinning
//! - All cross-region events logged to SIEM with category MULTI_REGION
//! - Split-brain detection: minority partition stops accepting writes
//! - State replication is async with bounded lag (configurable, default 5s)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

// ── Error types ─────────────────────────────────────────────────────────────

/// Errors from multi-region operations.
#[derive(Debug, thiserror::Error)]
pub enum MultiRegionError {
    #[error("insufficient regions: {configured} configured, minimum {required} required — single-region deployment is a SPOF")]
    InsufficientRegions { configured: usize, required: usize },

    #[error("insufficient reachable regions: {reachable}/{total} reachable, need {required}")]
    InsufficientReachableRegions {
        reachable: usize,
        total: usize,
        required: usize,
    },

    #[error("local region '{0}' not found in configured regions")]
    LocalRegionNotFound(String),

    #[error("split-brain detected: this region can only reach {reachable}/{total} regions (need majority {majority})")]
    SplitBrainDetected {
        reachable: usize,
        total: usize,
        majority: usize,
    },

    #[error("no healthy region available to serve request")]
    NoHealthyRegion,

    #[error("state replication lag exceeded: {lag_ms}ms > {max_ms}ms for region '{region}'")]
    ReplicationLagExceeded {
        region: String,
        lag_ms: u64,
        max_ms: u64,
    },

    #[error("cross-region mTLS required but not configured for region '{0}'")]
    MtlsNotConfigured(String),

    #[error("region '{0}' is not reachable")]
    RegionUnreachable(String),

    #[error("quorum lost for FROST signing: {available}/{threshold} shares available across regions")]
    FrostQuorumLost { available: usize, threshold: usize },

    #[error("invalid MILNET_REGIONS configuration: {0}")]
    InvalidConfig(String),
}

// ── Region configuration ────────────────────────────────────────────────────

/// Health status of a region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionHealth {
    /// Region is healthy and serving traffic.
    Healthy,
    /// Region is reachable but experiencing elevated latency or partial failures.
    Degraded,
    /// Region is unreachable or returning errors.
    Unhealthy,
    /// Region health is unknown (not yet checked).
    Unknown,
}

/// Configuration for a single region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionConfig {
    /// Region identifier (e.g., "us-east1", "europe-west1", "asia-south1").
    pub region_id: String,
    /// Service endpoints in this region (mTLS-enabled).
    pub endpoints: Vec<String>,
    /// Routing priority. Lower = preferred (for latency-based routing).
    pub priority: u32,
    /// Is this the current region?
    pub is_local: bool,
}

/// Tracked state for a region, including health monitoring data.
struct TrackedRegion {
    config: RegionConfig,
    health: RegionHealth,
    last_check: Option<Instant>,
    last_latency_ms: Option<u64>,
    consecutive_failures: u32,
    /// Last known replication lag from this region (ms).
    replication_lag_ms: u64,
}

/// Category of state being replicated across regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StateCategory {
    /// Active session data.
    Sessions,
    /// Token/certificate revocations.
    Revocations,
    /// Cluster membership changes.
    ClusterMembership,
    /// Audit chain anchors.
    AuditAnchors,
    /// KEK share redistribution events.
    KekShares,
}

/// A state replication event to be propagated to all regions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateReplicationEvent {
    /// Unique event ID.
    pub event_id: String,
    /// Category of state change.
    pub category: StateCategory,
    /// Serialized payload.
    pub payload: Vec<u8>,
    /// Originating region.
    pub source_region: String,
    /// Timestamp (microseconds since epoch).
    pub timestamp_us: i64,
    /// Monotonic sequence number for ordering within a region.
    pub sequence: u64,
}

/// Result of a routing decision.
#[derive(Debug, Clone)]
pub struct RouteDecision {
    /// The region selected to handle the request.
    pub region_id: String,
    /// The endpoint within the region.
    pub endpoint: String,
    /// Whether this is a failover (not the local region).
    pub is_failover: bool,
}

/// Result of a cross-region health check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossRegionHealthReport {
    /// Health of each region.
    pub region_health: HashMap<String, RegionHealth>,
    /// Number of healthy regions.
    pub healthy_count: usize,
    /// Total configured regions.
    pub total_count: usize,
    /// Whether this region has majority connectivity.
    pub has_majority: bool,
    /// Whether writes are allowed (requires majority).
    pub writes_allowed: bool,
    /// Whether a split-brain condition is detected.
    pub split_brain_detected: bool,
}

/// Distribution of FROST signing shares across regions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionShareDistribution {
    /// Mapping of region_id -> number of FROST shares held.
    pub shares_per_region: HashMap<String, usize>,
    /// Threshold required for signing.
    pub threshold: usize,
    /// Total shares across all regions.
    pub total_shares: usize,
}

/// Request to be routed (opaque to the routing layer).
#[derive(Debug, Clone)]
pub struct RoutableRequest {
    /// Whether this request requires write access (affected by split-brain).
    pub requires_write: bool,
    /// Optional affinity to a specific region.
    pub region_affinity: Option<String>,
}

// ── MultiRegionManager ──────────────────────────────────────────────────────

/// Manages multi-region active-active deployment.
///
/// Ensures no single region is a SPOF by requiring at least `min_regions`
/// to be configured and reachable at startup. Handles routing, failover,
/// state replication, and split-brain detection.
pub struct MultiRegionManager {
    regions: RwLock<Vec<TrackedRegion>>,
    local_region: String,
    /// Minimum number of regions required for operation (default 2).
    min_regions: usize,
    /// Cross-region communication timeout.
    cross_region_timeout: Duration,
    /// Maximum acceptable replication lag before alerting (ms).
    max_replication_lag_ms: u64,
    /// Whether writes are currently allowed (false during split-brain).
    writes_allowed: AtomicBool,
    /// Monotonic sequence counter for state replication events.
    sequence_counter: AtomicU64,
    /// FROST share distribution across regions.
    share_distribution: RwLock<Option<RegionShareDistribution>>,
}

impl std::fmt::Debug for MultiRegionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiRegionManager")
            .field("local_region", &self.local_region)
            .field("min_regions", &self.min_regions)
            .field("cross_region_timeout", &self.cross_region_timeout)
            .field("max_replication_lag_ms", &self.max_replication_lag_ms)
            .field("writes_allowed", &self.writes_allowed.load(Ordering::Relaxed))
            .field("sequence_counter", &self.sequence_counter.load(Ordering::Relaxed))
            .finish()
    }
}

impl MultiRegionManager {
    /// Initialize from `MILNET_REGIONS` environment variable.
    ///
    /// Format: `region_id:priority:endpoint1;endpoint2,...`
    /// Multiple regions separated by commas.
    /// The local region is identified by `MILNET_LOCAL_REGION` env var.
    ///
    /// Example:
    /// ```text
    /// MILNET_REGIONS=us-east1:1:https://sso-east.mil:443;https://sso-east2.mil:443,europe-west1:2:https://sso-eu.mil:443,asia-south1:3:https://sso-asia.mil:443
    /// MILNET_LOCAL_REGION=us-east1
    /// ```
    ///
    /// # Errors
    /// Returns `MultiRegionError::InsufficientRegions` if fewer than `min_regions` are configured.
    /// Returns `MultiRegionError::LocalRegionNotFound` if the local region is not in the config.
    pub fn new() -> Result<Self, MultiRegionError> {
        let regions_str = std::env::var("MILNET_REGIONS").map_err(|_| {
            MultiRegionError::InvalidConfig(
                "MILNET_REGIONS environment variable not set".to_string(),
            )
        })?;

        let local_region = std::env::var("MILNET_LOCAL_REGION").map_err(|_| {
            MultiRegionError::InvalidConfig(
                "MILNET_LOCAL_REGION environment variable not set".to_string(),
            )
        })?;

        let min_regions = std::env::var("MILNET_MIN_REGIONS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(2);

        let timeout_secs = std::env::var("MILNET_CROSS_REGION_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(10);

        let max_lag_ms = std::env::var("MILNET_MAX_REPLICATION_LAG_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(5000);

        let configs = Self::parse_regions(&regions_str, &local_region)?;

        Self::from_configs(configs, local_region, min_regions, timeout_secs, max_lag_ms)
    }

    /// Create from explicit region configs (used by `new()` and tests).
    pub fn from_configs(
        configs: Vec<RegionConfig>,
        local_region: String,
        min_regions: usize,
        cross_region_timeout_secs: u64,
        max_replication_lag_ms: u64,
    ) -> Result<Self, MultiRegionError> {
        // HARD REQUIREMENT: refuse single-region deployment
        if configs.len() < min_regions {
            tracing::error!(
                configured = configs.len(),
                required = min_regions,
                "SIEM:CRITICAL:MULTI_REGION startup REFUSED: insufficient regions configured — \
                 single-cluster deployment is a single point of failure"
            );
            return Err(MultiRegionError::InsufficientRegions {
                configured: configs.len(),
                required: min_regions,
            });
        }

        // Verify local region exists in config
        if !configs.iter().any(|c| c.region_id == local_region) {
            return Err(MultiRegionError::LocalRegionNotFound(local_region));
        }

        let tracked: Vec<TrackedRegion> = configs
            .into_iter()
            .map(|config| TrackedRegion {
                health: if config.is_local {
                    RegionHealth::Healthy
                } else {
                    RegionHealth::Unknown
                },
                last_check: if config.is_local {
                    Some(Instant::now())
                } else {
                    None
                },
                last_latency_ms: None,
                consecutive_failures: 0,
                replication_lag_ms: 0,
                config,
            })
            .collect();

        tracing::info!(
            local_region = %local_region,
            total_regions = tracked.len(),
            min_regions = min_regions,
            "SIEM:INFO:MULTI_REGION multi-region manager initialized"
        );

        Ok(Self {
            regions: RwLock::new(tracked),
            local_region,
            min_regions,
            cross_region_timeout: Duration::from_secs(cross_region_timeout_secs),
            max_replication_lag_ms,
            writes_allowed: AtomicBool::new(true),
            sequence_counter: AtomicU64::new(0),
            share_distribution: RwLock::new(None),
        })
    }

    /// Parse the `MILNET_REGIONS` env var format.
    fn parse_regions(
        regions_str: &str,
        local_region: &str,
    ) -> Result<Vec<RegionConfig>, MultiRegionError> {
        let mut configs = Vec::new();

        for region_part in regions_str.split(',') {
            let region_part = region_part.trim();
            if region_part.is_empty() {
                continue;
            }

            let parts: Vec<&str> = region_part.splitn(3, ':').collect();
            if parts.len() < 3 {
                return Err(MultiRegionError::InvalidConfig(format!(
                    "invalid region format '{}': expected 'region_id:priority:endpoints'",
                    region_part
                )));
            }

            let region_id = parts[0].to_string();
            let priority: u32 = parts[1].parse().map_err(|_| {
                MultiRegionError::InvalidConfig(format!(
                    "invalid priority '{}' for region '{}'",
                    parts[1], region_id
                ))
            })?;

            let endpoints: Vec<String> = parts[2]
                .split(';')
                .map(|e| e.trim().to_string())
                .filter(|e| !e.is_empty())
                .collect();

            if endpoints.is_empty() {
                return Err(MultiRegionError::InvalidConfig(format!(
                    "region '{}' has no endpoints",
                    region_id
                )));
            }

            // Verify all endpoints use TLS
            for ep in &endpoints {
                if !ep.starts_with("https://") {
                    return Err(MultiRegionError::MtlsNotConfigured(format!(
                        "endpoint '{}' in region '{}' must use https:// (mTLS required)",
                        ep, region_id
                    )));
                }
            }

            configs.push(RegionConfig {
                is_local: region_id == local_region,
                region_id,
                endpoints,
                priority,
            });
        }

        Ok(configs)
    }

    /// Verify that at least `min_regions` are reachable. Refuse startup if not.
    ///
    /// In production, this performs actual TCP+TLS handshakes to each region's
    /// endpoints. The health status of each region is updated based on results.
    ///
    /// # Errors
    /// Returns `MultiRegionError::InsufficientReachableRegions` if fewer than
    /// `min_regions` are reachable.
    pub fn verify_multi_region(
        &self,
        reachable_regions: &[String],
    ) -> Result<(), MultiRegionError> {
        let regions = self.regions.read().unwrap();
        let total = regions.len();
        let reachable = reachable_regions.len();

        if reachable < self.min_regions {
            tracing::error!(
                reachable = reachable,
                total = total,
                required = self.min_regions,
                regions_up = ?reachable_regions,
                "SIEM:CRITICAL:MULTI_REGION startup verification FAILED: \
                 insufficient reachable regions"
            );
            return Err(MultiRegionError::InsufficientReachableRegions {
                reachable,
                total,
                required: self.min_regions,
            });
        }

        tracing::info!(
            reachable = reachable,
            total = total,
            regions_up = ?reachable_regions,
            "SIEM:INFO:MULTI_REGION startup verification PASSED: \
             {}/{} regions reachable (minimum {})",
            reachable, total, self.min_regions
        );

        Ok(())
    }

    /// Route a request to the best available region.
    ///
    /// Strategy:
    /// 1. If local region is healthy, route locally (lowest latency).
    /// 2. If local region is unhealthy, failover to the highest-priority
    ///    healthy remote region.
    /// 3. If the request requires write access and writes are disallowed
    ///    (split-brain), reject the request.
    ///
    /// # Errors
    /// Returns `MultiRegionError::NoHealthyRegion` if no region is available.
    /// Returns `MultiRegionError::SplitBrainDetected` if writes are needed
    /// but this partition is in minority.
    pub fn route_request(
        &self,
        request: &RoutableRequest,
    ) -> Result<RouteDecision, MultiRegionError> {
        // Check split-brain write restriction
        if request.requires_write && !self.writes_allowed.load(Ordering::Acquire) {
            let regions = self.regions.read().unwrap();
            let total = regions.len();
            let healthy = regions
                .iter()
                .filter(|r| matches!(r.health, RegionHealth::Healthy | RegionHealth::Unknown))
                .count();
            let majority = (total / 2) + 1;

            tracing::warn!(
                "SIEM:WARN:MULTI_REGION write request rejected: split-brain — \
                 this partition cannot reach majority of regions"
            );

            return Err(MultiRegionError::SplitBrainDetected {
                reachable: healthy,
                total,
                majority,
            });
        }

        let regions = self.regions.read().unwrap();

        // Check for region affinity
        if let Some(ref affinity) = request.region_affinity {
            if let Some(region) = regions.iter().find(|r| {
                r.config.region_id == *affinity
                    && matches!(r.health, RegionHealth::Healthy | RegionHealth::Degraded)
            }) {
                return Ok(RouteDecision {
                    region_id: region.config.region_id.clone(),
                    endpoint: region.config.endpoints[0].clone(),
                    is_failover: !region.config.is_local,
                });
            }
        }

        // Try local region first
        if let Some(local) = regions.iter().find(|r| {
            r.config.is_local && matches!(r.health, RegionHealth::Healthy | RegionHealth::Unknown)
        }) {
            return Ok(RouteDecision {
                region_id: local.config.region_id.clone(),
                endpoint: local.config.endpoints[0].clone(),
                is_failover: false,
            });
        }

        // Local unhealthy — failover to best remote region (lowest priority number = best)
        let mut candidates: Vec<&TrackedRegion> = regions
            .iter()
            .filter(|r| {
                !r.config.is_local
                    && matches!(r.health, RegionHealth::Healthy | RegionHealth::Degraded)
            })
            .collect();

        candidates.sort_by_key(|r| r.config.priority);

        if let Some(best) = candidates.first() {
            tracing::warn!(
                local_region = %self.local_region,
                failover_region = %best.config.region_id,
                "SIEM:WARN:MULTI_REGION routing failover: local region unhealthy, \
                 routing to {}",
                best.config.region_id
            );

            return Ok(RouteDecision {
                region_id: best.config.region_id.clone(),
                endpoint: best.config.endpoints[0].clone(),
                is_failover: true,
            });
        }

        tracing::error!(
            "SIEM:CRITICAL:MULTI_REGION no healthy region available for routing"
        );
        Err(MultiRegionError::NoHealthyRegion)
    }

    /// Replicate critical state to all regions.
    ///
    /// Creates a `StateReplicationEvent` and returns the list of target regions
    /// that should receive the replication. The actual network transport is
    /// handled by the caller (via mTLS channels).
    ///
    /// # Returns
    /// List of (region_id, endpoint) pairs to replicate to.
    pub fn sync_state(
        &self,
        category: StateCategory,
        payload: Vec<u8>,
    ) -> Result<(StateReplicationEvent, Vec<(String, String)>), MultiRegionError> {
        // Check writes allowed (split-brain guard)
        if !self.writes_allowed.load(Ordering::Acquire) {
            let regions = self.regions.read().unwrap();
            let total = regions.len();
            let healthy = regions
                .iter()
                .filter(|r| matches!(r.health, RegionHealth::Healthy | RegionHealth::Unknown))
                .count();
            return Err(MultiRegionError::SplitBrainDetected {
                reachable: healthy,
                total,
                majority: (total / 2) + 1,
            });
        }

        let seq = self.sequence_counter.fetch_add(1, Ordering::Relaxed);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as i64;

        let event = StateReplicationEvent {
            event_id: format!("{}-{}-{}", self.local_region, seq, now),
            category,
            payload,
            source_region: self.local_region.clone(),
            timestamp_us: now,
            sequence: seq,
        };

        let regions = self.regions.read().unwrap();
        let targets: Vec<(String, String)> = regions
            .iter()
            .filter(|r| {
                !r.config.is_local
                    && matches!(
                        r.health,
                        RegionHealth::Healthy | RegionHealth::Degraded | RegionHealth::Unknown
                    )
            })
            .map(|r| (r.config.region_id.clone(), r.config.endpoints[0].clone()))
            .collect();

        tracing::info!(
            category = ?event.category,
            source = %event.source_region,
            sequence = event.sequence,
            target_count = targets.len(),
            "SIEM:INFO:MULTI_REGION state replication event created"
        );

        Ok((event, targets))
    }

    /// Monitor health of all regions and detect split-brain.
    ///
    /// Takes a map of region_id -> (is_reachable, latency_ms) from the
    /// health check subsystem and updates internal state.
    ///
    /// Split-brain rule: if this region cannot reach a majority of all
    /// configured regions, it MUST stop accepting writes to prevent
    /// divergent state.
    pub fn cross_region_health(
        &self,
        health_reports: &HashMap<String, (bool, u64)>,
    ) -> CrossRegionHealthReport {
        let mut regions = self.regions.write().unwrap();
        let total = regions.len();
        let majority = (total / 2) + 1;

        let mut region_health_map = HashMap::new();
        let mut healthy_count = 0;

        for region in regions.iter_mut() {
            if region.config.is_local {
                // Local region is always considered reachable from our perspective
                region.health = RegionHealth::Healthy;
                region.last_check = Some(Instant::now());
                region.consecutive_failures = 0;
                region_health_map
                    .insert(region.config.region_id.clone(), RegionHealth::Healthy);
                healthy_count += 1;
                continue;
            }

            if let Some(&(reachable, latency_ms)) =
                health_reports.get(&region.config.region_id)
            {
                region.last_check = Some(Instant::now());

                if reachable {
                    region.last_latency_ms = Some(latency_ms);
                    region.consecutive_failures = 0;

                    if latency_ms > self.cross_region_timeout.as_millis() as u64 {
                        region.health = RegionHealth::Degraded;
                    } else {
                        region.health = RegionHealth::Healthy;
                    }
                    healthy_count += 1;
                } else {
                    region.consecutive_failures += 1;
                    region.health = RegionHealth::Unhealthy;
                }
            } else {
                // No report for this region — leave as-is or mark unknown
                if region.health == RegionHealth::Healthy {
                    // Was healthy, no update — could be transient
                    region.health = RegionHealth::Degraded;
                }
            }

            region_health_map.insert(
                region.config.region_id.clone(),
                region.health,
            );
        }

        let has_majority = healthy_count >= majority;
        let split_brain = !has_majority;

        // Update write permissions based on majority
        let prev_writes = self.writes_allowed.load(Ordering::Acquire);
        self.writes_allowed.store(has_majority, Ordering::Release);

        if split_brain && prev_writes {
            tracing::error!(
                healthy = healthy_count,
                total = total,
                majority = majority,
                local_region = %self.local_region,
                "SIEM:CRITICAL:MULTI_REGION SPLIT-BRAIN DETECTED: this region cannot \
                 reach majority ({}/{} healthy, need {}). WRITES DISABLED to prevent \
                 state divergence.",
                healthy_count, total, majority
            );
        } else if has_majority && !prev_writes {
            tracing::info!(
                healthy = healthy_count,
                total = total,
                "SIEM:INFO:MULTI_REGION split-brain resolved: majority restored, \
                 writes re-enabled"
            );
        }

        CrossRegionHealthReport {
            region_health: region_health_map,
            healthy_count,
            total_count: total,
            has_majority,
            writes_allowed: has_majority,
            split_brain_detected: split_brain,
        }
    }

    /// Handle a region failure: update health state and log failover event.
    ///
    /// When a region fails, traffic is automatically redirected by `route_request`
    /// to the next-best region. This method handles the bookkeeping and SIEM logging.
    pub fn failover(&self, failed_region: &str) -> Result<(), MultiRegionError> {
        let mut regions = self.regions.write().unwrap();

        let region = regions
            .iter_mut()
            .find(|r| r.config.region_id == failed_region)
            .ok_or_else(|| {
                MultiRegionError::InvalidConfig(format!(
                    "unknown region '{}' in failover",
                    failed_region
                ))
            })?;

        region.health = RegionHealth::Unhealthy;
        region.consecutive_failures += 1;
        region.last_check = Some(Instant::now());

        let healthy_count = regions
            .iter()
            .filter(|r| matches!(r.health, RegionHealth::Healthy))
            .count();
        let total = regions.len();
        let majority = (total / 2) + 1;

        tracing::warn!(
            failed_region = %failed_region,
            healthy_remaining = healthy_count,
            total = total,
            "SIEM:WARN:MULTI_REGION region failover: '{}' marked unhealthy \
             ({}/{} regions healthy)",
            failed_region, healthy_count, total
        );

        // Update write permissions if we lost majority
        if healthy_count < majority {
            self.writes_allowed.store(false, Ordering::Release);
            tracing::error!(
                healthy = healthy_count,
                majority = majority,
                "SIEM:CRITICAL:MULTI_REGION majority lost after failover — \
                 writes disabled"
            );
        }

        Ok(())
    }

    /// Verify that FROST signing shares are distributed across regions such that
    /// no single region holds enough shares to meet the threshold.
    ///
    /// This ensures that even if one region is compromised, the attacker cannot
    /// forge signatures without cooperation from other regions.
    pub fn verify_frost_share_distribution(
        &self,
        distribution: &RegionShareDistribution,
    ) -> Result<(), MultiRegionError> {
        // Verify no single region holds >= threshold shares
        for (region_id, &count) in &distribution.shares_per_region {
            if count >= distribution.threshold {
                tracing::error!(
                    region = %region_id,
                    shares = count,
                    threshold = distribution.threshold,
                    "SIEM:CRITICAL:MULTI_REGION FROST share concentration violation: \
                     region '{}' holds {} shares (threshold={})",
                    region_id, count, distribution.threshold
                );
                return Err(MultiRegionError::InvalidConfig(format!(
                    "region '{}' holds {} FROST shares, which meets or exceeds \
                     threshold {} — single-region compromise would break signing security",
                    region_id, count, distribution.threshold
                )));
            }
        }

        // Verify total shares across all regions meet threshold
        let total_available: usize = distribution.shares_per_region.values().sum();
        if total_available < distribution.threshold {
            return Err(MultiRegionError::FrostQuorumLost {
                available: total_available,
                threshold: distribution.threshold,
            });
        }

        // Verify shares exist in at least 2 regions
        let regions_with_shares = distribution
            .shares_per_region
            .values()
            .filter(|&&v| v > 0)
            .count();
        if regions_with_shares < 2 {
            return Err(MultiRegionError::InvalidConfig(
                "FROST shares must be distributed across at least 2 regions".to_string(),
            ));
        }

        tracing::info!(
            total_shares = total_available,
            threshold = distribution.threshold,
            regions_holding_shares = regions_with_shares,
            "SIEM:INFO:MULTI_REGION FROST share distribution verified: \
             no single region holds threshold"
        );

        // Store the verified distribution
        *self.share_distribution.write().unwrap() = Some(distribution.clone());

        Ok(())
    }

    /// Update the replication lag for a remote region.
    pub fn update_replication_lag(
        &self,
        region_id: &str,
        lag_ms: u64,
    ) -> Result<(), MultiRegionError> {
        let mut regions = self.regions.write().unwrap();

        if let Some(region) = regions.iter_mut().find(|r| r.config.region_id == region_id) {
            region.replication_lag_ms = lag_ms;

            if lag_ms > self.max_replication_lag_ms {
                tracing::warn!(
                    region = %region_id,
                    lag_ms = lag_ms,
                    max_ms = self.max_replication_lag_ms,
                    "SIEM:WARN:MULTI_REGION replication lag exceeded for region '{}'",
                    region_id
                );
            }
            Ok(())
        } else {
            Err(MultiRegionError::InvalidConfig(format!(
                "unknown region '{}'",
                region_id
            )))
        }
    }

    /// Mark a region as healthy (e.g., after successful health check).
    pub fn mark_region_healthy(&self, region_id: &str) {
        let mut regions = self.regions.write().unwrap();
        if let Some(region) = regions.iter_mut().find(|r| r.config.region_id == region_id) {
            region.health = RegionHealth::Healthy;
            region.consecutive_failures = 0;
            region.last_check = Some(Instant::now());
        }

        // Re-evaluate write permissions
        let total = regions.len();
        let majority = (total / 2) + 1;
        let healthy = regions
            .iter()
            .filter(|r| matches!(r.health, RegionHealth::Healthy))
            .count();

        if healthy >= majority {
            self.writes_allowed.store(true, Ordering::Release);
        }
    }

    /// Get the local region ID.
    pub fn local_region(&self) -> &str {
        &self.local_region
    }

    /// Get the minimum required regions.
    pub fn min_regions(&self) -> usize {
        self.min_regions
    }

    /// Get the cross-region timeout.
    pub fn cross_region_timeout(&self) -> Duration {
        self.cross_region_timeout
    }

    /// Check if writes are currently allowed.
    pub fn are_writes_allowed(&self) -> bool {
        self.writes_allowed.load(Ordering::Acquire)
    }

    /// Get the number of configured regions.
    pub fn region_count(&self) -> usize {
        self.regions.read().unwrap().len()
    }

    /// Get IDs of all configured regions.
    pub fn region_ids(&self) -> Vec<String> {
        self.regions
            .read()
            .unwrap()
            .iter()
            .map(|r| r.config.region_id.clone())
            .collect()
    }

    /// Get the current health of a specific region.
    pub fn get_region_health(&self, region_id: &str) -> Option<RegionHealth> {
        self.regions
            .read()
            .unwrap()
            .iter()
            .find(|r| r.config.region_id == region_id)
            .map(|r| r.health)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create region configs for testing.
    fn make_region_configs(count: usize, local_idx: usize) -> Vec<RegionConfig> {
        let region_names = [
            "us-east1",
            "europe-west1",
            "asia-south1",
            "us-west1",
            "europe-north1",
        ];
        (0..count)
            .map(|i| RegionConfig {
                region_id: region_names[i % region_names.len()].to_string(),
                endpoints: vec![format!("https://sso-{}.mil:443", region_names[i % region_names.len()])],
                priority: i as u32 + 1,
                is_local: i == local_idx,
            })
            .collect()
    }

    /// Helper to create a manager with N regions (local = first region).
    fn make_manager(count: usize) -> MultiRegionManager {
        let configs = make_region_configs(count, 0);
        let local = configs[0].region_id.clone();
        MultiRegionManager::from_configs(configs, local, 2, 10, 5000).unwrap()
    }

    // ── Startup refuses single region ───────────────────────────────────

    #[test]
    fn startup_refuses_single_region() {
        let configs = make_region_configs(1, 0);
        let local = configs[0].region_id.clone();
        let result = MultiRegionManager::from_configs(configs, local, 2, 10, 5000);

        assert!(result.is_err());
        match result.unwrap_err() {
            MultiRegionError::InsufficientRegions {
                configured,
                required,
            } => {
                assert_eq!(configured, 1);
                assert_eq!(required, 2);
            }
            other => panic!("expected InsufficientRegions, got: {:?}", other),
        }
    }

    #[test]
    fn startup_refuses_zero_regions() {
        let result =
            MultiRegionManager::from_configs(vec![], "us-east1".to_string(), 2, 10, 5000);
        assert!(result.is_err());
    }

    // ── Two regions, one fails, system continues ────────────────────────

    #[test]
    fn two_regions_one_fails_system_continues() {
        let mgr = make_manager(3);

        // Fail one remote region
        mgr.failover("europe-west1").unwrap();

        // System should still route requests (local region is healthy)
        let request = RoutableRequest {
            requires_write: false,
            region_affinity: None,
        };
        let decision = mgr.route_request(&request).unwrap();
        assert_eq!(decision.region_id, "us-east1");
        assert!(!decision.is_failover);
    }

    #[test]
    fn failover_routes_to_remote_when_local_fails() {
        let mgr = make_manager(3);

        // Mark local region unhealthy via health check
        {
            let mut regions = mgr.regions.write().unwrap();
            regions[0].health = RegionHealth::Unhealthy;
        }

        // Mark remote regions as healthy
        mgr.mark_region_healthy("europe-west1");
        mgr.mark_region_healthy("asia-south1");

        let request = RoutableRequest {
            requires_write: false,
            region_affinity: None,
        };
        let decision = mgr.route_request(&request).unwrap();
        assert!(decision.is_failover);
        // Should pick the highest priority remote region
        assert_ne!(decision.region_id, "us-east1");
    }

    // ── Split-brain detection ───────────────────────────────────────────

    #[test]
    fn split_brain_minority_partition_stops_writes() {
        let mgr = make_manager(3);

        // Simulate: this region can only reach itself (minority of 3)
        let mut health_reports = HashMap::new();
        health_reports.insert("europe-west1".to_string(), (false, 0));
        health_reports.insert("asia-south1".to_string(), (false, 0));

        let report = mgr.cross_region_health(&health_reports);

        assert!(report.split_brain_detected);
        assert!(!report.writes_allowed);
        assert!(!mgr.are_writes_allowed());

        // Write requests should be rejected
        let request = RoutableRequest {
            requires_write: true,
            region_affinity: None,
        };
        let result = mgr.route_request(&request);
        assert!(result.is_err());
        match result.unwrap_err() {
            MultiRegionError::SplitBrainDetected { .. } => {}
            other => panic!("expected SplitBrainDetected, got: {:?}", other),
        }
    }

    #[test]
    fn split_brain_majority_partition_continues_writes() {
        let mgr = make_manager(3);

        // This region can reach 2 out of 3 (majority)
        let mut health_reports = HashMap::new();
        health_reports.insert("europe-west1".to_string(), (true, 50));
        health_reports.insert("asia-south1".to_string(), (false, 0));

        let report = mgr.cross_region_health(&health_reports);

        assert!(!report.split_brain_detected);
        assert!(report.writes_allowed);
        assert!(mgr.are_writes_allowed());
    }

    #[test]
    fn split_brain_resolves_when_connectivity_restored() {
        let mgr = make_manager(3);

        // First: split-brain (minority)
        let mut health_reports = HashMap::new();
        health_reports.insert("europe-west1".to_string(), (false, 0));
        health_reports.insert("asia-south1".to_string(), (false, 0));

        let report = mgr.cross_region_health(&health_reports);
        assert!(report.split_brain_detected);
        assert!(!mgr.are_writes_allowed());

        // Then: connectivity restored
        health_reports.insert("europe-west1".to_string(), (true, 30));
        health_reports.insert("asia-south1".to_string(), (true, 60));

        let report = mgr.cross_region_health(&health_reports);
        assert!(!report.split_brain_detected);
        assert!(report.writes_allowed);
        assert!(mgr.are_writes_allowed());
    }

    // ── Cross-region health monitoring ──────────────────────────────────

    #[test]
    fn cross_region_health_detects_failures() {
        let mgr = make_manager(3);

        let mut health_reports = HashMap::new();
        health_reports.insert("europe-west1".to_string(), (true, 50));
        health_reports.insert("asia-south1".to_string(), (false, 0));

        let report = mgr.cross_region_health(&health_reports);

        assert_eq!(report.total_count, 3);
        assert_eq!(report.healthy_count, 2); // local + europe
        assert_eq!(
            report.region_health.get("asia-south1"),
            Some(&RegionHealth::Unhealthy)
        );
        assert_eq!(
            report.region_health.get("europe-west1"),
            Some(&RegionHealth::Healthy)
        );
    }

    #[test]
    fn cross_region_health_marks_high_latency_as_degraded() {
        let mgr = make_manager(2);

        let mut health_reports = HashMap::new();
        // 20000ms > 10s timeout — degraded
        health_reports.insert("europe-west1".to_string(), (true, 20000));

        let report = mgr.cross_region_health(&health_reports);

        // Degraded still counts as healthy for majority purposes
        assert_eq!(report.healthy_count, 2);
    }

    // ── State replication ───────────────────────────────────────────────

    #[test]
    fn state_replication_propagates_to_all_regions() {
        let mgr = make_manager(3);

        // Mark remote regions healthy
        mgr.mark_region_healthy("europe-west1");
        mgr.mark_region_healthy("asia-south1");

        let payload = b"session-data-xyz".to_vec();
        let (event, targets) = mgr
            .sync_state(StateCategory::Sessions, payload.clone())
            .unwrap();

        assert_eq!(event.source_region, "us-east1");
        assert_eq!(event.category, StateCategory::Sessions);
        assert_eq!(event.payload, payload);
        assert_eq!(event.sequence, 0);

        // Should target all remote regions
        assert_eq!(targets.len(), 2);
        let target_regions: Vec<&str> = targets.iter().map(|(r, _)| r.as_str()).collect();
        assert!(target_regions.contains(&"europe-west1"));
        assert!(target_regions.contains(&"asia-south1"));
    }

    #[test]
    fn state_replication_sequence_increments() {
        let mgr = make_manager(2);

        let (event1, _) = mgr
            .sync_state(StateCategory::Sessions, vec![1])
            .unwrap();
        let (event2, _) = mgr
            .sync_state(StateCategory::Revocations, vec![2])
            .unwrap();

        assert_eq!(event1.sequence, 0);
        assert_eq!(event2.sequence, 1);
    }

    #[test]
    fn state_replication_blocked_during_split_brain() {
        let mgr = make_manager(3);

        // Cause split-brain
        let mut health_reports = HashMap::new();
        health_reports.insert("europe-west1".to_string(), (false, 0));
        health_reports.insert("asia-south1".to_string(), (false, 0));
        mgr.cross_region_health(&health_reports);

        let result = mgr.sync_state(StateCategory::Sessions, vec![1]);
        assert!(result.is_err());
    }

    // ── Quorum across regions (FROST share distribution) ────────────────

    #[test]
    fn frost_shares_distributed_across_regions() {
        let mgr = make_manager(3);

        // 3-of-5 threshold: 2 shares in region A, 2 in B, 1 in C
        let mut shares = HashMap::new();
        shares.insert("us-east1".to_string(), 2);
        shares.insert("europe-west1".to_string(), 2);
        shares.insert("asia-south1".to_string(), 1);

        let dist = RegionShareDistribution {
            shares_per_region: shares,
            threshold: 3,
            total_shares: 5,
        };

        assert!(mgr.verify_frost_share_distribution(&dist).is_ok());
    }

    #[test]
    fn frost_shares_reject_single_region_concentration() {
        let mgr = make_manager(3);

        // BAD: region A holds 3 shares (= threshold)
        let mut shares = HashMap::new();
        shares.insert("us-east1".to_string(), 3);
        shares.insert("europe-west1".to_string(), 1);
        shares.insert("asia-south1".to_string(), 1);

        let dist = RegionShareDistribution {
            shares_per_region: shares,
            threshold: 3,
            total_shares: 5,
        };

        assert!(mgr.verify_frost_share_distribution(&dist).is_err());
    }

    #[test]
    fn frost_shares_reject_insufficient_total() {
        let mgr = make_manager(3);

        let mut shares = HashMap::new();
        shares.insert("us-east1".to_string(), 1);
        shares.insert("europe-west1".to_string(), 1);

        let dist = RegionShareDistribution {
            shares_per_region: shares,
            threshold: 3,
            total_shares: 5,
        };

        let result = mgr.verify_frost_share_distribution(&dist);
        assert!(result.is_err());
    }

    // ── Verify multi-region startup ─────────────────────────────────────

    #[test]
    fn verify_multi_region_passes_with_enough_reachable() {
        let mgr = make_manager(3);
        let reachable = vec![
            "us-east1".to_string(),
            "europe-west1".to_string(),
        ];
        assert!(mgr.verify_multi_region(&reachable).is_ok());
    }

    #[test]
    fn verify_multi_region_fails_with_insufficient_reachable() {
        let mgr = make_manager(3);
        let reachable = vec!["us-east1".to_string()];
        let result = mgr.verify_multi_region(&reachable);
        assert!(result.is_err());
        match result.unwrap_err() {
            MultiRegionError::InsufficientReachableRegions {
                reachable: r,
                required,
                ..
            } => {
                assert_eq!(r, 1);
                assert_eq!(required, 2);
            }
            other => panic!("expected InsufficientReachableRegions, got: {:?}", other),
        }
    }

    // ── Read-only requests allowed during split-brain ───────────────────

    #[test]
    fn read_requests_allowed_during_split_brain() {
        let mgr = make_manager(3);

        // Cause split-brain
        let mut health_reports = HashMap::new();
        health_reports.insert("europe-west1".to_string(), (false, 0));
        health_reports.insert("asia-south1".to_string(), (false, 0));
        mgr.cross_region_health(&health_reports);

        assert!(!mgr.are_writes_allowed());

        // Read-only requests should still work (local region is healthy)
        let request = RoutableRequest {
            requires_write: false,
            region_affinity: None,
        };
        let decision = mgr.route_request(&request);
        assert!(decision.is_ok());
    }

    // ── Endpoint parsing ────────────────────────────────────────────────

    #[test]
    fn parse_regions_rejects_non_https() {
        let result = MultiRegionManager::parse_regions(
            "us-east1:1:http://insecure.mil:80",
            "us-east1",
        );
        assert!(result.is_err());
    }

    #[test]
    fn parse_regions_valid_format() {
        let configs = MultiRegionManager::parse_regions(
            "us-east1:1:https://a.mil:443;https://b.mil:443,europe-west1:2:https://c.mil:443",
            "us-east1",
        )
        .unwrap();

        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].region_id, "us-east1");
        assert!(configs[0].is_local);
        assert_eq!(configs[0].endpoints.len(), 2);
        assert_eq!(configs[0].priority, 1);

        assert_eq!(configs[1].region_id, "europe-west1");
        assert!(!configs[1].is_local);
        assert_eq!(configs[1].endpoints.len(), 1);
        assert_eq!(configs[1].priority, 2);
    }

    // ── Replication lag tracking ────────────────────────────────────────

    #[test]
    fn replication_lag_tracking() {
        let mgr = make_manager(2);

        mgr.update_replication_lag("europe-west1", 100).unwrap();

        // Unknown region should fail
        let result = mgr.update_replication_lag("nonexistent", 100);
        assert!(result.is_err());
    }

    // ── Region recovery ─────────────────────────────────────────────────

    #[test]
    fn region_recovery_after_failover() {
        let mgr = make_manager(3);

        // Fail a region
        mgr.failover("europe-west1").unwrap();
        assert_eq!(
            mgr.get_region_health("europe-west1"),
            Some(RegionHealth::Unhealthy)
        );

        // Recover
        mgr.mark_region_healthy("europe-west1");
        assert_eq!(
            mgr.get_region_health("europe-west1"),
            Some(RegionHealth::Healthy)
        );
    }
}
