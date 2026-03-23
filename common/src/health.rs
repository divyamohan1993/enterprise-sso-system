//! Service health checking with liveness probes and peer monitoring.

use std::collections::HashMap;
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
    check_interval: Duration,
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
            check_interval: Duration::from_secs(10),
            unhealthy_threshold: Duration::from_secs(30),
            degraded_threshold: Duration::from_secs(15),
        }
    }

    /// Record a successful interaction with a peer
    pub fn record_success(&self, peer: &str, response_time_ms: f64) {
        let mut peers = self.peers.lock().unwrap();
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
        let mut peers = self.peers.lock().unwrap();
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
        let peers = self.peers.lock().unwrap();
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
        let peers = self.peers.lock().unwrap();
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
}

impl Default for HealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}
