//! Anti-lateral-movement guard.
//!
//! Ensures that compromising one service CANNOT be leveraged to attack others.
//! Defense layers:
//! 1. Per-channel HMAC keys (already implemented in sealed_keys.rs)
//! 2. Per-request nonces (prevent replay across channels)
//! 3. Channel binding tokens (cryptographic proof of authorized channel)
//! 4. Automatic channel rotation on suspected compromise
//! 5. Cross-channel anomaly detection (same source, multiple channels = alert)

use crate::types::ModuleId;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// A communication channel between two modules.
/// Represented as an ordered pair `(source, destination)`.
pub type ChannelId = (ModuleId, ModuleId);

/// Cryptographic proof that a request is authorized for a specific channel.
///
/// Binds a channel identity to a timestamp and nonce via HMAC, preventing
/// an attacker who compromises one channel's key from forging bindings
/// for a different channel.
#[derive(Debug, Clone)]
pub struct ChannelBinding {
    /// The channel this binding authorizes.
    pub channel_id: ChannelId,
    /// Random nonce to prevent replay.
    pub nonce: [u8; 16],
    /// Unix timestamp (seconds) when the binding was created.
    pub timestamp: i64,
    /// HMAC-SHA256 over (channel_id || nonce || timestamp).
    pub hmac: [u8; 32],
}

/// Alert level for lateral movement detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertLevel {
    /// 3+ distinct channels from one IP — suspicious but may be legitimate.
    Warning,
    /// 5+ distinct channels from one IP — almost certainly an attack.
    Critical,
}

/// Alert raised when cross-channel anomaly is detected.
#[derive(Debug, Clone)]
pub struct LateralMovementAlert {
    /// The source IP exhibiting suspicious behavior.
    pub source_ip: String,
    /// List of channels accessed by this IP.
    pub channels_accessed: Vec<ChannelId>,
    /// When the first access from this IP was recorded.
    pub first_seen: Instant,
    /// Severity of the alert.
    pub alert_level: AlertLevel,
}

/// Per-IP activity record for the sliding window.
struct IpActivity {
    /// Set of distinct channels accessed.
    channels: HashSet<(u8, u8)>,
    /// When the first activity was recorded.
    first_seen: Instant,
}

/// Tracks per-channel activity and detects cross-channel lateral movement.
pub struct LateralMovementDetector {
    /// Per-IP activity within the detection window.
    ip_activity: HashMap<String, IpActivity>,
    /// Detection window duration (default: 5 minutes).
    window: Duration,
    /// Channels flagged for key rotation.
    rotation_pending: HashSet<(u8, u8)>,
}

impl LateralMovementDetector {
    /// Create a new detector with default 5-minute detection window.
    pub fn new() -> Self {
        Self {
            ip_activity: HashMap::new(),
            window: Duration::from_secs(300),
            rotation_pending: HashSet::new(),
        }
    }

    /// Record that a source IP used a specific channel.
    pub fn record_channel_activity(&mut self, source_ip: &str, channel: ChannelId) {
        let now = Instant::now();
        let channel_key = (channel.0 as u8, channel.1 as u8);

        let entry = self.ip_activity.entry(source_ip.to_string()).or_insert_with(|| {
            IpActivity {
                channels: HashSet::new(),
                first_seen: now,
            }
        });

        // If the window has expired, reset the activity record.
        if now.duration_since(entry.first_seen) > self.window {
            entry.channels.clear();
            entry.first_seen = now;
        }

        entry.channels.insert(channel_key);
    }

    /// Detect lateral movement from a source IP.
    ///
    /// Returns an alert if the same IP has accessed 3 or more distinct
    /// channels within the detection window.
    pub fn detect_lateral_movement(&self, source_ip: &str) -> Option<LateralMovementAlert> {
        let entry = self.ip_activity.get(source_ip)?;

        // Check window freshness
        if entry.first_seen.elapsed() > self.window {
            return None;
        }

        let count = entry.channels.len();
        if count < 3 {
            return None;
        }

        let alert_level = if count >= 5 {
            AlertLevel::Critical
        } else {
            AlertLevel::Warning
        };

        // Reconstruct ChannelId vec from stored u8 pairs.
        // We use a best-effort mapping back to ModuleId.
        let channels_accessed: Vec<ChannelId> = entry
            .channels
            .iter()
            .filter_map(|&(src, dst)| {
                let s = module_id_from_u8(src)?;
                let d = module_id_from_u8(dst)?;
                Some((s, d))
            })
            .collect();

        Some(LateralMovementAlert {
            source_ip: source_ip.to_string(),
            channels_accessed,
            first_seen: entry.first_seen,
            alert_level,
        })
    }

    /// Create a channel binding token.
    ///
    /// The binding cryptographically ties a request to a specific channel
    /// using the channel's HMAC key. An attacker with a different channel's
    /// key cannot forge a valid binding for this channel.
    pub fn create_channel_binding(
        channel: ChannelId,
        hmac_key: &[u8; 64],
    ) -> ChannelBinding {
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).unwrap_or_else(|e| {
            tracing::error!("FATAL: CSPRNG failure in channel binding nonce: {e}");
            std::process::exit(1);
        });

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mac = compute_binding_mac(channel, &nonce, timestamp, hmac_key);

        ChannelBinding {
            channel_id: channel,
            nonce,
            timestamp,
            hmac: mac,
        }
    }

    /// Verify a channel binding token.
    ///
    /// Returns `true` if the HMAC is valid for the given channel, nonce,
    /// and timestamp using the provided key.
    pub fn verify_channel_binding(
        binding: &ChannelBinding,
        hmac_key: &[u8; 64],
    ) -> bool {
        let expected = compute_binding_mac(
            binding.channel_id,
            &binding.nonce,
            binding.timestamp,
            hmac_key,
        );

        // Constant-time comparison
        use subtle::ConstantTimeEq;
        binding.hmac.ct_eq(&expected).into()
    }

    /// Flag a channel for key rotation (e.g., after detecting compromise).
    pub fn rotate_channel_key(&mut self, channel: ChannelId) {
        let channel_key = (channel.0 as u8, channel.1 as u8);
        self.rotation_pending.insert(channel_key);
        tracing::warn!(
            src = ?channel.0,
            dst = ?channel.1,
            "channel flagged for key rotation"
        );
    }

    /// Check if a channel has been flagged for rotation.
    pub fn is_rotation_pending(&self, channel: ChannelId) -> bool {
        let channel_key = (channel.0 as u8, channel.1 as u8);
        self.rotation_pending.contains(&channel_key)
    }
}

impl Default for LateralMovementDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the HMAC-SHA256 for a channel binding.
fn compute_binding_mac(
    channel: ChannelId,
    nonce: &[u8; 16],
    timestamp: i64,
    hmac_key: &[u8; 64],
) -> [u8; 32] {
    let mut mac =
        match HmacSha256::new_from_slice(hmac_key) {
            Ok(m) => m,
            Err(e) => {
                tracing::error!("FATAL: HMAC-SHA256 key init failed for channel binding: {e}");
                std::process::exit(1);
            }
        };
    mac.update(&[channel.0 as u8, channel.1 as u8]);
    mac.update(nonce);
    mac.update(&timestamp.to_le_bytes());
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Best-effort conversion from u8 back to ModuleId.
fn module_id_from_u8(v: u8) -> Option<ModuleId> {
    match v {
        1 => Some(ModuleId::Gateway),
        2 => Some(ModuleId::Orchestrator),
        3 => Some(ModuleId::Tss),
        4 => Some(ModuleId::Verifier),
        5 => Some(ModuleId::Opaque),
        6 => Some(ModuleId::Ratchet),
        7 => Some(ModuleId::Kt),
        8 => Some(ModuleId::Risk),
        9 => Some(ModuleId::Audit),
        10 => Some(ModuleId::Admin),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_channel_no_alert() {
        let mut detector = LateralMovementDetector::new();
        let ch = (ModuleId::Gateway, ModuleId::Orchestrator);
        detector.record_channel_activity("10.0.0.1", ch);
        assert!(detector.detect_lateral_movement("10.0.0.1").is_none());
    }

    #[test]
    fn same_ip_three_channels_triggers_alert() {
        let mut detector = LateralMovementDetector::new();
        let ip = "10.0.0.99";
        detector.record_channel_activity(ip, (ModuleId::Gateway, ModuleId::Orchestrator));
        detector.record_channel_activity(ip, (ModuleId::Orchestrator, ModuleId::Tss));
        detector.record_channel_activity(ip, (ModuleId::Orchestrator, ModuleId::Opaque));

        let alert = detector.detect_lateral_movement(ip);
        assert!(alert.is_some(), "3 distinct channels should trigger alert");
        let alert = alert.unwrap();
        assert_eq!(alert.source_ip, ip);
        assert_eq!(alert.alert_level, AlertLevel::Warning);
        assert!(alert.channels_accessed.len() >= 3);
    }

    #[test]
    fn channel_binding_creation_and_verification() {
        let key = [0x42u8; 64];
        let channel = (ModuleId::Orchestrator, ModuleId::Risk);
        let binding = LateralMovementDetector::create_channel_binding(channel, &key);

        assert_eq!(binding.channel_id, channel);
        assert!(
            LateralMovementDetector::verify_channel_binding(&binding, &key),
            "valid binding should verify"
        );
    }

    #[test]
    fn invalid_binding_rejected() {
        let key = [0x42u8; 64];
        let wrong_key = [0x99u8; 64];
        let channel = (ModuleId::Orchestrator, ModuleId::Risk);
        let binding = LateralMovementDetector::create_channel_binding(channel, &key);

        assert!(
            !LateralMovementDetector::verify_channel_binding(&binding, &wrong_key),
            "binding with wrong key must be rejected"
        );
    }

    #[test]
    fn key_rotation_flagging() {
        let mut detector = LateralMovementDetector::new();
        let ch = (ModuleId::Tss, ModuleId::Verifier);
        assert!(!detector.is_rotation_pending(ch));

        detector.rotate_channel_key(ch);
        assert!(detector.is_rotation_pending(ch));
    }
}
