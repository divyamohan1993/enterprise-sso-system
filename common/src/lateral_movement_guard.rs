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
use sha2::Sha512;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type HmacSha512 = Hmac<Sha512>;

/// Maximum age for channel bindings (seconds). Default 30s, configurable via
/// `MILNET_CHANNEL_BINDING_MAX_AGE_SECS`.
fn max_binding_age_secs() -> i64 {
    std::env::var("MILNET_CHANNEL_BINDING_MAX_AGE_SECS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(30)
}

/// Default grace period for dual-key rotation (seconds). Configurable via
/// `MILNET_CHANNEL_KEY_ROTATION_GRACE_SECS`.
fn rotation_grace_period_secs() -> u64 {
    std::env::var("MILNET_CHANNEL_KEY_ROTATION_GRACE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(60)
}

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
    /// HMAC-SHA512 over (channel_id || nonce || timestamp).
    pub hmac: [u8; 64],
}

/// Alert level for lateral movement detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertLevel {
    /// 3+ distinct channels from one IP -- suspicious but may be legitimate.
    Warning,
    /// 5+ distinct channels from one IP -- almost certainly an attack.
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

/// State for a channel key that supports dual-key rotation.
pub struct ChannelKeyState {
    /// Current active HMAC key.
    pub current_key: [u8; 64],
    /// Previous key retained during grace period for in-flight message verification.
    pub previous_key: Option<[u8; 64]>,
    /// When the previous key was retired (start of grace period).
    pub previous_key_retired_at: Option<Instant>,
    /// Whether a rotation has been requested but not yet executed.
    rotation_flag: AtomicBool,
}

impl ChannelKeyState {
    pub fn new(key: [u8; 64]) -> Self {
        Self {
            current_key: key,
            previous_key: None,
            previous_key_retired_at: None,
            rotation_flag: AtomicBool::new(false),
        }
    }

    pub fn flag_for_rotation(&self) {
        self.rotation_flag.store(true, Ordering::SeqCst);
    }

    pub fn is_rotation_flagged(&self) -> bool {
        self.rotation_flag.load(Ordering::SeqCst)
    }
}

/// Tracks per-channel activity and detects cross-channel lateral movement.
pub struct LateralMovementDetector {
    /// Per-IP activity within the detection window.
    ip_activity: HashMap<String, IpActivity>,
    /// Detection window duration (default: 5 minutes).
    window: Duration,
    /// Channels flagged for key rotation (legacy flag set).
    rotation_pending: HashSet<(u8, u8)>,
    /// Per-channel key state supporting dual-key rotation.
    channel_keys: HashMap<(u8, u8), ChannelKeyState>,
}

impl LateralMovementDetector {
    /// Create a new detector with default 5-minute detection window.
    pub fn new() -> Self {
        Self {
            ip_activity: HashMap::new(),
            window: Duration::from_secs(300),
            rotation_pending: HashSet::new(),
            channel_keys: HashMap::new(),
        }
    }

    /// Register a channel key for managed rotation.
    pub fn register_channel_key(&mut self, channel: ChannelId, key: [u8; 64]) {
        let channel_key = (channel.0 as u8, channel.1 as u8);
        self.channel_keys.insert(channel_key, ChannelKeyState::new(key));
    }

    /// Get the current key for a channel.
    pub fn get_channel_key(&self, channel: ChannelId) -> Option<&[u8; 64]> {
        let ck = (channel.0 as u8, channel.1 as u8);
        self.channel_keys.get(&ck).map(|s| &s.current_key)
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
    /// and timestamp using the provided key. Rejects bindings older than
    /// `MAX_BINDING_AGE` (default 30s, configurable via env var).
    pub fn verify_channel_binding(
        binding: &ChannelBinding,
        hmac_key: &[u8; 64],
    ) -> bool {
        // Timestamp max-age validation
        let now = crate::secure_time::secure_now_secs_i64();
        let max_age = max_binding_age_secs();
        let age = (now - binding.timestamp).abs();
        if age > max_age {
            tracing::warn!(
                target: "siem",
                channel_src = ?binding.channel_id.0,
                channel_dst = ?binding.channel_id.1,
                binding_timestamp = binding.timestamp,
                now = now,
                age_secs = age,
                max_age_secs = max_age,
                "SECURITY WARNING: channel binding timestamp expired or clock-skewed -- possible replay attack"
            );
            return false;
        }

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
    ///
    /// If the channel has a registered key state, the rotation flag is set
    /// atomically. Call `check_and_rotate` to execute pending rotations.
    pub fn rotate_channel_key(&mut self, channel: ChannelId) {
        let channel_key = (channel.0 as u8, channel.1 as u8);
        self.rotation_pending.insert(channel_key);
        if let Some(state) = self.channel_keys.get(&channel_key) {
            state.flag_for_rotation();
        }
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

    /// Check all channels for pending rotations and execute them.
    ///
    /// For each channel with a pending rotation flag:
    /// 1. Generate a new HMAC key via HKDF-SHA512 with fresh entropy
    /// 2. Move the current key to `previous_key` (dual-key period)
    /// 3. After the grace period, remove the old key
    pub fn check_and_rotate(&mut self) {
        let grace = Duration::from_secs(rotation_grace_period_secs());
        let channels_to_check: Vec<(u8, u8)> = self.channel_keys.keys().copied().collect();

        for ck in channels_to_check {
            let state = match self.channel_keys.get_mut(&ck) {
                Some(s) => s,
                None => continue,
            };

            // Expire old key if grace period has elapsed
            if let Some(retired_at) = state.previous_key_retired_at {
                if retired_at.elapsed() >= grace {
                    if let Some(mut old_key) = state.previous_key.take() {
                        zeroize::Zeroize::zeroize(&mut old_key);
                    }
                    state.previous_key_retired_at = None;
                }
            }

            // Execute rotation if flagged
            if state.rotation_flag.load(Ordering::SeqCst) {
                let mut ikm = [0u8; 64];
                getrandom::getrandom(&mut ikm).unwrap_or_else(|e| {
                    tracing::error!("FATAL: CSPRNG failure during key rotation: {e}");
                    std::process::exit(1);
                });

                let hk = hkdf::Hkdf::<Sha512>::new(None, &ikm);
                let mut new_key = [0u8; 64];
                hk.expand(b"milnet-channel-key-rotation", &mut new_key)
                    .unwrap_or_else(|e| {
                        tracing::error!("FATAL: HKDF expansion failed during key rotation: {e}");
                        std::process::exit(1);
                    });
                zeroize::Zeroize::zeroize(&mut ikm);

                if let Some(mut old_prev) = state.previous_key.take() {
                    zeroize::Zeroize::zeroize(&mut old_prev);
                }
                state.previous_key = Some(state.current_key);
                state.current_key = new_key;
                state.previous_key_retired_at = Some(Instant::now());
                state.rotation_flag.store(false, Ordering::SeqCst);
                self.rotation_pending.remove(&ck);

                tracing::info!(
                    target: "siem",
                    channel_src = ck.0,
                    channel_dst = ck.1,
                    "channel key rotation completed -- dual-key period active"
                );
            }
        }
    }

    /// Verify a channel binding against the current key, falling back to the
    /// previous key during the dual-key grace period.
    pub fn verify_channel_binding_with_rotation(
        &self,
        binding: &ChannelBinding,
        channel: ChannelId,
    ) -> bool {
        let ck = (channel.0 as u8, channel.1 as u8);
        if let Some(state) = self.channel_keys.get(&ck) {
            if Self::verify_channel_binding(binding, &state.current_key) {
                return true;
            }
            if let Some(ref prev_key) = state.previous_key {
                return Self::verify_channel_binding(binding, prev_key);
            }
        }
        false
    }
}

impl Default for LateralMovementDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the HMAC-SHA512 for a channel binding (CNSA 2.0 compliant).
fn compute_binding_mac(
    channel: ChannelId,
    nonce: &[u8; 16],
    timestamp: i64,
    hmac_key: &[u8; 64],
) -> [u8; 64] {
    let mut mac =
        match HmacSha512::new_from_slice(hmac_key) {
            Ok(m) => m,
            Err(e) => {
                tracing::error!("FATAL: HMAC-SHA512 key init failed for channel binding: {e}");
                std::process::exit(1);
            }
        };
    mac.update(&[channel.0 as u8, channel.1 as u8]);
    mac.update(nonce);
    mac.update(&timestamp.to_le_bytes());
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 64];
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
    fn fresh_binding_accepted() {
        let key = [0x42u8; 64];
        let channel = (ModuleId::Gateway, ModuleId::Orchestrator);
        let binding = LateralMovementDetector::create_channel_binding(channel, &key);
        assert!(LateralMovementDetector::verify_channel_binding(&binding, &key));
    }

    #[test]
    fn expired_binding_rejected() {
        let key = [0x42u8; 64];
        let channel = (ModuleId::Gateway, ModuleId::Orchestrator);
        let mut binding = LateralMovementDetector::create_channel_binding(channel, &key);

        // Set timestamp to 60 seconds ago (beyond 30s max age)
        let old_ts = binding.timestamp - 60;
        binding.timestamp = old_ts;
        binding.hmac = compute_binding_mac(channel, &binding.nonce, old_ts, &key);

        assert!(
            !LateralMovementDetector::verify_channel_binding(&binding, &key),
            "binding with timestamp >30s old must be rejected"
        );
    }

    #[test]
    fn binding_at_boundary_accepted() {
        let key = [0x42u8; 64];
        let channel = (ModuleId::Gateway, ModuleId::Orchestrator);
        // Fresh binding: age ~0, well within 30s
        let binding = LateralMovementDetector::create_channel_binding(channel, &key);
        assert!(
            LateralMovementDetector::verify_channel_binding(&binding, &key),
            "binding at creation time must be accepted"
        );
    }

    #[test]
    fn binding_with_clock_skew_future() {
        let key = [0x42u8; 64];
        let channel = (ModuleId::Gateway, ModuleId::Orchestrator);
        let mut binding = LateralMovementDetector::create_channel_binding(channel, &key);

        // Set timestamp 10 seconds in the future (within 30s tolerance)
        let future_ts = binding.timestamp + 10;
        binding.timestamp = future_ts;
        binding.hmac = compute_binding_mac(channel, &binding.nonce, future_ts, &key);

        assert!(
            LateralMovementDetector::verify_channel_binding(&binding, &key),
            "binding with minor future clock skew should be accepted"
        );
    }

    #[test]
    fn adversarial_replayed_binding_one_hour_old() {
        let key = [0x42u8; 64];
        let channel = (ModuleId::Orchestrator, ModuleId::Risk);
        let mut binding = LateralMovementDetector::create_channel_binding(channel, &key);

        let old_ts = binding.timestamp - 3600;
        binding.timestamp = old_ts;
        binding.hmac = compute_binding_mac(channel, &binding.nonce, old_ts, &key);

        assert!(
            !LateralMovementDetector::verify_channel_binding(&binding, &key),
            "replayed binding from 1 hour ago must be rejected"
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

    #[test]
    fn key_rotation_generates_new_distinct_key() {
        let mut detector = LateralMovementDetector::new();
        let ch = (ModuleId::Gateway, ModuleId::Orchestrator);
        let initial_key = [0x42u8; 64];
        detector.register_channel_key(ch, initial_key);

        let old_key = *detector.get_channel_key(ch).unwrap();
        detector.rotate_channel_key(ch);
        detector.check_and_rotate();

        let new_key = *detector.get_channel_key(ch).unwrap();
        assert_ne!(old_key, new_key, "rotated key must differ from original");
    }

    #[test]
    fn dual_key_period_allows_old_bindings() {
        let mut detector = LateralMovementDetector::new();
        let ch = (ModuleId::Gateway, ModuleId::Orchestrator);
        let initial_key = [0x42u8; 64];
        detector.register_channel_key(ch, initial_key);

        let binding = LateralMovementDetector::create_channel_binding(ch, &initial_key);

        detector.rotate_channel_key(ch);
        detector.check_and_rotate();

        assert!(
            detector.verify_channel_binding_with_rotation(&binding, ch),
            "old binding must verify during dual-key grace period"
        );
    }

    #[test]
    fn old_key_removed_after_grace_period() {
        let mut detector = LateralMovementDetector::new();
        let ch = (ModuleId::Gateway, ModuleId::Orchestrator);
        let initial_key = [0x42u8; 64];
        detector.register_channel_key(ch, initial_key);

        detector.rotate_channel_key(ch);
        detector.check_and_rotate();

        // Backdate retirement to simulate grace period expiry
        let ck = (ch.0 as u8, ch.1 as u8);
        if let Some(state) = detector.channel_keys.get_mut(&ck) {
            state.previous_key_retired_at = Some(Instant::now() - Duration::from_secs(120));
        }
        detector.check_and_rotate();

        let state = detector.channel_keys.get(&ck).unwrap();
        assert!(
            state.previous_key.is_none(),
            "previous key must be removed after grace period"
        );
    }

    #[test]
    fn rotation_under_concurrent_flag() {
        let mut detector = LateralMovementDetector::new();
        let ch = (ModuleId::Tss, ModuleId::Verifier);
        let initial_key = [0x55u8; 64];
        detector.register_channel_key(ch, initial_key);

        detector.rotate_channel_key(ch);
        detector.rotate_channel_key(ch);
        detector.rotate_channel_key(ch);
        detector.check_and_rotate();

        let new_key = *detector.get_channel_key(ch).unwrap();
        assert_ne!(initial_key, new_key, "key must have rotated");

        let ck = (ch.0 as u8, ch.1 as u8);
        let state = detector.channel_keys.get(&ck).unwrap();
        assert!(!state.is_rotation_flagged(), "rotation flag must be cleared");
    }

    #[test]
    fn adversarial_cross_channel_stolen_binding() {
        let key_a = [0x42u8; 64];
        let key_b = [0x99u8; 64];
        let channel_a = (ModuleId::Gateway, ModuleId::Orchestrator);
        let channel_b = (ModuleId::Orchestrator, ModuleId::Risk);

        let binding_a = LateralMovementDetector::create_channel_binding(channel_a, &key_a);

        assert!(
            !LateralMovementDetector::verify_channel_binding(&binding_a, &key_b),
            "stolen binding from channel A must not verify on channel B"
        );

        let mut forged = binding_a.clone();
        forged.channel_id = channel_b;
        assert!(
            !LateralMovementDetector::verify_channel_binding(&forged, &key_a),
            "forged channel ID must invalidate the HMAC"
        );
    }
}
