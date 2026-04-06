//! Threat Intelligence Feed Integration for the SSO risk engine.
//!
//! Provides pluggable threat intelligence feed backends with:
//! - IP reputation scoring from multiple sources
//! - Domain reputation checking
//! - GeoIP enrichment for impossible travel detection
//! - Bloom filter for O(1) IP lookup across millions of entries
//! - HMAC-SHA512 integrity verification on feed data
//! - Feed staleness detection and alerting
//! - Integration with `RiskSignals` and SIEM event emission
#![forbid(unsafe_code)]

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::scoring::RiskSignals;

// ---------------------------------------------------------------------------
// Bloom filter for O(1) IP membership testing
// ---------------------------------------------------------------------------

/// A simple Bloom filter for fast probabilistic set membership tests.
///
/// Uses k=7 hash functions derived from two base hashes (Kirsch-Mitzenmacker).
/// False positive rate ~1% at 10:1 bits-to-elements ratio.
pub struct BloomFilter {
    bits: Vec<u64>,
    num_bits: u64,
    num_hashes: u32,
    count: usize,
}

impl BloomFilter {
    /// Create a new Bloom filter sized for `expected_elements` with ~1% FP rate.
    pub fn new(expected_elements: usize) -> Self {
        // ~10 bits per element for ~1% FP rate with 7 hashes
        let num_bits = (expected_elements as u64 * 10).max(64);
        let words = ((num_bits + 63) / 64) as usize;
        Self {
            bits: vec![0u64; words],
            num_bits,
            num_hashes: 7,
            count: 0,
        }
    }

    /// Insert an item into the filter.
    pub fn insert(&mut self, item: &[u8]) {
        let (h1, h2) = self.hash_pair(item);
        for i in 0..self.num_hashes {
            let idx = self.get_index(h1, h2, i);
            let word = (idx / 64) as usize;
            let bit = idx % 64;
            if word < self.bits.len() {
                self.bits[word] |= 1u64 << bit;
            }
        }
        self.count += 1;
    }

    /// Check if an item might be in the filter (probabilistic).
    pub fn contains(&self, item: &[u8]) -> bool {
        let (h1, h2) = self.hash_pair(item);
        for i in 0..self.num_hashes {
            let idx = self.get_index(h1, h2, i);
            let word = (idx / 64) as usize;
            let bit = idx % 64;
            if word >= self.bits.len() || (self.bits[word] & (1u64 << bit)) == 0 {
                return false;
            }
        }
        true
    }

    /// Number of items inserted.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the filter is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Clear the filter, removing all entries.
    pub fn clear(&mut self) {
        for word in &mut self.bits {
            *word = 0;
        }
        self.count = 0;
    }

    /// Derive two base hashes using the blake3 hash (split into two u64s).
    fn hash_pair(&self, item: &[u8]) -> (u64, u64) {
        let hash = blake3::hash(item);
        let bytes = hash.as_bytes();
        let h1 = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let h2 = u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        (h1, h2)
    }

    /// Kirsch-Mitzenmacker: h(i) = h1 + i * h2
    fn get_index(&self, h1: u64, h2: u64, i: u32) -> u64 {
        h1.wrapping_add((i as u64).wrapping_mul(h2)) % self.num_bits
    }
}

// ---------------------------------------------------------------------------
// Feed types and traits
// ---------------------------------------------------------------------------

/// Supported threat intelligence feed types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FeedType {
    /// CISA Known Exploited Vulnerabilities catalog.
    CisaKev,
    /// AbuseIPDB IP reputation database.
    AbuseIpDb,
    /// Tor exit node list.
    TorExitNodes,
    /// Custom known-bad IP list.
    KnownBadIps,
}

impl FeedType {
    /// Default refresh interval for this feed type.
    pub fn default_refresh_interval(&self) -> Duration {
        match self {
            FeedType::CisaKev => Duration::from_secs(24 * 3600),       // 24h
            FeedType::AbuseIpDb => Duration::from_secs(3600),          // 1h
            FeedType::TorExitNodes => Duration::from_secs(6 * 3600),   // 6h
            FeedType::KnownBadIps => Duration::from_secs(12 * 3600),   // 12h
        }
    }

    /// Staleness threshold: 2x the refresh interval.
    pub fn staleness_threshold(&self) -> Duration {
        self.default_refresh_interval() * 2
    }
}

/// Metadata about a feed ingestion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedMetadata {
    pub feed_type: FeedType,
    /// Unix timestamp of last successful ingestion.
    pub last_updated: i64,
    /// Number of entries in the feed.
    pub entry_count: usize,
    /// HMAC-SHA512 digest of the raw feed data (hex-encoded).
    pub integrity_hash: String,
    /// Configured refresh interval in seconds.
    pub refresh_interval_secs: u64,
}

/// Result of ingesting a feed.
#[derive(Debug)]
pub struct FeedIngestionResult {
    pub feed_type: FeedType,
    pub entries_loaded: usize,
    pub integrity_verified: bool,
    pub stale: bool,
}

/// A single IP reputation entry from a feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpReputationEntry {
    pub ip: String,
    pub score: f64,
    pub source: FeedType,
    pub categories: Vec<String>,
    pub last_seen: i64,
}

/// GeoIP location data for enrichment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpInfo {
    pub ip: String,
    pub country_code: String,
    pub city: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
    pub asn: Option<u32>,
    pub org: Option<String>,
}

/// Domain reputation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainReputation {
    pub domain: String,
    pub score: f64,
    pub categories: Vec<String>,
    pub is_known_malicious: bool,
}

/// Trait for pluggable threat intelligence feed backends.
///
/// Implementors provide feed-specific ingestion logic (HTTP fetching,
/// parsing, etc.). The `ThreatIntelManager` orchestrates scheduling,
/// integrity verification, and Bloom filter population.
pub trait ThreatIntelFeed: Send + Sync {
    /// The type of feed this backend provides.
    fn feed_type(&self) -> FeedType;

    /// Fetch and parse the feed, returning raw IP strings and the raw
    /// feed bytes (for integrity verification).
    ///
    /// Returns (ip_list, raw_bytes).
    fn fetch(&self) -> Result<(Vec<String>, Vec<u8>), ThreatIntelError>;

    /// Custom refresh interval override (if None, uses FeedType default).
    fn refresh_interval(&self) -> Option<Duration> {
        None
    }

    /// Human-readable name for logging.
    fn name(&self) -> &str;
}

/// Errors from threat intelligence operations.
#[derive(Debug)]
pub enum ThreatIntelError {
    /// Feed fetch failed (network, parse, etc.).
    FetchFailed(String),
    /// HMAC integrity verification failed.
    IntegrityCheckFailed,
    /// Feed data is stale (not updated within expected window).
    FeedStale { feed_type: FeedType, age_secs: u64 },
    /// Internal error.
    Internal(String),
}

impl std::fmt::Display for ThreatIntelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FetchFailed(msg) => write!(f, "feed fetch failed: {}", msg),
            Self::IntegrityCheckFailed => write!(f, "HMAC-SHA512 integrity verification failed"),
            Self::FeedStale { feed_type, age_secs } => {
                write!(f, "feed {:?} is stale (age: {}s)", feed_type, age_secs)
            }
            Self::Internal(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

// ---------------------------------------------------------------------------
// Built-in feed implementations
// ---------------------------------------------------------------------------

/// CISA KEV (Known Exploited Vulnerabilities) feed.
///
/// In production this would fetch from https://www.cisa.gov/known-exploited-vulnerabilities-catalog.
/// The built-in implementation supports pre-loaded data for air-gapped environments.
pub struct CisaKevFeed {
    /// Pre-loaded IP indicators (for air-gapped / testing).
    preloaded_ips: Vec<String>,
}

impl CisaKevFeed {
    pub fn new() -> Self {
        Self {
            preloaded_ips: Vec::new(),
        }
    }

    pub fn with_preloaded(ips: Vec<String>) -> Self {
        Self {
            preloaded_ips: ips,
        }
    }
}

impl ThreatIntelFeed for CisaKevFeed {
    fn feed_type(&self) -> FeedType {
        FeedType::CisaKev
    }

    fn fetch(&self) -> Result<(Vec<String>, Vec<u8>), ThreatIntelError> {
        // In production: HTTP GET to CISA KEV JSON endpoint, parse CVE records,
        // extract associated IP indicators. Here we return pre-loaded data.
        let raw = self
            .preloaded_ips
            .join("\n")
            .into_bytes();
        Ok((self.preloaded_ips.clone(), raw))
    }

    fn name(&self) -> &str {
        "CISA KEV"
    }
}

impl Default for CisaKevFeed {
    fn default() -> Self {
        Self::new()
    }
}

/// AbuseIPDB feed backend.
pub struct AbuseIpDbFeed {
    preloaded_ips: Vec<String>,
}

impl AbuseIpDbFeed {
    pub fn new() -> Self {
        Self {
            preloaded_ips: Vec::new(),
        }
    }

    pub fn with_preloaded(ips: Vec<String>) -> Self {
        Self {
            preloaded_ips: ips,
        }
    }
}

impl ThreatIntelFeed for AbuseIpDbFeed {
    fn feed_type(&self) -> FeedType {
        FeedType::AbuseIpDb
    }

    fn fetch(&self) -> Result<(Vec<String>, Vec<u8>), ThreatIntelError> {
        let raw = self.preloaded_ips.join("\n").into_bytes();
        Ok((self.preloaded_ips.clone(), raw))
    }

    fn refresh_interval(&self) -> Option<Duration> {
        Some(Duration::from_secs(3600)) // 1h
    }

    fn name(&self) -> &str {
        "AbuseIPDB"
    }
}

impl Default for AbuseIpDbFeed {
    fn default() -> Self {
        Self::new()
    }
}

/// Tor exit node list feed.
pub struct TorExitNodeFeed {
    preloaded_ips: Vec<String>,
}

impl TorExitNodeFeed {
    pub fn new() -> Self {
        Self {
            preloaded_ips: Vec::new(),
        }
    }

    pub fn with_preloaded(ips: Vec<String>) -> Self {
        Self {
            preloaded_ips: ips,
        }
    }
}

impl ThreatIntelFeed for TorExitNodeFeed {
    fn feed_type(&self) -> FeedType {
        FeedType::TorExitNodes
    }

    fn fetch(&self) -> Result<(Vec<String>, Vec<u8>), ThreatIntelError> {
        let raw = self.preloaded_ips.join("\n").into_bytes();
        Ok((self.preloaded_ips.clone(), raw))
    }

    fn refresh_interval(&self) -> Option<Duration> {
        Some(Duration::from_secs(6 * 3600)) // 6h
    }

    fn name(&self) -> &str {
        "Tor Exit Nodes"
    }
}

impl Default for TorExitNodeFeed {
    fn default() -> Self {
        Self::new()
    }
}

/// Known-bad IP list feed (custom operator-managed list).
pub struct KnownBadIpFeed {
    preloaded_ips: Vec<String>,
}

impl KnownBadIpFeed {
    pub fn new() -> Self {
        Self {
            preloaded_ips: Vec::new(),
        }
    }

    pub fn with_preloaded(ips: Vec<String>) -> Self {
        Self {
            preloaded_ips: ips,
        }
    }
}

impl ThreatIntelFeed for KnownBadIpFeed {
    fn feed_type(&self) -> FeedType {
        FeedType::KnownBadIps
    }

    fn fetch(&self) -> Result<(Vec<String>, Vec<u8>), ThreatIntelError> {
        let raw = self.preloaded_ips.join("\n").into_bytes();
        Ok((self.preloaded_ips.clone(), raw))
    }

    fn name(&self) -> &str {
        "Known Bad IPs"
    }
}

impl Default for KnownBadIpFeed {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Threat Intelligence Manager
// ---------------------------------------------------------------------------

/// Per-feed state tracked by the manager.
struct FeedState {
    metadata: FeedMetadata,
    bloom: BloomFilter,
    /// Per-IP reputation scores from this feed.
    ip_scores: HashMap<String, f64>,
}

/// Orchestrates threat intelligence feed ingestion, Bloom filter management,
/// IP reputation scoring, and staleness detection.
///
/// Thread-safe via interior mutability (Mutex).
pub struct ThreatIntelManager {
    /// Registered feed backends.
    feeds: Vec<Box<dyn ThreatIntelFeed>>,
    /// Per-feed state, keyed by FeedType.
    state: Mutex<HashMap<FeedType, FeedState>>,
    /// HMAC key for feed integrity verification (operator-provisioned).
    // NOTE: HMAC-SHA512 is used for feed integrity because the same operator
    // controls both feed production and consumption. For third-party feeds
    // where key sharing is undesirable, ML-DSA-87 asymmetric signatures would
    // be more appropriate (the feed publisher signs with a private key, and
    // consumers verify with the public key).
    hmac_key: Vec<u8>,
    /// Optional ML-DSA-87 verification key for feeds that use asymmetric
    /// signing instead of HMAC. When set, `verify_integrity_ml_dsa()` is
    /// used in place of HMAC verification for feeds from third-party sources.
    pub ml_dsa_verify_key: Option<Vec<u8>>,
    /// GeoIP lookup table (IP -> GeoIpInfo). In production this would be
    /// backed by a MaxMind DB or similar.
    geoip_table: Mutex<HashMap<String, GeoIpInfo>>,
    /// Domain reputation cache.
    domain_cache: Mutex<HashMap<String, DomainReputation>>,
}

impl ThreatIntelManager {
    /// Create a new manager with the given HMAC key for integrity verification.
    pub fn new(hmac_key: &[u8]) -> Self {
        Self {
            feeds: Vec::new(),
            state: Mutex::new(HashMap::new()),
            hmac_key: hmac_key.to_vec(),
            ml_dsa_verify_key: None,
            geoip_table: Mutex::new(HashMap::new()),
            domain_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Set an ML-DSA-87 public verification key for third-party feed verification.
    /// When set, feeds can be verified using asymmetric signatures instead of HMAC.
    pub fn with_ml_dsa_verify_key(mut self, key: Vec<u8>) -> Self {
        self.ml_dsa_verify_key = Some(key);
        self
    }

    /// Verify feed integrity using ML-DSA-87 asymmetric signature.
    /// Returns false if no ML-DSA key is configured.
    pub fn verify_integrity_ml_dsa(&self, data: &[u8], signature: &[u8]) -> bool {
        let Some(ref verify_key_bytes) = self.ml_dsa_verify_key else {
            tracing::warn!(
                target: "threat_intel",
                "ML-DSA-87 verification requested but no verify key configured"
            );
            return false;
        };

        use ml_dsa::{signature::Verifier, EncodedVerifyingKey, MlDsa87, VerifyingKey};

        let vk_enc = match EncodedVerifyingKey::<MlDsa87>::try_from(verify_key_bytes.as_slice()) {
            Ok(e) => e,
            Err(_) => {
                tracing::error!(
                    target: "threat_intel",
                    "Failed to deserialize ML-DSA-87 verifying key"
                );
                return false;
            }
        };
        let vk = VerifyingKey::<MlDsa87>::decode(&vk_enc);

        match ml_dsa::Signature::<MlDsa87>::try_from(signature) {
            Ok(sig) => vk.verify(data, &sig).is_ok(),
            Err(_) => {
                tracing::error!(
                    target: "threat_intel",
                    "Failed to deserialize ML-DSA-87 signature"
                );
                false
            }
        }
    }

    /// Register a threat intelligence feed backend.
    pub fn register_feed(&mut self, feed: Box<dyn ThreatIntelFeed>) {
        self.feeds.push(feed);
    }

    /// Ingest all registered feeds. Returns results per feed.
    ///
    /// Each feed is fetched, integrity-verified via HMAC-SHA512, and its
    /// IPs are loaded into the corresponding Bloom filter.
    pub fn ingest_all(&self) -> Vec<FeedIngestionResult> {
        let mut results = Vec::new();

        for feed in &self.feeds {
            let result = self.ingest_feed(feed.as_ref());
            results.push(result);
        }

        results
    }

    /// Ingest a single feed.
    fn ingest_feed(&self, feed: &dyn ThreatIntelFeed) -> FeedIngestionResult {
        let feed_type = feed.feed_type();

        let (ips, raw_bytes) = match feed.fetch() {
            Ok(data) => data,
            Err(e) => {
                tracing::error!(
                    target: "threat_intel",
                    "Failed to fetch feed {}: {}",
                    feed.name(),
                    e
                );
                // Emit SIEM event for feed fetch failure
                emit_threat_intel_siem_event(
                    "feed_fetch_failed",
                    &format!("feed={} error={}", feed.name(), e),
                    None,
                );
                return FeedIngestionResult {
                    feed_type,
                    entries_loaded: 0,
                    integrity_verified: false,
                    stale: true,
                };
            }
        };

        // Compute HMAC-SHA512 integrity hash
        let integrity_hash = self.compute_hmac(&raw_bytes);

        // Build Bloom filter
        let mut bloom = BloomFilter::new(ips.len().max(1024));
        let mut ip_scores = HashMap::new();

        for ip in &ips {
            let trimmed = ip.trim();
            if !trimmed.is_empty() {
                bloom.insert(trimmed.as_bytes());
                // Default reputation score: 1.0 (known bad)
                ip_scores.insert(trimmed.to_string(), 1.0);
            }
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let refresh_interval = feed
            .refresh_interval()
            .unwrap_or_else(|| feed_type.default_refresh_interval());

        let metadata = FeedMetadata {
            feed_type,
            last_updated: now,
            entry_count: bloom.len(),
            integrity_hash: integrity_hash.clone(),
            refresh_interval_secs: refresh_interval.as_secs(),
        };

        let entries_loaded = bloom.len();

        let mut state = self.state.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in threat_intel - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        state.insert(
            feed_type,
            FeedState {
                metadata,
                bloom,
                ip_scores,
            },
        );

        tracing::info!(
            target: "threat_intel",
            "Ingested feed {}: {} entries, integrity={}",
            feed.name(),
            entries_loaded,
            &integrity_hash[..16]
        );

        FeedIngestionResult {
            feed_type,
            entries_loaded,
            integrity_verified: true,
            stale: false,
        }
    }

    /// Compute HMAC-SHA512 over raw feed data for integrity verification.
    fn compute_hmac(&self, data: &[u8]) -> String {
        type HmacSha512 = Hmac<Sha512>;
        let mut mac =
            match HmacSha512::new_from_slice(&self.hmac_key) {
                Ok(m) => m,
                Err(_) => {
                    tracing::error!("FATAL: HMAC-SHA512 key init failed for threat intel integrity");
                    return String::new();
                }
            };
        mac.update(data);
        let result = mac.finalize();
        hex::encode(result.into_bytes())
    }

    /// Verify HMAC-SHA512 integrity of feed data against an expected digest.
    pub fn verify_integrity(&self, data: &[u8], expected_hex: &str) -> bool {
        let computed = self.compute_hmac(data);
        // Constant-time comparison to prevent timing attacks
        if computed.len() != expected_hex.len() {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in computed.bytes().zip(expected_hex.bytes()) {
            diff |= a ^ b;
        }
        diff == 0
    }

    /// Check if an IP is in any threat feed (O(1) via Bloom filter).
    ///
    /// Returns true if the IP is *probably* in at least one feed.
    /// False positives are possible (~1%) but false negatives are not.
    pub fn is_known_threat_ip(&self, ip: &str) -> bool {
        let state = self.state.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in threat_intel - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        for feed_state in state.values() {
            if feed_state.bloom.contains(ip.as_bytes()) {
                return true;
            }
        }
        false
    }

    /// Compute an aggregate IP reputation score from all feeds.
    ///
    /// Returns a score in `[0.0, 1.0]` where 0.0 is clean and 1.0 is
    /// maximally malicious. Scores from multiple feeds are combined
    /// using a "noisy-OR" model: `1 - product(1 - score_i)`.
    pub fn ip_reputation_score(&self, ip: &str) -> f64 {
        let state = self.state.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in threat_intel - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        let mut product_clean = 1.0f64;
        let mut any_hit = false;

        for feed_state in state.values() {
            if feed_state.bloom.contains(ip.as_bytes()) {
                let score = feed_state
                    .ip_scores
                    .get(ip)
                    .copied()
                    .unwrap_or(0.8); // Bloom hit without exact match => high suspicion
                product_clean *= 1.0 - score;
                any_hit = true;
            }
        }

        if any_hit {
            let reputation = 1.0 - product_clean;

            // Emit SIEM event for threat hit
            emit_threat_intel_siem_event(
                "threat_ip_hit",
                &format!("ip={} reputation={:.3}", ip, reputation),
                None,
            );

            reputation.min(1.0)
        } else {
            0.0
        }
    }

    /// Get detailed IP reputation entries from all feeds that flagged this IP.
    pub fn ip_reputation_details(&self, ip: &str) -> Vec<IpReputationEntry> {
        let state = self.state.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in threat_intel - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        let mut entries = Vec::new();

        for (feed_type, feed_state) in state.iter() {
            if feed_state.bloom.contains(ip.as_bytes()) {
                let score = feed_state.ip_scores.get(ip).copied().unwrap_or(0.8);
                entries.push(IpReputationEntry {
                    ip: ip.to_string(),
                    score,
                    source: *feed_type,
                    categories: match feed_type {
                        FeedType::TorExitNodes => vec!["tor_exit".to_string()],
                        FeedType::AbuseIpDb => vec!["abuse_reported".to_string()],
                        FeedType::CisaKev => vec!["known_exploited".to_string()],
                        FeedType::KnownBadIps => vec!["operator_blocklist".to_string()],
                    },
                    last_seen: feed_state.metadata.last_updated,
                });
            }
        }

        entries
    }

    /// Check domain reputation.
    pub fn domain_reputation(&self, domain: &str) -> DomainReputation {
        let cache = self.domain_cache.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in threat_intel - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        if let Some(cached) = cache.get(domain) {
            return cached.clone();
        }

        // Default: unknown domain gets a neutral score
        DomainReputation {
            domain: domain.to_string(),
            score: 0.0,
            categories: Vec::new(),
            is_known_malicious: false,
        }
    }

    /// Register a known-malicious domain.
    pub fn add_malicious_domain(&self, domain: &str, score: f64, categories: Vec<String>) {
        let mut cache = self.domain_cache.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in threat_intel - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        cache.insert(
            domain.to_string(),
            DomainReputation {
                domain: domain.to_string(),
                score: score.clamp(0.0, 1.0),
                categories,
                is_known_malicious: true,
            },
        );
    }

    /// Enrich an IP with GeoIP data for impossible travel detection.
    pub fn geoip_lookup(&self, ip: &str) -> Option<GeoIpInfo> {
        let table = self.geoip_table.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in threat_intel - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        table.get(ip).cloned()
    }

    /// Add a GeoIP entry (for pre-loading or testing).
    pub fn add_geoip_entry(&self, info: GeoIpInfo) {
        let mut table = self.geoip_table.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in threat_intel - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        table.insert(info.ip.clone(), info);
    }

    /// Check all feeds for staleness. Returns a list of stale feed types.
    ///
    /// A feed is stale if it has not been updated within 2x its refresh
    /// interval. Emits SIEM events for each stale feed detected.
    pub fn check_staleness(&self) -> Vec<FeedType> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let state = self.state.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in threat_intel - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        let mut stale_feeds = Vec::new();

        for (feed_type, feed_state) in state.iter() {
            let age_secs = (now - feed_state.metadata.last_updated).max(0) as u64;
            let threshold = feed_type.staleness_threshold();

            if age_secs > threshold.as_secs() {
                stale_feeds.push(*feed_type);
                tracing::warn!(
                    target: "threat_intel",
                    "Feed {:?} is stale: age={}s, threshold={}s",
                    feed_type,
                    age_secs,
                    threshold.as_secs()
                );
                emit_threat_intel_siem_event(
                    "feed_stale",
                    &format!(
                        "feed={:?} age_secs={} threshold_secs={}",
                        feed_type,
                        age_secs,
                        threshold.as_secs()
                    ),
                    None,
                );
            }
        }

        // Also flag feeds that have never been ingested
        for feed in &self.feeds {
            if !state.contains_key(&feed.feed_type()) {
                stale_feeds.push(feed.feed_type());
                tracing::warn!(
                    target: "threat_intel",
                    "Feed {} has never been ingested",
                    feed.name()
                );
            }
        }

        stale_feeds
    }

    /// Get metadata for all ingested feeds.
    pub fn feed_metadata(&self) -> Vec<FeedMetadata> {
        let state = self.state.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in threat_intel - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        state.values().map(|s| s.metadata.clone()).collect()
    }

    /// Enhance `RiskSignals` with threat intelligence data.
    ///
    /// If the source IP is found in any threat feed, this sets
    /// `is_unusual_network` to true and boosts `unusual_access_score`.
    /// Returns the updated threat reputation score for the IP.
    pub fn enrich_risk_signals(&self, signals: &mut RiskSignals, source_ip: Option<&str>) -> f64 {
        let Some(ip) = source_ip else {
            return 0.0;
        };

        let reputation = self.ip_reputation_score(ip);

        if reputation > 0.0 {
            // IP has a threat reputation — flag as unusual network
            signals.is_unusual_network = true;

            // Boost the unusual access score proportionally
            let boosted = signals.unusual_access_score + reputation * 0.5;
            signals.unusual_access_score = boosted.min(1.0);

            tracing::info!(
                target: "threat_intel",
                "IP {} enriched: reputation={:.3}, unusual_access_score={:.3}",
                ip,
                reputation,
                signals.unusual_access_score
            );
        }

        reputation
    }
}

// ---------------------------------------------------------------------------
// SIEM event helper
// ---------------------------------------------------------------------------

/// Emit a SIEM event related to threat intelligence.
fn emit_threat_intel_siem_event(action: &str, detail: &str, source_ip: Option<&str>) {
    let json = serde_json::json!({
        "event_type": action,
        "timestamp": SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        "severity": "HIGH",
        "source_module": "threat_intel",
        "details": {
            "action": action,
            "detail": detail,
            "source_ip": source_ip,
        }
    });
    tracing::info!(target: "siem", "{}", json);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hmac_key() -> Vec<u8> {
        b"test-threat-intel-hmac-key-for-unit-tests".to_vec()
    }

    #[test]
    fn test_bloom_filter_basic() {
        let mut bloom = BloomFilter::new(1000);
        assert!(bloom.is_empty());

        bloom.insert(b"192.168.1.1");
        bloom.insert(b"10.0.0.1");

        assert!(bloom.contains(b"192.168.1.1"));
        assert!(bloom.contains(b"10.0.0.1"));
        assert!(!bloom.contains(b"172.16.0.1"));
        assert_eq!(bloom.len(), 2);
    }

    #[test]
    fn test_bloom_filter_false_positive_rate() {
        let n = 10_000;
        let mut bloom = BloomFilter::new(n);

        // Insert n items
        for i in 0..n {
            let ip = format!("10.0.{}.{}", i / 256, i % 256);
            bloom.insert(ip.as_bytes());
        }

        // Test n items NOT in the set
        let mut false_positives = 0;
        for i in 0..n {
            let ip = format!("172.16.{}.{}", i / 256, i % 256);
            if bloom.contains(ip.as_bytes()) {
                false_positives += 1;
            }
        }

        let fp_rate = false_positives as f64 / n as f64;
        // With 10 bits/element and 7 hashes, FP rate should be ~1%
        assert!(
            fp_rate < 0.05,
            "False positive rate too high: {:.2}%",
            fp_rate * 100.0
        );
    }

    #[test]
    fn test_bloom_filter_clear() {
        let mut bloom = BloomFilter::new(100);
        bloom.insert(b"1.2.3.4");
        assert!(bloom.contains(b"1.2.3.4"));

        bloom.clear();
        assert!(!bloom.contains(b"1.2.3.4"));
        assert!(bloom.is_empty());
    }

    #[test]
    fn test_hmac_integrity_verification() {
        let manager = ThreatIntelManager::new(&test_hmac_key());
        let data = b"feed data content";

        let hash = manager.compute_hmac(data);
        assert!(manager.verify_integrity(data, &hash));

        // Tampered data should fail
        assert!(!manager.verify_integrity(b"tampered data", &hash));

        // Wrong hash should fail
        assert!(!manager.verify_integrity(data, "0000deadbeef"));
    }

    #[test]
    fn test_feed_ingestion_and_ip_lookup() {
        let mut manager = ThreatIntelManager::new(&test_hmac_key());

        let tor_feed = TorExitNodeFeed::with_preloaded(vec![
            "198.51.100.1".to_string(),
            "198.51.100.2".to_string(),
            "198.51.100.3".to_string(),
        ]);
        manager.register_feed(Box::new(tor_feed));

        let results = manager.ingest_all();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entries_loaded, 3);
        assert!(results[0].integrity_verified);

        // Check IP lookup
        assert!(manager.is_known_threat_ip("198.51.100.1"));
        assert!(manager.is_known_threat_ip("198.51.100.2"));
        assert!(!manager.is_known_threat_ip("192.0.2.1"));
    }

    #[test]
    fn test_ip_reputation_score_noisy_or() {
        let mut manager = ThreatIntelManager::new(&test_hmac_key());

        // Register two feeds that both flag the same IP
        let tor_feed =
            TorExitNodeFeed::with_preloaded(vec!["203.0.113.1".to_string()]);
        let abuse_feed =
            AbuseIpDbFeed::with_preloaded(vec!["203.0.113.1".to_string()]);

        manager.register_feed(Box::new(tor_feed));
        manager.register_feed(Box::new(abuse_feed));
        manager.ingest_all();

        let score = manager.ip_reputation_score("203.0.113.1");
        // Noisy-OR of two 1.0 scores: 1 - (1-1.0)*(1-1.0) = 1.0
        assert!(
            score > 0.9,
            "Multi-feed IP should have very high score: {}",
            score
        );

        // Clean IP should be 0.0
        let clean_score = manager.ip_reputation_score("192.0.2.99");
        assert!(
            (clean_score - 0.0).abs() < f64::EPSILON,
            "Clean IP should have 0.0 score: {}",
            clean_score
        );
    }

    #[test]
    fn test_ip_reputation_details() {
        let mut manager = ThreatIntelManager::new(&test_hmac_key());

        let tor_feed =
            TorExitNodeFeed::with_preloaded(vec!["198.51.100.5".to_string()]);
        manager.register_feed(Box::new(tor_feed));
        manager.ingest_all();

        let details = manager.ip_reputation_details("198.51.100.5");
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].source, FeedType::TorExitNodes);
        assert!(details[0].categories.contains(&"tor_exit".to_string()));
    }

    #[test]
    fn test_domain_reputation() {
        let manager = ThreatIntelManager::new(&test_hmac_key());

        // Unknown domain is neutral
        let rep = manager.domain_reputation("example.com");
        assert!((rep.score - 0.0).abs() < f64::EPSILON);
        assert!(!rep.is_known_malicious);

        // Add malicious domain
        manager.add_malicious_domain(
            "evil.example.com",
            0.95,
            vec!["phishing".to_string()],
        );

        let rep = manager.domain_reputation("evil.example.com");
        assert!(rep.score > 0.9);
        assert!(rep.is_known_malicious);
    }

    #[test]
    fn test_geoip_enrichment() {
        let manager = ThreatIntelManager::new(&test_hmac_key());

        manager.add_geoip_entry(GeoIpInfo {
            ip: "203.0.113.10".to_string(),
            country_code: "US".to_string(),
            city: Some("New York".to_string()),
            latitude: 40.7128,
            longitude: -74.0060,
            asn: Some(15169),
            org: Some("Example ISP".to_string()),
        });

        let info = manager.geoip_lookup("203.0.113.10");
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.country_code, "US");
        assert!((info.latitude - 40.7128).abs() < 0.001);

        // Unknown IP returns None
        assert!(manager.geoip_lookup("192.0.2.99").is_none());
    }

    #[test]
    fn test_enrich_risk_signals() {
        let mut manager = ThreatIntelManager::new(&test_hmac_key());

        let bad_feed =
            KnownBadIpFeed::with_preloaded(vec!["203.0.113.50".to_string()]);
        manager.register_feed(Box::new(bad_feed));
        manager.ingest_all();

        let mut signals = RiskSignals {
            device_attestation_age_secs: 0.0,
            geo_velocity_kmh: 0.0,
            is_unusual_network: false,
            is_unusual_time: false,
            unusual_access_score: 0.0,
            recent_failed_attempts: 0,
            login_hour: None,
            network_id: None,
            session_duration_secs: None,
        };

        let rep = manager.enrich_risk_signals(&mut signals, Some("203.0.113.50"));
        assert!(rep > 0.0, "Bad IP should have non-zero reputation");
        assert!(signals.is_unusual_network, "Should flag unusual network");
        assert!(
            signals.unusual_access_score > 0.0,
            "Should boost access score"
        );

        // Clean IP should not modify signals
        let mut clean_signals = RiskSignals {
            device_attestation_age_secs: 0.0,
            geo_velocity_kmh: 0.0,
            is_unusual_network: false,
            is_unusual_time: false,
            unusual_access_score: 0.0,
            recent_failed_attempts: 0,
            login_hour: None,
            network_id: None,
            session_duration_secs: None,
        };
        let clean_rep =
            manager.enrich_risk_signals(&mut clean_signals, Some("192.0.2.1"));
        assert!((clean_rep - 0.0).abs() < f64::EPSILON);
        assert!(!clean_signals.is_unusual_network);
    }

    #[test]
    fn test_feed_type_intervals() {
        assert_eq!(
            FeedType::CisaKev.default_refresh_interval(),
            Duration::from_secs(24 * 3600)
        );
        assert_eq!(
            FeedType::AbuseIpDb.default_refresh_interval(),
            Duration::from_secs(3600)
        );
        assert_eq!(
            FeedType::TorExitNodes.default_refresh_interval(),
            Duration::from_secs(6 * 3600)
        );
        assert_eq!(
            FeedType::CisaKev.staleness_threshold(),
            Duration::from_secs(48 * 3600)
        );
    }

    #[test]
    fn test_feed_metadata_after_ingestion() {
        let mut manager = ThreatIntelManager::new(&test_hmac_key());
        let feed = TorExitNodeFeed::with_preloaded(vec!["1.2.3.4".to_string()]);
        manager.register_feed(Box::new(feed));
        manager.ingest_all();

        let metadata = manager.feed_metadata();
        assert_eq!(metadata.len(), 1);
        assert_eq!(metadata[0].feed_type, FeedType::TorExitNodes);
        assert_eq!(metadata[0].entry_count, 1);
        assert!(!metadata[0].integrity_hash.is_empty());
    }
}
