//! Threat-intel feeds (J12) — AbuseIPDB, MaxMind GeoLite2, Shodan.
//!
//! Each feed exposes `ThreatFeed::lookup(ip)`. The aggregator caches results
//! in-memory with a TTL and produces a single 0..100 maliciousness score for
//! the risk crate via `is_malicious_ip`.
#![forbid(unsafe_code)]

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Per-feed HTTP request timeout. `is_malicious_ip` runs on the auth hot
/// path, so a slow or hostile feed must never stall an auth decision.
const FEED_TIMEOUT: Duration = Duration::from_secs(4);

/// Hard cap on the in-memory result cache. The cache key is an attacker-
/// influenceable `IpAddr`; without a bound, random-IP traffic (trivial with
/// IPv6) would exhaust memory. When the cap is reached, expired entries are
/// swept and, if still full, the oldest entry is evicted.
const CACHE_CAPACITY: usize = 100_000;

#[derive(Debug, Error)]
pub enum ThreatError {
    #[error("transport: {0}")]
    Transport(String),
    #[error("rate-limited")]
    RateLimited,
    #[error("invalid response")]
    InvalidResponse,
    /// Upstream returned a non-success HTTP status other than 429 (e.g. a
    /// 401/403 from a bad API key, or a 5xx). Surfaced so a misconfigured
    /// feed does not silently degrade to `score: 0` for every IP.
    #[error("upstream HTTP status {0}")]
    UpstreamStatus(u16),
    /// The feed is declared but has no working implementation. Returned
    /// instead of a fabricated `score: 0` so a placeholder feed can never
    /// masquerade as a real evaluation.
    #[error("feed not implemented: {0}")]
    NotImplemented(&'static str),
}

/// Reject IPs that are not publicly routable before any outbound feed call.
///
/// `is_malicious_ip` takes a caller-supplied `IpAddr` that may originate from
/// attacker-controlled input (`X-Forwarded-For`, login forms, federation
/// metadata). Forwarding loopback / private / link-local / reserved addresses
/// to a third-party feed is an SSRF and internal-recon primitive, so anything
/// not globally routable is refused here.
fn is_globally_routable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation()
                // CGNAT (RFC 6598) 100.64.0.0/10.
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 0x40)
                // "This network" 0.0.0.0/8.
                || v4.octets()[0] == 0
                // Reserved 240.0.0.0/4.
                || v4.octets()[0] >= 240)
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // Unique local addresses fc00::/7.
                || (v6.segments()[0] & 0xFE00) == 0xFC00
                // Link-local fe80::/10.
                || (v6.segments()[0] & 0xFFC0) == 0xFE80
                // Documentation 2001:db8::/32.
                || (v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0DB8)
                // IPv4-mapped: validate the embedded V4 instead of trusting it.
                || v6.to_ipv4_mapped().is_some_and(|m| !is_globally_routable(&IpAddr::V4(m))))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatScore {
    pub score: u8,
    pub source: String,
    pub categories: Vec<String>,
}

#[async_trait]
pub trait ThreatFeed: Send + Sync {
    fn name(&self) -> &'static str;
    async fn lookup(&self, ip: IpAddr) -> Result<ThreatScore, ThreatError>;
}

pub struct AbuseIpDbFeed {
    pub api_key: String,
    pub http: reqwest::Client,
}

#[async_trait]
impl ThreatFeed for AbuseIpDbFeed {
    fn name(&self) -> &'static str { "abuseipdb" }
    async fn lookup(&self, ip: IpAddr) -> Result<ThreatScore, ThreatError> {
        let resp = self.http
            .get("https://api.abuseipdb.com/api/v2/check")
            .header("Key", &self.api_key)
            .header("Accept", "application/json")
            .query(&[("ipAddress", ip.to_string())])
            .send().await
            .map_err(|e| ThreatError::Transport(e.to_string()))?;
        let status = resp.status();
        if status == 429 { return Err(ThreatError::RateLimited); }
        // Check status before parsing: a 401/403 (bad key) or 5xx returns an
        // HTML/text error body that would otherwise be mis-mapped to an empty
        // `InvalidResponse`, hiding the real cause and yielding `score: 0`.
        if !status.is_success() {
            tracing::warn!(status = status.as_u16(), "threat-intel: abuseipdb non-success status");
            return Err(ThreatError::UpstreamStatus(status.as_u16()));
        }
        let v: serde_json::Value = resp.json().await.map_err(|_| ThreatError::InvalidResponse)?;
        // Saturate rather than wrap: a confidence score is 0..=100 per spec,
        // but a defensive cast must not turn an out-of-spec 256 into 0.
        let score = v["data"]["abuseConfidenceScore"]
            .as_u64()
            .unwrap_or(0)
            .min(100) as u8;
        Ok(ThreatScore { score, source: "abuseipdb".into(), categories: vec![] })
    }
}

/// MaxMind GeoLite2 feed.
///
/// The MaxMind DB reader is not yet wired up: parsing the `.mmdb` format
/// requires the `maxminddb` crate and a provisioned database file. Until that
/// is in place, `lookup` returns [`ThreatError::NotImplemented`] rather than a
/// fabricated `score: 0`, so this feed can never silently masquerade as a real
/// evaluation that found nothing.
pub struct MaxMindFeed {
    pub db_path: String,
}

#[async_trait]
impl ThreatFeed for MaxMindFeed {
    fn name(&self) -> &'static str { "maxmind" }
    async fn lookup(&self, _ip: IpAddr) -> Result<ThreatScore, ThreatError> {
        Err(ThreatError::NotImplemented("maxmind GeoLite2 reader not wired"))
    }
}

pub struct ShodanFeed {
    pub api_key: String,
    pub http: reqwest::Client,
}

#[async_trait]
impl ThreatFeed for ShodanFeed {
    fn name(&self) -> &'static str { "shodan" }
    async fn lookup(&self, ip: IpAddr) -> Result<ThreatScore, ThreatError> {
        // The API key must never appear in a URL string we build or log.
        // Shodan's documented REST API also accepts the key as the
        // `Authorization: Bearer` credential; send it as a header and keep
        // the constructed path key-free so no proxy/access log captures it.
        let path = format!("https://api.shodan.io/shodan/host/{ip}");
        let resp = self
            .http
            .get(&path)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", self.api_key),
            )
            .query(&[("minify", "true")])
            .send()
            .await
            .map_err(|e| ThreatError::Transport(e.to_string()))?;
        let status = resp.status();
        if status == 429 { return Err(ThreatError::RateLimited); }
        // Shodan returns 404 for an IP it has no data on — that is a genuine
        // "not found", i.e. score 0, not an error. Any other non-success
        // status is a real failure and is propagated so it is not mistaken
        // for a clean IP.
        if status.as_u16() == 404 {
            return Ok(ThreatScore { score: 0, source: "shodan".into(), categories: vec![] });
        }
        if !status.is_success() {
            tracing::warn!(status = status.as_u16(), "threat-intel: shodan non-success status");
            return Err(ThreatError::UpstreamStatus(status.as_u16()));
        }
        Ok(ThreatScore { score: 10, source: "shodan".into(), categories: vec!["exposed".into()] })
    }
}

pub struct ThreatAggregator {
    feeds: Vec<Box<dyn ThreatFeed>>,
    cache: Mutex<HashMap<IpAddr, (ThreatScore, Instant)>>,
    ttl: Duration,
}

impl ThreatAggregator {
    pub fn new(feeds: Vec<Box<dyn ThreatFeed>>, ttl: Duration) -> Self {
        Self { feeds, cache: Mutex::new(HashMap::new()), ttl }
    }

    pub async fn is_malicious_ip(&self, ip: IpAddr) -> u8 {
        // SSRF guard: never forward a non-globally-routable IP to a remote
        // feed. Treat such input as non-malicious and short-circuit; the
        // caller controls this value, so it must be validated before any
        // outbound request and before it can be cached.
        if !is_globally_routable(&ip) {
            tracing::warn!(%ip, "threat-intel: rejected non-global IP before feed lookup");
            return 0;
        }
        if let Ok(g) = self.cache.lock() {
            if let Some((s, t)) = g.get(&ip) {
                if t.elapsed() < self.ttl { return s.score; }
            }
        }
        let mut best = ThreatScore { score: 0, source: "none".into(), categories: vec![] };
        let mut any_feed_ok = false;
        for f in &self.feeds {
            // Bound each feed call: a slow or hostile feed must not stall the
            // auth hot path. A timeout is treated like any other feed error.
            match tokio::time::timeout(FEED_TIMEOUT, f.lookup(ip)).await {
                Ok(Ok(s)) => {
                    any_feed_ok = true;
                    if s.score > best.score { best = s; }
                }
                Ok(Err(e)) => {
                    tracing::warn!(feed = f.name(), error = %e, "threat-intel: feed lookup failed");
                }
                Err(_) => {
                    tracing::warn!(feed = f.name(), "threat-intel: feed lookup timed out");
                }
            }
        }
        // Only cache a real evaluation. If every feed errored we have no
        // information; caching `score: 0` would poison the cache with a false
        // negative for the whole TTL window after a transient outage.
        if any_feed_ok {
            if let Ok(mut g) = self.cache.lock() {
                self.evict_if_needed(&mut g);
                g.insert(ip, (best.clone(), Instant::now()));
            }
        } else if !self.feeds.is_empty() {
            tracing::warn!(%ip, "threat-intel: all feeds failed; result not cached");
        }
        best.score
    }

    /// Keep the cache bounded. Called while holding the cache lock: first
    /// sweep entries whose TTL has elapsed, then, if still at capacity, evict
    /// the single oldest entry so an insert can proceed.
    fn evict_if_needed(&self, cache: &mut HashMap<IpAddr, (ThreatScore, Instant)>) {
        if cache.len() < CACHE_CAPACITY {
            return;
        }
        let ttl = self.ttl;
        cache.retain(|_, (_, t)| t.elapsed() < ttl);
        if cache.len() >= CACHE_CAPACITY {
            if let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, (_, t))| *t)
                .map(|(k, _)| *k)
            {
                cache.remove(&oldest);
            }
        }
    }
}
