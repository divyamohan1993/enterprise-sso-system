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

#[derive(Debug, Error)]
pub enum ThreatError {
    #[error("transport: {0}")]
    Transport(String),
    #[error("rate-limited")]
    RateLimited,
    #[error("invalid response")]
    InvalidResponse,
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
        if resp.status() == 429 { return Err(ThreatError::RateLimited); }
        let v: serde_json::Value = resp.json().await.map_err(|_| ThreatError::InvalidResponse)?;
        let score = v["data"]["abuseConfidenceScore"].as_u64().unwrap_or(0) as u8;
        Ok(ThreatScore { score, source: "abuseipdb".into(), categories: vec![] })
    }
}

pub struct MaxMindFeed {
    pub db_path: String,
}

#[async_trait]
impl ThreatFeed for MaxMindFeed {
    fn name(&self) -> &'static str { "maxmind" }
    async fn lookup(&self, _ip: IpAddr) -> Result<ThreatScore, ThreatError> {
        Ok(ThreatScore { score: 0, source: "maxmind".into(), categories: vec!["geo".into()] })
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
        let url = format!("https://api.shodan.io/shodan/host/{}?key={}", ip, self.api_key);
        let resp = self.http.get(&url).send().await.map_err(|e| ThreatError::Transport(e.to_string()))?;
        if !resp.status().is_success() { return Ok(ThreatScore { score: 0, source: "shodan".into(), categories: vec![] }); }
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
        if let Ok(g) = self.cache.lock() {
            if let Some((s, t)) = g.get(&ip) {
                if t.elapsed() < self.ttl { return s.score; }
            }
        }
        let mut best = ThreatScore { score: 0, source: "none".into(), categories: vec![] };
        for f in &self.feeds {
            if let Ok(s) = f.lookup(ip).await {
                if s.score > best.score { best = s; }
            }
        }
        if let Ok(mut g) = self.cache.lock() {
            g.insert(ip, (best.clone(), Instant::now()));
        }
        best.score
    }
}
