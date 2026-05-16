use std::net::IpAddr;
use std::time::Duration;
use threat_intel::*;

#[tokio::test]
async fn empty_agg_returns_zero() {
    let agg = ThreatAggregator::new(vec![], Duration::from_secs(60));
    assert_eq!(agg.is_malicious_ip("1.2.3.4".parse::<IpAddr>().unwrap()).await, 0);
}

/// Non-globally-routable IPs must be rejected before any feed lookup, so even
/// with a feed that would score them they resolve to 0 (SSRF guard).
#[tokio::test]
async fn non_global_ips_are_rejected() {
    let agg = ThreatAggregator::new(vec![Box::new(AlwaysHostile)], Duration::from_secs(60));
    for ip in [
        "127.0.0.1",   // loopback
        "10.0.0.1",    // RFC1918
        "192.168.1.1", // RFC1918
        "169.254.0.1", // link-local
        "100.64.0.1",  // CGNAT
        "0.0.0.0",     // unspecified
        "240.0.0.1",   // reserved
        "::1",         // IPv6 loopback
        "fc00::1",     // IPv6 ULA
        "fe80::1",     // IPv6 link-local
    ] {
        let parsed: IpAddr = ip.parse().unwrap();
        assert_eq!(
            agg.is_malicious_ip(parsed).await,
            0,
            "non-global IP {ip} must be rejected before lookup"
        );
    }
}

/// A globally routable IP still reaches the feed and gets its score.
#[tokio::test]
async fn global_ip_reaches_feed() {
    let agg = ThreatAggregator::new(vec![Box::new(AlwaysHostile)], Duration::from_secs(60));
    let ip: IpAddr = "8.8.8.8".parse().unwrap();
    assert_eq!(agg.is_malicious_ip(ip).await, 99);
}

/// Test feed that scores every IP it is asked about as maximally hostile.
struct AlwaysHostile;

#[async_trait::async_trait]
impl ThreatFeed for AlwaysHostile {
    fn name(&self) -> &'static str {
        "always-hostile"
    }
    async fn lookup(&self, _ip: IpAddr) -> Result<ThreatScore, ThreatError> {
        Ok(ThreatScore { score: 99, source: "test".into(), categories: vec![] })
    }
}
