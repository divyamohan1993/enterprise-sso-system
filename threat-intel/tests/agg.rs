use std::net::IpAddr;
use std::time::Duration;
use threat_intel::*;

#[tokio::test]
async fn empty_agg_returns_zero() {
    let agg = ThreatAggregator::new(vec![], Duration::from_secs(60));
    assert_eq!(agg.is_malicious_ip("1.2.3.4".parse::<IpAddr>().unwrap()).await, 0);
}
