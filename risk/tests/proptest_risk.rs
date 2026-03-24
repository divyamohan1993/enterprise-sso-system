use proptest::prelude::*;
use risk::scoring::{RiskEngine, RiskSignals, RiskLevel};
use uuid::Uuid;
fn sig_strat() -> impl Strategy<Value = RiskSignals> { (0.0f64..86400.0, 0.0f64..50000.0, any::<bool>(), any::<bool>(), 0.0f64..1.0, 0u32..20).prop_map(|(d,g,n,t,u,f)| RiskSignals { device_attestation_age_secs: d, geo_velocity_kmh: g, is_unusual_network: n, is_unusual_time: t, unusual_access_score: u, recent_failed_attempts: f }) }
proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    #[test] fn bounded(s in sig_strat()) { let e = RiskEngine::new(); let sc = e.compute_score(&Uuid::new_v4(), &s); prop_assert!(sc >= 0.0 && sc <= 1.0); }
    #[test] fn impossible_travel(v in 10001.0f64..1e6) { let e = RiskEngine::new(); let s = RiskSignals { device_attestation_age_secs: 0.0, geo_velocity_kmh: v, is_unusual_network: false, is_unusual_time: false, unusual_access_score: 0.0, recent_failed_attempts: 0 }; prop_assert_eq!(e.compute_score(&Uuid::new_v4(), &s), 1.0); }
}
#[test] fn zero_vs_many_fails() { let e = RiskEngine::new(); let s = RiskSignals { device_attestation_age_secs: 100.0, geo_velocity_kmh: 50.0, is_unusual_network: false, is_unusual_time: false, unusual_access_score: 0.0, recent_failed_attempts: 0 }; let s0 = e.compute_score(&Uuid::new_v4(), &s); let uid = Uuid::new_v4(); for _ in 0..10 { e.record_failed_attempt(&uid); } assert!(s0 < e.compute_score(&uid, &s)); }
#[test] fn thresholds() { let e = RiskEngine::new(); assert_eq!(e.classify(0.0), RiskLevel::Normal); assert_eq!(e.classify(0.3), RiskLevel::Elevated); assert_eq!(e.classify(0.6), RiskLevel::High); assert_eq!(e.classify(0.8), RiskLevel::Critical); }
