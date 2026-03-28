#[test]
fn test_suspicion_decay() {
    let mut detector = common::stealth_detection::StealthDetector::new();
    detector.add_suspicion(0.5);
    assert!(
        detector.suspicion_score() >= 0.5,
        "suspicion should be >= 0.5 after adding 0.5, got {}",
        detector.suspicion_score()
    );
    detector.apply_decay(std::time::Duration::from_secs(300));
    assert!(
        detector.suspicion_score() < 0.5,
        "suspicion should decay after 5 minutes, got {}",
        detector.suspicion_score()
    );
    assert!(
        detector.suspicion_score() > 0.0,
        "suspicion should not fully decay in 5 minutes, got {}",
        detector.suspicion_score()
    );
}

#[test]
fn test_library_baseline_capture() {
    let mut detector = common::stealth_detection::StealthDetector::new();
    assert!(
        !detector.has_library_baseline(),
        "should not have baseline before capture"
    );
    detector.capture_library_baseline();
    // On Linux with /proc, baseline should be captured
    #[cfg(target_os = "linux")]
    assert!(
        detector.has_library_baseline(),
        "should have baseline after capture on Linux"
    );
}

#[test]
fn test_suspicion_decay_does_not_go_negative() {
    let mut detector = common::stealth_detection::StealthDetector::new();
    detector.add_suspicion(0.1);
    detector.apply_decay(std::time::Duration::from_secs(6000)); // 100 minutes
    assert_eq!(
        detector.suspicion_score(),
        0.0,
        "suspicion must not go below 0.0"
    );
}
