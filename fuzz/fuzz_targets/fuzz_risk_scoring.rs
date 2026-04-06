#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Deserialize fuzz input as RiskSignals JSON and run through RiskEngine
    if let Ok(req) = serde_json::from_slice::<risk::scoring::RiskRequest>(data) {
        let engine = risk::scoring::RiskEngine::new();
        let score = engine.compute_score(&req.user_id, &req.signals);
        // Score must always be in [0.0, 1.0]
        assert!(score >= 0.0 && score <= 1.0, "score out of bounds: {score}");
        let _level = engine.classify(score);
        let _ = engine.requires_step_up(score);
        let _ = engine.requires_termination(score);
    }
});
