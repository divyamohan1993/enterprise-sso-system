//! Unit tests for gateway internals: hash puzzle, wire protocol, and rate limiting.

use gateway::puzzle::{
    generate_challenge, get_adaptive_difficulty, current_difficulty,
    solve_challenge, verify_solution, ConsumedPuzzles, PuzzleChallenge, PuzzleSolution,
};
use gateway::wire::{AuthRequest, AuthResponse, KemCiphertext, OrchestratorRequest, OrchestratorResponse};
use gateway::distributed_rate_limit::{DistributedRateLimiter, RateLimitConfig, RateLimitResult};

// =========================================================================
// Hash Puzzle Tests
// =========================================================================

#[test]
fn test_puzzle_generation() {
    let challenge = generate_challenge(8);
    assert_eq!(challenge.difficulty, 8);
    assert!(challenge.timestamp > 0);
    // Nonce should not be all zeros (cryptographically random)
    assert_ne!(challenge.nonce, [0u8; 32]);
    // X-Wing fields are None by default (set by the server later)
    assert!(challenge.xwing_server_pk.is_none());
    assert!(challenge.xwing_server_pk_fingerprint.is_none());
}

#[test]
fn test_puzzle_generation_different_nonces() {
    let c1 = generate_challenge(4);
    let c2 = generate_challenge(4);
    // Two challenges should have different nonces (with overwhelming probability)
    assert_ne!(c1.nonce, c2.nonce);
}

#[test]
fn test_puzzle_validation_correct_solution() {
    let challenge = generate_challenge(4);
    let solution = solve_challenge(&challenge);
    assert!(
        verify_solution(&challenge, &solution),
        "valid solution must pass verification"
    );
}

#[test]
fn test_puzzle_validation_wrong_solution() {
    let challenge = generate_challenge(4);
    // All-0xFF is extremely unlikely to have 4 leading zero bits in SHA-512
    let bad_solution = [0xFFu8; 32];
    assert!(
        !verify_solution(&challenge, &bad_solution),
        "invalid nonce should be rejected"
    );
}

#[test]
fn test_puzzle_expired_challenge_rejected() {
    let mut challenge = generate_challenge(4);
    // Push timestamp 60 seconds into the past (well past 30s TTL)
    challenge.timestamp -= 60;
    let solution = solve_challenge(&challenge);
    assert!(
        !verify_solution(&challenge, &solution),
        "expired challenge must be rejected"
    );
}

#[test]
fn test_puzzle_ddos_mode_higher_difficulty() {
    // Normal load: < 100 connections -> difficulty 0
    let normal = get_adaptive_difficulty(50);
    assert_eq!(normal, 0, "normal load should return difficulty 0");

    // Moderate load: > 100 connections -> difficulty 18
    let moderate = get_adaptive_difficulty(150);
    assert_eq!(moderate, 18, "moderate load should return difficulty 18");

    // High load: > 500 connections -> difficulty 22
    let high = get_adaptive_difficulty(600);
    assert_eq!(high, 22, "high load should return difficulty 22");

    // DDoS level: > 1000 connections -> difficulty 24
    let ddos = get_adaptive_difficulty(1500);
    assert_eq!(ddos, 24, "DDoS load should return difficulty 24");
}

#[test]
fn test_adaptive_difficulty_updates_global() {
    let _ = get_adaptive_difficulty(1500);
    assert_eq!(current_difficulty(), 24);

    let _ = get_adaptive_difficulty(10);
    assert_eq!(current_difficulty(), 0);
}

#[test]
fn test_consumed_puzzles_replay_prevention() {
    let mut tracker = ConsumedPuzzles::new();
    let nonce = [0x42u8; 32];
    let now = 1000i64;

    assert!(!tracker.is_consumed(&nonce));
    tracker.insert(nonce, now);
    assert!(tracker.is_consumed(&nonce));
}

#[test]
fn test_consumed_puzzles_cleanup_expired() {
    let mut tracker = ConsumedPuzzles::new();
    let nonce = [0x42u8; 32];
    tracker.insert(nonce, 1000);

    // Clean up with a timestamp far in the future
    tracker.cleanup_expired(1100);
    assert!(!tracker.is_consumed(&nonce), "expired nonce should be cleaned up");
}

#[test]
fn test_consumed_puzzles_fresh_not_cleaned() {
    let mut tracker = ConsumedPuzzles::new();
    let nonce = [0x42u8; 32];
    let now = 1000i64;
    tracker.insert(nonce, now);

    // Clean up with a timestamp within the TTL
    tracker.cleanup_expired(now + 10);
    assert!(tracker.is_consumed(&nonce), "fresh nonce should NOT be cleaned up");
}

#[test]
fn test_puzzle_solution_serialization_roundtrip() {
    let solution = PuzzleSolution {
        nonce: [0xAB; 32],
        solution: [0xCD; 32],
        xwing_kem_ciphertext: Some(vec![1, 2, 3, 4]),
    };
    let bytes = postcard::to_allocvec(&solution).unwrap();
    let decoded: PuzzleSolution = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.nonce, solution.nonce);
    assert_eq!(decoded.solution, solution.solution);
    assert_eq!(decoded.xwing_kem_ciphertext, Some(vec![1, 2, 3, 4]));
}

#[test]
fn test_puzzle_challenge_serialization_roundtrip() {
    let challenge = PuzzleChallenge {
        nonce: [0x11; 32],
        difficulty: 16,
        timestamp: 1700000000,
        xwing_server_pk: Some(vec![0xAA; 100]),
        xwing_server_pk_fingerprint: Some("abcdef".to_string()),
    };
    let bytes = postcard::to_allocvec(&challenge).unwrap();
    let decoded: PuzzleChallenge = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.nonce, challenge.nonce);
    assert_eq!(decoded.difficulty, 16);
    assert_eq!(decoded.timestamp, 1700000000);
    assert_eq!(decoded.xwing_server_pk, Some(vec![0xAA; 100]));
    assert_eq!(decoded.xwing_server_pk_fingerprint.as_deref(), Some("abcdef"));
}

// =========================================================================
// Wire Protocol Tests
// =========================================================================

#[test]
fn test_wire_auth_request_serialization() {
    let req = AuthRequest {
        username: "alice".into(),
        password: vec![0x01, 0x02, 0x03],
        audience: Some("my-service".to_string()),
    };
    let bytes = postcard::to_allocvec(&req).unwrap();
    let decoded: AuthRequest = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.username, "alice");
    assert_eq!(decoded.password, vec![0x01, 0x02, 0x03]);
    assert_eq!(decoded.audience.as_deref(), Some("my-service"));
}

#[test]
fn test_wire_auth_request_no_audience() {
    let req = AuthRequest {
        username: "bob".into(),
        password: vec![],
        audience: None,
    };
    let bytes = postcard::to_allocvec(&req).unwrap();
    let decoded: AuthRequest = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.username, "bob");
    assert!(decoded.audience.is_none());
}

#[test]
fn test_wire_auth_response_success() {
    let resp = AuthResponse {
        success: true,
        token: Some(vec![0xDE, 0xAD]),
        error: None,
    };
    let bytes = postcard::to_allocvec(&resp).unwrap();
    let decoded: AuthResponse = postcard::from_bytes(&bytes).unwrap();
    assert!(decoded.success);
    assert_eq!(decoded.token, Some(vec![0xDE, 0xAD]));
    assert!(decoded.error.is_none());
}

#[test]
fn test_wire_auth_response_failure() {
    let resp = AuthResponse {
        success: false,
        token: None,
        error: Some("authentication failed".into()),
    };
    let bytes = postcard::to_allocvec(&resp).unwrap();
    let decoded: AuthResponse = postcard::from_bytes(&bytes).unwrap();
    assert!(!decoded.success);
    assert!(decoded.token.is_none());
    assert_eq!(decoded.error.as_deref(), Some("authentication failed"));
}

#[test]
fn test_wire_message_deserialization() {
    // Serialize an AuthResponse and then deserialize it
    let resp = AuthResponse {
        success: true,
        token: Some(vec![1, 2, 3]),
        error: None,
    };
    let bytes = postcard::to_allocvec(&resp).unwrap();
    let decoded: AuthResponse = postcard::from_bytes(&bytes).unwrap();
    assert!(decoded.success);
    assert_eq!(decoded.token, Some(vec![1, 2, 3]));
}

#[test]
fn test_wire_message_too_short() {
    // An empty byte slice should fail to deserialize
    let result = postcard::from_bytes::<AuthResponse>(&[]);
    assert!(result.is_err(), "empty bytes should fail deserialization");
}

#[test]
fn test_wire_message_corrupted() {
    // Random garbage should fail to deserialize
    let result = postcard::from_bytes::<AuthRequest>(&[0xFF, 0xFF, 0xFF]);
    assert!(result.is_err(), "corrupted bytes should fail deserialization");
}

#[test]
fn test_wire_kem_ciphertext_serialization() {
    let kem = KemCiphertext {
        ciphertext: vec![0xAA; 256],
    };
    let bytes = postcard::to_allocvec(&kem).unwrap();
    let decoded: KemCiphertext = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.ciphertext.len(), 256);
    assert_eq!(decoded.ciphertext[0], 0xAA);
}

#[test]
fn test_wire_orchestrator_request_serialization() {
    let req = OrchestratorRequest {
        username: "testuser".into(),
        password: vec![0xBB; 32],
        dpop_key_hash: [0xCC; 64],
        tier: 2,
        audience: Some("resource-server".to_string()),
        ceremony_id: [0u8; 32],
        device_attestation_age_secs: Some(120.0),
        geo_velocity_kmh: Some(50.0),
        is_unusual_network: Some(false),
        is_unusual_time: None,
        unusual_access_score: Some(0.1),
        recent_failed_attempts: Some(3),
    };
    let bytes = postcard::to_allocvec(&req).unwrap();
    let decoded: OrchestratorRequest = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.username, "testuser");
    assert_eq!(decoded.tier, 2);
    assert_eq!(decoded.dpop_key_hash, [0xCC; 64]);
    assert_eq!(decoded.audience.as_deref(), Some("resource-server"));
    assert_eq!(decoded.device_attestation_age_secs, Some(120.0));
    assert_eq!(decoded.recent_failed_attempts, Some(3));
}

#[test]
fn test_wire_orchestrator_response_serialization() {
    let resp = OrchestratorResponse {
        success: true,
        token_bytes: Some(vec![0xDD; 64]),
        error: None,
    };
    let bytes = postcard::to_allocvec(&resp).unwrap();
    let decoded: OrchestratorResponse = postcard::from_bytes(&bytes).unwrap();
    assert!(decoded.success);
    assert_eq!(decoded.token_bytes, Some(vec![0xDD; 64]));
    assert!(decoded.error.is_none());
}

// =========================================================================
// Rate Limiting Tests (distributed_rate_limit local fallback)
// =========================================================================

#[tokio::test]
async fn test_rate_limit_under_threshold() {
    let config = RateLimitConfig {
        per_ip_limit: 10,
        per_user_limit: 5,
        window_secs: 60,
        burst_size: 20,
        refill_rate: 1.0,
        redis_url: None, // local-only mode
    };
    let limiter = DistributedRateLimiter::new(config).await;

    let ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();

    // First request should be allowed
    let result = limiter.check_ip(ip).await;
    assert!(result.allowed, "first request should be allowed");
    assert_eq!(result.remaining, 9);
}

#[tokio::test]
async fn test_rate_limit_over_threshold() {
    let config = RateLimitConfig {
        per_ip_limit: 3,
        per_user_limit: 5,
        window_secs: 60,
        burst_size: 20,
        refill_rate: 1.0,
        redis_url: None,
    };
    let limiter = DistributedRateLimiter::new(config).await;

    let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();

    // Use up all 3 allowed requests
    for i in 0..3 {
        let result = limiter.check_ip(ip).await;
        assert!(result.allowed, "request {} should be allowed", i + 1);
    }

    // 4th request should be rejected
    let result = limiter.check_ip(ip).await;
    assert!(!result.allowed, "request over limit should be rejected");
    assert_eq!(result.remaining, 0);
}

#[tokio::test]
async fn test_rate_limit_different_ips_independent() {
    let config = RateLimitConfig {
        per_ip_limit: 2,
        per_user_limit: 5,
        window_secs: 60,
        burst_size: 20,
        refill_rate: 1.0,
        redis_url: None,
    };
    let limiter = DistributedRateLimiter::new(config).await;

    let ip1: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    let ip2: std::net::IpAddr = "10.0.0.2".parse().unwrap();

    // Exhaust ip1's limit
    limiter.check_ip(ip1).await;
    limiter.check_ip(ip1).await;
    let result = limiter.check_ip(ip1).await;
    assert!(!result.allowed, "ip1 should be rate limited");

    // ip2 should still be allowed
    let result = limiter.check_ip(ip2).await;
    assert!(result.allowed, "ip2 should NOT be affected by ip1's limit");
}

#[tokio::test]
async fn test_rate_limit_user_check() {
    let config = RateLimitConfig {
        per_ip_limit: 100,
        per_user_limit: 2,
        window_secs: 60,
        burst_size: 20,
        refill_rate: 1.0,
        redis_url: None,
    };
    let limiter = DistributedRateLimiter::new(config).await;

    // Use up user limit
    limiter.check_user("user123").await;
    limiter.check_user("user123").await;
    let result = limiter.check_user("user123").await;
    assert!(!result.allowed, "user should be rate limited after exceeding per-user limit");
}

#[tokio::test]
async fn test_rate_limit_result_fields() {
    let config = RateLimitConfig {
        per_ip_limit: 5,
        per_user_limit: 5,
        window_secs: 60,
        burst_size: 20,
        refill_rate: 1.0,
        redis_url: None,
    };
    let limiter = DistributedRateLimiter::new(config).await;

    let ip: std::net::IpAddr = "172.16.0.1".parse().unwrap();

    let result = limiter.check_ip(ip).await;
    assert!(result.allowed);
    assert_eq!(result.remaining, 4);
    assert_eq!(result.retry_after_secs, 0, "allowed requests should have retry_after=0");
}

#[tokio::test]
async fn test_rate_limit_config_from_defaults() {
    let config = RateLimitConfig::default();
    assert_eq!(config.per_ip_limit, 100);
    assert_eq!(config.per_user_limit, 50);
    assert_eq!(config.window_secs, 60);
    assert_eq!(config.burst_size, 20);
    assert!(config.redis_url.is_none());
}
