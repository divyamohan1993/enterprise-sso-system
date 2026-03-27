use common::network::is_permitted_channel;
use common::types::ModuleId;

#[test]
fn test_gateway_to_orchestrator_allowed() {
    assert!(is_permitted_channel(ModuleId::Gateway, ModuleId::Orchestrator));
}

#[test]
fn test_gateway_to_tss_blocked() {
    assert!(!is_permitted_channel(ModuleId::Gateway, ModuleId::Tss));
}

#[test]
fn test_orchestrator_to_opaque_allowed() {
    assert!(is_permitted_channel(ModuleId::Orchestrator, ModuleId::Opaque));
}

#[test]
fn test_orchestrator_to_risk_allowed() {
    assert!(is_permitted_channel(ModuleId::Orchestrator, ModuleId::Risk));
}

#[test]
fn test_all_to_audit_allowed() {
    for module in [
        ModuleId::Gateway,
        ModuleId::Orchestrator,
        ModuleId::Tss,
        ModuleId::Opaque,
        ModuleId::Risk,
        ModuleId::Ratchet,
        ModuleId::Kt,
        ModuleId::Verifier,
    ] {
        assert!(
            is_permitted_channel(module, ModuleId::Audit),
            "{:?} -> Audit should be allowed",
            module
        );
    }
}

#[test]
fn test_opaque_to_gateway_blocked() {
    assert!(!is_permitted_channel(ModuleId::Opaque, ModuleId::Gateway));
}

#[test]
fn test_tss_peer_to_peer_allowed() {
    assert!(is_permitted_channel(ModuleId::Tss, ModuleId::Tss));
}

#[test]
fn test_verifier_to_ratchet_allowed() {
    assert!(is_permitted_channel(ModuleId::Verifier, ModuleId::Ratchet));
}

#[test]
fn test_verifier_to_opaque_blocked() {
    assert!(!is_permitted_channel(ModuleId::Verifier, ModuleId::Opaque));
}

#[test]
fn test_gateway_to_risk_blocked() {
    assert!(!is_permitted_channel(ModuleId::Gateway, ModuleId::Risk));
}

// =========================================================================
// Hardened Security Tests — Communication Matrix & Circuit Breaker
// =========================================================================

#[test]
fn test_gateway_cannot_reach_tss_directly() {
    // Zero-trust: gateway cannot bypass orchestrator to reach TSS
    assert!(
        !is_permitted_channel(ModuleId::Gateway, ModuleId::Tss),
        "gateway must not communicate with TSS directly — must go through orchestrator"
    );
}

#[test]
fn test_gateway_to_orchestrator_permitted() {
    assert!(
        is_permitted_channel(ModuleId::Gateway, ModuleId::Orchestrator),
        "gateway -> orchestrator is the only permitted gateway egress channel"
    );
}

#[test]
fn test_any_module_can_send_to_audit() {
    for module in [
        ModuleId::Gateway,
        ModuleId::Orchestrator,
        ModuleId::Tss,
        ModuleId::Opaque,
    ] {
        assert!(
            is_permitted_channel(module, ModuleId::Audit),
            "{:?} -> Audit must be permitted for security logging",
            module
        );
    }
}

use common::circuit_breaker::{CircuitBreaker, CircuitState};
use std::time::Duration;

#[test]
fn test_circuit_breaker_opens_after_threshold() {
    // Cascade failure protection: breaker opens after N failures
    let threshold = 5;
    let breaker = CircuitBreaker::new(threshold, Duration::from_secs(30));

    // Record failures up to threshold
    for _ in 0..threshold {
        breaker.record_failure();
    }

    assert_eq!(
        breaker.state(),
        CircuitState::Open,
        "breaker must be Open after {} failures",
        threshold
    );
    assert!(
        !breaker.allow_request(),
        "open breaker must reject requests"
    );
}

#[test]
fn test_circuit_breaker_half_open_after_reset() {
    // Use a very short reset timeout so we can test the transition
    let threshold = 3;
    let breaker = CircuitBreaker::new(threshold, Duration::from_millis(50));

    // Trip the breaker
    for _ in 0..threshold {
        breaker.record_failure();
    }
    assert_eq!(breaker.state(), CircuitState::Open);

    // Wait for reset timeout to elapse
    std::thread::sleep(Duration::from_millis(60));

    // Should now be half-open
    assert_eq!(
        breaker.state(),
        CircuitState::HalfOpen,
        "breaker must transition to HalfOpen after reset_timeout"
    );
    assert!(
        breaker.allow_request(),
        "half-open breaker must allow one probe request"
    );
}
