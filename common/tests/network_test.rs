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
