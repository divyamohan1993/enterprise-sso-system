//! Module communication matrix enforcement (spec Appendix H, item 11).
//!
//! Defines which module-to-module communication channels are permitted.
//! All channels not explicitly listed here are DENIED.

use crate::types::ModuleId;

/// Returns `true` if the communication channel from `from` to `to` is permitted
/// per the spec's module communication matrix.
///
/// All other module-to-module communication is DENIED.
pub fn is_permitted_channel(from: ModuleId, to: ModuleId) -> bool {
    matches!(
        (from, to),
        // Gateway <-> Orchestrator
        (ModuleId::Gateway, ModuleId::Orchestrator)
            | (ModuleId::Orchestrator, ModuleId::Gateway)
            // Orchestrator <-> OPAQUE, TSS, Risk, Ratchet
            | (ModuleId::Orchestrator, ModuleId::Opaque)
            | (ModuleId::Opaque, ModuleId::Orchestrator)
            | (ModuleId::Orchestrator, ModuleId::Tss)
            | (ModuleId::Tss, ModuleId::Orchestrator)
            | (ModuleId::Orchestrator, ModuleId::Risk)
            | (ModuleId::Risk, ModuleId::Orchestrator)
            | (ModuleId::Orchestrator, ModuleId::Ratchet)
            | (ModuleId::Ratchet, ModuleId::Orchestrator)
            // TSS <-> TSS (peer-to-peer for FROST)
            | (ModuleId::Tss, ModuleId::Tss)
            // Verifier <-> Ratchet (heartbeat), TSS (JWKS refresh)
            | (ModuleId::Verifier, ModuleId::Ratchet)
            | (ModuleId::Ratchet, ModuleId::Verifier)
            | (ModuleId::Verifier, ModuleId::Tss)
            | (ModuleId::Tss, ModuleId::Verifier)
            // KT <-> Orchestrator, Audit
            | (ModuleId::Kt, ModuleId::Orchestrator)
            | (ModuleId::Orchestrator, ModuleId::Kt)
            | (ModuleId::Kt, ModuleId::Audit)
            | (ModuleId::Audit, ModuleId::Kt)
            // Risk <-> Ratchet, Audit
            | (ModuleId::Risk, ModuleId::Ratchet)
            | (ModuleId::Ratchet, ModuleId::Risk)
            | (ModuleId::Risk, ModuleId::Audit)
            | (ModuleId::Audit, ModuleId::Risk)
            // Audit receives from ALL modules
            | (_, ModuleId::Audit)
            // Audit <-> TSS
            | (ModuleId::Audit, ModuleId::Tss)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_orchestrator_bidirectional() {
        assert!(is_permitted_channel(
            ModuleId::Gateway,
            ModuleId::Orchestrator
        ));
        assert!(is_permitted_channel(
            ModuleId::Orchestrator,
            ModuleId::Gateway
        ));
    }

    #[test]
    fn any_module_can_send_to_audit() {
        let modules = [
            ModuleId::Gateway,
            ModuleId::Orchestrator,
            ModuleId::Tss,
            ModuleId::Verifier,
            ModuleId::Opaque,
            ModuleId::Ratchet,
            ModuleId::Kt,
            ModuleId::Risk,
            ModuleId::Audit,
        ];
        for m in modules {
            assert!(
                is_permitted_channel(m, ModuleId::Audit),
                "{m:?} -> Audit should be permitted"
            );
        }
    }

    #[test]
    fn gateway_cannot_reach_tss_directly() {
        assert!(!is_permitted_channel(ModuleId::Gateway, ModuleId::Tss));
    }

    #[test]
    fn gateway_cannot_reach_opaque_directly() {
        assert!(!is_permitted_channel(ModuleId::Gateway, ModuleId::Opaque));
    }

    #[test]
    fn verifier_cannot_reach_opaque() {
        assert!(!is_permitted_channel(ModuleId::Verifier, ModuleId::Opaque));
    }
}
