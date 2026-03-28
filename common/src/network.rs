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

/// Enforce the module communication matrix at runtime.
///
/// Returns `Ok(())` if the channel from `sender` to `receiver` is permitted,
/// or `Err` with a descriptive message if the channel is denied.  This is
/// intended to be called at connection establishment time in the SHARD
/// transport layer.
pub fn enforce_channel(sender: ModuleId, receiver: ModuleId) -> Result<(), &'static str> {
    if is_permitted_channel(sender, receiver) {
        Ok(())
    } else {
        Err("communication channel denied by module communication matrix")
    }
}

/// Assert that a communication channel is permitted, panicking on violation.
///
/// Intended for internal use where a denied channel indicates a programming
/// error or compromised module. Logs the violation to SIEM before panicking.
pub fn assert_allowed(sender: ModuleId, receiver: ModuleId) {
    if !is_permitted_channel(sender, receiver) {
        tracing::error!(
            target: "siem",
            category = "security",
            action = "communication_matrix_violation",
            sender = ?sender,
            receiver = ?receiver,
            "FATAL: communication channel {:?} -> {:?} denied by module communication matrix",
            sender,
            receiver,
        );
        panic!(
            "communication matrix violation: {:?} -> {:?} is not permitted",
            sender, receiver
        );
    }
}

/// Auto-detect the communication matrix from the cluster state.
/// Returns the set of permitted channels based on which services are
/// registered in the cluster. This replaces hardcoded channel lists
/// with dynamic detection.
pub fn auto_detect_channels(registered_services: &[ModuleId]) -> Vec<(ModuleId, ModuleId)> {
    let mut channels = Vec::new();
    for &svc in registered_services {
        // Each service gets its known dependency channels
        let deps = service_dependencies(svc);
        for dep in deps {
            if registered_services.contains(&dep) {
                channels.push((svc, dep));
                channels.push((dep, svc)); // bidirectional
            }
        }
    }
    // Sort by (src as u8, dst as u8) then dedup
    channels.sort_by_key(|&(a, b)| (a as u8, b as u8));
    channels.dedup();
    channels
}

/// Return the known dependencies for a service type.
fn service_dependencies(module: ModuleId) -> Vec<ModuleId> {
    match module {
        ModuleId::Gateway => vec![ModuleId::Orchestrator],
        ModuleId::Orchestrator => vec![
            ModuleId::Opaque,
            ModuleId::Tss,
            ModuleId::Risk,
            ModuleId::Ratchet,
            ModuleId::Verifier,
            ModuleId::Audit,
            ModuleId::Kt,
        ],
        ModuleId::Verifier => vec![ModuleId::Ratchet],
        ModuleId::Audit => vec![ModuleId::Kt],
        _ => vec![], // Leaf services have no outbound dependencies
    }
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

    #[test]
    fn auto_detect_gateway_orchestrator() {
        let services = vec![ModuleId::Gateway, ModuleId::Orchestrator];
        let channels = auto_detect_channels(&services);
        assert!(channels.contains(&(ModuleId::Gateway, ModuleId::Orchestrator)));
        assert!(channels.contains(&(ModuleId::Orchestrator, ModuleId::Gateway)));
    }

    #[test]
    fn auto_detect_excludes_unregistered() {
        // Only Gateway registered — Orchestrator is missing, so no channels
        let services = vec![ModuleId::Gateway];
        let channels = auto_detect_channels(&services);
        assert!(channels.is_empty());
    }

    #[test]
    fn auto_detect_full_cluster() {
        let services = vec![
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
        let channels = auto_detect_channels(&services);
        // Should have Gateway<->Orchestrator
        assert!(channels.contains(&(ModuleId::Gateway, ModuleId::Orchestrator)));
        // Should have Orchestrator<->Tss
        assert!(channels.contains(&(ModuleId::Orchestrator, ModuleId::Tss)));
        // Should have Verifier<->Ratchet
        assert!(channels.contains(&(ModuleId::Verifier, ModuleId::Ratchet)));
        // Should have Audit<->Kt
        assert!(channels.contains(&(ModuleId::Audit, ModuleId::Kt)));
        // No duplicates
        let mut sorted = channels.clone();
        sorted.sort_by_key(|&(a, b)| (a as u8, b as u8));
        sorted.dedup();
        assert_eq!(sorted.len(), channels.len(), "no duplicates expected");
    }
}
