#![no_main]
use libfuzzer_sys::fuzz_target;
use gateway::wire::{AuthRequest, AuthResponse, KemCiphertext, OrchestratorRequest, OrchestratorResponse};

fuzz_target!(|data: &[u8]| {
    // Fuzz deserialization of all wire protocol types (JSON format)
    let _ = serde_json::from_slice::<AuthRequest>(data);
    let _ = serde_json::from_slice::<AuthResponse>(data);
    let _ = serde_json::from_slice::<KemCiphertext>(data);
    let _ = serde_json::from_slice::<OrchestratorRequest>(data);
    let _ = serde_json::from_slice::<OrchestratorResponse>(data);

    // Also fuzz postcard (binary) deserialization
    let _ = postcard::from_bytes::<AuthRequest>(data);
    let _ = postcard::from_bytes::<OrchestratorRequest>(data);
});
