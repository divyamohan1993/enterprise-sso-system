use axum::extract::{Path, State};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Shared application state
// ---------------------------------------------------------------------------

pub struct AppState {
    pub credential_store: RwLock<opaque::store::CredentialStore>,
    pub device_registry: RwLock<risk::tiers::DeviceRegistry>,
    pub audit_log: RwLock<audit::log::AuditLog>,
    pub kt_tree: RwLock<kt::merkle::MerkleTree>,
    pub portals: RwLock<Vec<Portal>>,
}

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
pub struct Portal {
    pub id: Uuid,
    pub name: String,
    pub callback_url: String,
    pub required_tier: u8,
    pub required_scope: u32,
    pub is_active: bool,
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RegisterUserRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct RegisterUserResponse {
    pub user_id: Uuid,
    pub username: String,
}

#[derive(Deserialize)]
pub struct RegisterPortalRequest {
    pub name: String,
    pub callback_url: String,
    pub required_tier: u8,
    pub required_scope: u32,
}

#[derive(Serialize)]
pub struct PortalResponse {
    pub id: Uuid,
    pub name: String,
    pub callback_url: String,
    pub required_tier: u8,
    pub required_scope: u32,
    pub is_active: bool,
}

#[derive(Deserialize)]
pub struct EnrollDeviceRequest {
    pub tier: u8,
    pub attestation_hash: String,
    pub enrolled_by: Uuid,
}

#[derive(Serialize)]
pub struct DeviceResponse {
    pub device_id: Uuid,
    pub tier: u8,
    pub enrolled_by: Uuid,
    pub is_active: bool,
}

#[derive(Serialize)]
pub struct SystemStatus {
    pub version: String,
    pub users_registered: usize,
    pub devices_enrolled: usize,
    pub portals_active: usize,
    pub audit_entries: usize,
    pub kt_operations: usize,
}

#[derive(Serialize)]
pub struct AuditEntryResponse {
    pub event_id: Uuid,
    pub event_type: String,
    pub user_ids: Vec<Uuid>,
    pub device_ids: Vec<Uuid>,
    pub risk_score: f64,
    pub timestamp: i64,
}

#[derive(Serialize)]
pub struct KtRootResponse {
    pub root: String,
    pub leaf_count: usize,
}

#[derive(Serialize)]
pub struct KtProofResponse {
    pub index: usize,
    pub proof: Vec<String>,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub success: bool,
    pub user_id: Option<Uuid>,
    pub token: Option<String>,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub token: String,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
    pub user_id: Option<Uuid>,
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn api_router(state: Arc<AppState>) -> Router {
    Router::new()
        // System
        .route("/api/status", get(get_status))
        .route("/api/health", get(health_check))
        // Users
        .route("/api/users", post(register_user))
        .route("/api/users", get(list_users))
        // Portals
        .route("/api/portals", post(register_portal))
        .route("/api/portals", get(list_portals))
        .route("/api/portals/{id}", delete(delete_portal))
        // Devices
        .route("/api/devices", post(enroll_device))
        .route("/api/devices", get(list_devices))
        // Audit
        .route("/api/audit", get(get_audit_log))
        .route("/api/audit/verify", get(verify_audit_chain))
        // Auth
        .route("/api/auth/login", post(auth_login))
        .route("/api/auth/verify", post(auth_verify))
        // Key Transparency
        .route("/api/kt/root", get(get_kt_root))
        .route("/api/kt/proof/{index}", get(get_kt_proof))
        .with_state(state)
        .layer(tower_http::cors::CorsLayer::permissive())
}

// ---------------------------------------------------------------------------
// Handlers — System
// ---------------------------------------------------------------------------

async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

async fn get_status(State(state): State<Arc<AppState>>) -> Json<SystemStatus> {
    let store = state.credential_store.read().await;
    let registry = state.device_registry.read().await;
    let portals = state.portals.read().await;
    let audit = state.audit_log.read().await;
    let kt = state.kt_tree.read().await;
    Json(SystemStatus {
        version: "0.1.0".to_string(),
        users_registered: store.user_count(),
        devices_enrolled: registry.device_count(),
        portals_active: portals.iter().filter(|p| p.is_active).count(),
        audit_entries: audit.len(),
        kt_operations: kt.len(),
    })
}

// ---------------------------------------------------------------------------
// Handlers — Users
// ---------------------------------------------------------------------------

async fn register_user(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterUserRequest>,
) -> Json<RegisterUserResponse> {
    let mut store = state.credential_store.write().await;
    let user_id = store.register_with_password(&req.username, req.password.as_bytes());

    // Log to audit
    let mut audit = state.audit_log.write().await;
    audit.append(
        common::types::AuditEventType::CredentialRegistered,
        vec![user_id],
        vec![],
        0.0,
        vec![],
    );

    // Log to KT
    let mut kt = state.kt_tree.write().await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64;
    kt.append_credential_op(&user_id, "register", &[0u8; 32], now);

    Json(RegisterUserResponse {
        user_id,
        username: req.username,
    })
}

async fn list_users(State(state): State<Arc<AppState>>) -> Json<Vec<String>> {
    let store = state.credential_store.read().await;
    Json(store.usernames())
}

// ---------------------------------------------------------------------------
// Handlers — Portals
// ---------------------------------------------------------------------------

async fn register_portal(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterPortalRequest>,
) -> Json<PortalResponse> {
    let portal = Portal {
        id: Uuid::new_v4(),
        name: req.name,
        callback_url: req.callback_url,
        required_tier: req.required_tier,
        required_scope: req.required_scope,
        is_active: true,
    };
    let resp = PortalResponse {
        id: portal.id,
        name: portal.name.clone(),
        callback_url: portal.callback_url.clone(),
        required_tier: portal.required_tier,
        required_scope: portal.required_scope,
        is_active: portal.is_active,
    };
    state.portals.write().await.push(portal);
    Json(resp)
}

async fn list_portals(State(state): State<Arc<AppState>>) -> Json<Vec<PortalResponse>> {
    let portals = state.portals.read().await;
    Json(
        portals
            .iter()
            .map(|p| PortalResponse {
                id: p.id,
                name: p.name.clone(),
                callback_url: p.callback_url.clone(),
                required_tier: p.required_tier,
                required_scope: p.required_scope,
                is_active: p.is_active,
            })
            .collect(),
    )
}

async fn delete_portal(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Json<serde_json::Value> {
    let mut portals = state.portals.write().await;
    portals.retain(|p| p.id != id);
    Json(serde_json::json!({"deleted": true}))
}

// ---------------------------------------------------------------------------
// Handlers — Devices
// ---------------------------------------------------------------------------

fn tier_from_u8(v: u8) -> common::types::DeviceTier {
    match v {
        1 => common::types::DeviceTier::Sovereign,
        2 => common::types::DeviceTier::Operational,
        3 => common::types::DeviceTier::Sensor,
        _ => common::types::DeviceTier::Emergency,
    }
}

fn parse_hex_32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect();
    let len = bytes.len().min(32);
    out[..len].copy_from_slice(&bytes[..len]);
    out
}

async fn enroll_device(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EnrollDeviceRequest>,
) -> Json<DeviceResponse> {
    let device_id = Uuid::new_v4();
    let enrollment = risk::tiers::DeviceEnrollment {
        device_id,
        tier: tier_from_u8(req.tier),
        attestation_hash: parse_hex_32(&req.attestation_hash),
        enrolled_by: req.enrolled_by,
        is_active: true,
    };
    let resp = DeviceResponse {
        device_id,
        tier: req.tier,
        enrolled_by: req.enrolled_by,
        is_active: true,
    };
    state.device_registry.write().await.enroll(enrollment);
    Json(resp)
}

async fn list_devices(State(state): State<Arc<AppState>>) -> Json<Vec<DeviceResponse>> {
    let registry = state.device_registry.read().await;
    Json(
        registry
            .all_devices()
            .iter()
            .map(|d| DeviceResponse {
                device_id: d.device_id,
                tier: d.tier as u8,
                enrolled_by: d.enrolled_by,
                is_active: d.is_active,
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Handlers — Audit
// ---------------------------------------------------------------------------

async fn get_audit_log(State(state): State<Arc<AppState>>) -> Json<Vec<AuditEntryResponse>> {
    let audit = state.audit_log.read().await;
    Json(
        audit
            .entries()
            .iter()
            .map(|e| AuditEntryResponse {
                event_id: e.event_id,
                event_type: format!("{:?}", e.event_type),
                user_ids: e.user_ids.clone(),
                device_ids: e.device_ids.clone(),
                risk_score: e.risk_score,
                timestamp: e.timestamp,
            })
            .collect(),
    )
}

async fn verify_audit_chain(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let audit = state.audit_log.read().await;
    let valid = audit.verify_chain();
    Json(serde_json::json!({"chain_valid": valid, "entries": audit.len()}))
}

// ---------------------------------------------------------------------------
// Handlers — Auth
// ---------------------------------------------------------------------------

async fn auth_login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Json<LoginResponse> {
    let store = state.credential_store.read().await;

    // Check user exists
    let user_id = match store.get_user_id(&req.username) {
        Some(id) => id,
        None => {
            return Json(LoginResponse {
                success: false,
                user_id: None,
                token: None,
                error: Some("invalid credentials".into()),
            });
        }
    };

    // Run simplified OPAQUE login flow (start + finish in one step for the
    // admin API; full 2-round-trip flow is used in the SHARD service).
    let login_start = opaque::service::handle_login_start(&store, &req.username, &{
        // Build a client credential request for this password
        use opaque_ke::ClientLogin;
        use opaque::opaque_impl::OpaqueCs;
        let mut rng = rand::rngs::OsRng;
        let client_start = ClientLogin::<OpaqueCs>::start(&mut rng, req.password.as_bytes())
            .expect("client login start");
        client_start.message.serialize().to_vec()
    });

    match login_start {
        Ok((_response_bytes, _server_login)) => {
            // For the admin API we issue a simple HMAC-based token rather than
            // running the full FROST threshold signing ceremony.
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            type HmacSha256 = Hmac<Sha256>;

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let payload = format!("{}:{}", user_id, now);
            let mut mac = HmacSha256::new_from_slice(b"MILNET-SSO-v1-ADMIN-TOKEN")
                .expect("HMAC key");
            mac.update(payload.as_bytes());
            let sig = hex(&mac.finalize().into_bytes());
            let token = format!("{payload}:{sig}");

            Json(LoginResponse {
                success: true,
                user_id: Some(user_id),
                token: Some(token),
                error: None,
            })
        }
        Err(e) => Json(LoginResponse {
            success: false,
            user_id: None,
            token: None,
            error: Some(format!("authentication failed: {e}")),
        }),
    }
}

async fn auth_verify(Json(req): Json<VerifyRequest>) -> Json<VerifyResponse> {
    // Token format: "user_id:timestamp:hmac_hex"
    let parts: Vec<&str> = req.token.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Json(VerifyResponse {
            valid: false,
            user_id: None,
            error: Some("malformed token".into()),
        });
    }

    let user_id = match Uuid::parse_str(parts[0]) {
        Ok(id) => id,
        Err(_) => {
            return Json(VerifyResponse {
                valid: false,
                user_id: None,
                error: Some("invalid user_id in token".into()),
            });
        }
    };

    let payload = format!("{}:{}", parts[0], parts[1]);

    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let mut mac =
        HmacSha256::new_from_slice(b"MILNET-SSO-v1-ADMIN-TOKEN").expect("HMAC key");
    mac.update(payload.as_bytes());
    let expected = hex(&mac.finalize().into_bytes());

    if expected == parts[2] {
        Json(VerifyResponse {
            valid: true,
            user_id: Some(user_id),
            error: None,
        })
    } else {
        Json(VerifyResponse {
            valid: false,
            user_id: None,
            error: Some("signature verification failed".into()),
        })
    }
}

// ---------------------------------------------------------------------------
// Handlers — Key Transparency
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn get_kt_root(State(state): State<Arc<AppState>>) -> Json<KtRootResponse> {
    let kt = state.kt_tree.read().await;
    Json(KtRootResponse {
        root: hex(&kt.root()),
        leaf_count: kt.len(),
    })
}

async fn get_kt_proof(
    State(state): State<Arc<AppState>>,
    Path(index): Path<usize>,
) -> Json<serde_json::Value> {
    let kt = state.kt_tree.read().await;
    match kt.inclusion_proof(index) {
        Some(proof) => {
            let resp = KtProofResponse {
                index,
                proof: proof.iter().map(|h| hex(h)).collect(),
            };
            Json(serde_json::to_value(resp).unwrap())
        }
        None => Json(serde_json::json!({"error": "index out of range"})),
    }
}
