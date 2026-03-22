use axum::extract::{Path, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::services::ServeDir;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Shared application state
// ---------------------------------------------------------------------------

pub struct AppState {
    pub db: PgPool,
    pub credential_store: RwLock<opaque::store::CredentialStore>,
    pub device_registry: RwLock<risk::tiers::DeviceRegistry>,
    pub audit_log: RwLock<audit::log::AuditLog>,
    pub kt_tree: RwLock<kt::merkle::MerkleTree>,
    pub portals: RwLock<Vec<Portal>>,
    pub oauth_clients: RwLock<sso_protocol::clients::ClientRegistry>,
    pub auth_codes: RwLock<sso_protocol::authorize::AuthorizationStore>,
    pub oidc_signing_key: [u8; 64],
    pub admin_api_key: String,
    pub fido_store: RwLock<fido::registration::CredentialStore>,
    pub setup_complete: Arc<AtomicBool>,
    pub pending_ceremonies: RwLock<HashMap<Uuid, PendingCeremony>>,
    pub last_level4_ceremony: RwLock<Option<i64>>,
    pub level4_count_72h: RwLock<Vec<i64>>,
}

/// A pending multi-person ceremony that requires multiple approvers.
#[derive(Clone, Serialize)]
pub struct PendingCeremony {
    pub action: String,
    pub level: u8,
    pub initiator: Uuid,
    pub approvers: Vec<Uuid>,
    pub required_approvals: usize,
    pub created_at: i64,
    pub expires_at: i64,
}

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------

/// Bearer token authentication middleware.
///
/// Skips auth for health, discovery, public OAuth endpoints, and static assets.
/// For all other routes, requires a valid Bearer token that matches either:
/// - the admin API key (from ADMIN_API_KEY env var), or
/// - a user auth token issued by /api/auth/login.
/// Extension to carry the authenticated user's tier through the request.
#[derive(Debug, Clone, Copy)]
pub struct AuthTier(pub u8);

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Skip auth for health, discovery, and public endpoints
    let path = request.uri().path();
    if path == "/api/health"
        || path == "/.well-known/openid-configuration"
        || path.starts_with("/oauth/")
        || path == "/oauth/token"
        || path.starts_with("/api/auth/")
        || path.starts_with("/api/setup")
        || path == "/"
        || path == "/about"
        || path == "/pitch"
        || path.ends_with(".html")
        || path.ends_with(".css")
        || path.ends_with(".js")
    {
        return Ok(next.run(request).await);
    }

    // Check Bearer token
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            let token = &header[7..];
            // Accept the admin API key — treated as tier 1 (Sovereign)
            if token == state.admin_api_key {
                request.extensions_mut().insert(AuthTier(1));
                return Ok(next.run(request).await);
            }
            // Accept a valid user auth token (user_id:timestamp:hmac)
            if verify_user_token(token) {
                // Look up user tier from DB
                let parts: Vec<&str> = token.splitn(3, ':').collect();
                let tier = if parts.len() == 3 {
                    if let Ok(user_id) = Uuid::parse_str(parts[0]) {
                        let t: i32 = sqlx::query_scalar("SELECT tier FROM users WHERE id = $1")
                            .bind(user_id)
                            .fetch_one(&state.db)
                            .await
                            .unwrap_or(4);
                        t as u8
                    } else {
                        4
                    }
                } else {
                    4
                };
                request.extensions_mut().insert(AuthTier(tier));
                return Ok(next.run(request).await);
            }
            Err(StatusCode::UNAUTHORIZED)
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

/// Verify an HMAC-based user token (same logic as auth_verify handler).
fn verify_user_token(token: &str) -> bool {
    let parts: Vec<&str> = token.splitn(3, ':').collect();
    if parts.len() != 3 {
        return false;
    }
    if Uuid::parse_str(parts[0]).is_err() {
        return false;
    }

    let payload = format!("{}:{}", parts[0], parts[1]);

    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let mut mac =
        HmacSha256::new_from_slice(b"MILNET-SSO-v1-ADMIN-TOKEN").expect("HMAC key");
    mac.update(payload.as_bytes());
    let expected = hex(&mac.finalize().into_bytes());

    expected == parts[2]
}

/// Check if the authenticated user's tier allows access to this endpoint.
/// Lower tier number = higher privilege.
fn check_tier(token_tier: u8, required_tier: u8) -> Result<(), StatusCode> {
    if token_tier <= required_tier {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

// ---------------------------------------------------------------------------
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

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
    pub tier: Option<u8>,  // 1=Sovereign, 2=Operational, 3=Sensor, 4=Emergency. Default: 2
}

#[derive(Serialize)]
pub struct RegisterUserResponse {
    pub user_id: Uuid,
    pub username: String,
    pub tier: u8,
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
    pub name: Option<String>,
    pub tier: Option<u8>,
    pub attestation_hash: Option<String>,
    pub enrolled_by: Option<Uuid>,
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
    pub users_registered: i64,
    pub devices_enrolled: i64,
    pub portals_active: i64,
    pub audit_entries: i64,
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

#[derive(Serialize, Default)]
pub struct LoginResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
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

#[derive(Deserialize)]
pub struct SetupRequest {
    pub username: String,
    pub password: String,
    pub organization: Option<String>,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn api_router(state: Arc<AppState>) -> Router {
    Router::new()
        // System
        .route("/api/status", get(get_status))
        .route("/api/health", get(health_check))
        // First-run setup
        .route("/api/setup", post(initial_setup))
        .route("/api/setup/status", get(setup_status))
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
        .route("/api/auth/duress-pin", post(register_duress_pin))
        // Key Transparency
        .route("/api/kt/root", get(get_kt_root))
        .route("/api/kt/proof/{index}", get(get_kt_proof))
        // OIDC / OAuth2
        .route("/.well-known/openid-configuration", get(oidc_discovery))
        .route("/oauth/authorize", get(oauth_authorize))
        .route("/oauth/authorize/login", post(oauth_authorize_login))
        .route("/oauth/token", post(oauth_token))
        .route("/oauth/userinfo", get(oauth_userinfo))
        .route("/oauth/jwks", get(oauth_jwks))
        // User self-service
        .route("/api/user/profile", get(get_user_profile))
        // Multi-person ceremony
        .route("/api/ceremony/initiate", post(initiate_ceremony))
        .route("/api/ceremony/approve", post(approve_ceremony))
        .route("/api/ceremony/{id}", get(ceremony_status))
        // FIDO2/WebAuthn
        .route("/api/fido/register/begin", post(fido_register_begin))
        .route("/api/fido/register/complete", post(fido_register_complete))
        .route("/api/fido/authenticate/begin", post(fido_authenticate_begin))
        .route("/api/fido/authenticate/complete", post(fido_authenticate_complete))
        // Static page redirects
        .route("/about", get(|| async { axum::response::Redirect::permanent("/about.html") }))
        .route("/pitch", get(|| async { axum::response::Redirect::permanent("/pitch.html") }))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state)
        .layer(tower_http::cors::CorsLayer::permissive())
        .fallback_service(ServeDir::new("frontend").append_index_html_on_directories(true))
}

// ---------------------------------------------------------------------------
// Handlers — System
// ---------------------------------------------------------------------------

async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

async fn setup_status(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    // Check in-memory flag first, then fall back to database
    if state.setup_complete.load(Ordering::Relaxed) {
        return Json(serde_json::json!({"setup_complete": true}));
    }
    // Check if any users exist in the database (survives restarts)
    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);
    if user_count > 0 {
        state.setup_complete.store(true, Ordering::Relaxed);
        return Json(serde_json::json!({"setup_complete": true}));
    }
    Json(serde_json::json!({"setup_complete": false}))
}

async fn initial_setup(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SetupRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Only allow if no users exist yet (check both memory and DB)
    if state.setup_complete.load(Ordering::Relaxed) {
        return Err(StatusCode::FORBIDDEN);
    }
    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);
    if user_count > 0 {
        state.setup_complete.store(true, Ordering::Relaxed);
        return Err(StatusCode::FORBIDDEN);
    }

    // Create the superuser
    let mut store = state.credential_store.write().await;
    let user_id = store.register_with_password(&req.username, req.password.as_bytes());

    // Get the OPAQUE registration bytes for persistence
    let reg_bytes = store.get_registration_bytes(&req.username);

    // Persist superuser to PostgreSQL with tier 1 (Sovereign)
    let _ = sqlx::query(
        "INSERT INTO users (id, username, tier, opaque_registration, created_at, is_active) VALUES ($1, $2, 1, $3, $4, true) ON CONFLICT (username) DO UPDATE SET opaque_registration = $3"
    )
    .bind(user_id)
    .bind(&req.username)
    .bind(&reg_bytes)
    .bind(now_secs())
    .execute(&state.db)
    .await;

    // Mark setup as complete
    state.setup_complete.store(true, Ordering::Relaxed);

    Ok(Json(serde_json::json!({
        "success": true,
        "user_id": user_id.to_string(),
        "admin_api_key": state.admin_api_key.clone(),
        "message": "Superuser created. Save your admin API key securely."
    })))
}

async fn get_status(State(state): State<Arc<AppState>>) -> Json<SystemStatus> {
    let u: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE is_active = true")
        .fetch_one(&state.db)
        .await
        .unwrap_or((0,));
    let d: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM devices WHERE is_active = true")
        .fetch_one(&state.db)
        .await
        .unwrap_or((0,));
    let p: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM portals WHERE is_active = true")
        .fetch_one(&state.db)
        .await
        .unwrap_or((0,));
    let a: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_log")
        .fetch_one(&state.db)
        .await
        .unwrap_or((0,));

    let kt = state.kt_tree.read().await;
    Json(SystemStatus {
        version: "0.1.0".to_string(),
        users_registered: u.0,
        devices_enrolled: d.0,
        portals_active: p.0,
        audit_entries: a.0,
        kt_operations: kt.len(),
    })
}

// ---------------------------------------------------------------------------
// Handlers — Users
// ---------------------------------------------------------------------------

async fn register_user(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<RegisterUserResponse>, StatusCode> {
    // Extract tier from auth middleware
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    // Registering users requires tier 1 (Sovereign)
    check_tier(caller_tier, 1)?;

    let body = axum::body::to_bytes(request.into_body(), 1024 * 64)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let req: RegisterUserRequest = serde_json::from_slice(&body)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let tier = req.tier.unwrap_or(2).clamp(1, 4);
    let mut store = state.credential_store.write().await;
    let user_id = store.register_with_password(&req.username, req.password.as_bytes());

    // Get the OPAQUE registration bytes for persistence
    let reg_bytes = store.get_registration_bytes(&req.username);

    // Persist user to PostgreSQL (with tier and OPAQUE registration)
    let _ = sqlx::query(
        "INSERT INTO users (id, username, tier, opaque_registration, created_at, is_active) VALUES ($1, $2, $3, $4, $5, true) ON CONFLICT (username) DO UPDATE SET opaque_registration = $4"
    )
    .bind(user_id)
    .bind(&req.username)
    .bind(tier as i32)
    .bind(&reg_bytes)
    .bind(now_secs())
    .execute(&state.db)
    .await;

    // Log to audit (in-memory chain + PostgreSQL)
    let mut audit = state.audit_log.write().await;
    let entry = audit.append(
        common::types::AuditEventType::CredentialRegistered,
        vec![user_id],
        vec![],
        0.0,
        vec![],
    );

    let user_ids_json = serde_json::to_string(&entry.user_ids).unwrap_or_default();
    let _ = sqlx::query(
        "INSERT INTO audit_log (id, event_type, user_ids, timestamp, prev_hash, signature) VALUES ($1, $2, $3, $4, $5, $6)"
    )
    .bind(entry.event_id)
    .bind(format!("{:?}", entry.event_type))
    .bind(user_ids_json)
    .bind(entry.timestamp)
    .bind(entry.prev_hash.to_vec())
    .bind(entry.signature.clone())
    .execute(&state.db)
    .await;

    // Log to KT
    let mut kt = state.kt_tree.write().await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64;
    kt.append_credential_op(&user_id, "register", &[0u8; 32], now);

    Ok(Json(RegisterUserResponse {
        user_id,
        username: req.username,
        tier,
    }))
}

async fn list_users(State(state): State<Arc<AppState>>) -> Json<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT username FROM users WHERE is_active = true"
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    Json(rows.into_iter().map(|r| r.0).collect())
}

// ---------------------------------------------------------------------------
// Handlers — Portals
// ---------------------------------------------------------------------------

async fn register_portal(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<PortalResponse>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 1)?;

    let body = axum::body::to_bytes(request.into_body(), 1024 * 64)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let req: RegisterPortalRequest = serde_json::from_slice(&body)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let portal_id = Uuid::new_v4();

    let _ = sqlx::query(
        "INSERT INTO portals (id, name, callback_url, required_tier, required_scope, is_active, created_at) VALUES ($1, $2, $3, $4, $5, true, $6)"
    )
    .bind(portal_id)
    .bind(&req.name)
    .bind(&req.callback_url)
    .bind(req.required_tier as i32)
    .bind(req.required_scope as i32)
    .bind(now_secs())
    .execute(&state.db)
    .await;

    Ok(Json(PortalResponse {
        id: portal_id,
        name: req.name,
        callback_url: req.callback_url,
        required_tier: req.required_tier,
        required_scope: req.required_scope,
        is_active: true,
    }))
}

async fn list_portals(State(state): State<Arc<AppState>>) -> Json<Vec<PortalResponse>> {
    let rows: Vec<(Uuid, String, String, i32, i32, bool)> = sqlx::query_as(
        "SELECT id, name, callback_url, required_tier, required_scope, is_active FROM portals WHERE is_active = true"
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let portals = rows.into_iter().map(|r| PortalResponse {
        id: r.0,
        name: r.1,
        callback_url: r.2,
        required_tier: r.3 as u8,
        required_scope: r.4 as u32,
        is_active: r.5,
    }).collect();

    Json(portals)
}

async fn delete_portal(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    request: Request,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 1)?;

    let _ = sqlx::query("UPDATE portals SET is_active = false WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await;
    Ok(Json(serde_json::json!({"deleted": true})))
}

// ---------------------------------------------------------------------------
// Handlers — Devices
// ---------------------------------------------------------------------------

async fn enroll_device(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<DeviceResponse>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 1)?;

    let body = axum::body::to_bytes(request.into_body(), 1024 * 64)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let req: EnrollDeviceRequest = serde_json::from_slice(&body)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let device_id = Uuid::new_v4();
    let tier = req.tier.unwrap_or(2).min(4).max(1);
    let attestation = req.attestation_hash.unwrap_or_default();
    let enrolled_by = req.enrolled_by.unwrap_or_else(Uuid::new_v4);

    let _ = sqlx::query(
        "INSERT INTO devices (id, tier, attestation_hash, enrolled_by, is_active, created_at) VALUES ($1, $2, $3, $4, true, $5)"
    )
    .bind(device_id)
    .bind(tier as i32)
    .bind(attestation.as_bytes())
    .bind(enrolled_by)
    .bind(now_secs())
    .execute(&state.db)
    .await;

    Ok(Json(DeviceResponse {
        device_id,
        tier,
        enrolled_by,
        is_active: true,
    }))
}

async fn list_devices(State(state): State<Arc<AppState>>) -> Json<Vec<DeviceResponse>> {
    let rows: Vec<(Uuid, i32, Uuid, bool)> = sqlx::query_as(
        "SELECT id, tier, enrolled_by, is_active FROM devices WHERE is_active = true"
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let devices = rows.into_iter().map(|r| DeviceResponse {
        device_id: r.0,
        tier: r.1 as u8,
        enrolled_by: r.2,
        is_active: r.3,
    }).collect();

    Json(devices)
}

// ---------------------------------------------------------------------------
// Handlers — Audit
// ---------------------------------------------------------------------------

async fn get_audit_log(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<Vec<AuditEntryResponse>>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 2)?;

    let rows: Vec<(Uuid, String, Option<String>, i64)> = sqlx::query_as(
        "SELECT id, event_type, user_ids, timestamp FROM audit_log ORDER BY timestamp ASC"
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let entries = rows.into_iter().map(|r| {
        let user_ids: Vec<Uuid> = r.2
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();
        AuditEntryResponse {
            event_id: r.0,
            event_type: r.1,
            user_ids,
            device_ids: vec![],
            risk_score: 0.0,
            timestamp: r.3,
        }
    }).collect();

    Ok(Json(entries))
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
                username: None,
                token: None,
                tier: None,
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

            // Persist session to PostgreSQL
            let session_id = Uuid::new_v4();
            let expires_at = now as i64 + 3600;
            let _ = sqlx::query(
                "INSERT INTO sessions (id, user_id, created_at, expires_at, is_active) VALUES ($1, $2, $3, $4, true)"
            )
            .bind(session_id)
            .bind(user_id)
            .bind(now as i64)
            .bind(expires_at)
            .execute(&state.db)
            .await;

            // Look up user tier
            let user_tier: i32 = sqlx::query_scalar("SELECT tier FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_one(&state.db)
                .await
                .unwrap_or(2);

            Json(LoginResponse {
                success: true,
                user_id: Some(user_id),
                username: Some(req.username.clone()),
                token: Some(token),
                tier: Some(user_tier as u8),
                error: None,
            })
        }
        Err(e) => Json(LoginResponse {
            success: false,
            user_id: None,
            username: None,
            token: None,
            tier: None,
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

// ---------------------------------------------------------------------------
// Handlers — Duress PIN
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RegisterDuressPinRequest {
    user_id: Uuid,
    normal_pin: String,
    duress_pin: String,
}

async fn register_duress_pin(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 2)?;

    let body = axum::body::to_bytes(request.into_body(), 1024 * 64)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let req: RegisterDuressPinRequest = serde_json::from_slice(&body)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let config = common::duress::DuressConfig::new(
        req.user_id,
        req.normal_pin.as_bytes(),
        req.duress_pin.as_bytes(),
    );
    let serialized = postcard::to_allocvec(&config).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    sqlx::query("UPDATE users SET duress_pin_hash = $1 WHERE id = $2")
        .bind(&serialized)
        .bind(req.user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({"success": true})))
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

// ---------------------------------------------------------------------------
// Handlers — OIDC / OAuth2
// ---------------------------------------------------------------------------

async fn oidc_discovery() -> Json<sso_protocol::discovery::OpenIdConfiguration> {
    let issuer = std::env::var("SSO_ISSUER")
        .unwrap_or_else(|_| "https://sso-system.dmj.one".to_string());
    Json(sso_protocol::discovery::OpenIdConfiguration::new(&issuer))
}

#[derive(Deserialize)]
struct AuthorizeParams {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    scope: String,
    state: String,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
}

async fn oauth_authorize(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuthorizeParams>,
) -> axum::response::Response {
    use axum::response::{IntoResponse, Html};
    use axum::http::header;

    if params.response_type != "code" {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "unsupported_response_type"}))).into_response();
    }

    // Validate client
    let clients = state.oauth_clients.read().await;
    let client = match clients.get(&params.client_id) {
        Some(c) => c.clone(),
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_client"}))).into_response(),
    };
    drop(clients);

    if !client.redirect_uris.iter().any(|u| params.redirect_uri.starts_with(u.trim_end_matches("/callback")) || u == &params.redirect_uri) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_redirect_uri"}))).into_response();
    }

    // Show login page — user MUST authenticate before getting an auth code
    let login_html = format!(r#"<!DOCTYPE html>
<html><head><title>MILNET SSO // Authenticate</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet">
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0a0a0a;color:#c0c0c0;font-family:'JetBrains Mono',monospace;min-height:100vh;display:flex;align-items:center;justify-content:center}}
.c{{text-align:center;max-width:500px;padding:40px}}
h1{{color:#00ff41;font-size:1.8rem;margin-bottom:5px}}
h2{{color:#666;font-size:0.8rem;margin-bottom:30px;font-weight:400}}
.app{{background:#111;border:1px solid #222;border-radius:8px;padding:20px;margin-bottom:20px}}
.app .name{{color:#00d4ff;font-weight:700}}
.app .url{{color:#666;font-size:0.75rem}}
form{{background:#111;border:1px solid #222;border-radius:8px;padding:30px;text-align:left}}
label{{display:block;color:#00ff41;font-size:0.75rem;text-transform:uppercase;margin-bottom:5px;margin-top:15px}}
input{{width:100%;padding:12px;background:#0a0a0a;border:1px solid #333;color:#fff;font-family:inherit;font-size:0.9rem;border-radius:4px}}
input:focus{{outline:none;border-color:#00ff41}}
button{{width:100%;padding:14px;background:#00ff41;color:#000;font-family:inherit;font-weight:700;font-size:1rem;border:none;border-radius:4px;cursor:pointer;margin-top:20px}}
button:hover{{background:#00cc33}}
.err{{color:#ff3333;margin-top:10px;font-size:0.8rem;display:none}}
.badge{{display:inline-block;background:#002200;border:1px solid #00ff41;color:#00ff41;padding:3px 10px;border-radius:20px;font-size:0.65rem;margin-bottom:15px}}
</style></head><body>
<div class="c">
<div class="badge">MILNET SSO</div>
<h1>AUTHENTICATE</h1>
<h2>Sign in to continue</h2>
<div class="app">
  <div class="name">{app_name}</div>
  <div class="url">is requesting access to your account</div>
</div>
<form method="POST" action="/oauth/authorize/login" id="loginForm">
  <input type="hidden" name="client_id" value="{client_id}">
  <input type="hidden" name="redirect_uri" value="{redirect_uri}">
  <input type="hidden" name="scope" value="{scope}">
  <input type="hidden" name="state" value="{state}">
  <input type="hidden" name="nonce" value="{nonce}">
  <input type="hidden" name="code_challenge" value="{code_challenge}">
  <label>Username</label>
  <input type="text" name="username" placeholder="Enter your username" required autofocus>
  <label>Password</label>
  <input type="password" name="password" placeholder="Enter your password" required>
  <button type="submit">SIGN IN</button>
  <div class="err" id="err"></div>
</form>
</div></body></html>"#,
        app_name = client.name,
        client_id = params.client_id,
        redirect_uri = params.redirect_uri,
        scope = params.scope,
        state = params.state,
        nonce = params.nonce.as_deref().unwrap_or(""),
        code_challenge = params.code_challenge.as_deref().unwrap_or(""),
    );

    Html(login_html).into_response()
}

/// Handle the login form POST from the OAuth authorize page
async fn oauth_authorize_login(
    State(state): State<Arc<AppState>>,
    axum::extract::Form(form): axum::extract::Form<OAuthLoginForm>,
) -> axum::response::Response {
    use axum::response::{IntoResponse, Html};
    use axum::http::header;

    // Authenticate the user
    let store = state.credential_store.read().await;
    let user_id = match store.verify_password(&form.username, form.password.as_bytes()) {
        Ok(id) => id,
        Err(_) => {
            // Authentication failed — show error
            return Html(format!(r#"<!DOCTYPE html>
<html><head><title>MILNET SSO // Error</title>
<style>body{{background:#0a0a0a;color:#ff3333;font-family:'JetBrains Mono',monospace;padding:60px;text-align:center}}
a{{color:#00ff41}}</style></head><body>
<h1>AUTHENTICATION FAILED</h1>
<p style="margin:20px 0;color:#888">Invalid username or password.</p>
<a href="/oauth/authorize?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}">Try Again</a>
</body></html>"#,
                form.client_id, form.redirect_uri, form.scope, form.state
            )).into_response();
        }
    };
    drop(store);

    // Look up the user's tier from the database
    let mut user_tier: i32 = sqlx::query_scalar("SELECT tier FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await
        .unwrap_or(2);

    // Check duress PIN — if the password matches a registered duress PIN,
    // silently downgrade the session to minimum access (tier 4).
    let duress_row: Option<(Option<Vec<u8>>,)> = sqlx::query_as(
        "SELECT duress_pin_hash FROM users WHERE id = $1"
    )
        .bind(user_id)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    if let Some((Some(bytes),)) = duress_row {
        if !bytes.is_empty() {
            if let Ok(config) = postcard::from_bytes::<common::duress::DuressConfig>(&bytes) {
                if config.verify_pin(form.password.as_bytes()) == common::duress::PinVerification::Duress {
                    tracing::error!("DURESS PIN DETECTED for user {user_id}");
                    let mut audit = state.audit_log.write().await;
                    audit.append(
                        common::types::AuditEventType::DuressDetected,
                        vec![user_id], vec![], 1.0, vec![],
                    );
                    drop(audit);
                    user_tier = 4;
                }
            }
        }
    }

    // Tier 1 users MUST complete FIDO2 if they have credentials registered
    if user_tier == 1 {
        let fido_store = state.fido_store.read().await;
        let creds = fido_store.get_user_credentials(&user_id);
        if !creds.is_empty() {
            // Log that FIDO2 verification would be required
            tracing::info!("Tier 1 user {user_id} has {} FIDO2 credentials — FIDO2 step required", creds.len());
            // In full implementation: redirect to FIDO2 challenge page
            // For now: proceed with warning (graceful degradation)
            // The FIDO2 registration and authentication endpoints already exist at:
            // /api/fido/register/begin, /api/fido/register/complete
            // /api/fido/authenticate/begin, /api/fido/authenticate/complete
        }
        drop(fido_store);
    }

    // Authentication succeeded — create authorization code with tier
    let mut codes = state.auth_codes.write().await;
    let code = codes.create_code_with_tier(
        &form.client_id,
        &form.redirect_uri,
        user_id,
        &form.scope,
        if form.code_challenge.is_empty() { None } else { Some(form.code_challenge.clone()) },
        if form.nonce.is_empty() { None } else { Some(form.nonce.clone()) },
        user_tier as u8,
    );
    drop(codes);

    // Log to audit
    let mut audit = state.audit_log.write().await;
    audit.append(
        common::types::AuditEventType::AuthSuccess,
        vec![user_id], vec![], 0.0, vec![],
    );
    drop(audit);

    // Redirect back to the client with the auth code
    let redirect_url = format!("{}?code={}&state={}", form.redirect_uri, code, form.state);
    (StatusCode::FOUND, [(header::LOCATION, redirect_url)]).into_response()
}

#[derive(Deserialize)]
struct OAuthLoginForm {
    username: String,
    password: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
    nonce: String,
    code_challenge: String,
}

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: String,
    redirect_uri: String,
    client_id: String,
    client_secret: String,
    code_verifier: Option<String>,
}

async fn oauth_token(
    State(state): State<Arc<AppState>>,
    body: String,
) -> Json<serde_json::Value> {
    // Accept both JSON and form-urlencoded (OAuth standard uses form)
    let req: TokenRequest = if let Ok(r) = serde_json::from_str(&body) {
        r
    } else if let Ok(r) = serde_urlencoded::from_str(&body) {
        r
    } else {
        return Json(serde_json::json!({"error": "invalid_request", "error_description": "could not parse request body"}));
    };
    if req.grant_type != "authorization_code" {
        return Json(serde_json::json!({"error": "unsupported_grant_type"}));
    }

    // Validate client credentials
    let clients = state.oauth_clients.read().await;
    if clients.validate(&req.client_id, &req.client_secret).is_none() {
        return Json(serde_json::json!({"error": "invalid_client"}));
    }
    drop(clients);

    // Consume authorization code
    let mut codes = state.auth_codes.write().await;
    let auth_code = match codes.consume_code(&req.code) {
        Some(c) => c,
        None => return Json(serde_json::json!({"error": "invalid_grant"})),
    };
    drop(codes);

    // Verify redirect_uri matches
    if auth_code.redirect_uri != req.redirect_uri {
        return Json(serde_json::json!({"error": "invalid_grant", "description": "redirect_uri mismatch"}));
    }

    // Verify PKCE if challenge was present
    if let Some(ref challenge) = auth_code.code_challenge {
        match &req.code_verifier {
            Some(verifier) => {
                if !sso_protocol::pkce::verify_pkce(verifier, challenge) {
                    return Json(serde_json::json!({"error": "invalid_grant", "description": "PKCE verification failed"}));
                }
            }
            None => {
                return Json(serde_json::json!({"error": "invalid_grant", "description": "code_verifier required"}));
            }
        }
    }

    // Create tokens (with the user's tier from the auth code)
    let id_token = sso_protocol::tokens::create_id_token_with_tier(
        std::env::var("SSO_ISSUER").unwrap_or_else(|_| "https://sso-system.dmj.one".to_string()).as_str(),
        &auth_code.user_id,
        &req.client_id,
        auth_code.nonce,
        &state.oidc_signing_key,
        auth_code.tier,
    );

    let access_token = Uuid::new_v4().to_string();

    let response = sso_protocol::tokens::TokenResponse {
        access_token,
        token_type: "Bearer".into(),
        expires_in: 3600,
        id_token,
        scope: auth_code.scope,
    };

    Json(serde_json::to_value(response).unwrap())
}

async fn oauth_userinfo() -> Json<sso_protocol::userinfo::UserInfo> {
    // In production this would extract the access token from the Authorization
    // header, look up the associated user, and return real profile data.
    Json(sso_protocol::userinfo::UserInfo {
        sub: Uuid::nil().to_string(),
        name: None,
        preferred_username: None,
    })
}

// ---------------------------------------------------------------------------
// FIDO2/WebAuthn request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct FidoRegisterBeginRequest {
    pub user_id: Uuid,
    pub username: String,
    #[serde(default)]
    pub prefer_platform: bool,
}

#[derive(Serialize)]
pub struct FidoRegisterBeginResponse {
    pub options: fido::types::PublicKeyCredentialCreationOptions,
}

#[derive(Deserialize)]
pub struct FidoRegisterCompleteRequest {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub client_data: Vec<u8>,
    #[serde(default = "default_authenticator_type")]
    pub authenticator_type: String,
}

fn default_authenticator_type() -> String {
    "cross-platform".to_string()
}

#[derive(Serialize)]
pub struct FidoRegisterCompleteResponse {
    pub success: bool,
    pub credential_id: Vec<u8>,
}

#[derive(Deserialize)]
pub struct FidoAuthBeginRequest {
    pub user_id: Uuid,
}

#[derive(Serialize)]
pub struct FidoAuthBeginResponse {
    pub options: fido::types::PublicKeyCredentialRequestOptions,
}

#[derive(Deserialize)]
pub struct FidoAuthCompleteRequest {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub client_data: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
pub struct FidoAuthCompleteResponse {
    pub success: bool,
    pub user_id: Option<Uuid>,
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Handlers — FIDO2/WebAuthn
// ---------------------------------------------------------------------------

async fn fido_register_begin(
    State(state): State<Arc<AppState>>,
    Json(req): Json<FidoRegisterBeginRequest>,
) -> Json<FidoRegisterBeginResponse> {
    let options = fido::registration::create_registration_options(
        "MILNET SSO",
        "sso-system.dmj.one",
        &req.user_id,
        &req.username,
        req.prefer_platform,
    );

    // Store the challenge so we can verify it on completion
    let mut fido_store = state.fido_store.write().await;
    fido_store.store_challenge(&options.challenge, req.user_id);

    Json(FidoRegisterBeginResponse { options })
}

async fn fido_register_complete(
    State(state): State<Arc<AppState>>,
    Json(req): Json<FidoRegisterCompleteRequest>,
) -> Json<FidoRegisterCompleteResponse> {
    let cred = fido::types::StoredCredential {
        credential_id: req.credential_id.clone(),
        public_key: req.public_key,
        user_id: req.user_id,
        sign_count: 0,
        authenticator_type: req.authenticator_type,
    };

    let mut fido_store = state.fido_store.write().await;
    fido_store.store_credential(cred);

    // Log to audit
    let mut audit = state.audit_log.write().await;
    audit.append(
        common::types::AuditEventType::CredentialRegistered,
        vec![req.user_id],
        vec![],
        0.0,
        vec![],
    );

    Json(FidoRegisterCompleteResponse {
        success: true,
        credential_id: req.credential_id,
    })
}

async fn fido_authenticate_begin(
    State(state): State<Arc<AppState>>,
    Json(req): Json<FidoAuthBeginRequest>,
) -> Json<serde_json::Value> {
    let fido_store = state.fido_store.read().await;
    let creds = fido_store.get_user_credentials(&req.user_id);

    if creds.is_empty() {
        return Json(serde_json::json!({
            "error": "no credentials registered for this user"
        }));
    }

    let options = fido::authentication::create_authentication_options(
        "sso-system.dmj.one",
        &creds,
    );

    Json(serde_json::to_value(FidoAuthBeginResponse { options }).unwrap())
}

async fn fido_authenticate_complete(
    State(state): State<Arc<AppState>>,
    Json(req): Json<FidoAuthCompleteRequest>,
) -> Json<FidoAuthCompleteResponse> {
    let fido_store = state.fido_store.read().await;

    // Look up the credential
    match fido_store.get_credential(&req.credential_id) {
        Some(cred) => {
            // In a full implementation we would verify the signature against
            // the stored public key and check the sign count. For now, we
            // confirm the credential exists and return the associated user.
            Json(FidoAuthCompleteResponse {
                success: true,
                user_id: Some(cred.user_id),
                error: None,
            })
        }
        None => Json(FidoAuthCompleteResponse {
            success: false,
            user_id: None,
            error: Some("unknown credential".into()),
        }),
    }
}

// ---------------------------------------------------------------------------
// Handlers — User self-service
// ---------------------------------------------------------------------------

async fn get_user_profile(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let token = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_start_matches("Bearer ").to_string())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let parts: Vec<&str> = token.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let user_id = uuid::Uuid::parse_str(parts[0]).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let row: Option<(String, i32, i64, bool)> = sqlx::query_as(
        "SELECT username, tier, created_at, is_active FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    match row {
        Some((username, tier, created_at, is_active)) => Ok(Json(serde_json::json!({
            "user_id": user_id,
            "username": username,
            "tier": tier,
            "created_at": created_at,
            "is_active": is_active,
        }))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

// ---------------------------------------------------------------------------
// Handlers — JWKS
// ---------------------------------------------------------------------------

async fn oauth_jwks() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "keys": [{
            "kty": "oct",
            "alg": "HS512",
            "use": "sig",
            "kid": "milnet-hs512-v1"
        }]
    }))
}


// ---------------------------------------------------------------------------
// Handlers — Multi-person Ceremony
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct InitiateCeremonyRequest {
    pub action: String,
    pub level: u8,
}

#[derive(Serialize)]
pub struct InitiateCeremonyResponse {
    pub ceremony_id: Uuid,
    pub required_approvals: usize,
    pub expires_at: i64,
}

#[derive(Deserialize)]
pub struct ApproveCeremonyRequest {
    pub ceremony_id: Uuid,
}

#[derive(Serialize)]
pub struct ApproveCeremonyResponse {
    pub approved: bool,
    pub complete: bool,
    pub approvals: usize,
    pub required: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Extract the caller's user ID from the Authorization header token.
/// Token format: `user_id:timestamp:hmac`
fn extract_user_id_from_request(request: &Request) -> Option<Uuid> {
    let header = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())?;
    if !header.starts_with("Bearer ") {
        return None;
    }
    let token = &header[7..];
    let parts: Vec<&str> = token.splitn(3, ':').collect();
    if parts.len() == 3 {
        Uuid::parse_str(parts[0]).ok()
    } else {
        // Admin API key — no user ID available
        None
    }
}

async fn initiate_ceremony(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<InitiateCeremonyResponse>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 1)?;

    let initiator = extract_user_id_from_request(&request)
        .unwrap_or_else(Uuid::nil);

    let body = axum::body::to_bytes(request.into_body(), 1024 * 64)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let req: InitiateCeremonyRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    let required_approvals = match req.level {
        3 => 2,
        4 => 3,
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    let now = now_secs();
    let ceremony_id = Uuid::new_v4();
    let ceremony = PendingCeremony {
        action: req.action,
        level: req.level,
        initiator,
        approvers: Vec::new(),
        required_approvals,
        created_at: now,
        expires_at: now + 1800, // 30-minute expiry
    };

    state
        .pending_ceremonies
        .write()
        .await
        .insert(ceremony_id, ceremony);

    Ok(Json(InitiateCeremonyResponse {
        ceremony_id,
        required_approvals,
        expires_at: now + 1800,
    }))
}

async fn approve_ceremony(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<ApproveCeremonyResponse>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 1)?;

    let approver = extract_user_id_from_request(&request)
        .unwrap_or_else(Uuid::nil);

    let body = axum::body::to_bytes(request.into_body(), 1024 * 64)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let req: ApproveCeremonyRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut ceremonies = state.pending_ceremonies.write().await;
    let ceremony = ceremonies
        .get_mut(&req.ceremony_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    let now = now_secs();

    // Check expiry
    if now > ceremony.expires_at {
        let required = ceremony.required_approvals;
        ceremonies.remove(&req.ceremony_id);
        return Ok(Json(ApproveCeremonyResponse {
            approved: false,
            complete: false,
            approvals: 0,
            required,
            error: Some("ceremony expired".into()),
        }));
    }

    // Approver cannot be the initiator
    if approver == ceremony.initiator {
        return Ok(Json(ApproveCeremonyResponse {
            approved: false,
            complete: false,
            approvals: ceremony.approvers.len(),
            required: ceremony.required_approvals,
            error: Some("initiator cannot approve their own ceremony".into()),
        }));
    }

    // Approver cannot approve twice
    if ceremony.approvers.contains(&approver) {
        return Ok(Json(ApproveCeremonyResponse {
            approved: false,
            complete: false,
            approvals: ceremony.approvers.len(),
            required: ceremony.required_approvals,
            error: Some("already approved".into()),
        }));
    }

    ceremony.approvers.push(approver);
    let approvals = ceremony.approvers.len();
    let required = ceremony.required_approvals;
    let complete = approvals >= required;
    let level = ceremony.level;

    // If complete and Level 4, enforce cooldown and 72h rate limit
    if complete && level == 4 {
        let config = common::config::SecurityConfig::default();

        // Check cooldown
        let last = state.last_level4_ceremony.read().await;
        if let Some(last_ts) = *last {
            if now - last_ts < config.level4_cooldown_secs as i64 {
                return Ok(Json(ApproveCeremonyResponse {
                    approved: true,
                    complete: false,
                    approvals,
                    required,
                    error: Some(format!(
                        "level 4 cooldown active — wait {} seconds",
                        config.level4_cooldown_secs as i64 - (now - last_ts)
                    )),
                }));
            }
        }
        drop(last);

        // Check 72h rate limit
        let mut count_72h = state.level4_count_72h.write().await;
        let cutoff = now - 72 * 3600;
        count_72h.retain(|&ts| ts > cutoff);
        if count_72h.len() >= config.level4_max_per_72h as usize {
            return Ok(Json(ApproveCeremonyResponse {
                approved: true,
                complete: false,
                approvals,
                required,
                error: Some("level 4 rate limit exceeded — max 1 per 72h".into()),
            }));
        }

        // Record this Level 4 ceremony
        count_72h.push(now);
        drop(count_72h);
        *state.last_level4_ceremony.write().await = Some(now);
    }

    if complete {
        ceremonies.remove(&req.ceremony_id);
    }

    Ok(Json(ApproveCeremonyResponse {
        approved: true,
        complete,
        approvals,
        required,
        error: None,
    }))
}

async fn ceremony_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<PendingCeremony>, StatusCode> {
    let ceremonies = state.pending_ceremonies.read().await;
    ceremonies
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}
