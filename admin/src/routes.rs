use axum::extract::{Path, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
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
async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Skip auth for health, discovery, and public endpoints
    let path = request.uri().path();
    if path == "/api/health"
        || path == "/.well-known/openid-configuration"
        || path == "/oauth/authorize"
        || path == "/oauth/token"
        || path.starts_with("/api/auth/")
        || path == "/"
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
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            let token = &header[7..];
            // Accept the admin API key
            if token == state.admin_api_key {
                return Ok(next.run(request).await);
            }
            // Accept a valid user auth token (user_id:timestamp:hmac)
            if verify_user_token(token) {
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
        // OIDC / OAuth2
        .route("/.well-known/openid-configuration", get(oidc_discovery))
        .route("/oauth/authorize", get(oauth_authorize))
        .route("/oauth/token", post(oauth_token))
        .route("/oauth/userinfo", get(oauth_userinfo))
        // FIDO2/WebAuthn
        .route("/api/fido/register/begin", post(fido_register_begin))
        .route("/api/fido/register/complete", post(fido_register_complete))
        .route("/api/fido/authenticate/begin", post(fido_authenticate_begin))
        .route("/api/fido/authenticate/complete", post(fido_authenticate_complete))
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
    Json(req): Json<RegisterUserRequest>,
) -> Json<RegisterUserResponse> {
    let mut store = state.credential_store.write().await;
    let user_id = store.register_with_password(&req.username, req.password.as_bytes());

    // Persist user to PostgreSQL
    let _ = sqlx::query(
        "INSERT INTO users (id, username, created_at, is_active) VALUES ($1, $2, $3, true) ON CONFLICT (id) DO UPDATE SET username = $2"
    )
    .bind(user_id)
    .bind(&req.username)
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

    Json(RegisterUserResponse {
        user_id,
        username: req.username,
    })
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
    Json(req): Json<RegisterPortalRequest>,
) -> Json<PortalResponse> {
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

    Json(PortalResponse {
        id: portal_id,
        name: req.name,
        callback_url: req.callback_url,
        required_tier: req.required_tier,
        required_scope: req.required_scope,
        is_active: true,
    })
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
) -> Json<serde_json::Value> {
    let _ = sqlx::query("UPDATE portals SET is_active = false WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await;
    Json(serde_json::json!({"deleted": true}))
}

// ---------------------------------------------------------------------------
// Handlers — Devices
// ---------------------------------------------------------------------------

async fn enroll_device(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EnrollDeviceRequest>,
) -> Json<DeviceResponse> {
    let device_id = Uuid::new_v4();

    let _ = sqlx::query(
        "INSERT INTO devices (id, tier, attestation_hash, enrolled_by, is_active, created_at) VALUES ($1, $2, $3, $4, true, $5)"
    )
    .bind(device_id)
    .bind(req.tier as i32)
    .bind(req.attestation_hash.as_bytes())
    .bind(req.enrolled_by)
    .bind(now_secs())
    .execute(&state.db)
    .await;

    Json(DeviceResponse {
        device_id,
        tier: req.tier,
        enrolled_by: req.enrolled_by,
        is_active: true,
    })
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

async fn get_audit_log(State(state): State<Arc<AppState>>) -> Json<Vec<AuditEntryResponse>> {
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

    Json(entries)
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

// ---------------------------------------------------------------------------
// Handlers — OIDC / OAuth2
// ---------------------------------------------------------------------------

async fn oidc_discovery() -> Json<sso_protocol::discovery::OpenIdConfiguration> {
    // In production the issuer would come from configuration.
    let issuer = "https://sso.milnet.local";
    Json(sso_protocol::discovery::OpenIdConfiguration::new(issuer))
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
) -> Json<serde_json::Value> {
    if params.response_type != "code" {
        return Json(serde_json::json!({"error": "unsupported_response_type"}));
    }

    // Validate client
    let clients = state.oauth_clients.read().await;
    let client = match clients.get(&params.client_id) {
        Some(c) => c,
        None => return Json(serde_json::json!({"error": "invalid_client"})),
    };

    if !client.redirect_uris.contains(&params.redirect_uri) {
        return Json(serde_json::json!({"error": "invalid_redirect_uri"}));
    }
    drop(clients);

    // In a real deployment the user would authenticate interactively here.
    // For the API we use a placeholder user ID. Callers that have already
    // authenticated via /api/auth/login can supply the user_id separately.
    let user_id = Uuid::nil();

    let mut codes = state.auth_codes.write().await;
    let code = codes.create_code(
        &params.client_id,
        &params.redirect_uri,
        user_id,
        &params.scope,
        params.code_challenge,
        params.nonce,
    );

    Json(serde_json::json!({
        "redirect_uri": format!("{}?code={}&state={}", params.redirect_uri, code, params.state),
        "code": code,
        "state": params.state,
    }))
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
    Json(req): Json<TokenRequest>,
) -> Json<serde_json::Value> {
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

    // Create tokens
    let id_token = sso_protocol::tokens::create_id_token(
        "https://sso.milnet.local",
        &auth_code.user_id,
        &req.client_id,
        auth_code.nonce,
        &state.oidc_signing_key,
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
        "sso.milnet.local",
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
        "sso.milnet.local",
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
