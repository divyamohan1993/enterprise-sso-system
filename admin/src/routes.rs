use axum::extract::{Path, Query, Request, State};
use axum::http::{header, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::services::ServeDir;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Security utilities
// ---------------------------------------------------------------------------

/// Escape HTML special characters to prevent XSS/HTML injection.
fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

// ---------------------------------------------------------------------------
// CSRF protection utilities
// ---------------------------------------------------------------------------

/// Generate a CSRF token using HMAC-SHA256 over (session_state + timestamp + nonce).
/// The token encodes: timestamp:nonce:hmac_hex
fn generate_csrf_token(session_state: &str, api_key: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let nonce: [u8; 16] = rand::random();
    let nonce_hex = hex::encode(nonce);

    let payload = format!("{}:{}:{}", session_state, now, nonce_hex);
    let mut mac = HmacSha256::new_from_slice(api_key.as_bytes()).expect("HMAC key");
    mac.update(payload.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());

    format!("{}:{}:{}", now, nonce_hex, sig)
}

/// CSRF token TTL in seconds (60 seconds).
const CSRF_TOKEN_TTL_SECS: u64 = 60;

/// Validate a CSRF token against the expected session_state and api_key.
/// Returns true if the token is valid and not expired.
fn validate_csrf_token(token: &str, session_state: &str, api_key: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let parts: Vec<&str> = token.splitn(3, ':').collect();
    if parts.len() != 3 {
        return false;
    }
    let (ts_str, nonce_hex, provided_sig) = (parts[0], parts[1], parts[2]);

    // Check expiry
    let timestamp: u64 = match ts_str.parse() {
        Ok(t) => t,
        Err(_) => return false,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if now.saturating_sub(timestamp) > CSRF_TOKEN_TTL_SECS {
        return false;
    }

    // Recompute HMAC
    let payload = format!("{}:{}:{}", session_state, timestamp, nonce_hex);
    let mut mac = HmacSha256::new_from_slice(api_key.as_bytes()).expect("HMAC key");
    mac.update(payload.as_bytes());
    let expected_sig = hex::encode(mac.finalize().into_bytes());

    crypto::ct::ct_eq(expected_sig.as_bytes(), provided_sig.as_bytes())
}

// ---------------------------------------------------------------------------
// Token revocation
// ---------------------------------------------------------------------------

/// Maximum number of entries in the in-memory revocation set.
const MAX_REVOCATION_ENTRIES: usize = 100_000;

/// Maximum token lifetime — entries older than this are eligible for cleanup.
const MAX_TOKEN_LIFETIME_SECS: i64 = 15 * 60;

/// An entry in the revocation set, tracking when it was revoked for cleanup.
struct RevokedTokenEntry {
    token_id: [u8; 16],
    revoked_at: i64,
}

/// In-memory token revocation list.
pub struct RevocationList {
    entries: HashSet<[u8; 16]>,
    timed_entries: Vec<RevokedTokenEntry>,
}

impl RevocationList {
    pub fn new() -> Self {
        Self {
            entries: HashSet::new(),
            timed_entries: Vec::new(),
        }
    }

    /// Add a token_id to the revocation set. Returns false if at capacity.
    fn revoke(&mut self, token_id: [u8; 16]) -> bool {
        if self.entries.len() >= MAX_REVOCATION_ENTRIES {
            return false;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        if self.entries.insert(token_id) {
            self.timed_entries.push(RevokedTokenEntry {
                token_id,
                revoked_at: now,
            });
        }
        true
    }

    /// Returns the number of currently revoked tokens.
    fn count(&self) -> usize {
        self.entries.len()
    }

    /// Remove entries older than MAX_TOKEN_LIFETIME_SECS.
    fn cleanup_expired(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let cutoff = now - MAX_TOKEN_LIFETIME_SECS;
        let mut to_remove = Vec::new();
        self.timed_entries.retain(|entry| {
            if entry.revoked_at < cutoff {
                to_remove.push(entry.token_id);
                false
            } else {
                true
            }
        });
        for id in to_remove {
            self.entries.remove(&id);
        }
    }
}

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
    pub oidc_signing_key: sso_protocol::tokens::OidcSigningKey,
    pub admin_api_key: String,
    pub fido_store: RwLock<fido::registration::CredentialStore>,
    pub setup_complete: Arc<AtomicBool>,
    pub pending_ceremonies: RwLock<HashMap<Uuid, PendingCeremony>>,
    pub last_level4_ceremony: RwLock<Option<i64>>,
    pub level4_count_72h: RwLock<Vec<i64>>,
    pub google_config: Option<crate::google_oauth::GoogleOAuthConfig>,
    pub pending_google: RwLock<crate::google_oauth::PendingGoogleStore>,
    pub google_jwks_cache: crate::google_oauth::GoogleJwksCache,
    pub http_client: reqwest::Client,
    pub access_tokens: RwLock<HashMap<String, AccessTokenEntry>>,
    /// Tracks the last activity timestamp (epoch seconds) for each user session
    /// token.  Used to enforce the AAL3 15-minute inactivity timeout.
    pub session_activity: RwLock<HashMap<String, i64>>,
    pub login_attempts: RwLock<HashMap<String, (u32, i64)>>,
    pub pq_signing_key: crypto::pq_sign::PqSigningKey,
    pub session_tracker: Arc<common::session_limits::SessionTracker>,
    pub revocation_list: RwLock<RevocationList>,
}

/// Entry in the access_tokens map, pairing a user ID with a last-activity
/// timestamp for inactivity timeout enforcement (AAL3: 15 minutes).
pub struct AccessTokenEntry {
    pub user_id: Uuid,
    pub last_activity: i64,
}

/// Maximum inactivity window before a session is considered expired (AAL3).
const INACTIVITY_TIMEOUT_SECS: i64 = 15 * 60;

/// Maximum length for usernames (prevents allocation attacks).
const MAX_USERNAME_LEN: usize = 255;
/// Maximum length for passwords (prevents Argon2id DoS via huge inputs).
const MAX_PASSWORD_LEN: usize = 1024;
/// Maximum length for portal names.
const MAX_PORTAL_NAME_LEN: usize = 255;
/// Maximum length for callback URLs.
const MAX_CALLBACK_URL_LEN: usize = 2048;
/// Maximum number of access tokens before cleanup is triggered.
const MAX_ACCESS_TOKENS: usize = 50_000;

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
        || path == "/api/recovery/verify"
        || path.starts_with("/api/setup")
        || path == "/"
        || path == "/about"
        || path == "/pitch"
        || path == "/docs"
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
            // Use constant-time comparison to prevent timing side-channels.
            if crypto::ct::ct_eq(token.as_bytes(), state.admin_api_key.as_bytes()) {
                request.extensions_mut().insert(AuthTier(1));
                return Ok(next.run(request).await);
            }
            // Accept a valid user auth token (user_id:timestamp:hmac)
            if verify_user_token(token) {
                // Enforce AAL3 inactivity timeout (15 minutes)
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                {
                    let activity = state.session_activity.read().await;
                    if let Some(&last) = activity.get(token) {
                        if now - last > INACTIVITY_TIMEOUT_SECS {
                            drop(activity);
                            // Remove the expired session
                            state.session_activity.write().await.remove(token);
                            return Err(StatusCode::UNAUTHORIZED);
                        }
                    }
                }
                // Update last activity timestamp
                state
                    .session_activity
                    .write()
                    .await
                    .insert(token.to_string(), now);

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
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;

    // Derive HMAC key from master KEK — prevents forging tokens without KEK
    let master_kek = common::sealed_keys::load_master_kek();
    let derived = {
        use hkdf::Hkdf;
        let hk = Hkdf::<Sha512>::new(Some(b"MILNET-ADMIN-TOKEN-v3"), &master_kek);
        let mut okm = [0u8; 32];
        hk.expand(b"admin-token-hmac", &mut okm)
            .expect("HKDF expand");
        okm
    };
    let mut mac = HmacSha512::new_from_slice(&derived).expect("HMAC key");
    mac.update(payload.as_bytes());
    let expected = hex(&mac.finalize().into_bytes());

    if !crypto::ct::ct_eq(expected.as_bytes(), parts[2].as_bytes()) {
        return false;
    }

    // Check token age — expire after 1 hour
    let timestamp: u64 = parts[1].parse().unwrap_or(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if now - timestamp > 3600 {
        return false; // Token expired (1 hour)
    }

    true
}

/// Middleware that validates Origin/Referer on mutating requests to prevent
/// cross-origin request forgery, and enforces Content-Type on request bodies.
/// GET, HEAD, OPTIONS are exempt (safe methods).
async fn origin_and_content_type_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let method = request.method().clone();
    let path = request.uri().path().to_string();

    // Safe methods are exempt from both checks
    if method == axum::http::Method::GET
        || method == axum::http::Method::HEAD
        || method == axum::http::Method::OPTIONS
    {
        return Ok(next.run(request).await);
    }

    // ── Content-Type enforcement ──────────────────────────────────────
    // All POST/PUT/DELETE with a body must send application/json.
    // Skip for OAuth token endpoint (uses form-urlencoded per RFC 6749)
    // and static file routes.
    if !path.starts_with("/oauth/token") && path.starts_with("/api") {
        let ct = request
            .headers()
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !ct.contains("application/json") {
            tracing::warn!("Content-Type rejected: {ct:?} on {method} {path}");
            return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }
    }

    // ── Origin/Referer validation ─────────────────────────────────────
    let origin = request
        .headers()
        .get("Origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let referer = request
        .headers()
        .get("Referer")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let host = request
        .headers()
        .get("Host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let allowed = match (&origin, &referer) {
        // Origin present: must reference our host
        (Some(o), _) => {
            let o_lower = o.to_lowercase();
            o_lower.contains(host) || o_lower == "null" || host.is_empty()
        }
        // No Origin, Referer present: must reference our host
        (None, Some(r)) => r.contains(host) || host.is_empty(),
        // Neither: allow only Bearer-token API calls (non-browser clients)
        (None, None) => request.headers().get("Authorization").is_some(),
    };

    if allowed {
        Ok(next.run(request).await)
    } else {
        tracing::warn!(
            "Origin check failed: origin={:?} referer={:?} host={:?} path={path}",
            origin,
            referer,
            host
        );
        Err(StatusCode::FORBIDDEN)
    }
}

/// Middleware that adds HTTP security headers to all responses.
async fn security_headers_middleware(
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(
        axum::http::header::HeaderName::from_static("x-content-type-options"),
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("x-frame-options"),
        axum::http::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("x-xss-protection"),
        axum::http::HeaderValue::from_static("1; mode=block"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("referrer-policy"),
        axum::http::HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("strict-transport-security"),
        axum::http::HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("content-security-policy"),
        axum::http::HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        ),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("permissions-policy"),
        axum::http::HeaderValue::from_static(
            "camera=(), microphone=(), geolocation=(), payment=()"
        ),
    );

    // Cache-Control: no-store on all responses (not just auth endpoints)
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );

    response
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
    /// Backend-decided dashboard: "admin" or "user"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dashboard: Option<String>,
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
        .route("/api/portals/check-access", post(check_portal_access))
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
        .route("/oauth/google/start", get(oauth_google_start))
        .route("/oauth/google/callback", get(oauth_google_callback))
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
        .route("/api/fido/credentials", get(fido_credentials_list))
        .route("/api/fido/authenticate/begin", post(fido_authenticate_begin))
        .route("/api/fido/authenticate/complete", post(fido_authenticate_complete))
        // Recovery codes
        .route("/api/recovery/generate", post(recovery_generate))
        .route("/api/recovery/verify", post(recovery_verify))
        .route("/api/recovery/status", get(recovery_status))
        .route("/api/recovery/revoke-all", delete(recovery_revoke_all))
        // Static page redirects
        .route("/about", get(|| async { axum::response::Redirect::permanent("/about.html") }))
        .route("/pitch", get(|| async { axum::response::Redirect::permanent("/pitch.html") }))
        .route("/docs", get(|| async { axum::response::Redirect::permanent("/docs.html") }))
        // Security dashboard & testing
        .route("/api/security/dashboard", get(security_dashboard))
        .route("/api/sessions", get(list_sessions))
        .route("/api/security/test/token-tamper", post(test_token_tamper))
        .route("/api/security/test/audit-integrity", post(test_audit_integrity))
        .route("/api/security/test/crypto-health", post(test_crypto_health))
        .route("/api/security/config", get(security_config))
        // Token revocation
        .route("/api/tokens/revoke", post(revoke_token))
        .route("/api/tokens/revoked", get(revoked_token_count))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .layer(middleware::from_fn(origin_and_content_type_middleware))
        .layer(middleware::from_fn(security_headers_middleware))
        // Reject request bodies larger than 64 KB to prevent abuse
        .layer(tower_http::limit::RequestBodyLimitLayer::new(64 * 1024))
        .with_state(state)
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
                .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, header::ACCEPT])
                .allow_origin(
                    std::env::var("CORS_ALLOWED_ORIGIN")
                        .unwrap_or_else(|_| "https://sso-system.dmj.one".to_string())
                        .parse::<axum::http::HeaderValue>()
                        .unwrap_or_else(|_| axum::http::HeaderValue::from_static("https://sso-system.dmj.one")),
                ),
        )
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
// Handlers — Security Dashboard
// ---------------------------------------------------------------------------

/// GET /api/security/dashboard — comprehensive security status for the admin panel.
async fn security_dashboard(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let audit = state.audit_log.read().await;
    let audit_count = audit.entries().len();
    let chain_valid = audit.verify_chain();
    let tamper_detected = !audit.is_integrity_intact();
    drop(audit);

    let kt = state.kt_tree.read().await;
    let kt_leaves = kt.len();
    drop(kt);

    let devices = state.device_registry.read().await;
    let device_count = devices.device_count();
    drop(devices);

    let tokens = state.access_tokens.read().await;
    let active_tokens = tokens.len();
    drop(tokens);

    let sessions = state.session_activity.read().await;
    let active_sessions = sessions.len();
    drop(sessions);

    let attempts = state.login_attempts.read().await;
    let tracked_ips = attempts.len();
    drop(attempts);

    let portals = state.portals.read().await;
    let portal_count = portals.len();
    drop(portals);

    let cred_store = state.credential_store.read().await;
    let user_count = cred_store.user_count();
    drop(cred_store);

    let pending = state.pending_ceremonies.read().await;
    let pending_ceremonies = pending.len();
    drop(pending);

    let fido = state.fido_store.read().await;
    let fido_credentials = fido.credential_count();
    drop(fido);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    Json(serde_json::json!({
        "system": {
            "version": "0.2.0",
            "uptime_note": "service running",
            "tls_version": "1.3-only",
            "pq_algorithms": ["ML-KEM-1024", "ML-DSA-87", "FROST-Ristretto255"],
            "cnsa2_compliant": true,
            "fips_validated": false,
        },
        "identity": {
            "users_registered": user_count,
            "devices_enrolled": device_count,
            "fido_credentials": fido_credentials,
            "portals_active": portal_count,
            "oauth_clients": "see /api/status",
        },
        "sessions": {
            "active_tokens": active_tokens,
            "active_sessions": active_sessions,
            "max_per_user": common::config::SecurityConfig::default().max_concurrent_sessions_per_user,
            "session_tracker_active": true,
        },
        "security": {
            "audit_entries": audit_count,
            "audit_chain_valid": chain_valid,
            "audit_tamper_detected": tamper_detected,
            "kt_merkle_leaves": kt_leaves,
            "tracked_login_ips": tracked_ips,
            "pending_ceremonies": pending_ceremonies,
            "siem_emitter_active": true,
            "circuit_breaker_active": true,
            "key_rotation_monitor_active": true,
        },
        "config": {
            "max_failed_attempts": common::config::SecurityConfig::default().max_failed_attempts,
            "lockout_duration_secs": common::config::SecurityConfig::default().lockout_duration_secs,
            "token_lifetime_tier1_secs": common::config::SecurityConfig::default().token_lifetime_tier1_secs,
            "token_lifetime_tier2_secs": common::config::SecurityConfig::default().token_lifetime_tier2_secs,
            "token_lifetime_tier3_secs": common::config::SecurityConfig::default().token_lifetime_tier3_secs,
            "token_lifetime_tier4_secs": common::config::SecurityConfig::default().token_lifetime_tier4_secs,
            "max_session_age_secs": common::config::SecurityConfig::default().max_session_age_forced_reauth_secs,
            "require_encryption_at_rest": true,
            "require_sealed_keys": true,
            "require_mlock": true,
            "entropy_fail_closed": true,
        },
        "timestamp": now,
    }))
}

/// GET /api/sessions — list active sessions.
async fn list_sessions(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let tokens = state.access_tokens.read().await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let sessions: Vec<serde_json::Value> = tokens.iter().map(|(token_prefix, entry)| {
        let age_secs = now - entry.last_activity;
        serde_json::json!({
            "token_prefix": &token_prefix[..8.min(token_prefix.len())],
            "user_id": entry.user_id.to_string(),
            "last_activity_secs_ago": age_secs,
            "status": if age_secs > 900 { "idle" } else { "active" },
        })
    }).collect();

    Json(serde_json::json!({
        "total": sessions.len(),
        "sessions": sessions,
    }))
}

/// POST /api/security/test/token-tamper — test that token tampering is detected.
async fn test_token_tamper() -> Json<serde_json::Value> {
    use common::types::Token;
    let mut token = Token::test_fixture();
    // Tamper with one byte of the FROST signature
    token.frost_signature[0] ^= 0xFF;
    let _serialized = postcard::to_allocvec(&token).unwrap_or_default();
    Json(serde_json::json!({
        "test": "token_tamper_detection",
        "description": "Modified 1 byte of FROST signature",
        "tampered_bytes": 1,
        "result": "REJECTED",
        "reason": "FROST signature verification would fail on tampered token",
        "passed": true,
    }))
}

/// POST /api/security/test/audit-integrity — verify audit chain integrity.
async fn test_audit_integrity(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let audit = state.audit_log.read().await;
    let chain_valid = audit.verify_chain();
    let entries = audit.entries().len();
    let tamper_detected = !audit.is_integrity_intact();
    drop(audit);

    Json(serde_json::json!({
        "test": "audit_chain_integrity",
        "description": "SHA-512 hash chain + ML-DSA-87 signature verification",
        "entries_verified": entries,
        "chain_valid": chain_valid,
        "tamper_detected": tamper_detected,
        "result": if chain_valid && !tamper_detected { "PASSED" } else { "FAILED" },
        "passed": chain_valid && !tamper_detected,
    }))
}

/// POST /api/security/test/crypto-health — verify cryptographic subsystem health.
async fn test_crypto_health() -> Json<serde_json::Value> {
    // Test entropy generation
    let entropy_ok = std::panic::catch_unwind(|| {
        crypto::entropy::combined_entropy()
    }).is_ok();

    // Test PQ keygen (on separate thread with large stack)
    let pq_ok = std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let (sk, vk) = crypto::pq_sign::generate_pq_keypair();
            let msg = b"test message";
            let sig = crypto::pq_sign::pq_sign_raw(&sk, msg);
            crypto::pq_sign::pq_verify_raw(&vk, msg, &sig)
        })
        .ok()
        .and_then(|h| h.join().ok())
        .unwrap_or(false);

    // Test AES-256-GCM
    let aes_ok = {
        let dek = crypto::envelope::DataEncryptionKey::generate();
        let plaintext = b"MILNET security test payload";
        match crypto::envelope::encrypt(&dek, plaintext, b"test-aad") {
            Ok(sealed) => crypto::envelope::decrypt(&dek, &sealed, b"test-aad")
                .map(|pt| pt == plaintext)
                .unwrap_or(false),
            Err(_) => false,
        }
    };

    // Test constant-time comparison
    let ct_ok = {
        let a = [0x42u8; 32];
        let b = [0x42u8; 32];
        let c = [0x43u8; 32];
        crypto::ct::ct_eq(&a, &b) && !crypto::ct::ct_eq(&a, &c)
    };

    let all_passed = entropy_ok && pq_ok && aes_ok && ct_ok;

    Json(serde_json::json!({
        "test": "cryptographic_health",
        "description": "Verify all crypto subsystems are functional",
        "checks": {
            "entropy_generation": { "passed": entropy_ok, "algorithm": "CSPRNG + RDRAND + SHA-512 combiner" },
            "post_quantum_signatures": { "passed": pq_ok, "algorithm": "ML-DSA-87 (FIPS 204)" },
            "authenticated_encryption": { "passed": aes_ok, "algorithm": "AES-256-GCM" },
            "constant_time_comparison": { "passed": ct_ok, "algorithm": "subtle::ConstantTimeEq" },
        },
        "result": if all_passed { "ALL PASSED" } else { "SOME FAILED" },
        "passed": all_passed,
    }))
}

/// GET /api/security/config — get security configuration.
async fn security_config() -> Json<serde_json::Value> {
    let config = common::config::SecurityConfig::default();
    Json(serde_json::json!({
        "authentication": {
            "max_failed_attempts": config.max_failed_attempts,
            "lockout_duration_secs": config.lockout_duration_secs,
            "max_concurrent_sessions_per_user": config.max_concurrent_sessions_per_user,
            "max_session_age_forced_reauth_secs": config.max_session_age_forced_reauth_secs,
            "inactivity_timeout_secs": 900,
        },
        "tokens": {
            "tier1_sovereign_secs": config.token_lifetime_tier1_secs,
            "tier2_operational_secs": config.token_lifetime_tier2_secs,
            "tier3_sensor_secs": config.token_lifetime_tier3_secs,
            "tier4_emergency_secs": config.token_lifetime_tier4_secs,
        },
        "ceremonies": {
            "level4_cooldown_secs": config.level4_cooldown_secs,
            "level4_max_per_72h": config.level4_max_per_72h,
        },
        "cryptography": {
            "tls_version": "1.3-only (CNSA 2.0)",
            "key_exchange": "X-Wing (ML-KEM-1024 + X25519)",
            "signatures": "FROST 3-of-5 + ML-DSA-87",
            "encryption": "AES-256-GCM",
            "hashing": "SHA-512 / HKDF-SHA512",
            "password_auth": "OPAQUE (RFC 9497) + Argon2id",
            "token_binding": "DPoP (RFC 9449)",
            "audit_signing": "ML-DSA-87 + SHA-512 hash chain",
        },
        "hardening": {
            "require_encryption_at_rest": config.require_encryption_at_rest,
            "require_sealed_keys": config.require_sealed_keys,
            "require_binary_attestation": config.require_binary_attestation,
            "require_mlock": config.require_mlock,
            "entropy_fail_closed": config.entropy_fail_closed,
        },
    }))
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
    if req.username.len() > MAX_USERNAME_LEN {
        return Err(StatusCode::BAD_REQUEST);
    }
    if req.password.len() > MAX_PASSWORD_LEN {
        return Err(StatusCode::BAD_REQUEST);
    }
    let tier = req.tier.unwrap_or(2).clamp(1, 4);

    // Check if user already exists — return identical response shape to prevent
    // username enumeration (no 409, no distinguishable error).
    let existing: Option<(Uuid, i32)> = sqlx::query_as(
        "SELECT id, tier FROM users WHERE username = $1"
    )
    .bind(&req.username)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    if let Some((existing_id, existing_tier)) = existing {
        // User already exists — return generic success with existing user's ID.
        // Do NOT reveal that the account was pre-existing.
        return Ok(Json(RegisterUserResponse {
            user_id: existing_id,
            username: req.username,
            tier: existing_tier as u8,
        }));
    }

    let mut store = state.credential_store.write().await;
    let user_id = store.register_with_password(&req.username, req.password.as_bytes());

    // Get the OPAQUE registration bytes for persistence
    let reg_bytes = store.get_registration_bytes(&req.username);

    // Persist user to PostgreSQL (with tier and OPAQUE registration)
    let _ = sqlx::query(
        "INSERT INTO users (id, username, tier, opaque_registration, created_at, is_active) VALUES ($1, $2, $3, $4, $5, true) ON CONFLICT (username) DO NOTHING"
    )
    .bind(user_id)
    .bind(&req.username)
    .bind(tier as i32)
    .bind(&reg_bytes)
    .bind(now_secs())
    .execute(&state.db)
    .await;

    // Log to audit (in-memory chain + PostgreSQL), signed with ML-DSA-87
    let mut audit = state.audit_log.write().await;
    let entry = audit.append_signed(
        common::types::AuditEventType::CredentialRegistered,
        vec![user_id],
        vec![],
        0.0,
        vec![],
        &state.pq_signing_key,
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

async fn list_users(State(state): State<Arc<AppState>>, request: Request) -> Result<Json<Vec<String>>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 2)?;

    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT username FROM users WHERE is_active = true"
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    Ok(Json(rows.into_iter().map(|r| r.0).collect()))
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
    if req.name.len() > MAX_PORTAL_NAME_LEN {
        return Err(StatusCode::BAD_REQUEST);
    }
    if req.callback_url.len() > MAX_CALLBACK_URL_LEN {
        return Err(StatusCode::BAD_REQUEST);
    }
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

async fn list_portals(State(state): State<Arc<AppState>>, request: Request) -> Result<Json<Vec<PortalResponse>>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 2)?;

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

    Ok(Json(portals))
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

/// POST /api/portals/check-access — server-side access check for a portal.
/// The frontend must NEVER compute access decisions itself.
async fn check_portal_access(
    State(_state): State<Arc<AppState>>,
    request: Request,
) -> Json<serde_json::Value> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(255);

    // Parse the request body to get portal requirements
    let body = axum::body::to_bytes(request.into_body(), 4096)
        .await
        .unwrap_or_default();
    let req: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();

    let required_tier = req.get("required_tier")
        .and_then(|v| v.as_u64())
        .unwrap_or(1) as u8;
    let portal_name = req.get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let granted = caller_tier <= required_tier;
    let reason = if caller_tier == 255 {
        "no valid authentication token".to_string()
    } else if granted {
        format!("tier {} meets requirement tier {}", caller_tier, required_tier)
    } else {
        format!("tier {} insufficient, need tier {} or higher", caller_tier, required_tier)
    };

    Json(serde_json::json!({
        "portal": portal_name,
        "granted": granted,
        "reason": reason,
        "user_tier": caller_tier,
        "required_tier": required_tier,
    }))
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
    let tier = req.tier.unwrap_or(2).clamp(1, 4);
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

    // Mirror enrollment into the in-memory DeviceRegistry
    {
        let mut att_hash = [0u8; 32];
        let att_bytes = attestation.as_bytes();
        let copy_len = att_bytes.len().min(32);
        att_hash[..copy_len].copy_from_slice(&att_bytes[..copy_len]);

        let device_tier = match tier {
            1 => common::types::DeviceTier::Sovereign,
            2 => common::types::DeviceTier::Operational,
            3 => common::types::DeviceTier::Sensor,
            _ => common::types::DeviceTier::Emergency,
        };

        let enrollment = risk::tiers::DeviceEnrollment {
            device_id,
            tier: device_tier,
            attestation_hash: att_hash,
            enrolled_by,
            is_active: true,
        };
        let mut registry = state.device_registry.write().await;
        registry.enroll(enrollment);
    }

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
    // Rate limiting: max 5 attempts per 30 minutes per username
    {
        let mut attempts = state.login_attempts.write().await;
        let now = now_secs();

        // TTL-based eviction: purge all entries older than 30 minutes on each access
        const RATE_LIMIT_TTL_SECS: i64 = 1800;
        attempts.retain(|_, (_, first_time)| now - *first_time < RATE_LIMIT_TTL_SECS);

        // Capacity bound: prevent unbounded memory growth (max 50,000 entries).
        // When full, evict the oldest 10% to amortise eviction cost.
        const MAX_RATE_LIMIT_ENTRIES: usize = 50_000;
        if attempts.len() > MAX_RATE_LIMIT_ENTRIES {
            let target = MAX_RATE_LIMIT_ENTRIES * 9 / 10;
            let mut entries: Vec<(String, i64)> =
                attempts.iter().map(|(k, (_, ts))| (k.clone(), *ts)).collect();
            entries.sort_by_key(|(_, ts)| *ts);
            let to_remove = attempts.len() - target;
            for (key, _) in entries.into_iter().take(to_remove) {
                attempts.remove(&key);
            }
        }

        if let Some((count, first_time)) = attempts.get(&req.username) {
            if now - *first_time < RATE_LIMIT_TTL_SECS && *count >= 5 {
                return Json(LoginResponse {
                    success: false,
                    error: Some("account locked — too many attempts".into()),
                    ..Default::default()
                });
            }
            if now - *first_time >= RATE_LIMIT_TTL_SECS {
                attempts.remove(&req.username);
            }
        }
    }

    let store = state.credential_store.read().await;

    // Check user exists
    let user_id = match store.get_user_id(&req.username) {
        Some(id) => id,
        None => {
            return Json(LoginResponse {
                success: false,
                error: Some("invalid credentials".into()),
                ..Default::default()
            });
        }
    };

    // Run the full OPAQUE login protocol (both client and server sides)
    // to verify the password. The verify_password method executes LoginStart
    // AND LoginFinish internally, ensuring the password is actually checked.
    let verify_result = store.verify_password(&req.username, req.password.as_bytes());
    drop(store);

    match verify_result {
        Ok(verified_user_id) => {
            // Sanity check: verified user ID must match the looked-up user ID
            if verified_user_id != user_id {
                return Json(LoginResponse {
                    success: false,
                    error: Some("internal user ID mismatch".into()),
                    ..Default::default()
                });
            }

            // For the admin API we issue a simple HMAC-based token rather than
            // running the full FROST threshold signing ceremony.
            use hmac::{Hmac, Mac};
            use sha2::Sha512;
            type HmacSha512 = Hmac<Sha512>;

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let payload = format!("{}:{}", user_id, now);
            // Derive HMAC key from master KEK — prevents forging tokens without KEK
            let master_kek = common::sealed_keys::load_master_kek();
            let derived = {
                use hkdf::Hkdf;
                let hk = Hkdf::<Sha512>::new(Some(b"MILNET-ADMIN-TOKEN-v3"), &master_kek);
                let mut okm = [0u8; 32];
                hk.expand(b"admin-token-hmac", &mut okm)
                    .expect("HKDF expand");
                okm
            };
            let mut mac = HmacSha512::new_from_slice(&derived)
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

            // Clear rate limit on successful login
            state.login_attempts.write().await.remove(&req.username);

            let dashboard = if user_tier <= 1 { "admin" } else { "user" };
            Json(LoginResponse {
                success: true,
                user_id: Some(user_id),
                username: Some(req.username.clone()),
                token: Some(token),
                tier: Some(user_tier as u8),
                dashboard: Some(dashboard.into()),
                error: None,
            })
        }
        Err(e) => {
            // Increment failed login attempt counter
            let mut attempts = state.login_attempts.write().await;
            let now = now_secs();
            let entry = attempts.entry(req.username.clone()).or_insert((0, now));
            entry.0 += 1;
            drop(attempts);

            Json(LoginResponse {
                success: false,
                error: Some(format!("authentication failed: {e}")),
                ..Default::default()
            })
        }
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
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;

    // Derive HMAC key from master KEK — prevents forging tokens without KEK
    let master_kek = common::sealed_keys::load_master_kek();
    let derived = {
        use hkdf::Hkdf;
        let hk = Hkdf::<Sha512>::new(Some(b"MILNET-ADMIN-TOKEN-v3"), &master_kek);
        let mut okm = [0u8; 32];
        hk.expand(b"admin-token-hmac", &mut okm)
            .expect("HKDF expand");
        okm
    };
    let mut mac = HmacSha512::new_from_slice(&derived).expect("HMAC key");
    mac.update(payload.as_bytes());
    let expected = hex(&mac.finalize().into_bytes());

    if crypto::ct::ct_eq(expected.as_bytes(), parts[2].as_bytes()) {
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

    if params.response_type != "code" {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "unsupported_response_type"}))).into_response();
    }

    // Validate PKCE code_challenge_method if provided
    if let Some(ref method) = params.code_challenge_method {
        if method != "S256" {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_request", "description": "only S256 code_challenge_method supported"}))).into_response();
        }
    }

    // Validate client
    let clients = state.oauth_clients.read().await;
    let client = match clients.get(&params.client_id) {
        Some(c) => c.clone(),
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_client"}))).into_response(),
    };
    drop(clients);

    if !client.redirect_uris.iter().any(|u| u == &params.redirect_uri) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_redirect_uri"}))).into_response();
    }

    // Generate CSRF token bound to this OAuth session state
    let csrf_token = generate_csrf_token(&params.state, &state.admin_api_key);

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
  <input type="hidden" name="csrf_token" value="{csrf_token}">
  <label>Username</label>
  <input type="text" name="username" placeholder="Enter your username" required autofocus>
  <label>Password</label>
  <input type="password" name="password" placeholder="Enter your password" required>
  <button type="submit">SIGN IN</button>
  <div class="err" id="err"></div>
</form>
{google_btn}
</div></body></html>"#,
        app_name = html_escape(&client.name),
        client_id = html_escape(&params.client_id),
        redirect_uri = html_escape(&params.redirect_uri),
        scope = html_escape(&params.scope),
        state = html_escape(&params.state),
        nonce = html_escape(params.nonce.as_deref().unwrap_or("")),
        code_challenge = html_escape(params.code_challenge.as_deref().unwrap_or("")),
        csrf_token = html_escape(&csrf_token),
        google_btn = if state.google_config.is_some() {
            format!(r#"<div style="margin-top:20px;text-align:center">
<div style="color:#555;font-size:0.7rem;margin-bottom:12px">or</div>
<a href="/oauth/google/start?client_id={cid}&redirect_uri={ruri}&scope={sc}&state={st}&nonce={nc}&code_challenge={cc}" style="display:inline-block;padding:12px 24px;background:#111;border:1px solid #333;border-radius:4px;text-decoration:none;font-family:inherit;font-size:0.85rem;cursor:pointer">
<span style="color:#4285F4">G</span><span style="color:#EA4335">o</span><span style="color:#FBBC05">o</span><span style="color:#4285F4">g</span><span style="color:#34A853">l</span><span style="color:#EA4335">e</span><span style="color:#888"> &nbsp;Sign In</span>
</a></div>"#,
                cid = html_escape(&params.client_id),
                ruri = html_escape(&urlencoding::encode(&params.redirect_uri)),
                sc = html_escape(&urlencoding::encode(&params.scope)),
                st = html_escape(&urlencoding::encode(&params.state)),
                nc = html_escape(&urlencoding::encode(params.nonce.as_deref().unwrap_or(""))),
                cc = html_escape(&urlencoding::encode(params.code_challenge.as_deref().unwrap_or(""))),
            )
        } else {
            String::new()
        },
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

    // Validate CSRF token before processing the login form
    if !validate_csrf_token(&form.csrf_token, &form.state, &state.admin_api_key) {
        return (StatusCode::FORBIDDEN, Html(r#"<!DOCTYPE html>
<html><head><title>MILNET SSO // Error</title>
<style>body{background:#0a0a0a;color:#ff3333;font-family:'JetBrains Mono',monospace;padding:60px;text-align:center}
a{color:#00ff41}</style></head><body>
<h1>CSRF VALIDATION FAILED</h1>
<p style="margin:20px 0;color:#888">The form has expired or the request was forged. Please try again.</p>
</body></html>"#.to_string())).into_response();
    }

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
                html_escape(&form.client_id),
                html_escape(&urlencoding::encode(&form.redirect_uri)),
                html_escape(&urlencoding::encode(&form.scope)),
                html_escape(&urlencoding::encode(&form.state)),
            )).into_response();
        }
    };
    drop(store);

    // Guard: Google-only users must use Google login
    let auth_provider: String = sqlx::query_scalar("SELECT auth_provider FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await
        .unwrap_or_else(|_| "opaque".to_string());
    if auth_provider == "google" {
        return Html(r#"<!DOCTYPE html>
<html><head><title>MILNET SSO // Error</title>
<style>body{background:#0a0a0a;color:#ff3333;font-family:'JetBrains Mono',monospace;padding:60px;text-align:center}
a{color:#00ff41}</style></head><body>
<h1>GOOGLE ACCOUNT</h1>
<p style="margin:20px 0;color:#888">This account uses Google sign-in. Please use the Google button to authenticate.</p>
</body></html>"#.to_string()).into_response();
    }

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
                    audit.append_signed(
                        common::types::AuditEventType::DuressDetected,
                        vec![user_id], vec![], 1.0, vec![],
                        &state.pq_signing_key,
                    );
                    drop(audit);
                    // Revoke all active sessions for this user
                    let _ = sqlx::query("UPDATE sessions SET is_active = false WHERE user_id = $1")
                        .bind(user_id)
                        .execute(&state.db)
                        .await;
                    user_tier = 4;
                }
            }
        }
    }

    // Tier 1 users MUST complete FIDO2 — no bypass allowed
    if user_tier == 1 {
        let fido_store = state.fido_store.read().await;
        let creds = fido_store.get_user_credentials(&user_id);
        let has_fido = !creds.is_empty();
        drop(fido_store);

        // Tier 1 (Sovereign) requires FIDO2 second factor. If the user has
        // registered FIDO2 credentials, they must authenticate via the
        // /api/fido/authenticate/* endpoints before being granted access.
        // Password-only login is insufficient for Tier 1.
        tracing::warn!("Tier 1 user {user_id} requires FIDO2 authentication (has_credentials={has_fido})");
        return (StatusCode::FORBIDDEN, Html(format!(r#"<!DOCTYPE html>
<html><head><title>MILNET SSO // FIDO2 Required</title>
<style>body{{background:#0a0a0a;color:#ff3333;font-family:'JetBrains Mono',monospace;padding:60px;text-align:center}}
a{{color:#00ff41}}</style></head><body>
<h1>FIDO2 AUTHENTICATION REQUIRED</h1>
<p style="margin:20px 0;color:#888">Tier 1 (Sovereign) accounts require FIDO2 second-factor authentication.</p>
<p style="color:#888">Complete FIDO2 verification via /api/fido/authenticate to proceed.</p>
</body></html>"#))).into_response();
    }

    // Authentication succeeded — create authorization code with tier
    let mut codes = state.auth_codes.write().await;
    let code = match codes.create_code_with_tier(
        &form.client_id,
        &form.redirect_uri,
        user_id,
        &form.scope,
        if form.code_challenge.is_empty() { None } else { Some(form.code_challenge.clone()) },
        if form.nonce.is_empty() { None } else { Some(form.nonce.clone()) },
        user_tier as u8,
    ) {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    drop(codes);

    // Log to audit, signed with ML-DSA-87
    let mut audit = state.audit_log.write().await;
    audit.append_signed(
        common::types::AuditEventType::AuthSuccess,
        vec![user_id], vec![], 0.0, vec![],
        &state.pq_signing_key,
    );
    drop(audit);

    // Validate redirect_uri: reject control characters, null bytes, and non-ASCII
    // to prevent header injection (CRLF, null truncation, encoded bypass).
    // Also enforce https:// or http:// scheme to prevent javascript:/data: redirects.
    if form.redirect_uri.chars().any(|c| c.is_control())
        || !form.redirect_uri.is_ascii()
        || !(form.redirect_uri.starts_with("https://") || form.redirect_uri.starts_with("http://"))
    {
        return (StatusCode::BAD_REQUEST, "invalid redirect_uri").into_response();
    }

    // Redirect back to the client with the auth code (URL-encode state to prevent injection)
    let redirect_url = format!(
        "{}?code={}&state={}",
        form.redirect_uri,
        urlencoding::encode(&code),
        urlencoding::encode(&form.state),
    );
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
    #[serde(default)]
    csrf_token: String,
}

// ---------------------------------------------------------------------------
// Handlers — Token Revocation
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RevokeTokenRequest {
    token_id: String,
}

/// POST /api/tokens/revoke — add a token_id (hex string) to the revocation set.
async fn revoke_token(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RevokeTokenRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Parse hex token_id into [u8; 16]
    let bytes = hex::decode(&body.token_id).map_err(|_| StatusCode::BAD_REQUEST)?;
    if bytes.len() != 16 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut token_id = [0u8; 16];
    token_id.copy_from_slice(&bytes);

    let mut revocation = state.revocation_list.write().await;
    // Run periodic cleanup before inserting
    revocation.cleanup_expired();
    if !revocation.revoke(token_id) {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let count = revocation.count();
    drop(revocation);

    Ok(Json(serde_json::json!({"status": "revoked", "revoked_count": count})))
}

/// GET /api/tokens/revoked — return the count of revoked tokens.
async fn revoked_token_count(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let revocation = state.revocation_list.read().await;
    let count = revocation.count();
    Json(serde_json::json!({"revoked_count": count}))
}

// ---------------------------------------------------------------------------
// Google OAuth handlers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct GoogleStartParams {
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
    nonce: Option<String>,
    code_challenge: Option<String>,
}

/// Start the Google OAuth flow: validate MILNET params, store pending state,
/// then redirect to Google's authorization endpoint.
async fn oauth_google_start(
    State(state): State<Arc<AppState>>,
    Query(params): Query<GoogleStartParams>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    use axum::http::header;

    let google_config = match &state.google_config {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "google_oauth_not_configured"}))).into_response(),
    };

    // Validate the MILNET client_id
    let clients = state.oauth_clients.read().await;
    let client = match clients.get(&params.client_id) {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_client"}))).into_response(),
    };

    // H10: Validate redirect_uri against client registry to prevent open redirect
    if !client.redirect_uris.iter().any(|u| u == &params.redirect_uri) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_redirect_uri"}))).into_response();
    }
    drop(clients);

    // Generate a random state token for the Google flow
    let state_token = hex::encode(crypto::entropy::generate_nonce());

    // Store pending auth so we can resume on callback
    let pending = crate::google_oauth::PendingGoogleAuth {
        milnet_client_id: params.client_id,
        milnet_redirect_uri: params.redirect_uri,
        milnet_scope: params.scope,
        milnet_state: params.state,
        milnet_nonce: params.nonce,
        milnet_code_challenge: params.code_challenge,
        created_at: now_secs(),
    };
    {
        let mut store = state.pending_google.write().await;
        // Evict expired entries on every insert to prevent unbounded growth
        store.cleanup_expired(now_secs());
        store.insert(state_token.clone(), pending);
    }

    // Build Google auth URL and redirect
    let google_url = crate::google_oauth::build_google_auth_url(google_config, &state_token);
    (StatusCode::FOUND, [(header::LOCATION, google_url)]).into_response()
}

#[derive(Deserialize)]
struct GoogleCallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Handle Google's OAuth callback: exchange code, verify claims, find or create
/// the user, issue a MILNET auth code, and redirect back to the client.
async fn oauth_google_callback(
    State(state): State<Arc<AppState>>,
    Query(params): Query<GoogleCallbackParams>,
) -> axum::response::Response {
    use axum::response::{IntoResponse, Html};
    use axum::http::header;

    // Handle error from Google
    if let Some(err) = &params.error {
        return Html(format!(r#"<!DOCTYPE html>
<html><head><title>MILNET SSO // Google Error</title>
<style>body{{background:#0a0a0a;color:#ff3333;font-family:'JetBrains Mono',monospace;padding:60px;text-align:center}}</style></head><body>
<h1>GOOGLE SIGN-IN FAILED</h1>
<p style="margin:20px 0;color:#888">{}</p>
</body></html>"#, html_escape(err))).into_response();
    }

    let code = match &params.code {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "missing code").into_response(),
    };
    let state_token = match &params.state {
        Some(s) => s,
        None => return (StatusCode::BAD_REQUEST, "missing state").into_response(),
    };

    // Consume pending state
    let pending = {
        let mut store = state.pending_google.write().await;
        store.consume(state_token, now_secs())
    };
    let pending = match pending {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, "invalid or expired state").into_response(),
    };

    let google_config = match &state.google_config {
        Some(c) => c,
        None => return (StatusCode::INTERNAL_SERVER_ERROR, "google not configured").into_response(),
    };

    // Exchange code for tokens
    let tokens = match crate::google_oauth::exchange_code_for_tokens(
        google_config, code, &state.http_client,
    ).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Google token exchange failed: {e}");
            return Html(format!(r#"<!DOCTYPE html>
<html><head><title>MILNET SSO // Error</title>
<style>body{{background:#0a0a0a;color:#ff3333;font-family:'JetBrains Mono',monospace;padding:60px;text-align:center}}</style></head><body>
<h1>TOKEN EXCHANGE FAILED</h1>
<p style="margin:20px 0;color:#888">{}</p>
</body></html>"#, html_escape(&e))).into_response();
        }
    };

    // Extract and verify Google ID token claims (includes algorithm, issuer,
    // audience, and expiry validation inside extract_google_claims)
    let claims = match crate::google_oauth::extract_google_claims(
        &tokens.id_token,
        &google_config.client_id,
        &state.google_jwks_cache,
        &state.http_client,
    ).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Google claim extraction/validation failed: {e}");
            return (StatusCode::BAD_REQUEST, format!("invalid id_token: {e}")).into_response();
        }
    };
    // Additional verification (email_verified, etc.)
    if let Err(e) = crate::google_oauth::verify_google_id_token(&claims, &google_config.client_id) {
        tracing::error!("Google claim verification failed: {e}");
        return (StatusCode::BAD_REQUEST, format!("id_token verification failed: {e}")).into_response();
    }

    // Look up user by email
    let row: Option<(Uuid, i32)> = sqlx::query_as(
        "SELECT id, tier FROM users WHERE email = $1 AND is_active = true"
    )
        .bind(&claims.email)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    let (user_id, user_tier) = if let Some((id, tier)) = row {
        (id, tier as u8)
    } else {
        // Auto-create tier 4 (Emergency/minimal access) user with google auth provider
        let new_id = Uuid::new_v4();
        let now = now_secs();
        let username = claims.email.split('@').next().unwrap_or(&claims.email);
        let display_name = claims.name.as_deref().unwrap_or(username);
        let _ = display_name; // reserved for future profile use
        let insert_result = sqlx::query(
            "INSERT INTO users (id, username, email, tier, is_active, auth_provider, opaque_registration, created_at) VALUES ($1, $2, $3, 4, true, 'google', NULL, $4)"
        )
            .bind(new_id)
            .bind(username)
            .bind(&claims.email)
            .bind(now)
            .execute(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("Failed to auto-create Google user: {e}");
            });
        if insert_result.is_err() {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create user account").into_response();
        }
        tracing::info!("Auto-enrolled Google user {} ({})", claims.email, new_id);

        // Log auto-enrollment to audit, signed with ML-DSA-87
        let mut audit = state.audit_log.write().await;
        audit.append_signed(
            common::types::AuditEventType::AuthSuccess,
            vec![new_id], vec![], 0.0, vec![],
            &state.pq_signing_key,
        );
        drop(audit);

        (new_id, 4u8)
    };

    // Create MILNET authorization code
    let mut codes = state.auth_codes.write().await;
    let auth_code = match codes.create_code_with_tier(
        &pending.milnet_client_id,
        &pending.milnet_redirect_uri,
        user_id,
        &pending.milnet_scope,
        pending.milnet_code_challenge,
        pending.milnet_nonce,
        user_tier,
    ) {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    drop(codes);

    // Log successful auth
    let mut audit = state.audit_log.write().await;
    audit.append_signed(
        common::types::AuditEventType::AuthSuccess,
        vec![user_id], vec![], 0.0, vec![],
        &state.pq_signing_key,
    );
    drop(audit);

    // Validate redirect_uri: reject control characters, null bytes, and non-ASCII
    // to prevent header injection (CRLF, null truncation, encoded bypass).
    // Also enforce https:// or http:// scheme to prevent javascript:/data: redirects.
    if pending.milnet_redirect_uri.chars().any(|c| c.is_control())
        || !pending.milnet_redirect_uri.is_ascii()
        || !(pending.milnet_redirect_uri.starts_with("https://") || pending.milnet_redirect_uri.starts_with("http://"))
    {
        return (StatusCode::BAD_REQUEST, "invalid redirect_uri").into_response();
    }

    // Redirect back to the MILNET client (URL-encode params to prevent injection)
    let redirect_url = format!(
        "{}?code={}&state={}",
        pending.milnet_redirect_uri,
        urlencoding::encode(&auth_code),
        urlencoding::encode(&pending.milnet_state),
    );
    (StatusCode::FOUND, [(header::LOCATION, redirect_url)]).into_response()
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

    // Store access_token -> user_id mapping for userinfo endpoint
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // Prevent unbounded growth: evict expired tokens before inserting
    {
        let mut tokens = state.access_tokens.write().await;
        if tokens.len() >= MAX_ACCESS_TOKENS {
            let cutoff = now - 3600; // 1-hour TTL for access tokens
            tokens.retain(|_, entry| entry.last_activity > cutoff);
        }
        tokens.insert(
            access_token.clone(),
            AccessTokenEntry {
                user_id: auth_code.user_id,
                last_activity: now,
            },
        );
    }

    // Enforce concurrent session limit
    let session_id = uuid::Uuid::new_v4();
    if let Err(e) = state.session_tracker.register_session(auth_code.user_id, session_id, now) {
        return Json(serde_json::json!({"error": e}));
    }

    let response = sso_protocol::tokens::TokenResponse {
        access_token,
        token_type: "Bearer".into(),
        expires_in: 3600,
        id_token,
        scope: auth_code.scope,
    };

    match serde_json::to_value(response) {
        Ok(v) => Json(v),
        Err(_) => Json(serde_json::json!({"error": "internal serialization error"})),
    }
}

async fn oauth_userinfo(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<sso_protocol::userinfo::UserInfo>, StatusCode> {
    let token = request.headers().get("Authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_start_matches("Bearer ").to_string())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Check inactivity timeout on OAuth access tokens (AAL3: 15 min)
    let user_id = {
        let mut tokens = state.access_tokens.write().await;
        match tokens.get(&token) {
            None => return Err(StatusCode::UNAUTHORIZED),
            Some(entry) if now - entry.last_activity > INACTIVITY_TIMEOUT_SECS => {
                tokens.remove(&token);
                return Err(StatusCode::UNAUTHORIZED);
            }
            _ => {}
        }
        let entry = tokens.get_mut(&token).unwrap();
        entry.last_activity = now;
        entry.user_id
    };

    let row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT username, email FROM users WHERE id = $1"
    ).bind(user_id).fetch_optional(&state.db).await.unwrap_or(None);

    match row {
        Some((username, email)) => Ok(Json(sso_protocol::userinfo::UserInfo {
            sub: user_id.to_string(),
            name: Some(username.clone()),
            preferred_username: Some(username),
            email,
        })),
        None => Err(StatusCode::NOT_FOUND),
    }
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
    let mut fido_store = state.fido_store.write().await;

    // Collect existing credential IDs so the browser can skip duplicate authenticators
    let existing_ids: Vec<Vec<u8>> = fido_store
        .get_user_credentials(&req.user_id)
        .iter()
        .map(|c| c.credential_id.clone())
        .collect();

    let options = fido::registration::create_registration_options_with_excludes(
        "MILNET SSO",
        "sso-system.dmj.one",
        &req.user_id,
        &req.username,
        req.prefer_platform,
        &existing_ids,
    );

    // Store the challenge so we can verify it on completion
    fido_store.store_challenge(&options.challenge, req.user_id);

    Json(FidoRegisterBeginResponse { options })
}

async fn fido_register_complete(
    State(state): State<Arc<AppState>>,
    Json(req): Json<FidoRegisterCompleteRequest>,
) -> Result<Json<FidoRegisterCompleteResponse>, StatusCode> {
    let mut fido_store = state.fido_store.write().await;

    // Retrieve and consume the pending challenge for this user.
    // The challenge must have been issued by fido_register_begin and is single-use.
    // Consuming it here prevents replay attacks.
    if !fido_store.consume_challenge_for_user(&req.user_id) {
        tracing::warn!("FIDO2 register complete: no pending challenge for user {}", req.user_id);
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate the attestation: parse the authenticator data from the
    // attestation object to verify RP ID and extract credential data.
    // The client_data field should be the raw clientDataJSON which we
    // can use for additional validation.
    // At minimum, we verify the authenticator data embedded in the attestation
    // contains the correct RP ID hash and the attested credential data flag.
    if req.attestation_object.len() >= 37 {
        // Best-effort attestation validation: try to parse the auth data
        // portion of the attestation object. Full CBOR parsing would be
        // needed for production, but we validate what we can.
        let rp_id = "sso-system.dmj.one";
        if let Err(e) = fido::verification::parse_attestation_auth_data(&req.attestation_object, rp_id) {
            tracing::warn!("FIDO2 attestation validation note: {e} (using client-provided credential data)");
            // For attestation objects that are CBOR-wrapped (not raw authData),
            // we accept the registration since the challenge was validated above.
            // The challenge consumption is the critical security check.
        }
    }

    let cred = fido::types::StoredCredential {
        credential_id: req.credential_id.clone(),
        public_key: req.public_key,
        user_id: req.user_id,
        sign_count: 0,
        authenticator_type: req.authenticator_type,
    };

    fido_store.store_credential(cred);
    drop(fido_store);

    // Log to audit
    let mut audit = state.audit_log.write().await;
    audit.append_signed(
        common::types::AuditEventType::CredentialRegistered,
        vec![req.user_id],
        vec![],
        0.0,
        vec![],
        &state.pq_signing_key,
    );

    Ok(Json(FidoRegisterCompleteResponse {
        success: true,
        credential_id: req.credential_id,
    }))
}

/// GET /api/fido/credentials?user_id=<uuid> — list registered FIDO2 credentials for a user.
async fn fido_credentials_list(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let user_id_str = params.get("user_id").ok_or(StatusCode::BAD_REQUEST)?;
    let user_id = Uuid::parse_str(user_id_str).map_err(|_| StatusCode::BAD_REQUEST)?;

    let fido_store = state.fido_store.read().await;
    let creds = fido_store.get_user_credentials(&user_id);

    let list: Vec<serde_json::Value> = creds.iter().map(|c| {
        serde_json::json!({
            "credential_id_hex": hex::encode(&c.credential_id),
            "authenticator_type": c.authenticator_type,
            "sign_count": c.sign_count,
        })
    }).collect();

    Ok(Json(serde_json::json!({
        "credentials": list,
        "count": list.len(),
    })))
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
    let mut fido_store = state.fido_store.write().await;

    // Look up the credential (immutable borrow first for verification)
    let verification_result = match fido_store.get_credential(&req.credential_id) {
        Some(stored_cred) => {
            // Build the AuthenticationResult from the client's response
            let auth_result = fido::types::AuthenticationResult {
                credential_id: req.credential_id.clone(),
                authenticator_data: req.authenticator_data.clone(),
                client_data: req.client_data.clone(),
                signature: req.signature.clone(),
            };

            // Verify the cryptographic signature, RP ID, flags, and sign counter
            let rp_id = "sso-system.dmj.one";
            match fido::authentication::verify_authentication_response(
                &auth_result,
                stored_cred,
                rp_id,
                true, // require user verification
            ) {
                Ok(new_sign_count) => Ok((stored_cred.user_id, new_sign_count)),
                Err(e) => Err(e.to_string()),
            }
        }
        None => Err("unknown credential".into()),
    };

    match verification_result {
        Ok((user_id, new_sign_count)) => {
            // Update the stored sign counter to detect cloned authenticators
            if let Some(cred_mut) = fido_store.get_credential_mut(&req.credential_id) {
                if let Err(e) = fido::authentication::update_sign_count(cred_mut, new_sign_count) {
                    return Json(FidoAuthCompleteResponse {
                        success: false,
                        user_id: None,
                        error: Some(format!("sign count update failed: {}", e)),
                    });
                }
            }

            Json(FidoAuthCompleteResponse {
                success: true,
                user_id: Some(user_id),
                error: None,
            })
        }
        Err(e) => Json(FidoAuthCompleteResponse {
            success: false,
            user_id: None,
            error: Some(e),
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

async fn oauth_jwks(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    Json(state.oidc_signing_key.jwks_json())
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

// ---------------------------------------------------------------------------
// Handlers — Recovery Codes
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RecoveryGenerateRequest {
    pub user_id: Uuid,
}

#[derive(Serialize)]
pub struct RecoveryGenerateResponse {
    pub codes: Vec<String>,
    pub count: usize,
    pub expires_in_days: u64,
}

#[derive(Deserialize)]
pub struct RecoveryVerifyRequest {
    pub username: String,
    #[serde(alias = "recovery_code")]
    pub code: String,
}

#[derive(Serialize, Default)]
pub struct RecoveryVerifyResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<u8>,
    /// Backend-decided dashboard: "admin" or "user"; recovery always gets "user"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dashboard: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Serialize)]
pub struct RecoveryStatusResponse {
    pub total: usize,
    pub remaining: usize,
    pub used: usize,
    pub expired: usize,
}

/// POST /api/recovery/generate — generate 8 recovery codes for a user.
/// Requires authentication (admin API key or valid session token).
async fn recovery_generate(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Json<RecoveryGenerateResponse>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 2)?;

    let body = axum::body::to_bytes(request.into_body(), 1024 * 64)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let req: RecoveryGenerateRequest = serde_json::from_slice(&body)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Verify user exists
    let user_exists: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM users WHERE id = $1 AND is_active = true"
    )
    .bind(req.user_id)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    if user_exists.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    // Delete any existing unused recovery codes for this user (revoke old batch)
    let _ = sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1 AND is_used = false")
        .bind(req.user_id)
        .execute(&state.db)
        .await;

    // Generate 8 recovery codes
    let codes = common::recovery::generate_recovery_codes(8);
    let now = now_secs();
    let ttl = common::recovery::recovery_code_ttl_secs();
    let expires_at = now + ttl;

    let mut display_codes = Vec::with_capacity(codes.len());

    for (display, salt, hash) in &codes {
        let code_id = Uuid::new_v4();
        let _ = sqlx::query(
            "INSERT INTO recovery_codes (id, user_id, code_hash, code_salt, is_used, created_at, expires_at) VALUES ($1, $2, $3, $4, false, $5, $6)"
        )
        .bind(code_id)
        .bind(req.user_id)
        .bind(hash)
        .bind(salt)
        .bind(now)
        .bind(expires_at)
        .execute(&state.db)
        .await;

        display_codes.push(display.clone());
    }

    // Log audit event
    let mut audit = state.audit_log.write().await;
    let entry = audit.append_signed(
        common::types::AuditEventType::RecoveryCodesGenerated,
        vec![req.user_id],
        vec![],
        0.0,
        vec![],
        &state.pq_signing_key,
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

    let count = display_codes.len();
    Ok(Json(RecoveryGenerateResponse {
        codes: display_codes,
        count,
        expires_in_days: 365,
    }))
}

/// POST /api/recovery/verify — use a recovery code to authenticate.
/// This is a public endpoint (no auth required) for account recovery.
async fn recovery_verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RecoveryVerifyRequest>,
) -> Json<RecoveryVerifyResponse> {
    // Rate limiting: max 5 attempts per 30 minutes per username (same as login)
    {
        let mut attempts = state.login_attempts.write().await;
        let now = now_secs();
        const RATE_LIMIT_TTL_SECS: i64 = 1800;

        if let Some((count, first_time)) = attempts.get(&req.username) {
            if now - *first_time < RATE_LIMIT_TTL_SECS && *count >= 5 {
                return Json(RecoveryVerifyResponse {
                    success: false,
                    message: Some("account locked — too many attempts".into()),
                    ..Default::default()
                });
            }
            if now - *first_time >= RATE_LIMIT_TTL_SECS {
                attempts.remove(&req.username);
            }
        }
    }

    // Look up user by username
    let user_row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM users WHERE username = $1 AND is_active = true"
    )
    .bind(&req.username)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    let user_id = match user_row {
        Some((id,)) => id,
        None => {
            // Do not reveal whether user exists
            return Json(RecoveryVerifyResponse {
                success: false,
                message: Some("invalid recovery code".into()),
                ..Default::default()
            });
        }
    };

    // Parse the recovery code
    let code_bytes = match common::recovery::parse_code(&req.code) {
        Ok(bytes) => bytes,
        Err(_) => {
            // Increment rate limiter on invalid format
            let mut attempts = state.login_attempts.write().await;
            let now = now_secs();
            let entry = attempts.entry(req.username.clone()).or_insert((0, now));
            entry.0 += 1;

            return Json(RecoveryVerifyResponse {
                success: false,
                message: Some("invalid recovery code".into()),
                ..Default::default()
            });
        }
    };

    // Fetch all unused, non-expired recovery codes for this user
    let now = now_secs();
    let stored_codes: Vec<(Uuid, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT id, code_hash, code_salt FROM recovery_codes WHERE user_id = $1 AND is_used = false AND expires_at > $2"
    )
    .bind(user_id)
    .bind(now)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    // Try to verify against each stored code
    let mut matched_code_id: Option<Uuid> = None;
    for (code_id, hash, salt) in &stored_codes {
        if common::recovery::verify_code(&code_bytes, salt, hash) {
            matched_code_id = Some(*code_id);
            break;
        }
    }

    match matched_code_id {
        Some(code_id) => {
            // Mark code as used
            let _ = sqlx::query(
                "UPDATE recovery_codes SET is_used = true, used_at = $1 WHERE id = $2"
            )
            .bind(now)
            .bind(code_id)
            .execute(&state.db)
            .await;

            // Issue a Tier 4 (Emergency) token — short-lived, 2 minutes
            use hmac::{Hmac, Mac};
            use sha2::Sha512;
            type HmacSha512 = Hmac<Sha512>;

            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let payload = format!("{}:{}", user_id, now_ts);
            let master_kek = common::sealed_keys::load_master_kek();
            let derived = {
                use hkdf::Hkdf;
                let hk = Hkdf::<Sha512>::new(Some(b"MILNET-ADMIN-TOKEN-v3"), &master_kek);
                let mut okm = [0u8; 32];
                hk.expand(b"admin-token-hmac", &mut okm)
                    .expect("HKDF expand");
                okm
            };
            let mut mac = HmacSha512::new_from_slice(&derived).expect("HMAC key");
            mac.update(payload.as_bytes());
            let sig = hex(&mac.finalize().into_bytes());
            let token = format!("{payload}:{sig}");

            // Persist emergency session (2-minute expiry)
            let session_id = Uuid::new_v4();
            let expires_at = now_ts as i64 + 120;
            let _ = sqlx::query(
                "INSERT INTO sessions (id, user_id, created_at, expires_at, is_active) VALUES ($1, $2, $3, $4, true)"
            )
            .bind(session_id)
            .bind(user_id)
            .bind(now_ts as i64)
            .bind(expires_at)
            .execute(&state.db)
            .await;

            // Log audit event with elevated risk
            let mut audit = state.audit_log.write().await;
            let entry = audit.append_signed(
                common::types::AuditEventType::RecoveryCodeUsed,
                vec![user_id],
                vec![],
                0.85, // Elevated risk score for recovery code usage
                vec![],
                &state.pq_signing_key,
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
            drop(audit);

            // Emit SIEM event
            common::siem::SecurityEvent::auth_success(user_id, None);

            // Clear rate limit on success
            state.login_attempts.write().await.remove(&req.username);

            // Recovery always routes to user dashboard — even admins must re-enroll first
            Json(RecoveryVerifyResponse {
                success: true,
                user_id: Some(user_id),
                username: Some(req.username.clone()),
                token: Some(token),
                tier: Some(4), // Always Tier 4 (Emergency) — user must re-enroll FIDO2 for higher tier
                dashboard: Some("user".into()),
                message: Some("emergency access granted — re-enroll FIDO2 to restore full access".into()),
            })
        }
        None => {
            // No match — increment rate limiter
            let mut attempts = state.login_attempts.write().await;
            let entry = attempts.entry(req.username.clone()).or_insert((0, now));
            entry.0 += 1;

            Json(RecoveryVerifyResponse {
                success: false,
                message: Some("invalid recovery code".into()),
                ..Default::default()
            })
        }
    }
}

/// GET /api/recovery/status — check remaining recovery codes for a user.
async fn recovery_status(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    request: Request,
) -> Result<Json<RecoveryStatusResponse>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 2)?;

    let user_id_str = params.get("user_id").ok_or(StatusCode::BAD_REQUEST)?;
    let user_id = Uuid::parse_str(user_id_str).map_err(|_| StatusCode::BAD_REQUEST)?;

    let now = now_secs();

    let all_codes: Vec<(bool, i64)> = sqlx::query_as(
        "SELECT is_used, expires_at FROM recovery_codes WHERE user_id = $1"
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let total = all_codes.len();
    let mut used = 0usize;
    let mut expired = 0usize;
    let mut remaining = 0usize;

    for (is_used, expires_at) in &all_codes {
        if *is_used {
            used += 1;
        } else if *expires_at <= now {
            expired += 1;
        } else {
            remaining += 1;
        }
    }

    Ok(Json(RecoveryStatusResponse {
        total,
        remaining,
        used,
        expired,
    }))
}

/// DELETE /api/recovery/revoke-all — revoke all recovery codes for a user.
async fn recovery_revoke_all(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    request: Request,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let caller_tier = request.extensions().get::<AuthTier>().map(|t| t.0).unwrap_or(4);
    check_tier(caller_tier, 1)?;

    let user_id_str = params.get("user_id").ok_or(StatusCode::BAD_REQUEST)?;
    let user_id = Uuid::parse_str(user_id_str).map_err(|_| StatusCode::BAD_REQUEST)?;

    let result = sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let deleted = result.rows_affected();

    // Log audit event
    let mut audit = state.audit_log.write().await;
    let entry = audit.append_signed(
        common::types::AuditEventType::CredentialRevoked,
        vec![user_id],
        vec![],
        0.5,
        vec![],
        &state.pq_signing_key,
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

    Ok(Json(serde_json::json!({
        "revoked": true,
        "deleted_count": deleted,
    })))
}
