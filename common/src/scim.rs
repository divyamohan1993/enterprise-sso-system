//! SCIM 2.0 Server Implementation (RFC 7643/7644) for the MILNET SSO system.
//!
//! Provides a full SCIM 2.0 server for automated identity provisioning and
//! deprovisioning from external HR systems and identity providers.
//!
//! Supported resources: Users, Groups
//! Operations: Create, Read, Update, Delete, List, Search, Bulk, Patch
//! Discovery: /Schemas, /ResourceTypes, /ServiceProviderConfig
//! Filtering: eq, ne, co, sw, ew, gt, lt, ge, le operators
//! Pagination: startIndex + count
//! ETags for conflict detection
//! Bearer token authentication for SCIM clients
//! Rate limiting per SCIM client
//! SIEM logging for all provisioning events
//! Integration with idm.rs ProvisioningRequest workflow
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::siem::{SecurityEvent, Severity};

// ── SCIM Schema Constants ────────────────────────────────────────────

/// SCIM 2.0 User schema URN.
pub const SCHEMA_USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
/// SCIM 2.0 Group schema URN.
pub const SCHEMA_GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
/// SCIM 2.0 List Response schema URN.
pub const SCHEMA_LIST_RESPONSE: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
/// SCIM 2.0 Error schema URN.
pub const SCHEMA_ERROR: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
/// SCIM 2.0 Patch Op schema URN.
pub const SCHEMA_PATCH_OP: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
/// SCIM 2.0 Bulk Request schema URN.
pub const SCHEMA_BULK_REQUEST: &str = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
/// SCIM 2.0 Bulk Response schema URN.
pub const SCHEMA_BULK_RESPONSE: &str = "urn:ietf:params:scim:api:messages:2.0:BulkResponse";

// ── SCIM Resource Meta ───────────────────────────────────────────────

/// SCIM resource metadata (common to all resources).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimMeta {
    /// Resource type (e.g. "User", "Group").
    #[serde(rename = "resourceType")]
    pub resource_type: String,
    /// ISO 8601 timestamp when the resource was created.
    pub created: String,
    #[serde(rename = "lastModified")]
    /// ISO 8601 timestamp when the resource was last modified.
    pub last_modified: String,
    /// Resource location URI.
    pub location: String,
    /// ETag for conflict detection.
    pub version: String,
}

// ── SCIM User Resource ───────────────────────────────────────────────

/// SCIM 2.0 User Name component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimName {
    /// Full formatted name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    /// Family name (last name).
    #[serde(rename = "familyName", skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    /// Given name (first name).
    #[serde(rename = "givenName", skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
}

/// SCIM 2.0 Email entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimEmail {
    /// Email address value.
    pub value: String,
    /// Type (e.g. "work", "home").
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub email_type: Option<String>,
    /// Whether this is the primary email.
    #[serde(default)]
    pub primary: bool,
}

/// SCIM 2.0 Group membership reference (for User.groups).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimGroupRef {
    /// Group resource ID.
    pub value: String,
    /// Display name of the group.
    #[serde(rename = "display", skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    /// URI reference to the Group resource.
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none")]
    pub ref_uri: Option<String>,
}

/// SCIM 2.0 User resource.
#[derive(Clone, Serialize, Deserialize)]
pub struct ScimUser {
    /// Schema URNs.
    pub schemas: Vec<String>,
    /// Unique resource identifier.
    pub id: String,
    /// External identifier (from the provisioning source).
    #[serde(rename = "externalId", skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// Unique username.
    #[serde(rename = "userName")]
    pub user_name: String,
    /// Structured name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<ScimName>,
    /// Display name.
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Email addresses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<ScimEmail>,
    /// Whether the user account is active.
    #[serde(default = "default_true")]
    pub active: bool,
    /// Group memberships (read-only, managed via Group resource).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<ScimGroupRef>,
    /// Department.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    /// Resource metadata.
    pub meta: ScimMeta,
}

impl std::fmt::Debug for ScimUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScimUser")
            .field("id", &self.id)
            .field("user_name", &"[REDACTED]")
            .field("display_name", &"[REDACTED]")
            .field("emails", &format!("[{} entries]", self.emails.len()))
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

impl Drop for ScimUser {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.user_name.zeroize();
        self.display_name.take();
        self.external_id.take();
        for email in &mut self.emails {
            email.value.zeroize();
        }
    }
}

fn default_true() -> bool {
    true
}

// ── SCIM Group Resource ──────────────────────────────────────────────

/// SCIM 2.0 member reference (for Group.members).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimMemberRef {
    /// User resource ID.
    pub value: String,
    /// Display name of the member.
    #[serde(rename = "display", skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    /// URI reference to the User resource.
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none")]
    pub ref_uri: Option<String>,
}

/// SCIM 2.0 Group resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimGroup {
    /// Schema URNs.
    pub schemas: Vec<String>,
    /// Unique resource identifier.
    pub id: String,
    /// External identifier.
    #[serde(rename = "externalId", skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// Display name of the group.
    #[serde(rename = "displayName")]
    pub display_name: String,
    /// Group members.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<ScimMemberRef>,
    /// Resource metadata.
    pub meta: ScimMeta,
}

// ── SCIM List Response ───────────────────────────────────────────────

/// SCIM 2.0 List Response (RFC 7644 Section 3.4.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimListResponse<T: Serialize> {
    /// Schema URNs.
    pub schemas: Vec<String>,
    /// Total number of results matching the query.
    #[serde(rename = "totalResults")]
    pub total_results: usize,
    /// The 1-based index of the first result in the current page.
    #[serde(rename = "startIndex")]
    pub start_index: usize,
    /// Number of results per page.
    #[serde(rename = "itemsPerPage")]
    pub items_per_page: usize,
    /// The resources in this page.
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

// ── SCIM Error Response ──────────────────────────────────────────────

/// SCIM 2.0 Error Response (RFC 7644 Section 3.12).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimError {
    /// Schema URNs.
    pub schemas: Vec<String>,
    /// Human-readable detail.
    pub detail: String,
    /// HTTP status code.
    pub status: u16,
    /// SCIM error type (e.g. "invalidFilter", "tooMany", "uniqueness").
    #[serde(rename = "scimType", skip_serializing_if = "Option::is_none")]
    pub scim_type: Option<String>,
}

impl ScimError {
    /// Create a new SCIM error.
    pub fn new(status: u16, detail: impl Into<String>, scim_type: Option<&str>) -> Self {
        Self {
            schemas: vec![SCHEMA_ERROR.to_string()],
            detail: detail.into(),
            status,
            scim_type: scim_type.map(|s| s.to_string()),
        }
    }

    /// 400 Bad Request.
    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self::new(400, detail, None)
    }

    /// 401 Unauthorized.
    pub fn unauthorized() -> Self {
        Self::new(401, "Authorization required", None)
    }

    /// 404 Not Found.
    pub fn not_found(resource_type: &str, id: &str) -> Self {
        Self::new(404, format!("{} '{}' not found", resource_type, id), None)
    }

    /// 409 Conflict (ETag mismatch).
    pub fn conflict(detail: impl Into<String>) -> Self {
        Self::new(409, detail, Some("uniqueness"))
    }

    /// 429 Too Many Requests.
    pub fn too_many_requests() -> Self {
        Self::new(429, "Rate limit exceeded", Some("tooMany"))
    }
}

// ── SCIM Filter ──────────────────────────────────────────────────────

/// SCIM filter comparison operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScimFilterOp {
    /// Equal.
    Eq,
    /// Not equal.
    Ne,
    /// Contains.
    Co,
    /// Starts with.
    Sw,
    /// Ends with.
    Ew,
    /// Greater than.
    Gt,
    /// Less than.
    Lt,
    /// Greater than or equal.
    Ge,
    /// Less than or equal.
    Le,
    /// Present (attribute exists and has a value).
    Pr,
}

/// A single SCIM filter expression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimFilter {
    /// Attribute path (e.g. "userName", "emails.value").
    pub attribute: String,
    /// Comparison operator.
    pub op: ScimFilterOp,
    /// Comparison value (None for `pr` operator).
    pub value: Option<String>,
}

impl ScimFilter {
    /// Parse a simple SCIM filter string (e.g. `userName eq "john"`).
    ///
    /// Supports single-expression filters only. Complex filters with `and`/`or`
    /// are not yet implemented.
    pub fn parse(filter_str: &str) -> Result<Self, ScimError> {
        let parts: Vec<&str> = filter_str.splitn(3, ' ').collect();
        if parts.len() < 2 {
            return Err(ScimError::bad_request(format!(
                "invalid filter: '{}'",
                filter_str
            )));
        }

        let attribute = parts[0].to_string();
        let op = match parts[1].to_lowercase().as_str() {
            "eq" => ScimFilterOp::Eq,
            "ne" => ScimFilterOp::Ne,
            "co" => ScimFilterOp::Co,
            "sw" => ScimFilterOp::Sw,
            "ew" => ScimFilterOp::Ew,
            "gt" => ScimFilterOp::Gt,
            "lt" => ScimFilterOp::Lt,
            "ge" => ScimFilterOp::Ge,
            "le" => ScimFilterOp::Le,
            "pr" => ScimFilterOp::Pr,
            other => {
                return Err(ScimError::new(
                    400,
                    format!("unsupported filter operator: '{}'", other),
                    Some("invalidFilter"),
                ));
            }
        };

        if op == ScimFilterOp::Pr {
            return Ok(Self {
                attribute,
                op,
                value: None,
            });
        }

        if parts.len() < 3 {
            return Err(ScimError::bad_request(format!(
                "filter operator '{}' requires a value",
                parts[1]
            )));
        }

        // Strip surrounding quotes from the value
        let raw_value = parts[2];
        let value = raw_value
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or(raw_value);

        Ok(Self {
            attribute,
            op,
            value: Some(value.to_string()),
        })
    }

    /// Evaluate this filter against a SCIM user.
    pub fn matches_user(&self, user: &ScimUser) -> bool {
        let attr_value = match self.attribute.as_str() {
            "userName" => Some(user.user_name.clone()),
            "displayName" => user.display_name.clone(),
            "active" => Some(user.active.to_string()),
            "id" => Some(user.id.clone()),
            "externalId" => user.external_id.clone(),
            "emails.value" => user.emails.first().map(|e| e.value.clone()),
            "name.familyName" => user.name.as_ref().and_then(|n| n.family_name.clone()),
            "name.givenName" => user.name.as_ref().and_then(|n| n.given_name.clone()),
            "department" => user.department.clone(),
            _ => None,
        };

        match (&self.op, &attr_value, &self.value) {
            (ScimFilterOp::Pr, Some(_), _) => true,
            (ScimFilterOp::Pr, None, _) => false,
            (_, None, _) => false,
            (_, _, None) => false,
            (ScimFilterOp::Eq, Some(a), Some(v)) => a == v,
            (ScimFilterOp::Ne, Some(a), Some(v)) => a != v,
            (ScimFilterOp::Co, Some(a), Some(v)) => a.contains(v.as_str()),
            (ScimFilterOp::Sw, Some(a), Some(v)) => a.starts_with(v.as_str()),
            (ScimFilterOp::Ew, Some(a), Some(v)) => a.ends_with(v.as_str()),
            (ScimFilterOp::Gt, Some(a), Some(v)) => a.as_str() > v.as_str(),
            (ScimFilterOp::Lt, Some(a), Some(v)) => a.as_str() < v.as_str(),
            (ScimFilterOp::Ge, Some(a), Some(v)) => a.as_str() >= v.as_str(),
            (ScimFilterOp::Le, Some(a), Some(v)) => a.as_str() <= v.as_str(),
        }
    }

    /// Evaluate this filter against a SCIM group.
    pub fn matches_group(&self, group: &ScimGroup) -> bool {
        let attr_value = match self.attribute.as_str() {
            "displayName" => Some(group.display_name.clone()),
            "id" => Some(group.id.clone()),
            "externalId" => group.external_id.clone(),
            _ => None,
        };

        match (&self.op, &attr_value, &self.value) {
            (ScimFilterOp::Pr, Some(_), _) => true,
            (ScimFilterOp::Pr, None, _) => false,
            (_, None, _) => false,
            (_, _, None) => false,
            (ScimFilterOp::Eq, Some(a), Some(v)) => a == v,
            (ScimFilterOp::Ne, Some(a), Some(v)) => a != v,
            (ScimFilterOp::Co, Some(a), Some(v)) => a.contains(v.as_str()),
            (ScimFilterOp::Sw, Some(a), Some(v)) => a.starts_with(v.as_str()),
            (ScimFilterOp::Ew, Some(a), Some(v)) => a.ends_with(v.as_str()),
            (ScimFilterOp::Gt, Some(a), Some(v)) => a.as_str() > v.as_str(),
            (ScimFilterOp::Lt, Some(a), Some(v)) => a.as_str() < v.as_str(),
            (ScimFilterOp::Ge, Some(a), Some(v)) => a.as_str() >= v.as_str(),
            (ScimFilterOp::Le, Some(a), Some(v)) => a.as_str() <= v.as_str(),
        }
    }
}

// ── SCIM Patch Operations ────────────────────────────────────────────

/// SCIM Patch operation type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PatchOpType {
    /// Add a value to an attribute.
    Add,
    /// Replace the value of an attribute.
    Replace,
    /// Remove an attribute or value.
    Remove,
}

/// A single SCIM Patch operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchOperation {
    /// Operation type.
    pub op: PatchOpType,
    /// Attribute path (e.g. "displayName", "members").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Value to set (for add/replace). JSON value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

/// SCIM Patch request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimPatchRequest {
    /// Schema URNs (must include PatchOp schema).
    pub schemas: Vec<String>,
    /// List of patch operations.
    #[serde(rename = "Operations")]
    pub operations: Vec<PatchOperation>,
}

// ── SCIM Bulk Operations ─────────────────────────────────────────────

/// HTTP method for bulk operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum BulkMethod {
    Post,
    Put,
    Patch,
    Delete,
}

/// A single operation within a SCIM Bulk request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkOperation {
    /// HTTP method.
    pub method: BulkMethod,
    /// Resource path (e.g. "/Users", "/Groups/abc-123").
    pub path: String,
    /// Bulk operation ID (for cross-referencing).
    #[serde(rename = "bulkId", skip_serializing_if = "Option::is_none")]
    pub bulk_id: Option<String>,
    /// Request body (JSON).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// SCIM Bulk request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimBulkRequest {
    /// Schema URNs.
    pub schemas: Vec<String>,
    /// List of operations.
    #[serde(rename = "Operations")]
    pub operations: Vec<BulkOperation>,
}

/// Result of a single bulk operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkOperationResult {
    /// HTTP method.
    pub method: BulkMethod,
    /// Resource path.
    pub path: String,
    /// Bulk operation ID.
    #[serde(rename = "bulkId", skip_serializing_if = "Option::is_none")]
    pub bulk_id: Option<String>,
    /// HTTP status code.
    pub status: u16,
    /// Resource location (for POST).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

/// SCIM Bulk response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimBulkResponse {
    /// Schema URNs.
    pub schemas: Vec<String>,
    /// Results of each operation.
    #[serde(rename = "Operations")]
    pub operations: Vec<BulkOperationResult>,
}

// ── SCIM Discovery Types ─────────────────────────────────────────────

/// SCIM Service Provider Configuration (RFC 7643 Section 5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceProviderConfig {
    /// Schema URNs.
    pub schemas: Vec<String>,
    /// Patch support.
    pub patch: FeatureSupport,
    /// Bulk support.
    pub bulk: BulkSupport,
    /// Filter support.
    pub filter: FilterSupport,
    /// Change password support.
    #[serde(rename = "changePassword")]
    pub change_password: FeatureSupport,
    /// Sort support.
    pub sort: FeatureSupport,
    /// ETag support.
    pub etag: FeatureSupport,
    /// Authentication schemes.
    #[serde(rename = "authenticationSchemes")]
    pub authentication_schemes: Vec<AuthenticationScheme>,
}

/// Feature support toggle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureSupport {
    pub supported: bool,
}

/// Bulk operation support configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkSupport {
    pub supported: bool,
    #[serde(rename = "maxOperations")]
    pub max_operations: usize,
    #[serde(rename = "maxPayloadSize")]
    pub max_payload_size: usize,
}

/// Filter support configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterSupport {
    pub supported: bool,
    #[serde(rename = "maxResults")]
    pub max_results: usize,
}

/// Authentication scheme descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationScheme {
    /// Scheme name.
    pub name: String,
    /// Scheme description.
    pub description: String,
    /// Scheme type (e.g. "oauthbearertoken").
    #[serde(rename = "type")]
    pub scheme_type: String,
    /// Whether this is the primary scheme.
    pub primary: bool,
}

// ── SCIM Client Token & Rate Limiting ────────────────────────────────

/// A registered SCIM client with bearer token and rate limit state.
#[derive(Debug, Clone)]
pub struct ScimClient {
    /// Client identifier.
    pub client_id: String,
    /// Bearer token (hashed for storage in production; plaintext here for simplicity).
    pub token_hash: String,
    /// Human-readable client description (e.g. "Workday HR Integration").
    pub description: String,
    /// Maximum requests per minute.
    pub rate_limit_rpm: u32,
    /// Current request count in the current window.
    pub current_window_count: u32,
    /// Unix timestamp (seconds) when the current rate limit window started.
    pub window_start: i64,
}

// ── SCIM Server ──────────────────────────────────────────────────────

/// The SCIM 2.0 server implementation.
///
/// Manages Users and Groups with full CRUD, filtering, pagination,
/// ETags, and rate limiting. Integrates with the IDM subsystem for
/// provisioning workflows.
pub struct ScimServer {
    /// Users indexed by SCIM resource ID.
    users: HashMap<String, ScimUser>,
    /// Groups indexed by SCIM resource ID.
    groups: HashMap<String, ScimGroup>,
    /// Registered SCIM clients for authentication and rate limiting.
    clients: HashMap<String, ScimClient>,
    /// Base URL for resource location URIs.
    base_url: String,
    /// ETag counter for version generation.
    etag_counter: u64,
    /// Maximum bulk operations per request.
    max_bulk_operations: usize,
    /// Maximum filter results.
    max_filter_results: usize,
    /// Current unix timestamp provider.
    now_fn: fn() -> i64,
}

/// Returns the current Unix timestamp in seconds.
fn system_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn now_iso8601() -> String {
    SecurityEvent::now_iso8601()
}

impl ScimServer {
    /// Create a new SCIM server with the given base URL.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            users: HashMap::new(),
            groups: HashMap::new(),
            clients: HashMap::new(),
            base_url: base_url.into(),
            etag_counter: 0,
            max_bulk_operations: 1000,
            max_filter_results: 200,
            now_fn: system_now,
        }
    }

    /// Create a SCIM server with a custom clock (for testing).
    #[cfg(test)]
    fn with_clock(base_url: impl Into<String>, now_fn: fn() -> i64) -> Self {
        Self {
            users: HashMap::new(),
            groups: HashMap::new(),
            clients: HashMap::new(),
            base_url: base_url.into(),
            etag_counter: 0,
            max_bulk_operations: 1000,
            max_filter_results: 200,
            now_fn,
        }
    }

    fn now(&self) -> i64 {
        (self.now_fn)()
    }

    fn next_etag(&mut self) -> String {
        self.etag_counter += 1;
        format!("W/\"{}\"", self.etag_counter)
    }

    // ── Client Management ────────────────────────────────────────────

    /// Register a SCIM client with a bearer token.
    pub fn register_client(&mut self, client: ScimClient) {
        emit_scim_siem_event(
            "scim_client_registered",
            Severity::Info,
            "success",
            None,
            Some(format!("client_id={}", client.client_id)),
        );
        self.clients.insert(client.client_id.clone(), client);
    }

    /// Authenticate a SCIM client by bearer token.
    ///
    /// Returns the client_id if authenticated, or a SCIM error.
    pub fn authenticate(&mut self, bearer_token: &str) -> Result<String, ScimError> {
        let now = self.now();

        for client in self.clients.values_mut() {
            if {
                use subtle::ConstantTimeEq;
                let a = client.token_hash.as_bytes();
                let b = bearer_token.as_bytes();
                // Constant-time comparison including length check
                let len_eq: subtle::Choice = (a.len() as u64).ct_eq(&(b.len() as u64));
                let min_len = std::cmp::min(a.len(), b.len());
                let content_eq: subtle::Choice = a[..min_len].ct_eq(&b[..min_len]);
                bool::from(len_eq & content_eq)
            } {
                // Rate limit check
                if now - client.window_start >= 60 {
                    // Reset window
                    client.window_start = now;
                    client.current_window_count = 0;
                }
                client.current_window_count += 1;
                if client.current_window_count > client.rate_limit_rpm {
                    emit_scim_siem_event(
                        "scim_rate_limit_exceeded",
                        Severity::Warning,
                        "failure",
                        None,
                        Some(format!("client_id={}", client.client_id)),
                    );
                    return Err(ScimError::too_many_requests());
                }
                return Ok(client.client_id.clone());
            }
        }

        emit_scim_siem_event(
            "scim_auth_failure",
            Severity::Medium,
            "failure",
            None,
            Some("invalid bearer token".to_string()),
        );
        Err(ScimError::unauthorized())
    }

    // ── User CRUD ────────────────────────────────────────────────────

    /// Create a SCIM User.
    pub fn create_user(&mut self, mut user: ScimUser) -> Result<ScimUser, ScimError> {
        // Ensure schemas
        if !user.schemas.contains(&SCHEMA_USER.to_string()) {
            user.schemas = vec![SCHEMA_USER.to_string()];
        }

        // Check uniqueness of userName
        if self
            .users
            .values()
            .any(|u| u.user_name == user.user_name)
        {
            return Err(ScimError::conflict(format!(
                "userName '{}' already exists",
                user.user_name
            )));
        }

        // Generate ID if empty
        if user.id.is_empty() {
            user.id = Uuid::new_v4().to_string();
        }

        // Set metadata
        let now = now_iso8601();
        let etag = self.next_etag();
        user.meta = ScimMeta {
            resource_type: "User".to_string(),
            created: now.clone(),
            last_modified: now,
            location: format!("{}/Users/{}", self.base_url, user.id),
            version: etag,
        };

        emit_scim_siem_event(
            "scim_user_created",
            Severity::Info,
            "success",
            None,
            Some(format!(
                "user_id={} userName={}",
                user.id, user.user_name
            )),
        );

        self.users.insert(user.id.clone(), user.clone());
        Ok(user)
    }

    /// Get a SCIM User by ID.
    pub fn get_user(&self, id: &str) -> Result<&ScimUser, ScimError> {
        self.users
            .get(id)
            .ok_or_else(|| ScimError::not_found("User", id))
    }

    /// Update (replace) a SCIM User.
    pub fn update_user(
        &mut self,
        id: &str,
        mut user: ScimUser,
        if_match: Option<&str>,
    ) -> Result<ScimUser, ScimError> {
        let existing = self
            .users
            .get(id)
            .ok_or_else(|| ScimError::not_found("User", id))?;

        // ETag check
        if let Some(expected_etag) = if_match {
            if existing.meta.version != expected_etag {
                return Err(ScimError::new(
                    412,
                    "ETag mismatch — resource was modified",
                    None,
                ));
            }
        }

        let created_at = existing.meta.created.clone();

        user.id = id.to_string();
        user.schemas = vec![SCHEMA_USER.to_string()];

        let etag = self.next_etag();
        user.meta = ScimMeta {
            resource_type: "User".to_string(),
            created: created_at,
            last_modified: now_iso8601(),
            location: format!("{}/Users/{}", self.base_url, id),
            version: etag,
        };

        emit_scim_siem_event(
            "scim_user_updated",
            Severity::Info,
            "success",
            None,
            Some(format!("user_id={}", id)),
        );

        self.users.insert(id.to_string(), user.clone());
        Ok(user)
    }

    /// Delete a SCIM User by ID.
    pub fn delete_user(&mut self, id: &str) -> Result<(), ScimError> {
        if self.users.remove(id).is_none() {
            return Err(ScimError::not_found("User", id));
        }

        // Remove user from all groups
        for group in self.groups.values_mut() {
            group.members.retain(|m| m.value != id);
        }

        emit_scim_siem_event(
            "scim_user_deleted",
            Severity::Medium,
            "success",
            None,
            Some(format!("user_id={}", id)),
        );

        Ok(())
    }

    /// Patch a SCIM User.
    pub fn patch_user(
        &mut self,
        id: &str,
        patch: &ScimPatchRequest,
    ) -> Result<ScimUser, ScimError> {
        let user = self
            .users
            .get(id)
            .ok_or_else(|| ScimError::not_found("User", id))?
            .clone();

        let mut user = user;

        for op in &patch.operations {
            match op.op {
                PatchOpType::Replace => {
                    if let (Some(path), Some(value)) = (&op.path, &op.value) {
                        match path.as_str() {
                            "userName" => {
                                if let Some(v) = value.as_str() {
                                    user.user_name = v.to_string();
                                }
                            }
                            "displayName" => {
                                if let Some(v) = value.as_str() {
                                    user.display_name = Some(v.to_string());
                                }
                            }
                            "active" => {
                                if let Some(v) = value.as_bool() {
                                    user.active = v;
                                }
                            }
                            "department" => {
                                if let Some(v) = value.as_str() {
                                    user.department = Some(v.to_string());
                                }
                            }
                            _ => {}
                        }
                    }
                }
                PatchOpType::Add => {
                    // Add operations append to multi-valued attributes
                    if let (Some(path), Some(value)) = (&op.path, &op.value) {
                        if path == "emails" {
                            if let Ok(email) =
                                serde_json::from_value::<ScimEmail>(value.clone())
                            {
                                user.emails.push(email);
                            }
                        }
                    }
                }
                PatchOpType::Remove => {
                    if let Some(path) = &op.path {
                        match path.as_str() {
                            "displayName" => user.display_name = None,
                            "department" => user.department = None,
                            _ => {}
                        }
                    }
                }
            }
        }

        let etag = self.next_etag();
        user.meta.last_modified = now_iso8601();
        user.meta.version = etag;

        emit_scim_siem_event(
            "scim_user_patched",
            Severity::Info,
            "success",
            None,
            Some(format!("user_id={}", id)),
        );

        self.users.insert(id.to_string(), user.clone());
        Ok(user)
    }

    /// List/search SCIM Users with optional filter and pagination.
    pub fn list_users(
        &self,
        filter: Option<&ScimFilter>,
        start_index: usize,
        count: usize,
    ) -> ScimListResponse<ScimUser> {
        let start = if start_index == 0 { 1 } else { start_index };
        let page_size = count.min(self.max_filter_results);

        let mut matched: Vec<&ScimUser> = if let Some(f) = filter {
            self.users.values().filter(|u| f.matches_user(u)).collect()
        } else {
            self.users.values().collect()
        };

        // Sort by ID for deterministic pagination
        matched.sort_by(|a, b| a.id.cmp(&b.id));

        let total = matched.len();
        let skip = (start - 1).min(total);
        let page: Vec<ScimUser> = matched
            .into_iter()
            .skip(skip)
            .take(page_size)
            .cloned()
            .collect();

        ScimListResponse {
            schemas: vec![SCHEMA_LIST_RESPONSE.to_string()],
            total_results: total,
            start_index: start,
            items_per_page: page.len(),
            resources: page,
        }
    }

    // ── Group CRUD ───────────────────────────────────────────────────

    /// Create a SCIM Group.
    pub fn create_group(&mut self, mut group: ScimGroup) -> Result<ScimGroup, ScimError> {
        if !group.schemas.contains(&SCHEMA_GROUP.to_string()) {
            group.schemas = vec![SCHEMA_GROUP.to_string()];
        }

        if group.id.is_empty() {
            group.id = Uuid::new_v4().to_string();
        }

        let now = now_iso8601();
        let etag = self.next_etag();
        group.meta = ScimMeta {
            resource_type: "Group".to_string(),
            created: now.clone(),
            last_modified: now,
            location: format!("{}/Groups/{}", self.base_url, group.id),
            version: etag,
        };

        emit_scim_siem_event(
            "scim_group_created",
            Severity::Info,
            "success",
            None,
            Some(format!(
                "group_id={} displayName={}",
                group.id, group.display_name
            )),
        );

        self.groups.insert(group.id.clone(), group.clone());
        Ok(group)
    }

    /// Get a SCIM Group by ID.
    pub fn get_group(&self, id: &str) -> Result<&ScimGroup, ScimError> {
        self.groups
            .get(id)
            .ok_or_else(|| ScimError::not_found("Group", id))
    }

    /// Update (replace) a SCIM Group.
    pub fn update_group(
        &mut self,
        id: &str,
        mut group: ScimGroup,
        if_match: Option<&str>,
    ) -> Result<ScimGroup, ScimError> {
        let existing = self
            .groups
            .get(id)
            .ok_or_else(|| ScimError::not_found("Group", id))?;

        if let Some(expected_etag) = if_match {
            if existing.meta.version != expected_etag {
                return Err(ScimError::new(
                    412,
                    "ETag mismatch — resource was modified",
                    None,
                ));
            }
        }

        let created_at = existing.meta.created.clone();

        group.id = id.to_string();
        group.schemas = vec![SCHEMA_GROUP.to_string()];

        let etag = self.next_etag();
        group.meta = ScimMeta {
            resource_type: "Group".to_string(),
            created: created_at,
            last_modified: now_iso8601(),
            location: format!("{}/Groups/{}", self.base_url, id),
            version: etag,
        };

        emit_scim_siem_event(
            "scim_group_updated",
            Severity::Info,
            "success",
            None,
            Some(format!("group_id={}", id)),
        );

        self.groups.insert(id.to_string(), group.clone());
        Ok(group)
    }

    /// Delete a SCIM Group by ID.
    pub fn delete_group(&mut self, id: &str) -> Result<(), ScimError> {
        if self.groups.remove(id).is_none() {
            return Err(ScimError::not_found("Group", id));
        }

        emit_scim_siem_event(
            "scim_group_deleted",
            Severity::Medium,
            "success",
            None,
            Some(format!("group_id={}", id)),
        );

        Ok(())
    }

    /// Patch a SCIM Group (primarily for adding/removing members).
    pub fn patch_group(
        &mut self,
        id: &str,
        patch: &ScimPatchRequest,
    ) -> Result<ScimGroup, ScimError> {
        let group = self
            .groups
            .get(id)
            .ok_or_else(|| ScimError::not_found("Group", id))?
            .clone();

        let mut group = group;

        for op in &patch.operations {
            match op.op {
                PatchOpType::Replace => {
                    if let (Some(path), Some(value)) = (&op.path, &op.value) {
                        if path == "displayName" {
                            if let Some(v) = value.as_str() {
                                group.display_name = v.to_string();
                            }
                        }
                    }
                }
                PatchOpType::Add => {
                    if let Some(value) = &op.value {
                        // Add members
                        if let Ok(member) =
                            serde_json::from_value::<ScimMemberRef>(value.clone())
                        {
                            if !group.members.iter().any(|m| m.value == member.value) {
                                group.members.push(member);
                            }
                        }
                    }
                }
                PatchOpType::Remove => {
                    if let Some(path) = &op.path {
                        // Remove member by filter: members[value eq "user-id"]
                        if path.starts_with("members[value eq ") {
                            let member_id = path
                                .strip_prefix("members[value eq \"")
                                .and_then(|s| s.strip_suffix("\"]"))
                                .unwrap_or("");
                            group.members.retain(|m| m.value != member_id);
                        }
                    }
                }
            }
        }

        let etag = self.next_etag();
        group.meta.last_modified = now_iso8601();
        group.meta.version = etag;

        emit_scim_siem_event(
            "scim_group_patched",
            Severity::Info,
            "success",
            None,
            Some(format!("group_id={}", id)),
        );

        self.groups.insert(id.to_string(), group.clone());
        Ok(group)
    }

    /// List/search SCIM Groups with optional filter and pagination.
    pub fn list_groups(
        &self,
        filter: Option<&ScimFilter>,
        start_index: usize,
        count: usize,
    ) -> ScimListResponse<ScimGroup> {
        let start = if start_index == 0 { 1 } else { start_index };
        let page_size = count.min(self.max_filter_results);

        let mut matched: Vec<&ScimGroup> = if let Some(f) = filter {
            self.groups
                .values()
                .filter(|g| f.matches_group(g))
                .collect()
        } else {
            self.groups.values().collect()
        };

        matched.sort_by(|a, b| a.id.cmp(&b.id));

        let total = matched.len();
        let skip = (start - 1).min(total);
        let page: Vec<ScimGroup> = matched
            .into_iter()
            .skip(skip)
            .take(page_size)
            .cloned()
            .collect();

        ScimListResponse {
            schemas: vec![SCHEMA_LIST_RESPONSE.to_string()],
            total_results: total,
            start_index: start,
            items_per_page: page.len(),
            resources: page,
        }
    }

    // ── Bulk Operations ──────────────────────────────────────────────

    /// Execute a SCIM Bulk request.
    pub fn execute_bulk(
        &mut self,
        bulk_req: &ScimBulkRequest,
    ) -> Result<ScimBulkResponse, ScimError> {
        if bulk_req.operations.len() > self.max_bulk_operations {
            return Err(ScimError::new(
                413,
                format!(
                    "too many operations: {} (max {})",
                    bulk_req.operations.len(),
                    self.max_bulk_operations
                ),
                Some("tooMany"),
            ));
        }

        let mut results = Vec::new();

        for op in &bulk_req.operations {
            let result = match (&op.method, op.path.as_str()) {
                (BulkMethod::Post, "/Users") => {
                    if let Some(data) = &op.data {
                        match serde_json::from_value::<ScimUser>(data.clone()) {
                            Ok(user) => match self.create_user(user) {
                                Ok(created) => BulkOperationResult {
                                    method: BulkMethod::Post,
                                    path: op.path.clone(),
                                    bulk_id: op.bulk_id.clone(),
                                    status: 201,
                                    location: Some(created.meta.location),
                                },
                                Err(e) => BulkOperationResult {
                                    method: BulkMethod::Post,
                                    path: op.path.clone(),
                                    bulk_id: op.bulk_id.clone(),
                                    status: e.status,
                                    location: None,
                                },
                            },
                            Err(_) => BulkOperationResult {
                                method: BulkMethod::Post,
                                path: op.path.clone(),
                                bulk_id: op.bulk_id.clone(),
                                status: 400,
                                location: None,
                            },
                        }
                    } else {
                        BulkOperationResult {
                            method: BulkMethod::Post,
                            path: op.path.clone(),
                            bulk_id: op.bulk_id.clone(),
                            status: 400,
                            location: None,
                        }
                    }
                }
                (BulkMethod::Delete, path) if path.starts_with("/Users/") => {
                    let id = &path[7..];
                    match self.delete_user(id) {
                        Ok(()) => BulkOperationResult {
                            method: BulkMethod::Delete,
                            path: op.path.clone(),
                            bulk_id: op.bulk_id.clone(),
                            status: 204,
                            location: None,
                        },
                        Err(e) => BulkOperationResult {
                            method: BulkMethod::Delete,
                            path: op.path.clone(),
                            bulk_id: op.bulk_id.clone(),
                            status: e.status,
                            location: None,
                        },
                    }
                }
                (BulkMethod::Post, "/Groups") => {
                    if let Some(data) = &op.data {
                        match serde_json::from_value::<ScimGroup>(data.clone()) {
                            Ok(group) => match self.create_group(group) {
                                Ok(created) => BulkOperationResult {
                                    method: BulkMethod::Post,
                                    path: op.path.clone(),
                                    bulk_id: op.bulk_id.clone(),
                                    status: 201,
                                    location: Some(created.meta.location),
                                },
                                Err(e) => BulkOperationResult {
                                    method: BulkMethod::Post,
                                    path: op.path.clone(),
                                    bulk_id: op.bulk_id.clone(),
                                    status: e.status,
                                    location: None,
                                },
                            },
                            Err(_) => BulkOperationResult {
                                method: BulkMethod::Post,
                                path: op.path.clone(),
                                bulk_id: op.bulk_id.clone(),
                                status: 400,
                                location: None,
                            },
                        }
                    } else {
                        BulkOperationResult {
                            method: BulkMethod::Post,
                            path: op.path.clone(),
                            bulk_id: op.bulk_id.clone(),
                            status: 400,
                            location: None,
                        }
                    }
                }
                _ => BulkOperationResult {
                    method: op.method.clone(),
                    path: op.path.clone(),
                    bulk_id: op.bulk_id.clone(),
                    status: 400,
                    location: None,
                },
            };
            results.push(result);
        }

        emit_scim_siem_event(
            "scim_bulk_executed",
            Severity::Info,
            "success",
            None,
            Some(format!("operations={}", results.len())),
        );

        Ok(ScimBulkResponse {
            schemas: vec![SCHEMA_BULK_RESPONSE.to_string()],
            operations: results,
        })
    }

    // ── Discovery Endpoints ──────────────────────────────────────────

    /// Return the SCIM Service Provider Configuration.
    pub fn service_provider_config(&self) -> ServiceProviderConfig {
        ServiceProviderConfig {
            schemas: vec![
                "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig".to_string(),
            ],
            patch: FeatureSupport { supported: true },
            bulk: BulkSupport {
                supported: true,
                max_operations: self.max_bulk_operations,
                max_payload_size: 1_048_576, // 1 MB
            },
            filter: FilterSupport {
                supported: true,
                max_results: self.max_filter_results,
            },
            change_password: FeatureSupport { supported: false },
            sort: FeatureSupport { supported: false },
            etag: FeatureSupport { supported: true },
            authentication_schemes: vec![AuthenticationScheme {
                name: "OAuth Bearer Token".to_string(),
                description: "Authentication scheme using the OAuth Bearer Token Standard"
                    .to_string(),
                scheme_type: "oauthbearertoken".to_string(),
                primary: true,
            }],
        }
    }

    /// Return the SCIM Resource Types.
    pub fn resource_types(&self) -> Vec<serde_json::Value> {
        vec![
            serde_json::json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "User",
                "name": "User",
                "endpoint": "/Users",
                "description": "User Account",
                "schema": SCHEMA_USER,
                "meta": {
                    "resourceType": "ResourceType",
                    "location": format!("{}/ResourceTypes/User", self.base_url)
                }
            }),
            serde_json::json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "Group",
                "name": "Group",
                "endpoint": "/Groups",
                "description": "Group",
                "schema": SCHEMA_GROUP,
                "meta": {
                    "resourceType": "ResourceType",
                    "location": format!("{}/ResourceTypes/Group", self.base_url)
                }
            }),
        ]
    }

    /// Return the SCIM Schemas.
    pub fn schemas(&self) -> Vec<serde_json::Value> {
        vec![
            serde_json::json!({
                "id": SCHEMA_USER,
                "name": "User",
                "description": "User Account",
                "attributes": [
                    {"name": "userName", "type": "string", "multiValued": false, "required": true, "uniqueness": "server"},
                    {"name": "name", "type": "complex", "multiValued": false, "required": false},
                    {"name": "displayName", "type": "string", "multiValued": false, "required": false},
                    {"name": "emails", "type": "complex", "multiValued": true, "required": false},
                    {"name": "active", "type": "boolean", "multiValued": false, "required": false},
                    {"name": "groups", "type": "complex", "multiValued": true, "required": false, "mutability": "readOnly"},
                    {"name": "department", "type": "string", "multiValued": false, "required": false}
                ],
                "meta": {
                    "resourceType": "Schema",
                    "location": format!("{}/Schemas/{}", self.base_url, SCHEMA_USER)
                }
            }),
            serde_json::json!({
                "id": SCHEMA_GROUP,
                "name": "Group",
                "description": "Group",
                "attributes": [
                    {"name": "displayName", "type": "string", "multiValued": false, "required": true},
                    {"name": "members", "type": "complex", "multiValued": true, "required": false}
                ],
                "meta": {
                    "resourceType": "Schema",
                    "location": format!("{}/Schemas/{}", self.base_url, SCHEMA_GROUP)
                }
            }),
        ]
    }

    // ── IDM Integration ──────────────────────────────────────────────

    /// Map a SCIM User to an IDM UserAttributes structure.
    ///
    /// This creates the internal representation used by the IDM subsystem
    /// for provisioning workflows.
    pub fn map_to_idm_user(
        &self,
        scim_user: &ScimUser,
    ) -> crate::idm::UserAttributes {
        let now = self.now();
        let user_id = Uuid::parse_str(&scim_user.id).unwrap_or_else(|_| Uuid::new_v4());

        let email = scim_user
            .emails
            .first()
            .map(|e| e.value.clone())
            .unwrap_or_default();

        let groups: Vec<String> = scim_user
            .groups
            .iter()
            .map(|g| g.display.clone().unwrap_or_else(|| g.value.clone()))
            .collect();

        let lifecycle_status = if scim_user.active {
            crate::idm::UserLifecycleStatus::Active
        } else {
            crate::idm::UserLifecycleStatus::Suspended
        };

        crate::idm::UserAttributes {
            user_id,
            username: scim_user.user_name.clone(),
            email,
            department: scim_user.department.clone().unwrap_or_default(),
            cost_center: None,
            groups,
            entitlements: Vec::new(),
            manager_id: None,
            lifecycle_status,
            created_at: now,
            updated_at: now,
            last_active_at: now,
            provisioned_by: None,
            deprovisioned_at: None,
        }
    }

    /// Map an IDM UserAttributes to a SCIM User resource.
    pub fn map_from_idm_user(
        &self,
        idm_user: &crate::idm::UserAttributes,
    ) -> ScimUser {
        let emails = if idm_user.email.is_empty() {
            Vec::new()
        } else {
            vec![ScimEmail {
                value: idm_user.email.clone(),
                email_type: Some("work".to_string()),
                primary: true,
            }]
        };

        let groups: Vec<ScimGroupRef> = idm_user
            .groups
            .iter()
            .map(|g| ScimGroupRef {
                value: g.clone(),
                display: Some(g.clone()),
                ref_uri: None,
            })
            .collect();

        ScimUser {
            schemas: vec![SCHEMA_USER.to_string()],
            id: idm_user.user_id.to_string(),
            external_id: None,
            user_name: idm_user.username.clone(),
            name: None,
            display_name: Some(idm_user.username.clone()),
            emails,
            active: idm_user.lifecycle_status == crate::idm::UserLifecycleStatus::Active,
            groups,
            department: if idm_user.department.is_empty() {
                None
            } else {
                Some(idm_user.department.clone())
            },
            meta: ScimMeta {
                resource_type: "User".to_string(),
                created: format!("{}Z", idm_user.created_at),
                last_modified: format!("{}Z", idm_user.updated_at),
                location: format!("{}/Users/{}", self.base_url, idm_user.user_id),
                version: String::new(),
            },
        }
    }

    /// Get user count.
    pub fn user_count(&self) -> usize {
        self.users.len()
    }

    /// Get group count.
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }
}

// ── SIEM Helper ──────────────────────────────────────────────────────

/// Emit a SIEM event for SCIM operations (mirrors the pattern from idm.rs).
fn emit_scim_siem_event(
    action: &'static str,
    severity: Severity,
    outcome: &'static str,
    user_id: Option<Uuid>,
    detail: Option<String>,
) {
    let event = SecurityEvent {
        timestamp: SecurityEvent::now_iso8601(),
        category: "scim_provisioning",
        action,
        severity,
        outcome,
        user_id,
        source_ip: None,
        detail,
    };
    let json = event.to_json();
    tracing::info!(target: "siem", "{}", json);

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let siem_event = crate::siem::SiemEvent {
        timestamp,
        severity: severity as u8,
        event_type: action.to_string(),
        json,
    };
    crate::siem::broadcast_event(&siem_event);
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_now() -> i64 {
        1_000_000
    }

    fn make_server() -> ScimServer {
        ScimServer::with_clock("https://sso.example.mil/scim/v2", test_now)
    }

    fn sample_user(username: &str) -> ScimUser {
        ScimUser {
            schemas: vec![SCHEMA_USER.to_string()],
            id: String::new(),
            external_id: Some("ext-001".to_string()),
            user_name: username.to_string(),
            name: Some(ScimName {
                formatted: Some("John Doe".to_string()),
                family_name: Some("Doe".to_string()),
                given_name: Some("John".to_string()),
            }),
            display_name: Some("John Doe".to_string()),
            emails: vec![ScimEmail {
                value: format!("{}@example.mil", username),
                email_type: Some("work".to_string()),
                primary: true,
            }],
            active: true,
            groups: Vec::new(),
            department: Some("Operations".to_string()),
            meta: ScimMeta {
                resource_type: String::new(),
                created: String::new(),
                last_modified: String::new(),
                location: String::new(),
                version: String::new(),
            },
        }
    }

    fn sample_group(name: &str) -> ScimGroup {
        ScimGroup {
            schemas: vec![SCHEMA_GROUP.to_string()],
            id: String::new(),
            external_id: None,
            display_name: name.to_string(),
            members: Vec::new(),
            meta: ScimMeta {
                resource_type: String::new(),
                created: String::new(),
                last_modified: String::new(),
                location: String::new(),
                version: String::new(),
            },
        }
    }

    // ── User CRUD Tests ──────────────────────────────────────────────

    #[test]
    fn create_user_assigns_id_and_meta() {
        let mut server = make_server();
        let user = server.create_user(sample_user("jdoe")).unwrap();

        assert!(!user.id.is_empty());
        assert_eq!(user.meta.resource_type, "User");
        assert!(user.meta.location.contains(&user.id));
        assert!(!user.meta.version.is_empty());
        assert_eq!(server.user_count(), 1);
    }

    #[test]
    fn create_duplicate_username_fails() {
        let mut server = make_server();
        server.create_user(sample_user("jdoe")).unwrap();
        let result = server.create_user(sample_user("jdoe"));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().status, 409);
    }

    #[test]
    fn get_user_by_id() {
        let mut server = make_server();
        let created = server.create_user(sample_user("jdoe")).unwrap();
        let fetched = server.get_user(&created.id).unwrap();
        assert_eq!(fetched.user_name, "jdoe");
    }

    #[test]
    fn get_nonexistent_user_returns_404() {
        let server = make_server();
        let result = server.get_user("nonexistent");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().status, 404);
    }

    #[test]
    fn update_user_changes_etag() {
        let mut server = make_server();
        let created = server.create_user(sample_user("jdoe")).unwrap();
        let old_etag = created.meta.version.clone();

        let mut updated_user = sample_user("jdoe_updated");
        updated_user.id = created.id.clone();
        let updated = server
            .update_user(&created.id, updated_user, None)
            .unwrap();

        assert_ne!(updated.meta.version, old_etag);
        assert_eq!(updated.user_name, "jdoe_updated");
    }

    #[test]
    fn update_with_wrong_etag_fails() {
        let mut server = make_server();
        let created = server.create_user(sample_user("jdoe")).unwrap();

        let result = server.update_user(
            &created.id,
            sample_user("jdoe2"),
            Some("W/\"wrong\""),
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().status, 412);
    }

    #[test]
    fn delete_user_removes_it() {
        let mut server = make_server();
        let created = server.create_user(sample_user("jdoe")).unwrap();
        server.delete_user(&created.id).unwrap();
        assert_eq!(server.user_count(), 0);
        assert!(server.get_user(&created.id).is_err());
    }

    #[test]
    fn delete_nonexistent_user_returns_404() {
        let mut server = make_server();
        assert!(server.delete_user("nonexistent").is_err());
    }

    // ── User Patch Tests ─────────────────────────────────────────────

    #[test]
    fn patch_user_replace_active() {
        let mut server = make_server();
        let created = server.create_user(sample_user("jdoe")).unwrap();

        let patch = ScimPatchRequest {
            schemas: vec![SCHEMA_PATCH_OP.to_string()],
            operations: vec![PatchOperation {
                op: PatchOpType::Replace,
                path: Some("active".to_string()),
                value: Some(serde_json::json!(false)),
            }],
        };

        let patched = server.patch_user(&created.id, &patch).unwrap();
        assert!(!patched.active);
    }

    #[test]
    fn patch_user_remove_department() {
        let mut server = make_server();
        let created = server.create_user(sample_user("jdoe")).unwrap();
        assert!(created.department.is_some());

        let patch = ScimPatchRequest {
            schemas: vec![SCHEMA_PATCH_OP.to_string()],
            operations: vec![PatchOperation {
                op: PatchOpType::Remove,
                path: Some("department".to_string()),
                value: None,
            }],
        };

        let patched = server.patch_user(&created.id, &patch).unwrap();
        assert!(patched.department.is_none());
    }

    // ── Group CRUD Tests ─────────────────────────────────────────────

    #[test]
    fn create_and_get_group() {
        let mut server = make_server();
        let created = server.create_group(sample_group("ops-team")).unwrap();

        assert!(!created.id.is_empty());
        assert_eq!(created.display_name, "ops-team");
        assert_eq!(server.group_count(), 1);

        let fetched = server.get_group(&created.id).unwrap();
        assert_eq!(fetched.display_name, "ops-team");
    }

    #[test]
    fn patch_group_add_member() {
        let mut server = make_server();
        let user = server.create_user(sample_user("jdoe")).unwrap();
        let group = server.create_group(sample_group("ops-team")).unwrap();

        let patch = ScimPatchRequest {
            schemas: vec![SCHEMA_PATCH_OP.to_string()],
            operations: vec![PatchOperation {
                op: PatchOpType::Add,
                path: Some("members".to_string()),
                value: Some(serde_json::json!({
                    "value": user.id,
                    "display": "John Doe"
                })),
            }],
        };

        let patched = server.patch_group(&group.id, &patch).unwrap();
        assert_eq!(patched.members.len(), 1);
        assert_eq!(patched.members[0].value, user.id);
    }

    #[test]
    fn patch_group_remove_member() {
        let mut server = make_server();
        let user = server.create_user(sample_user("jdoe")).unwrap();
        let mut group = sample_group("ops-team");
        group.members.push(ScimMemberRef {
            value: user.id.clone(),
            display: Some("John Doe".to_string()),
            ref_uri: None,
        });
        let created_group = server.create_group(group).unwrap();

        let patch = ScimPatchRequest {
            schemas: vec![SCHEMA_PATCH_OP.to_string()],
            operations: vec![PatchOperation {
                op: PatchOpType::Remove,
                path: Some(format!("members[value eq \"{}\"]", user.id)),
                value: None,
            }],
        };

        let patched = server.patch_group(&created_group.id, &patch).unwrap();
        assert!(patched.members.is_empty());
    }

    // ── Filter Tests ─────────────────────────────────────────────────

    #[test]
    fn filter_parse_eq() {
        let f = ScimFilter::parse("userName eq \"jdoe\"").unwrap();
        assert_eq!(f.attribute, "userName");
        assert_eq!(f.op, ScimFilterOp::Eq);
        assert_eq!(f.value, Some("jdoe".to_string()));
    }

    #[test]
    fn filter_parse_sw() {
        let f = ScimFilter::parse("userName sw \"j\"").unwrap();
        assert_eq!(f.op, ScimFilterOp::Sw);
    }

    #[test]
    fn filter_parse_pr() {
        let f = ScimFilter::parse("displayName pr").unwrap();
        assert_eq!(f.op, ScimFilterOp::Pr);
        assert!(f.value.is_none());
    }

    #[test]
    fn filter_matches_user() {
        let mut server = make_server();
        let created = server.create_user(sample_user("jdoe")).unwrap();

        let f = ScimFilter::parse("userName eq \"jdoe\"").unwrap();
        assert!(f.matches_user(&created));

        let f2 = ScimFilter::parse("userName eq \"other\"").unwrap();
        assert!(!f2.matches_user(&created));
    }

    #[test]
    fn filter_contains_user() {
        let mut server = make_server();
        let created = server.create_user(sample_user("jdoe")).unwrap();

        let f = ScimFilter::parse("userName co \"do\"").unwrap();
        assert!(f.matches_user(&created));
    }

    // ── List & Pagination Tests ──────────────────────────────────────

    #[test]
    fn list_users_with_pagination() {
        let mut server = make_server();
        for i in 0..5 {
            server
                .create_user(sample_user(&format!("user{}", i)))
                .unwrap();
        }

        let page1 = server.list_users(None, 1, 2);
        assert_eq!(page1.total_results, 5);
        assert_eq!(page1.items_per_page, 2);
        assert_eq!(page1.start_index, 1);

        let page2 = server.list_users(None, 3, 2);
        assert_eq!(page2.items_per_page, 2);
        assert_eq!(page2.start_index, 3);
    }

    #[test]
    fn list_users_with_filter() {
        let mut server = make_server();
        server.create_user(sample_user("alpha")).unwrap();
        server.create_user(sample_user("bravo")).unwrap();
        server.create_user(sample_user("charlie")).unwrap();

        let filter = ScimFilter::parse("userName sw \"a\"").unwrap();
        let result = server.list_users(Some(&filter), 1, 100);
        assert_eq!(result.total_results, 1);
        assert_eq!(result.resources[0].user_name, "alpha");
    }

    // ── Bulk Operations Tests ────────────────────────────────────────

    #[test]
    fn bulk_create_users() {
        let mut server = make_server();

        let bulk = ScimBulkRequest {
            schemas: vec![SCHEMA_BULK_REQUEST.to_string()],
            operations: vec![
                BulkOperation {
                    method: BulkMethod::Post,
                    path: "/Users".to_string(),
                    bulk_id: Some("1".to_string()),
                    data: Some(serde_json::to_value(sample_user("bulk1")).unwrap()),
                },
                BulkOperation {
                    method: BulkMethod::Post,
                    path: "/Users".to_string(),
                    bulk_id: Some("2".to_string()),
                    data: Some(serde_json::to_value(sample_user("bulk2")).unwrap()),
                },
            ],
        };

        let response = server.execute_bulk(&bulk).unwrap();
        assert_eq!(response.operations.len(), 2);
        assert_eq!(response.operations[0].status, 201);
        assert_eq!(response.operations[1].status, 201);
        assert_eq!(server.user_count(), 2);
    }

    // ── Discovery Tests ──────────────────────────────────────────────

    #[test]
    fn service_provider_config_populated() {
        let server = make_server();
        let config = server.service_provider_config();
        assert!(config.patch.supported);
        assert!(config.bulk.supported);
        assert!(config.filter.supported);
        assert!(config.etag.supported);
        assert!(!config.authentication_schemes.is_empty());
    }

    #[test]
    fn resource_types_returns_user_and_group() {
        let server = make_server();
        let types = server.resource_types();
        assert_eq!(types.len(), 2);
    }

    #[test]
    fn schemas_returns_user_and_group() {
        let server = make_server();
        let schemas = server.schemas();
        assert_eq!(schemas.len(), 2);
    }

    // ── Authentication & Rate Limiting ───────────────────────────────

    #[test]
    fn authenticate_valid_token() {
        let mut server = make_server();
        server.register_client(ScimClient {
            client_id: "workday".to_string(),
            token_hash: "secret-token-123".to_string(),
            description: "Workday HR".to_string(),
            rate_limit_rpm: 100,
            current_window_count: 0,
            window_start: 0,
        });

        let result = server.authenticate("secret-token-123");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "workday");
    }

    #[test]
    fn authenticate_invalid_token() {
        let mut server = make_server();
        server.register_client(ScimClient {
            client_id: "workday".to_string(),
            token_hash: "secret-token-123".to_string(),
            description: "Workday HR".to_string(),
            rate_limit_rpm: 100,
            current_window_count: 0,
            window_start: 0,
        });

        let result = server.authenticate("wrong-token");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().status, 401);
    }

    #[test]
    fn rate_limit_exceeded() {
        let mut server = make_server();
        server.register_client(ScimClient {
            client_id: "workday".to_string(),
            token_hash: "token".to_string(),
            description: "Workday HR".to_string(),
            rate_limit_rpm: 2,
            current_window_count: 0,
            window_start: test_now(),
        });

        // First two should succeed
        assert!(server.authenticate("token").is_ok());
        assert!(server.authenticate("token").is_ok());

        // Third should be rate limited
        let result = server.authenticate("token");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().status, 429);
    }

    // ── IDM Integration Tests ────────────────────────────────────────

    #[test]
    fn map_to_idm_user_preserves_fields() {
        let mut server = make_server();
        let scim_user = server.create_user(sample_user("jdoe")).unwrap();

        let idm_user = server.map_to_idm_user(&scim_user);
        assert_eq!(idm_user.username, "jdoe");
        assert_eq!(idm_user.email, "jdoe@example.mil");
        assert_eq!(idm_user.department, "Operations");
        assert_eq!(
            idm_user.lifecycle_status,
            crate::idm::UserLifecycleStatus::Active
        );
    }

    #[test]
    fn map_inactive_user_maps_to_suspended() {
        let mut server = make_server();
        let mut user = sample_user("suspended");
        user.active = false;
        let created = server.create_user(user).unwrap();

        let idm_user = server.map_to_idm_user(&created);
        assert_eq!(
            idm_user.lifecycle_status,
            crate::idm::UserLifecycleStatus::Suspended
        );
    }

    #[test]
    fn map_from_idm_roundtrip() {
        let server = make_server();
        let idm_user = crate::idm::UserAttributes {
            user_id: Uuid::new_v4(),
            username: "roundtrip".to_string(),
            email: "roundtrip@example.mil".to_string(),
            department: "Engineering".to_string(),
            cost_center: None,
            groups: vec!["dev-team".to_string()],
            entitlements: Vec::new(),
            manager_id: None,
            lifecycle_status: crate::idm::UserLifecycleStatus::Active,
            created_at: 1000,
            updated_at: 2000,
            last_active_at: 2000,
            provisioned_by: None,
            deprovisioned_at: None,
        };

        let scim_user = server.map_from_idm_user(&idm_user);
        assert_eq!(scim_user.user_name, "roundtrip");
        assert_eq!(scim_user.id, idm_user.user_id.to_string());
        assert!(scim_user.active);
        assert_eq!(scim_user.department, Some("Engineering".to_string()));
    }

    // ── ETag Tests ───────────────────────────────────────────────────

    #[test]
    fn etag_increments_on_operations() {
        let mut server = make_server();
        let u1 = server.create_user(sample_user("u1")).unwrap();
        let u2 = server.create_user(sample_user("u2")).unwrap();

        // Each creation should get a different ETag
        assert_ne!(u1.meta.version, u2.meta.version);
    }

    #[test]
    fn update_with_correct_etag_succeeds() {
        let mut server = make_server();
        let created = server.create_user(sample_user("jdoe")).unwrap();
        let etag = created.meta.version.clone();

        let result = server.update_user(
            &created.id,
            sample_user("jdoe_updated"),
            Some(&etag),
        );
        assert!(result.is_ok());
    }

    // ── Delete user removes from groups ──────────────────────────────

    #[test]
    fn delete_user_removes_from_groups() {
        let mut server = make_server();
        let user = server.create_user(sample_user("jdoe")).unwrap();

        let mut group = sample_group("ops-team");
        group.members.push(ScimMemberRef {
            value: user.id.clone(),
            display: Some("John Doe".to_string()),
            ref_uri: None,
        });
        let created_group = server.create_group(group).unwrap();

        server.delete_user(&user.id).unwrap();

        let fetched_group = server.get_group(&created_group.id).unwrap();
        assert!(fetched_group.members.is_empty());
    }
}
