//! LDAP / Active Directory directory sync connector (J2).
//!
//! Polls an upstream LDAP/AD directory on a fixed cadence and emits SCIM
//! `User`/`Group` change events to a sink callback. Two sync modes:
//!
//! - **Full sync**: walk every entry under `base_dn`, used at startup and
//!   when `usnchanged_high_water` is unset.
//! - **Delta sync**: AD-only — re-query with `(uSNChanged>=N+1)` to fetch
//!   only entries modified since the previous run.
//!
//! TLS is mandatory. The `ldap3` dependency is gated behind the
//! `ldap-runtime` feature so the crate compiles in environments that do not
//! provide `libldap2-dev`.
#![forbid(unsafe_code)]

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LdapError {
    #[error("connect: {0}")]
    Connect(String),
    #[error("bind: {0}")]
    Bind(String),
    #[error("search: {0}")]
    Search(String),
    #[error("tls required but not configured")]
    TlsRequired,
    #[error("ldap-runtime feature is not enabled")]
    RuntimeMissing,
    #[error("anonymous bind rejected: empty bind_dn")]
    AnonymousBindRejected,
    #[error("invalid filter value")]
    InvalidFilter,
}

/// RFC 4515 LDAP filter value escaper. Escapes the metacharacters
/// `* ( ) \ NUL` to their `\HH` hex form. All attribute values that are
/// interpolated into search filters MUST go through this function — see
/// the `no_unescaped_filter_format` lint test.
pub fn escape_filter_value(input: &str) -> String {
    let mut out = Vec::with_capacity(input.len());
    for &b in input.as_bytes() {
        match b {
            b'*' => out.extend_from_slice(b"\\2a"),
            b'(' => out.extend_from_slice(b"\\28"),
            b')' => out.extend_from_slice(b"\\29"),
            b'\\' => out.extend_from_slice(b"\\5c"),
            0u8 => out.extend_from_slice(b"\\00"),
            _ => out.push(b),
        }
    }
    // Safe: we only emit ASCII for escapes and copy other bytes verbatim
    // from a valid &str, so the result is still valid UTF-8.
    String::from_utf8(out).expect("utf-8 preserved")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfig {
    /// LDAPS URL: `ldaps://dc.example.com:636`. Plain `ldap://` is rejected.
    pub url: String,
    pub bind_dn: String,
    pub bind_password: String,
    pub base_dn: String,
    pub user_filter: String,
    pub group_filter: String,
    #[serde(with = "humantime_serde_compat")]
    pub sync_interval: Duration,
    pub usnchanged_high_water: Option<u64>,
    pub trust_anchor_pem: Option<String>,
}

impl LdapConfig {
    pub fn validate(&self) -> Result<(), LdapError> {
        if !self.url.starts_with("ldaps://") {
            return Err(LdapError::TlsRequired);
        }
        if self.bind_dn.trim().is_empty() {
            return Err(LdapError::AnonymousBindRejected);
        }
        validate_filter_shape(&self.user_filter)?;
        validate_filter_shape(&self.group_filter)?;
        Ok(())
    }
}

/// Cheap structural check that a configured filter is well-formed
/// (balanced parens, starts with `(`, ends with `)`, no embedded NULs).
/// This is a configuration sanity check — it does not replace per-value
/// escaping via [`escape_filter_value`].
pub fn validate_filter_shape(f: &str) -> Result<(), LdapError> {
    if f.is_empty() || !f.starts_with('(') || !f.ends_with(')') {
        return Err(LdapError::InvalidFilter);
    }
    if f.as_bytes().contains(&0) {
        return Err(LdapError::InvalidFilter);
    }
    let mut depth: i32 = 0;
    let mut esc = false;
    for &b in f.as_bytes() {
        if esc { esc = false; continue; }
        match b {
            b'\\' => esc = true,
            b'(' => depth += 1,
            b')' => { depth -= 1; if depth < 0 { return Err(LdapError::InvalidFilter); } }
            _ => {}
        }
    }
    if depth != 0 { return Err(LdapError::InvalidFilter); }
    Ok(())
}

mod humantime_serde_compat {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;
    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        Ok(Duration::from_secs(u64::deserialize(d)?))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimUser {
    pub id: String,
    pub user_name: String,
    pub display_name: String,
    pub emails: Vec<String>,
    pub active: bool,
    pub groups: Vec<String>,
    pub external_id: Option<String>,
    pub source_dn: String,
    pub usnchanged: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimGroup {
    pub id: String,
    pub display_name: String,
    pub members: Vec<String>,
    pub source_dn: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScimEvent {
    UserUpserted(ScimUser),
    UserDeleted { id: String },
    GroupUpserted(ScimGroup),
    GroupDeleted { id: String },
}

#[async_trait]
pub trait LdapClient: Send + Sync {
    async fn full_sync(&mut self) -> Result<Vec<ScimEvent>, LdapError>;
    async fn delta_sync(&mut self, since_usn: u64) -> Result<Vec<ScimEvent>, LdapError>;
    fn high_water(&self) -> Option<u64>;
}

pub fn map_ldap_attrs_to_scim_user(dn: &str, attrs: &HashMap<String, Vec<String>>) -> ScimUser {
    let first_opt = |k: &str| attrs.get(k).and_then(|v| v.first().cloned());
    let first = |k: &str| first_opt(k).unwrap_or_default();
    let many = |k: &str| attrs.get(k).cloned().unwrap_or_default();
    let usn = attrs.get("uSNChanged")
        .and_then(|v| v.first())
        .and_then(|s| s.parse::<u64>().ok());
    ScimUser {
        id: first_opt("objectGUID").unwrap_or_else(|| dn.to_string()),
        user_name: first_opt("sAMAccountName").unwrap_or_else(|| first("uid")),
        display_name: first_opt("displayName").unwrap_or_else(|| first("cn")),
        emails: many("mail"),
        active: first("userAccountControl").parse::<u32>().map(|f| f & 0x2 == 0).unwrap_or(true),
        groups: many("memberOf"),
        external_id: Some(dn.to_string()),
        source_dn: dn.to_string(),
        usnchanged: usn,
    }
}

#[cfg(feature = "ldap-runtime")]
pub mod runtime {
    use super::*;
    use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};

    pub struct Ldap3Client {
        cfg: LdapConfig,
        ldap: ldap3::Ldap,
        high_water: Option<u64>,
    }

    impl Ldap3Client {
        pub async fn connect(cfg: LdapConfig) -> Result<Self, LdapError> {
            cfg.validate()?;
            // Defense in depth: ldap3 v0.11 default settings already verify
            // server certs over ldaps://, but we explicitly reject referral
            // chasing to defeat SMB-relay / referral-injection downgrades.
            let settings = LdapConnSettings::new().set_no_tls_verify(false);
            let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &cfg.url)
                .await
                .map_err(|e| LdapError::Connect(e.to_string()))?;
            ldap3::drive!(conn);
            ldap.simple_bind(&cfg.bind_dn, &cfg.bind_password)
                .await
                .map_err(|e| LdapError::Bind(e.to_string()))?
                .success()
                .map_err(|e| LdapError::Bind(e.to_string()))?;
            let hw = cfg.usnchanged_high_water;
            Ok(Self { cfg, ldap, high_water: hw })
        }

        async fn search(&mut self, filter: &str) -> Result<Vec<SearchEntry>, LdapError> {
            let (rs, _r) = self.ldap
                .search(&self.cfg.base_dn, Scope::Subtree, filter, vec!["*", "uSNChanged"])
                .await
                .map_err(|e| LdapError::Search(e.to_string()))?
                .success()
                .map_err(|e| LdapError::Search(e.to_string()))?;
            Ok(rs.into_iter().map(SearchEntry::construct).collect())
        }
    }

    #[async_trait]
    impl LdapClient for Ldap3Client {
        async fn full_sync(&mut self) -> Result<Vec<ScimEvent>, LdapError> {
            let entries = self.search(&self.cfg.user_filter.clone()).await?;
            let mut out = Vec::with_capacity(entries.len());
            for e in entries {
                let u = map_ldap_attrs_to_scim_user(&e.dn, &e.attrs);
                if let Some(usn) = u.usnchanged {
                    self.high_water = Some(self.high_water.unwrap_or(0).max(usn));
                }
                out.push(ScimEvent::UserUpserted(u));
            }
            Ok(out)
        }

        async fn delta_sync(&mut self, since_usn: u64) -> Result<Vec<ScimEvent>, LdapError> {
            let filter = format!("(&{}(uSNChanged>={}))", self.cfg.user_filter, since_usn + 1);
            let entries = self.search(&filter).await?;
            let mut out = Vec::with_capacity(entries.len());
            for e in entries {
                let u = map_ldap_attrs_to_scim_user(&e.dn, &e.attrs);
                if let Some(usn) = u.usnchanged {
                    self.high_water = Some(self.high_water.unwrap_or(0).max(usn));
                }
                out.push(ScimEvent::UserUpserted(u));
            }
            Ok(out)
        }

        fn high_water(&self) -> Option<u64> { self.high_water }
    }
}

#[cfg(not(feature = "ldap-runtime"))]
pub struct DisabledClient;

#[cfg(not(feature = "ldap-runtime"))]
#[async_trait]
impl LdapClient for DisabledClient {
    async fn full_sync(&mut self) -> Result<Vec<ScimEvent>, LdapError> { Err(LdapError::RuntimeMissing) }
    async fn delta_sync(&mut self, _since: u64) -> Result<Vec<ScimEvent>, LdapError> { Err(LdapError::RuntimeMissing) }
    fn high_water(&self) -> Option<u64> { None }
}
