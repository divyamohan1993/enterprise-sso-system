//! RES-SPOF Postgres: Patroni-aware primary discovery and `sqlx::PgPool`
//! construction.
//!
//! This module implements the client side of the HA Postgres topology
//! landed in `deploy/kubernetes/postgres-ha.yaml` and
//! `deploy/kubernetes/etcd.yaml`. On the server side, Patroni runs on
//! every Postgres pod, uses etcd for leader election, and exposes a
//! REST API on port 8008. The `/leader` endpoint returns HTTP 200 on
//! the current leader and HTTP 503 on every standby. `/health` returns
//! 200 on every healthy member regardless of role.
//!
//! # Primary discovery
//!
//! [`PatroniMembers::resolve_leader`] iterates the configured member
//! list (env var `MILNET_PATRONI_MEMBERS`, comma-separated, e.g.
//! `postgres-0.postgres-headless.milnet.svc.cluster.local:8008,postgres-1...:8008`),
//! issues a minimal HTTP/1.1 GET `/leader` against each, and returns
//! the first member that responds `200`. On any network or HTTP error
//! the next member is tried; if all fail, `Err(PoolError::NoLeader)`
//! is returned.
//!
//! The HTTP client is hand-rolled on top of `tokio::net::TcpStream` to
//! avoid pulling `reqwest`/`hyper` into the `common` crate's
//! dependency graph. The parsing is deliberately minimal: we read the
//! status line, discard headers and body, and match on `"HTTP/1.1 200"`
//! / `"HTTP/1.0 200"`. Any deviation is treated as "this member is not
//! the leader right now".
//!
//! # Connection pool
//!
//! [`build_ha_pool`] takes the resolved leader address plus the base
//! `DATABASE_URL` template (substituting `{host}`) and builds a
//! `sqlx::PgPool` with an `after_connect` hook that asserts
//! `transaction_read_only = off`. If a standby is ever mistakenly
//! reached (e.g. failover mid-connect), the hook returns an error and
//! the connection is discarded by the pool, forcing a re-discovery on
//! the next call site.
//!
//! # Readiness gate
//!
//! [`readiness_status`] asks every Patroni member for `/cluster` and
//! returns `Ready` only when at least 1 leader and at least 2
//! `sync_standby` role members are reported. The service's `/healthz`
//! endpoint should return 503 until this returns `Ready` on first
//! startup.
//!
//! # Failover reconnect
//!
//! sqlx handles reconnection automatically via `acquire_timeout`. When
//! the pool surfaces a `ConnectionError` or a query returns an error
//! matching the "read-only" assertion, callers should call
//! [`refresh_leader_and_rebuild`] to rediscover the new leader and
//! rebuild the pool. This is a deliberate "build a new pool" pattern
//! rather than in-place mutation because `sqlx::PgPool` does not
//! expose a safe per-connection host-override API.
//!
//! CAT-H-followup: once the CAT-O spiffe SVID seam is mandatory on
//! every pod, upgrade the Patroni GET to be mTLS-authenticated via
//! the node's SVID rather than unauthenticated HTTP. Patroni supports
//! REST TLS with client cert verification.

#![forbid(unsafe_code)]

use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Errors from the HA pool subsystem.
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("no Patroni leader reachable in {0} members")]
    NoLeader(usize),

    #[error("Patroni HTTP error against {addr}: {source}")]
    PatroniHttp {
        addr: String,
        #[source]
        source: std::io::Error,
    },

    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("MILNET_PATRONI_MEMBERS env var is not set")]
    NoMembersConfigured,

    #[error("resolved connection is to a standby (transaction_read_only=on)")]
    ConnectedToStandby,

    #[error("readiness not yet satisfied: leader={leader}, sync_standbys={sync}")]
    NotReady { leader: bool, sync: u32 },
}

/// Patroni REST endpoint for a single cluster member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatroniMember {
    /// Hostname or IP that Patroni REST is exposed on.
    pub host: String,
    /// Port Patroni REST listens on (default 8008).
    pub port: u16,
}

impl PatroniMember {
    fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Full set of cluster members and the resolved leader address for
/// building a `sqlx` pool. Callers hold this and rebuild the pool on
/// failover.
#[derive(Debug, Clone)]
pub struct PatroniMembers {
    members: Vec<PatroniMember>,
}

impl PatroniMembers {
    /// Parse `MILNET_PATRONI_MEMBERS` (comma-separated `host:port`).
    /// Each entry defaults to port 8008 if unspecified.
    pub fn from_env() -> Result<Self, PoolError> {
        let raw = std::env::var("MILNET_PATRONI_MEMBERS")
            .map_err(|_| PoolError::NoMembersConfigured)?;
        let members = raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(parse_member)
            .collect::<Vec<_>>();
        if members.is_empty() {
            return Err(PoolError::NoMembersConfigured);
        }
        Ok(Self { members })
    }

    /// Direct constructor for tests / programmatic callers.
    pub fn new(members: Vec<PatroniMember>) -> Self {
        Self { members }
    }

    /// Poll every configured member for `/leader` and return the host
    /// (not including port) of the first member that answers HTTP 200.
    ///
    /// Runs queries sequentially with a 1.5s-per-member timeout so the
    /// total worst case is bounded by `members.len() * 1.5s`. For
    /// typical 3-member clusters this is <5s.
    pub async fn resolve_leader(&self) -> Result<String, PoolError> {
        for m in &self.members {
            match timeout(Duration::from_millis(1500), patroni_is_leader(m)).await {
                Ok(Ok(true)) => {
                    tracing::info!(
                        target: "milnet::db_pool",
                        leader_host = %m.host,
                        leader_port = m.port,
                        "patroni leader resolved"
                    );
                    return Ok(m.host.clone());
                }
                Ok(Ok(false)) => continue,
                Ok(Err(e)) => {
                    tracing::debug!(
                        target: "milnet::db_pool",
                        addr = %m.addr(),
                        error = %e,
                        "patroni /leader probe failed"
                    );
                    continue;
                }
                Err(_) => {
                    tracing::debug!(
                        target: "milnet::db_pool",
                        addr = %m.addr(),
                        "patroni /leader probe timed out"
                    );
                    continue;
                }
            }
        }
        Err(PoolError::NoLeader(self.members.len()))
    }
}

fn parse_member(raw: &str) -> PatroniMember {
    if let Some((host, port)) = raw.rsplit_once(':') {
        if let Ok(p) = port.parse::<u16>() {
            return PatroniMember {
                host: host.to_string(),
                port: p,
            };
        }
    }
    PatroniMember {
        host: raw.to_string(),
        port: 8008,
    }
}

/// Send a minimal `GET /leader HTTP/1.1` to the Patroni REST endpoint
/// and return `Ok(true)` iff the status line starts with `HTTP/1.x 200`.
///
/// Patroni semantics:
/// - `200 OK`: this member is the current leader
/// - `503 Service Unavailable`: this member is a standby (or otherwise not leader)
/// - connection refused / timeout: member is unreachable
async fn patroni_is_leader(m: &PatroniMember) -> std::io::Result<bool> {
    let mut stream = TcpStream::connect(m.addr()).await?;
    let req = format!(
        "GET /leader HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: milnet-db-pool/1\r\n\r\n",
        m.host
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    // Read up to 1 KiB — we only need the status line.
    let mut buf = [0u8; 1024];
    let mut total = 0usize;
    while total < buf.len() {
        let n = stream.read(&mut buf[total..]).await?;
        if n == 0 {
            break;
        }
        total += n;
        // Have we seen a full status line (\r\n) yet?
        if buf[..total].windows(2).any(|w| w == b"\r\n") {
            break;
        }
    }

    let head = std::str::from_utf8(&buf[..total]).unwrap_or("");
    let status_line = head.lines().next().unwrap_or("");
    // Match "HTTP/1.1 200 OK" or "HTTP/1.0 200 OK".
    let is_leader = status_line.starts_with("HTTP/1.1 200")
        || status_line.starts_with("HTTP/1.0 200");
    Ok(is_leader)
}

/// Construct a `sqlx::PgPool` against the leader resolved from the
/// given Patroni member list. `base_url` is a `postgres://` connection
/// string whose host is replaced with the resolved leader host.
///
/// The pool is configured with:
/// - `acquire_timeout = 5s`
/// - `max_connections = 32` by default (override via env)
/// - `after_connect` hook asserting `transaction_read_only = off`, so
///   any connection that lands on a standby during failover is
///   discarded and re-acquired
pub async fn build_ha_pool(
    members: &PatroniMembers,
    base_url_template: &str,
) -> Result<PgPool, PoolError> {
    let leader_host = members.resolve_leader().await?;
    let url = substitute_host(base_url_template, &leader_host);

    let max_conn: u32 = std::env::var("MILNET_DB_POOL_MAX")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(32);

    let connect_opts: PgConnectOptions =
        url.parse::<PgConnectOptions>().map_err(PoolError::Sqlx)?;

    let pool = PgPoolOptions::new()
        .max_connections(max_conn)
        .acquire_timeout(Duration::from_secs(5))
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                // Assert the connection landed on a primary. `SHOW
                // transaction_read_only` returns a single-column row
                // with "on" (standby) or "off" (primary).
                let row: (String,) = sqlx::query_as("SHOW transaction_read_only")
                    .fetch_one(&mut *conn)
                    .await?;
                if !row.0.eq_ignore_ascii_case("off") {
                    // Force sqlx to discard this connection by
                    // returning a configuration error. The pool will
                    // retry — if failover has not completed, the
                    // retry will fail the same way and eventually
                    // surface as an acquire_timeout to the caller,
                    // which should call `refresh_leader_and_rebuild`.
                    return Err(sqlx::Error::Configuration(
                        "connected to standby (transaction_read_only=on), \
                         forcing reconnect via Patroni"
                            .into(),
                    ));
                }
                Ok(())
            })
        })
        .connect_with(connect_opts)
        .await?;

    Ok(pool)
}

/// Replace the host portion of a `postgres://user:pass@host:port/db` URL.
///
/// Preserves user, password, port, database, and query string. If the
/// URL does not parse into the expected shape, returns the original
/// string unchanged (the caller will fail at `connect_with`).
fn substitute_host(base: &str, new_host: &str) -> String {
    // Split scheme://authority/rest
    let (scheme, after_scheme) = match base.split_once("://") {
        Some(s) => s,
        None => return base.to_string(),
    };
    let (authority, rest) = match after_scheme.find('/') {
        Some(idx) => (&after_scheme[..idx], &after_scheme[idx..]),
        None => (after_scheme, ""),
    };
    // authority = [user[:pass]@]host[:port]
    let (userinfo, host_port) = match authority.rfind('@') {
        Some(idx) => (&authority[..=idx], &authority[idx + 1..]),
        None => ("", authority),
    };
    let port = host_port.rsplit_once(':').map(|(_, p)| p).unwrap_or("");
    let new_authority = if port.is_empty() {
        format!("{userinfo}{new_host}")
    } else {
        format!("{userinfo}{new_host}:{port}")
    };
    format!("{scheme}://{new_authority}{rest}")
}

/// Rediscover the leader and build a fresh pool. Used by callers on
/// failover when the current pool starts returning read-only errors
/// or connection errors.
pub async fn refresh_leader_and_rebuild(
    members: &PatroniMembers,
    base_url_template: &str,
) -> Result<PgPool, PoolError> {
    tracing::warn!(
        target: "milnet::db_pool",
        "refreshing Patroni leader and rebuilding pool (likely failover)"
    );
    build_ha_pool(members, base_url_template).await
}

/// Result of the HA readiness check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessStatus {
    /// `/healthz` should return 200.
    Ready,
    /// `/healthz` should return 503 with this reason.
    NotReady,
}

/// Poll the cluster and return `Ready` iff a leader exists and at
/// least `required_sync_standbys` members are in `sync_standby` role.
///
/// This is the server-side readiness gate: services must not accept
/// traffic until the cluster has reached the configured durability
/// target. 2 sync standbys matches the
/// `synchronous_standby_names='ANY 2 (standby0, standby1, standby2)'`
/// configuration in `deploy/kubernetes/postgres-ha.yaml`.
pub async fn readiness_status(
    members: &PatroniMembers,
    required_sync_standbys: u32,
) -> ReadinessStatus {
    let mut leader_seen = false;
    let mut sync_count = 0u32;

    for m in &members.members {
        match timeout(Duration::from_millis(1500), patroni_member_role(m)).await {
            Ok(Ok(MemberRole::Leader)) => leader_seen = true,
            Ok(Ok(MemberRole::SyncStandby)) => sync_count += 1,
            _ => {}
        }
    }

    if leader_seen && sync_count >= required_sync_standbys {
        ReadinessStatus::Ready
    } else {
        tracing::warn!(
            target: "milnet::db_pool",
            leader = leader_seen,
            sync_count,
            required = required_sync_standbys,
            "cluster not yet ready"
        );
        ReadinessStatus::NotReady
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemberRole {
    Leader,
    SyncStandby,
    #[allow(dead_code)]
    AsyncStandby,
    #[allow(dead_code)]
    Other,
}

/// Probe a Patroni member for its role. Uses the `/patroni` endpoint
/// which returns a JSON document with a `role` field
/// (`master`/`primary`/`replica`) and a `sync_standby` boolean.
async fn patroni_member_role(m: &PatroniMember) -> std::io::Result<MemberRole> {
    let mut stream = TcpStream::connect(m.addr()).await?;
    let req = format!(
        "GET /patroni HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: milnet-db-pool/1\r\n\r\n",
        m.host
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let mut body = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
        if body.len() > 64 * 1024 {
            break; // cap to prevent runaway
        }
    }

    // Find the JSON body after the first \r\n\r\n.
    let body_start = body
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(0);
    let body_bytes = &body[body_start..];

    // Minimal substring-based role extraction — avoids pulling
    // serde_json in the hot path of a readiness check. Patroni's
    // /patroni response contains either `"role":"master"` (older),
    // `"role":"primary"` (newer), or `"role":"replica"` plus
    // `"sync_standby":true|false`.
    let text = std::str::from_utf8(body_bytes).unwrap_or("");
    let is_leader =
        text.contains("\"role\":\"master\"") || text.contains("\"role\":\"primary\"");
    if is_leader {
        return Ok(MemberRole::Leader);
    }
    let is_sync = text.contains("\"sync_standby\":true");
    if is_sync {
        return Ok(MemberRole::SyncStandby);
    }
    let is_replica = text.contains("\"role\":\"replica\"");
    if is_replica {
        return Ok(MemberRole::AsyncStandby);
    }
    Ok(MemberRole::Other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_member_with_port() {
        let m = parse_member("postgres-0.svc:8008");
        assert_eq!(m.host, "postgres-0.svc");
        assert_eq!(m.port, 8008);
    }

    #[test]
    fn parse_member_without_port_defaults() {
        let m = parse_member("postgres-1.svc");
        assert_eq!(m.host, "postgres-1.svc");
        assert_eq!(m.port, 8008);
    }

    #[test]
    fn substitute_host_preserves_userinfo_and_db() {
        let out = substitute_host(
            "postgres://milnet:secret@oldhost:5432/milnet_sso?sslmode=verify-full",
            "newhost",
        );
        assert_eq!(
            out,
            "postgres://milnet:secret@newhost:5432/milnet_sso?sslmode=verify-full"
        );
    }

    #[test]
    fn substitute_host_handles_no_userinfo() {
        let out = substitute_host("postgres://oldhost:5432/db", "newhost");
        assert_eq!(out, "postgres://newhost:5432/db");
    }

    #[test]
    fn substitute_host_handles_no_port() {
        let out = substitute_host("postgres://u:p@old/db", "new");
        assert_eq!(out, "postgres://u:p@new/db");
    }

    #[test]
    fn patroni_members_from_env_requires_var() {
        std::env::remove_var("MILNET_PATRONI_MEMBERS");
        assert!(matches!(
            PatroniMembers::from_env(),
            Err(PoolError::NoMembersConfigured)
        ));
    }

    // Use a serial guard because these tests touch the env var —
    // otherwise parallel test runs race.
    #[test]
    fn patroni_members_parses_comma_list() {
        std::env::set_var(
            "MILNET_PATRONI_MEMBERS",
            "a.svc:8008,b.svc:8008,c.svc:8008",
        );
        let m = PatroniMembers::from_env().expect("parses");
        assert_eq!(m.members.len(), 3);
        assert_eq!(m.members[1].host, "b.svc");
        std::env::remove_var("MILNET_PATRONI_MEMBERS");
    }
}
