//! Hardened secret loader.
//!
//! Resolves named secrets in priority order:
//! 1. Unix-domain socket at `/run/milnet/secrets.sock` (helper process).
//! 2. systemd `LoadCredential` via `MILNET_SECRET_FD_<NAME>` file descriptor
//!    pointing at a sealed credential file (`$CREDENTIALS_DIRECTORY`).
//! 3. Environment variable `MILNET_<NAME>_SEALED` — only when the
//!    `MILNET_DEV_ALLOW_ENV_SECRETS=1` escape hatch is set, which emits a
//!    CRITICAL log because the bytes become visible to any process that can
//!    read `/proc/<pid>/environ`.
//!
//! The returned [`SecretBuffer`] holds the bytes inside a `Zeroizing<Vec<u8>>`
//! so they are wiped from memory on drop.
#![forbid(unsafe_code)]

use std::io::Read;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use zeroize::Zeroizing;

const SECRET_SOCKET_PATH: &str = "/run/milnet/secrets.sock";
const ENV_ESCAPE_HATCH: &str = "MILNET_DEV_ALLOW_ENV_SECRETS";

/// Owned secret bytes that zeroize on drop.
pub type SecretBuffer = Zeroizing<Vec<u8>>;

/// Errors returned by the secret loader.
#[derive(Debug)]
pub enum SecretLoadError {
    NotFound(String),
    SocketError(String),
    CredentialError(String),
    DevPathDisabled(String),
}

impl std::fmt::Display for SecretLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(n) => write!(f, "secret not found: {n}"),
            Self::SocketError(e) => write!(f, "secret socket error: {e}"),
            Self::CredentialError(e) => write!(f, "credential read error: {e}"),
            Self::DevPathDisabled(n) => write!(
                f,
                "secret {n}: env var path disabled in production. \
                 Risk: /proc/PID/environ exposes secrets to any process able to \
                 read the directory. Set MILNET_DEV_ALLOW_ENV_SECRETS=1 to opt in \
                 for non-production use only."
            ),
        }
    }
}

impl std::error::Error for SecretLoadError {}

/// Load a secret by name using the layered resolver.
///
/// `name` is expected to be the bare secret identifier (e.g. `MASTER_KEK`),
/// not the env-var spelling.
pub fn load_secret(name: &str) -> Result<SecretBuffer, SecretLoadError> {
    if let Some(buf) = try_load_from_socket(name)? {
        return Ok(buf);
    }
    if let Some(buf) = try_load_from_credentials(name)? {
        return Ok(buf);
    }
    try_load_from_env(name)
}

fn try_load_from_socket(name: &str) -> Result<Option<SecretBuffer>, SecretLoadError> {
    if !std::path::Path::new(SECRET_SOCKET_PATH).exists() {
        return Ok(None);
    }
    let mut stream = UnixStream::connect(SECRET_SOCKET_PATH)
        .map_err(|e| SecretLoadError::SocketError(format!("connect: {e}")))?;
    use std::io::Write;
    let req = format!("GET {}\n", name);
    stream
        .write_all(req.as_bytes())
        .map_err(|e| SecretLoadError::SocketError(format!("write: {e}")))?;
    let mut buf: Vec<u8> = Vec::new();
    stream
        .read_to_end(&mut buf)
        .map_err(|e| SecretLoadError::SocketError(format!("read: {e}")))?;
    if buf.is_empty() {
        return Ok(None);
    }
    Ok(Some(Zeroizing::new(buf)))
}

fn try_load_from_credentials(name: &str) -> Result<Option<SecretBuffer>, SecretLoadError> {
    // systemd LoadCredential places files under $CREDENTIALS_DIRECTORY.
    let dir = match std::env::var("CREDENTIALS_DIRECTORY") {
        Ok(d) => PathBuf::from(d),
        Err(_) => return Ok(None),
    };
    let path = dir.join(name);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path)
        .map_err(|e| SecretLoadError::CredentialError(format!("read {}: {e}", path.display())))?;
    Ok(Some(Zeroizing::new(bytes)))
}

fn try_load_from_env(name: &str) -> Result<SecretBuffer, SecretLoadError> {
    let env_name = format!("MILNET_{}_SEALED", name);
    let allow_env = std::env::var(ENV_ESCAPE_HATCH).as_deref() == Ok("1");
    let is_production = std::env::var("MILNET_PRODUCTION").as_deref() == Ok("1")
        || std::env::var("MILNET_MILITARY_DEPLOYMENT").as_deref() == Ok("1");

    if is_production && !allow_env {
        return Err(SecretLoadError::DevPathDisabled(env_name));
    }
    if let Ok(val) = std::env::var(&env_name) {
        if allow_env {
            tracing::error!(
                target: "siem",
                env = %env_name,
                "SIEM:CRITICAL secret loaded from environment variable. \
                 Bytes are visible via /proc/PID/environ. \
                 Migrate to /run/milnet/secrets.sock or systemd LoadCredential."
            );
        }
        return Ok(Zeroizing::new(val.into_bytes()));
    }
    Err(SecretLoadError::NotFound(env_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_path_blocked_in_production_without_opt_in() {
        // Save and clear conflicting env state.
        let prev_prod = std::env::var("MILNET_PRODUCTION").ok();
        let prev_opt = std::env::var(ENV_ESCAPE_HATCH).ok();
        std::env::set_var("MILNET_PRODUCTION", "1");
        std::env::remove_var(ENV_ESCAPE_HATCH);
        std::env::set_var("MILNET_TESTSEC_SEALED", "deadbeef");

        let result = load_secret("TESTSEC");
        assert!(matches!(result, Err(SecretLoadError::DevPathDisabled(_))));

        std::env::remove_var("MILNET_TESTSEC_SEALED");
        if let Some(v) = prev_prod { std::env::set_var("MILNET_PRODUCTION", v); }
        else { std::env::remove_var("MILNET_PRODUCTION"); }
        if let Some(v) = prev_opt { std::env::set_var(ENV_ESCAPE_HATCH, v); }
    }

    #[test]
    fn env_path_works_with_opt_in() {
        let prev_prod = std::env::var("MILNET_PRODUCTION").ok();
        std::env::remove_var("MILNET_PRODUCTION");
        std::env::set_var(ENV_ESCAPE_HATCH, "1");
        std::env::set_var("MILNET_OPTINSEC_SEALED", "abcd1234");

        let buf = load_secret("OPTINSEC").expect("opt-in env path should work");
        assert_eq!(&buf[..], b"abcd1234");

        std::env::remove_var("MILNET_OPTINSEC_SEALED");
        std::env::remove_var(ENV_ESCAPE_HATCH);
        if let Some(v) = prev_prod { std::env::set_var("MILNET_PRODUCTION", v); }
    }

    #[test]
    fn missing_secret_returns_not_found() {
        let prev_prod = std::env::var("MILNET_PRODUCTION").ok();
        std::env::remove_var("MILNET_PRODUCTION");
        std::env::remove_var("CREDENTIALS_DIRECTORY");
        let result = load_secret("DEFINITELY_NOT_SET_42");
        assert!(matches!(result, Err(SecretLoadError::NotFound(_))));
        if let Some(v) = prev_prod { std::env::set_var("MILNET_PRODUCTION", v); }
    }
}
