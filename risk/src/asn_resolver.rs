//! F2: Server-side ASN derivation from source IP.
//!
//! Client-declared `network_id` is untrusted and MUST be cross-checked
//! against a server-derived ASN label. When the database is unavailable
//! the feature is disabled (signals pass through unchanged) and a
//! warning is logged.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::OnceLock;

use maxminddb::{geoip2, Reader};

static ASN_READER: OnceLock<Option<Reader<Vec<u8>>>> = OnceLock::new();

/// Default path for the GeoLite2-ASN database.
pub const DEFAULT_ASN_DB_PATH: &str = "/usr/share/GeoIP/GeoLite2-ASN.mmdb";

/// Initialize the reader lazily on first use. Missing DB == disabled feature.
fn reader() -> Option<&'static Reader<Vec<u8>>> {
    let cell = ASN_READER.get_or_init(|| {
        let path: PathBuf = std::env::var("MILNET_ASN_DB_PATH")
            .unwrap_or_else(|_| DEFAULT_ASN_DB_PATH.to_string())
            .into();
        match Reader::open_readfile(&path) {
            Ok(r) => {
                tracing::info!(path = %path.display(), "ASN database loaded for F2 network-id verification");
                Some(r)
            }
            Err(e) => {
                tracing::warn!(
                    target: "siem",
                    path = %path.display(),
                    error = %e,
                    "SIEM:WARNING GeoLite2-ASN database unavailable — F2 client network_id verification DISABLED"
                );
                None
            }
        }
    });
    cell.as_ref()
}

/// Return true if ASN lookup is available.
pub fn is_available() -> bool {
    reader().is_some()
}

/// Derive a canonical network_id (e.g. `AS15169`) from a source IP.
/// Returns None when the database is missing or the IP has no record.
pub fn derive_network_id(ip: IpAddr) -> Option<String> {
    let r = reader()?;
    let asn: geoip2::Asn = r.lookup(ip).ok()?;
    asn.autonomous_system_number.map(|n| format!("AS{n}"))
}

/// Verify the client-declared `network_id` against the server-derived ASN.
/// Returns `Ok(())` if consistent or if the feature is disabled.
/// Returns `Err` with a brief reason otherwise — caller must hard-reject.
pub fn verify_network_id(ip: Option<IpAddr>, declared: Option<&str>) -> Result<(), &'static str> {
    let Some(ip) = ip else { return Ok(()) };
    let Some(declared) = declared else { return Ok(()) };
    if declared.is_empty() {
        return Ok(());
    }
    if !is_available() {
        return Ok(());
    }
    match derive_network_id(ip) {
        Some(server_asn) => {
            if server_asn.eq_ignore_ascii_case(declared) {
                Ok(())
            } else {
                tracing::warn!(
                    target: "siem",
                    declared = %declared,
                    derived = %server_asn,
                    source_ip = %ip,
                    "SIEM:CRITICAL F2 client network_id mismatch — rejecting"
                );
                Err("network_id mismatch with server-derived ASN")
            }
        }
        None => Ok(()),
    }
}
