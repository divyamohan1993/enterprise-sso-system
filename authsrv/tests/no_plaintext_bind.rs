#![cfg(feature = "test-util")]

//! D-11/D-12: the binary refuses to bind anything other than a loopback
//! socket.  The bind-validation logic lives inside `main.rs` so it is
//! covered by the unit tests in `authsrv/src/main.rs::tests::*`
//! (loopback_v4_accepted / loopback_v6_accepted / wildcard_v4_refused /
//! wildcard_v6_refused / public_ip_refused).
//!
//! This integration-level test documents the shape of the refusal: an
//! environment variable `MILNET_AUTHSRV_BIND` set to a non-loopback address
//! must terminate the binary with a non-zero exit code.  Driving a full
//! sub-process here would require a long-running process model; we keep
//! the assertion in the binary's own `#[cfg(test)]` module which `cargo
//! test -p authsrv` runs as part of the unified test target.

#[test]
fn bind_validation_unit_tests_exist() {
    // Sentinel — the actual validation is enforced by the parse_bind unit
    // tests inside main.rs.  If the unit tests there are removed, this
    // sentinel keeps the integration suite from silently losing coverage.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    assert!(path.exists(), "main.rs missing");
    let body = std::fs::read_to_string(&path).expect("read main.rs");
    for marker in [
        "loopback_v4_accepted",
        "loopback_v6_accepted",
        "wildcard_v4_refused",
        "wildcard_v6_refused",
        "public_ip_refused",
    ] {
        assert!(
            body.contains(marker),
            "main.rs lost the bind-validation unit test `{marker}` — D-11/D-12 regression"
        );
    }
}
