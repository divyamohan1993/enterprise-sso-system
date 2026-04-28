//! Build-time guards for the cryptographic root of trust.
//!
//! Today the post-quantum signature library `ml-dsa` is shipped as a release
//! candidate (e.g. `0.1.0-rc.7`). RC versions are explicitly NOT FIPS 140-3
//! validated. For production / classified deployment we require a stable
//! release of the underlying PQ libraries; the guard below enforces that
//! invariant at build time so a stable release can be adopted by changing
//! one version pin in `Cargo.toml` without any further code changes.
//!
//! The guard activates when one of the following env vars is set at build
//! time:
//!
//! * `MILNET_MILITARY_DEPLOYMENT=1`  — military / classified deployment
//! * `MILNET_REQUIRE_FIPS_VALIDATED_PQ=1`  — explicit FIPS-validated build
//!
//! When neither is set the guard reports a `cargo:warning=` diagnostic so
//! developers see the gap during normal builds but the build still succeeds.

use std::env;
use std::path::Path;
use std::process;

fn main() {
    println!("cargo:rerun-if-env-changed=MILNET_MILITARY_DEPLOYMENT");
    println!("cargo:rerun-if-env-changed=MILNET_REQUIRE_FIPS_VALIDATED_PQ");

    // Resolve the workspace `Cargo.lock` (one level up from this crate).
    let manifest_dir = match env::var("CARGO_MANIFEST_DIR") {
        Ok(v) => v,
        Err(_) => return, // Non-cargo build context — skip the guard.
    };
    let lockfile = Path::new(&manifest_dir).join("..").join("Cargo.lock");
    println!("cargo:rerun-if-changed={}", lockfile.display());

    let lock = match std::fs::read_to_string(&lockfile) {
        Ok(s) => s,
        Err(_) => {
            // Lockfile not present (e.g. published crate). Skip rather
            // than fail on environments we don't control.
            return;
        }
    };

    let ml_dsa_version = parse_locked_version(&lock, "ml-dsa");
    let ml_kem_version = parse_locked_version(&lock, "ml-kem");

    let strict =
        env::var("MILNET_MILITARY_DEPLOYMENT").as_deref() == Ok("1")
            || env::var("MILNET_REQUIRE_FIPS_VALIDATED_PQ").as_deref() == Ok("1");

    for (name, version) in [("ml-dsa", &ml_dsa_version), ("ml-kem", &ml_kem_version)] {
        let v = match version {
            Some(s) => s.as_str(),
            None => {
                if strict {
                    eprintln!(
                        "[milnet build-guard] strict PQ build but `{name}` not present in Cargo.lock"
                    );
                    process::exit(1);
                }
                continue;
            }
        };
        if is_prerelease(v) {
            if strict {
                eprintln!(
                    "[milnet build-guard] crate `{name}` is at pre-release version `{v}`. \
                     Strict (military / FIPS-validated) builds require a stable release. \
                     Upgrade `{name}` in workspace Cargo.toml to a stable version."
                );
                process::exit(1);
            } else {
                println!(
                    "cargo:warning=[milnet] {name} is a pre-release ({v}) — not FIPS validated. \
                     Build will FAIL when MILNET_MILITARY_DEPLOYMENT=1 is set."
                );
            }
        }
    }
}

/// Parse the version of a named package from Cargo.lock TOML.
fn parse_locked_version(lock: &str, package: &str) -> Option<String> {
    let needle = format!("name = \"{package}\"");
    for block in lock.split("[[package]]") {
        if !block.contains(&needle) {
            continue;
        }
        for line in block.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("version = \"") {
                if let Some(end) = rest.find('"') {
                    if let Some(prefix) = rest.get(..end) {
                        return Some(prefix.to_string());
                    }
                }
            }
        }
    }
    None
}

/// SemVer-aware pre-release detector. Anything containing `-` after the
/// numeric core (e.g. `0.1.0-rc.7`, `1.0.0-beta`) is pre-release.
fn is_prerelease(v: &str) -> bool {
    let core = v.split('+').next().unwrap_or(v);
    core.contains('-')
}
