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
//! developers see the gap during normal builds but the build still succeeds
//! (the rest of the codebase tolerates the RC under non-classified profiles).

use std::env;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-env-changed=MILNET_MILITARY_DEPLOYMENT");
    println!("cargo:rerun-if-env-changed=MILNET_REQUIRE_FIPS_VALIDATED_PQ");

    // Resolve the workspace `Cargo.lock` (one level up from this crate).
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo");
    let lockfile = Path::new(&manifest_dir).join("..").join("Cargo.lock");
    println!("cargo:rerun-if-changed={}", lockfile.display());

    let lock = match std::fs::read_to_string(&lockfile) {
        Ok(s) => s,
        Err(_) => {
            // Lockfile not present (e.g. in a published crate). Skip the
            // guard rather than fail on environments we don't control.
            return;
        }
    };

    let ml_dsa_version = parse_locked_version(&lock, "ml-dsa");
    let ml_kem_version = parse_locked_version(&lock, "ml-kem");

    let strict =
        env::var("MILNET_MILITARY_DEPLOYMENT").as_deref() == Ok("1")
            || env::var("MILNET_REQUIRE_FIPS_VALIDATED_PQ").as_deref() == Ok("1");

    for (name, version) in [("ml-dsa", &ml_dsa_version), ("ml-kem", &ml_kem_version)] {
        let Some(v) = version else {
            if strict {
                panic!(
                    "[milnet build-guard] strict PQ build but `{}` not present in Cargo.lock",
                    name
                );
            }
            continue;
        };
        if is_prerelease(v) {
            if strict {
                panic!(
                    "[milnet build-guard] crate `{}` is at pre-release version `{}`. \
                     Strict (military / FIPS-validated) builds require a stable release. \
                     Upgrade `{}` in workspace Cargo.toml to a stable version.",
                    name, v, name
                );
            } else {
                println!(
                    "cargo:warning=[milnet] {} is a pre-release ({}) — not FIPS validated. \
                     Build will FAIL when MILNET_MILITARY_DEPLOYMENT=1 is set.",
                    name, v
                );
            }
        }
    }
}

/// Parse the version of a named package from Cargo.lock TOML.
fn parse_locked_version(lock: &str, package: &str) -> Option<String> {
    let needle = format!("name = \"{}\"", package);
    let mut iter = lock.split("[[package]]");
    while let Some(block) = iter.next() {
        if block.contains(&needle) {
            for line in block.lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("version = \"") {
                    if let Some(end) = rest.find('"') {
                        return Some(rest[..end].to_string());
                    }
                }
            }
        }
    }
    None
}

/// SemVer-aware pre-release detector. Anything containing `-` after the
/// numeric core (e.g. `0.1.0-rc.7`, `1.0.0-beta`) is pre-release. Stable
/// versions are `^[0-9]+(\.[0-9]+){0,2}$`.
fn is_prerelease(v: &str) -> bool {
    let core = v.split('+').next().unwrap_or(v);
    core.contains('-')
}
