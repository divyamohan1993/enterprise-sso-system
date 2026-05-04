// X-J: KT must refuse `MILNET_KT_DEPLOYMENT_MODE=single` whenever
// `MILNET_MILITARY_DEPLOYMENT=1`. The single-host derivation of all 5
// signer keys defeats the 2-of-5 consensus property.
//
// Env-var tests must serialize because std::env globally mutates the process
// environment and tests run in parallel by default within a single test
// binary. We use serial_test on the workspace; this crate gets it via
// `kt`'s cfg(test) cluster — so we use a private serialization mutex here
// instead, to avoid pulling new deps for one test.

use kt::consensus::{select_deployment_mode, KtDeploymentMode, KtKeyError};
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct EnvGuard {
    keys: Vec<&'static str>,
}
impl EnvGuard {
    fn set(keys: &'static [(&'static str, Option<&'static str>)]) -> Self {
        let mut held = Vec::with_capacity(keys.len());
        for (k, v) in keys {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
            held.push(*k);
        }
        Self { keys: held }
    }
}
impl Drop for EnvGuard {
    fn drop(&mut self) {
        for k in &self.keys {
            std::env::remove_var(k);
        }
    }
}

#[test]
fn single_in_military_is_rejected() {
    let _g = ENV_LOCK.lock().unwrap();
    let _env = EnvGuard::set(&[
        ("MILNET_MILITARY_DEPLOYMENT", Some("1")),
        ("MILNET_KT_DEPLOYMENT_MODE", Some("single")),
    ]);
    let err = select_deployment_mode().expect_err("single+military must fail");
    assert!(
        matches!(err, KtKeyError::SingleInMilitary),
        "got {err:?}"
    );
}

#[test]
fn distributed_is_default_under_military() {
    let _g = ENV_LOCK.lock().unwrap();
    let _env = EnvGuard::set(&[
        ("MILNET_MILITARY_DEPLOYMENT", Some("1")),
        ("MILNET_KT_DEPLOYMENT_MODE", None),
    ]);
    let mode = select_deployment_mode().expect("military default ok");
    assert_eq!(mode, KtDeploymentMode::Distributed);
}

#[test]
fn single_outside_military_is_allowed() {
    let _g = ENV_LOCK.lock().unwrap();
    let _env = EnvGuard::set(&[
        ("MILNET_MILITARY_DEPLOYMENT", None),
        ("MILNET_KT_DEPLOYMENT_MODE", Some("single")),
    ]);
    let mode = select_deployment_mode().expect("dev single ok");
    assert_eq!(mode, KtDeploymentMode::Single);
}

#[test]
fn unknown_mode_is_rejected() {
    let _g = ENV_LOCK.lock().unwrap();
    let _env = EnvGuard::set(&[
        ("MILNET_MILITARY_DEPLOYMENT", None),
        ("MILNET_KT_DEPLOYMENT_MODE", Some("hybrid")),
    ]);
    let err = select_deployment_mode().expect_err("bogus mode rejected");
    assert!(matches!(err, KtKeyError::BadMode(_)));
}
