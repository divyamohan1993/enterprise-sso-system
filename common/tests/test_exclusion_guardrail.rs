//! Test-exclusion guardrail.
//!
//! Walks the workspace and fails if any `#[ignore]` test, `.disabled` test file,
//! or `required-features`-gated test target exists outside `ignore_allowlist.toml`.
//!
//! Rationale: silent test exclusions rot. Every exclusion must carry a citation
//! (reason + audit date) in the allowlist. Adding one requires a code review.

use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Deserialize)]
struct Allowlist {
    #[allow(dead_code)]
    schema_version: u32,
    #[serde(default)]
    ignored: Vec<IgnoredEntry>,
    #[serde(default)]
    disabled_files: Vec<DisabledEntry>,
}

#[derive(Debug, Deserialize)]
struct IgnoredEntry {
    file: String,
    test: String,
    #[allow(dead_code)]
    reason: String,
    #[allow(dead_code)]
    audit: String,
}

#[derive(Debug, Deserialize)]
struct DisabledEntry {
    path: String,
    #[allow(dead_code)]
    reason: String,
    #[allow(dead_code)]
    audit: String,
}

fn workspace_root() -> PathBuf {
    // common/ is directly under workspace root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("common/ must have a parent (workspace root)")
        .to_path_buf()
}

fn is_skipped(path: &Path) -> bool {
    for comp in path.components() {
        let s = comp.as_os_str();
        if s == "target" || s == ".git" || s == ".claude" || s == "node_modules" {
            return true;
        }
    }
    false
}

fn rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Find all `#[ignore]`-annotated test functions under any `/tests/` directory.
/// Returns (relative_file, test_name) tuples.
fn find_ignored_tests(root: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if is_skipped(path) {
            continue;
        }
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let rel_path = rel(root, path);
        if !rel_path.contains("/tests/") {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(path) else {
            continue;
        };
        let lines: Vec<&str> = src.lines().collect();
        let mut i = 0;
        while i < lines.len() {
            let trimmed = lines[i].trim_start();
            if trimmed.starts_with("#[ignore]") || trimmed.starts_with("#[ignore ") || trimmed.starts_with("#[ignore=") {
                // Scan forward for next `fn NAME`, skipping attribute lines.
                let mut j = i + 1;
                let mut name: Option<String> = None;
                while j < lines.len() {
                    let t = lines[j].trim_start();
                    if t.is_empty() || t.starts_with("//") || t.starts_with("#[") || t.starts_with("#![") {
                        j += 1;
                        continue;
                    }
                    if let Some(rest) = t.strip_prefix("pub ") {
                        if let Some(after) = rest.trim_start().strip_prefix("fn ") {
                            name = Some(extract_fn_name(after));
                        }
                    } else if let Some(after) = t.strip_prefix("fn ") {
                        name = Some(extract_fn_name(after));
                    } else if let Some(after) = t.strip_prefix("async fn ") {
                        name = Some(extract_fn_name(after));
                    }
                    break;
                }
                if let Some(n) = name {
                    out.push((rel_path.clone(), n));
                }
            }
            i += 1;
        }
    }
    out.sort();
    out
}

fn extract_fn_name(after_fn: &str) -> String {
    after_fn
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect()
}

fn find_disabled_files(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if is_skipped(path) {
            continue;
        }
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("disabled") {
            continue;
        }
        let r = rel(root, path);
        if r.contains("/tests/") {
            out.push(r);
        }
    }
    out.sort();
    out
}

#[derive(Debug, Deserialize)]
struct CargoToml {
    #[serde(default, rename = "test")]
    tests: Vec<TestTarget>,
}

#[derive(Debug, Deserialize)]
struct TestTarget {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "required-features")]
    required_features: Option<Vec<String>>,
}

fn find_required_feature_tests(root: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if is_skipped(path) {
            continue;
        }
        if !path.is_file() || path.file_name().and_then(|n| n.to_str()) != Some("Cargo.toml") {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(path) else {
            continue;
        };
        let Ok(parsed) = toml::from_str::<CargoToml>(&src) else {
            continue;
        };
        for t in parsed.tests {
            if t.required_features.is_some() {
                let name = t.name.unwrap_or_else(|| "<unnamed>".into());
                out.push((rel(root, path), name));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn no_unexpected_test_exclusions() {
    let root = workspace_root();
    let allowlist_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("ignore_allowlist.toml");
    let allowlist_src = std::fs::read_to_string(&allowlist_path)
        .unwrap_or_else(|e| panic!("cannot read allowlist at {}: {e}", allowlist_path.display()));
    let allow: Allowlist = toml::from_str(&allowlist_src)
        .unwrap_or_else(|e| panic!("allowlist parse error: {e}"));

    let allowed_ignored: HashSet<(String, String)> = allow
        .ignored
        .iter()
        .map(|e| (e.file.clone(), e.test.clone()))
        .collect();
    let allowed_disabled: HashSet<String> =
        allow.disabled_files.iter().map(|e| e.path.clone()).collect();

    let found_ignored = find_ignored_tests(&root);
    let found_disabled = find_disabled_files(&root);
    let found_reqfeat = find_required_feature_tests(&root);

    let mut violations: Vec<String> = Vec::new();

    for entry in &found_ignored {
        if !allowed_ignored.contains(entry) {
            violations.push(format!(
                "unlisted #[ignore] test: {}::{}",
                entry.0, entry.1
            ));
        }
    }
    for path in &found_disabled {
        if !allowed_disabled.contains(path) {
            violations.push(format!("unlisted .disabled test file: {path}"));
        }
    }
    for (manifest, name) in &found_reqfeat {
        violations.push(format!(
            "unlisted required-features test target: {manifest} -> [[test]] {name}"
        ));
    }

    // Also fail if allowlist has stale entries pointing at nothing (drift cleanup).
    let found_ignored_set: HashSet<(String, String)> = found_ignored.iter().cloned().collect();
    for entry in &allowed_ignored {
        if !found_ignored_set.contains(entry) {
            violations.push(format!(
                "stale allowlist entry (no matching #[ignore] found): {}::{}",
                entry.0, entry.1
            ));
        }
    }
    let found_disabled_set: HashSet<String> = found_disabled.iter().cloned().collect();
    for p in &allowed_disabled {
        if !found_disabled_set.contains(p) {
            violations.push(format!(
                "stale allowlist entry (no matching .disabled file): {p}"
            ));
        }
    }

    if !violations.is_empty() {
        let mut msg = String::from("\ntest-exclusion guardrail FAILED:\n");
        for v in &violations {
            msg.push_str("  - ");
            msg.push_str(v);
            msg.push('\n');
        }
        msg.push_str(
            "\nhint: add an entry to common/tests/ignore_allowlist.toml with reason+audit,\n\
             or remove the #[ignore]/.disabled/required-features exclusion.\n",
        );
        panic!("{msg}");
    }
}
