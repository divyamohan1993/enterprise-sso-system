//! SC-MAP-TIMING lint: forbid `HashMap<Secret, _>` and `HashMap<_, Secret>`.
//!
//! Hashing on secret content lets an attacker measure SipHash collision
//! timing as a side-channel. Use `BTreeMap` (constant-time-ish ordering)
//! or an `IndexMap` with a fixed deterministic hasher seeded outside the
//! secret domain. If a hash-keyed lookup is unavoidable, derive the key
//! via HKDF first (the kid lookup pattern).

use std::path::Path;

fn walk_rs_files(dir: &Path, sink: &mut Vec<std::path::PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Skip target/ and build artefact dirs.
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if matches!(name, "target" | ".git" | "node_modules" | "fuzz") {
                continue;
            }
            walk_rs_files(&path, sink);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            sink.push(path);
        }
    }
}

#[test]
fn forbid_hashmap_keyed_on_secret() {
    // Walk the workspace from the parent of `common/`.
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("common has a parent (workspace root)");

    let mut files = Vec::new();
    walk_rs_files(workspace_root, &mut files);

    // Pattern: `HashMap<...Secret...,` or `HashMap<..., ...Secret...>`.
    // We deliberately use a coarse substring match so we catch
    // `HashMap<SecretKey, _>`, `HashMap<&Secret, _>`, etc.
    let mut violations: Vec<String> = Vec::new();
    for path in &files {
        // Skip this lint file itself so the patterns below don't self-match.
        if path.file_name().and_then(|s| s.to_str()) == Some("no_secret_hashmap_lint.rs") {
            continue;
        }
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for (lineno, line) in content.lines().enumerate() {
            let l = line.trim();
            if l.starts_with("//") || l.starts_with("///") || l.starts_with("*") {
                continue;
            }
            if l.contains("HashMap<") && l.contains("Secret") {
                violations.push(format!("{}:{}: {}", path.display(), lineno + 1, line.trim()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "SC-MAP-TIMING: {} HashMap<Secret,_> usage(s) found — use BTreeMap or HKDF-derived kid:\n{}",
        violations.len(),
        violations.join("\n"),
    );
}
