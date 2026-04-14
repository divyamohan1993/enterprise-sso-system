//! G13: enforce that EVERY pub struct in `common/src/` that derives
//! `serde::Deserialize` is also annotated with `#[serde(deny_unknown_fields)]`.
//!
//! Why: lenient deserialisation lets a forged or rolled-back payload smuggle
//! extra fields that one part of the system silently ignores while another
//! part trusts. Strict rejection is the only safe default for a system whose
//! threat model includes adversarial DTOs over the wire and at rest.
//!
//! How: this test parses every `.rs` file under `common/src/` with `syn`
//! and walks the AST. For every `ItemStruct` that
//!   1. has `pub` visibility,
//!   2. derives `Deserialize` (anywhere in any `derive(...)` attribute),
//!   3. is NOT a unit struct (`struct Foo;`) or tuple struct (`struct Foo(T);`)
//!      — those have no named fields, so the attribute would be a no-op,
//! the test asserts that the same struct carries `#[serde(deny_unknown_fields)]`
//! among its outer attributes. Failures are reported with the file:line
//! location of every offending struct.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use syn::{visit::Visit, Fields, ItemStruct, Visibility};

struct Violation {
    file: PathBuf,
    name: String,
}

struct Checker {
    file: PathBuf,
    violations: Vec<Violation>,
}

fn derives_deserialize(s: &ItemStruct) -> bool {
    for attr in &s.attrs {
        if !attr.path().is_ident("derive") {
            continue;
        }
        // Walk the tokens textually — this catches both `Deserialize` and
        // `serde::Deserialize` regardless of import style.
        let toks = attr.to_token_stream().to_string();
        if toks.contains("Deserialize") {
            return true;
        }
    }
    false
}

fn has_deny_unknown(s: &ItemStruct) -> bool {
    for attr in &s.attrs {
        if !attr.path().is_ident("serde") {
            continue;
        }
        let toks = attr.to_token_stream().to_string();
        if toks.contains("deny_unknown_fields") {
            return true;
        }
    }
    false
}

use quote::ToTokens;

impl<'ast> Visit<'ast> for Checker {
    fn visit_item_struct(&mut self, s: &'ast ItemStruct) {
        let is_pub = matches!(s.vis, Visibility::Public(_));
        if !is_pub {
            return;
        }
        // Skip unit and tuple structs — `deny_unknown_fields` is only
        // meaningful for structs with named fields.
        if !matches!(s.fields, Fields::Named(_)) {
            return;
        }
        if !derives_deserialize(s) {
            return;
        }
        if has_deny_unknown(s) {
            return;
        }
        // proc-macro2 Span::start().line is gated behind procmacro2_semver_exempt
        // on stable; report file + struct name only.
        self.violations.push(Violation {
            file: self.file.clone(),
            name: s.ident.to_string(),
        });
    }
}

fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return,
    };
    for entry in read.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_rust_files(&p, out);
        } else if p.extension().map(|e| e == "rs").unwrap_or(false) {
            out.push(p);
        }
    }
}

#[test]
fn every_pub_deserialize_struct_has_deny_unknown_fields() {
    // common/src lives at $CARGO_MANIFEST_DIR/src.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let src_dir = Path::new(manifest_dir).join("src");
    assert!(
        src_dir.is_dir(),
        "expected common/src to exist at {}",
        src_dir.display()
    );

    let mut files = Vec::new();
    collect_rust_files(&src_dir, &mut files);
    assert!(!files.is_empty(), "no .rs files found under common/src");

    let mut all_violations: Vec<Violation> = Vec::new();
    for f in &files {
        let src = match std::fs::read_to_string(f) {
            Ok(s) => s,
            Err(e) => panic!("read {}: {e}", f.display()),
        };
        let parsed = match syn::parse_file(&src) {
            Ok(p) => p,
            Err(e) => panic!("parse {}: {e}", f.display()),
        };
        let mut checker = Checker {
            file: f.clone(),
            violations: Vec::new(),
        };
        checker.visit_file(&parsed);
        all_violations.extend(checker.violations);
    }

    if !all_violations.is_empty() {
        let mut msg = String::from(
            "G13: the following pub Deserialize-deriving structs are missing \
             #[serde(deny_unknown_fields)]:\n",
        );
        for v in &all_violations {
            msg.push_str(&format!("  {} -- {}\n", v.file.display(), v.name));
        }
        panic!("{msg}");
    }
}
