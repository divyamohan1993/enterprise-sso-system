//! Exclusive XML Canonicalization 1.0 (W3C `xml-exc-c14n`) — the only
//! canonicalization algorithm we accept on the verifier side. SAML 2.0
//! mandates `xml-exc-c14n` for Web Browser SSO; inclusive C14N has known
//! pitfalls with namespace context that make it hostile in a federation.
//!
//! Implemented strictly per the spec, without comments
//! (http://www.w3.org/2001/10/xml-exc-c14n#). The differences from inclusive
//! C14N are:
//! - Only namespace declarations *visibly utilized* in the output subtree are
//!   emitted on each element.
//! - Default namespace inheritance is broken across the output root.
//! - An optional `InclusiveNamespaces/PrefixList` may force-include extra
//!   namespace declarations on the apex element.
//!
//! Output rules (the parts we implement):
//! 1. UTF-8 encoding, no BOM.
//! 2. Attribute values use double quotes; `<`, `&`, `"`, CR (`#xD`),
//!    `#x9`, `#xA` are escaped.
//! 3. Text node content escapes `<`, `>`, `&`, CR.
//! 4. Namespace declarations and attributes are sorted lexicographically:
//!    namespace decls first (sorted by local name with default first), then
//!    attributes by (namespace URI, local name).
//! 5. Empty elements are serialized as `<tag></tag>`.

use crate::dom::{Dom, Element, Node, NodeId};
use crate::SamlError;
use std::collections::BTreeMap;

/// Canonicalize the subtree rooted at `apex` per ExcC14N#WithoutComments.
/// `inclusive_prefixes` lists prefix names from `<InclusiveNamespaces/>`,
/// including the empty string for the default namespace.
pub fn exc_c14n(
    dom: &Dom,
    apex: NodeId,
    inclusive_prefixes: &[String],
) -> Result<Vec<u8>, SamlError> {
    let mut out: Vec<u8> = Vec::with_capacity(4096);
    // The visible utilized set is empty at the root of canonicalization —
    // ExcC14N does NOT inherit default namespace from outside.
    let rendered: BTreeMap<String, String> = BTreeMap::new();
    serialize(dom, apex, &rendered, inclusive_prefixes, true, &mut out)?;
    Ok(out)
}

fn serialize(
    dom: &Dom,
    nid: NodeId,
    rendered: &BTreeMap<String, String>,
    inclusive_prefixes: &[String],
    is_apex: bool,
    out: &mut Vec<u8>,
) -> Result<(), SamlError> {
    let e = dom.element(nid)?;

    // The element's own prefix is visibly utilized.
    let mut utilized_prefixes: Vec<String> = vec![e.prefix.clone()];
    // Each non-default-namespace attribute prefix is visibly utilized
    // (xmlns declarations are not counted as attributes here).
    for a in &e.attrs {
        if !a.prefix.is_empty() {
            utilized_prefixes.push(a.prefix.clone());
        }
    }
    // InclusiveNamespaces forces additional prefixes into the apex output.
    if is_apex {
        for p in inclusive_prefixes {
            utilized_prefixes.push(p.clone());
        }
    }
    utilized_prefixes.sort();
    utilized_prefixes.dedup();

    // Walk up the parent chain to compute the in-scope namespace bindings
    // so that each utilized prefix can be resolved to a URI.
    let in_scope = compute_in_scope_namespaces(dom, nid)?;

    // Determine which namespace declarations to emit at this element under
    // ExcC14N rules. A declaration is emitted if:
    //   (a) the prefix is visibly utilized in this element, AND
    //   (b) the URI differs from what the *output ancestor* (i.e. `rendered`)
    //       has currently bound for that prefix.
    let mut to_emit: BTreeMap<String, String> = BTreeMap::new();
    for pfx in &utilized_prefixes {
        let uri = in_scope.get(pfx).cloned().unwrap_or_default();
        // Default prefix: omit emission if URI is empty AND ancestor also
        // has nothing rendered (which is the case at the apex). Otherwise
        // emit `xmlns=""` to undeclare a previously rendered default.
        let prev = rendered.get(pfx).cloned();
        let needs = match (&prev, uri.as_str()) {
            (None, "") => false,
            (Some(p), u) if p == u => false,
            _ => true,
        };
        if needs {
            to_emit.insert(pfx.clone(), uri);
        }
    }

    // Compose the new rendered set for descendants.
    let mut child_rendered = rendered.clone();
    for (k, v) in &to_emit {
        child_rendered.insert(k.clone(), v.clone());
    }

    // Open tag.
    out.push(b'<');
    if !e.prefix.is_empty() {
        out.extend_from_slice(e.prefix.as_bytes());
        out.push(b':');
    }
    out.extend_from_slice(e.local.as_bytes());

    // Namespace declarations: default first (xmlns=""), then sorted by prefix.
    if let Some(uri) = to_emit.get("") {
        out.extend_from_slice(b" xmlns=\"");
        write_attr_escape(out, uri);
        out.push(b'"');
    }
    for (pfx, uri) in &to_emit {
        if pfx.is_empty() {
            continue;
        }
        out.extend_from_slice(b" xmlns:");
        out.extend_from_slice(pfx.as_bytes());
        out.extend_from_slice(b"=\"");
        write_attr_escape(out, uri);
        out.push(b'"');
    }

    // Real attributes: sorted by (namespace URI, local name). Attributes in
    // no namespace come first.
    let mut sorted_attrs = e.attrs.clone();
    sorted_attrs.sort_by(|a, b| {
        let ak = (a.ns.as_str(), a.local.as_str());
        let bk = (b.ns.as_str(), b.local.as_str());
        ak.cmp(&bk)
    });
    for a in &sorted_attrs {
        out.push(b' ');
        if !a.prefix.is_empty() {
            out.extend_from_slice(a.prefix.as_bytes());
            out.push(b':');
        }
        out.extend_from_slice(a.local.as_bytes());
        out.extend_from_slice(b"=\"");
        write_attr_escape(out, &a.value);
        out.push(b'"');
    }

    out.push(b'>');

    // Children. Comments were already dropped at parse time. Text nodes are
    // serialized with the text-escape rules; element children recurse.
    for &c in &e.children {
        match dom.node(c) {
            Node::Element(_) => {
                serialize(dom, c, &child_rendered, &[], false, out)?;
            }
            Node::Text(t) => {
                write_text_escape(out, t);
            }
        }
    }

    // Close tag.
    out.extend_from_slice(b"</");
    if !e.prefix.is_empty() {
        out.extend_from_slice(e.prefix.as_bytes());
        out.push(b':');
    }
    out.extend_from_slice(e.local.as_bytes());
    out.push(b'>');

    let _ = is_apex; // suppress unused warning in some configurations
    Ok(())
}

/// Walk parent chain and merge namespace declarations to produce the full
/// in-scope namespace map for this element. Closer ancestors win.
pub fn compute_in_scope_namespaces(
    dom: &Dom,
    nid: NodeId,
) -> Result<BTreeMap<String, String>, SamlError> {
    let mut chain: Vec<&Element> = Vec::new();
    let mut cur = Some(nid);
    while let Some(id) = cur {
        let e = dom.element(id)?;
        chain.push(e);
        cur = e.parent;
    }
    // Apply from outermost to innermost so inner overrides outer.
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    for e in chain.iter().rev() {
        for (k, v) in &e.ns_decls {
            map.insert(k.clone(), v.clone());
        }
    }
    Ok(map)
}

fn write_attr_escape(out: &mut Vec<u8>, s: &str) {
    for ch in s.chars() {
        match ch {
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '"' => out.extend_from_slice(b"&quot;"),
            '\t' => out.extend_from_slice(b"&#x9;"),
            '\n' => out.extend_from_slice(b"&#xA;"),
            '\r' => out.extend_from_slice(b"&#xD;"),
            _ => {
                let mut buf = [0u8; 4];
                let s = ch.encode_utf8(&mut buf);
                out.extend_from_slice(s.as_bytes());
            }
        }
    }
}

fn write_text_escape(out: &mut Vec<u8>, s: &str) {
    for ch in s.chars() {
        match ch {
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '>' => out.extend_from_slice(b"&gt;"),
            '\r' => out.extend_from_slice(b"&#xD;"),
            _ => {
                let mut buf = [0u8; 4];
                let s = ch.encode_utf8(&mut buf);
                out.extend_from_slice(s.as_bytes());
            }
        }
    }
}
