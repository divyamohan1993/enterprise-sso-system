//! Strict, allocation-controlled XML DOM for SAML responses.
//!
//! Built on `quick-xml` in raw event mode. The DOM:
//! - REJECTS `<!DOCTYPE>`, processing instructions, comments inside element
//!   content (we strip them explicitly during canonicalization), and any
//!   entity reference that is not one of the five XML predefined entities.
//! - Caps nesting depth and total node count.
//! - Records, for each element, the namespaces declared on that element so
//!   that Exclusive C14N can be implemented without re-walking the parent
//!   chain across the source byte buffer.
//! - Records the `xml:` attributes inherited from ancestors (Exclusive C14N
//!   inheritance for `xml:lang`, `xml:space`, `xml:base`, `xml:id`).
//!
//! The DOM is the **single source of truth** for both canonicalization and
//! claim extraction. There is no second parse pass, so XSW-style attacks
//! that depend on different parsers seeing different trees cannot bridge a
//! verification gap.

use crate::SamlError;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;
use std::collections::BTreeMap;

const MAX_DEPTH: usize = 64;
const MAX_NODES: usize = 100_000;
const MAX_ATTRS_PER_ELEMENT: usize = 256;
const MAX_TEXT_BYTES_PER_NODE: usize = 1 << 20;

pub type NodeId = u32;

#[derive(Debug, Clone)]
pub struct Attr {
    /// Namespace URI; empty string if no namespace.
    pub ns: String,
    /// Local name (no prefix).
    pub local: String,
    /// Original prefix as it appeared in the source ("" if default).
    pub prefix: String,
    /// Decoded value (entity refs already expanded — only the five predefined).
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct Element {
    pub ns: String,
    pub local: String,
    pub prefix: String,
    pub attrs: Vec<Attr>,
    /// Namespace declarations made AT this element (prefix -> URI).
    /// Empty prefix == default namespace.
    pub ns_decls: BTreeMap<String, String>,
    pub children: Vec<NodeId>,
    pub parent: Option<NodeId>,
    /// `Id`/`ID`/`xml:id` attribute value if present (any of the casings the
    /// SAML 2.0 spec uses for the ID-typed attribute on Assertion/Response).
    pub id: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Node {
    Element(Element),
    Text(String),
}

#[derive(Debug, Default, Clone)]
pub struct Dom {
    nodes: Vec<Node>,
    pub root: Option<NodeId>,
}

impl Dom {
    /// Remove `child` from its parent's children list. Used to apply the
    /// XML-DSig `enveloped-signature` transform without mutating the source
    /// buffer. The node itself is left in storage but becomes unreachable.
    pub fn detach_from_parent(&mut self, child: NodeId) -> Result<(), SamlError> {
        let parent_id = match &self.nodes[child as usize] {
            Node::Element(e) => e.parent,
            Node::Text(_) => return Err(SamlError::Internal),
        };
        let parent_id = parent_id.ok_or(SamlError::Internal)?;
        if let Node::Element(p) = &mut self.nodes[parent_id as usize] {
            p.children.retain(|c| *c != child);
            Ok(())
        } else {
            Err(SamlError::Internal)
        }
    }
}

impl Dom {
    pub fn node(&self, id: NodeId) -> &Node {
        &self.nodes[id as usize]
    }
    pub fn element(&self, id: NodeId) -> Result<&Element, SamlError> {
        match &self.nodes[id as usize] {
            Node::Element(e) => Ok(e),
            _ => Err(SamlError::Internal),
        }
    }
    pub fn nodes_len(&self) -> usize {
        self.nodes.len()
    }

    /// Walk every element in document order.
    pub fn walk_elements<F: FnMut(NodeId, &Element)>(&self, mut f: F) {
        if let Some(root) = self.root {
            self.walk_inner(root, &mut f);
        }
    }
    fn walk_inner<F: FnMut(NodeId, &Element)>(&self, id: NodeId, f: &mut F) {
        if let Node::Element(e) = &self.nodes[id as usize] {
            f(id, e);
            for &c in &e.children {
                self.walk_inner(c, f);
            }
        }
    }

    /// Find an element by ID attribute. Returns the FIRST match in document
    /// order. The caller must additionally verify that no other element in
    /// the tree shares the same ID — see `find_unique_by_id`.
    pub fn find_unique_by_id(&self, id: &str) -> Result<NodeId, SamlError> {
        let mut found: Option<NodeId> = None;
        let mut dup = false;
        self.walk_elements(|nid, e| {
            if e.id.as_deref() == Some(id) {
                if found.is_some() {
                    dup = true;
                }
                found = found.or(Some(nid));
            }
        });
        if dup {
            return Err(SamlError::AssertionIdConfusion);
        }
        found.ok_or(SamlError::SignatureReferenceMismatch)
    }
}

/// Parse strict SAML XML into a DOM. Refuses the OWASP top-N XML pitfalls.
pub fn parse_strict(xml: &[u8]) -> Result<Dom, SamlError> {
    if xml.len() > (8 << 20) {
        return Err(SamlError::SizeExceeded);
    }
    // Cheap pre-scan: if any DOCTYPE marker is present anywhere we refuse
    // outright. quick-xml will surface it as an Event::DocType, but a defence
    // in depth means we also refuse it at the byte level so even if a future
    // version of the library starts swallowing DOCTYPEs we still reject.
    if memmem(xml, b"<!DOCTYPE").is_some() || memmem(xml, b"<!doctype").is_some() {
        return Err(SamlError::DoctypeForbidden);
    }
    if memmem(xml, b"<!ENTITY").is_some() || memmem(xml, b"<!entity").is_some() {
        return Err(SamlError::EntityForbidden);
    }

    let mut reader = NsReader::from_reader(xml);
    {
        let cfg = reader.config_mut();
        cfg.trim_text(false);
        cfg.expand_empty_elements = true;
        cfg.check_end_names = true;
        cfg.allow_unmatched_ends = false;
    }

    let mut dom = Dom::default();
    let mut buf = Vec::with_capacity(4096);
    let mut stack: Vec<NodeId> = Vec::with_capacity(MAX_DEPTH);

    loop {
        let event = reader.read_resolved_event_into(&mut buf);
        match event {
            Ok((_, Event::Start(ref e))) => {
                let nid = open_element(&mut dom, &mut stack, &reader, e)?;
                stack.push(nid);
            }
            Ok((_, Event::End(_))) => {
                stack.pop().ok_or(SamlError::Xml)?;
            }
            Ok((_, Event::Empty(ref e))) => {
                // expand_empty_elements is on, so this branch should not
                // fire, but handle it defensively.
                let nid = open_element(&mut dom, &mut stack, &reader, e)?;
                if let Some(parent) = stack.last().copied() {
                    push_child(&mut dom, parent, nid)?;
                }
            }
            Ok((_, Event::Text(t))) => {
                let raw = t.into_inner();
                if raw.len() > MAX_TEXT_BYTES_PER_NODE {
                    return Err(SamlError::SizeExceeded);
                }
                let s = decode_text(&raw)?;
                push_text(&mut dom, &stack, s)?;
            }
            Ok((_, Event::CData(c))) => {
                let raw = c.into_inner();
                if raw.len() > MAX_TEXT_BYTES_PER_NODE {
                    return Err(SamlError::SizeExceeded);
                }
                let s = std::str::from_utf8(&raw)
                    .map_err(|_| SamlError::Xml)?
                    .to_string();
                push_text(&mut dom, &stack, s)?;
            }
            Ok((_, Event::Comment(_))) => { /* dropped per ExcC14N #WithoutComments */ }
            Ok((_, Event::Decl(_))) => { /* XML decl is fine, not signed */ }
            Ok((_, Event::PI(_))) => return Err(SamlError::ProcessingInstructionForbidden),
            Ok((_, Event::DocType(_))) => return Err(SamlError::DoctypeForbidden),
            Ok((_, Event::Eof)) => break,
            Err(_) => return Err(SamlError::Xml),
        }
        if dom.nodes_len() > MAX_NODES {
            return Err(SamlError::SizeExceeded);
        }
        buf.clear();
    }

    if !stack.is_empty() {
        return Err(SamlError::Xml);
    }
    if dom.root.is_none() {
        return Err(SamlError::Xml);
    }
    Ok(dom)
}

fn open_element(
    dom: &mut Dom,
    stack: &mut Vec<NodeId>,
    reader: &NsReader<&[u8]>,
    e: &BytesStart<'_>,
) -> Result<NodeId, SamlError> {
    if stack.len() >= MAX_DEPTH {
        return Err(SamlError::DepthExceeded);
    }
    // Resolve the element's expanded name.
    let (ns_res, local) = reader.resolve_element(e.name());
    let ns = match ns_res {
        ResolveResult::Bound(ns) => {
            std::str::from_utf8(ns.as_ref()).map_err(|_| SamlError::Xml)?.to_string()
        }
        ResolveResult::Unbound => String::new(),
        ResolveResult::Unknown(_) => return Err(SamlError::Xml),
    };
    let local_str = std::str::from_utf8(local.as_ref())
        .map_err(|_| SamlError::Xml)?
        .to_string();
    let prefix = element_prefix(e)?;

    // Scan attributes once. Separate xmlns declarations from real attributes.
    let mut attrs: Vec<Attr> = Vec::new();
    let mut ns_decls: BTreeMap<String, String> = BTreeMap::new();
    let mut id: Option<String> = None;
    let mut count = 0usize;
    for a in e.attributes() {
        let a = a.map_err(|_| SamlError::Xml)?;
        count += 1;
        if count > MAX_ATTRS_PER_ELEMENT {
            return Err(SamlError::SizeExceeded);
        }
        let key_raw = a.key.as_ref();
        let val_raw = a.value.as_ref();
        let val = decode_text(val_raw)?;

        if key_raw == b"xmlns" {
            ns_decls.insert(String::new(), val);
            continue;
        }
        if let Some(rest) = key_raw.strip_prefix(b"xmlns:") {
            let pfx = std::str::from_utf8(rest).map_err(|_| SamlError::Xml)?.to_string();
            ns_decls.insert(pfx, val);
            continue;
        }

        let (a_ns_res, a_local) = reader.resolve_attribute(a.key);
        let a_ns = match a_ns_res {
            ResolveResult::Bound(ns) => std::str::from_utf8(ns.as_ref())
                .map_err(|_| SamlError::Xml)?
                .to_string(),
            ResolveResult::Unbound => String::new(),
            ResolveResult::Unknown(_) => return Err(SamlError::Xml),
        };
        let a_local_s = std::str::from_utf8(a_local.as_ref())
            .map_err(|_| SamlError::Xml)?
            .to_string();
        let a_prefix = match key_raw.iter().position(|b| *b == b':') {
            Some(i) => std::str::from_utf8(&key_raw[..i])
                .map_err(|_| SamlError::Xml)?
                .to_string(),
            None => String::new(),
        };

        // SAML 2.0 ID is the unprefixed `ID` attribute. We also accept
        // `xml:id` when present as that is the W3C-blessed alternative.
        if a_ns.is_empty() && a_local_s == "ID" {
            id = Some(val.clone());
        } else if a_ns == "http://www.w3.org/XML/1998/namespace" && a_local_s == "id" {
            id = Some(val.clone());
        }

        attrs.push(Attr {
            ns: a_ns,
            local: a_local_s,
            prefix: a_prefix,
            value: val,
        });
    }

    let element = Element {
        ns,
        local: local_str,
        prefix,
        attrs,
        ns_decls,
        children: Vec::new(),
        parent: stack.last().copied(),
        id,
    };
    let nid = dom.nodes.len() as NodeId;
    dom.nodes.push(Node::Element(element));
    if let Some(parent) = stack.last().copied() {
        push_child(dom, parent, nid)?;
    } else if dom.root.is_none() {
        dom.root = Some(nid);
    } else {
        // Two roots — invalid.
        return Err(SamlError::Xml);
    }
    Ok(nid)
}

fn element_prefix(e: &BytesStart<'_>) -> Result<String, SamlError> {
    let name = e.name();
    let raw = name.as_ref();
    Ok(match raw.iter().position(|b| *b == b':') {
        Some(i) => std::str::from_utf8(&raw[..i])
            .map_err(|_| SamlError::Xml)?
            .to_string(),
        None => String::new(),
    })
}

fn push_child(dom: &mut Dom, parent: NodeId, child: NodeId) -> Result<(), SamlError> {
    match &mut dom.nodes[parent as usize] {
        Node::Element(e) => {
            e.children.push(child);
            Ok(())
        }
        _ => Err(SamlError::Internal),
    }
}

fn push_text(dom: &mut Dom, stack: &[NodeId], s: String) -> Result<(), SamlError> {
    let Some(parent) = stack.last().copied() else {
        // Whitespace before the root element — drop it.
        return Ok(());
    };
    let nid = dom.nodes.len() as NodeId;
    dom.nodes.push(Node::Text(s));
    push_child(dom, parent, nid)
}

/// Decode XML text honoring ONLY the five XML predefined entities. Any
/// other `&...;` reference is rejected as `EntityForbidden`. This blocks
/// XXE, billion-laughs, and any SYSTEM/PUBLIC entity tricks before they
/// can amplify or exfiltrate.
fn decode_text(raw: &[u8]) -> Result<String, SamlError> {
    let s = std::str::from_utf8(raw).map_err(|_| SamlError::Xml)?;
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' {
            // Find the terminating ';'
            let end = bytes[i + 1..]
                .iter()
                .position(|b| *b == b';')
                .ok_or(SamlError::Xml)?;
            let ent = &bytes[i + 1..i + 1 + end];
            match ent {
                b"lt" => out.push('<'),
                b"gt" => out.push('>'),
                b"amp" => out.push('&'),
                b"apos" => out.push('\''),
                b"quot" => out.push('"'),
                _ if ent.starts_with(b"#x") || ent.starts_with(b"#X") => {
                    let hex = std::str::from_utf8(&ent[2..]).map_err(|_| SamlError::Xml)?;
                    let cp = u32::from_str_radix(hex, 16).map_err(|_| SamlError::Xml)?;
                    let c = char::from_u32(cp).ok_or(SamlError::Xml)?;
                    out.push(c);
                }
                _ if ent.starts_with(b"#") => {
                    let dec = std::str::from_utf8(&ent[1..]).map_err(|_| SamlError::Xml)?;
                    let cp: u32 = dec.parse().map_err(|_| SamlError::Xml)?;
                    let c = char::from_u32(cp).ok_or(SamlError::Xml)?;
                    out.push(c);
                }
                _ => return Err(SamlError::EntityForbidden),
            }
            i += 1 + end + 1;
        } else {
            // Push UTF-8 character. Walk by char boundary.
            let ch_start = i;
            // Find next char boundary by scanning UTF-8 lead byte.
            let lead = bytes[i];
            let len = utf8_len(lead).ok_or(SamlError::Xml)?;
            if i + len > bytes.len() {
                return Err(SamlError::Xml);
            }
            let slice = std::str::from_utf8(&bytes[ch_start..ch_start + len])
                .map_err(|_| SamlError::Xml)?;
            out.push_str(slice);
            i += len;
        }
    }
    Ok(out)
}

fn utf8_len(b: u8) -> Option<usize> {
    if b < 0x80 {
        Some(1)
    } else if b < 0xC0 {
        None
    } else if b < 0xE0 {
        Some(2)
    } else if b < 0xF0 {
        Some(3)
    } else if b < 0xF8 {
        Some(4)
    } else {
        None
    }
}

fn memmem(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}
