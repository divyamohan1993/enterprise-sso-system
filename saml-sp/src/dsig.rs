//! XML-DSig validation for SAML 2.0 — tightly scoped to the algorithms we
//! permit. Permitted set:
//!
//! Canonicalization:    `http://www.w3.org/2001/10/xml-exc-c14n#`
//! Transforms:          `enveloped-signature`, `xml-exc-c14n#`
//! Digest:              `http://www.w3.org/2001/04/xmlenc#sha256`
//! Signature:           `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`
//!                      `http://www.w3.org/2007/05/xmldsig-more#mldsa87`
//!
//! Forbidden algorithms result in `*Forbidden` errors. SHA-1, MD5, RSA-SHA1,
//! C14N (inclusive), and any unknown URI are categorically rejected.

use crate::c14n::exc_c14n;
use crate::dom::{Dom, Element, Node, NodeId};
use crate::trust::{KeyAlg, TrustAnchor};
use crate::SamlError;
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const NS_DS: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const ALG_C14N_EXC: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
pub const ALG_TRANSFORM_ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
pub const ALG_DIGEST_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
pub const ALG_SIG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
pub const ALG_SIG_ML_DSA_87: &str = "http://www.w3.org/2007/05/xmldsig-more#mldsa87";

/// What a successfully verified XML-DSig binds.
#[derive(Debug, Clone)]
pub struct VerifiedSignature {
    /// The DOM node ID of the assertion the signature actually covered.
    pub signed_assertion: NodeId,
    /// The signature algorithm URI that was used.
    pub sig_alg: String,
    /// Issuer (subject CN/DN) of the trust anchor that verified the signature.
    pub trust_anchor_subject: String,
}

/// Find every `<ds:Signature>` element whose Reference URI points to the
/// candidate `assertion_id`. Reject if zero or more than one. The returned
/// signature node ID is the unique signature that protects the assertion.
fn find_unique_signature_for(
    dom: &Dom,
    assertion_id: &str,
) -> Result<NodeId, SamlError> {
    let mut hits: Vec<NodeId> = Vec::new();
    dom.walk_elements(|nid, e| {
        if e.ns == NS_DS && e.local == "Signature" {
            if let Some(reference) = find_child(dom, nid, NS_DS, "SignedInfo")
                .and_then(|si| find_child(dom, si, NS_DS, "Reference"))
            {
                if let Ok(ref_el) = dom.element(reference) {
                    if let Some(uri) = attr_value(ref_el, "", "URI") {
                        if let Some(stripped) = uri.strip_prefix('#') {
                            if stripped == assertion_id {
                                hits.push(nid);
                            }
                        }
                    }
                }
            }
        }
    });
    match hits.len() {
        1 => Ok(hits[0]),
        0 => Err(SamlError::SignatureCardinality),
        _ => Err(SamlError::SignatureCardinality),
    }
}

/// Count total `<ds:Signature>` elements anywhere in the document — used to
/// enforce that only ONE signature exists, which kills several XSW variants
/// that paper over an unsigned attacker assertion with a signature elsewhere.
pub fn count_signatures(dom: &Dom) -> usize {
    let mut n = 0usize;
    dom.walk_elements(|_, e| {
        if e.ns == NS_DS && e.local == "Signature" {
            n += 1;
        }
    });
    n
}

/// Count `<saml:Assertion>` elements anywhere in the document.
pub fn count_assertions(dom: &Dom) -> usize {
    let mut n = 0usize;
    dom.walk_elements(|_, e| {
        if e.ns == "urn:oasis:names:tc:SAML:2.0:assertion" && e.local == "Assertion" {
            n += 1;
        }
    });
    n
}

/// Find the unique top-level `<saml:Assertion>` and return its node ID +
/// its `ID` attribute. Errors if there is not exactly one.
pub fn unique_assertion(dom: &Dom) -> Result<(NodeId, String), SamlError> {
    let mut hits: Vec<NodeId> = Vec::new();
    dom.walk_elements(|nid, e| {
        if e.ns == "urn:oasis:names:tc:SAML:2.0:assertion" && e.local == "Assertion" {
            hits.push(nid);
        }
    });
    if hits.len() != 1 {
        return Err(SamlError::AssertionCardinality);
    }
    let id = dom
        .element(hits[0])?
        .id
        .clone()
        .ok_or(SamlError::SignatureReferenceMismatch)?;
    Ok((hits[0], id))
}

/// Verify the unique XML-DSig that protects the unique assertion.
pub fn verify(
    dom: &Dom,
    trust: &dyn TrustAnchor,
    issuer_entity_id: &str,
) -> Result<VerifiedSignature, SamlError> {
    if count_assertions(dom) != 1 {
        return Err(SamlError::AssertionCardinality);
    }
    if count_signatures(dom) != 1 {
        return Err(SamlError::SignatureCardinality);
    }
    let (assertion_node, assertion_id) = unique_assertion(dom)?;
    // Cross-check: the assertion ID must be unique in the entire DOM.
    let _ = dom.find_unique_by_id(&assertion_id)?;

    let sig_node = find_unique_signature_for(dom, &assertion_id)?;
    // The signature must be a child of the assertion (enveloped) — anywhere
    // else is non-conforming for SAML 2.0 and a known XSW vector.
    let sig_el = dom.element(sig_node)?;
    if sig_el.parent != Some(assertion_node) {
        return Err(SamlError::SignatureReferenceMismatch);
    }

    let signed_info_node = find_child(dom, sig_node, NS_DS, "SignedInfo")
        .ok_or(SamlError::Xml)?;
    let sig_value_node = find_child(dom, sig_node, NS_DS, "SignatureValue")
        .ok_or(SamlError::Xml)?;
    let key_info_node = find_child(dom, sig_node, NS_DS, "KeyInfo")
        .ok_or(SamlError::Xml)?;

    let signed_info = dom.element(signed_info_node)?;
    let canon_alg_node = find_child(dom, signed_info_node, NS_DS, "CanonicalizationMethod")
        .ok_or(SamlError::Xml)?;
    let canon_alg = attr_value(dom.element(canon_alg_node)?, "", "Algorithm")
        .ok_or(SamlError::Xml)?;
    if canon_alg != ALG_C14N_EXC {
        return Err(SamlError::CanonicalizationAlgorithmForbidden);
    }
    let sig_method_node = find_child(dom, signed_info_node, NS_DS, "SignatureMethod")
        .ok_or(SamlError::Xml)?;
    let sig_alg = attr_value(dom.element(sig_method_node)?, "", "Algorithm")
        .ok_or(SamlError::Xml)?;
    if sig_alg != ALG_SIG_RSA_SHA256 && sig_alg != ALG_SIG_ML_DSA_87 {
        return Err(SamlError::SignatureAlgorithmForbidden);
    }

    let reference_node = find_child(dom, signed_info_node, NS_DS, "Reference")
        .ok_or(SamlError::Xml)?;
    let reference = dom.element(reference_node)?;
    let uri = attr_value(reference, "", "URI").ok_or(SamlError::Xml)?;
    if uri.strip_prefix('#') != Some(assertion_id.as_str()) {
        return Err(SamlError::SignatureReferenceMismatch);
    }

    // Validate transforms: must be exactly enveloped-signature followed by
    // exclusive C14N (the SAML 2.0 mandated chain).
    let transforms_node = find_child(dom, reference_node, NS_DS, "Transforms")
        .ok_or(SamlError::Xml)?;
    validate_transform_chain(dom, transforms_node)?;

    let digest_method_node = find_child(dom, reference_node, NS_DS, "DigestMethod")
        .ok_or(SamlError::Xml)?;
    let digest_alg = attr_value(dom.element(digest_method_node)?, "", "Algorithm")
        .ok_or(SamlError::Xml)?;
    if digest_alg != ALG_DIGEST_SHA256 {
        return Err(SamlError::DigestAlgorithmForbidden);
    }
    let digest_value_node = find_child(dom, reference_node, NS_DS, "DigestValue")
        .ok_or(SamlError::Xml)?;
    let digest_value_b64 = collect_text(dom, digest_value_node);
    let expected_digest = STANDARD
        .decode(digest_value_b64.trim().as_bytes())
        .map_err(|_| SamlError::Xml)?;

    // Apply the enveloped-signature transform: drop the <ds:Signature> from
    // the assertion subtree before canonicalization. We do this by passing a
    // filtering walker — the simplest way is to clone the DOM and drop the
    // signature child, but we can also detect the signature node during c14n.
    // Use a temporary DOM rewrite via a minimal helper.
    let canonical = canonicalize_with_signature_removed(dom, assertion_node, sig_node)?;

    let actual_digest = Sha256::digest(&canonical);
    if !bool::from(actual_digest.as_slice().ct_eq(&expected_digest)) {
        return Err(SamlError::DigestMismatch);
    }

    // Canonicalize SignedInfo. Inclusive prefixes from
    // <ec:InclusiveNamespaces PrefixList="..."/> inside CanonicalizationMethod
    // are honored.
    let inc_prefixes = inclusive_prefixes(dom, canon_alg_node);
    let canonical_si = exc_c14n(dom, signed_info_node, &inc_prefixes)?;

    let sig_value_b64 = collect_text(dom, sig_value_node);
    let sig_bytes = STANDARD
        .decode(sig_value_b64.trim().as_bytes())
        .map_err(|_| SamlError::Xml)?;

    // <KeyInfo> is informational. Trust comes from the pinned material for
    // the validated `issuer_entity_id`. We deliberately do NOT consult any
    // certificate that the response itself supplies for trust decisions.
    let _key_info_certs = extract_x509_certs(dom, key_info_node)?;
    let pinned = trust.resolve(issuer_entity_id)?;

    if sig_alg == ALG_SIG_RSA_SHA256 {
        if pinned.alg != KeyAlg::Rsa {
            return Err(SamlError::PublicKeyUnsupported);
        }
        // RS256 verify via aws-lc-rs (constant-time, FIPS-validated).
        // Replaces the prior `rsa` crate path which carried RUSTSEC-2023-0071
        // (Marvin timing channel). The pinned material is already SPKI DER.
        rsa_verify_shim::verify_rs256_spki_der(
            &pinned.spki_der,
            &canonical_si,
            sig_bytes.as_slice(),
        )
        .map_err(|_| SamlError::SignatureInvalid)?;
    } else if sig_alg == ALG_SIG_ML_DSA_87 {
        // ML-DSA pinned material: the raw `EncodedVerifyingKey<MlDsa87>` bytes
        // are stored in `spki_der` (storage uniformity with the X.509 path).
        if pinned.alg != KeyAlg::MlDsa87 {
            return Err(SamlError::PublicKeyUnsupported);
        }
        if !verify_ml_dsa_87(&pinned.spki_der, &canonical_si, &sig_bytes) {
            return Err(SamlError::SignatureInvalid);
        }
    } else {
        return Err(SamlError::SignatureAlgorithmForbidden);
    }

    let _ = signed_info;
    Ok(VerifiedSignature {
        signed_assertion: assertion_node,
        sig_alg,
        trust_anchor_subject: hex_short(&pinned.spki_sha512),
    })
}

/// Direct ML-DSA-87 verify against a raw encoded verifying key (no domain
/// separation context — XML-DSig does the framing for us by way of the
/// canonicalized SignedInfo). Returns `true` only on a clean verify.
fn verify_ml_dsa_87(vk_bytes: &[u8], data: &[u8], sig_bytes: &[u8]) -> bool {
    use ml_dsa::signature::Verifier;
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa87, VerifyingKey};
    let vk_enc = match <EncodedVerifyingKey<MlDsa87> as TryFrom<&[u8]>>::try_from(vk_bytes) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let vk = VerifyingKey::<MlDsa87>::decode(&vk_enc);
    let sig_enc = match <EncodedSignature<MlDsa87> as TryFrom<&[u8]>>::try_from(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let sig = match ml_dsa::Signature::<MlDsa87>::decode(&sig_enc) {
        Some(s) => s,
        None => return false,
    };
    vk.verify(data, &sig).is_ok()
}

fn hex_short(fp: &[u8; 64]) -> String {
    let mut s = String::with_capacity(16);
    for b in &fp[..8] {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn validate_transform_chain(dom: &Dom, transforms_node: NodeId) -> Result<(), SamlError> {
    let parent = dom.element(transforms_node)?;
    let mut algs: Vec<String> = Vec::new();
    for &c in &parent.children {
        if let Node::Element(e) = dom.node(c) {
            if e.ns == NS_DS && e.local == "Transform" {
                let alg = attr_value(e, "", "Algorithm").ok_or(SamlError::Xml)?;
                algs.push(alg);
            }
        }
    }
    if algs.len() != 2 {
        return Err(SamlError::TransformForbidden);
    }
    if algs[0] != ALG_TRANSFORM_ENVELOPED || algs[1] != ALG_C14N_EXC {
        return Err(SamlError::TransformForbidden);
    }
    Ok(())
}

fn inclusive_prefixes(dom: &Dom, canon_alg_node: NodeId) -> Vec<String> {
    let Ok(parent) = dom.element(canon_alg_node) else {
        return Vec::new();
    };
    for &c in &parent.children {
        if let Node::Element(e) = dom.node(c) {
            if e.local == "InclusiveNamespaces" {
                if let Some(list) = attr_value(e, "", "PrefixList") {
                    return list
                        .split_ascii_whitespace()
                        .map(|s| if s == "#default" { String::new() } else { s.to_string() })
                        .collect();
                }
            }
        }
    }
    Vec::new()
}

/// Walk KeyInfo and pull every `<ds:X509Certificate>` payload as DER bytes.
fn extract_x509_certs(dom: &Dom, key_info: NodeId) -> Result<Vec<Vec<u8>>, SamlError> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    walk_collect(dom, key_info, NS_DS, "X509Certificate", &mut |nid| {
        let b64 = collect_text(dom, nid);
        let cleaned: String = b64.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        let der = STANDARD
            .decode(cleaned.as_bytes())
            .map_err(|_| SamlError::CertificateParse)?;
        out.push(der);
        Ok(())
    })?;
    Ok(out)
}

fn walk_collect<F>(
    dom: &Dom,
    nid: NodeId,
    ns: &str,
    local: &str,
    f: &mut F,
) -> Result<(), SamlError>
where
    F: FnMut(NodeId) -> Result<(), SamlError>,
{
    if let Node::Element(e) = dom.node(nid) {
        if e.ns == ns && e.local == local {
            f(nid)?;
        }
        for &c in &e.children {
            walk_collect(dom, c, ns, local, f)?;
        }
    }
    Ok(())
}

/// Canonicalize the assertion subtree with the signature element elided
/// (the enveloped-signature transform).
fn canonicalize_with_signature_removed(
    dom: &Dom,
    apex: NodeId,
    sig_node: NodeId,
) -> Result<Vec<u8>, SamlError> {
    let mut filtered = dom.clone();
    filtered.detach_from_parent(sig_node)?;
    crate::c14n::exc_c14n(&filtered, apex, &[])
}

pub fn find_child(dom: &Dom, parent: NodeId, ns: &str, local: &str) -> Option<NodeId> {
    let parent_el = dom.element(parent).ok()?;
    for &c in &parent_el.children {
        if let Node::Element(e) = dom.node(c) {
            if e.ns == ns && e.local == local {
                return Some(c);
            }
        }
    }
    None
}

pub fn find_children(dom: &Dom, parent: NodeId, ns: &str, local: &str) -> Vec<NodeId> {
    let mut out = Vec::new();
    if let Ok(parent_el) = dom.element(parent) {
        for &c in &parent_el.children {
            if let Node::Element(e) = dom.node(c) {
                if e.ns == ns && e.local == local {
                    out.push(c);
                }
            }
        }
    }
    out
}

pub fn attr_value(e: &Element, ns: &str, local: &str) -> Option<String> {
    e.attrs
        .iter()
        .find(|a| a.ns == ns && a.local == local)
        .map(|a| a.value.clone())
}

pub fn collect_text(dom: &Dom, nid: NodeId) -> String {
    let mut out = String::new();
    if let Ok(e) = dom.element(nid) {
        for &c in &e.children {
            if let Node::Text(t) = dom.node(c) {
                out.push_str(t);
            }
        }
    }
    out
}
