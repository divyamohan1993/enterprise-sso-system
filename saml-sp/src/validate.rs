//! Orchestrator: drives the strict validation pipeline end-to-end.
//!
//! See crate root for the mandated order. This module is the **only** place
//! that touches the validated `<Assertion>` node ID for claim extraction.

use crate::c14n;
use crate::dom::{self, Dom, Node, NodeId};
use crate::dsig::{self, attr_value, collect_text, find_child, find_children};
use crate::replay_cache::ReplayCache;
use crate::request_cache::RequestCache;
use crate::time::parse_iso8601;
use crate::trust::TrustAnchor;
use crate::{SamlAssertion, SamlError};
use std::collections::BTreeMap;
use subtle::ConstantTimeEq;

const NS_SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const NS_SAMLP: &str = "urn:oasis:names:tc:SAML:2.0:protocol";

/// Configuration for a single SP / IdP relationship. All fields are required.
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// IdP `entity_id` (matches the `<saml:Issuer>` value, constant-time check).
    pub expected_issuer: String,
    /// SP entity ID (matches `<Audience>`).
    pub sp_entity_id: String,
    /// SP Assertion Consumer Service URL (matches `Destination` and
    /// `SubjectConfirmationData/@Recipient`).
    pub acs_url: String,
    /// Maximum tolerated clock skew, seconds. Hard cap of 60s enforced.
    pub clock_skew_secs: i64,
    /// If false, an `InResponseTo` MUST be present and must match a tracked
    /// outstanding `AuthnRequest`. Unsolicited responses are rejected.
    pub allow_unsolicited: bool,
}

#[derive(Debug, Clone)]
pub struct ValidatedAssertion {
    pub claims: SamlAssertion,
}

pub fn consume_response(
    raw_xml: &[u8],
    cfg: &ValidationConfig,
    trust: &dyn TrustAnchor,
    requests: &RequestCache,
    replays: &ReplayCache,
    now: i64,
) -> Result<SamlAssertion, SamlError> {
    if cfg.clock_skew_secs < 0 || cfg.clock_skew_secs > 60 {
        return Err(SamlError::ClockSkewExceeded);
    }

    // 1. Strict parse — refuses DOCTYPE, PI, entities, oversize, etc.
    let dom = dom::parse_strict(raw_xml)?;

    // 2. Top-level element must be <samlp:Response>.
    let root = dom.root.ok_or(SamlError::Xml)?;
    let root_el = dom.element(root)?;
    if root_el.ns != NS_SAMLP || root_el.local != "Response" {
        return Err(SamlError::Xml);
    }

    // 3. Status must be Success before we even consider the assertion.
    let status_node = find_child(&dom, root, NS_SAMLP, "Status").ok_or(SamlError::Xml)?;
    let status_code_node =
        find_child(&dom, status_node, NS_SAMLP, "StatusCode").ok_or(SamlError::Xml)?;
    let status_code = attr_value(dom.element(status_code_node)?, "", "Value")
        .ok_or(SamlError::Xml)?;
    if status_code != "urn:oasis:names:tc:SAML:2.0:status:Success" {
        return Err(SamlError::StatusNotSuccess);
    }

    // 4. Issuer at the Response level must match configured IdP entity ID.
    let resp_issuer_node = find_child(&dom, root, NS_SAML, "Issuer").ok_or(SamlError::Xml)?;
    let resp_issuer = collect_text(&dom, resp_issuer_node);
    if !ct_str_eq(&resp_issuer, &cfg.expected_issuer) {
        return Err(SamlError::UnknownIssuer);
    }

    // 5. Destination on the Response (per Web SSO Profile §4.1.4.5).
    let dest = attr_value(root_el, "", "Destination").ok_or(SamlError::DestinationMismatch)?;
    if !ct_str_eq(&dest, &cfg.acs_url) {
        return Err(SamlError::DestinationMismatch);
    }

    // 6. Reject EncryptedAssertion (no decryption configured here yet) and
    //    reject any structure that has zero or multiple <Assertion> elements.
    if find_child(&dom, root, NS_SAML, "EncryptedAssertion").is_some() {
        return Err(SamlError::AssertionCardinality);
    }
    if dsig::count_assertions(&dom) != 1 {
        return Err(SamlError::AssertionCardinality);
    }
    let (assertion_node, assertion_id) = dsig::unique_assertion(&dom)?;

    // The unique <Assertion> must be a direct child of the Response — XSW
    // attacks classically smuggle a second assertion deeper in the tree.
    let assertion_el = dom.element(assertion_node)?;
    if assertion_el.parent != Some(root) {
        return Err(SamlError::AssertionIdConfusion);
    }

    // 7. Verify the unique XML-DSig that protects the unique assertion.
    let verified = dsig::verify(&dom, trust, &cfg.expected_issuer)?;

    // 8. Cross-check: the signed assertion node ID is the assertion node ID
    //    we plan to consume. Anything else is XSW.
    if verified.signed_assertion != assertion_node {
        return Err(SamlError::AssertionIdConfusion);
    }

    // 9. Issuer inside the assertion must also match.
    let inner_issuer_node =
        find_child(&dom, assertion_node, NS_SAML, "Issuer").ok_or(SamlError::Xml)?;
    let inner_issuer = collect_text(&dom, inner_issuer_node);
    if !ct_str_eq(&inner_issuer, &cfg.expected_issuer) {
        return Err(SamlError::UnknownIssuer);
    }

    // 10. Conditions: NotBefore / NotOnOrAfter / AudienceRestriction.
    let conditions_node =
        find_child(&dom, assertion_node, NS_SAML, "Conditions").ok_or(SamlError::Xml)?;
    let cond_el = dom.element(conditions_node)?;
    let not_before = match attr_value(cond_el, "", "NotBefore") {
        Some(s) => parse_iso8601(&s)?,
        None => i64::MIN,
    };
    let not_on_or_after_attr = attr_value(cond_el, "", "NotOnOrAfter")
        .ok_or(SamlError::Expired)?;
    let not_on_or_after = parse_iso8601(&not_on_or_after_attr)?;

    if now + cfg.clock_skew_secs < not_before {
        return Err(SamlError::NotYetValid);
    }
    if not_on_or_after <= now - cfg.clock_skew_secs {
        return Err(SamlError::Expired);
    }

    // AudienceRestriction (one or more, OR semantics within, AND across).
    let audience_value = check_audience(&dom, conditions_node, &cfg.sp_entity_id)?;

    // 11. Subject + SubjectConfirmation (bearer + Recipient + InResponseTo).
    let subject_nodes = find_children(&dom, assertion_node, NS_SAML, "Subject");
    if subject_nodes.len() != 1 {
        return Err(SamlError::SubjectCardinality);
    }
    let subject_node = subject_nodes[0];
    let nameid_node = find_child(&dom, subject_node, NS_SAML, "NameID")
        .ok_or(SamlError::SubjectCardinality)?;
    let nameid = collect_text(&dom, nameid_node);

    let confirmations = find_children(&dom, subject_node, NS_SAML, "SubjectConfirmation");
    if confirmations.len() != 1 {
        return Err(SamlError::SubjectCardinality);
    }
    let confirmation = confirmations[0];
    let confirmation_el = dom.element(confirmation)?;
    let method = attr_value(confirmation_el, "", "Method")
        .ok_or(SamlError::SubjectConfirmationMethod)?;
    if method != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
        return Err(SamlError::SubjectConfirmationMethod);
    }
    let confirmation_data =
        find_child(&dom, confirmation, NS_SAML, "SubjectConfirmationData")
            .ok_or(SamlError::SubjectConfirmationRecipient)?;
    let cd_el = dom.element(confirmation_data)?;
    let recipient = attr_value(cd_el, "", "Recipient")
        .ok_or(SamlError::SubjectConfirmationRecipient)?;
    if !ct_str_eq(&recipient, &cfg.acs_url) {
        return Err(SamlError::SubjectConfirmationRecipient);
    }
    let cd_not_on_or_after = attr_value(cd_el, "", "NotOnOrAfter")
        .ok_or(SamlError::SubjectConfirmationExpired)?;
    let cd_expires = parse_iso8601(&cd_not_on_or_after)?;
    if cd_expires <= now - cfg.clock_skew_secs {
        return Err(SamlError::SubjectConfirmationExpired);
    }

    let in_response_to = match attr_value(cd_el, "", "InResponseTo") {
        Some(v) => {
            requests.consume(&v, now)?;
            v
        }
        None => {
            if !cfg.allow_unsolicited {
                return Err(SamlError::InResponseToMismatch);
            }
            String::new()
        }
    };

    // Cross-check that the `InResponseTo` on the Response (if present) matches
    // the one inside SubjectConfirmationData.
    if let Some(resp_irt) = attr_value(root_el, "", "InResponseTo") {
        if !in_response_to.is_empty() && !ct_str_eq(&resp_irt, &in_response_to) {
            return Err(SamlError::InResponseToMismatch);
        }
    }

    // 12. AuthnStatement (optional but recommended) — pull AuthnInstant,
    //     SessionNotOnOrAfter, and AuthnContextClassRef when present.
    let mut authn_instant: Option<i64> = None;
    let mut session_noa: Option<i64> = None;
    let mut authn_class: Option<String> = None;
    if let Some(stmt) = find_child(&dom, assertion_node, NS_SAML, "AuthnStatement") {
        let stmt_el = dom.element(stmt)?;
        if let Some(ai) = attr_value(stmt_el, "", "AuthnInstant") {
            authn_instant = Some(parse_iso8601(&ai)?);
        }
        if let Some(sn) = attr_value(stmt_el, "", "SessionNotOnOrAfter") {
            let v = parse_iso8601(&sn)?;
            if v <= now - cfg.clock_skew_secs {
                return Err(SamlError::Expired);
            }
            session_noa = Some(v);
        }
        if let Some(ctx) = find_child(&dom, stmt, NS_SAML, "AuthnContext") {
            if let Some(class_ref) = find_child(&dom, ctx, NS_SAML, "AuthnContextClassRef") {
                authn_class = Some(collect_text(&dom, class_ref));
            }
        }
    }

    // 13. Attributes from <AttributeStatement> — namespace-strict.
    let attributes = collect_attributes(&dom, assertion_node)?;

    // 14. Replay protection. TTL = NotOnOrAfter + skew (we cap with skew).
    replays.check_and_insert(&assertion_id, not_on_or_after + cfg.clock_skew_secs, now)?;

    let _ = c14n::compute_in_scope_namespaces; // keep symbol exported & checked
    let _ = verified;

    Ok(SamlAssertion {
        assertion_id,
        issuer: inner_issuer,
        subject: nameid,
        audience: audience_value,
        destination: dest,
        in_response_to,
        not_before: if not_before == i64::MIN { 0 } else { not_before },
        not_on_or_after,
        session_not_on_or_after: session_noa,
        authn_instant,
        authn_context_class_ref: authn_class,
        attributes,
    })
}

fn check_audience(
    dom: &Dom,
    conditions: NodeId,
    sp_entity_id: &str,
) -> Result<String, SamlError> {
    let restrictions = find_children(dom, conditions, NS_SAML, "AudienceRestriction");
    if restrictions.is_empty() {
        return Err(SamlError::AudienceMismatch);
    }
    let mut last_audience = String::new();
    for r in restrictions {
        let audiences = find_children(dom, r, NS_SAML, "Audience");
        if audiences.is_empty() {
            return Err(SamlError::AudienceMismatch);
        }
        let mut matched_within = false;
        for a in audiences {
            let val = collect_text(dom, a);
            if ct_str_eq(&val, sp_entity_id) {
                matched_within = true;
                last_audience = val;
            }
        }
        if !matched_within {
            return Err(SamlError::AudienceMismatch);
        }
    }
    Ok(last_audience)
}

fn collect_attributes(
    dom: &Dom,
    assertion: NodeId,
) -> Result<BTreeMap<String, Vec<String>>, SamlError> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let stmts = find_children(dom, assertion, NS_SAML, "AttributeStatement");
    for stmt in stmts {
        let attrs = find_children(dom, stmt, NS_SAML, "Attribute");
        for a in attrs {
            let a_el = dom.element(a)?;
            let name = attr_value(a_el, "", "Name").ok_or(SamlError::Xml)?;
            let mut vals: Vec<String> = Vec::new();
            for &c in &a_el.children {
                if let Node::Element(av) = dom.node(c) {
                    if av.ns == NS_SAML && av.local == "AttributeValue" {
                        vals.push(collect_text(dom, c));
                    }
                }
            }
            out.entry(name).or_default().extend(vals);
        }
    }
    Ok(out)
}

fn ct_str_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}
