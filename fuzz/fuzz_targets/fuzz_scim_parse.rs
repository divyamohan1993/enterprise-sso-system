#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use common::scim::{ScimBulkRequest, ScimFilter, ScimGroup, ScimPatchRequest, ScimUser};

/// Structured SCIM input generator for more effective fuzzing.
/// Generates valid JSON with SCIM schema URNs to exercise the SCIM
/// parser more deeply than random bytes.
#[derive(Debug, Arbitrary)]
struct FuzzScimInput {
    /// Use structured JSON or raw bytes.
    use_structured: bool,
    /// Which SCIM operation to fuzz.
    operation: ScimOperation,
    /// Raw fallback data.
    raw_data: Vec<u8>,
}

#[derive(Debug, Arbitrary)]
enum ScimOperation {
    Filter(FuzzScimFilter),
    User(FuzzScimUser),
    Group(FuzzScimGroup),
    Patch(FuzzScimPatch),
    Bulk(FuzzScimBulk),
}

#[derive(Debug, Arbitrary)]
struct FuzzScimFilter {
    attribute: String,
    operator: FilterOp,
    value: String,
}

#[derive(Debug, Arbitrary)]
enum FilterOp {
    Eq, Ne, Co, Sw, Ew, Gt, Lt, Ge, Le, Pr,
}

impl FilterOp {
    fn as_str(&self) -> &str {
        match self {
            Self::Eq => "eq", Self::Ne => "ne", Self::Co => "co",
            Self::Sw => "sw", Self::Ew => "ew", Self::Gt => "gt",
            Self::Lt => "lt", Self::Ge => "ge", Self::Le => "le",
            Self::Pr => "pr",
        }
    }
}

#[derive(Debug, Arbitrary)]
struct FuzzScimUser {
    user_name: String,
    active: bool,
    display_name: Option<String>,
    family_name: Option<String>,
    given_name: Option<String>,
    email: Option<String>,
    extra_schemas: Vec<String>,
}

#[derive(Debug, Arbitrary)]
struct FuzzScimGroup {
    display_name: String,
    member_values: Vec<String>,
}

#[derive(Debug, Arbitrary)]
struct FuzzScimPatch {
    op: PatchOp,
    path: String,
    value: String,
}

#[derive(Debug, Arbitrary)]
enum PatchOp { Add, Remove, Replace }

impl PatchOp {
    fn as_str(&self) -> &str {
        match self {
            Self::Add => "add", Self::Remove => "remove", Self::Replace => "replace",
        }
    }
}

#[derive(Debug, Arbitrary)]
struct FuzzScimBulk {
    operations: Vec<BulkOp>,
}

#[derive(Debug, Arbitrary)]
struct BulkOp {
    method: BulkMethod,
    path: String,
    user_name: String,
}

#[derive(Debug, Arbitrary)]
enum BulkMethod { Post, Put, Patch, Delete }

impl BulkMethod {
    fn as_str(&self) -> &str {
        match self {
            Self::Post => "POST", Self::Put => "PUT",
            Self::Patch => "PATCH", Self::Delete => "DELETE",
        }
    }
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
        .chars()
        .take(500)
        .collect()
}

fuzz_target!(|input: FuzzScimInput| {
    if input.use_structured {
        match &input.operation {
            ScimOperation::Filter(f) => {
                let attr: String = f.attribute.chars().take(100).collect();
                let val: String = f.value.chars().take(200).collect();
                let filter_str = if matches!(f.operator, FilterOp::Pr) {
                    format!("{} pr", attr)
                } else {
                    format!("{} {} \"{}\"", attr, f.operator.as_str(), json_escape(&val))
                };
                let _ = ScimFilter::parse(&filter_str);
            }
            ScimOperation::User(u) => {
                let json = format!(
                    r#"{{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"{}","active":{}{}{}{}{}}}"#,
                    json_escape(&u.user_name),
                    u.active,
                    u.display_name.as_ref().map(|n| format!(r#","displayName":"{}""#, json_escape(n))).unwrap_or_default(),
                    u.family_name.as_ref().map(|n| format!(r#","name":{{"familyName":"{}"}}"#, json_escape(n))).unwrap_or_default(),
                    u.given_name.as_ref().map(|n| format!(r#","name":{{"givenName":"{}"}}"#, json_escape(n))).unwrap_or_default(),
                    u.email.as_ref().map(|e| format!(r#","emails":[{{"value":"{}","primary":true}}]"#, json_escape(e))).unwrap_or_default(),
                );
                let _ = serde_json::from_str::<ScimUser>(&json);
            }
            ScimOperation::Group(g) => {
                let members: String = g.member_values.iter().take(10)
                    .map(|m| format!(r#"{{"value":"{}"}}"#, json_escape(m)))
                    .collect::<Vec<_>>()
                    .join(",");
                let json = format!(
                    r#"{{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"{}","members":[{}]}}"#,
                    json_escape(&g.display_name),
                    members,
                );
                let _ = serde_json::from_str::<ScimGroup>(&json);
            }
            ScimOperation::Patch(p) => {
                let json = format!(
                    r#"{{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{{"op":"{}","path":"{}","value":"{}"}}]}}"#,
                    p.op.as_str(),
                    json_escape(&p.path),
                    json_escape(&p.value),
                );
                let _ = serde_json::from_str::<ScimPatchRequest>(&json);
            }
            ScimOperation::Bulk(b) => {
                let ops: String = b.operations.iter().take(5)
                    .map(|op| format!(
                        r#"{{"method":"{}","path":"{}","data":{{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"{}","active":true}}}}"#,
                        op.method.as_str(),
                        json_escape(&op.path),
                        json_escape(&op.user_name),
                    ))
                    .collect::<Vec<_>>()
                    .join(",");
                let json = format!(
                    r#"{{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[{}]}}"#,
                    ops,
                );
                let _ = serde_json::from_str::<ScimBulkRequest>(&json);
            }
        }
    } else {
        let text = String::from_utf8_lossy(&input.raw_data);
        let _ = ScimFilter::parse(&text);
        let _ = serde_json::from_slice::<ScimUser>(&input.raw_data);
        let _ = serde_json::from_slice::<ScimGroup>(&input.raw_data);
        let _ = serde_json::from_slice::<ScimPatchRequest>(&input.raw_data);
        let _ = serde_json::from_slice::<ScimBulkRequest>(&input.raw_data);
    }
});
