use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const CATALOG: &str = include_str!("../capabilities/cloudflare-mcp-parity.json");
const SCHEMAS: &str = include_str!("../capabilities/cloudflare-input-schemas.json");
const FIXTURES: &str = include_str!("../capabilities/cloudflare-schema-fixtures.json");
pub const SOURCE_COMMIT: &str = "70ff690553722f731849ede6ba9ce98958395a23";
const DENOMINATOR: usize = 172;
const DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";
const SCHEMA_EVIDENCE_ID: &str = "ev-phase1-canonical-schemas";
const SCHEMA_SOURCE_REF: &str = "https://github.com/cloudflare/mcp-server-cloudflare/commit/70ff690553722f731849ede6ba9ce98958395a23";
const SCHEMA_EVIDENCE_FACT: &str = "Registration-input schemas originate from exact pinned upstream registration files and dependency declarations enumerated by source file, blob, span, and expression hash in local capabilities/cloudflare-input-schemas.json; local artifact identity is bound separately by schema_artifacts and per-capability contract hashes.";
const DEPENDENCY_PROVENANCE_COUNT: usize = 803;
const DEPENDENCY_PROVENANCE_SHA256: &str =
    "bd6c83d69c8464ec0d5b428a2631972aa1d30acabdf89f310b1a06f8d5678d04";
const LEGACY_METADATA_SHA256: &str =
    "fa2d722b3953d2737f2ad69ccc0a8c240acc25cef3d9c8119c6fb63162786f00";
const LEGACY_METADATA_FNV1A: u64 = 0xadea63317dd97177;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InputField {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: String,
    pub required: bool,
    #[serde(default)]
    pub default: Option<Value>,
    #[serde(default)]
    pub condition: Option<String>,
}

macro_rules! status_enum {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
        #[serde(rename_all = "snake_case", deny_unknown_fields)]
        pub enum $name { $($variant),+ }
    };
}
status_enum!(InventoryStatus {
    Unresolved,
    Complete
});
status_enum!(SchemaStatus {
    Unresolved,
    Complete,
    ZeroInputEvidenced
});
status_enum!(RouteStatus {
    Unresolved,
    Complete,
    ExternalBlocked
});
status_enum!(BehaviorStatus {
    Unresolved,
    Specified,
    Verified
});
status_enum!(PolicyStatus {
    Unresolved,
    Classified,
    Verified
});
status_enum!(VerificationStatus {
    Unverified,
    HermeticVerified
});
status_enum!(DiscoveryStatus {
    Missing,
    Generated,
    Verified
});
status_enum!(ExternalBlockerStatus {
    None,
    Open,
    Resolved
});
status_enum!(EvidenceDimension {
    Inventory,
    Schema,
    Route,
    Behavior,
    Policy,
    Verification,
    Discovery,
    ExternalBlocker
});
status_enum!(EvidenceKind {
    Missing,
    SourceVerified,
    OfficialVerified,
    HermeticVerified
});
status_enum!(LedgerBlockerStatus { Open, Resolved });

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    pub name: String,
    pub family: String,
    pub apps: Vec<String>,
    pub source: String,
    pub source_ref: String,
    pub source_commit: String,
    pub description: String,
    pub input_fields: Vec<InputField>,
    pub schema_contract_sha256: String,
    pub scope: String,
    pub operation: String,
    pub transport: String,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub path_template: Option<String>,
    #[serde(default)]
    pub sdk_method: Option<String>,
    pub cli_access: String,
    #[serde(default)]
    pub blocker: Option<String>,
    pub parity: Parity,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Parity {
    pub inventory: Dimension<InventoryStatus>,
    pub schema: Dimension<SchemaStatus>,
    pub route: Dimension<RouteStatus>,
    pub behavior: Dimension<BehaviorStatus>,
    pub policy: Dimension<PolicyStatus>,
    pub verification: Dimension<VerificationStatus>,
    pub discovery: Dimension<DiscoveryStatus>,
    pub external_blocker: BlockerDimension,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Dimension<S> {
    pub status: S,
    pub evidence_ids: Vec<String>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlockerDimension {
    pub status: ExternalBlockerStatus,
    #[serde(default)]
    pub blocker_id: Option<String>,
    pub evidence_ids: Vec<String>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub id: String,
    pub dimension: EvidenceDimension,
    pub source_repo: String,
    pub source_commit: String,
    pub source_ref: String,
    pub kind: EvidenceKind,
    pub fact: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Blocker {
    pub id: String,
    pub status: LedgerBlockerStatus,
    pub family: String,
    pub summary: String,
    pub affected_names: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaArtifacts {
    pub bundle_sha256: String,
    pub fixtures_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub schema_version: u32,
    pub catalog_id: String,
    pub source: Source,
    pub schema_artifacts: SchemaArtifacts,
    pub denominator: usize,
    pub legacy_metadata_sha256: String,
    pub evidence: Vec<Evidence>,
    pub blockers: Vec<Blocker>,
    pub capabilities: Vec<Capability>,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub repo: String,
    pub commit: String,
    #[serde(rename = "ref")]
    pub ref_: String,
}

fn invalid(message: impl Into<String>) -> serde_json::Error {
    serde_json::Error::io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message.into(),
    ))
}
fn validate_evidence_ids<'a>(
    ids: &'a [String],
    dimension: EvidenceDimension,
    evidence: &BTreeMap<&str, &'a Evidence>,
    used: &mut BTreeSet<&'a str>,
) -> Result<(), serde_json::Error> {
    let mut local = BTreeSet::new();
    for id in ids {
        if !local.insert(id.as_str()) {
            return Err(invalid("duplicate evidence ref"));
        }
        let item = evidence
            .get(id.as_str())
            .ok_or_else(|| invalid("dangling evidence ID"))?;
        if item.dimension != dimension
            || item.source_repo != "https://github.com/cloudflare/mcp-server-cloudflare"
            || item.source_commit != SOURCE_COMMIT
            || item.source_ref.is_empty()
        {
            return Err(invalid("evidence dimension or provenance mismatch"));
        }
        used.insert(id);
    }
    Ok(())
}
fn has_evidence_kind(
    ids: &[String],
    evidence: &BTreeMap<&str, &Evidence>,
    kind: EvidenceKind,
) -> bool {
    ids.iter().any(|id| {
        evidence
            .get(id.as_str())
            .is_some_and(|item| item.kind == kind)
    })
}

fn has_authoritative_evidence(ids: &[String], evidence: &BTreeMap<&str, &Evidence>) -> bool {
    has_evidence_kind(ids, evidence, EvidenceKind::SourceVerified)
        || has_evidence_kind(ids, evidence, EvidenceKind::OfficialVerified)
}

fn counts<'a>(values: impl Iterator<Item = &'a str>) -> BTreeMap<&'a str, usize> {
    let mut result = BTreeMap::new();
    for value in values {
        *result.entry(value).or_insert(0) += 1;
    }
    result
}

fn blocker_id(family: &str) -> Option<&'static str> {
    match family {
        "dex-analysis" => Some("B-DEX"),
        "cloudflare-one-casb" => Some("B-CASB"),
        "sandbox-container" => Some("B-CONTAINER"),
        "workers-observability" => Some("B-OBS"),
        "shared" => Some("B-SHARED"),
        "stack-mcp" => Some("B-STACK"),
        _ => None,
    }
}
fn canonical_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonical_json).collect()),
        Value::Object(object) => {
            let mut entries: Vec<_> = object.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut sorted = serde_json::Map::new();
            for (key, value) in entries {
                sorted.insert(key, canonical_json(value));
            }
            Value::Object(sorted)
        }
        value => value,
    }
}

fn json_sha256(value: &Value) -> Result<String, serde_json::Error> {
    let bytes = serde_json::to_vec(&canonical_json(value.clone()))
        .map_err(|error| invalid(error.to_string()))?;
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn is_lower_hex(value: Option<&str>, length: usize) -> bool {
    value.is_some_and(|value| {
        value.len() == length
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn valid_span(value: Option<&Value>) -> bool {
    let Some(span) = value.and_then(Value::as_object) else {
        return false;
    };
    if span.len() != 4
        || !["start_byte", "end_byte", "start_line", "end_line"]
            .iter()
            .all(|key| span.contains_key(*key))
    {
        return false;
    }
    let Some(start_byte) = span["start_byte"].as_u64() else {
        return false;
    };
    let Some(end_byte) = span["end_byte"].as_u64() else {
        return false;
    };
    let Some(start_line) = span["start_line"].as_u64() else {
        return false;
    };
    let Some(end_line) = span["end_line"].as_u64() else {
        return false;
    };
    start_byte < end_byte && start_line >= 1 && start_line <= end_line
}

fn validate_dependency_provenance(
    value: &Value,
    contract_index: usize,
) -> Result<&str, serde_json::Error> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("dependency provenance object required"))?;
    let expected = [
        "id",
        "name",
        "file",
        "blob_oid",
        "classification",
        "source_span_kind",
        "source_span",
        "source_sha256",
    ];
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(invalid(format!(
            "dependency provenance shape mismatch for contract {contract_index}"
        )));
    }
    let text = |key: &str| {
        object[key]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid(format!("dependency provenance {key} required")))
    };
    let id = text("id")?;
    text("name")?;
    let file = text("file")?;
    let classification = text("classification")?;
    text("source_span_kind")?;
    if file.starts_with('/')
        || ![
            "dependency_node",
            "external_package_boundary",
            "language_builtin_boundary",
            "lexical_parameter_boundary",
        ]
        .contains(&classification)
        || !is_lower_hex(object["blob_oid"].as_str(), 40)
        || !is_lower_hex(object["source_sha256"].as_str(), 64)
        || !valid_span(object.get("source_span"))
    {
        return Err(invalid(format!(
            "invalid dependency provenance for contract {contract_index}"
        )));
    }
    Ok(id)
}

fn compact_schema_type(schema: &Value) -> String {
    if schema.get("enum").is_some() {
        return "enum".into();
    }
    if let Some(kind) = schema.get("type").and_then(Value::as_str) {
        if kind == "array" {
            return format!(
                "array<{}>",
                schema
                    .get("items")
                    .map(compact_schema_type)
                    .unwrap_or_else(|| "any".into())
            );
        }
        return kind.into();
    }
    if let Some(branches) = schema
        .get("anyOf")
        .or_else(|| schema.get("oneOf"))
        .and_then(Value::as_array)
    {
        return branches
            .iter()
            .map(compact_schema_type)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join("|");
    }
    "any".into()
}

fn compact_input_fields(contract: &Value) -> Result<Vec<InputField>, serde_json::Error> {
    let schema = contract
        .get("raw_input_schema")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("raw input schema object required"))?;
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("raw input schema properties required"))?;
    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    let mut fields = properties
        .iter()
        .map(|(name, field_schema)| InputField {
            name: name.clone(),
            field_type: compact_schema_type(field_schema),
            required: required.contains(name.as_str()),
            default: field_schema.get("default").cloned(),
            condition: None,
        })
        .collect::<Vec<_>>();
    for overlay in contract
        .get("context_overlays")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("context overlays array required"))?
    {
        if overlay.get("operation").and_then(Value::as_str) != Some("extend_optional_property") {
            continue;
        }
        let property = overlay
            .get("property")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("context overlay property required"))?;
        if properties.contains_key(property) {
            return Err(invalid("context overlay duplicates base property"));
        }
        let overlay_schema = overlay
            .get("schema")
            .ok_or_else(|| invalid("context overlay schema required"))?;
        fields.push(InputField {
            name: property.into(),
            field_type: compact_schema_type(overlay_schema),
            required: false,
            default: None,
            condition: Some(
                overlay
                    .get("predicate")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("context overlay predicate required"))?
                    .into(),
            ),
        });
    }
    fields.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(fields)
}

fn validate_schema_artifacts(catalog: &Catalog) -> Result<(), serde_json::Error> {
    let bundle: Value = serde_json::from_str(SCHEMAS)?;
    let fixtures: Value = serde_json::from_str(FIXTURES)?;
    validate_schema_artifact_values(catalog, &bundle, &fixtures)
}

fn validate_schema_artifact_values(
    catalog: &Catalog,
    bundle: &Value,
    fixtures: &Value,
) -> Result<(), serde_json::Error> {
    let bundle_hash = json_sha256(bundle)?;
    let fixtures_hash = json_sha256(fixtures)?;
    let contracts = bundle
        .get("contracts")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("schema contracts array required"))?;
    if bundle.get("version").and_then(Value::as_str) != Some("2")
        || bundle.get("compiler_version").and_then(Value::as_str) != Some("phase1-oxc-static-0.4")
        || bundle.get("source_access").and_then(Value::as_str) != Some("exact_pinned_git_blobs")
        || bundle.get("execution_policy").and_then(Value::as_str)
            != Some(
                "static_only; never import or execute upstream TypeScript, Zod modules, registrations, or handlers",
            )
        || bundle.get("zod_version").and_then(Value::as_str) != Some("4.4.3")
        || bundle.get("source_commit").and_then(Value::as_str) != Some(SOURCE_COMMIT)
        || bundle.get("tree_oid").and_then(Value::as_str)
            != Some("1a51c6ff07170dfe3c3212c8fb96eb85d66f0b96")
        || bundle.get("dialect").and_then(Value::as_str) != Some(DIALECT)
        || bundle
            .get("candidate_complete_count")
            .and_then(Value::as_u64)
            != Some(168)
        || bundle
            .get("candidate_zero_input_count")
            .and_then(Value::as_u64)
            != Some(4)
        || bundle.get("unresolved_count").and_then(Value::as_u64) != Some(0)
        || bundle
            .get("dependency_provenance_count")
            .and_then(Value::as_u64)
            != Some(DEPENDENCY_PROVENANCE_COUNT as u64)
        || bundle
            .get("dependency_provenance_sha256")
            .and_then(Value::as_str)
            != Some(DEPENDENCY_PROVENANCE_SHA256)
        || contracts.len() != DENOMINATOR
    {
        return Err(invalid("invalid canonical schema bundle envelope"));
    }
    let mut schemas = BTreeMap::<String, Vec<String>>::new();
    let mut complete_count = 0;
    let mut zero_input_count = 0;
    let mut dependency_provenance_count = 0;
    let mut dependency_provenance_by_capability = serde_json::Map::new();
    for (index, (row, contract)) in catalog.capabilities.iter().zip(contracts).enumerate() {
        let capability = contract
            .get("capability")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("schema contract capability required"))?;
        let schema = contract
            .get("raw_input_schema")
            .ok_or_else(|| invalid("raw input schema required"))?;
        let schema_hash = contract
            .get("raw_input_schema_sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("raw schema hash required"))?;
        let contract_hash = contract
            .get("contract_sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("schema contract hash required"))?;
        let status = contract
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("schema contract status required"))?;
        let zero = match status {
            "candidate_complete" => {
                complete_count += 1;
                false
            }
            "candidate_zero_input" => {
                zero_input_count += 1;
                true
            }
            _ => return Err(invalid("invalid schema contract status")),
        };
        let source_file = contract
            .get("source_file")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("schema contract source file required"))?;
        let dependency_provenance = contract
            .get("dependency_provenance")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("dependency provenance array required"))?;
        let dependency_ids = dependency_provenance
            .iter()
            .map(|entry| validate_dependency_provenance(entry, index))
            .collect::<Result<Vec<_>, _>>()?;
        let dependency_provenance_valid = !dependency_ids.windows(2).any(|pair| pair[0] >= pair[1])
            && contract
                .get("unresolved_reasons")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty);
        dependency_provenance_count += dependency_provenance.len();
        dependency_provenance_by_capability.insert(
            capability.into(),
            Value::Array(dependency_provenance.clone()),
        );
        let mut unhashed = contract.clone();
        unhashed["contract_sha256"] = Value::Null;
        let expected_zero_schema = json!({"properties": {}, "type": "object"});
        let provenance_valid =
            is_lower_hex(contract.get("source_blob_oid").and_then(Value::as_str), 40)
                && valid_span(contract.get("registration_span"))
                && is_lower_hex(Some(schema_hash), 64)
                && is_lower_hex(Some(contract_hash), 64)
                && if zero {
                    contract.get("schema_span").is_some_and(Value::is_null)
                        && contract
                            .get("schema_expression_sha256")
                            .is_some_and(Value::is_null)
                } else {
                    valid_span(contract.get("schema_span"))
                        && is_lower_hex(
                            contract
                                .get("schema_expression_sha256")
                                .and_then(Value::as_str),
                            64,
                        )
                };
        if capability != row.name
            || row.schema_contract_sha256 != contract_hash
            || !schema.is_object()
            || json_sha256(schema)? != schema_hash
            || json_sha256(&unhashed)? != contract_hash
            || row.input_fields != compact_input_fields(contract)?
            || !row.source.starts_with(&format!("{source_file}:"))
            || (zero && *schema != expected_zero_schema)
            || (zero && row.parity.schema.status != SchemaStatus::ZeroInputEvidenced)
            || !provenance_valid
            || (!zero && row.parity.schema.status != SchemaStatus::Complete)
            || !dependency_provenance_valid
        {
            return Err(invalid(format!(
                "schema artifact mismatch for {}",
                row.name
            )));
        }
        schemas
            .entry(schema_hash.into())
            .or_default()
            .push(row.name.clone());
    }
    let derived_dependency_provenance_sha256 =
        json_sha256(&Value::Object(dependency_provenance_by_capability))?;
    if dependency_provenance_count != DEPENDENCY_PROVENANCE_COUNT
        || derived_dependency_provenance_sha256 != DEPENDENCY_PROVENANCE_SHA256
    {
        return Err(invalid("derived dependency provenance mismatch"));
    }
    if complete_count != 168 || zero_input_count != 4 {
        return Err(invalid(format!(
            "derived schema status counts mismatch: complete={complete_count}, zero_input={zero_input_count}"
        )));
    }
    let fixture_rows = fixtures
        .get("fixtures")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("schema fixtures array required"))?;
    let fixture_map = fixture_rows
        .iter()
        .map(|fixture| {
            fixture
                .get("raw_input_schema_sha256")
                .and_then(Value::as_str)
                .map(|hash| (hash, fixture))
                .ok_or_else(|| invalid("fixture schema hash required"))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    if fixtures.get("version").and_then(Value::as_str) != Some("schema-fixtures-v1")
        || fixtures.get("source_commit").and_then(Value::as_str) != Some(SOURCE_COMMIT)
        || fixtures.get("tree_oid").and_then(Value::as_str)
            != Some("1a51c6ff07170dfe3c3212c8fb96eb85d66f0b96")
        || fixtures.get("dialect").and_then(Value::as_str) != Some(DIALECT)
        || fixtures
            .get("distinct_schema_count")
            .and_then(Value::as_u64)
            != Some(schemas.len() as u64)
        || catalog.schema_artifacts.bundle_sha256 != bundle_hash
        || catalog.schema_artifacts.fixtures_sha256 != fixtures_hash
        || fixtures.get("bundle_sha256").and_then(Value::as_str) != Some(&json_sha256(bundle)?)
        || fixtures.get("contract_count").and_then(Value::as_u64) != Some(DENOMINATOR as u64)
        || fixture_map.len() != schemas.len()
    {
        return Err(invalid("invalid schema fixture envelope"));
    }
    for (hash, capabilities) in schemas {
        let fixture = fixture_map
            .get(hash.as_str())
            .ok_or_else(|| invalid("missing distinct-schema fixture"))?;
        let actual = fixture
            .get("capabilities")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("fixture capabilities required"))?
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();
        if actual != capabilities.iter().map(String::as_str).collect::<Vec<_>>()
            || fixture.get("positive").is_none()
            || fixture.get("negative").is_none()
        {
            return Err(invalid("fixture capability join mismatch"));
        }
    }
    Ok(())
}

fn legacy_metadata_checksum(raw: &str) -> Result<u64, serde_json::Error> {
    let mut value: Value = serde_json::from_str(raw)?;
    let capabilities = value
        .get_mut("capabilities")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| invalid("catalog capabilities must be an array"))?;
    for capability in &mut *capabilities {
        capability
            .as_object_mut()
            .ok_or_else(|| invalid("catalog capability must be an object"))?
            .retain(|key, _| {
                ![
                    "source_ref",
                    "parity",
                    "input_fields",
                    "schema_contract_sha256",
                ]
                .contains(&key.as_str())
            });
    }
    let encoded = serde_json::to_vec(&canonical_json(Value::Array(capabilities.clone())))
        .map_err(|error| invalid(error.to_string()))?;
    Ok(encoded.iter().fold(0xcbf29ce484222325u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    }))
}

fn parse_catalog(raw: &str) -> Result<Catalog, serde_json::Error> {
    if legacy_metadata_checksum(raw)? != LEGACY_METADATA_FNV1A {
        return Err(invalid("per-capability legacy metadata checksum mismatch"));
    }
    let catalog: Catalog = serde_json::from_str(raw)?;
    validate(&catalog)?;
    Ok(catalog)
}

pub fn validate(c: &Catalog) -> Result<(), serde_json::Error> {
    if c.schema_version != 2
        || c.catalog_id != "cloudflare-mcp-parity"
        || c.denominator != DENOMINATOR
        || c.legacy_metadata_sha256 != LEGACY_METADATA_SHA256
        || c.source.commit != SOURCE_COMMIT
        || c.source.repo != "https://github.com/cloudflare/mcp-server-cloudflare"
        || c.source.ref_ != "pinned-source"
    {
        return Err(invalid("unsupported catalog envelope or pinned baseline"));
    }
    if c.capabilities.len() != DENOMINATOR {
        return Err(invalid("catalog denominator mismatch"));
    }
    let names: Vec<_> = c.capabilities.iter().map(|x| x.name.as_str()).collect();
    if names.windows(2).any(|w| w[0] >= w[1]) || names.iter().any(|x| x.is_empty()) {
        return Err(invalid("names must be sorted, unique, and nonempty"));
    }

    let evidence: BTreeMap<_, _> = c.evidence.iter().map(|x| (x.id.as_str(), x)).collect();
    if evidence.len() != c.evidence.len()
        || c.evidence.iter().any(|item| {
            item.id.is_empty()
                || item.fact.is_empty()
                || item.source_repo != "https://github.com/cloudflare/mcp-server-cloudflare"
                || item.source_commit != SOURCE_COMMIT
                || item.source_ref.is_empty()
        })
    {
        return Err(invalid("invalid or duplicate evidence"));
    }
    let schema_evidence = evidence
        .get(SCHEMA_EVIDENCE_ID)
        .ok_or_else(|| invalid("Phase 1 schema evidence required"))?;
    if schema_evidence.dimension != EvidenceDimension::Schema
        || schema_evidence.kind != EvidenceKind::SourceVerified
        || schema_evidence.source_repo != "https://github.com/cloudflare/mcp-server-cloudflare"
        || schema_evidence.source_commit != SOURCE_COMMIT
        || schema_evidence.source_ref != SCHEMA_SOURCE_REF
        || schema_evidence.fact != SCHEMA_EVIDENCE_FACT
    {
        return Err(invalid("Phase 1 schema evidence provenance mismatch"));
    }
    let blockers: BTreeMap<_, _> = c.blockers.iter().map(|x| (x.id.as_str(), x)).collect();
    if blockers.len() != c.blockers.len() {
        return Err(invalid("duplicate blocker ID"));
    }
    for blocker in &c.blockers {
        if blocker.id.is_empty()
            || blocker.summary.is_empty()
            || blocker.affected_names.is_empty()
            || blocker_id(&blocker.family) != Some(blocker.id.as_str())
            || blocker
                .affected_names
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid("invalid blocker ledger entry"));
        }
    }

    let mut used = BTreeSet::new();
    for row in &c.capabilities {
        if row.source_commit != SOURCE_COMMIT
            || row.source_ref != row.source
            || row.source.is_empty()
            || row.family.is_empty()
            || row.apps.is_empty()
            || row.description.is_empty()
            || !["public", "account", "zone", "custom"].contains(&row.scope.as_str())
        {
            return Err(invalid(format!("invalid source metadata for {}", row.name)));
        }
        if row.cli_access == "blocked" && row.blocker.as_deref().is_none_or(str::is_empty) {
            return Err(invalid("blocked capability lacks blocker"));
        }

        if row.parity.inventory.status != InventoryStatus::Complete
            || row.parity.inventory.evidence_ids.len() != 1
        {
            return Err(invalid("inventory completion requires one evidence ref"));
        }
        if row.parity.schema.evidence_ids.len() != 1
            || row.parity.schema.evidence_ids[0] != SCHEMA_EVIDENCE_ID
        {
            return Err(invalid(
                "schema completion requires canonical Phase 1 evidence",
            ));
        }
        let evidence_groups = [
            (
                EvidenceDimension::Inventory,
                row.parity.inventory.evidence_ids.as_slice(),
            ),
            (
                EvidenceDimension::Schema,
                row.parity.schema.evidence_ids.as_slice(),
            ),
            (
                EvidenceDimension::Route,
                row.parity.route.evidence_ids.as_slice(),
            ),
            (
                EvidenceDimension::Behavior,
                row.parity.behavior.evidence_ids.as_slice(),
            ),
            (
                EvidenceDimension::Policy,
                row.parity.policy.evidence_ids.as_slice(),
            ),
            (
                EvidenceDimension::Verification,
                row.parity.verification.evidence_ids.as_slice(),
            ),
            (
                EvidenceDimension::Discovery,
                row.parity.discovery.evidence_ids.as_slice(),
            ),
            (
                EvidenceDimension::ExternalBlocker,
                row.parity.external_blocker.evidence_ids.as_slice(),
            ),
        ];
        for (dimension, ids) in evidence_groups {
            validate_evidence_ids(ids, dimension, &evidence, &mut used)?;
        }
        let inventory_evidence = evidence
            .get(row.parity.inventory.evidence_ids[0].as_str())
            .ok_or_else(|| invalid("missing inventory evidence"))?;
        if inventory_evidence.kind != EvidenceKind::SourceVerified
            || inventory_evidence.source_ref != row.source
        {
            return Err(invalid("inventory evidence mismatch"));
        }

        let needs_evidence = (matches!(
            row.parity.schema.status,
            SchemaStatus::Complete | SchemaStatus::ZeroInputEvidenced
        ) && row.parity.schema.evidence_ids.is_empty())
            || (matches!(
                row.parity.route.status,
                RouteStatus::Complete | RouteStatus::ExternalBlocked
            ) && row.parity.route.evidence_ids.is_empty())
            || (matches!(
                row.parity.policy.status,
                PolicyStatus::Classified | PolicyStatus::Verified
            ) && row.parity.policy.evidence_ids.is_empty())
            || (row.parity.verification.status == VerificationStatus::HermeticVerified
                && row.parity.verification.evidence_ids.is_empty())
            || (matches!(
                row.parity.discovery.status,
                DiscoveryStatus::Generated | DiscoveryStatus::Verified
            ) && row.parity.discovery.evidence_ids.is_empty());
        if needs_evidence {
            return Err(invalid("advanced parity status requires evidence"));
        }
        let schema_complete = matches!(
            row.parity.schema.status,
            SchemaStatus::Complete | SchemaStatus::ZeroInputEvidenced
        );
        let route_complete = matches!(
            row.parity.route.status,
            RouteStatus::Complete | RouteStatus::ExternalBlocked
        );
        let behavior_verified = row.parity.behavior.status == BehaviorStatus::Verified;
        let policy_verified = row.parity.policy.status == PolicyStatus::Verified;
        let missing_kind =
            |ids: &[String]| has_evidence_kind(ids, &evidence, EvidenceKind::Missing);
        if (schema_complete
            && (!has_authoritative_evidence(&row.parity.schema.evidence_ids, &evidence)
                || missing_kind(&row.parity.schema.evidence_ids)))
            || (route_complete
                && (!has_authoritative_evidence(&row.parity.route.evidence_ids, &evidence)
                    || missing_kind(&row.parity.route.evidence_ids)))
            || (row.parity.behavior.status == BehaviorStatus::Specified
                && !has_authoritative_evidence(&row.parity.behavior.evidence_ids, &evidence))
            || (behavior_verified
                && (!has_authoritative_evidence(&row.parity.behavior.evidence_ids, &evidence)
                    || !has_evidence_kind(
                        &row.parity.behavior.evidence_ids,
                        &evidence,
                        EvidenceKind::HermeticVerified,
                    )
                    || missing_kind(&row.parity.behavior.evidence_ids)))
            || (row.parity.policy.status == PolicyStatus::Classified
                && !has_authoritative_evidence(&row.parity.policy.evidence_ids, &evidence))
            || (policy_verified
                && (!has_authoritative_evidence(&row.parity.policy.evidence_ids, &evidence)
                    || !has_evidence_kind(
                        &row.parity.policy.evidence_ids,
                        &evidence,
                        EvidenceKind::HermeticVerified,
                    )
                    || missing_kind(&row.parity.policy.evidence_ids)))
            || (row.parity.verification.status == VerificationStatus::HermeticVerified
                && (!has_evidence_kind(
                    &row.parity.verification.evidence_ids,
                    &evidence,
                    EvidenceKind::HermeticVerified,
                ) || missing_kind(&row.parity.verification.evidence_ids)))
            || (matches!(
                row.parity.discovery.status,
                DiscoveryStatus::Generated | DiscoveryStatus::Verified
            ) && (!has_evidence_kind(
                &row.parity.discovery.evidence_ids,
                &evidence,
                EvidenceKind::HermeticVerified,
            ) || missing_kind(&row.parity.discovery.evidence_ids)))
        {
            return Err(invalid("parity status lacks applicable evidence kind"));
        }

        let external = &row.parity.external_blocker;
        if external.status == ExternalBlockerStatus::None
            && (external.blocker_id.is_some() || !external.evidence_ids.is_empty())
        {
            return Err(invalid("none blocker cannot have ID or evidence"));
        }
        if external.status != ExternalBlockerStatus::None
            && (external.evidence_ids.is_empty()
                || external
                    .blocker_id
                    .as_ref()
                    .is_none_or(|id| !blockers.contains_key(id.as_str())))
        {
            return Err(invalid("blocker status requires ledger ID and evidence"));
        }
        if external.status == ExternalBlockerStatus::Resolved
            && has_evidence_kind(&external.evidence_ids, &evidence, EvidenceKind::Missing)
        {
            return Err(invalid("resolved blocker requires non-missing evidence"));
        }
        if external.status == ExternalBlockerStatus::Open
            && row.blocker.as_deref().is_none_or(str::is_empty)
        {
            return Err(invalid("open blocker lacks legacy blocker metadata"));
        }
    }
    if used.len() != evidence.len() {
        return Err(invalid("orphan evidence"));
    }

    for blocker in &c.blockers {
        let actual: Vec<_> = c
            .capabilities
            .iter()
            .filter(|row| row.parity.external_blocker.blocker_id.as_deref() == Some(&blocker.id))
            .collect();
        if actual
            .iter()
            .map(|row| row.name.as_str())
            .collect::<Vec<_>>()
            != blocker
                .affected_names
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
            || actual.iter().any(|row| row.family != blocker.family)
        {
            return Err(invalid("blocker affected names mismatch"));
        }
        let expected = if actual
            .iter()
            .any(|row| row.parity.external_blocker.status == ExternalBlockerStatus::Open)
        {
            LedgerBlockerStatus::Open
        } else {
            LedgerBlockerStatus::Resolved
        };
        if blocker.status != expected {
            return Err(invalid("blocker ledger status mismatch"));
        }
    }

    let family = counts(c.capabilities.iter().map(|row| row.family.as_str()));
    let transport = counts(c.capabilities.iter().map(|row| row.transport.as_str()));
    let access = counts(c.capabilities.iter().map(|row| row.cli_access.as_str()));
    let operation = counts(c.capabilities.iter().map(|row| row.operation.as_str()));
    if family
        != BTreeMap::from([
            ("ai-gateway", 5),
            ("auditlogs", 1),
            ("autorag", 3),
            ("browser-rendering", 13),
            ("cloudflare-blog", 4),
            ("cloudflare-one-casb", 11),
            ("demo-day", 1),
            ("dex-analysis", 18),
            ("dns-analytics", 3),
            ("graphql", 6),
            ("logpush", 1),
            ("radar", 66),
            ("sandbox-container", 7),
            ("shared", 7),
            ("stack-mcp", 2),
            ("workers-bindings", 18),
            ("workers-builds", 3),
            ("workers-observability", 3),
        ])
        || transport
            != BTreeMap::from([
                ("custom_container", 7),
                ("graphql", 6),
                ("internal_binding", 2),
                ("public_http", 86),
                ("rest", 71),
            ])
        || access
            != BTreeMap::from([
                ("blocked", 1),
                ("mcp_remote", 26),
                ("public_direct", 6),
                ("raw_graphql", 6),
                ("raw_rest", 133),
            ])
        || operation != BTreeMap::from([("read", 150), ("write", 22)])
        || c.capabilities
            .iter()
            .filter(|row| row.method.is_some())
            .count()
            != 147
        || c.capabilities
            .iter()
            .filter(|row| row.path_template.is_some())
            .count()
            != 6
        || c.capabilities
            .iter()
            .filter(|row| row.blocker.is_some())
            .count()
            != 41
    {
        return Err(invalid("legacy baseline metadata drift"));
    }
    validate_schema_artifacts(c)?;
    Ok(())
}
fn complete<S: PartialEq>(s: &S, yes: &[S]) -> bool {
    yes.iter().any(|x| x == s)
}
pub fn x_count(c: &Catalog) -> usize {
    c.capabilities
        .iter()
        .filter(|r| {
            r.parity.external_blocker.status == ExternalBlockerStatus::Open
                || r.parity.route.status == RouteStatus::ExternalBlocked
        })
        .count()
}
fn parity_vector(c: &Catalog) -> Value {
    json!({"I":c.capabilities.iter().filter(|r|r.parity.inventory.status==InventoryStatus::Complete).count(),"S":c.capabilities.iter().filter(|r|complete(&r.parity.schema.status,&[SchemaStatus::Complete,SchemaStatus::ZeroInputEvidenced])).count(),"R":c.capabilities.iter().filter(|r|r.parity.route.status==RouteStatus::Complete).count(),"B":c.capabilities.iter().filter(|r|r.parity.behavior.status==BehaviorStatus::Verified).count(),"P":c.capabilities.iter().filter(|r|r.parity.policy.status==PolicyStatus::Verified).count(),"V":c.capabilities.iter().filter(|r|r.parity.verification.status==VerificationStatus::HermeticVerified).count(),"D":c.capabilities.iter().filter(|r|r.parity.discovery.status==DiscoveryStatus::Verified).count(),"X":x_count(c)})
}
pub fn catalog() -> Result<Catalog, serde_json::Error> {
    parse_catalog(CATALOG)
}
pub fn all() -> Result<Vec<Capability>, serde_json::Error> {
    Ok(catalog()?.capabilities)
}
pub fn list(
    family: Option<&str>,
    access: Option<&str>,
    full: bool,
) -> Result<Value, serde_json::Error> {
    let entries: Vec<_> = all()?
        .into_iter()
        .filter(|e| family.is_none_or(|v| e.family == v))
        .filter(|e| access.is_none_or(|v| e.cli_access == v))
        .collect();
    let mut families = BTreeMap::new();
    let mut accesses = BTreeMap::new();
    for e in &entries {
        *families.entry(e.family.clone()).or_insert(0usize) += 1;
        *accesses.entry(e.cli_access.clone()).or_insert(0usize) += 1;
    }
    let rows = if full {
        serde_json::to_value(entries)?
    } else {
        Value::Array(entries.iter().map(|e|json!({"name":e.name,"family":e.family,"operation":e.operation,"catalog_access":e.cli_access})).collect())
    };
    Ok(
        json!({"count":rows.as_array().map_or(0,Vec::len),"families":families,"access":accesses,"parity_status":"inventory and registration-input schemas complete; routes, behavior, policy, verification, and discovery remain unresolved","global_parity":parity_vector(&catalog()?),"entries":rows}),
    )
}
pub fn get(name: &str) -> Result<Option<Capability>, serde_json::Error> {
    Ok(all()?.into_iter().find(|e| e.name == name))
}
pub fn access_recipe(e: &Capability) -> Value {
    json!({"name":e.name,"family":e.family,"operation":e.operation,"scope":e.scope,"catalog_access":e.cli_access,"status":"registration_schema_complete_route_unresolved","source":e.source,"source_commit":e.source_commit,"description":e.description,"catalog_input_fields":e.input_fields,"schema_contract_sha256":e.schema_contract_sha256,"method":e.method,"path_template":e.path_template,"blocker":e.blocker,"next_command":format!("magi-cloudflare-axi tool schema {} --server <server>",e.name),"warning":"pinned registration-input schema is complete; live schema may vary by request context, and route/behavior/policy evidence remains incomplete"})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catalog_is_valid_and_baseline() {
        let c = catalog().unwrap();
        assert_eq!(c.capabilities.len(), 172);
        assert_eq!(
            c.capabilities
                .iter()
                .filter(|x| x.parity.inventory.status == InventoryStatus::Complete)
                .count(),
            172
        );
        assert_eq!(x_count(&c), 41);
    }
    #[test]
    fn capability_output_reports_schema_completion_without_route_overclaim() {
        let summary = list(None, None, false).unwrap();
        assert!(
            summary["parity_status"]
                .as_str()
                .unwrap()
                .contains("schemas complete")
        );
        assert_eq!(summary["global_parity"]["S"], 172);
        let capability = all().unwrap().into_iter().next().unwrap();
        let recipe = access_recipe(&capability);
        assert_eq!(
            recipe["status"],
            "registration_schema_complete_route_unresolved"
        );
        assert!(
            recipe["warning"]
                .as_str()
                .unwrap()
                .contains("route/behavior/policy")
        );
    }

    #[test]
    fn typed_status_rejects_cross_dimension() {
        let mut v: Value = serde_json::from_str(CATALOG).unwrap();
        v["capabilities"][0]["parity"]["inventory"]["status"] = json!("verified");
        assert!(serde_json::from_value::<Catalog>(v).is_err());
    }
    #[test]
    fn unknown_field_rejected() {
        let mut v: Value = serde_json::from_str(CATALOG).unwrap();
        v["capabilities"][0]["unexpected"] = json!(true);
        assert!(serde_json::from_value::<Catalog>(v).is_err());
    }
    #[test]
    fn semantic_validation_rejects_evidence_free_completion() {
        let mut c: Catalog = serde_json::from_str(CATALOG).unwrap();
        c.capabilities[0].parity.inventory.evidence_ids.clear();
        assert!(validate(&c).is_err());
    }

    #[test]
    fn semantic_validation_rejects_missing_completion_evidence_kind() {
        let mut c: Catalog = serde_json::from_str(CATALOG).unwrap();
        let source_ref = c.capabilities[0].source.clone();
        c.evidence.push(Evidence {
            id: "test-schema-missing".into(),
            dimension: EvidenceDimension::Schema,
            source_repo: "https://github.com/cloudflare/mcp-server-cloudflare".into(),
            source_commit: SOURCE_COMMIT.into(),
            source_ref,
            kind: EvidenceKind::Missing,
            fact: "test missing evidence".into(),
        });
        c.capabilities[0].parity.schema.status = SchemaStatus::Complete;
        c.capabilities[0].parity.schema.evidence_ids = vec!["test-schema-missing".into()];
        assert!(validate(&c).is_err());
    }
    #[test]
    fn route_external_blocked_rejects_missing_evidence() {
        let mut c: Catalog = serde_json::from_str(CATALOG).unwrap();
        let source_ref = c.capabilities[0].source.clone();
        c.evidence.push(Evidence {
            id: "test-route-missing".into(),
            dimension: EvidenceDimension::Route,
            source_repo: "https://github.com/cloudflare/mcp-server-cloudflare".into(),
            source_commit: SOURCE_COMMIT.into(),
            source_ref,
            kind: EvidenceKind::Missing,
            fact: "test missing evidence".into(),
        });
        c.capabilities[0].parity.route.status = RouteStatus::ExternalBlocked;
        c.capabilities[0].parity.route.evidence_ids = vec!["test-route-missing".into()];
        assert!(validate(&c).is_err());
    }

    #[test]
    fn verification_hermetic_rejects_missing_evidence() {
        let mut c: Catalog = serde_json::from_str(CATALOG).unwrap();
        let source_ref = c.capabilities[0].source.clone();
        c.evidence.push(Evidence {
            id: "test-verification-hermetic".into(),
            dimension: EvidenceDimension::Verification,
            source_repo: "https://github.com/cloudflare/mcp-server-cloudflare".into(),
            source_commit: SOURCE_COMMIT.into(),
            source_ref: source_ref.clone(),
            kind: EvidenceKind::HermeticVerified,
            fact: "test hermetic evidence".into(),
        });
        c.evidence.push(Evidence {
            id: "test-verification-missing".into(),
            dimension: EvidenceDimension::Verification,
            source_repo: "https://github.com/cloudflare/mcp-server-cloudflare".into(),
            source_commit: SOURCE_COMMIT.into(),
            source_ref,
            kind: EvidenceKind::Missing,
            fact: "test missing evidence".into(),
        });
        c.capabilities[0].parity.verification.status = VerificationStatus::HermeticVerified;
        c.capabilities[0].parity.verification.evidence_ids = vec![
            "test-verification-hermetic".into(),
            "test-verification-missing".into(),
        ];
        assert!(validate(&c).is_err());
    }

    #[test]
    fn discovery_verified_rejects_missing_evidence() {
        let mut c: Catalog = serde_json::from_str(CATALOG).unwrap();
        let source_ref = c.capabilities[0].source.clone();
        c.evidence.push(Evidence {
            id: "test-discovery-hermetic".into(),
            dimension: EvidenceDimension::Discovery,
            source_repo: "https://github.com/cloudflare/mcp-server-cloudflare".into(),
            source_commit: SOURCE_COMMIT.into(),
            source_ref: source_ref.clone(),
            kind: EvidenceKind::HermeticVerified,
            fact: "test hermetic evidence".into(),
        });
        c.evidence.push(Evidence {
            id: "test-discovery-missing".into(),
            dimension: EvidenceDimension::Discovery,
            source_repo: "https://github.com/cloudflare/mcp-server-cloudflare".into(),
            source_commit: SOURCE_COMMIT.into(),
            source_ref,
            kind: EvidenceKind::Missing,
            fact: "test missing evidence".into(),
        });
        c.capabilities[0].parity.discovery.status = DiscoveryStatus::Verified;
        c.capabilities[0].parity.discovery.evidence_ids = vec![
            "test-discovery-hermetic".into(),
            "test-discovery-missing".into(),
        ];
        assert!(validate(&c).is_err());
    }

    #[test]
    fn parse_catalog_rejects_aggregate_preserving_metadata_swap() {
        let mut value: Value = serde_json::from_str(CATALOG).unwrap();
        let first_description = value["capabilities"][0]["description"].clone();
        value["capabilities"][0]["description"] = value["capabilities"][1]["description"].clone();
        value["capabilities"][1]["description"] = first_description;
        assert!(parse_catalog(&serde_json::to_string(&value).unwrap()).is_err());
    }

    #[test]
    fn external_blocker_union_counts_each_record_once() {
        let mut c: Catalog = serde_json::from_str(CATALOG).unwrap();
        let baseline = x_count(&c);
        c.capabilities[0].parity.route.status = RouteStatus::ExternalBlocked;
        assert_eq!(x_count(&c), baseline + 1);
        c.capabilities[0].parity.external_blocker.status = ExternalBlockerStatus::Open;
        assert_eq!(x_count(&c), baseline + 1);
    }

    fn rebind_schema_artifacts(catalog: &mut Catalog, bundle: &Value, fixtures: &mut Value) {
        let bundle_hash = json_sha256(bundle).unwrap();
        fixtures["bundle_sha256"] = Value::String(bundle_hash.clone());
        catalog.schema_artifacts.bundle_sha256 = bundle_hash;
        catalog.schema_artifacts.fixtures_sha256 = json_sha256(fixtures).unwrap();
    }

    fn rebind_schema_contract(
        catalog: &mut Catalog,
        bundle: &mut Value,
        fixtures: &mut Value,
        index: usize,
    ) {
        let contract = &mut bundle["contracts"][index];
        contract["contract_sha256"] = Value::Null;
        let contract_hash = json_sha256(contract).unwrap();
        contract["contract_sha256"] = Value::String(contract_hash.clone());
        catalog.capabilities[index].schema_contract_sha256 = contract_hash;
        rebind_schema_artifacts(catalog, bundle, fixtures);
    }

    #[test]
    fn schema_evidence_requires_exact_upstream_provenance() {
        let mut catalog: Catalog = serde_json::from_str(CATALOG).unwrap();
        let evidence = catalog
            .evidence
            .iter_mut()
            .find(|item| item.id == SCHEMA_EVIDENCE_ID)
            .unwrap();
        evidence.source_ref = "capabilities/cloudflare-input-schemas.json".into();
        assert!(validate(&catalog).is_err());
    }

    #[test]
    fn schema_artifacts_reject_fabricated_status_after_hash_rebinding() {
        let mut catalog: Catalog = serde_json::from_str(CATALOG).unwrap();
        let mut bundle: Value = serde_json::from_str(SCHEMAS).unwrap();
        let mut fixtures: Value = serde_json::from_str(FIXTURES).unwrap();
        let contract = &mut bundle["contracts"][0];
        contract["status"] = Value::String("fabricated".into());
        contract["contract_sha256"] = Value::Null;
        let contract_hash = json_sha256(contract).unwrap();
        contract["contract_sha256"] = Value::String(contract_hash.clone());
        catalog.capabilities[0].schema_contract_sha256 = contract_hash;
        rebind_schema_artifacts(&mut catalog, &bundle, &mut fixtures);
        assert!(validate_schema_artifact_values(&catalog, &bundle, &fixtures).is_err());
    }

    #[test]
    fn schema_artifacts_derive_status_counts_after_hash_rebinding() {
        let mut catalog: Catalog = serde_json::from_str(CATALOG).unwrap();
        let mut bundle: Value = serde_json::from_str(SCHEMAS).unwrap();
        let mut fixtures: Value = serde_json::from_str(FIXTURES).unwrap();
        let index = bundle["contracts"]
            .as_array()
            .unwrap()
            .iter()
            .position(|contract| contract["status"] == "candidate_zero_input")
            .unwrap();
        let contract = &mut bundle["contracts"][index];
        contract["status"] = Value::String("candidate_complete".into());
        contract["contract_sha256"] = Value::Null;
        let contract_hash = json_sha256(contract).unwrap();
        contract["contract_sha256"] = Value::String(contract_hash.clone());
        catalog.capabilities[index].schema_contract_sha256 = contract_hash;
        catalog.capabilities[index].parity.schema.status = SchemaStatus::Complete;
        rebind_schema_artifacts(&mut catalog, &bundle, &mut fixtures);
        assert!(validate_schema_artifact_values(&catalog, &bundle, &fixtures).is_err());
    }

    #[test]
    fn schema_artifacts_reject_malformed_provenance_after_hash_rebinding() {
        for (field, value) in [
            ("source_blob_oid", Value::String("bad".into())),
            (
                "registration_span",
                json!({"start_byte": 1, "end_byte": 1, "start_line": 1, "end_line": 1}),
            ),
            ("schema_span", Value::Null),
        ] {
            let mut catalog: Catalog = serde_json::from_str(CATALOG).unwrap();
            let mut bundle: Value = serde_json::from_str(SCHEMAS).unwrap();
            let mut fixtures: Value = serde_json::from_str(FIXTURES).unwrap();
            let contract = &mut bundle["contracts"][0];
            contract[field] = value;
            contract["contract_sha256"] = Value::Null;
            let contract_hash = json_sha256(contract).unwrap();
            contract["contract_sha256"] = Value::String(contract_hash.clone());
            catalog.capabilities[0].schema_contract_sha256 = contract_hash;
            rebind_schema_artifacts(&mut catalog, &bundle, &mut fixtures);
            assert!(validate_schema_artifact_values(&catalog, &bundle, &fixtures).is_err());
        }
    }

    #[test]
    fn schema_artifacts_reject_dependency_provenance_removal_after_hash_rebinding() {
        for remove_field in [false, true] {
            let mut catalog: Catalog = serde_json::from_str(CATALOG).unwrap();
            let mut bundle: Value = serde_json::from_str(SCHEMAS).unwrap();
            let mut fixtures: Value = serde_json::from_str(FIXTURES).unwrap();
            let index = bundle["contracts"]
                .as_array()
                .unwrap()
                .iter()
                .position(|contract| {
                    contract["dependency_provenance"]
                        .as_array()
                        .is_some_and(|entries| !entries.is_empty())
                })
                .unwrap();
            if remove_field {
                bundle["contracts"][index]
                    .as_object_mut()
                    .unwrap()
                    .remove("dependency_provenance");
            } else {
                bundle["contracts"][index]["dependency_provenance"] = json!([]);
            }
            rebind_schema_contract(&mut catalog, &mut bundle, &mut fixtures, index);
            assert!(validate_schema_artifact_values(&catalog, &bundle, &fixtures).is_err());
        }
    }

    #[test]
    fn schema_artifacts_reject_fabricated_dependency_after_hash_rebinding() {
        let mut catalog: Catalog = serde_json::from_str(CATALOG).unwrap();
        let mut bundle: Value = serde_json::from_str(SCHEMAS).unwrap();
        let mut fixtures: Value = serde_json::from_str(FIXTURES).unwrap();
        let index = bundle["contracts"]
            .as_array()
            .unwrap()
            .iter()
            .position(|contract| {
                contract["dependency_provenance"]
                    .as_array()
                    .is_some_and(|entries| !entries.is_empty())
            })
            .unwrap();
        bundle["contracts"][index]["dependency_provenance"][0]["name"] =
            Value::String("fabricated".into());
        rebind_schema_contract(&mut catalog, &mut bundle, &mut fixtures, index);
        assert!(validate_schema_artifact_values(&catalog, &bundle, &fixtures).is_err());
    }

    #[test]
    fn schema_artifacts_reject_unresolved_reason_after_hash_rebinding() {
        let mut catalog: Catalog = serde_json::from_str(CATALOG).unwrap();
        let mut bundle: Value = serde_json::from_str(SCHEMAS).unwrap();
        let mut fixtures: Value = serde_json::from_str(FIXTURES).unwrap();
        bundle["contracts"][0]["unresolved_reasons"] = json!(["fabricated"]);
        rebind_schema_contract(&mut catalog, &mut bundle, &mut fixtures, 0);
        assert!(validate_schema_artifact_values(&catalog, &bundle, &fixtures).is_err());
    }

    #[test]
    fn schema_artifacts_reject_malformed_dependency_source_after_hash_rebinding() {
        for (field, value) in [
            ("source_sha256", Value::String("bad".into())),
            ("blob_oid", Value::String("bad".into())),
            (
                "source_span",
                json!({"start_byte": 1, "end_byte": 1, "start_line": 1, "end_line": 1}),
            ),
        ] {
            let mut catalog: Catalog = serde_json::from_str(CATALOG).unwrap();
            let mut bundle: Value = serde_json::from_str(SCHEMAS).unwrap();
            let mut fixtures: Value = serde_json::from_str(FIXTURES).unwrap();
            let index = bundle["contracts"]
                .as_array()
                .unwrap()
                .iter()
                .position(|contract| {
                    contract["dependency_provenance"]
                        .as_array()
                        .is_some_and(|entries| !entries.is_empty())
                })
                .unwrap();
            bundle["contracts"][index]["dependency_provenance"][0][field] = value;
            rebind_schema_contract(&mut catalog, &mut bundle, &mut fixtures, index);
            assert!(validate_schema_artifact_values(&catalog, &bundle, &fixtures).is_err());
        }
    }

    #[test]
    fn schema_artifacts_reject_wrong_dialect_after_hash_rebinding() {
        let mut catalog: Catalog = serde_json::from_str(CATALOG).unwrap();
        let mut bundle: Value = serde_json::from_str(SCHEMAS).unwrap();
        let mut fixtures: Value = serde_json::from_str(FIXTURES).unwrap();
        bundle["dialect"] = Value::String("https://example.com/schema".into());
        rebind_schema_artifacts(&mut catalog, &bundle, &mut fixtures);
        assert!(validate_schema_artifact_values(&catalog, &bundle, &fixtures).is_err());
    }
}
