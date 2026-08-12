use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const CATALOG: &str = include_str!("../capabilities/cloudflare-mcp-parity.json");
const SCHEMAS: &str = include_str!("../capabilities/cloudflare-input-schemas.json");
const FIXTURES: &str = include_str!("../capabilities/cloudflare-schema-fixtures.json");
const OPERATIONS: &str = include_str!("../capabilities/cloudflare-operation-contracts.json");
pub const SOURCE_COMMIT: &str = "70ff690553722f731849ede6ba9ce98958395a23";
const OPERATION_BUNDLE_SHA256: &str =
    "9c083c24d8fb3a88196534ed74fc391d5336f545be20fc8c7e1c6b9cf4fffc68";
const OPERATION_NAMES: [&str; 9] = [
    "d1_database_delete",
    "d1_database_get",
    "get_post",
    "get_url_html_content",
    "graphql_schema_overview",
    "list_posts",
    "list_tags",
    "search_cloudflare_documentation",
    "search_posts",
];
const OPERATION_HASHES: [&str; 9] = [
    "d20fe0588da599ada8ff20f3baba6e948041033b6b635546943ec423173970da",
    "6f17fcc6c6d39125a11e32b7716f3d3f8f96ea2048eb2d7a55ef15f5ca8bd5c7",
    "c8db96e377307473c88cd2948acb864dd48016ab131b668941c1dec0b43af4e1",
    "5a84bbcdbead36b9caae6cde60445f71d614681f387d0b0b02ee2b6e4c2b4909",
    "72fdb97a538fc6cf3a465e62c9d612a59605cc3829a21d08d3918a016d53d0cc",
    "f9a765b3d1a962ab8d09cbdf304f855cbdbe87a03b73a9e280b343d4bec0a46c",
    "7702537f950b693041ce32f2dc8d8c82c226cf4058b45319e060383a0095b2bd",
    "9c1240a95b266aebc995c0a4bd8aa08cb7a5bc25a8bd562162336a75e7f2aa41",
    "50cedf16e00086e8505bee4d83bfe202687f5d15eaffa3e7f71723651a3cae91",
];
const DENOMINATOR: usize = 172;
const DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";
const SCHEMA_EVIDENCE_ID: &str = "ev-phase1-canonical-schemas";
const SCHEMA_SOURCE_REF: &str = "https://github.com/cloudflare/mcp-server-cloudflare/commit/70ff690553722f731849ede6ba9ce98958395a23";
const SCHEMA_EVIDENCE_FACT: &str = "Registration-input schemas originate from exact pinned upstream registration files and dependency declarations enumerated by source file, blob, span, and expression hash in local capabilities/cloudflare-input-schemas.json; local artifact identity is bound separately by schema_artifacts and per-capability contract hashes.";
const DEPENDENCY_PROVENANCE_COUNT: usize = 803;
const DEPENDENCY_PROVENANCE_SHA256: &str =
    "bd6c83d69c8464ec0d5b428a2631972aa1d30acabdf89f310b1a06f8d5678d04";
const LEGACY_METADATA_SHA256: &str =
    "fd27d3dbd35b4fb0c098aa3160bf563482f01bab7e37870c4e178761f39d40d1";
const LEGACY_METADATA_FNV1A: u64 = 0x1ab48618bee73ca1;

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
#[serde(tag = "kind", deny_unknown_fields)]
pub enum EvidenceProvenance {
    #[serde(rename = "missing")]
    Missing { context_ref: String, fact: String },
    #[serde(rename = "pinned_git")]
    PinnedGit {
        repo: String,
        commit: String,
        source_ref: String,
        blob: Option<String>,
        span: Option<String>,
        source_sha256: Option<String>,
    },
    #[serde(rename = "official_docs")]
    OfficialDocs {
        url: String,
        documentation_date: String,
        fact_sha256: String,
    },
    #[serde(rename = "generated_artifact")]
    GeneratedArtifact {
        artifact: String,
        sha256: String,
        fact: String,
        #[serde(default)]
        capability: Option<String>,
        #[serde(default)]
        contract_sha256: Option<String>,
    },
    #[serde(rename = "hermetic_test")]
    HermeticTest { test_id: String, fact: String },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub id: String,
    pub dimension: EvidenceDimension,
    pub fact: String,
    pub provenance: EvidenceProvenance,
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
pub struct OperationContractArtifact {
    pub capability: String,
    pub contract_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationArtifacts {
    pub path: String,
    pub bundle_sha256: String,
    pub contracts: Vec<OperationContractArtifact>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub schema_version: u32,
    pub catalog_id: String,
    pub source: Source,
    pub schema_artifacts: SchemaArtifacts,
    pub operation_artifacts: OperationArtifacts,
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
fn provenance_is(provenance: &EvidenceProvenance, expected: &str) -> bool {
    matches!(
        (provenance, expected),
        (EvidenceProvenance::Missing { .. }, "missing")
            | (EvidenceProvenance::PinnedGit { .. }, "pinned_git")
            | (EvidenceProvenance::OfficialDocs { .. }, "official_docs")
            | (
                EvidenceProvenance::GeneratedArtifact { .. },
                "generated_artifact"
            )
            | (EvidenceProvenance::HermeticTest { .. }, "hermetic_test")
    )
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
        if item.dimension != dimension || item.fact.is_empty() {
            return Err(invalid("evidence dimension or fact mismatch"));
        }
        validate_provenance(item)?;
        used.insert(id);
    }
    Ok(())
}

fn has_provenance(ids: &[String], evidence: &BTreeMap<&str, &Evidence>, expected: &str) -> bool {
    ids.iter().any(|id| {
        evidence
            .get(id.as_str())
            .is_some_and(|item| provenance_is(&item.provenance, expected))
    })
}

fn has_authoritative_evidence(ids: &[String], evidence: &BTreeMap<&str, &Evidence>) -> bool {
    has_provenance(ids, evidence, "pinned_git") || has_provenance(ids, evidence, "official_docs")
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

fn safe_relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
}

fn valid_source_ref(value: &str) -> bool {
    if value == SCHEMA_SOURCE_REF {
        return true;
    }
    let Some((path, location)) = value.rsplit_once(':') else {
        return false;
    };
    safe_relative_path(path) && location.split(';').all(valid_line_span)
}

fn valid_line_span(value: &str) -> bool {
    value.split(';').all(|part| {
        if let Ok(line) = part.parse::<usize>() {
            return line > 0;
        }
        let Some((start, end)) = part.split_once('-') else {
            return false;
        };
        start.parse::<usize>().is_ok_and(|s| s > 0)
            && end
                .parse::<usize>()
                .is_ok_and(|e| e >= start.parse::<usize>().unwrap_or(0))
    })
}

fn valid_date(value: &str) -> bool {
    let Ok(parts) = value
        .split('-')
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
    else {
        return false;
    };
    if parts.len() != 3 || value.len() != 10 {
        return false;
    }
    let (year, month, day) = (parts[0], parts[1], parts[2]);
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let maximum = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=maximum).contains(&day)
}

fn valid_test_id(value: &str) -> bool {
    let Some((path, name)) = value.split_once("::") else {
        return false;
    };
    path.starts_with("tests/")
        && path.ends_with(".rs")
        && safe_relative_path(path)
        && !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn validate_provenance(item: &Evidence) -> Result<(), serde_json::Error> {
    let valid = match &item.provenance {
        EvidenceProvenance::Missing { context_ref, fact } => {
            !context_ref.is_empty() && fact == &item.fact
        }
        EvidenceProvenance::PinnedGit {
            repo,
            commit,
            source_ref,
            blob,
            span,
            source_sha256,
        } => {
            let exact = match (blob, span, source_sha256) {
                (None, None, None) => true,
                (Some(blob), Some(span), Some(hash)) => {
                    is_lower_hex(Some(blob), 40)
                        && valid_line_span(span)
                        && is_lower_hex(Some(hash), 64)
                }
                _ => false,
            };
            repo == "https://github.com/cloudflare/mcp-server-cloudflare"
                && commit == SOURCE_COMMIT
                && valid_source_ref(source_ref)
                && exact
        }
        EvidenceProvenance::OfficialDocs {
            url,
            documentation_date,
            fact_sha256,
        } => {
            url::Url::parse(url).is_ok_and(|parsed| {
                parsed.scheme() == "https"
                    && parsed.host_str().is_some()
                    && parsed.username().is_empty()
                    && parsed.password().is_none()
                    && parsed.query().is_none()
                    && parsed.fragment().is_none()
            }) && valid_date(documentation_date)
                && is_lower_hex(Some(fact_sha256), 64)
        }
        EvidenceProvenance::GeneratedArtifact {
            artifact,
            sha256,
            fact,
            capability,
            contract_sha256,
        } => {
            [
                "capabilities/cloudflare-input-schemas.json",
                "capabilities/cloudflare-operation-contracts.json",
            ]
            .contains(&artifact.as_str())
                && safe_relative_path(artifact)
                && is_lower_hex(Some(sha256), 64)
                && fact == &item.fact
                && match (capability, contract_sha256) {
                    (None, None) => true,
                    (Some(name), Some(hash)) => !name.is_empty() && is_lower_hex(Some(hash), 64),
                    _ => false,
                }
        }
        EvidenceProvenance::HermeticTest { test_id, fact } => {
            valid_test_id(test_id) && fact == &item.fact
        }
    };
    if valid {
        Ok(())
    } else {
        Err(invalid(format!("invalid provenance for {}", item.id)))
    }
}

fn legacy_metadata_checksum_from_catalog(catalog: &Catalog) -> Result<u64, serde_json::Error> {
    let mut capabilities = serde_json::to_value(&catalog.capabilities)?;
    let rows = capabilities
        .as_array_mut()
        .ok_or_else(|| invalid("typed catalog capabilities must be an array"))?;
    for capability in &mut *rows {
        capability
            .as_object_mut()
            .ok_or_else(|| invalid("typed catalog capability must be an object"))?
            .retain(|key, value| {
                ![
                    "source_ref",
                    "parity",
                    "input_fields",
                    "schema_contract_sha256",
                ]
                .contains(&key.as_str())
                    && !value.is_null()
            });
    }
    let encoded = serde_json::to_vec(&canonical_json(Value::Array(rows.clone())))
        .map_err(|error| invalid(error.to_string()))?;
    Ok(encoded.iter().fold(0xcbf29ce484222325u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    }))
}

fn validate_operation_contract(contract: &Value) -> Result<(), serde_json::Error> {
    let transport = contract["route"]["transport"]
        .as_str()
        .ok_or_else(|| invalid("operation route transport required"))?;
    let operation = contract["safety"]["operation"].as_str().unwrap_or("");
    let retry = contract["safety"]["retry_policy"].as_str().unwrap_or("");
    if !["rest", "graphql", "mcp"].contains(&transport)
        || contract["implementation"]["status"] != "verified"
        || contract["route"]["auth"].as_str().is_none()
        || ((operation == "write" && retry != "never")
            || (operation != "write" && !matches!(retry, "never" | "transient_read")))
    {
        return Err(invalid("unsupported operation contract"));
    }
    if transport == "mcp"
        && (contract["route"]["auth"] != "none"
            || contract["route"]["method"] != "tools/call"
            || contract["route"]["protocol"] != "2026-07-28"
            || contract["route"]["tool"] != contract["capability"])
    {
        return Err(invalid("MCP operation route mismatch"));
    }
    if ["get_post", "list_posts", "list_tags", "search_posts"]
        .contains(&contract["capability"].as_str().unwrap_or(""))
    {
        let host = if contract["capability"] == "search_posts" {
            "search.blog.cloudflare.com"
        } else {
            "blog.cloudflare.com"
        };
        let method = if contract["capability"] == "search_posts" {
            "POST"
        } else {
            "GET"
        };
        let handler = &contract["evidence"]["pinned_handler"];
        let deployment = &contract["evidence"]["pinned_deployment"];
        let (handler_lines, handler_sha) = match contract["capability"].as_str().unwrap_or("") {
            "get_post" => (
                "182-216",
                "19ab680af0684117663fc33a93d6a3b32f1ea00d5fd6b739a1403e28086e449f",
            ),
            "list_posts" => (
                "132-178",
                "823824afc90a47456d129f8b165116954f5e9aa7515c49ab669c6b82dd3c739e",
            ),
            "list_tags" => (
                "220-250",
                "2326d45ff50c4d1f2dc202ccc70a5c2a1d46124b5ffba213c4aa546349b6aeaa",
            ),
            "search_posts" => (
                "38-128",
                "d034bddda8639a9f034c05df5ee4d9287ea05fb59aad85bd7e58ea01481e6334",
            ),
            _ => unreachable!(),
        };
        if operation != "read"
            || contract["safety"]["destructive"] != false
            || contract["safety"]["metered"] != false
            || contract["safety"]["data_egress"] != false
            || contract["safety"]["long_running"] != false
            || retry != "never"
            || contract["route"]["transport"] != "rest"
            || contract["route"]["host"] != host
            || contract["route"]["method"] != method
            || contract["route"]["auth"] != "none"
            || contract["implementation"]["adapter"] != "rest"
            || handler["commit"] != SOURCE_COMMIT
            || handler["file"] != "apps/cloudflare-blog/src/tools/blog.tools.ts"
            || handler["blob_oid"] != "8088b2d44ad256afd06493fe266d2d6089103559"
            || handler["lines"] != handler_lines
            || handler["source_sha256"] != handler_sha
            || deployment["commit"] != SOURCE_COMMIT
            || deployment["file"] != "apps/cloudflare-blog/wrangler.jsonc"
            || deployment["blob_oid"] != "ca5c1716fa35da43a862c1902f3822bba2a314ee"
            || deployment["lines"] != "25-30;67-82"
            || deployment["source_sha256"]
                != "5daaacef4ef444ff1137b1466a0c402934bf13e6f8ed00751717f88006a5c05f"
        {
            return Err(invalid("Cloudflare Blog evidence or safety mismatch"));
        }
    }
    Ok(())
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

fn completed_route_matches(row: &Capability, contract: &Value) -> bool {
    let route = &contract["route"];
    let blog = ["get_post", "list_posts", "list_tags", "search_posts"].contains(&row.name.as_str());
    let transport_matches = if row.name == "get_url_html_content" {
        row.transport == "rest" && row.method.as_deref() == Some("POST")
    } else if row.name == "search_cloudflare_documentation" {
        row.transport == "mcp"
    } else if blog {
        row.transport == "public_http"
            && row.method.as_deref() == contract["route"]["method"].as_str()
    } else {
        row.transport == route["transport"]
    };
    transport_matches && row.scope == route["scope"]
}

fn validate_operation_evidence(
    row: &Capability,
    contract: &Value,
    evidence: &BTreeMap<&str, &Evidence>,
) -> Result<(), serde_json::Error> {
    let capability = row.name.as_str();
    let blog = ["get_post", "list_posts", "list_tags", "search_posts"].contains(&capability);
    let complete = |dimension| match dimension {
        "route" => row.parity.route.status == RouteStatus::Complete,
        "behavior" => matches!(
            row.parity.behavior.status,
            BehaviorStatus::Specified | BehaviorStatus::Verified
        ),
        "policy" => matches!(
            row.parity.policy.status,
            PolicyStatus::Classified | PolicyStatus::Verified
        ),
        "verification" => row.parity.verification.status == VerificationStatus::HermeticVerified,
        "discovery" => matches!(
            row.parity.discovery.status,
            DiscoveryStatus::Generated | DiscoveryStatus::Verified
        ),
        _ => false,
    };
    let ids = |dimension| match dimension {
        "route" => &row.parity.route.evidence_ids,
        "behavior" => &row.parity.behavior.evidence_ids,
        "policy" => &row.parity.policy.evidence_ids,
        "verification" => &row.parity.verification.evidence_ids,
        "discovery" => &row.parity.discovery.evidence_ids,
        _ => unreachable!(),
    };
    for dimension in ["route", "behavior", "policy", "verification", "discovery"] {
        if !complete(dimension) {
            continue;
        }
        for id in ids(dimension) {
            let item = evidence
                .get(id.as_str())
                .ok_or_else(|| invalid("operation evidence missing"))?;
            let pinned = &contract["evidence"]["pinned_handler"];
            let authoritative = match &item.provenance {
                EvidenceProvenance::PinnedGit {
                    repo,
                    commit,
                    source_ref,
                    blob,
                    span,
                    source_sha256,
                    ..
                } => {
                    *repo == "https://github.com/cloudflare/mcp-server-cloudflare"
                        && *commit == SOURCE_COMMIT
                        && source_ref
                            == &format!(
                                "{}:{}",
                                pinned["file"].as_str().unwrap_or(""),
                                pinned["lines"].as_str().unwrap_or("")
                            )
                        && blob.as_deref() == pinned["blob_oid"].as_str()
                        && span.as_deref() == pinned["lines"].as_str()
                        && source_sha256.as_deref() == pinned["source_sha256"].as_str()
                }
                EvidenceProvenance::OfficialDocs {
                    url,
                    documentation_date,
                    fact_sha256,
                } => contract["evidence"]["official_docs"]
                    .as_object()
                    .is_some_and(|docs| {
                        Some(url.as_str()) == docs.get("url").and_then(Value::as_str)
                            && Some(documentation_date.as_str())
                                == docs.get("documentation_date").and_then(Value::as_str)
                            && Some(fact_sha256.as_str())
                                == docs.get("fact_sha256").and_then(Value::as_str)
                    }),
                _ => false,
            };
            let test = matches!(&item.provenance, EvidenceProvenance::HermeticTest { test_id, .. } if test_id.as_str() == contract["implementation"]["test_id"].as_str().unwrap_or(""));
            let applicable = match dimension {
                "route" => authoritative,
                "behavior" | "policy" => authoritative || test,
                "verification" => test,
                "discovery" => match &item.provenance {
                    EvidenceProvenance::GeneratedArtifact {
                        artifact,
                        capability: bound,
                        contract_sha256,
                        ..
                    } => {
                        artifact == "capabilities/cloudflare-operation-contracts.json"
                            && bound.as_deref() == Some(capability)
                            && contract_sha256.as_deref() == contract["contract_sha256"].as_str()
                    }
                    EvidenceProvenance::HermeticTest { test_id, .. } => {
                        blog && test_id
                            == "tests/integration.rs::capability_blog_discovery_examples_are_exact"
                    }
                    _ => false,
                },
                _ => false,
            };
            if !applicable {
                return Err(invalid(
                    "completed operation evidence does not reverse-join contract",
                ));
            }
        }
    }
    Ok(())
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
    if legacy_metadata_checksum_from_catalog(c)? != LEGACY_METADATA_FNV1A {
        return Err(invalid("per-capability legacy metadata checksum mismatch"));
    }

    if c.schema_version != 3
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
            item.id.is_empty() || item.fact.is_empty() || validate_provenance(item).is_err()
        })
    {
        return Err(invalid("invalid or duplicate evidence"));
    }

    let operations: Value = serde_json::from_str(OPERATIONS)?;
    let mut operation_root = operations.clone();
    operation_root["bundle_sha256"] = Value::Null;
    let contracts = operations["contracts"]
        .as_array()
        .ok_or_else(|| invalid("operation contracts array required"))?;
    if operations["version"] != "phase3-operation-contracts-v1"
        || operations["source_commit"] != SOURCE_COMMIT
        || json_sha256(&operation_root)? != OPERATION_BUNDLE_SHA256
        || contracts
            .iter()
            .map(|c| c["capability"].as_str().unwrap_or(""))
            .collect::<Vec<_>>()
            != OPERATION_NAMES
        || operations["bundle_sha256"] != OPERATION_BUNDLE_SHA256
    {
        return Err(invalid("operation envelope pin mismatch"));
    }
    for (index, contract) in contracts.iter().enumerate() {
        validate_operation_contract(contract)?;
        let mut unhashed = contract.clone();
        unhashed["contract_sha256"] = Value::Null;
        if contract["contract_sha256"] != OPERATION_HASHES[index]
            || json_sha256(&unhashed)? != OPERATION_HASHES[index]
        {
            return Err(invalid("operation contract hash mismatch"));
        }
    }
    let _artifact_bindings = contracts
        .iter()
        .map(|contract| {
            Ok((
                contract["capability"]
                    .as_str()
                    .ok_or_else(|| invalid("operation capability required"))?,
                contract["contract_sha256"]
                    .as_str()
                    .ok_or_else(|| invalid("operation contract hash required"))?,
            ))
        })
        .collect::<Result<Vec<_>, serde_json::Error>>()?;
    let catalog_bindings = c
        .operation_artifacts
        .contracts
        .iter()
        .map(|binding| {
            (
                binding.capability.as_str(),
                binding.contract_sha256.as_str(),
            )
        })
        .collect::<Vec<_>>();
    if c.operation_artifacts.path != "capabilities/cloudflare-operation-contracts.json"
        || c.operation_artifacts.bundle_sha256 != OPERATION_BUNDLE_SHA256
        || catalog_bindings != _artifact_bindings
    {
        return Err(invalid("operation artifact binding mismatch"));
    }
    let schema_bundle: Value = serde_json::from_str(SCHEMAS)?;
    for item in &c.evidence {
        if let EvidenceProvenance::GeneratedArtifact {
            artifact,
            sha256,
            capability,
            contract_sha256,
            ..
        } = &item.provenance
        {
            let (actual, artifact_contracts) = match artifact.as_str() {
                "capabilities/cloudflare-input-schemas.json" => (
                    json_sha256(&schema_bundle)?,
                    schema_bundle["contracts"].as_array(),
                ),
                "capabilities/cloudflare-operation-contracts.json" => {
                    (json_sha256(&operations)?, Some(contracts))
                }
                _ => return Err(invalid("unknown generated artifact")),
            };
            let binding_valid = match (capability.as_deref(), contract_sha256.as_deref()) {
                (None, None) => true,
                (Some(name), Some(hash)) => artifact_contracts.is_some_and(|rows| {
                    rows.iter().any(|row| {
                        row["capability"].as_str() == Some(name)
                            && row["contract_sha256"].as_str() == Some(hash)
                    })
                }),
                _ => false,
            };
            if sha256 != &actual || !binding_valid {
                return Err(invalid("generated artifact provenance mismatch"));
            }
        }
    }
    let schema_evidence = evidence
        .get(SCHEMA_EVIDENCE_ID)
        .ok_or_else(|| invalid("Phase 1 schema evidence required"))?;
    if schema_evidence.dimension != EvidenceDimension::Schema
        || !matches!(&schema_evidence.provenance, EvidenceProvenance::PinnedGit { source_ref, blob: None, span: None, source_sha256: None, .. } if source_ref == SCHEMA_SOURCE_REF)
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
        let operation_complete = row.parity.route.status == RouteStatus::Complete
            || matches!(
                row.parity.behavior.status,
                BehaviorStatus::Specified | BehaviorStatus::Verified
            )
            || matches!(
                row.parity.policy.status,
                PolicyStatus::Classified | PolicyStatus::Verified
            )
            || row.parity.verification.status == VerificationStatus::HermeticVerified
            || matches!(
                row.parity.discovery.status,
                DiscoveryStatus::Generated | DiscoveryStatus::Verified
            );
        let contract = contracts
            .iter()
            .find(|contract| contract["capability"] == row.name);
        if operation_complete && contract.is_none() {
            return Err(invalid("completed operation dimension lacks contract"));
        }
        if let Some(contract) = contract {
            validate_operation_evidence(row, contract, &evidence)?;
        }
        let inventory_evidence = evidence
            .get(row.parity.inventory.evidence_ids[0].as_str())
            .ok_or_else(|| invalid("missing inventory evidence"))?;
        if !matches!(&inventory_evidence.provenance, EvidenceProvenance::PinnedGit { source_ref, .. } if source_ref == &row.source)
        {
            return Err(invalid("inventory evidence mismatch"));
        }
        if row.parity.route.status == RouteStatus::Complete {
            let contract = contracts
                .iter()
                .find(|contract| contract["capability"] == row.name)
                .ok_or_else(|| invalid("completed route lacks operation contract"))?;
            if !completed_route_matches(row, contract) {
                return Err(invalid("completed route does not match operation contract"));
            }
        }
        let schema_complete = matches!(
            row.parity.schema.status,
            SchemaStatus::Complete | SchemaStatus::ZeroInputEvidenced
        );
        let route_complete = matches!(
            row.parity.route.status,
            RouteStatus::Complete | RouteStatus::ExternalBlocked
        );
        let missing = |ids: &[String]| has_provenance(ids, &evidence, "missing");
        let hermetic = |ids: &[String]| has_provenance(ids, &evidence, "hermetic_test");
        let generated = |ids: &[String]| has_provenance(ids, &evidence, "generated_artifact");
        if (schema_complete
            && (!has_authoritative_evidence(&row.parity.schema.evidence_ids, &evidence)
                || missing(&row.parity.schema.evidence_ids)))
            || (route_complete
                && (!has_authoritative_evidence(&row.parity.route.evidence_ids, &evidence)
                    || missing(&row.parity.route.evidence_ids)))
            || (row.parity.behavior.status == BehaviorStatus::Specified
                && !has_authoritative_evidence(&row.parity.behavior.evidence_ids, &evidence))
            || (row.parity.behavior.status == BehaviorStatus::Verified
                && (missing(&row.parity.behavior.evidence_ids)
                    || !has_authoritative_evidence(&row.parity.behavior.evidence_ids, &evidence)
                    || !hermetic(&row.parity.behavior.evidence_ids)))
            || (row.parity.policy.status == PolicyStatus::Classified
                && !has_authoritative_evidence(&row.parity.policy.evidence_ids, &evidence))
            || (row.parity.policy.status == PolicyStatus::Verified
                && (missing(&row.parity.policy.evidence_ids)
                    || !has_authoritative_evidence(&row.parity.policy.evidence_ids, &evidence)
                    || !hermetic(&row.parity.policy.evidence_ids)))
            || (row.parity.verification.status == VerificationStatus::HermeticVerified
                && (!hermetic(&row.parity.verification.evidence_ids)
                    || missing(&row.parity.verification.evidence_ids)))
            || (row.parity.discovery.status == DiscoveryStatus::Generated
                && (!generated(&row.parity.discovery.evidence_ids)
                    || missing(&row.parity.discovery.evidence_ids)))
            || (row.parity.discovery.status == DiscoveryStatus::Verified
                && (!generated(&row.parity.discovery.evidence_ids)
                    || !hermetic(&row.parity.discovery.evidence_ids)
                    || missing(&row.parity.discovery.evidence_ids)))
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
            && has_provenance(&external.evidence_ids, &evidence, "missing")
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
                ("internal_binding", 1),
                ("mcp", 1),
                ("public_http", 85),
                ("rest", 72),
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
            != 40
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
        serde_json::to_value(&entries)?
    } else {
        Value::Array(entries.iter().map(|e|json!({"name":e.name,"family":e.family,"operation":e.operation,"catalog_access":e.cli_access})).collect())
    };
    Ok(
        json!({"count":rows.as_array().map_or(0,Vec::len),"families":families,"access":accesses,"parity_status":format!("inventory and registration-input schemas complete; {} routes complete; behavior {}, policy {}, verification {}, discovery {}", entries.iter().filter(|e|e.parity.route.status == RouteStatus::Complete).count(), entries.iter().filter(|e|e.parity.behavior.status == BehaviorStatus::Verified).count(), entries.iter().filter(|e|e.parity.policy.status == PolicyStatus::Verified).count(), entries.iter().filter(|e|e.parity.verification.status == VerificationStatus::HermeticVerified).count(), entries.iter().filter(|e|e.parity.discovery.status == DiscoveryStatus::Verified).count()),"global_parity":parity_vector(&catalog()?),"entries":rows}),
    )
}
pub fn get(name: &str) -> Result<Option<Capability>, serde_json::Error> {
    Ok(all()?.into_iter().find(|e| e.name == name))
}
pub fn access_recipe(e: &Capability) -> Value {
    let route_complete = e.parity.route.status == RouteStatus::Complete;
    let verified = route_complete
        && e.parity.behavior.status == BehaviorStatus::Verified
        && e.parity.policy.status == PolicyStatus::Verified
        && e.parity.verification.status == VerificationStatus::HermeticVerified;
    json!({
        "name": e.name,
        "family": e.family,
        "operation": e.operation,
        "scope": e.scope,
        "catalog_access": e.cli_access,
        "status": if verified { "operation_verified" } else if route_complete { "registration_schema_and_route_complete" } else { "registration_schema_complete_route_unresolved" },
        "parity": e.parity,
        "source": e.source,
        "source_commit": e.source_commit,
        "description": e.description,
        "catalog_input_fields": e.input_fields,
        "schema_contract_sha256": e.schema_contract_sha256,
        "method": e.method,
        "path_template": e.path_template,
        "blocker": e.blocker,
        "next_command": if verified { match e.name.as_str() { "get_post" => "magi-cloudflare-axi capability invoke get_post --input '{\"slug\":\"<slug>\"}'".to_string(), "list_posts" | "list_tags" => format!("magi-cloudflare-axi capability invoke {} --input '{{}}'", e.name), "search_posts" => "magi-cloudflare-axi capability invoke search_posts --input '{\"query\":\"<query>\"}'".to_string(), _ => format!("magi-cloudflare-axi capability invoke {} --input '<json>'", e.name) } } else { format!("magi-cloudflare-axi tool schema {} --server <server>", e.name) },
        "warning": if verified { "route, behavior, policy, and hermetic verification are complete; discovery remains separately gated" } else { "pinned registration-input schema is complete; live schema may vary by request context, and route/behavior/policy evidence remains incomplete" }
    })
}
pub fn schema_contract(name: &str) -> Result<Option<Value>, serde_json::Error> {
    let bundle: Value = serde_json::from_str(SCHEMAS)?;
    Ok(bundle["contracts"]
        .as_array()
        .and_then(|contracts| {
            contracts
                .iter()
                .find(|contract| contract["capability"] == name)
        })
        .cloned())
}

pub fn schema(name: &str) -> Result<Value, crate::error::AppError> {
    let entry = get(name)
        .map_err(|_| crate::error::AppError::api("embedded capability inventory is invalid"))?
        .ok_or_else(|| crate::error::AppError::usage(format!("unknown capability '{name}'")))?;
    let contract = schema_contract(name)
        .map_err(|_| crate::error::AppError::api("embedded schema bundle is invalid"))?
        .ok_or_else(|| {
            crate::error::AppError::api(format!("schema unavailable for capability '{name}'"))
        })?;
    Ok(json!({
        "name": name,
        "dialect": DIALECT,
        "raw_input_schema": contract["raw_input_schema"],
        "raw_input_schema_sha256": contract["raw_input_schema_sha256"],
        "schema_contract_sha256": entry.schema_contract_sha256,
        "source": {"kind":"exact_pinned_git_blob","commit":SOURCE_COMMIT,"file":contract["source_file"],"blob_oid":contract["source_blob_oid"],"schema_span":contract["schema_span"]},
        "semantics": {"unknown_key_behavior":contract["unknown_key_behavior"],"unknown_key_policies":contract["unknown_key_policies"],"context_overlays":contract["context_overlays"],"defaults":contract["defaults"],"normalizations":contract["normalizations"],"refinements":contract["refinements"],"transforms":contract["transforms"]}
    }))
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
        assert_eq!(x_count(&c), 40);
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
    fn d1_capability_output_reports_verified_operation() {
        let capability = get("d1_database_get").unwrap().unwrap();
        let recipe = access_recipe(&capability);
        assert_eq!(recipe["status"], "operation_verified");
        assert_eq!(recipe["parity"]["route"]["status"], "complete");
        assert_eq!(recipe["parity"]["behavior"]["status"], "verified");
        assert!(
            recipe["next_command"]
                .as_str()
                .unwrap()
                .contains("capability invoke d1_database_get")
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
    fn completed_statuses_reject_missing_provenance() {
        for (dimension, status) in [
            ("route", "complete"),
            ("verification", "hermetic_verified"),
            ("discovery", "verified"),
        ] {
            let mut value: Value = serde_json::from_str(CATALOG).unwrap();
            value["evidence"].as_array_mut().unwrap().push(json!({
                "id":format!("test-{dimension}"),
                "dimension":dimension,
                "provenance":{"kind":"missing","context_ref":"tests/fixture","fact":"missing proof"},
                "fact":"missing proof"
            }));
            value["capabilities"][0]["parity"][dimension] =
                json!({"status":status,"evidence_ids":[format!("test-{dimension}")]});
            let catalog: Catalog = serde_json::from_value(value).unwrap();
            assert!(validate(&catalog).is_err(), "accepted {dimension}");
        }
    }

    #[test]
    fn provenance_variants_reject_malformed_values_and_legacy_fields() {
        let mut legacy: Value = serde_json::from_str(CATALOG).unwrap();
        legacy["evidence"][0]["source_repo"] = json!("https://example.com");
        assert!(serde_json::from_value::<Catalog>(legacy).is_err());
        for (id, provenance) in [
            (
                "git",
                json!({"kind":"pinned_git","repo":"https://example.com","commit":SOURCE_COMMIT,"source_ref":"x.ts:1","blob":null,"span":null,"source_sha256":null}),
            ),
            (
                "blob",
                json!({"kind":"pinned_git","repo":"https://github.com/cloudflare/mcp-server-cloudflare","commit":SOURCE_COMMIT,"source_ref":"x.ts:1","blob":"bad","span":"1-1","source_sha256":"bad"}),
            ),
            (
                "docs",
                json!({"kind":"official_docs","url":"http://example.com","documentation_date":"2026-02-30","fact_sha256":"bad"}),
            ),
            (
                "artifact",
                json!({"kind":"generated_artifact","artifact":"../bad","sha256":"bad","fact":"proof"}),
            ),
            (
                "test",
                json!({"kind":"hermetic_test","test_id":"bad","fact":"proof"}),
            ),
        ] {
            let evidence = Evidence {
                id: id.into(),
                dimension: EvidenceDimension::Route,
                provenance: serde_json::from_value(provenance).unwrap(),
                fact: "proof".into(),
            };
            assert!(validate_provenance(&evidence).is_err(), "accepted {id}");
        }
    }

    #[test]
    fn operation_artifact_bindings_reject_drift() {
        let mut catalog: Catalog = serde_json::from_str(CATALOG).unwrap();
        catalog.operation_artifacts.bundle_sha256 = "0".repeat(64);
        assert!(validate(&catalog).is_err());
        let mut catalog: Catalog = serde_json::from_str(CATALOG).unwrap();
        catalog.operation_artifacts.contracts[0].contract_sha256 = "0".repeat(64);
        assert!(validate(&catalog).is_err());
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
        if let EvidenceProvenance::PinnedGit { source_ref, .. } = &mut evidence.provenance {
            *source_ref = "capabilities/cloudflare-input-schemas.json".to_owned();
        }
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

#[cfg(test)]
mod operation_reverse_join_tests {
    use super::*;

    #[test]
    fn completed_route_matcher_rejects_transport_and_scope_mismatch() {
        let catalog: Catalog = serde_json::from_str(CATALOG).unwrap();
        let row = catalog
            .capabilities
            .iter()
            .find(|row| row.name == "d1_database_get")
            .unwrap();
        let operations: Value = serde_json::from_str(OPERATIONS).unwrap();
        let contract = operations["contracts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|contract| contract["capability"] == "d1_database_get")
            .unwrap();
        assert!(completed_route_matches(row, contract));
        let mut wrong = row.clone();
        wrong.transport = "graphql".into();
        assert!(!completed_route_matches(&wrong, contract));
        wrong.transport = row.transport.clone();
        wrong.scope = "zone".into();
        assert!(!completed_route_matches(&wrong, contract));
    }

    #[test]
    fn d1_operation_evidence_reverse_join_rejects_cross_capability_swaps() {
        for dimension in ["route", "behavior", "policy", "verification", "discovery"] {
            let mut catalog: Catalog = serde_json::from_str(CATALOG).unwrap();
            let get = catalog
                .capabilities
                .iter()
                .position(|row| row.name == "d1_database_get")
                .unwrap();
            let delete = catalog
                .capabilities
                .iter()
                .position(|row| row.name == "d1_database_delete")
                .unwrap();
            let operations: Value = serde_json::from_str(OPERATIONS).unwrap();
            let contract = operations["contracts"]
                .as_array()
                .unwrap()
                .iter()
                .find(|contract| contract["capability"] == "d1_database_get")
                .unwrap();
            let (left, right) = if get < delete {
                let (low, high) = catalog.capabilities.split_at_mut(delete);
                (&mut low[get], &mut high[0])
            } else {
                let (low, high) = catalog.capabilities.split_at_mut(get);
                (&mut high[0], &mut low[delete])
            };
            match dimension {
                "route" => std::mem::swap(
                    &mut left.parity.route.evidence_ids,
                    &mut right.parity.route.evidence_ids,
                ),
                "behavior" => std::mem::swap(
                    &mut left.parity.behavior.evidence_ids,
                    &mut right.parity.behavior.evidence_ids,
                ),
                "policy" => std::mem::swap(
                    &mut left.parity.policy.evidence_ids,
                    &mut right.parity.policy.evidence_ids,
                ),
                "verification" => std::mem::swap(
                    &mut left.parity.verification.evidence_ids,
                    &mut right.parity.verification.evidence_ids,
                ),
                _ => std::mem::swap(
                    &mut left.parity.discovery.evidence_ids,
                    &mut right.parity.discovery.evidence_ids,
                ),
            }
            let evidence: BTreeMap<_, _> = catalog
                .evidence
                .iter()
                .map(|item| (item.id.as_str(), item))
                .collect();
            let error =
                validate_operation_evidence(&catalog.capabilities[get], contract, &evidence)
                    .unwrap_err()
                    .to_string();
            assert!(error.contains("reverse-join"), "{dimension}: {error}");
        }
    }

    #[test]
    fn operation_reverse_join_uses_provenance_not_evidence_id_names() {
        let mut catalog: Catalog = serde_json::from_str(CATALOG).unwrap();
        let row = catalog
            .capabilities
            .iter_mut()
            .find(|row| row.name == "d1_database_get")
            .unwrap();
        let old = row.parity.route.evidence_ids[0].clone();
        let renamed = "renamed-valid-route-evidence".to_owned();
        row.parity.route.evidence_ids[0] = renamed.clone();
        catalog
            .evidence
            .iter_mut()
            .find(|item| item.id == old)
            .unwrap()
            .id = renamed;
        assert!(validate(&catalog).is_ok());
    }

    #[test]
    fn uncontracted_capability_cannot_borrow_completed_operation_evidence() {
        let baseline: Catalog = serde_json::from_str(CATALOG).unwrap();
        let source = baseline
            .capabilities
            .iter()
            .find(|row| row.name == "d1_database_get")
            .unwrap()
            .clone();
        for dimension in ["route", "behavior", "policy", "verification", "discovery"] {
            let mut catalog = baseline.clone();
            let target = catalog
                .capabilities
                .iter_mut()
                .find(|row| row.name == "ai_search")
                .unwrap();
            match dimension {
                "route" => target.parity.route = source.parity.route.clone(),
                "behavior" => target.parity.behavior = source.parity.behavior.clone(),
                "policy" => target.parity.policy = source.parity.policy.clone(),
                "verification" => target.parity.verification = source.parity.verification.clone(),
                _ => target.parity.discovery = source.parity.discovery.clone(),
            }
            let error = validate(&catalog).unwrap_err().to_string();
            assert!(error.contains("lacks contract"), "{dimension}: {error}");
        }
    }
}
