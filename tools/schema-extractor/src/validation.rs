use jsonschema::draft202012;
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Debug, Serialize)]
pub struct FixtureEnvelope {
    pub version: &'static str,
    pub dialect: &'static str,
    pub bundle_version: Value,
    pub source_commit: String,
    pub tree_oid: String,
    pub bundle_sha256: String,
    pub contract_count: usize,
    pub distinct_schema_count: usize,
    pub fixtures: Vec<SchemaFixture>,
}

#[derive(Debug, Serialize)]
pub struct SchemaFixture {
    pub raw_input_schema_sha256: String,
    pub capabilities: Vec<String>,
    pub positive: Value,
    pub negative: Value,
}

pub fn validate_bundle_file(path: &Path) -> Result<FixtureEnvelope, String> {
    let text =
        fs::read_to_string(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let bundle: Value = serde_json::from_str(&text)
        .map_err(|error| format!("parse {}: {error}", path.display()))?;
    validate_bundle(&bundle)
}

pub fn validate_bundle(bundle: &Value) -> Result<FixtureEnvelope, String> {
    validate_bundle_inner(
        bundle,
        Some((
            803,
            "bd6c83d69c8464ec0d5b428a2631972aa1d30acabdf89f310b1a06f8d5678d04",
        )),
    )
}

fn validate_bundle_inner(
    bundle: &Value,
    expected_dependency_provenance: Option<(usize, &str)>,
) -> Result<FixtureEnvelope, String> {
    const COMMIT: &str = "70ff690553722f731849ede6ba9ce98958395a23";
    const TREE: &str = "1a51c6ff07170dfe3c3212c8fb96eb85d66f0b96";
    if bundle.get("version").and_then(Value::as_str) != Some("2")
        || bundle.get("compiler_version").and_then(Value::as_str) != Some("phase1-oxc-static-0.4")
        || bundle.get("source_access").and_then(Value::as_str) != Some("exact_pinned_git_blobs")
        || bundle.get("execution_policy").and_then(Value::as_str)
            != Some(
                "static_only; never import or execute upstream TypeScript, Zod modules, registrations, or handlers",
            )
        || bundle.get("zod_version").and_then(Value::as_str) != Some("4.4.3")
        || bundle.get("source_commit").and_then(Value::as_str) != Some(COMMIT)
        || bundle.get("tree_oid").and_then(Value::as_str) != Some(TREE)
        || bundle.get("dialect").and_then(Value::as_str)
            != Some("https://json-schema.org/draft/2020-12/schema")
    {
        return Err("unsupported bundle envelope or pinned source".into());
    }
    let contracts = bundle
        .get("contracts")
        .and_then(Value::as_array)
        .ok_or_else(|| "bundle contracts must be an array".to_owned())?;
    if contracts.len() != 172
        || bundle
            .get("candidate_complete_count")
            .and_then(Value::as_u64)
            != Some(168)
        || bundle
            .get("candidate_zero_input_count")
            .and_then(Value::as_u64)
            != Some(4)
        || bundle.get("unresolved_count").and_then(Value::as_u64) != Some(0)
    {
        return Err("bundle requires 168 complete, 4 evidenced zero-input, 0 unresolved".into());
    }
    let mut schemas = BTreeMap::new();
    let mut names = Vec::new();
    let mut complete_count = 0;
    let mut zero_input_count = 0;
    let mut unresolved_count = 0;
    let mut dependency_provenance_count = 0;
    let mut dependency_provenance_by_capability = Map::new();
    for (index, contract) in contracts.iter().enumerate() {
        let name = contract
            .get("capability")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("contract {index} missing capability"))?;
        names.push(name);
        let dependency_provenance = contract
            .get("dependency_provenance")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("contract {index} missing dependency_provenance"))?;
        let dependency_ids = dependency_provenance
            .iter()
            .map(|entry| validate_dependency_provenance(entry, index))
            .collect::<Result<Vec<_>, _>>()?;
        if dependency_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(format!(
                "contract {index} dependency provenance must be sorted and unique"
            ));
        }
        dependency_provenance_count += dependency_provenance.len();
        dependency_provenance_by_capability
            .insert(name.into(), Value::Array(dependency_provenance.clone()));
        if contract
            .get("unresolved_reasons")
            .and_then(Value::as_array)
            .is_none_or(|reasons| !reasons.is_empty())
        {
            return Err(format!("contract {index} has unresolved reasons"));
        }
        match contract.get("status").and_then(Value::as_str) {
            Some("candidate_complete") => complete_count += 1,
            Some("candidate_zero_input") => zero_input_count += 1,
            Some("unresolved") => unresolved_count += 1,
            _ => return Err(format!("contract {index} has invalid status")),
        }
        let schema = contract
            .get("raw_input_schema")
            .filter(|value| !value.is_null())
            .ok_or_else(|| format!("contract {index} missing raw_input_schema"))?;
        let sha = contract
            .get("raw_input_schema_sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("contract {index} missing raw_input_schema_sha256"))?;
        let source_file = contract
            .get("source_file")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("contract {index} missing source_file"))?;
        if source_file.starts_with('/')
            || !is_lower_hex(contract.get("source_blob_oid").and_then(Value::as_str), 40)
            || !valid_span(contract.get("registration_span"))
            || !is_lower_hex(Some(sha), 64)
        {
            return Err(format!("contract {index} has invalid source provenance"));
        }
        let zero = contract.get("status").and_then(Value::as_str) == Some("candidate_zero_input");
        let semantic_provenance_valid = if zero {
            contract.get("schema_span").is_some_and(Value::is_null)
                && contract
                    .get("schema_expression_sha256")
                    .is_some_and(Value::is_null)
                && schema == &serde_json::json!({"properties": {}, "type": "object"})
        } else {
            valid_span(contract.get("schema_span"))
                && is_lower_hex(
                    contract
                        .get("schema_expression_sha256")
                        .and_then(Value::as_str),
                    64,
                )
        };
        if !semantic_provenance_valid {
            return Err(format!("contract {index} has invalid schema provenance"));
        }
        if digest_json(schema) != sha {
            return Err(format!("contract {index} raw schema hash mismatch"));
        }
        let expected_contract_hash = contract
            .get("contract_sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("contract {index} missing contract_sha256"))?;
        if !is_lower_hex(Some(expected_contract_hash), 64) {
            return Err(format!("contract {index} has invalid contract hash"));
        }
        let mut unhashed = contract.clone();
        unhashed["contract_sha256"] = Value::Null;
        if digest_json(&unhashed) != expected_contract_hash {
            return Err(format!("contract {index} contract hash mismatch"));
        }
        jsonschema::meta::validate(schema).map_err(|error| {
            format!("contract {index} schema is not a valid JSON Schema: {error}")
        })?;
        let validator = draft202012::options()
            .should_validate_formats(true)
            .build(schema)
            .map_err(|error| format!("contract {index} schema cannot compile: {error}"))?;
        match schemas.entry(sha.to_owned()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert((schema.clone(), validator, vec![name.to_owned()]));
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if entry.get().0 != *schema {
                    return Err(format!("raw schema hash {sha} has conflicting schemas"));
                }
                entry.get_mut().2.push(name.to_owned());
            }
        }
    }
    if complete_count != 168 || zero_input_count != 4 || unresolved_count != 0 {
        return Err(format!(
            "derived contract status counts mismatch: complete={complete_count}, zero_input={zero_input_count}, unresolved={unresolved_count}"
        ));
    }
    if names.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("contract capability names must be sorted and unique".into());
    }

    let derived_dependency_provenance_sha256 =
        digest_json(&Value::Object(dependency_provenance_by_capability));
    if bundle
        .get("dependency_provenance_count")
        .and_then(Value::as_u64)
        != Some(dependency_provenance_count as u64)
        || bundle
            .get("dependency_provenance_sha256")
            .and_then(Value::as_str)
            != Some(derived_dependency_provenance_sha256.as_str())
        || expected_dependency_provenance.is_some_and(|(count, hash)| {
            dependency_provenance_count != count || derived_dependency_provenance_sha256 != hash
        })
    {
        return Err("dependency provenance envelope mismatch".into());
    }
    let fixtures = schemas
        .into_iter()
        .map(|(sha, (schema, validator, capabilities))| {
            let positive = positive_instance(&schema);
            if !validator.is_valid(&positive) {
                return Err(format!("generated positive fixture is invalid for {sha}"));
            }
            let negative = negative_instance(&schema, &positive);
            if validator.is_valid(&negative) {
                return Err(format!("generated negative fixture is valid for {sha}"));
            }
            Ok(SchemaFixture {
                raw_input_schema_sha256: sha,
                capabilities,
                positive,
                negative,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let bundle_sha256 = digest_json(bundle);
    Ok(FixtureEnvelope {
        version: "schema-fixtures-v1",
        dialect: "https://json-schema.org/draft/2020-12/schema",
        bundle_version: bundle.get("version").cloned().unwrap_or(Value::Null),
        source_commit: COMMIT.into(),
        tree_oid: TREE.into(),
        bundle_sha256,
        contract_count: contracts.len(),
        distinct_schema_count: fixtures.len(),
        fixtures,
    })
}

fn is_lower_hex(value: Option<&str>, length: usize) -> bool {
    value.is_some_and(|value| {
        value.len() == length
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn validate_dependency_provenance(entry: &Value, contract_index: usize) -> Result<&str, String> {
    let object = entry
        .as_object()
        .ok_or_else(|| format!("contract {contract_index} dependency provenance must be object"))?;
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
        return Err(format!(
            "contract {contract_index} dependency provenance shape mismatch"
        ));
    }
    let text = |key: &str| {
        object[key]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                format!("contract {contract_index} dependency provenance {key} required")
            })
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
        return Err(format!(
            "contract {contract_index} dependency provenance invalid"
        ));
    }
    Ok(id)
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
    let values = ["start_byte", "end_byte", "start_line", "end_line"].map(|key| span[key].as_u64());
    let [
        Some(start_byte),
        Some(end_byte),
        Some(start_line),
        Some(end_line),
    ] = values
    else {
        return false;
    };
    start_byte < end_byte && start_line >= 1 && start_line <= end_line
}

fn digest_json(value: &Value) -> String {
    let mut bytes = Vec::new();
    write_canonical_json(value, &mut bytes);
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) {
    match value {
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output);
            }
            output.push(b']');
        }
        Value::Object(object) => {
            output.push(b'{');
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key).expect("canonical JSON key serialization");
                output.push(b':');
                write_canonical_json(&object[key], output);
            }
            output.push(b'}');
        }
        _ => serde_json::to_writer(output, value).expect("canonical JSON scalar serialization"),
    }
}

fn positive_instance(schema: &Value) -> Value {
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        return values.first().cloned().unwrap_or(Value::Null);
    }
    if let Some(value) = schema.get("const") {
        return value.clone();
    }
    for keyword in ["anyOf", "oneOf", "allOf"] {
        if let Some(branches) = schema.get(keyword).and_then(Value::as_array) {
            if let Some(branch) = branches.first() {
                return positive_instance(branch);
            }
        }
    }
    if schema.get("type").and_then(Value::as_str) == Some("array") {
        let item = schema
            .get("items")
            .map(positive_instance)
            .unwrap_or(Value::Null);
        let count = usize::from(schema.get("minItems").and_then(Value::as_u64).unwrap_or(0) > 0);
        return Value::Array(std::iter::repeat_n(item, count).collect());
    }
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        let required = schema.get("required").and_then(Value::as_array);
        let mut object = Map::new();
        for (name, child) in properties {
            if required.is_some_and(|items| items.iter().any(|item| item.as_str() == Some(name))) {
                object.insert(name.clone(), positive_instance(child));
            }
        }
        return Value::Object(object);
    }
    match schema.get("type").and_then(Value::as_str) {
        Some("string") => match schema.get("format").and_then(Value::as_str) {
            Some("uuid") => Value::String("00000000-0000-4000-8000-000000000000".into()),
            Some("date-time") => Value::String("2000-01-01T00:00:00Z".into()),
            Some("email") => Value::String("fixture@example.com".into()),
            Some("uri") => Value::String("https://example.com/".into()),
            Some("ipv4") => Value::String("192.0.2.1".into()),
            Some("ipv6") => Value::String("2001:db8::1".into()),
            _ => schema
                .get("pattern")
                .and_then(Value::as_str)
                .map(|pattern| {
                    if pattern.contains("[A-Fa-f0-9]{64}") {
                        "0000000000000000000000000000000000000000000000000000000000000000".into()
                    } else if pattern.contains("T(?:[01]\\d|2[0-3])") && pattern.ends_with("Z$") {
                        "2000-01-01T00:00:00Z".into()
                    } else if pattern.contains("[1-8][0-9a-fA-F]{3}") {
                        "550e8400-e29b-41d4-a716-446655440000".into()
                    } else if pattern.starts_with("^(?!\\.)") {
                        "fixture@example.com".into()
                    } else if (pattern.contains("-02-29|\\d{4}-") && pattern.ends_with('$'))
                        || pattern.contains("\\d{4}-\\d{2}-\\d{2}")
                    {
                        "2000-01-01".into()
                    } else if pattern.contains("[0-9]+") {
                        "1".into()
                    } else {
                        "fixture".into()
                    }
                })
                .unwrap_or_else(|| "fixture".into()),
        },
        Some("integer") => Value::Number(1.into()),
        Some("number") => serde_json::json!(1.0),
        Some("boolean") => Value::Bool(true),
        Some("array") => Value::Array(Vec::new()),
        Some("null") => Value::Null,
        _ => Value::Object(Map::new()),
    }
}

fn negative_instance(schema: &Value, positive: &Value) -> Value {
    if let (Some(required), Some(object)) = (
        schema.get("required").and_then(Value::as_array),
        positive.as_object(),
    ) {
        if let Some(name) = required.iter().filter_map(Value::as_str).next() {
            let mut invalid = object.clone();
            invalid.remove(name);
            return Value::Object(invalid);
        }
    }
    match positive {
        Value::String(_) => Value::Number(1.into()),
        Value::Number(_) => Value::String("fixture".into()),
        Value::Bool(_) => Value::String("fixture".into()),
        Value::Array(_) => Value::String("fixture".into()),
        Value::Object(_) => Value::String("fixture".into()),
        Value::Null => Value::String("fixture".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_bundle(schema: Value) -> Value {
        let contracts = (0..172)
            .map(|index| {
                let zero = index >= 168;
                let contract_schema = if zero {
                    serde_json::json!({"properties": {}, "type": "object"})
                } else {
                    schema.clone()
                };
                let schema_sha = digest_json(&contract_schema);
                let span = serde_json::json!({
                    "start_byte": 0,
                    "end_byte": 1,
                    "start_line": 1,
                    "end_line": 1
                });
                let mut contract = serde_json::json!({
                    "capability": format!("capability-{index:03}"),
                    "status": if zero { "candidate_zero_input" } else { "candidate_complete" },
                    "source_file": "fixture.ts",
                    "source_blob_oid": "0000000000000000000000000000000000000000",
                    "registration_span": span,
                    "schema_span": if zero { Value::Null } else { span },
                    "schema_expression_sha256": if zero { Value::Null } else { Value::String("0000000000000000000000000000000000000000000000000000000000000000".into()) },
                    "contract_sha256": null,
                    "raw_input_schema": contract_schema,
                    "raw_input_schema_sha256": schema_sha,
                    "dependency_provenance": [],
                    "unresolved_reasons": [],
                });
                contract["contract_sha256"] = Value::String(digest_json(&contract));
                contract
            })
            .collect::<Vec<_>>();
        let dependency_provenance_by_capability = contracts
            .iter()
            .map(|contract| {
                (
                    contract["capability"].as_str().unwrap().to_owned(),
                    contract["dependency_provenance"].clone(),
                )
            })
            .collect::<Map<_, _>>();
        let dependency_provenance_sha256 =
            digest_json(&Value::Object(dependency_provenance_by_capability));
        serde_json::json!({
            "version": "2",
            "compiler_version": "phase1-oxc-static-0.4",
            "source_access": "exact_pinned_git_blobs",
            "execution_policy": "static_only; never import or execute upstream TypeScript, Zod modules, registrations, or handlers",
            "zod_version": "4.4.3",
            "source_commit": "70ff690553722f731849ede6ba9ce98958395a23",
            "tree_oid": "1a51c6ff07170dfe3c3212c8fb96eb85d66f0b96",
            "dialect": "https://json-schema.org/draft/2020-12/schema",
            "candidate_complete_count": 168,
            "candidate_zero_input_count": 4,
            "unresolved_count": 0,
            "dependency_provenance_count": 0,
            "dependency_provenance_sha256": dependency_provenance_sha256,
            "contracts": contracts,
        })
    }

    #[test]
    fn validates_formats_hashes_and_deduplicates_schemas() {
        let bundle = fixture_bundle(serde_json::json!({"type":"string","format":"uuid"}));
        let envelope = validate_bundle_inner(&bundle, None).unwrap();
        assert_eq!(envelope.fixtures.len(), 2);
        assert_eq!(
            envelope
                .fixtures
                .iter()
                .map(|fixture| fixture.capabilities.len())
                .sum::<usize>(),
            172
        );
        assert!(
            envelope
                .fixtures
                .iter()
                .all(|fixture| fixture.positive != fixture.negative)
        );
    }

    #[test]
    fn rejects_invalid_schema_metaschema() {
        let bundle = fixture_bundle(serde_json::json!({"type":"not-a-type"}));
        assert!(validate_bundle_inner(&bundle, None).is_err());
    }

    #[test]
    fn rejects_contract_hash_drift() {
        let mut bundle = fixture_bundle(serde_json::json!({"type":"string"}));
        bundle["contracts"][0]["capability"] = Value::String("drift".into());
        assert!(validate_bundle_inner(&bundle, None).is_err());
    }
    #[test]
    fn rejects_declared_status_count_drift() {
        let mut bundle = fixture_bundle(serde_json::json!({"type":"string"}));
        bundle["contracts"][0]["status"] = Value::String("candidate_zero_input".into());
        bundle["contracts"][0]["contract_sha256"] = Value::Null;
        let hash = digest_json(&bundle["contracts"][0]);
        bundle["contracts"][0]["contract_sha256"] = Value::String(hash);
        assert!(validate_bundle_inner(&bundle, None).is_err());
    }
}
