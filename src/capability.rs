use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const CATALOG: &str = include_str!("../capabilities/cloudflare-mcp-parity.json");

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InputField {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: String,
    pub required: bool,
    #[serde(default)]
    pub default: Option<Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Capability {
    pub name: String,
    pub family: String,
    pub apps: Vec<String>,
    pub source: String,
    pub source_commit: String,
    pub description: String,
    pub input_fields: Vec<InputField>,
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
}

pub fn all() -> Result<Vec<Capability>, serde_json::Error> {
    serde_json::from_str(CATALOG)
}

pub fn list(
    family: Option<&str>,
    status: Option<&str>,
    full: bool,
) -> Result<Value, serde_json::Error> {
    let entries: Vec<_> = all()?
        .into_iter()
        .filter(|entry| family.is_none_or(|value| entry.family == value))
        .filter(|entry| status.is_none_or(|value| entry.cli_access == value))
        .collect();
    let mut families = std::collections::BTreeMap::new();
    let mut access = std::collections::BTreeMap::new();
    for entry in &entries {
        *families.entry(entry.family.clone()).or_insert(0usize) += 1;
        *access.entry(entry.cli_access.clone()).or_insert(0usize) += 1;
    }
    let entries = if full {
        serde_json::to_value(entries)?
    } else {
        Value::Array(
            entries
                .iter()
                .map(|entry| {
                    json!({
                        "name": entry.name,
                        "family": entry.family,
                        "operation": entry.operation,
                        "catalog_access": entry.cli_access
                    })
                })
                .collect(),
        )
    };
    Ok(json!({
        "count": entries.as_array().map_or(0, Vec::len),
        "families": families,
        "access": access,
        "inventory_status": "registered name parity; schemas and direct endpoint mappings are not complete",
        "entries": entries
    }))
}

pub fn get(name: &str) -> Result<Option<Capability>, serde_json::Error> {
    Ok(all()?.into_iter().find(|entry| entry.name == name))
}

pub fn access_recipe(entry: &Capability) -> Value {
    let verified_rest = entry.method.is_some() && entry.path_template.is_some();
    let (status, command) = match entry.cli_access.as_str() {
        "mcp_remote" => (
            "live_schema_required",
            Some(format!(
                "magi-cloudflare-axi tool schema {} --server <server>",
                entry.name
            )),
        ),
        "raw_rest" if verified_rest => (
            "verified_path_metadata",
            Some(format!(
                "magi-cloudflare-axi api {} {}",
                entry.method.as_deref().unwrap_or("GET"),
                entry.path_template.as_deref().unwrap_or("<path>")
            )),
        ),
        "raw_graphql" => (
            "query_document_required",
            Some("magi-cloudflare-axi graphql --query <query>".to_owned()),
        ),
        "public_direct" => ("public_endpoint_evidence_required", None),
        "blocked" => ("blocked", None),
        _ => ("unverified_direct_mapping", None),
    };
    json!({
        "name": entry.name,
        "family": entry.family,
        "operation": entry.operation,
        "scope": entry.scope,
        "catalog_access": entry.cli_access,
        "status": status,
        "source": entry.source,
        "source_commit": entry.source_commit,
        "description": entry.description,
        "catalog_input_fields": entry.input_fields,
        "method": entry.method,
        "path_template": entry.path_template,
        "blocker": entry.blocker,
        "next_command": command,
        "warning": "catalog proves registered name inventory only; use live MCP schema or official API evidence before invocation"
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catalog_is_sorted_unique_registered_name_inventory() {
        let entries = all().unwrap();
        assert_eq!(entries.len(), 172);
        assert!(entries.windows(2).all(|pair| pair[0].name < pair[1].name));
        assert!(entries.iter().all(|entry| {
            !entry.source.is_empty()
                && !entry.family.is_empty()
                && ["public", "account", "zone", "custom"].contains(&entry.scope.as_str())
                && [
                    "rest",
                    "graphql",
                    "public_http",
                    "internal_binding",
                    "custom_container",
                ]
                .contains(&entry.transport.as_str())
                && [
                    "modeled",
                    "raw_rest",
                    "raw_graphql",
                    "public_direct",
                    "blocked",
                    "mcp_remote",
                ]
                .contains(&entry.cli_access.as_str())
                && (entry.cli_access != "blocked"
                    || entry.blocker.as_deref().is_some_and(|x| !x.is_empty()))
        }));
        for family in [
            "ai-gateway",
            "auditlogs",
            "autorag",
            "browser-rendering",
            "cloudflare-blog",
            "cloudflare-one-casb",
            "demo-day",
            "dex-analysis",
            "dns-analytics",
            "graphql",
            "logpush",
            "radar",
            "sandbox-container",
            "shared",
            "stack-mcp",
            "workers-bindings",
            "workers-builds",
            "workers-observability",
        ] {
            assert!(entries.iter().any(|entry| entry.family == family));
        }
        for name in [
            "dex_test_statistics",
            "list_gateways",
            "integration_by_id",
            "graphql_query",
            "kv_namespaces_list",
            "container_exec",
            "search_cloudflare_documentation",
            "mcp_demo_day_info",
        ] {
            assert!(entries.iter().any(|entry| entry.name == name));
        }
    }
    #[test]
    fn family_counts_sum() {
        let mut counts = std::collections::BTreeMap::new();
        for entry in all().unwrap() {
            *counts.entry(entry.family).or_insert(0usize) += 1;
        }
        assert_eq!(counts.values().sum::<usize>(), 172);
    }
}
