use crate::{capability, client, config, error::AppError, mcp};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const CONTRACTS: &str = include_str!("../capabilities/cloudflare-operation-contracts.json");
const SOURCE_COMMIT: &str = "70ff690553722f731849ede6ba9ce98958395a23";
const BUNDLE_SHA256: &str = "d9b9528bd9f53de5b1c621c00e6d9938051c7bb6208205bd6333a6dda208469a";
const CONTRACT_NAMES: [&str; 18] = [
    "d1_database_delete",
    "d1_database_get",
    "get_crawl_result",
    "get_post",
    "get_url_html_content",
    "get_url_json",
    "get_url_links",
    "get_url_markdown",
    "get_url_pdf",
    "get_url_screenshot",
    "get_url_snapshot",
    "graphql_schema_overview",
    "list_browser_sessions",
    "list_posts",
    "list_tags",
    "scrape_url_elements",
    "search_cloudflare_documentation",
    "search_posts",
];
const CONTRACT_HASHES: [&str; 18] = [
    "d20fe0588da599ada8ff20f3baba6e948041033b6b635546943ec423173970da",
    "6f17fcc6c6d39125a11e32b7716f3d3f8f96ea2048eb2d7a55ef15f5ca8bd5c7",
    "e0743e3581acf1b7b0961b2588632a77838ae54a4ad922b58c635e15f040ac52",
    "c8db96e377307473c88cd2948acb864dd48016ab131b668941c1dec0b43af4e1",
    "5a84bbcdbead36b9caae6cde60445f71d614681f387d0b0b02ee2b6e4c2b4909",
    "930b1ee212733b0fcd7e600bd346001ddb6e0154f99bbeebe27bc079e42cdb6d",
    "5c2aad547b8c1a50e9af0290d29b2bbe7639d4d580a0c8d6713b30c0ef31ae83",
    "853f582a9e39fe0a908117b2b7982be75d4c3c96c5bf5927d767ce8adc70abed",
    "c544d991b6a98bace228cd7eb1bb124bd4934a6fa1cf318523579769e9e9780d",
    "97ac366335b2110918db9244d13dfb4bafc35492032810778fd52200497fdbdc",
    "3efc9a49696872d3ee6635a132056725737832846914cd816a0e18bc55b37588",
    "72fdb97a538fc6cf3a465e62c9d612a59605cc3829a21d08d3918a016d53d0cc",
    "e4a219d186616d0e00b5f33e3b856350282a727a4fcccbaac3920fe2aa34a5a1",
    "f9a765b3d1a962ab8d09cbdf304f855cbdbe87a03b73a9e280b343d4bec0a46c",
    "7702537f950b693041ce32f2dc8d8c82c226cf4058b45319e060383a0095b2bd",
    "a5b4b365d1239a717b90f27a5cc3f7f9378f393e4e73e92ce3d3bb32ee54d415",
    "9c1240a95b266aebc995c0a4bd8aa08cb7a5bc25a8bd562162336a75e7f2aa41",
    "50cedf16e00086e8505bee4d83bfe202687f5d15eaffa3e7f71723651a3cae91",
];
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    version: String,
    source_commit: String,
    canonicalization: String,
    contract_count: usize,
    bundle_sha256: String,
    contracts: Vec<Contract>,
}
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Contract {
    capability: String,
    contract_sha256: String,
    route: Value,
    behavior: Value,
    safety: Safety,
    implementation: Value,
    evidence: Value,
}
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Safety {
    operation: String,
    destructive: bool,
    metered: bool,
    data_egress: bool,
    long_running: bool,
    retry_policy: String,
}
#[derive(Debug, Clone, Copy, Default)]
pub struct GuardFlags<'a> {
    pub allow_write: bool,
    pub allow_metered: bool,
    pub allow_egress: bool,
    pub allow_long_running: bool,
    pub confirm: Option<&'a str>,
}

fn canonical(v: Value) -> Value {
    match v {
        Value::Array(a) => Value::Array(a.into_iter().map(canonical).collect()),
        Value::Object(o) => {
            let mut e = o.into_iter().collect::<Vec<_>>();
            e.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(e.into_iter().map(|(k, v)| (k, canonical(v))).collect())
        }
        v => v,
    }
}
fn digest(v: &Value) -> String {
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&canonical(v.clone())).unwrap())
    )
}
fn contracts() -> Result<Bundle, AppError> {
    let bundle: Bundle = serde_json::from_str(CONTRACTS)
        .map_err(|e| AppError::api(format!("embedded operation contracts are invalid: {e}")))?;
    if bundle.source_commit != SOURCE_COMMIT
        || bundle.contract_count != 18
        || bundle.contracts.len() != 18
        || bundle
            .contracts
            .iter()
            .map(|c| c.capability.as_str())
            .collect::<Vec<_>>()
            != CONTRACT_NAMES
        || bundle.version != "phase4d-operation-contracts-v1"
    {
        return Err(AppError::api(
            "embedded operation contract envelope is invalid",
        ));
    }
    let mut root: Value = serde_json::from_str(CONTRACTS)
        .map_err(|_| AppError::api("embedded operation contracts are invalid"))?;
    root["bundle_sha256"] = Value::Null;
    if digest(&root) != BUNDLE_SHA256 || bundle.bundle_sha256 != BUNDLE_SHA256 {
        return Err(AppError::api("operation bundle hash mismatch"));
    }
    let mut names = BTreeSet::new();
    for (index, c) in bundle.contracts.iter().enumerate() {
        if !names.insert(&c.capability) {
            return Err(AppError::api("duplicate operation contract"));
        }
        let mut v = serde_json::to_value(c).unwrap();
        v["contract_sha256"] = Value::Null;
        if c.contract_sha256.is_empty()
            || digest(&v) != c.contract_sha256
            || CONTRACT_HASHES[index] != c.contract_sha256
        {
            return Err(AppError::api(format!(
                "operation contract hash mismatch for {}",
                c.capability
            )));
        }
        validate_contract(c)?;
    }
    Ok(bundle)
}
fn validate_contract(c: &Contract) -> Result<(), AppError> {
    let transport = c
        .route
        .get("transport")
        .and_then(Value::as_str)
        .unwrap_or("");
    let retry_valid = if c.safety.operation == "write" {
        c.safety.retry_policy == "never"
    } else {
        matches!(c.safety.retry_policy.as_str(), "never" | "transient_read")
    };
    if !["rest", "graphql", "mcp"].contains(&transport)
        || c.implementation.get("status") != Some(&Value::String("verified".into()))
        || c.route.get("auth").and_then(Value::as_str).is_none()
        || !retry_valid
    {
        return Err(AppError::api("unsupported or drifted operation contract"));
    }
    if c.capability == "graphql_schema_overview"
        && c.behavior
            .get("fixed_document_sha256")
            .and_then(Value::as_str)
            != Some("7a041df0f3b28c0eccf5c3dfa2ae5b1f4d2be4b3aaef8457ca08342d4bb5b94")
    {
        return Err(AppError::api("GraphQL operation semantic pin mismatch"));
    }
    if c.capability == "search_cloudflare_documentation"
        && (c.route.get("auth") != Some(&Value::String("none".into()))
            || c.route.get("method") != Some(&Value::String("tools/call".into()))
            || c.route.get("protocol") != Some(&Value::String("2026-07-28".into()))
            || c.route.get("tool") != Some(&Value::String(c.capability.clone())))
    {
        return Err(AppError::api("MCP operation route mismatch"));
    }
    if [
        "get_url_html_content",
        "get_url_json",
        "get_url_links",
        "get_url_markdown",
        "get_url_pdf",
        "get_url_screenshot",
        "get_url_snapshot",
        "scrape_url_elements",
    ]
    .contains(&c.capability.as_str())
        && (!c.safety.metered || !c.safety.data_egress || !c.safety.long_running)
    {
        return Err(AppError::api("browser content safety mismatch"));
    }
    if ["get_url_pdf", "get_url_screenshot"].contains(&c.capability.as_str()) {
        let (
            expected_route,
            expected_behavior,
            expected_handler_lines,
            expected_handler_sha,
            expected_projection,
            expected_test,
        ) = if c.capability == "get_url_pdf" {
            (
                ("POST", "/accounts/{account_id}/browser-run/pdf", "{url}"),
                (
                    "filesystem_new_file",
                    "new_file",
                    "binary_media_and_signature",
                ),
                "146-194",
                "772c45de366c6caca12226ee605c9c055f3790bf836abac98b069c9e655f30eb",
                "binary_pdf",
                "tests/transport.rs::capability_get_url_pdf_exact_request",
            )
        } else {
            (
                (
                    "POST",
                    "/accounts/{account_id}/browser-run/screenshot",
                    "{url,viewport}",
                ),
                (
                    "filesystem_new_file",
                    "new_file",
                    "binary_media_and_signature",
                ),
                "92-144",
                "19aa8f9fc558723f9e1a7ca6e0ea16d75cb99af15ff871ca485289e74b9f4354",
                "binary_png",
                "tests/transport.rs::capability_get_url_screenshot_exact_request",
            )
        };
        let handler = &c.evidence["pinned_handler"];
        if c.route["transport"] != "rest"
            || c.route["method"] != expected_route.0
            || c.route["path_template"] != expected_route.1
            || c.route["path_parameters"]
                != json!([{"name": "account_id", "source": "resolved_account", "format": "single_path_segment", "max_length": 32}])
            || c.route["query_parameters"] != json!([])
            || c.route["body"] != expected_route.2
            || c.route["scope"] != "account"
            || c.route["content_type"] != "application/json"
            || c.route["auth"] != "account"
            || c.behavior["output_projection"] != expected_projection
            || c.behavior["empty_state"] != expected_behavior.1
            || c.behavior["pagination"] != "none"
            || c.behavior["artifact"] != expected_behavior.0
            || c.behavior["error"] != expected_behavior.2
            || c.safety.operation != "read"
            || c.safety.destructive
            || !c.safety.metered
            || !c.safety.data_egress
            || !c.safety.long_running
            || c.safety.retry_policy != "never"
            || c.implementation["status"] != "verified"
            || c.implementation["adapter"] != "rest"
            || c.implementation["test_id"] != expected_test
            || c.implementation["documentation_id"]
                != format!("cloudflare-browser-{}", c.capability)
            || c.implementation["reviewed_at"] != "2026-08-11"
            || handler["commit"] != SOURCE_COMMIT
            || handler["file"] != "apps/browser-rendering/src/tools/browser.tools.ts"
            || handler["blob_oid"] != "ae998f642ba8548b715e1573bc0049c96c9e1f28"
            || handler["lines"] != expected_handler_lines
            || handler["source_sha256"] != expected_handler_sha
        {
            return Err(AppError::api("browser binary operation semantic mismatch"));
        }
    }
    if ["get_crawl_result", "get_url_json", "get_url_snapshot"].contains(&c.capability.as_str())
        && (c.route.get("scope") != Some(&Value::String("account".into()))
            || c.route.get("method")
                != Some(&Value::String(
                    if c.capability == "get_crawl_result" {
                        "GET"
                    } else {
                        "POST"
                    }
                    .into(),
                ))
            || c.route.get("auth") != Some(&Value::String("account".into()))
            || c.route.get("transport") != Some(&Value::String("rest".into())))
    {
        return Err(AppError::api("browser JSON/snapshot/crawl route mismatch"));
    }
    if c.capability == "list_browser_sessions" {
        let handler = &c.evidence["pinned_handler"];
        if c.route["transport"] != "rest"
            || c.route["method"] != "GET"
            || c.route["path_template"] != "/accounts/{account_id}/browser-run/devtools/session"
            || c.route["scope"] != "account"
            || c.route["auth"] != "account"
            || c.route["body"] != "none"
            || c.route["query_parameters"] != json!([])
            || c.behavior["output_projection"] != "session_array"
            || c.behavior["empty_state"] != "empty_array"
            || c.behavior["pagination"] != "none"
            || c.behavior["error"] != "bare_json_or_result_array"
            || c.safety.operation != "read"
            || c.safety.destructive
            || c.safety.metered
            || !c.safety.data_egress
            || c.safety.long_running
            || c.safety.retry_policy != "transient_read"
            || c.implementation["adapter"] != "rest"
            || c.implementation["test_id"]
                != "tests/transport.rs::capability_list_browser_sessions_exact_request"
            || handler["commit"] != SOURCE_COMMIT
            || handler["file"] != "apps/browser-rendering/src/tools/browser.tools.ts"
            || handler["blob_oid"] != "ae998f642ba8548b715e1573bc0049c96c9e1f28"
            || handler["lines"] != "522-560"
            || handler["source_sha256"]
                != "c6b05861d44395a6e2bc84ac37320cd04d9a7edded73cf14d410fce32e31a361"
        {
            return Err(AppError::api(
                "browser sessions operation semantic mismatch",
            ));
        }
    }
    if ["get_post", "list_posts", "list_tags", "search_posts"].contains(&c.capability.as_str()) {
        let expected_method = if c.capability == "search_posts" {
            "POST"
        } else {
            "GET"
        };
        let (handler_lines, handler_sha) = match c.capability.as_str() {
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
        let handler = c
            .evidence
            .get("pinned_handler")
            .ok_or_else(|| AppError::api("Blog handler evidence missing"))?;
        let deployment = c
            .evidence
            .get("pinned_deployment")
            .ok_or_else(|| AppError::api("Blog deployment evidence missing"))?;
        let expected_behavior = match c.capability.as_str() {
            "get_post" => (
                "/api/mcp/posts/{slug}",
                "post",
                "not_applicable_detail",
                "none",
                "bare_json_strict",
            ),
            "list_posts" => (
                "/api/mcp/posts",
                "posts_and_next_cursor",
                "empty_posts",
                "cursor",
                "bare_json_strict",
            ),
            "list_tags" => (
                "/api/mcp/tags",
                "tags",
                "empty_tags",
                "none",
                "bare_json_strict",
            ),
            "search_posts" => (
                "/search",
                "results",
                "empty_results",
                "none",
                "upstream_search_envelope_strict",
            ),
            _ => unreachable!(),
        };
        if c.safety.operation != "read"
            || c.safety.destructive
            || c.safety.metered
            || c.safety.data_egress
            || c.safety.long_running
            || c.safety.retry_policy != "never"
            || c.route.get("path_template") != Some(&Value::String(expected_behavior.0.into()))
            || c.behavior.get("output_projection")
                != Some(&Value::String(expected_behavior.1.into()))
            || c.behavior.get("empty_state") != Some(&Value::String(expected_behavior.2.into()))
            || c.behavior.get("pagination") != Some(&Value::String(expected_behavior.3.into()))
            || c.behavior.get("error") != Some(&Value::String(expected_behavior.4.into()))
            || c.route.get("method") != Some(&Value::String(expected_method.into()))
            || c.route.get("auth") != Some(&Value::String("none".into()))
            || c.route.get("scope") != Some(&Value::String("public".into()))
            || c.implementation.get("adapter") != Some(&Value::String("rest".into()))
            || handler.get("commit") != Some(&Value::String(SOURCE_COMMIT.into()))
            || handler.get("file")
                != Some(&Value::String(
                    "apps/cloudflare-blog/src/tools/blog.tools.ts".into(),
                ))
            || handler.get("blob_oid")
                != Some(&Value::String(
                    "8088b2d44ad256afd06493fe266d2d6089103559".into(),
                ))
            || handler.get("lines") != Some(&Value::String(handler_lines.into()))
            || handler.get("source_sha256") != Some(&Value::String(handler_sha.into()))
            || deployment.get("commit") != Some(&Value::String(SOURCE_COMMIT.into()))
            || deployment.get("file")
                != Some(&Value::String("apps/cloudflare-blog/wrangler.jsonc".into()))
            || deployment.get("blob_oid")
                != Some(&Value::String(
                    "ca5c1716fa35da43a862c1902f3822bba2a314ee".into(),
                ))
            || deployment.get("lines") != Some(&Value::String("25-30;67-82".into()))
            || deployment.get("source_sha256").and_then(Value::as_str)
                != Some("5daaacef4ef444ff1137b1466a0c402934bf13e6f8ed00751717f88006a5c05f")
        {
            return Err(AppError::api(
                "Cloudflare Blog evidence or semantic pin mismatch",
            ));
        }
    }
    if c.capability == "d1_database_delete"
        && (!c.safety.destructive
            || !c.safety.metered
            || !c.safety.data_egress
            || c.safety.operation != "write")
    {
        return Err(AppError::api("D1 delete safety mismatch"));
    }
    Ok(())
}
fn guard(name: &str, s: &Safety, f: GuardFlags<'_>) -> Result<(), AppError> {
    let mut m = Vec::new();
    if s.operation == "write" && !f.allow_write {
        m.push("--allow-write".into())
    }
    if s.metered && !f.allow_metered {
        m.push("--allow-metered".into())
    }
    if s.data_egress && !f.allow_egress {
        m.push("--allow-egress".into())
    }
    if s.long_running && !f.allow_long_running {
        m.push("--allow-long-running".into())
    }
    if s.destructive && f.confirm != Some(name) {
        m.push(format!("--confirm {name}"))
    }
    if m.is_empty() {
        Ok(())
    } else {
        Err(AppError::usage(format!(
            "capability requires safety flags: {}",
            m.join(", ")
        )))
    }
}
fn path_segment(v: &str, label: &str, max: Option<usize>) -> Result<String, AppError> {
    if v.is_empty()
        || max.is_some_and(|n| v.len() > n)
        || v == "."
        || v == ".."
        || v.bytes()
            .any(|b| matches!(b, b'/' | b'\\' | b'%' | b'?' | b'#'))
    {
        Err(AppError::usage(format!(
            "{label} must be one safe non-empty path segment"
        )))
    } else {
        Ok(v.into())
    }
}
fn encode_uri_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                *byte,
                b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
            )
        {
            encoded.push(*byte as char);
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{:02X}", byte));
        }
    }
    encoded
}

fn database_id(v: &Value) -> Result<String, AppError> {
    let id = v
        .as_str()
        .ok_or_else(|| AppError::usage("database_id is required"))?;
    let valid = id.len() == 36
        && id.as_bytes().iter().enumerate().all(|(i, b)| {
            matches!(i, 8 | 13 | 18 | 23) && *b == b'-'
                || !matches!(i, 8 | 13 | 18 | 23) && b.is_ascii_hexdigit()
        });
    if valid {
        Ok(id.into())
    } else {
        Err(AppError::usage("database_id must be a UUID"))
    }
}
fn effective(name: &str, input: Value) -> Result<Map<String, Value>, AppError> {
    let schema = capability::schema_contract(name)
        .map_err(|_| AppError::api("embedded schema bundle is invalid"))?
        .ok_or_else(|| AppError::api("schema unavailable"))?;
    let mut s = schema["raw_input_schema"].clone();
    if let Some(o) = schema["context_overlays"]
        .as_array()
        .and_then(|x| x.first())
    {
        s["properties"]["account_id"] = o["schema"].clone();
    }
    if name == "graphql_schema_overview" {
        s["properties"]["page"]["type"] = json!("number");
        s["properties"]["pageSize"]["type"] = json!("number");
    }
    if !jsonschema::draft202012::new(&s)
        .map_err(|_| AppError::api("embedded capability schema is invalid"))?
        .is_valid(&input)
    {
        return Err(AppError::usage(format!(
            "input does not match schema for capability '{name}'"
        )));
    }
    let mut o = input
        .as_object()
        .cloned()
        .ok_or_else(|| AppError::usage("capability input must be a JSON object"))?;
    if let Some(p) = s["properties"].as_object() {
        o.retain(|k, _| p.contains_key(k));
    }
    for (k, v) in [("page", json!(1)), ("pageSize", json!(100))] {
        if name == "graphql_schema_overview" && !o.contains_key(k) {
            o.insert(k.into(), v);
        }
    }
    if [
        "get_url_html_content",
        "get_url_json",
        "get_url_links",
        "get_url_markdown",
        "get_url_pdf",
        "get_url_screenshot",
        "get_url_snapshot",
        "scrape_url_elements",
    ]
    .contains(&name)
    {
        let url = o
            .get("url")
            .and_then(Value::as_str)
            .map(str::trim)
            .ok_or_else(|| AppError::usage("url is required"))?
            .to_owned();
        url::Url::parse(&url).map_err(|_| AppError::usage("url must be valid"))?;
        o.insert("url".into(), Value::String(url));
    }
    if name == "get_url_screenshot" {
        if let Some(viewport) = o.get("viewport").and_then(Value::as_object) {
            let mut normalized = Map::new();
            normalized.insert(
                "width".into(),
                viewport.get("width").cloned().unwrap_or_else(|| json!(800)),
            );
            normalized.insert(
                "height".into(),
                viewport
                    .get("height")
                    .cloned()
                    .unwrap_or_else(|| json!(600)),
            );
            o.insert("viewport".into(), Value::Object(normalized));
        }
    }
    Ok(o)
}
pub fn preflight(
    name: &str,
    input: Option<&Value>,
    endpoint: Option<&str>,
    account: Option<&str>,
    flags: GuardFlags<'_>,
) -> Result<(), AppError> {
    let b = contracts()?;
    let c = b
        .contracts
        .iter()
        .find(|x| x.capability == name)
        .ok_or_else(|| {
            AppError::usage(format!(
                "capability '{name}' has no complete route contract"
            ))
        })?;
    guard(name, &c.safety, flags)?;
    let Some(input) = input else {
        return Ok(());
    };
    if name.starts_with("d1_database_") && input.is_object() && input.get("database_id").is_some() {
        database_id(input.get("database_id").unwrap_or(&Value::Null))?;
    }
    let effective = effective(name, input.clone())?;
    if let Some(input_account) = effective.get("account_id").and_then(Value::as_str) {
        path_segment(input_account, "account_id", Some(32))?;
        if account.is_some_and(|resolved| resolved != input_account) {
            return Err(AppError::usage(
                "input account_id conflicts with resolved account scope",
            ));
        }
    }
    if let Some(e) = endpoint {
        client::validate_endpoint(e)?;
    }
    if let Some(a) = account {
        path_segment(a, "account_id", Some(32))?;
    }
    if name.starts_with("d1_database_") {
        database_id(effective.get("database_id").unwrap_or(&Value::Null))?;
    }
    Ok(())
}
fn blog_endpoint(endpoint: Option<&str>, host: &str) -> Result<config::Config, AppError> {
    let default = format!("https://{host}/");
    let raw = endpoint.unwrap_or(&default);
    let url = client::validate_endpoint(raw)?;
    let loopback = matches!(url.host(), Some(url::Host::Domain("localhost")))
        || matches!(url.host(), Some(url::Host::Ipv4(v)) if v.is_loopback())
        || matches!(url.host(), Some(url::Host::Ipv6(v)) if v.is_loopback());
    if !loopback && url.host_str() != Some(host) {
        return Err(AppError::config(format!(
            "Cloudflare Blog endpoint must remain {host}"
        )));
    }
    Ok(config::Config {
        endpoint: url.to_string(),
        account: None,
        zone: None,
    })
}
fn blog_client(endpoint: Option<&str>, host: &str) -> Result<client::CloudflareClient, AppError> {
    client::CloudflareClient::new(blog_endpoint(endpoint, host)?, config::Auth::None)
}
fn string_field(o: &Map<String, Value>, key: &str) -> Result<String, AppError> {
    o.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| AppError::api(format!("blog field {key} must be a string")))
}
fn nullable_string(o: &Map<String, Value>, key: &str) -> Result<Value, AppError> {
    match o.get(key) {
        Some(Value::Null) => Ok(Value::Null),
        Some(Value::String(v)) => Ok(Value::String(v.clone())),
        _ => Err(AppError::api(format!(
            "blog field {key} must be null or string"
        ))),
    }
}
fn string_array(o: &Map<String, Value>, key: &str) -> Result<Value, AppError> {
    let a = o
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::api(format!("blog field {key} must be an array")))?;
    if !a.iter().all(Value::is_string) {
        return Err(AppError::api(format!(
            "blog field {key} must contain strings"
        )));
    }
    Ok(Value::Array(a.clone()))
}
fn blog_post(v: &Value, content: bool) -> Result<Value, AppError> {
    let o = v
        .as_object()
        .ok_or_else(|| AppError::api("blog post must be an object"))?;
    let mut out = Map::new();
    for k in ["slug", "title", "excerpt", "url"] {
        out.insert(k.into(), Value::String(string_field(o, k)?));
    }
    out.insert("publishedAt".into(), nullable_string(o, "publishedAt")?);
    for k in ["tags", "authors"] {
        out.insert(k.into(), string_array(o, k)?);
    }
    if content {
        out.insert("content".into(), Value::String(string_field(o, "content")?));
    }
    Ok(Value::Object(out))
}
fn blog_json(r: client::CloudflareResponse) -> Result<Value, AppError> {
    if r.envelope.is_null() || !r.envelope.is_object() {
        return Err(AppError::api(
            "blog provider response must be a JSON object",
        ));
    }
    Ok(r.envelope)
}
fn blog_request(
    name: &str,
    input: &Map<String, Value>,
    endpoint: Option<&str>,
) -> Result<Value, AppError> {
    let (host, method, path, query, body) = match name {
        "get_post" => (
            "blog.cloudflare.com",
            client::Method::Get,
            format!(
                "/api/mcp/posts/{}",
                encode_uri_component(input["slug"].as_str().unwrap_or(""))
            ),
            vec![],
            None,
        ),
        "list_posts" => {
            let mut q = vec![];
            for k in ["limit", "cursor", "tag"] {
                if let Some(v) = input
                    .get(k)
                    .filter(|v| k == "limit" || !v.as_str().is_none_or(str::is_empty))
                {
                    q.push((
                        k.into(),
                        if k == "limit" {
                            v.to_string()
                        } else {
                            v.as_str().unwrap_or_default().into()
                        },
                    ));
                }
            }
            (
                "blog.cloudflare.com",
                client::Method::Get,
                "/api/mcp/posts".into(),
                q,
                None,
            )
        }
        "list_tags" => (
            "blog.cloudflare.com",
            client::Method::Get,
            "/api/mcp/tags".into(),
            vec![],
            None,
        ),
        "search_posts" => (
            "search.blog.cloudflare.com",
            client::Method::Post,
            "/search".into(),
            vec![],
            Some(json!({"query":input["query"]})),
        ),
        _ => {
            return Err(AppError::usage(format!(
                "capability '{name}' has no complete route contract"
            )));
        }
    };
    let r = blog_client(endpoint, host)?.request(client::RequestOptions {
        method,
        path,
        query,
        body,
        allow_write: false,
        confirm_delete: None,
        retry_policy: client::RetryPolicy::Never,
        allow_classified_read_post: true,
    })?;
    if name == "search_posts" {
        return blog_search(r);
    }
    let result = blog_json(r)?;
    match name {
        "get_post" => blog_post(&result, true),
        "list_posts" => {
            let o = result
                .as_object()
                .ok_or_else(|| AppError::api("blog posts result must be object"))?;
            let posts = o
                .get("posts")
                .and_then(Value::as_array)
                .ok_or_else(|| AppError::api("blog posts must be array"))?
                .iter()
                .map(|v| blog_post(v, false))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(json!({"posts":posts,"nextCursor":nullable_string(o,"nextCursor")?}))
        }
        "list_tags" => {
            let o = result
                .as_object()
                .ok_or_else(|| AppError::api("blog tags result must be object"))?;
            let tags = o
                .get("tags")
                .and_then(Value::as_array)
                .ok_or_else(|| AppError::api("blog tags must be array"))?;
            let mut out = vec![];
            for v in tags {
                let x = v
                    .as_object()
                    .ok_or_else(|| AppError::api("blog tag must be object"))?;
                out.push(json!({"slug":string_field(x,"slug")?,"label":string_field(x,"label")?}));
            }
            Ok(json!({"tags":out}))
        }
        _ => unreachable!(),
    }
}
fn blog_search(r: client::CloudflareResponse) -> Result<Value, AppError> {
    let root = r
        .envelope
        .get("result")
        .filter(|_| r.envelope.get("success") == Some(&Value::Bool(true)))
        .ok_or_else(|| AppError::api("blog search provider response envelope is malformed"))?;
    let chunks = root
        .as_object()
        .and_then(|o| o.get("chunks"))
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::api("blog search result chunks must be array"))?;
    let mut rows = Vec::<(String, String, String, f64)>::new();
    for c in chunks {
        let Some(o) = c.as_object() else { continue };
        let Some(item) = o.get("item").and_then(Value::as_object) else {
            continue;
        };
        let Some(url) = item
            .get("key")
            .and_then(Value::as_str)
            .filter(|x| !x.is_empty())
        else {
            continue;
        };
        let score = o
            .get("score")
            .and_then(Value::as_f64)
            .filter(|x| x.is_finite())
            .unwrap_or(0.0);
        let m = item.get("metadata").and_then(Value::as_object);
        let title = m
            .and_then(|x| x.get("title"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .into();
        let excerpt = m
            .and_then(|x| x.get("description"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| {
                truncate_js_slice_300(o.get("text").and_then(Value::as_str).unwrap_or(""))
            });
        if let Some(existing) = rows.iter_mut().find(|row| row.0 == url) {
            if score > existing.3 {
                *existing = (url.into(), title, excerpt, score);
            }
        } else {
            rows.push((url.into(), title, excerpt, score));
        }
    }
    rows.sort_by(|a, b| b.3.total_cmp(&a.3));
    let results = rows
        .into_iter()
        .map(|(url, title, excerpt, score)| json!({"url":url,"title":title,"excerpt":excerpt,"score":score}))
        .collect::<Vec<_>>();
    Ok(json!({"results":results}))
}

fn truncate_js_slice_300(value: &str) -> String {
    let mut units = 0;
    let mut end = 0;
    for (index, character) in value.char_indices() {
        let width = character.len_utf16();
        if units + width > 300 {
            break;
        }
        units += width;
        end = index + character.len_utf8();
    }
    value[..end].to_owned()
}

fn browser_request(
    name: &str,
    input: &Map<String, Value>,
    endpoint: Option<&str>,
    cli_account: Option<String>,
) -> Result<Value, AppError> {
    let mut cfg = config::load(endpoint.map(str::to_owned), cli_account, None)?;
    if let (Some(configured), Some(provided)) = (
        cfg.account.as_deref(),
        input.get("account_id").and_then(Value::as_str),
    ) {
        if configured != provided {
            return Err(AppError::usage(
                "input account_id conflicts with resolved account scope",
            ));
        }
    }
    if cfg.account.is_none() {
        cfg.account = input
            .get("account_id")
            .and_then(Value::as_str)
            .map(str::to_owned);
    }
    let account = path_segment(
        cfg.account.as_deref().ok_or_else(|| {
            AppError::usage("account scope required; use --account or input account_id")
        })?,
        "account_id",
        Some(32),
    )?;
    let body = match name {
        "scrape_url_elements" => json!({"url":input["url"],"elements":input["elements"]}),
        "get_url_links" => {
            let mut body = json!({"url":input["url"]});
            if let Some(value) = input.get("visibleLinksOnly") {
                body["visibleLinksOnly"] = value.clone();
            }
            body
        }
        "get_url_json" => {
            let mut body = json!({"url":input["url"]});
            if input
                .get("prompt")
                .and_then(Value::as_str)
                .is_some_and(|v| !v.is_empty())
            {
                body["prompt"] = input["prompt"].clone();
            }
            if let Some(value) = input.get("response_format") {
                body["response_format"] = value.clone();
            }
            body
        }
        "get_crawl_result" | "list_browser_sessions" => Value::Null,
        _ => json!({"url":input["url"]}),
    };
    let (method, path, retry_policy) = if name == "get_crawl_result" {
        (
            client::Method::Get,
            format!(
                "/accounts/{account}/browser-run/crawl/{}",
                path_segment(input["job_id"].as_str().unwrap_or(""), "job_id", Some(256))?
            ),
            client::RetryPolicy::TransientRead,
        )
    } else if name == "list_browser_sessions" {
        (
            client::Method::Get,
            format!("/accounts/{account}/browser-run/devtools/session"),
            client::RetryPolicy::TransientRead,
        )
    } else {
        let suffix = match name {
            "get_url_json" => "json",
            "get_url_snapshot" => "snapshot",
            "get_url_markdown" => "markdown",
            "get_url_links" => "links",
            "scrape_url_elements" => "scrape",
            _ => return Err(AppError::usage("unsupported browser capability")),
        };
        (
            client::Method::Post,
            format!("/accounts/{account}/browser-run/{suffix}"),
            client::RetryPolicy::Never,
        )
    };
    let r = client::CloudflareClient::new(cfg.clone(), config::auth_for(&cfg)?)?.request(
        client::RequestOptions {
            method,
            path,
            query: vec![],
            body: (method != client::Method::Get).then_some(body),
            allow_write: false,
            confirm_delete: None,
            retry_policy,
            allow_classified_read_post: true,
        },
    )?;
    if name == "list_browser_sessions" {
        let result = if r.envelope.is_array() {
            r.envelope
        } else {
            if r.envelope.get("success").is_some_and(|value| value != true)
                || r.envelope
                    .get("errors")
                    .is_some_and(|value| !value.as_array().is_some_and(Vec::is_empty))
            {
                return Err(AppError::api("browser sessions response is malformed"));
            }
            r.result
                .ok_or_else(|| AppError::api("browser sessions result is missing"))?
        };
        result
            .as_array()
            .ok_or_else(|| AppError::api("browser sessions result must be an array"))?;
        return Ok(result);
    }
    if r.envelope.get("success") != Some(&Value::Bool(true))
        || !r
            .envelope
            .get("errors")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
    {
        return Err(AppError::api("capability response envelope is malformed"));
    }
    let result = r
        .result
        .ok_or_else(|| AppError::api("browser result is missing"))?;
    match name {
        "get_url_json" | "get_crawl_result" => Ok(result),
        "get_url_snapshot" => {
            let object = result
                .as_object()
                .ok_or_else(|| AppError::api("browser snapshot result must be an object"))?;
            if object
                .keys()
                .any(|key| key != "content" && key != "screenshot")
                || object
                    .get("content")
                    .is_some_and(|v| !v.is_string() && !v.is_null())
                || object
                    .get("screenshot")
                    .is_some_and(|v| !v.is_null() && v.as_str().is_none_or(|s| s.is_empty()))
            {
                return Err(AppError::api("browser snapshot result is malformed"));
            }
            Ok(result)
        }
        "get_url_markdown" => result
            .as_str()
            .map(|x| Value::String(x.into()))
            .ok_or_else(|| AppError::api("browser markdown result must be a string")),
        "get_url_links" => {
            if result
                .as_array()
                .is_some_and(|a| a.iter().all(Value::is_string))
            {
                Ok(result)
            } else {
                Err(AppError::api(
                    "browser links result must be an array of strings",
                ))
            }
        }
        _ => {
            let records = result
                .as_array()
                .ok_or_else(|| AppError::api("browser scrape result must be an array"))?;
            for record in records {
                let object = record.as_object().ok_or_else(|| {
                    AppError::api("browser scrape selector record must be an object")
                })?;
                if object.len() != 2
                    || object
                        .get("selector")
                        .and_then(Value::as_str)
                        .is_none_or(str::is_empty)
                    || !object.get("results").is_some_and(|value| {
                        value.as_array().is_some_and(|results| {
                            results.iter().all(|item| {
                                let Some(item) = item.as_object() else {
                                    return false;
                                };
                                item.get("attributes").is_some_and(|value| {
                                    value.as_array().is_some_and(|attributes| {
                                        attributes.iter().all(|attribute| {
                                            let Some(attribute) = attribute.as_object() else {
                                                return false;
                                            };
                                            attribute.len() == 2
                                                && attribute
                                                    .get("name")
                                                    .is_some_and(Value::is_string)
                                                && attribute
                                                    .get("value")
                                                    .is_some_and(Value::is_string)
                                        })
                                    })
                                }) && item.get("height").is_some_and(Value::is_number)
                                    && item.get("html").is_some_and(Value::is_string)
                                    && item.get("left").is_some_and(Value::is_number)
                                    && item.get("text").is_some_and(Value::is_string)
                                    && item.get("top").is_some_and(Value::is_number)
                                    && item.get("width").is_some_and(Value::is_number)
                            })
                        })
                    })
                {
                    return Err(AppError::api("browser scrape selector record is malformed"));
                }
            }
            Ok(Value::Array(records.to_vec()))
        }
    }
}

struct TemporaryArtifact(std::path::PathBuf);

impl Drop for TemporaryArtifact {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn prepare_artifact(output: &std::path::Path) -> Result<TemporaryArtifact, AppError> {
    if output.as_os_str().is_empty() || output == std::path::Path::new("-") {
        return Err(AppError::usage(
            "--output must be a filesystem path, not stdout",
        ));
    }
    if output.to_str().is_none() {
        return Err(AppError::usage("--output path must be valid UTF-8"));
    }
    if output.file_name().is_none() {
        return Err(AppError::usage("--output must name a file"));
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    if !parent.is_dir() {
        return Err(AppError::usage("--output parent directory must exist"));
    }
    if output.exists() {
        return Err(AppError::usage("--output destination already exists"));
    }
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    let file_name = output.file_name().unwrap().to_string_lossy();
    (0..16)
        .find_map(|_| {
            let path = parent.join(format!(
                ".{file_name}.tmp-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(file) => {
                    drop(file);
                    Some(Ok(TemporaryArtifact(path)))
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => None,
                Err(e) => Some(Err(AppError::output(format!(
                    "cannot create temporary artifact: {e}"
                )))),
            }
        })
        .transpose()?
        .ok_or_else(|| AppError::output("cannot allocate temporary artifact path"))
}
fn finish_artifact(
    temporary: &TemporaryArtifact,
    output: &std::path::Path,
    bytes: &[u8],
) -> Result<(), AppError> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(&temporary.0)
        .map_err(|error| AppError::output(format!("cannot open temporary artifact: {error}")))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| AppError::output(format!("cannot write artifact: {error}")))?;
    drop(file);
    std::fs::hard_link(&temporary.0, output)
        .map_err(|error| AppError::output(format!("cannot install artifact: {error}")))
}
pub fn binary_request(
    name: &str,
    input: Value,
    endpoint: Option<String>,
    cli_account: Option<String>,
    output: &std::path::Path,
    flags: GuardFlags<'_>,
) -> Result<Value, AppError> {
    let temporary = prepare_artifact(output)?;
    let bundle = contracts()?;
    let input = effective(name, input)?;
    let contract = bundle
        .contracts
        .iter()
        .find(|c| c.capability == name)
        .ok_or_else(|| {
            AppError::usage(format!(
                "capability '{name}' has no complete route contract"
            ))
        })?;
    guard(name, &contract.safety, flags)?;
    let mut cfg = config::load(endpoint, cli_account, None)?;
    if let (Some(a), Some(b)) = (
        cfg.account.as_deref(),
        input.get("account_id").and_then(Value::as_str),
    ) {
        if a != b {
            return Err(AppError::usage(
                "input account_id conflicts with resolved account scope",
            ));
        }
    }
    if cfg.account.is_none() {
        cfg.account = input
            .get("account_id")
            .and_then(Value::as_str)
            .map(str::to_owned);
    }
    let account = path_segment(
        cfg.account.as_deref().ok_or_else(|| {
            AppError::usage("account scope required; use --account or input account_id")
        })?,
        "account_id",
        Some(32),
    )?;
    let (suffix, body, media_type, magic) = match name {
        "get_url_screenshot" => {
            let mut body = json!({"url": input["url"]});
            if let Some(viewport) = input.get("viewport") {
                body["viewport"] = viewport.clone();
            }
            (
                "screenshot",
                body,
                "image/png",
                b"\x89PNG\r\n\x1a\n".as_slice(),
            )
        }
        "get_url_pdf" => (
            "pdf",
            json!({"url": input["url"]}),
            "application/pdf",
            b"%PDF-".as_slice(),
        ),
        _ => return Err(AppError::usage("unsupported binary capability")),
    };
    let response = client::CloudflareClient::new(cfg.clone(), config::auth_for(&cfg)?)?
        .request_binary(client::RequestOptions {
            method: client::Method::Post,
            path: format!("/accounts/{account}/browser-run/{suffix}"),
            query: vec![],
            body: Some(body),
            allow_write: false,
            confirm_delete: None,
            retry_policy: client::RetryPolicy::Never,
            allow_classified_read_post: true,
        })?;
    if !response
        .content_type
        .split(';')
        .next()
        .is_some_and(|v| v.trim().eq_ignore_ascii_case(media_type))
        || !response.bytes.starts_with(magic)
    {
        return Err(AppError::api(
            "binary response media type or signature is invalid",
        ));
    }
    let output_path = output
        .to_str()
        .ok_or_else(|| AppError::usage("--output path must be valid UTF-8"))?
        .to_owned();
    let metadata = json!({"artifact":{"path":output_path,"media_type":media_type,"bytes":response.bytes.len(),"sha256":format!("{:x}", Sha256::digest(&response.bytes))}});
    finish_artifact(&temporary, output, &response.bytes)?;
    Ok(metadata)
}

pub fn invoke(
    name: &str,
    input: Value,
    endpoint: Option<String>,
    cli_account: Option<String>,
    mcp_endpoint: Option<String>,
    flags: GuardFlags<'_>,
) -> Result<Value, AppError> {
    let _bundle = contracts()?;
    let input = effective(name, input)?;
    let contract = _bundle
        .contracts
        .iter()
        .find(|c| c.capability == name)
        .ok_or_else(|| {
            AppError::usage(format!(
                "capability '{name}' has no complete route contract"
            ))
        })?;
    guard(name, &contract.safety, flags)?;
    match name {
        "get_post" | "list_posts" | "list_tags" | "search_posts" => {
            blog_request(name, &input, endpoint.as_deref())
        }
        "search_cloudflare_documentation" => {
            mcp::verified_call(name, Value::Object(input), mcp_endpoint.as_deref())
        }
        "graphql_schema_overview" => {
            let page_value = input["page"].clone();
            let size_value = input["pageSize"].clone();
            let page = input["page"].as_f64().unwrap_or(1.0);
            let size = input["pageSize"].as_f64().unwrap_or(100.0);
            let cfg = config::load(endpoint, cli_account, None)?;
            let auth = config::auth_for(&cfg)?;
            let api = client::CloudflareClient::new(cfg, auth)?;
            let q = "\n\t\tquery SchemaOverview {\n\t\t\t__schema {\n\t\t\t\tqueryType { name }\n\t\t\t\tmutationType { name }\n\t\t\t\tsubscriptionType { name }\n\t\t\t\ttypes {\n\t\t\t\t\tname\n\t\t\t\t\tkind\n\t\t\t\t\tdescription\n\t\t\t\t}\n\t\t\t}\n\t\t}\n\t";
            let r = api.request(client::RequestOptions {
                method: client::Method::Post,
                path: "/graphql".into(),
                query: vec![],
                body: Some(json!({"query": q})),
                allow_write: false,
                confirm_delete: None,
                retry_policy: client::RetryPolicy::TransientRead,
                allow_classified_read_post: true,
            })?;
            let root = r
                .envelope
                .get("data")
                .and_then(|x| x.get("__schema"))
                .ok_or_else(|| AppError::api("GraphQL response missing data.__schema"))?;
            let types = root
                .get("types")
                .and_then(Value::as_array)
                .ok_or_else(|| AppError::api("GraphQL schema types must be an array"))?;
            let total = types.len();
            let start_value = ((page - 1.0) * size).trunc();
            let end_value = (((page - 1.0) * size) + size).min(total as f64).trunc();
            let index = |value: f64| {
                if !value.is_finite() || value >= total as f64 {
                    total
                } else {
                    value as usize
                }
            };
            let start = index(start_value);
            let end = index(end_value).max(start);
            let data = types[start..end].to_vec();
            let total_pages = (total as f64 / size).ceil() as usize;
            Ok(json!({
                "data":{"__schema":{"queryType":root["queryType"],"mutationType":root["mutationType"],"subscriptionType":root["subscriptionType"],"types":data}},
                "pagination":{"page":page_value,"pageSize":size_value,"totalTypes":total,"totalPages":total_pages,"hasNextPage":page < total_pages as f64,"hasPreviousPage":page > 1.0}
            }))
        }
        "get_url_html_content" => {
            let url = input["url"]
                .as_str()
                .ok_or_else(|| AppError::usage("url is required"))?;
            let mut cfg = config::load(endpoint, cli_account, None)?;
            if let (Some(configured), Some(provided)) = (
                cfg.account.as_deref(),
                input.get("account_id").and_then(Value::as_str),
            ) {
                if configured != provided {
                    return Err(AppError::usage(
                        "input account_id conflicts with resolved account scope",
                    ));
                }
            }
            if cfg.account.is_none() {
                cfg.account = input
                    .get("account_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
            }
            let account = path_segment(
                cfg.account.as_deref().ok_or_else(|| {
                    AppError::usage("account scope required; use --account or input account_id")
                })?,
                "account_id",
                Some(32),
            )?;
            let auth = config::auth_for(&cfg)?;
            let api = client::CloudflareClient::new(cfg, auth)?;
            let r = api.request(client::RequestOptions {
                method: client::Method::Post,
                path: format!("/accounts/{account}/browser-rendering/content"),
                query: vec![],
                body: Some(json!({"url":url})),
                allow_write: false,
                confirm_delete: None,
                retry_policy: client::RetryPolicy::Never,
                allow_classified_read_post: true,
            })?;
            if r.envelope.get("success") != Some(&Value::Bool(true))
                || !r
                    .envelope
                    .get("errors")
                    .and_then(Value::as_array)
                    .is_some_and(Vec::is_empty)
            {
                return Err(AppError::api("capability response envelope is malformed"));
            }
            r.result
                .and_then(|x| x.as_str().map(String::from))
                .map(Value::String)
                .ok_or_else(|| AppError::api("browser content result must be a string"))
        }
        "d1_database_get" | "d1_database_delete" => {
            let id = database_id(input.get("database_id").unwrap_or(&Value::Null))?;
            let mut cfg = config::load(endpoint, cli_account, None)?;
            if let (Some(configured), Some(provided)) = (
                cfg.account.as_deref(),
                input.get("account_id").and_then(Value::as_str),
            ) {
                if configured != provided {
                    return Err(AppError::usage(
                        "input account_id conflicts with resolved account scope",
                    ));
                }
            }
            if cfg.account.is_none() {
                cfg.account = input
                    .get("account_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
            }
            let account = path_segment(
                cfg.account.as_deref().ok_or_else(|| {
                    AppError::usage("account scope required; use --account or input account_id")
                })?,
                "account_id",
                Some(32),
            )?;
            let auth = config::auth_for(&cfg)?;
            let api = client::CloudflareClient::new(cfg, auth)?;
            let delete = name == "d1_database_delete";
            let path = format!("/accounts/{account}/d1/database/{id}");
            let r = api.request(client::RequestOptions {
                method: if delete {
                    client::Method::Delete
                } else {
                    client::Method::Get
                },
                path: path.clone(),
                query: vec![],
                body: None,
                allow_write: delete,
                confirm_delete: delete.then_some(path.clone()),
                retry_policy: if delete {
                    client::RetryPolicy::Never
                } else {
                    client::RetryPolicy::TransientRead
                },
                allow_classified_read_post: false,
            })?;
            if delete && r.envelope.is_null() {
                return Ok(Value::Null);
            }
            if r.envelope.get("success") != Some(&Value::Bool(true))
                || !r
                    .envelope
                    .get("errors")
                    .and_then(Value::as_array)
                    .is_some_and(Vec::is_empty)
            {
                return Err(AppError::api("capability response envelope is malformed"));
            }
            if delete {
                Ok(r.result.unwrap_or(Value::Null))
            } else {
                r.result
                    .filter(|x| x.is_object())
                    .ok_or_else(|| AppError::api("capability response result must be an object"))
            }
        }
        "get_url_json"
        | "get_url_snapshot"
        | "get_crawl_result"
        | "get_url_markdown"
        | "get_url_links"
        | "list_browser_sessions"
        | "scrape_url_elements" => browser_request(name, &input, endpoint.as_deref(), cli_account),
        _ => Err(AppError::usage(format!(
            "capability '{name}' has no complete route contract"
        ))),
    }
}
