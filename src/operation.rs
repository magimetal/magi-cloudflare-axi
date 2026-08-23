use crate::{capability, client, config, error::AppError, mcp};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const CONTRACTS: &str = include_str!("../capabilities/cloudflare-operation-contracts.json");
const SOURCE_COMMIT: &str = "70ff690553722f731849ede6ba9ce98958395a23";
const BUNDLE_SHA256: &str = "152335217fb4766f9843fac569cf5e1c01bb57ef400f1417ac6b30fcf465e2ac";
const CONTRACT_NAMES: [&str; 22] = [
    "auditlogs_by_account_id",
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
    "list_rags",
    "list_tags",
    "logpush_jobs_by_account_id",
    "scrape_url_elements",
    "search_cloudflare_documentation",
    "search_posts",
    "workers_builds_get_build",
];
const CONTRACT_HASHES: [&str; 22] = [
    "630b34fad5d51bde597cc56ea7528ba993f904b5723236be830a1f99f80fd1ac",
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
    "fef8065dad846d2ac68c9893fefafd68e59281516f595d0d788e84a2a4bf02d9",
    "7702537f950b693041ce32f2dc8d8c82c226cf4058b45319e060383a0095b2bd",
    "cbe26861e59a2594e0639b1367fdf882ba7e8d98cc666a9b2cb080ce12adc4ef",
    "a5b4b365d1239a717b90f27a5cc3f7f9378f393e4e73e92ce3d3bb32ee54d415",
    "9c1240a95b266aebc995c0a4bd8aa08cb7a5bc25a8bd562162336a75e7f2aa41",
    "50cedf16e00086e8505bee4d83bfe202687f5d15eaffa3e7f71723651a3cae91",
    "156b720aa8b8a9c239a6a34a213a9dba11c6cc8362ab27db650bbb83d69dc5aa",
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
        || bundle.contract_count != CONTRACT_NAMES.len()
        || bundle.contracts.len() != CONTRACT_NAMES.len()
        || bundle
            .contracts
            .iter()
            .map(|c| c.capability.as_str())
            .collect::<Vec<_>>()
            != CONTRACT_NAMES
        || bundle.version != "phase4h-operation-contracts-v1"
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
    if c.capability == "auditlogs_by_account_id" {
        let evidence = &c.evidence;
        let query_parameters = json!([
            {"name":"account_name","optional":true,"source":"input"},
            {"name":"action_result","optional":true,"source":"input"},
            {"name":"action_type","optional":true,"source":"input"},
            {"name":"actor_context","optional":true,"source":"input"},
            {"name":"actor_email","optional":true,"source":"input"},
            {"name":"actor_id","optional":true,"source":"input"},
            {"name":"actor_ip_address","optional":true,"source":"input"},
            {"name":"actor_token_id","optional":true,"source":"input"},
            {"name":"actor_token_name","optional":true,"source":"input"},
            {"name":"actor_type","optional":true,"source":"input"},
            {"name":"audit_log_id","optional":true,"source":"input"},
            {"name":"raw_cf_ray_id","optional":true,"source":"input"},
            {"name":"raw_method","optional":true,"source":"input"},
            {"name":"raw_status_code","optional":true,"serialization":"javascript_string","source":"input"},
            {"name":"raw_uri","optional":true,"source":"input"},
            {"name":"resource_id","optional":true,"source":"input"},
            {"name":"resource_product","optional":true,"source":"input"},
            {"name":"resource_type","optional":true,"source":"input"},
            {"name":"resource_scope","optional":true,"source":"input"},
            {"name":"zone_id","optional":true,"source":"input"},
            {"name":"zone_name","optional":true,"source":"input"},
            {"name":"since","optional":false,"source":"input"},
            {"name":"before","optional":false,"source":"input"},
            {"name":"direction","optional":true,"source":"input"},
            {"default":10,"name":"limit","optional":true,"serialization":"javascript_string","source":"input"},
            {"name":"cursor","optional":true,"source":"input"}
        ]);
        if c.route["transport"] != "rest"
            || c.route["method"] != "GET"
            || c.route["path_template"] != "/accounts/{account_id}/logs/audit"
            || c.route["path_parameters"]
                != json!([{"name":"account_id","source":"resolved_account","format":"single_path_segment","max_length":32}])
            || c.route["query_parameters"] != query_parameters
            || c.route["body"] != "none"
            || c.route["scope"] != "account"
            || c.route["content_type"] != "application/json"
            || c.route["auth"] != "account"
            || c.route["fixed_headers"]
                != json!({"Content-Type":"application/json","portal-version":"2"})
            || c.behavior
                != json!({"output_projection":"strict_trimmed_audit_logs","empty_state":"logs_empty_with_result_info","pagination":"cursor_result_info","artifact":"none","error":"pinned_audit_logs_response_schema","projection_validation":"full_response_before_projection","result_info":"count_and_optional_cursor"})
            || c.safety.operation != "read"
            || c.safety.destructive
            || c.safety.metered
            || !c.safety.data_egress
            || c.safety.long_running
            || c.safety.retry_policy != "never"
            || c.implementation
                != json!({"status":"verified","adapter":"rest","test_id":"tests/transport.rs::capability_auditlogs_by_account_id_exact_request","documentation_id":"cloudflare-auditlogs-list-account","reviewed_at":"2026-08-12"})
            || evidence["pinned_handler"]
                != json!({"commit":SOURCE_COMMIT,"file":"apps/auditlogs/src/tools/auditlogs.tools.ts","blob_oid":"0c86a79c6dabdad38667f835e3b671a982d293f4","lines":"181-278","source_sha256":"36d58e2948d20662bc297bc50ac64f659bf5241515900a6215322d16bf081e2e"})
            || evidence["response_schema"]
                != json!({"commit":SOURCE_COMMIT,"file":"apps/auditlogs/src/tools/auditlogs.tools.ts","blob_oid":"0c86a79c6dabdad38667f835e3b671a982d293f4","lines":"78-177","source_sha256":"1eb3d816d570a1e6af1fd55fddfdcd854bd55f0bac68c565d03d7480c590557f"})
            || evidence["query_helper"]
                != json!({"commit":SOURCE_COMMIT,"file":"packages/mcp-common/src/cloudflare-api.ts","blob_oid":"b53d834e977cfb57467a2b1fe4f814f9c2bb2cc7","lines":"20-71","source_sha256":"31c1f165a446e241dc93f4880445ad2ea096a9b11a7b757e3e82cc2f63d230d0"})
            || evidence["auth_scopes"]
                != json!({"commit":SOURCE_COMMIT,"file":"apps/auditlogs/src/auditlogs.app.ts","blob_oid":"30b4294a04d17ad54c29a18a99df15e01843ebb1","lines":"8-17","source_sha256":"4478bfffaf7e1534767c516a86173a803cc8820fc8345d274ea67413f1c7693f"})
        {
            return Err(AppError::api(
                "Audit Logs operation semantic or evidence mismatch",
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
    if c.capability == "list_rags" {
        let expected_route = json!({"auth":"account","body":"none","content_type":"application/json","method":"GET","path_parameters":[{"format":"single_path_segment","max_length":32,"name":"account_id","source":"resolved_account"}],"path_template":"/accounts/{account_id}/autorag/rags","query_parameters":[{"default":1,"name":"page","optional":true,"serialization":"javascript_string","source":"input"},{"default":20,"name":"per_page","optional":true,"serialization":"javascript_string","source":"input"}],"scope":"account","transport":"rest"});
        let expected_behavior = json!({"artifact":"none","empty_state":"empty_array","error":"strict_autorag_response_schema","output_projection":"autorags_and_total_count","pagination":"page_per_page","projection_validation":"full_response_before_projection","result_info":"numeric_total_count"});
        let expected_safety = Safety {
            destructive: false,
            operation: "read".into(),
            metered: false,
            data_egress: true,
            long_running: false,
            retry_policy: "transient_read".into(),
        };
        let expected_implementation = json!({"adapter":"rest","documentation_id":"cloudflare-autorag-list-rags","reviewed_at":"2026-08-12","status":"verified","test_id":"tests/transport.rs::capability_list_rags_exact_request"});
        let expected_evidence = json!({"auth_scopes":{"blob_oid":"3036f8e33fb527637d1d69f4425a603a6ada7deb","commit":SOURCE_COMMIT,"file":"apps/autorag/src/autorag.app.ts","lines":"36-46","source_sha256":"c9f743841e3bffa3d81fbab99fee32f5fada9e2029c8897f85f4558e6a9f1d07"},"input_defaults":{"blob_oid":"6bb37934201dc963750d214e51c7caae479834ee","commit":SOURCE_COMMIT,"file":"apps/autorag/src/types.ts","lines":"1-4","source_sha256":"cee736067ff85c697035ad0a77000fe251d3b2b7bdcf5d32f67eeb86ce03feec"},"pinned_handler":{"blob_oid":"82a5c852a9495569dc2e2f81a5713b79298ba8a4","commit":SOURCE_COMMIT,"file":"apps/autorag/src/tools/autorag.tools.ts","lines":"10-60","source_sha256":"45a826e987690d0e03dec8387f06a0d2f30048da71c2ee6effb358a9dba127f0"},"api_client":{"blob_oid":"b53d834e977cfb57467a2b1fe4f814f9c2bb2cc7","commit":SOURCE_COMMIT,"file":"packages/mcp-common/src/cloudflare-api.ts","lines":"8-18","source_sha256":"353802917c4371c7fbc6298c1e4ad05a75a2402636f8c6bbe5c34319c488bd52"}});
        if c.route != expected_route
            || c.behavior != expected_behavior
            || c.safety.operation != expected_safety.operation
            || c.safety.destructive != expected_safety.destructive
            || c.safety.metered != expected_safety.metered
            || c.safety.data_egress != expected_safety.data_egress
            || c.safety.long_running != expected_safety.long_running
            || c.safety.retry_policy != expected_safety.retry_policy
            || c.implementation != expected_implementation
            || c.evidence != expected_evidence
        {
            return Err(AppError::api(
                "AutoRAG list_rags operation semantic or evidence mismatch",
            ));
        }
    }
    if c.capability == "workers_builds_get_build" {
        let expected_route = json!({"auth":"account","body":"none","content_type":"application/json","method":"GET","path_parameters":[{"format":"single_path_segment","max_length":32,"name":"account_id","source":"resolved_account"},{"format":"single_path_segment","max_length":256,"name":"buildUUID","source":"input"}],"path_template":"/accounts/{account_id}/builds/builds/{buildUUID}","query_parameters":[],"scope":"account","transport":"rest"});
        let expected_behavior = json!({"artifact":"none","empty_state":"null","error":"strict_v4_build_details_response_schema","output_projection":"strict_build_details","pagination":"none","projection_validation":"full_response_before_projection"});
        let expected_safety = json!({"operation":"read","destructive":false,"metered":false,"data_egress":true,"long_running":false,"retry_policy":"transient_read"});
        let expected_implementation = json!({"status":"verified","adapter":"rest","test_id":"tests/transport.rs::capability_workers_builds_get_build_exact_request","documentation_id":"cloudflare-workers-builds-get-build","reviewed_at":"2026-08-14"});
        let expected_evidence = json!({"api_client":{"blob_oid":"b53d834e977cfb57467a2b1fe4f814f9c2bb2cc7","commit":SOURCE_COMMIT,"file":"packages/mcp-common/src/cloudflare-api.ts","lines":"20-71","source_sha256":"31c1f165a446e241dc93f4880445ad2ea096a9b11a7b757e3e82cc2f63d230d0"},"api_route":{"blob_oid":"061f5240161acc5c2d355d968002e7a178df416b","commit":SOURCE_COMMIT,"file":"apps/workers-builds/src/api/workers-builds.api.ts","lines":"34-49","source_sha256":"8bdd02f9580cfffc1f40e6f33f38f1dc8d8650e5d5778876c60ed4e28bbc7f84"},"auth_scopes":{"blob_oid":"1d1ce050974abaebc3b6497d833b3f7c8f39ab94","commit":SOURCE_COMMIT,"file":"apps/workers-builds/src/workers-builds.app.ts","lines":"21-28","source_sha256":"e087ea416688217a28e509e26401a74ef76b53742cb97ca4f8244d6f93adf384"},"get_build_alias":{"blob_oid":"7520d4accba6d6ace4d59fb11cf25e096e90501e","commit":SOURCE_COMMIT,"file":"apps/workers-builds/src/types/workers-builds.types.ts","lines":"82-83","source_sha256":"d8b455f727a41608914f7d3c0a94ff05b87e6385f41b15eed989432e16245926"},"pinned_handler":{"blob_oid":"3936684ab52f24fd02247b6a5e785f061b9bd2bd","commit":SOURCE_COMMIT,"file":"apps/workers-builds/src/tools/workers-builds.tools.ts","lines":"78-129","source_sha256":"fe096c34187b7646ad6e2ee033a3c2f46d50ee8623b4a9619f1f1bd6e8045ae3"},"response_schema":{"blob_oid":"7520d4accba6d6ace4d59fb11cf25e096e90501e","commit":SOURCE_COMMIT,"file":"apps/workers-builds/src/types/workers-builds.types.ts","lines":"3-64","source_sha256":"a830f11089342d0ad203ee29f66e9eee6664cffad1386e7da2c1f1044e8bfd75"},"v4_envelope":{"blob_oid":"6748c68b64694c7a7c225dbd5daa388c779ab135","commit":SOURCE_COMMIT,"file":"packages/mcp-common/src/v4-api.ts","lines":"29-55","source_sha256":"2866e0a419736d107bc77dc8d49bb95583101caa5317ecc8660a40062093fdfc"}});
        if c.route != expected_route
            || c.behavior != expected_behavior
            || serde_json::to_value(&c.safety).unwrap() != expected_safety
            || c.implementation != expected_implementation
            || c.evidence != expected_evidence
        {
            return Err(AppError::api(
                "Workers Builds get-build operation semantic or evidence mismatch",
            ));
        }
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
fn workers_account_id(v: &str) -> Result<String, AppError> {
    if v.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(AppError::usage(
            "account_id must be one safe non-empty path segment",
        ));
    }
    path_segment(v, "account_id", Some(32))
}

fn workers_build_uuid(v: &str) -> Result<String, AppError> {
    if v.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(AppError::usage(
            "buildUUID must be one safe non-empty path segment",
        ));
    }
    path_segment(v, "buildUUID", Some(256))
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
        if name == "workers_builds_get_build" {
            workers_account_id(input_account)?;
        } else {
            path_segment(input_account, "account_id", Some(32))?;
        }
        if account.is_some_and(|resolved| resolved != input_account) {
            return Err(AppError::usage(
                "input account_id conflicts with resolved account scope",
            ));
        }
    }
    if name == "workers_builds_get_build" {
        let build_uuid = effective
            .get("buildUUID")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::usage("buildUUID is required"))?;
        workers_build_uuid(build_uuid)?;
    }
    if name == "workers_builds_get_build" {
        if let Some(a) = account {
            workers_account_id(a)?;
        }
    }
    if let Some(e) = endpoint {
        client::validate_endpoint(e)?;
    }
    if let Some(a) = account {
        if name != "workers_builds_get_build" {
            path_segment(a, "account_id", Some(32))?;
        }
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

fn logpush_datetime(value: &str) -> bool {
    let (date, time) = match value.split_once('T') {
        Some(parts) => parts,
        None => return false,
    };
    let mut d = date.split('-');
    let (year, month, day) = match (d.next(), d.next(), d.next(), d.next()) {
        (Some(y), Some(m), Some(day), None) if y.len() == 4 && m.len() == 2 && day.len() == 2 => (
            y.parse::<u32>().ok(),
            m.parse::<u32>().ok(),
            day.parse::<u32>().ok(),
        ),
        _ => return false,
    };
    let (year, month, day) = match (year, month, day) {
        (Some(y), Some(m), Some(d)) => (y, m, d),
        _ => return false,
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&month) || day == 0 || day > days[(month - 1) as usize] {
        return false;
    }
    let time = match time.strip_suffix('Z') {
        Some(time) => time,
        None => return false,
    };
    let (clock, fraction) = match time.split_once('.') {
        Some((clock, fraction))
            if !fraction.is_empty() && fraction.bytes().all(|b| b.is_ascii_digit()) =>
        {
            (clock, Some(fraction))
        }
        Some(_) => return false,
        None => (time, None),
    };
    let parts = clock.split(':').collect::<Vec<_>>();
    if !matches!(parts.len(), 2 | 3)
        || parts
            .iter()
            .any(|part| part.len() != 2 || !part.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    let hour = parts[0].parse::<u32>().unwrap();
    let minute = parts[1].parse::<u32>().unwrap();
    if hour > 23 || minute > 59 {
        return false;
    }
    match parts.get(2) {
        None => fraction.is_none(),
        Some(seconds) => seconds.parse::<u32>().unwrap() <= 59,
    }
}

fn logpush_job(v: &Value) -> Result<Value, AppError> {
    if v.is_null() {
        return Ok(Value::Null);
    }
    let object = v
        .as_object()
        .ok_or_else(|| AppError::api("logpush job must be an object"))?;
    let mut out = Map::new();
    if let Some(id) = object.get("id") {
        let id = id
            .as_u64()
            .or_else(|| {
                id.as_f64()
                    .filter(|id| id.is_finite() && id.fract() == 0.0)
                    .map(|id| id as u64)
            })
            .filter(|id| (1..=9_007_199_254_740_991).contains(id))
            .ok_or_else(|| AppError::api("logpush job id must be a positive safe integer"))?;
        out.insert("id".into(), json!(id));
    }
    if let Some(enabled) = object.get("enabled") {
        if !enabled.is_boolean() {
            return Err(AppError::api("logpush job enabled must be boolean"));
        }
        out.insert("enabled".into(), enabled.clone());
    }
    for (key, max, allowed) in [("name", 512usize, "name"), ("dataset", 256usize, "dataset")] {
        if let Some(value) = object.get(key) {
            if !value.is_null() {
                let text = value.as_str().ok_or_else(|| {
                    AppError::api(format!("logpush job {key} must be null or string"))
                })?;
                if text.len() > max
                    || !text.bytes().all(|b| {
                        b.is_ascii_alphanumeric()
                            || if allowed == "name" {
                                matches!(b, b'.' | b'-')
                            } else {
                                matches!(b, b'_' | b'-')
                            }
                    })
                {
                    return Err(AppError::api(format!("logpush job {key} is malformed")));
                }
            }
            out.insert(key.into(), value.clone());
        }
    }
    for key in ["last_complete", "last_error"] {
        if let Some(value) = object.get(key) {
            if !value.is_null() {
                let text = value.as_str().ok_or_else(|| {
                    AppError::api(format!("logpush job {key} must be null or string"))
                })?;
                if !logpush_datetime(text) {
                    return Err(AppError::api(format!(
                        "logpush job {key} is not valid UTC RFC3339"
                    )));
                }
            }
            out.insert(key.into(), value.clone());
        }
    }
    if let Some(value) = object.get("error_message") {
        if !value.is_null() && !value.is_string() {
            return Err(AppError::api(
                "logpush job error_message must be null or string",
            ));
        }
        out.insert("error_message".into(), value.clone());
    }
    Ok(Value::Object(out))
}

fn logpush_request(
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
    let auth = config::auth_for(&cfg)?;
    let response = client::CloudflareClient::new(cfg, auth)?.request_with_trusted_headers(
        client::RequestOptions {
            method: client::Method::Get,
            path: format!("/accounts/{account}/logpush/jobs"),
            query: vec![],
            body: None,
            allow_write: false,
            confirm_delete: None,
            retry_policy: client::RetryPolicy::Never,
            allow_classified_read_post: false,
        },
        &[
            ("Content-Type", "application/json"),
            ("portal-version", "2"),
        ],
        true,
    )?;
    let envelope = response
        .envelope
        .as_object()
        .ok_or_else(|| AppError::api("logpush response envelope is malformed"))?;
    if envelope.get("success") != Some(&Value::Bool(true)) {
        return Err(AppError::api("logpush response envelope is malformed"));
    }
    if let Some(errors) = envelope.get("errors") {
        if !errors.as_array().is_some_and(Vec::is_empty) {
            return Err(AppError::api("logpush response envelope is malformed"));
        }
    }
    let jobs = match envelope.get("result") {
        None => vec![],
        Some(Value::Array(jobs)) => jobs.clone(),
        Some(_) => return Err(AppError::api("logpush result must be an array")),
    };
    let projected = jobs
        .iter()
        .map(logpush_job)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({"result": projected.into_iter().take(100).collect::<Vec<_>>() }))
}

const ZOD_EMAIL_PATTERN: &str = r"^(?!\.)(?!.*\.\.)([A-Za-z0-9_'+\-\.]*)[A-Za-z0-9_+-]@([A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}$";
const ZOD_DATETIME_PATTERN: &str = r"^(?:(?:\d\d[2468][048]|\d\d[13579][26]|\d\d0[48]|[02468][048]00|[13579][26]00)-02-29|\d{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12]\d|3[01])|(?:0[469]|11)-(?:0[1-9]|[12]\d|30)|(?:02)-(?:0[1-9]|1\d|2[0-8])))T(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d+)?)?Z$";

fn auditlogs_response_schema() -> Value {
    json!({
        "type": "object",
        "required": ["success", "result_info"],
        "properties": {
            "success": {"const": true},
            "errors": {"type": "array", "items": {"type": "object", "required": ["message"], "properties": {"message": {"type": "string"}}}},
            "result": {"type": "array", "items": {
                "type": "object",
                "required": ["id", "account", "action"],
                "properties": {
                    "id": {"type": "string", "maxLength": 36},
                    "account": {"type": "object", "required": ["id", "name"], "properties": {"id": {"type": "string"}, "name": {"type": "string"}}},
                    "action": {"type": "object", "required": ["result", "time", "type"], "properties": {
                        "description": {"type": "string"},
                        "result": {"enum": ["success", "failure", ""]},
                        "time": {"type": "string", "pattern": ZOD_DATETIME_PATTERN},
                        "type": {"enum": ["create", "delete", "view", "update", "login"]}
                    }},
                    "actor": {"type": "object", "properties": {
                        "context": {"enum": ["api_key", "api_token", "dash", "oauth", "origin_ca_key"]},
                        "email": {"type": "string", "pattern": ZOD_EMAIL_PATTERN},
                        "id": {"type": "string"},
                        "ip_address": {"type": "string"},
                        "type": {"enum": ["cloudflare_admin", "account", "user", "system"]},
                        "token_id": {"type": "string"},
                        "token_name": {"type": "string"}
                    }},
                    "resource": {"type": "object", "properties": {
                        "id": {"type": "string"},
                        "product": {"type": "string"},
                        "request": {"type": "object"},
                        "response": {"type": "object"},
                        "scope": {"anyOf": [{"type": "string"}, {"type": "object"}]},
                        "type": {"type": "string"}
                    }},
                    "raw": {"type": "object", "properties": {
                        "cf_ray_id": {"type": "string"},
                        "method": {"type": "string"},
                        "status_code": {"type": "number"},
                        "uri": {"type": "string"},
                        "user_agent": {"type": "string"}
                    }},
                    "zone": {"type": "object", "properties": {"id": {"type": "string"}, "name": {"type": "string"}}}
                }
            }},
            "result_info": {"type": "object", "required": ["count"], "properties": {"count": {"type": "number"}, "cursor": {"type": "string"}}}
        }
    })
}

fn auditlog_projection(value: &Value) -> Result<Value, AppError> {
    let object = value
        .as_object()
        .ok_or_else(|| AppError::api("audit log entry must be an object"))?;
    if object
        .get("id")
        .and_then(Value::as_str)
        .is_none_or(|id| id.encode_utf16().count() > 36)
    {
        return Err(AppError::api(
            "audit log id must be a string of at most 36 UTF-16 units",
        ));
    }
    let action = object
        .get("action")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::api("audit log action must be an object"))?;
    let time = action
        .get("time")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::api("audit log action time must be a string"))?;
    let mut out = Map::new();
    out.insert(
        "description".into(),
        Value::String(
            action
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .into(),
        ),
    );
    out.insert("time".into(), Value::String(time.into()));
    if let Some(actor) = object.get("actor").and_then(Value::as_object) {
        if let Some(email) = actor.get("email") {
            out.insert("actor_email".into(), email.clone());
        }
        if let Some(token_name) = actor.get("token_name") {
            out.insert("actor_token_name".into(), token_name.clone());
        }
    }
    if let Some(resource) = object.get("resource").and_then(Value::as_object) {
        if let Some(product) = resource.get("product") {
            out.insert("product".into(), product.clone());
        }
        if let Some(kind) = resource.get("type") {
            out.insert("type".into(), kind.clone());
        }
    }
    Ok(Value::Object(out))
}

fn javascript_number_string(value: &Value) -> Result<String, AppError> {
    let number = value
        .as_f64()
        .filter(|number| number.is_finite())
        .ok_or_else(|| AppError::usage("numeric query value is invalid"))?;
    if number == 0.0 {
        return Ok("0".into());
    }
    let negative = number.is_sign_negative();
    let absolute = number.abs();
    let mut text = absolute.to_string();
    if let Some((mantissa, exponent)) = text.split_once(['e', 'E']) {
        let exponent = exponent
            .parse::<i32>()
            .map_err(|_| AppError::usage("numeric query value cannot be serialized"))?;
        return Ok(format!(
            "{}{mantissa}e{}{exponent}",
            if negative { "-" } else { "" },
            if exponent >= 0 { "+" } else { "" }
        ));
    }
    if absolute >= 1e21 {
        let exponent = text.find('.').unwrap_or(text.len()) as i32 - 1;
        text.retain(|character| character != '.');
        while text.ends_with('0') {
            text.pop();
        }
        let (first, rest) = text.split_at(1);
        return Ok(format!(
            "{}{}{}e+{exponent}",
            if negative { "-" } else { "" },
            first,
            if rest.is_empty() {
                String::new()
            } else {
                format!(".{rest}")
            }
        ));
    }
    if absolute < 1e-6 {
        let fraction = text
            .strip_prefix("0.")
            .ok_or_else(|| AppError::usage("numeric query value cannot be serialized"))?;
        let zeros = fraction.bytes().take_while(|byte| *byte == b'0').count();
        let digits = fraction[zeros..].trim_end_matches('0');
        let (first, rest) = digits.split_at(1);
        return Ok(format!(
            "{}{}{}e-{}",
            if negative { "-" } else { "" },
            first,
            if rest.is_empty() {
                String::new()
            } else {
                format!(".{rest}")
            },
            zeros + 1
        ));
    }
    if negative {
        text.insert(0, '-');
    }
    Ok(text)
}

fn auditlogs_request(
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
    let mut query = Vec::new();
    for key in [
        "account_name",
        "action_result",
        "action_type",
        "actor_context",
        "actor_email",
        "actor_id",
        "actor_ip_address",
        "actor_token_id",
        "actor_token_name",
        "actor_type",
        "audit_log_id",
        "raw_cf_ray_id",
        "raw_method",
        "raw_status_code",
        "raw_uri",
        "resource_id",
        "resource_product",
        "resource_type",
        "resource_scope",
        "zone_id",
        "zone_name",
        "since",
        "before",
        "direction",
        "limit",
        "cursor",
    ] {
        let value = if key == "limit" {
            input.get(key).cloned().unwrap_or_else(|| json!(10))
        } else if let Some(value) = input.get(key) {
            value.clone()
        } else {
            continue;
        };
        let value = match value {
            Value::String(value) => value,
            Value::Number(_) => javascript_number_string(&value)?,
            _ => return Err(AppError::usage("audit log query value has invalid type")),
        };
        query.push((key.into(), value));
    }
    let auth = config::auth_for(&cfg)?;
    let response = client::CloudflareClient::new(cfg, auth)?.request_with_trusted_headers(
        client::RequestOptions {
            method: client::Method::Get,
            path: format!("/accounts/{account}/logs/audit"),
            query,
            body: None,
            allow_write: false,
            confirm_delete: None,
            retry_policy: client::RetryPolicy::Never,
            allow_classified_read_post: false,
        },
        &[
            ("Content-Type", "application/json"),
            ("portal-version", "2"),
        ],
        true,
    )?;
    let schema = auditlogs_response_schema();
    let validator = jsonschema::draft202012::new(&schema)
        .map_err(|_| AppError::api("embedded audit logs response schema is invalid"))?;
    if !validator.is_valid(&response.envelope) {
        return Err(AppError::api("audit logs response envelope is malformed"));
    }
    let envelope = response
        .envelope
        .as_object()
        .ok_or_else(|| AppError::api("audit logs response envelope is malformed"))?;
    let rows = envelope
        .get("result")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let logs = rows
        .iter()
        .map(auditlog_projection)
        .collect::<Result<Vec<_>, _>>()?;
    let info = envelope["result_info"]
        .as_object()
        .ok_or_else(|| AppError::api("audit logs result_info is malformed"))?;
    let mut result_info = Map::new();
    result_info.insert("count".into(), info["count"].clone());
    if let Some(cursor) = info.get("cursor") {
        result_info.insert("cursor".into(), cursor.clone());
    }
    Ok(json!({"logs": logs, "result_info": result_info}))
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
    let auth = config::auth_for(&cfg)?;
    let r = client::CloudflareClient::new(cfg, auth)?.request(client::RequestOptions {
        method,
        path,
        query: vec![],
        body: (method != client::Method::Get).then_some(body),
        allow_write: false,
        confirm_delete: None,
        retry_policy,
        allow_classified_read_post: true,
    })?;
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
    let auth = config::auth_for(&cfg)?;
    let response =
        client::CloudflareClient::new(cfg, auth)?.request_binary(client::RequestOptions {
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

fn autorag_request(
    input: &Map<String, Value>,
    endpoint: Option<&str>,
    cli_account: Option<String>,
) -> Result<Value, AppError> {
    let mut cfg = config::load(endpoint.map(str::to_owned), cli_account, None)?;
    if let (Some(a), Some(i)) = (
        cfg.account.as_deref(),
        input.get("account_id").and_then(Value::as_str),
    ) {
        if a != i {
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
    let query = [
        (
            "page",
            input.get("page").cloned().unwrap_or_else(|| json!(1)),
        ),
        (
            "per_page",
            input.get("per_page").cloned().unwrap_or_else(|| json!(20)),
        ),
    ]
    .into_iter()
    .map(|(k, v)| Ok::<_, AppError>((k.to_owned(), javascript_number_string(&v)?)))
    .collect::<Result<Vec<_>, _>>()?;
    let auth = config::auth_for(&cfg)?;
    let response = client::CloudflareClient::new(cfg, auth)?.request(client::RequestOptions {
        method: client::Method::Get,
        path: format!("/accounts/{account}/autorag/rags"),
        query,
        body: None,
        allow_write: false,
        confirm_delete: None,
        retry_policy: client::RetryPolicy::TransientRead,
        allow_classified_read_post: false,
    })?;
    let root = response
        .envelope
        .as_object()
        .ok_or_else(|| AppError::api("AutoRAG response envelope is malformed"))?;
    if root.get("success") != Some(&Value::Bool(true)) {
        return Err(AppError::api("AutoRAG response envelope is malformed"));
    }
    let rows = root
        .get("result")
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::api("AutoRAG result must be an array"))?;
    let info = root
        .get("result_info")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::api("AutoRAG result_info must be an object"))?;
    let total = info
        .get("total_count")
        .filter(|v| v.is_number())
        .cloned()
        .ok_or_else(|| AppError::api("AutoRAG total_count must be numeric"))?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let o = row
            .as_object()
            .ok_or_else(|| AppError::api("AutoRAG result entry must be an object"))?;
        out.push(json!({"id": o.get("id").and_then(Value::as_str).ok_or_else(|| AppError::api("AutoRAG id must be a string"))?, "source": o.get("source").and_then(Value::as_str).ok_or_else(|| AppError::api("AutoRAG source must be a string"))?, "paused": o.get("paused").and_then(Value::as_bool).ok_or_else(|| AppError::api("AutoRAG paused must be boolean"))?}));
    }
    Ok(json!({"autorags": out, "total_count": total}))
}

fn workers_response_error(field: &str) -> AppError {
    AppError::api(format!("Workers Builds response {field} is malformed"))
}

fn workers_object<'a>(value: &'a Value, field: &str) -> Result<&'a Map<String, Value>, AppError> {
    value
        .as_object()
        .ok_or_else(|| workers_response_error(&format!("{field} must be an object")))
}

fn workers_string(object: &Map<String, Value>, field: &str) -> Result<String, AppError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| workers_response_error(&format!("{field} must be a string")))
}

fn workers_nullable_string(object: &Map<String, Value>, field: &str) -> Result<Value, AppError> {
    match object.get(field) {
        Some(Value::Null) => Ok(Value::Null),
        Some(Value::String(value)) => Ok(Value::String(value.clone())),
        _ => Err(workers_response_error(&format!(
            "{field} must be null or a string"
        ))),
    }
}

fn workers_nullable_string_type(object: &Map<String, Value>, field: &str) -> Result<(), AppError> {
    match object.get(field) {
        Some(Value::Null | Value::String(_)) => Ok(()),
        _ => Err(workers_response_error(&format!(
            "{field} must be null or a string"
        ))),
    }
}

fn workers_bool(object: &Map<String, Value>, field: &str) -> Result<(), AppError> {
    if object.get(field).is_some_and(Value::is_boolean) {
        Ok(())
    } else {
        Err(workers_response_error(&format!(
            "{field} must be a boolean"
        )))
    }
}

fn workers_string_array(object: &Map<String, Value>, field: &str) -> Result<(), AppError> {
    let values = object
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| workers_response_error(&format!("{field} must be an array")))?;
    if values.iter().all(Value::is_string) {
        Ok(())
    } else {
        Err(workers_response_error(&format!(
            "{field} must contain only strings"
        )))
    }
}

const WORKERS_DATE_MAX_MILLIS: i128 = 8_640_000_000_000_000;

fn workers_digits(bytes: &[u8], start: usize, length: usize) -> Option<u32> {
    let end = start.checked_add(length)?;
    if end > bytes.len() {
        return None;
    }
    let mut value = 0u32;
    for byte in &bytes[start..end] {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value
            .checked_mul(10)?
            .checked_add(u32::from(*byte - b'0'))?;
    }
    Some(value)
}

fn workers_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn workers_days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 {
        year / 400
    } else {
        (year - 399) / 400
    };
    let year_of_era = year - era * 400;
    let month_prime = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn workers_civil_from_days(days: i64) -> (i64, u32, u32) {
    let days = days + 719_468;
    let era = if days >= 0 {
        days / 146_097
    } else {
        (days - 146_096) / 146_097
    };
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    (year + i64::from(month <= 2), month as u32, day as u32)
}

fn workers_iso_millis(timestamp: i128) -> Option<String> {
    if !(-WORKERS_DATE_MAX_MILLIS..=WORKERS_DATE_MAX_MILLIS).contains(&timestamp) {
        return None;
    }
    let timestamp = i64::try_from(timestamp).ok()?;
    let seconds = timestamp.div_euclid(1_000);
    let millis = timestamp.rem_euclid(1_000);
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let (year, month, day) = workers_civil_from_days(days);
    let hour = day_seconds / 3_600;
    let minute = day_seconds.rem_euclid(3_600) / 60;
    let second = day_seconds.rem_euclid(60);
    let year = match year {
        0..=9_999 => format!("{year:04}"),
        year if year < 0 => format!("-{:06}", year.unsigned_abs()),
        year => format!("+{year:06}"),
    };
    Some(format!(
        "{year}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z"
    ))
}

// The pinned provider schema uses z.coerce.date(). JSON responses carry this
// as an ISO date/time string or a millisecond number; reject ambiguous values
// and project both accepted forms through the Date.toISOString() shape.
fn workers_parse_iso_date(value: &str) -> Option<i128> {
    let bytes = value.trim().as_bytes();
    if bytes.len() < 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let year = i64::from(workers_digits(bytes, 0, 4)?);
    let month = workers_digits(bytes, 5, 2)?;
    let day = workers_digits(bytes, 8, 2)?;
    let maximum_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if workers_leap(year) => 29,
        2 => 28,
        _ => return None,
    };
    if day == 0 || day > maximum_day {
        return None;
    }
    if bytes.len() == 10 {
        return Some(i128::from(workers_days_from_civil(year, month, day)) * 86_400_000);
    }
    if bytes.len() < 20 || bytes[10] != b'T' || bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    let hour = workers_digits(bytes, 11, 2)?;
    let minute = workers_digits(bytes, 14, 2)?;
    let second = workers_digits(bytes, 17, 2)?;
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }

    let mut index = 19;
    let mut fraction = 0u32;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        let digits = &bytes[start..index];
        if digits.is_empty() || digits.len() > 9 {
            return None;
        }
        for byte in digits.iter().take(3) {
            fraction = fraction * 10 + u32::from(*byte - b'0');
        }
        for _ in digits.len().min(3)..3 {
            fraction *= 10;
        }
    }

    let offset_minutes = match bytes.get(index) {
        Some(b'Z') if index + 1 == bytes.len() => 0,
        Some(sign @ (b'+' | b'-')) if index + 6 == bytes.len() && bytes[index + 3] == b':' => {
            let offset_hour = workers_digits(bytes, index + 1, 2)?;
            let offset_minute = workers_digits(bytes, index + 4, 2)?;
            if offset_hour > 23 || offset_minute > 59 {
                return None;
            }
            let minutes = i32::try_from(offset_hour * 60 + offset_minute).ok()?;
            if *sign == b'+' { minutes } else { -minutes }
        }
        _ => return None,
    };
    let local = i128::from(workers_days_from_civil(year, month, day)) * 86_400_000
        + i128::from(hour) * 3_600_000
        + i128::from(minute) * 60_000
        + i128::from(second) * 1_000
        + i128::from(fraction);
    Some(local - i128::from(offset_minutes) * 60_000)
}

fn workers_coerce_date(value: &Value) -> Option<String> {
    let timestamp = match value {
        Value::Number(number) => {
            let millis = number.as_f64()?;
            if !millis.is_finite()
                || millis < -(WORKERS_DATE_MAX_MILLIS as f64)
                || millis > WORKERS_DATE_MAX_MILLIS as f64
            {
                return None;
            }
            millis.trunc() as i128
        }
        Value::String(value) => workers_parse_iso_date(value)?,
        _ => return None,
    };
    workers_iso_millis(timestamp)
}

fn workers_date(object: &Map<String, Value>, field: &str) -> Result<String, AppError> {
    workers_coerce_date(
        object
            .get(field)
            .ok_or_else(|| workers_response_error(&format!("{field} is required")))?,
    )
    .ok_or_else(|| workers_response_error(&format!("{field} must be a valid date")))
}

fn workers_nullable_date(object: &Map<String, Value>, field: &str) -> Result<(), AppError> {
    let value = object
        .get(field)
        .ok_or_else(|| workers_response_error(&format!("{field} is required")))?;
    if value.is_null() {
        Ok(())
    } else {
        workers_coerce_date(value)
            .map(|_| ())
            .ok_or_else(|| workers_response_error(&format!("{field} must be null or a valid date")))
    }
}

fn workers_validate_environment_variables(object: &Map<String, Value>) -> Result<(), AppError> {
    let variables = workers_object(
        object
            .get("environment_variables")
            .ok_or_else(|| workers_response_error("environment_variables is required"))?,
        "environment_variables",
    )?;
    for (name, value) in variables {
        let variable = workers_object(value, &format!("environment_variables.{name}"))?;
        workers_bool(variable, "is_secret")?;
        workers_date(variable, "created_on")?;
        workers_nullable_string_type(variable, "value")?;
    }
    Ok(())
}

fn workers_validate_build_details(value: &Value) -> Result<Value, AppError> {
    let build = workers_object(value, "result")?;
    let build_uuid = workers_string(build, "build_uuid")?;
    let status = workers_string(build, "status")?;
    let build_outcome = workers_nullable_string(build, "build_outcome")?;
    let created_on = workers_date(build, "created_on")?;
    workers_date(build, "modified_on")?;
    workers_nullable_date(build, "initializing_on")?;
    workers_nullable_date(build, "running_on")?;
    workers_nullable_date(build, "stopped_on")?;

    let trigger = workers_object(
        build
            .get("trigger")
            .ok_or_else(|| workers_response_error("trigger is required"))?,
        "trigger",
    )?;
    for field in [
        "trigger_uuid",
        "external_script_id",
        "trigger_name",
        "build_command",
        "deploy_command",
        "root_directory",
    ] {
        workers_string(trigger, field)?;
    }
    for field in [
        "branch_includes",
        "branch_excludes",
        "path_includes",
        "path_excludes",
    ] {
        workers_string_array(trigger, field)?;
    }
    workers_bool(trigger, "build_caching_enabled")?;
    workers_date(trigger, "created_on")?;
    workers_date(trigger, "modified_on")?;
    workers_nullable_date(trigger, "deleted_on")?;
    let repo_connection = workers_object(
        trigger
            .get("repo_connection")
            .ok_or_else(|| workers_response_error("repo_connection is required"))?,
        "repo_connection",
    )?;
    for field in [
        "repo_connection_uuid",
        "repo_id",
        "repo_name",
        "provider_type",
        "provider_account_id",
        "provider_account_name",
    ] {
        workers_string(repo_connection, field)?;
    }
    workers_date(repo_connection, "created_on")?;
    workers_date(repo_connection, "modified_on")?;
    workers_nullable_date(repo_connection, "deleted_on")?;

    let metadata = workers_object(
        build
            .get("build_trigger_metadata")
            .ok_or_else(|| workers_response_error("build_trigger_metadata is required"))?,
        "build_trigger_metadata",
    )?;
    for field in [
        "build_trigger_source",
        "branch",
        "commit_hash",
        "commit_message",
        "author",
        "build_command",
        "deploy_command",
        "root_directory",
        "build_token_uuid",
        "repo_name",
        "provider_account_name",
        "provider_type",
    ] {
        workers_string(metadata, field)?;
    }
    workers_validate_environment_variables(metadata)?;
    if !build.contains_key("pull_request") {
        return Err(workers_response_error("pull_request is required"));
    }

    Ok(json!({
        "buildUUID": build_uuid,
        "createdOn": created_on,
        "status": status,
        "buildOutcome": build_outcome,
        "branch": workers_string(metadata, "branch")?,
        "commitHash": workers_string(metadata, "commit_hash")?,
        "commitMessage": workers_string(metadata, "commit_message")?,
        "commitAuthor": workers_string(metadata, "author")?,
        "buildCommand": workers_string(metadata, "build_command")?,
        "deployCommand": workers_string(metadata, "deploy_command")?,
    }))
}

fn workers_builds_response(envelope: Value) -> Result<Value, AppError> {
    let root = workers_object(&envelope, "root envelope")?;
    if root.get("success") != Some(&Value::Bool(true)) {
        return Err(workers_response_error("success must be true"));
    }
    let errors = root
        .get("errors")
        .and_then(Value::as_array)
        .ok_or_else(|| workers_response_error("errors must be an array"))?;
    for error in errors {
        let error = workers_object(error, "errors entry")?;
        workers_string(error, "message")?;
        if let Some(code) = error.get("code") {
            if !code.is_number() {
                return Err(workers_response_error("error code must be a number"));
            }
        }
    }
    if !root.get("messages").is_some_and(Value::is_array) {
        return Err(workers_response_error("messages must be an array"));
    }
    let result = root
        .get("result")
        .ok_or_else(|| workers_response_error("result is required"))?;
    if result.is_null() {
        Ok(Value::Null)
    } else {
        workers_validate_build_details(result)
    }
}

fn workers_builds_get_build_request(
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
    let account = workers_account_id(cfg.account.as_deref().ok_or_else(|| {
        AppError::usage("account scope required; use --account or input account_id")
    })?)?;
    let build_uuid = workers_build_uuid(
        input
            .get("buildUUID")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::usage("buildUUID is required"))?,
    )?;
    client::validate_endpoint(&cfg.endpoint)?;
    let auth = config::auth_for(&cfg)?;
    let response = client::CloudflareClient::new(cfg, auth)?.request_with_trusted_headers(
        client::RequestOptions {
            method: client::Method::Get,
            path: format!("/accounts/{account}/builds/builds/{build_uuid}"),
            query: vec![],
            body: None,
            allow_write: false,
            confirm_delete: None,
            retry_policy: client::RetryPolicy::TransientRead,
            allow_classified_read_post: false,
        },
        &[],
        true,
    )?;
    workers_builds_response(response.envelope)
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
        "logpush_jobs_by_account_id" => logpush_request(&input, endpoint.as_deref(), cli_account),
        "auditlogs_by_account_id" => auditlogs_request(&input, endpoint.as_deref(), cli_account),
        "workers_builds_get_build" => {
            workers_builds_get_build_request(&input, endpoint.as_deref(), cli_account)
        }
        "list_rags" => autorag_request(&input, endpoint.as_deref(), cli_account),
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
