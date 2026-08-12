use crate::{
    capability::{self, Capability},
    config::{self, Auth},
    error::AppError,
};
use serde_json::{Value, json};
use std::{io::Read, time::Duration};
use url::Url;
pub const MAX_RESPONSE: usize = 8 * 1024 * 1024;
const MAX_REQUEST: usize = 1024 * 1024;
const PROTOCOL: &str = "2026-07-28";
#[derive(Clone, Copy, Debug)]
pub struct Server {
    pub name: &'static str,
    pub url: &'static str,
    pub authenticated: bool,
    pub family: &'static str,
    pub deprecated: bool,
}
pub const SERVERS: &[Server] = &[
    Server {
        name: "cloudflare",
        url: "https://mcp.cloudflare.com/mcp",
        authenticated: true,
        family: "unified-cloudflare-api",
        deprecated: false,
    },
    Server {
        name: "docs",
        url: "https://docs.mcp.cloudflare.com/mcp",
        authenticated: false,
        family: "shared",
        deprecated: false,
    },
    Server {
        name: "bindings",
        url: "https://bindings.mcp.cloudflare.com/mcp",
        authenticated: true,
        family: "workers-bindings",
        deprecated: false,
    },
    Server {
        name: "builds",
        url: "https://builds.mcp.cloudflare.com/mcp",
        authenticated: true,
        family: "workers-builds",
        deprecated: false,
    },
    Server {
        name: "observability",
        url: "https://observability.mcp.cloudflare.com/mcp",
        authenticated: true,
        family: "workers-observability",
        deprecated: false,
    },
    Server {
        name: "containers",
        url: "https://containers.mcp.cloudflare.com/mcp",
        authenticated: true,
        family: "sandbox-container",
        deprecated: false,
    },
    Server {
        name: "browser",
        url: "https://browser.mcp.cloudflare.com/mcp",
        authenticated: true,
        family: "browser-rendering",
        deprecated: false,
    },
    Server {
        name: "logs",
        url: "https://logs.mcp.cloudflare.com/mcp",
        authenticated: true,
        family: "logpush",
        deprecated: false,
    },
    Server {
        name: "ai-gateway",
        url: "https://ai-gateway.mcp.cloudflare.com/mcp",
        authenticated: true,
        family: "ai-gateway",
        deprecated: false,
    },
    Server {
        name: "autorag",
        url: "https://autorag.mcp.cloudflare.com/mcp",
        authenticated: true,
        family: "autorag",
        deprecated: true,
    },
    Server {
        name: "auditlogs",
        url: "https://auditlogs.mcp.cloudflare.com/mcp",
        authenticated: true,
        family: "auditlogs",
        deprecated: false,
    },
    Server {
        name: "dns-analytics",
        url: "https://dns-analytics.mcp.cloudflare.com/mcp",
        authenticated: true,
        family: "dns-analytics",
        deprecated: false,
    },
    Server {
        name: "dex",
        url: "https://dex.mcp.cloudflare.com/mcp",
        authenticated: true,
        family: "dex-analysis",
        deprecated: false,
    },
    Server {
        name: "casb",
        url: "https://casb.mcp.cloudflare.com/mcp",
        authenticated: true,
        family: "cloudflare-one-casb",
        deprecated: false,
    },
    Server {
        name: "radar",
        url: "https://radar.mcp.cloudflare.com/mcp",
        authenticated: true,
        family: "radar",
        deprecated: true,
    },
    Server {
        name: "graphql",
        url: "https://graphql.mcp.cloudflare.com/mcp",
        authenticated: true,
        family: "graphql",
        deprecated: true,
    },
    Server {
        name: "agents-docs",
        url: "https://agents.cloudflare.com/mcp",
        authenticated: false,
        family: "agents-sdk-docs",
        deprecated: false,
    },
    Server {
        name: "blog",
        url: "https://blog.mcp.cloudflare.com/mcp",
        authenticated: false,
        family: "cloudflare-blog",
        deprecated: false,
    },
    Server {
        name: "demo-day",
        url: "https://demo-day.mcp.cloudflare.com/mcp",
        authenticated: false,
        family: "demo-day",
        deprecated: false,
    },
];
pub fn server(name: &str) -> Result<&'static Server, AppError> {
    SERVERS
        .iter()
        .find(|s| s.name == name)
        .ok_or_else(|| AppError::usage(format!("unknown MCP server '{name}'")))
}
pub fn list_servers() -> Value {
    json!({"servers":SERVERS.iter().map(|s|json!({"name":s.name,"url":s.url,"auth":if s.authenticated{"bearer"}else{"public"},"family":s.family,"deprecated":s.deprecated})).collect::<Vec<_>>()})
}
fn mapped(e: &Capability) -> Result<&'static Server, AppError> {
    let name = match e.family.as_str() {
        "shared" => "docs",
        "cloudflare-blog" => "blog",
        "demo-day" => "demo-day",
        "cloudflare-one-casb" => "casb",
        "dex-analysis" => "dex",
        "sandbox-container" => "containers",
        "browser-rendering" => "browser",
        "logpush" => "logs",
        "ai-gateway" => "ai-gateway",
        "autorag" => "autorag",
        "auditlogs" => "auditlogs",
        "dns-analytics" => "dns-analytics",
        "radar" => "radar",
        "workers-bindings" => "bindings",
        "workers-builds" => "builds",
        "workers-observability" => "observability",
        "graphql" => "graphql",
        "stack-mcp" => {
            return Err(AppError::api(
                "stack-mcp has no authoritative hosted endpoint",
            ));
        }
        _ => {
            return Err(AppError::api(format!(
                "no MCP mapping for family '{}'",
                e.family
            )));
        }
    };
    server(name)
}
fn validate_input(v: &Value) -> Result<(), AppError> {
    if serde_json::to_vec(v)
        .map_err(|_| AppError::usage("tool input cannot be serialized"))?
        .len()
        > MAX_REQUEST
    {
        return Err(AppError::usage("tool input exceeds 1 MiB"));
    }
    if !v.is_object() {
        return Err(AppError::usage("tool input must be a JSON object"));
    }
    Ok(())
}
fn guard_remote(
    server: &Server,
    name: &str,
    input: &Value,
    allow_write: bool,
    allow_metered: bool,
    confirm: Option<&str>,
) -> Result<(), AppError> {
    validate_input(input)?;
    if server.name == "cloudflare" && name == "search" {
        return Ok(());
    }
    if server.name == "docs" && name == "search_cloudflare_documentation" {
        if allow_metered {
            return Ok(());
        }
        return Err(AppError::usage(format!(
            "tool '{name}' requires --allow-metered"
        )));
    }
    if !allow_write || !allow_metered || confirm != Some(name) {
        return Err(AppError::usage(format!(
            "remote tool '{name}' requires --allow-write --allow-metered --confirm {name}; local inventory is not authoritative safety metadata"
        )));
    }
    Ok(())
}
fn auth_for(s: &Server) -> Result<Option<Auth>, AppError> {
    if !s.authenticated {
        return Ok(None);
    }
    let auth = config::auth()?;
    if !matches!(auth, Auth::Bearer(_)) {
        return Err(AppError::auth(
            "hosted MCP requires CLOUDFLARE_API_TOKEN bearer authentication",
        ));
    }
    Ok(Some(auth))
}
fn redact(s: &str, secret: Option<&str>) -> String {
    secret.map_or_else(|| s.to_owned(), |x| s.replace(x, "[redacted]"))
}
fn body(
    mut r: ureq::http::Response<ureq::Body>,
    secret: Option<&str>,
) -> Result<(u16, String, String), AppError> {
    let status = r.status().as_u16();
    let ct = r
        .headers()
        .get("content-type")
        .and_then(|x| x.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let mut b = Vec::new();
    r.body_mut()
        .as_reader()
        .take((MAX_RESPONSE + 1) as u64)
        .read_to_end(&mut b)
        .map_err(|e| AppError::network(redact(&e.to_string(), secret)))?;
    if b.len() > MAX_RESPONSE {
        return Err(AppError::network("MCP response exceeds 8 MiB"));
    }
    Ok((status, ct, redact(&String::from_utf8_lossy(&b), secret)))
}
fn rpc(v: Value) -> Result<Value, AppError> {
    if let Some(error) = v.get("error") {
        let code = error
            .get("code")
            .and_then(Value::as_i64)
            .map(|code| format!(" (JSON-RPC code {code})"))
            .unwrap_or_default();
        return Err(AppError::api(format!("MCP request failed{code}")));
    }
    let result = v
        .get("result")
        .ok_or_else(|| AppError::api("MCP response missing result"))?;
    if result.get("isError").and_then(Value::as_bool) == Some(true) {
        return Err(AppError::api("MCP tool reported an execution error"));
    }
    Ok(result.clone())
}
fn parse(ct: &str, text: &str) -> Result<Value, AppError> {
    if ct.contains("text/event-stream") {
        for line in text.lines().filter_map(|line| line.strip_prefix("data:")) {
            if let Ok(value) = serde_json::from_str::<Value>(line.trim()) {
                if value.get("result").is_some() || value.get("error").is_some() {
                    return rpc(value);
                }
            }
        }
        return Err(AppError::network(
            "MCP SSE response contained no JSON-RPC result",
        ));
    }
    rpc(serde_json::from_str(text).map_err(|_| AppError::network("MCP response was not JSON"))?)
}
fn metadata() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": PROTOCOL,
        "io.modelcontextprotocol/clientInfo": {
            "name": env!("CARGO_PKG_NAME"),
            "version": env!("CARGO_PKG_VERSION")
        },
        "io.modelcontextprotocol/clientCapabilities": {}
    })
}

fn post(
    s: &Server,
    endpoint: Option<&str>,
    method: &str,
    params: Value,
    account: Option<&str>,
) -> Result<Value, AppError> {
    let url = endpoint.unwrap_or(s.url);
    let u = Url::parse(url).map_err(|e| AppError::config(format!("invalid MCP endpoint: {e}")))?;
    if !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err(AppError::config(
            "MCP endpoint must not contain userinfo, query, or fragment",
        ));
    }
    let loopback = matches!(u.host(), Some(url::Host::Domain("localhost")))
        || matches!(u.host(),Some(url::Host::Ipv4(v))if v.is_loopback())
        || matches!(u.host(),Some(url::Host::Ipv6(v))if v.is_loopback());
    if u.scheme() != "https" && !(u.scheme() == "http" && loopback) {
        return Err(AppError::config(
            "MCP endpoint must use HTTPS; HTTP only permitted for loopback",
        ));
    }
    let a = auth_for(s)?;
    let secret = match &a {
        Some(Auth::Bearer(x)) | Some(Auth::KeyBearer(x)) => Some(x.as_str()),
        _ => None,
    };
    let mut params = params;
    if let Some(object) = params.as_object_mut() {
        object.insert("_meta".into(), metadata());
    }
    let tool_name = params
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let data = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        .map_err(|_| AppError::usage("MCP request cannot be serialized"))?;
    if data.len() > MAX_REQUEST {
        return Err(AppError::usage("MCP request exceeds 1 MiB"));
    }
    let ag: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .into();
    let mut q = ag
        .post(url)
        .header("Accept", "application/json, text/event-stream")
        .header("Content-Type", "application/json")
        .header("MCP-Protocol-Version", PROTOCOL)
        .header("Mcp-Method", method);
    if let Some(name) = &tool_name {
        q = q.header("Mcp-Name", name);
    }
    if let Some(x) = account {
        q = q.header("cf-account-id", x)
    }
    if let Some(Auth::Bearer(x) | Auth::KeyBearer(x)) = &a {
        q = q.header("Authorization", format!("Bearer {x}"))
    }
    let r = q
        .send(data)
        .map_err(|e| AppError::network(redact(&e.to_string(), secret)))?;
    let (st, ct, text) = body(r, secret)?;
    if !(200..300).contains(&st) {
        return Err(match st {
            401 | 403 => AppError::auth(format!("hosted MCP authorization failed (HTTP {st})")),
            429 => AppError::network("hosted MCP rate limited (HTTP 429)"),
            _ => AppError::api(format!("hosted MCP request failed (HTTP {st})")),
        });
    }
    parse(&ct, &text)
}
pub fn tools_list(n: Option<&str>, e: Option<&str>, a: Option<&str>) -> Result<Value, AppError> {
    post(server(n.unwrap_or("docs"))?, e, "tools/list", json!({}), a)
}
pub fn schema(
    name: &str,
    n: Option<&str>,
    e: Option<&str>,
    a: Option<&str>,
) -> Result<Value, AppError> {
    let selected = if let Some(server_name) = n {
        server(server_name)?
    } else {
        let capability = capability::get(name)
            .map_err(|_| AppError::api("embedded capability inventory is invalid"))?
            .ok_or_else(|| AppError::usage(format!("unknown tool '{name}'")))?;
        mapped(&capability)?
    };
    tools_list(Some(selected.name), e, a)?
        .get("tools")
        .and_then(Value::as_array)
        .and_then(|tools| {
            tools
                .iter()
                .find(|tool| tool.get("name").and_then(Value::as_str) == Some(name))
        })
        .cloned()
        .ok_or_else(|| {
            AppError::usage(format!(
                "tool '{name}' is not exposed by server '{}'",
                selected.name
            ))
        })
}

#[allow(clippy::too_many_arguments)]
pub fn call(
    name: &str,
    input: Value,
    n: Option<&str>,
    e: Option<&str>,
    a: Option<&str>,
    w: bool,
    m: bool,
    c: Option<&str>,
) -> Result<Value, AppError> {
    let capability = capability::get(name)
        .map_err(|_| AppError::api("embedded capability inventory is invalid"))?;
    let selected = if let Some(server_name) = n {
        server(server_name)?
    } else {
        let known = capability
            .as_ref()
            .ok_or_else(|| AppError::usage(format!("unknown tool '{name}'")))?;
        mapped(known)?
    };
    guard_remote(selected, name, &input, w, m, c)?;
    let r = post(
        selected,
        e,
        "tools/call",
        json!({"name":name,"arguments":input}),
        a,
    )?;
    Ok(normalize(r))
}

pub fn verified_call(name: &str, input: Value, endpoint: Option<&str>) -> Result<Value, AppError> {
    let selected = server("docs")?;
    validate_input(&input)?;
    let result = post(
        selected,
        endpoint,
        "tools/call",
        json!({"name": name, "arguments": input}),
        None,
    )?;
    let content = result
        .get("structuredContent")
        .ok_or_else(|| AppError::api("MCP tool response missing structuredContent"))?;
    let results = content
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::api("MCP structuredContent must be {results:[...] }"))?;
    let mut projected = Vec::with_capacity(results.len());
    for (index, record) in results.iter().enumerate() {
        let object = record
            .as_object()
            .ok_or_else(|| AppError::api(format!("MCP result {index} must be an object")))?;
        let similarity = object
            .get("similarity")
            .and_then(Value::as_f64)
            .filter(|value| value.is_finite())
            .ok_or_else(|| {
                AppError::api(format!(
                    "MCP result {index} similarity must be finite number"
                ))
            })?;
        let string_field = |name: &str| {
            object
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| AppError::api(format!("MCP result {index} {name} must be string")))
        };
        projected.push(json!({
            "similarity": similarity,
            "id": string_field("id")?,
            "url": string_field("url")?,
            "title": string_field("title")?,
            "text": string_field("text")?,
        }));
    }
    Ok(json!({"results": projected}))
}
fn normalize(v: Value) -> Value {
    if let Some(x) = v.get("structuredContent") {
        return x.clone();
    }
    if let Some(c) = v.get("content").and_then(Value::as_array) {
        if let Some(x) = c
            .iter()
            .filter_map(|x| x.get("text").and_then(Value::as_str))
            .find_map(|x| serde_json::from_str(x).ok())
        {
            return x;
        }
        return Value::Array(c.clone());
    }
    v
}
