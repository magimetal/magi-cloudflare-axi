mod capability;
mod cli;
mod client;
mod config;
mod error;
mod mcp;
mod operation;
mod session;
use clap::Parser;
use cli::*;
use error::{AppError, output_error, render, truncate};
use serde_json::{Value, json};
pub fn main_exit() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 2 && matches!(args[1].as_str(), "-v" | "-V" | "--version") {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return std::process::ExitCode::SUCCESS;
    }
    match Cli::try_parse() {
        Ok(cli) => {
            if cli.version {
                println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
                return std::process::ExitCode::SUCCESS;
            }
            let format = cli.format.clone();
            match run(cli) {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => {
                    output_error(&e, &format);
                    std::process::ExitCode::from(e.code())
                }
            }
        }
        Err(e) => {
            let format = args
                .windows(2)
                .find(|pair| pair[0] == "--format")
                .map(|pair| pair[1].as_str())
                .or_else(|| args.iter().find_map(|arg| arg.strip_prefix("--format=")))
                .filter(|value| *value == "json")
                .unwrap_or("toon");
            if e.use_stderr() {
                let message = e
                    .to_string()
                    .lines()
                    .next()
                    .unwrap_or("invalid command input")
                    .trim_start_matches("error: ")
                    .to_owned();
                output_error(&AppError::usage(message), format);
                std::process::ExitCode::from(2)
            } else {
                print!("{e}");
                std::process::ExitCode::SUCCESS
            }
        }
    }
}
fn scope_list(
    c: &Cli,
    zone: bool,
    fields: Vec<String>,
    limit: u32,
    page: u32,
    per_page: u32,
) -> Result<Value, AppError> {
    let defaults: &[&str] = if zone {
        &["id", "name", "status", "account"]
    } else {
        &["id", "name", "type"]
    };
    let requested: Vec<String> = fields
        .into_iter()
        .flat_map(|x| {
            x.split(',')
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect();
    let allowed: &[&str] = if zone {
        &[
            "id",
            "name",
            "status",
            "account",
            "plan",
            "paused",
            "name_servers",
        ]
    } else {
        &["id", "name", "type", "settings", "created_on", "managed_by"]
    };
    for field in &requested {
        if !allowed.contains(&field.as_str()) {
            return Err(AppError::usage(format!(
                "invalid {} field '{}'; valid fields: {}",
                if zone { "zone" } else { "account" },
                field,
                allowed.join(", ")
            )));
        }
    }
    let selected: Vec<&str> = if requested.is_empty() {
        defaults.to_vec()
    } else {
        requested.iter().map(String::as_str).collect()
    };
    let cfg = config::load(c.endpoint.clone(), c.account.clone(), c.zone.clone())?;
    let auth = config::auth_for(&cfg)?;
    let account_scope = if zone { cfg.account.clone() } else { None };
    let mut query = vec![
        ("page".into(), page.to_string()),
        ("per_page".into(), per_page.to_string()),
    ];
    if let Some(account) = &account_scope {
        query.push(("account.id".into(), account.clone()));
    }
    let api = client::CloudflareClient::new(cfg, auth)?;
    let path = if zone { "/zones" } else { "/accounts" };
    let response = api.request(client::RequestOptions {
        method: client::Method::Get,
        path: path.into(),
        query,
        body: None,
        allow_write: false,
        confirm_delete: None,
        retry_policy: client::RetryPolicy::TransientRead,
        allow_classified_read_post: false,
    })?;
    let mut rows = response
        .result
        .unwrap_or_else(|| json!([]))
        .as_array()
        .cloned()
        .unwrap_or_default();
    let total = response
        .result_info
        .as_ref()
        .and_then(|x| x.get("total_count").or_else(|| x.get("total")))
        .and_then(Value::as_u64)
        .unwrap_or(rows.len() as u64);
    rows.truncate(limit as usize);
    let data: Vec<Value> = rows
        .into_iter()
        .map(|row| {
            let mut out = serde_json::Map::new();
            if let Value::Object(obj) = row {
                for key in &selected {
                    if let Some(value) = obj.get(*key) {
                        out.insert((*key).into(), value.clone());
                    }
                }
            }
            Value::Object(out)
        })
        .collect();
    let info = response.result_info.unwrap_or_else(|| json!({}));
    let count = data.len();
    let total_pages = info
        .get("total_pages")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| {
            if per_page == 0 {
                0
            } else {
                total.div_ceil(per_page as u64)
            }
        });
    let noun = if zone { "zone" } else { "account" };
    let command_scope = account_scope
        .as_deref()
        .map(|account| format!("--account {} ", shell_argument(account)))
        .unwrap_or_default();
    let mut next = format!(
        "magi-cloudflare-axi {command_scope}{noun} list --page {} --per-page {per_page} --limit {limit}",
        page + 1
    );
    if !selected.is_empty() {
        next.push_str(&format!(" --fields {}", selected.join(",")));
    }
    let message = if count == 0 {
        Some(match &account_scope {
            Some(account) => format!("0 {noun}s found on page {page} for account {account}"),
            None => format!("0 {noun}s found on page {page}"),
        })
    } else {
        None
    };
    Ok(json!({
        "scope": {"resource": noun, "account": account_scope},
        "data": if zone {json!({"zones": data})} else {json!({"accounts": data})},
        "page": {"count": count, "total": total, "page": page, "per_page": per_page, "total_pages": total_pages},
        "message": message,
        "suggestions": if total_pages > page as u64 {Some(vec![next])} else {None::<Vec<String>>}
    }))
}
fn graphql_is_mutation(query: &str) -> bool {
    #[derive(Clone, Copy)]
    enum State {
        Normal,
        Comment,
        String { escaped: bool },
        BlockString,
    }

    let bytes = query.as_bytes();
    let mut state = State::Normal;
    let mut token = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        match state {
            State::Comment => {
                if bytes[index] == b'\n' || bytes[index] == b'\r' {
                    state = State::Normal;
                }
                index += 1;
            }
            State::String { escaped } => {
                state = match (escaped, bytes[index]) {
                    (true, _) => State::String { escaped: false },
                    (false, b'\\') => State::String { escaped: true },
                    (false, b'"') => State::Normal,
                    _ => State::String { escaped: false },
                };
                index += 1;
            }
            State::BlockString => {
                if bytes[index..].starts_with(b"\"\"\"")
                    && (index == 0 || bytes[index - 1] != b'\\')
                {
                    state = State::Normal;
                    index += 3;
                } else {
                    index += 1;
                }
            }
            State::Normal => {
                if bytes[index] == b'#' {
                    state = State::Comment;
                    index += 1;
                } else if bytes[index..].starts_with(b"\"\"\"") {
                    state = State::BlockString;
                    index += 3;
                } else if bytes[index] == b'"' {
                    state = State::String { escaped: false };
                    index += 1;
                } else if bytes[index].is_ascii_alphabetic() {
                    token.push(bytes[index].to_ascii_lowercase());
                    index += 1;
                } else {
                    if token == b"mutation" {
                        return true;
                    }
                    token.clear();
                    index += 1;
                }
            }
        }
    }
    matches!(state, State::Normal | State::Comment) && token == b"mutation"
}

fn paginate_api(
    a: &ApiArgs,
    body: Option<Value>,
    endpoint: Option<String>,
) -> Result<Value, AppError> {
    let mut query = a.query.clone();
    let mut merged = Vec::new();
    let mut info = Value::Null;
    if !matches!(a.method.to_ascii_uppercase().as_str(), "GET" | "HEAD") {
        return Err(AppError::usage(
            "--paginate is allowed only with GET or HEAD",
        ));
    }
    let mut partial = false;
    for page in 1..=a.max_pages {
        query.retain(|x| !x.starts_with("page="));
        query.push(format!("page={page}"));
        let read = matches!(a.method.to_ascii_uppercase().as_str(), "GET" | "HEAD");
        let response = client::request_response(
            &a.method,
            &a.path,
            body.clone(),
            endpoint.clone(),
            a.allow_write,
            (a.confirm_delete.as_deref(), read),
            &query,
        )?;
        info = response.result_info.unwrap_or(Value::Null);
        let result = response.result.unwrap_or(response.envelope);
        let Some(items) = result.as_array() else {
            return Ok(result);
        };
        for item in items {
            if merged.len() >= a.max_items as usize {
                partial = true;
                break;
            }
            merged.push(item.clone());
        }
        let reached_total = info
            .get("total_pages")
            .and_then(Value::as_u64)
            .is_some_and(|total| page as u64 >= total);
        if partial || items.is_empty() || reached_total {
            break;
        }
        if page == a.max_pages {
            partial = true;
        }
    }
    let mut out = json!({"result": merged, "result_info": info});
    if partial {
        out["suggestions"] = json!(["rerun with higher --max-pages or --max-items"]);
    }
    Ok(out)
}

fn shell_argument(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn resource_id(value: String, noun: &str) -> Result<String, AppError> {
    if value.is_empty()
        || value.contains('/')
        || value.contains('\\')
        || value == "."
        || value == ".."
    {
        return Err(AppError::usage(format!(
            "{noun} ID must be one non-empty path segment"
        )));
    }
    Ok(value)
}

fn run(c: Cli) -> Result<(), AppError> {
    let mut v = match c.command.clone() {
        None => {
            let cfg = config::load(c.endpoint.clone(), c.account.clone(), c.zone.clone())?;
            cli::home(&cfg, config::auth_for(&cfg))?
        }
        Some(Command::Server {
            command: ServerCommand::List,
        }) => mcp::list_servers(),
        Some(Command::Auth {
            command: AuthCommand::Status,
        }) => {
            let config = config::load(c.endpoint.clone(), c.account.clone(), c.zone.clone())?;
            client::validate_endpoint(&config.endpoint)?;
            let auth = config::auth_for(&config).ok();
            json!({
                "auth_configured": auth.is_some(),
                "auth_mode": auth.as_ref().map(|value| value.label()),
                "api_base": config.endpoint,
                "scope": {"account":config.account, "zone":config.zone}
            })
        }
        Some(Command::Auth {
            command: AuthCommand::Verify,
        }) => client::request(
            "GET",
            "/user/tokens/verify",
            None,
            c.endpoint,
            false,
            (None, true),
            &[],
        )?,
        Some(Command::Account {
            command:
                ScopeCommand::List {
                    fields,
                    limit,
                    page,
                    per_page,
                },
        }) => scope_list(&c, false, fields, limit, page, per_page)?,
        Some(Command::Zone {
            command:
                ScopeCommand::List {
                    fields,
                    limit,
                    page,
                    per_page,
                },
        }) => scope_list(&c, true, fields, limit, page, per_page)?,
        Some(Command::Account {
            command: ScopeCommand::Get { id },
        }) => {
            let cfg = config::load(c.endpoint.clone(), c.account.clone(), c.zone.clone())?;
            let id = resource_id(
                id.or(cfg.account)
                    .ok_or_else(|| AppError::usage("account ID required"))?,
                "account",
            )?;
            client::request(
                "GET",
                &format!("/accounts/{id}"),
                None,
                Some(cfg.endpoint),
                false,
                (None, true),
                &[],
            )?
        }
        Some(Command::Zone {
            command: ScopeCommand::Get { id },
        }) => {
            let cfg = config::load(c.endpoint.clone(), c.account.clone(), c.zone.clone())?;
            let id = resource_id(
                id.or(cfg.zone)
                    .ok_or_else(|| AppError::usage("zone ID required"))?,
                "zone",
            )?;
            client::request(
                "GET",
                &format!("/zones/{id}"),
                None,
                Some(cfg.endpoint),
                false,
                (None, true),
                &[],
            )?
        }
        Some(Command::Api(a)) => {
            let read = matches!(a.method.to_ascii_uppercase().as_str(), "GET" | "HEAD");
            if a.paginate && !read {
                return Err(AppError::usage(
                    "--paginate is allowed only with GET or HEAD",
                ));
            }
            client::preflight_raw(
                &a.method,
                &a.path,
                c.endpoint.as_deref(),
                a.allow_write,
                a.confirm_delete.as_deref(),
                (a.file.as_deref(), a.stdin, a.body.as_deref()),
            )?;
            let b = client::read_body(a.file.as_deref(), a.stdin, a.body.as_deref())?;
            let read = matches!(a.method.to_ascii_uppercase().as_str(), "GET" | "HEAD");
            if a.paginate {
                paginate_api(&a, b, c.endpoint)?
            } else {
                client::request(
                    &a.method,
                    &a.path,
                    b,
                    c.endpoint,
                    a.allow_write,
                    (a.confirm_delete.as_deref(), read),
                    &a.query,
                )?
            }
        }
        Some(Command::Graphql {
            query,
            file,
            schema,
            stdin,
            variables,
            variables_file,
            allow_write,
        }) => {
            let q = if schema {
                "query { __schema { queryType { name } } }".into()
            } else if stdin {
                client::read_text_stdin("GraphQL query")?
            } else if let Some(path) = file {
                client::read_text_file(&path, "GraphQL query")?
            } else {
                query.ok_or_else(|| {
                    AppError::usage("--query, --file, --stdin, or --schema required")
                })?
            };
            let vars = if let Some(path) = variables_file {
                client::read_text_file(&path, "GraphQL variables")?
            } else {
                variables.unwrap_or_else(|| "{}".into())
            };
            let vars: Value = serde_json::from_str(&vars)
                .map_err(|e| AppError::usage(format!("invalid variables JSON: {e}")))?;
            if !vars.is_object() {
                return Err(AppError::usage("GraphQL variables must be a JSON object"));
            }
            let mutation = graphql_is_mutation(&q);
            if mutation && !allow_write {
                return Err(AppError::usage("GraphQL mutations require --allow-write"));
            }
            client::request(
                "POST",
                "/graphql",
                Some(json!({"query": q, "variables": vars})),
                c.endpoint,
                allow_write || !mutation,
                (None, !mutation),
                &[],
            )?
        }
        Some(Command::Capability {
            command: CapabilityCommand::List { family, access },
        }) => capability::list(family.as_deref(), access.as_deref(), false)
            .map_err(|_| AppError::api("embedded capability inventory is invalid"))?,
        Some(Command::Capability {
            command: CapabilityCommand::Get { name },
        }) => {
            let entry = capability::get(&name)
                .map_err(|_| AppError::api("embedded capability inventory is invalid"))?
                .ok_or_else(|| AppError::usage(format!("unknown capability '{name}'")))?;
            capability::access_recipe(&entry)
        }
        Some(Command::Capability {
            command: CapabilityCommand::Schema { name },
        }) => capability::schema(&name)?,
        Some(Command::Capability {
            command:
                CapabilityCommand::Invoke {
                    name,
                    input,
                    file,
                    stdin,
                    allow_write,
                    allow_metered,
                    allow_egress,
                    allow_long_running,
                    confirm,
                },
        }) => {
            let flags = operation::GuardFlags {
                allow_write,
                allow_metered,
                allow_egress,
                allow_long_running,
                confirm: confirm.as_deref(),
            };
            operation::preflight(
                &name,
                None,
                c.endpoint.as_deref(),
                c.account.as_deref(),
                flags,
            )?;
            let body = client::read_body(file.as_deref(), stdin, input.as_deref())?
                .unwrap_or_else(|| json!({}));
            operation::preflight(
                &name,
                Some(&body),
                c.endpoint.as_deref(),
                c.account.as_deref(),
                flags,
            )?;
            operation::invoke(&name, body, c.endpoint, c.account, c.mcp_endpoint, flags)?
        }
        Some(Command::Tool { command }) => {
            let resolved = config::load(c.endpoint.clone(), c.account.clone(), c.zone.clone())?;
            let account = resolved.account.as_deref();
            match command {
                ToolCommand::List { all, server } => {
                    if server.is_some() {
                        mcp::tools_list(server.as_deref(), c.mcp_endpoint.as_deref(), account)?
                    } else {
                        capability::list(None, None, all).map_err(|_| {
                            AppError::api("embedded capability inventory is invalid")
                        })?
                    }
                }
                ToolCommand::Schema { name, server } => {
                    mcp::schema(&name, server.as_deref(), c.mcp_endpoint.as_deref(), account)?
                }
                ToolCommand::Call {
                    name,
                    server,
                    allow_write,
                    allow_metered,
                    confirm,
                    file,
                    stdin,
                    input,
                } => {
                    let body = client::read_body(file.as_deref(), stdin, input.as_deref())?
                        .unwrap_or_else(|| json!({}));
                    mcp::call(
                        &name,
                        body,
                        server.as_deref(),
                        c.mcp_endpoint.as_deref(),
                        account,
                        allow_write,
                        allow_metered,
                        confirm.as_deref(),
                    )?
                }
            }
        }
        Some(Command::Session { command }) => match command {
            SessionCommand::Context => return session::execute_context(&c.format),
            SessionCommand::Setup(a) => session::setup(a)?,
            SessionCommand::Status(a) => session::status(a)?,
            SessionCommand::Remove(a) => session::remove(a)?,
        },
        Some(Command::Setup(a)) => session::setup(a)?,
    };
    let mut seen = false;
    truncate(&mut v, c.full, &mut seen);
    if seen && !c.full {
        if let Value::Object(object) = &mut v {
            let suggestions = object.entry("suggestions").or_insert_with(|| json!([]));
            if let Some(items) = suggestions.as_array_mut() {
                items.push(json!("rerun the same command with --full"));
            }
        }
    }
    render(&v, &c.format)
}
#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    #[test]
    fn clap() {
        Cli::command().debug_assert();
    }
    #[test]
    fn trunc() {
        let mut v = json!({"x":"a".repeat(1001)});
        let mut s = false;
        truncate(&mut v, false, &mut s);
        assert!(s);
    }
    #[test]
    fn graphql_mutation_detection_skips_comments_and_strings() {
        assert!(!graphql_is_mutation(
            r#"query { value(text: "mutation \\" ignored") block(text: """mutation ignored""") }"#
        ));
        assert!(!graphql_is_mutation("# mutation\n query { value }"));
        assert!(graphql_is_mutation(
            r#"query { value(text: "escaped \\\")") } mutation Update { change }"#
        ));
    }
    #[test]
    fn guidance_artifacts_keep_core_contract_in_sync() {
        let readme = include_str!("../README.md");
        let contract = include_str!("../docs/plans/cloudflare-axi-contract.md");
        let roadmap = include_str!("../docs/plans/cloudflare-full-capability-parity-roadmap.md");
        let skill = include_str!("../skills/magi-cloudflare-axi/SKILL.md");
        for phrase in [
            "schema v3",
            "I=172; S=172; R=B=P=V=15; D=10; X=40",
            "capability invoke d1_database_get",
            "Phase 4B adds three authenticated Browser reads",
        ] {
            assert!(readme.contains(phrase), "README missing {phrase}");
            assert!(contract.contains(phrase), "contract missing {phrase}");
            assert!(skill.contains(phrase), "skill missing {phrase}");
        }
        for artifact in [readme, contract, skill] {
            assert!(artifact.contains("Phase 3"));
        }
        assert!(roadmap.contains("current_phase: phase-4-in-progress"));
        assert!(roadmap.contains("Blog direct reads = 4/4 complete and discovery-verified"));
        assert!(roadmap.contains("157 routes unresolved"));
        for phrase in [
            "registration-input schema",
            "--allow-write --allow-metered --confirm",
            "tool schema search --server cloudflare",
            "capability schema d1_database_get",
        ] {
            assert!(readme.contains(phrase), "README missing {phrase}");
            assert!(skill.contains(phrase), "skill missing {phrase}");
        }
    }
}
