use clap::{Args, Parser, Subcommand};
use serde_json::json;
use std::path::PathBuf;
#[derive(Parser, Debug, Clone)]
#[command(
    name = "magi-cloudflare-axi",
    about = "Agent-native Cloudflare REST, GraphQL, and hosted MCP CLI",
    disable_help_subcommand = true,
    after_help = "Examples:\n  magi-cloudflare-axi\n  magi-cloudflare-axi account list --fields id,name\n  magi-cloudflare-axi tool list --server cloudflare"
)]
pub struct Cli {
    /// Print version and exit without loading config or credentials.
    #[arg(short = 'v', short_alias = 'V', long = "version", global = true)]
    pub version: bool,
    /// Structured output format.
    #[arg(long, global=true, default_value="toon", value_parser=["toon", "json"])]
    pub format: String,
    /// Disable recursive long-value truncation.
    #[arg(long, global = true)]
    pub full: bool,
    /// Cloudflare account ID; overrides environment and config.
    #[arg(long, global = true)]
    pub account: Option<String>,
    /// Cloudflare zone ID; overrides environment and config.
    #[arg(long, global = true)]
    pub zone: Option<String>,
    /// Cloudflare REST API base URL; HTTPS required except loopback.
    #[arg(long, global = true)]
    pub endpoint: Option<String>,
    /// Override hosted MCP URL for controlled tests or private gateways.
    #[arg(long, global = true, hide = true)]
    pub mcp_endpoint: Option<String>,
    #[command(subcommand)]
    pub command: Option<Command>,
}
#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Inspect or verify Cloudflare credentials.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// List or retrieve Cloudflare accounts.
    Account {
        #[command(subcommand)]
        command: ScopeCommand,
    },
    /// List or retrieve Cloudflare zones.
    Zone {
        #[command(subcommand)]
        command: ScopeCommand,
    },
    /// Call Cloudflare REST API directly.
    #[command(
        after_help = "Examples:\n  magi-cloudflare-axi api GET /accounts\n  magi-cloudflare-axi api GET /zones --paginate --max-pages 3\n  magi-cloudflare-axi api POST /accounts/<id>/example --allow-write --body '{}'"
    )]
    Api(ApiArgs),
    /// List known hosted Cloudflare MCP servers.
    Server {
        #[command(subcommand)]
        command: ServerCommand,
    },
    /// Run a Cloudflare GraphQL query or schema introspection.
    #[command(
        after_help = "Examples:\n  magi-cloudflare-axi graphql --schema\n  magi-cloudflare-axi graphql --query 'query { viewer { userName } }'\n  cat query.graphql | magi-cloudflare-axi graphql --stdin"
    )]
    Graphql {
        /// Inline GraphQL document.
        #[arg(long, conflicts_with_all=["file","schema","stdin"])]
        query: Option<String>,
        /// Read GraphQL document from file.
        #[arg(long, conflicts_with_all=["query","schema","stdin"])]
        file: Option<PathBuf>,
        /// Query minimal GraphQL schema metadata.
        #[arg(long, conflicts_with_all=["query", "file"])]
        schema: bool,
        /// Read GraphQL document from standard input.
        #[arg(long, conflicts_with_all=["query","file","schema"])]
        stdin: bool,
        /// Variables as a JSON object.
        #[arg(long, conflicts_with = "variables_file")]
        variables: Option<String>,
        /// Read variables JSON object from file.
        #[arg(long, conflicts_with = "variables")]
        variables_file: Option<PathBuf>,
        /// Permit GraphQL mutation documents.
        #[arg(long)]
        allow_write: bool,
    },
    /// Inspect pinned Cloudflare MCP tool inventory evidence.
    Capability {
        #[command(subcommand)]
        command: CapabilityCommand,
    },
    /// Discover schemas or call hosted MCP tools.
    Tool {
        #[command(subcommand)]
        command: ToolCommand,
    },
    /// Manage opt-in Claude, Codex, and OpenCode context integrations.
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
    /// Alias for `session setup`.
    Setup(SetupArgs),
}
#[derive(Subcommand, Debug, Clone)]
pub enum ServerCommand {
    /// List hosted server names, URLs, auth, family, and deprecation state.
    #[command(
        after_help = "Examples:\n  magi-cloudflare-axi server list\n  magi-cloudflare-axi server list --format json"
    )]
    List,
}
#[derive(Subcommand, Debug, Clone)]
pub enum ToolCommand {
    /// List compact local inventory, or live tools from one hosted server.
    #[command(
        after_help = "Examples:\n  magi-cloudflare-axi tool list\n  magi-cloudflare-axi tool list --all\n  magi-cloudflare-axi tool list --server cloudflare"
    )]
    List {
        /// Include full local catalog metadata instead of compact fields.
        #[arg(long)]
        all: bool,
        /// Query exact hosted server instead of local inventory.
        #[arg(long)]
        server: Option<String>,
    },
    /// Retrieve one live MCP input schema.
    #[command(
        after_help = "Examples:\n  magi-cloudflare-axi tool schema search_cloudflare_documentation --server docs\n  magi-cloudflare-axi tool schema search --server cloudflare"
    )]
    Schema {
        /// Exact MCP tool name.
        name: String,
        /// Exact server from `server list`.
        #[arg(long)]
        server: Option<String>,
    },
    /// Call one hosted MCP tool with JSON object input.
    #[command(
        after_help = "Examples:\n  magi-cloudflare-axi tool call search_cloudflare_documentation --server docs --input '{\"query\":\"Workers\"}' --allow-metered\n  magi-cloudflare-axi tool call execute --server cloudflare --file input.json --allow-write --allow-metered --confirm execute"
    )]
    Call {
        /// Exact MCP tool name.
        name: String,
        /// Exact server from `server list`.
        #[arg(long)]
        server: Option<String>,
        /// Permit tools classified as mutating or conservatively unknown.
        #[arg(long)]
        allow_write: bool,
        /// Permit tools classified as metered or conservatively unknown.
        #[arg(long)]
        allow_metered: bool,
        /// Exact tool name confirmation for writes.
        #[arg(long)]
        confirm: Option<String>,
        /// Inline JSON object input.
        #[arg(long)]
        input: Option<String>,
        /// Read JSON object input from file.
        #[arg(long)]
        file: Option<PathBuf>,
        /// Read JSON object input from standard input.
        #[arg(long)]
        stdin: bool,
    },
}
#[derive(Subcommand, Debug, Clone)]
pub enum SessionCommand {
    /// Emit compact directory-scoped context for managed hooks.
    #[command(
        after_help = "Examples:\n  magi-cloudflare-axi session context\n  magi-cloudflare-axi session context --format json"
    )]
    Context,
    /// Install or repair selected session integrations.
    Setup(SetupArgs),
    /// Validate managed integration content and executable paths.
    Status(SetupArgs),
    /// Remove only managed integration entries.
    Remove(SetupArgs),
}
#[derive(Subcommand, Debug, Clone)]
pub enum AuthCommand {
    /// Show local credential mode without revealing values.
    #[command(
        after_help = "Examples:\n  magi-cloudflare-axi auth status\n  magi-cloudflare-axi auth status --format json"
    )]
    Status,
    /// Verify credentials with a read-only Cloudflare API call.
    #[command(
        after_help = "Examples:\n  magi-cloudflare-axi auth verify\n  magi-cloudflare-axi auth verify --format json"
    )]
    Verify,
}
#[derive(Subcommand, Debug, Clone)]
pub enum ScopeCommand {
    /// List projected resources with provider totals and explicit empty state.
    #[command(
        after_help = "Examples:\n  magi-cloudflare-axi account list --fields id,name\n  magi-cloudflare-axi zone list --fields id,name,status,account\n  magi-cloudflare-axi zone list --page 2 --per-page 100"
    )]
    List {
        /// Repeated or comma-separated projected output fields.
        #[arg(long, action = clap::ArgAction::Append)]
        fields: Vec<String>,
        /// Maximum rows emitted from requested page.
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=10_000))]
        limit: u32,
        /// Cloudflare page number.
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=10_000))]
        page: u32,
        /// Cloudflare page size.
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=1000))]
        per_page: u32,
    },
    /// Retrieve one resource by ID or resolved global selector.
    #[command(
        after_help = "Examples:\n  magi-cloudflare-axi account get <id>\n  magi-cloudflare-axi --account <id> account get\n  magi-cloudflare-axi zone get <id>"
    )]
    Get {
        /// Resource ID; falls back to global account/zone selector.
        id: Option<String>,
    },
}
#[derive(Subcommand, Debug, Clone)]
pub enum CapabilityCommand {
    /// List compact registered-tool inventory evidence.
    #[command(
        after_help = "Examples:\n  magi-cloudflare-axi capability list\n  magi-cloudflare-axi capability list --family workers-bindings\n  magi-cloudflare-axi capability list --status mcp_remote"
    )]
    List {
        /// Exact source family filter.
        #[arg(long)]
        family: Option<String>,
        /// Exact catalog access-classification filter.
        #[arg(long)]
        status: Option<String>,
    },
    /// Show evidence, limitations, and safest access route for one tool.
    #[command(
        after_help = "Examples:\n  magi-cloudflare-axi capability get d1_database_create\n  magi-cloudflare-axi capability get search_cloudflare_documentation"
    )]
    Get {
        /// Exact registered source tool name.
        name: String,
    },
}
#[derive(Args, Debug, Clone)]
pub struct ApiArgs {
    /// HTTP method: GET, HEAD, POST, PUT, PATCH, or DELETE.
    pub method: String,
    /// Absolute path beneath configured API base, for example `/accounts`.
    pub path: String,
    /// Query pair in KEY=VALUE form; repeat for multiple pairs.
    #[arg(long)]
    pub query: Vec<String>,
    /// Inline JSON request body.
    #[arg(long)]
    pub body: Option<String>,
    /// Read JSON request body from file.
    #[arg(long)]
    pub file: Option<PathBuf>,
    /// Read JSON request body from standard input.
    #[arg(long)]
    pub stdin: bool,
    /// Permit non-GET/HEAD requests.
    #[arg(long)]
    pub allow_write: bool,
    /// Exact DELETE path confirmation.
    #[arg(long)]
    pub confirm_delete: Option<String>,
    /// Merge top-level array result pages.
    #[arg(long)]
    pub paginate: bool,
    /// Maximum pages requested during raw pagination.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..=100))]
    pub max_pages: u32,
    /// Maximum merged items emitted during raw pagination.
    #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u32).range(1..=100_000))]
    pub max_items: u32,
}
#[derive(Args, Debug, Clone, Default)]
pub struct SetupArgs {
    #[arg(long, alias = "path", conflicts_with = "target_dir")]
    pub root: Option<PathBuf>,
    #[arg(long, conflicts_with = "root")]
    pub target_dir: Option<PathBuf>,
    #[arg(long = "target", value_parser = ["claude", "codex", "opencode"], action = clap::ArgAction::Append, conflicts_with_all = ["claude", "codex", "opencode"])]
    pub targets: Vec<String>,
    #[arg(long, conflicts_with = "targets")]
    pub claude: bool,
    #[arg(long, conflicts_with = "targets")]
    pub codex: bool,
    #[arg(long, conflicts_with = "targets")]
    pub opencode: bool,
}
pub fn home(
    config: &crate::config::Config,
    auth: Result<crate::config::Auth, crate::error::AppError>,
) -> Result<serde_json::Value, crate::error::AppError> {
    crate::client::validate_endpoint(&config.endpoint)?;
    let entries = crate::capability::all().unwrap_or_default();
    let blockers = entries.iter().filter(|x| x.blocker.is_some()).count();
    let mode = auth.as_ref().ok().map(crate::config::Auth::label);
    let live = match auth {
        Ok(auth) => {
            match crate::client::CloudflareClient::new(config.clone(), auth).and_then(|api| {
                api.request(crate::client::RequestOptions {
                    method: crate::client::Method::Get,
                    path: "/accounts".into(),
                    query: vec![("page".into(), "1".into()), ("per_page".into(), "3".into())],
                    body: None,
                    allow_write: false,
                    confirm_delete: None,
                    retry_read_post: false,
                })
            }) {
                Ok(response) => {
                    let accounts = response
                        .result
                        .and_then(|v| v.as_array().cloned())
                        .unwrap_or_default();
                    let accounts: Vec<_> = accounts.into_iter().map(|row| json!({
                    "id": row.get("id"), "name": row.get("name"), "type": row.get("type")
                })).collect();
                    let total = response
                        .result_info
                        .as_ref()
                        .and_then(|v| v.get("total_count").or_else(|| v.get("total")))
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(accounts.len() as u64);
                    json!({"status":"available", "accounts":accounts, "total_accounts":total,
                    "message": if total == 0 {Some("0 accounts accessible to configured credential")} else {None::<&str>}})
                }
                Err(error) => json!({"status":"unavailable", "error_type":error.kind(),
                "suggestions":["magi-cloudflare-axi auth verify"]}),
            }
        }
        Err(_) => {
            json!({"status":"not_configured", "suggestions":["set CLOUDFLARE_API_TOKEN, then run `magi-cloudflare-axi auth verify`"]})
        }
    };
    let executable = std::env::current_exe().ok();
    let bin = executable
        .as_deref()
        .map(crate::session::display_path)
        .unwrap_or_else(|| "magi-cloudflare-axi".into());
    let mut commands = vec![
        "magi-cloudflare-axi auth status".to_owned(),
        "magi-cloudflare-axi account list".to_owned(),
        "magi-cloudflare-axi zone list".to_owned(),
        "magi-cloudflare-axi tool list --server cloudflare".to_owned(),
    ];
    if let Some(account) = &config.account {
        commands[2] = format!(
            "magi-cloudflare-axi --account {} zone list",
            shell_word(account)
        );
    }
    Ok(json!({
        "bin": bin,
        "description": "Agent-native Cloudflare REST, GraphQL, and hosted MCP CLI",
        "cwd": std::env::current_dir().ok().map(|p| crate::session::display_path(&p)),
        "config": {
            "project": std::env::current_dir().ok().map(|p| crate::session::display_path(&p.join(".cloudflare-axi.toml"))),
            "global": crate::config::global_config_path().as_deref().map(crate::session::display_path)
        },
        "auth": {"configured": mode.is_some(), "mode": mode},
        "scope": {"account": config.account, "zone": config.zone},
        "live": live,
        "capabilities": {"registered_tool_names": entries.len(), "blocked": blockers,
            "claim": "inventory parity only; use live tool schema before calls"},
        "commands": commands
    }))
}

fn shell_word(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
