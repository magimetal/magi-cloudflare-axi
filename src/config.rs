use crate::error::AppError;
use serde::Deserialize;
use std::{
    env, fs,
    path::{Path, PathBuf},
};

const DEFAULT_BASE: &str = "https://api.cloudflare.com/client/v4/";
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    api_base: Option<String>,
    endpoint: Option<String>,
    account_id: Option<String>,
    zone_id: Option<String>,
}
#[derive(Debug, Clone)]
pub struct Config {
    pub endpoint: String,
    pub account: Option<String>,
    pub zone: Option<String>,
}
#[derive(Debug, Clone)]
pub enum Auth {
    Bearer(String),
    KeyEmail { key: String, email: String },
    KeyBearer(String),
}
impl Auth {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Bearer(_) => "bearer",
            Self::KeyEmail { .. } => "global_key_headers",
            Self::KeyBearer(_) => "compatibility_bearer",
        }
    }
}
fn nonempty(v: Option<String>) -> Option<String> {
    v.filter(|x| !x.trim().is_empty())
}
fn load_file(path: &Path) -> Result<FileConfig, AppError> {
    let text = match fs::read_to_string(path) {
        Ok(x) => x,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(FileConfig::default()),
        Err(e) => {
            return Err(AppError::config(format!(
                "cannot read config {}: {e}",
                path.display()
            )));
        }
    };
    let value: toml::Value = toml::from_str(&text).map_err(|e| {
        let location = e
            .span()
            .map(|span| format!(" near byte {}", span.start))
            .unwrap_or_default();
        AppError::config(format!("cannot parse config {}{location}", path.display()))
    })?;
    if let Some(table) = value.as_table() {
        for key in table.keys() {
            if ["api_token", "api_key", "api_email"].contains(&key.as_str()) {
                return Err(AppError::config(format!(
                    "secret config key '{key}' forbidden in {}",
                    path.display()
                )));
            }
            if !["api_base", "endpoint", "account_id", "zone_id"].contains(&key.as_str()) {
                return Err(AppError::config(format!(
                    "unsupported config key '{key}' in {}",
                    path.display()
                )));
            }
        }
    }
    value.try_into().map_err(|_| {
        AppError::config(format!(
            "config {} contains unsupported keys or value types",
            path.display()
        ))
    })
}
fn global_path(root: Option<&Path>) -> Option<PathBuf> {
    if let Some(root) = root {
        return Some(root.join("cloudflare").join("cloudflare-axi.toml"));
    }
    if cfg!(windows) {
        env::var_os("APPDATA")
            .map(PathBuf::from)
            .map(|p| p.join("cloudflare").join("config.toml"))
    } else {
        env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|p| PathBuf::from(p).join(".config")))
            .map(|p| p.join("cloudflare").join("cloudflare-axi.toml"))
    }
}

pub fn global_config_path() -> Option<PathBuf> {
    global_path(None)
}
pub fn load(
    cli_endpoint: Option<String>,
    cli_account: Option<String>,
    cli_zone: Option<String>,
) -> Result<Config, AppError> {
    load_with_paths(cli_endpoint, cli_account, cli_zone, Path::new("."), None)
}
pub fn load_with_paths(
    cli_endpoint: Option<String>,
    cli_account: Option<String>,
    cli_zone: Option<String>,
    cwd: &Path,
    config_root: Option<&Path>,
) -> Result<Config, AppError> {
    let project = load_file(&cwd.join(".cloudflare-axi.toml"))?;
    if project.api_base.is_some() || project.endpoint.is_some() {
        return Err(AppError::config(
            "project .cloudflare-axi.toml cannot set api_base or endpoint; use --endpoint, environment, or global config",
        ));
    }
    let global = global_path(config_root)
        .map(|p| load_file(&p))
        .transpose()?
        .unwrap_or_default();
    let endpoint = nonempty(cli_endpoint)
        .or_else(|| nonempty(env::var("CLOUDFLARE_API_BASE").ok()))
        .or_else(|| nonempty(env::var("CLOUDFLARE_ENDPOINT").ok()))
        .or_else(|| nonempty(global.api_base.clone().or(global.endpoint.clone())))
        .unwrap_or_else(|| DEFAULT_BASE.into());
    Ok(Config {
        endpoint,
        account: nonempty(cli_account)
            .or_else(|| nonempty(env::var("CLOUDFLARE_ACCOUNT_ID").ok()))
            .or_else(|| nonempty(env::var("CLOUDFLARE_ACOUNT_ID").ok()))
            .or_else(|| nonempty(project.account_id.clone()))
            .or_else(|| nonempty(global.account_id.clone())),
        zone: nonempty(cli_zone)
            .or_else(|| nonempty(env::var("CLOUDFLARE_ZONE_ID").ok()))
            .or_else(|| nonempty(project.zone_id.clone()))
            .or_else(|| nonempty(global.zone_id.clone())),
    })
}
pub fn load_resolved(
    cli_endpoint: Option<String>,
    cli_account: Option<String>,
    cli_zone: Option<String>,
) -> Result<(Config, Auth), AppError> {
    let cfg = load(cli_endpoint, cli_account, cli_zone)?;
    let auth = auth_for(&cfg)?;
    Ok((cfg, auth))
}
pub fn auth() -> Result<Auth, AppError> {
    load_resolved(None, None, None).map(|(_, auth)| auth)
}
pub fn auth_for(_: &Config) -> Result<Auth, AppError> {
    if let Some(token) = nonempty(env::var("CLOUDFLARE_API_TOKEN").ok()) {
        return Ok(Auth::Bearer(token));
    }
    if let Some(key) = nonempty(env::var("CLOUDFLARE_API_KEY").ok()) {
        return Ok(match nonempty(env::var("CLOUDFLARE_API_EMAIL").ok()) {
            Some(email) => Auth::KeyEmail { key, email },
            None => Auth::KeyBearer(key),
        });
    }
    Err(AppError::auth(
        "set CLOUDFLARE_API_TOKEN, or CLOUDFLARE_API_KEY with CLOUDFLARE_API_EMAIL",
    ))
}
