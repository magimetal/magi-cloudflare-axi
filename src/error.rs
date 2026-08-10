use serde_json::Value;
use std::fmt;
#[derive(Debug)]
pub enum AppError {
    Usage(String),
    Auth(String),
    Config(String),
    Network(String),
    Api(String),
    Output(String),
}
impl AppError {
    pub fn usage(s: impl Into<String>) -> Self {
        Self::Usage(s.into())
    }
    pub fn auth(s: impl Into<String>) -> Self {
        Self::Auth(s.into())
    }
    pub fn config(s: impl Into<String>) -> Self {
        Self::Config(s.into())
    }
    pub fn network(s: impl Into<String>) -> Self {
        Self::Network(s.into())
    }
    pub fn api(s: impl Into<String>) -> Self {
        Self::Api(s.into())
    }
    pub fn code(&self) -> u8 {
        if matches!(self, Self::Usage(_)) { 2 } else { 1 }
    }
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Usage(_) => "usage",
            Self::Auth(_) => "auth",
            Self::Config(_) => "config",
            Self::Network(_) => "network",
            Self::Api(_) => "api",
            Self::Output(_) => "output",
        }
    }

    fn help(&self) -> &'static str {
        match self {
            Self::Usage(message) if message.contains("unknown capability") => {
                "run `magi-cloudflare-axi capability list` and retry with an exact name"
            }
            Self::Usage(message) if message.contains("unknown tool") => {
                "run `magi-cloudflare-axi tool list` or `tool list --server <server>`"
            }
            Self::Usage(_) => {
                "run `magi-cloudflare-axi --help` or the failing command with `--help`"
            }
            Self::Auth(_) => "set CLOUDFLARE_API_TOKEN, then run `magi-cloudflare-axi auth verify`",
            Self::Config(_) => {
                "fix the reported config or endpoint, then run `magi-cloudflare-axi auth status`"
            }
            Self::Network(_) => {
                "check HTTPS endpoint and connectivity, then retry the same command"
            }
            Self::Api(_) => "run `magi-cloudflare-axi auth verify`; then retry with explicit IDs",
            Self::Output(_) => {
                "retry with `--format json`; report the output failure if it persists"
            }
        }
    }
}
impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(x)
            | Self::Auth(x)
            | Self::Config(x)
            | Self::Network(x)
            | Self::Api(x)
            | Self::Output(x) => f.write_str(x),
        }
    }
}
pub fn render(v: &Value, format: &str) -> Result<(), AppError> {
    let s = if format == "json" {
        serde_json::to_string(v).map_err(|e| AppError::Output(e.to_string()))?
    } else {
        toon_format::encode(v, &toon_format::EncodeOptions::default())
            .map_err(|e| AppError::Output(e.to_string()))?
    };
    println!("{s}");
    Ok(())
}
pub fn output_error(e: &AppError, format: &str) {
    let document = serde_json::json!({
        "error": {
            "type": e.kind(),
            "code": e.code(),
            "message": truncate_message(&e.to_string()),
            "help": e.help()
        }
    });
    if render(&document, format).is_err() {
        eprintln!("output serialization failed; retry with --format json");
    }
}
fn truncate_message(s: &str) -> String {
    s.chars().take(2000).collect()
}
pub fn truncate(v: &mut Value, full: bool, seen: &mut bool) {
    if full {
        return;
    }
    match v {
        Value::String(s) if s.chars().count() > 1000 => {
            let n = s.chars().count();
            *s = format!(
                "{}… [truncated, {n} chars; use --full]",
                s.chars().take(1000).collect::<String>()
            );
            *seen = true
        }
        Value::Array(a) => a.iter_mut().for_each(|x| truncate(x, full, seen)),
        Value::Object(o) => o.values_mut().for_each(|x| truncate(x, full, seen)),
        _ => {}
    }
}
