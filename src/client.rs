use crate::{
    config::{self, Auth, Config},
    error::AppError,
};
use serde_json::Value;
use std::{fs, io::Read, path::Path, time::Duration};
use url::Url;

pub const MAX_RESPONSE: usize = 8 * 1024 * 1024;
pub const MAX_REQUEST: usize = 1024 * 1024;
const ATTEMPTS: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
}
impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }
    fn read_only(self) -> bool {
        matches!(self, Self::Get | Self::Head)
    }
}
impl TryFrom<&str> for Method {
    type Error = AppError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_ascii_uppercase().as_str() {
            "GET" => Ok(Self::Get),
            "HEAD" => Ok(Self::Head),
            "POST" => Ok(Self::Post),
            "PUT" => Ok(Self::Put),
            "PATCH" => Ok(Self::Patch),
            "DELETE" => Ok(Self::Delete),
            _ => Err(AppError::usage("unsupported HTTP method")),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetryPolicy {
    Never,
    TransientRead,
}
#[derive(Debug, Clone)]
pub struct RequestOptions {
    pub method: Method,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub body: Option<Value>,
    pub allow_write: bool,
    pub confirm_delete: Option<String>,
    pub retry_policy: RetryPolicy,
    pub allow_classified_read_post: bool,
}
#[derive(Debug, Clone)]
pub struct CloudflareResponse {
    pub envelope: Value,
    pub result: Option<Value>,
    pub result_info: Option<Value>,
}
pub struct CloudflareClient {
    base: Url,
    auth: Auth,
    agent: ureq::Agent,
}

pub(crate) fn validate_endpoint(raw: &str) -> Result<Url, AppError> {
    let mut u =
        Url::parse(raw).map_err(|e| AppError::config(format!("invalid API endpoint: {e}")))?;
    let loopback = matches!(u.host(), Some(url::Host::Domain("localhost")))
        || matches!(u.host(), Some(url::Host::Ipv4(v)) if v.is_loopback())
        || matches!(u.host(), Some(url::Host::Ipv6(v)) if v.is_loopback());
    if u.scheme() != "https" && !(u.scheme() == "http" && loopback) {
        return Err(AppError::config(
            "API endpoint must use HTTPS; HTTP only permitted for loopback",
        ));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(AppError::config("API endpoint cannot contain userinfo"));
    }
    if u.query().is_some() || u.fragment().is_some() {
        return Err(AppError::config(
            "API endpoint cannot contain query or fragment",
        ));
    }
    let decoded = decode_path(u.path(), "API endpoint contains invalid encoding")?;
    let decoded = decode_path(&decoded, "API endpoint contains invalid encoding")?;
    if decoded.split('/').any(|s| s == ".." || s == ".") || decoded.contains('\\') {
        return Err(AppError::config("API endpoint path contains traversal"));
    }
    let mut path = u.path().to_owned();
    if !path.ends_with('/') {
        path.push('/');
    }
    u.set_path(&path);
    Ok(u)
}
fn red(s: &str, secrets: &[&str]) -> String {
    secrets.iter().fold(s.to_owned(), |x, k| {
        if k.is_empty() {
            x
        } else {
            x.replace(k, "[redacted]")
        }
    })
}
fn provider_code(envelope: &Value) -> Option<String> {
    envelope
        .get("errors")
        .and_then(Value::as_array)
        .and_then(|errors| errors.first())
        .and_then(|error| error.get("code"))
        .and_then(|code| match code {
            Value::Number(number) => Some(number.to_string()),
            Value::String(text) if text.len() <= 64 => Some(text.clone()),
            _ => None,
        })
}

fn provider_failure(status: u16, envelope: &Value, secrets: &[&str]) -> AppError {
    let code = provider_code(envelope)
        .map(|code| format!(", provider code {}", red(&code, secrets)))
        .unwrap_or_default();
    let message = format!("Cloudflare API request failed (HTTP {status}{code})");
    match status {
        401 | 403 => AppError::auth(message),
        429 => AppError::network("Cloudflare API rate limited (HTTP 429)"),
        _ => AppError::api(message),
    }
}
fn decode_path(raw: &str, error: &str) -> Result<String, AppError> {
    let mut out = Vec::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let hex = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    };
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(AppError::usage(error));
            }
            let hi = hex(bytes[i + 1]).ok_or_else(|| AppError::usage(error))?;
            let lo = hex(bytes[i + 2]).ok_or_else(|| AppError::usage(error))?;
            out.push(hi * 16 + lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| AppError::usage(error))
}
fn target(base: &Url, raw: &str) -> Result<Url, AppError> {
    if !raw.starts_with('/') || raw.starts_with("//") {
        return Err(AppError::usage(
            "API path must be absolute beneath configured base and cannot contain traversal",
        ));
    }
    let decoded = decode_path(raw, "invalid API path encoding")
        .and_then(|decoded| decode_path(&decoded, "invalid API path encoding"))
        .map_err(|_| AppError::usage("invalid API path encoding"))?;
    if decoded.starts_with("//")
        || decoded.contains('\\')
        || decoded.split('/').any(|s| s == ".." || s == ".")
    {
        return Err(AppError::usage("API path cannot contain traversal"));
    }
    let target = format!("{}{}", base.as_str(), raw.trim_start_matches('/'));
    Url::parse(&target).map_err(|_| AppError::usage("invalid API path encoding"))
}
fn limited_text(mut reader: impl Read, label: &str) -> Result<String, AppError> {
    let mut text = String::new();
    reader
        .by_ref()
        .take((MAX_REQUEST + 1) as u64)
        .read_to_string(&mut text)
        .map_err(|e| AppError::usage(format!("cannot read {label}: {e}")))?;
    if text.len() > MAX_REQUEST {
        return Err(AppError::usage(format!("{label} exceeds 1 MiB")));
    }
    Ok(text)
}

pub fn read_text_file(path: &Path, label: &str) -> Result<String, AppError> {
    let file = fs::File::open(path)
        .map_err(|e| AppError::usage(format!("cannot read {}: {e}", path.display())))?;
    limited_text(file, label)
}

pub fn read_text_stdin(label: &str) -> Result<String, AppError> {
    limited_text(std::io::stdin(), label)
}

fn body(file: Option<&Path>, stdin: bool, raw: Option<&str>) -> Result<Option<Value>, AppError> {
    if [file.is_some(), stdin, raw.is_some()]
        .iter()
        .filter(|x| **x)
        .count()
        > 1
    {
        return Err(AppError::usage(
            "body sources are mutually exclusive; choose one of --body, --file, --stdin",
        ));
    }
    let text = if let Some(path) = file {
        read_text_file(path, "request body")?
    } else if stdin {
        read_text_stdin("request body")?
    } else if let Some(raw) = raw {
        if raw.len() > MAX_REQUEST {
            return Err(AppError::usage("request body exceeds 1 MiB"));
        }
        raw.to_owned()
    } else {
        return Ok(None);
    };
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|e| AppError::usage(format!("invalid JSON body: {e}")))
}
pub fn preflight_raw(
    method: &str,
    path: &str,
    endpoint: Option<&str>,
    allow_write: bool,
    confirm_delete: Option<&str>,
    sources: (Option<&Path>, bool, Option<&str>),
) -> Result<(), AppError> {
    let (file, stdin, raw) = sources;
    let method = Method::try_from(method)?;
    if [file.is_some(), stdin, raw.is_some()]
        .into_iter()
        .filter(|present| *present)
        .count()
        > 1
    {
        return Err(AppError::usage(
            "body sources are mutually exclusive; choose one of --body, --file, --stdin",
        ));
    }
    if !method.read_only() && !allow_write {
        return Err(AppError::usage("write API calls require --allow-write"));
    }
    if method == Method::Delete && confirm_delete != Some(path) {
        return Err(AppError::usage(
            "DELETE requires --confirm-delete PATH exactly",
        ));
    }
    if let Some(raw) = raw {
        if raw.len() > MAX_REQUEST {
            return Err(AppError::usage("request body exceeds 1 MiB"));
        }
    }
    if let Some(file) = file {
        if file
            .metadata()
            .map(|meta| meta.len() > MAX_REQUEST as u64)
            .unwrap_or(false)
        {
            return Err(AppError::usage("request body exceeds 1 MiB"));
        }
    }
    if let Some(endpoint) = endpoint {
        let base = validate_endpoint(endpoint)?;
        target(&base, path)?;
    }
    Ok(())
}

pub fn read_body(
    file: Option<&Path>,
    stdin: bool,
    raw: Option<&str>,
) -> Result<Option<Value>, AppError> {
    body(file, stdin, raw)
}

impl CloudflareClient {
    pub fn new(config: Config, auth: Auth) -> Result<Self, AppError> {
        let base = validate_endpoint(&config.endpoint)?;
        Ok(Self {
            base,
            auth,
            agent: ureq::Agent::config_builder()
                .http_status_as_error(false)
                .max_redirects(0)
                .timeout_global(Some(Duration::from_secs(30)))
                .build()
                .into(),
        })
    }

    pub fn request(&self, options: RequestOptions) -> Result<CloudflareResponse, AppError> {
        if options.method != Method::Get
            && options.method != Method::Head
            && !(options.method == Method::Post && options.allow_classified_read_post)
            && !options.allow_write
        {
            return Err(AppError::usage("write API calls require --allow-write"));
        }
        if options.method == Method::Delete
            && options.confirm_delete.as_deref() != Some(options.path.as_str())
        {
            return Err(AppError::usage(
                "DELETE requires --confirm-delete PATH exactly",
            ));
        }
        let mut url = target(&self.base, &options.path)?;
        for (key, value) in &options.query {
            url.query_pairs_mut().append_pair(key, value);
        }
        let body = options
            .body
            .as_ref()
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|_| AppError::usage("request body cannot be serialized"))?;
        if body.as_ref().is_some_and(|bytes| bytes.len() > MAX_REQUEST) {
            return Err(AppError::usage("request body exceeds 1 MiB"));
        }
        let secrets = match &self.auth {
            Auth::None => Vec::new(),
            Auth::Bearer(token) | Auth::KeyBearer(token) => vec![token.as_str()],
            Auth::KeyEmail { key, email } => vec![key.as_str(), email.as_str()],
        };
        let attempts = if options.retry_policy == RetryPolicy::TransientRead {
            ATTEMPTS
        } else {
            1
        };
        let mut last = None;
        for attempt in 0..attempts {
            let mut builder = ureq::http::Request::builder()
                .method(options.method.as_str())
                .uri(url.as_str());
            builder = match &self.auth {
                Auth::None => builder,
                Auth::Bearer(token) | Auth::KeyBearer(token) => {
                    builder.header("Authorization", format!("Bearer {token}"))
                }
                Auth::KeyEmail { key, email } => builder
                    .header("X-Auth-Key", key)
                    .header("X-Auth-Email", email),
            };
            if body.is_some() {
                builder = builder.header("Content-Type", "application/json");
            }
            let request = builder
                .body(body.clone().unwrap_or_default())
                .map_err(|error| AppError::network(error.to_string()))?;
            match self.agent.run(request) {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let retryable_status = status == 429 || (500..=599).contains(&status);
                    let mut bytes = Vec::new();
                    let read_result = response
                        .into_body()
                        .into_reader()
                        .take((MAX_RESPONSE + 1) as u64)
                        .read_to_end(&mut bytes);
                    if let Err(error) = read_result {
                        last = Some(AppError::network(red(&error.to_string(), &secrets)));
                        if attempt + 1 < attempts {
                            continue;
                        }
                        break;
                    }
                    if bytes.len() > MAX_RESPONSE {
                        return Err(AppError::network("response exceeds 8 MiB"));
                    }
                    let envelope = if bytes.is_empty() {
                        Value::Null
                    } else {
                        serde_json::from_slice(&bytes).unwrap_or_else(|_| {
                            Value::String(String::from_utf8_lossy(&bytes).into_owned())
                        })
                    };
                    let response = CloudflareResponse {
                        result: envelope.get("result").cloned(),
                        result_info: envelope.get("result_info").cloned(),
                        envelope,
                    };
                    if (200..300).contains(&status) {
                        if response
                            .envelope
                            .get("errors")
                            .and_then(Value::as_array)
                            .is_some_and(|errors| !errors.is_empty())
                        {
                            return Err(AppError::api(
                                "GraphQL query returned 1 provider error(s)",
                            ));
                        }
                        return Ok(response);
                    }
                    last = Some(provider_failure(status, &response.envelope, &secrets));
                    if !retryable_status {
                        break;
                    }
                }
                Err(error) => last = Some(AppError::network(red(&error.to_string(), &secrets))),
            }
            if attempt + 1 < attempts {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        Err(last.unwrap_or_else(|| AppError::network("request failed")))
    }
}

pub fn request_response(
    method: &str,
    path: &str,
    payload: Option<Value>,
    endpoint: Option<String>,
    allow_write: bool,
    guard: (Option<&str>, bool),
    query: &[String],
) -> Result<CloudflareResponse, AppError> {
    let method = Method::try_from(method)?;
    let query = query
        .iter()
        .map(|x| {
            x.split_once('=')
                .filter(|(key, _)| !key.is_empty())
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .ok_or_else(|| AppError::usage("--query requires non-empty KEY=VALUE"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !method.read_only() && !allow_write {
        return Err(AppError::usage("write API calls require --allow-write"));
    }
    if method == Method::Delete && guard.0 != Some(path) {
        return Err(AppError::usage(
            "DELETE requires --confirm-delete PATH exactly",
        ));
    }
    if payload
        .as_ref()
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|_| AppError::usage("request body cannot be serialized"))?
        .is_some_and(|body| body.len() > MAX_REQUEST)
    {
        return Err(AppError::usage("request body exceeds 1 MiB"));
    }
    let config = config::load(endpoint, None, None)?;
    let base = validate_endpoint(&config.endpoint)?;
    target(&base, path)?;
    let auth = config::auth_for(&config)?;
    let client = CloudflareClient::new(config, auth)?;
    client.request(RequestOptions {
        method,
        path: path.to_owned(),
        query,
        body: payload,
        allow_write,
        confirm_delete: guard.0.map(str::to_owned),
        retry_policy: if guard.1 && (method.read_only() || method == Method::Post) {
            RetryPolicy::TransientRead
        } else {
            RetryPolicy::Never
        },
        allow_classified_read_post: false,
    })
}

pub fn request(
    method: &str,
    path: &str,
    payload: Option<Value>,
    endpoint: Option<String>,
    allow_write: bool,
    guard: (Option<&str>, bool),
    query: &[String],
) -> Result<Value, AppError> {
    let response = request_response(method, path, payload, endpoint, allow_write, guard, query)?;
    Ok(response.result.unwrap_or(response.envelope))
}
