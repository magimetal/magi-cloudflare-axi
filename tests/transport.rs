use std::{
    io::{Read, Write},
    net::TcpListener,
    process::{Command, Output, Stdio},
    sync::{Arc, Mutex},
    thread,
};

use serde_json::Value;
use tempfile::TempDir;

#[derive(Clone, Debug)]
struct Request {
    method: String,
    target: String,
    headers: String,
    body: String,
}

struct Server {
    endpoint: String,
    requests: Arc<Mutex<Vec<Request>>>,
    join: Option<thread::JoinHandle<()>>,
}

impl Server {
    fn start(responses: Vec<(u16, &'static str)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/client/v4", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        let join = thread::spawn(move || {
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut bytes = Vec::new();
                let mut chunk = [0; 4096];
                let header_end = loop {
                    let n = stream.read(&mut chunk).unwrap();
                    assert!(n > 0, "client closed before request headers");
                    bytes.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&bytes[..header_end]).to_string();
                let first = headers
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .collect::<Vec<_>>();
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("Content-Length:")
                            .or_else(|| line.strip_prefix("content-length:"))
                    })
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                while bytes.len() < header_end + content_length {
                    let n = stream.read(&mut chunk).unwrap();
                    assert!(n > 0, "client closed before request body");
                    bytes.extend_from_slice(&chunk[..n]);
                }
                seen.lock().unwrap().push(Request {
                    method: first[0].to_owned(),
                    target: first[1].to_owned(),
                    headers,
                    body: String::from_utf8_lossy(&bytes[header_end..header_end + content_length])
                        .to_string(),
                });
                let reason = if status == 200 { "OK" } else { "Test" };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        Self {
            endpoint,
            requests,
            join: Some(join),
        }
    }

    fn finish(mut self) -> Vec<Request> {
        self.join.take().unwrap().join().unwrap();
        Arc::try_unwrap(self.requests)
            .unwrap()
            .into_inner()
            .unwrap()
    }
}

struct RedirectServer {
    endpoint: String,
    requests: Arc<Mutex<Vec<String>>>,
    join: Option<thread::JoinHandle<()>>,
}

impl RedirectServer {
    fn start() -> Self {
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let second = TcpListener::bind("127.0.0.1:0").unwrap();
        second.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}/client/v4", first.local_addr().unwrap());
        let location = format!("http://{}/client/v4/leak", second.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        let join = thread::spawn(move || {
            let (mut stream, _) = first.accept().unwrap();
            let mut bytes = Vec::new();
            let mut chunk = [0; 4096];
            loop {
                let n = stream.read(&mut chunk).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&chunk[..n]);
                if bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            seen.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&bytes).into_owned());
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).unwrap();
            thread::sleep(std::time::Duration::from_millis(250));
            if let Ok((mut stream, _)) = second.accept() {
                let mut bytes = Vec::new();
                loop {
                    let n = stream.read(&mut chunk).unwrap();
                    if n == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&chunk[..n]);
                    if bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                seen.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&bytes).into_owned());
            }
        });
        Self {
            endpoint,
            requests,
            join: Some(join),
        }
    }

    fn finish(mut self) -> Vec<String> {
        self.join.take().unwrap().join().unwrap();
        Arc::try_unwrap(self.requests)
            .unwrap()
            .into_inner()
            .unwrap()
    }
}

#[test]
fn rest_redirect_does_not_forward_credentials() {
    let server = RedirectServer::start();
    let (output, _) = run(
        &["--format", "json", "api", "GET", "/accounts"],
        Some(&server.endpoint),
        Some("fake-token"),
    );
    assert!(!output.status.success());
    let requests = server.finish();
    assert_eq!(
        requests.len(),
        1,
        "redirect target received request: {requests:?}"
    );
    assert!(requests[0].contains("fake-token"));
}

#[test]
fn key_email_redirect_does_not_forward_global_credentials() {
    let server = RedirectServer::start();
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"))
        .args([
            "--format",
            "json",
            "--endpoint",
            &server.endpoint,
            "api",
            "GET",
            "/zones",
        ])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .env("CLOUDFLARE_API_KEY", "fake-global-key")
        .env("CLOUDFLARE_API_EMAIL", "fake@example.invalid")
        .env_remove("CLOUDFLARE_API_TOKEN")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].contains("fake-global-key"));
    assert!(requests[0].contains("fake@example.invalid"));
}

#[test]
fn graphql_variables_are_validated_before_network() {
    let dir = tempfile::tempdir().unwrap();
    let variables = dir.path().join("variables.json");
    std::fs::write(&variables, "{}").unwrap();
    for extra in [
        vec![
            "--variables",
            "{}",
            "--variables-file",
            variables.to_str().unwrap(),
        ],
        vec!["--variables", "[]"],
    ] {
        let mut args = vec!["--format", "json", "graphql", "--query", "query { viewer }"];
        args.extend(extra);
        let (output, _) = run(&args, Some("http://127.0.0.1:1"), None);
        assert_eq!(output.status.code(), Some(2));
    }
}

fn run(args: &[&str], endpoint: Option<&str>, token: Option<&str>) -> (Output, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let xdg = dir.path().join("xdg");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&xdg).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"));
    cmd.args(args)
        .current_dir(dir.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg);
    for key in [
        "CLOUDFLARE_API_BASE",
        "CLOUDFLARE_ENDPOINT",
        "CLOUDFLARE_API_TOKEN",
        "CLOUDFLARE_API_KEY",
        "CLOUDFLARE_API_EMAIL",
        "CLOUDFLARE_ACCOUNT_ID",
        "CLOUDFLARE_ACOUNT_ID",
        "CLOUDFLARE_ZONE_ID",
    ] {
        cmd.env_remove(key);
    }
    if let Some(endpoint) = endpoint {
        cmd.args(["--endpoint", endpoint]);
    }
    if let Some(token) = token {
        cmd.env("CLOUDFLARE_API_TOKEN", token);
    }
    (cmd.output().unwrap(), dir)
}

fn json_stdout(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn default_client_v4_path_and_bearer() {
    let server = Server::start(vec![(200, r#"{"result":{"ok":true}}"#)]);
    let (out, _) = run(
        &["--format", "json", "api", "GET", "/accounts"],
        Some(&server.endpoint),
        Some("tok"),
    );
    assert!(
        out.status.success(),
        "stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let requests = server.finish();
    assert_eq!(requests[0].target, "/client/v4/accounts");
    assert!(
        requests[0]
            .headers
            .to_ascii_lowercase()
            .contains("authorization: bearer tok")
    );
}

#[test]
fn key_email_auth_has_no_bearer() {
    let server = Server::start(vec![(200, r#"{"result":[]}"#)]);
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"));
    cmd.args([
        "--format",
        "json",
        "--endpoint",
        &server.endpoint,
        "api",
        "GET",
        "/zones",
    ])
    .current_dir(dir.path())
    .env("HOME", dir.path())
    .env("XDG_CONFIG_HOME", dir.path())
    .env_remove("CLOUDFLARE_API_BASE")
    .env_remove("CLOUDFLARE_ENDPOINT")
    .env_remove("CLOUDFLARE_API_TOKEN")
    .env("CLOUDFLARE_API_KEY", "key")
    .env("CLOUDFLARE_API_EMAIL", "me@example.com");
    assert!(cmd.output().unwrap().status.success());
    let requests = server.finish();
    assert!(
        requests[0]
            .headers
            .to_ascii_lowercase()
            .contains("x-auth-key: key")
    );
    assert!(
        requests[0]
            .headers
            .to_ascii_lowercase()
            .contains("x-auth-email: me@example.com")
    );
    assert!(!requests[0].headers.contains("Authorization:"));
}

#[test]
fn compatibility_key_without_email_uses_bearer() {
    let server = Server::start(vec![(200, r#"{"result":1}"#)]);
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"));
    cmd.args([
        "--format",
        "json",
        "--endpoint",
        &server.endpoint,
        "api",
        "GET",
        "/zones",
    ])
    .current_dir(dir.path())
    .env("HOME", dir.path())
    .env("XDG_CONFIG_HOME", dir.path())
    .env_remove("CLOUDFLARE_API_BASE")
    .env_remove("CLOUDFLARE_ENDPOINT")
    .env_remove("CLOUDFLARE_API_TOKEN")
    .env_remove("CLOUDFLARE_API_EMAIL")
    .env("CLOUDFLARE_API_KEY", "legacy");
    assert!(cmd.output().unwrap().status.success());
    assert!(
        server.finish()[0]
            .headers
            .to_ascii_lowercase()
            .contains("authorization: bearer legacy")
    );
}

#[test]
fn query_values_are_percent_encoded() {
    let server = Server::start(vec![(200, r#"{"result":true}"#)]);
    let (out, _) = run(
        &["--format", "json", "api", "GET", "/x", "--query", "a=b c&d"],
        Some(&server.endpoint),
        Some("t"),
    );
    assert!(out.status.success());
    assert_eq!(server.finish()[0].target, "/client/v4/x?a=b+c%26d");
}

#[test]
fn remote_http_rejected_before_auth() {
    let (out, _) = run(
        &["--format", "json", "api", "GET", "/x"],
        Some("http://example.com"),
        None,
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains("HTTPS"));
    assert!(out.stderr.is_empty());
}

#[test]
fn loopback_http_allowed() {
    let server = Server::start(vec![(200, r#"{"result":"ok"}"#)]);
    let (out, _) = run(
        &["--format", "json", "api", "GET", "/x"],
        Some(&server.endpoint),
        Some("t"),
    );
    assert!(out.status.success());
    assert_eq!(json_stdout(&out), "ok");
    server.finish();
}

#[test]
fn traversal_and_percent_traversal_rejected() {
    for path in ["/../x", "/%2e%2e/x", "/%252e%252e/x"] {
        let (out, _) = run(
            &["--format", "json", "api", "GET", path],
            Some("http://127.0.0.1:9"),
            Some("t"),
        );
        assert_eq!(out.status.code(), Some(2), "{path}");
    }
}

#[test]
fn body_sources_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("body.json");
    std::fs::write(&file, "{}").unwrap();
    let (out, _) = run(
        &[
            "api",
            "POST",
            "/x",
            "--body",
            "{}",
            "--file",
            file.to_str().unwrap(),
        ],
        Some("http://127.0.0.1:9"),
        Some("t"),
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn post_guard_rejects_without_allow_write() {
    let (out, _) = run(
        &["api", "POST", "/x", "--body", "{}"],
        Some("http://127.0.0.1:9"),
        Some("t"),
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn delete_requires_exact_confirmation() {
    let (out, _) = run(
        &[
            "api",
            "DELETE",
            "/x",
            "--allow-write",
            "--confirm-delete",
            "/wrong",
        ],
        Some("http://127.0.0.1:9"),
        Some("t"),
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn get_500_retries_exactly_three_times() {
    let server = Server::start(vec![(500, "{}"), (500, "{}"), (500, "{}")]);
    let (out, _) = run(
        &["--format", "json", "api", "GET", "/x"],
        Some(&server.endpoint),
        Some("t"),
    );
    assert!(!out.status.success());
    assert_eq!(server.finish().len(), 3);
}

#[test]
fn mutation_is_sent_once() {
    let server = Server::start(vec![(200, r#"{"result":true}"#)]);
    let (out, _) = run(
        &[
            "--format",
            "json",
            "api",
            "POST",
            "/x",
            "--allow-write",
            "--body",
            "{}",
        ],
        Some(&server.endpoint),
        Some("t"),
    );
    assert!(out.status.success());
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "POST");
}

#[test]
fn empty_204_is_null() {
    let server = Server::start(vec![(204, "")]);
    let (out, _) = run(
        &["--format", "json", "api", "GET", "/x"],
        Some(&server.endpoint),
        Some("t"),
    );
    assert!(out.status.success());
    assert!(json_stdout(&out).is_null());
    server.finish();
}

#[test]
fn head_response_is_supported() {
    let server = Server::start(vec![(200, "")]);
    let (out, _) = run(
        &["--format", "json", "api", "HEAD", "/x"],
        Some(&server.endpoint),
        Some("t"),
    );
    assert!(out.status.success());
    server.finish();
}

#[test]
fn text_response_is_string() {
    let server = Server::start(vec![(200, "plain text")]);
    let (out, _) = run(
        &["--format", "json", "api", "GET", "/x"],
        Some(&server.endpoint),
        Some("t"),
    );
    assert!(out.status.success());
    assert_eq!(json_stdout(&out), "plain text");
    server.finish();
}

#[test]
fn graphql_read_posts_query_and_variables() {
    let server = Server::start(vec![(200, r#"{"result":{"ok":1}}"#)]);
    let (out, _) = run(
        &[
            "--format",
            "json",
            "graphql",
            "--query",
            "query Q { viewer }",
            "--variables",
            r#"{"id":7}"#,
        ],
        Some(&server.endpoint),
        Some("t"),
    );
    assert!(
        out.status.success(),
        "stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let requests = server.finish();
    assert_eq!(requests[0].method, "POST");
    let body: Value = serde_json::from_str(&requests[0].body).unwrap();
    assert_eq!(body["variables"]["id"], 7);
}

#[test]
fn graphql_errors_fail_even_on_http_success() {
    let server = Server::start(vec![(200, r#"{"errors":[{"message":"bad"}]}"#)]);
    let (out, _) = run(
        &["--format", "json", "graphql", "--query", "query { x }"],
        Some(&server.endpoint),
        Some("secret"),
    );
    assert!(!out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("GraphQL query returned 1 provider error"));
    assert!(!stdout.contains("bad"));
    assert!(out.stderr.is_empty());
    server.finish();
}

#[test]
fn secrets_are_redacted_from_errors() {
    let server = Server::start(vec![
        (500, r#"{"errors":[{"message":"secret-token"}]}"#),
        (500, "{}"),
        (500, "{}"),
    ]);
    let (out, _) = run(
        &["--format", "json", "api", "GET", "/x"],
        Some(&server.endpoint),
        Some("secret-token"),
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!text.contains("secret-token"));
    server.finish();
}

#[test]
fn errors_have_json_and_nonzero_exit() {
    let (out, _) = run(
        &["--format", "json", "api", "BOGUS", "/x"],
        Some("http://127.0.0.1:9"),
        Some("t"),
    );
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(json_stdout(&out)["error"]["type"], "usage");
}

#[test]
fn response_bound_is_enforced() {
    let body = "x".repeat(8 * 1024 * 1024 + 1);
    let leaked: &'static str = Box::leak(body.into_boxed_str());
    let server = Server::start(vec![(200, leaked)]);
    let (out, _) = run(
        &["--format", "json", "api", "GET", "/x"],
        Some(&server.endpoint),
        Some("t"),
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("8 MiB"));
    server.finish();
}

#[test]
fn delete_with_confirmation_reaches_server() {
    let server = Server::start(vec![(204, "")]);
    let (out, _) = run(
        &[
            "--format",
            "json",
            "api",
            "DELETE",
            "/x",
            "--allow-write",
            "--confirm-delete",
            "/x",
        ],
        Some(&server.endpoint),
        Some("t"),
    );
    assert!(out.status.success());
    assert_eq!(server.finish()[0].method, "DELETE");
}

#[test]
fn account_list_projects_fields_and_preserves_provider_totals() {
    let server = Server::start(vec![(
        200,
        r#"{"result":[{"id":"a1","name":"Main","type":"standard","settings":{"x":1},"ignored":true}],"result_info":{"total_count":25,"total_pages":3}}"#,
    )]);
    let (output, _) = run(
        &[
            "--format",
            "json",
            "account",
            "list",
            "--fields",
            "id,name,settings",
        ],
        Some(&server.endpoint),
        Some("token"),
    );
    assert!(output.status.success());
    let value = json_stdout(&output);
    assert_eq!(value["page"]["total"], 25);
    assert_eq!(value["page"]["total_pages"], 3);
    assert_eq!(value["data"]["accounts"][0]["id"], "a1");
    assert!(value["data"]["accounts"][0].get("type").is_none());
    assert!(
        value["suggestions"][0]
            .as_str()
            .unwrap()
            .contains("account list --page 2")
    );
    server.finish();
}

#[test]
fn zone_list_empty_state_and_account_scope_are_explicit() {
    let server = Server::start(vec![(
        200,
        r#"{"result":[],"result_info":{"total_count":1,"total_pages":3}}"#,
    )]);
    let (output, _) = run(
        &[
            "--format",
            "json",
            "--account",
            "acct",
            "zone",
            "list",
            "--page",
            "2",
        ],
        Some(&server.endpoint),
        Some("token"),
    );
    assert!(output.status.success());
    let value = json_stdout(&output);
    assert_eq!(value["page"]["count"], 0);
    assert_eq!(value["scope"]["account"], "acct");
    assert_eq!(value["message"], "0 zones found on page 2 for account acct");
    assert!(
        value["suggestions"][0]
            .as_str()
            .unwrap()
            .contains("--account 'acct' zone list")
    );
    assert!(server.finish()[0].target.contains("account.id=acct"));
}

#[test]
fn invalid_modeled_fields_fail_before_auth_or_network() {
    for noun in ["account", "zone"] {
        let (output, _) = run(
            &["--format", "json", noun, "list", "--fields", "secret"],
            Some("http://127.0.0.1:1"),
            None,
        );
        assert_eq!(output.status.code(), Some(2));
        let value = json_stdout(&output);
        assert!(
            value["error"]["message"]
                .as_str()
                .unwrap()
                .contains("invalid")
        );
    }
}

#[test]
fn raw_pagination_merges_pages_and_preserves_query() {
    let server = Server::start(vec![
        (200, r#"{"result":[1,2],"result_info":{"total_pages":3}}"#),
        (200, r#"{"result":[3],"result_info":{"total_pages":3}}"#),
        (200, r#"{"result":[4],"result_info":{"total_pages":3}}"#),
    ]);
    let (output, _) = run(
        &[
            "--format",
            "json",
            "api",
            "GET",
            "/items",
            "--query",
            "kind=a b",
            "--paginate",
            "--max-pages",
            "3",
        ],
        Some(&server.endpoint),
        Some("token"),
    );
    assert!(output.status.success());
    assert_eq!(
        json_stdout(&output)["result"],
        serde_json::json!([1, 2, 3, 4])
    );
    let requests = server.finish();
    assert_eq!(requests.len(), 3);
    for (index, request) in requests.iter().enumerate() {
        assert!(request.target.contains("kind=a+b"));
        assert!(request.target.contains(&format!("page={}", index + 1)));
    }
}

#[test]
fn home_uses_bounded_live_account_state_when_authenticated() {
    let server = Server::start(vec![(
        200,
        r#"{"result":[{"id":"a","name":"Main","type":"standard"}],"result_info":{"total_count":1}}"#,
    )]);
    let (output, _) = run(&["--format", "json"], Some(&server.endpoint), Some("token"));
    assert!(output.status.success());
    let value = json_stdout(&output);
    assert_eq!(value["live"]["status"], "available");
    assert_eq!(value["live"]["total_accounts"], 1);
    let requests = server.finish();
    assert!(requests[0].target.contains("per_page=3"));
}

#[test]
fn config_precedence_and_account_typo_alias_are_deterministic() {
    let directory = tempfile::tempdir().unwrap();
    let xdg = directory.path().join("xdg");
    std::fs::create_dir_all(xdg.join("cloudflare")).unwrap();
    std::fs::write(
        xdg.join("cloudflare/cloudflare-axi.toml"),
        "account_id = 'global'\n",
    )
    .unwrap();
    std::fs::write(
        directory.path().join(".cloudflare-axi.toml"),
        "account_id = 'project'\n",
    )
    .unwrap();

    let invoke = |extra: &[&str], canonical: Option<&str>, typo: Option<&str>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"));
        command
            .args(["--format", "json"])
            .args(extra)
            .args(["auth", "status"])
            .current_dir(directory.path())
            .env("HOME", directory.path())
            .env("XDG_CONFIG_HOME", &xdg)
            .env_remove("CLOUDFLARE_ACCOUNT_ID")
            .env_remove("CLOUDFLARE_ACOUNT_ID");
        if let Some(value) = canonical {
            command.env("CLOUDFLARE_ACCOUNT_ID", value);
        }
        if let Some(value) = typo {
            command.env("CLOUDFLARE_ACOUNT_ID", value);
        }
        json_stdout(&command.output().unwrap())
    };

    assert_eq!(
        invoke(&["--account", "cli"], Some("env"), Some("typo"))["scope"]["account"],
        "cli"
    );
    assert_eq!(
        invoke(&[], Some("env"), Some("typo"))["scope"]["account"],
        "env"
    );
    assert_eq!(invoke(&[], None, Some("typo"))["scope"]["account"], "typo");
    assert_eq!(invoke(&[], None, None)["scope"]["account"], "project");

    std::fs::remove_file(directory.path().join(".cloudflare-axi.toml")).unwrap();
    assert_eq!(invoke(&[], None, None)["scope"]["account"], "global");
}

fn run_with_stdin(
    args: &[&str],
    input: &[u8],
    endpoint: Option<&str>,
    token: Option<&str>,
) -> (Output, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let xdg = dir.path().join("xdg");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&xdg).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"));
    command
        .args(args)
        .current_dir(dir.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for key in [
        "CLOUDFLARE_API_BASE",
        "CLOUDFLARE_ENDPOINT",
        "CLOUDFLARE_API_TOKEN",
        "CLOUDFLARE_API_KEY",
        "CLOUDFLARE_API_EMAIL",
        "CLOUDFLARE_ACCOUNT_ID",
        "CLOUDFLARE_ACOUNT_ID",
        "CLOUDFLARE_ZONE_ID",
    ] {
        command.env_remove(key);
    }
    if let Some(endpoint) = endpoint {
        command.args(["--endpoint", endpoint]);
    }
    if let Some(token) = token {
        command.env("CLOUDFLARE_API_TOKEN", token);
    }
    let mut child = command.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let input = input.to_vec();
    let writer = thread::spawn(move || stdin.write_all(&input));
    let output = child.wait_with_output().unwrap();
    let _ = writer.join().unwrap();
    (output, dir)
}

fn run_with_project_config(config: &str) -> (Output, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let xdg = dir.path().join("xdg");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&xdg).unwrap();
    std::fs::write(dir.path().join(".cloudflare-axi.toml"), config).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"))
        .args(["--format", "json", "auth", "status"])
        .current_dir(dir.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env_remove("CLOUDFLARE_API_TOKEN")
        .env_remove("CLOUDFLARE_API_KEY")
        .env_remove("CLOUDFLARE_API_EMAIL")
        .output()
        .unwrap();
    (output, dir)
}

#[test]
fn project_endpoint_settings_rejected_before_auth_or_network() {
    for key in ["endpoint", "api_base"] {
        let (output, _) = run_with_project_config(&format!("{key} = 'http://127.0.0.1:9'\n"));
        assert_eq!(output.status.code(), Some(1), "{key}");
        assert_eq!(json_stdout(&output)["error"]["type"], "config");
        assert!(String::from_utf8_lossy(&output.stdout).contains("cannot set"));
    }
}

#[test]
fn unknown_project_config_key_rejected_before_auth_or_network() {
    let (output, _) = run_with_project_config("unexpected = true\n");
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(json_stdout(&output)["error"]["type"], "config");
    assert!(String::from_utf8_lossy(&output.stdout).contains("unsupported config key"));
}

#[test]
fn raw_pagination_rejects_writes_before_auth_or_network() {
    for method in ["POST", "PUT", "PATCH", "DELETE"] {
        let (output, _) = run(
            &["--format", "json", "api", method, "/items", "--paginate"],
            Some("http://127.0.0.1:9"),
            None,
        );
        assert_eq!(output.status.code(), Some(2), "{method}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("allowed only"));
    }
}

#[test]
fn oversized_rest_json_file_and_stdin_rejected_before_network() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("body.json");
    let body = format!("{{\"x\":\"{}\"}}", "x".repeat(1024 * 1024));
    std::fs::write(&file, body.as_bytes()).unwrap();
    let (file_output, _) = run(
        &[
            "--format",
            "json",
            "api",
            "POST",
            "/x",
            "--file",
            file.to_str().unwrap(),
        ],
        Some("http://127.0.0.1:9"),
        None,
    );
    assert_eq!(file_output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&file_output.stdout).contains("exceeds 1 MiB"));

    let (stdin_output, _) = run_with_stdin(
        &["--format", "json", "api", "POST", "/x", "--stdin"],
        body.as_bytes(),
        Some("http://127.0.0.1:9"),
        None,
    );
    assert_eq!(stdin_output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&stdin_output.stdout).contains("exceeds 1 MiB"));
}

#[test]
fn oversized_graphql_file_stdin_and_variables_rejected_before_network() {
    let dir = tempfile::tempdir().unwrap();
    let query_file = dir.path().join("query.graphql");
    let variables_file = dir.path().join("variables.json");
    let oversized_query = format!("query Q {{ viewer }}\n#{}", "x".repeat(1024 * 1024));
    let oversized_variables = format!("{{\"x\":\"{}\"}}", "x".repeat(1024 * 1024));
    std::fs::write(&query_file, oversized_query.as_bytes()).unwrap();
    std::fs::write(&variables_file, oversized_variables.as_bytes()).unwrap();

    let (file_output, _) = run(
        &[
            "--format",
            "json",
            "graphql",
            "--file",
            query_file.to_str().unwrap(),
        ],
        Some("http://127.0.0.1:9"),
        None,
    );
    assert_eq!(file_output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&file_output.stdout).contains("GraphQL query exceeds 1 MiB"));

    let (stdin_output, _) = run_with_stdin(
        &["--format", "json", "graphql", "--stdin"],
        oversized_query.as_bytes(),
        Some("http://127.0.0.1:9"),
        None,
    );
    assert_eq!(stdin_output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&stdin_output.stdout).contains("GraphQL query exceeds 1 MiB"));

    let (variables_output, _) = run(
        &[
            "--format",
            "json",
            "graphql",
            "--query",
            "query { viewer }",
            "--variables-file",
            variables_file.to_str().unwrap(),
        ],
        Some("http://127.0.0.1:9"),
        None,
    );
    assert_eq!(variables_output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&variables_output.stdout)
            .contains("GraphQL variables exceeds 1 MiB")
    );
}

#[test]
fn get_commands_use_resolved_account_and_zone_selectors() {
    for noun in ["account", "zone"] {
        for source in ["env", "project", "global"] {
            let server = Server::start(vec![(200, r#"{"result":{"id":"resolved"}}"#)]);
            let d = tempfile::tempdir().unwrap();
            let home = d.path().join("home");
            let xdg = d.path().join("xdg");
            std::fs::create_dir_all(xdg.join("cloudflare")).unwrap();
            if source == "project" {
                std::fs::write(
                    d.path().join(".cloudflare-axi.toml"),
                    format!(
                        "{}_id = 'project-id'\n",
                        if noun == "account" { "account" } else { "zone" }
                    ),
                )
                .unwrap();
            } else if source == "global" {
                std::fs::write(
                    xdg.join("cloudflare/cloudflare-axi.toml"),
                    format!(
                        "{}_id = 'global-id'\n",
                        if noun == "account" { "account" } else { "zone" }
                    ),
                )
                .unwrap();
            }
            let mut command = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"));
            command
                .args(["--format", "json", noun, "get"])
                .current_dir(d.path())
                .env("HOME", &home)
                .env("XDG_CONFIG_HOME", &xdg)
                .env_remove("CLOUDFLARE_ACCOUNT_ID")
                .env_remove("CLOUDFLARE_ACOUNT_ID")
                .env_remove("CLOUDFLARE_ZONE_ID")
                .env("CLOUDFLARE_API_TOKEN", "test-token")
                .arg("--endpoint")
                .arg(&server.endpoint);
            if source == "env" {
                command.env(
                    if noun == "account" {
                        "CLOUDFLARE_ACCOUNT_ID"
                    } else {
                        "CLOUDFLARE_ZONE_ID"
                    },
                    "env-id",
                );
            }
            if source != "env" {
                command.env_remove(if noun == "account" {
                    "CLOUDFLARE_ACCOUNT_ID"
                } else {
                    "CLOUDFLARE_ZONE_ID"
                });
            }
            let output = command.output().unwrap();
            assert!(output.status.success(), "{noun}/{source}: {:?}", output);
            let expected = if source == "env" {
                "env-id"
            } else if source == "project" {
                "project-id"
            } else {
                "global-id"
            };
            assert_eq!(
                server.finish()[0].target,
                format!(
                    "/client/v4/{}s/{expected}",
                    if noun == "account" { "account" } else { "zone" }
                )
            );
        }
    }
}
