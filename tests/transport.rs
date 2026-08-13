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
        (500, r#"{"errors":[{"code":"secret-token"}]}"#),
        (500, r#"{"errors":[{"message":"secret-token"}]}"#),
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
            "--allow-write",
            "--file",
            file.to_str().unwrap(),
        ],
        Some("http://127.0.0.1:9"),
        None,
    );
    assert_eq!(file_output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&file_output.stdout).contains("exceeds 1 MiB"));

    let (stdin_output, _) = run_with_stdin(
        &[
            "--format",
            "json",
            "api",
            "POST",
            "/x",
            "--allow-write",
            "--stdin",
        ],
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

#[test]
fn capability_d1_database_get_exact_request() {
    let server = Server::start(vec![(
        200,
        r#"{"success":true,"errors":[],"result":{"uuid":"00000000-0000-0000-0000-000000000000","name":"fixture"}}"#,
    )]);
    let (output, _) = run(
        &[
            "--format",
            "json",
            "--account",
            "0123456789abcdef0123456789abcdef",
            "capability",
            "invoke",
            "d1_database_get",
            "--input",
            r#"{"database_id":"00000000-0000-0000-0000-000000000000","ignored":true}"#,
        ],
        Some(&server.endpoint),
        Some("fixture-token"),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(output.stderr.is_empty());
    let value = json_stdout(&output);
    assert_eq!(value["uuid"], "00000000-0000-0000-0000-000000000000");
    assert_eq!(value["name"], "fixture");
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(
        requests[0].target,
        "/client/v4/accounts/0123456789abcdef0123456789abcdef/d1/database/00000000-0000-0000-0000-000000000000"
    );
    assert!(
        requests[0]
            .headers
            .to_ascii_lowercase()
            .contains("authorization: bearer fixture-token")
    );
    assert!(requests[0].body.is_empty());
}

#[test]
fn capability_d1_database_get_key_email_auth_uses_explicit_headers() {
    let server = Server::start(vec![(
        200,
        r#"{"success":true,"errors":[],"result":{"uuid":"00000000-0000-0000-0000-000000000000"}}"#,
    )]);
    let directory = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"))
        .args([
            "--format",
            "json",
            "--endpoint",
            &server.endpoint,
            "--account",
            "0123456789abcdef0123456789abcdef",
            "capability",
            "invoke",
            "d1_database_get",
            "--input",
            r#"{"database_id":"00000000-0000-0000-0000-000000000000"}"#,
        ])
        .current_dir(directory.path())
        .env("HOME", directory.path())
        .env("XDG_CONFIG_HOME", directory.path())
        .env_remove("CLOUDFLARE_API_TOKEN")
        .env("CLOUDFLARE_API_KEY", "fixture-key")
        .env("CLOUDFLARE_API_EMAIL", "fixture@example.com")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let request = &server.finish()[0];
    let headers = request.headers.to_ascii_lowercase();
    assert!(headers.contains("x-auth-key: fixture-key"));
    assert!(headers.contains("x-auth-email: fixture@example.com"));
    assert!(!headers.contains("authorization: bearer"));
}

#[test]
fn capability_cli_account_and_endpoint_precede_malformed_config() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join(".cloudflare-axi.toml"), "[").unwrap();
    for (extra, expected_code, expected) in [
        (
            vec!["--account", "bad/account"],
            2,
            "account_id must be one safe",
        ),
        (vec!["--endpoint", "http://example.com"], 1, "HTTPS"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"))
            .args([
                "--format",
                "json",
                "capability",
                "invoke",
                "d1_database_get",
                "--input",
                r#"{"database_id":"00000000-0000-0000-0000-000000000000"}"#,
            ])
            .args(&extra)
            .current_dir(directory.path())
            .env("HOME", directory.path())
            .env("XDG_CONFIG_HOME", directory.path())
            .env_remove("CLOUDFLARE_API_TOKEN")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(expected_code));
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains(expected), "{text}");
        assert!(!text.contains("cannot parse config"), "{text}");
    }
}

#[test]
fn capability_d1_database_get_uses_explicit_transient_retry_policy() {
    let server = Server::start(vec![
        (500, r#"{"errors":[{"code":1000}]}"#),
        (500, r#"{"errors":[{"code":1000}]}"#),
        (500, r#"{"errors":[{"code":1000}]}"#),
    ]);
    let (output, _) = run(
        &[
            "--format",
            "json",
            "--account",
            "0123456789abcdef0123456789abcdef",
            "capability",
            "invoke",
            "d1_database_get",
            "--input",
            r#"{"database_id":"00000000-0000-0000-0000-000000000000"}"#,
        ],
        Some(&server.endpoint),
        Some("fixture-token"),
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    assert_eq!(server.finish().len(), 3);
}

#[test]
fn capability_d1_database_get_rejects_malformed_success_responses() {
    for body in [
        "not-json",
        r#"{"success":true}"#,
        r#"{"success":true,"errors":{}}"#,
        r#"{"success":true,"errors":[],"result":[]}"#,
        r#"{"success":false,"result":{"unexpected":true}}"#,
        r#"{"success":true,"errors":[{"code":1000}],"result":null}"#,
    ] {
        let server = Server::start(vec![(200, body)]);
        let (output, _) = run(
            &[
                "--format",
                "json",
                "--account",
                "0123456789abcdef0123456789abcdef",
                "capability",
                "invoke",
                "d1_database_get",
                "--input",
                r#"{"database_id":"00000000-0000-0000-0000-000000000000"}"#,
            ],
            Some(&server.endpoint),
            Some("fixture-token"),
        );
        assert!(!output.status.success(), "response accepted: {body}");
        assert_eq!(server.finish().len(), 1);
    }
}

#[test]
fn capability_endpoint_validation_precedes_auth_resolution() {
    let (output, _) = run(
        &[
            "--format",
            "json",
            "--endpoint",
            "http://example.com/client/v4",
            "capability",
            "invoke",
            "d1_database_get",
            "--input",
            r#"{"database_id":"00000000-0000-0000-0000-000000000000"}"#,
        ],
        None,
        None,
    );
    assert!(!output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("HTTPS") || text.contains("endpoint"),
        "{text}"
    );
    assert!(!text.contains("CLOUDFLARE_API_TOKEN"));
}

#[test]
fn capability_inline_file_and_stdin_inputs_are_equivalent() {
    let input = r#"{"database_id":"00000000-0000-0000-0000-000000000000","account_id":"0123456789abcdef0123456789abcdef"}"#;
    let expected_path = "/client/v4/accounts/0123456789abcdef0123456789abcdef/d1/database/00000000-0000-0000-0000-000000000000";

    let server = Server::start(vec![(
        200,
        r#"{"success":true,"errors":[],"result":{"source":"inline"}}"#,
    )]);
    let (output, _) = run(
        &[
            "--format",
            "json",
            "capability",
            "invoke",
            "d1_database_get",
            "--input",
            input,
        ],
        Some(&server.endpoint),
        Some("token"),
    );
    assert!(output.status.success());
    assert_eq!(json_stdout(&output)["source"], "inline");
    assert_eq!(server.finish()[0].target, expected_path);

    let file_dir = tempfile::tempdir().unwrap();
    let file = file_dir.path().join("input.json");
    std::fs::write(&file, input).unwrap();
    let server = Server::start(vec![(
        200,
        r#"{"success":true,"errors":[],"result":{"source":"file"}}"#,
    )]);
    let (output, _) = run(
        &[
            "--format",
            "json",
            "capability",
            "invoke",
            "d1_database_get",
            "--file",
            file.to_str().unwrap(),
        ],
        Some(&server.endpoint),
        Some("token"),
    );
    assert!(output.status.success());
    assert_eq!(json_stdout(&output)["source"], "file");
    assert_eq!(server.finish()[0].target, expected_path);

    let server = Server::start(vec![(
        200,
        r#"{"success":true,"errors":[],"result":{"source":"stdin"}}"#,
    )]);
    let (output, _) = run_with_stdin(
        &[
            "--format",
            "json",
            "capability",
            "invoke",
            "d1_database_get",
            "--stdin",
        ],
        input.as_bytes(),
        Some(&server.endpoint),
        Some("token"),
    );
    assert!(output.status.success());
    assert_eq!(json_stdout(&output)["source"], "stdin");
    assert_eq!(server.finish()[0].target, expected_path);
}

#[test]
fn capability_input_must_be_object_and_within_one_mib() {
    let (output, _) = run(
        &[
            "--format",
            "json",
            "capability",
            "invoke",
            "d1_database_get",
            "--input",
            "[]",
        ],
        Some("http://127.0.0.1:1"),
        None,
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stdout).contains("input does not match schema"));

    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("input.json");
    std::fs::write(
        &file,
        format!("{{\"database_id\":\"{}\"}}", "x".repeat(1024 * 1024)),
    )
    .unwrap();
    let (output, _) = run(
        &[
            "--format",
            "json",
            "capability",
            "invoke",
            "d1_database_get",
            "--file",
            file.to_str().unwrap(),
        ],
        Some("http://127.0.0.1:1"),
        None,
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stdout).contains("request body exceeds 1 MiB"));
}

#[test]
fn capability_input_account_conflict_precedes_auth_and_network() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join(".cloudflare-axi.toml"),
        "account_id = 'configured'\n",
    )
    .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"));
    command
        .args([
            "--format",
            "json",
            "--endpoint",
            "http://127.0.0.1:1",
            "capability",
            "invoke",
            "d1_database_get",
            "--input",
            r#"{"database_id":"00000000-0000-0000-0000-000000000000","account_id":"provided"}"#,
        ])
        .current_dir(directory.path())
        .env("HOME", directory.path())
        .env("XDG_CONFIG_HOME", directory.path())
        .env_remove("CLOUDFLARE_API_TOKEN");
    let output = command.output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("conflicts with resolved account scope")
    );
}

#[test]
fn browser_input_account_conflict_precedes_auth_and_network() {
    for name in [
        "get_url_markdown",
        "get_url_links",
        "scrape_url_elements",
        "get_url_json",
        "get_url_snapshot",
        "get_crawl_result",
    ] {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join(".cloudflare-axi.toml"),
            "account_id = 'configured'\n",
        )
        .unwrap();
        let input = match name {
            "scrape_url_elements" => {
                r#"{"url":"https://example.com","elements":[{"selector":"h1"}],"account_id":"provided"}"#
            }
            "get_crawl_result" => r#"{"job_id":"job-123","account_id":"provided"}"#,
            _ => r#"{"url":"https://example.com","account_id":"provided"}"#,
        };
        let mut command = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"));
        command
            .args([
                "--format",
                "json",
                "--endpoint",
                "http://127.0.0.1:1",
                "capability",
                "invoke",
                name,
                "--input",
                input,
                "--allow-metered",
                "--allow-egress",
                "--allow-long-running",
            ])
            .current_dir(directory.path())
            .env("HOME", directory.path())
            .env("XDG_CONFIG_HOME", directory.path())
            .env_remove("CLOUDFLARE_API_TOKEN");
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{name}");
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("conflicts with resolved account scope"),
            "{name}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[test]
fn invalid_capability_account_and_path_precede_malformed_config() {
    for input in [
        r#"{"database_id":"00000000-0000-0000-0000-000000000000","account_id":"../bad"}"#,
        r#"{"database_id":"../bad"}"#,
    ] {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join(".cloudflare-axi.toml"), "[").unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"));
        command
            .args([
                "--format",
                "json",
                "--endpoint",
                "http://127.0.0.1:1",
                "capability",
                "invoke",
                "d1_database_get",
                "--input",
                input,
            ])
            .current_dir(directory.path())
            .env("HOME", directory.path())
            .env("XDG_CONFIG_HOME", directory.path())
            .env_remove("CLOUDFLARE_API_TOKEN");
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(!text.contains("config"), "{text}");
        assert!(!text.contains("connection"), "{text}");
    }
}

#[test]
fn capability_non_retry_status_is_requested_once() {
    let server = Server::start(vec![(400, r#"{"errors":[{"code":1000}]}"#)]);
    let (output, _) = run(
        &[
            "--format",
            "json",
            "--account",
            "0123456789abcdef0123456789abcdef",
            "capability",
            "invoke",
            "d1_database_get",
            "--input",
            r#"{"database_id":"00000000-0000-0000-0000-000000000000"}"#,
        ],
        Some(&server.endpoint),
        Some("token"),
    );
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(server.finish().len(), 1);
}

struct RawResponseServer {
    endpoint: String,
    requests: Arc<Mutex<usize>>,
    join: Option<thread::JoinHandle<()>>,
}

impl RawResponseServer {
    fn start(responses: Vec<&'static str>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/client/v4", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(0));
        let seen = Arc::clone(&requests);
        let join = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut bytes = Vec::new();
                let mut chunk = [0; 4096];
                loop {
                    let n = stream.read(&mut chunk).unwrap();
                    assert!(n > 0, "client closed before request headers");
                    bytes.extend_from_slice(&chunk[..n]);
                    if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                *seen.lock().unwrap() += 1;
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        Self {
            endpoint,
            requests,
            join: Some(join),
        }
    }

    fn finish(mut self) -> usize {
        self.join.take().unwrap().join().unwrap();
        *self.requests.lock().unwrap()
    }
}

#[test]
fn transient_read_failure_retries_and_succeeds() {
    let server = RawResponseServer::start(vec![
        "HTTP/1.1 200 OK\r\nContent-Length: 32\r\nConnection: close\r\n\r\n{\"result\":",
        "HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"result\":true}",
    ]);
    let (output, _) = run(
        &["--format", "json", "api", "GET", "/x"],
        Some(&server.endpoint),
        Some("token"),
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(server.finish(), 2);
}

#[test]
fn rate_limit_retry_after_malformed_is_bounded_and_exact() {
    let server = RawResponseServer::start(vec![
        "HTTP/1.1 429 Too Many Requests\r\nRetry-After: malformed\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        "HTTP/1.1 429 Too Many Requests\r\nRetry-After: malformed\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        "HTTP/1.1 429 Too Many Requests\r\nRetry-After: malformed\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
    ]);
    let (output, _) = run(
        &["--format", "json", "api", "GET", "/x"],
        Some(&server.endpoint),
        Some("token"),
    );
    assert!(!output.status.success());
    assert_eq!(server.finish(), 3);
}

#[test]
fn unsupported_capability_preflight_precedes_missing_file() {
    let (output, _) = run(
        &[
            "--format",
            "json",
            "capability",
            "invoke",
            "unsupported-capability",
            "--file",
            "/nonexistent/preflight-input.json",
        ],
        Some("http://127.0.0.1:1"),
        None,
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(2));
    assert!(text.contains("no complete route contract"), "{text}");
    assert!(!text.contains("cannot read"), "{text}");
}

#[test]
fn raw_write_guard_precedes_missing_file() {
    let (output, _) = run(
        &[
            "--format",
            "json",
            "api",
            "POST",
            "/x",
            "--file",
            "/nonexistent/preflight-body.json",
        ],
        Some("http://127.0.0.1:1"),
        None,
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        text.contains("write API calls require --allow-write"),
        "{text}"
    );
    assert!(!text.contains("cannot read"), "{text}");
}

const TEST_ACCOUNT: &str = "account-123";
const TEST_DATABASE: &str = "123e4567-e89b-12d3-a456-426614174000";

fn capability_args<'a>(name: &'a str, input: &'a str) -> Vec<&'a str> {
    vec![
        "--format",
        "json",
        "--account",
        TEST_ACCOUNT,
        "capability",
        "invoke",
        name,
        "--input",
        input,
    ]
}

fn assert_usage_before_network(args: &[&str], expected: &str) {
    let (out, _) = run(args, Some("http://example.com"), None);
    assert_eq!(out.status.code(), Some(2), "{args:?}");
    assert!(out.stderr.is_empty());
    assert!(String::from_utf8_lossy(&out.stdout).contains(expected));
}

#[test]
fn capability_d1_database_delete_exact_request() {
    let input = format!(r#"{{"database_id":"{TEST_DATABASE}"}}"#);
    for flag in [
        "--allow-write",
        "--allow-metered",
        "--allow-egress",
        "--confirm",
    ] {
        let mut args = capability_args("d1_database_delete", &input);
        args.extend(match flag {
            "--confirm" => vec!["--allow-write", "--allow-metered", "--allow-egress"],
            _ => vec![
                "--allow-write",
                "--allow-metered",
                "--allow-egress",
                "--confirm",
                "d1_database_delete",
            ],
        });
        if flag == "--confirm" {
            args.retain(|arg| {
                *arg != "--allow-write" && *arg != "--allow-metered" && *arg != "--allow-egress"
            });
            args.extend(["--allow-write", "--allow-metered", "--allow-egress"]);
        } else {
            args.retain(|arg| *arg != flag);
        }
        assert_usage_before_network(&args, flag);
    }

    let server = Server::start(vec![(204, "")]);
    let mut args = capability_args("d1_database_delete", &input);
    args.extend([
        "--allow-write",
        "--allow-metered",
        "--allow-egress",
        "--confirm",
        "d1_database_delete",
    ]);
    let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
    assert!(
        out.status.success(),
        "stdout={:?} stderr={:?}",
        out.stdout,
        out.stderr
    );
    assert_eq!(json_stdout(&out), Value::Null);
    assert!(out.stderr.is_empty());
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "DELETE");
    assert_eq!(
        requests[0].target,
        format!("/client/v4/accounts/{TEST_ACCOUNT}/d1/database/{TEST_DATABASE}")
    );
    assert!(
        requests[0]
            .headers
            .to_ascii_lowercase()
            .contains("authorization: bearer token")
    );
    assert!(
        requests[0]
            .headers
            .to_ascii_lowercase()
            .contains("content-length: 0")
    );
    assert!(requests[0].body.is_empty());

    for (status, body) in [
        (200, r#"{"success":false,"errors":[{"code":1000}]}"#),
        (500, "{}"),
    ] {
        let server = Server::start(vec![(status, body)]);
        let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
        assert!(!out.status.success());
        assert!(out.stderr.is_empty());
        assert_eq!(server.finish().len(), 1);
    }
}

#[test]
fn capability_get_url_markdown_exact_request() {
    assert_browser_guards("get_url_markdown", r#"{"url":"https://example.com"}"#);
    assert_browser_invalid_urls("get_url_markdown", r#"{"url":"https://example.com"}"#);

    let server = Server::start(vec![(
        200,
        r##"{"success":true,"errors":[],"result":"# hi"}"##,
    )]);
    let args = browser_args(
        "get_url_markdown",
        r#"{"url":"  https://example.com/path  "}"#,
    );
    let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
    assert!(out.status.success(), "{out:?}");
    assert_eq!(json_stdout(&out), "# hi");
    assert_browser_request(
        &server.finish(),
        "markdown",
        serde_json::json!({"url":"https://example.com/path"}),
    );

    for response in [
        "not-json",
        r#"{"success":true}"#,
        r#"{"success":true,"errors":{},"result":"x"}"#,
        r#"{"success":true,"errors":[],"result":7}"#,
    ] {
        let server = Server::start(vec![(200, response)]);
        let (out, _) = run(
            &browser_args("get_url_markdown", r#"{"url":"https://example.com"}"#),
            Some(&server.endpoint),
            Some("token"),
        );
        assert!(!out.status.success(), "accepted {response}");
        assert_eq!(server.finish().len(), 1);
    }
    let server = Server::start(vec![(500, "{}")]);
    let (out, _) = run(
        &browser_args("get_url_markdown", r#"{"url":"https://example.com"}"#),
        Some(&server.endpoint),
        Some("token"),
    );
    assert!(!out.status.success());
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn capability_get_url_links_exact_request() {
    assert_browser_guards("get_url_links", r#"{"url":"https://example.com"}"#);
    assert_browser_invalid_urls("get_url_links", r#"{"url":"https://example.com"}"#);

    for (input, expected_body) in [
        (
            r#"{"url":"https://example.com"}"#,
            serde_json::json!({"url":"https://example.com"}),
        ),
        (
            r#"{"url":"https://example.com","visibleLinksOnly":true}"#,
            serde_json::json!({"url":"https://example.com","visibleLinksOnly":true}),
        ),
    ] {
        let server = Server::start(vec![(
            200,
            r#"{"success":true,"errors":[],"result":["https://example.com/a"]}"#,
        )]);
        let (out, _) = run(
            &browser_args("get_url_links", input),
            Some(&server.endpoint),
            Some("token"),
        );
        assert!(out.status.success(), "{out:?}");
        assert_eq!(
            json_stdout(&out),
            serde_json::json!(["https://example.com/a"])
        );
        assert_browser_request(&server.finish(), "links", expected_body);
    }

    for response in [
        "not-json",
        r#"{"success":true,"errors":{},"result":[]}"#,
        r#"{"success":true,"errors":[],"result":"not-links"}"#,
    ] {
        let server = Server::start(vec![(200, response)]);
        let (out, _) = run(
            &browser_args("get_url_links", r#"{"url":"https://example.com"}"#),
            Some(&server.endpoint),
            Some("token"),
        );
        assert!(!out.status.success(), "accepted {response}");
        assert_eq!(server.finish().len(), 1);
    }
    let server = Server::start(vec![(500, "{}")]);
    let (out, _) = run(
        &browser_args("get_url_links", r#"{"url":"https://example.com"}"#),
        Some(&server.endpoint),
        Some("token"),
    );
    assert!(!out.status.success());
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn capability_scrape_url_elements_exact_request() {
    assert_browser_guards(
        "scrape_url_elements",
        r#"{"url":"https://example.com","elements":[{"selector":"h1"}]}"#,
    );
    assert_browser_invalid_urls(
        "scrape_url_elements",
        r#"{"url":"https://example.com","elements":[{"selector":"h1"}]}"#,
    );

    let response = r#"{"success":true,"errors":[],"result":[{"selector":"h1","results":[{"attributes":[],"height":39,"html":"Example Domain","left":100,"text":"Example Domain","top":133.4375,"width":600}]}]}"#;
    let server = Server::start(vec![(200, response)]);
    let input = r#"{"url":"  https://example.com/path  ","elements":[{"selector":"h1"}]}"#;
    let (out, _) = run(
        &browser_args("scrape_url_elements", input),
        Some(&server.endpoint),
        Some("token"),
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(json_stdout(&out)[0]["selector"], "h1");
    assert_browser_request(
        &server.finish(),
        "scrape",
        serde_json::json!({"url":"https://example.com/path","elements":[{"selector":"h1"}]}),
    );

    for response in [
        r#"{"success":true,"errors":[],"result":{}}"#,
        r#"{"success":true,"errors":[],"result":[{"selector":"h1","results":[],"unknown":true}]}"#,
        r#"{"success":true,"errors":[],"result":[{"selector":"h1","results":[{"attributes":[],"height":"39","html":"x","left":1,"text":"x","top":1,"width":1}]}]}"#,
        r#"{"success":true,"errors":[],"result":[{"selector":"h1","results":[{"attributes":[{"name":"class"}],"height":1,"html":"x","left":1,"text":"x","top":1,"width":1}]}]}"#,
    ] {
        let server = Server::start(vec![(200, response)]);
        let (out, _) = run(
            &browser_args(
                "scrape_url_elements",
                r#"{"url":"https://example.com","elements":[{"selector":"h1"}]}"#,
            ),
            Some(&server.endpoint),
            Some("token"),
        );
        assert!(!out.status.success(), "accepted {response}");
        assert_eq!(server.finish().len(), 1);
    }
    let server = Server::start(vec![(500, "{}")]);
    let (out, _) = run(
        &browser_args(
            "scrape_url_elements",
            r#"{"url":"https://example.com","elements":[{"selector":"h1"}]}"#,
        ),
        Some(&server.endpoint),
        Some("token"),
    );
    assert!(!out.status.success());
    assert_eq!(server.finish().len(), 1);
}

fn browser_args<'a>(name: &'a str, input: &'a str) -> Vec<&'a str> {
    let mut args = capability_args(name, input);
    args.extend(["--allow-metered", "--allow-egress", "--allow-long-running"]);
    args
}

fn assert_browser_guards(name: &str, input: &str) {
    for omitted in ["--allow-metered", "--allow-egress", "--allow-long-running"] {
        let mut args = browser_args(name, input);
        args.retain(|arg| *arg != omitted);
        assert_usage_before_network(&args, omitted);
    }
}

fn assert_browser_invalid_urls(name: &str, input: &str) {
    for url in ["relative/path", "://malformed"] {
        let input = input.replace("https://example.com", url);
        let (out, _) = run(
            &browser_args(name, &input),
            Some("http://example.com"),
            None,
        );
        assert_eq!(out.status.code(), Some(2), "{name}: {url}");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("url must be valid"), "{text}");
        assert!(!text.contains("authentication"), "{text}");
        assert!(!text.contains("HTTPS"), "{text}");
    }
}

fn assert_browser_request(requests: &[Request], suffix: &str, body: Value) {
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method, "POST");
    assert_eq!(
        request.target,
        format!("/client/v4/accounts/{TEST_ACCOUNT}/browser-run/{suffix}")
    );
    let headers = request.headers.to_ascii_lowercase();
    assert!(headers.contains("authorization: bearer token"));
    assert!(headers.contains("content-type: application/json"));
    assert_eq!(serde_json::from_str::<Value>(&request.body).unwrap(), body);
}

#[test]
fn capability_get_url_json_exact_request() {
    assert_browser_guards("get_url_json", r#"{"url":"https://example.com"}"#);
    assert_browser_invalid_urls("get_url_json", r#"{"url":"https://example.com"}"#);
    let server = Server::start(vec![(
        200,
        r#"{"success":true,"errors":[],"result":{"answer":42}}"#,
    )]);
    let (out, _) = run(
        &browser_args(
            "get_url_json",
            r#"{"url":"  https://example.com/path  ","prompt":"answer","response_format":{"type":"json_object"}}"#,
        ),
        Some(&server.endpoint),
        Some("token"),
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(json_stdout(&out), serde_json::json!({"answer":42}));
    assert_browser_request(
        &server.finish(),
        "json",
        serde_json::json!({"url":"https://example.com/path","prompt":"answer","response_format":{"type":"json_object"}}),
    );
    for response in [
        r#"{"success":true,"errors":[],"result":null}"#,
        r#"{"success":true,"errors":[]}"#,
    ] {
        let server = Server::start(vec![(200, response)]);
        let (out, _) = run(
            &browser_args("get_url_json", r#"{"url":"https://example.com"}"#),
            Some(&server.endpoint),
            Some("token"),
        );
        assert_eq!(out.status.success(), response.contains("result"));
        assert_eq!(server.finish().len(), 1);
    }
    let server = Server::start(vec![(500, "{}")]);
    let (out, _) = run(
        &browser_args("get_url_json", r#"{"url":"https://example.com"}"#),
        Some(&server.endpoint),
        Some("token"),
    );
    assert!(!out.status.success());
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn capability_get_url_snapshot_exact_request() {
    assert_browser_guards("get_url_snapshot", r#"{"url":"https://example.com"}"#);
    assert_browser_invalid_urls("get_url_snapshot", r#"{"url":"https://example.com"}"#);
    let server = Server::start(vec![(
        200,
        r#"{"success":true,"errors":[],"result":{"content":"<html>ok</html>","screenshot":null}}"#,
    )]);
    let (out, _) = run(
        &browser_args("get_url_snapshot", r#"{"url":"https://example.com"}"#),
        Some(&server.endpoint),
        Some("token"),
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        json_stdout(&out),
        serde_json::json!({"content":"<html>ok</html>","screenshot":null})
    );
    assert_browser_request(
        &server.finish(),
        "snapshot",
        serde_json::json!({"url":"https://example.com"}),
    );
    for result in [r#"{"content":7}"#, r#"{"screenshot":false}"#] {
        let response = Box::leak(
            format!(r#"{{"success":true,"errors":[],"result":{result}}}"#).into_boxed_str(),
        );
        let server = Server::start(vec![(200, response)]);
        let (out, _) = run(
            &browser_args("get_url_snapshot", r#"{"url":"https://example.com"}"#),
            Some(&server.endpoint),
            Some("token"),
        );
        assert!(!out.status.success());
        assert_eq!(server.finish().len(), 1);
    }
    let server = Server::start(vec![(500, "{}")]);
    let (out, _) = run(
        &browser_args("get_url_snapshot", r#"{"url":"https://example.com"}"#),
        Some(&server.endpoint),
        Some("token"),
    );
    assert!(!out.status.success());
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn capability_get_crawl_result_exact_request() {
    let (out, _) = run(
        &capability_args("get_crawl_result", r#"{"job_id":"job-123"}"#),
        Some("http://127.0.0.1:1"),
        Some("token"),
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stdout).contains("--allow-egress"));

    for job_id in ["../bad", "job/bad", "job%2Fbad", &"x".repeat(257)] {
        let input = format!(r#"{{"job_id":"{job_id}"}}"#);
        let mut args = capability_args("get_crawl_result", &input);
        args.push("--allow-egress");
        let (out, _) = run(&args, Some("http://127.0.0.1:1"), Some("token"));
        assert_eq!(out.status.code(), Some(2), "{job_id}");
    }

    let server = Server::start(vec![(
        200,
        r#"{"success":true,"errors":[],"result":{"status":"complete"}}"#,
    )]);
    let mut args = capability_args("get_crawl_result", r#"{"job_id":"job 123"}"#);
    args.push("--allow-egress");
    let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
    assert!(out.status.success(), "{out:?}");
    assert_eq!(json_stdout(&out), serde_json::json!({"status":"complete"}));
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(
        requests[0].target,
        format!("/client/v4/accounts/{TEST_ACCOUNT}/browser-run/crawl/job%20123")
    );

    let server = Server::start(vec![(400, "{}")]);
    let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
    assert!(!out.status.success());
    assert_eq!(server.finish().len(), 1);

    let server = Server::start(vec![(500, "{}"), (500, "{}"), (500, "{}")]);
    let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
    assert!(!out.status.success());
    assert_eq!(server.finish().len(), 3);
}

#[test]
fn capability_get_url_html_content_exact_request() {
    let input = r#"{"url":"  https://example.com/path  "}"#;
    for omitted in ["--allow-metered", "--allow-egress", "--allow-long-running"] {
        let args = capability_args("get_url_html_content", input);
        assert_usage_before_network(&args, omitted);
    }
    let server = Server::start(vec![(
        200,
        r#"{"success":true,"errors":[],"result":"<html>ok</html>"}"#,
    )]);
    let mut args = capability_args("get_url_html_content", input);
    args.extend(["--allow-metered", "--allow-egress", "--allow-long-running"]);
    let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
    assert!(out.status.success());
    assert_eq!(json_stdout(&out), "<html>ok</html>");
    assert!(out.stderr.is_empty());
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(
        requests[0].target,
        format!("/client/v4/accounts/{TEST_ACCOUNT}/browser-rendering/content")
    );
    assert!(
        requests[0]
            .headers
            .to_ascii_lowercase()
            .contains("authorization: bearer token")
    );
    assert!(
        requests[0]
            .headers
            .to_ascii_lowercase()
            .contains("content-type: application/json")
    );
    assert_eq!(
        serde_json::from_str::<Value>(&requests[0].body).unwrap(),
        serde_json::json!({"url":"https://example.com/path"})
    );

    for body in [
        r#"{"success":true,"errors":[],"result":7}"#,
        r#"{"success":true,"errors":[{"message":"bad"}],"result":"x"}"#,
    ] {
        let server = Server::start(vec![(200, body)]);
        let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
        assert!(!out.status.success());
        assert_eq!(server.finish().len(), 1);
    }
    let server = Server::start(vec![(500, "{}")]);
    let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
    assert!(!out.status.success());
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn capability_graphql_schema_overview_exact_request() {
    for input in [r#"{"page":0}"#, r#"{"pageSize":0}"#] {
        let args = capability_args("graphql_schema_overview", input);
        let (out, _) = run(&args, Some("http://127.0.0.1:1"), None);
        assert_eq!(out.status.code(), Some(2), "{input}: {:?}", out);
    }
    let response = r#"{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":null,"subscriptionType":null,"types":[{"name":"A","kind":"OBJECT","description":"a"},{"name":"B","kind":"SCALAR","description":"b"}]}},"errors":[]}"#;
    let server = Server::start(vec![(200, response)]);
    let args = capability_args("graphql_schema_overview", r#"{"page":1,"pageSize":10}"#);
    let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        json_stdout(&out)["pagination"],
        serde_json::json!({"page":1,"pageSize":10,"totalTypes":2,"totalPages":1,"hasNextPage":false,"hasPreviousPage":false})
    );
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].target, "/client/v4/graphql");
    assert!(
        requests[0]
            .headers
            .to_ascii_lowercase()
            .contains("authorization: bearer token")
    );
    let body: Value = serde_json::from_str(&requests[0].body).unwrap();
    assert_eq!(body.as_object().unwrap().len(), 1);
    assert_eq!(
        body["query"],
        "\n\t\tquery SchemaOverview {\n\t\t\t__schema {\n\t\t\t\tqueryType { name }\n\t\t\t\tmutationType { name }\n\t\t\t\tsubscriptionType { name }\n\t\t\t\ttypes {\n\t\t\t\t\tname\n\t\t\t\t\tkind\n\t\t\t\t\tdescription\n\t\t\t\t}\n\t\t\t}\n\t\t}\n\t"
    );
    for response in [
        r#"{"errors":[{"message":"bad"}]}"#,
        r#"{"data":{"__schema":{"types":{}}}}"#,
    ] {
        let server = Server::start(vec![(200, response)]);
        let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
        assert!(!out.status.success());
        assert_eq!(server.finish().len(), 1);
    }
    let server = Server::start(vec![(500, "{}"), (500, "{}"), (500, "{}")]);
    let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
    assert!(!out.status.success());
    assert_eq!(server.finish().len(), 3);
}

#[test]
fn capability_browser_guard_permutations_precede_endpoint_auth_and_network() {
    for omitted in ["--allow-metered", "--allow-egress", "--allow-long-running"] {
        let args = capability_args("get_url_html_content", r#"{"url":"https://example.com"}"#);
        let mut args = args;
        args.extend(["--allow-metered", "--allow-egress", "--allow-long-running"]);
        args.retain(|arg| *arg != omitted);
        assert_usage_before_network(&args, omitted);
    }
}

#[test]
fn capability_browser_invalid_urls_precede_endpoint_auth_and_network() {
    for url in ["relative/path", "://malformed"] {
        let input = format!(r#"{{"url":"{url}"}}"#);
        let mut args = capability_args("get_url_html_content", &input);
        args.extend(["--allow-metered", "--allow-egress", "--allow-long-running"]);
        let (out, _) = run(&args, Some("http://example.com"), None);
        assert_eq!(out.status.code(), Some(2), "{url}");
        assert!(out.stderr.is_empty());
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("url must be valid"), "{text}");
        assert!(!text.contains("authentication"), "{text}");
        assert!(!text.contains("HTTPS"), "{text}");
    }
}

#[test]
fn capability_graphql_schema_overview_defaults_page_one_and_size_100() {
    let types = (0..11)
        .map(|index| format!(r#"{{"name":"Type{index}","kind":"OBJECT"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let response = format!(
        r#"{{"data":{{"__schema":{{"queryType":{{"name":"Query"}},"mutationType":null,"subscriptionType":null,"types":[{types}]}}}}}}"#
    );
    let response: &'static str = Box::leak(response.into_boxed_str());
    let server = Server::start(vec![(200, response)]);
    let args = capability_args("graphql_schema_overview", "{}");
    let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
    assert!(out.status.success(), "{out:?}");
    let value = json_stdout(&out);
    assert_eq!(
        value["pagination"],
        serde_json::json!({"page":1,"pageSize":100,"totalTypes":11,"totalPages":1,"hasNextPage":false,"hasPreviousPage":false})
    );
    assert_eq!(value["data"]["__schema"]["types"][0]["name"], "Type0");
    assert_eq!(value["data"]["__schema"]["types"][10]["name"], "Type10");
    let request = &server.finish()[0];
    let body: Value = serde_json::from_str(&request.body).unwrap();
    assert_eq!(body.as_object().unwrap().len(), 1);
    assert!(body["query"].as_str().unwrap().contains("types"));
}

#[test]
fn capability_graphql_schema_overview_slices_page_two_and_empty_page() {
    let types = (0..11)
        .map(|index| format!(r#"{{"name":"Type{index}","kind":"OBJECT"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let response = format!(
        r#"{{"data":{{"__schema":{{"queryType":{{"name":"Query"}},"mutationType":null,"subscriptionType":null,"types":[{types}]}}}}}}"#
    );
    let response: &'static str = Box::leak(response.into_boxed_str());
    for (input, expected) in [
        (r#"{"page":2,"pageSize":10}"#, vec!["Type10"]),
        (r#"{"page":3,"pageSize":10}"#, Vec::new()),
    ] {
        let server = Server::start(vec![(200, response)]);
        let args = capability_args("graphql_schema_overview", input);
        let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
        assert!(out.status.success(), "{out:?}");
        let value = json_stdout(&out);
        let names = value["data"]["__schema"]["types"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(names, expected);
        server.finish();
    }
}

#[test]
fn capability_graphql_schema_overview_accepts_page_size_1000() {
    let server = Server::start(vec![(
        200,
        r#"{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":null,"subscriptionType":null,"types":[]}}}"#,
    )]);
    let args = capability_args("graphql_schema_overview", r#"{"page":1,"pageSize":1000}"#);
    let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
    assert!(out.status.success(), "{out:?}");
    assert_eq!(json_stdout(&out)["pagination"]["pageSize"], 1000);
    server.finish();
}

#[test]
fn capability_graphql_schema_overview_accepts_fractional_numbers_and_huge_pages() {
    let types = (0..20)
        .map(|index| format!(r#"{{"name":"Type{index}","kind":"OBJECT"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let response = Box::leak(
        format!(r#"{{"data":{{"__schema":{{"queryType":{{"name":"Query"}},"mutationType":null,"subscriptionType":null,"types":[{types}]}}}}}}"#)
            .into_boxed_str(),
    );
    for (input, expected) in [
        (r#"{"page":1.55,"pageSize":10.8}"#, vec!["Type5", "Type15"]),
        (r#"{"page":1e300,"pageSize":10}"#, Vec::new()),
    ] {
        let server = Server::start(vec![(200, response)]);
        let args = capability_args("graphql_schema_overview", input);
        let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
        assert!(out.status.success(), "{out:?}");
        let value = json_stdout(&out);
        let types = value["data"]["__schema"]["types"].as_array().unwrap();
        let boundary = types
            .first()
            .into_iter()
            .chain(types.last())
            .map(|value| value["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(boundary, expected);
        server.finish();
    }
}

fn blog_args<'a>(name: &'a str, input: &'a str) -> Vec<&'a str> {
    vec![
        "--format",
        "json",
        "capability",
        "invoke",
        name,
        "--input",
        input,
    ]
}

fn run_blog(name: &str, input: &str, endpoint: &str, token: Option<&str>) -> Output {
    let args = blog_args(name, input);
    run(&args, Some(endpoint), token).0
}

#[test]
fn capability_cloudflare_blog_public_reads_exact_requests() {
    let post = r#"{"slug":"workers/python support/é","title":"Title","excerpt":"Excerpt","url":"https://blog.example/post","publishedAt":null,"tags":["workers"],"authors":["Ada"],"content":"Body","extra":true}"#;
    let server = Server::start(vec![(200, post)]);
    let out = run_blog(
        "get_post",
        r#"{"slug":"workers/python support/é"}"#,
        &server.endpoint,
        Some("token"),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(json_stdout(&out)["content"], "Body");
    assert!(json_stdout(&out).get("extra").is_none());
    let request = &server.finish()[0];
    assert_eq!(request.method, "GET");
    assert_eq!(
        request.target,
        "/client/v4/api/mcp/posts/workers%2Fpython%20support%2F%C3%A9"
    );
    assert!(request.body.is_empty());
    let headers = request.headers.to_ascii_lowercase();
    assert!(
        !headers.contains("authorization:")
            && !headers.contains("x-auth-")
            && !headers.contains("cf-account")
    );

    let server = Server::start(vec![(
        200,
        r#"{"posts":[{"slug":"s","title":"T","excerpt":"E","url":"u","publishedAt":"now","tags":[],"authors":[],"ignored":1}],"nextCursor":"a b"}"#,
    )]);
    let out = run_blog(
        "list_posts",
        r#"{"limit":7,"cursor":"a b/é","tag":"zero trust"}"#,
        &server.endpoint,
        Some("token"),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(json_stdout(&out)["posts"][0].get("ignored"), None);
    assert_eq!(
        server.finish()[0].target,
        "/client/v4/api/mcp/posts?limit=7&cursor=a+b%2F%C3%A9&tag=zero+trust"
    );

    let server = Server::start(vec![(200, r#"{"posts":[],"nextCursor":null}"#)]);
    let out = run_blog(
        "list_posts",
        r#"{"limit":7,"cursor":"","tag":""}"#,
        &server.endpoint,
        None,
    );
    assert!(out.status.success());
    assert_eq!(
        server.finish()[0].target,
        "/client/v4/api/mcp/posts?limit=7"
    );

    let server = Server::start(vec![(
        200,
        r#"{"tags":[{"slug":"workers","label":"Workers","extra":1}]}"#,
    )]);
    let out = run_blog("list_tags", "{}", &server.endpoint, Some("token"));
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(
        json_stdout(&out),
        serde_json::json!({"tags":[{"slug":"workers","label":"Workers"}]})
    );
    assert_eq!(server.finish()[0].target, "/client/v4/api/mcp/tags");

    let text = "x".repeat(301);
    let body = format!(
        r#"{{"success":true,"result":{{"chunks":[{{"score":0.2,"text":"{text}","item":{{"key":"/a","metadata":{{"title":"low"}}}}}},{{"score":0.9,"text":"ignored","item":{{"key":"/a","metadata":{{"title":"high","description":"desc"}}}}}},{{"score":0.4,"text":"{text}","item":{{"key":"/b","metadata":{{}}}}}}]}}}}"#
    );
    let body: &'static str = Box::leak(body.into_boxed_str());
    let server = Server::start(vec![(200, body)]);
    let out = run_blog(
        "search_posts",
        r#"{"query":"workers é"}"#,
        &server.endpoint,
        Some("token"),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let value = json_stdout(&out);
    assert_eq!(value["results"].as_array().unwrap().len(), 2);
    assert_eq!(
        value["results"][0],
        serde_json::json!({"url":"/a","title":"high","excerpt":"desc","score":0.9})
    );
    assert_eq!(
        value["results"][1]["excerpt"]
            .as_str()
            .unwrap()
            .chars()
            .count(),
        300
    );
    let request = &server.finish()[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.target, "/client/v4/search");
    assert_eq!(request.body, r#"{"query":"workers é"}"#);
    assert!(
        request
            .headers
            .to_ascii_lowercase()
            .contains("content-type: application/json")
    );
    let headers = request.headers.to_ascii_lowercase();
    assert!(
        !headers.contains("authorization:")
            && !headers.contains("x-auth-")
            && !headers.contains("cf-account")
    );
}

#[test]
fn capability_cloudflare_blog_invalid_input_and_endpoint_precede_network() {
    for (name, input) in [
        ("get_post", "{}"),
        ("search_posts", r#"{"query":1}"#),
        ("list_posts", r#"{"limit":0}"#),
    ] {
        let out = run_blog(name, input, "http://example.com", None);
        assert_eq!(out.status.code(), Some(2), "{name}: {:?}", out);
    }
    for endpoint in ["http://example.com", "http://127.0.0.1.evil"] {
        let out = run_blog("list_tags", "{}", endpoint, None);
        assert_eq!(out.status.code(), Some(1), "{endpoint}: {:?}", out);
    }
}

#[test]
fn capability_cloudflare_blog_explicit_empty_outputs() {
    for (name, body, input, expected) in [
        (
            "list_posts",
            r#"{"posts":[],"nextCursor":null}"#,
            "{}",
            r#"{"posts":[],"nextCursor":null}"#,
        ),
        ("list_tags", r#"{"tags":[]}"#, "{}", r#"{"tags":[]}"#),
        (
            "search_posts",
            r#"{"success":true,"result":{"chunks":[]}}"#,
            r#"{"query":"x"}"#,
            r#"{"results":[]}"#,
        ),
    ] {
        let server = Server::start(vec![(200, body)]);
        let out = run_blog(name, input, &server.endpoint, None);
        assert!(out.status.success(), "{name}: {:?}", out);
        assert_eq!(
            json_stdout(&out),
            serde_json::from_str::<Value>(expected).unwrap()
        );
        assert_eq!(server.finish().len(), 1);
    }
}

#[test]
fn capability_cloudflare_blog_bad_responses_are_single_request_failures() {
    let cases = [
        ("get_post", r#"not-json"#),
        ("get_post", r#"{"success":true}"#),
        ("list_posts", r#"{"success":true,"result":[]}"#),
        ("list_tags", r#"{"success":false,"result":{"tags":[]}}"#),
        ("search_posts", r#"{"success":true,"result":{}}"#),
    ];
    for (name, body) in cases {
        let server = Server::start(vec![(200, body)]);
        let input = if name == "search_posts" {
            r#"{"query":"x"}"#
        } else if name == "get_post" {
            r#"{"slug":"x"}"#
        } else {
            "{}"
        };
        let out = run_blog(name, input, &server.endpoint, Some("token"));
        assert!(!out.status.success(), "{name}: {body}");
        assert_eq!(server.finish().len(), 1);
    }
    for name in ["get_post", "list_posts", "list_tags", "search_posts"] {
        let server = Server::start(vec![(500, "{}"); 1]);
        let input = if name == "search_posts" {
            r#"{"query":"x"}"#
        } else if name == "get_post" {
            r#"{"slug":"x"}"#
        } else {
            "{}"
        };
        let out = run_blog(name, input, &server.endpoint, Some("token"));
        assert!(!out.status.success(), "{name}");
        assert_eq!(server.finish().len(), 1);
    }
}

#[test]
fn capability_cloudflare_blog_response_limit_and_redirect_are_hermetic() {
    let oversized: &'static str = Box::leak("x".repeat(8 * 1024 * 1024 + 1).into_boxed_str());
    let server = Server::start(vec![(200, oversized)]);
    let out = run_blog("list_tags", "{}", &server.endpoint, None);
    assert!(!out.status.success());
    assert_eq!(server.finish().len(), 1);

    let server = RedirectServer::start();
    let out = run_blog("list_tags", "{}", &server.endpoint, Some("secret"));
    assert!(!out.status.success());
    assert_eq!(server.finish().len(), 1);
}
