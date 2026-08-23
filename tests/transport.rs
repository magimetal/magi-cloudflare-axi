use std::{
    io::{Read, Write},
    net::TcpListener,
    process::{Command, Output, Stdio},
    sync::{Arc, Mutex},
    thread,
};

use serde_json::Value;
use sha2::{Digest, Sha256};
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
fn capability_list_rags_redirect_refuses_credential_forwarding() {
    let server = RedirectServer::start();
    let (output, _) = run(
        &[
            "--format",
            "json",
            "--account",
            "0123456789abcdef0123456789abcdef",
            "capability",
            "invoke",
            "list_rags",
            "--input",
            "{}",
            "--allow-egress",
        ],
        Some(&server.endpoint),
        Some("redirect-secret"),
    );
    assert!(!output.status.success());
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].contains("redirect-secret"));
}

#[test]
fn capability_list_rags_key_email_auth_has_explicit_headers() {
    let server = Server::start(vec![(
        200,
        r#"{"success":true,"result":[],"result_info":{"total_count":0}}"#,
    )]);
    let dir = tempfile::tempdir().unwrap();
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
            "list_rags",
            "--input",
            "{}",
            "--allow-egress",
        ])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .env("CLOUDFLARE_API_KEY", "key")
        .env("CLOUDFLARE_API_EMAIL", "me@example.com")
        .env_remove("CLOUDFLARE_API_TOKEN")
        .output()
        .unwrap();
    assert!(output.status.success());
    let request = &server.finish()[0];
    assert!(
        request
            .headers
            .to_ascii_lowercase()
            .contains("x-auth-key: key")
    );
    assert!(
        request
            .headers
            .to_ascii_lowercase()
            .contains("x-auth-email: me@example.com")
    );
    assert!(
        !request
            .headers
            .to_ascii_lowercase()
            .contains("authorization:")
    );
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
fn capability_list_rags_exact_request() {
    let server = Server::start(vec![(
        200,
        r#"{"success":true,"result":[{"id":"rag-1","source":"s3","paused":false,"ignored":true}],"result_info":{"total_count":7,"ignored":true},"ignored":true}"#,
    )]);
    let (output, _) = run(
        &[
            "--format",
            "json",
            "--account",
            "0123456789abcdef0123456789abcdef",
            "capability",
            "invoke",
            "list_rags",
            "--input",
            "{}",
            "--allow-egress",
        ],
        Some(&server.endpoint),
        Some("fixture-token"),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        json_stdout(&output),
        serde_json::json!({"autorags":[{"id":"rag-1","source":"s3","paused":false}],"total_count":7})
    );
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(
        requests[0].target,
        "/client/v4/accounts/0123456789abcdef0123456789abcdef/autorag/rags?page=1&per_page=20"
    );
    assert!(requests[0].body.is_empty());
}

#[test]
fn capability_list_rags_supplied_pagination_and_request_headers() {
    let server = Server::start(vec![(
        200,
        r#"{"success":true,"result":[],"result_info":{"total_count":0,"ignored":true},"ignored":true}"#,
    )]);
    let (output, _) = run(
        &[
            "--format",
            "json",
            "--account",
            "0123456789abcdef0123456789abcdef",
            "capability",
            "invoke",
            "list_rags",
            "--input",
            r#"{"page":2,"per_page":50,"unknown":true}"#,
            "--allow-egress",
        ],
        Some(&server.endpoint),
        Some("fixture-token"),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].target,
        "/client/v4/accounts/0123456789abcdef0123456789abcdef/autorag/rags?page=2&per_page=50"
    );
    assert!(requests[0].body.is_empty());
    assert!(
        requests[0]
            .headers
            .to_ascii_lowercase()
            .contains("authorization: bearer fixture-token")
    );
}

#[test]
fn capability_list_rags_empty_result_is_empty_array() {
    let server = Server::start(vec![(
        200,
        r#"{"success":true,"result":[],"result_info":{"total_count":0}}"#,
    )]);
    let (output, _) = run(
        &[
            "--format",
            "json",
            "--account",
            "0123456789abcdef0123456789abcdef",
            "capability",
            "invoke",
            "list_rags",
            "--input",
            "{}",
            "--allow-egress",
        ],
        Some(&server.endpoint),
        Some("token"),
    );
    assert_eq!(
        json_stdout(&output),
        serde_json::json!({"autorags":[],"total_count":0})
    );
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn capability_list_rags_validation_precedes_auth_and_network() {
    for input in [
        r#"{"page":0}"#,
        r#"{"page":1.5}"#,
        r#"{"page":"1"}"#,
        r#"{"page":true}"#,
        r#"{"page":null}"#,
        r#"{"per_page":0}"#,
        r#"{"per_page":51}"#,
        r#"{"per_page":1.5}"#,
        r#"{"per_page":"1"}"#,
        r#"{"per_page":true}"#,
        r#"{"per_page":null}"#,
    ] {
        let (output, _) = run(
            &[
                "--format",
                "json",
                "--account",
                "bad",
                "capability",
                "invoke",
                "list_rags",
                "--input",
                input,
                "--allow-egress",
            ],
            None,
            None,
        );
        assert!(
            !output.status.success(),
            "input unexpectedly accepted: {input}"
        );
    }
}

#[test]
fn capability_list_rags_account_and_egress_guards_precede_network() {
    for args in [
        vec![
            "--format",
            "json",
            "capability",
            "invoke",
            "list_rags",
            "--input",
            "{}",
        ],
        vec![
            "--format",
            "json",
            "--account",
            "one",
            "capability",
            "invoke",
            "list_rags",
            "--input",
            "{}",
        ],
    ] {
        let (output, _) = run(&args, Some("http://127.0.0.1:1/client/v4"), None);
        assert!(!output.status.success());
    }
}

#[test]
fn capability_list_rags_malformed_responses_are_api_failures_once() {
    for body in [
        "not-json",
        "[]",
        r#"{"result":[],"result_info":{"total_count":0}}"#,
        r#"{"success":true,"result":{}}"#,
        r#"{"success":false,"result":[],"result_info":{"total_count":0}}"#,
        r#"{"success":true,"result":[],"result_info":{}}"#,
        r#"{"success":true,"result":[],"result_info":{"total_count":"1"}}"#,
        r#"{"success":true,"result":[1],"result_info":{"total_count":1}}"#,
        r#"{"success":true,"result":[{"id":1,"source":"s","paused":false}],"result_info":{"total_count":1}}"#,
        r#"{"success":true,"result":[{"id":"id","source":1,"paused":false}],"result_info":{"total_count":1}}"#,
        r#"{"success":true,"result":[{"id":"id","source":"s","paused":0}],"result_info":{"total_count":1}}"#,
        r#"{"success":true,"result":[{"id":"id","source":"s"}],"result_info":{"total_count":1}}"#,
        r#"{"success":true,"result":[{"id":"ok","source":"s","paused":false},{"id":"bad","source":1,"paused":false}],"result_info":{"total_count":2}}"#,
    ] {
        let server = Server::start(vec![(200, Box::leak(body.to_owned().into_boxed_str()))]);
        let (output, _) = run(
            &[
                "--format",
                "json",
                "--account",
                "0123456789abcdef0123456789abcdef",
                "capability",
                "invoke",
                "list_rags",
                "--input",
                "{}",
                "--allow-egress",
            ],
            Some(&server.endpoint),
            Some("token"),
        );
        assert!(
            !output.status.success(),
            "response unexpectedly accepted: {body}"
        );
        assert_eq!(server.finish().len(), 1);
    }
}

#[test]
fn capability_list_rags_retries_500_three_times() {
    let server = Server::start(vec![(500, "{}"), (500, "{}"), (500, "{}")]);
    let (output, _) = run(
        &[
            "--format",
            "json",
            "--account",
            "0123456789abcdef0123456789abcdef",
            "capability",
            "invoke",
            "list_rags",
            "--input",
            "{}",
            "--allow-egress",
        ],
        Some(&server.endpoint),
        Some("token-secret"),
    );
    assert!(!output.status.success());
    assert_eq!(server.finish().len(), 3);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("token-secret"));
}

#[test]
fn capability_list_rags_retries_500_then_succeeds() {
    let server = Server::start(vec![
        (500, "{}"),
        (
            200,
            r#"{"success":true,"result":[],"result_info":{"total_count":0}}"#,
        ),
    ]);
    let (output, _) = run(
        &[
            "--format",
            "json",
            "--account",
            "0123456789abcdef0123456789abcdef",
            "capability",
            "invoke",
            "list_rags",
            "--input",
            "{}",
            "--allow-egress",
        ],
        Some(&server.endpoint),
        Some("token"),
    );
    assert!(output.status.success());
    assert_eq!(server.finish().len(), 2);
}

#[test]
fn capability_list_rags_status_redaction_and_response_bound_are_enforced() {
    let args = [
        "--format",
        "json",
        "--account",
        "0123456789abcdef0123456789abcdef",
        "capability",
        "invoke",
        "list_rags",
        "--input",
        "{}",
        "--allow-egress",
    ];
    for (status, kind) in [(400, "api"), (401, "auth")] {
        let server = Server::start(vec![(
            status,
            r#"{"errors":[{"code":"credential-secret","message":"provider-secret-message"}]}"#,
        )]);
        let (output, _) = run(&args, Some(&server.endpoint), Some("credential-secret"));
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(json_stdout(&output)["error"]["type"], kind);
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(!text.contains("provider-secret-message"));
        assert!(!text.contains("credential-secret"));
        assert_eq!(server.finish().len(), 1);
    }

    let server = Server::start(vec![
        (
            429,
            r#"{"errors":[{"code":"credential-secret","message":"provider-secret-message"}]}"#,
        );
        3
    ]);
    let (output, _) = run(&args, Some(&server.endpoint), Some("credential-secret"));
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(json_stdout(&output)["error"]["type"], "network");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(!text.contains("provider-secret-message"));
    assert!(!text.contains("credential-secret"));
    assert_eq!(server.finish().len(), 3);

    let oversized: &'static str = Box::leak("x".repeat(8 * 1024 * 1024 + 1).into_boxed_str());
    let server = Server::start(vec![(200, oversized)]);
    let (output, _) = run(&args, Some(&server.endpoint), Some("token"));
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(json_stdout(&output)["error"]["type"], "network");
    assert_eq!(
        json_stdout(&output)["error"]["message"],
        "response exceeds 8 MiB"
    );
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn capability_list_rags_preserves_numeric_total_count_exactly() {
    let server = Server::start(vec![(
        200,
        r#"{"success":true,"result":[],"result_info":{"total_count":7.5}}"#,
    )]);
    let (output, _) = run(
        &[
            "--format",
            "json",
            "--account",
            "0123456789abcdef0123456789abcdef",
            "capability",
            "invoke",
            "list_rags",
            "--input",
            "{}",
            "--allow-egress",
        ],
        Some(&server.endpoint),
        Some("token"),
    );
    assert!(output.status.success());
    assert_eq!(json_stdout(&output)["total_count"], 7.5);
    assert_eq!(server.finish().len(), 1);
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
fn workers_args(input: &str) -> Vec<&str> {
    let mut args = capability_args("workers_builds_get_build", input);
    args.push("--allow-egress");
    args
}

fn workers_build_response(created_on: &str) -> &'static str {
    let created_on: Value = serde_json::from_str(created_on).unwrap();
    let response = serde_json::json!({
        "success": true,
        "errors": [{"message": "fixture warning", "code": 1001, "ignored": "strip"}],
        "messages": ["fixture message"],
        "result": {
            "build_uuid": "build-not-a-uuid",
            "status": "success",
            "build_outcome": "success",
            "created_on": created_on,
            "modified_on": "2024-01-02T03:04:05.678Z",
            "initializing_on": null,
            "running_on": "2024-01-02T03:04:05Z",
            "stopped_on": null,
            "trigger": {
                "trigger_uuid": "trigger-1",
                "external_script_id": "script-1",
                "trigger_name": "main",
                "build_command": "npm run build",
                "deploy_command": "npm run deploy",
                "root_directory": "/",
                "branch_includes": ["main"],
                "branch_excludes": [],
                "path_includes": [],
                "path_excludes": [],
                "build_caching_enabled": true,
                "created_on": "2024-01-02T03:04:05Z",
                "modified_on": "2024-01-02T03:04:05Z",
                "deleted_on": null,
                "repo_connection": {
                    "repo_connection_uuid": "repo-connection-1",
                    "repo_id": "repo-1",
                    "repo_name": "example",
                    "provider_type": "github",
                    "provider_account_id": "account-1",
                    "provider_account_name": "example-account",
                    "created_on": "2024-01-02T03:04:05Z",
                    "modified_on": "2024-01-02T03:04:05Z",
                    "deleted_on": null,
                    "ignored_repo_field": "strip"
                },
                "ignored_trigger_field": "strip"
            },
            "build_trigger_metadata": {
                "build_trigger_source": "push",
                "branch": "main",
                "commit_hash": "abc123",
                "commit_message": "fixture commit",
                "author": "fixture author",
                "build_command": "npm run build",
                "deploy_command": "npm run deploy",
                "root_directory": "/",
                "build_token_uuid": "build-token-1",
                "environment_variables": {
                    "SECRET_TOKEN": {
                        "is_secret": true,
                        "created_on": "2024-01-02T03:04:05Z",
                        "value": "top-secret",
                        "ignored_variable_field": "strip"
                    },
                    "PUBLIC_VALUE": {
                        "is_secret": false,
                        "created_on": "2024-01-02T03:04:05Z",
                        "value": "public"
                    }
                },
                "repo_name": "example",
                "provider_account_name": "example-account",
                "provider_type": "github",
                "ignored_metadata_field": "strip"
            },
            "pull_request": null,
            "ignored_build_field": "strip"
        },
        "ignored_root_field": "strip"
    });
    Box::leak(serde_json::to_string(&response).unwrap().into_boxed_str())
}
fn workers_build_response_with_change(pointer: &str, replacement: Option<Value>) -> &'static str {
    let mut response: Value =
        serde_json::from_str(workers_build_response(r#""2024-01-01T00:00:00.000Z""#)).unwrap();
    let (parent, field) = pointer.rsplit_once('/').unwrap();
    let object = response
        .pointer_mut(parent)
        .and_then(Value::as_object_mut)
        .unwrap();
    match replacement {
        Some(value) => {
            let _ = object.insert(field.to_owned(), value);
        }
        None => {
            let _ = object.remove(field);
        }
    }
    Box::leak(serde_json::to_string(&response).unwrap().into_boxed_str())
}
fn run_workers_without_auth(
    environment_endpoint: Option<&str>,
    global_endpoint: Option<&str>,
) -> (Output, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let xdg = dir.path().join("xdg");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&xdg).unwrap();
    if let Some(endpoint) = global_endpoint {
        let global = xdg.join("cloudflare");
        std::fs::create_dir_all(&global).unwrap();
        std::fs::write(
            global.join("cloudflare-axi.toml"),
            format!("endpoint = {endpoint:?}\n"),
        )
        .unwrap();
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"));
    command
        .args([
            "--format",
            "json",
            "--account",
            TEST_ACCOUNT,
            "capability",
            "invoke",
            "workers_builds_get_build",
            "--input",
            r#"{"buildUUID":"build-not-a-uuid"}"#,
            "--allow-egress",
        ])
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
        command.env_remove(key);
    }
    if let Some(endpoint) = environment_endpoint {
        command.env("CLOUDFLARE_ENDPOINT", endpoint);
    }
    (command.output().unwrap(), dir)
}

fn run_workers_with_account_source(source: &str, account: &str) -> Output {
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().join("home");
    let xdg = directory.path().join("xdg");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&xdg).unwrap();
    if source == "global" {
        std::fs::create_dir_all(xdg.join("cloudflare")).unwrap();
        let serialized = serde_json::to_string(account).unwrap();
        std::fs::write(
            xdg.join("cloudflare/cloudflare-axi.toml"),
            format!("account_id = {serialized}\n"),
        )
        .unwrap();
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"));
    command
        .args([
            "--format",
            "json",
            "--endpoint",
            "http://127.0.0.1:1/client/v4",
        ])
        .current_dir(directory.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("CLOUDFLARE_API_TOKEN", "fixture-token");
    for key in [
        "CLOUDFLARE_API_BASE",
        "CLOUDFLARE_ENDPOINT",
        "CLOUDFLARE_API_KEY",
        "CLOUDFLARE_API_EMAIL",
        "CLOUDFLARE_ACCOUNT_ID",
        "CLOUDFLARE_ACOUNT_ID",
        "CLOUDFLARE_ZONE_ID",
    ] {
        command.env_remove(key);
    }
    if source == "cli" {
        command.args(["--account", account]);
    } else if source == "environment" {
        command.env("CLOUDFLARE_ACCOUNT_ID", account);
    }
    command
        .args([
            "capability",
            "invoke",
            "workers_builds_get_build",
            "--input",
            r#"{"buildUUID":"build-not-a-uuid"}"#,
            "--allow-egress",
        ])
        .output()
        .unwrap()
}

fn workers_oversized_response() -> &'static str {
    let mut response =
        String::from(r#"{"success":true,"errors":[],"messages":[],"result":null,"padding":"#);
    response.push_str(&"x".repeat(8 * 1024 * 1024 + 1));
    response.push_str(r#""}"#);
    Box::leak(response.into_boxed_str())
}

#[test]
fn capability_workers_builds_get_build_exact_request() {
    let server = Server::start(vec![(
        200,
        workers_build_response(r#""2024-01-01T00:00:00.123Z""#),
    )]);
    let (output, _) = run(
        &workers_args(r#"{"buildUUID":"build-not-a-uuid","unknown":true}"#),
        Some(&server.endpoint),
        Some("fixture-token"),
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        json_stdout(&output),
        serde_json::json!({
            "buildUUID": "build-not-a-uuid",
            "createdOn": "2024-01-01T00:00:00.123Z",
            "status": "success",
            "buildOutcome": "success",
            "branch": "main",
            "commitHash": "abc123",
            "commitMessage": "fixture commit",
            "commitAuthor": "fixture author",
            "buildCommand": "npm run build",
            "deployCommand": "npm run deploy"
        })
    );
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(
        requests[0].target,
        "/client/v4/accounts/account-123/builds/builds/build-not-a-uuid"
    );
    assert!(requests[0].body.is_empty());
    let headers = requests[0].headers.to_ascii_lowercase();
    assert!(headers.contains("authorization: bearer fixture-token"));
    assert!(!headers.contains("content-type:"));
    let output_text = String::from_utf8_lossy(&output.stdout);
    assert!(!output_text.contains("top-secret"));
    assert!(!output_text.contains("environment_variables"));
}

#[test]
fn capability_workers_builds_get_build_key_email_auth_has_explicit_headers() {
    let server = Server::start(vec![(
        200,
        r#"{"success":true,"errors":[],"messages":[],"result":null}"#,
    )]);
    let directory = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"))
        .args([
            "--format",
            "json",
            "--endpoint",
            server.endpoint.as_str(),
            "--account",
            TEST_ACCOUNT,
            "capability",
            "invoke",
            "workers_builds_get_build",
            "--input",
            r#"{"buildUUID":"build-not-a-uuid"}"#,
            "--allow-egress",
        ])
        .current_dir(directory.path())
        .env("HOME", directory.path())
        .env("XDG_CONFIG_HOME", directory.path())
        .env_remove("CLOUDFLARE_API_BASE")
        .env_remove("CLOUDFLARE_ENDPOINT")
        .env_remove("CLOUDFLARE_API_TOKEN")
        .env("CLOUDFLARE_API_KEY", "fixture-key")
        .env("CLOUDFLARE_API_EMAIL", "fixture@example.invalid")
        .env_remove("CLOUDFLARE_ACCOUNT_ID")
        .env_remove("CLOUDFLARE_ACOUNT_ID")
        .env_remove("CLOUDFLARE_ZONE_ID")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    let headers = requests[0].headers.to_ascii_lowercase();
    assert!(headers.contains("x-auth-key: fixture-key"));
    assert!(headers.contains("x-auth-email: fixture@example.invalid"));
    assert!(!headers.contains("authorization:"));
}

#[test]
fn capability_workers_builds_get_build_accepts_iso_and_numeric_dates() {
    for (created_on, expected) in [
        (
            r#""2024-01-01T02:00:00.123+02:00""#,
            "2024-01-01T00:00:00.123Z",
        ),
        ("1704067200123", "2024-01-01T00:00:00.123Z"),
    ] {
        let server = Server::start(vec![(200, workers_build_response(created_on))]);
        let (output, _) = run(
            &workers_args(r#"{"buildUUID":"build-not-a-uuid"}"#),
            Some(&server.endpoint),
            Some("fixture-token"),
        );
        assert!(output.status.success(), "{output:?}");
        assert_eq!(json_stdout(&output)["createdOn"], expected);
        assert_eq!(server.finish().len(), 1);
    }
}
#[test]
fn capability_workers_builds_get_build_null_result_is_json_null() {
    let server = Server::start(vec![(
        200,
        r#"{"success":true,"errors":[],"messages":[],"result":null,"ignored":true}"#,
    )]);
    let (output, _) = run(
        &workers_args(r#"{"buildUUID":"build-not-a-uuid"}"#),
        Some(&server.endpoint),
        Some("fixture-token"),
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(json_stdout(&output), Value::Null);
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn capability_workers_builds_get_build_rejects_malformed_full_responses() {
    let cases = vec![
        ("success", "/success", Some(serde_json::json!(false)), false),
        ("errors type", "/errors", Some(serde_json::json!({})), false),
        (
            "error entry type",
            "/errors",
            Some(serde_json::json!(["not-an-object"])),
            false,
        ),
        (
            "error message type",
            "/errors/0/message",
            Some(serde_json::json!(1001)),
            false,
        ),
        ("error message required", "/errors/0/message", None, false),
        (
            "error code type",
            "/errors/0/code",
            Some(serde_json::json!("1001")),
            false,
        ),
        (
            "messages type",
            "/messages",
            Some(serde_json::json!({})),
            false,
        ),
        (
            "result type",
            "/result",
            Some(serde_json::json!("not-an-object")),
            false,
        ),
        ("pull request required", "/result/pull_request", None, false),
        (
            "unknown pull request value",
            "/result/pull_request",
            Some(serde_json::json!({"provider_shape": [true, null]})),
            true,
        ),
        (
            "build UUID type",
            "/result/build_uuid",
            Some(serde_json::json!(false)),
            false,
        ),
        (
            "status type",
            "/result/status",
            Some(serde_json::json!(false)),
            false,
        ),
        (
            "build outcome nullable type",
            "/result/build_outcome",
            Some(serde_json::json!(false)),
            false,
        ),
        (
            "created date type",
            "/result/created_on",
            Some(serde_json::json!(null)),
            false,
        ),
        (
            "modified date type",
            "/result/modified_on",
            Some(serde_json::json!(null)),
            false,
        ),
        (
            "initializing nullable date type",
            "/result/initializing_on",
            Some(serde_json::json!(false)),
            false,
        ),
        (
            "running nullable date type",
            "/result/running_on",
            Some(serde_json::json!(false)),
            false,
        ),
        (
            "stopped nullable date type",
            "/result/stopped_on",
            Some(serde_json::json!(false)),
            false,
        ),
        (
            "trigger object type",
            "/result/trigger",
            Some(serde_json::json!("not-an-object")),
            false,
        ),
        (
            "trigger string type",
            "/result/trigger/trigger_uuid",
            Some(serde_json::json!(false)),
            false,
        ),
        (
            "trigger array type",
            "/result/trigger/branch_includes",
            Some(serde_json::json!("main")),
            false,
        ),
        (
            "trigger array item type",
            "/result/trigger/branch_excludes",
            Some(serde_json::json!([false])),
            false,
        ),
        (
            "trigger boolean type",
            "/result/trigger/build_caching_enabled",
            Some(serde_json::json!("true")),
            false,
        ),
        (
            "trigger date type",
            "/result/trigger/created_on",
            Some(serde_json::json!(null)),
            false,
        ),
        (
            "trigger nullable date type",
            "/result/trigger/deleted_on",
            Some(serde_json::json!(false)),
            false,
        ),
        (
            "repo connection object type",
            "/result/trigger/repo_connection",
            Some(serde_json::json!([])),
            false,
        ),
        (
            "repo connection string type",
            "/result/trigger/repo_connection/repo_id",
            Some(serde_json::json!(false)),
            false,
        ),
        (
            "repo connection date type",
            "/result/trigger/repo_connection/created_on",
            Some(serde_json::json!(null)),
            false,
        ),
        (
            "repo connection nullable date type",
            "/result/trigger/repo_connection/deleted_on",
            Some(serde_json::json!(false)),
            false,
        ),
        (
            "build metadata object type",
            "/result/build_trigger_metadata",
            Some(serde_json::json!([])),
            false,
        ),
        (
            "build metadata string type",
            "/result/build_trigger_metadata/branch",
            Some(serde_json::json!(false)),
            false,
        ),
        (
            "environment variables object type",
            "/result/build_trigger_metadata/environment_variables",
            Some(serde_json::json!([])),
            false,
        ),
        (
            "environment variable record type",
            "/result/build_trigger_metadata/environment_variables/SECRET_TOKEN",
            Some(serde_json::json!("not-an-object")),
            false,
        ),
        (
            "environment variable boolean type",
            "/result/build_trigger_metadata/environment_variables/SECRET_TOKEN/is_secret",
            Some(serde_json::json!("true")),
            false,
        ),
        (
            "environment variable date type",
            "/result/build_trigger_metadata/environment_variables/SECRET_TOKEN/created_on",
            Some(serde_json::json!(null)),
            false,
        ),
        (
            "environment variable nullable value type",
            "/result/build_trigger_metadata/environment_variables/SECRET_TOKEN/value",
            Some(serde_json::json!(false)),
            false,
        ),
    ];
    for (label, pointer, replacement, expected_success) in cases {
        let body = workers_build_response_with_change(pointer, replacement);
        let server = Server::start(vec![(200, body)]);
        let (output, _) = run(
            &workers_args(r#"{"buildUUID":"build-not-a-uuid"}"#),
            Some(&server.endpoint),
            Some("fixture-token"),
        );
        assert_eq!(
            output.status.success(),
            expected_success,
            "{label}: {output:?}"
        );
        if expected_success {
            let projected = json_stdout(&output);
            assert_eq!(projected["buildUUID"], "build-not-a-uuid", "{label}");
            assert_eq!(
                projected["createdOn"], "2024-01-01T00:00:00.000Z",
                "{label}"
            );
            assert!(
                !projected.to_string().contains("environment_variables"),
                "{label}"
            );
        } else {
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("malformed"),
                "{label}: {output:?}"
            );
        }
        assert_eq!(server.finish().len(), 1, "{label}");
    }
}
#[test]
fn capability_workers_builds_get_build_preflight_guards_and_path_limits() {
    assert_usage_before_network(
        &capability_args(
            "workers_builds_get_build",
            r#"{"buildUUID":"build-not-a-uuid"}"#,
        ),
        "--allow-egress",
    );
    assert_usage_before_network(&workers_args(r#"{"buildUUID":"bad/path"}"#), "buildUUID");
    for build_uuid in [" leading", "trailing ", "\t", "\n", "\r", "\u{0000}"] {
        let input = serde_json::json!({"buildUUID": build_uuid}).to_string();
        assert_usage_before_network(&workers_args(&input), "buildUUID");
    }
    let too_long = format!(r#"{{"buildUUID":"{}"}}"#, "x".repeat(257));
    assert_usage_before_network(&workers_args(&too_long), "buildUUID");
    assert_usage_before_network(
        &workers_args(r#"{"buildUUID":"build-not-a-uuid","account_id":"other"}"#),
        "conflicts with resolved account scope",
    );
}

#[test]
fn capability_workers_builds_get_build_rejects_resolved_account_whitespace_and_control_before_auth_or_network()
 {
    for source in ["cli", "environment", "global"] {
        for account in ["account with space", "account\u{0007}with-control"] {
            let output = run_workers_with_account_source(source, account);
            assert_eq!(output.status.code(), Some(2), "{source} {account:?}");
            let error = json_stdout(&output)["error"].clone();
            assert_eq!(error["type"], "usage", "{source} {account:?}");
            assert!(
                error["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("account_id must be one safe")),
                "{source} {account:?}: {error}"
            );
            assert_ne!(error["type"], "auth", "{source} {account:?}");
            assert_ne!(error["type"], "network", "{source} {account:?}");
        }
    }
}

#[test]
fn capability_workers_builds_get_build_validates_resolved_endpoint_before_auth() {
    for (source, environment_endpoint, global_endpoint) in [
        ("environment", Some("http://example.com/client/v4"), None),
        ("global config", None, Some("http://example.com/client/v4")),
    ] {
        let (output, _directory) = run_workers_without_auth(environment_endpoint, global_endpoint);
        let text = String::from_utf8_lossy(&output.stdout);
        assert_eq!(output.status.code(), Some(1), "{source}: {text}");
        assert!(
            text.contains("HTTPS") || text.contains("invalid API endpoint"),
            "{source}: {text}"
        );
        assert!(!text.contains("CLOUDFLARE_API_TOKEN"), "{source}: {text}");
    }
}

#[test]
fn capability_workers_builds_get_build_status_retry_redaction_and_redirects() {
    let failure = r#"{"errors":[{"code":"fixture-token","message":"failure"}]}"#;
    let server = Server::start(vec![(500, failure), (500, failure), (500, failure)]);
    let (output, _) = run(
        &workers_args(r#"{"buildUUID":"build-not-a-uuid"}"#),
        Some(&server.endpoint),
        Some("fixture-token"),
    );
    assert!(!output.status.success());
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!text.contains("fixture-token"));
    assert_eq!(server.finish().len(), 3);

    let server = Server::start(vec![(400, failure)]);
    let (output, _) = run(
        &workers_args(r#"{"buildUUID":"build-not-a-uuid"}"#),
        Some(&server.endpoint),
        Some("fixture-token"),
    );
    assert!(!output.status.success());
    assert_eq!(server.finish().len(), 1);

    let server = RedirectServer::start();
    let (output, _) = run(
        &workers_args(r#"{"buildUUID":"build-not-a-uuid"}"#),
        Some(&server.endpoint),
        Some("fixture-token"),
    );
    assert!(!output.status.success());
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn capability_workers_builds_get_build_response_bound_is_enforced() {
    let server = Server::start(vec![(200, workers_oversized_response())]);
    let (output, _) = run(
        &workers_args(r#"{"buildUUID":"build-not-a-uuid"}"#),
        Some(&server.endpoint),
        Some("fixture-token"),
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("response exceeds 8 MiB"));
    assert_eq!(server.finish().len(), 1);
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
fn capability_list_browser_sessions_exact_request() {
    let (out, _) = run(
        &capability_args("list_browser_sessions", "{}"),
        Some("http://127.0.0.1:1"),
        Some("token"),
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stdout).contains("--allow-egress"));

    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join(".cloudflare-axi.toml"),
        "account_id = 'configured'\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"))
        .args([
            "--format",
            "json",
            "--endpoint",
            "http://127.0.0.1:1",
            "capability",
            "invoke",
            "list_browser_sessions",
            "--input",
            r#"{"account_id":"provided"}"#,
            "--allow-egress",
        ])
        .current_dir(directory.path())
        .env("HOME", directory.path())
        .env("XDG_CONFIG_HOME", directory.path())
        .env_remove("CLOUDFLARE_API_TOKEN")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("conflicts with resolved account scope")
    );

    for (response, expected) in [
        (
            r#"[{"id":"session-1","custom":{"state":"ready"}}]"#,
            serde_json::json!([{"id":"session-1","custom":{"state":"ready"}}]),
        ),
        (
            r#"{"result":[{"id":"session-1","custom":{"state":"ready"}}]}"#,
            serde_json::json!([{"id":"session-1","custom":{"state":"ready"}}]),
        ),
        (r#"[]"#, serde_json::json!([])),
        (r#"{"result":[]}"#, serde_json::json!([])),
    ] {
        let server = Server::start(vec![(200, response)]);
        let mut args = capability_args("list_browser_sessions", "{}");
        args.push("--allow-egress");
        let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
        assert!(out.status.success(), "{out:?}");
        assert_eq!(json_stdout(&out), expected);
        let requests = server.finish();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "GET");
        assert_eq!(
            requests[0].target,
            format!("/client/v4/accounts/{TEST_ACCOUNT}/browser-run/devtools/session")
        );
        let headers = requests[0].headers.to_ascii_lowercase();
        assert!(headers.contains("authorization: bearer token"));
        assert!(!headers.contains("content-type:"));
        assert!(requests[0].body.is_empty());
    }

    for response in [
        "not-json",
        r#"{"result":{}}"#,
        r#"{}"#,
        r#"{"success":false,"errors":[],"result":[]}"#,
        r#"{"success":true,"errors":[{"code":1000}],"result":[]}"#,
    ] {
        let server = Server::start(vec![(200, response)]);
        let mut args = capability_args("list_browser_sessions", "{}");
        args.push("--allow-egress");
        let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
        assert!(!out.status.success(), "accepted {response}");
        assert_eq!(server.finish().len(), 1);
    }

    let mut args = capability_args("list_browser_sessions", "{}");
    args.push("--allow-egress");
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

#[derive(Clone)]
struct BinaryResponse {
    status: u16,
    content_type: Option<&'static str>,
    body: Vec<u8>,
    headers: Vec<(&'static str, &'static str)>,
}

struct BinaryServer {
    endpoint: String,
    requests: Arc<Mutex<Vec<Request>>>,
    join: Option<thread::JoinHandle<()>>,
}

impl BinaryServer {
    fn start(responses: Vec<BinaryResponse>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/client/v4", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        let join = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut bytes = Vec::new();
                let mut chunk = [0; 4096];
                let header_end = loop {
                    let n = stream.read(&mut chunk).unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&bytes[..header_end]).into_owned();
                let first = headers
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .collect::<Vec<_>>();
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|v| v.trim().parse().ok())
                    })
                    .unwrap_or(0);
                while bytes.len() < header_end + length {
                    let n = stream.read(&mut chunk).unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&chunk[..n]);
                }
                seen.lock().unwrap().push(Request {
                    method: first[0].into(),
                    target: first[1].into(),
                    headers,
                    body: String::from_utf8_lossy(&bytes[header_end..header_end + length])
                        .into_owned(),
                });
                let mut wire = format!(
                    "HTTP/1.1 {} Test\r\nContent-Length: {}\r\nConnection: close\r\n",
                    response.status,
                    response.body.len()
                );
                if let Some(content_type) = response.content_type {
                    wire.push_str(&format!("Content-Type: {content_type}\r\n"));
                }
                for (name, value) in response.headers {
                    wire.push_str(&format!("{name}: {value}\r\n"));
                }
                wire.push_str("\r\n");
                stream.write_all(wire.as_bytes()).unwrap();
                stream.write_all(&response.body).unwrap();
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

fn binary_response(status: u16, content_type: &'static str, body: &[u8]) -> BinaryResponse {
    BinaryResponse {
        status,
        content_type: Some(content_type),
        body: body.to_vec(),
        headers: vec![],
    }
}

fn binary_response_without_content_type(status: u16, body: &[u8]) -> BinaryResponse {
    BinaryResponse {
        status,
        content_type: None,
        body: body.to_vec(),
        headers: vec![],
    }
}

fn binary_args<'a>(name: &'a str, input: &'a str, output: &'a str) -> Vec<&'a str> {
    let mut args = browser_args(name, input);
    args.extend(["--output", output]);
    args
}

#[test]
fn capability_get_url_pdf_exact_request() {
    let body = b"%PDF-\0binary\xff";
    let server = BinaryServer::start(vec![binary_response(200, "application/pdf", body)]);
    let (out, dir) = run(
        &binary_args(
            "get_url_pdf",
            r#"{"url":"  https://example.com/path  "}"#,
            "result.pdf",
        ),
        Some(&server.endpoint),
        Some("token"),
    );
    assert!(out.status.success(), "{out:?}");
    assert!(out.stderr.is_empty());
    assert_eq!(std::fs::read(dir.path().join("result.pdf")).unwrap(), body);
    let metadata = json_stdout(&out)["artifact"].clone();
    assert_eq!(metadata["bytes"], body.len());
    assert_eq!(metadata["media_type"], "application/pdf");
    assert_eq!(metadata["sha256"], format!("{:x}", Sha256::digest(body)));
    assert_eq!(metadata["path"], "result.pdf");
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert_binary_request(
        &requests[0],
        "pdf",
        serde_json::json!({"url":"https://example.com/path"}),
    );
}
#[test]
fn capability_get_url_screenshot_exact_request() {
    let body = b"\x89PNG\r\n\x1a\n\0\xff";
    for (input, expected) in [
        (
            r#"{"url":"https://example.com"}"#,
            serde_json::json!({"url":"https://example.com"}),
        ),
        (
            r#"{"url":"https://example.com","viewport":{}}"#,
            serde_json::json!({"url":"https://example.com","viewport":{"width":800,"height":600}}),
        ),
        (
            r#"{"url":"https://example.com","viewport":{"width":800}}"#,
            serde_json::json!({"url":"https://example.com","viewport":{"width":800,"height":600}}),
        ),
        (
            r#"{"url":"https://example.com","viewport":{"width":800,"height":600}}"#,
            serde_json::json!({"url":"https://example.com","viewport":{"width":800,"height":600}}),
        ),
        (
            r#"{"url":"https://example.com","viewport":{"width":800,"unknown":true}}"#,
            serde_json::json!({"url":"https://example.com","viewport":{"width":800,"height":600}}),
        ),
    ] {
        let server = BinaryServer::start(vec![binary_response(200, "image/png", body)]);
        let (out, dir) = run(
            &binary_args("get_url_screenshot", input, "shot.png"),
            Some(&server.endpoint),
            Some("token"),
        );
        assert!(out.status.success(), "{out:?}");
        assert!(out.stderr.is_empty());
        assert_eq!(std::fs::read(dir.path().join("shot.png")).unwrap(), body);
        let artifact = &json_stdout(&out)["artifact"];
        assert_eq!(artifact["bytes"], body.len());
        assert_eq!(artifact["media_type"], "image/png");
        assert_eq!(artifact["sha256"], format!("{:x}", Sha256::digest(body)));
        assert_eq!(artifact["path"], "shot.png");
        let requests = server.finish();
        assert_eq!(requests.len(), 1);
        assert_binary_request(&requests[0], "screenshot", expected.clone());
    }
}
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn assert_binary_request(request: &Request, suffix: &str, body: Value) {
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

fn assert_no_artifact(dir: &TempDir, output: &str) {
    assert!(!dir.path().join(output).exists(), "destination created");
    let entries = std::fs::read_dir(dir.path())
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(entries.iter().all(|entry| {
        let name = entry.file_name();
        !name.to_string_lossy().contains(".tmp-")
    }));
}

#[test]
fn binary_success_asserts_transport_metadata_and_permissions() {
    let pdf = b"%PDF-1.7\nfixture";
    let server = BinaryServer::start(vec![binary_response(200, "APPLICATION/PDF", pdf)]);
    let (out, dir) = run(
        &binary_args(
            "get_url_pdf",
            r#"{"url":"https://example.com"}"#,
            "result.pdf",
        ),
        Some(&server.endpoint),
        Some("token"),
    );
    assert!(out.status.success(), "{out:?}");
    let path = dir.path().join("result.pdf");
    assert_eq!(std::fs::read(&path).unwrap(), pdf);
    let artifact = &json_stdout(&out)["artifact"];
    assert_eq!(artifact["bytes"], pdf.len());
    assert_eq!(artifact["media_type"], "application/pdf");
    assert_eq!(artifact["sha256"], format!("{:x}", Sha256::digest(pdf)));
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert_binary_request(
        &requests[0],
        "pdf",
        serde_json::json!({"url":"https://example.com"}),
    );
    #[cfg(unix)]
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn binary_preflight_with_output_has_no_network_or_artifact() {
    for omitted in ["--allow-metered", "--allow-egress", "--allow-long-running"] {
        let mut args = binary_args(
            "get_url_pdf",
            r#"{"url":"https://example.com"}"#,
            "result.pdf",
        );
        args.retain(|argument| *argument != omitted);
        let (out, dir) = run(&args, Some("http://127.0.0.1:1"), None);
        assert_eq!(out.status.code(), Some(2), "{omitted}: {out:?}");
        assert!(String::from_utf8_lossy(&out.stdout).contains(omitted));
        assert_no_artifact(&dir, "result.pdf");
    }
    let (out, dir) = run(
        &browser_args("get_url_pdf", r#"{"url":"https://example.com"}"#),
        Some("http://127.0.0.1:1"),
        None,
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stdout).contains("require explicit --output"));
    assert_no_artifact(&dir, "result.pdf");

    let mut non_binary = browser_args("get_url_markdown", r#"{"url":"https://example.com"}"#);
    non_binary.extend(["--output", "result.pdf"]);
    let (out, dir) = run(&non_binary, Some("http://127.0.0.1:1"), None);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stdout).contains("only for binary capabilities"));
    assert_no_artifact(&dir, "result.pdf");

    for output in ["-", "missing/parent/result.pdf"] {
        let (out, dir) = run(
            &binary_args("get_url_pdf", r#"{"url":"https://example.com"}"#, output),
            Some("http://127.0.0.1:1"),
            None,
        );
        assert_eq!(out.status.code(), Some(2), "{output}: {out:?}");
        assert_no_artifact(&dir, "result.pdf");
    }
    let dir = tempfile::tempdir().unwrap();
    let destination = dir.path().join("existing.pdf");
    std::fs::write(&destination, b"keep").unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"));
    command
        .args(binary_args(
            "get_url_pdf",
            r#"{"url":"https://example.com"}"#,
            destination.to_str().unwrap(),
        ))
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .env_remove("CLOUDFLARE_API_TOKEN");
    assert!(!command.output().unwrap().status.success());
    assert_eq!(std::fs::read(&destination).unwrap(), b"keep");
    for name in ["get_url_pdf", "get_url_screenshot"] {
        let (out, dir) = run(
            &binary_args(name, r#"{"url":"relative/path"}"#, "result.bin"),
            Some("http://127.0.0.1:1"),
            None,
        );
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stdout).contains("url must be valid"));
        assert_no_artifact(&dir, "result.bin");
        let (out, dir) = run(
            &binary_args(
                name,
                r#"{"url":"https://example.com","account_id":"provided"}"#,
                "result.bin",
            ),
            Some("http://127.0.0.1:1"),
            None,
        );
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stdout).contains("conflicts"));
        assert_no_artifact(&dir, "result.bin");
    }
}

#[test]
fn binary_oversized_response_leaves_no_destination() {
    let body: &'static [u8] = Box::leak(vec![b'x'; 8 * 1024 * 1024 + 1].into_boxed_slice());
    let server = BinaryServer::start(vec![binary_response(200, "application/pdf", body)]);
    let (out, dir) = run(
        &binary_args(
            "get_url_pdf",
            r#"{"url":"https://example.com"}"#,
            "result.pdf",
        ),
        Some(&server.endpoint),
        Some("token"),
    );
    assert!(!out.status.success());
    assert_no_artifact(&dir, "result.pdf");
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn oversized_binary_error_responses_preserve_status_classification() {
    let body: &'static [u8] = Box::leak(vec![b'x'; 8 * 1024 * 1024 + 1].into_boxed_slice());
    for (status, kind) in [(401, "auth"), (429, "network"), (500, "api")] {
        let server = BinaryServer::start(vec![binary_response(status, "application/json", body)]);
        let (out, dir) = run(
            &binary_args(
                "get_url_pdf",
                r#"{"url":"https://example.com"}"#,
                "result.pdf",
            ),
            Some(&server.endpoint),
            Some("token"),
        );
        assert_eq!(out.status.code(), Some(1));
        assert_eq!(json_stdout(&out)["error"]["type"], kind);
        assert_no_artifact(&dir, "result.pdf");
        assert_eq!(server.finish().len(), 1);
    }
}

#[test]
fn binary_failure_paths_are_single_request_and_leave_no_files() {
    let valid = b"%PDF-1.7\nvalid";
    let cases = vec![
        ("get_url_pdf", binary_response(200, "text/plain", valid)),
        (
            "get_url_pdf",
            binary_response_without_content_type(200, valid),
        ),
        (
            "get_url_pdf",
            binary_response(200, "application/pdf", b"bad"),
        ),
        ("get_url_pdf", binary_response(200, "application/pdf", b"")),
        (
            "get_url_pdf",
            binary_response(200, "application/pdf", b"%PDF"),
        ),
        (
            "get_url_screenshot",
            binary_response(200, "image/png", b"\x89PNG\r\n\x1a"),
        ),
        (
            "get_url_pdf",
            binary_response(400, "application/pdf", valid),
        ),
        (
            "get_url_pdf",
            binary_response(500, "application/pdf", valid),
        ),
    ];
    for (name, response) in cases {
        let server = BinaryServer::start(vec![response]);
        let (out, dir) = run(
            &binary_args(name, r#"{"url":"https://example.com"}"#, "result.pdf"),
            Some(&server.endpoint),
            Some("token"),
        );
        assert!(!out.status.success());
        assert_no_artifact(&dir, "result.pdf");
        assert_eq!(server.finish().len(), 1);
    }
}

#[test]
fn binary_redirect_is_rejected_without_forwarding_credentials() {
    let server = RedirectServer::start();
    let (out, _) = run(
        &binary_args(
            "get_url_pdf",
            r#"{"url":"https://example.com"}"#,
            "result.pdf",
        ),
        Some(&server.endpoint),
        Some("secret"),
    );
    assert!(!out.status.success());
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].contains("secret"));
}

#[test]
fn capability_logpush_jobs_by_account_id_exact_request() {
    let input = r#"{"account_id":"account-123","ignored":true}"#;
    let mut args = capability_args("logpush_jobs_by_account_id", input);
    args.push("--allow-egress");

    let without_egress = capability_args("logpush_jobs_by_account_id", input);
    let (out, _) = run(&without_egress, Some("http://example.com"), None);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(json_stdout(&out)["error"]["type"], "usage");

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".cloudflare-axi.toml"),
        "account_id = 'configured'",
    )
    .unwrap();
    let conflict = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"))
        .args([
            "--format",
            "json",
            "--endpoint",
            "http://127.0.0.1:1",
            "capability",
            "invoke",
            "logpush_jobs_by_account_id",
            "--input",
            r#"{"account_id":"provided"}"#,
            "--allow-egress",
        ])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .env_remove("CLOUDFLARE_API_TOKEN")
        .output()
        .unwrap();
    assert_eq!(conflict.status.code(), Some(2));
    assert_eq!(
        json_stdout(&conflict)["error"]["message"],
        "input account_id conflicts with resolved account scope"
    );

    for account in ["../bad", "bad/account", "bad%2Faccount", &"x".repeat(33)] {
        let input = format!(r#"{{"account_id":"{account}"}}"#);
        let mut invalid_args = capability_args("logpush_jobs_by_account_id", &input);
        invalid_args.push("--allow-egress");
        let (out, _) = run(&invalid_args, Some("http://127.0.0.1:1"), Some("token"));
        assert_eq!(out.status.code(), Some(2), "{account}");
        assert_eq!(json_stdout(&out)["error"]["type"], "usage");
    }

    let valid_job = r#"{"id":1,"enabled":true,"name":"job-1","dataset":"http_requests","last_complete":"2024-01-02T03:04:05Z","last_error":null,"error_message":null,"credential":"secret"}"#;
    let success: &'static str = Box::leak(
        format!(r#"{{"success":true,"errors":[],"result":[{valid_job}]}}"#).into_boxed_str(),
    );
    let server = Server::start(vec![(200, success)]);
    let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        json_stdout(&out),
        serde_json::json!({"result":[{"id":1,"enabled":true,"name":"job-1","dataset":"http_requests","last_complete":"2024-01-02T03:04:05Z","last_error":null,"error_message":null}]})
    );
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(
        requests[0].target,
        "/client/v4/accounts/account-123/logpush/jobs"
    );
    assert!(requests[0].body.is_empty());
    let headers = requests[0].headers.to_ascii_lowercase();
    assert!(headers.contains("authorization: bearer token"));
    assert!(headers.contains("content-type: application/json"));
    assert!(headers.contains("portal-version: 2"));
    assert!(!requests[0].target.contains('?'));

    for response in [r#"{"success":true,"errors":[]}"#, r#"{"success":true}"#] {
        let server = Server::start(vec![(200, response)]);
        let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
        assert!(out.status.success(), "{response}: {out:?}");
        assert_eq!(json_stdout(&out), serde_json::json!({"result":[]}));
        assert_eq!(server.finish().len(), 1);
    }

    let nullable = r#"{"success":true,"result":[null,{"name":null,"dataset":null,"last_complete":null,"last_error":null,"error_message":null,"unknown":true}]}"#;
    let server = Server::start(vec![(200, nullable)]);
    let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        json_stdout(&out),
        serde_json::json!({"result":[null,{"name":null,"dataset":null,"last_complete":null,"last_error":null,"error_message":null}]})
    );
    assert_eq!(server.finish().len(), 1);

    for timestamp in [
        "2024-01-02T03:04Z",
        "2024-01-02T03:04:05Z",
        "2024-01-02T03:04:05.1Z",
        "2024-02-29T23:59:59.123456Z",
    ] {
        let body: &'static str = Box::leak(
            format!(r#"{{"success":true,"result":[{{"last_complete":"{timestamp}","last_error":"{timestamp}"}}]}}"#)
                .into_boxed_str(),
        );
        let server = Server::start(vec![(200, body)]);
        let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
        assert!(out.status.success(), "rejected {timestamp}: {out:?}");
        assert_eq!(server.finish().len(), 1);
    }
    for timestamp in [
        "2023-02-29T03:04Z",
        "2024-01-02T24:00Z",
        "2024-01-02T03:60Z",
        "2024-01-02T03:04:60Z",
        "2024-01-02T03:04:05:06Z",
        "2024-01-02T03:04.1Z",
        "2024-01-02T03:04:05.Z",
        "2024-01-02T03:04:05+00:00",
    ] {
        let body: &'static str = Box::leak(
            format!(r#"{{"success":true,"result":[{{"last_complete":"{timestamp}"}}]}}"#)
                .into_boxed_str(),
        );
        let server = Server::start(vec![(200, body)]);
        let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
        assert_eq!(out.status.code(), Some(1), "accepted {timestamp}");
        let error = json_stdout(&out);
        assert_eq!(error["error"]["type"], "api");
        assert_eq!(error["error"]["code"], 1);
        assert_eq!(
            error["error"]["message"],
            "logpush job last_complete is not valid UTC RFC3339"
        );
        assert_eq!(server.finish().len(), 1);
    }

    for id in ["1", "1.0", "1e0", "9007199254740991"] {
        let body: &'static str =
            Box::leak(format!(r#"{{"success":true,"result":[{{"id":{id}}}]}}"#).into_boxed_str());
        let server = Server::start(vec![(200, body)]);
        let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
        assert!(out.status.success(), "rejected {id}: {out:?}");
        let expected = if id == "9007199254740991" {
            9_007_199_254_740_991u64
        } else {
            1
        };
        assert_eq!(
            json_stdout(&out),
            serde_json::json!({"result":[{"id":expected}]})
        );
        assert_eq!(server.finish().len(), 1);
    }
    for id in ["0", "-1", "1.5", "9007199254740992"] {
        let body: &'static str =
            Box::leak(format!(r#"{{"success":true,"result":[{{"id":{id}}}]}}"#).into_boxed_str());
        let server = Server::start(vec![(200, body)]);
        let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
        assert_eq!(out.status.code(), Some(1), "accepted {id}");
        let error = json_stdout(&out);
        assert_eq!(error["error"]["type"], "api");
        assert_eq!(error["error"]["code"], 1);
        assert_eq!(
            error["error"]["message"],
            "logpush job id must be a positive safe integer"
        );
        assert_eq!(server.finish().len(), 1);
    }

    for invalid in [
        r#"{"id":"1"}"#,
        r#"{"enabled":"yes"}"#,
        r#"{"name":7}"#,
        r#"{"name":"bad name"}"#,
        r#"{"dataset":7}"#,
        r#"{"dataset":"bad.dataset"}"#,
        r#"{"last_error":7}"#,
        r#"{"error_message":7}"#,
        r#"[]"#,
    ] {
        let body: &'static str = Box::leak(
            format!(r#"{{"success":true,"errors":[],"result":[{invalid}]}}"#).into_boxed_str(),
        );
        let server = Server::start(vec![(200, body)]);
        let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
        assert_eq!(out.status.code(), Some(1), "accepted {invalid}");
        assert_eq!(json_stdout(&out)["error"]["type"], "api");
        assert_eq!(server.finish().len(), 1);
    }

    for (envelope, message) in [
        (
            r#"{"success":true,"errors":[],"result":null}"#,
            "logpush result must be an array",
        ),
        (r#"{}"#, "logpush response envelope is malformed"),
        (
            r#"{"success":false,"errors":[],"result":[]}"#,
            "logpush response envelope is malformed",
        ),
        (
            r#"{"success":true,"errors":[{"message":"bad"}],"result":[]}"#,
            "logpush response envelope is malformed",
        ),
        (
            r#"{"success":true,"errors":{},"result":[]}"#,
            "logpush response envelope is malformed",
        ),
        (
            r#"{"success":true,"errors":[],"result":{}}"#,
            "logpush result must be an array",
        ),
    ] {
        let server = Server::start(vec![(200, envelope)]);
        let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
        assert_eq!(out.status.code(), Some(1), "accepted {envelope}");
        let error = json_stdout(&out);
        assert_eq!(error["error"]["type"], "api");
        assert_eq!(error["error"]["code"], 1);
        assert_eq!(error["error"]["message"], message);
        assert_eq!(server.finish().len(), 1);
    }

    let many = (1..=101)
        .map(|id| format!(r#"{{"id":{id}}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let body: &'static str =
        Box::leak(format!(r#"{{"success":true,"errors":[],"result":[{many}]}}"#).into_boxed_str());
    let server = Server::start(vec![(200, body)]);
    let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        json_stdout(&out)["result"],
        Value::Array((1..=100).map(|id| serde_json::json!({"id":id})).collect())
    );
    assert_eq!(server.finish().len(), 1);

    let first_hundred = (1..=100)
        .map(|id| format!(r#"{{"id":{id}}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let body: &'static str = Box::leak(
        format!(r#"{{"success":true,"result":[{first_hundred},{{"id":"bad"}}]}}"#).into_boxed_str(),
    );
    let server = Server::start(vec![(200, body)]);
    let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        json_stdout(&out)["error"]["message"],
        "logpush job id must be a positive safe integer"
    );
    assert_eq!(server.finish().len(), 1);

    for (status, body, kind, message) in [
        (
            400,
            r#"{"errors":[{"code":1001,"message":"secret-provider-body"}]}"#,
            "api",
            "Cloudflare API request failed (HTTP 400, provider code 1001)",
        ),
        (
            401,
            r#"{"errors":[{"code":1002,"message":"secret-provider-body"}]}"#,
            "auth",
            "Cloudflare API request failed (HTTP 401, provider code 1002)",
        ),
        (
            429,
            r#"{"errors":[{"code":1003,"message":"secret-provider-body"}]}"#,
            "network",
            "Cloudflare API rate limited (HTTP 429)",
        ),
        (
            500,
            r#"{"errors":[{"code":1004,"message":"secret-provider-body"}]}"#,
            "api",
            "Cloudflare API request failed (HTTP 500, provider code 1004)",
        ),
    ] {
        let server = Server::start(vec![(status, body)]);
        let (out, _) = run(&args, Some(&server.endpoint), Some("secret-token"));
        assert_eq!(out.status.code(), Some(1));
        let error = json_stdout(&out);
        assert_eq!(error["error"]["type"], kind);
        assert_eq!(error["error"]["code"], 1);
        assert_eq!(error["error"]["message"], message);
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(!text.contains("secret-provider-body"));
        assert!(!text.contains("secret-token"));
        assert_eq!(server.finish().len(), 1);
    }

    let redirect = RedirectServer::start();
    let (out, _) = run(&args, Some(&redirect.endpoint), Some("secret-token"));
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(json_stdout(&out)["error"]["type"], "api");
    let requests = redirect.finish();
    assert_eq!(
        requests.len(),
        1,
        "redirect target received request: {requests:?}"
    );
    assert!(requests[0].contains("secret-token"));

    let oversized: &'static str = Box::leak("x".repeat(8 * 1024 * 1024 + 1).into_boxed_str());
    let server = Server::start(vec![(200, oversized)]);
    let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
    assert_eq!(out.status.code(), Some(1));
    let error = json_stdout(&out);
    assert_eq!(error["error"]["type"], "network");
    assert_eq!(error["error"]["code"], 1);
    assert_eq!(error["error"]["message"], "response exceeds 8 MiB");
    assert_eq!(server.finish().len(), 1);

    let server = Server::start(vec![(200, r#"{"success":true,"errors":[],"result":[]}"#)]);
    let auth_dir = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"))
        .args([
            "--format",
            "json",
            "--endpoint",
            &server.endpoint,
            "--account",
            "account-123",
            "capability",
            "invoke",
            "logpush_jobs_by_account_id",
            "--input",
            "{}",
            "--allow-egress",
        ])
        .current_dir(auth_dir.path())
        .env("HOME", auth_dir.path())
        .env("XDG_CONFIG_HOME", auth_dir.path())
        .env_remove("CLOUDFLARE_API_TOKEN")
        .env("CLOUDFLARE_API_KEY", "key-secret")
        .env("CLOUDFLARE_API_EMAIL", "email-secret@example.com")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    let headers = requests[0].headers.to_ascii_lowercase();
    assert!(headers.contains("x-auth-key: key-secret"));
    assert!(headers.contains("x-auth-email: email-secret@example.com"));
    assert!(!headers.contains("authorization:"));
}

#[test]
fn capability_auditlogs_by_account_id_exact_request() {
    let input = r#"{"since":"2024-01-01","before":"2024-01-02","account_name":"Acme & Co","action_result":"success","action_type":"create","actor_context":"api_token","actor_email":"a+b@example.com","actor_id":"actor 1","actor_ip_address":"192.0.2.1","actor_token_id":"tok/1","actor_token_name":"token name","actor_type":"user","audit_log_id":"log/1","raw_cf_ray_id":"ray?1","raw_method":"GET /x","raw_status_code":1e21,"raw_uri":"/a b?x=1&y=2","resource_id":"res 1","resource_product":"Workers","resource_type":"worker","resource_scope":"accounts","zone_id":"zone/1","zone_name":"Zone & One","direction":"asc","limit":1e0,"cursor":"next cursor","unknown":true}"#;
    let server = Server::start(vec![(
        200,
        r#"{"success":true,"errors":[],"result":[],"result_info":{"count":0,"cursor":"next"}}"#,
    )]);
    let mut args = capability_args("auditlogs_by_account_id", input);
    args.push("--allow-egress");
    let (out, _) = run(&args, Some(&server.endpoint), Some("token"));
    assert!(out.status.success(), "{out:?}");
    assert!(out.stderr.is_empty());
    let value = json_stdout(&out);
    assert_eq!(value["logs"], serde_json::json!([]));
    assert_eq!(value["result_info"]["count"], 0);
    assert_eq!(value["result_info"]["cursor"], "next");

    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method, "GET");
    assert!(request.body.is_empty());
    assert_eq!(
        request.target,
        "/client/v4/accounts/account-123/logs/audit?account_name=Acme+%26+Co&action_result=success&action_type=create&actor_context=api_token&actor_email=a%2Bb%40example.com&actor_id=actor+1&actor_ip_address=192.0.2.1&actor_token_id=tok%2F1&actor_token_name=token+name&actor_type=user&audit_log_id=log%2F1&raw_cf_ray_id=ray%3F1&raw_method=GET+%2Fx&raw_status_code=1e%2B21&raw_uri=%2Fa+b%3Fx%3D1%26y%3D2&resource_id=res+1&resource_product=Workers&resource_type=worker&resource_scope=accounts&zone_id=zone%2F1&zone_name=Zone+%26+One&since=2024-01-01&before=2024-01-02&direction=asc&limit=1&cursor=next+cursor"
    );
    let headers = request.headers.to_ascii_lowercase();
    assert!(headers.contains("authorization: bearer token"));
    assert!(headers.contains("content-type: application/json"));
    assert!(headers.contains("portal-version: 2"));
    assert!(!headers.contains("x-auth-key:"));
    assert!(!headers.contains("x-auth-email:"));

    for status in [400, 401, 429, 500] {
        let server = Server::start(vec![(status, r#"{"errors":[{"message":"secret"}]}"#)]);
        let mut args = capability_args(
            "auditlogs_by_account_id",
            r#"{"since":"2024-01-01","before":"2024-01-02"}"#,
        );
        args.push("--allow-egress");
        let (out, _) = run(&args, Some(&server.endpoint), Some("secret"));
        assert!(!out.status.success());
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!text.contains("secret"));
        assert_eq!(server.finish().len(), 1);
    }
}

fn audit_args(input: &str) -> Vec<&str> {
    let input = if input == "{}" {
        r#"{"since":"2024-01-01","before":"2024-01-02"}"#
    } else {
        input
    };
    let mut args = capability_args("auditlogs_by_account_id", input);
    args.push("--allow-egress");
    args
}

fn audit_entry(id: &str) -> String {
    format!(
        r#"{{"id":"{id}","account":{{"id":"acct","name":"Account"}},"action":{{"result":"success","time":"2024-02-29T23:59:59.123Z","type":"create","description":"created"}}}}"#
    )
}

#[test]
fn capability_auditlogs_guards_and_scope_validation_precede_network() {
    for input in [
        r#"{"since":"2024-01-01","before":"2024-01-02","account_id":"bad/account"}"#,
        r#"{"since":"2024-01-01","before":"2024-01-02","account_id":"bad%account"}"#,
        r#"{"since":"2024-01-01","before":"2024-01-02","account_id":"bad?account"}"#,
    ] {
        let mut args = capability_args("auditlogs_by_account_id", input);
        let (out, _) = run(&args, Some("http://example.com"), None);
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stdout).contains("--allow-egress"));
        args.push("--allow-egress");
        let (out, _) = run(&args, Some("http://example.com"), None);
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stdout).contains("account_id"));
        assert!(!String::from_utf8_lossy(&out.stdout).contains("HTTPS"));
    }

    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join(".cloudflare-axi.toml"),
        "account_id = 'configured'\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"))
        .args(audit_args(
            r#"{"since":"2024-01-01","before":"2024-01-02","account_id":"provided"}"#,
        ))
        .current_dir(directory.path())
        .env("HOME", directory.path())
        .env("XDG_CONFIG_HOME", directory.path())
        .env_remove("CLOUDFLARE_API_TOKEN")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("conflicts with resolved account scope")
    );
}

#[test]
fn capability_auditlogs_default_limit_and_javascript_number_serialization() {
    for (input, expected) in [
        (
            r#"{"since":"2024-01-01","before":"2024-01-02"}"#,
            "limit=10",
        ),
        (
            r#"{"raw_status_code":-0,"since":"2024-01-01","before":"2024-01-02"}"#,
            "raw_status_code=0",
        ),
        (
            r#"{"raw_status_code":1e-6,"since":"2024-01-01","before":"2024-01-02"}"#,
            "raw_status_code=0.000001",
        ),
        (
            r#"{"raw_status_code":1e20,"since":"2024-01-01","before":"2024-01-02"}"#,
            "raw_status_code=100000000000000000000",
        ),
        (
            r#"{"raw_status_code":1e21,"since":"2024-01-01","before":"2024-01-02"}"#,
            "raw_status_code=1e%2B21",
        ),
        (
            r#"{"raw_status_code":1e-7,"since":"2024-01-01","before":"2024-01-02"}"#,
            "raw_status_code=1e-7",
        ),
        (
            r#"{"raw_status_code":-2.5e-7,"since":"2024-01-01","before":"2024-01-02"}"#,
            "raw_status_code=-2.5e-7",
        ),
        (
            r#"{"raw_status_code":9007199254740993,"since":"2024-01-01","before":"2024-01-02"}"#,
            "raw_status_code=9007199254740992",
        ),
        (
            r#"{"raw_status_code":1.7976931348623157e308,"since":"2024-01-01","before":"2024-01-02"}"#,
            "raw_status_code=1.7976931348623157e%2B308",
        ),
        (
            r#"{"raw_status_code":1000000000000000128,"since":"2024-01-01","before":"2024-01-02"}"#,
            "raw_status_code=1000000000000000100",
        ),
        (
            r#"{"raw_status_code":5e-324,"since":"2024-01-01","before":"2024-01-02"}"#,
            "raw_status_code=5e-324",
        ),
        (
            r#"{"raw_status_code":-1.7976931348623157e308,"since":"2024-01-01","before":"2024-01-02"}"#,
            "raw_status_code=-1.7976931348623157e%2B308",
        ),
    ] {
        let server = Server::start(vec![(
            200,
            r#"{"success":true,"errors":[],"result":[],"result_info":{"count":0}}"#,
        )]);
        let out = run(&audit_args(input), Some(&server.endpoint), Some("token")).0;
        assert!(out.status.success(), "{input}: {out:?}");
        assert!(server.finish()[0].target.contains(expected), "{input}");
    }
}

#[test]
fn capability_auditlogs_validates_success_envelope_errors_and_result_presence() {
    for body in [
        r#"{"success":true,"result_info":{"count":0}}"#,
        r#"{"success":true,"errors":[],"result_info":{"count":0}}"#,
        r#"{"success":true,"errors":[{"message":"notice"}],"result_info":{"count":0}}"#,
    ] {
        let server = Server::start(vec![(200, body)]);
        let out = run(&audit_args("{}"), Some(&server.endpoint), Some("token")).0;
        assert!(out.status.success(), "accepted envelope failed: {body}");
        assert_eq!(json_stdout(&out)["logs"], serde_json::json!([]));
        server.finish();
    }
    for body in [
        r#"{"success":true,"errors":[{}],"result_info":{"count":0}}"#,
        r#"{"success":true,"errors":[{"message":7}],"result_info":{"count":0}}"#,
    ] {
        let server = Server::start(vec![(200, body)]);
        let out = run(&audit_args("{}"), Some(&server.endpoint), Some("token")).0;
        assert!(!out.status.success(), "accepted invalid errors: {body}");
        server.finish();
    }
}

#[test]
fn capability_auditlogs_redirect_is_refused_without_forwarding_credentials() {
    let server = RedirectServer::start();
    let out = run(
        &audit_args("{}"),
        Some(&server.endpoint),
        Some("audit-secret"),
    )
    .0;
    assert!(!out.status.success());
    let requests = server.finish();
    assert_eq!(
        requests.len(),
        1,
        "Audit request followed redirect: {requests:?}"
    );
    assert!(requests[0].contains("audit-secret"));
}

#[test]
fn capability_auditlogs_projects_full_known_nested_fields_and_scope_variants() {
    let body = r#"{"success":true,"errors":[],"result":[
        {"id":"log-string","account":{"id":"acct","name":"Account"},"action":{"result":"success","time":"2024-02-29T23:59:59.123Z","type":"create","description":"string scope"},"actor":{"context":"api_key","email":"user@example.com","id":"actor","ip_address":"192.0.2.1","type":"user","token_id":"tid","token_name":"tname"},"resource":{"id":"rid","product":"Workers","request":{},"response":{},"scope":"accounts","type":"worker"},"raw":{"cf_ray_id":"ray","method":"GET","status_code":200,"uri":"/x","user_agent":"ua"},"zone":{"id":"zone","name":"Zone"}},
        {"id":"log-object","account":{"id":"acct","name":"Account"},"action":{"result":"failure","time":"2024-02-29T23:59:59.123Z","type":"delete"},"resource":{"scope":{} }}
    ],"result_info":{"count":2}}"#;
    let server = Server::start(vec![(200, body)]);
    let out = run(&audit_args("{}"), Some(&server.endpoint), Some("token")).0;
    assert!(out.status.success(), "{out:?}");
    let logs = &json_stdout(&out)["logs"];
    assert_eq!(logs[0]["actor_email"], "user@example.com");
    assert_eq!(logs[0]["actor_token_name"], "tname");
    assert_eq!(logs[0]["product"], "Workers");
    assert_eq!(logs[0]["type"], "worker");
    assert_eq!(logs[1]["description"], "");
    assert_eq!(logs[1]["time"], "2024-02-29T23:59:59.123Z");
    server.finish();
}

#[test]
fn capability_auditlogs_key_email_auth_and_full_projection_are_strict() {
    let entry = r#"{"id":"log-1","account":{"id":"acct","name":"Account"},"action":{"result":"success","time":"2024-02-29T23:59:59.123Z","type":"create"},"actor":{"email":"user@example.com","token_name":"deploy"},"resource":{"product":"Workers","type":"worker","scope":{"id":"scope"}},"raw":{"status_code":200,"user_agent":"ua"},"zone":{"id":"zone","name":"Zone"},"secret":"strip"}"#;
    let body = format!(
        r#"{{"success":true,"errors":[],"result":[{entry}],"result_info":{{"count":1,"cursor":"next"}}}}"#
    );
    let leaked: &'static str = Box::leak(body.into_boxed_str());
    let server = Server::start(vec![(200, leaked)]);
    let directory = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"))
        .args(audit_args("{}"))
        .current_dir(directory.path())
        .env("HOME", directory.path())
        .env("XDG_CONFIG_HOME", directory.path())
        .env_remove("CLOUDFLARE_API_TOKEN")
        .env("CLOUDFLARE_API_KEY", "key")
        .env("CLOUDFLARE_API_EMAIL", "auth@example.com")
        .arg("--endpoint")
        .arg(&server.endpoint)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let value = json_stdout(&output);
    assert_eq!(
        value["logs"][0],
        serde_json::json!({"description":"","time":"2024-02-29T23:59:59.123Z","actor_email":"user@example.com","actor_token_name":"deploy","product":"Workers","type":"worker"})
    );
    assert_eq!(value["result_info"]["cursor"], "next");
    let request = &server.finish()[0];
    let headers = request.headers.to_ascii_lowercase();
    assert!(headers.contains("x-auth-key: key"));
    assert!(headers.contains("x-auth-email: auth@example.com"));
    assert!(!headers.contains("authorization:"));
}
#[test]
fn capability_auditlogs_rejects_malformed_roots_nested_values_and_bounds() {
    let valid = audit_entry("ok");
    let cases = [
        ("not-json", "api"),
        (r#"{}"#, "api"),
        (
            r#"{"success":true,"errors":[],"result":{},"result_info":{"count":0}}"#,
            "api",
        ),
        (
            r#"{"success":true,"errors":[],"result":[],"result_info":{}}"#,
            "api",
        ),
        (
            r#"{"success":true,"errors":[],"result":[1],"result_info":{"count":1}}"#,
            "api",
        ),
        (
            r#"{"success":true,"errors":[],"result":[{"account":{},"action":{}}],"result_info":{"count":1}}"#,
            "api",
        ),
        (
            r#"{"success":true,"errors":[],"result":[{"id":"x","account":{"id":"a","name":"n"},"action":{"result":"success","time":"2023-02-29T00:00Z","type":"create"}}],"result_info":{"count":1}}"#,
            "api",
        ),
        (
            r#"{"success":true,"errors":[],"result":[{"id":"x","account":{"id":"a","name":"n"},"action":{"result":"success","time":"2024-01-01T00:00Z","type":"create"},"actor":{"email":"bad"}}],"result_info":{"count":1}}"#,
            "api",
        ),
        (
            r#"{"success":true,"errors":[],"result":[{"id":"x","account":{"id":"a","name":"n"},"action":{"result":"success","time":"2024-01-01T00:00Z","type":"create"},"actor":{"context":"bad"}}],"result_info":{"count":1}}"#,
            "api",
        ),
        (
            r#"{"success":true,"errors":[],"result":[{"id":"x","account":{"id":"a","name":"n"},"action":{"result":"success","time":"2024-01-01T00:00Z","type":"create"},"resource":{"scope":7}}],"result_info":{"count":1}}"#,
            "api",
        ),
        (
            r#"{"success":true,"errors":[],"result":[{"id":"x","account":{"id":"a","name":"n"},"action":{"result":"success","time":"2024-01-01T00:00Z","type":"create"},"raw":{"status_code":"200"}}],"result_info":{"count":1}}"#,
            "api",
        ),
        (
            r#"{"success":true,"errors":[],"result":[{"id":"x","account":{"id":"a","name":"n"},"action":{"result":"success","time":"2024-01-01T00:00Z","type":"create"},"zone":{"id":7}}],"result_info":{"count":1}}"#,
            "api",
        ),
        (
            r#"{"success":true,"errors":[],"result":[{"id":"😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀","account":{"id":"a","name":"n"},"action":{"result":"success","time":"2024-01-01T00:00Z","type":"create"}}],"result_info":{"count":1}}"#,
            "api",
        ),
    ];
    for (body, kind) in cases {
        let server = Server::start(vec![(200, body)]);
        let out = run(&audit_args("{}"), Some(&server.endpoint), Some("token")).0;
        assert_eq!(out.status.code(), Some(1), "accepted {body}");
        assert_eq!(json_stdout(&out)["error"]["type"], kind);
        assert_eq!(server.finish().len(), 1);
    }
    let server = Server::start(vec![(
        200,
        Box::leak(
            format!(
                r#"{{"success":true,"errors":[],"result":[{}],"result_info":{{"count":1}}}}"#,
                valid
            )
            .into_boxed_str(),
        ),
    )]);
    let out = run(&audit_args("{}"), Some(&server.endpoint), Some("token")).0;
    assert!(out.status.success());
    assert_eq!(json_stdout(&out)["logs"][0]["description"], "created");
    server.finish();
}

#[test]
fn capability_auditlogs_does_not_retry_and_rejects_provider_errors_redirects_and_large_body() {
    for status in [400, 401, 429, 500] {
        let server = Server::start(vec![(
            status,
            r#"{"errors":[{"code":"token-secret","message":"provider-message"}]}"#,
        )]);
        let out = run(
            &audit_args("{}"),
            Some(&server.endpoint),
            Some("token-secret"),
        )
        .0;
        assert!(!out.status.success());
        assert_eq!(
            json_stdout(&out)["error"]["type"],
            if status == 401 {
                "auth"
            } else if status == 429 {
                "network"
            } else {
                "api"
            }
        );
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(!text.contains("token-secret"));
        assert!(!text.contains("provider-message"));
        if status != 429 {
            assert!(text.contains("[redacted]"));
        }
        assert_eq!(server.finish().len(), 1);
    }
    let oversized: &'static str = Box::leak("x".repeat(8 * 1024 * 1024 + 1).into_boxed_str());
    let server = Server::start(vec![(200, oversized)]);
    let out = run(&audit_args("{}"), Some(&server.endpoint), Some("token")).0;
    assert_eq!(json_stdout(&out)["error"]["type"], "network");
    assert_eq!(server.finish().len(), 1);
}
