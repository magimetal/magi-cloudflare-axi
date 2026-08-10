use std::{
    io::{Read, Write},
    net::TcpListener,
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

struct Redirect {
    endpoint: String,
    requests: Arc<Mutex<Vec<String>>>,
    join: Option<thread::JoinHandle<()>>,
}

impl Redirect {
    fn start() -> Self {
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let second = TcpListener::bind("127.0.0.1:0").unwrap();
        second.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}/mcp", first.local_addr().unwrap());
        let location = format!("http://{}/mcp", second.local_addr().unwrap());
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
            thread::sleep(Duration::from_millis(250));
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

fn command(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"));
    command.args(args);
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
    command
}

fn run_in(root: &std::path::Path, args: &[&str]) -> std::process::Output {
    command(args)
        .current_dir(root)
        .env("HOME", root)
        .env("XDG_CONFIG_HOME", root)
        .output()
        .unwrap()
}

fn account_request(root: &std::path::Path) -> String {
    let (url, handle) = endpoint(rpc(r#"{"result":{"tools":[]}}"#));
    let output = run_in(
        root,
        &[
            "--format",
            "json",
            "--mcp-endpoint",
            &url,
            "tool",
            "list",
            "--server",
            "docs",
        ],
    );
    assert!(output.status.success());
    handle.join().unwrap()
}

fn account_request_with_env(root: &std::path::Path, account: Option<&str>) -> String {
    let (url, handle) = endpoint(rpc(r#"{"result":{"tools":[]}}"#));
    let mut process = command(&[
        "--format",
        "json",
        "--mcp-endpoint",
        &url,
        "tool",
        "list",
        "--server",
        "docs",
    ]);
    process
        .current_dir(root)
        .env("HOME", root)
        .env("XDG_CONFIG_HOME", root);
    if let Some(account) = account {
        process.env("CLOUDFLARE_ACCOUNT_ID", account);
    }
    let output = process.output().unwrap();
    assert!(output.status.success());
    handle.join().unwrap()
}

#[test]
fn account_id_resolves_from_environment() {
    let d = tempfile::tempdir().unwrap();
    assert!(
        account_request_with_env(d.path(), Some("env-account"))
            .contains("cf-account-id: env-account")
    );
}

#[test]
fn account_id_resolves_from_project_config() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(
        d.path().join(".cloudflare-axi.toml"),
        "account_id = \"project-account\"\n",
    )
    .unwrap();
    assert!(account_request(d.path()).contains("cf-account-id: project-account"));
}

#[test]
fn account_id_resolves_from_global_config() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("cloudflare")).unwrap();
    std::fs::write(
        d.path().join("cloudflare/cloudflare-axi.toml"),
        "account_id = \"global-account\"\n",
    )
    .unwrap();
    assert!(account_request(d.path()).contains("cf-account-id: global-account"));
}
fn run(args: &[&str]) -> std::process::Output {
    command(args).output().unwrap()
}
fn endpoint(response: &'static str) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut bytes = Vec::new();
        let mut chunk = [0; 4096];
        let header_end = loop {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0);
            bytes.extend_from_slice(&chunk[..read]);
            if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let headers = String::from_utf8_lossy(&bytes[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(str::trim)
                    .map(str::to_owned)
            })
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        while bytes.len() < header_end + content_length {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0);
            bytes.extend_from_slice(&chunk[..read]);
        }
        stream.write_all(response.as_bytes()).unwrap();
        String::from_utf8_lossy(&bytes[..header_end + content_length]).into_owned()
    });
    (url, handle)
}
fn rpc(body: &'static str) -> &'static str {
    Box::leak(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).into_boxed_str())
}
#[test]
fn public_tools_list_real_binary() {
    let (u, h) = endpoint(rpc(r#"{"result":{"tools":[]}}"#));
    let o = run(&[
        "--format",
        "json",
        "--mcp-endpoint",
        &u,
        "tool",
        "list",
        "--server",
        "docs",
    ]);
    assert!(o.status.success());
    h.join().unwrap();
}
#[test]
fn exact_json_rpc_request() {
    let (u, h) = endpoint(rpc(r#"{"result":{"tools":[]}}"#));
    let output = run(&[
        "--format",
        "json",
        "--mcp-endpoint",
        &u,
        "tool",
        "list",
        "--server",
        "docs",
    ]);
    assert!(output.status.success());
    let request = h.join().unwrap();
    let lower = request.to_ascii_lowercase();
    assert!(lower.contains("mcp-protocol-version: 2026-07-28"));
    assert!(lower.contains("mcp-method: tools/list"));
    let body: serde_json::Value =
        serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(body["method"], "tools/list");
    assert_eq!(
        body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
        "2026-07-28"
    );
    assert_eq!(
        body["params"]["_meta"]["io.modelcontextprotocol/clientInfo"]["name"],
        "magi-cloudflare-axi"
    );
}
#[test]
fn account_header() {
    let (u, h) = endpoint(rpc(r#"{"result":{"tools":[]}}"#));
    let _ = run(&[
        "--format",
        "json",
        "--account",
        "acct",
        "--mcp-endpoint",
        &u,
        "tool",
        "list",
        "--server",
        "docs",
    ]);
    assert!(h.join().unwrap().contains("cf-account-id: acct"));
}
#[test]
fn json_result() {
    let (u, h) = endpoint(rpc(r#"{"result":{"x":1}}"#));
    let output = run(&[
        "--format",
        "json",
        "--mcp-endpoint",
        &u,
        "tool",
        "list",
        "--server",
        "docs",
    ]);
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["x"],
        1
    );
    h.join().unwrap();
}
#[test]
fn sse_result() {
    let b = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n";
    let (u, h) = endpoint(Box::leak(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", b.len(), b).into_boxed_str()));
    let o = run(&[
        "--format",
        "json",
        "--mcp-endpoint",
        &u,
        "tool",
        "list",
        "--server",
        "docs",
    ]);
    assert!(o.status.success());
    h.join().unwrap();
}
#[test]
fn structured_content() {
    let (u, h) = endpoint(rpc(r#"{"result":{"structuredContent":{"ok":1}}}"#));
    let output = run(&[
        "--format",
        "json",
        "--mcp-endpoint",
        &u,
        "tool",
        "call",
        "search_cloudflare_documentation",
        "--server",
        "docs",
        "--input",
        r#"{"query":"Workers"}"#,
        "--allow-metered",
    ]);
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!({"ok":1})
    );
    let request = h.join().unwrap();
    assert!(
        request
            .to_ascii_lowercase()
            .contains("mcp-name: search_cloudflare_documentation")
    );
    let body: serde_json::Value =
        serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(body["params"]["name"], "search_cloudflare_documentation");
    assert_eq!(body["params"]["arguments"]["query"], "Workers");
}
#[test]
fn json_rpc_error() {
    let (u, h) = endpoint(rpc(r#"{"error":{"message":"bad"}}"#));
    let o = run(&[
        "--format",
        "json",
        "--mcp-endpoint",
        &u,
        "tool",
        "list",
        "--server",
        "docs",
    ]);
    assert!(!o.status.success());
    h.join().unwrap();
}
#[test]
fn is_error() {
    let (u, h) = endpoint(rpc(r#"{"result":{"isError":true}}"#));
    let o = run(&[
        "--format",
        "json",
        "--mcp-endpoint",
        &u,
        "tool",
        "list",
        "--server",
        "docs",
    ]);
    assert!(!o.status.success());
    h.join().unwrap();
}
#[test]
fn http_error() {
    let (u, h) = endpoint("HTTP/1.1 500 Test\r\nContent-Length: 3\r\nConnection: close\r\n\r\nbad");
    let o = run(&[
        "--format",
        "json",
        "--mcp-endpoint",
        &u,
        "tool",
        "list",
        "--server",
        "docs",
    ]);
    assert!(!o.status.success());
    h.join().unwrap();
}
#[test]
fn endpoint_query_rejected() {
    let o = run(&[
        "--mcp-endpoint",
        "http://127.0.0.1:1/mcp?x=1",
        "tool",
        "list",
        "--server",
        "docs",
    ]);
    assert!(!o.status.success());
}
#[test]
fn ftp_rejected() {
    let o = run(&[
        "--mcp-endpoint",
        "ftp://127.0.0.1/mcp",
        "tool",
        "list",
        "--server",
        "docs",
    ]);
    assert!(!o.status.success());
}
#[test]
fn write_guard_before_request() {
    let o = run(&[
        "--mcp-endpoint",
        "http://127.0.0.1:1/mcp",
        "tool",
        "call",
        "d1_database_create",
        "--server",
        "bindings",
        "--input",
        "{}",
    ]);
    assert!(!o.status.success());
}
#[test]
fn key_auth_rejected_before_request() {
    let o = command(&[
        "--mcp-endpoint",
        "http://127.0.0.1:1/mcp",
        "tool",
        "list",
        "--server",
        "bindings",
    ])
    .env("CLOUDFLARE_API_KEY", "secret")
    .env("CLOUDFLARE_API_EMAIL", "x@y")
    .output()
    .unwrap();
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stdout).contains("CLOUDFLARE_API_TOKEN"));
}

#[test]
fn explicit_server_schema_does_not_require_local_catalog_entry() {
    let (url, handle) = endpoint(rpc(
        r#"{"result":{"tools":[{"name":"remote_only","inputSchema":{"type":"object"}}]}}"#,
    ));
    let output = run(&[
        "--format",
        "json",
        "--mcp-endpoint",
        &url,
        "tool",
        "schema",
        "remote_only",
        "--server",
        "docs",
    ]);
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["name"],
        "remote_only"
    );
    handle.join().unwrap();
}

#[test]
fn unverified_remote_mutation_requires_all_safety_flags() {
    let output = run(&[
        "--format",
        "json",
        "--mcp-endpoint",
        "http://127.0.0.1:1/mcp",
        "tool",
        "call",
        "execute",
        "--server",
        "docs",
        "--input",
        "{}",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stdout).contains("--allow-write --allow-metered"));
}

#[test]
fn endpoint_userinfo_and_fragment_are_rejected() {
    for endpoint in [
        "http://user@127.0.0.1:1/mcp",
        "http://127.0.0.1:1/mcp#fragment",
    ] {
        let output = run(&[
            "--format",
            "json",
            "--mcp-endpoint",
            endpoint,
            "tool",
            "list",
            "--server",
            "docs",
        ]);
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stdout).contains("userinfo, query, or fragment"));
    }
}

#[test]
fn cataloged_mutation_requires_every_explicit_server_safety_flag() {
    for missing in ["--allow-write", "--allow-metered", "--confirm"] {
        let args = match missing {
            "--allow-write" => vec![
                "--format",
                "json",
                "--mcp-endpoint",
                "http://127.0.0.1:1/mcp",
                "tool",
                "call",
                "d1_database_create",
                "--server",
                "bindings",
                "--input",
                "{}",
                "--allow-metered",
                "--confirm",
                "d1_database_create",
            ],
            "--allow-metered" => vec![
                "--format",
                "json",
                "--mcp-endpoint",
                "http://127.0.0.1:1/mcp",
                "tool",
                "call",
                "d1_database_create",
                "--server",
                "bindings",
                "--input",
                "{}",
                "--allow-write",
                "--confirm",
                "d1_database_create",
            ],
            _ => vec![
                "--format",
                "json",
                "--mcp-endpoint",
                "http://127.0.0.1:1/mcp",
                "tool",
                "call",
                "d1_database_create",
                "--server",
                "bindings",
                "--input",
                "{}",
                "--allow-write",
                "--allow-metered",
            ],
        };
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2), "missing {missing}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("requires --allow-write"));
    }

    let output = command(&[
        "--format",
        "json",
        "--mcp-endpoint",
        "http://127.0.0.1:1/mcp",
        "tool",
        "call",
        "d1_database_create",
        "--server",
        "bindings",
        "--input",
        "{}",
        "--allow-write",
        "--allow-metered",
        "--confirm",
        "d1_database_create",
    ])
    .env("CLOUDFLARE_API_TOKEN", "test-token")
    .output()
    .unwrap();
    assert_ne!(output.status.code(), Some(2));
}

#[test]
fn final_mcp_json_rpc_request_is_bounded() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("input.json");
    let framing = r#"{"payload":""}"#;
    let input = format!(
        r#"{{"payload":"{}"}}"#,
        "x".repeat(1024 * 1024 - framing.len())
    );
    assert_eq!(input.len(), 1024 * 1024);
    std::fs::write(&file, input).unwrap();
    let output = command(&[
        "--format",
        "json",
        "--mcp-endpoint",
        "http://127.0.0.1:1/mcp",
        "tool",
        "call",
        "execute",
        "--server",
        "docs",
        "--file",
        file.to_str().unwrap(),
        "--allow-write",
        "--allow-metered",
        "--confirm",
        "execute",
    ])
    .current_dir(directory.path())
    .env("HOME", directory.path())
    .env("XDG_CONFIG_HOME", directory.path())
    .output()
    .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stdout).contains("MCP request exceeds 1 MiB"));
}

#[test]
fn mcp_redirect_does_not_forward_token_or_account() {
    let server = Redirect::start();
    let output = command(&[
        "--format",
        "json",
        "--account",
        "fake-account",
        "--mcp-endpoint",
        &server.endpoint,
        "tool",
        "list",
        "--server",
        "bindings",
    ])
    .env("CLOUDFLARE_API_TOKEN", "fake-token")
    .output()
    .unwrap();
    assert!(!output.status.success());
    let requests = server.finish();
    assert_eq!(
        requests.len(),
        1,
        "redirect target received request: {requests:?}"
    );
    assert!(requests[0].contains("fake-token"));
    assert!(requests[0].contains("fake-account"));
}
