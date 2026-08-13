use std::process::Command;
#[test]
fn binary_help_works_without_auth() {
    let o = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(o.status.success());
}

#[test]
fn version_aliases_are_early_and_consistent() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join(".cloudflare-axi.toml"), "[").unwrap();
    for flag in ["-v", "-V", "--version"] {
        let output = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"))
            .arg(flag)
            .current_dir(directory.path())
            .output()
            .unwrap();
        assert!(output.status.success(), "{flag}");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            format!("magi-cloudflare-axi {}\n", env!("CARGO_PKG_VERSION"))
        );
    }
}

#[test]
fn leaf_help_has_descriptions_and_examples() {
    let output = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"))
        .args(["tool", "call", "--help"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(text.contains("Exact MCP tool name"));
    assert!(text.contains("Examples:"));
}

#[test]
fn equal_format_syntax_controls_parse_errors() {
    let output = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"))
        .args(["--format=json", "--unknown"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["type"], "usage");
    assert!(output.stderr.is_empty());
}

#[test]
fn no_args_home_is_structured_and_useful_without_auth() {
    let dir = tempfile::tempdir().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"));
    command
        .args(["--format", "json"])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path());
    clean_cloudflare_env(&mut command);
    let output = command.output().unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["live"]["status"], "not_configured");
    assert_eq!(value["capabilities"]["registered_tool_names"], 172);
    assert!(value["bin"].as_str().unwrap().starts_with('/'));
}

fn clean_cloudflare_env(command: &mut Command) {
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
}

fn run(root: &std::path::Path, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"));
    command
        .args(args)
        .arg("--root")
        .arg(root)
        .env("HOME", root)
        .env("XDG_CONFIG_HOME", root);
    clean_cloudflare_env(&mut command);
    command.output().unwrap()
}

#[test]
fn capability_schema_is_offline_and_ignores_malformed_config() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join(".cloudflare-axi.toml"), "[").unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"));
    command
        .args([
            "--format",
            "json",
            "capability",
            "schema",
            "d1_database_get",
        ])
        .current_dir(directory.path());
    clean_cloudflare_env(&mut command);
    let output = command.output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["name"], "d1_database_get");
    assert_eq!(
        value["raw_input_schema"]["required"],
        serde_json::json!(["database_id"])
    );
    assert_eq!(
        value["source"]["commit"],
        "70ff690553722f731849ede6ba9ce98958395a23"
    );
}

#[test]
fn capability_preflight_errors_win_over_config_auth_and_network() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join(".cloudflare-axi.toml"), "[").unwrap();
    for (name, input, expected) in [
        (
            "d1_database_get",
            r#"{"database_id":"bad"}"#,
            "database_id must be a UUID",
        ),
        ("d1_database_delete", "{}", "requires safety flags"),
    ] {
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
            ])
            .current_dir(directory.path());
        clean_cloudflare_env(&mut command);
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stderr.is_empty());
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            value["error"]["message"]
                .as_str()
                .unwrap()
                .contains(expected)
        );
    }
}
#[test]
fn session_claude_filesystem_setup() {
    let d = tempfile::tempdir().unwrap();
    assert!(
        run(d.path(), &["session", "setup", "--target", "claude"])
            .status
            .success()
    );
    assert!(d.path().join(".claude/settings.json").exists());
}
#[test]
fn session_codex_filesystem_setup() {
    let d = tempfile::tempdir().unwrap();
    assert!(
        run(d.path(), &["session", "setup", "--target", "codex"])
            .status
            .success()
    );
    assert!(d.path().join(".codex/hooks.json").exists());
    assert!(d.path().join(".codex/config.toml").exists());
}
#[test]
fn session_opencode_filesystem_setup() {
    let d = tempfile::tempdir().unwrap();
    assert!(
        run(d.path(), &["session", "setup", "--target", "opencode"])
            .status
            .success()
    );
    assert!(
        std::fs::read_to_string(
            d.path()
                .join(".config/opencode/plugins/magi-cloudflare-axi.js")
        )
        .unwrap()
        .contains("managed plugin")
    );
}
#[test]
fn session_preserves_unrelated_json() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join(".claude")).unwrap();
    std::fs::write(d.path().join(".claude/settings.json"), r#"{"custom":true}"#).unwrap();
    assert!(
        run(d.path(), &["session", "setup", "--target", "claude"])
            .status
            .success()
    );
    assert!(
        std::fs::read_to_string(d.path().join(".claude/settings.json"))
            .unwrap()
            .contains("custom")
    );
}
#[test]
fn session_setup_is_idempotent() {
    let d = tempfile::tempdir().unwrap();
    assert!(
        run(d.path(), &["session", "setup", "--target", "claude"])
            .status
            .success()
    );
    let p = d.path().join(".claude/settings.json");
    let a = std::fs::read(&p).unwrap();
    assert!(
        run(d.path(), &["session", "setup", "--target", "claude"])
            .status
            .success()
    );
    assert_eq!(a, std::fs::read(p).unwrap());
}
#[test]
fn session_repairs_stale_hook() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join(".codex")).unwrap();
    std::fs::write(
        d.path().join(".codex/hooks.json"),
        r#"{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"/old/magi-cloudflare-axi session context --format toon","managed_by":"magi-cloudflare-axi"}]}]}}"#,
    )
    .unwrap();
    assert!(
        run(d.path(), &["session", "setup", "--target", "codex"])
            .status
            .success()
    );
    assert!(
        !std::fs::read_to_string(d.path().join(".codex/hooks.json"))
            .unwrap()
            .contains("/old/")
    );
}
#[test]
fn session_rejects_malformed_without_overwrite() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join(".claude")).unwrap();
    let p = d.path().join(".claude/settings.json");
    std::fs::write(&p, "[").unwrap();
    assert!(
        !run(d.path(), &["session", "setup", "--target", "claude"])
            .status
            .success()
    );
    assert_eq!(std::fs::read_to_string(p).unwrap(), "[");
}
#[test]
fn session_remove_preserves_unrelated() {
    let d = tempfile::tempdir().unwrap();
    assert!(
        run(d.path(), &["session", "setup", "--target", "claude"])
            .status
            .success()
    );
    let p = d.path().join(".claude/settings.json");
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
    v["custom"] = serde_json::json!(1);
    std::fs::write(&p, serde_json::to_string(&v).unwrap()).unwrap();
    assert!(
        run(d.path(), &["session", "remove", "--target", "claude"])
            .status
            .success()
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&std::fs::read_to_string(p).unwrap()).unwrap()["custom"],
        1
    );
}
#[test]
fn session_hook_invokes_context() {
    let d = tempfile::tempdir().unwrap();
    assert!(
        run(d.path(), &["session", "setup", "--target", "codex"])
            .status
            .success()
    );
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(d.path().join(".codex/hooks.json")).unwrap())
            .unwrap();
    let c = v["hooks"]["SessionStart"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    let mut command = std::process::Command::new("sh");
    command.args(["-c", c]).env("HOME", d.path());
    clean_cloudflare_env(&mut command);
    let o = command.output().unwrap();
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stdout).contains("commands"));
}

#[test]
fn session_status_validates_content_not_file_existence() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join(".claude")).unwrap();
    std::fs::write(d.path().join(".claude/settings.json"), "{}").unwrap();
    let output = run(
        d.path(),
        &[
            "--format", "json", "session", "status", "--target", "claude",
        ],
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["claude"]["state"], "unmanaged");

    assert!(
        run(d.path(), &["session", "setup", "--target", "claude"])
            .status
            .success()
    );
    let output = run(
        d.path(),
        &[
            "--format", "json", "session", "status", "--target", "claude",
        ],
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["claude"]["state"], "configured");
}

#[test]
fn repeated_session_setup_reports_unchanged() {
    let d = tempfile::tempdir().unwrap();
    assert!(
        run(d.path(), &["session", "setup", "--target", "codex"])
            .status
            .success()
    );
    let output = run(
        d.path(),
        &["--format", "json", "session", "setup", "--target", "codex"],
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "unchanged");
}

#[test]
fn session_repairs_managed_hook_type_and_matcher() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join(".codex")).unwrap();
    std::fs::write(
        d.path().join(".codex/hooks.json"),
        r#"{"hooks":{"SessionStart":[{"matcher":"wrong","managed_by":"magi-cloudflare-axi","hooks":[{"type":"prompt","command":"/old/magi-cloudflare-axi session context --format toon","managed_by":"magi-cloudflare-axi"}]}]}}"#,
    )
    .unwrap();
    assert!(
        run(d.path(), &["session", "setup", "--target", "codex"])
            .status
            .success()
    );
    let value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(d.path().join(".codex/hooks.json")).unwrap())
            .unwrap();
    let group = &value["hooks"]["SessionStart"][0];
    assert_eq!(group["matcher"], "startup|resume|clear|compact|fork");
    assert_eq!(group["hooks"][0]["type"], "command");
}

#[test]
fn session_codex_status_reports_trust_unverified() {
    let d = tempfile::tempdir().unwrap();
    assert!(
        run(d.path(), &["session", "setup", "--target", "codex"])
            .status
            .success()
    );
    let output = run(
        d.path(),
        &["--format", "json", "session", "status", "--target", "codex"],
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["codex"]["state"], "configured_trust_unverified");
}

#[test]
fn session_setup_prevalidates_all_targets_before_writing() {
    let d = tempfile::tempdir().unwrap();
    let plugin = d
        .path()
        .join(".config/opencode/plugins/magi-cloudflare-axi.js");
    std::fs::create_dir_all(plugin.parent().unwrap()).unwrap();
    std::fs::write(plugin, "user plugin without managed marker").unwrap();
    let output = run(
        d.path(),
        &[
            "session", "setup", "--target", "claude", "--target", "opencode",
        ],
    );
    assert!(!output.status.success());
    assert!(!d.path().join(".claude/settings.json").exists());
}

#[test]
fn session_remove_preserves_unmarked_hook_with_marker_in_command() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join(".claude")).unwrap();
    let p = d.path().join(".claude/settings.json");
    let original = serde_json::json!({"hooks":{"SessionStart":[{"matcher":"*","hooks":[{"type":"command","command":"magi-cloudflare-axi custom-user-hook"}]}]}});
    std::fs::write(&p, serde_json::to_string(&original).unwrap()).unwrap();
    assert!(
        run(d.path(), &["session", "remove", "--target", "claude"])
            .status
            .success()
    );
    let value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    assert_eq!(
        value["hooks"]["SessionStart"][0]["hooks"][0]["command"],
        "magi-cloudflare-axi custom-user-hook"
    );
}

#[test]
fn session_status_reports_only_selected_target() {
    let d = tempfile::tempdir().unwrap();
    let output = run(
        d.path(),
        &[
            "--format", "json", "session", "status", "--target", "claude",
        ],
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value.as_object().unwrap().keys().collect::<Vec<_>>(),
        vec!["claude"]
    );
}

#[test]
fn session_without_home_requires_root() {
    let d = tempfile::tempdir().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"));
    command.args(["session", "status", "--target", "claude"]);
    clean_cloudflare_env(&mut command);
    command.env_remove("HOME").env_remove("XDG_CONFIG_HOME");
    let output = command.current_dir(d.path()).output().unwrap();
    assert!(!output.status.success());
    let diagnostics = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(diagnostics.contains("HOME is unset"));
}

#[test]
fn setup_rejects_conflicting_root_forms_and_targets() {
    let d = tempfile::tempdir().unwrap();
    for args in [
        vec!["session", "setup", "--root", "a", "--target-dir", "b"],
        vec!["session", "setup", "--target", "claude", "--claude"],
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"));
        command
            .args(&args)
            .current_dir(d.path())
            .env("HOME", d.path())
            .env("XDG_CONFIG_HOME", d.path());
        clean_cloudflare_env(&mut command);
        assert_eq!(command.output().unwrap().status.code(), Some(2));
    }
}

#[test]
fn session_status_rejects_duplicate_managed_handler() {
    let d = tempfile::tempdir().unwrap();
    assert!(
        run(d.path(), &["session", "setup", "--target", "claude"])
            .status
            .success()
    );
    let path = d.path().join(".claude/settings.json");
    let mut value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let handler = value["hooks"]["SessionStart"][0]["hooks"][0].clone();
    value["hooks"]["SessionStart"][0]["hooks"]
        .as_array_mut()
        .unwrap()
        .push(handler);
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let output = run(
        d.path(),
        &[
            "--format", "json", "session", "status", "--target", "claude",
        ],
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["claude"]["state"], "invalid_managed_hook");
}

#[test]
fn session_status_reports_missing_codex_config() {
    let d = tempfile::tempdir().unwrap();
    assert!(
        run(d.path(), &["session", "setup", "--target", "codex"])
            .status
            .success()
    );
    std::fs::remove_file(d.path().join(".codex/config.toml")).unwrap();
    let output = run(
        d.path(),
        &["--format", "json", "session", "status", "--target", "codex"],
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["codex"]["state"], "missing_config");
}

#[cfg(unix)]
#[test]
fn session_managed_files_are_private_and_preserve_existing_mode() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let d = tempfile::tempdir().unwrap();
    assert!(
        run(d.path(), &["session", "setup", "--target", "claude"])
            .status
            .success()
    );
    let path = d.path().join(".claude/settings.json");
    assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let mut value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    value["unrelated"] = serde_json::json!(true);
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(
        run(d.path(), &["session", "setup", "--target", "claude"])
            .status
            .success()
    );
    assert_eq!(std::fs::metadata(path).unwrap().mode() & 0o777, 0o640);
}

#[test]
fn capability_blog_discovery_examples_are_exact() {
    for (name, example) in [
        ("get_post", "get_post --input '{\"slug\":\"<slug>\"}'"),
        ("list_posts", "list_posts --input '{}'"),
        ("list_tags", "list_tags --input '{}'"),
        (
            "search_posts",
            "search_posts --input '{\"query\":\"<query>\"}'",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"))
            .args(["--format", "json", "capability", "get", name])
            .output()
            .unwrap();
        assert!(output.status.success());
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            value["next_command"],
            format!("magi-cloudflare-axi capability invoke {example}")
        );
    }
}

#[test]
fn capability_browser_discovery_examples_are_exact() {
    for (name, example) in [
        (
            "get_url_markdown",
            "get_url_markdown --input '{\"url\":\"<url>\"}'",
        ),
        (
            "get_url_links",
            "get_url_links --input '{\"url\":\"<url>\"}'",
        ),
        (
            "scrape_url_elements",
            "scrape_url_elements --input '{\"url\":\"<url>\",\"elements\":[{\"selector\":\"h1\"}]}'",
        ),
        ("get_url_json", "get_url_json --input '{\"url\":\"<url>\"}'"),
        (
            "get_url_snapshot",
            "get_url_snapshot --input '{\"url\":\"<url>\"}'",
        ),
        (
            "get_crawl_result",
            "get_crawl_result --input '{\"job_id\":\"<job_id>\"}'",
        ),
        (
            "list_browser_sessions",
            "list_browser_sessions --input '{}'",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_magi-cloudflare-axi"))
            .args(["--format", "json", "capability", "get", name])
            .output()
            .unwrap();
        assert!(output.status.success());
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            value["next_command"],
            format!("magi-cloudflare-axi capability invoke {example}")
        );
    }
}
