use crate::{cli::SetupArgs, config, error::AppError};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

const MARKER: &str = "magi-cloudflare-axi";

pub fn context() -> Result<Value, AppError> {
    let cfg = config::load(None, None, None)?;
    crate::cli::home(&cfg, config::auth_for(&cfg))
}

pub fn execute_context(format: &str) -> Result<(), AppError> {
    crate::error::render(&context()?, format)
}

pub fn setup(args: SetupArgs) -> Result<Value, AppError> {
    let root = root(&args)?;
    let current = std::env::current_exe()
        .map_err(|e| AppError::config(format!("cannot resolve executable: {e}")))?;
    let executable = portable_executable(&current);
    let selected = targets(&args);
    let mut installed = Vec::new();
    let mut prepared = Vec::new();

    for target in selected {
        match target {
            "claude" => {
                let path = root.join(".claude/settings.json");
                let mut value = read_json(&path)?;
                merge_claude(&mut value, &executable, &path)?;
                prepared.push((path, json_text(&value)?));
                installed.push("claude");
            }
            "codex" => {
                let config_path = root.join(".codex/config.toml");
                let mut config = read_toml(&config_path)?;
                let table = config
                    .as_table_mut()
                    .ok_or_else(|| schema(&config_path, "top-level table"))?;
                let features = table
                    .entry("features")
                    .or_insert_with(|| toml::Value::Table(Default::default()))
                    .as_table_mut()
                    .ok_or_else(|| schema(&config_path, "features table"))?;
                features.insert("hooks".into(), toml::Value::Boolean(true));
                let hooks_path = root.join(".codex/hooks.json");
                let mut hooks = read_json(&hooks_path)?;
                merge_codex(&mut hooks, &executable, &hooks_path)?;
                prepared.push((hooks_path, json_text(&hooks)?));
                prepared.push((
                    config_path,
                    toml::to_string_pretty(&config)
                        .map_err(|_| AppError::config("cannot serialize Codex config"))?,
                ));
                installed.push("codex");
            }
            "opencode" => {
                let path = root.join(".config/opencode/plugins/magi-cloudflare-axi.js");
                let old = read_optional(&path)?;
                if old
                    .as_deref()
                    .is_some_and(|text| !text.starts_with(&format!("// {MARKER} managed plugin\n")))
                {
                    return Err(schema(&path, "managed plugin or absent"));
                }
                prepared.push((path, plugin(&executable)?));
                installed.push("opencode");
            }
            _ => unreachable!(),
        }
    }

    let mut changed = false;
    for (path, content) in prepared {
        changed |= write_atomic(&path, &content)?;
    }
    Ok(json!({
        "status": if changed {"configured"} else {"unchanged"},
        "targets":installed,
        "codex_trust": if installed.contains(&"codex") {Some("review hook in Codex `/hooks`; trust cannot be verified non-interactively")} else {None::<&str>}
    }))
}

pub fn status(args: SetupArgs) -> Result<Value, AppError> {
    let root = root(&args)?;
    let current = std::env::current_exe()
        .map_err(|e| AppError::config(format!("cannot resolve executable: {e}")))?;
    let executable = portable_executable(&current);
    let mut result = serde_json::Map::new();
    for target in targets(&args) {
        let value = match target {
            "claude" => hook_status(&root.join(".claude/settings.json"), &executable, None)?,
            "codex" => hook_status(
                &root.join(".codex/hooks.json"),
                &executable,
                Some(&root.join(".codex/config.toml")),
            )?,
            "opencode" => plugin_status(
                &root.join(".config/opencode/plugins/magi-cloudflare-axi.js"),
                &executable,
            )?,
            _ => unreachable!(),
        };
        result.insert(target.into(), value);
    }
    Ok(Value::Object(result))
}

pub fn remove(args: SetupArgs) -> Result<Value, AppError> {
    let root = root(&args)?;
    let targets = targets(&args);
    let mut removed = Vec::new();
    for target in targets {
        match target {
            "claude" => {
                let p = root.join(".claude/settings.json");
                if p.exists() {
                    let mut v = read_json(&p)?;
                    remove_hooks(&mut v);
                    let _ = write_json(&p, &v)?;
                }
                removed.push("claude");
            }
            "codex" => {
                let p = root.join(".codex/hooks.json");
                if p.exists() {
                    let mut v = read_json(&p)?;
                    remove_hooks(&mut v);
                    let _ = write_json(&p, &v)?;
                }
                removed.push("codex");
            }
            "opencode" => {
                let p = root.join(".config/opencode/plugins/magi-cloudflare-axi.js");
                if read_optional(&p)?
                    .is_some_and(|s| s.starts_with(&format!("// {MARKER} managed plugin\n")))
                {
                    fs::remove_file(&p).map_err(|e| {
                        AppError::config(format!("cannot remove {}: {e}", p.display()))
                    })?;
                }
                removed.push("opencode");
            }
            _ => unreachable!(),
        }
    }
    Ok(json!({"status":"removed", "targets":removed}))
}

fn targets(a: &SetupArgs) -> Vec<&'static str> {
    if !a.targets.is_empty() {
        return a
            .targets
            .iter()
            .map(|s| match s.as_str() {
                "claude" => "claude",
                "codex" => "codex",
                "opencode" => "opencode",
                _ => unreachable!(),
            })
            .collect();
    }
    let mut v = Vec::new();
    if a.claude {
        v.push("claude");
    }
    if a.codex {
        v.push("codex");
    }
    if a.opencode {
        v.push("opencode");
    }
    if v.is_empty() {
        vec!["claude", "codex", "opencode"]
    } else {
        v
    }
}
fn root(a: &SetupArgs) -> Result<PathBuf, AppError> {
    a.root
        .clone()
        .or_else(|| a.target_dir.clone())
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .ok_or_else(|| AppError::config("HOME is unset; pass --root explicitly"))
}
pub(crate) fn display_path(p: &Path) -> String {
    let s = p.to_string_lossy();
    std::env::var_os("HOME")
        .and_then(|h| {
            s.strip_prefix(h.to_string_lossy().as_ref())
                .map(|x| format!("~{x}"))
        })
        .unwrap_or_else(|| s.into_owned())
}
fn schema(p: &Path, expected: &str) -> AppError {
    AppError::config(format!("{}: expected {expected}", p.display()))
}
fn read_optional(p: &Path) -> Result<Option<String>, AppError> {
    match fs::read_to_string(p) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(AppError::config(format!(
            "cannot read {}: {e}",
            p.display()
        ))),
    }
}
fn read_json(p: &Path) -> Result<Value, AppError> {
    match read_optional(p)? {
        Some(s) => serde_json::from_str(&s).map_err(|e| {
            AppError::config(format!(
                "cannot parse {} at line {}, column {}",
                p.display(),
                e.line(),
                e.column()
            ))
        }),
        None => Ok(json!({})),
    }
}
fn read_toml(p: &Path) -> Result<toml::Value, AppError> {
    match read_optional(p)? {
        Some(s) => toml::from_str(&s).map_err(|e| {
            let location = e
                .span()
                .map(|span| format!(" near byte {}", span.start))
                .unwrap_or_default();
            AppError::config(format!("cannot parse {}{location}", p.display()))
        }),
        None => Ok(toml::Value::Table(Default::default())),
    }
}
fn json_text(value: &Value) -> Result<String, AppError> {
    serde_json::to_string_pretty(value)
        .map_err(|_| AppError::config("cannot serialize integration JSON"))
}

fn write_json(p: &Path, v: &Value) -> Result<bool, AppError> {
    write_atomic(p, &json_text(v)?)
}
fn write_atomic(p: &Path, s: &str) -> Result<bool, AppError> {
    if read_optional(p)?.as_deref() == Some(s) {
        return Ok(false);
    }
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| AppError::config(format!("cannot create {}: {e}", parent.display())))?;
    }
    let permissions = fs::metadata(p).ok().map(|metadata| metadata.permissions());
    let tmp = p.with_extension(format!("tmp-{}", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(
            permissions
                .as_ref()
                .map(PermissionsExt::mode)
                .unwrap_or(0o600),
        );
    }
    let mut file = options
        .open(&tmp)
        .map_err(|e| AppError::config(format!("cannot write {}: {e}", tmp.display())))?;
    file.write_all(s.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| AppError::config(format!("cannot write {}: {e}", tmp.display())))?;
    drop(file);
    if let Some(permissions) = permissions {
        fs::set_permissions(&tmp, permissions).map_err(|e| {
            AppError::config(format!(
                "cannot preserve permissions for {}: {e}",
                p.display()
            ))
        })?;
    }
    fs::rename(&tmp, p)
        .map_err(|e| AppError::config(format!("cannot replace {}: {e}", p.display())))?;
    Ok(true)
}
fn portable_executable(current: &Path) -> PathBuf {
    let Some(name) = current.file_name() else {
        return current.to_owned();
    };
    let current_canonical = current.canonicalize().ok();
    let matches_path = std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|directory| {
            directory
                .join(name)
                .canonicalize()
                .ok()
                .zip(current_canonical.as_ref())
                .is_some_and(|(candidate, current)| candidate == *current)
        })
    });
    if matches_path {
        PathBuf::from(name)
    } else {
        current.to_owned()
    }
}
fn hook_command(e: &Path) -> String {
    format!(
        "{} session context --format toon",
        shell_quote(&e.display().to_string())
    )
}
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
fn is_managed_hook(v: &Value) -> bool {
    v.get("managed_by").and_then(Value::as_str) == Some(MARKER)
}
fn merge_claude(v: &mut Value, e: &Path, p: &Path) -> Result<(), AppError> {
    let root = v.as_object_mut().ok_or_else(|| schema(p, "object"))?;
    let hooks = root
        .entry("hooks")
        .or_insert(json!({}))
        .as_object_mut()
        .ok_or_else(|| schema(p, "hooks object"))?;
    let groups = hooks
        .entry("SessionStart")
        .or_insert(json!([]))
        .as_array_mut()
        .ok_or_else(|| schema(p, "SessionStart array"))?;

    groups.retain_mut(|group| {
        let keep = if let Some(handlers) = group.get_mut("hooks").and_then(Value::as_array_mut) {
            handlers.retain(|handler| !is_managed_hook(handler));
            !handlers.is_empty()
        } else {
            true
        };
        if keep && group.get("managed_by").and_then(Value::as_str) == Some(MARKER) {
            if let Some(object) = group.as_object_mut() {
                object.remove("managed_by");
            }
        }
        keep
    });
    groups.push(json!({
        "matcher":"startup|resume|clear|compact|fork",
        "managed_by":MARKER,
        "hooks":[{
            "type":"command",
            "command":hook_command(e),
            "managed_by":MARKER
        }]
    }));
    Ok(())
}
fn merge_codex(v: &mut Value, e: &Path, p: &Path) -> Result<(), AppError> {
    merge_claude(v, e, p)
}
fn remove_hooks(v: &mut Value) {
    if let Some(groups) = v
        .pointer_mut("/hooks/SessionStart")
        .and_then(Value::as_array_mut)
    {
        groups.retain_mut(|group| {
            let keep = if let Some(hooks) = group.get_mut("hooks").and_then(Value::as_array_mut) {
                hooks.retain(|hook| !is_managed_hook(hook));
                !hooks.is_empty()
            } else {
                true
            };
            if keep && group.get("managed_by").and_then(Value::as_str) == Some(MARKER) {
                if let Some(object) = group.as_object_mut() {
                    object.remove("managed_by");
                }
            }
            keep
        });
    }
}
fn plugin(e: &Path) -> Result<String, AppError> {
    let executable = serde_json::to_string(&e.display().to_string())
        .map_err(|_| AppError::config("cannot serialize OpenCode executable path"))?;
    Ok(format!(
        "// {MARKER} managed plugin\nexport const CloudflareAxiPlugin = async ({{ $, directory }}) => ({{\n  \"experimental.chat.system.transform\": async (_input, output) => {{\n    const result = await $`${{{}}} session context --format toon`.cwd(directory).quiet().nothrow();\n    if (result.exitCode === 0) {{ const context = result.stdout.toString().trim().slice(0, 8192); if (context) output.system.push(context); }}\n  }},\n}});\n",
        executable
    ))
}

fn hook_status(
    p: &Path,
    executable: &Path,
    codex_config: Option<&Path>,
) -> Result<Value, AppError> {
    let Some(text) = read_optional(p)? else {
        return Ok(json!({"state":"missing", "path":display_path(p)}));
    };
    let value: Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(_) => return Ok(json!({"state":"malformed", "path":display_path(p)})),
    };
    let expected = hook_command(executable);
    let expected_matcher = "startup|resume|clear|compact|fork";
    let mut managed_groups = 0usize;
    let mut managed_handlers = 0usize;
    let mut all_valid = true;
    if let Some(groups) = value
        .pointer("/hooks/SessionStart")
        .and_then(Value::as_array)
    {
        for group in groups {
            let group_managed = group.get("managed_by").and_then(Value::as_str) == Some(MARKER);
            if group_managed {
                managed_groups += 1;
            }
            if let Some(handlers) = group.get("hooks").and_then(Value::as_array) {
                for handler in handlers {
                    if is_managed_hook(handler) {
                        managed_handlers += 1;
                        all_valid &= group_managed
                            && group.get("matcher").and_then(Value::as_str)
                                == Some(expected_matcher)
                            && handler.get("type").and_then(Value::as_str) == Some("command")
                            && handler.get("command").and_then(Value::as_str) == Some(&expected);
                    }
                }
            }
        }
    }
    let mut state = if managed_groups == 1 && managed_handlers == 1 && all_valid {
        "configured"
    } else if managed_groups > 0 || managed_handlers > 0 {
        "invalid_managed_hook"
    } else {
        "unmanaged"
    };
    let mut help = None;
    if state == "configured" {
        if let Some(config_path) = codex_config {
            let Some(text) = read_optional(config_path)? else {
                return Ok(json!({"state":"missing_config", "path":display_path(config_path)}));
            };
            let config = match toml::from_str::<toml::Value>(&text) {
                Ok(value) => value,
                Err(_) => {
                    return Ok(json!({"state":"malformed", "path":display_path(config_path)}));
                }
            };
            match config
                .get("features")
                .and_then(|value| value.get("hooks"))
                .and_then(toml::Value::as_bool)
            {
                Some(true) => {
                    state = "configured_trust_unverified";
                    help = Some("open Codex `/hooks` and review/trust this hook");
                }
                Some(false) => state = "disabled",
                None => state = "hooks_not_enabled",
            }
        }
    }
    Ok(json!({"state":state, "path":display_path(p), "help":help}))
}

fn plugin_status(p: &Path, executable: &Path) -> Result<Value, AppError> {
    let Some(text) = read_optional(p)? else {
        return Ok(json!({"state":"missing", "path":display_path(p)}));
    };
    let state = if !text.starts_with(&format!("// {MARKER} managed plugin\n")) {
        "unmanaged"
    } else if text == plugin(executable)? {
        "configured"
    } else {
        "stale_path"
    };
    Ok(json!({"state":state, "path":display_path(p)}))
}
