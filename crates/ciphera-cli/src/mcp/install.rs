//! `ciphera mcp install` / `uninstall`: wires the `ciphera mcp serve` MCP
//! server and the `ciphera mcp guard` PreToolUse hook into Claude Code, and
//! (Phase C1) offers to migrate inline secrets out of an opencode config.
//!
//! Claude Code's config schema (verified against
//! <https://code.claude.com/docs/en/mcp.md> and
//! <https://code.claude.com/docs/en/hooks.md>):
//! - MCP servers are declared in `.mcp.json` (project root, or `~/.mcp.json`
//!   for a user-level default), under a top-level `"mcpServers"` object.
//! - Hooks are declared in `.claude/settings.json` (project) or
//!   `~/.claude/settings.json` (user), under `"hooks"."PreToolUse"`: an
//!   array of `{"matcher": "<tool>", "hooks": [{"type":"command","command":"..."}]}`
//!   groups.
//!
//! Every write here is a JSON merge: only the keys `ciphera mcp install`
//! itself owns are added/updated/removed. Everything else in the file is
//! left untouched.

use serde_json::{Map, Value, json};
use std::env;
use std::path::{Path, PathBuf};

use super::opencode;

/// The exact hook command string used to tag (and later find/remove) the
/// guard hook entry this command owns. Also used for idempotency: re-running
/// `install` never adds a second copy.
const GUARD_HOOK_COMMAND: &str = "ciphera mcp guard";
const MCP_SERVER_NAME: &str = "ciphera";

fn home_dir() -> Result<PathBuf, String> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "Could not determine home directory (HOME is not set).".to_string())
}

fn git_project_root() -> Option<PathBuf> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

fn mcp_json_path() -> PathBuf {
    match git_project_root() {
        Some(root) => root.join(".mcp.json"),
        None => home_dir()
            .map(|h| h.join(".mcp.json"))
            .unwrap_or_else(|_| PathBuf::from(".mcp.json")),
    }
}

fn settings_json_path() -> Result<PathBuf, String> {
    match git_project_root() {
        Some(root) => Ok(root.join(".claude").join("settings.json")),
        None => Ok(home_dir()?.join(".claude").join("settings.json")),
    }
}

fn read_json_object(path: &Path) -> Result<Map<String, Value>, String> {
    if !path.is_file() {
        return Ok(Map::new());
    }
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    if content.trim().is_empty() {
        return Ok(Map::new());
    }
    let value: Value = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse {} as JSON: {e}", path.display()))?;
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(format!(
            "{} does not contain a JSON object at its root; refusing to touch it.",
            path.display()
        )),
    }
}

fn write_json_object(path: &Path, map: &Map<String, Value>) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create {}: {e}", parent.display()))?;
    }
    let content = serde_json::to_string_pretty(&Value::Object(map.clone()))
        .map_err(|e| format!("Failed to serialize {}: {e}", path.display()))?;
    std::fs::write(path, content + "\n")
        .map_err(|e| format!("Failed to write {}: {e}", path.display()))
}

fn pretty(map: &Map<String, Value>) -> String {
    serde_json::to_string_pretty(&Value::Object(map.clone())).unwrap_or_default()
}

/// Minimal line-based diff (LCS), good enough for the small JSON merges
/// this command makes. `-` lines were removed, `+` lines were added.
fn print_diff(before: &str, after: &str) {
    let a: Vec<&str> = before.lines().collect();
    let b: Vec<&str> = after.lines().collect();
    let n = a.len();
    let m = b.len();
    let mut lcs = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if a[i] == b[j] {
            println!("  {}", a[i]);
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            println!("- {}", a[i]);
            i += 1;
        } else {
            println!("+ {}", b[j]);
            j += 1;
        }
    }
    while i < n {
        println!("- {}", a[i]);
        i += 1;
    }
    while j < m {
        println!("+ {}", b[j]);
        j += 1;
    }
}

fn ciphera_mcp_server_entry() -> Value {
    json!({
        "command": "ciphera",
        "args": ["mcp", "serve"]
    })
}

/// Merges (or removes, if `remove` is true) the ciphera entry under
/// `mcpServers`. Returns the updated map.
fn apply_mcp_json(mut root: Map<String, Value>, remove: bool) -> Map<String, Value> {
    let servers = root
        .entry("mcpServers".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    if let Value::Object(servers) = servers {
        if remove {
            servers.remove(MCP_SERVER_NAME);
        } else {
            servers.insert(MCP_SERVER_NAME.to_string(), ciphera_mcp_server_entry());
        }
    }
    root
}

/// Merges (or removes) the guard PreToolUse/Bash hook entry.
fn apply_settings_json(mut root: Map<String, Value>, remove: bool) -> Map<String, Value> {
    if remove {
        if let Some(Value::Object(hooks)) = root.get_mut("hooks")
            && let Some(Value::Array(pre_tool_use)) = hooks.get_mut("PreToolUse")
        {
            for group in pre_tool_use.iter_mut() {
                if let Value::Object(group) = group
                    && group.get("matcher").and_then(Value::as_str) == Some("Bash")
                    && let Some(Value::Array(group_hooks)) = group.get_mut("hooks")
                {
                    group_hooks.retain(|h| {
                        h.get("command").and_then(Value::as_str) != Some(GUARD_HOOK_COMMAND)
                    });
                }
            }
            pre_tool_use.retain(|group| {
                group
                    .get("hooks")
                    .and_then(Value::as_array)
                    .is_none_or(|h| !h.is_empty())
            });
            if pre_tool_use.is_empty() {
                hooks.remove("PreToolUse");
            }
            if hooks.is_empty() {
                root.remove("hooks");
            }
        }
        return root;
    }

    let hooks = root
        .entry("hooks".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let Value::Object(hooks) = hooks else {
        return root;
    };
    let pre_tool_use = hooks
        .entry("PreToolUse".to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    let Value::Array(pre_tool_use) = pre_tool_use else {
        return root;
    };

    let already_present = pre_tool_use.iter().any(|group| {
        group.get("matcher").and_then(Value::as_str) == Some("Bash")
            && group
                .get("hooks")
                .and_then(Value::as_array)
                .is_some_and(|hooks| {
                    hooks.iter().any(|h| {
                        h.get("command").and_then(Value::as_str) == Some(GUARD_HOOK_COMMAND)
                    })
                })
    });
    if already_present {
        return root;
    }

    if let Some(group) = pre_tool_use
        .iter_mut()
        .find(|group| group.get("matcher").and_then(Value::as_str) == Some("Bash"))
        && let Value::Object(group) = group
        && let Some(Value::Array(group_hooks)) = group.get_mut("hooks")
    {
        group_hooks.push(json!({"type": "command", "command": GUARD_HOOK_COMMAND}));
        return root;
    }

    pre_tool_use.push(json!({
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": GUARD_HOOK_COMMAND}]
    }));
    root
}

fn other_tools_note() {
    println!("\nFor AI tools other than Claude Code: add this MCP server entry to whatever");
    println!("config file that tool reads for MCP servers (the exact file/location differs");
    println!("per tool and isn't guessed here):");
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "mcpServers": { MCP_SERVER_NAME: ciphera_mcp_server_entry() }
        }))
        .unwrap_or_default()
    );
}

pub fn install(dry_run: bool) -> Result<(), String> {
    let mcp_path = mcp_json_path();
    let settings_path = settings_json_path()?;

    let mcp_before = read_json_object(&mcp_path)?;
    let mcp_after = apply_mcp_json(mcp_before.clone(), false);

    let settings_before = read_json_object(&settings_path)?;
    let settings_after = apply_settings_json(settings_before.clone(), false);

    if dry_run {
        println!("--dry-run: no files written.\n");
        println!("{}:", mcp_path.display());
        print_diff(&pretty(&mcp_before), &pretty(&mcp_after));
        println!("\n{}:", settings_path.display());
        print_diff(&pretty(&settings_before), &pretty(&settings_after));
        other_tools_note();
        return Ok(());
    }

    write_json_object(&mcp_path, &mcp_after)?;
    println!(
        "Registered the ciphera MCP server in {}",
        mcp_path.display()
    );

    write_json_object(&settings_path, &settings_after)?;
    println!(
        "Installed the `ciphera mcp guard` PreToolUse hook in {}",
        settings_path.display()
    );

    println!("\nRestart Claude Code (or run `/mcp` to reload) to pick up the new MCP server.");
    other_tools_note();
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    let mcp_path = mcp_json_path();
    let settings_path = settings_json_path()?;

    let mcp_before = read_json_object(&mcp_path)?;
    let mcp_after = apply_mcp_json(mcp_before.clone(), true);
    if mcp_after != mcp_before {
        write_json_object(&mcp_path, &mcp_after)?;
        println!(
            "Removed the ciphera MCP server entry from {}",
            mcp_path.display()
        );
    } else {
        println!(
            "No ciphera MCP server entry found in {}",
            mcp_path.display()
        );
    }

    let settings_before = read_json_object(&settings_path)?;
    let settings_after = apply_settings_json(settings_before.clone(), true);
    if settings_after != settings_before {
        write_json_object(&settings_path, &settings_after)?;
        println!(
            "Removed the ciphera guard hook from {}",
            settings_path.display()
        );
    } else {
        println!("No ciphera guard hook found in {}", settings_path.display());
    }

    Ok(())
}

/// Phase C1: scan any discoverable opencode config for inline secrets and
/// offer to migrate them into Ciphera. Best-effort — only runs when a
/// config is actually found, and never guesses which ciphera
/// project/environment to store secrets in (takes `--project`/`--env`, or
/// prompts interactively, or prints instructions when neither is possible).
pub async fn migrate_opencode(
    api_url: &str,
    token: &str,
    project: Option<String>,
    env_name: Option<String>,
    assume_yes: bool,
) -> Result<(), String> {
    let configs = opencode::discover_configs();
    if configs.is_empty() {
        return Ok(());
    }

    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());

    let (project_id, environment) = match (project, env_name) {
        (Some(p), Some(e)) => (p, e),
        _ if is_tty => {
            use dialoguer::Input;
            let project_id: String = Input::new()
                .with_prompt("Ciphera project id to store opencode secrets in")
                .interact_text()
                .map_err(|e| format!("Prompt failed: {e}"))?;
            let environment: String = Input::new()
                .with_prompt("Environment")
                .default("development".to_string())
                .interact_text()
                .map_err(|e| format!("Prompt failed: {e}"))?;
            (project_id, environment)
        }
        _ => {
            println!(
                "\nFound an opencode config ({}) but no --project/--env was given and stdin isn't \
                a TTY to prompt for one. Re-run with `ciphera mcp install --project <id> --env <name>` \
                to also migrate inline secrets out of it.",
                configs[0].display()
            );
            return Ok(());
        }
    };

    for path in configs {
        opencode::migrate_config(&path, api_url, token, &project_id, &environment, assume_yes)
            .await?;
    }

    Ok(())
}
