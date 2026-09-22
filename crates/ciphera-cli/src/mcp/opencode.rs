//! Phase C1: detect inline secret-shaped values in opencode's config
//! (`opencode.json`) and offer to move them into Ciphera, rewriting the
//! config to opencode's own `{env:VAR_NAME}` interpolation (confirmed
//! supported, alongside `{file:...}`, in opencode's docs) so the plaintext
//! value never has to live in the config file again.
//!
//! Scope for v1: opencode specifically — its config shape and `{env:}`
//! interpolation are confirmed. Any other tool that supports the same
//! `{env:}`-style substitution can be wired the same way later; we don't
//! guess at config shapes we haven't verified.

use crate::uploader::Uploader;
use ciphera_core::SecretInput;
use dialoguer::Confirm;
use serde_json::Value;
use std::env;
use std::path::{Path, PathBuf};

/// One inline secret-shaped value found in an opencode config, addressed by
/// a human-readable location (for the diff) and the JSON pointer used to
/// rewrite it.
struct Finding {
    /// e.g. "provider.anthropic.options.apiKey"
    location: String,
    pointer: String,
    value: String,
    /// Env var name opencode's `{env:...}` syntax should reference.
    var_name: String,
}

fn is_placeholder(value: &str) -> bool {
    value.starts_with("{env:") || value.starts_with("{file:")
}

fn sanitize_env_var_component(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// Walks the known secret-bearing locations in an opencode config:
/// `provider.*.options.apiKey`, `mcp.*.environment.*`, `mcp.*.headers.*`.
fn find_inline_secrets(config: &Value) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(providers) = config.get("provider").and_then(Value::as_object) {
        for (provider_id, provider) in providers {
            if let Some(api_key) = provider
                .get("options")
                .and_then(|o| o.get("apiKey"))
                .and_then(Value::as_str)
                && !is_placeholder(api_key)
                && !api_key.trim().is_empty()
            {
                findings.push(Finding {
                    location: format!("provider.{provider_id}.options.apiKey"),
                    pointer: format!("/provider/{provider_id}/options/apiKey"),
                    value: api_key.to_string(),
                    var_name: format!("{}_API_KEY", sanitize_env_var_component(provider_id)),
                });
            }
        }
    }

    if let Some(servers) = config.get("mcp").and_then(Value::as_object) {
        for (mcp_id, server) in servers {
            if let Some(environment) = server.get("environment").and_then(Value::as_object) {
                for (env_key, env_value) in environment {
                    if let Some(v) = env_value.as_str()
                        && !is_placeholder(v)
                        && !v.trim().is_empty()
                    {
                        findings.push(Finding {
                            location: format!("mcp.{mcp_id}.environment.{env_key}"),
                            pointer: format!("/mcp/{mcp_id}/environment/{env_key}"),
                            value: v.to_string(),
                            // The key here is already meant to be an env
                            // var name (it *is* the child process's env).
                            var_name: sanitize_env_var_component(env_key),
                        });
                    }
                }
            }
            if let Some(headers) = server.get("headers").and_then(Value::as_object) {
                for (header_key, header_value) in headers {
                    if let Some(v) = header_value.as_str()
                        && !is_placeholder(v)
                        && !v.trim().is_empty()
                    {
                        findings.push(Finding {
                            location: format!("mcp.{mcp_id}.headers.{header_key}"),
                            pointer: format!("/mcp/{mcp_id}/headers/{header_key}"),
                            value: v.to_string(),
                            var_name: format!(
                                "{}_{}",
                                sanitize_env_var_component(mcp_id),
                                sanitize_env_var_component(header_key)
                            ),
                        });
                    }
                }
            }
        }
    }

    findings
}

fn mask(value: &str) -> String {
    if value.len() <= 4 {
        "*".repeat(value.len())
    } else {
        format!("{}...{}", &value[..2], "*".repeat(6))
    }
}

fn project_config_path() -> Option<PathBuf> {
    let candidate = Path::new(".opencode/opencode.json");
    candidate.is_file().then(|| candidate.to_path_buf())
}

fn user_config_path() -> Option<PathBuf> {
    let home = env::var_os("HOME")?;
    let candidate = PathBuf::from(home).join(".config/opencode/opencode.json");
    candidate.is_file().then_some(candidate)
}

/// Returns every opencode config file this session can find, project-local
/// first.
pub fn discover_configs() -> Vec<PathBuf> {
    [project_config_path(), user_config_path()]
        .into_iter()
        .flatten()
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub async fn migrate_config(
    path: &Path,
    api_url: &str,
    token: &str,
    project_id: &str,
    environment: &str,
    assume_yes: bool,
) -> Result<(), String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    let mut config: Value = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse {}: {e}", path.display()))?;

    let findings = find_inline_secrets(&config);
    if findings.is_empty() {
        println!("{}: no inline secret-shaped values found.", path.display());
        return Ok(());
    }

    println!(
        "{}: found {} inline secret-shaped value(s):",
        path.display(),
        findings.len()
    );
    for f in &findings {
        println!(
            "  - {} = \"{}\"  ->  \"{{env:{}}}\"",
            f.location,
            mask(&f.value),
            f.var_name
        );
    }
    println!(
        "\nThese will be stored as Ciphera secrets in project {project_id} [{environment}] and \
        removed from {}. Going forward, launch opencode via:",
        path.display()
    );
    println!("  ciphera run --project {project_id} --env {environment} -- opencode");

    if !assume_yes {
        let confirmed = Confirm::new()
            .with_prompt("Apply this rewrite?")
            .default(false)
            .interact()
            .map_err(|e| format!("Prompt failed: {e}"))?;
        if !confirmed {
            println!("Aborted; {} left unchanged.", path.display());
            return Ok(());
        }
    }

    let secrets: Vec<SecretInput> = findings
        .iter()
        .map(|f| SecretInput {
            key: f.var_name.clone(),
            value: f.value.clone(),
        })
        .collect();

    let uploader = Uploader::new(api_url.to_string(), token.to_string());
    uploader
        .upload_in_batches(project_id, environment, secrets, 50)
        .await?;

    for f in &findings {
        let pointer_parts: Vec<&str> = f.pointer.split('/').filter(|p| !p.is_empty()).collect();
        if let Some(slot) = pointer_into_mut(&mut config, &pointer_parts) {
            *slot = Value::String(format!("{{env:{}}}", f.var_name));
        }
    }

    let rewritten = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize rewritten config: {e}"))?;
    std::fs::write(path, rewritten + "\n")
        .map_err(|e| format!("Failed to write {}: {e}", path.display()))?;

    println!(
        "Rewrote {} and stored the {} value(s) in Ciphera.",
        path.display(),
        findings.len()
    );
    Ok(())
}

fn pointer_into_mut<'a>(root: &'a mut Value, parts: &[&str]) -> Option<&'a mut Value> {
    let mut current = root;
    for part in parts {
        current = current.get_mut(*part)?;
    }
    Some(current)
}
