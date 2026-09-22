//! `ciphera mcp guard`: a hidden subcommand used as a Claude Code
//! `PreToolUse` hook (matching the `Bash` tool). Reads the hook's proposed
//! tool input as JSON on stdin and blocks commands that look like an
//! attempt to print/exfiltrate a secret value.
//!
//! This is defense-in-depth, not a guarantee: the pattern list below is
//! conservative and will not catch every way to leak a value through a
//! shell (e.g. anything routed through an intermediate script). It exists
//! to catch the obvious, common cases — reading `.env`/`.ciphera` files
//! directly, dumping the process environment, or hitting the reveal
//! endpoint — cheaply, before the command runs.
//!
//! Claude Code's hook contract (see
//! <https://docs.claude.com/en/docs/claude-code/hooks>): the hook receives a
//! JSON object on stdin describing the proposed tool call, and communicates
//! a decision either via exit code (0 = allow, 2 = block, stderr shown to
//! the model) or by printing a JSON object with a `hookSpecificOutput`
//! block. We use the simple exit-code contract here.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct HookInput {
    #[serde(default)]
    tool_name: Option<String>,
    #[serde(default)]
    tool_input: Option<ToolInput>,
}

#[derive(Debug, Deserialize)]
struct ToolInput {
    #[serde(default)]
    command: Option<String>,
}

/// Patterns that look like an attempt to print or exfiltrate a secret
/// value. Matched case-insensitively against the raw command string.
const DENY_PATTERNS: &[&str] = &[
    // Dumping the process environment (where `ciphera run` injects
    // secrets) rather than letting it exec the target process directly.
    "printenv",
    "env |",
    "env >",
    "export -p",
];

/// The reveal endpoint's path shape: `/secrets/{environment}/{key}/value`.
/// Matched as two substrings rather than a literal path so it still catches
/// the endpoint being hit through a variable or a differently-rooted URL.
fn references_reveal_endpoint(command: &str) -> bool {
    command.contains("secrets") && command.contains("/value")
}

/// Extra scrutiny for `cat`/`grep` specifically: only deny when they also
/// reference an env/ciphera-shaped path (a bare `cat file.txt` is fine).
const FILE_READERS: &[&str] = &["cat ", "grep ", "less ", "more "];
const SECRET_SHAPED_PATHS: &[&str] = &[".env", ".ciphera"];

/// `ciphera run ... > file` / `ciphera run ... | something-other-than-exec`
/// redirecting the injected-secrets subprocess output somewhere persistent.
fn looks_like_redirected_run(command: &str) -> bool {
    let lower = command.to_lowercase();
    if !lower.contains("ciphera run") {
        return false;
    }
    lower.contains('>') || lower.contains(" | tee") || lower.contains(" | cat")
}

fn command_is_suspicious(command: &str) -> bool {
    let lower = command.to_lowercase();

    if looks_like_redirected_run(&lower) {
        return true;
    }

    if references_reveal_endpoint(&lower) {
        return true;
    }

    for reader in FILE_READERS {
        if lower.contains(reader) && SECRET_SHAPED_PATHS.iter().any(|p| lower.contains(p)) {
            return true;
        }
    }

    DENY_PATTERNS.iter().any(|pat| lower.contains(pat))
}

/// Reads the hook payload from stdin, decides, and exits the process:
/// exit 0 (allow) for anything that doesn't match the denylist, exit 2
/// (block, per Claude Code's PreToolUse contract) with an explanation on
/// stderr for anything that does. Non-`Bash` tool calls and unparseable
/// input are allowed through (fail open — this is a guard, not the primary
/// access control).
pub fn run() -> Result<(), String> {
    use std::io::Read;

    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        return Ok(());
    }

    let parsed: HookInput = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };

    if parsed.tool_name.as_deref() != Some("Bash") {
        return Ok(());
    }

    let Some(command) = parsed.tool_input.and_then(|t| t.command) else {
        return Ok(());
    };

    if command_is_suspicious(&command) {
        eprintln!(
            "ciphera mcp guard: blocked a command that looks like it could print or \
            exfiltrate a secret value ({command:?}). This is a conservative, \
            defense-in-depth check, not a guarantee — see `ciphera mcp install --help`. \
            If this is a false positive, run the command outside Claude Code."
        );
        std::process::exit(2);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_cat_on_env_file() {
        assert!(command_is_suspicious("cat .env"));
        assert!(command_is_suspicious("cat .env.production"));
    }

    #[test]
    fn blocks_grep_on_ciphera_dir() {
        assert!(command_is_suspicious("grep -r API_KEY .ciphera/"));
    }

    #[test]
    fn blocks_printenv_and_env_dump() {
        assert!(command_is_suspicious("printenv"));
        assert!(command_is_suspicious("env | grep SECRET"));
    }

    #[test]
    fn blocks_reveal_endpoint_reference() {
        assert!(command_is_suspicious(
            "curl https://api.ciphera.dev/v1/projects/p1/secrets/prod/KEY/value"
        ));
    }

    #[test]
    fn blocks_redirected_ciphera_run() {
        assert!(command_is_suspicious(
            "ciphera run --env prod -- env > out.txt"
        ));
    }

    #[test]
    fn allows_plain_ciphera_run() {
        assert!(!command_is_suspicious(
            "ciphera run --env prod -- npm start"
        ));
    }

    #[test]
    fn allows_unrelated_commands() {
        assert!(!command_is_suspicious("ls -la"));
        assert!(!command_is_suspicious("git status"));
        assert!(!command_is_suspicious("cat README.md"));
    }
}
