mod commands;
mod config;
mod env_parser;
mod interactive;
mod mcp;
mod uploader;

/// Best-effort hostname for the default device label; falls back to a
/// static name when the hostname is unavailable.
fn hostname_label() -> Option<String> {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .filter(|name| !name.is_empty() && name.len() <= 100)
}

use clap::{Parser, Subcommand};

fn cli_styles() -> clap::builder::Styles {
    use clap::builder::styling::AnsiColor;
    clap::builder::Styles::styled()
        .header(AnsiColor::Yellow.on_default().bold())
        .usage(AnsiColor::Yellow.on_default().bold())
        .literal(AnsiColor::Green.on_default().bold())
        .placeholder(AnsiColor::Cyan.on_default())
        .error(AnsiColor::Red.on_default().bold())
        .valid(AnsiColor::Green.on_default())
        .invalid(AnsiColor::Yellow.on_default())
}

const QUICK_EXAMPLES: &str = "\
Quick examples (see `ciphera <command> --help` for the full reference):
  ciphera login                                       # human login, opens a browser
  ciphera init --project <id> --env development        # bind this directory to a project/env
  ciphera run --env development -- npm start            # inject secrets, exec the command
  ciphera token create --name ci-deploy --project <id> --env production --ttl-days 90
                                                        # machine token for CI/CD, always expires
  ciphera doctor                                        # check auth, API reachability, keyring

Run `ciphera --help` for the full command list.";

#[derive(Parser, Debug)]
#[command(name = "ciphera")]
#[command(
    about = "Ciphera Secret Management System CLI",
    after_help = QUICK_EXAMPLES,
    version,
    styles = cli_styles()
)]
struct Cli {
    #[arg(
        long,
        global = true,
        help = "API URL (default: CIPHERA_API_URL env, config global, ou embutida no build)"
    )]
    api_url: Option<String>,

    #[arg(long, global = true, env = "CIPHERA_TOKEN")]
    token: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Authenticate via the browser (device flow) and save tokens
    /// securely into the OS Keyring. Alternatively pass --token, or
    /// --email and --password, to log in without the browser.
    #[command(long_about = "\
Authenticate via the browser (RFC 8628 device flow) and save the resulting \
session tokens securely into the OS Keyring. Alternatively pass --token \
(an existing session or service token) or --email/--password to log in \
without opening a browser.

Examples:
  ciphera login                         # opens a browser, polls until approved
  ciphera login --device-name my-laptop
  ciphera login --email a@b.com --password '...'
  ciphera login --token <existing-token>

IMPORTANT: this device flow is for a human authenticating interactively at \
a keyboard. It must never be scripted or run unattended on a server, in CI, \
or inside a container — it opens a browser and waits for a person to click \
through it. For any non-interactive context, use a scoped machine token \
instead: `ciphera token create` (see `ciphera token create --help`).")]
    Login {
        #[arg(long)]
        token: Option<String>,

        #[arg(long)]
        email: Option<String>,

        #[arg(long)]
        password: Option<String>,

        /// Friendly device label shown in the account area's session list
        /// (device-flow logins only). Defaults to the hostname.
        #[arg(long)]
        device_name: Option<String>,
    },

    /// Refresh the stored access token using the stored refresh token
    Refresh,

    /// Revoke the current session and remove stored tokens
    Logout,

    /// Initialize local ciphera.toml configuration file
    #[command(long_about = "\
Write a local ciphera.toml recording the project id (and, optionally, a \
default environment) so other commands (`ciphera run`, `ciphera import`, \
`ciphera token create`, ...) don't need --project/--env on every invocation.

Examples:
  ciphera init --project proj_abc123
  ciphera init --project proj_abc123 --env staging")]
    Init {
        #[arg(short, long)]
        project: String,

        #[arg(short, long)]
        env: Option<String>,
    },

    /// Project management subcommands
    Project {
        #[command(subcommand)]
        command: ProjectCommands,
    },

    /// Secret management subcommands
    Secret {
        #[command(subcommand)]
        command: SecretCommands,
    },

    /// Import secrets from a local .env file in batch
    Import {
        #[arg(short, long)]
        file: String,

        #[arg(short, long)]
        project: Option<String>,

        #[arg(short, long)]
        env: Option<String>,
    },

    /// Manage global CLI configuration
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },

    /// Create service tokens for CI/CD or machine authorization
    Token {
        #[command(subcommand)]
        command: TokenCommands,
    },

    /// Manage OIDC trust policies (exchange a CI/CD-provided OIDC token for
    /// a service token, without a static credential)
    #[command(long_about = "\
Manage OIDC trust policies: an admin registers which external OIDC issuer, \
audience and claims are trusted, and CI/CD then exchanges its own OIDC \
token (e.g. from an identity provider your infrastructure already trusts) \
for a normal, short-lived Ciphera service token via `ciphera token \
oidc-exchange` — no static, never-expiring credential needs to be stored \
in CI at all.

Examples:
  ciphera oidc-policy create --project my-project --env production \\
      --issuer https://auth.example.com --audience ciphera \\
      --claim sub=ci-deploy-bot --ttl-seconds 900
  ciphera oidc-policy list --project my-project
  ciphera oidc-policy revoke --project my-project --id <policy-id>")]
    OidcPolicy {
        #[command(subcommand)]
        command: OidcPolicyCommands,
    },

    /// Rollback a secret to a previous version
    Rollback {
        #[arg(short, long)]
        key: String,

        #[arg(short, long)]
        target_version: i32,

        #[arg(short, long)]
        project: Option<String>,

        #[arg(short, long)]
        env: Option<String>,
    },

    /// Display compliance audit logs for the project
    Audit {
        #[arg(short, long)]
        project: Option<String>,

        #[arg(short, long, default_value = "50")]
        limit: i64,
    },

    /// Inject secrets into environment and execute target command
    #[command(long_about = "\
Fetch every secret in a project/environment and exec the given command with \
them injected as environment variables. On Unix the child process replaces \
this one (exec), so secrets never sit in an intermediate shell's environment \
longer than necessary.

Examples:
  ciphera run -- npm start
  ciphera run --project proj_abc123 --env production -- ./server
  ciphera run --env staging -- docker compose up

Avoid redirecting this command's output to a file or a non-exec pipe \
(e.g. `ciphera run -- env > out.txt`) — that can leave decrypted values on \
disk or in a log. Let it exec the target process directly.")]
    Run {
        #[arg(short, long)]
        project: Option<String>,

        #[arg(short, long)]
        env: Option<String>,

        #[arg(last = true, required = true)]
        command: Vec<String>,
    },

    /// Manage pending `ciphera login` device approvals (Owner/Administrator
    /// only) and the org's device-approval policy
    Devices {
        #[command(subcommand)]
        command: DeviceCommands,
    },

    /// Metadata-only MCP server for AI coding assistants, plus its installer
    #[command(long_about = "\
Metadata-only Model Context Protocol server (`ciphera mcp serve`) and its \
installer for AI coding assistants. No tool this server exposes ever \
returns a decrypted secret value — it can list projects, environments, key \
names, tokens, pending device approvals, and the audit log, and it can \
create scoped machine tokens, but it cannot read a secret's value. That's a \
structural guarantee: there is no get_secret_value/reveal_secret tool.

  ciphera mcp serve      Run the server over stdio (usually launched by an
                          AI tool, not invoked directly)
  ciphera mcp install    Wire the server + a defense-in-depth guard hook
                          into Claude Code (.mcp.json, .claude/settings.json)
  ciphera mcp uninstall  Remove exactly what `install` added
")]
    Mcp {
        #[command(subcommand)]
        command: McpCommands,
    },

    /// Check API reachability, auth, and keyring availability
    Doctor,
}

#[derive(Subcommand, Debug)]
enum McpCommands {
    /// Run the metadata-only MCP server over stdio
    Serve,

    /// Wire the MCP server and guard hook into Claude Code (and print the
    /// equivalent config for other AI tools)
    Install {
        /// Print what would change without writing any files
        #[arg(long)]
        dry_run: bool,

        /// Skip interactive confirmation prompts (e.g. the opencode secret
        /// migration)
        #[arg(short, long)]
        yes: bool,

        /// Ciphera project id to store secrets found in an opencode config
        /// (Phase C1). Prompted for interactively if omitted and stdin is a
        /// TTY.
        #[arg(long)]
        project: Option<String>,

        /// Environment to store those secrets in
        #[arg(long)]
        env: Option<String>,
    },

    /// Remove exactly what `ciphera mcp install` added
    Uninstall,

    /// Hidden: PreToolUse hook classifier invoked by Claude Code, not by
    /// hand. Reads the hook payload from stdin.
    #[command(hide = true)]
    Guard,
}

#[derive(Subcommand, Debug)]
enum DeviceCommands {
    /// List device logins awaiting admin approval
    ListPending,

    /// Approve a pending device login by its id (from `list-pending`)
    Approve { id: String },

    /// Deny a pending device login by its id (from `list-pending`)
    Deny { id: String },

    /// Require an Owner/Administrator to approve every new `ciphera login`
    /// device before it can complete
    RequireApproval {
        #[arg(value_parser = ["on", "off"])]
        setting: String,
    },
}

#[derive(Subcommand, Debug)]
enum ProjectCommands {
    /// Create a new project
    Create {
        #[arg(short, long)]
        name: String,
    },
}

#[derive(Subcommand, Debug)]
enum ConfigCommands {
    /// Set the default API URL (persisted globally)
    SetApiUrl { url: String },

    /// Show the effective/resolved API URL (env, config, build default)
    Show,
}

#[derive(Subcommand, Debug)]
enum SecretCommands {
    /// Soft delete a secret (creates tombstone version)
    Delete {
        #[arg(short, long)]
        key: String,

        #[arg(short, long)]
        project: Option<String>,

        #[arg(short, long)]
        env: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum TokenCommands {
    /// Create a service token for machine authentication
    #[command(long_about = "\
Create a scoped, expiring machine (service) token. `--project` accepts a project \
name or UUID (the UUID is resolved automatically when a name is provided). \
This is the correct \
credential for CI/CD, a VPS, a container, or any other non-interactive \
context — never `ciphera login`'s device flow, which is for a human at a \
keyboard and must not be scripted.

Machine tokens always expire (--ttl-days, default 30, capped at 90 by the \
server) and can optionally be locked to specific source IPs \
(--allow-cidr, repeatable) for defense-in-depth if the caller's egress IP \
is known and stable.

Examples:
  ciphera token create --name ci-deploy --project my-project --env production
  ciphera token create --name vps-app --project my-project --env production --ttl-days 90 \\
      --allow-cidr 203.0.113.4/32")]
    Create {
        #[arg(short, long)]
        name: String,

        #[arg(short, long)]
        project: Option<String>,

        #[arg(short, long)]
        env: Option<String>,

        /// Token lifetime in days (default: 30, max: 90). Machine tokens
        /// always expire; there is no "no expiry" option.
        #[arg(long, default_value_t = 30)]
        ttl_days: i64,

        /// CIDR the token may be used from (e.g. 203.0.113.4/32). Repeatable;
        /// omit to leave the token unrestricted by IP.
        #[arg(long = "allow-cidr")]
        allow_cidrs: Vec<String>,
    },

    /// Exchange a CI/CD-provided OIDC token for a service token
    #[command(long_about = "\
Exchange an externally-signed OIDC token for a normal, short-lived Ciphera \
service token, per a trust policy an Owner/Admin already registered with \
`ciphera oidc-policy create`. Not session-authenticated: the OIDC token \
itself is the credential, so this works with no prior `ciphera login`.

Reads the token from --oidc-token, or the CIPHERA_OIDC_TOKEN env var if \
--oidc-token is omitted — prefer the env var in CI so the raw token never \
appears as a literal argument in a process listing.

Example (GitHub Actions, after requesting an OIDC token into $ID_TOKEN):
  export CIPHERA_OIDC_TOKEN=\"$ID_TOKEN\"
  ciphera token oidc-exchange")]
    OidcExchange {
        #[arg(
            long = "oidc-token",
            env = "CIPHERA_OIDC_TOKEN",
            hide_env_values = true
        )]
        oidc_token: String,
    },
}

#[derive(Subcommand, Debug)]
enum OidcPolicyCommands {
    /// Register a trusted OIDC issuer/audience/claims combination
    Create {
        #[arg(short, long)]
        project: Option<String>,

        #[arg(short, long)]
        env: Option<String>,

        /// The trusted issuer's URL, e.g. https://auth.example.com
        #[arg(long)]
        issuer: String,

        /// The `aud` claim a presented token must carry
        #[arg(long)]
        audience: String,

        /// A required claim as key=value; repeatable. The value may use a
        /// leading/trailing '*' as a glob (e.g. --claim ref=refs/heads/*).
        #[arg(long = "claim")]
        claims: Vec<String>,

        /// Lifetime, in seconds, of service tokens minted through this
        /// policy (default: 900 = 15 minutes).
        #[arg(long, default_value_t = 900)]
        ttl_seconds: i64,

        /// CIDR the minted token may be used from. Repeatable.
        #[arg(long = "allow-cidr")]
        allow_cidrs: Vec<String>,
    },

    /// List OIDC trust policies for a project
    List {
        #[arg(short, long)]
        project: Option<String>,
    },

    /// Revoke an OIDC trust policy
    Revoke {
        #[arg(short, long)]
        project: Option<String>,

        #[arg(long)]
        id: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let api_url = match config::validate_api_url(&config::resolve_api_url(cli.api_url.clone())) {
        Ok(url) => url,
        Err(error) => {
            eprintln!("Error: {error}");
            std::process::exit(2);
        }
    };

    let result = match cli.command {
        Commands::Login {
            token,
            email,
            password,
            device_name,
        } => match (token, email, password) {
            (Some(t), _, _) => commands::handle_login(&t),
            (None, Some(e), Some(p)) => commands::handle_login_password(&api_url, &e, &p).await,
            (None, None, None) => {
                let name = device_name.or_else(hostname_label);
                commands::handle_login_device(&api_url, name.as_deref()).await
            }
            (None, Some(_), None) => Err("Provide --password together with --email.".to_string()),
            (None, None, Some(_)) => Err("Provide --email together with --password.".to_string()),
        },
        Commands::Refresh => commands::handle_refresh(&api_url).await,
        Commands::Logout => commands::handle_logout(&api_url).await,
        Commands::Init { project, env } => commands::handle_init(&project, env.as_deref()),
        Commands::Project { command } => match command {
            ProjectCommands::Create { name } => {
                match commands::resolve_token(&api_url, cli.token).await {
                    Ok(token) => commands::handle_project_create(&api_url, &token, &name).await,
                    Err(e) => Err(e),
                }
            }
        },
        Commands::Config { command } => match command {
            ConfigCommands::SetApiUrl { url } => commands::handle_config_set_api_url(&url),
            ConfigCommands::Show => commands::handle_config_show(cli.api_url.as_deref()),
        },
        Commands::Secret { command } => match command {
            SecretCommands::Delete { key, project, env } => {
                match commands::resolve_token(&api_url, cli.token).await {
                    Ok(token) => {
                        commands::handle_secret_delete(&api_url, &token, &key, project, env).await
                    }
                    Err(e) => Err(e),
                }
            }
        },
        Commands::Import { file, project, env } => {
            match commands::resolve_token(&api_url, cli.token).await {
                Ok(token) => commands::handle_import(&api_url, &token, &file, project, env).await,
                Err(e) => Err(e),
            }
        }
        Commands::Token { command } => match command {
            TokenCommands::Create {
                name,
                project,
                env,
                ttl_days,
                allow_cidrs,
            } => match commands::resolve_token(&api_url, cli.token).await {
                Ok(token) => {
                    commands::handle_token_create(
                        &api_url,
                        &token,
                        &name,
                        project,
                        env,
                        ttl_days,
                        allow_cidrs,
                    )
                    .await
                }
                Err(e) => Err(e),
            },
            TokenCommands::OidcExchange { oidc_token } => {
                commands::handle_oidc_exchange(&api_url, &oidc_token).await
            }
        },
        Commands::OidcPolicy { command } => match command {
            OidcPolicyCommands::Create {
                project,
                env,
                issuer,
                audience,
                claims,
                ttl_seconds,
                allow_cidrs,
            } => match commands::resolve_token(&api_url, cli.token).await {
                Ok(token) => {
                    commands::handle_oidc_policy_create(
                        &api_url,
                        &token,
                        &issuer,
                        &audience,
                        &claims,
                        project,
                        env,
                        ttl_seconds,
                        allow_cidrs,
                    )
                    .await
                }
                Err(e) => Err(e),
            },
            OidcPolicyCommands::List { project } => {
                match commands::resolve_token(&api_url, cli.token).await {
                    Ok(token) => commands::handle_oidc_policy_list(&api_url, &token, project).await,
                    Err(e) => Err(e),
                }
            }
            OidcPolicyCommands::Revoke { project, id } => {
                match commands::resolve_token(&api_url, cli.token).await {
                    Ok(token) => {
                        commands::handle_oidc_policy_revoke(&api_url, &token, project, &id).await
                    }
                    Err(e) => Err(e),
                }
            }
        },
        Commands::Rollback {
            key,
            target_version,
            project,
            env,
        } => match commands::resolve_token(&api_url, cli.token).await {
            Ok(token) => {
                commands::handle_rollback(&api_url, &token, &key, target_version, project, env)
                    .await
            }
            Err(e) => Err(e),
        },
        Commands::Audit { project, limit } => {
            match commands::resolve_token(&api_url, cli.token).await {
                Ok(token) => commands::handle_audit(&api_url, &token, project, limit).await,
                Err(e) => Err(e),
            }
        }
        Commands::Run {
            project,
            env,
            command,
        } => match commands::resolve_token(&api_url, cli.token).await {
            Ok(token) => commands::handle_run(&api_url, &token, project, env, command).await,
            Err(e) => Err(e),
        },
        Commands::Devices { command } => match commands::resolve_token(&api_url, cli.token).await {
            Ok(token) => match command {
                DeviceCommands::ListPending => {
                    commands::handle_devices_list_pending(&api_url, &token).await
                }
                DeviceCommands::Approve { id } => {
                    commands::handle_devices_approve(&api_url, &token, &id).await
                }
                DeviceCommands::Deny { id } => {
                    commands::handle_devices_deny(&api_url, &token, &id).await
                }
                DeviceCommands::RequireApproval { setting } => {
                    commands::handle_devices_require_approval(&api_url, &token, setting == "on")
                        .await
                }
            },
            Err(e) => Err(e),
        },
        Commands::Mcp { command } => match command {
            McpCommands::Serve => match commands::resolve_token(&api_url, cli.token).await {
                Ok(token) => mcp::serve(api_url, token).await,
                Err(e) => Err(e),
            },
            McpCommands::Install {
                dry_run,
                yes,
                project,
                env,
            } => match mcp::install::install(dry_run) {
                Ok(()) if dry_run => Ok(()),
                Ok(()) => match commands::resolve_token(&api_url, cli.token).await {
                    Ok(token) => {
                        mcp::install::migrate_opencode(&api_url, &token, project, env, yes).await
                    }
                    Err(_) => Ok(()), // no ciphera auth yet: skip the opencode migration silently
                },
                Err(e) => Err(e),
            },
            McpCommands::Uninstall => mcp::install::uninstall(),
            McpCommands::Guard => mcp::guard::run(),
        },
        Commands::Doctor => commands::handle_doctor(&api_url, cli.token).await,
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
