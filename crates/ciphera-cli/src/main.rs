mod commands;
mod config;
mod env_parser;
mod interactive;
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
use keyring::Entry;
use std::env;

#[derive(Parser, Debug)]
#[command(name = "ciphera")]
#[command(about = "Ciphera Secret Management System CLI", version)]
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
}

fn resolve_token(cli_token: Option<String>) -> Result<String, String> {
    if let Some(t) = cli_token {
        return Ok(t);
    }
    if let Ok(t) = env::var("CIPHERA_TOKEN") {
        return Ok(t);
    }
    if let Ok(stored) = Entry::new("ciphera", "session_token").and_then(|e| e.get_password()) {
        return Ok(stored);
    }
    Err("Not authenticated. Set CIPHERA_TOKEN, run `ciphera login`, or pass --token.".to_string())
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
            ProjectCommands::Create { name } => match resolve_token(cli.token) {
                Ok(token) => commands::handle_project_create(&api_url, &token, &name).await,
                Err(e) => Err(e),
            },
        },
        Commands::Config { command } => match command {
            ConfigCommands::SetApiUrl { url } => commands::handle_config_set_api_url(&url),
            ConfigCommands::Show => commands::handle_config_show(cli.api_url.as_deref()),
        },
        Commands::Secret { command } => match command {
            SecretCommands::Delete { key, project, env } => match resolve_token(cli.token) {
                Ok(token) => {
                    commands::handle_secret_delete(&api_url, &token, &key, project, env).await
                }
                Err(e) => Err(e),
            },
        },
        Commands::Import { file, project, env } => match resolve_token(cli.token) {
            Ok(token) => commands::handle_import(&api_url, &token, &file, project, env).await,
            Err(e) => Err(e),
        },
        Commands::Token { command } => match command {
            TokenCommands::Create {
                name,
                project,
                env,
                ttl_days,
                allow_cidrs,
            } => match resolve_token(cli.token) {
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
        },
        Commands::Rollback {
            key,
            target_version,
            project,
            env,
        } => match resolve_token(cli.token) {
            Ok(token) => {
                commands::handle_rollback(&api_url, &token, &key, target_version, project, env)
                    .await
            }
            Err(e) => Err(e),
        },
        Commands::Audit { project, limit } => match resolve_token(cli.token) {
            Ok(token) => commands::handle_audit(&api_url, &token, project, limit).await,
            Err(e) => Err(e),
        },
        Commands::Run {
            project,
            env,
            command,
        } => match resolve_token(cli.token) {
            Ok(token) => commands::handle_run(&api_url, &token, project, env, command).await,
            Err(e) => Err(e),
        },
        Commands::Devices { command } => match resolve_token(cli.token) {
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
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
