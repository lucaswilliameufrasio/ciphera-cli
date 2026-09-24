use crate::config::{
    DEFAULT_API_URL, GlobalConfig, load_global_config, resolve_api_url, resolve_context,
    save_global_config, write_ciphera_toml,
};
use crate::env_parser::parse_env_file;
use crate::uploader::Uploader;
use base64::Engine as _;
use ciphera_core::auth::AuthTokens;
use ciphera_core::{
    AuditLogItem, CreateOidcTrustPolicyRequest, CreateProjectRequest, CreateProjectResponse,
    CreateTokenRequest, CreateTokenResponse, OidcTokenExchangeRequest, OidcTrustPolicyInfo,
    RollbackRequest, SecretOutput,
};
use keyring::Entry;
use reqwest::Client;
use std::env;
use std::process::Command;

/// Refresh proactively once the access token has this many seconds or less
/// left, so a request never races an expiry that lands mid-flight.
const TOKEN_REFRESH_SKEW_SECONDS: i64 = 30;

/// Best-effort read of a JWT's `exp` claim, without verifying the signature
/// (the server is the source of truth on validity; this is only used to
/// decide whether it's worth trying a proactive refresh). Returns `None` for
/// anything that isn't a 3-part JWT with a numeric `exp` (e.g. an opaque
/// service token), in which case the caller should use the token as-is and
/// let the API reject it if it's actually invalid.
fn decode_jwt_exp(token: &str) -> Option<i64> {
    let payload_b64 = token.split('.').nth(1)?;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    value.get("exp")?.as_i64()
}

enum RefreshError {
    /// Couldn't even reach the API (DNS, connection refused, timeout, ...).
    Network(String),
    /// The API rejected the refresh token itself (expired, revoked, or
    /// invalid) — only `ciphera login` can fix this.
    InvalidRefreshToken(String),
    /// The API reached but returned something else unexpected.
    Server(String),
}

async fn do_refresh(api_url: &str, refresh_token: String) -> Result<AuthTokens, RefreshError> {
    let client = Client::new();
    let url = format!("{}/v1/auth/refresh", api_url);

    let response = client
        .post(&url)
        .json(&ciphera_core::auth::RefreshRequest { refresh_token })
        .send()
        .await
        .map_err(|e| RefreshError::Network(e.to_string()))?;

    let status = response.status();
    if status.is_success() {
        response
            .json::<AuthTokens>()
            .await
            .map_err(|e| RefreshError::Server(format!("failed to parse refresh response: {e}")))
    } else if status == reqwest::StatusCode::UNAUTHORIZED
        || status == reqwest::StatusCode::FORBIDDEN
    {
        Err(RefreshError::InvalidRefreshToken(
            response.text().await.unwrap_or_default(),
        ))
    } else {
        let err_text = response.text().await.unwrap_or_default();
        Err(RefreshError::Server(format!("{status}: {err_text}")))
    }
}

/// Resolves the bearer token for an API call, transparently refreshing the
/// stored session first if it's expired or about to expire. This is what
/// every authenticated command should call instead of reading the keyring
/// directly, so users never have to run `ciphera refresh` by hand.
pub async fn resolve_token(api_url: &str, cli_token: Option<String>) -> Result<String, String> {
    if let Some(t) = cli_token {
        return Ok(t);
    }
    if let Ok(t) = env::var("CIPHERA_TOKEN") {
        return Ok(t);
    }

    let stored = match Entry::new("ciphera", "session_token").and_then(|e| e.get_password()) {
        Ok(t) => t,
        Err(_) => {
            return Err(
                "Not authenticated. Set CIPHERA_TOKEN, run `ciphera login`, or pass --token."
                    .to_string(),
            );
        }
    };

    let needs_refresh = match decode_jwt_exp(&stored) {
        Some(exp) => exp <= chrono::Utc::now().timestamp() + TOKEN_REFRESH_SKEW_SECONDS,
        None => false,
    };

    if !needs_refresh {
        return Ok(stored);
    }

    let refresh_token = match Entry::new("ciphera", "refresh_token").and_then(|e| e.get_password())
    {
        Ok(t) => t,
        // No refresh token stored (e.g. a service token was saved via
        // `ciphera login --token`): use the access token as-is and let the
        // API's own 401 explain things if it's truly expired.
        Err(_) => return Ok(stored),
    };

    match do_refresh(api_url, refresh_token).await {
        Ok(tokens) => {
            save_tokens(&tokens).await?;
            Ok(tokens.access_token)
        }
        Err(RefreshError::InvalidRefreshToken(msg)) => Err(format!(
            "Your session has expired and could not be refreshed automatically ({}). Run `ciphera login` to sign in again.",
            if msg.trim().is_empty() {
                "refresh token rejected".to_string()
            } else {
                msg
            }
        )),
        Err(RefreshError::Network(msg)) => Err(format!(
            "Could not reach {} to refresh your session: {}. Check your network connection or --api-url and try again; if it keeps happening, run `ciphera login`.",
            api_url, msg
        )),
        Err(RefreshError::Server(msg)) => Err(format!(
            "Automatic token refresh failed ({}). Try the command again; if it keeps failing, run `ciphera login`.",
            msg
        )),
    }
}

pub fn handle_login(token: &str) -> Result<(), String> {
    let entry =
        Entry::new("ciphera", "session_token").map_err(|e| format!("Keyring error: {}", e))?;
    entry
        .set_password(token)
        .map_err(|e| format!("Failed to save token to OS Keyring: {}", e))?;

    println!("Successfully authenticated! Session token stored securely in OS Keyring.");
    Ok(())
}

async fn save_tokens(tokens: &AuthTokens) -> Result<(), String> {
    Entry::new("ciphera", "session_token")
        .map_err(|e| format!("Keyring error: {}", e))?
        .set_password(&tokens.access_token)
        .map_err(|e| format!("Failed to save access token: {}", e))?;
    Entry::new("ciphera", "refresh_token")
        .map_err(|e| format!("Keyring error: {}", e))?
        .set_password(&tokens.refresh_token)
        .map_err(|e| format!("Failed to save refresh token: {}", e))?;
    Ok(())
}

pub async fn handle_login_password(
    api_url: &str,
    email: &str,
    password: &str,
) -> Result<(), String> {
    let client = Client::new();
    let url = format!("{}/v1/auth/login", api_url);

    let response = client
        .post(&url)
        .json(&ciphera_core::auth::LoginRequest {
            email: email.to_string(),
            password: password.to_string(),
        })
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status().is_success() {
        let tokens: AuthTokens = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse login response: {}", e))?;
        save_tokens(&tokens).await?;
        println!(
            "Authenticated as {} (role: {})",
            tokens.user.email, tokens.user.tenant_role
        );
        Ok(())
    } else {
        let err_text = response.text().await.unwrap_or_default();
        Err(format!("Login failed: {}", err_text))
    }
}

/// Opens the URL in the system browser; best effort, the printed URL always
/// works as a fallback.
fn open_in_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let opener = ("open", vec![url]);
    #[cfg(target_os = "windows")]
    let opener = ("cmd", vec!["/C", "start", url]);
    #[cfg(all(unix, not(target_os = "macos")))]
    let opener = ("xdg-open", vec![url]);

    let spawned = Command::new(opener.0)
        .args(opener.1)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();

    if spawned.is_err() {
        println!("Could not open a browser automatically; open the URL above manually.");
    }
}

/// Browser-based login (RFC 8628 device flow): asks the backend for a device
/// code, opens the activation page, and polls until the user completes the
/// login or the code expires.
pub async fn handle_login_device(api_url: &str, device_name: Option<&str>) -> Result<(), String> {
    let client = Client::new();

    let code_response = client
        .post(format!("{}/v1/auth/device/code", api_url))
        .json(&serde_json::json!({ "device_name": device_name }))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if !code_response.status().is_success() {
        let err_text = code_response.text().await.unwrap_or_default();
        return Err(format!("Could not start device login: {}", err_text));
    }

    let code: ciphera_core::auth::DeviceCodeResponse = code_response
        .json()
        .await
        .map_err(|e| format!("Failed to parse device code response: {}", e))?;

    println!("To authenticate, open this URL in a browser and log in:");
    println!("  {}", code.verification_url_complete);
    println!("Device code: {}", code.user_code);

    open_in_browser(&code.verification_url_complete);
    println!("\nWaiting for authorization in the browser... (Ctrl+C to cancel)");

    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(code.expires_in.max(1) as u64);
    let mut interval_secs = code.interval.max(1) as u64;
    let mut printed_awaiting_admin = false;

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;

        if std::time::Instant::now() >= deadline {
            return Err(
                "Device code expired before the login was completed. Run `ciphera login` again."
                    .to_string(),
            );
        }

        let response = client
            .post(format!("{}/v1/auth/device/token", api_url))
            .json(&ciphera_core::auth::DeviceTokenRequest {
                device_code: code.device_code.clone(),
            })
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        let status = response.status();
        if status.is_success() {
            let tokens: AuthTokens = response
                .json()
                .await
                .map_err(|e| format!("Failed to parse login response: {}", e))?;
            save_tokens(&tokens).await?;
            println!(
                "Authenticated as {} (role: {})",
                tokens.user.email, tokens.user.tenant_role
            );
            return Ok(());
        }

        let body_text = response.text().await.unwrap_or_default();
        let error_code = serde_json::from_str::<serde_json::Value>(&body_text)
            .ok()
            .and_then(|body| body["error_code"].as_str().map(|code| code.to_string()))
            .unwrap_or_default();

        match error_code.as_str() {
            "AUTHORIZATION_PENDING" => continue,
            "PENDING_ADMIN_APPROVAL" => {
                if !printed_awaiting_admin {
                    println!(
                        "Login approved in the browser; waiting for an admin to approve this device..."
                    );
                    printed_awaiting_admin = true;
                }
                continue;
            }
            "SLOW_DOWN" => interval_secs += 5,
            "ACCESS_DENIED" => {
                return Err("The login was not completed for this device code.".to_string());
            }
            "EXPIRED_DEVICE_CODE" => {
                return Err(
                    "Device code expired or already used. Run `ciphera login` again.".to_string(),
                );
            }
            other => {
                return Err(format!(
                    "Unexpected response while polling ({}): {}",
                    status,
                    if other.is_empty() {
                        if body_text.is_empty() {
                            "no response body".to_string()
                        } else {
                            body_text
                        }
                    } else {
                        other.to_string()
                    }
                ));
            }
        }
    }
}

/// Manually forces a refresh. No longer needed in normal use — every
/// authenticated command refreshes transparently via `resolve_token` — but
/// kept for scripts/debugging.
pub async fn handle_refresh(api_url: &str) -> Result<(), String> {
    let refresh = Entry::new("ciphera", "refresh_token")
        .and_then(|e| e.get_password())
        .map_err(|_| "No refresh token stored. Run `ciphera login` first.".to_string())?;

    match do_refresh(api_url, refresh).await {
        Ok(tokens) => {
            save_tokens(&tokens).await?;
            println!("Tokens refreshed.");
            Ok(())
        }
        Err(RefreshError::InvalidRefreshToken(msg)) => Err(format!(
            "Refresh failed: {}. Run `ciphera login` to sign in again.",
            if msg.trim().is_empty() {
                "refresh token rejected".to_string()
            } else {
                msg
            }
        )),
        Err(RefreshError::Network(msg)) => Err(format!(
            "Refresh failed: could not reach {}: {}",
            api_url, msg
        )),
        Err(RefreshError::Server(msg)) => Err(format!("Refresh failed: {}", msg)),
    }
}

pub async fn handle_logout(api_url: &str) -> Result<(), String> {
    let refresh = Entry::new("ciphera", "refresh_token").and_then(|e| e.get_password());

    if let Ok(refresh) = refresh {
        let client = Client::new();
        let url = format!("{}/v1/auth/logout", api_url);
        let _ = client
            .post(&url)
            .json(&ciphera_core::auth::LogoutRequest {
                refresh_token: refresh,
            })
            .send()
            .await;
    }

    for service in ["session_token", "refresh_token"] {
        if let Ok(entry) = Entry::new("ciphera", service) {
            let _ = entry.delete_credential();
        }
    }

    println!("Logged out.");
    Ok(())
}

pub fn handle_init(project_id: &str, env: Option<&str>) -> Result<(), String> {
    write_ciphera_toml("ciphera.toml", project_id, env)?;
    println!(
        "Initialized ciphera.toml with project_id: {} (default_environment: {})",
        project_id,
        env.unwrap_or("development")
    );
    Ok(())
}

pub fn handle_config_set_api_url(url: &str) -> Result<(), String> {
    let cfg = GlobalConfig {
        api_url: Some(url.to_string()),
    };
    let path = save_global_config(&cfg)?;
    println!("Default API URL saved to: {}", path.display());
    println!("Use `ciphera config show` to see the resolved value.");
    Ok(())
}

pub fn handle_config_show(cli_api_url: Option<&str>) -> Result<(), String> {
    let cfg = load_global_config()?;
    let effective = resolve_api_url(cli_api_url.map(str::to_string));
    println!("Effective API URL:   {}", effective);
    println!(
        "Config (persisted):  {}",
        cfg.api_url.as_deref().unwrap_or("(not set)")
    );
    println!("Build default:       {}", DEFAULT_API_URL);
    Ok(())
}

pub async fn handle_project_create(api_url: &str, token: &str, name: &str) -> Result<(), String> {
    let client = Client::new();
    let url = format!("{}/v1/projects", api_url);

    let response = client
        .post(&url)
        .bearer_auth(token)
        .json(&CreateProjectRequest {
            name: name.to_string(),
        })
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status().is_success() {
        let created: CreateProjectResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;
        println!("Project successfully created!");
        println!("  ID:   {}", created.id);
        println!("  Name: {}", created.name);
        println!("\nYou can initialize local project context using:");
        println!("  ciphera init --project {}", created.id);
        Ok(())
    } else {
        let err_text = response.text().await.unwrap_or_default();
        Err(format!("Failed to create project: {}", err_text))
    }
}

pub async fn handle_import(
    api_url: &str,
    token: &str,
    file_path: &str,
    cli_project: Option<String>,
    cli_env: Option<String>,
) -> Result<(), String> {
    let (project_id, environment) = resolve_context(api_url, token, cli_project, cli_env).await?;

    println!("Parsing secrets from {}...", file_path);
    let secrets = parse_env_file(file_path)?;

    if secrets.is_empty() {
        println!("No valid secrets found in file.");
        return Ok(());
    }

    let uploader = Uploader::new(api_url.to_string(), token.to_string());
    uploader
        .upload_in_batches(&project_id, &environment, secrets, 50)
        .await?;

    println!(
        "Use `ciphera run --env {} -- <command>` to execute processes with injected secrets.",
        environment
    );

    Ok(())
}

pub async fn handle_secret_delete(
    api_url: &str,
    token: &str,
    key: &str,
    cli_project: Option<String>,
    cli_env: Option<String>,
) -> Result<(), String> {
    let (project_id, environment) = resolve_context(api_url, token, cli_project, cli_env).await?;

    let client = Client::new();
    let url = format!(
        "{}/v1/projects/{}/secrets/{}/{}",
        api_url, project_id, environment, key
    );

    let response = client
        .delete(&url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status().is_success() {
        println!(
            "Secret '{}' in environment [{}] soft-deleted (tombstone version created)!",
            key, environment
        );
        Ok(())
    } else {
        let err_text = response.text().await.unwrap_or_default();
        Err(format!("Failed to delete secret: {}", err_text))
    }
}

pub async fn handle_token_create(
    api_url: &str,
    token: &str,
    name: &str,
    cli_project: Option<String>,
    cli_env: Option<String>,
    ttl_days: i64,
    allowed_cidrs: Vec<String>,
) -> Result<(), String> {
    if ttl_days <= 0 {
        return Err("--ttl-days must be a positive number of days".to_string());
    }
    let (project_id, environment) = resolve_context(api_url, token, cli_project, cli_env).await?;

    let client = Client::new();
    let url = format!("{}/v1/projects/{}/tokens", api_url, project_id);

    let response = client
        .post(&url)
        .bearer_auth(token)
        .json(&CreateTokenRequest {
            environment: environment.clone(),
            name: name.to_string(),
            expires_in_seconds: ttl_days * 24 * 60 * 60,
            allowed_cidrs,
        })
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status().is_success() {
        let token_resp: CreateTokenResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        println!("Service token successfully issued!");
        println!("  Name:        {}", token_resp.name);
        println!("  Environment: {}", token_resp.environment);
        println!("  Token:       {}", token_resp.token);
        println!("\nIMPORTANT: Save this token now. It will not be displayed again.");
        Ok(())
    } else {
        let err_text = response.text().await.unwrap_or_default();
        Err(format!("Failed to create token: {}", err_text))
    }
}

/// Parses repeatable `--claim key=value` flags into a JSON object suitable
/// for `CreateOidcTrustPolicyRequest::claims_matcher`.
fn parse_claims(raw: &[String]) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let mut map = serde_json::Map::new();
    for entry in raw {
        let (key, value) = entry
            .split_once('=')
            .ok_or_else(|| format!("Invalid --claim '{entry}': expected key=value"))?;
        if key.is_empty() {
            return Err(format!("Invalid --claim '{entry}': key must not be empty"));
        }
        map.insert(
            key.to_string(),
            serde_json::Value::String(value.to_string()),
        );
    }
    Ok(map)
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_oidc_policy_create(
    api_url: &str,
    token: &str,
    issuer: &str,
    audience: &str,
    claims: &[String],
    cli_project: Option<String>,
    cli_env: Option<String>,
    ttl_seconds: i64,
    allowed_cidrs: Vec<String>,
) -> Result<(), String> {
    let claims_matcher = parse_claims(claims)?;
    let (project_id, environment) = resolve_context(api_url, token, cli_project, cli_env).await?;

    let client = Client::new();
    let url = format!("{}/v1/projects/{}/oidc-policies", api_url, project_id);

    let response = client
        .post(&url)
        .bearer_auth(token)
        .json(&CreateOidcTrustPolicyRequest {
            issuer: issuer.to_string(),
            audience: audience.to_string(),
            claims_matcher,
            environment,
            ttl_seconds,
            allowed_cidrs,
        })
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status().is_success() {
        let policy: OidcTrustPolicyInfo = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;
        println!("OIDC trust policy created!");
        println!("  ID:       {}", policy.id);
        println!("  Issuer:   {}", policy.issuer);
        println!("  Audience: {}", policy.audience);
        println!(
            "\nAny token from this issuer, matching this audience and every --claim, can now be \
exchanged via `ciphera token oidc-exchange` for a service token scoped to project {} / env {}.",
            project_id, policy.environment
        );
        Ok(())
    } else {
        let err_text = response.text().await.unwrap_or_default();
        Err(format!("Failed to create OIDC trust policy: {}", err_text))
    }
}

pub async fn handle_oidc_policy_list(
    api_url: &str,
    token: &str,
    cli_project: Option<String>,
) -> Result<(), String> {
    let (project_id, _environment) = resolve_context(api_url, token, cli_project, None).await?;

    let client = Client::new();
    let url = format!("{}/v1/projects/{}/oidc-policies", api_url, project_id);

    let response = client
        .get(&url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status().is_success() {
        let policies: Vec<OidcTrustPolicyInfo> = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;
        if policies.is_empty() {
            println!("No OIDC trust policies registered for this project.");
            return Ok(());
        }
        for policy in policies {
            let status = if policy.revoked_at.is_some() {
                "revoked"
            } else {
                "active"
            };
            println!(
                "{}  [{}]  aud={}  env={}  issuer={}",
                policy.id, status, policy.audience, policy.environment, policy.issuer
            );
        }
        Ok(())
    } else {
        let err_text = response.text().await.unwrap_or_default();
        Err(format!("Failed to list OIDC trust policies: {}", err_text))
    }
}

pub async fn handle_oidc_policy_revoke(
    api_url: &str,
    token: &str,
    cli_project: Option<String>,
    policy_id: &str,
) -> Result<(), String> {
    let (project_id, _environment) = resolve_context(api_url, token, cli_project, None).await?;

    let client = Client::new();
    let url = format!(
        "{}/v1/projects/{}/oidc-policies/{}",
        api_url, project_id, policy_id
    );

    let response = client
        .delete(&url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status().is_success() {
        println!("OIDC trust policy {} revoked.", policy_id);
        Ok(())
    } else {
        let err_text = response.text().await.unwrap_or_default();
        Err(format!("Failed to revoke OIDC trust policy: {}", err_text))
    }
}

/// Exchanges an externally-signed OIDC token (e.g. from CI/CD) for a
/// Ciphera service token, per a registered trust policy. Not
/// session-authenticated: the OIDC token itself is the credential.
pub async fn handle_oidc_exchange(api_url: &str, oidc_token: &str) -> Result<(), String> {
    let client = Client::new();
    let url = format!("{}/v1/oidc/token", api_url);

    let response = client
        .post(&url)
        .json(&OidcTokenExchangeRequest {
            token: oidc_token.to_string(),
        })
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status().is_success() {
        let token_resp: CreateTokenResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;
        println!("Service token successfully issued via OIDC exchange!");
        println!("  Environment: {}", token_resp.environment);
        println!("  Token:       {}", token_resp.token);
        println!("\nIMPORTANT: Save this token now. It will not be displayed again.");
        Ok(())
    } else {
        let err_text = response.text().await.unwrap_or_default();
        Err(format!("OIDC token exchange failed: {}", err_text))
    }
}

pub async fn handle_rollback(
    api_url: &str,
    token: &str,
    key: &str,
    target_version: i32,
    cli_project: Option<String>,
    cli_env: Option<String>,
) -> Result<(), String> {
    let (project_id, environment) = resolve_context(api_url, token, cli_project, cli_env).await?;

    let client = Client::new();
    let url = format!(
        "{}/v1/projects/{}/secrets/{}/{}/rollback",
        api_url, project_id, environment, key
    );

    let response = client
        .post(&url)
        .bearer_auth(token)
        .json(&RollbackRequest { target_version })
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status().is_success() {
        println!(
            "Successfully rolled back secret '{}' in [{}] to version {}!",
            key, environment, target_version
        );
        Ok(())
    } else {
        let err_text = response.text().await.unwrap_or_default();
        Err(format!("Failed to rollback secret: {}", err_text))
    }
}

pub async fn handle_audit(
    api_url: &str,
    token: &str,
    cli_project: Option<String>,
    limit: i64,
) -> Result<(), String> {
    let (project_id, _) = resolve_context(api_url, token, cli_project, None).await?;

    let client = Client::new();
    let url = format!(
        "{}/v1/projects/{}/audit-logs?limit={}",
        api_url, project_id, limit
    );

    let response = client
        .get(&url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status().is_success() {
        let logs: Vec<AuditLogItem> = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse audit log response: {}", e))?;

        println!("=== Compliance Audit Logs (Latest {}) ===", logs.len());
        for log in logs {
            println!(
                "[{}] {} | Principal: {} | Status: {}",
                log.created_at, log.action, log.principal_id, log.status
            );
            if let Some(details) = log.details {
                println!("    Details: {}", details);
            }
        }
        Ok(())
    } else {
        let err_text = response.text().await.unwrap_or_default();
        Err(format!("Failed to fetch audit logs: {}", err_text))
    }
}

pub async fn handle_run(
    api_url: &str,
    token: &str,
    cli_project: Option<String>,
    cli_env: Option<String>,
    command_args: Vec<String>,
) -> Result<(), String> {
    if command_args.is_empty() {
        return Err("No target command provided for `ciphera run`.".to_string());
    }

    let (project_id, environment) = resolve_context(api_url, token, cli_project, cli_env).await?;

    let client = Client::new();
    let url = format!(
        "{}/v1/projects/{}/secrets/{}",
        api_url, project_id, environment
    );

    let response = client
        .get(&url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if !response.status().is_success() {
        let err_text = response.text().await.unwrap_or_default();
        return Err(format!("Failed to fetch secrets: {}", err_text));
    }

    let secrets: Vec<SecretOutput> = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse secrets payload: {}", e))?;

    let program = &command_args[0];
    let args = &command_args[1..];

    let mut cmd = Command::new(program);
    cmd.args(args);

    for s in secrets {
        cmd.env(s.key, s.value);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        Err(format!("Failed to execute process: {}", err))
    }

    #[cfg(not(unix))]
    {
        let status = cmd
            .status()
            .map_err(|e| format!("Failed to execute command: {}", e))?;
        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }
        Ok(())
    }
}

pub async fn handle_devices_list_pending(api_url: &str, token: &str) -> Result<(), String> {
    let client = Client::new();
    let response = client
        .get(format!("{}/v1/tenants/devices/pending", api_url))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if !response.status().is_success() {
        let err_text = response.text().await.unwrap_or_default();
        return Err(format!("Failed to list pending devices: {}", err_text));
    }

    let pending: Vec<ciphera_core::auth::PendingDeviceApproval> = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    if pending.is_empty() {
        println!("No device logins awaiting approval.");
        return Ok(());
    }
    for p in pending {
        println!(
            "{}  {}  {}  requested {}",
            p.id,
            p.user_email,
            p.device_name.as_deref().unwrap_or("(unnamed device)"),
            p.created_at
        );
    }
    Ok(())
}

pub async fn handle_devices_approve(api_url: &str, token: &str, id: &str) -> Result<(), String> {
    let client = Client::new();
    let response = client
        .post(format!("{}/v1/tenants/devices/{}/approve", api_url, id))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status().is_success() {
        println!("Device login approved.");
        Ok(())
    } else {
        let err_text = response.text().await.unwrap_or_default();
        Err(format!("Failed to approve device: {}", err_text))
    }
}

pub async fn handle_devices_deny(api_url: &str, token: &str, id: &str) -> Result<(), String> {
    let client = Client::new();
    let response = client
        .post(format!("{}/v1/tenants/devices/{}/deny", api_url, id))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status().is_success() {
        println!("Device login denied.");
        Ok(())
    } else {
        let err_text = response.text().await.unwrap_or_default();
        Err(format!("Failed to deny device: {}", err_text))
    }
}

/// `ciphera doctor`: checks API reachability, whether a token can be
/// resolved (env/flag/keyring) and is still valid, and whether the OS
/// keyring backend works. Prints a short pass/fail list; returns `Err` (so
/// the CLI exits non-zero) if any critical check failed.
pub async fn handle_doctor(api_url: &str, cli_token: Option<String>) -> Result<(), String> {
    let mut critical_failure = false;
    let client = Client::new();

    println!("Ciphera doctor\n");

    // 1. API reachability.
    print!("[ ] API reachable at {api_url} ... ");
    match client.get(format!("{}/health", api_url)).send().await {
        Ok(resp) if resp.status().is_success() => println!("\r[ok] API reachable at {api_url}"),
        Ok(resp) => {
            println!("\r[FAIL] API at {api_url} responded with {}", resp.status());
            critical_failure = true;
        }
        Err(e) => {
            println!("\r[FAIL] API at {api_url} is unreachable: {e}");
            critical_failure = true;
        }
    }

    // 2. Token resolution (env / --token / keyring), refreshing transparently
    // if the stored session token is expired or about to expire.
    let token = match resolve_token(api_url, cli_token).await {
        Ok(t) => {
            println!("[ok] Auth token resolved (--token, CIPHERA_TOKEN, or OS Keyring)");
            Some(t)
        }
        Err(e) => {
            println!("[FAIL] No auth token resolvable: {e}");
            critical_failure = true;
            None
        }
    };

    // 3. Token validity, for both session (user) and machine (service)
    // tokens. `/v1/auth/me` 200s for a valid session token; it 403s with a
    // specific message for a *valid* machine token (which has no user
    // profile) — so both are "valid", only an actual 401 means the token
    // itself is bad.
    if let Some(token) = &token {
        let response = client
            .get(format!("{}/v1/auth/me", api_url))
            .bearer_auth(token)
            .send()
            .await;
        match response {
            Ok(resp) if resp.status().is_success() => {
                let user: Result<ciphera_core::auth::AuthUser, _> = resp.json().await;
                match user {
                    Ok(u) => println!(
                        "[ok] Token is valid (signed in as {}, role: {})",
                        u.email, u.tenant_role
                    ),
                    Err(_) => println!("[ok] Token is valid (session)"),
                }
            }
            Ok(resp) if resp.status() == reqwest::StatusCode::FORBIDDEN => {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                if body["error_code"].as_str() == Some("FORBIDDEN") {
                    println!("[ok] Token is valid (machine/service token)");
                } else {
                    println!(
                        "[FAIL] Token rejected: {}",
                        body["message"].as_str().unwrap_or("forbidden")
                    );
                    critical_failure = true;
                }
            }
            Ok(resp) if resp.status() == reqwest::StatusCode::UNAUTHORIZED => {
                println!("[FAIL] Token is invalid or expired");
                critical_failure = true;
            }
            Ok(resp) => {
                println!(
                    "[FAIL] Unexpected response checking token validity: {}",
                    resp.status()
                );
                critical_failure = true;
            }
            Err(e) => {
                println!("[FAIL] Could not check token validity: {e}");
                critical_failure = true;
            }
        }
    } else {
        println!("[--] Skipped token validity check (no token resolvable)");
    }

    // 4. OS keyring backend availability. Not critical: CIPHERA_TOKEN/--token
    // work fine without it.
    match Entry::new("ciphera", "doctor_probe") {
        Ok(entry) => match entry.get_password() {
            Ok(_) => println!("[ok] OS Keyring backend is available"),
            Err(keyring::Error::NoEntry) => println!("[ok] OS Keyring backend is available"),
            Err(e) => println!("[warn] OS Keyring backend may be unavailable: {e}"),
        },
        Err(e) => println!("[warn] OS Keyring backend is unavailable: {e}"),
    }

    println!();
    if critical_failure {
        Err("One or more critical checks failed.".to_string())
    } else {
        println!("All critical checks passed.");
        Ok(())
    }
}

pub async fn handle_devices_require_approval(
    api_url: &str,
    token: &str,
    enabled: bool,
) -> Result<(), String> {
    let client = Client::new();
    let response = client
        .patch(format!("{}/v1/tenants/settings", api_url))
        .bearer_auth(token)
        .json(&ciphera_core::auth::UpdateTenantSettingsRequest {
            require_device_approval: enabled,
        })
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status().is_success() {
        println!(
            "Device admin approval is now {}.",
            if enabled { "required" } else { "not required" }
        );
        Ok(())
    } else {
        let err_text = response.text().await.unwrap_or_default();
        Err(format!("Failed to update tenant settings: {}", err_text))
    }
}
