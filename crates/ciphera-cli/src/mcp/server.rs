//! `ciphera mcp serve`: a metadata-only Model Context Protocol server over
//! stdio.
//!
//! HARD INVARIANT: no tool defined here may ever call a secret-reveal
//! endpoint (`GET .../secrets/{environment}/{key}/value`) or any endpoint
//! that returns decrypted secret values (e.g. the one `ciphera run` uses).
//! This is by construction, not a runtime check: the reveal-capable
//! endpoints are simply never wired into any tool handler below. Do not add
//! a `get_secret_value`/`reveal_secret` tool under any name.
//!
//! Auth reuses the same resolution as every other CLI command
//! (`--token` / `CIPHERA_TOKEN` / OS keyring), so the server acts with
//! whatever principal the surrounding `ciphera` CLI is authenticated as.

use reqwest::Client;
use rmcp::{
    ErrorData as McpError, ServiceExt,
    handler::server::wrapper::Parameters,
    model::{Implementation, ServerCapabilities, ServerConfig},
    schemars, tool, tool_handler, tool_router,
};
use serde::Deserialize;

/// Guidance repeated in the server's top-level instructions and in the
/// description of every tool that can act as (or point at) a credential:
/// machine tokens are for non-interactive contexts, device-flow `login` is
/// for a human.
const AUTOMATION_GUIDANCE: &str = "For CI, a VPS, a container, or any other non-interactive context, create and use a scoped machine token (create_service_token, or `ciphera token create` from the shell) — ideally with allow_cidrs and a capped ttl_days. `ciphera login`'s device flow is for a human authenticating interactively at a keyboard and must never be scripted or run unattended on a server.";

fn server_instructions() -> String {
    format!(
        "Ciphera MCP server: metadata and management only. No tool here ever returns a decrypted secret value \
        — there is no get_secret_value/reveal_secret tool, by design, so this server cannot be used to leak a \
        secret into a model transcript or log. To fetch actual secret values into a process's environment, use \
        `ciphera run --project <p> --env <e> -- <command>` from a shell, never through this server. {AUTOMATION_GUIDANCE}"
    )
}

fn default_ttl_days() -> i64 {
    30
}

fn default_audit_limit() -> i64 {
    50
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ProjectIdParams {
    /// The Ciphera project id (see list_projects).
    pub project_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SecretKeysParams {
    /// The Ciphera project id (see list_projects).
    pub project_id: String,
    /// The environment name within the project (see list_environments).
    pub environment: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateServiceTokenParams {
    /// The Ciphera project id the token grants access to.
    pub project_id: String,
    /// A human-readable name for the token (e.g. "prod-deploy-ci").
    pub name: String,
    /// The environment this token may read secrets from.
    pub environment: String,
    /// Token lifetime in days. Defaults to 30; capped server-side at 90.
    /// Machine tokens always expire — there is no "no expiry" option.
    #[serde(default = "default_ttl_days")]
    pub ttl_days: i64,
    /// Optional list of CIDRs (e.g. "203.0.113.4/32") the token may be used
    /// from. Leave empty to leave the token unrestricted by IP.
    #[serde(default)]
    pub allow_cidrs: Vec<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AuditLogParams {
    /// The Ciphera project id.
    pub project_id: String,
    /// Maximum number of audit log entries to return. Defaults to 50.
    #[serde(default = "default_audit_limit")]
    pub limit: i64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DeviceIdParams {
    /// The pending device-approval id (see list_pending_devices).
    pub id: String,
}

#[derive(Clone)]
pub struct CipheraMcpServer {
    api_url: String,
    token: String,
    client: Client,
    tool_router: rmcp::handler::server::router::tool::ToolRouter<Self>,
}

impl CipheraMcpServer {
    pub fn new(api_url: String, token: String) -> Self {
        Self {
            api_url,
            token,
            client: Client::new(),
            tool_router: Self::tool_router(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.api_url, path)
    }

    /// Fetches `path` and returns the response re-serialized as pretty
    /// JSON text (rather than a typed `Json<T>` tool result) so the tool
    /// DTOs don't need a `schemars::JsonSchema` impl on `ciphera-core`
    /// types shared with the backend.
    async fn get_json<T: serde::de::DeserializeOwned + serde::Serialize>(
        &self,
        path: &str,
    ) -> Result<String, McpError> {
        let response = self
            .client
            .get(self.url(path))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| McpError::internal_error(format!("Request failed: {e}"), None))?;

        if !response.status().is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(McpError::internal_error(
                format!("Ciphera API error: {text}"),
                None,
            ));
        }

        let parsed = response.json::<T>().await.map_err(|e| {
            McpError::internal_error(format!("Failed to parse response: {e}"), None)
        })?;
        serde_json::to_string_pretty(&parsed).map_err(|e| {
            McpError::internal_error(format!("Failed to serialize response: {e}"), None)
        })
    }

    async fn post_json<B: serde::Serialize, T: serde::de::DeserializeOwned + serde::Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<String, McpError> {
        let response = self
            .client
            .post(self.url(path))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await
            .map_err(|e| McpError::internal_error(format!("Request failed: {e}"), None))?;

        if !response.status().is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(McpError::internal_error(
                format!("Ciphera API error: {text}"),
                None,
            ));
        }

        let parsed = response.json::<T>().await.map_err(|e| {
            McpError::internal_error(format!("Failed to parse response: {e}"), None)
        })?;
        serde_json::to_string_pretty(&parsed).map_err(|e| {
            McpError::internal_error(format!("Failed to serialize response: {e}"), None)
        })
    }

    async fn post_empty(&self, path: &str) -> Result<(), McpError> {
        let response = self
            .client
            .post(self.url(path))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| McpError::internal_error(format!("Request failed: {e}"), None))?;

        if !response.status().is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(McpError::internal_error(
                format!("Ciphera API error: {text}"),
                None,
            ));
        }
        Ok(())
    }
}

#[tool_router]
impl CipheraMcpServer {
    #[tool(description = "List the Ciphera projects visible to the authenticated principal.")]
    async fn list_projects(&self) -> Result<String, McpError> {
        self.get_json::<Vec<ciphera_core::ProjectInfo>>("/v1/projects")
            .await
    }

    #[tool(description = "List the environments defined for a Ciphera project.")]
    async fn list_environments(
        &self,
        Parameters(params): Parameters<ProjectIdParams>,
    ) -> Result<String, McpError> {
        let path = format!("/v1/projects/{}/environments", params.project_id);
        self.get_json::<Vec<ciphera_core::EnvironmentInfo>>(&path)
            .await
    }

    #[tool(
        description = "List secret key names (with version, no values) for a project/environment. \
        Never returns a decrypted secret value — there is no tool that does."
    )]
    async fn list_secret_keys(
        &self,
        Parameters(params): Parameters<SecretKeysParams>,
    ) -> Result<String, McpError> {
        let path = format!(
            "/v1/projects/{}/secrets/{}/summary",
            params.project_id, params.environment
        );
        self.get_json::<Vec<ciphera_core::SecretSummary>>(&path)
            .await
    }

    #[tool(description = "List service (machine) tokens issued for a project.")]
    async fn list_service_tokens(
        &self,
        Parameters(params): Parameters<ProjectIdParams>,
    ) -> Result<String, McpError> {
        let path = format!("/v1/projects/{}/tokens", params.project_id);
        self.get_json::<Vec<ciphera_core::auth::ServiceTokenInfo>>(&path)
            .await
    }

    #[tool(description = "\
        Create a scoped, expiring machine (service) token for a project/environment. \
        This is the correct credential for CI, a VPS, a container, or any other \
        non-interactive use — prefer a capped ttl_days and, when the caller's egress IP \
        is known, allow_cidrs. Never use ciphera login's device flow in an unattended \
        context; it is for a human at a keyboard.")]
    async fn create_service_token(
        &self,
        Parameters(params): Parameters<CreateServiceTokenParams>,
    ) -> Result<String, McpError> {
        if params.ttl_days <= 0 {
            return Err(McpError::invalid_params(
                "ttl_days must be a positive number of days",
                None,
            ));
        }
        let path = format!("/v1/projects/{}/tokens", params.project_id);
        let body = ciphera_core::CreateTokenRequest {
            environment: params.environment,
            name: params.name,
            expires_in_seconds: params.ttl_days * 24 * 60 * 60,
            allowed_cidrs: params.allow_cidrs,
        };
        self.post_json::<_, ciphera_core::CreateTokenResponse>(&path, &body)
            .await
    }

    #[tool(description = "Fetch the compliance audit log for a project.")]
    async fn get_audit_log(
        &self,
        Parameters(params): Parameters<AuditLogParams>,
    ) -> Result<String, McpError> {
        let path = format!(
            "/v1/projects/{}/audit-logs?limit={}",
            params.project_id, params.limit
        );
        self.get_json::<Vec<ciphera_core::AuditLogItem>>(&path)
            .await
    }

    #[tool(
        description = "List `ciphera login` device logins awaiting admin approval (Owner/Administrator only)."
    )]
    async fn list_pending_devices(&self) -> Result<String, McpError> {
        self.get_json::<Vec<ciphera_core::auth::PendingDeviceApproval>>(
            "/v1/tenants/devices/pending",
        )
        .await
    }

    #[tool(description = "Approve a pending `ciphera login` device login by its id.")]
    async fn approve_device(
        &self,
        Parameters(params): Parameters<DeviceIdParams>,
    ) -> Result<String, McpError> {
        let path = format!("/v1/tenants/devices/{}/approve", params.id);
        self.post_empty(&path).await?;
        Ok(format!("Device login {} approved.", params.id))
    }

    #[tool(description = "Deny a pending `ciphera login` device login by its id.")]
    async fn deny_device(
        &self,
        Parameters(params): Parameters<DeviceIdParams>,
    ) -> Result<String, McpError> {
        let path = format!("/v1/tenants/devices/{}/deny", params.id);
        self.post_empty(&path).await?;
        Ok(format!("Device login {} denied.", params.id))
    }
}

#[tool_handler(router = self.tool_router)]
impl rmcp::ServerHandler for CipheraMcpServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(server_instructions())
            .with_server_info(
                Implementation::new("ciphera", env!("CARGO_PKG_VERSION"))
                    .with_title("Ciphera")
                    .with_description("Metadata-only secret management MCP server"),
            )
    }
}

/// Runs the MCP server over stdio until the client disconnects.
pub async fn serve(api_url: String, token: String) -> Result<(), String> {
    let server = CipheraMcpServer::new(api_url, token);
    let running = server
        .serve(rmcp::transport::stdio())
        .await
        .map_err(|e| format!("Failed to start MCP server: {e}"))?;
    running
        .waiting()
        .await
        .map_err(|e| format!("MCP server exited with an error: {e}"))?;
    Ok(())
}
