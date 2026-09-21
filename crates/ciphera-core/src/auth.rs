use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// RFC 8628 device authorization response: the CLI opens
/// `verification_url_complete` in a browser and polls `device_code` at
/// `interval` seconds until the user completes the login.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_url: String,
    pub verification_url_complete: String,
    pub expires_in: i64,
    pub interval: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTokenRequest {
    pub device_code: String,
}

/// Optional metadata the CLI sends when starting a device login.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeviceCodeRequest {
    /// Friendly device label stored on the resulting session (e.g. hostname).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthorizeRequest {
    pub user_code: String,
    pub email: String,
    pub password: String,
}

/// Session-based approval (RFC 8628 step 2): the activation page sends this
/// with the browser's Bearer access token; the approving user is derived from
/// the token, never from the payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceApproveRequest {
    pub user_code: String,
}

/// Rejects a pending device code; the CLI's next poll receives
/// `ACCESS_DENIED`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceDenyRequest {
    pub user_code: String,
}

/// Completes first-boot setup: consumes the one-time code from the server
/// logs and creates the first `system_admin` account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupRequest {
    pub code: String,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupClaimRequest {
    pub code: String,
}

/// Whether `/setup` can still create the first system admin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupStatusResponse {
    pub available: bool,
}

/// Accepts a system admin invite. A passwordless account sets `password`;
/// an existing account must confirm `current_password`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptInviteRequest {
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// Response of `POST /v1/admin/invites`: the raw invite token is displayed
/// exactly once and delivered to the invitee out-of-band.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminInviteCreated {
    pub invite_id: String,
    pub email: String,
    pub invite_token: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminInviteInfo {
    pub id: String,
    pub email: String,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminUserInfo {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub system_role: String,
    pub created_at: String,
    pub blocked_at: Option<String>,
    pub blocked_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserStatusRequest {
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSummary {
    pub users: i64,
    pub system_admins: i64,
    pub tenants: i64,
    pub projects: i64,
    pub active_kek_version: i32,
    pub setup_closed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminProjectInfo {
    pub id: String,
    pub name: String,
    pub tenant_id: String,
    pub kek_version: i32,
    pub active_kek_version: i32,
    pub needs_rotation: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetSystemRoleRequest {
    pub system_role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffboardMemberResponse {
    pub sessions_revoked: i64,
    pub project_memberships_removed: i64,
    pub service_tokens_revoked: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUser {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub email_verified: bool,
    pub tenant_id: String,
    pub tenant_role: String,
    /// Global role, independent from project/tenant roles:
    /// `member` (default) or `system_admin`.
    #[serde(default = "default_system_role")]
    pub system_role: String,
}

fn default_system_role() -> String {
    "member".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub user: AuthUser,
}

/// One active login session (web browser, CLI device login or OIDC).
/// Never includes the refresh token or its hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub id: String,
    /// `web`, `cli` or `oidc`.
    pub client_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    /// Approximate: only set when a trusted proxy provides it (e.g.
    /// Cloudflare's CF-IPCountry). No external GeoIP lookup is performed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub expires_at: String,
    /// True when this is the session the request was made with.
    pub current: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeOthersResponse {
    pub revoked: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOidcAuthUrlRequest {
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcCallbackRequest {
    pub provider: String,
    pub code: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcAuthUrlResponse {
    pub url: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListServiceTokensRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_revoked: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceTokenInfo {
    pub id: String,
    pub name: String,
    pub environment: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub is_read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeTokenRequest {
    pub token_id: String,
}

/// A service token from the account area: tokens of projects where the user
/// is Owner or Admin. Never includes the raw token or its hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineTokenAccountInfo {
    pub id: String,
    pub project_id: String,
    pub project_name: String,
    pub name: String,
    pub environment: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub is_read_only: bool,
}

/// Audit event for the personal (account) view: the user's own events
/// across projects, with the originating session when applicable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalAuditItem {
    pub id: String,
    pub principal_id: String,
    pub action: String,
    pub status: String,
    pub details: Option<serde_json::Value>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

/// Query filters for `GET /v1/auth/audit-logs`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PersonalAuditQuery {
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    /// RFC 3339 lower bound (inclusive) on the event timestamp.
    #[serde(default)]
    pub since: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
}

/// Renames the friendly device label of one of the user's own sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSessionDeviceNameRequest {
    /// `null` clears the label. Max 100 characters after trim.
    #[serde(default)]
    pub device_name: Option<String>,
}

/// Active session in the Admin (system admin) global view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSessionInfo {
    pub id: String,
    pub user_id: String,
    pub user_email: String,
    /// `web`, `cli` or `oidc`.
    pub client_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgotPasswordResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reset_token: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResendVerificationRequest {
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResendVerificationResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_token: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddMemberRequest {
    pub user_id: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateMemberRequest {
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberInfo {
    pub user_id: String,
    pub email: String,
    pub role: String,
    pub created_at: String,
}

/// Org-level member (tenant membership).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantMemberInfo {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
    pub role: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddTenantMemberRequest {
    pub email: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantSettings {
    pub require_device_approval: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateTenantSettingsRequest {
    pub require_device_approval: bool,
}

/// A `ciphera login` device-flow attempt awaiting an Owner/Administrator's
/// approval before tokens are issued (only created when the tenant has
/// `require_device_approval` enabled).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingDeviceApproval {
    pub id: String,
    pub user_id: String,
    pub user_email: String,
    pub device_name: Option<String>,
    pub created_at: String,
}
