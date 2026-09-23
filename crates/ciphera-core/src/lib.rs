pub mod auth;

use serde::{Deserialize, Serialize};
use std::str::FromStr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CipheraError {
    #[error("Validation Error: {0}")]
    ValidationError(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Not Found: {0}")]
    NotFound(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Crypto Error: {0}")]
    Crypto(String),

    #[error("Database Error: {0}")]
    Database(String),

    #[error("Unexpected Error: {0}")]
    Unexpected(String),
}

impl CipheraError {
    pub fn error_code(&self) -> &'static str {
        match self {
            CipheraError::ValidationError(_) => "VALIDATION_ERROR",
            CipheraError::Unauthorized(_) => "UNAUTHORIZED",
            CipheraError::Forbidden(_) => "FORBIDDEN",
            CipheraError::NotFound(_) => "NOT_FOUND",
            CipheraError::Conflict(_) => "CONFLICT",
            CipheraError::Crypto(_) => "CRYPTO_ERROR",
            CipheraError::Database(_) => "DATABASE_ERROR",
            CipheraError::Unexpected(_) => "UNEXPECTED_ERROR",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProjectId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Environment(pub String);

impl Environment {
    pub fn is_production(&self) -> bool {
        self.0.to_lowercase() == "production" || self.0.to_lowercase() == "prod"
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProjectRole {
    Owner,
    Admin,
    Developer,
    Viewer,
}

impl FromStr for ProjectRole {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "owner" => Ok(ProjectRole::Owner),
            "admin" => Ok(ProjectRole::Admin),
            "developer" | "dev" => Ok(ProjectRole::Developer),
            "viewer" => Ok(ProjectRole::Viewer),
            _ => Err(()),
        }
    }
}

impl ProjectRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProjectRole::Owner => "owner",
            ProjectRole::Admin => "admin",
            ProjectRole::Developer => "developer",
            ProjectRole::Viewer => "viewer",
        }
    }

    pub fn authorize_read(&self, env: &Environment) -> Result<(), String> {
        match self {
            ProjectRole::Owner | ProjectRole::Admin => Ok(()),
            ProjectRole::Developer | ProjectRole::Viewer => {
                if env.is_production() {
                    Err(
                        "Access denied: Your role does not allow reading production secrets."
                            .to_string(),
                    )
                } else {
                    Ok(())
                }
            }
        }
    }

    pub fn authorize_write(&self, env: &Environment) -> Result<(), String> {
        match self {
            ProjectRole::Owner | ProjectRole::Admin => Ok(()),
            ProjectRole::Developer => {
                if env.is_production() {
                    Err("Access denied: Developers cannot modify production secrets.".to_string())
                } else {
                    Ok(())
                }
            }
            ProjectRole::Viewer => Err("Access denied: Viewers cannot modify secrets.".to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Principal {
    User {
        user_id: String,
    },
    Machine {
        project_id: ProjectId,
        allowed_env: Environment,
    },
}

impl Principal {
    pub fn get_id(&self) -> String {
        match self {
            Principal::User { user_id } => user_id.clone(),
            Principal::Machine {
                project_id,
                allowed_env,
            } => {
                format!("machine:{}:{}", project_id.0, allowed_env.0)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    pub tenant_id: TenantId,
    pub principal: Principal,
    /// Identifier of the login session backing a user access token. Absent
    /// for machine (service token) principals and for legacy tokens.
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretInput {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretOutput {
    pub key: String,
    pub value: String,
    pub version: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretSummary {
    pub key: String,
    pub version: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretHistoryItem {
    pub version: i32,
    pub is_deleted: bool,
    pub created_at: String,
    pub created_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateProjectRequest {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateProjectResponse {
    pub id: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectInfo {
    pub id: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentInfo {
    pub name: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEnvironmentRequest {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameEnvironmentRequest {
    pub new_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchCreateSecretsRequest {
    pub environment: String,
    pub secrets: Vec<SecretInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackRequest {
    pub target_version: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTokenRequest {
    pub environment: String,
    pub name: String,
    /// Required: machine tokens must always carry an expiry. The server
    /// additionally caps this at [`MAX_SERVICE_TOKEN_TTL_SECONDS`].
    pub expires_in_seconds: i64,
    /// CIDRs the token may be used from (e.g. "203.0.113.4/32"). Empty means
    /// unrestricted.
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
}

/// Maximum lifetime a machine (service) token may be issued for: 90 days.
/// Enforced server-side regardless of what the client requests.
pub const MAX_SERVICE_TOKEN_TTL_SECONDS: i64 = 90 * 24 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTokenResponse {
    pub token: String,
    pub name: String,
    pub environment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// A registered OIDC trust policy: presenting a verified token from
/// `issuer` with `audience` and claims matching `claims_matcher` exchanges
/// for a service token scoped to `project_id`/`environment`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOidcTrustPolicyRequest {
    pub issuer: String,
    pub audience: String,
    /// Exact-match claim requirements; a leading/trailing `*` in the
    /// expected value glob-matches (e.g. `"refs/heads/*"`).
    #[serde(default)]
    pub claims_matcher: serde_json::Map<String, serde_json::Value>,
    pub environment: String,
    pub ttl_seconds: i64,
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcTrustPolicyInfo {
    pub id: String,
    pub issuer: String,
    pub audience: String,
    pub claims_matcher: serde_json::Map<String, serde_json::Value>,
    pub environment: String,
    pub ttl_seconds: i64,
    pub allowed_cidrs: Vec<String>,
    pub created_by: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcTokenExchangeRequest {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogItem {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    pub principal_id: String,
    pub action: String,
    pub status: String,
    pub details: Option<serde_json::Value>,
    pub created_at: String,
}

/// ViaLivre API standard error payload format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    pub message: String,
    pub error_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

impl ApiErrorResponse {
    pub fn new(message: impl Into<String>, error_code: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            error_code: error_code.into(),
            extra: None,
        }
    }

    pub fn with_extra(
        message: impl Into<String>,
        error_code: impl Into<String>,
        extra: serde_json::Value,
    ) -> Self {
        Self {
            message: message.into(),
            error_code: error_code.into(),
            extra: Some(extra),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_permissions_production() {
        let prod = Environment("production".to_string());
        let dev_env = Environment("development".to_string());

        assert!(ProjectRole::Owner.authorize_read(&prod).is_ok());
        assert!(ProjectRole::Admin.authorize_write(&prod).is_ok());

        assert!(ProjectRole::Developer.authorize_read(&prod).is_err());
        assert!(ProjectRole::Developer.authorize_write(&prod).is_err());
        assert!(ProjectRole::Developer.authorize_read(&dev_env).is_ok());
        assert!(ProjectRole::Developer.authorize_write(&dev_env).is_ok());

        assert!(ProjectRole::Viewer.authorize_read(&dev_env).is_ok());
        assert!(ProjectRole::Viewer.authorize_write(&dev_env).is_err());
    }

    #[test]
    fn test_error_response_serialization() {
        let err = ApiErrorResponse::new("Resource not found", "NOT_FOUND");
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains(r#""message":"Resource not found""#));
        assert!(json.contains(r#""error_code":"NOT_FOUND""#));
        assert!(!json.contains(r#""extra""#));

        let err_extra = ApiErrorResponse::with_extra(
            "Validation failed",
            "VALIDATION_ERROR",
            serde_json::json!({"field": "name"}),
        );
        let json_extra = serde_json::to_string(&err_extra).unwrap();
        assert!(json_extra.contains(r#""extra":{"field":"name"}"#));
    }

    #[test]
    fn environment_is_production_detects_aliases() {
        assert!(Environment("production".to_string()).is_production());
        assert!(Environment("PROD".to_string()).is_production());
        assert!(!Environment("development".to_string()).is_production());
        assert!(!Environment("staging".to_string()).is_production());
    }

    #[test]
    fn project_role_from_str_and_as_str() {
        use std::str::FromStr;
        assert_eq!(ProjectRole::from_str("owner").unwrap(), ProjectRole::Owner);
        assert_eq!(ProjectRole::from_str("ADMIN").unwrap(), ProjectRole::Admin);
        assert_eq!(
            ProjectRole::from_str("dev").unwrap(),
            ProjectRole::Developer
        );
        assert_eq!(
            ProjectRole::from_str("viewer").unwrap(),
            ProjectRole::Viewer
        );
        assert!(ProjectRole::from_str("nope").is_err());

        assert_eq!(ProjectRole::Owner.as_str(), "owner");
        assert_eq!(ProjectRole::Admin.as_str(), "admin");
        assert_eq!(ProjectRole::Developer.as_str(), "developer");
        assert_eq!(ProjectRole::Viewer.as_str(), "viewer");
    }

    #[test]
    fn role_authorization_matrix() {
        let prod = Environment("production".to_string());
        let dev = Environment("development".to_string());

        assert!(ProjectRole::Owner.authorize_read(&prod).is_ok());
        assert!(ProjectRole::Owner.authorize_write(&prod).is_ok());
        assert!(ProjectRole::Admin.authorize_read(&prod).is_ok());
        assert!(ProjectRole::Admin.authorize_write(&prod).is_ok());
        assert!(ProjectRole::Developer.authorize_write(&dev).is_ok());
        assert!(ProjectRole::Developer.authorize_read(&dev).is_ok());
        assert!(ProjectRole::Developer.authorize_read(&prod).is_err());
        assert!(ProjectRole::Developer.authorize_write(&prod).is_err());
        assert!(ProjectRole::Viewer.authorize_read(&dev).is_ok());
        assert!(ProjectRole::Viewer.authorize_read(&prod).is_err());
        assert!(ProjectRole::Viewer.authorize_write(&dev).is_err());
        assert!(ProjectRole::Viewer.authorize_write(&prod).is_err());
    }

    #[test]
    fn principal_get_id_formats() {
        let u = Principal::User {
            user_id: "u1".to_string(),
        };
        assert_eq!(u.get_id(), "u1");

        let m = Principal::Machine {
            project_id: ProjectId("p1".to_string()),
            allowed_env: Environment("dev".to_string()),
        };
        assert_eq!(m.get_id(), "machine:p1:dev");
    }

    #[test]
    fn error_code_mapping() {
        assert_eq!(
            CipheraError::ValidationError("x".into()).error_code(),
            "VALIDATION_ERROR"
        );
        assert_eq!(
            CipheraError::Unauthorized("x".into()).error_code(),
            "UNAUTHORIZED"
        );
        assert_eq!(
            CipheraError::Forbidden("x".into()).error_code(),
            "FORBIDDEN"
        );
        assert_eq!(CipheraError::NotFound("x".into()).error_code(), "NOT_FOUND");
        assert_eq!(CipheraError::Conflict("x".into()).error_code(), "CONFLICT");
        assert_eq!(
            CipheraError::Crypto("x".into()).error_code(),
            "CRYPTO_ERROR"
        );
        assert_eq!(
            CipheraError::Database("x".into()).error_code(),
            "DATABASE_ERROR"
        );
        assert_eq!(
            CipheraError::Unexpected("x".into()).error_code(),
            "UNEXPECTED_ERROR"
        );
    }
}
