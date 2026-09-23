use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Default API URL embutida no build.
///
/// Compile com `CIPHERA_API_URL` exportada para embutir a URL desejada
/// (ex.: `CIPHERA_API_URL=https://... cargo install --path crates/ciphera-cli`).
/// Fallback: `http://localhost:3000`.
pub const DEFAULT_API_URL: &str = match option_env!("CIPHERA_API_URL") {
    Some(url) => url,
    None => "http://localhost:3000",
};

/// Config global do CLI (`~/.config/ciphera/config.toml`).
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct GlobalConfig {
    pub api_url: Option<String>,
}

pub fn global_config_path() -> Result<PathBuf, String> {
    let base = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .ok_or_else(|| {
            "Não foi possível determinar o diretório de config (sete XDG_CONFIG_HOME ou HOME)."
                .to_string()
        })?;
    Ok(base.join("ciphera").join("config.toml"))
}

pub fn load_global_config() -> Result<GlobalConfig, String> {
    let path = global_config_path()?;
    if !path.is_file() {
        return Ok(GlobalConfig::default());
    }
    let content = fs::read_to_string(&path).map_err(|e| format!("Falha ao ler config: {}", e))?;
    toml::from_str(&content).map_err(|e| format!("Falha ao parsear config: {}", e))
}

pub fn save_global_config(cfg: &GlobalConfig) -> Result<PathBuf, String> {
    let path = global_config_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Falha ao criar dir de config: {}", e))?;
    }
    let content =
        toml::to_string_pretty(cfg).map_err(|e| format!("Falha ao serializar config: {}", e))?;
    fs::write(&path, content).map_err(|e| format!("Falha ao escrever config: {}", e))?;
    Ok(path)
}

/// Resolve a API URL com prioridade: flag -> env `CIPHERA_API_URL` ->
/// config global -> default embutido no build.
pub fn resolve_api_url(cli: Option<String>) -> String {
    cli.or_else(|| env::var("CIPHERA_API_URL").ok())
        .or_else(|| load_global_config().ok().and_then(|c| c.api_url))
        .unwrap_or_else(|| DEFAULT_API_URL.to_string())
}

pub fn validate_api_url(raw: &str) -> Result<String, String> {
    let url = raw.trim().trim_end_matches('/');
    let (scheme, authority) = url
        .split_once("://")
        .ok_or_else(|| "API URL must include http:// or https://".to_string())?;
    let host = authority
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .split('@')
        .next_back()
        .unwrap_or_default()
        .split(':')
        .next()
        .unwrap_or_default()
        .trim_matches(['[', ']']);
    if scheme == "https" {
        return Ok(url.to_string());
    }
    if scheme == "http" && matches!(host, "localhost" | "127.0.0.1" | "::1") {
        return Ok(url.to_string());
    }
    Err("Refusing to send credentials to a non-HTTPS API URL outside localhost".to_string())
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CipheraConfig {
    pub project: ProjectConfig,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectConfig {
    pub id: String,
    pub default_environment: Option<String>,
}

pub fn find_ciphera_toml() -> Option<PathBuf> {
    let mut current = env::current_dir().ok()?;
    loop {
        let config_path = current.join("ciphera.toml");
        if config_path.is_file() {
            return Some(config_path);
        }
        if !current.pop() {
            break;
        }
    }
    None
}

pub fn load_ciphera_toml<P: AsRef<Path>>(path: P) -> Result<CipheraConfig, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("Failed to read ciphera.toml: {}", e))?;
    toml::from_str(&content).map_err(|e| format!("Failed to parse ciphera.toml: {}", e))
}

pub fn write_ciphera_toml<P: AsRef<Path>>(
    path: P,
    project_id: &str,
    default_env: Option<&str>,
) -> Result<(), String> {
    let config = CipheraConfig {
        project: ProjectConfig {
            id: project_id.to_string(),
            default_environment: default_env.map(|s| s.to_string()),
        },
    };
    let content = toml::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    fs::write(path, content).map_err(|e| format!("Failed to write ciphera.toml: {}", e))
}

/// Resolve o contexto (projeto + ambiente) com precedência:
/// flag -> env -> `ciphera.toml`. Projeto ausente em TTY cai no select
/// interativo (lista os projetos da API) e oferece salvar o `ciphera.toml`.
pub async fn resolve_context(
    api_url: &str,
    token: &str,
    cli_project: Option<String>,
    cli_env: Option<String>,
) -> Result<(String, String), String> {
    let file_config = find_ciphera_toml().and_then(|p| load_ciphera_toml(p).ok());

    let mut selected_interactively = false;
    let project_id = match cli_project
        .or_else(|| env::var("CIPHERA_PROJECT_ID").ok())
        .or_else(|| file_config.as_ref().map(|c| c.project.id.clone()))
    {
        Some(project) => crate::interactive::resolve_project(api_url, token, &project).await?,
        None => {
            selected_interactively = true;
            crate::interactive::select_project(api_url, token).await?
        }
    };

    let environment = cli_env
        .or_else(|| env::var("CIPHERA_ENV").ok())
        .or_else(|| {
            file_config
                .as_ref()
                .and_then(|c| c.project.default_environment.clone())
        })
        .unwrap_or_else(|| "development".to_string());

    if selected_interactively {
        crate::interactive::offer_save_context(&project_id, &environment);
    }

    Ok((project_id, environment))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_serialization() {
        let config = CipheraConfig {
            project: ProjectConfig {
                id: "proj_abc123".to_string(),
                default_environment: Some("staging".to_string()),
            },
        };
        let toml_str = toml::to_string(&config).unwrap();
        let parsed: CipheraConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(config, parsed);
    }

    #[test]
    fn test_global_config_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        unsafe {
            env::set_var("XDG_CONFIG_HOME", tmp.path());
        }
        let cfg = GlobalConfig {
            api_url: Some("https://api.example.com".to_string()),
        };
        save_global_config(&cfg).unwrap();
        let loaded = load_global_config().unwrap();
        assert_eq!(loaded, cfg);
        unsafe {
            env::remove_var("XDG_CONFIG_HOME");
        }
    }

    #[test]
    fn test_api_url_validation() {
        assert!(validate_api_url("https://api.example.com/").is_ok());
        assert!(validate_api_url("http://localhost:3000").is_ok());
        assert!(validate_api_url("http://api.example.com").is_err());
    }

    #[tokio::test]
    async fn test_resolve_context_cli_flag_priority() {
        unsafe {
            env::remove_var("CIPHERA_PROJECT_ID");
            env::remove_var("CIPHERA_ENV");
        }
        let (project, environment) = resolve_context(
            "http://localhost:1",
            "token",
            Some("00000000-0000-0000-0000-000000000001".to_string()),
            Some("staging".to_string()),
        )
        .await
        .unwrap();
        assert_eq!(project, "00000000-0000-0000-0000-000000000001");
        assert_eq!(environment, "staging");
    }

    #[tokio::test]
    async fn test_resolve_context_errors_without_project_outside_tty() {
        unsafe {
            env::remove_var("CIPHERA_PROJECT_ID");
            env::remove_var("CIPHERA_ENV");
        }
        // Isola de `ciphera.toml` em diretórios pais (ex.: ~/projects),
        // senão o teste depende do filesystem da máquina.
        let tmp = tempfile::tempdir().unwrap();
        let prev = env::current_dir().unwrap();
        env::set_current_dir(tmp.path()).unwrap();
        let result = resolve_context("http://localhost:1", "token", None, None).await;
        env::set_current_dir(prev).unwrap();
        let err = result.unwrap_err();
        assert!(err.contains("Project ID not specified"));
    }
}
