use crate::config::{find_ciphera_toml, write_ciphera_toml};
use ciphera_core::ProjectInfo;
use dialoguer::{Confirm, Select};
use reqwest::Client;
use std::io::{self, IsTerminal};

pub fn is_interactive() -> bool {
    io::stdin().is_terminal() && io::stderr().is_terminal()
}

async fn fetch_projects(api_url: &str, token: &str) -> Result<Vec<ProjectInfo>, String> {
    let client = Client::new();
    let url = format!("{}/v1/projects", api_url);
    let response = client
        .get(&url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if !response.status().is_success() {
        let err_text = response.text().await.unwrap_or_default();
        return Err(format!("Failed to list projects: {}", err_text));
    }

    response
        .json()
        .await
        .map_err(|e| format!("Failed to parse projects response: {}", e))
}

/// Resolve a project name to its UUID, while continuing to accept UUIDs
/// directly for non-interactive use and existing config files.
pub async fn resolve_project(api_url: &str, token: &str, project: &str) -> Result<String, String> {
    if uuid::Uuid::parse_str(project).is_ok() {
        return Ok(project.to_string());
    }

    let projects = fetch_projects(api_url, token).await?;
    let matches: Vec<&ProjectInfo> = projects
        .iter()
        .filter(|candidate| candidate.name == project)
        .collect();

    match matches.as_slice() {
        [matched] => Ok(matched.id.clone()),
        [] => Err(format!(
            "No project named '{project}' found. Use its UUID with --project, or choose one of: {}",
            projects
                .iter()
                .map(|candidate| candidate.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
        _ => Err(format!(
            "More than one project is named '{project}'. Use the project UUID with --project."
        )),
    }
}

/// Fallback interativo quando nenhum projeto foi especificado
/// (flag, env `CIPHERA_PROJECT_ID` ou `ciphera.toml`).
///
/// Fora de um TTY (CI/scripts) mantém o comportamento original: erro.
pub async fn select_project(api_url: &str, token: &str) -> Result<String, String> {
    if !is_interactive() {
        return Err(
            "Project ID not specified. Provide --project, set CIPHERA_PROJECT_ID, or run `ciphera init`."
                .to_string(),
        );
    }

    let projects = fetch_projects(api_url, token).await?;

    if projects.is_empty() {
        return Err(
            "No projects found for your account. Create one with `ciphera project create --name <name>`."
                .to_string(),
        );
    }

    if projects.len() == 1 {
        let project = &projects[0];
        println!(
            "Using the only available project: {} ({})",
            project.name, project.id
        );
        return Ok(project.id.clone());
    }

    let items: Vec<String> = projects
        .iter()
        .map(|p| format!("{} ({})", p.name, p.id))
        .collect();

    let selection = Select::new()
        .with_prompt("Select a project")
        .items(items.iter().map(String::as_str))
        .default(0)
        .interact()
        .map_err(|_| "Project selection cancelled.".to_string())?;

    Ok(projects[selection].id.clone())
}

/// Oferece persistir o contexto escolhido em `ciphera.toml` no diretório atual.
/// Silencioso fora de TTY ou quando já existe um `ciphera.toml` no caminho.
pub fn offer_save_context(project_id: &str, environment: &str) {
    if !is_interactive() || find_ciphera_toml().is_some() {
        return;
    }

    let should_save = Confirm::new()
        .with_prompt(format!(
            "Save this context to ciphera.toml? (project: {}, default_environment: {})",
            project_id, environment
        ))
        .default(true)
        .interact()
        .unwrap_or(false);

    if !should_save {
        return;
    }

    match write_ciphera_toml("ciphera.toml", project_id, Some(environment)) {
        Ok(()) => println!("Saved ciphera.toml in the current directory."),
        Err(e) => eprintln!("Warning: could not save ciphera.toml: {}", e),
    }
}
