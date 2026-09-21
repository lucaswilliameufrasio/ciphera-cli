//! Integration tests for the `ciphera` CLI against a mocked API server.
//!
//! Every command runs through the real binary (`CARGO_BIN_EXE_ciphera`),
//! pointed at a local axum mock that records requests by method+path.

use std::process::Command;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use axum::{
    Json, Router,
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};

type Store = Arc<Mutex<Vec<(String, String)>>>;

const PROJECT_ID: &str = "proj_00000000-0000-0000-0000-000000000001";

async fn record(store: axum::extract::State<Store>, req: Request<Body>, next: Next) -> Response {
    store
        .lock()
        .unwrap()
        .push((req.method().to_string(), req.uri().path().to_string()));
    next.run(req).await
}

async fn start_mock() -> (String, Store) {
    let store: Store = Arc::new(Mutex::new(Vec::new()));
    let device_polls = Arc::new(AtomicUsize::new(0));

    let app = Router::new()
        .route(
            "/v1/projects",
            post(|| async {
                (
                    StatusCode::CREATED,
                    Json(serde_json::json!({
                        "id": PROJECT_ID,
                        "name": "created",
                        "created_at": "2026-08-26T00:00:00Z"
                    })),
                )
            }),
        )
        .route(
            "/v1/projects/{project_id}/secrets/batch",
            post(|| async { StatusCode::CREATED }),
        )
        .route(
            "/v1/projects/{project_id}/secrets/{environment}",
            get(|| async {
                Json(serde_json::json!([{
                    "key": "FOO", "value": "bar", "version": 1
                }]))
            }),
        )
        .route(
            "/v1/projects/{project_id}/secrets/{environment}/{key}",
            delete(|| async {
                Json(serde_json::json!({
                    "key": "K", "tombstone_version": 2, "is_deleted": true
                }))
            }),
        )
        .route(
            "/v1/projects/{project_id}/secrets/{environment}/{key}/rollback",
            post(|| async { Json(serde_json::json!({ "key": "K", "new_version": 3 })) }),
        )
        .route(
            "/v1/projects/{project_id}/tokens",
            post(|| async {
                (
                    StatusCode::CREATED,
                    Json(serde_json::json!({
                        "token": "st_mocktoken",
                        "name": "ci",
                        "environment": "development"
                    })),
                )
            }),
        )
        .route(
            "/v1/projects/{project_id}/audit-logs",
            get(|| async { Json(serde_json::json!([])) }),
        )
        .route(
            "/v1/auth/login",
            post(|| async {
                Json(serde_json::json!({
                    "access_token": "access.xyz",
                    "refresh_token": "refresh.xyz",
                    "token_type": "Bearer",
                    "expires_in": 900,
                    "user": {
                        "id": "u1", "email": "a@b.c", "display_name": "a",
                        "email_verified": true, "tenant_id": "t1", "tenant_role": "owner"
                    }
                }))
            }),
        )
        .route(
            "/v1/auth/refresh",
            post(|| async { StatusCode::NO_CONTENT }),
        )
        .route("/v1/auth/logout", post(|| async { StatusCode::NO_CONTENT }))
        // Device flow: the first two polls are pending, the third issues tokens.
        .route(
            "/v1/auth/device/code",
            post(|| async {
                Json(serde_json::json!({
                    "device_code": "dev_mock_123",
                    "user_code": "ABCD-2345",
                    "verification_url": "http://localhost/activate",
                    "verification_url_complete": "http://localhost/activate?user_code=ABCD-2345",
                    "expires_in": 600,
                    "interval": 0
                }))
            }),
        )
        .route(
            "/v1/auth/device/token",
            post(move || {
                let polls = Arc::clone(&device_polls);
                async move {
                    let poll_number = polls.fetch_add(1, Ordering::SeqCst);
                    if poll_number < 2 {
                        (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({ "error_code": "AUTHORIZATION_PENDING" })),
                        )
                            .into_response()
                    } else {
                        (
                            StatusCode::OK,
                            Json(serde_json::json!({
                                "access_token": "access.xyz",
                                "refresh_token": "refresh.xyz",
                                "token_type": "Bearer",
                                "expires_in": 900,
                                "user": {
                                    "id": "u1", "email": "a@b.c", "display_name": "a",
                                    "email_verified": true, "tenant_id": "t1", "tenant_role": "owner"
                                }
                            })),
                        )
                            .into_response()
                    }
                }
            }),
        )
        .layer(axum::middleware::from_fn_with_state(store.clone(), record));

    // Serve on a dedicated thread with its own runtime so `Command::output()`
    // (which blocks the test thread) never deadlocks the server task.
    let (tx, rx) = std::sync::mpsc::channel::<std::net::SocketAddr>();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tx.send(addr).unwrap();
            axum::serve(listener, app).await.unwrap();
        });
    });
    let addr = rx.recv().expect("mock server address");

    (format!("http://{addr}"), store)
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ciphera")
}

fn run_cli(dir: &std::path::Path, envs: &[(&str, &str)], args: &[&str]) -> String {
    let mut cmd = Command::new(bin());
    cmd.current_dir(dir);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.args(args);
    let out = cmd.output().expect("run ciphera binary");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "ciphera {args:?} failed\nstdout: {stdout}\nstderr: {stderr}"
    );
    stdout
}

fn assert_recorded(store: &Store, method: &str, path: &str) {
    let all = store.lock().unwrap();
    assert!(
        all.iter().any(|(m, p)| m == method && p == path),
        "expected {method} {path}, recorded: {all:?}"
    );
}

/// Runs the CLI expecting a non-zero exit; returns (stdout, stderr).
fn run_cli_err(dir: &std::path::Path, envs: &[(&str, &str)], args: &[&str]) -> (String, String) {
    let mut cmd = Command::new(bin());
    cmd.current_dir(dir);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.args(args);
    let out = cmd.output().expect("run ciphera binary");
    assert!(
        !out.status.success(),
        "expected failure for {args:?}, but it succeeded"
    );
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[tokio::test]
async fn run_requires_a_command() {
    let dir = tempfile::tempdir().unwrap();
    let (_, err) = run_cli_err(
        dir.path(),
        &[("CIPHERA_TOKEN", "tok")],
        &["run", "--project", PROJECT_ID, "--env", "development"],
    );
    assert!(
        err.contains("No target command") || err.contains("required"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn login_device_flow_reports_unreachable_api() {
    let dir = tempfile::tempdir().unwrap();
    let (_, err) = run_cli_err(
        dir.path(),
        &[("CIPHERA_API_URL", "http://127.0.0.1:1")],
        &["login"],
    );
    assert!(
        err.contains("Could not start device login") || err.contains("Request failed"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn login_device_flow_polls_until_authorized() {
    let (url, store) = start_mock().await;
    let dir = tempfile::tempdir().unwrap();

    let out = run_cli(dir.path(), &[("CIPHERA_API_URL", url.as_str())], &["login"]);

    assert!(
        out.contains("ABCD-2345"),
        "should print the user code: {out}"
    );
    assert!(out.contains("Authenticated as a@b.c"), "stdout: {out}");
    assert_recorded(&store, "POST", "/v1/auth/device/code");
    assert_recorded(&store, "POST", "/v1/auth/device/token");
}

#[tokio::test]
async fn unknown_command_fails() {
    let dir = tempfile::tempdir().unwrap();
    let (_, err) = run_cli_err(dir.path(), &[], &["frobnicate"]);
    assert!(!err.is_empty());
}

#[tokio::test]
async fn run_injects_secrets_into_process() {
    let (url, _store) = start_mock().await;
    let dir = tempfile::tempdir().unwrap();
    let out = run_cli(
        dir.path(),
        &[("CIPHERA_API_URL", url.as_str()), ("CIPHERA_TOKEN", "tok")],
        &[
            "run",
            "--project",
            PROJECT_ID,
            "--env",
            "development",
            "--",
            "sh",
            "-c",
            "printf %s \"$FOO\"",
        ],
    );
    assert_eq!(
        out, "bar",
        "secret should be injected into the child process"
    );
}

#[tokio::test]
async fn import_uploads_batch_and_injects_run() {
    let (url, store) = start_mock().await;
    let dir = tempfile::tempdir().unwrap();
    let env_file = dir.path().join("secrets.env");
    std::fs::write(&env_file, "FOO=bar\nBAZ=qux\n# comment\n").unwrap();

    run_cli(
        dir.path(),
        &[("CIPHERA_API_URL", url.as_str()), ("CIPHERA_TOKEN", "tok")],
        &[
            "import",
            "-f",
            env_file.to_str().unwrap(),
            "--project",
            PROJECT_ID,
            "--env",
            "development",
        ],
    );
    assert_recorded(
        &store,
        "POST",
        &format!("/v1/projects/{PROJECT_ID}/secrets/batch"),
    );
}

#[tokio::test]
async fn project_create_audit_rollback_delete_token() {
    let (url, store) = start_mock().await;
    let dir = tempfile::tempdir().unwrap();
    let base_env = [("CIPHERA_API_URL", url.as_str()), ("CIPHERA_TOKEN", "tok")];

    run_cli(
        dir.path(),
        &base_env,
        &["project", "create", "--name", "Demo"],
    );
    assert_recorded(&store, "POST", "/v1/projects");

    run_cli(
        dir.path(),
        &base_env,
        &["audit", "--project", PROJECT_ID, "--limit", "10"],
    );
    assert_recorded(
        &store,
        "GET",
        &format!("/v1/projects/{PROJECT_ID}/audit-logs"),
    );

    run_cli(
        dir.path(),
        &base_env,
        &[
            "rollback",
            "--key",
            "K",
            "--target-version",
            "1",
            "--project",
            PROJECT_ID,
            "--env",
            "development",
        ],
    );
    assert_recorded(
        &store,
        "POST",
        &format!("/v1/projects/{PROJECT_ID}/secrets/development/K/rollback"),
    );

    run_cli(
        dir.path(),
        &base_env,
        &[
            "secret",
            "delete",
            "--key",
            "K",
            "--project",
            PROJECT_ID,
            "--env",
            "development",
        ],
    );
    assert_recorded(
        &store,
        "DELETE",
        &format!("/v1/projects/{PROJECT_ID}/secrets/development/K"),
    );

    run_cli(
        dir.path(),
        &base_env,
        &[
            "token",
            "create",
            "--name",
            "ci",
            "--project",
            PROJECT_ID,
            "--env",
            "development",
        ],
    );
    assert_recorded(&store, "POST", &format!("/v1/projects/{PROJECT_ID}/tokens"));
}

#[tokio::test]
async fn run_uses_config_default_api_url() {
    let (url, store) = start_mock().await;
    let dir = tempfile::tempdir().unwrap();
    let config_home = tempfile::tempdir().unwrap();

    // Persist the default API URL via the CLI's own config command.
    run_cli(
        dir.path(),
        &[("XDG_CONFIG_HOME", config_home.path().to_str().unwrap())],
        &["config", "set-api-url", url.as_str()],
    );
    let show = run_cli(
        dir.path(),
        &[("XDG_CONFIG_HOME", config_home.path().to_str().unwrap())],
        &["config", "show"],
    );
    assert!(
        show.contains(url.as_str()),
        "config show should print the URL: {show}"
    );

    // `run` without --api-url / CIPHERA_API_URL must still hit the mock.
    run_cli(
        dir.path(),
        &[
            ("XDG_CONFIG_HOME", config_home.path().to_str().unwrap()),
            ("CIPHERA_TOKEN", "tok"),
        ],
        &[
            "run",
            "--project",
            PROJECT_ID,
            "--env",
            "development",
            "--",
            "sh",
            "-c",
            "printf %s \"$FOO\"",
        ],
    );
    assert_recorded(
        &store,
        "GET",
        &format!("/v1/projects/{PROJECT_ID}/secrets/development"),
    );
}
