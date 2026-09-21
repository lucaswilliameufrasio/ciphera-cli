use ciphera_core::{BatchCreateSecretsRequest, SecretInput};
use reqwest::{Client, StatusCode};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{Duration, sleep};

/// Batches uploaded in flight at once. The server caps batch throughput, so
/// a small fan-out already amortises the sequential round-trips without
/// flooding it.
const UPLOAD_CONCURRENCY: usize = 4;

#[derive(Clone)]
pub struct Uploader {
    client: Client,
    api_url: String,
    session_token: String,
}

impl Uploader {
    pub fn new(api_url: String, session_token: String) -> Self {
        Self {
            client: Client::new(),
            api_url,
            session_token,
        }
    }

    pub async fn upload_in_batches(
        &self,
        project_id: &str,
        environment: &str,
        secrets: Vec<SecretInput>,
        batch_size: usize,
    ) -> Result<(), String> {
        let total = secrets.len();
        let total_batches = secrets.chunks(batch_size).count();

        println!("Preparing upload of {total} secrets in {total_batches} batch(es)...");

        let url = Arc::new(format!(
            "{}/v1/projects/{}/secrets/batch",
            self.api_url, project_id
        ));
        let semaphore = Arc::new(Semaphore::new(UPLOAD_CONCURRENCY));
        let completed = Arc::new(AtomicUsize::new(0));
        let mut tasks = JoinSet::new();

        for (i, chunk) in secrets.chunks(batch_size).enumerate() {
            let uploader = self.clone();
            let url = Arc::clone(&url);
            let semaphore = Arc::clone(&semaphore);
            let completed = Arc::clone(&completed);
            let environment = environment.to_string();
            let payload = BatchCreateSecretsRequest {
                environment,
                secrets: chunk.to_vec(),
            };
            let batch_no = i + 1;

            tasks.spawn(async move {
                let _permit = semaphore
                    .acquire_owned()
                    .await
                    .map_err(|e| format!("Upload semaphore closed: {e}"))?;

                uploader
                    .send_with_retry(&url, &payload, batch_no, total_batches)
                    .await?;

                let done = completed.fetch_add(1, Ordering::SeqCst) + 1;
                println!("Uploaded {done}/{total_batches} batch(es)");
                Ok(())
            });
        }

        let mut first_error: Option<String> = None;
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    first_error = Some(e);
                    tasks.abort_all();
                    break;
                }
                Err(e) => {
                    first_error = Some(format!("Upload task failed: {e}"));
                    tasks.abort_all();
                    break;
                }
            }
        }

        match first_error {
            Some(e) => Err(e),
            None => {
                println!("All batches successfully uploaded!");
                Ok(())
            }
        }
    }

    async fn send_with_retry(
        &self,
        url: &str,
        payload: &BatchCreateSecretsRequest,
        current_batch: usize,
        total_batches: usize,
    ) -> Result<(), String> {
        let max_retries = 3;
        let mut attempt = 0;

        loop {
            attempt += 1;
            println!("Sending batch {current_batch}/{total_batches} (attempt {attempt})");

            let response = self
                .client
                .post(url)
                .bearer_auth(&self.session_token)
                .json(payload)
                .send()
                .await;

            match response {
                Ok(resp) if resp.status().is_success() => {
                    return Ok(());
                }
                Ok(resp) if resp.status() == StatusCode::UNAUTHORIZED => {
                    return Err(
                        "Authentication failed: Session or service token expired/invalid."
                            .to_string(),
                    );
                }
                Ok(resp) if resp.status() == StatusCode::FORBIDDEN => {
                    return Err(
                        "Access denied: You do not have permission for this project/environment."
                            .to_string(),
                    );
                }
                Ok(resp) => {
                    eprintln!("API returned status error: {}", resp.status());
                }
                Err(e) => {
                    eprintln!("Network request failed: {e}");
                }
            }

            if attempt >= max_retries {
                return Err(format!(
                    "Failed to upload batch {current_batch}/{total_batches} after {max_retries} attempts."
                ));
            }

            let backoff_secs = 2_u64.pow(attempt as u32);
            println!(
                "Batch {current_batch}/{total_batches}: waiting {backoff_secs}s before retrying"
            );
            sleep(Duration::from_secs(backoff_secs)).await;
        }
    }
}
