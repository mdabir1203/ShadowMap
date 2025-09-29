use std::net::SocketAddr;

use axum::{
    extract::{Form, Path, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use serde::Deserialize;
use shadowmap::{run, Args};
use tracing::{error, info};

mod web;

use web::{
    render_index_page, render_job_row, render_job_rows, AppState, JobConfig, JobId, JobStatus,
};

#[derive(Debug, Deserialize)]
struct JobRequest {
    domain: String,
    #[serde(default = "default_concurrency")]
    concurrency: usize,
    #[serde(default = "default_timeout")]
    timeout: u64,
    #[serde(default = "default_retries")]
    retries: usize,
}

fn default_concurrency() -> usize {
    JobConfig::default().concurrency
}

fn default_timeout() -> u64 {
    JobConfig::default().timeout
}

fn default_retries() -> usize {
    JobConfig::default().retries
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();

    let state = AppState::new();
    let app = Router::new()
        .route("/", get(index))
        .route("/jobs", get(list_jobs).post(create_job))
        .route("/jobs/:id", get(job_row))
        .route("/jobs/:id/report", get(job_report))
        .with_state(state);

    let addr: SocketAddr = "0.0.0.0:8080".parse()?;
    info!("Starting ShadowMap HTMX server on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    info!("shutdown signal received");
}

async fn index(State(state): State<AppState>) -> Html<String> {
    let jobs = state.list_jobs().await;
    Html(render_index_page(&jobs))
}

async fn list_jobs(State(state): State<AppState>) -> Html<String> {
    let jobs = state.list_jobs().await;
    if jobs.is_empty() {
        Html(r#"<tr><td colspan="5" class="table-empty">No jobs yet. Launch a scan to populate the dashboard.</td></tr>"#.into())
    } else {
        Html(render_job_rows(&jobs))
    }
}

async fn job_row(
    Path(id): Path<JobId>,
    State(state): State<AppState>,
) -> Result<Html<String>, StatusCode> {
    let job = state.get_job(&id).await.ok_or(StatusCode::NOT_FOUND)?;
    Ok(Html(render_job_row(&job)))
}

async fn job_report(
    Path(id): Path<JobId>,
    State(state): State<AppState>,
) -> Result<Response, StatusCode> {
    let job = state.get_job(&id).await.ok_or(StatusCode::NOT_FOUND)?;
    if job.status != JobStatus::Completed {
        return Err(StatusCode::CONFLICT);
    }
    let output_dir = job.output_path.ok_or(StatusCode::NOT_FOUND)?;
    let file_path = format!("{}/{}_report.json", output_dir, job.domain);
    match tokio::fs::read_to_string(&file_path).await {
        Ok(contents) => {
            Ok(([(header::CONTENT_TYPE, "application/json")], contents).into_response())
        }
        Err(err) => {
            error!(job_id = %job.id, path = %file_path, ?err, "failed to read report");
            Err(StatusCode::NOT_FOUND)
        }
    }
}

async fn create_job(
    State(state): State<AppState>,
    Form(request): Form<JobRequest>,
) -> Result<Html<String>, (StatusCode, String)> {
    let domain = request.domain.trim();
    if domain.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Domain is required".to_string()));
    }

    let config = JobConfig {
        concurrency: request.concurrency.clamp(1, 500),
        timeout: request.timeout.clamp(1, 300),
        retries: request.retries.clamp(0, 10),
    };

    let job = state.create_job(domain.to_string(), config.clone()).await;
    let job_id = job.id.clone();
    let domain = job.domain.clone();

    tokio::spawn(run_job(state.clone(), job_id, domain, config));

    Ok(Html(render_job_row(&job)))
}

async fn run_job(state: AppState, job_id: JobId, domain: String, config: JobConfig) {
    state.mark_running(&job_id).await;
    let args = Args {
        domain: domain.clone(),
        concurrency: config.concurrency,
        timeout: config.timeout,
        retries: config.retries,
        autonomous: false,
    };
    match run(args).await {
        Ok(path) => {
            state.mark_completed(&job_id, path).await;
            info!(job_id = %job_id, domain = %domain, "job completed");
        }
        Err(err) => {
            error!(job_id = %job_id, domain = %domain, ?err, "job failed");
            state.mark_failed(&job_id, err.to_string()).await;
        }
    }
}
