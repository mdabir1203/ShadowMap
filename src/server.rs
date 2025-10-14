use std::net::SocketAddr;

use axum::{
    extract::{Form, Path, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use shadowmap::{run, Args};
use tracing::{error, info};

mod web;

use web::{
    render_index_page, render_job_row, render_job_rows, render_landing_page, AppState, JobConfig,
    JobId, JobStatus, LandingPageContext, PricingPlan,
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
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let state = AppState::new().await?;
    let app = Router::new()
        .route("/", get(landing))
        .route("/app", get(index))
        .route("/jobs", get(list_jobs).post(create_job))
        .route("/jobs/:id", get(job_row))
        .route("/jobs/:id/report", get(job_report))
        .route("/create-checkout-session", post(create_checkout_session))
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

async fn landing() -> Html<String> {
    let context = build_landing_page_context();
    Html(render_landing_page(&context))
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

#[derive(Debug, Deserialize)]
struct CheckoutRequest {
    plan_id: String,
    region: String,
    email: Option<String>,
}

#[derive(Debug, Serialize)]
struct CheckoutResponse {
    session_id: String,
}

#[derive(Debug, Deserialize)]
struct StripeSession {
    id: String,
}

async fn create_checkout_session(

    State(state): State<AppState>,

    Json(payload): Json<CheckoutRequest>,
) -> Result<Json<CheckoutResponse>, (StatusCode, String)> {
    let plan = payload.plan_id.trim().to_lowercase();
    let region = payload.region.trim().to_lowercase();
    let lead_email = payload.email.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    });

    let Some(env_key) = stripe_price_env_key(&plan, &region) else {
        return Err((
            StatusCode::BAD_REQUEST,
            "Unknown plan or region selected".to_string(),
        ));
    };

    if let Some(email) = lead_email.as_deref() {
        if let Err(err) = state.record_work_email(email, &plan, &region).await {
            error!(?err, email = %email, plan = %plan, region = %region, "failed to store lead email");
        }
    }

    let price_id = std::env::var(env_key).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Checkout is not available for the selected plan in this region yet.".to_string(),
        )
    })?;

    let secret_key = std::env::var("STRIPE_SECRET_KEY").map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Stripe payments are not configured.".to_string(),
        )
    })?;

    let success_url = std::env::var("STRIPE_SUCCESS_URL")
        .unwrap_or_else(|_| "https://shadowmap.io/app?checkout=success".to_string());
    let cancel_url = std::env::var("STRIPE_CANCEL_URL")
        .unwrap_or_else(|_| "https://shadowmap.io/pricing".to_string());

    let mut form_body = vec![
        ("mode".to_string(), "subscription".to_string()),
        ("line_items[0][price]".to_string(), price_id),
        ("line_items[0][quantity]".to_string(), "1".to_string()),
        ("success_url".to_string(), success_url),
        ("cancel_url".to_string(), cancel_url),
        ("allow_promotion_codes".to_string(), "true".to_string()),
    ];

    if let Some(email) = lead_email {
        form_body.push(("customer_email".to_string(), email));
    }

    let client = reqwest::Client::new();
    let response = client
        .post("https://api.stripe.com/v1/checkout/sessions")
        .bearer_auth(secret_key)
        .form(&form_body)
        .send()
        .await
        .map_err(|err| {
            error!(?err, "failed to talk to stripe");
            (
                StatusCode::BAD_GATEWAY,
                "Unable to reach Stripe right now. Please try again.".to_string(),
            )
        })?;

    let status = response.status();
    let body = response.text().await.map_err(|err| {
        error!(?err, "failed to read stripe response");
        (
            StatusCode::BAD_GATEWAY,
            "Received an unexpected response from Stripe.".to_string(),
        )
    })?;

    if !status.is_success() {
        error!(?status, body = %body, "stripe returned an error");
        return Err((
            StatusCode::BAD_GATEWAY,
            "Stripe rejected the checkout session. Contact support if this persists.".to_string(),
        ));
    }

    let session: StripeSession = serde_json::from_str(&body).map_err(|err| {
        error!(?err, body = %body, "failed to parse stripe session");
        (
            StatusCode::BAD_GATEWAY,
            "Unexpected response from payment processor.".to_string(),
        )
    })?;

    Ok(Json(CheckoutResponse {
        session_id: session.id,
    }))
}

fn build_landing_page_context() -> LandingPageContext {
    let publishable_key = std::env::var("STRIPE_PUBLISHABLE_KEY").ok();
    let plans = vec![
        PricingPlan {
            id: "starter",
            name: "Starter",
            summary: "Launch automation-grade recon for boutique agencies and red teams.",
            ideal_for: "Solo operators",
            highlight: false,
            usd_cents: 7900,
            eur_cents: 7500,
            features: &[
                "Unlimited on-demand reconnaissance jobs",
                "Live subdomain, DNS, and takeover detection",
                "Automated PDF & JSON reporting exports",
                "Email support with 1-business-day SLA",
            ],
            checkout_ready_us: stripe_price_configured("starter", "us"),
            checkout_ready_eu: stripe_price_configured("starter", "eu"),
        },
        PricingPlan {
            id: "growth",
            name: "Growth",
            summary: "Scale your practice with team workspaces, automations, and real-time monitoring.",
            ideal_for: "Agencies & MSSPs",
            highlight: true,
            usd_cents: 15900,
            eur_cents: 14900,
            features: &[
                "Everything in Starter plus scheduled monitoring",
                "Team workspaces with role-based access control",
                "Slack and webhook alerting for high-risk findings",
                "Dedicated success engineer and quarterly playbooks",
            ],
            checkout_ready_us: stripe_price_configured("growth", "us"),
            checkout_ready_eu: stripe_price_configured("growth", "eu"),
        },
        PricingPlan {
            id: "enterprise",
            name: "Enterprise",
            summary: "For global security organizations that need private deployments and custom workflows.",
            ideal_for: "Global teams",
            highlight: false,
            usd_cents: 34900,
            eur_cents: 32900,
            features: &[
                "Private cloud or on-premise deployment options",
                "Custom modules and API surface for internal tooling",
                "Advanced compliance reporting & SOC2 documentation",
                "24/7 incident response with named TAM",
            ],
            checkout_ready_us: stripe_price_configured("enterprise", "us"),
            checkout_ready_eu: stripe_price_configured("enterprise", "eu"),
        },
    ];

    LandingPageContext {
        publishable_key,
        plans,
    }
}

fn stripe_price_configured(plan: &str, region: &str) -> bool {
    stripe_price_env_key(plan, region)
        .and_then(|key| std::env::var(key).ok())
        .is_some()
}

fn stripe_price_env_key(plan: &str, region: &str) -> Option<&'static str> {
    match (plan, region) {
        ("starter", "us") => Some("STRIPE_PRICE_STARTER_USD"),
        ("starter", "eu") => Some("STRIPE_PRICE_STARTER_EUR"),
        ("growth", "us") => Some("STRIPE_PRICE_GROWTH_USD"),
        ("growth", "eu") => Some("STRIPE_PRICE_GROWTH_EUR"),
        ("enterprise", "us") => Some("STRIPE_PRICE_ENTERPRISE_USD"),
        ("enterprise", "eu") => Some("STRIPE_PRICE_ENTERPRISE_EUR"),
        _ => None,
    }
}
