use std::{collections::HashMap, sync::Arc};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rand::{distributions::Alphanumeric, Rng};
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use tokio::sync::RwLock;

pub type JobId = String;

#[derive(Clone, Debug)]
pub struct JobConfig {
    pub concurrency: usize,
    pub timeout: u64,
    pub retries: usize,
}

impl Default for JobConfig {
    fn default() -> Self {
        Self {
            concurrency: 50,
            timeout: 10,
            retries: 3,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed,
}

#[derive(Clone, Debug)]
pub struct Job {
    pub id: JobId,
    pub domain: String,
    pub status: JobStatus,
    pub output_path: Option<String>,
    pub error: Option<String>,
    pub config: JobConfig,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Job {
    pub fn new(domain: String, config: JobConfig) -> Self {
        let now = Utc::now();
        Self {
            id: generate_job_id(),
            domain,
            status: JobStatus::Queued,
            output_path: None,
            error: None,
            config,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn mark_running(&mut self) {
        self.status = JobStatus::Running;
        self.updated_at = Utc::now();
    }

    pub fn mark_completed(&mut self, output_path: String) {
        self.status = JobStatus::Completed;
        self.output_path = Some(output_path);
        self.error = None;
        self.updated_at = Utc::now();
    }

    pub fn mark_failed(&mut self, error: String) {
        self.status = JobStatus::Failed;
        self.error = Some(error);
        self.output_path = None;
        self.updated_at = Utc::now();
    }
}

fn generate_job_id() -> JobId {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect()
}

#[derive(Clone)]
pub struct AppState {
    jobs: Arc<RwLock<HashMap<JobId, Job>>>,
    leads: LeadStore,
}

impl AppState {
    pub async fn new() -> Result<Self> {
        let database_url =
            std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://shadowmap.db".to_string());
        let leads = LeadStore::initialize(&database_url).await?;

        Ok(Self {
            jobs: Arc::new(RwLock::new(HashMap::new())),
            leads,
        })
    }

    pub async fn create_job(&self, domain: String, config: JobConfig) -> Job {
        let job = Job::new(domain, config);
        self.jobs.write().await.insert(job.id.clone(), job.clone());
        job
    }

    pub async fn record_work_email(
        &self,
        email: &str,
        plan: &str,
        region: &str,
    ) -> sqlx::Result<()> {
        self.leads.record_email(email, plan, region).await
    }

    pub async fn list_jobs(&self) -> Vec<Job> {
        let mut jobs: Vec<_> = self.jobs.read().await.values().cloned().collect();
        jobs.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        jobs
    }

    pub async fn get_job(&self, id: &JobId) -> Option<Job> {
        self.jobs.read().await.get(id).cloned()
    }

    pub async fn mark_running(&self, id: &JobId) {
        if let Some(job) = self.jobs.write().await.get_mut(id) {
            job.mark_running();
        }
    }

    pub async fn mark_completed(&self, id: &JobId, output_path: String) {
        if let Some(job) = self.jobs.write().await.get_mut(id) {
            job.mark_completed(output_path);
        }
    }

    pub async fn mark_failed(&self, id: &JobId, error: String) {
        if let Some(job) = self.jobs.write().await.get_mut(id) {
            job.mark_failed(error);
        }
    }
}

#[derive(Clone)]
struct LeadStore {
    pool: SqlitePool,
}

impl LeadStore {
    async fn initialize(database_url: &str) -> Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await
            .with_context(|| format!("failed to connect to database at {database_url}"))?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS landing_leads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                plan_id TEXT NOT NULL,
                region TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'now')),
                updated_at TEXT NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'now'))
            )
            "#,
        )
        .execute(&pool)
        .await
        .context("failed to initialize landing_leads table")?;

        Ok(Self { pool })
    }

    async fn record_email(&self, email: &str, plan: &str, region: &str) -> sqlx::Result<()> {
        let normalized_email = email.trim().to_ascii_lowercase();
        if normalized_email.is_empty() {
            return Ok(());
        }

        let normalized_plan = plan.trim().to_ascii_lowercase();
        let normalized_region = region.trim().to_ascii_lowercase();

        sqlx::query(
            r#"
            INSERT INTO landing_leads (email, plan_id, region, created_at, updated_at)
            VALUES (?1, ?2, ?3, STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'now'), STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'now'))
            ON CONFLICT(email) DO UPDATE SET
                plan_id = excluded.plan_id,
                region = excluded.region,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(normalized_email)
        .bind(normalized_plan)
        .bind(normalized_region)
        .execute(&self.pool)
        .await
        .map(|_| ())
    }
}
