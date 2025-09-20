use std::{collections::HashMap, sync::Arc};

use chrono::{DateTime, Utc};
use rand::{distributions::Alphanumeric, Rng};
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

#[derive(Clone, Default)]
pub struct AppState {
    jobs: Arc<RwLock<HashMap<JobId, Job>>>,
}

impl AppState {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn create_job(&self, domain: String, config: JobConfig) -> Job {
        let job = Job::new(domain, config);
        self.jobs.write().await.insert(job.id.clone(), job.clone());
        job
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
