pub mod state;
pub mod views;

pub use state::{AppState, JobConfig, JobId, JobStatus};
pub use views::{render_index_page, render_job_row, render_job_rows};
