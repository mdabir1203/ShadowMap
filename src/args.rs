#[derive(Clone, Debug)]
pub struct Args {
    /// Target domain to perform subdomain enumeration on
    pub domain: String,

    /// Maximum number of concurrent connections
    pub concurrency: usize,

    /// Request timeout in seconds
    pub timeout: u64,

    /// Number of retries for failed requests
    pub retries: usize,

    /// Enable the autonomous Rig-inspired orchestration engine
    pub autonomous: bool,
}
