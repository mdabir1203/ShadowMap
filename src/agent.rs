use std::collections::{HashMap, HashSet};
use std::env;
use std::path::Path;

use anyhow::anyhow;
use chrono::Local;
use idna::domain_to_unicode;
use reqwest::{redirect::Policy, Client};
use tokio::time::Duration;

use crate::cloud::{cloud_saas_recon, deep_cloud_asset_discovery, CloudAssetFinding};
use crate::constants::{IP_REGEX, SUBDOMAIN_REGEX};
use crate::cors::check_cors;
use crate::dns::{check_dns_live, create_secure_resolver};
use crate::enumeration::crtsh_enum_async;
use crate::fingerprint::fingerprint_software;
use crate::headers::check_headers_tls;
use crate::ports::scan_ports;
use crate::social::{SocialContext, SocialIntelligenceEngine, SocialIntelligenceSummary};
use crate::takeover::check_subdomain_takeover;
use crate::Args;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Debug)]
pub struct EnumerationResult {
    pub discovered: Vec<String>,
    pub validated: HashSet<String>,
}

#[derive(Debug, Default)]
struct AgentExecutionState {
    enumeration: Option<EnumerationResult>,
    live_subdomains: Option<HashSet<String>>,
    open_ports_map: Option<HashMap<String, Vec<u16>>>,
    header_map: Option<HashMap<String, (u16, Option<String>)>>,
    cors_map: Option<HashMap<String, Vec<String>>>,
    software_map: Option<HashMap<String, HashMap<String, String>>>,
    takeover_map: Option<HashMap<String, Vec<String>>>,
    cloud_saas_map: Option<HashMap<String, Vec<String>>>,
    cloud_asset_map: Option<HashMap<String, Vec<CloudAssetFinding>>>,
    social_intel: Option<SocialIntelligenceSummary>,
}

pub struct ReconEngine {
    args: Args,
    client: Client,
    output_dir: String,
    social_engine: SocialIntelligenceEngine,
}

impl ReconEngine {
    pub async fn bootstrap(args: Args) -> Result<Self, BoxError> {
        let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
        let output_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("recon_results")
            .join(format!("{}_{}", args.domain, timestamp));
        std::fs::create_dir_all(&output_dir)?;

        let client = Client::builder()
            .timeout(Duration::from_secs(args.timeout))
            .redirect(Policy::limited(2))
            .danger_accept_invalid_certs(false)
            .pool_idle_timeout(Some(Duration::from_secs(30)))
            .build()?;

        let social_engine = match env::var("SHADOWMAP_SOCIAL_CONFIG") {
            Ok(path) if !path.trim().is_empty() => {
                SocialIntelligenceEngine::from_path(path.trim())?
            }
            _ => SocialIntelligenceEngine::from_embedded()?,
        };

        Ok(Self {
            args,
            client,
            output_dir: output_dir.to_string_lossy().to_string(),
            social_engine,
        })
    }

    pub fn is_autonomous(&self) -> bool {
        self.args.autonomous
    }

    pub fn log_run_banner(&self) {
        eprintln!(
            "[*] Starting security-enhanced recon for *.{}",
            self.args.domain
        );
        eprintln!("[*] Configuration:");
        eprintln!("    - Domain: {}", self.args.domain);
        eprintln!("    - Concurrency: {}", self.args.concurrency);
        eprintln!("    - Timeout: {}s", self.args.timeout);
        eprintln!("    - Retries: {}", self.args.retries);
        eprintln!("    - Output: {}", self.output_dir);
        if self.is_autonomous() {
            eprintln!("    - Orchestration: autonomous agent (Rig-style)");
        }
    }

    pub fn domain(&self) -> &str {
        &self.args.domain
    }

    pub fn output_dir(&self) -> &str {
        &self.output_dir
    }

    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.args.timeout)
    }

    pub fn concurrency(&self) -> usize {
        self.args.concurrency
    }

    pub fn retries(&self) -> usize {
        self.args.retries.max(1)
    }

    pub async fn enumerate_subdomains(&self) -> Result<EnumerationResult, BoxError> {
        let raw_subdomains =
            crtsh_enum_async(&self.client, &self.args.domain, self.args.retries).await?;

        let mut discovered: Vec<String> = raw_subdomains.iter().cloned().collect();
        discovered.sort();

        let validated: HashSet<String> = discovered
            .iter()
            .filter_map(|raw| {
                let s = raw.replace("*.", "").replace("www.", "");
                let (decoded, result) = domain_to_unicode(&s);
                if result.is_err() {
                    return None;
                }
                let s_lower = decoded.to_lowercase();

                if IP_REGEX.is_match(&s_lower) || !SUBDOMAIN_REGEX.is_match(&s_lower) {
                    return None;
                }

                if s_lower.ends_with(&format!(".{}", self.args.domain))
                    || s_lower == self.args.domain
                {
                    Some(s_lower)
                } else {
                    None
                }
            })
            .collect();

        Ok(EnumerationResult {
            discovered,
            validated,
        })
    }

    pub async fn resolve_live_subdomains(
        &self,
        validated: &HashSet<String>,
    ) -> Result<HashSet<String>, BoxError> {
        let resolver = create_secure_resolver().await?;
        Ok(check_dns_live(validated, resolver, self.args.concurrency).await)
    }

    pub async fn scan_open_ports(&self, subs: &HashSet<String>) -> HashMap<String, Vec<u16>> {
        scan_ports(subs, self.args.concurrency).await
    }

    pub async fn inspect_headers(
        &self,
        subs: &HashSet<String>,
    ) -> HashMap<String, (u16, Option<String>)> {
        check_headers_tls(&self.client, subs, self.args.concurrency, self.args.timeout).await
    }

    pub async fn inspect_cors(&self, subs: &HashSet<String>) -> HashMap<String, Vec<String>> {
        check_cors(&self.client, subs, self.args.concurrency, self.args.timeout).await
    }

    pub async fn fingerprint_software(
        &self,
        subs: &HashSet<String>,
    ) -> HashMap<String, HashMap<String, String>> {
        fingerprint_software(&self.client, subs, self.args.concurrency, self.args.timeout).await
    }

    pub async fn discover_cloud_saas(
        &self,
        subs: &HashSet<String>,
    ) -> Result<HashMap<String, Vec<String>>, BoxError> {
        let resolver_for_cloud = create_secure_resolver().await?;
        Ok(cloud_saas_recon(subs, resolver_for_cloud, self.args.concurrency).await)
    }

    pub async fn discover_cloud_assets(
        &self,
        subs: &HashSet<String>,
    ) -> HashMap<String, Vec<CloudAssetFinding>> {
        deep_cloud_asset_discovery(
            subs,
            &self.client,
            self.args.concurrency,
            self.request_timeout(),
        )
        .await
    }

    pub async fn detect_takeovers(&self, subs: &HashSet<String>) -> HashMap<String, Vec<String>> {
        check_subdomain_takeover(subs).await
    }

    fn synthesize_social_from_state(
        &self,
        state: &AgentExecutionState,
    ) -> Result<SocialIntelligenceSummary, BoxError> {
        let live = state
            .live_subdomains
            .as_ref()
            .ok_or_else(|| missing_step_error("live subdomains missing"))?;

        let empty_ports: HashMap<String, Vec<u16>> = HashMap::new();
        let empty_cors: HashMap<String, Vec<String>> = HashMap::new();
        let empty_takeover: HashMap<String, Vec<String>> = HashMap::new();
        let empty_saas: HashMap<String, Vec<String>> = HashMap::new();
        let empty_assets: HashMap<String, Vec<CloudAssetFinding>> = HashMap::new();

        let open_ports = state.open_ports_map.as_ref().unwrap_or(&empty_ports);
        let cors = state.cors_map.as_ref().unwrap_or(&empty_cors);
        let takeover = state.takeover_map.as_ref().unwrap_or(&empty_takeover);
        let saas = state.cloud_saas_map.as_ref().unwrap_or(&empty_saas);
        let assets = state.cloud_asset_map.as_ref().unwrap_or(&empty_assets);

        Ok(self.analyze_social_from_parts(live, open_ports, cors, takeover, saas, assets))
    }

    fn analyze_social_from_parts(
        &self,
        live: &HashSet<String>,
        open_ports: &HashMap<String, Vec<u16>>,
        cors: &HashMap<String, Vec<String>>,
        takeover: &HashMap<String, Vec<String>>,
        saas: &HashMap<String, Vec<String>>,
        assets: &HashMap<String, Vec<CloudAssetFinding>>,
    ) -> SocialIntelligenceSummary {
        let context = self.build_social_context(live, open_ports, cors, takeover, saas, assets);
        self.social_engine.analyze(&context)
    }

    fn build_social_context<'a>(
        &'a self,
        live: &'a HashSet<String>,
        open_ports: &'a HashMap<String, Vec<u16>>,
        cors: &'a HashMap<String, Vec<String>>,
        takeover: &'a HashMap<String, Vec<String>>,
        saas: &'a HashMap<String, Vec<String>>,
        assets: &'a HashMap<String, Vec<CloudAssetFinding>>,
    ) -> SocialContext<'a> {
        SocialContext {
            domain: self.domain(),
            live_subdomains: live,
            open_ports,
            cors_issues: cors,
            takeover_risks: takeover,
            cloud_saas: saas,
            cloud_assets: assets,
        }
    }

    pub async fn execute_full_scan(self) -> Result<ReconReport, BoxError> {
        let enumeration = self.enumerate_subdomains().await?;
        eprintln!(
            "[+] crt.sh found {} potential subdomains",
            enumeration.discovered.len()
        );
        eprintln!("[+] Validated {} subdomains", enumeration.validated.len());

        let live_subs = self.resolve_live_subdomains(&enumeration.validated).await?;
        eprintln!("[+] {} live subdomains detected", live_subs.len());

        let open_ports_map = self.scan_open_ports(&live_subs).await;
        eprintln!(
            "[+] Port scan complete - found {} subdomains with open ports",
            open_ports_map.len()
        );

        let header_map = self.inspect_headers(&live_subs).await;
        eprintln!("[+] Header/TLS check complete");

        let cors_map = self.inspect_cors(&live_subs).await;
        eprintln!(
            "[+] CORS check complete - found {} potential issues",
            cors_map.len()
        );

        let software_map = self.fingerprint_software(&live_subs).await;
        eprintln!("[+] Software fingerprinting complete");

        let cloud_saas_map = self.discover_cloud_saas(&live_subs).await?;
        eprintln!(
            "[+] Cloud/SaaS reconnaissance complete - found {} subdomains with SaaS patterns or predictions",
            cloud_saas_map.len()
        );

        let cloud_asset_map = self.discover_cloud_assets(&live_subs).await;
        eprintln!(
            "[+] Deep cloud asset discovery complete - flagged {} subdomains",
            cloud_asset_map.len()
        );

        let takeover_map = self.detect_takeovers(&live_subs).await;
        eprintln!(
            "[+] Takeover check complete - found {} potential targets (including cloud)",
            takeover_map.len()
        );

        let social_intel = self.analyze_social_from_parts(
            &live_subs,
            &open_ports_map,
            &cors_map,
            &takeover_map,
            &cloud_saas_map,
            &cloud_asset_map,
        );

        Ok(ReconReport {
            domain: self.args.domain,
            output_dir: self.output_dir,
            discovered_subdomains: enumeration.discovered,
            validated_subdomains: enumeration.validated,
            live_subdomains: live_subs,
            open_ports_map,
            header_map,
            cors_map,
            software_map,
            takeover_map,
            cloud_saas_map,
            cloud_asset_map,
            social_intel: Some(social_intel),
        })
    }
}

pub struct AutonomousReconAgent {
    engine: ReconEngine,
    step_retries: usize,
}

impl AutonomousReconAgent {
    pub fn new(engine: ReconEngine) -> Self {
        let step_retries = engine.retries();
        Self {
            engine,
            step_retries,
        }
    }

    pub async fn execute(self) -> Result<ReconReport, BoxError> {
        let AutonomousReconAgent {
            engine,
            step_retries,
        } = self;

        let mut state = AgentExecutionState::default();
        for step in plan(step_retries) {
            eprintln!("[agent] ➡️ {}", step.name);

            let mut attempt = 0usize;
            loop {
                attempt += 1;
                let step_result = match step.kind {
                    StepKind::Enumerate => match engine.enumerate_subdomains().await {
                        Ok(enumeration) => {
                            eprintln!(
                                "[agent]    discovered {} candidates, {} survived validation",
                                enumeration.discovered.len(),
                                enumeration.validated.len()
                            );
                            state.enumeration = Some(enumeration);
                            Ok(())
                        }
                        Err(err) => Err(err),
                    },
                    StepKind::Resolve => {
                        if let Some(enumeration) = state.enumeration.as_ref() {
                            match engine.resolve_live_subdomains(&enumeration.validated).await {
                                Ok(live) => {
                                    eprintln!(
                                        "[agent]    {} live subdomains after DNS validation",
                                        live.len()
                                    );
                                    state.live_subdomains = Some(live);
                                    Ok(())
                                }
                                Err(err) => Err(err),
                            }
                        } else {
                            Err(missing_step_error("enumeration step missing"))
                        }
                    }
                    StepKind::Ports => {
                        if let Some(live) = state.live_subdomains.as_ref() {
                            let ports = engine.scan_open_ports(live).await;
                            eprintln!("[agent]    {} subdomains expose open ports", ports.len());
                            state.open_ports_map = Some(ports);
                            Ok(())
                        } else {
                            Err(missing_step_error("live subdomains missing"))
                        }
                    }
                    StepKind::Headers => {
                        if let Some(live) = state.live_subdomains.as_ref() {
                            let headers = engine.inspect_headers(live).await;
                            state.header_map = Some(headers);
                            Ok(())
                        } else {
                            Err(missing_step_error("live subdomains missing"))
                        }
                    }
                    StepKind::Cors => {
                        if let Some(live) = state.live_subdomains.as_ref() {
                            let cors = engine.inspect_cors(live).await;
                            eprintln!("[agent]    CORS anomalies flagged on {} hosts", cors.len());
                            state.cors_map = Some(cors);
                            Ok(())
                        } else {
                            Err(missing_step_error("live subdomains missing"))
                        }
                    }
                    StepKind::Fingerprint => {
                        if let Some(live) = state.live_subdomains.as_ref() {
                            let fingerprints = engine.fingerprint_software(live).await;
                            state.software_map = Some(fingerprints);
                            Ok(())
                        } else {
                            Err(missing_step_error("live subdomains missing"))
                        }
                    }
                    StepKind::CloudSaas => {
                        if let Some(live) = state.live_subdomains.as_ref() {
                            match engine.discover_cloud_saas(live).await {
                                Ok(saas) => {
                                    eprintln!(
                                        "[agent]    {} SaaS indicators identified",
                                        saas.len()
                                    );
                                    state.cloud_saas_map = Some(saas);
                                    Ok(())
                                }
                                Err(err) => Err(err),
                            }
                        } else {
                            Err(missing_step_error("live subdomains missing"))
                        }
                    }
                    StepKind::CloudAssets => {
                        if let Some(live) = state.live_subdomains.as_ref() {
                            let assets = engine.discover_cloud_assets(live).await;
                            eprintln!("[agent]    {} cloud assets worth review", assets.len());
                            state.cloud_asset_map = Some(assets);
                            Ok(())
                        } else {
                            Err(missing_step_error("live subdomains missing"))
                        }
                    }
                    StepKind::Takeover => {
                        if let Some(live) = state.live_subdomains.as_ref() {
                            let takeover = engine.detect_takeovers(live).await;
                            eprintln!("[agent]    {} takeover candidates queued", takeover.len());
                            state.takeover_map = Some(takeover);
                            Ok(())
                        } else {
                            Err(missing_step_error("live subdomains missing"))
                        }
                    }
                    StepKind::SocialIntel => match engine.synthesize_social_from_state(&state) {
                        Ok(summary) => {
                            eprintln!(
                                    "[agent]    social stream surfaced {} signals (avg confidence {:.0}%)",
                                    summary.metrics.total_signals,
                                    summary.metrics.average_confidence
                                );
                            state.social_intel = Some(summary);
                            Ok(())
                        }
                        Err(err) => Err(err),
                    },
                };

                match step_result {
                    Ok(_) => {
                        if attempt > 1 {
                            eprintln!("[agent]    recovered after {} attempts", attempt);
                        }
                        break;
                    }
                    Err(err) => {
                        if attempt >= step.max_attempts {
                            return Err(err);
                        }
                        eprintln!(
                            "[agent]    attempt {} failed ({}), retrying...",
                            attempt, err
                        );
                    }
                }
            }
        }

        let enumeration = state
            .enumeration
            .ok_or_else(|| missing_step_error("enumeration missing"))?;
        let live_subdomains = state
            .live_subdomains
            .ok_or_else(|| missing_step_error("live subdomains missing"))?;

        let ReconEngine {
            args,
            client: _,
            output_dir,
            ..
        } = engine;
        let Args { domain, .. } = args;

        Ok(ReconReport {
            domain,
            output_dir,
            discovered_subdomains: enumeration.discovered,
            validated_subdomains: enumeration.validated,
            live_subdomains,
            open_ports_map: state.open_ports_map.unwrap_or_default(),
            header_map: state.header_map.unwrap_or_default(),
            cors_map: state.cors_map.unwrap_or_default(),
            software_map: state.software_map.unwrap_or_default(),
            takeover_map: state.takeover_map.unwrap_or_default(),
            cloud_saas_map: state.cloud_saas_map.unwrap_or_default(),
            cloud_asset_map: state.cloud_asset_map.unwrap_or_default(),
            social_intel: state.social_intel,
        })
    }
}

fn plan(step_retries: usize) -> Vec<AgentStep> {
    let max_attempts = step_retries.max(1);
    vec![
        AgentStep::new(
            "Enumerate subdomains via CRT.sh",
            StepKind::Enumerate,
            max_attempts,
        ),
        AgentStep::new("Validate DNS responses", StepKind::Resolve, max_attempts),
        AgentStep::new("Port scan live assets", StepKind::Ports, max_attempts),
        AgentStep::new("Capture headers & TLS", StepKind::Headers, max_attempts),
        AgentStep::new("Analyse CORS controls", StepKind::Cors, max_attempts),
        AgentStep::new(
            "Fingerprint running software",
            StepKind::Fingerprint,
            max_attempts,
        ),
        AgentStep::new(
            "Predict SaaS/cloud usage",
            StepKind::CloudSaas,
            max_attempts,
        ),
        AgentStep::new(
            "Discover deep cloud assets",
            StepKind::CloudAssets,
            max_attempts,
        ),
        AgentStep::new("Assess takeover exposure", StepKind::Takeover, max_attempts),
        AgentStep::new(
            "Synthesize social intelligence",
            StepKind::SocialIntel,
            max_attempts,
        ),
    ]
}

struct AgentStep {
    name: &'static str,
    kind: StepKind,
    max_attempts: usize,
}

impl AgentStep {
    fn new(name: &'static str, kind: StepKind, max_attempts: usize) -> Self {
        Self {
            name,
            kind,
            max_attempts,
        }
    }
}

#[derive(Copy, Clone)]
enum StepKind {
    Enumerate,
    Resolve,
    Ports,
    Headers,
    Cors,
    Fingerprint,
    CloudSaas,
    CloudAssets,
    Takeover,
    SocialIntel,
}

pub struct ReconReport {
    pub domain: String,
    pub output_dir: String,
    pub discovered_subdomains: Vec<String>,
    pub validated_subdomains: HashSet<String>,
    pub live_subdomains: HashSet<String>,
    pub open_ports_map: HashMap<String, Vec<u16>>,
    pub header_map: HashMap<String, (u16, Option<String>)>,
    pub cors_map: HashMap<String, Vec<String>>,
    pub software_map: HashMap<String, HashMap<String, String>>,
    pub takeover_map: HashMap<String, Vec<String>>,
    pub cloud_saas_map: HashMap<String, Vec<String>>,
    pub cloud_asset_map: HashMap<String, Vec<CloudAssetFinding>>,
    pub social_intel: Option<SocialIntelligenceSummary>,
}

fn missing_step_error(message: &str) -> BoxError {
    anyhow!(message.to_string()).into()
}
