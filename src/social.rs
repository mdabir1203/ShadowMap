use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;

use serde::Deserialize;
use serde::Serialize;

use crate::cloud::CloudAssetFinding;
use crate::BoxError;

const EMBEDDED_CONFIG: &str = include_str!("../configs/social-intelligence.yaml");

#[derive(Debug, Clone, Serialize)]
pub struct SocialIntelligenceSummary {
    pub framework_name: String,
    pub framework_version: String,
    pub framework_description: String,
    pub scenarios: Vec<String>,
    pub plans: Vec<PlannerOutcome>,
    pub signals: Vec<SocialSignal>,
    pub correlations: Vec<SocialCorrelation>,
    pub remediations: Vec<RemediationPlaybook>,
    pub reports: Vec<SocialReportView>,
    pub metrics: SocialMetrics,
    pub guardrails: Vec<String>,
    pub localization: LocalizationSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlannerOutcome {
    pub scenario: String,
    pub topic: String,
    pub intents: Vec<String>,
    pub steps: Vec<PlannerStep>,
    pub confidence: f32,
    pub expected_outputs: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlannerStep {
    pub step: usize,
    pub tool: String,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SocialSignal {
    pub signal_id: String,
    pub scenario: String,
    pub topic: String,
    pub severity: String,
    pub confidence: f32,
    pub vendor_cloud: Vec<String>,
    pub services: Vec<String>,
    pub regions: Vec<String>,
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SocialCorrelation {
    pub asset_id: String,
    pub reasons: Vec<String>,
    pub risk_score: f32,
    pub supporting_findings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemediationPlaybook {
    pub scenario: String,
    pub title: String,
    pub severity: String,
    pub due_days: u32,
    pub steps: Vec<String>,
    pub rollback: Vec<String>,
    pub verification: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SocialReportView {
    pub scenario: String,
    pub executive_brief: String,
    pub engineer_brief: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SocialMetrics {
    pub total_signals: usize,
    pub correlated_assets: usize,
    pub average_confidence: f32,
    pub severity_breakdown: BTreeMap<String, usize>,
    pub live_hosts: usize,
    pub saas_watchlist: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct LocalizationSummary {
    pub primary_geo: Option<String>,
    pub languages: Vec<String>,
    pub regions: Vec<String>,
    pub environments: Vec<String>,
    pub controls_available: Vec<String>,
    pub change_windows: Vec<String>,
}

pub struct SocialContext<'a> {
    pub domain: &'a str,
    pub live_subdomains: &'a HashSet<String>,
    pub open_ports: &'a HashMap<String, Vec<u16>>,
    pub cors_issues: &'a HashMap<String, Vec<String>>,
    pub takeover_risks: &'a HashMap<String, Vec<String>>,
    pub cloud_saas: &'a HashMap<String, Vec<String>>,
    pub cloud_assets: &'a HashMap<String, Vec<CloudAssetFinding>>,
}

#[derive(Debug, Deserialize)]
struct FrameworkConfig {
    version: String,
    name: String,
    description: String,
    agents: Vec<AgentSpec>,
    guardrails: Vec<GuardrailSpec>,
    tools: Vec<ToolSpec>,
    #[serde(default)]
    defaults: FrameworkDefaults,
    #[serde(default)]
    testing: TestingConfig,
}

#[derive(Debug, Deserialize)]
struct AgentSpec {
    id: String,
    #[serde(default)]
    confidence_threshold: Option<f32>,
}

#[derive(Debug, Deserialize)]
struct GuardrailSpec {
    description: String,
}

#[derive(Debug, Deserialize)]
struct ToolSpec {
    name: String,
}

#[derive(Debug, Default, Deserialize)]
struct FrameworkDefaults {
    #[serde(default)]
    org_filters: Option<OrgFilters>,
    #[serde(default)]
    controls_available: Vec<String>,
    #[serde(default)]
    change_windows: Vec<String>,
    #[serde(default)]
    localization: Option<LocalizationConfig>,
}

#[derive(Debug, Default, Deserialize)]
struct OrgFilters {
    #[serde(default)]
    env: Vec<String>,
    #[serde(default)]
    regions: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct LocalizationConfig {
    #[serde(default)]
    geo: Option<String>,
    #[serde(default)]
    languages: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct TestingConfig {
    #[serde(default)]
    scenarios: Vec<ScenarioConfig>,
}

impl TestingConfig {
    fn scenario_by_name(&self, name: &str) -> Option<&ScenarioConfig> {
        self.scenarios.iter().find(|scenario| scenario.name == name)
    }
}

#[derive(Debug, Deserialize)]
struct ScenarioConfig {
    name: String,
    topic: String,
    #[serde(default)]
    expected_output: Vec<String>,
}

#[derive(Debug)]
struct ScenarioDescriptor {
    name: String,
    topic: String,
    expected_output: Vec<String>,
}

#[derive(Debug, Copy, Clone)]
struct ScenarioProfile {
    severity: &'static str,
    vendor_cloud: &'static [&'static str],
    services: &'static [&'static str],
    base_confidence: f32,
    base_risk: f32,
}

pub struct SocialIntelligenceEngine {
    config: FrameworkConfig,
    planner_confidence: f32,
}

impl SocialIntelligenceEngine {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, BoxError> {
        let yaml = fs::read_to_string(path)?;
        Self::from_yaml_str(&yaml)
    }

    pub fn from_yaml_str(yaml: &str) -> Result<Self, BoxError> {
        let config: FrameworkConfig = serde_yaml::from_str(yaml)?;
        let planner_confidence = config
            .agents
            .iter()
            .find(|agent| agent.id == "planner")
            .and_then(|agent| agent.confidence_threshold)
            .unwrap_or(0.6);
        Ok(Self {
            config,
            planner_confidence,
        })
    }

    pub fn from_embedded() -> Result<Self, BoxError> {
        Self::from_yaml_str(EMBEDDED_CONFIG)
    }

    pub fn analyze(&self, context: &SocialContext<'_>) -> SocialIntelligenceSummary {
        let scenarios = self.select_scenarios(context);
        let mut signals = Vec::new();
        let mut correlations = Vec::new();
        let mut remediations = Vec::new();
        let mut reports = Vec::new();
        let mut plans = Vec::new();
        let mut severity_breakdown: BTreeMap<String, usize> = BTreeMap::new();
        let mut correlated_assets: HashSet<String> = HashSet::new();
        let mut confidence_total = 0.0_f32;

        for (index, scenario) in scenarios.iter().enumerate() {
            let profile = scenario_profile(&scenario.name);
            let plan = self.build_plan(index, scenario, profile);
            plans.push(plan);

            let signal = self.build_signal(index, scenario, profile, context);
            confidence_total += signal.confidence;
            *severity_breakdown
                .entry(signal.severity.clone())
                .or_insert(0) += 1;
            signals.push(signal.clone());

            if let Some(correlation) = self.build_correlation(scenario, profile, context) {
                correlated_assets.insert(correlation.asset_id.clone());
                correlations.push(correlation);
            }

            remediations.push(self.build_remediation(scenario, profile, context));
            reports.push(self.build_report_view(scenario, profile, context));
        }

        let average_confidence = if signals.is_empty() {
            0.0
        } else {
            (confidence_total / signals.len() as f32 * 100.0).round() / 100.0
        };

        let metrics = SocialMetrics {
            total_signals: signals.len(),
            correlated_assets: correlated_assets.len(),
            average_confidence,
            severity_breakdown,
            live_hosts: context.live_subdomains.len(),
            saas_watchlist: context.cloud_saas.len(),
        };

        SocialIntelligenceSummary {
            framework_name: self.config.name.clone(),
            framework_version: self.config.version.clone(),
            framework_description: self.config.description.clone(),
            scenarios: scenarios.iter().map(|s| s.name.clone()).collect(),
            plans,
            signals,
            correlations,
            remediations,
            reports,
            metrics,
            guardrails: self
                .config
                .guardrails
                .iter()
                .map(|guardrail| guardrail.description.clone())
                .collect(),
            localization: self.localization_summary(),
        }
    }

    fn select_scenarios(&self, context: &SocialContext<'_>) -> Vec<ScenarioDescriptor> {
        let mut names: Vec<String> = Vec::new();

        if context
            .open_ports
            .values()
            .any(|ports| ports.contains(&6379))
        {
            names.push("redis_exploit".to_string());
        }

        if context.cloud_assets.values().any(|findings| {
            findings.iter().any(|finding| {
                finding.asset.contains("s3")
                    || finding.asset.contains("storage.googleapis.com")
                    || finding.asset.contains("blob.core.windows.net")
            })
        }) {
            names.push("s3_public_acl".to_string());
        }

        if context
            .takeover_risks
            .keys()
            .chain(context.cors_issues.keys())
            .any(|host| host.contains("login") || host.contains("auth"))
        {
            names.push("iam_mfa_fatigue".to_string());
        }

        if names.is_empty() {
            if let Some(default_scenario) = self.config.testing.scenarios.first() {
                names.push(default_scenario.name.clone());
            } else {
                names.push("shadowmap_social_watch".to_string());
            }
        }

        names.sort();
        names.dedup();

        names
            .into_iter()
            .map(|name| {
                let (topic, expected) = self
                    .config
                    .testing
                    .scenario_by_name(&name)
                    .map(|scenario| (scenario.topic.clone(), scenario.expected_output.clone()))
                    .unwrap_or_else(|| (name.replace('_', " "), Vec::new()));

                ScenarioDescriptor {
                    name,
                    topic,
                    expected_output: expected,
                }
            })
            .collect()
    }

    fn build_plan(
        &self,
        _index: usize,
        descriptor: &ScenarioDescriptor,
        profile: ScenarioProfile,
    ) -> PlannerOutcome {
        let intents = vec![
            "collect_signals".to_string(),
            "classify_risk".to_string(),
            "correlate_assets".to_string(),
            "propose_remediation".to_string(),
            "deliver_report".to_string(),
        ];

        let mut steps = Vec::new();
        let tools = self
            .config
            .tools
            .iter()
            .map(|tool| tool.name.clone())
            .collect::<Vec<_>>();
        let fallbacks = vec![
            "social_feed.fetch".to_string(),
            "nvd_cve.search".to_string(),
            "asset_graph.search".to_string(),
            "vuln_scan.query".to_string(),
            "cloud_cfg.check".to_string(),
            "notify.create".to_string(),
            "page.create".to_string(),
        ];

        let sequence = if tools.is_empty() { fallbacks } else { tools };

        for (step_index, tool) in sequence.iter().take(6).enumerate() {
            steps.push(PlannerStep {
                step: step_index + 1,
                tool: tool.clone(),
                rationale: format!(
                    "Apply {tool} to progress the {} pipeline for scenario '{}'",
                    descriptor.name.replace('_', " "),
                    descriptor.topic
                ),
            });
        }

        let confidence = (self.planner_confidence + profile.base_confidence).min(0.99);

        PlannerOutcome {
            scenario: descriptor.name.clone(),
            topic: descriptor.topic.clone(),
            intents,
            steps,
            confidence,
            expected_outputs: descriptor.expected_output.clone(),
        }
    }

    fn build_signal(
        &self,
        index: usize,
        descriptor: &ScenarioDescriptor,
        profile: ScenarioProfile,
        context: &SocialContext<'_>,
    ) -> SocialSignal {
        let regions = self
            .config
            .defaults
            .org_filters
            .as_ref()
            .map(|filters| filters.regions.clone())
            .unwrap_or_default();

        SocialSignal {
            signal_id: format!("SOC-{:03}", index + 1),
            scenario: descriptor.name.clone(),
            topic: descriptor.topic.clone(),
            severity: profile.severity.to_string(),
            confidence: profile.base_confidence,
            vendor_cloud: profile
                .vendor_cloud
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            services: profile.services.iter().map(|s| (*s).to_string()).collect(),
            regions,
            indicators: build_indicators(descriptor, context),
        }
    }

    fn build_correlation(
        &self,
        descriptor: &ScenarioDescriptor,
        profile: ScenarioProfile,
        context: &SocialContext<'_>,
    ) -> Option<SocialCorrelation> {
        let mut supporting = Vec::new();
        let asset_id = match descriptor.name.as_str() {
            "redis_exploit" => find_host_with_port(context, 6379).map(|host| {
                supporting.push(format!("Redis port 6379 open on {host}"));
                host
            }),
            "s3_public_acl" => find_cloud_asset(context, |asset| asset.contains("s3")),
            "iam_mfa_fatigue" => find_identity_surface(context),
            _ => Some(context.domain.to_string()),
        }?;

        if supporting.is_empty() {
            supporting.push("Matched contextual heuristics".to_string());
        }

        Some(SocialCorrelation {
            asset_id,
            reasons: vec![format!(
                "{} alignment with {} signal",
                profile.severity.to_uppercase(),
                descriptor.topic
            )],
            risk_score: profile.base_risk,
            supporting_findings: supporting,
        })
    }

    fn build_remediation(
        &self,
        descriptor: &ScenarioDescriptor,
        profile: ScenarioProfile,
        context: &SocialContext<'_>,
    ) -> RemediationPlaybook {
        let due_days = match profile.severity {
            "critical" => 1,
            "high" => 3,
            "medium" => 5,
            _ => 7,
        };

        let mut steps = vec![
            format!(
                "Validate intelligence context for '{}' against live telemetry",
                descriptor.topic
            ),
            format!(
                "Engage impacted service owners for {} to scope blast radius",
                context.domain
            ),
        ];

        steps.extend(
            self.config
                .defaults
                .controls_available
                .iter()
                .map(|control| {
                    format!(
                        "Apply {control} control set to mitigate {} exposure",
                        descriptor.name
                    )
                }),
        );

        let rollback = vec![
            "Document original control state and owners before execution".to_string(),
            "Use change window rollback procedure if user impact detected".to_string(),
        ];

        let verification = vec![
            "Re-run ShadowMap reconnaissance on affected assets".to_string(),
            "Confirm social feed silence for the scenario over 24h".to_string(),
        ];

        RemediationPlaybook {
            scenario: descriptor.name.clone(),
            title: format!("Stabilize {}", descriptor.topic),
            severity: profile.severity.to_string(),
            due_days,
            steps,
            rollback,
            verification,
        }
    }

    fn build_report_view(
        &self,
        descriptor: &ScenarioDescriptor,
        profile: ScenarioProfile,
        context: &SocialContext<'_>,
    ) -> SocialReportView {
        let live_scope = context.live_subdomains.len();
        let saas_scope = context.cloud_saas.len();
        let executive_brief = format!(
            "{} signal detected targeting {} — severity {} with {} guardrails active across {} live assets.",
            descriptor.topic,
            context.domain,
            profile.severity,
            self.config.guardrails.len(),
            live_scope
        );

        let engineer_brief = format!(
            "Scenario '{}': focus on {} services. Use {} change windows and controls ({}) for remediation across {} SaaS surfaces.",
            descriptor.topic,
            profile.services.join(", "),
            self
                .config
                .defaults
                .change_windows
                .first()
                .cloned()
                .unwrap_or_else(|| "standard".to_string()),
            self.config
                .defaults
                .controls_available
                .join(", "),
            saas_scope
        );

        SocialReportView {
            scenario: descriptor.name.clone(),
            executive_brief,
            engineer_brief,
        }
    }

    fn localization_summary(&self) -> LocalizationSummary {
        let localization = self.config.defaults.localization.as_ref();
        LocalizationSummary {
            primary_geo: localization.and_then(|loc| loc.geo.clone()),
            languages: localization
                .map(|loc| loc.languages.clone())
                .unwrap_or_default(),
            regions: self
                .config
                .defaults
                .org_filters
                .as_ref()
                .map(|filters| filters.regions.clone())
                .unwrap_or_default(),
            environments: self
                .config
                .defaults
                .org_filters
                .as_ref()
                .map(|filters| filters.env.clone())
                .unwrap_or_default(),
            controls_available: self.config.defaults.controls_available.clone(),
            change_windows: self.config.defaults.change_windows.clone(),
        }
    }
}

fn scenario_profile(name: &str) -> ScenarioProfile {
    match name {
        "redis_exploit" => ScenarioProfile {
            severity: "critical",
            vendor_cloud: &["aws", "gcp"],
            services: &["redis", "elasticache"],
            base_confidence: 0.86,
            base_risk: 0.9,
        },
        "s3_public_acl" => ScenarioProfile {
            severity: "high",
            vendor_cloud: &["aws"],
            services: &["s3", "object-storage"],
            base_confidence: 0.8,
            base_risk: 0.78,
        },
        "iam_mfa_fatigue" => ScenarioProfile {
            severity: "medium",
            vendor_cloud: &["aws"],
            services: &["iam", "signin"],
            base_confidence: 0.74,
            base_risk: 0.68,
        },
        _ => ScenarioProfile {
            severity: "medium",
            vendor_cloud: &["shadowmap"],
            services: &["monitoring"],
            base_confidence: 0.7,
            base_risk: 0.6,
        },
    }
}

fn build_indicators(descriptor: &ScenarioDescriptor, context: &SocialContext<'_>) -> Vec<String> {
    match descriptor.name.as_str() {
        "redis_exploit" => context
            .open_ports
            .iter()
            .filter(|(_, ports)| ports.contains(&6379))
            .map(|(host, _)| format!("Redis service exposed on {host}:6379"))
            .collect(),
        "s3_public_acl" => context
            .cloud_assets
            .iter()
            .flat_map(|(host, findings)| {
                findings
                    .iter()
                    .filter(|finding| finding.asset.contains("s3"))
                    .map(move |finding| format!("{} with asset {}", host, finding.asset))
            })
            .collect(),
        "iam_mfa_fatigue" => context
            .cors_issues
            .keys()
            .chain(context.takeover_risks.keys())
            .filter(|host| host.contains("login") || host.contains("auth"))
            .map(|host| format!("Authentication surface {} flagged in recon", host))
            .collect(),
        _ => Vec::new(),
    }
}

fn find_host_with_port(context: &SocialContext<'_>, port: u16) -> Option<String> {
    context
        .open_ports
        .iter()
        .find(|(_, ports)| ports.contains(&port))
        .map(|(host, _)| host.clone())
}

fn find_cloud_asset<F>(context: &SocialContext<'_>, predicate: F) -> Option<String>
where
    F: Fn(&str) -> bool,
{
    for (host, findings) in context.cloud_assets.iter() {
        for finding in findings {
            if predicate(&finding.asset) {
                return Some(host.clone());
            }
        }
    }
    None
}

fn find_identity_surface(context: &SocialContext<'_>) -> Option<String> {
    context
        .cors_issues
        .keys()
        .chain(context.takeover_risks.keys())
        .find(|host| host.contains("login") || host.contains("auth"))
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud::{CloudAssetFinding, CloudAssetStatus};
    use std::iter::FromIterator;
    use std::path::Path;

    fn base_context() -> SocialContext<'static> {
        static DOMAIN: &str = "example.com";
        let live = HashSet::from_iter(["api.example.com".to_string()]);
        let open_ports = HashMap::from_iter([("api.example.com".to_string(), vec![80, 443, 6379])]);
        let cors = HashMap::new();
        let takeover = HashMap::new();
        let cloud_saas = HashMap::new();
        let cloud_assets = HashMap::new();
        SocialContext {
            domain: DOMAIN,
            live_subdomains: Box::leak(Box::new(live)),
            open_ports: Box::leak(Box::new(open_ports)),
            cors_issues: Box::leak(Box::new(cors)),
            takeover_risks: Box::leak(Box::new(takeover)),
            cloud_saas: Box::leak(Box::new(cloud_saas)),
            cloud_assets: Box::leak(Box::new(cloud_assets)),
        }
    }

    #[test]
    fn parses_embedded_config_and_generates_signal() {
        let engine = SocialIntelligenceEngine::from_embedded().expect("config");
        let context = base_context();
        let summary = engine.analyze(&context);
        assert_eq!(summary.framework_version, "1.0");
        assert!(summary.metrics.total_signals >= 1);
        assert!(summary
            .signals
            .iter()
            .any(|signal| signal.scenario == "redis_exploit"));
    }

    #[test]
    fn surfaces_s3_scenario_when_asset_present() {
        let engine = SocialIntelligenceEngine::from_embedded().expect("config");
        let mut context = base_context();
        let mut assets = HashMap::new();
        assets.insert(
            "assets.example.com".to_string(),
            vec![CloudAssetFinding {
                provider: "aws".to_string(),
                asset: "https://example-bucket.s3.amazonaws.com".to_string(),
                status: CloudAssetStatus::Accessible,
                notes: None,
            }],
        );
        context.cloud_assets = Box::leak(Box::new(assets));
        let summary = engine.analyze(&context);
        assert!(summary
            .signals
            .iter()
            .any(|signal| signal.scenario == "s3_public_acl"));
        assert!(summary
            .correlations
            .iter()
            .any(|correlation| correlation.asset_id == "assets.example.com"));
    }

    #[test]
    fn loads_config_from_path() {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let config_path = manifest.join("configs/social-intelligence.yaml");
        let engine = SocialIntelligenceEngine::from_path(&config_path).expect("config file");
        let summary = engine.analyze(&base_context()).framework_name;
        assert_eq!(summary, "ShadowMap Codex Intelligence Framework");
    }
}
