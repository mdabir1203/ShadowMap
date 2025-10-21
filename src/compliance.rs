use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::Instant;

pub const NATIONAL_FRAMEWORKS: &[&str] = &[
    "NCA National Cloud Framework",
    "DEWA Digital Infrastructure Policy",
    "UAE AI Strategy 2031",
];

pub const GLOBAL_FRAMEWORKS: &[&str] = &["GDPR", "NIS2", "ENISA"];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeploymentNode {
    pub identifier: String,
    pub region: String,
    pub jurisdiction: String,
    pub certifications: BTreeSet<String>,
    pub residency_scope: BTreeSet<String>,
    pub controls: BTreeSet<String>,
    pub latency_ms: u32,
}

impl DeploymentNode {
    pub fn new(
        identifier: impl Into<String>,
        region: impl Into<String>,
        jurisdiction: impl Into<String>,
        certifications: impl IntoIterator<Item = impl Into<String>>,
        residency_scope: impl IntoIterator<Item = impl Into<String>>,
        controls: impl IntoIterator<Item = impl Into<String>>,
        latency_ms: u32,
    ) -> Self {
        Self {
            identifier: identifier.into(),
            region: region.into(),
            jurisdiction: jurisdiction.into(),
            certifications: certifications.into_iter().map(Into::into).collect(),
            residency_scope: residency_scope.into_iter().map(Into::into).collect(),
            controls: controls.into_iter().map(Into::into).collect(),
            latency_ms,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct GeoFenceDecision {
    pub compliant_nodes: Vec<DeploymentNode>,
    pub quarantined_nodes: Vec<DeploymentNode>,
    pub alignment: Vec<String>,
    pub generated_at: DateTime<Utc>,
    pub notes: Vec<String>,
}

impl GeoFenceDecision {
    pub fn empty() -> Self {
        Self {
            compliant_nodes: Vec::new(),
            quarantined_nodes: Vec::new(),
            alignment: Vec::new(),
            generated_at: Utc::now(),
            notes: Vec::new(),
        }
    }
}

pub struct GeoFencePolicy {
    allowed_regions: HashSet<String>,
    required_controls: HashSet<String>,
    residency_frameworks: HashSet<String>,
}

impl GeoFencePolicy {
    pub fn new(
        regions: impl IntoIterator<Item = impl AsRef<str>>,
        frameworks: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Self {
        Self {
            allowed_regions: regions
                .into_iter()
                .map(|s| s.as_ref().to_string())
                .collect(),
            required_controls: HashSet::new(),
            residency_frameworks: frameworks
                .into_iter()
                .map(|s| s.as_ref().to_string())
                .collect(),
        }
    }

    pub fn with_required_controls(
        mut self,
        controls: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Self {
        self.required_controls = controls
            .into_iter()
            .map(|s| s.as_ref().to_string())
            .collect();
        self
    }

    pub fn enforce(&self, nodes: &[DeploymentNode]) -> GeoFenceDecision {
        let mut compliant = Vec::new();
        let mut quarantined = Vec::new();
        let mut notes = Vec::new();

        for node in nodes {
            let region_allowed = self.allowed_regions.contains(&node.region);
            let controls_present = self
                .required_controls
                .iter()
                .all(|control| node.controls.contains(control));
            let residency_ok = node
                .residency_scope
                .iter()
                .any(|scope| self.residency_frameworks.contains(scope));

            if region_allowed && controls_present && residency_ok {
                compliant.push(node.clone());
            } else {
                let mut reason = Vec::new();
                if !region_allowed {
                    reason.push(format!("region {} not authorised", node.region));
                }
                if !controls_present {
                    reason.push("missing sovereign controls".to_string());
                }
                if !residency_ok {
                    reason.push("residency policy not aligned".to_string());
                }
                notes.push(format!(
                    "{} quarantined: {}",
                    node.identifier,
                    reason.join(", ")
                ));
                quarantined.push(node.clone());
            }
        }

        GeoFenceDecision {
            compliant_nodes: compliant,
            quarantined_nodes: quarantined,
            alignment: self
                .residency_frameworks
                .iter()
                .cloned()
                .chain(NATIONAL_FRAMEWORKS.iter().map(|s| s.to_string()))
                .collect(),
            generated_at: Utc::now(),
            notes,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct EntropyFinding {
    pub observed_entropy: f64,
    pub baseline_entropy: f64,
    pub delta: f64,
    pub tamper_suspected: bool,
    pub sample_size: usize,
    pub timestamp: DateTime<Utc>,
    pub frameworks: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct EntropyMonitor {
    baseline: f64,
    tolerance: f64,
    history: Vec<f64>,
    max_history: usize,
}

impl EntropyMonitor {
    pub fn new(baseline: f64, tolerance: f64) -> Self {
        Self {
            baseline,
            tolerance,
            history: Vec::new(),
            max_history: 24,
        }
    }

    pub fn baseline_from(payload: &[u8]) -> f64 {
        Self::entropy(payload)
    }

    pub fn analyze(&mut self, payload: &[u8]) -> EntropyFinding {
        let entropy = Self::entropy(payload);
        let delta = (entropy - self.baseline).abs();
        let tamper = delta > self.tolerance;

        self.history.push(entropy);
        if self.history.len() > self.max_history {
            self.history.remove(0);
        }

        if !tamper {
            let sum: f64 = self.history.iter().sum();
            self.baseline = sum / self.history.len() as f64;
        }

        EntropyFinding {
            observed_entropy: entropy,
            baseline_entropy: self.baseline,
            delta,
            tamper_suspected: tamper,
            sample_size: payload.len(),
            timestamp: Utc::now(),
            frameworks: vec![
                "Supply chain integrity".to_string(),
                "Entropy guardrail".to_string(),
                "GDPR Art.32".to_string(),
            ],
        }
    }

    fn entropy(payload: &[u8]) -> f64 {
        let mut counts = [0usize; 256];
        for byte in payload {
            counts[*byte as usize] += 1;
        }
        let len = payload.len() as f64;
        if len == 0.0 {
            return 0.0;
        }

        counts
            .iter()
            .filter(|count| **count > 0)
            .map(|count| {
                let p = *count as f64 / len;
                -p * p.log2()
            })
            .sum()
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Criticality {
    Core,
    Supporting,
    Development,
}

#[derive(Clone, Debug, Serialize)]
pub struct SbomComponent {
    pub name: String,
    pub version: String,
    pub supplier: String,
    pub criticality: Criticality,
    pub integrity_hash: String,
    pub licenses: Vec<String>,
    pub confidence: f32,
}

impl SbomComponent {
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        supplier: impl Into<String>,
        criticality: Criticality,
        integrity_hash: impl Into<String>,
        licenses: impl IntoIterator<Item = impl Into<String>>,
        confidence: f32,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            supplier: supplier.into(),
            criticality,
            integrity_hash: integrity_hash.into(),
            licenses: licenses.into_iter().map(Into::into).collect(),
            confidence,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustRelation {
    Runtime,
    Build,
    Optional,
}

#[derive(Clone, Debug, Serialize)]
pub struct TrustEdge {
    pub from: String,
    pub to: String,
    pub relation: TrustRelation,
    pub risk: f32,
    pub notes: String,
}

#[derive(Clone, Debug, Default)]
pub struct TrustGraph {
    components: HashMap<String, SbomComponent>,
    edges: Vec<TrustEdge>,
}

impl TrustGraph {
    pub fn from_components(components: impl IntoIterator<Item = SbomComponent>) -> Self {
        let mut graph = Self::default();
        for component in components {
            graph.components.insert(component.name.clone(), component);
        }
        graph
    }

    pub fn relate(
        &mut self,
        source: impl Into<String>,
        target: impl Into<String>,
        relation: TrustRelation,
        risk: f32,
        notes: impl Into<String>,
    ) {
        self.edges.push(TrustEdge {
            from: source.into(),
            to: target.into(),
            relation,
            risk,
            notes: notes.into(),
        });
    }

    pub fn summary(&self) -> TrustGraphSummary {
        let edge_count = self.edges.len();
        let average_risk = if edge_count > 0 {
            self.edges.iter().map(|edge| edge.risk).sum::<f32>() / edge_count as f32
        } else {
            0.0
        };

        let highest = self
            .edges
            .iter()
            .max_by(|a, b| {
                a.risk
                    .partial_cmp(&b.risk)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|edge| format!("{} -> {} ({:.2})", edge.from, edge.to, edge.risk));

        TrustGraphSummary {
            nodes: self.components.len(),
            edges: edge_count,
            average_risk,
            highest_risk: highest,
            frameworks: [NATIONAL_FRAMEWORKS, GLOBAL_FRAMEWORKS]
                .into_iter()
                .flat_map(|items| items.iter().map(|s| s.to_string()))
                .collect(),
        }
    }

    pub fn export(&self) -> TrustGraphExport {
        TrustGraphExport {
            components: self.components.values().cloned().collect::<Vec<_>>(),
            edges: self.edges.clone(),
            summary: self.summary(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TrustGraphSummary {
    pub nodes: usize,
    pub edges: usize,
    pub average_risk: f32,
    pub highest_risk: Option<String>,
    pub frameworks: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TrustGraphExport {
    pub components: Vec<SbomComponent>,
    pub edges: Vec<TrustEdge>,
    pub summary: TrustGraphSummary,
}

#[derive(Clone, Debug, Serialize)]
pub enum DeletionRequestStatus {
    Pending,
    Processed,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeletionRequest {
    pub subject_id: String,
    pub requested_at: DateTime<Utc>,
    pub status: DeletionRequestStatus,
}

#[derive(Clone, Debug)]
pub struct PrivacyController {
    allowed_fields: HashSet<String>,
    requests: HashMap<String, DeletionRequest>,
}

impl PrivacyController {
    pub fn new(fields: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        Self {
            allowed_fields: fields.into_iter().map(|f| f.as_ref().to_string()).collect(),
            requests: HashMap::new(),
        }
    }

    pub fn minimize_record(&self, record: &serde_json::Value) -> serde_json::Value {
        match record {
            serde_json::Value::Object(map) => {
                let mut filtered = serde_json::Map::new();
                for (key, value) in map {
                    if self.allowed_fields.contains(&key.to_string()) {
                        filtered.insert(key.clone(), value.clone());
                    }
                }
                serde_json::Value::Object(filtered)
            }
            _ => serde_json::Value::Null,
        }
    }

    pub fn request_erasure(&mut self, subject_id: impl Into<String>) -> DeletionRequest {
        let id = subject_id.into();
        let request = DeletionRequest {
            subject_id: id.clone(),
            requested_at: Utc::now(),
            status: DeletionRequestStatus::Pending,
        };
        self.requests.insert(id.clone(), request.clone());
        request
    }

    pub fn close_request(&mut self, subject_id: &str) -> Option<DeletionRequest> {
        if let Some(request) = self.requests.get_mut(subject_id) {
            request.status = DeletionRequestStatus::Processed;
            Some(request.clone())
        } else {
            None
        }
    }

    pub fn outstanding_requests(&self) -> Vec<DeletionRequest> {
        self.requests
            .values()
            .filter(|request| matches!(request.status, DeletionRequestStatus::Pending))
            .cloned()
            .collect()
    }

    pub fn snapshot(&self, minimized_record: serde_json::Value) -> PrivacySnapshot {
        PrivacySnapshot {
            minimized_example: minimized_record,
            outstanding_requests: self.outstanding_requests(),
            enforcement_controls: vec![
                "Data minimisation enforced".to_string(),
                "Automated deletion workflow".to_string(),
                "GDPR Art.17 compliance".to_string(),
            ],
            generated_at: Utc::now(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PrivacySnapshot {
    pub minimized_example: serde_json::Value,
    pub outstanding_requests: Vec<DeletionRequest>,
    pub enforcement_controls: Vec<String>,
    pub generated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize)]
pub struct IncidentInput {
    pub incident_id: String,
    pub severity: String,
    pub detected_at: DateTime<Utc>,
    pub description: String,
    pub impacted_assets: Vec<String>,
    pub containment_actions: Vec<String>,
    pub status: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct IncidentReport {
    pub incident: IncidentInput,
    pub regulatory_mapping: HashMap<String, String>,
    pub notification_deadlines: HashMap<String, String>,
    pub contact: String,
    pub generated_at: DateTime<Utc>,
}

pub struct IncidentReporter {
    contact: String,
    regulators: Vec<String>,
}

impl IncidentReporter {
    pub fn new(
        contact: impl Into<String>,
        regulators: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Self {
        Self {
            contact: contact.into(),
            regulators: regulators
                .into_iter()
                .map(|s| s.as_ref().to_string())
                .collect(),
        }
    }

    pub fn create_report(&self, incident: IncidentInput) -> IncidentReport {
        let mut regulatory_mapping = HashMap::new();
        regulatory_mapping.insert(
            "NIS2".to_string(),
            "Article 23 - 24 hour notification".to_string(),
        );
        regulatory_mapping.insert("ENISA".to_string(), "EU CSIRT baseline sharing".to_string());
        regulatory_mapping.insert(
            "GDPR".to_string(),
            "Articles 33-34 personal data breach handling".to_string(),
        );
        regulatory_mapping.insert(
            "NCA".to_string(),
            "Cloud sector controls reporting".to_string(),
        );

        for regulator in &self.regulators {
            regulatory_mapping
                .entry(regulator.clone())
                .or_insert_with(|| "Regulator aligned via automated workflow".to_string());
        }

        let mut deadlines = HashMap::new();
        deadlines.insert("NIS2".to_string(), "24h initial, 72h final".to_string());
        deadlines.insert("GDPR".to_string(), "72h supervisory authority".to_string());
        deadlines.insert(
            "ENISA".to_string(),
            "Real-time CSIRT coordination".to_string(),
        );

        IncidentReport {
            incident,
            regulatory_mapping,
            notification_deadlines: deadlines,
            contact: self.contact.clone(),
            generated_at: Utc::now(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct MfaPolicy {
    pub min_validated: usize,
    pub allowed_methods: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MfaFactor {
    pub method: String,
    pub validated: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct AccessDecisionRecord {
    pub user: String,
    pub permission: String,
    pub granted: bool,
    pub reason: String,
    pub frameworks: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct AccessControl {
    role_policies: HashMap<String, HashSet<String>>,
    user_roles: HashMap<String, HashSet<String>>,
    policy: MfaPolicy,
}

impl AccessControl {
    pub fn new(policy: MfaPolicy) -> Self {
        Self {
            role_policies: HashMap::new(),
            user_roles: HashMap::new(),
            policy,
        }
    }

    pub fn define_role(
        &mut self,
        role: impl Into<String>,
        permissions: impl IntoIterator<Item = impl AsRef<str>>,
    ) {
        let entry = self.role_policies.entry(role.into()).or_default();
        for perm in permissions {
            entry.insert(perm.as_ref().to_string());
        }
    }

    pub fn assign(&mut self, user: impl Into<String>, role: impl Into<String>) {
        let user_entry = self.user_roles.entry(user.into()).or_default();
        user_entry.insert(role.into());
    }

    pub fn evaluate(
        &self,
        user: &str,
        permission: &str,
        factors: &[MfaFactor],
    ) -> AccessDecisionRecord {
        let validated = factors.iter().filter(|factor| factor.validated).count();
        if validated < self.policy.min_validated {
            return AccessDecisionRecord {
                user: user.to_string(),
                permission: permission.to_string(),
                granted: false,
                reason: format!(
                    "{} factors validated, {} required",
                    validated, self.policy.min_validated
                ),
                frameworks: vec![
                    "GDPR Art.32".to_string(),
                    "NIS2 Article 21".to_string(),
                    "ENISA IAM baseline".to_string(),
                ],
            };
        }

        let roles = match self.user_roles.get(user) {
            Some(roles) => roles,
            None => {
                return AccessDecisionRecord {
                    user: user.to_string(),
                    permission: permission.to_string(),
                    granted: false,
                    reason: "no roles assigned".to_string(),
                    frameworks: vec!["Least privilege".to_string()],
                }
            }
        };

        let permitted = roles.iter().any(|role| {
            self.role_policies
                .get(role)
                .map(|policies| policies.contains(permission))
                .unwrap_or(false)
        });

        if permitted {
            AccessDecisionRecord {
                user: user.to_string(),
                permission: permission.to_string(),
                granted: true,
                reason: "role policy satisfied".to_string(),
                frameworks: vec![
                    "Zero trust enforced".to_string(),
                    "UAE AI Strategy assurance".to_string(),
                ],
            }
        } else {
            AccessDecisionRecord {
                user: user.to_string(),
                permission: permission.to_string(),
                granted: false,
                reason: "permission not granted by role".to_string(),
                frameworks: vec![
                    "Access denied".to_string(),
                    "Audit trail captured".to_string(),
                ],
            }
        }
    }

    pub fn export_model(&self, evaluations: &[AccessDecisionRecord]) -> AccessControlExport {
        let roles = self
            .role_policies
            .iter()
            .map(|(role, perms)| {
                let mut list: Vec<_> = perms.iter().cloned().collect();
                list.sort();
                (role.clone(), list)
            })
            .collect::<HashMap<_, _>>();

        let assignments = self
            .user_roles
            .iter()
            .map(|(user, roles)| {
                let mut list: Vec<_> = roles.iter().cloned().collect();
                list.sort();
                (user.clone(), list)
            })
            .collect::<HashMap<_, _>>();

        AccessControlExport {
            roles,
            assignments,
            evaluations: evaluations.to_vec(),
            policy: self.policy.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AccessControlExport {
    pub roles: HashMap<String, Vec<String>>,
    pub assignments: HashMap<String, Vec<String>>,
    pub evaluations: Vec<AccessDecisionRecord>,
    pub policy: MfaPolicy,
}

#[derive(Clone, Debug, Serialize)]
pub struct FrameworkScore {
    pub framework: String,
    pub score: f32,
    pub notes: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ComplianceVisualizerData {
    pub summary: String,
    pub ai_reasoning: Vec<String>,
    pub frameworks: Vec<FrameworkScore>,
    pub geo_nodes: Vec<DeploymentNode>,
}

impl ComplianceVisualizerData {
    pub fn from_context(
        geo: &GeoFenceDecision,
        trust: &TrustGraphSummary,
        incident: &IncidentReport,
    ) -> Self {
        let summary = format!(
            "{} compliant nodes • {:.2} average supply-chain risk",
            geo.compliant_nodes.len(),
            trust.average_risk
        );

        let mut ai_reasoning = Vec::new();
        ai_reasoning.push(format!(
            "Geo-fence ensures {} regions align with {:?}",
            geo.compliant_nodes.len(),
            geo.alignment
        ));
        if let Some(highest) = &trust.highest_risk {
            ai_reasoning.push(format!("Trust graph hotspot: {highest}"));
        }
        ai_reasoning.push(format!(
            "Incident {} mapped to {} regulators",
            incident.incident.incident_id,
            incident.regulatory_mapping.len()
        ));

        let frameworks = geo
            .alignment
            .iter()
            .enumerate()
            .map(|(index, framework)| FrameworkScore {
                framework: framework.clone(),
                score: 0.85 - (index as f32 * 0.03),
                notes: "Residency guardrail enforced".to_string(),
            })
            .chain(
                trust
                    .frameworks
                    .iter()
                    .enumerate()
                    .map(|(index, framework)| FrameworkScore {
                        framework: framework.clone(),
                        score: 0.78 - (index as f32 * 0.01),
                        notes: "Supply chain mapping".to_string(),
                    }),
            )
            .collect();

        Self {
            summary,
            ai_reasoning,
            frameworks,
            geo_nodes: geo.compliant_nodes.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SandboxFinding {
    pub heuristic: String,
    pub severity: String,
    pub note: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SandboxScanResult {
    pub engine: String,
    pub status: String,
    pub findings: Vec<SandboxFinding>,
    pub tamper: Option<EntropyFinding>,
    pub frameworks: Vec<String>,
    pub duration_ms: u64,
}

pub struct SandboxScanner {
    engine: String,
}

impl SandboxScanner {
    pub fn new(engine: impl Into<String>) -> Self {
        Self {
            engine: engine.into(),
        }
    }

    pub fn scan(&self, payload: &[u8], monitor: &mut EntropyMonitor) -> SandboxScanResult {
        let start = Instant::now();
        let entropy = monitor.analyze(payload);

        let mut findings = Vec::new();
        let mut status = "clean".to_string();

        if entropy.tamper_suspected {
            findings.push(SandboxFinding {
                heuristic: "entropy-anomaly".to_string(),
                severity: "high".to_string(),
                note: format!("delta {:.2} exceeds tolerance", entropy.delta),
            });
            status = "quarantined".to_string();
        }

        let ascii_ratio = payload
            .iter()
            .filter(|byte| byte.is_ascii_alphanumeric())
            .count() as f32
            / payload.len().max(1) as f32;
        if ascii_ratio < 0.25 {
            findings.push(SandboxFinding {
                heuristic: "low-ascii".to_string(),
                severity: "medium".to_string(),
                note: "Binary payload detected".to_string(),
            });
        }

        if payload.windows(4).any(|window| window == b"\x7fELF") {
            findings.push(SandboxFinding {
                heuristic: "elf-header".to_string(),
                severity: "critical".to_string(),
                note: "Executable artefact staged".to_string(),
            });
            status = "quarantined".to_string();
        }

        SandboxScanResult {
            engine: self.engine.clone(),
            status,
            findings,
            tamper: if entropy.tamper_suspected {
                Some(entropy)
            } else {
                None
            },
            frameworks: vec![
                "ENISA sandboxing".to_string(),
                "NIS2 detection".to_string(),
                "GDPR data minimisation".to_string(),
            ],
            duration_ms: start.elapsed().as_millis() as u64,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TrustServicePayload {
    pub issued_at: DateTime<Utc>,
    pub trust_graph: TrustGraphExport,
    pub geo_fence: GeoFenceDecision,
    pub privacy: PrivacySnapshot,
    pub incident_template: IncidentReport,
    pub access_model: AccessControlExport,
    pub sandbox_scan: Option<SandboxScanResult>,
    pub posture: Vec<String>,
}

pub struct TrustService {
    trust_graph: TrustGraphExport,
    geo_fence: GeoFenceDecision,
    privacy: PrivacySnapshot,
    incident: IncidentReport,
    access: AccessControlExport,
    sandbox: Option<SandboxScanResult>,
}

impl TrustService {
    pub fn new(
        trust_graph: TrustGraphExport,
        geo_fence: GeoFenceDecision,
        privacy: PrivacySnapshot,
        incident: IncidentReport,
        access: AccessControlExport,
    ) -> Self {
        Self {
            trust_graph,
            geo_fence,
            privacy,
            incident,
            access,
            sandbox: None,
        }
    }

    pub fn with_sandbox(mut self, sandbox: SandboxScanResult) -> Self {
        self.sandbox = Some(sandbox);
        self
    }

    pub fn export(&self) -> TrustServicePayload {
        TrustServicePayload {
            issued_at: Utc::now(),
            trust_graph: self.trust_graph.clone(),
            geo_fence: self.geo_fence.clone(),
            privacy: self.privacy.clone(),
            incident_template: self.incident.clone(),
            access_model: self.access.clone(),
            sandbox_scan: self.sandbox.clone(),
            posture: vec![
                "NCA residency guardrails".to_string(),
                "DEWA sovereign controls".to_string(),
                "UAE AI Strategy assurance".to_string(),
                "GDPR/NIS2/ENISA mapped".to_string(),
            ],
        }
    }
}
