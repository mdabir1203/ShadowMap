#![cfg(feature = "dashboard")]

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering as AtomicOrdering},
    Arc, Mutex,
};
use std::thread;

use chrono::Local;
use shadowmap::passkeys::{PasskeyAuthenticator, PasskeyLogin, PasskeyMetadata};
use shadowmap::{
    generate_compliance_outputs, Args, AutonomousReconAgent, ReconEngine, ReconReport,
};
use slint::{Brush, Color, ModelRc, SharedString, VecModel};
use tokio::runtime::Builder;

slint::include_modules!();

pub fn main() -> Result<(), slint::PlatformError> {
    let ui = Dashboard::new()?;
    initialize_demo_state(&ui);
    ui.set_report_available(false);
    ui.set_authenticated(false);
    ui.set_auth_in_progress(false);
    ui.set_passkey_ready(false);
    ui.set_auth_status(SharedString::from(
        "Authenticate with your passkey to unlock live reconnaissance tooling.",
    ));
    ui.set_passkey_label(SharedString::from("Verify local passkey"));

    let passkey_controller = Arc::new(PasskeyController::new());
    ui.set_passkey_ready(passkey_controller.is_ready());
    if let Some(meta) = passkey_controller.metadata() {
        let display_name = passkey_display_name(&meta);
        let created = meta
            .created_at
            .with_timezone(&Local)
            .format("%Y-%m-%d %H:%M:%S");
        ui.set_passkey_label(SharedString::from(format!("Verify {display_name}")));
        ui.set_auth_status(SharedString::from(format!(
            "{display_name} provisioned on {created}. Authenticate to continue.",
        )));
    } else if let Some(err) = passkey_controller.last_error() {
        ui.set_auth_status(SharedString::from(format!(
            "Passkey initialization failed: {err}. Configure configs/passkeys.json and retry.",
        )));
        ui.set_status_text(SharedString::from(
            "Passkey setup required before launching ShadowMap scans.",
        ));
        ui.set_status_color(Brush::from(Color::from_rgb_u8(255, 122, 142)));
    }

    let last_report: Arc<Mutex<Option<Arc<ReconReport>>>> = Arc::new(Mutex::new(None));
    let weak = ui.as_weak();
    let scan_report_state = last_report.clone();
    let weak_for_scan = weak.clone();
    let passkey_for_scan = passkey_controller.clone();

    ui.on_start_scan(move |domain| {
        let domain = domain.trim().to_string();
        let weak_for_callback = weak_for_scan.clone();
        let report_state = scan_report_state.clone();
        let passkey_state = passkey_for_scan.clone();

        if !passkey_state.is_ready() {
            if let Some(ui) = weak_for_callback.upgrade() {
                ui.set_status_text(SharedString::from(
                    "Configure a passkey before launching scans.",
                ));
                ui.set_status_color(Brush::from(Color::from_rgb_u8(255, 122, 142)));
            }
            return;
        }

        if !passkey_state.is_authenticated() {
            if let Some(ui) = weak_for_callback.upgrade() {
                ui.set_status_text(SharedString::from(
                    "Authenticate with your passkey before launching scans.",
                ));
                ui.set_status_color(Brush::from(Color::from_rgb_u8(255, 210, 120)));
            }
            return;
        }

        if domain.is_empty() {
            if let Some(ui) = weak_for_callback.upgrade() {
                ui.set_status_text(SharedString::from("Enter a domain to start scanning."));
                ui.set_status_color(Brush::from(Color::from_rgb_u8(255, 122, 142)));
            }
            return;
        }

        if let Some(ui) = weak_for_callback.upgrade() {
            ui.set_status_text(SharedString::from(format!("Scanning {domain}...")));
            ui.set_status_color(Brush::from(Color::from_rgb_u8(120, 190, 255)));
            ui.set_scan_in_progress(true);
            ui.set_scan_progress(0.12);
            ui.set_report_available(false);
        }

        {
            let mut guard = report_state.lock().unwrap_or_else(|err| err.into_inner());
            *guard = None;
        }

        let weak_for_thread = weak_for_scan.clone();
        let report_state_for_thread = scan_report_state.clone();
        thread::spawn(move || {
            let result = perform_scan(domain.clone());
            match result {
                Ok(report) => {
                    let report_arc = Arc::new(report);
                    {
                        let mut guard = report_state_for_thread
                            .lock()
                            .unwrap_or_else(|err| err.into_inner());
                        *guard = Some(report_arc.clone());
                    }
                    let summary = DashboardSummary::from_report(report_arc.as_ref());
                    let weak_ui = weak_for_thread.clone();
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak_ui.upgrade() {
                            apply_summary(&ui, summary);
                            ui.set_report_available(true);
                        }
                    })
                    .expect("failed to update UI with scan results");
                }
                Err(err) => {
                    let message = format!("Scan failed: {err}");
                    let weak_ui = weak_for_thread.clone();
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak_ui.upgrade() {
                            ui.set_status_text(SharedString::from(message));
                            ui.set_status_color(Brush::from(Color::from_rgb_u8(255, 122, 142)));
                            ui.set_scan_in_progress(false);
                            ui.set_scan_progress(0.0);
                            ui.set_report_available(false);
                        }
                    })
                    .expect("failed to update UI with error state");
                }
            }
        });
    });

    let weak_for_auth = weak.clone();
    let passkey_for_auth = passkey_controller.clone();
    ui.on_request_passkey(move || {
        let controller = passkey_for_auth.clone();
        if !controller.is_ready() {
            if let Some(ui) = weak_for_auth.upgrade() {
                ui.set_auth_status(SharedString::from(
                    "No passkey configured. Edit configs/passkeys.json to provision one.",
                ));
                ui.set_passkey_ready(false);
                ui.set_status_text(SharedString::from(
                    "Passkey setup required before launching ShadowMap scans.",
                ));
                ui.set_status_color(Brush::from(Color::from_rgb_u8(255, 122, 142)));
            }
            return;
        }

        if let Some(ui) = weak_for_auth.upgrade() {
            ui.set_auth_in_progress(true);
            ui.set_auth_status(SharedString::from(
                "Waiting for passkey confirmation. Complete the system prompt.",
            ));
        }

        let weak_after = weak_for_auth.clone();
        thread::spawn(move || {
            let outcome = controller.authenticate();
            slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak_after.upgrade() {
                    ui.set_auth_in_progress(false);
                    match outcome {
                        Ok(login) => {
                            let display_name = passkey_login_display_name(&login);
                            let verified_at = login
                                .authenticated_at
                                .with_timezone(&Local)
                                .format("%Y-%m-%d %H:%M:%S");
                            ui.set_authenticated(true);
                            ui.set_passkey_ready(true);
                            ui.set_passkey_label(SharedString::from(format!(
                                "{display_name} verified",
                            )));
                            ui.set_auth_status(SharedString::from(format!(
                                "{display_name} verified at {verified_at}.",
                            )));
                            ui.set_status_text(SharedString::from(
                                "Passkey verified. Ready to launch scans.",
                            ));
                            ui.set_status_color(Brush::from(Color::from_rgb_u8(140, 225, 180)));
                        }
                        Err(err) => {
                            let message = SharedString::from(err.clone());
                            ui.set_auth_status(message);
                            ui.set_status_text(SharedString::from(format!(
                                "Passkey authentication failed: {err}",
                            )));
                            ui.set_status_color(Brush::from(Color::from_rgb_u8(255, 122, 142)));
                        }
                    }
                }
            })
            .expect("failed to update UI after passkey authentication");
        });
    });

    let weak_for_download = weak.clone();
    let download_report_state = last_report.clone();
    ui.on_download_compliance_report(move || {
        let weak_now = weak_for_download.clone();
        let maybe_report = {
            download_report_state
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .clone()
        };

        if let Some(report) = maybe_report {
            let report_clone = report.clone();
            let weak_for_thread = weak_now.clone();
            thread::spawn(move || {
                let result = generate_compliance_package(report_clone.as_ref());
                slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak_for_thread.upgrade() {
                        match result {
                            Ok(path) => {
                                ui.set_status_text(SharedString::from(format!(
                                    "Compliance package saved to {path}"
                                )));
                                ui.set_status_color(Brush::from(Color::from_rgb_u8(140, 225, 180)));
                            }
                            Err(err) => {
                                ui.set_status_text(SharedString::from(err));
                                ui.set_status_color(Brush::from(Color::from_rgb_u8(255, 122, 142)));
                                ui.set_report_available(false);
                            }
                        }
                    }
                })
                .expect("failed to update UI after compliance export");
            });
        } else if let Some(ui) = weak_now.upgrade() {
            ui.set_status_text(SharedString::from(
                "Run a scan to export the compliance package.",
            ));
            ui.set_status_color(Brush::from(Color::from_rgb_u8(255, 210, 120)));
        }
    });

    ui.run()
}

fn initialize_demo_state(ui: &Dashboard) {
    let summary = DashboardSummary::demo();
    apply_summary(ui, summary);
}

struct PasskeyController {
    authenticator: Option<PasskeyAuthenticator>,
    authenticated: AtomicBool,
    error: Mutex<Option<String>>,
}

impl PasskeyController {
    fn new() -> Self {
        match PasskeyAuthenticator::open_default() {
            Ok(authenticator) => Self {
                authenticator: Some(authenticator),
                authenticated: AtomicBool::new(false),
                error: Mutex::new(None),
            },
            Err(err) => Self {
                authenticator: None,
                authenticated: AtomicBool::new(false),
                error: Mutex::new(Some(err.to_string())),
            },
        }
    }

    fn is_ready(&self) -> bool {
        self.authenticator.is_some()
    }

    fn metadata(&self) -> Option<PasskeyMetadata> {
        self.authenticator
            .as_ref()
            .and_then(|auth| auth.primary_passkey())
    }

    fn authenticate(&self) -> Result<PasskeyLogin, String> {
        let Some(authenticator) = self.authenticator.as_ref() else {
            return Err(self
                .last_error()
                .unwrap_or_else(|| "Passkey authenticator unavailable".to_string()));
        };

        match authenticator.authenticate_with_local() {
            Ok(login) => {
                self.authenticated.store(true, AtomicOrdering::SeqCst);
                if let Ok(mut guard) = self.error.lock() {
                    *guard = None;
                }
                Ok(login)
            }
            Err(err) => {
                let message = err.to_string();
                if let Ok(mut guard) = self.error.lock() {
                    *guard = Some(message.clone());
                }
                Err(message)
            }
        }
    }

    fn is_authenticated(&self) -> bool {
        self.authenticated.load(AtomicOrdering::SeqCst)
    }

    fn last_error(&self) -> Option<String> {
        match self.error.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => None,
        }
    }
}

fn passkey_display_name(meta: &PasskeyMetadata) -> String {
    meta.label
        .clone()
        .unwrap_or_else(|| format!("passkey {}", abbreviate_credential_id(&meta.credential_id)))
}

fn passkey_login_display_name(login: &PasskeyLogin) -> String {
    login
        .label
        .clone()
        .unwrap_or_else(|| format!("passkey {}", abbreviate_credential_id(&login.credential_id)))
}

fn abbreviate_credential_id(value: &str) -> String {
    let mut shortened: String = value.chars().take(8).collect();
    if value.chars().count() > 8 {
        shortened.push('…');
    }
    shortened
}

fn perform_scan(domain: String) -> Result<ReconReport, String> {
    let args = default_args(domain.clone());
    let runtime = Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| err.to_string())?;

    runtime.block_on(async move {
        let engine = ReconEngine::bootstrap(args.clone())
            .await
            .map_err(|err| err.to_string())?;

        if args.autonomous {
            AutonomousReconAgent::new(engine)
                .execute()
                .await
                .map_err(|err| err.to_string())
        } else {
            engine
                .execute_full_scan()
                .await
                .map_err(|err| err.to_string())
        }
    })
}

fn generate_compliance_package(report: &ReconReport) -> Result<String, String> {
    generate_compliance_outputs(report).map_err(|err| err.to_string())?;

    let report_path = Path::new(&report.output_dir).join(format!("{}_report.json", report.domain));

    Ok(report_path.to_string_lossy().into_owned())
}

fn default_args(domain: String) -> Args {
    Args {
        domain,
        concurrency: 32,
        timeout: 30,
        retries: 1,
        autonomous: true,
    }
}

struct DashboardSummary {
    domain: String,
    current_date: String,
    current_time: String,
    last_run: String,
    status_message: String,
    status_color: Color,
    progress: f32,
    stats: Vec<StatCardData>,
    subdomains: Vec<SubdomainRowData>,
    activity: Vec<ActivityBarData>,
    alerts: Vec<AlertRowData>,
    feature_feedback: Vec<FeatureFeedbackRowData>,
}

struct StatCardData {
    title: String,
    value: String,
    subtitle: String,
}

struct SubdomainRowData {
    name: String,
    status: String,
    highlight: bool,
}

struct ActivityBarData {
    label: String,
    value: f32,
}

struct AlertRowData {
    label: String,
    count: String,
    accent: Color,
}

struct FeatureFeedbackRowData {
    title: String,
    detail: String,
}

impl DashboardSummary {
    fn demo() -> Self {
        let now = Local::now();
        let stats = vec![
            StatCardData {
                title: "Discovered".into(),
                value: "152".into(),
                subtitle: "Total enumerated subdomains".into(),
            },
            StatCardData {
                title: "Live Hosts".into(),
                value: "38".into(),
                subtitle: "Reachable attack surface".into(),
            },
            StatCardData {
                title: "Open Ports".into(),
                value: "124".into(),
                subtitle: "Across 18 services".into(),
            },
            StatCardData {
                title: "Social Signals".into(),
                value: "12".into(),
                subtitle: "5 high+critical mentions".into(),
            },
        ];

        let subdomains = vec![
            SubdomainRowData {
                name: "api.shadowmap.io".into(),
                status: "3 open ports • cloud assets".into(),
                highlight: true,
            },
            SubdomainRowData {
                name: "cdn.shadowmap.io".into(),
                status: "Healthy".into(),
                highlight: false,
            },
            SubdomainRowData {
                name: "staging.shadowmap.io".into(),
                status: "takeover risk".into(),
                highlight: true,
            },
            SubdomainRowData {
                name: "dev.shadowmap.io".into(),
                status: "2 CORS issues".into(),
                highlight: true,
            },
            SubdomainRowData {
                name: "assets.shadowmap.io".into(),
                status: "Healthy".into(),
                highlight: false,
            },
            SubdomainRowData {
                name: "login.shadowmap.io".into(),
                status: "4 open ports".into(),
                highlight: true,
            },
        ];

        let activity = vec![
            ActivityBarData {
                label: "api".into(),
                value: 1.0,
            },
            ActivityBarData {
                label: "edge".into(),
                value: 0.72,
            },
            ActivityBarData {
                label: "auth".into(),
                value: 0.58,
            },
            ActivityBarData {
                label: "cdn".into(),
                value: 0.36,
            },
            ActivityBarData {
                label: "dev".into(),
                value: 0.24,
            },
            ActivityBarData {
                label: "qa".into(),
                value: 0.18,
            },
        ];

        let alerts = vec![
            AlertRowData {
                label: "CORS Alerts".into(),
                count: "8".into(),
                accent: Color::from_rgb_u8(111, 193, 255),
            },
            AlertRowData {
                label: "Takeover Risks".into(),
                count: "5".into(),
                accent: Color::from_rgb_u8(255, 168, 121),
            },
            AlertRowData {
                label: "Cloud Assets".into(),
                count: "9".into(),
                accent: Color::from_rgb_u8(173, 144, 255),
            },
            AlertRowData {
                label: "SaaS Matches".into(),
                count: "4".into(),
                accent: Color::from_rgb_u8(120, 255, 214),
            },
            AlertRowData {
                label: "Social Mentions".into(),
                count: "5 / 12 high".into(),
                accent: Color::from_rgb_u8(255, 214, 94),
            },
        ];

        let feature_feedback = vec![
            FeatureFeedbackRowData {
                title: "Surface Coverage".into(),
                detail: "152 monitored features across 38 live hosts".into(),
            },
            FeatureFeedbackRowData {
                title: "Alert Stream".into(),
                detail: "26 risk signals trending upward in the last cycle".into(),
            },
            FeatureFeedbackRowData {
                title: "Social Intelligence".into(),
                detail: "12 social mentions — focus on takeover chatter".into(),
            },
        ];

        Self {
            domain: "shadowmap.io".into(),
            current_date: now.format("%A %d %B %Y").to_string(),
            current_time: now.format("%I:%M %p").to_string(),
            last_run: now.format("%d %b %Y %H:%M").to_string(),
            status_message: "Ready to launch reconnaissance.".into(),
            status_color: Color::from_rgb_u8(136, 210, 255),
            progress: 0.0,
            stats,
            subdomains,
            activity,
            alerts,
            feature_feedback,
        }
    }

    fn from_report(report: &ReconReport) -> Self {
        let discovered = report.discovered_subdomains.len();
        let live = report.live_subdomains.len();
        let open_hosts = report.open_ports_map.len();
        let open_ports: usize = report
            .open_ports_map
            .values()
            .map(|ports| ports.len())
            .sum();

        let cors_count: usize = report.cors_map.values().map(|items| items.len()).sum();
        let takeover_count: usize = report.takeover_map.values().map(|items| items.len()).sum();
        let saas_count: usize = report
            .cloud_saas_map
            .values()
            .map(|items| items.len())
            .sum();
        let cloud_asset_count: usize = report
            .cloud_asset_map
            .values()
            .map(|items| items.len())
            .sum();
        let total_alerts = cors_count + takeover_count + saas_count + cloud_asset_count;

        let (social_total, social_high, social_avg_conf, social_assets) = report
            .social_intel
            .as_ref()
            .map(|intel| {
                let high = intel
                    .metrics
                    .severity_breakdown
                    .get("critical")
                    .cloned()
                    .unwrap_or(0)
                    + intel
                        .metrics
                        .severity_breakdown
                        .get("high")
                        .cloned()
                        .unwrap_or(0);
                (
                    intel.metrics.total_signals,
                    high,
                    intel.metrics.average_confidence,
                    intel.correlations.len(),
                )
            })
            .unwrap_or((0, 0, 0.0, 0));
        let combined_alerts = total_alerts + social_total;

        let stats = vec![
            StatCardData {
                title: "Discovered".into(),
                value: discovered.to_string(),
                subtitle: "Total enumerated subdomains".into(),
            },
            StatCardData {
                title: "Live Hosts".into(),
                value: live.to_string(),
                subtitle: "Reachable attack surface".into(),
            },
            StatCardData {
                title: "Open Ports".into(),
                value: open_ports.to_string(),
                subtitle: format!("Across {open_hosts} services"),
            },
            StatCardData {
                title: "Social Signals".into(),
                value: social_total.to_string(),
                subtitle: if social_total > 0 {
                    format!("{social_high} high+critical mentions")
                } else {
                    "Monitoring quiet channels".into()
                },
            },
        ];

        let mut live_subdomains_vec: Vec<String> = report.live_subdomains.iter().cloned().collect();
        live_subdomains_vec.sort();

        let mut subdomains = Vec::new();
        for host in live_subdomains_vec.iter().take(8) {
            let mut badges = Vec::new();
            let mut highlight = false;

            if let Some(ports) = report.open_ports_map.get(host) {
                if !ports.is_empty() {
                    badges.push(format!("{} open ports", ports.len()));
                    highlight = true;
                }
            }
            if let Some(entries) = report.cors_map.get(host) {
                if !entries.is_empty() {
                    badges.push(format!("{} CORS issues", entries.len()));
                    highlight = true;
                }
            }
            if let Some(entries) = report.takeover_map.get(host) {
                if !entries.is_empty() {
                    badges.push("takeover risk".into());
                    highlight = true;
                }
            }
            if let Some(entries) = report.cloud_asset_map.get(host) {
                if !entries.is_empty() {
                    badges.push("cloud assets".into());
                    highlight = true;
                }
            }
            if badges.is_empty() {
                badges.push("Healthy".into());
            }

            subdomains.push(SubdomainRowData {
                name: host.clone(),
                status: badges.join(" • "),
                highlight,
            });
        }

        if subdomains.is_empty() {
            subdomains.push(SubdomainRowData {
                name: "No live subdomains".into(),
                status: "Scan completed with no active hosts".into(),
                highlight: false,
            });
        }

        let mut activity = build_activity_data(&report.open_ports_map, &subdomains);
        if activity.is_empty() {
            activity.push(ActivityBarData {
                label: "scan".into(),
                value: 0.25,
            });
        }

        let alerts = vec![
            AlertRowData {
                label: "CORS Alerts".into(),
                count: cors_count.to_string(),
                accent: Color::from_rgb_u8(111, 193, 255),
            },
            AlertRowData {
                label: "Takeover Risks".into(),
                count: takeover_count.to_string(),
                accent: Color::from_rgb_u8(255, 168, 121),
            },
            AlertRowData {
                label: "Cloud Assets".into(),
                count: cloud_asset_count.to_string(),
                accent: Color::from_rgb_u8(173, 144, 255),
            },
            AlertRowData {
                label: "SaaS Matches".into(),
                count: saas_count.to_string(),
                accent: Color::from_rgb_u8(120, 255, 214),
            },
            AlertRowData {
                label: "Social Mentions".into(),
                count: if social_total > 0 {
                    format!("{social_high} / {social_total} high")
                } else {
                    "0".into()
                },
                accent: Color::from_rgb_u8(255, 214, 94),
            },
        ];

        let mut alert_hosts: HashSet<String> = report
            .cors_map
            .keys()
            .chain(report.takeover_map.keys())
            .chain(report.cloud_saas_map.keys())
            .chain(report.cloud_asset_map.keys())
            .map(|entry| entry.clone())
            .collect();
        if let Some(intel) = report.social_intel.as_ref() {
            for correlation in &intel.correlations {
                alert_hosts.insert(correlation.asset_id.clone());
            }
        }
        let alert_host_count = alert_hosts.len();

        let feature_feedback = vec![
            FeatureFeedbackRowData {
                title: "Surface Coverage".into(),
                detail: format!(
                    "{} validated • {} live hosts under watch",
                    report.validated_subdomains.len(),
                    live
                ),
            },
            FeatureFeedbackRowData {
                title: "Alert Stream".into(),
                detail: format!(
                    "{combined_alerts} active signals across {alert_host_count} assets"
                ),
            },
            FeatureFeedbackRowData {
                title: "Social Intelligence".into(),
                detail: if social_total > 0 {
                    format!(
                        "{social_total} mentions • {social_high} high • avg {:.0}% confidence • {social_assets} assets linked",
                        social_avg_conf * 100.0
                    )
                } else {
                    "No actionable social chatter detected".into()
                },
            },
        ];

        let now = Local::now();
        Self {
            domain: report.domain.clone(),
            current_date: now.format("%A %d %B %Y").to_string(),
            current_time: now.format("%I:%M %p").to_string(),
            last_run: now.format("%d %b %Y %H:%M").to_string(),
            status_message: format!(
                "Recon complete — {live} live hosts and {combined_alerts} alert markers"
            ),
            status_color: Color::from_rgb_u8(140, 225, 180),
            progress: 1.0,
            stats,
            subdomains,
            activity,
            alerts,
            feature_feedback,
        }
    }
}

fn build_activity_data(
    open_ports_map: &HashMap<String, Vec<u16>>,
    subdomains: &[SubdomainRowData],
) -> Vec<ActivityBarData> {
    let mut values: Vec<ActivityBarData> = open_ports_map
        .iter()
        .map(|(host, ports)| ActivityBarData {
            label: host.split('.').next().unwrap_or(host).to_string(),
            value: ports.len() as f32,
        })
        .collect();

    if values.is_empty() {
        for row in subdomains.iter().take(6) {
            values.push(ActivityBarData {
                label: row.name.split('.').next().unwrap_or(&row.name).to_string(),
                value: if row.highlight { 1.0 } else { 0.4 },
            });
        }
    }

    values.sort_by(|a, b| b.value.partial_cmp(&a.value).unwrap_or(Ordering::Equal));
    values.truncate(6);

    let max_value = values
        .iter()
        .fold(0.0_f32, |acc, entry| acc.max(entry.value));

    if max_value > 0.0 {
        for entry in &mut values {
            entry.value = (entry.value / max_value).max(0.18);
        }
    }

    values
}

fn apply_summary(ui: &Dashboard, summary: DashboardSummary) {
    ui.set_current_date(SharedString::from(summary.current_date));
    ui.set_current_time(SharedString::from(summary.current_time));
    ui.set_domain_input(SharedString::from(summary.domain.clone()));
    ui.set_last_run(SharedString::from(summary.last_run));
    ui.set_status_text(SharedString::from(summary.status_message));
    ui.set_status_color(Brush::from(summary.status_color));
    ui.set_scan_in_progress(false);
    ui.set_scan_progress(summary.progress);

    let stats_model = ModelRc::new(VecModel::from(
        summary
            .stats
            .into_iter()
            .map(|entry| StatCard {
                title: SharedString::from(entry.title),
                value: SharedString::from(entry.value),
                subtitle: SharedString::from(entry.subtitle),
            })
            .collect::<Vec<_>>(),
    ));
    ui.set_stats(stats_model);

    let subdomains_model = ModelRc::new(VecModel::from(
        summary
            .subdomains
            .into_iter()
            .map(|entry| SubdomainRow {
                name: SharedString::from(entry.name),
                status: SharedString::from(entry.status),
                highlight: entry.highlight,
            })
            .collect::<Vec<_>>(),
    ));
    ui.set_subdomains(subdomains_model);

    let activity_model = ModelRc::new(VecModel::from(
        summary
            .activity
            .into_iter()
            .map(|entry| ActivityBar {
                label: SharedString::from(entry.label),
                value: entry.value,
            })
            .collect::<Vec<_>>(),
    ));
    ui.set_activity(activity_model);

    let alerts_model = ModelRc::new(VecModel::from(
        summary
            .alerts
            .into_iter()
            .map(|entry| AlertRow {
                label: SharedString::from(entry.label),
                count: SharedString::from(entry.count),
                accent: Brush::from(entry.accent),
            })
            .collect::<Vec<_>>(),
    ));
    ui.set_alerts(alerts_model);

    let feedback_model = ModelRc::new(VecModel::from(
        summary
            .feature_feedback
            .into_iter()
            .map(|entry| FeatureFeedbackRow {
                title: SharedString::from(entry.title),
                detail: SharedString::from(entry.detail),
            })
            .collect::<Vec<_>>(),
    ));
    ui.set_feature_feedback(feedback_model);
}
