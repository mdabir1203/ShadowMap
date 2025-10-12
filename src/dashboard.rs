#![cfg(feature = "dashboard")]

use std::cmp::Ordering;
use std::collections::HashMap;
use std::thread;

use chrono::Local;
use shadowmap::{Args, AutonomousReconAgent, ReconEngine, ReconReport};
use slint::{Brush, Color, ModelRc, SharedString, VecModel};
use tokio::runtime::Builder;

slint::include_modules!();

pub fn main() -> Result<(), slint::PlatformError> {
    let ui = Dashboard::new()?;
    initialize_demo_state(&ui);

    let weak = ui.as_weak();

    ui.on_start_scan(move |domain| {
        let domain = domain.trim().to_string();
        let weak_for_callback = weak.clone();

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
        }

        let weak_for_thread = weak.clone();
        thread::spawn(move || {
            let result = perform_scan(domain.clone());
            match result {
                Ok(report) => {
                    let summary = DashboardSummary::from_report(report);
                    let weak_ui = weak_for_thread.clone();
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak_ui.upgrade() {
                            apply_summary(&ui, summary);
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
                        }
                    })
                    .expect("failed to update UI with error state");
                }
            }
        });
    });

    ui.run()
}

fn initialize_demo_state(ui: &Dashboard) {
    let summary = DashboardSummary::demo();
    apply_summary(ui, summary);
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
                title: "Security Alerts".into(),
                value: "26".into(),
                subtitle: "CORS, takeover & cloud".into(),
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
        }
    }

    fn from_report(report: ReconReport) -> Self {
        let ReconReport {
            domain,
            discovered_subdomains,
            live_subdomains,
            open_ports_map,
            cors_map,
            takeover_map,
            cloud_saas_map,
            cloud_asset_map,
            ..
        } = report;

        let discovered = discovered_subdomains.len();
        let live = live_subdomains.len();
        let open_hosts = open_ports_map.len();
        let open_ports: usize = open_ports_map.values().map(|ports| ports.len()).sum();

        let cors_count: usize = cors_map.values().map(|items| items.len()).sum();
        let takeover_count: usize = takeover_map.values().map(|items| items.len()).sum();
        let saas_count: usize = cloud_saas_map.values().map(|items| items.len()).sum();
        let cloud_asset_count: usize = cloud_asset_map.values().map(|items| items.len()).sum();
        let total_alerts = cors_count + takeover_count + saas_count + cloud_asset_count;

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
                title: "Security Alerts".into(),
                value: total_alerts.to_string(),
                subtitle: "CORS, takeover & cloud".into(),
            },
        ];

        let mut live_subdomains_vec: Vec<String> = live_subdomains.into_iter().collect();
        live_subdomains_vec.sort();

        let mut subdomains = Vec::new();
        for host in live_subdomains_vec.iter().take(8) {
            let mut badges = Vec::new();
            let mut highlight = false;

            if let Some(ports) = open_ports_map.get(host) {
                if !ports.is_empty() {
                    badges.push(format!("{} open ports", ports.len()));
                    highlight = true;
                }
            }
            if let Some(entries) = cors_map.get(host) {
                if !entries.is_empty() {
                    badges.push(format!("{} CORS issues", entries.len()));
                    highlight = true;
                }
            }
            if let Some(entries) = takeover_map.get(host) {
                if !entries.is_empty() {
                    badges.push("takeover risk".into());
                    highlight = true;
                }
            }
            if let Some(entries) = cloud_asset_map.get(host) {
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

        let mut activity = build_activity_data(&open_ports_map, &subdomains);
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
        ];

        let now = Local::now();
        Self {
            domain,
            current_date: now.format("%A %d %B %Y").to_string(),
            current_time: now.format("%I:%M %p").to_string(),
            last_run: now.format("%d %b %Y %H:%M").to_string(),
            status_message: format!(
                "Recon complete — {live} live hosts and {total_alerts} alert markers"
            ),
            status_color: Color::from_rgb_u8(140, 225, 180),
            progress: 1.0,
            stats,
            subdomains,
            activity,
            alerts,
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
}
