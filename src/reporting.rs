use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Write;

use csv::Writer;
use itertools::Itertools;

use crate::cloud::CloudAssetFinding;
use crate::social::SocialIntelligenceSummary;
use crate::pretty_report::{PrettyReportGenerator, ReconSummary};

pub struct ReconMaps<'a> {
    pub header_map: &'a HashMap<String, (u16, Option<String>)>,
    pub open_ports_map: &'a HashMap<String, Vec<u16>>,
    pub cors_map: &'a HashMap<String, Vec<String>>,
    pub software_map: &'a HashMap<String, HashMap<String, String>>,
    pub takeover_map: &'a HashMap<String, Vec<String>>,
    pub cloud_saas_map: &'a HashMap<String, Vec<String>>,
    pub cloud_asset_map: &'a HashMap<String, Vec<CloudAssetFinding>>,
    pub social_intel: Option<&'a SocialIntelligenceSummary>,
}

pub fn write_outputs(
    subs: &HashSet<String>,
    maps: ReconMaps<'_>,
    output_dir: &str,
    domain: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let txt_file = format!("{}/{}_subdomains.txt", output_dir, domain);
    let mut file = File::create(&txt_file)?;
    for sub in subs.iter().sorted() {
        writeln!(file, "{}", sub)?;
    }

    let json_file = format!("{}/{}_report.json", output_dir, domain);
    let mut json_obj = serde_json::Map::new();

    for sub in subs.iter().sorted() {
        let mut entry = serde_json::Map::new();

        if let Some((status, server)) = maps.header_map.get(sub) {
            entry.insert("http_status".to_string(), serde_json::json!(status));
            entry.insert("server_header".to_string(), serde_json::json!(server));
        }

        entry.insert(
            "open_ports".to_string(),
            serde_json::json!(maps.open_ports_map.get(sub).cloned().unwrap_or_default()),
        );

        entry.insert(
            "cors_issues".to_string(),
            serde_json::json!(maps.cors_map.get(sub).cloned().unwrap_or_default()),
        );

        entry.insert(
            "fingerprints".to_string(),
            serde_json::json!(maps.software_map.get(sub).cloned().unwrap_or_default()),
        );

        entry.insert(
            "takeover_risks".to_string(),
            serde_json::json!(maps.takeover_map.get(sub).cloned().unwrap_or_default()),
        );

        entry.insert(
            "cloud_saas".to_string(),
            serde_json::json!(maps.cloud_saas_map.get(sub).cloned().unwrap_or_default()),
        );

        entry.insert(
            "cloud_assets".to_string(),
            serde_json::json!(maps.cloud_asset_map.get(sub).cloned().unwrap_or_default()),
        );

        json_obj.insert(sub.clone(), serde_json::Value::Object(entry));
    }

    std::fs::write(json_file, serde_json::to_string_pretty(&json_obj)?)?;

    let csv_file = format!("{}/{}_report.csv", output_dir, domain);
    let mut wtr = Writer::from_path(&csv_file)?;
    wtr.write_record([
        "subdomain",
        "http_status",
        "server_header",
        "open_ports",
        "cors_issues",
        "fingerprints",
        "takeover_risks",
        "cloud_saas",
        "cloud_assets",
    ])?;

    for sub in subs.iter().sorted() {
        let (status, server) = maps.header_map.get(sub).cloned().unwrap_or((0, None));
        let ports = maps.open_ports_map.get(sub).map_or("".to_string(), |v| {
            v.iter().map(|p| p.to_string()).join(",")
        });
        let cors = maps
            .cors_map
            .get(sub)
            .map_or("".to_string(), |v| v.join("; "));
        let fingerprints = maps.software_map.get(sub).map_or("".to_string(), |v| {
            serde_json::to_string(v).unwrap_or_default()
        });
        let takeover = maps
            .takeover_map
            .get(sub)
            .map_or("".to_string(), |v| v.join("; "));
        let cloud_saas = maps
            .cloud_saas_map
            .get(sub)
            .map_or("".to_string(), |v| v.join("; "));
        let cloud_assets = maps
            .cloud_asset_map
            .get(sub)
            .map_or_else(|| "".to_string(), |v| format_cloud_assets(v.as_slice()));

        wtr.write_record([
            sub,
            &status.to_string(),
            &server.unwrap_or_default(),
            &ports,
            &cors,
            &fingerprints,
            &takeover,
            &cloud_saas,
            &cloud_assets,
        ])?;
    }
    wtr.flush()?;

    let findings_file = format!("{}/{}_security_findings.txt", output_dir, domain);
    let mut findings = File::create(&findings_file)?;

    writeln!(findings, "Security Findings Summary for {}", domain)?;
    writeln!(findings, "=============================================")?;
    writeln!(findings, "Total subdomains found: {}", subs.len())?;
    writeln!(
        findings,
        "Subdomains with CORS issues: {}",
        maps.cors_map.len()
    )?;
    writeln!(
        findings,
        "Potential takeover targets: {}",
        maps.takeover_map.len()
    )?;
    writeln!(
        findings,
        "Deep cloud assets flagged: {}",
        maps.cloud_asset_map.len()
    )?;

    if let Some(intel) = maps.social_intel {
        let social_file = format!("{}/{}_social_intelligence.json", output_dir, domain);
        std::fs::write(&social_file, serde_json::to_string_pretty(intel)?)?;

        let high_signals = intel
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

        writeln!(
            findings,
            "Social intelligence signals: {} ({} high+critical)",
            intel.metrics.total_signals, high_signals
        )?;
    }

    let cloud_file = format!("{}/{}_cloud_saas.json", output_dir, domain);
    std::fs::write(
        cloud_file,
        serde_json::to_string_pretty(&maps.cloud_saas_map)?,
    )?;

    let deep_cloud_file = format!("{}/{}_cloud_assets.json", output_dir, domain);
    std::fs::write(
        deep_cloud_file,
        serde_json::to_string_pretty(&maps.cloud_asset_map)?,
    )?;

    // Generate beautiful markdown report
    let summary = ReconSummary {
        domain,
        subs,
        header_map: maps.header_map,
        open_ports_map: maps.open_ports_map,
        cors_map: maps.cors_map,
        software_map: maps.software_map,
        takeover_map: maps.takeover_map,
        cloud_saas_map: maps.cloud_saas_map,
        cloud_asset_map: maps.cloud_asset_map,
        social_intel: maps.social_intel,
        output_dir,
    };
    
    PrettyReportGenerator::generate_markdown_report(&summary)?;

    // Print terminal summary
    PrettyReportGenerator::print_terminal_summary(&summary);

    Ok(())
}

fn format_cloud_assets(findings: &[CloudAssetFinding]) -> String {
    findings
        .iter()
        .map(|finding| {
            format!(
                "{} [{}] {}",
                finding.provider,
                finding.status_string(),
                finding.asset
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}
