mod agent;
pub mod args;
pub mod cli;
mod cloud;
pub mod compliance;
mod constants;
mod cors;
mod dns;
mod enumeration;
mod fingerprint;
mod headers;
pub mod passkeys;
mod ports;
mod reporting;
mod social;
mod takeover;
pub mod web;

pub use agent::BoxError;
pub use agent::{AutonomousReconAgent, ReconEngine, ReconReport};
pub use args::Args;
pub use reporting::{write_outputs, ReconMaps};
pub use social::{
    LocalizationSummary as SocialLocalizationSummary, SocialCorrelation, SocialIntelligenceSummary,
    SocialMetrics, SocialReportView, SocialSignal,
};

pub fn generate_compliance_outputs(report: &ReconReport) -> Result<(), BoxError> {
    write_outputs(
        &report.live_subdomains,
        ReconMaps {
            header_map: &report.header_map,
            open_ports_map: &report.open_ports_map,
            cors_map: &report.cors_map,
            software_map: &report.software_map,
            takeover_map: &report.takeover_map,
            cloud_saas_map: &report.cloud_saas_map,
            cloud_asset_map: &report.cloud_asset_map,
            social_intel: report.social_intel.as_ref(),
        },
        &report.output_dir,
        &report.domain,
    )
}

pub async fn run(args: Args) -> Result<String, BoxError> {
    let engine = ReconEngine::bootstrap(args).await?;
    engine.log_run_banner();
    let use_agent = engine.is_autonomous();

    let report = if use_agent {
        AutonomousReconAgent::new(engine).execute().await?
    } else {
        engine.execute_full_scan().await?
    };

    generate_compliance_outputs(&report)?;

    if let Some(intel) = &report.social_intel {
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

        eprintln!(
            "[intel] {} social signals mapped ({} high+critical, avg confidence {:.0}%)",
            intel.metrics.total_signals,
            high,
            intel.metrics.average_confidence * 100.0
        );
    }

    eprintln!(
        "[*] Recon complete. Outputs in: {} ({} live, {} deep cloud alerts)",
        report.output_dir,
        report.live_subdomains.len(),
        report.cloud_asset_map.len()
    );

    Ok(report.output_dir)
}
