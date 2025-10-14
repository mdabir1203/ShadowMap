mod agent;
pub mod args;
pub mod cli;
mod cloud;
mod constants;
mod cors;
mod dns;
mod enumeration;
mod fingerprint;
mod headers;
mod ports;
mod reporting;
mod takeover;

pub use agent::BoxError;
pub use agent::{AutonomousReconAgent, ReconEngine, ReconReport};
pub use args::Args;
pub use reporting::{write_outputs, ReconMaps};

pub async fn run(args: Args) -> Result<String, BoxError> {
    let engine = ReconEngine::bootstrap(args).await?;
    engine.log_run_banner();
    let use_agent = engine.is_autonomous();

    let report = if use_agent {
        AutonomousReconAgent::new(engine).execute().await?
    } else {
        engine.execute_full_scan().await?
    };

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
        },
        &report.output_dir,
        &report.domain,
    )?;

    eprintln!(
        "[*] Recon complete. Outputs in: {} ({} live, {} deep cloud alerts)",
        report.output_dir,
        report.live_subdomains.len(),
        report.cloud_asset_map.len()
    );

    Ok(report.output_dir)
}
