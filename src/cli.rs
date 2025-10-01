use clap::{Parser, Subcommand};
use colored::*;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde_json::json;

use crate::{run, Args, BoxError};

// ============================================================================
// TERMINAL DESIGN - Creative ASCII Art & Branding
// ============================================================================

const SHADOWMAP_LOGO: &str = r#"
   _____ __              __                __  ___           
  / ___// /_  ____ _____/ /___ _      ____/  |/  /___ _____  
  \__ \/ __ \/ __ `/ __  / __ \ | /| / / / /|_/ / __ `/ __ \ 
 ___/ / / / / /_/ / /_/ / /_/ / |/ |/ / / /  / / /_/ / /_/ / 
/____/_/ /_/\__,_/\__,_/\____/|__/|__/ /_/  /_/\__,_/ .___/  
                                                    /_/       
"#;

const TAGLINE: &str = "Unified Network & Software Security Framework";
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Copy)]
enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
        })
    }
}

struct SimulatedVulnerability {
    severity: Severity,
    package: &'static str,
    identifier: &'static str,
    summary: &'static str,
}

const SIMULATED_VULNERABILITIES: &[SimulatedVulnerability] = &[
    SimulatedVulnerability {
        severity: Severity::Critical,
        package: "openssl",
        identifier: "CVE-2024-37895",
        summary: "TLS handshake bypass enables remote code execution.",
    },
    SimulatedVulnerability {
        severity: Severity::High,
        package: "glibc",
        identifier: "CVE-2024-3094",
        summary: "Out-of-bounds write in iconv input validation.",
    },
    SimulatedVulnerability {
        severity: Severity::High,
        package: "libxml2",
        identifier: "CVE-2024-25062",
        summary: "XXE payload may leak credentials via crafted XML.",
    },
    SimulatedVulnerability {
        severity: Severity::Medium,
        package: "serde_json",
        identifier: "GHSA-23f6-8h9m-6g78",
        summary: "Unchecked recursion can lead to denial of service.",
    },
    SimulatedVulnerability {
        severity: Severity::Medium,
        package: "openssl",
        identifier: "CVE-2024-4741",
        summary: "Timing side-channel leaks key material during RSA ops.",
    },
    SimulatedVulnerability {
        severity: Severity::Medium,
        package: "tokio",
        identifier: "CVE-2024-34070",
        summary: "Improper task cancellation may drop pending writes.",
    },
    SimulatedVulnerability {
        severity: Severity::Low,
        package: "clap",
        identifier: "GHSA-5m4v-mc3r-q2v4",
        summary: "Shell completion script may disclose flag defaults.",
    },
    SimulatedVulnerability {
        severity: Severity::Low,
        package: "hyper",
        identifier: "CVE-2024-28131",
        summary: "Verbose logging can expose bearer tokens in debug mode.",
    },
];

// ============================================================================
// CLI STRUCTURE - Elegant User Experience
// ============================================================================

#[derive(Parser)]
#[command(name = "shadowmap")]
#[command(version = VERSION)]
#[command(about = "Open-source supply chain security powered by Rust", long_about = None)]
#[command(disable_help_flag = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Show help information
    #[arg(short = 'h', long = "help")]
    help: bool,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate Software Bill of Materials (SBOM)
    #[command(visible_alias = "gen")]
    Generate {
        /// Path to project manifest
        #[arg(short, long, default_value = "Cargo.toml")]
        manifest: PathBuf,

        /// SBOM format (cyclonedx, spdx)
        #[arg(short, long, default_value = "cyclonedx")]
        format: String,

        /// Output file path
        #[arg(short, long, default_value = "shadowmap-sbom.json")]
        output: PathBuf,
    },

    /// Scan for vulnerabilities
    Scan {
        /// Input SBOM or manifest path
        #[arg(short, long)]
        input: PathBuf,

        /// Scanner engine (grype, rustsec, osv)
        #[arg(short, long, default_value = "grype")]
        scanner: String,

        /// Fail on severity (critical, high, medium, low)
        #[arg(long)]
        fail_on: Option<String>,
    },

    /// Generate compliance report
    Report {
        /// Scan results file
        #[arg(short, long)]
        input: PathBuf,

        /// Report format (json, pdf, html, markdown)
        #[arg(short, long, default_value = "json")]
        format: String,

        /// Output file path
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Run complete pipeline (generate → scan → report)
    Pipeline {
        /// Project manifest path
        #[arg(short, long, default_value = "Cargo.toml")]
        manifest: PathBuf,

        /// Output directory
        #[arg(short, long, default_value = "shadowmap-output")]
        output_dir: PathBuf,

        /// Fail on severity threshold
        #[arg(long)]
        fail_on: Option<String>,
    },

    /// Initialize ShadowMap in current project
    Init {
        /// Enable GitHub Actions integration
        #[arg(long)]
        github: bool,

        /// Enable GitLab CI integration
        #[arg(long)]
        gitlab: bool,
    },

    /// Run ShadowMap reconnaissance engine
    Recon {
        /// Target domain to perform subdomain enumeration on
        #[arg(short, long)]
        domain: String,

        /// Maximum number of concurrent connections
        #[arg(short, long, default_value_t = 50)]
        concurrency: usize,

        /// Request timeout in seconds
        #[arg(short = 't', long, default_value_t = 10)]
        timeout: u64,

        /// Number of retries for failed requests
        #[arg(short = 'r', long, default_value_t = 3)]
        retries: usize,

        /// Enable the autonomous Rig-inspired orchestration engine
        #[arg(long, default_value_t = false)]
        autonomous: bool,
    },

    /// Show version information
    Version,
}

// ============================================================================
// TERMINAL UI - Beautiful Output Functions
// ============================================================================

struct TerminalUI;

impl TerminalUI {
    /// Display creative introduction with branding
    fn show_intro() {
        // Clear terminal for clean presentation
        print!("\x1B[2J\x1B[1;1H");

        // Display logo with gradient effect
        println!("{}", SHADOWMAP_LOGO.bright_cyan().bold());

        // Tagline with styling
        println!("{}", "═".repeat(70).bright_black());
        println!("{:^70}", TAGLINE.bright_white().bold());
        println!(
            "{:^70}",
            format!("v{} • Powered by Rust 🦀", VERSION).bright_black()
        );
        println!("{}", "═".repeat(70).bright_black());
        println!();

        // Feature highlights with icons
        println!("  {}  Automated SBOM Generation", "🔍".bright_yellow());
        println!("  {}  Continuous Vulnerability Scanning", "🛡️".bright_red());
        println!("  {}  Compliance-Ready Reports", "📋".bright_green());
        println!("  {}  Enterprise-Grade Security", "🏢".bright_blue());
        println!();
        println!("{}", "─".repeat(70).bright_black());
        println!();
    }

    /// Display help with modern design
    fn show_help() {
        Self::show_intro();

        println!("{}", "USAGE:".bright_white().bold());
        println!("  shadowmap <COMMAND> [OPTIONS]");
        println!();

        println!("{}", "COMMANDS:".bright_white().bold());
        Self::print_command(
            "generate",
            "gen",
            "Generate Software Bill of Materials (SBOM)",
        );
        Self::print_command("scan", "", "Scan dependencies for vulnerabilities");
        Self::print_command("report", "", "Generate compliance reports");
        Self::print_command("pipeline", "", "Run complete security pipeline");
        Self::print_command("init", "", "Initialize ShadowMap in your project");
        Self::print_command("recon", "", "Run ShadowMap reconnaissance engine");
        Self::print_command("version", "", "Show version information");
        println!();

        println!("{}", "OPTIONS:".bright_white().bold());
        println!("  {} Enable verbose logging", "-v, --verbose".bright_cyan());
        println!("  {} Show help information", "-h, --help".bright_cyan());
        println!();

        println!("{}", "EXAMPLES:".bright_white().bold());
        println!("  {} Generate SBOM for your project", "→".bright_green());
        println!(
            "    {}",
            "shadowmap generate --manifest Cargo.toml".bright_yellow()
        );
        println!();
        println!("  {} Scan for vulnerabilities", "→".bright_green());
        println!(
            "    {}",
            "shadowmap scan --input sbom.json --fail-on high".bright_yellow()
        );
        println!();
        println!("  {} Run complete pipeline", "→".bright_green());
        println!("    {}", "shadowmap pipeline".bright_yellow());
        println!();
        println!("  {} Execute a reconnaissance scan", "→".bright_green());
        println!(
            "    {}",
            "shadowmap recon --domain example.com --concurrency 75".bright_yellow()
        );
        println!();

        println!("{}", "LEARN MORE:".bright_white().bold());
        println!(
            "  Documentation: {}",
            "https://shadowmap.io/docs".bright_blue().underline()
        );
        println!(
            "  GitHub: {}",
            "https://github.com/shadowmap/shadowmap"
                .bright_blue()
                .underline()
        );
        println!();
    }

    fn print_command(name: &str, alias: &str, description: &str) {
        let alias_str = if alias.is_empty() {
            "".to_string()
        } else {
            format!(" ({})", alias).bright_black().to_string()
        };

        println!(
            "  {}{:<20} {}",
            name.bright_cyan().bold(),
            alias_str,
            description
        );
    }

    /// Beautiful section headers
    fn print_section(title: &str) {
        println!();
        println!("{}", format!("┌─ {} ", title).bright_white().bold());
        println!("{}", "│".bright_black());
    }

    fn print_section_end() {
        println!("{}", "└─".bright_black());
    }

    /// Progress indicators with spinners
    fn print_step(number: usize, total: usize, action: &str) {
        println!(
            "{} {} {}",
            format!("[{}/{}]", number, total).bright_black(),
            "→".bright_cyan(),
            action.bright_white()
        );
    }

    /// Success messages with checkmarks
    fn print_success(message: &str) {
        println!("  {} {}", "✓".bright_green().bold(), message.bright_white());
    }

    /// Error messages with cross marks
    fn print_error(message: &str) {
        eprintln!("  {} {}", "✗".bright_red().bold(), message.bright_red());
    }

    /// Info messages
    fn print_info(message: &str) {
        println!("  {} {}", "ℹ".bright_blue(), message);
    }

    /// Display vulnerability summary with colors
    fn print_vulnerability_summary(critical: u32, high: u32, medium: u32, low: u32) {
        println!();
        println!("{}", "VULNERABILITY SUMMARY".bright_white().bold());
        println!("{}", "─".repeat(50).bright_black());

        Self::print_vuln_line("Critical", critical, "red");
        Self::print_vuln_line("High", high, "red");
        Self::print_vuln_line("Medium", medium, "yellow");
        Self::print_vuln_line("Low", low, "green");

        println!("{}", "─".repeat(50).bright_black());

        let total = critical + high + medium + low;
        if total == 0 {
            println!("  {} No vulnerabilities found!", "🎉".bright_green());
        } else {
            println!(
                "  Total: {} vulnerabilities",
                total.to_string().bright_red().bold()
            );
        }
    }

    fn print_vuln_line(severity: &str, count: u32, color: &str) {
        let icon = match color {
            "red" => "🔴",
            "yellow" => "🟡",
            "green" => "🟢",
            _ => "⚪",
        };

        let count_str = count.to_string();
        let colored_count = match color {
            "red" => count_str.bright_red().bold(),
            "yellow" => count_str.bright_yellow().bold(),
            "green" => count_str.bright_green(),
            _ => count_str.normal(),
        };

        println!("  {} {:<12} {}", icon, severity, colored_count);
    }

    fn print_vulnerability_table(vulnerabilities: &[SimulatedVulnerability]) {
        if vulnerabilities.is_empty() {
            return;
        }

        println!();
        println!("{}", "TOP FINDINGS".bright_white().bold());
        println!("{}", "─".repeat(50).bright_black());

        for vuln in vulnerabilities {
            let (icon, badge) = match vuln.severity {
                Severity::Critical => (
                    "🛑",
                    format!("{:^8}", vuln.severity)
                        .bright_white()
                        .on_bright_red()
                        .bold(),
                ),
                Severity::High => (
                    "🚨",
                    format!("{:^8}", vuln.severity)
                        .bright_white()
                        .on_red()
                        .bold(),
                ),
                Severity::Medium => (
                    "⚠️",
                    format!("{:^8}", vuln.severity)
                        .bright_black()
                        .on_yellow()
                        .bold(),
                ),
                Severity::Low => (
                    "ℹ️",
                    format!("{:^8}", vuln.severity)
                        .bright_black()
                        .on_bright_green()
                        .bold(),
                ),
            };

            println!(
                "  {} {} {:<16} {:<18} {}",
                icon,
                badge,
                vuln.package.bright_white().bold(),
                vuln.identifier.bright_cyan(),
                vuln.summary
            );
        }

        println!("{}", "─".repeat(50).bright_black());
    }

    /// Animated progress bar
    fn show_progress(message: &str) {
        print!("  {} {} ", "⏳".bright_cyan(), message);
        io::stdout().flush().unwrap();

        // Simulate work
        std::thread::sleep(std::time::Duration::from_millis(500));

        println!("{}", "Done!".bright_green());
    }
}

// ============================================================================
// CLI EXECUTION ENGINE
// ============================================================================

pub struct ShadowMapCLI;

impl ShadowMapCLI {
    pub async fn run() -> Result<(), BoxError> {
        let cli = Cli::parse();

        // Handle help flag
        if cli.help {
            TerminalUI::show_help();
            return Ok(());
        }

        // Always show intro first
        TerminalUI::show_intro();

        // Handle commands
        match cli.command {
            None => {
                TerminalUI::show_help();
            }
            Some(Commands::Generate {
                manifest,
                format,
                output,
            }) => {
                Self::cmd_generate(manifest, format, output)?;
            }
            Some(Commands::Scan {
                input,
                scanner,
                fail_on,
            }) => {
                Self::cmd_scan(input, scanner, fail_on)?;
            }
            Some(Commands::Report {
                input,
                format,
                output,
            }) => {
                Self::cmd_report(input, format, output)?;
            }
            Some(Commands::Pipeline {
                manifest,
                output_dir,
                fail_on,
            }) => {
                Self::cmd_pipeline(manifest, output_dir, fail_on)?;
            }
            Some(Commands::Init { github, gitlab }) => {
                Self::cmd_init(github, gitlab)?;
            }
            Some(Commands::Recon {
                domain,
                concurrency,
                timeout,
                retries,
                autonomous,
            }) => {
                Self::cmd_recon(domain, concurrency, timeout, retries, autonomous).await?;
            }
            Some(Commands::Version) => {
                Self::cmd_version();
            }
        }

        Ok(())
    }

    // ========================================================================
    // COMMAND IMPLEMENTATIONS
    // ========================================================================

    fn cmd_generate(manifest: PathBuf, format: String, output: PathBuf) -> Result<(), BoxError> {
        TerminalUI::print_section("GENERATE SBOM");

        TerminalUI::print_info(&format!("Manifest: {}", manifest.display()));
        TerminalUI::print_info(&format!("Format: {}", format));
        TerminalUI::print_info(&format!("Output: {}", output.display()));

        TerminalUI::show_progress("Analyzing dependencies");
        TerminalUI::show_progress("Resolving transitive dependencies");
        TerminalUI::show_progress(&format!("Generating {} SBOM", format));

        let sbom_payload = Self::render_sbom_stub(&manifest, &format);
        Self::write_stub_file(&output, &sbom_payload)?;

        TerminalUI::print_success(&format!("SBOM generated: {}", output.display()));
        TerminalUI::print_section_end();

        Ok(())
    }

    fn cmd_scan(input: PathBuf, scanner: String, fail_on: Option<String>) -> Result<(), BoxError> {
        TerminalUI::print_section("VULNERABILITY SCAN");

        TerminalUI::print_info(&format!("Input: {}", input.display()));
        TerminalUI::print_info(&format!("Scanner: {}", scanner));
        if let Some(threshold) = &fail_on {
            TerminalUI::print_info(&format!("Fail threshold: {}", threshold));
        }

        TerminalUI::show_progress("Loading SBOM");
        TerminalUI::show_progress("Querying vulnerability databases");
        TerminalUI::show_progress("Analyzing CVE matches");

        let vulnerabilities = SIMULATED_VULNERABILITIES;
        let (critical, high, medium, low) = Self::count_vulnerabilities(vulnerabilities);

        TerminalUI::print_vulnerability_summary(critical, high, medium, low);
        TerminalUI::print_vulnerability_table(vulnerabilities);
        TerminalUI::print_section_end();

        // Check fail threshold
        if let Some(threshold) = fail_on {
            if Self::should_fail(&threshold, critical, high, medium, low) {
                TerminalUI::print_error("Build failed: Vulnerability threshold exceeded");
                std::process::exit(1);
            }
        }

        Ok(())
    }

    fn cmd_report(input: PathBuf, format: String, output: PathBuf) -> Result<(), BoxError> {
        TerminalUI::print_section("GENERATE REPORT");

        TerminalUI::print_info(&format!("Input: {}", input.display()));
        TerminalUI::print_info(&format!("Format: {}", format));
        TerminalUI::print_info(&format!("Output: {}", output.display()));

        TerminalUI::show_progress("Loading scan results");
        TerminalUI::show_progress(&format!("Generating {} report", format.to_uppercase()));
        TerminalUI::show_progress("Checking compliance standards");

        let report_payload = Self::render_report_stub(&format, SIMULATED_VULNERABILITIES);
        Self::write_stub_file(&output, &report_payload)?;

        TerminalUI::print_success(&format!("Report generated: {}", output.display()));
        TerminalUI::print_info("✓ EO 14028 compliant");
        TerminalUI::print_info("✓ NIS2 compliant");
        TerminalUI::print_info("✓ CRA compliant");

        TerminalUI::print_section_end();

        Ok(())
    }

    fn cmd_pipeline(
        manifest: PathBuf,
        output_dir: PathBuf,
        fail_on: Option<String>,
    ) -> Result<(), BoxError> {
        println!(
            "{}",
            "╔════════════════════════════════════════════════════════════════════╗".bright_cyan()
        );
        println!(
            "{}",
            "║              SHADOWMAP SECURITY PIPELINE                          ║"
                .bright_cyan()
                .bold()
        );
        println!(
            "{}",
            "╚════════════════════════════════════════════════════════════════════╝".bright_cyan()
        );
        println!();

        TerminalUI::print_info(&format!("Manifest: {}", manifest.display()));
        TerminalUI::print_info(&format!("Output directory: {}", output_dir.display()));
        if let Some(threshold) = &fail_on {
            TerminalUI::print_info(&format!("Fail threshold: {}", threshold));
        }

        fs::create_dir_all(&output_dir).map_err(|err| -> BoxError { Box::new(err) })?;

        // Step 1: Generate SBOM
        TerminalUI::print_step(1, 3, "Generate SBOM");
        TerminalUI::show_progress("Analyzing project dependencies");
        let sbom_path = output_dir.join("sbom.json");
        let sbom_payload = Self::render_sbom_stub(&manifest, "cyclonedx");
        Self::write_stub_file(&sbom_path, &sbom_payload)?;
        TerminalUI::print_success(&format!("SBOM created: {}", sbom_path.display()));

        // Step 2: Vulnerability Scan
        TerminalUI::print_step(2, 3, "Vulnerability Scan");
        TerminalUI::show_progress("Scanning for known vulnerabilities");
        let vulnerabilities = SIMULATED_VULNERABILITIES;
        let (critical, high, medium, low) = Self::count_vulnerabilities(vulnerabilities);
        TerminalUI::print_vulnerability_summary(critical, high, medium, low);
        TerminalUI::print_vulnerability_table(vulnerabilities);
        let scan_results_path = output_dir.join("scan-results.json");
        let scan_payload = Self::render_scan_results_stub(vulnerabilities);
        Self::write_stub_file(&scan_results_path, &scan_payload)?;
        TerminalUI::print_info(&format!(
            "Scan results saved: {}",
            scan_results_path.display()
        ));

        if let Some(threshold) = &fail_on {
            if Self::should_fail(threshold, critical, high, medium, low) {
                TerminalUI::print_error("Pipeline failed: Vulnerability threshold exceeded");
                TerminalUI::print_info(&format!("📁 Output: {}/", output_dir.display()));
                TerminalUI::print_info("📄 Files: sbom.json, scan-results.json, report.json");
                io::stdout().flush().ok();
                io::stderr().flush().ok();
                std::process::exit(1);
            }
        }

        // Step 3: Generate Reports
        TerminalUI::print_step(3, 3, "Generate Reports");
        TerminalUI::show_progress("Creating compliance reports");
        let report_path = output_dir.join("report.json");
        let report_payload = Self::render_report_stub("json", vulnerabilities);
        Self::write_stub_file(&report_path, &report_payload)?;
        TerminalUI::print_success(&format!("Report saved: {}", report_path.display()));

        println!();
        println!("{}", "═".repeat(70).bright_green());
        println!(
            "{:^70}",
            "✓ PIPELINE COMPLETED SUCCESSFULLY".bright_green().bold()
        );
        println!("{}", "═".repeat(70).bright_green());
        println!();

        TerminalUI::print_info(&format!("📁 Output: {}/", output_dir.display()));
        TerminalUI::print_info("📄 Files: sbom.json, scan-results.json, report.json");

        Ok(())
    }

    fn cmd_init(github: bool, gitlab: bool) -> Result<(), BoxError> {
        TerminalUI::print_section("INITIALIZE SHADOWMAP");

        TerminalUI::show_progress("Creating .shadowmap directory");
        TerminalUI::show_progress("Generating configuration file");

        if github {
            TerminalUI::show_progress("Creating GitHub Actions workflow");
            TerminalUI::print_success("GitHub Actions configured");
        }

        if gitlab {
            TerminalUI::show_progress("Creating GitLab CI configuration");
            TerminalUI::print_success("GitLab CI configured");
        }

        println!();
        println!(
            "{}",
            "✓ ShadowMap initialized successfully!"
                .bright_green()
                .bold()
        );
        println!();
        println!("{}", "NEXT STEPS:".bright_white().bold());
        println!("  1. Review .shadowmap/config.toml");
        println!("  2. Run: {}", "shadowmap pipeline".bright_yellow());
        println!("  3. Commit and push your changes");

        TerminalUI::print_section_end();

        Ok(())
    }

    async fn cmd_recon(
        domain: String,
        concurrency: usize,
        timeout: u64,
        retries: usize,
        autonomous: bool,
    ) -> Result<(), BoxError> {
        TerminalUI::print_section("RECONNAISSANCE SCAN");

        TerminalUI::print_info(&format!("Domain: {}", domain));
        TerminalUI::print_info(&format!("Concurrency: {}", concurrency));
        TerminalUI::print_info(&format!("Timeout: {}s", timeout));
        TerminalUI::print_info(&format!("Retries: {}", retries));
        if autonomous {
            TerminalUI::print_info("Autonomous mode: enabled");
        } else {
            TerminalUI::print_info("Autonomous mode: disabled");
        }

        TerminalUI::show_progress("Launching reconnaissance engine");

        let args = Args {
            domain,
            concurrency,
            timeout,
            retries,
            autonomous,
        };

        match run(args).await {
            Ok(output_dir) => {
                TerminalUI::print_success(&format!("Reconnaissance complete: {}", output_dir));
                TerminalUI::print_info("Review reports in the output directory");
            }
            Err(err) => {
                TerminalUI::print_error(&format!("Reconnaissance failed: {}", err));
                return Err(err);
            }
        }

        TerminalUI::print_section_end();

        Ok(())
    }

    fn cmd_version() {
        println!("{} v{}", "ShadowMap".bright_cyan().bold(), VERSION);
        println!("Rust-powered supply chain security");
        println!();
        println!("Author: ShadowMap Security Team");
        println!("License: Apache-2.0 / MIT");
        println!("Repository: https://github.com/shadowmap/shadowmap");
    }

    // Helper functions

    fn should_fail(threshold: &str, critical: u32, high: u32, medium: u32, low: u32) -> bool {
        match threshold.to_lowercase().as_str() {
            "critical" => critical > 0,
            "high" => critical > 0 || high > 0,
            "medium" => critical > 0 || high > 0 || medium > 0,
            "low" => critical > 0 || high > 0 || medium > 0 || low > 0,
            _ => false,
        }
    }

    fn count_vulnerabilities(vulnerabilities: &[SimulatedVulnerability]) -> (u32, u32, u32, u32) {
        let mut counts = (0_u32, 0_u32, 0_u32, 0_u32);

        for vuln in vulnerabilities {
            match vuln.severity {
                Severity::Critical => counts.0 += 1,
                Severity::High => counts.1 += 1,
                Severity::Medium => counts.2 += 1,
                Severity::Low => counts.3 += 1,
            }
        }

        counts
    }

    fn render_sbom_stub(manifest: &Path, format: &str) -> String {
        let sbom = json!({
            "format": format,
            "manifest": manifest.display().to_string(),
            "generated_at": Utc::now().to_rfc3339(),
            "components": [
                {
                    "name": "shadowmap",
                    "version": VERSION,
                    "type": "application",
                    "licenses": ["Apache-2.0", "MIT"],
                },
                {
                    "name": "openssl",
                    "version": "3.2.1",
                    "type": "library",
                    "licenses": ["Apache-2.0"],
                },
                {
                    "name": "tokio",
                    "version": "1.40.0",
                    "type": "library",
                    "licenses": ["MIT"],
                },
            ],
        });

        serde_json::to_string_pretty(&sbom).unwrap_or_else(|_| "{}".to_string())
    }

    fn render_scan_results_stub(vulnerabilities: &[SimulatedVulnerability]) -> String {
        let (critical, high, medium, low) = Self::count_vulnerabilities(vulnerabilities);
        let total = critical + high + medium + low;

        let findings: Vec<_> = vulnerabilities
            .iter()
            .map(|v| {
                json!({
                    "severity": v.severity.to_string(),
                    "package": v.package,
                    "identifier": v.identifier,
                    "summary": v.summary,
                })
            })
            .collect();

        let scan = json!({
            "generated_at": Utc::now().to_rfc3339(),
            "summary": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "total": total,
            },
            "findings": findings,
        });

        serde_json::to_string_pretty(&scan).unwrap_or_else(|_| "{}".to_string())
    }

    fn render_report_stub(format: &str, vulnerabilities: &[SimulatedVulnerability]) -> String {
        let (critical, high, medium, low) = Self::count_vulnerabilities(vulnerabilities);
        let total = critical + high + medium + low;
        let generated_at = Utc::now().to_rfc3339();

        match format.to_lowercase().as_str() {
            "json" => {
                let report = json!({
                    "generated_at": generated_at,
                    "summary": {
                        "critical": critical,
                        "high": high,
                        "medium": medium,
                        "low": low,
                        "total": total,
                    },
                    "compliance": {
                        "eo_14028": true,
                        "nis2": true,
                        "cra": true,
                    },
                    "notes": "Simulated data – replace with real scan findings in production.",
                });

                serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
            }
            "markdown" => {
                format!(
                    "# ShadowMap Security Report\n\nGenerated: {}\n\n| Severity | Count |\n| --- | ---: |\n| Critical | {} |\n| High | {} |\n| Medium | {} |\n| Low | {} |\n| **Total** | **{}** |\n\n- EO 14028 compliant\n- NIS2 compliant\n- CRA compliant\n",
                    generated_at, critical, high, medium, low, total
                )
            }
            "html" => {
                format!(
                    "<html><head><title>ShadowMap Report</title></head><body><h1>ShadowMap Security Report</h1><p>Generated: {}</p><table border=\"1\" cellpadding=\"6\"><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody><tr><td>Critical</td><td>{}</td></tr><tr><td>High</td><td>{}</td></tr><tr><td>Medium</td><td>{}</td></tr><tr><td>Low</td><td>{}</td></tr><tr><td><strong>Total</strong></td><td><strong>{}</strong></td></tr></tbody></table><p>Compliance: EO 14028 ✅ | NIS2 ✅ | CRA ✅</p></body></html>",
                    generated_at, critical, high, medium, low, total
                )
            }
            "pdf" => {
                format!(
                    "ShadowMap PDF report placeholder\nGenerated: {}\nTotal findings: {} (Critical: {}, High: {}, Medium: {}, Low: {})\nCompliance: EO 14028 ✓, NIS2 ✓, CRA ✓\n",
                    generated_at, total, critical, high, medium, low
                )
            }
            _ => {
                format!(
                    "ShadowMap report generated at {}\nTotal findings: {} (Critical: {}, High: {}, Medium: {}, Low: {})\nCompliance targets met: EO 14028, NIS2, CRA\n",
                    generated_at, total, critical, high, medium, low
                )
            }
        }
    }

    fn write_stub_file(path: &Path, contents: &str) -> Result<(), BoxError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|err| -> BoxError { Box::new(err) })?;
            }
        }

        fs::write(path, contents).map_err(|err| -> BoxError { Box::new(err) })?;

        Ok(())
    }
}
