# ShadowMap

<img width="512" alt="ShadowMap logo" src="https://github.com/user-attachments/assets/95d39e5e-d51c-4eb4-9053-2db1e1042410" />

ShadowMap is a Rust framework for disciplined subdomain enumeration, vulnerability detection, and attack-surface mapping at scale.

---

## Key Features

- **Comprehensive discovery**: Aggregates subdomains from CRT.sh and complementary sources with IDN normalization and wildcard handling.
- **Built-in validation**: Resolves DNS, inspects headers and TLS, and flags CORS or takeover risks with heuristic de-duplication.
- **Performance-first engine**: Async Rust core with configurable concurrency to cover large scopes quickly.
- **Actionable exports**: Ships clean CSV, JSON, and TXT outputs for reporting or downstream automation.
- **Extensible recon modules**: Plug-in architecture for port scanning, fingerprinting, and cloud exposure checks.
- **Rig-style autonomy**: Optional agent orchestrator that sequences every recon module, retries failures, and flags deep cloud assets automatically.

---

## Getting Started

### Prerequisites
- Rust 1.70 or newer (includes Cargo)

### Build & Install
```bash
git clone https://github.com/YOUR-ORG/ShadowMap.git
cd ShadowMap
cargo build --release
```

### First Scan
```bash
./target/release/shadowmap -d example.com -o results.csv
```

### Quality Checks
```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

### Landing page, billing checkout & Vercel

ShadowMap now includes a minimalist, luxury-inspired landing page that mirrors the in-app experience. The Rust server renders it dynamically with localized pricing and optional Stripe checkout, while a static export in `landing-page/index.html` is ready for Vercel hosting.

#### Keep the static export in sync

```bash
cargo run --bin export_landing
```

The helper binary regenerates `landing-page/index.html` from the latest templates in `src/web/views.rs`. Run it after copy or styling updates so commits (and deployments) always ship the current markup.

#### Optional: enable Stripe checkout

1. Export your Stripe credentials and price IDs (test or live):
   ```bash
   export STRIPE_PUBLISHABLE_KEY=pk_test_...
   export STRIPE_SECRET_KEY=sk_test_...
   export STRIPE_PRICE_STARTER_USD=price_123
   export STRIPE_PRICE_STARTER_EUR=price_456
   export STRIPE_PRICE_GROWTH_USD=price_789
   export STRIPE_PRICE_GROWTH_EUR=price_abc
   export STRIPE_PRICE_ENTERPRISE_USD=price_def
   export STRIPE_PRICE_ENTERPRISE_EUR=price_ghi
   # Optional overrides for post-checkout navigation
   export STRIPE_SUCCESS_URL=https://shadowmap.io/app?checkout=success
   export STRIPE_CANCEL_URL=https://shadowmap.io/pricing
   ```

2. (Optional) Point the lead-capture database at a custom SQLite location. The server defaults to `sqlite://shadowmap.db` in the working directory and creates the `landing_leads` table automatically:
   ```bash
   export DATABASE_URL=sqlite:///var/lib/shadowmap/leads.db
   ```

3. Launch the server:
   ```bash
   cargo run --bin shadowmap-server
   ```

4. Visit `http://localhost:8080/` for the public landing page and `http://localhost:8080/app` for the recon dashboard. Checkout attempts log the work email, plan, and region to the `landing_leads` table for follow-up.

#### Deploy the static page to Vercel

1. Install the [Vercel CLI](https://vercel.com/cli) and authenticate (`vercel login`).
2. From the repository root, deploy the static export:
   ```bash
   vercel --prod
   ```
   The included `vercel.json` registers `landing-page/index.html` as the build artifact and rewrites all routes to it.
3. Future updates only require re-running `cargo run --bin export_landing`, committing the refreshed HTML, and redeploying with `vercel --prod`.

> **Note:** Checkout buttons remain disabled in the static export until the server exposes Stripe keys, keeping the hosted page aligned with production capabilities.

### Supply Chain Security

ShadowMap includes a lightweight workflow for generating a Software Bill of Materials (SBOM) and scanning it for known vulnerab
ilities. The steps below follow the [cargo-cyclonedx + Grype quickstart](https://gitlab.com/-/snippets/4892073) from the securi
ty guide referenced in this task.

1. **Install cargo-cyclonedx** (once per machine):
   ```bash
   cargo install cargo-cyclonedx
   ```

2. **Install Grype** (Linux/WSL example):
   ```bash
   curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
   ```
   Refer to the [Grype README](https://github.com/anchore/grype) for macOS and Windows alternatives.

3. **Generate the SBOM** in CycloneDX JSON format with all ShadowMap features enabled. Overriding the filename causes `cargo-cyclonedx` to place the SBOM in the current working directory, making it easy to move or archive:
   ```bash
   cargo cyclonedx --format json --spec-version 1.5 --all-features --override-filename bom
   # cargo-cyclonedx writes bom.json into the current working directory; move it if you prefer a different location
   ```

4. **Scan the SBOM with Grype** (pointing at whichever location you chose above):
   ```bash
   grype sbom:./bom.json
   ```

5. (Optional) Export detailed findings:
   ```bash
   grype sbom:./bom.json -o json --file vulnerability-report.json
   ```

For repeatability you can run `./scripts/security-scan.sh` which wraps the SBOM generation and Grype scan with sensible defaults.

### Data Security & Compliance

ShadowMap aligns its operational safeguards with SOC 2 Trust Services Criteria and GDPR privacy requirements. The
[Data Security and Compliance Strategy](docs/data-security.md) describes the control owners, evidence expectations, and
validation activities that keep reconnaissance data secure throughout its lifecycle.

### Social intelligence-driven security automation

Teams layering social listening on top of ShadowMap can adopt the
[Social Intelligence Insights for Security](docs/social-intelligence-security.md) guide. It explains how the Codex
agent configuration transforms emerging chatter into normalized signals, correlates them with known assets, and drives
guardrailed remediation playbooks.

The framework now runs those social intelligence stages natively during every autonomous scan. Normalized mentions are
correlated with live assets, exported alongside the technical report, and surfaced in the interactive dashboard so
teams can immediately see high-signal chatter, affected hosts, and recommended responses. Override the baked-in Codex
plan by setting `SHADOWMAP_SOCIAL_CONFIG=/path/to/framework.yaml` before launching a run to load a custom orchestration
file without recompiling.

### Technical report automation

Run `./scripts/generate-technical-report.sh` to materialize the latest reconnaissance brief as `build/technical-report.md`.
The [Generate technical report PDF workflow](.github/workflows/generate-technical-report-pdf.yml) wires this script into the
CI pipeline and uses Pandoc to emit a downloadable artifact—trigger it manually from the **Actions** tab whenever you need a
fresh PDF without committing binaries.

### Application Governance & Resilience

Teams that need to spot unapproved apps, fragmented data flows, or silent system failures can extend ShadowMap's
discoveries into governance and reliability workflows using the
[Application Governance Integration guide](docs/app-governance-integration.md). It outlines how to fuse ShadowMap outputs
with CMDBs, data lineage tools, and observability platforms to close monitoring gaps.

### Organizational Adoption Playbook

Security programs that want to operationalize ShadowMap across large enterprises can follow the
[Organizational Adoption Playbook](docs/org-adaptation.md). It lays out governance structures, stakeholder roles, and
business metrics that translate reconnaissance coverage into measurable risk reduction and executive-aligned value.

### Automated security workflow

The repository ships with a dedicated GitHub Action located at [`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml). It installs `cargo-cyclonedx` and `grype`, generates `shadowmap-bom.json`, scans it for vulnerabilities, and uploads the SBOM plus a JSON report as build artifacts. The workflow runs automatically for pull requests and pushes to `main`, and can also be started manually from the **Actions** tab via the **Run workflow** button.

### Desktop GUI (optional)
```bash
cargo run --features gui --bin shadowmap-gui
```
Enter a target domain in the GUI and select **Run Scan**; results are written to the output directory displayed on completion. The interface is implemented entirely in Rust via [`iced`](https://github.com/iced-rs/iced).

### Slint dashboard preview (experimental)
```bash
cargo run --features dashboard --bin shadowmap-dashboard
```
Use the Slint-powered dashboard to launch scans, review live status messages, and visualize summaries of subdomain activity and alert categories.

---

## Usage

Run a default reconnaissance scan and export CSV output:
```bash
shadowmap -d example.com -o results.csv
```

Adjust concurrency to tune throughput for large scopes:
```bash
shadowmap -d example.com -c 50 -o results.json
```

Pipe JSON output for downstream automation:
```bash
shadowmap -d target.com --json > report.json
```

Enable the autonomous Rig-inspired orchestrator with deep cloud discovery:
```bash
shadowmap -d target.com --autonomous
```
The agent executes each reconnaissance stage with retry-aware control flow, surfaces SaaS predictors, and produces `cloud_assets.json` alongside traditional reports for deep storage/bucket exposure review.

---

## Output

```csv
subdomain,http_status,server_header,open_ports,cors_issues,fingerprints,takeover_risks
api.example.com,200,nginx,"80,443","Wildcard CORS allowed","{server: nginx, framework: react}","None"
cdn.example.com,0,,,"","",Potential AWS S3 takeover
```

## Roadmap

- Passive and active DNS integrations (SecurityTrails, Shodan, etc.)
- Advanced port fingerprinting through Nmap integration
- Plugin system for bespoke reconnaissance modules
- Cloud asset exposure detection (GCP Buckets, Azure Blobs, etc.)
- Continuous recon mode for persistent monitoring

## Acknowledgements

ShadowMap's SBOM generation and vulnerability scanning workflows rely on the
[CycloneDX](https://cyclonedx.org/) standard and the [Grype](https://github.com/anchore/grype)
scanner maintained by Anchore. If you redistribute ShadowMap guidance or reuse the automation
scripts, please keep those upstream attributions (or submodule references) intact so the
maintainers receive credit for their work.

## Disclaimer
This tool is for educational and authorized security testing only.
Do not use ShadowMap against systems you don’t own or have explicit permission to test.

## Contributing
Pull requests are welcome! Please open an issue to discuss improvements, new modules, or bug fixes.

## Project Principles
ShadowMap is built on the idea that defenders need fast, global, reliable, and open tooling to match adversary velocity.

## Contributions 

![Alt](https://repobeats.axiom.co/api/embed/09cd32b3e91b58e3094e7592a33604c397c96f40.svg "Repobeats analytics image")
