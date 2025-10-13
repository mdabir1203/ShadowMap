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

### Landing page & billing checkout

ShadowMap now ships with a minimalist marketing landing page, localized pricing, and optional Stripe Checkout integration.

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


2. (Optional) Point the lead-capture database at a custom SQLite location. The server defaults to
   `sqlite://shadowmap.db` in the working directory and will automatically create the
   `landing_leads` table when it starts:
   ```bash
   export DATABASE_URL=sqlite:///var/lib/shadowmap/leads.db
   ```

3. Launch the server:
   ```bash
   cargo run --bin shadowmap-server
   ```

4. Visit `http://localhost:8080/` for the public landing page and `http://localhost:8080/app` for the authenticated recon dashboard. Every checkout attempt stores the work email, plan, and region in
   the `landing_leads` table for follow-up.


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
