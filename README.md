# ShadowMap

ShadowMap is a Rust framework for disciplined subdomain enumeration, vulnerability detection, and attack-surface mapping at scale.

![Uploading 20250927-1723-29.1659684.gif…]

---

## Key Features

- **Comprehensive discovery**: Aggregates subdomains from CRT.sh and complementary sources with IDN normalization and wildcard handling.
- **Built-in validation**: Resolves DNS, inspects headers and TLS, and flags CORS or takeover risks with heuristic de-duplication.
- **Performance-first engine**: Async Rust core with configurable concurrency to cover large scopes quickly.
- **Actionable exports**: Ships clean CSV, JSON, and TXT outputs for reporting or downstream automation.
- **Extensible recon modules**: Plug-in architecture for port scanning, fingerprinting, and cloud exposure checks.

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

### Automated security workflow

The repository ships with a dedicated GitHub Action located at [`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml). It installs `cargo-cyclonedx` and `grype`, generates `shadowmap-bom.json`, scans it for vulnerabilities, and uploads the SBOM plus a JSON report as build artifacts. The workflow runs automatically for pull requests and pushes to `main`, and can also be started manually from the **Actions** tab via the **Run workflow** button.

### Desktop GUI (optional)
```bash
cargo run --features gui --bin shadowmap-gui
```
Enter a target domain in the GUI and select **Run Scan**; results are written to the output directory displayed on completion. The interface is implemented entirely in Rust via [`iced`](https://github.com/iced-rs/iced).

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

## Disclaimer
This tool is for educational and authorized security testing only.
Do not use ShadowMap against systems you don’t own or have explicit permission to test.

## Contributing
Pull requests are welcome! Please open an issue to discuss improvements, new modules, or bug fixes.

## Project Principles
ShadowMap is built on the idea that defenders need fast, global, reliable, and open tooling to match adversary velocity.

## Contributions 

![Alt](https://repobeats.axiom.co/api/embed/09cd32b3e91b58e3094e7592a33604c397c96f40.svg "Repobeats analytics image")
