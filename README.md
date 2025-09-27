# ShadowMap

<img width="384" alt="ShadowMap logo" src="https://github.com/user-attachments/assets/95d39e5e-d51c-4eb4-9053-2db1e1042410" />

ShadowMap maps the cloud attack surface across AWS, Azure, and GCP so security teams and bug bounty hunters can spot risky assets before adversaries do. Everything runs from the command line—no coding required.

---

## Why teams choose ShadowMap

- **Complete visibility** – Unifies managed DNS, storage, edge, and serverless endpoints across the three major clouds.
- **Trustworthy validation** – Confirms exposure with live DNS/HTTP/TLS checks and flags misconfigurations that matter.
- **Actionable reporting** – Exports CSV/JSON/Markdown plus GPT-4 assisted briefs for fast stakeholder-ready updates.

## What ShadowMap discovers

| Cloud | High-value targets | Validation highlights |
| --- | --- | --- |
| **AWS** | Route53 zones, API Gateway, CloudFront, ALB/NLB, S3, Lambda URLs, Amplify | SigV4-aware checks, public bucket detection, dangling DNS identification |
| **Azure** | DNS Zones, App Service, Functions, Front Door, Storage, CDN, API Management | Managed identity exposure, default hostname reachability, blob ACL review |
| **GCP** | Cloud DNS, Cloud Run, Cloud Functions, Cloud Storage, Load Balancers, Firebase Hosting | IAM boundary review, anonymous invoke detection, certificate fingerprinting |

<img width="512" alt="ShadowMap logo" src="https://github.com/user-attachments/assets/95d39e5e-d51c-4eb4-9053-2db1e1042410" />

ShadowMap is a Rust framework for disciplined subdomain enumeration, vulnerability detection, and attack-surface mapping at scale.

---

## Key Features

- **Comprehensive discovery**: Aggregates subdomains from CRT.sh and complementary sources with IDN normalization and wildcard handling.
- **Built-in validation**: Resolves DNS, inspects headers and TLS, and flags CORS or takeover risks with heuristic de-duplication.
- **Performance-first engine**: Async Rust core with configurable concurrency to cover large scopes quickly.
- **Actionable exports**: Ships clean CSV, JSON, and TXT outputs for reporting or downstream automation.
- **Extensible recon modules**: Plug-in architecture for port scanning, fingerprinting, and cloud exposure checks.

```bash
git clone https://github.com/YOUR-ORG/ShadowMap.git
cd ShadowMap
cargo build --release
```

This compiles a ready-to-run binary at `./target/release/shadowmap`.

### 3. Run your first scan

### Quality Checks
```bash
./target/release/shadowmap \
  --domain example.com \
  --providers aws,azure,gcp \
  --report markdown
```

The command above writes a markdown report to the `reports/` folder with confirmed findings and remediation notes.


## GPT-4 assisted reporting (optional)

ShadowMap can draft proof-of-concept steps and disclosure-ready summaries when an OpenAI API key is available.

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

Pipe JSON output for downstream automation:
```bash
export OPENAI_API_KEY="sk-..."
./target/release/shadowmap --domain example.com --providers aws,azure,gcp --report markdown --gpt4 --poc
```
You keep full control: review the generated markdown before sharing with engineering or program owners.


```csv
provider,asset_type,endpoint,risk,validation,gpt4_summary
aws,S3 Bucket,media.example.com,PublicReadEnabled,"ACL: public-read","Marketing assets exposed; see PoC#1"
azure,App Service,api-contoso.azurewebsites.net,DefaultHostnameExposed,"HTTP 200","Default host reachable; enable Front Door"
gcp,Cloud Run,app.run.app,UnauthenticatedInvoke,"IAM allows allUsers","Anonymous invoke open; PoC includes curl command"
```


## Roadmap highlights

- Terraform/OpenTofu drift repair suggestions delivered alongside findings.
- Native integrations with ticketing platforms to turn findings into tracked work automatically.


## Responsible use

ShadowMap is for authorized security testing only. Always secure written approval, respect cloud provider policies, and validate proof-of-concepts in controlled environments.


## Contributing & support

Issues and pull requests are welcome—share modules, detection ideas, or doc fixes. ShadowMap exists to help defenders and researchers operate faster, together.

![Alt](https://repobeats.axiom.co/api/embed/09cd32b3e91b58e3094e7592a33604c397c96f40.svg "Repobeats analytics image")
