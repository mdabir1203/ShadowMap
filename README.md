# ShadowMap

ShadowMap is a Rust toolkit for mapping exposed assets, confirming risky services, and exporting clear recon results.

# Why and the Decision Process 

ShadowMap dashboards provide a live view into global subdomain reconnaissance, but they’re new! Expect hacker-grade speed, not polished analytics. Real-time data may fluctuate, charts may be dense, and initial setups need a bit of infra love. We’re improving UX, aggregation, and performance — contributions welcome!


## Quick start

### Requirements
- Rust 1.70 or newer (Cargo included)

### Build the binaries
```bash
git clone https://github.com/YOUR-ORG/ShadowMap.git
cd ShadowMap
cargo build --release
```

### Run your first scan
```bash
./target/release/shadowmap -d example.com -o results.csv
```

### Routine quality checks
```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

### Landing page, billing checkout & Vercel

ShadowMap now includes a minimalist, luxury-inspired landing page that mirrors the in-app experience. The Rust server renders it dynamically with localized pricing and optional Stripe checkout, while a static export in `landing-page/index.html` is ready for Vercel hosting.

## Profiling benchmark
The Hotpath CI workflow expects an example benchmark. You can replay the same workload locally to confirm profiling data is produced:

```bash
cargo run --example benchmark --features='hotpath,hotpath-ci'
```

Add `hotpath-alloc-count-total` to the feature list if you also need allocation metrics.

---

ShadowMap now ships a SLSA-ready, reproducible release system that elevates the earlier SBOM scan into an end-to-end provenance chain. The architecture, mission, and operational guardrails are captured in [`docs/security/slsa-ready-pipeline.md`](docs/security/slsa-ready-pipeline.md), while [`docs/security/verify.md`](docs/security/verify.md) teaches consumers how to validate each release.

#### Step-by-step secure release flow

1. **Signed commits & tags** – Developers sign commits, cut an annotated tag, and push to GitHub. The [`slsa-release`](.github/workflows/slsa-release.yml) workflow starts automatically for `v*` tags.
2. **Primary hermetic build** – The `primary-build` job pins toolchains, fetches dependencies with `--locked`, disables outbound networking, compiles the binaries, and produces SBOM + checksum manifests.
3. **Independent rebuild** – `reproducibility-build` repeats the process on a separate runner to generate a second checksum manifest.
4. **Determinism check** – `compare-builds` downloads both manifests and performs a byte-for-byte diff. Any mismatch fails the release.
5. **Provenance generation** – Once the checksums match, the reusable `slsa-github-generator` workflow emits a DSSE attestation that records the workflow run, materials, and artifact digest.
6. **Keyless signing & publishing** – The `publish` job signs the attestation with cosign keyless OIDC credentials, bundles the `.intoto.jsonl` + `.sig` + SBOM + binaries, and uploads everything to the GitHub Release.
7. **Consumer verification** – Operators download the release bundle and run `./scripts/verify_release.sh` to validate the signature, provenance, checksum, and SBOM in one command.

For day-to-day SBOM inspection or CI gating you can still run the lightweight scan locally:

1. **Primary hermetic build** – Pin the toolchain, fetch locked dependencies, disable outbound network access, and build the release binaries plus SBOM and checksums.
2. **Independent rebuild** – Run the same steps on a second runner to generate another checksum set.
3. **Determinism check** – Compare both checksum files; any mismatch stops the release.
4. **Provenance generation** – Call the `slsa-github-generator` workflow to create a DSSE attestation that records the build run and artifact digests.
5. **Signing & publish** – Use cosign keyless signing, bundle the binaries, SBOM, provenance, and signature, and upload the bundle to the GitHub release.

The full architecture, controls, and reasoning live in [`docs/security/slsa-ready-pipeline.md`](docs/security/slsa-ready-pipeline.md).

---

## Verify a downloaded release
1. Download the release artifact, its `.intoto.jsonl` provenance file, the `.sig` signature, and the SBOM.
2. Run the helper script:
   ```bash
   ./scripts/verify_release.sh shadowmap-vX.Y.Z.tar.gz
   ```
3. The script performs signature, provenance, checksum, and SBOM validation. Any failure exits with a non-zero status so it can be wired into automation.

For repeatability you can run `./scripts/security-scan.sh` which wraps the SBOM generation and Grype scan with sensible defaults,
while `./scripts/verify_release.sh` handles the full attestation verification for published releases.

---

### Data Security & Compliance

ShadowMap aligns its operational safeguards with SOC 2 Trust Services Criteria and GDPR privacy requirements. The
[Data Security and Compliance Strategy](docs/data-security.md) describes the control owners, evidence expectations, and
validation activities that keep reconnaissance data secure throughout its lifecycle.

---

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

---

### Technical report automation

Run `./scripts/generate-technical-report.sh` to materialize the latest reconnaissance brief as `build/technical-report.md`.
The [Generate technical report PDF workflow](.github/workflows/generate-technical-report-pdf.yml) wires this script into the
CI pipeline and uses Pandoc to emit a downloadable artifact—trigger it manually from the **Actions** tab whenever you need a
fresh PDF without committing binaries.

---

### Application Governance & Resilience

Teams that need to spot unapproved apps, fragmented data flows, or silent system failures can extend ShadowMap's
discoveries into governance and reliability workflows using the
[Application Governance Integration guide](docs/app-governance-integration.md). It outlines how to fuse ShadowMap outputs
with CMDBs, data lineage tools, and observability platforms to close monitoring gaps.

---

### Organizational Adoption Playbook

Security programs that want to operationalize ShadowMap across large enterprises can follow the
[Organizational Adoption Playbook](docs/org-adaptation.md). It lays out governance structures, stakeholder roles, and
business metrics that translate reconnaissance coverage into measurable risk reduction and executive-aligned value.

---

### Automated security workflow

The repository ships with a dedicated GitHub Action located at [`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml). It installs `cargo-cyclonedx` and `grype`, generates `shadowmap-bom.json`, scans it for vulnerabilities, and uploads the SBOM plus a JSON report as build artifacts. The workflow runs automatically for pull requests and pushes to `main`, and can also be started manually from the **Actions** tab via the **Run workflow** button.

---

### Desktop GUI (optional)
```bash
cargo run --features gui --bin shadowmap-gui
```
Enter a target domain in the GUI and select **Run Scan**; results are written to the output directory displayed on completion. The interface is implemented entirely in Rust via [`iced`](https://github.com/iced-rs/iced).

---

### Slint dashboard preview (experimental)
```bash
cargo run --features dashboard --bin shadowmap-dashboard
```
Use the Slint-powered dashboard to launch scans, review live status messages, and visualize summaries of subdomain activity and alert categories.

---

## Additional documentation
- [`docs/data-security.md`](docs/data-security.md) – Data security controls and compliance notes.
- [`docs/app-governance-integration.md`](docs/app-governance-integration.md) – Extending results into governance workflows.
- [`docs/security/slsa-whitepaper.md`](docs/security/slsa-whitepaper.md) – Executive overview of the reproducible supply chain strategy.
- [`docs/org-adaptation.md`](docs/org-adaptation.md) – Roll-out guidance for large teams.
- [`landing-page/`](landing-page/) – Static marketing page and Vercel deployment metadata.

