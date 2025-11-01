# ShadowMap

ShadowMap is a Rust toolkit for mapping exposed assets, confirming risky services, and exporting clear recon results.

---

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

---

## Profiling benchmark
The Hotpath CI workflow expects an example benchmark. You can replay the same workload locally to confirm profiling data is produced:

```bash
cargo run --example benchmark --features='hotpath,hotpath-ci'
```

Add `hotpath-alloc-count-total` to the feature list if you also need allocation metrics.

---

## Secure release pipeline (step by step)
ShadowMap ships with a reproducible release pipeline that follows the SLSA guidance. Each release tag runs the jobs below in order:

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

Consumers who prefer manual checks can review [`docs/security/verify.md`](docs/security/verify.md).

---

## Additional documentation
- [`docs/data-security.md`](docs/data-security.md) – Data security controls and compliance notes.
- [`docs/app-governance-integration.md`](docs/app-governance-integration.md) – Extending results into governance workflows.
- [`docs/security/slsa-whitepaper.md`](docs/security/slsa-whitepaper.md) – Executive overview of the reproducible supply chain strategy.
- [`docs/org-adaptation.md`](docs/org-adaptation.md) – Roll-out guidance for large teams.
- [`landing-page/`](landing-page/) – Static marketing page and Vercel deployment metadata.

