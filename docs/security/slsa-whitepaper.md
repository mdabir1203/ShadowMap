# ShadowMap Reproducible Supply Chain Whitepaper

## Executive Summary
ShadowMap delivers a verifiable release process designed for enterprises that demand cryptographic proof of the code they deploy. The reproducible pipeline provides:

- **Deterministic builds** that emit byte-identical artifacts across independent runners.
- **Complete provenance** through SLSA-compliant attestations signed with keyless infrastructure.
- **Auditable release evidence** — SBOM, checksums, logs, and signatures — packaged for regulators and security teams.
- **Automated consumer validation** with a turnkey verification script and transparent documentation.

This document outlines the reference architecture, control objectives, and operational model supporting the pipeline.

## Mission and Scope
The reproducible pipeline focuses on ShadowMap release artifacts distributed from the official repository. It enforces the mission to “ensure every released artifact can prove its own integrity — showing who built it, from what source, with which tools, and how it can be independently reproduced.” The scope covers:

1. Build orchestration in GitHub Actions.
2. Toolchain and dependency governance.
3. Artifact signing, attestation, and disclosure.
4. Consumer verification workflows and controls.

## Architecture Overview
The system follows five layered controls:

1. **Immutable Inputs** – Toolchains, actions, and container images are pinned by digest. Cargo manifests (`Cargo.lock`, `.rust-toolchain.toml`) lock compiler and dependency versions. Build runners fetch dependencies before network egress is disabled.
2. **Trusted Build Context** – CI jobs execute in hardened, hermetic containers. Once dependencies are cached, outbound network traffic is blocked to eliminate mutation risk.
3. **Deterministic Build Stages** – Primary and secondary builds run on separate runners. Their checksum manifests must match exactly before releases continue.
4. **Transparent Provenance** – The `slsa-github-generator` reusable workflow produces DSSE-formatted provenance linking git commit, build metadata, and artifact digests.
5. **Continuous Verification** – Signed attestations, SBOMs, and verification scripts are shipped with each release. Rekor transparency entries provide public discoverability.

The architecture diagram in `docs/shadowmap-architecture.d2` maps the data flow between these layers, highlighting artifact packaging, signing, and publication.

## Control Objectives
| Objective | Control Description | Evidence |
|-----------|--------------------|----------|
| Immutable Inputs | `.rust-toolchain.toml`, `Cargo.lock`, and pinned GitHub Actions ensure deterministic tooling. | Repository manifests, workflow YAML |
| Reproducible Builds | Dual-runner build jobs enforce identical checksums before release. | Build logs, checksum comparison report |
| Attestation Integrity | DSSE provenance is generated and stored with signatures anchored in Rekor. | Provenance files, Rekor entry IDs |
| Artifact Transparency | SBOMs and verification scripts are published with every release tag. | Release assets, documentation |
| Consumer Validation | `verify_release.sh` performs signature, provenance, checksum, and SBOM validation. | Script logs, CI verification job |

## Build Lifecycle
1. **Tag Detection** – Pushing a semantic version tag triggers the release workflow.
2. **Primary Build** – The hermetic job compiles binaries, generates SBOMs with `syft`, and records SHA-256 digests.
3. **Independent Rebuild** – A secondary runner repeats the build. Both checksum manifests are diffed; mismatches halt the pipeline.
4. **Provenance Creation** – `slsa-github-generator` uses GitHub OIDC to sign an in-toto/DSSE attestation linking commit SHA and artifact digests.
5. **Release Bundle** – Cosign keyless signing produces signatures for binaries and provenance. Assets uploaded to GitHub Releases include binaries, SBOM, checksums, provenance, and signature files.
6. **Transparency Publication** – Cosign submits the signature bundle to Rekor, creating a verifiable audit trail.

## Consumer Verification Model
Security and compliance teams can verify releases using two approaches:

- **Automated script** – `./scripts/verify_release.sh` orchestrates cosign verification, SLSA provenance validation, checksum comparison, and SBOM digest checks.
- **Manual procedure** – Detailed steps in `docs/security/verify.md` allow auditors to run each check independently.

Both paths rely on public Rekor entries and DSSE attestations to independently confirm the build run and artifact integrity.

## Operational Metrics
To ensure continuous assurance, the pipeline tracks:

- 100% attestation coverage across tagged releases.
- ≥95% byte-identical rebuild rate across independent runners.
- ≤30% CI runtime overhead compared to non-hardened builds.
- 100% verification success for published release bundles.
- ≤1% drift in audit controls (e.g., pinned versions, workflow changes).

Alerts fire if any metric breaches its target, prompting investigation before the next release cycle.

## Enterprise Adoption Guidance
- **Dual-track CI** – Developers use a fast lane without hermetic restrictions for daily work. The secure lane applies full provenance controls for release tags.
- **Change Management** – Document workflow updates and require code review approvals for YAML edits affecting build security.
- **Incident Response** – In case of discrepancy (e.g., checksum mismatch), block releases, rotate compromised credentials, and regenerate attestations.
- **Regulatory Reporting** – Bundle provenance, SBOM, and verification evidence for frameworks such as FedRAMP, SOC 2, and ISO 27001.

## Future Enhancements
1. Enable automated diffing of SBOM versions between releases.
2. Integrate policy-as-code checks that refuse releases lacking required attestations.
3. Expand double-build coverage to include container images and documentation artifacts.
4. Provide optional reproducibility attestations for customer-hosted rebuilds.

## Conclusion
ShadowMap’s reproducible pipeline provides end-to-end integrity guarantees aligned with SLSA level 3 requirements. Enterprises can trust that every artifact carries verifiable evidence of origin, toolchain, and immutability — reducing supply chain risk while preserving developer velocity.
