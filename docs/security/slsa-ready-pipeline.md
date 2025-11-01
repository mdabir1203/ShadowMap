# SLSA-Ready Reproducible Pipeline

## Mission Statement

Ensure that every released artifact can prove its own integrity — showing who built it, from what source, with which tools, and how it can be independently reproduced.

## Core Design Principles

| Principle | Description |
| --- | --- |
| Immutable Inputs | All toolchains, actions, and dependencies are pinned and version-locked. |
| Transparent Provenance | Each artifact includes a DSSE-formatted SLSA attestation proving its origin. |
| Deterministic Builds | Builds are reproducible; identical inputs produce byte-identical outputs across environments. |
| Trusted Build Context | CI workflows and containers are pinned, signed, and hermetically executed. |
| Continuous Verification | Verification and attestation are automated for every release tag. |

## Architecture Overview

```mermaid
graph TD
    subgraph Dev[Developer Space]
        D1[Signed Commits (GPG / Sigstore)]
        D2[Source Repository (shadowmap.git)]
    end

    subgraph Build[Build System]
        B1[Pinned Toolchains<br/>Rust toolchain.lock]
        B2[Hermetic Build Runner<br/>Nix shell / Docker]
        B3[SLSA Generator (DSSE provenance)]
        B4[Artifact Fingerprint (SHA256)]
    end

    subgraph Release[Release & Consumers]
        R1[Release bundles (.tar.gz, checksums)]
        R2[Attestation (.intoto.jsonl)]
        R3[Signature (.sig via cosign)]
        R4[SBOM (CycloneDX JSON)]
    end

    subgraph Repro[Reproducibility & Verification]
        V1[Double Builder (secondary runner)]
        V2[Checksum Comparison]
        V3[Attestation Verification]
        V4[SBOM Transparency]
    end

    subgraph Trust[Trust Consumers]
        T1[Partner / Regulator View]
        T2[Security Platform Integrations]
        T3[Internal Reliability Dashboards]
    end

    D1 --> B1
    D2 --> B1
    B1 --> B2
    B2 --> B3
    B3 --> B4
    B4 --> R1
    B3 --> R2
    B4 --> R3
    B2 --> R4
    R1 --> V2
    R2 --> V3
    R3 --> V3
    R4 --> V4
    V2 --> Trust
    V3 --> Trust
    V4 --> Trust
```

The architecture mirrors the provided design diagram: commits signed by developers flow into a hermetic build system that generates signed artifacts, DSSE attestations, and SBOMs. Independent rebuilders repeat the process to confirm determinism before consumers verify everything through the supplied script.

## Key Components

| Component | Function | Tooling |
| --- | --- | --- |
| Hermetic Build Runner | Builds artifacts inside a network-isolated container after dependency materialization. | GitHub Actions, Docker, Nix shell |
| Toolchain Locking | Freezes the Rust compiler, cargo, and dependencies for deterministic builds. | `.rust-toolchain.toml`, `cargo.lock` |
| SLSA Generator | Emits DSSE provenance for every build. | [`slsa-github-generator`](https://github.com/slsa-framework/slsa-github-generator) |
| Keyless Signing | Signs artifacts and attestations using GitHub OIDC without long-lived keys. | [`cosign`](https://github.com/sigstore/cosign) |
| SBOM Generator | Produces comprehensive dependency inventories and license metadata. | [`syft`](https://github.com/anchore/syft), [`trivy`](https://github.com/aquasecurity/trivy) |
| Double Builder | Re-runs builds on independent runners to assert reproducibility. | Secondary GitHub Actions runner |
| Transparency Log | Publishes signatures and attestations to an append-only log. | [`rekor`](https://github.com/sigstore/rekor) |

## Operational Controls

1. **Pin & Lock** – All GitHub Actions, containers, and toolchains are referenced by immutable digests.
2. **Hermetic Mode** – Build jobs disable outbound networking after dependencies and toolchains are fetched.
3. **Double Build Check** – Tagged releases trigger a parallel rebuild that must produce byte-identical artifacts.
4. **Attest & Sign** – Provenance is generated with SLSA and signed with cosign keyless flows, with entries recorded in Rekor.
5. **Audit Trail** – SBOMs, attestation JSON, signatures, and verification logs are retained per release.

## Release Flow

1. Developer merges a signed commit and pushes a Git tag.
2. The **Primary Build** job:
   - Checks out source with submodules and verifies signatures.
   - Restores the pinned Rust toolchain and caches dependencies using `cargo fetch --locked`.
   - Builds release artifacts inside a container with the network disabled post-fetch.
   - Generates SBOMs, checksums, and uploads artifacts to the workflow.
3. The **Reproducibility Build** job repeats the same steps on an isolated runner.
4. The **Provenance** job compares the checksums from both builds; if they match it produces the DSSE attestation, signs everything, and pushes signatures to Rekor.
5. Release artifacts, checksums, attestation, and verification logs are published to the GitHub Release.

## Continuous Verification

- Every release artifact includes:
  - `shadowmap.tar.gz` – the compiled binaries.
  - `shadowmap.sha256` – checksums for all release files.
  - `shadowmap.intoto.jsonl` – DSSE SLSA provenance.
  - `shadowmap.intoto.jsonl.sig` – cosign signature for the DSSE payload.
  - `shadowmap.sbom.json` – CycloneDX SBOM output.
- Consumers run `./scripts/verify_release.sh` to validate signatures, provenance, checksums, and SBOM metadata automatically.

## Metrics & Observability

| Metric | Target | Purpose |
| --- | --- | --- |
| Valid Attestations | 100% | Proves each release is accompanied by provenance. |
| Byte-Identical Rebuilds | ≥ 95% | Ensures reproducibility expectations. |
| CI Runtime Overhead | ≤ 30% | Tracks developer productivity impact. |
| Verification Success | 100% | Confidence that consumers can verify artifacts. |
| Audit Drift | ≤ 1% | Measures variance between SBOM inventories and deployed binaries. |

## Developer Experience Enhancements

- **Dual-path CI** – Pull requests exercise fast lint/test jobs, while release tags run the secure pipeline.
- **Non-Repro Sandbox** – Developers can run iterative builds locally without the hermetic restrictions.
- **Documentation** – `/docs/security/verify.md` walks through verification and troubleshooting.
- **Automation** – `./scripts/verify_release.sh` encapsulates the verification workflow for operators.

## Expected Outcomes

- ✅ Auditable trust chain from commit → artifact → consumer.
- ✅ Regulatory-ready provenance compliant with SLSA v3 requirements.
- ✅ Fast developer feedback with minimal disruption to the inner loop.
- ✅ Public verifiability without revealing sensitive internals.
