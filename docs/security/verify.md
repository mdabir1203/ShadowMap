# Release Verification Guide

This guide walks security teams, regulators, and customers through verifying a ShadowMap release using the reproducible supply-chain controls.

## Prerequisites

Install the verification tooling (all available via Homebrew, apt, or GitHub releases):

- [`cosign`](https://github.com/sigstore/cosign) v2.2 or newer
- [`slsa-verifier`](https://github.com/slsa-framework/slsa-verifier) v2.4 or newer
- [`jq`](https://stedolan.github.io/jq/)
- `sha256sum` (Linux) or `shasum -a 256` (macOS)
- Optional: [`syft`](https://github.com/anchore/syft) or [`trivy`](https://github.com/aquasecurity/trivy) for deeper SBOM analysis

## Download the Release Bundle

From the GitHub Releases page download the following four files for the version you want to verify (replace `<VERSION>` with the tag, e.g. `v1.2.3`):

- `shadowmap-<VERSION>.tar.gz`
- `shadowmap-<VERSION>.sha256`
- `shadowmap-<VERSION>.intoto.jsonl`
- `shadowmap-<VERSION>.intoto.jsonl.sig`
- `shadowmap-<VERSION>.sbom.json`

Place them in a common directory along with the helper script from the repository:

```bash
curl -sSfL "https://raw.githubusercontent.com/YOUR-ORG/ShadowMap/<VERSION>/scripts/verify_release.sh" -o verify_release.sh
chmod +x verify_release.sh
```

## Run the Automated Verification

Execute the helper script with the version and base filename (omit extensions):

```bash
./verify_release.sh \
  --artifact shadowmap-<VERSION>.tar.gz \
  --checksum shadowmap-<VERSION>.sha256 \
  --provenance shadowmap-<VERSION>.intoto.jsonl \
  --signature shadowmap-<VERSION>.intoto.jsonl.sig \
  --sbom shadowmap-<VERSION>.sbom.json
```

The script performs the following steps:

1. Validates the cosign signature using keyless Rekor transparency log lookups.
2. Checks the DSSE SLSA provenance against the expected repository, tag, and workflow.
3. Recomputes SHA-256 digests of every artifact listed in the checksum file.
4. Confirms the checksum file is recorded as a material in the provenance statement.
5. Optionally (if `syft` is installed) compares the SBOM manifest to the compiled binary hash for drift detection.

All checks must pass for the script to exit successfully. A non-zero exit code indicates which step failed.

## Manual Verification (Optional)

For environments that cannot run scripts, replicate the flow manually:

```bash
# 1. Verify signature & transparency log
COSIGN_EXPERIMENTAL=1 cosign verify-blob \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/YOUR-ORG/ShadowMap/.github/workflows/slsa-release.yml@refs/tags/<VERSION>" \
  --bundle < shadowmap-<VERSION>.intoto.jsonl.sig \
  shadowmap-<VERSION>.intoto.jsonl

# 2. Validate SLSA provenance
slsa-verifier verify-artifact \
  --provenance shadowmap-<VERSION>.intoto.jsonl \
  --source-uri github.com/YOUR-ORG/ShadowMap \
  --branch main \
  --tag <VERSION> \
  --build-workflow-input github.com/YOUR-ORG/ShadowMap/.github/workflows/slsa-release.yml@refs/tags/<VERSION> \
  shadowmap-<VERSION>.tar.gz

# 3. Check checksums
sha256sum --check shadowmap-<VERSION>.sha256

# 4. Inspect SBOM
jq '.metadata, .components[] | {name, version, licenses}' shadowmap-<VERSION>.sbom.json | less
```

## Troubleshooting

| Symptom | Resolution |
| --- | --- |
| `cosign: certificate invalid` | Confirm system clock is accurate and the signature was generated within the 10 minute OIDC validity window. |
| `slsa-verifier: predicate mismatch` | Ensure the downloaded provenance file matches the target artifact and tag. Delete and redownload assets if necessary. |
| `sha256sum: WARNING: 1 computed checksum did NOT match` | The artifact may be corrupted or tampered with. Re-download; if the issue persists contact ShadowMap security. |
| SBOM drift detected | Run the reproducibility build locally (see README) and share the rebuild hash comparison with the security team. |

## Continuous Improvement

Verification logs should be archived with your compliance evidence. Open issues with `security` and `supply-chain` labels if you discover a reproducibility or provenance regression.
