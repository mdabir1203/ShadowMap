#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<USAGE
Usage: $0 --artifact <path> --checksum <path> --provenance <path> --signature <path> --sbom <path>

Required flags:
  --artifact     Path to the release archive to verify.
  --checksum     Path to the sha256 checksum file shipped with the release.
  --provenance   Path to the DSSE SLSA provenance JSONL.
  --signature    Path to the cosign bundle/signature for the provenance file.
  --sbom         Path to the CycloneDX SBOM JSON.

Environment overrides:
  EXPECTED_IDENTITY_REGEXP  Overrides the cosign certificate identity check.
  EXPECTED_ISSUER           Overrides the OIDC issuer (default: https://token.actions.githubusercontent.com).
  EXPECTED_SOURCE_URI       Overrides the repository used for SLSA verification.
  EXPECTED_TAG              Forces a specific git tag if the artifact name is not canonical.
  EXPECTED_BUILDER_ID       Overrides the expected builder identity (default: SLSA generic builder v2.0.1).
USAGE
}

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command '$1' not found in PATH" >&2
    exit 1
  fi
}

ARTIFACT=""
CHECKSUM=""
PROVENANCE=""
SIGNATURE=""
SBOM=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifact)
      ARTIFACT="$2"
      shift 2
      ;;
    --checksum)
      CHECKSUM="$2"
      shift 2
      ;;
    --provenance)
      PROVENANCE="$2"
      shift 2
      ;;
    --signature)
      SIGNATURE="$2"
      shift 2
      ;;
    --sbom)
      SBOM="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$ARTIFACT" || -z "$CHECKSUM" || -z "$PROVENANCE" || -z "$SIGNATURE" || -z "$SBOM" ]]; then
  echo "error: missing required arguments" >&2
  usage
  exit 1
fi

require cosign
require slsa-verifier
require jq

if command -v sha256sum >/dev/null 2>&1; then
  SHA_CMD=(sha256sum)
else
  require shasum
  SHA_CMD=(shasum -a 256)
fi

IDENTITY_REGEXP=${EXPECTED_IDENTITY_REGEXP:-"https://github.com/.*/ShadowMap/.github/workflows/slsa-release.yml@refs/tags/.*"}
OIDC_ISSUER=${EXPECTED_ISSUER:-"https://token.actions.githubusercontent.com"}
SOURCE_URI=${EXPECTED_SOURCE_URI:-"github.com/YOUR-ORG/ShadowMap"}
BUILDER_ID=${EXPECTED_BUILDER_ID:-"https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.0.1"}

printf "[1/5] Verifying cosign signature and Rekor entry...\n"
COSIGN_EXPERIMENTAL=1 cosign verify-blob \
  --certificate-oidc-issuer "$OIDC_ISSUER" \
  --certificate-identity-regexp "$IDENTITY_REGEXP" \
  --bundle "$SIGNATURE" \
  "$PROVENANCE"

ARTIFACT_BASENAME=$(basename "$ARTIFACT")
SOURCE_TAG=${EXPECTED_TAG:-}
if [[ -z "$SOURCE_TAG" ]] && [[ "$ARTIFACT_BASENAME" =~ shadowmap-(.+)\.tar\.gz ]]; then
  SOURCE_TAG="${BASH_REMATCH[1]}"
fi

printf "[2/5] Validating SLSA provenance for artifact %s...\n" "$ARTIFACT"
SLSA_CMD=(slsa-verifier verify-artifact --provenance "$PROVENANCE" --source-uri "$SOURCE_URI" --builder-id "$BUILDER_ID" "$ARTIFACT")
if [[ -n "$SOURCE_TAG" ]]; then
  SLSA_CMD+=(--source-tag "$SOURCE_TAG")
fi
"${SLSA_CMD[@]}"

printf "[3/5] Checking checksums from %s...\n" "$CHECKSUM"
"${SHA_CMD[@]}" --check "$CHECKSUM"

printf "[4/5] Ensuring provenance lists the checksum manifest...\n"
CHECKSUM_BASENAME=$(basename "$CHECKSUM")
if ! jq -e --arg target "$CHECKSUM_BASENAME" '.predicate.materials[]?.uri | select(endswith($target))' "$PROVENANCE" >/dev/null; then
  echo "error: checksum manifest $CHECKSUM_BASENAME not declared in provenance materials" >&2
  exit 1
fi

printf "[5/5] Inspecting SBOM integrity metadata...\n"
ARTIFACT_DIGEST=$("${SHA_CMD[@]}" "$ARTIFACT" | awk '{print $1}')
SBOM_DIGEST=$(jq -r '.metadata.component.hashes[]? | select((.alg // .algorithm | ascii_upcase) == "SHA-256") | .content' "$SBOM" | head -n 1)
if [[ -n "$SBOM_DIGEST" ]]; then
  if [[ "$ARTIFACT_DIGEST" != "$SBOM_DIGEST" ]]; then
    echo "warning: SBOM embedded digest ($SBOM_DIGEST) does not match artifact digest ($ARTIFACT_DIGEST)" >&2
    exit 1
  fi
else
  echo "note: SBOM does not embed artifact hash metadata; skipping digest comparison" >&2
fi

if command -v syft >/dev/null 2>&1; then
  echo "syft detected; generating on-the-fly SBOM snapshot for drift comparison..."
  TEMP_SBOM=$(mktemp)
  syft "file:$ARTIFACT" -o cyclonedx-json > "$TEMP_SBOM"
  diff --unified <(jq 'del(.metadata.tools)' "$SBOM") <(jq 'del(.metadata.tools)' "$TEMP_SBOM") || {
    echo "warning: SBOM drift detected between published SBOM and local syft scan" >&2
    rm -f "$TEMP_SBOM"
    exit 1
  }
  rm -f "$TEMP_SBOM"
fi

echo "All verification steps passed."
