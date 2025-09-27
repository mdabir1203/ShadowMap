#!/usr/bin/env bash
set -euo pipefail

BOM_FILENAME="${1:-bom.json}"
REPORT_FILENAME="${2:-}" # optional second arg for JSON report

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

if ! command_exists cargo; then
  echo "cargo is required to generate the SBOM." >&2
  exit 1
fi

if ! cargo cyclonedx --version >/dev/null 2>&1; then
  cat <<'MSG' >&2
cargo-cyclonedx is not installed.
Install it with: cargo install cargo-cyclonedx
MSG
  exit 1
fi

if ! command_exists grype; then
  cat <<'MSG' >&2
grype is not installed.
Install it with: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
MSG
  exit 1
fi

# Generate SBOM
cargo cyclonedx \
  --format json \
  --spec-version 1.5 \
  --all-features \
  --override-filename "$BOM_FILENAME"

echo "Generated SBOM at $BOM_FILENAME"

# Scan SBOM with Grype
if [[ -n "$REPORT_FILENAME" ]]; then
  grype "sbom:./$BOM_FILENAME" -o json --file "$REPORT_FILENAME"
  echo "Stored vulnerability report at $REPORT_FILENAME"
else
  grype "sbom:./$BOM_FILENAME"
fi

