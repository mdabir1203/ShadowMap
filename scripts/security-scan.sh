#!/usr/bin/env bash
set -euo pipefail

BOM_FILENAME="${1:-bom.json}"
REPORT_FILENAME="${2:-}" # optional second arg for JSON report

if [[ "$BOM_FILENAME" = /* ]]; then
  BOM_PATH="$BOM_FILENAME"
else
  BOM_PATH="$PWD/$BOM_FILENAME"
fi
BOM_DIR="$(dirname "$BOM_PATH")"
BOM_BASENAME="$(basename "$BOM_PATH")"

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

# Generate the SBOM and copy it to the requested destination (defaults to the CWD)
mkdir -p "$BOM_DIR"

cargo cyclonedx \
  --format json \
  --spec-version 1.5 \
  --all-features \
  --override-filename "$BOM_BASENAME"

SOURCE_DIR="${CARGO_TARGET_DIR:-target}/cyclonedx"
SOURCE_PATH="$SOURCE_DIR/$BOM_BASENAME"

if [[ ! -f "$SOURCE_PATH" ]]; then
  echo "cargo-cyclonedx did not produce $SOURCE_PATH" >&2
  exit 1
fi

SOURCE_DIR_ABS="$(cd "$(dirname "$SOURCE_PATH")" && pwd)"
SOURCE_PATH="$SOURCE_DIR_ABS/$BOM_BASENAME"

if [[ "$SOURCE_PATH" != "$BOM_PATH" ]]; then
  cp "$SOURCE_PATH" "$BOM_PATH"
fi

echo "Generated SBOM at $BOM_PATH"

# Scan SBOM with Grype
if [[ -n "$REPORT_FILENAME" ]]; then
  grype "sbom:$BOM_PATH" -o json --file "$REPORT_FILENAME"
  echo "Stored vulnerability report at $REPORT_FILENAME"
else
  grype "sbom:$BOM_PATH"
fi

