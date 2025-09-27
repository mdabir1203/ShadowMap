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

case "$BOM_BASENAME" in
  *.json)
    BOM_EXTENSION="json"
    ;;
  *.xml)
    BOM_EXTENSION="xml"
    ;;
  *)
    BOM_EXTENSION="json"
    BOM_BASENAME="$BOM_BASENAME.json"
    BOM_PATH="$BOM_DIR/$BOM_BASENAME"
    ;;
esac

BOM_STEM="${BOM_BASENAME%.*}"

if [[ -z "$BOM_STEM" ]]; then
  echo "SBOM filename must include a base name (got '$BOM_BASENAME')." >&2
  exit 1
fi

if [[ -n "$REPORT_FILENAME" ]]; then
  if [[ "$REPORT_FILENAME" = /* ]]; then
    REPORT_PATH="$REPORT_FILENAME"
  else
    REPORT_PATH="$PWD/$REPORT_FILENAME"
  fi
  REPORT_DIR="$(dirname "$REPORT_PATH")"
  mkdir -p "$REPORT_DIR"
else
  REPORT_PATH=""
fi

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

# Generate the SBOM and move it to the requested destination (defaults to the CWD)
mkdir -p "$BOM_DIR"

GENERATED_NAME="$BOM_STEM.$BOM_EXTENSION"
GENERATED_PATH="$PWD/$GENERATED_NAME"

rm -f "$GENERATED_PATH"

cargo cyclonedx \
  --format "$BOM_EXTENSION" \
  --spec-version 1.5 \
  --all-features \
  --override-filename "$BOM_STEM"

if [[ ! -f "$GENERATED_PATH" ]]; then
  echo "cargo-cyclonedx did not produce $GENERATED_PATH" >&2
  exit 1
fi

if [[ "$GENERATED_PATH" != "$BOM_PATH" ]]; then
  mv "$GENERATED_PATH" "$BOM_PATH"
fi

echo "Generated SBOM at $BOM_PATH"

# Scan SBOM with Grype
if [[ -n "$REPORT_PATH" ]]; then
  grype "sbom:$BOM_PATH" -o json --file "$REPORT_PATH"
  echo "Stored vulnerability report at $REPORT_PATH"
else
  grype "sbom:$BOM_PATH"
fi

