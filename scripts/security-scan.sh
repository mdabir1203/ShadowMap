#!/usr/bin/env bash
set -euo pipefail

FAIL_ON_LEVEL="medium"
ENABLE_REACHABILITY=0
FUNCTION_MAP=""
SOURCE_ROOT=""

POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --fail-on)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --fail-on" >&2
        exit 1
      fi
      FAIL_ON_LEVEL="$2"
      shift 2
      ;;
    --enable-reachability-analysis)
      ENABLE_REACHABILITY=1
      shift
      ;;
    --function-map)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --function-map" >&2
        exit 1
      fi
      FUNCTION_MAP="$2"
      shift 2
      ;;
    --source-root)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --source-root" >&2
        exit 1
      fi
      SOURCE_ROOT="$2"
      shift 2
      ;;
    --)
      shift
      while [[ $# -gt 0 ]]; do
        POSITIONAL+=("$1")
        shift
      done
      ;;
    -*)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done

if [[ -z "$SOURCE_ROOT" ]]; then
  if SOURCE_ROOT=$(git rev-parse --show-toplevel 2>/dev/null); then
    :
  else
    SOURCE_ROOT="$PWD"
  fi
fi

set -- "${POSITIONAL[@]}"

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

REPORT_IS_TEMP=0
if [[ -n "$REPORT_FILENAME" ]]; then
  if [[ "$REPORT_FILENAME" = /* ]]; then
    REPORT_PATH="$REPORT_FILENAME"
  else
    REPORT_PATH="$PWD/$REPORT_FILENAME"
  fi
  REPORT_DIR="$(dirname "$REPORT_PATH")"
  mkdir -p "$REPORT_DIR"
else
  REPORT_PATH="$(mktemp)"
  REPORT_IS_TEMP=1
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
GRYPE_CMD=(grype "sbom:$BOM_PATH" -o json --file "$REPORT_PATH")
if [[ -n "$FAIL_ON_LEVEL" ]]; then
  GRYPE_CMD+=(--fail-on "$FAIL_ON_LEVEL")
fi

echo "Running: ${GRYPE_CMD[*]}"
set +e
"${GRYPE_CMD[@]}"
GRYPE_EXIT=$?
set -e

if [[ ! -f "$REPORT_PATH" ]]; then
  if [[ "$GRYPE_EXIT" -ne 0 ]]; then
    echo "grype failed to produce a report (exit code $GRYPE_EXIT)." >&2
    exit "$GRYPE_EXIT"
  fi
  echo "grype did not create a report file; skipping post-processing." >&2
  exit 1
fi

POSTPROCESS_ARGS=(--report "$REPORT_PATH" --fail-on "$FAIL_ON_LEVEL")
if [[ "$ENABLE_REACHABILITY" -eq 1 ]]; then
  POSTPROCESS_ARGS+=(--enable-reachability-analysis --source-root "$SOURCE_ROOT")
  if [[ -n "$FUNCTION_MAP" ]]; then
    POSTPROCESS_ARGS+=(--function-map "$FUNCTION_MAP")
  fi
fi

python3 "$(dirname "$0")/grype-postprocess.py" --grype-exit-code "$GRYPE_EXIT" "${POSTPROCESS_ARGS[@]}"
SCAN_RESULT=$?

if [[ "$REPORT_IS_TEMP" -eq 0 ]]; then
  echo "Stored vulnerability report at $REPORT_PATH"
else
  rm -f "$REPORT_PATH"
fi

exit "$SCAN_RESULT"
