#!/usr/bin/env bash
set -euo pipefail

# First-principles pipeline:
# 1) Compile the composition (structure is valid).
# 2) Render the video (runtime is valid).
# 3) Verify the artifact exists (delivery is valid).

echo "[1/3] Building Remotion bundle..."
yarn build

echo "[2/3] Rendering MP4..."
if yarn render; then
  echo "Render succeeded."
else
  echo "Render failed. If your environment cannot download Chrome Headless Shell,"
  echo "set REMOTION_CHROME_EXECUTABLE to a local Chrome/Chromium binary and retry."
  exit 1
fi

echo "[3/3] Verifying downloadable artifact..."
if [[ -f out/shadowmap-tech-explainer.mp4 ]]; then
  ls -lh out/shadowmap-tech-explainer.mp4
  shasum -a 256 out/shadowmap-tech-explainer.mp4
  echo "Artifact ready: remotion-explainer/out/shadowmap-tech-explainer.mp4"
else
  echo "Expected output missing: out/shadowmap-tech-explainer.mp4"
  exit 1
fi
