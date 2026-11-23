#!/usr/bin/env bash
#
# Build, test, and stage-publish acs-component-search to the npm registry,
# then open the staged-packages page in a browser on success.
#
# Usage:
#   ./stage-publish.sh            # build, test, stage publish current version
#   ./stage-publish.sh patch      # bump patch version first (also: minor | major)
#
# Any failing step aborts the script (set -e) and the browser is NOT opened.

set -euo pipefail

STAGE_URL="https://www.npmjs.com/settings/devsops/staged-packages"

# Run from the directory this script lives in, regardless of the caller's CWD.
cd "$(dirname "$0")"

bump="${1:-}"
if [ -n "$bump" ]; then
  echo "[1/4] Bumping version: $bump"
  npm version "$bump" --no-git-tag-version
else
  echo "[1/4] Skipping version bump (pass patch|minor|major to bump)"
fi

echo "[2/4] Building (npm install)..."
npm install --no-audit --no-fund

echo "[3/4] Testing..."
npm test

echo "[4/4] Stage publishing..."
npm stage publish

echo "Stage publish succeeded. Opening $STAGE_URL"
if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$STAGE_URL"
elif command -v open >/dev/null 2>&1; then
  open "$STAGE_URL"
elif command -v powershell.exe >/dev/null 2>&1; then
  powershell.exe -NoProfile -Command "Start-Process '$STAGE_URL'"
elif command -v cmd.exe >/dev/null 2>&1; then
  cmd.exe /c start "" "$STAGE_URL"
else
  echo "Could not detect a browser opener; open this URL manually:"
  echo "  $STAGE_URL"
fi
