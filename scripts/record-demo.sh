#!/usr/bin/env bash
# Re-record docs/assets/demo.gif from the published linchpin v0.2.1 package (--demo only).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/linchpin-demo-XXXXXX")"
VENV="$STAGE/venv"
WORK="$STAGE/work"

cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

command -v vhs >/dev/null || { echo "vhs is required" >&2; exit 1; }
command -v ttyd >/dev/null || { echo "ttyd is required by vhs" >&2; exit 1; }

mkdir -p "$WORK"
cp "$ROOT/scripts/demo.tape" "$WORK/demo.tape"

python3 -m venv "$VENV"
"$VENV/bin/python" -m pip install -q "git+https://github.com/chriswayneh/linchpin.git@v0.2.1"

export LINCHPIN_BIN_DIR="$VENV/bin"
export LINCHPIN_DEMO_HOME="$WORK"
export PATH="$LINCHPIN_BIN_DIR:$PATH"

# Offline sanity: --demo must work with no IdP or app credentials.
unset OKTA_TOKEN OKTA_API_TOKEN AZURE_CLIENT_ID AZURE_CLIENT_SECRET \
  BBWARDEN_TOKEN CROWD_PASSWORD ENTRA_TOKEN || true
"$VENV/bin/linchpin" --version >/dev/null
"$VENV/bin/linchpin" signals --demo >/dev/null

( cd "$WORK" && vhs demo.tape )

mkdir -p "$ROOT/docs/assets"
cp "$WORK/demo.gif" "$ROOT/docs/assets/demo.gif"
echo "Wrote $ROOT/docs/assets/demo.gif"
