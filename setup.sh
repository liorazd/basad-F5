#!/usr/bin/env bash
# F5 VIP Portal — first-time setup (bash).
#
# 1. Install Python deps from requirements.txt
# 2. Install frontend deps under frontend/
# 3. Hand off to scripts/install.py for the interactive .env + F5 wizard
#
# Re-running is safe: install.py keeps your existing answers.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Error: $1 is not on PATH. Install it and re-run." >&2
        exit 1
    fi
}

echo "=== Checking prerequisites ==="
need python3
need npm
python3 --version
node --version
npm --version

echo ""
echo "=== Installing Python dependencies ==="
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

echo ""
echo "=== Installing npm dependencies ==="
PORTAL="$SCRIPT_DIR/frontend"
if [ ! -d "$PORTAL" ]; then
    echo "Portal folder not found at $PORTAL" >&2
    exit 1
fi
(
    cd "$PORTAL"
    if [ -f package-lock.json ]; then
        npm ci || npm install --legacy-peer-deps
    else
        npm install || npm install --legacy-peer-deps
    fi
)

echo ""
echo "=== Running interactive installer ==="
python3 "$SCRIPT_DIR/scripts/install.py"
