#!/usr/bin/env bash
# Start backend and frontend together.
#   ./run.sh         dev mode (vite + tornado)
#   ./run.sh build   build frontend/dist/, then run the backend
#
# NOTE: `build` compiles the frontend but Tornado does NOT serve dist/ -- the
# backend registers API routes only, no static-file handler. Serve dist/ with a
# real web server and proxy the API paths to :8889.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ -f .env ]; then
    echo "Loading .env"
    set -a
    # shellcheck disable=SC1091
    . ./.env
    set +a
else
    echo "Warning: .env not found. Copy .env.example to .env, configure F5_ENVIRONMENTS_FILE or legacy F5_* vars, and add FERNET_KEY (or FERNET_KEY_FILE) to enable the read-only cache pre-warm + cert-replace API." >&2
fi

env_config_file="${F5_ENVIRONMENTS_FILE:-f5_environments.json}"
if [ "${env_config_file#/}" = "$env_config_file" ]; then
    env_config_file="$SCRIPT_DIR/$env_config_file"
fi

has_environment_file=false
if [ -f "$env_config_file" ]; then
    has_environment_file=true
fi

has_legacy_pair=false
if [ -n "${F5_DMZ_URL:-}" ] && [ -n "${F5_LAN_URL:-}" ]; then
    has_legacy_pair=true
fi

if [ "$has_environment_file" = false ] && [ "$has_legacy_pair" = false ]; then
    echo "Error: no F5 environment configuration found. Create $env_config_file with scripts/configure_environments.py or set legacy F5_DMZ_URL/F5_LAN_URL values in .env." >&2
    exit 1
fi

PORTAL="$SCRIPT_DIR/frontend"

if [ "${1:-}" = "build" ]; then
    echo "Building frontend..."
    (cd "$PORTAL" && npm run build)
    echo "Starting backend..."
    exec python3 app.py
fi

# Dev mode: run backend + frontend; trap to clean up both
echo "Starting Tornado backend on :8889..."
python3 app.py &
BACKEND_PID=$!
echo "  backend pid=$BACKEND_PID"

cleanup() {
    echo ""
    echo "Stopping..."
    kill "$BACKEND_PID" 2>/dev/null || true
    kill "$FRONTEND_PID" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

sleep 2
echo "Starting Vite frontend on :8080..."
(cd "$PORTAL" && npm run dev) &
FRONTEND_PID=$!

wait
