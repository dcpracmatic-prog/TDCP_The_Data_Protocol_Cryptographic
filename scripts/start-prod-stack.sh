#!/usr/bin/env bash
# Start Authority (durable MVP) + web demo UI for local prod-stack exercises.
# Does NOT claim HSM. Prefer docker compose when available.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

AUTHORITY_PORT="${TDCP_AUTHORITY_PORT:-8787}"
WEB_PORT="${PORT:-8080}"
DATA_DIR="${TDCP_AUTHORITY_DATA_DIR:-$ROOT/data/authority}"
# Local default only — override in real deploys
export TDCP_AUTHORITY_ADMIN_TOKEN="${TDCP_AUTHORITY_ADMIN_TOKEN:-local-dev-only-change-me}"
export TDCP_SIGNING_BACKEND="${TDCP_SIGNING_BACKEND:-file}"
mkdir -p "$DATA_DIR"

if [[ ! -d node_modules ]]; then
  echo "[prod-stack] npm install..."
  npm install
fi

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  echo "[prod-stack] starting docker compose (authority + web)..."
  exec docker compose up --build
fi

echo "[prod-stack] docker compose unavailable — starting Authority + Vite locally"
echo "[prod-stack] Authority data: $DATA_DIR"

TDCP_AUTHORITY_PORT="$AUTHORITY_PORT" TDCP_AUTHORITY_DATA_DIR="$DATA_DIR" \
  node --experimental-strip-types server/authority/index.ts &
AUTH_PID=$!

cleanup() {
  kill "$AUTH_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Wait for health
for i in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:${AUTHORITY_PORT}/health" >/dev/null; then
    break
  fi
  sleep 0.5
done

export TDCP_AUTHORITY_URL="http://127.0.0.1:${AUTHORITY_PORT}"
export VITE_TDCP_AUTHORITY_URL="$TDCP_AUTHORITY_URL"
export VITE_TDCP_AUTHORITY_ADMIN_TOKEN="$TDCP_AUTHORITY_ADMIN_TOKEN"
export PORT="$WEB_PORT"

echo "[prod-stack] Authority: $TDCP_AUTHORITY_URL"
echo "[prod-stack] Web:       http://127.0.0.1:${WEB_PORT}/"
exec npm run dev
