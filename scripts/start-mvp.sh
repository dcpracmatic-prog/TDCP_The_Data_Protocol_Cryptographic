#!/usr/bin/env bash
# One-command operational MVP: Authority (:8787) + Web (:8080) with demo mode.
# Does NOT claim HSM. Ctrl+C or ./scripts/stop-mvp.sh to stop.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MVP_DIR="$ROOT/.mvp"
AUTHORITY_PORT="${TDCP_AUTHORITY_PORT:-8787}"
WEB_PORT="${PORT:-8080}"
DATA_DIR="${TDCP_AUTHORITY_DATA_DIR:-$ROOT/data/authority}"
ADMIN_TOKEN="${TDCP_AUTHORITY_ADMIN_TOKEN:-}"

mkdir -p "$MVP_DIR" "$DATA_DIR"

if [[ ! -d node_modules ]]; then
  echo "[mvp] npm install..."
  npm install
fi

# Local admin token if missing (persisted under .mvp/ for smoke + restart)
if [[ -z "$ADMIN_TOKEN" ]]; then
  if [[ -f "$MVP_DIR/admin-token" ]]; then
    ADMIN_TOKEN="$(cat "$MVP_DIR/admin-token")"
  else
    if command -v openssl >/dev/null 2>&1; then
      ADMIN_TOKEN="$(openssl rand -hex 24)"
    else
      ADMIN_TOKEN="mvp-local-$(date +%s)-change-me"
    fi
    printf '%s' "$ADMIN_TOKEN" > "$MVP_DIR/admin-token"
    chmod 600 "$MVP_DIR/admin-token" 2>/dev/null || true
  fi
fi
export TDCP_AUTHORITY_ADMIN_TOKEN="$ADMIN_TOKEN"
export TDCP_SIGNING_BACKEND="${TDCP_SIGNING_BACKEND:-file}"
export TDCP_AUTHORITY_ADMIN_AUTH="${TDCP_AUTHORITY_ADMIN_AUTH:-token}"
export TDCP_AUTHORITY_PORT="$AUTHORITY_PORT"
export TDCP_AUTHORITY_DATA_DIR="$DATA_DIR"
export TDCP_AUTHORITY_URL="http://127.0.0.1:${AUTHORITY_PORT}"
export VITE_TDCP_AUTHORITY_URL="$TDCP_AUTHORITY_URL"
export VITE_TDCP_AUTHORITY_ADMIN_TOKEN="$ADMIN_TOKEN"
export TDCP_DEMO_MODE=1
export VITE_TDCP_DEMO_MODE=1
export VITE_AUTH_ENABLED="${VITE_AUTH_ENABLED:-false}"
export PORT="$WEB_PORT"

# Stop leftovers from a previous MVP run
if [[ -f "$MVP_DIR/authority.pid" ]]; then
  OLD_PID="$(cat "$MVP_DIR/authority.pid" 2>/dev/null || true)"
  if [[ -n "${OLD_PID:-}" ]] && kill -0 "$OLD_PID" 2>/dev/null; then
    echo "[mvp] stopping previous Authority pid=$OLD_PID"
    kill "$OLD_PID" 2>/dev/null || true
    sleep 0.5
  fi
  rm -f "$MVP_DIR/authority.pid"
fi
if [[ -f "$MVP_DIR/web.pid" ]]; then
  OLD_WEB="$(cat "$MVP_DIR/web.pid" 2>/dev/null || true)"
  if [[ -n "${OLD_WEB:-}" ]] && kill -0 "$OLD_WEB" 2>/dev/null; then
    echo "[mvp] stopping previous Web pid=$OLD_WEB"
    kill "$OLD_WEB" 2>/dev/null || true
    sleep 0.5
  fi
  rm -f "$MVP_DIR/web.pid"
fi

echo "[mvp] starting Authority on :${AUTHORITY_PORT} (data: $DATA_DIR)..."
node --experimental-strip-types server/authority/index.ts >"$MVP_DIR/authority.log" 2>&1 &
AUTH_PID=$!
echo "$AUTH_PID" > "$MVP_DIR/authority.pid"

cleanup() {
  echo ""
  echo "[mvp] shutting down..."
  if [[ -n "${WEB_PID:-}" ]]; then
    kill "$WEB_PID" 2>/dev/null || true
  fi
  if [[ -n "${AUTH_PID:-}" ]]; then
    kill "$AUTH_PID" 2>/dev/null || true
  fi
  rm -f "$MVP_DIR/authority.pid" "$MVP_DIR/web.pid"
}
trap cleanup EXIT INT TERM

# Wait for /health + /ready
READY=0
for i in $(seq 1 40); do
  if curl -sf "http://127.0.0.1:${AUTHORITY_PORT}/health" >/dev/null 2>&1 \
    && curl -sf "http://127.0.0.1:${AUTHORITY_PORT}/ready" >/dev/null 2>&1; then
    READY=1
    break
  fi
  if ! kill -0 "$AUTH_PID" 2>/dev/null; then
    echo "[mvp] Authority exited early. Log:"
    tail -n 40 "$MVP_DIR/authority.log" || true
    exit 1
  fi
  sleep 0.25
done

if [[ "$READY" != "1" ]]; then
  echo "[mvp] Authority did not become ready. Log:"
  tail -n 60 "$MVP_DIR/authority.log" || true
  exit 1
fi

echo "[mvp] Authority healthy."
echo "[mvp] starting Web on :${WEB_PORT} (demo mode)..."

npm run dev >"$MVP_DIR/web.log" 2>&1 &
WEB_PID=$!
echo "$WEB_PID" > "$MVP_DIR/web.pid"

# Wait for web to accept connections (best-effort)
for i in $(seq 1 60); do
  if curl -sf -o /dev/null --max-time 1 "http://127.0.0.1:${WEB_PORT}/" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$WEB_PID" 2>/dev/null; then
    echo "[mvp] Web exited early. Log:"
    tail -n 40 "$MVP_DIR/web.log" || true
    exit 1
  fi
  sleep 0.5
done

cat <<BANNER

╔══════════════════════════════════════════════════════════════╗
║  TDCP Operational MVP                                        ║
╠══════════════════════════════════════════════════════════════╣
║  Authority:  http://127.0.0.1:${AUTHORITY_PORT}/
║  Web UI:     http://127.0.0.1:${WEB_PORT}/
║                                                              ║
║  Demo entry: open Web → click                                 ║
║    «Continuar en modo demo (MVP)»                             ║
║  (no Firebase/Gemini; local session only — crypto intact)     ║
║                                                              ║
║  Admin token (local): stored in .mvp/admin-token              ║
║  Logs / pids: .mvp/                                           ║
║  Stop: Ctrl+C  or  ./scripts/stop-mvp.sh                      ║
╚══════════════════════════════════════════════════════════════╝

BANNER

# Keep foreground attached to web process
wait "$WEB_PID"
