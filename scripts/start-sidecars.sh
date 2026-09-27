#!/usr/bin/env bash
# Start free self-hosted CSG + Smart Token Prod sidecars for TDCP pre-prod.
# Does not vendor upstream trees — expects clones or pip install from git.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STP_DIR="${SMART_TOKEN_REPO:-$ROOT/../Smart-Token-Prod}"
# Also accept artifacts checkout layout used in this workspace
if [[ ! -d "$STP_DIR" && -d /home/workdir/artifacts/Smart-Token-Prod ]]; then
  STP_DIR=/home/workdir/artifacts/Smart-Token-Prod
fi

API_KEY="${SMART_TOKEN_API_KEY:-$(openssl rand -hex 32)}"
STP_PORT="${SMART_TOKEN_PORT:-8000}"
CSG_PORT="${CSG_PORT:-8010}"

echo "==> CSG sidecar (TDCP server/csg-sidecar) on :$CSG_PORT"
export CSG_PORT CSG_DATA_DIR="${CSG_DATA_DIR:-$ROOT/data/csg-sidecar}"
python3 "$ROOT/server/csg-sidecar/main.py" &
CSG_PID=$!
echo "    PID=$CSG_PID  CSG_SEAL_URL=http://127.0.0.1:$CSG_PORT"

if [[ -d "$STP_DIR/api" ]]; then
  echo "==> Smart Token Prod API from $STP_DIR on :$STP_PORT"
  echo "    SMART_TOKEN_API_KEY=$API_KEY"
  (
    cd "$STP_DIR"
    export SMART_TOKEN_API_KEY="$API_KEY"
    export SMART_TOKEN_STORAGE_BACKEND="${SMART_TOKEN_STORAGE_BACKEND:-local}"
    # Prefer venv if present
    if [[ -x .venv/bin/uvicorn ]]; then
      .venv/bin/uvicorn api.main:app --host 127.0.0.1 --port "$STP_PORT"
    else
      uvicorn api.main:app --host 127.0.0.1 --port "$STP_PORT"
    fi
  ) &
  STP_PID=$!
  echo "    PID=$STP_PID  SMART_TOKEN_API_URL=http://127.0.0.1:$STP_PORT"
else
  echo "!! Smart-Token-Prod not found at $STP_DIR"
  echo "   git clone https://github.com/dcpracmatic-prog/Smart-Token-Prod.git"
  echo "   cd Smart-Token-Prod && python3 -m venv .venv && .venv/bin/pip install -e '.[dev]' -r api/requirements.txt"
  STP_PID=""
fi

echo ""
echo "TDCP env (export before npm run dev / start-mvp):"
echo "  export VITE_CSG_SEAL_URL=http://127.0.0.1:$CSG_PORT"
echo "  export CSG_SEAL_URL=http://127.0.0.1:$CSG_PORT"
if [[ -n "$STP_PID" ]]; then
  echo "  export VITE_SMART_TOKEN_API_URL=http://127.0.0.1:$STP_PORT"
  echo "  export VITE_SMART_TOKEN_API_KEY=$API_KEY"
  echo "  export SMART_TOKEN_API_URL=http://127.0.0.1:$STP_PORT"
  echo "  export SMART_TOKEN_API_KEY=$API_KEY"
fi
echo ""
echo "Ctrl+C stops this script's background jobs only if you foreground wait."
echo "PIDs: CSG=$CSG_PID STP=${STP_PID:-none}"

wait
