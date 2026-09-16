#!/usr/bin/env bash
# Start TDCP Web (Vite) on http://127.0.0.1:8080/
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${PORT:-8080}"
URL="http://127.0.0.1:${PORT}/"

if [[ ! -d node_modules ]]; then
  echo "[start] node_modules missing — running npm install..."
  npm install
fi

if curl -sf -o /dev/null --max-time 2 "$URL"; then
  echo "[start] already running at $URL"
  echo "$URL"
  exit 0
fi

echo "[start] launching npm run dev (port ${PORT})..."
echo "[start] open: $URL"
exec npm run dev
