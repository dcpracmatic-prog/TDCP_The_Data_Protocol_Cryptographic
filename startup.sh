#!/usr/bin/env bash
# Compatibility wrapper used by some sandboxes. Prefer: ./scripts/start.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
PORT="${PORT:-8080}"
URL="http://127.0.0.1:${PORT}/"

if curl -sf -o /dev/null --max-time 2 "$URL"; then
  echo "$URL"
  exit 0
fi

if [[ ! -d node_modules ]]; then
  npm install
fi

npm run dev >/tmp/tdcp-dev.log 2>&1 &
for _ in $(seq 1 60); do
  if curl -sf -o /dev/null --max-time 2 "$URL"; then
    echo "$URL"
    exit 0
  fi
  sleep 0.5
done
echo "[startup] timed out waiting for $URL (see /tmp/tdcp-dev.log)" >&2
echo "$URL"
exit 0
