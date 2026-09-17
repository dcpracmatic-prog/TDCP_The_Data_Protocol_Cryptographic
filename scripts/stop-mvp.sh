#!/usr/bin/env bash
# Stop MVP stack started by ./scripts/start-mvp.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MVP_DIR="$ROOT/.mvp"

stop_pidfile() {
  local name="$1"
  local file="$MVP_DIR/${name}.pid"
  if [[ -f "$file" ]]; then
    local pid
    pid="$(cat "$file" 2>/dev/null || true)"
    if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
      echo "[mvp] stopping $name pid=$pid"
      kill "$pid" 2>/dev/null || true
      sleep 0.3
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$file"
  fi
}

stop_pidfile web
stop_pidfile authority

# Also kill anything still bound to default ports (best-effort, local only)
for port in 8787 8080; do
  if command -v lsof >/dev/null 2>&1; then
    pids="$(lsof -ti ":$port" 2>/dev/null || true)"
    if [[ -n "${pids:-}" ]]; then
      echo "[mvp] freeing :$port ($pids)"
      # shellcheck disable=SC2086
      kill $pids 2>/dev/null || true
    fi
  fi
done

echo "[mvp] stopped. (admin token in .mvp/admin-token kept for next start)"
