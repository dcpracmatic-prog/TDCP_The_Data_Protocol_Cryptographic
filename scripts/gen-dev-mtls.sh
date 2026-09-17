#!/usr/bin/env bash
# Mint a local CA + server + client certs for Authority mTLS demos/tests.
# DEV ONLY — do not use these certs in production.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/data/mtls-dev}"
mkdir -p "$OUT"
cd "$OUT"

echo "[gen-dev-mtls] writing certs under $OUT"

# CA
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout ca.key -out ca.crt \
  -subj "/CN=TDCP-Dev-CA"

# Server (Authority HTTPS)
openssl req -newkey rsa:2048 -nodes \
  -keyout server.key -out server.csr \
  -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 825 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

# Client (admin)
openssl req -newkey rsa:2048 -nodes \
  -keyout client.key -out client.csr \
  -subj "/CN=tdcp-admin-dev"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 825

rm -f server.csr client.csr ca.srl

cat > env.snippet << SNIP
# Paste into .env for local mTLS Authority (DEV ONLY)
TDCP_AUTHORITY_ADMIN_AUTH=mtls
TDCP_AUTHORITY_TLS_CERT_FILE=$OUT/server.crt
TDCP_AUTHORITY_TLS_KEY_FILE=$OUT/server.key
TDCP_MTLS_CA_FILE=$OUT/ca.crt
TDCP_MTLS_ALLOWED_CNS=tdcp-admin-dev
# Optional: also require OIDC with oidc+mtls
# TDCP_AUTHORITY_ADMIN_AUTH=oidc+mtls
SNIP

echo "[gen-dev-mtls] done."
echo "[gen-dev-mtls] CA:     $OUT/ca.crt"
echo "[gen-dev-mtls] server: $OUT/server.crt + server.key"
echo "[gen-dev-mtls] client: $OUT/client.crt + client.key (CN=tdcp-admin-dev)"
echo "[gen-dev-mtls] env snippet: $OUT/env.snippet"
echo
echo "curl example:"
echo "  curl --cacert $OUT/ca.crt --cert $OUT/client.crt --key $OUT/client.key \\"
echo "    https://127.0.0.1:8787/v1/documents"
