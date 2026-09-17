#!/usr/bin/env node
/**
 * Operational MVP smoke: Authority health/ready, admin register, challenge/authorize.
 * Exit nonzero on failure. Does not weaken crypto.
 *
 * Env:
 *   TDCP_AUTHORITY_URL (default http://127.0.0.1:8787)
 *   TDCP_AUTHORITY_ADMIN_TOKEN (or .mvp/admin-token)
 */
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

function readAdminToken() {
  if (process.env.TDCP_AUTHORITY_ADMIN_TOKEN?.trim()) {
    return process.env.TDCP_AUTHORITY_ADMIN_TOKEN.trim();
  }
  const p = join(ROOT, '.mvp', 'admin-token');
  if (existsSync(p)) {
    return readFileSync(p, 'utf8').trim();
  }
  return 'local-dev-only-change-me';
}

const BASE = (process.env.TDCP_AUTHORITY_URL || 'http://127.0.0.1:8787').replace(/\/$/, '');
const TOKEN = readAdminToken();

let failed = 0;

function ok(label) {
  console.log(`  ✓ ${label}`);
}
function fail(label, detail) {
  failed += 1;
  console.error(`  ✗ ${label}${detail ? `: ${detail}` : ''}`);
}

async function json(method, path, body, opts = {}) {
  const headers = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (opts.admin) headers.authorization = `Bearer ${TOKEN}`;
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: Object.keys(headers).length ? headers : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let parsed = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = { _raw: text };
  }
  return { res, parsed };
}

async function main() {
  console.log(`[smoke:mvp] Authority ${BASE}`);

  // 1) health
  {
    const { res, parsed } = await json('GET', '/health');
    if (res.ok && parsed?.ok) ok('GET /health');
    else fail('GET /health', `${res.status} ${JSON.stringify(parsed)}`);
  }

  // 2) ready
  {
    const { res, parsed } = await json('GET', '/ready');
    if (res.ok && parsed?.ready) ok('GET /ready');
    else fail('GET /ready', `${res.status} ${JSON.stringify(parsed)}`);
  }

  // 3) metrics (best-effort parse)
  {
    const res = await fetch(`${BASE}/metrics`);
    const text = await res.text();
    if (res.ok && text.includes('tdcp_authority_')) ok('GET /metrics');
    else fail('GET /metrics', `${res.status}`);
  }

  const docId = `DOC-SMOKE-${Date.now()}`;
  const pkgId = `PKG-SMOKE-${Date.now()}`;

  // 4) admin register with Bearer
  {
    const { res, parsed } = await json(
      'POST',
      '/v1/documents/register',
      {
        documentId: docId,
        packageId: pkgId,
        policyLevel: 'STANDARD',
        allowExtraction: true,
        createdAt: Date.now(),
      },
      { admin: true }
    );
    if (res.ok && parsed?.wrapSecretBase64) ok('POST /v1/documents/register (admin Bearer)');
    else fail('admin register', `${res.status} ${JSON.stringify(parsed)}`);
  }

  // 5) challenge + authorize happy path
  let challenge;
  {
    const { res, parsed } = await json('POST', '/v1/challenge');
    if (res.ok && parsed?.challenge) {
      challenge = parsed.challenge;
      ok('POST /v1/challenge');
    } else {
      fail('challenge', `${res.status} ${JSON.stringify(parsed)}`);
    }
  }

  if (challenge) {
    const { res, parsed } = await json('POST', '/v1/authorize', {
      requestId: 'REQ-SMOKE',
      documentId: docId,
      packageId: pkgId,
      deviceId: 'DEV-SMOKE',
      credentialId: 'CRED-SMOKE',
      operationId: `OP-SMOKE-${Date.now()}`,
      challenge,
      requestedOperation: 'READ',
      timestamp: Date.now(),
    });
    if (res.ok && parsed?.granted === true && parsed?.grant) {
      ok('POST /v1/authorize (granted)');
    } else {
      fail(
        'authorize happy path',
        `${res.status} granted=${parsed?.granted} code=${parsed?.rejectionCode || ''} ${parsed?.rejectionReason || ''}`
      );
    }
  }

  if (failed > 0) {
    console.error(`[smoke:mvp] FAILED (${failed} check(s))`);
    process.exit(1);
  }
  console.log('[smoke:mvp] OK');
}

main().catch((err) => {
  console.error('[smoke:mvp] FATAL', err);
  process.exit(1);
});
