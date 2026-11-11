#!/usr/bin/env node
/**
 * TDCP external signing sidecar — example (P0-2).
 *
 * A tiny HTTP signer the Authority talks to when
 * TDCP_SIGNING_BACKEND=external and TDCP_SIGNING_EXTERNAL_URL points here.
 *
 *   GET  /health         -> { "ok": true, "mode": "fake"|"kms" }
 *   GET  /v1/public-key  -> { "keyId", "publicKeySpkiBase64" }   (SPKI DER, base64)
 *   POST /v1/sign        -> { "canonical": "<utf8>" } in, { "signatureBase64" } out
 *                            (raw ECDSA P-256 signature r||s, 64 bytes, base64 —
 *                            the same bytes WebCrypto returns, so TDCP grant
 *                            verification works unchanged)
 *
 * Modes:
 *   fake (default) — ephemeral P-256 key generated in memory at startup.
 *     FOR TESTS AND LOCAL DEMO ONLY. The key is not a KMS key, it can be
 *     extracted from memory, and it vanishes on restart. Never production.
 *   kms — real AWS KMS. Needs @aws-sdk/client-kms installed in THIS
 *     sidecar's own directory (NOT a TDCP repo dependency — install it
 *     where you deploy the sidecar):
 *       npm install @aws-sdk/client-kms
 *     Env: AWS_KMS_KEY_ID (key ARN or alias, required), AWS_REGION.
 *     Credentials come from the standard AWS chain (env vars, ~/.aws,
 *     IAM role on the host). NEVER put credentials in this repo.
 *     KMS returns DER signatures; this sidecar converts DER -> raw r||s.
 *
 * Optional shared token: if SIDECAR_TOKEN is set, /v1/sign and
 * /v1/public-key require `Authorization: Bearer <token>` (set the same
 * value in TDCP_SIGNING_EXTERNAL_TOKEN on the Authority). /health stays open.
 *
 * Usage:
 *   node kms-signing-sidecar.mjs [--mode fake|kms] [--port 8011] [--host 127.0.0.1]
 *
 * This sidecar holds the ONLY copy of the signing key path. Keep it on the
 * same host / private network as the Authority (127.0.0.1 by default) and
 * put TLS / a reverse proxy in front of it if it ever leaves localhost.
 */

import { createServer } from 'node:http';

function argValue(argv, name, fallback) {
  const idx = argv.indexOf(name);
  if (idx >= 0 && argv[idx + 1]) return argv[idx + 1];
  return fallback;
}

const MODE = argValue(process.argv.slice(2), '--mode', process.env.SIDECAR_MODE || 'fake');
const PORT = Number(argValue(process.argv.slice(2), '--port', process.env.PORT || '8011'));
const HOST = argValue(process.argv.slice(2), '--host', process.env.HOST || '127.0.0.1');
const KEY_ID =
  process.env.SIDECAR_KEY_ID ||
  (MODE === 'kms' ? process.env.AWS_KMS_KEY_ID || 'AWS-KMS-KEY' : 'FAKE-KMS-SIDECAR-DEV');
const TOKEN = process.env.SIDECAR_TOKEN || '';

if (MODE !== 'fake' && MODE !== 'kms') {
  console.error(`Unknown mode ${JSON.stringify(MODE)} (expected "fake" or "kms").`);
  process.exit(2);
}

/** Convert a DER ECDSA signature (SEQUENCE of two INTEGERs) to raw r||s (64 bytes). */
function derToRaw(der) {
  let off = 0;
  const readLen = () => {
    let len = der[off++];
    if (len & 0x80) {
      const n = len & 0x7f;
      len = 0;
      for (let i = 0; i < n; i++) len = (len << 8) | der[off++];
    }
    return len;
  };
  const readInt = () => {
    if (der[off++] !== 0x02) throw new Error('DER signature: expected INTEGER');
    const len = readLen();
    let bytes = der.subarray(off, off + len);
    off += len;
    while (bytes.length > 1 && bytes[0] === 0x00) bytes = bytes.subarray(1);
    if (bytes.length > 32) throw new Error('DER signature: integer too long for P-256');
    const out = new Uint8Array(32);
    out.set(bytes, 32 - bytes.length);
    return out;
  };
  if (der[off++] !== 0x30) throw new Error('DER signature: expected SEQUENCE');
  readLen();
  const r = readInt();
  const s = readInt();
  const raw = new Uint8Array(64);
  raw.set(r, 0);
  raw.set(s, 32);
  return raw;
}

let fakeKeyPair = null;
let kmsClient = null;

async function init() {
  if (MODE === 'fake') {
    fakeKeyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign', 'verify']
    );
    console.log('[sidecar] mode=fake — ephemeral in-memory key. NOT a KMS key, NOT production.');
  } else {
    let kms;
    try {
      kms = await import('@aws-sdk/client-kms');
    } catch {
      console.error(
        'KMS mode needs the AWS SDK in this sidecar directory: run `npm install @aws-sdk/client-kms` here.\n' +
          'It is intentionally NOT a dependency of the TDCP repo.'
      );
      process.exit(2);
    }
    const keyId = process.env.AWS_KMS_KEY_ID;
    if (!keyId) {
      console.error('KMS mode needs AWS_KMS_KEY_ID (key ARN or alias).');
      process.exit(2);
    }
    kmsClient = new kms.KMSClient({ region: process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION });
    console.log(`[sidecar] mode=kms keyId=${keyId} (credentials from the AWS chain, never from this repo)`);
  }
}

async function getPublicKeySpkiBase64() {
  if (MODE === 'fake') {
    const spki = await crypto.subtle.exportKey('spki', fakeKeyPair.publicKey);
    return Buffer.from(spki).toString('base64');
  }
  const { GetPublicKeyCommand } = await import('@aws-sdk/client-kms');
  const out = await kmsClient.send(new GetPublicKeyCommand({ KeyId: process.env.AWS_KMS_KEY_ID }));
  if (!out.PublicKey) throw new Error('KMS GetPublicKey returned no public key.');
  return Buffer.from(out.PublicKey).toString('base64');
}

async function signCanonical(canonical) {
  if (MODE === 'fake') {
    const sig = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      fakeKeyPair.privateKey,
      new TextEncoder().encode(canonical)
    );
    return Buffer.from(sig).toString('base64');
  }
  const { SignCommand } = await import('@aws-sdk/client-kms');
  const out = await kmsClient.send(
    new SignCommand({
      KeyId: process.env.AWS_KMS_KEY_ID,
      Message: new TextEncoder().encode(canonical),
      MessageType: 'RAW',
      SigningAlgorithm: 'ECDSA_SHA_256',
    })
  );
  if (!out.Signature) throw new Error('KMS Sign returned no signature.');
  return Buffer.from(derToRaw(new Uint8Array(out.Signature))).toString('base64');
}

function sendJson(res, status, body) {
  const data = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) });
  res.end(data);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url || '/', `http://${req.headers.host || '127.0.0.1'}`);
    if (req.method === 'GET' && url.pathname === '/health') {
      sendJson(res, 200, { ok: true, mode: MODE, keyId: KEY_ID });
      return;
    }
    if (TOKEN) {
      const auth = req.headers.authorization || '';
      if (auth !== `Bearer ${TOKEN}`) {
        sendJson(res, 401, { error: 'unauthorized' });
        return;
      }
    }
    if (req.method === 'GET' && url.pathname === '/v1/public-key') {
      const publicKeySpkiBase64 = await getPublicKeySpkiBase64();
      sendJson(res, 200, { keyId: KEY_ID, publicKeySpkiBase64 });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/v1/sign') {
      const body = JSON.parse(await readBody(req));
      if (typeof body.canonical !== 'string' || !body.canonical) {
        sendJson(res, 400, { error: 'canonical (string) is required' });
        return;
      }
      const signatureBase64 = await signCanonical(body.canonical);
      sendJson(res, 200, { signatureBase64 });
      return;
    }
    sendJson(res, 404, { error: 'not found' });
  } catch (err) {
    console.error('[sidecar] error:', err instanceof Error ? err.message : String(err));
    if (!res.headersSent) sendJson(res, 500, { error: 'signing failed' });
  }
});

await init();
server.listen(PORT, HOST, () => {
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : PORT;
  console.log(`kms-signing-sidecar listening on http://${HOST}:${port} (mode=${MODE} keyId=${KEY_ID})`);
});
