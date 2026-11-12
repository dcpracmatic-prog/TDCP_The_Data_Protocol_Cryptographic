/**
 * FAKE Smart Token HTTP server — SOLO PARA PRUEBAS. NO ES PRODUCCION.
 *
 * Imita el contrato HTTP observable del servicio real Smart Token Prod
 * v0.10.5 (`api/main.py` en github.com/dcpracmatic-prog/Smart-Token-Prod),
 * que es el contrato que habla `sdk/typescript/src/smart-token-client.ts`:
 *
 *   GET  /healthz                        (sin auth, como el real)
 *   GET  /v1/status                     (Bearer; sdk_status)
 *   POST /v1/artifacts                  (Bearer + X-Smart-Token-Master,
 *                                        multipart campo 'file')
 *   POST /v1/artifacts/{id}/open       (Bearer + X-Smart-Token-Master)
 *   GET  /v1/artifacts/{id}/friction   (Bearer)
 *
 * Todo vive solo en memoria (Map): sin disco, sin persistencia. El blob
 * protegido se guarda ENVUELTO con PBKDF2-SHA256 (100.000 iteraciones) +
 * AES-256-GCM derivado de la contraseña maestra; del master solo se guarda
 * su SHA-256 para verificar, como el doble en memoria de
 * `src/protection/smart-token-cek-custody.ts`. El blob en claro NUNCA se
 * guarda: el cliente lo manda en claro por HTTP local y la fake lo cifra
 * antes de guardarlo.
 *
 * DIFERENCIA DOCUMENTADA (no un engaño): el servicio real envuelve con
 * ML-KEM-768 + AES-256-GCM y endurece cada intento con Argon2id. Eso NO es
 * observable por el contrato HTTP, así que la fake usa PBKDF2 + AES-GCM
 * derivado de la contraseña. Tampoco imita: la máquina de fricción
 * persistente file-borne (friction_snapshot real viaja en el .stok),
 * la validation ladder (N+1 aciertos consecutivos tras fallos), el hang
 * de fase 3, el tarpit, el núcleo C++ ni el almacenamiento local/S3.
 * La fricción de la fake es sintética y en memoria (ver README).
 *
 * DIVERGENCIAS INTENCIONADAS respecto al real, pedidas por la tarea:
 * - Artefacto desconocido en /open → 403 con cuerpo opaco `DENIED`
 *   (el real devuelve 404 "Artifact not found"). La fake no distingue
 *   entre master incorrecto y artefacto desconocido.
 * - Sin API key configurada en el servidor → 503 en /v1/* (como el real).
 *
 * Endpoints de control SOLO-FAKE (loopback, sin auth, fuera del contrato):
 *   POST /__fake__/down   → simula caída (todo responde 503)
 *   POST /__fake__/up     → vuelve a levantar
 *   POST /__fake__/reset  → vacía la memoria (artefactos + fricción)
 *   GET  /__fake__/state  → { down, artifacts }
 *
 * Solo node:http y node:crypto. Sin dependencias nuevas.
 */

import { createHash, createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';

export const FAKE_VERSION = '0.10.5-FAKE';
export const FAKE_MIRRORS_REAL_VERSION = '0.10.5';
export const PBKDF2_ITERATIONS = 100000;
export const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;

function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

/** tier sintético 0→0, 1→1, 2→2, ≥3→3 (el real escala 1→2→3 por fallos). */
function tierForFailCount(failCount) {
  if (failCount <= 0) return 0;
  if (failCount === 1) return 1;
  if (failCount === 2) return 2;
  return 3;
}

function workFactorForTier(tier) {
  return [1, 2, 4, 8][tier] ?? 1;
}

function wrapBlob(plaintext, masterSecret) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = pbkdf2Sync(masterSecret, salt, PBKDF2_ITERATIONS, 32, 'sha256');
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  key.fill(0);
  return { salt, iv, ciphertext: Buffer.concat([ciphertext, tag]) };
}

function unwrapBlob(wrapped, masterSecret) {
  const key = pbkdf2Sync(masterSecret, wrapped.salt, PBKDF2_ITERATIONS, 32, 'sha256');
  try {
    const tag = wrapped.ciphertext.subarray(wrapped.ciphertext.length - 16);
    const body = wrapped.ciphertext.subarray(0, wrapped.ciphertext.length - 16);
    const decipher = createDecipheriv('aes-256-gcm', key, wrapped.iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(body), decipher.final()]);
  } finally {
    key.fill(0);
  }
}

/**
 * Parser mínimo de multipart/form-data (un solo campo 'file').
 * Devuelve { filename, data } o null si no hay parte 'file'.
 */
function parseMultipartFile(body, contentType) {
  const m = /boundary=(?:"([^"]+)"|([^;]+))/.exec(contentType ?? '');
  if (!m) return null;
  const boundary = Buffer.from(`--${(m[1] ?? m[2]).trim()}`);
  const headerEnd = Buffer.from('\r\n\r\n');
  let start = body.indexOf(boundary);
  while (start !== -1) {
    const afterBoundary = start + boundary.length;
    if (body.subarray(afterBoundary, afterBoundary + 2).toString() === '--') break;
    const headStart = afterBoundary + 2; // CRLF tras el boundary
    const headEnd = body.indexOf(headerEnd, headStart);
    if (headEnd === -1) return null;
    const headers = body.subarray(headStart, headEnd).toString('latin1');
    const nameMatch = /name="file"/.exec(headers);
    if (nameMatch) {
      const fileMatch = /filename="([^"]*)"/.exec(headers);
      const dataStart = headEnd + headerEnd.length;
      let dataEnd = body.indexOf(boundary, dataStart);
      if (dataEnd === -1) return null;
      dataEnd -= 2; // CRLF previo al boundary
      return { filename: fileMatch ? fileMatch[1] : 'artifact.bin', data: body.subarray(dataStart, dataEnd) };
    }
    const next = body.indexOf(boundary, headEnd);
    if (next === -1) break;
    start = next;
  }
  return null;
}

function frictionPayload(artifactId, entry) {
  const tier = tierForFailCount(entry.failCount);
  return {
    path: `fake-memory://${artifactId}/artifact.stok`,
    friction_snapshot: {
      fail_count: entry.failCount,
      recovery_tier: tier,
      work_factor: workFactorForTier(tier),
      cumulative_iters: entry.failCount * 1000,
      stok_id: artifactId,
      flag_fibonacci: false,
      flag_persistencia: false,
      tarpit_triggered: false,
    },
    public_label: entry.filename,
    target_coherence: 1.0,
    has_embedded_sk: false,
    recovery_tier: tier,
    work_factor: workFactorForTier(tier),
    cumulative_iters: entry.failCount * 1000,
  };
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
  res.end(body);
}

function sendText(res, status, text, headers = {}) {
  res.writeHead(status, { 'content-type': 'text/plain', ...headers, 'content-length': Buffer.byteLength(text) });
  res.end(text);
}

/**
 * Crea el servidor fake. Opciones:
 *   apiKey (string, obligatorio para /v1/*; sin él → 503 como el real),
 *   down (boolean, arranca simulando caída),
 *   storageBackend (string, solo se refleja en /healthz; default 'memory').
 */
export function createFakeSmartTokenServer(options = {}) {
  const apiKey = options.apiKey ?? '';
  const storageBackend = options.storageBackend ?? 'memory';
  const store = new Map();
  let down = Boolean(options.down);

  const server = createServer((req, res) => {
    const chunks = [];
    let tooLarge = false;
    req.on('data', (c) => {
      if (chunks.reduce((n, b) => n + b.length, 0) + c.length > MAX_UPLOAD_BYTES) tooLarge = true;
      chunks.push(c);
    });
    req.on('end', () => {
      try {
        handle(req, res, Buffer.concat(chunks), tooLarge);
      } catch (err) {
        sendJson(res, 500, { detail: `FAKE internal error: ${err.message}` });
      }
    });
  });

  function handle(req, res, body, tooLarge) {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    const path = url.pathname;
    const method = req.method ?? 'GET';

    // --- Control SOLO-FAKE (fuera del contrato real) ---
    if (path.startsWith('/__fake__/')) {
      if (method === 'POST' && path === '/__fake__/down') {
        down = true;
        return sendJson(res, 200, { down: true });
      }
      if (method === 'POST' && path === '/__fake__/up') {
        down = false;
        return sendJson(res, 200, { down: false });
      }
      if (method === 'POST' && path === '/__fake__/reset') {
        store.clear();
        return sendJson(res, 200, { down, artifacts: 0 });
      }
      if (method === 'GET' && path === '/__fake__/state') {
        return sendJson(res, 200, { down, artifacts: store.size });
      }
      return sendJson(res, 404, { detail: 'FAKE control endpoint not found' });
    }

    // --- Simulación de caída: todo el contrato responde 503 ---
    if (down) {
      if (method === 'GET' && path === '/healthz') {
        return sendJson(res, 503, { ok: false, storage_backend: storageBackend, smart_token_available: false });
      }
      return sendJson(res, 503, { detail: 'FAKE Smart Token down (simulated)' });
    }

    // --- GET /healthz (sin auth, como el real) ---
    if (method === 'GET' && path === '/healthz') {
      return sendJson(res, 200, { ok: true, storage_backend: storageBackend, smart_token_available: true });
    }

    // --- Auth Bearer para /v1/* (como el real: sin key → 503, mala key → 401) ---
    if (path.startsWith('/v1/')) {
      if (!apiKey) return sendJson(res, 503, { detail: 'API authentication is not configured' });
      const auth = req.headers.authorization ?? '';
      if (!auth.startsWith('Bearer ')) return sendJson(res, 401, { detail: 'Missing bearer token' });
      if (auth.slice(7).trim() !== apiKey) return sendJson(res, 401, { detail: 'Invalid bearer token' });
    }

    // --- GET /v1/status ---
    if (method === 'GET' && path === '/v1/status') {
      return sendJson(res, 200, {
        version: FAKE_MIRRORS_REAL_VERSION,
        native_friction: false,
        import_error: null,
        role: 'sdk',
        available: true,
        fake: true,
        storage_backend: storageBackend,
      });
    }

    // --- POST /v1/artifacts ---
    if (method === 'POST' && path === '/v1/artifacts') {
      const master = req.headers['x-smart-token-master'];
      if (!master) return sendJson(res, 400, { detail: 'Master secret is required' });
      if (tooLarge) return sendJson(res, 413, { detail: 'Upload exceeds configured size limit' });
      const file = parseMultipartFile(body, req.headers['content-type'] ?? '');
      if (!file) return sendJson(res, 400, { detail: 'file is required' });
      const artifactId = randomBytes(16).toString('hex'); // mismo formato que el real (token_hex(16))
      store.set(artifactId, {
        filename: file.filename || 'artifact.bin',
        wrapped: wrapBlob(file.data, master),
        masterHash: sha256Hex(Buffer.from(master, 'utf8')),
        failCount: 0,
      });
      return sendJson(res, 200, { artifact_id: artifactId, filename: file.filename || 'artifact.bin', status: 'PROTECTED' });
    }

    // --- POST /v1/artifacts/{id}/open y GET /v1/artifacts/{id}/friction ---
    const openMatch = /^\/v1\/artifacts\/([^/]+)\/open$/.exec(path);
    const frictionMatch = /^\/v1\/artifacts\/([^/]+)\/friction$/.exec(path);
    if (openMatch || frictionMatch) {
      const artifactId = (openMatch ?? frictionMatch)[1];
      if (openMatch) {
        if (method !== 'POST') return sendJson(res, 405, { detail: 'Method not allowed' });
        const master = req.headers['x-smart-token-master'];
        if (!master) return sendJson(res, 400, { detail: 'Master secret is required' });
        const entry = store.get(artifactId);
        // Opaco: desconocido o master incorrecto → mismo 403 DENIED.
        if (!entry || sha256Hex(Buffer.from(master, 'utf8')) !== entry.masterHash) {
          if (entry) entry.failCount += 1;
          return sendText(res, 403, 'DENIED');
        }
        let plaintext;
        try {
          plaintext = unwrapBlob(entry.wrapped, master);
        } catch {
          return sendText(res, 403, 'DENIED');
        }
        entry.failCount = 0; // la fake NO implementa la validation ladder del real
        res.writeHead(200, {
          'content-type': 'application/octet-stream',
          'content-length': plaintext.length,
          'X-Smart-Token-Status': 'OPEN',
        });
        return res.end(plaintext);
      }
      // friction
      if (method !== 'GET') return sendJson(res, 405, { detail: 'Method not allowed' });
      const entry = store.get(artifactId);
      if (!entry) return sendJson(res, 404, { detail: 'Artifact not found' });
      return sendJson(res, 200, frictionPayload(artifactId, entry));
    }

    return sendJson(res, 404, { detail: 'not found' });
  }

  function listen(port = 0, host = '127.0.0.1') {
    return new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, () => {
        server.removeListener('error', reject);
        const addr = server.address();
        resolve({ port: typeof addr === 'object' && addr ? addr.port : port, host, url: `http://${host}:${typeof addr === 'object' && addr ? addr.port : port}` });
      });
    });
  }

  function close() {
    return new Promise((resolve) => server.close(() => resolve()));
  }

  return {
    server,
    listen,
    close,
    setDown(value) {
      down = Boolean(value);
    },
    isDown() {
      return down;
    },
    artifactCount() {
      return store.size;
    },
    /** Introspección SOLO PARA TESTS (no es endpoint HTTP): bytes guardados. */
    debugStoredBytes(artifactId) {
      const entry = store.get(artifactId);
      if (!entry) return null;
      return Buffer.concat([entry.wrapped.salt, entry.wrapped.iv, entry.wrapped.ciphertext]);
    },
    /** Introspección SOLO PARA TESTS: del master solo existe su SHA-256. */
    debugMasterHash(artifactId) {
      return store.get(artifactId)?.masterHash ?? null;
    },
    debugFailCount(artifactId) {
      return store.get(artifactId)?.failCount ?? null;
    },
  };
}
