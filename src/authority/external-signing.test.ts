/**
 * External signing backend (P0-2): HTTP sidecar + local command signer.
 *
 * Spawns the real example fake sidecar (examples/kms-signing-sidecar/),
 * issues a grant through DurableAuthorityService, verifies the signature
 * against the sidecar's public key, and proves fail-closed behavior:
 * when the signer is gone, no grant is issued and nothing silently falls
 * back to the `file` backend.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DurableAuthorityService } from '../../server/authority/service.ts';
import { readSigningBackendFromEnv } from '../../server/authority/signing-backend.ts';
import { ExternalSigningError } from '../../server/authority/external-signing-backend.ts';
import { canonicalizeGrant } from '../core/authorization/types.ts';
import {
  arrayBufferToBase64,
  base64ToUint8Array,
  verifySignatureECDSA,
} from '../core/crypto/primitives.ts';
import type { AuthorizationRequest } from '../core/authorization/types.ts';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const sidecarPath = join(repoRoot, 'examples', 'kms-signing-sidecar', 'kms-signing-sidecar.mjs');
const cmdSignerPath = join(repoRoot, 'examples', 'kms-signing-sidecar', 'fake-cmd-signer.mjs');

const ENV_KEYS = [
  'TDCP_SIGNING_BACKEND',
  'TDCP_SIGNING_EXTERNAL_URL',
  'TDCP_SIGNING_EXTERNAL_CMD',
  'TDCP_SIGNING_EXTERNAL_KEY_ID',
  'TDCP_SIGNING_EXTERNAL_PUBLIC_KEY_B64',
  'TDCP_SIGNING_EXTERNAL_PUBLIC_KEY_FILE',
  'TDCP_SIGNING_EXTERNAL_TIMEOUT_MS',
  'TDCP_SIGNING_EXTERNAL_TOKEN',
  'TDCP_SIGNING_EXTERNAL_ATTESTED',
];

function setEnv(vars: Record<string, string>): () => void {
  const saved: Record<string, string | undefined> = {};
  for (const k of ENV_KEYS) saved[k] = process.env[k];
  for (const k of ENV_KEYS) delete process.env[k];
  Object.assign(process.env, vars);
  return () => {
    for (const k of ENV_KEYS) delete process.env[k];
    for (const [k, v] of Object.entries(saved)) if (v !== undefined) process.env[k] = v;
  };
}

async function waitForHealth(port: number, timeoutMs = 10_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/health`);
      if (res.ok) return;
    } catch {
      /* not up yet */
    }
    if (Date.now() > deadline) throw new Error(`Sidecar on :${port} never became healthy.`);
    await new Promise((r) => setTimeout(r, 100));
  }
}

async function startFakeSidecar(): Promise<{ child: ChildProcess; port: number }> {
  const child = spawn(process.execPath, [sidecarPath, '--mode', 'fake', '--port', '0', '--host', '127.0.0.1'], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  const port = await new Promise<number>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Sidecar did not print a port. Output: ${out}`)), 10_000);
    child.stdout?.on('data', (d: Buffer) => {
      out += d.toString('utf8');
      const m = /listening on http:\/\/127\.0\.0\.1:(\d+)/.exec(out);
      if (m) {
        clearTimeout(timer);
        resolve(Number(m[1]));
      }
    });
    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`Sidecar exited early with code ${code}. Output: ${out}`));
    });
  });
  await waitForHealth(port);
  return { child, port };
}

function stopChild(child: ChildProcess): Promise<void> {
  return new Promise((resolve) => {
    // NOTE: a process killed by a signal has exitCode === null and
    // signalCode set — checking exitCode alone would wait the full timeout.
    if (child.exitCode !== null || child.signalCode !== null) return resolve();
    const timer = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch {
        /* already gone */
      }
      resolve();
    }, 3000);
    timer.unref();
    child.on('exit', () => {
      clearTimeout(timer);
      resolve();
    });
    child.kill('SIGTERM');
  });
}

function makeRequest(overrides: {
  documentId: string;
  packageId: string;
  challenge: string;
  operationId: string;
}): AuthorizationRequest {
  return {
    requestId: 'REQ-EXT',
    deviceId: 'DEV-EXT',
    credentialId: 'CRED-EXT',
    requestedOperation: 'READ',
    timestamp: Date.now(),
    ...overrides,
  };
}

async function importSpki(b64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'spki',
    base64ToUint8Array(b64) as BufferSource,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify']
  );
}

describe('External signing backend (P0-2)', () => {
  let dir: string;

  before(() => {
    dir = mkdtempSync(join(tmpdir(), 'tdcp-ext-sign-'));
  });

  after(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('signs a grant through the HTTP fake sidecar and the signature verifies', async () => {
    const { child, port } = await startFakeSidecar();
    const restoreEnv = setEnv({
      TDCP_SIGNING_BACKEND: 'external',
      TDCP_SIGNING_EXTERNAL_URL: `http://127.0.0.1:${port}`,
    });
    try {
      const svc = new DurableAuthorityService(dir);
      await svc.initialize();
      const readiness = await svc.getReadiness();
      assert.equal(readiness.signingBackend, 'external');
      assert.equal(readiness.ready, true);
      // Unattested fake signer: honestly NOT production-grade.
      assert.equal(readiness.developmentOnly, true);

      const info = await svc.getPublicInfo();
      assert.equal(info.keyId, 'FAKE-KMS-SIDECAR-DEV');

      await svc.registerDocumentPolicy({
        documentId: 'DOC-EXT-1',
        packageId: 'PKG-EXT-1',
        policyLevel: 'STANDARD',
        allowExtraction: false,
        createdAt: Date.now(),
      });
      const challenge = await svc.issueChallenge();
      const result = await svc.processAuthorizationRequest(
        makeRequest({
          documentId: 'DOC-EXT-1',
          packageId: 'PKG-EXT-1',
          challenge,
          operationId: 'OP-EXT-1',
        })
      );
      assert.equal(result.granted, true);
      assert.ok(result.grant);
      assert.equal(result.grant!.oracleKeyId, 'FAKE-KMS-SIDECAR-DEV');

      // Verify the grant signature against the sidecar public key, by hand.
      const { signature, ...unsigned } = result.grant!;
      const pub = await importSpki(info.publicKeySpkiBase64);
      const ok = await verifySignatureECDSA(pub, signature, canonicalizeGrant(unsigned));
      assert.equal(ok, true);
    } finally {
      restoreEnv();
      await stopChild(child);
    }
  });

  it('fails closed: no grant when the sidecar dies, and no fallback to file', async () => {
    const { child, port } = await startFakeSidecar();
    const restoreEnv = setEnv({
      TDCP_SIGNING_BACKEND: 'external',
      TDCP_SIGNING_EXTERNAL_URL: `http://127.0.0.1:${port}`,
    });
    try {
      const svc = new DurableAuthorityService(join(dir, 'fail-closed'));
      await svc.initialize();
      await svc.registerDocumentPolicy({
        documentId: 'DOC-EXT-2',
        packageId: 'PKG-EXT-2',
        policyLevel: 'STANDARD',
        allowExtraction: false,
        createdAt: Date.now(),
      });
      const challenge = await svc.issueChallenge();

      // Kill the signer mid-flight: the next grant must fail, not fall back.
      await stopChild(child);
      await assert.rejects(
        () =>
          svc.processAuthorizationRequest(
            makeRequest({
              documentId: 'DOC-EXT-2',
              packageId: 'PKG-EXT-2',
              challenge,
              operationId: 'OP-EXT-2',
            })
          ),
        (err: unknown) => {
          assert.ok(err instanceof ExternalSigningError, `expected ExternalSigningError, got ${String(err)}`);
          assert.match(err.message, /External signing failed/);
          return true;
        }
      );

      // And the service must refuse to start against a dead signer at all.
           const svc2 = new DurableAuthorityService(join(dir, 'fail-closed-2'));
      await assert.rejects(() => svc2.initialize(), ExternalSigningError);
    } finally {
      restoreEnv();
      await stopChild(child);
    }
  });

  it('signs through a local command signer (no HTTP)', async () => {
    const keyDir = join(dir, 'cmd-key');
    const { mkdirSync } = await import('node:fs');
    mkdirSync(keyDir, { recursive: true });
    const pair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
    const spki = await crypto.subtle.exportKey('spki', pair.publicKey);
    const keyFile = join(keyDir, 'private.jwk.json');
    writeFileSync(keyFile, JSON.stringify(privateJwk), { mode: 0o600 });
    const spkiB64 = arrayBufferToBase64(spki);

    const restoreEnv = setEnv({
      TDCP_SIGNING_BACKEND: 'external',
      TDCP_SIGNING_EXTERNAL_CMD: `${process.execPath} ${cmdSignerPath} ${keyFile}`,
      TDCP_SIGNING_EXTERNAL_PUBLIC_KEY_B64: spkiB64,
      TDCP_SIGNING_EXTERNAL_KEY_ID: 'TEST-CMD-KEY',
    });
    try {
      const svc = new DurableAuthorityService(join(dir, 'cmd-mode'));
      await svc.initialize();
      assert.equal((await svc.getReadiness()).signingBackend, 'external');
      await svc.registerDocumentPolicy({
        documentId: 'DOC-EXT-3',
        packageId: 'PKG-EXT-3',
        policyLevel: 'STANDARD',
        allowExtraction: false,
        createdAt: Date.now(),
      });
      const challenge = await svc.issueChallenge();
      const result = await svc.processAuthorizationRequest(
        makeRequest({
          documentId: 'DOC-EXT-3',
          packageId: 'PKG-EXT-3',
          challenge,
          operationId: 'OP-EXT-3',
        })
      );
      assert.equal(result.granted, true);
      assert.ok(result.grant);
      assert.equal(result.grant!.oracleKeyId, 'TEST-CMD-KEY');
      const { signature, ...unsigned } = result.grant!;
      const ok = await verifySignatureECDSA(pair.publicKey, signature, canonicalizeGrant(unsigned));
      assert.equal(ok, true);
    } finally {
      restoreEnv();
    }
  });

  it('rejects unknown backends and misconfigured external backends at startup', () => {
    assert.throws(
      () => readSigningBackendFromEnv({ TDCP_SIGNING_BACKEND: 'magic' }),
      /Unknown TDCP_SIGNING_BACKEND/
    );
    assert.throws(
      () => readSigningBackendFromEnv({ TDCP_SIGNING_BACKEND: 'external' }),
      /needs TDCP_SIGNING_EXTERNAL_URL/
    );
    assert.throws(
      () =>
        readSigningBackendFromEnv({
          TDCP_SIGNING_BACKEND: 'external',
          TDCP_SIGNING_EXTERNAL_URL: 'http://127.0.0.1:8011',
          TDCP_SIGNING_EXTERNAL_CMD: '/bin/true',
        }),
      /only one of/
    );
    assert.throws(
      () =>
        readSigningBackendFromEnv({
          TDCP_SIGNING_BACKEND: 'external',
          TDCP_SIGNING_EXTERNAL_URL: 'ftp://example.com/signer',
        }),
      /must be http\(s\)/
    );
    // A non-exportable store never hands out a private key.
    assert.throws(
      () =>
        readSigningBackendFromEnv({
          TDCP_SIGNING_BACKEND: 'external',
          TDCP_SIGNING_EXTERNAL_CMD: '/bin/true',
        }),
      /public key/
    );
  });
});
