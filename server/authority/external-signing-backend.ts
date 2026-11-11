/**
 * External signing backend (P0-2) — the plug for real KMS / HSM signing.
 *
 * The Authority process NEVER sees the private key. It asks a signer that
 * lives outside this process to sign the canonical grant bytes, and only
 * ever holds the public key (to publish it and verify grants).
 *
 * Two transports, both configured by environment — no code change needed
 * to switch between them:
 *
 *   1. HTTP sidecar  — TDCP_SIGNING_EXTERNAL_URL=http://127.0.0.1:8011
 *      POST /v1/sign      { "canonical": "<utf8>" } -> { "signatureBase64": "<raw r||s, base64>" }
 *      GET  /v1/public-key -> { "keyId": "...", "publicKeySpkiBase64": "<SPKI DER, base64>" }
 *      GET  /health       -> { "ok": true }
 *      See server/authority/examples/kms-signing-sidecar.mjs (fake mode for
 *      tests, AWS KMS mode for production).
 *
 *   2. Local command — TDCP_SIGNING_EXTERNAL_CMD=/usr/local/bin/kms-signer
 *      The command is run WITHOUT a shell (argv split on whitespace), the
 *      canonical UTF-8 bytes go to its stdin, and it prints one line on
 *      stdout: the raw r||s signature in base64. The public key comes from
 *      TDCP_SIGNING_EXTERNAL_PUBLIC_KEY_B64 or
 *      TDCP_SIGNING_EXTERNAL_PUBLIC_KEY_FILE (SPKI DER, base64).
 *
 * FAIL CLOSED: if the sidecar/command is unreachable, slow, or returns
 * anything unexpected, signing throws ExternalSigningError and the grant
 * is NOT issued. There is NO silent fallback to the `file` backend.
 * A misconfigured `external` backend also fails Authority startup instead
 * of starting with a different backend.
 *
 * HONESTY: this backend is only as good as the signer behind it. It reports
 * production-grade ONLY when the operator explicitly attests it with
 * TDCP_SIGNING_EXTERNAL_ATTESTED=true (meaning: the signer is a real
 * KMS/HSM with a non-exportable key). A local fake signer is NOT
 * production-grade, and neither is this file by itself.
 *
 * No AWS SDK, no credentials in this file. The sidecar owns its own
 * credentials (AWS credential chain, IAM role, ...); this process never
 * receives them.
 */

import { execFile } from 'node:child_process';
import { readFileSync } from 'node:fs';
import type { OracleKeyStore, OracleKeyStoreKind } from '../../src/oracle/oracle-key-store.ts';
import { base64ToUint8Array } from '../../src/core/crypto/primitives.ts';

/** Thrown when the external signer cannot sign. Never a fallback signal. */
export class ExternalSigningError extends Error {
  public readonly code = 'EXTERNAL_SIGNING_UNAVAILABLE' as const;
  constructor(message: string) {
    super(`External signing failed: ${message}`);
    this.name = 'ExternalSigningError';
  }
}

export type ExternalSigningTransport = 'http' | 'command';

export interface ExternalSigningConfig {
  transport: ExternalSigningTransport;
  /** HTTP sidecar base URL (http transport). No path suffix, no credentials in it. */
  url?: string;
  /** Local signer argv, first element is the executable (command transport). */
  command?: string[];
  /** Key id reported in grants (oracleKeyId). Adopted from the sidecar when unset. */
  keyId?: string;
  /** Milliseconds before a sign / public-key request aborts. Default 5000. */
  timeoutMs: number;
  /** Optional Bearer token sent to the HTTP sidecar (never logged). */
  token?: string;
  /** SPKI DER (base64) of the public key — required for command transport. */
  publicKeySpkiBase64?: string;
  /** File holding the SPKI DER (base64) — alternative to publicKeySpkiBase64. */
  publicKeyFile?: string;
  /** Operator attestation: true ONLY when the signer is a real KMS/HSM. */
  attestedProductionGrade: boolean;
  /** Label for the key store kind. Default 'KMS'. */
  kind: OracleKeyStoreKind;
}

const DEFAULT_KEY_ID = 'AUTHORITY-KEY-EXTERNAL';
const DEFAULT_TIMEOUT_MS = 5000;

function parseTimeoutMs(raw: string | undefined): number {
  if (!raw) return DEFAULT_TIMEOUT_MS;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) {
    throw new ExternalSigningError(
      `TDCP_SIGNING_EXTERNAL_TIMEOUT_MS must be a positive number of milliseconds, got ${JSON.stringify(raw)}.`
    );
  }
  return Math.floor(n);
}

function parseCommand(raw: string): string[] {
  const argv = raw.trim().split(/\s+/).filter(Boolean);
  if (argv.length === 0) {
    throw new ExternalSigningError('TDCP_SIGNING_EXTERNAL_CMD is empty.');
  }
  return argv;
}

/**
 * Read the external signer configuration from the environment.
 * Throws ExternalSigningError on anything missing or malformed — the
 * Authority must refuse to start rather than sign with the wrong backend.
 */
export function readExternalSigningConfigFromEnv(
  env: Record<string, string | undefined> = process.env as Record<string, string | undefined>
): ExternalSigningConfig {
  const url = env.TDCP_SIGNING_EXTERNAL_URL?.trim() || undefined;
  const cmdRaw = env.TDCP_SIGNING_EXTERNAL_CMD?.trim() || undefined;
  if (url && cmdRaw) {
    throw new ExternalSigningError(
      'Set only one of TDCP_SIGNING_EXTERNAL_URL or TDCP_SIGNING_EXTERNAL_CMD, not both.'
    );
  }
  if (!url && !cmdRaw) {
    throw new ExternalSigningError(
      'TDCP_SIGNING_BACKEND=external needs TDCP_SIGNING_EXTERNAL_URL (HTTP sidecar) or ' +
        'TDCP_SIGNING_EXTERNAL_CMD (local signer command). See docs/AUTHORITY.md.'
    );
  }
  let parsedUrl: URL | undefined;
  if (url) {
    try {
      parsedUrl = new URL(url);
    } catch {
      throw new ExternalSigningError(
        `TDCP_SIGNING_EXTERNAL_URL is not a valid URL: ${JSON.stringify(url)}.`
      );
    }
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      throw new ExternalSigningError(
        `TDCP_SIGNING_EXTERNAL_URL must be http(s), got ${parsedUrl.protocol}.`
      );
    }
    if (parsedUrl.username || parsedUrl.password) {
      throw new ExternalSigningError(
        'TDCP_SIGNING_EXTERNAL_URL must not contain credentials; use TDCP_SIGNING_EXTERNAL_TOKEN instead.'
      );
    }
  }
  const kindRaw = (env.TDCP_SIGNING_EXTERNAL_KIND || 'KMS').trim().toUpperCase();
  const kind: OracleKeyStoreKind =
    kindRaw === 'HSM' || kindRaw === 'CLOUD_HSM' || kindRaw === 'KMS' ? kindRaw : 'KMS';
  const publicKeySpkiBase64 = env.TDCP_SIGNING_EXTERNAL_PUBLIC_KEY_B64?.trim() || undefined;
  const publicKeyFile = env.TDCP_SIGNING_EXTERNAL_PUBLIC_KEY_FILE?.trim() || undefined;
  if (!url && !publicKeySpkiBase64 && !publicKeyFile) {
    throw new ExternalSigningError(
      'Command transport needs the public key: set TDCP_SIGNING_EXTERNAL_PUBLIC_KEY_B64 or ' +
        'TDCP_SIGNING_EXTERNAL_PUBLIC_KEY_FILE (SPKI DER, base64).'
    );
  }
  return {
    transport: url ? 'http' : 'command',
    ...(url ? { url: parsedUrl!.toString().replace(/\/$/, '') } : {}),
    ...(cmdRaw ? { command: parseCommand(cmdRaw) } : {}),
    keyId: env.TDCP_SIGNING_EXTERNAL_KEY_ID?.trim() || undefined,
    timeoutMs: parseTimeoutMs(env.TDCP_SIGNING_EXTERNAL_TIMEOUT_MS),
    token: env.TDCP_SIGNING_EXTERNAL_TOKEN?.trim() || undefined,
    publicKeySpkiBase64,
    publicKeyFile,
    attestedProductionGrade: env.TDCP_SIGNING_EXTERNAL_ATTESTED === 'true',
    kind,
  };
}

function decodeBase64Field(value: unknown, field: string): Uint8Array {
  if (typeof value !== 'string' || !value) {
    throw new ExternalSigningError(`Sidecar response is missing ${field}.`);
  }
  try {
    return base64ToUint8Array(value);
  } catch {
    throw new ExternalSigningError(`Sidecar response has invalid base64 in ${field}.`);
  }
}

/**
 * OracleKeyStore that delegates every signature to an external signer.
 * The private key never enters this process, so getOrCreateSigningKey()
 * always throws — callers must use signCanonical() + getPublicKey().
 */
export class ExternalOracleKeyStore implements OracleKeyStore {
  public readonly kind: OracleKeyStoreKind;
  public readonly isProductionGrade: boolean;
  public readonly developmentOnly: boolean;

  private readonly config: ExternalSigningConfig;
  private keyId: string;
  private publicKeyPromise: Promise<CryptoKey> | null = null;

  constructor(config: ExternalSigningConfig) {
    this.config = config;
    this.kind = config.kind;
    // Production-grade only when the operator attests the signer is a real
    // KMS/HSM. Default (unattested, e.g. the fake sidecar) is NOT.
    this.isProductionGrade = config.attestedProductionGrade;
    this.developmentOnly = !config.attestedProductionGrade;
    this.keyId = config.keyId || DEFAULT_KEY_ID;
    if (config.transport === 'command' && !config.publicKeySpkiBase64 && !config.publicKeyFile) {
      throw new ExternalSigningError(
        'Command transport needs the public key: set TDCP_SIGNING_EXTERNAL_PUBLIC_KEY_B64 or ' +
          'TDCP_SIGNING_EXTERNAL_PUBLIC_KEY_FILE (SPKI DER, base64).'
      );
    }
  }

  public getKeyId(): string {
    return this.keyId;
  }

  /**
   * Non-exportable key: there is no private CryptoKey in this process.
   * Always throws — this is the point, not a bug. Use signCanonical().
   */
  public async getOrCreateSigningKey(): Promise<CryptoKeyPair> {
    throw new ExternalSigningError(
      'The signing key is non-exportable (external KMS/HSM). ' +
        'Use signCanonical() to sign and getPublicKey() to verify; no private key exists in this process.'
    );
  }

  public async getPublicKey(): Promise<CryptoKey> {
    if (!this.publicKeyPromise) {
      this.publicKeyPromise = this.fetchPublicKey().catch((err) => {
        this.publicKeyPromise = null;
        throw err;
      });
    }
    return this.publicKeyPromise;
  }

  private async fetchPublicKey(): Promise<CryptoKey> {
    let spki: Uint8Array;
    let sidecarKeyId: string | undefined;
    if (this.config.transport === 'http') {
      const body = await this.httpJson('GET', '/v1/public-key');
      spki = decodeBase64Field(body.publicKeySpkiBase64, 'publicKeySpkiBase64');
      if (typeof body.keyId === 'string' && body.keyId) sidecarKeyId = body.keyId;
    } else {
      const b64 = this.config.publicKeySpkiBase64 ?? readPublicKeyFile(this.config.publicKeyFile!);
      spki = decodeBase64Field(b64, 'public key (SPKI)');
    }
    if (sidecarKeyId) {
      if (this.config.keyId && sidecarKeyId !== this.config.keyId) {
        throw new ExternalSigningError(
          `Sidecar keyId ${JSON.stringify(sidecarKeyId)} does not match ` +
            `TDCP_SIGNING_EXTERNAL_KEY_ID=${JSON.stringify(this.config.keyId)}. Refusing to sign with the wrong key.`
        );
      }
      this.keyId = sidecarKeyId;
    }
    try {
      return await crypto.subtle.importKey(
        'spki',
        spki as BufferSource,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['verify']
      );
    } catch {
      throw new ExternalSigningError('The external signer public key is not a valid P-256 SPKI key.');
    }
  }

  /**
   * Sign canonical grant bytes with the external signer.
   * Returns the raw ECDSA P-256 signature (r||s, 64 bytes), the same bytes
   * WebCrypto produces — so grant verification is unchanged.
   */
  public async signCanonical(canonicalUtf8: string): Promise<ArrayBuffer> {
    const raw = this.config.transport === 'http'
      ? await this.signViaHttp(canonicalUtf8)
      : await this.signViaCommand(canonicalUtf8);
    if (raw.byteLength !== 64) {
      throw new ExternalSigningError(
        `External signer returned a ${raw.byteLength}-byte signature; a P-256 raw signature must be 64 bytes.`
      );
    }
    // Copy into a fresh ArrayBuffer (no shared backing store surprises).
    return raw.slice(0, 64).buffer as ArrayBuffer;
  }

  private async signViaHttp(canonicalUtf8: string): Promise<Uint8Array> {
    const body = await this.httpJson('POST', '/v1/sign', { canonical: canonicalUtf8 });
    return decodeBase64Field(body.signatureBase64, 'signatureBase64');
  }

  private async httpJson(
    method: 'GET' | 'POST',
    path: string,
    payload?: Record<string, string>
  ): Promise<Record<string, unknown>> {
    const url = `${this.config.url}${path}`;
    let res: Response;
    try {
      res = await fetch(url, {
        method,
        headers: {
          'content-type': 'application/json',
          ...(this.config.token ? { authorization: `Bearer ${this.config.token}` } : {}),
        },
        ...(payload ? { body: JSON.stringify(payload) } : {}),
        signal: AbortSignal.timeout(this.config.timeoutMs),
      });
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      throw new ExternalSigningError(`Cannot reach external signer at ${url} (${reason}).`);
    }
    if (!res.ok) {
      throw new ExternalSigningError(
        `External signer at ${url} answered HTTP ${res.status}. Signing refused (fail closed).`
      );
    }
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      throw new ExternalSigningError(`External signer at ${url} answered with invalid JSON.`);
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      throw new ExternalSigningError(`External signer at ${url} answered with an unexpected body.`);
    }
    return body as Record<string, unknown>;
  }

  private signViaCommand(canonicalUtf8: string): Promise<Uint8Array> {
    const argv = this.config.command!;
    const timeoutMs = this.config.timeoutMs;
    return new Promise<Uint8Array>((resolve, reject) => {
      let stdout = '';
      let stderr = '';
      let settled = false;
      const fail = (message: string) => {
        if (settled) return;
        settled = true;
        reject(new ExternalSigningError(message));
      };
      let child;
      try {
        child = execFile(argv[0], argv.slice(1), { timeout: timeoutMs, maxBuffer: 1024 * 1024 });
      } catch (err) {
        fail(`Cannot start external signer command (${err instanceof Error ? err.message : String(err)}).`);
        return;
      }
      const timer = setTimeout(() => {
        try {
          child.kill('SIGKILL');
        } catch {
          /* already gone */
        }
        fail(`External signer command timed out after ${timeoutMs} ms.`);
      }, timeoutMs + 1000);
      child.stdout?.on('data', (chunk: Buffer | string) => {
        stdout += chunk.toString('utf8');
      });
      child.stderr?.on('data', (chunk: Buffer | string) => {
        stderr += chunk.toString('utf8');
      });
      child.on('error', (err) => {
        clearTimeout(timer);
        fail(`Cannot start external signer command (${err.message}).`);
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        if (settled) return;
        if (code !== 0) {
          fail(
            `External signer command exited with code ${code}` +
              (stderr.trim() ? `: ${stderr.trim().slice(0, 200)}` : '.') +
              ' Signing refused (fail closed).'
          );
          return;
        }
        const line = stdout.trim().split(/\s+/)[0] ?? '';
        if (!line) {
          fail('External signer command printed no signature on stdout.');
          return;
        }
        try {
          settled = true;
          resolve(base64ToUint8Array(line));
        } catch {
          fail('External signer command printed an invalid base64 signature.');
        }
      });
      // Canonical UTF-8 bytes on stdin; close stdin so the signer can finish.
      child.stdin?.end(canonicalUtf8, 'utf8');
    });
  }
}

function readPublicKeyFile(path: string): string {
  try {
    return readFileSync(path, 'utf8').trim();
  } catch (err) {
    throw new ExternalSigningError(
      `Cannot read TDCP_SIGNING_EXTERNAL_PUBLIC_KEY_FILE ${JSON.stringify(path)} (${err instanceof Error ? err.message : String(err)}).`
    );
  }
}
