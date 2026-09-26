/**
 * Encrypt Authority signing private JWK at rest (AES-256-GCM + scrypt).
 * No AWS KMS — passphrase from env or key file only.
 *
 * Env:
 *   TDCP_AUTHORITY_KEY_PASSPHRASE  — preferred for operators
 *   TDCP_AUTHORITY_KEY_FILE        — optional path to passphrase file (0600)
 *
 * Without a passphrase, keys may remain plaintext JSON (development only; warned).
 */

import {
  createHash,
  randomBytes,
  createCipheriv,
  createDecipheriv,
  scryptSync,
} from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';

const MAGIC = 'TDCP-KEY1';
const IV_LEN = 12;
const TAG_LEN = 16;

export type EncryptedPrivateKeyBlob = {
  v: 1;
  alg: 'AES-256-GCM';
  /** base64 iv */
  iv: string;
  /** base64 ciphertext+tag */
  ct: string;
  /** salt for passphrase → key (base64) */
  salt: string;
};

export function readAuthorityKeyPassphrase(
  env: Record<string, string | undefined> = process.env as Record<string, string | undefined>
): string | null {
  const direct = env.TDCP_AUTHORITY_KEY_PASSPHRASE?.trim();
  if (direct) return direct;
  const file = env.TDCP_AUTHORITY_KEY_FILE?.trim();
  if (file && existsSync(file)) {
    try {
      return readFileSync(file, 'utf8').trim() || null;
    } catch {
      return null;
    }
  }
  return null;
}

function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, 32, { N: 16384, r: 8, p: 1 });
}

export function encryptPrivateJwk(
  privateJwk: JsonWebKey,
  passphrase: string
): EncryptedPrivateKeyBlob {
  const salt = randomBytes(16);
  const key = deriveKey(passphrase, salt);
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const plain = Buffer.from(JSON.stringify(privateJwk), 'utf8');
  const enc = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    v: 1,
    alg: 'AES-256-GCM',
    iv: iv.toString('base64'),
    ct: Buffer.concat([enc, tag]).toString('base64'),
    salt: salt.toString('base64'),
  };
}

export function decryptPrivateJwk(
  blob: EncryptedPrivateKeyBlob,
  passphrase: string
): JsonWebKey {
  if (blob.v !== 1 || blob.alg !== 'AES-256-GCM') {
    throw new Error('UNSUPPORTED_ENCRYPTED_KEY_BLOB');
  }
  const salt = Buffer.from(blob.salt, 'base64');
  const key = deriveKey(passphrase, salt);
  const iv = Buffer.from(blob.iv, 'base64');
  const data = Buffer.from(blob.ct, 'base64');
  if (data.length < TAG_LEN) throw new Error('CORRUPT_ENCRYPTED_KEY');
  const tag = data.subarray(data.length - TAG_LEN);
  const enc = data.subarray(0, data.length - TAG_LEN);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(enc), decipher.final()]);
  return JSON.parse(plain.toString('utf8')) as JsonWebKey;
}

export function isEncryptedPrivateKeyBlob(value: unknown): value is EncryptedPrivateKeyBlob {
  if (!value || typeof value !== 'object') return false;
  const v = value as Record<string, unknown>;
  return v.v === 1 && v.alg === 'AES-256-GCM' && typeof v.iv === 'string' && typeof v.ct === 'string';
}

/** Fingerprint for logging without revealing key material. */
export function passphraseFingerprint(passphrase: string): string {
  return createHash('sha256').update(MAGIC).update(passphrase).digest('hex').slice(0, 12);
}
