/**
 * Soft Smart Token path for free/demo when no remote API is configured.
 * AES-256-GCM + master via PBKDF2. Not the full ML-KEM Smart Token Prod stack.
 * Prefer SmartTokenClient + self-hosted API when VITE_SMART_TOKEN_API_URL is set.
 */

export interface SoftSmartTokenArtifact {
  schema: 'tdcp.soft-stok.v1';
  artifactId: string;
  filename: string;
  mimeType: string;
  createdAt: number;
  saltBase64: string;
  ivBase64: string;
  ciphertextBase64: string;
  developmentOnly: true;
  note: string;
}

function b64(buf: ArrayBuffer | Uint8Array): string {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]!);
  return btoa(s);
}

function fromB64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function deriveKey(master: string, salt: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(master),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt.buffer as ArrayBuffer, iterations: 210_000, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function softSmartTokenProtect(
  plaintext: ArrayBuffer,
  master: string,
  filename: string,
  mimeType: string
): Promise<SoftSmartTokenArtifact> {
  if (!master || master.length < 8) {
    throw new Error('Smart Token master debe tener al menos 8 caracteres');
  }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(master, salt);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    plaintext
  );
  const artifactId = `stok-soft-${Date.now().toString(16)}-${b64(salt).slice(0, 6)}`;
  return {
    schema: 'tdcp.soft-stok.v1',
    artifactId,
    filename,
    mimeType,
    createdAt: Date.now(),
    saltBase64: b64(salt),
    ivBase64: b64(iv),
    ciphertextBase64: b64(ct),
    developmentOnly: true,
    note: 'Soft Smart Token (AES-GCM). Use self-hosted Smart-Token-Prod API for ML-KEM + friction machine.',
  };
}

export async function softSmartTokenOpen(
  artifact: SoftSmartTokenArtifact,
  master: string
): Promise<ArrayBuffer> {
  const salt = fromB64(artifact.saltBase64);
  const iv = fromB64(artifact.ivBase64);
  const ct = fromB64(artifact.ciphertextBase64);
  const key = await deriveKey(master, salt);
  return crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
    key,
    ct.buffer as ArrayBuffer
  );
}

export function allowSoftSmartToken(): boolean {
  const env =
    typeof import.meta !== 'undefined'
      ? (import.meta as ImportMeta & { env?: Record<string, string> }).env
      : undefined;
  const v = (env?.VITE_TDCP_ALLOW_SOFT_STP ?? '1').trim().toLowerCase();
  // Default ON for free/demo deploys; set VITE_TDCP_ALLOW_SOFT_STP=0 for pre-prod.
  return v !== '0' && v !== 'false' && v !== 'no';
}

export function readSmartTokenApiConfig(): { baseUrl: string; apiKey: string } | null {
  const env =
    typeof import.meta !== 'undefined'
      ? (import.meta as ImportMeta & { env?: Record<string, string> }).env
      : undefined;
  const baseUrl = (env?.VITE_SMART_TOKEN_API_URL || '').trim();
  if (!baseUrl) return null;
  return {
    baseUrl,
    apiKey: (env?.VITE_SMART_TOKEN_API_KEY || '').trim(),
  };
}
