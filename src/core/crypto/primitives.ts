/**
 * The Data Cryptographic Protocol (TDCP)
 * Core Cryptographic Primitives (Web Crypto API compliant)
 * 
 * Standards:
 * - NIST SP 800-38D (AES-GCM)
 * - RFC 5869 (HKDF)
 * - FIPS 186-4 (ECDSA P-256)
 * - RFC 8018 (PBKDF2)
 */

export interface KeyDerivationContext {
  documentId: string;
  deviceId: string;
  authorizationEpoch: number;
  operationId: string;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Narrow Uint8Array for DOM lib BufferSource (TS 5.7+ ArrayBufferLike). */
function asBufferSource(data: Uint8Array | ArrayBuffer): BufferSource {
  if (data instanceof ArrayBuffer) return data;
  return data as unknown as BufferSource;
}


/**
 * High-entropy CSPRNG buffer generation
 */
export function generateRandomBytes(byteLength: number): Uint8Array {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * Generate cryptographically random hex/base64 string
 */
export function generateRandomId(prefix: string = 'ID'): string {
  const randomBytes = generateRandomBytes(12);
  const hex = Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${prefix}-${hex.toUpperCase()}`;
}

/**
 * Computes SHA-256 digest
 */
export async function computeSHA256(data: ArrayBuffer | Uint8Array | string): Promise<string> {
  const buffer: BufferSource = typeof data === 'string'
    ? encoder.encode(data)
    : asBufferSource(data);
  const digestBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(digestBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Derives a root key from user password and salt using PBKDF2 (100,000 to 600,000 rounds)
 */
export const TDCP_DEFAULT_PBKDF2_ITERATIONS = 600_000;

export async function deriveRootKeyFromSecret(
  password: string,
  salt: Uint8Array,
  iterations = TDCP_DEFAULT_PBKDF2_ITERATIONS
): Promise<CryptoKey> {
  if (!Number.isInteger(iterations) || iterations < 100_000 || iterations > 2_000_000) {
    throw new Error('INVALID_PBKDF2_ITERATIONS');
  }
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: asBufferSource(salt),
      iterations,
      hash: 'SHA-256'
    },
    keyMaterial,
    256
  );

  return await crypto.subtle.importKey(
    'raw',
    bits,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );
}

/**
 * Generates an independent, cryptographically random root content encryption key (CEK)
 */
export async function generateContentEncryptionKey(): Promise<CryptoKey> {
  return await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true, // exportable for packaging encryption
    ['encrypt', 'decrypt']
  );
}

/**
 * TDCP Mandatory Principle: "The token is not the document key."
 * Uses HKDF (RFC 5869) to derive an ephemeral, context-bound AES-256-GCM key.
 * 
 * Context binds: document_id, device_id, authorization_epoch, operation_id.
 */
export async function deriveEphemeralDocumentKey(
  rootKeyMaterial: CryptoKey,
  salt: Uint8Array,
  context: KeyDerivationContext
): Promise<CryptoKey> {
  // Construct canonical contextual info string
  const canonicalContext = [
    'TDCP-EPHEMERAL-KEY-v2.5',
    `DOC:${context.documentId}`,
    `DEV:${context.deviceId}`,
    `EPOCH:${context.authorizationEpoch}`,
    `OP:${context.operationId}`
  ].join('|');

  const infoBytes = encoder.encode(canonicalContext);

  return await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: asBufferSource(salt),
      info: asBufferSource(infoBytes)
    },
    rootKeyMaterial,
    { name: 'AES-GCM', length: 256 },
    false, // Never export ephemeral keys from memory
    ['encrypt', 'decrypt']
  );
}

/**
 * Authenticated Encryption with AES-256-GCM
 */
export async function encryptAESGCM(
  key: CryptoKey,
  plaintext: Uint8Array | ArrayBuffer,
  iv: Uint8Array,
  additionalData?: Uint8Array
): Promise<ArrayBuffer> {
  const params: AesGcmParams = {
    name: 'AES-GCM',
    iv: asBufferSource(iv),
    tagLength: 128
  };
  if (additionalData && additionalData.byteLength > 0) {
    params.additionalData = asBufferSource(additionalData);
  }
  return await crypto.subtle.encrypt(params, key, asBufferSource(plaintext));
}

/**
 * Authenticated Decryption with AES-256-GCM
 */
export async function decryptAESGCM(
  key: CryptoKey,
  ciphertextWithTag: Uint8Array | ArrayBuffer,
  iv: Uint8Array,
  additionalData?: Uint8Array
): Promise<ArrayBuffer> {
  const params: AesGcmParams = {
    name: 'AES-GCM',
    iv: asBufferSource(iv),
    tagLength: 128
  };
  if (additionalData && additionalData.byteLength > 0) {
    params.additionalData = asBufferSource(additionalData);
  }
  return await crypto.subtle.decrypt(params, key, asBufferSource(ciphertextWithTag));
}

/**
 * ECDSA P-256 Keypair generation for Authorization Oracle
 */
export async function generateOracleKeyPair(): Promise<CryptoKeyPair> {
  return await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256'
    },
    true,
    ['sign', 'verify']
  );
}

/**
 * ECDSA P-256 Signature over payload string
 */
export async function signDataECDSA(privateKey: CryptoKey, data: string): Promise<string> {
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    privateKey,
    encoder.encode(data)
  );
  return arrayBufferToBase64(signature);
}

/**
 * ECDSA P-256 Signature verification
 */
export async function verifySignatureECDSA(
  publicKey: CryptoKey,
  signatureBase64: string,
  data: string
): Promise<boolean> {
  try {
    const sigBuffer = base64ToArrayBuffer(signatureBase64);
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      publicKey,
      sigBuffer,
      encoder.encode(data)
    );
  } catch {
    return false;
  }
}

/**
 * Best-effort zeroization of TypedArrays.
 * Note: JavaScript garbage collection is managed and strings cannot be physically overwritten,
 * but typed buffers should always be wiped explicitly.
 */
export function wipeBuffer(buf: ArrayBuffer | Uint8Array | null | undefined): void {
  if (!buf) return;
  try {
    const view = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    view.fill(0);
    // Overwrite with random before release
    crypto.getRandomValues(view);
    view.fill(0);
  } catch {
    // Ignored in read-only buffer edge cases
  }
}

// Base64 helper utilities
export function arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}
