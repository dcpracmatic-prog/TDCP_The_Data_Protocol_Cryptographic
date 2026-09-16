/**
 * The Data Cryptographic Protocol (TDCP)
 * Versioned Cryptographic Package Format (.pkg)
 *
 * Guarantees:
 * - Versioned envelope
 * - Zero plaintext stored
 * - Zero master secrets or reusable credentials stored
 * - Metadata authenticated via AES-GCM Additional Authenticated Data (AAD)
 * - Storage independent: Can be copied anywhere without granting authorization
 *
 * THIS IS THE SINGLE PACKAGE SPECIFICATION. Do not invent a parallel format.
 */

import { computeSHA256, arrayBufferToBase64, TDCP_DEFAULT_PBKDF2_ITERATIONS } from '../crypto/primitives.ts';
import type { PolicyLevel } from '../authorization/types.ts';
import type { UltraCriticalABCBundle } from './ultra-critical.ts';

export const TDCP_MAGIC_HEADER = 'TDCP_SECURE_PKG';
export const TDCP_CURRENT_VERSION = '2.5-SEC';

/** Envelope wrapping always uses this epoch so restore/revoke can rotate grant epochs independently. */
export const TDCP_ENVELOPE_WRAP_EPOCH = 1;

export interface TDCPPackageMetadata {
  originalFileName: string;
  mimeType: string;
  originalSizeBytes: number;
  createdAt: number;
  policyLevel: PolicyLevel;
  expirationDays?: number;
  viewOnce?: boolean;
  watermarkRequired?: boolean;
  allowExtraction?: boolean;
  /** UI preference only — not an authorization decision. */
  blurMode?: boolean;
  /** Explicit KDF work factor for deterministic package interpretation. */
  kdfIterations: number;
  documentId: string;
  packageId: string;
}

export interface TDCPPackage {
  magicHeader: string;
  version: string;
  algorithm: 'AES-256-GCM / HKDF-SHA256';
  documentId: string;
  packageId: string;
  saltBase64: string;
  ivBase64: string;
  ciphertextBase64: string;
  aadBase64: string;
  metadata: TDCPPackageMetadata;
  integrityHash: string;
  wrappedKeyBase64?: string;
  ivKeyBase64?: string;
  /** Always 1. Authorization epoch lives in the Oracle, not in the package. */
  envelopeEpoch: number;
  /** Present only when policyLevel === ULTRA_CRITICAL. */
  ultraCritical?: UltraCriticalABCBundle;
}

/**
 * Creates the AAD bytes that must be cryptographically bound to AES-GCM
 */
export interface SecurityAADContext {
  policyLevel: PolicyLevel;
  allowExtraction: boolean;
  expirationDays?: number;
  viewOnce?: boolean;
  kdfIterations: number;
}

export function createAADBytes(
  documentId: string,
  packageId: string,
  version: string,
  security?: SecurityAADContext
): Uint8Array {
  const aadString = [
    'TDCP-AAD-v2.5',
    `DOC=${documentId}`,
    `PKG=${packageId}`,
    `VER=${version}`,
    `POLICY=${security?.policyLevel ?? 'UNSPECIFIED'}`,
    `EXTRACT=${security?.allowExtraction ? '1' : '0'}`,
    `EXP_DAYS=${security?.expirationDays ?? ''}`,
    `VIEW_ONCE=${security?.viewOnce ? '1' : '0'}`,
    `KDF_ITERS=${security?.kdfIterations ?? TDCP_DEFAULT_PBKDF2_ITERATIONS}`,
  ].join('|');
  return new TextEncoder().encode(aadString);
}

/**
 * Derives the key-wrapping key (KWK) for protecting the content encryption key (CEK).
 *
 * Password-derived root key is NOT sufficient: `oracleWrapSecret` is a
 * document-bound secret held only by the Authorization Oracle. Copying the
 * package does not copy this secret.
 */
export async function deriveKeyWrappingKey(
  rootKey: CryptoKey,
  salt: Uint8Array,
  documentId: string,
  epoch: number,
  oracleWrapSecret: Uint8Array
): Promise<CryptoKey> {
  const secretHex = Array.from(oracleWrapSecret)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  const contextInfo = new TextEncoder().encode(
    `TDCP-ENVELOPE-WRAP-v2.5::DOC:${documentId}::EPOCH:${epoch}::ORACLEWRAP:${secretHex}`
  );
  return await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt as unknown as BufferSource,
      info: contextInfo as unknown as BufferSource,
    },
    rootKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function serializeTDCPPackage(pkg: TDCPPackage): Promise<Blob> {
  const json = JSON.stringify(pkg, null, 2);
  return new Blob([json], { type: 'application/octet-stream' });
}

export async function deserializeTDCPPackage(data: ArrayBuffer | string): Promise<{
  isValidEnvelope: boolean;
  package?: TDCPPackage;
  error?: string;
}> {
  try {
    let jsonStr: string;
    if (typeof data === 'string') {
      jsonStr = data;
    } else {
      jsonStr = new TextDecoder().decode(data);
    }

    const parsed = JSON.parse(jsonStr) as TDCPPackage;

    if (!parsed || parsed.magicHeader !== TDCP_MAGIC_HEADER) {
      return {
        isValidEnvelope: false,
        error: 'Cabecera inválida. No es un paquete criptográfico TDCP auténtico.',
      };
    }

    if (parsed.version !== TDCP_CURRENT_VERSION || parsed.algorithm !== 'AES-256-GCM / HKDF-SHA256') {
      return {
        isValidEnvelope: false,
        error: 'Versión o suite criptográfica TDCP no soportada por este runtime.',
      };
    }

    if (parsed.metadata?.documentId !== parsed.documentId || parsed.metadata?.packageId !== parsed.packageId) {
      return {
        isValidEnvelope: false,
        error: 'Identidad del paquete inconsistente entre envelope y metadata.',
      };
    }

    if (
      !parsed.documentId ||
      !parsed.packageId ||
      !parsed.ivBase64 ||
      !parsed.saltBase64
    ) {
      return {
        isValidEnvelope: false,
        error: 'Estructura de paquete incompleta o corrupta.',
      };
    }

    if (!parsed.wrappedKeyBase64 || !parsed.ivKeyBase64) {
      return {
        isValidEnvelope: false,
        error: 'El paquete no contiene CEK envuelto. Formato antiguo o incompleto.',
      };
    }

    if (parsed.metadata?.policyLevel === 'ULTRA_CRITICAL' && !parsed.ultraCritical) {
      return {
        isValidEnvelope: false,
        error: 'Paquete ULTRA_CRITICAL sin fragmentos A/B/C.',
      };
    }

    if (parsed.metadata?.policyLevel !== 'ULTRA_CRITICAL' && !parsed.ciphertextBase64) {
      return {
        isValidEnvelope: false,
        error: 'Paquete sin ciphertext autenticado.',
      };
    }

    if (parsed.envelopeEpoch === undefined) {
      parsed.envelopeEpoch = TDCP_ENVELOPE_WRAP_EPOCH;
    }

    if (!Number.isInteger(parsed.metadata?.kdfIterations) || parsed.metadata.kdfIterations < 100_000 || parsed.metadata.kdfIterations > 2_000_000) {
      return { isValidEnvelope: false, error: 'Paquete con kdfIterations ausente o fuera de rango.' };
    }

    try {
      const ivLength = new Uint8Array(atob(parsed.ivBase64).length).byteLength;
      const saltLength = new Uint8Array(atob(parsed.saltBase64).length).byteLength;
      const keyIvLength = new Uint8Array(atob(parsed.ivKeyBase64).length).byteLength;
      if (ivLength !== 12 || keyIvLength !== 12 || saltLength < 16) {
        return { isValidEnvelope: false, error: 'Longitudes criptográficas inválidas (IV/salt).' };
      }
    } catch {
      return { isValidEnvelope: false, error: 'Base64 criptográfico inválido en el paquete.' };
    }

    return {
      isValidEnvelope: true,
      package: parsed,
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      isValidEnvelope: false,
      error: `Fallo al deserializar paquete TDCP: ${message}`,
    };
  }
}

export async function computePackageIntegrityHash(pkg: TDCPPackage): Promise<string> {
  // Unkeyed envelope integrity is a corruption/tamper signal only; AES-GCM
  // remains the authenticity boundary for ciphertext. Keep the canonical
  // representation explicit so security-relevant metadata cannot drift.
  const canonical = JSON.stringify({
    magicHeader: pkg.magicHeader,
    version: pkg.version,
    algorithm: pkg.algorithm,
    documentId: pkg.documentId,
    packageId: pkg.packageId,
    saltBase64: pkg.saltBase64,
    ivBase64: pkg.ivBase64,
    ciphertextBase64: pkg.ciphertextBase64,
    aadBase64: pkg.aadBase64,
    metadata: pkg.metadata,
    wrappedKeyBase64: pkg.wrappedKeyBase64 ?? '',
    ivKeyBase64: pkg.ivKeyBase64 ?? '',
    envelopeEpoch: pkg.envelopeEpoch,
    ultraCritical: pkg.ultraCritical ?? null,
  });
  return computeSHA256(canonical);
}

export { arrayBufferToBase64 };
