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

import { computeSHA256, bytesToHex, arrayBufferToBase64, base64ToByteLength, TDCP_DEFAULT_PBKDF2_ITERATIONS } from '../crypto/primitives.ts';
import type { PolicyLevel } from '../authorization/types.ts';
import type { UltraCriticalABCBundle } from './ultra-critical.ts';
import type { CsgSealDocument } from '../../protection/csg-seal.ts';

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
  /**
   * Custodia de la CEK. `'oracle'` (default, sin cambios) o
   * `'smart-token'` (P2-6: la CEK vive custodiada por Smart Token y el
   * paquete no contiene CEK envuelta por el Oracle).
   */
  custodyMode?: 'oracle' | 'smart-token';
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
  /**
   * Optional CSG integrity seal over the whole package (P2-5).
   * Covers the canonical envelope bytes (see canonicalPackageEnvelopeString):
   * structure + full content (ciphertext, AAD, metadata, wrapped CEK,
   * ultra-critical fragments). It lives INSIDE the .pkg so the seal travels
   * with the package — no sidecar file needed.
   * Absent on legacy packages: they still open via the current path, but
   * without any CSG guarantee. The seal is an ADDITIONAL integrity layer:
   * it never replaces AES-GCM authentication or the Gatekeeper grant.
   * Deliberately EXCLUDED from the canonical envelope string (and therefore
   * from integrityHash): the seal is computed over the envelope, so including
   * it would be circular.
   */
  csgSeal?: CsgSealDocument;
  /**
   * Present only when metadata.custodyMode === 'smart-token' (P2-6).
   * Referencia opaca al artefacto Smart Token que custodia la CEK.
   * En este modo NO hay wrappedKeyBase64/ivKeyBase64: el paquete no
   * contiene ninguna copia de la CEK envuelta por el Oracle.
   */
  smartTokenCustody?: { artifactId: string; version: 1 };
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
  const secretHex = bytesToHex(oracleWrapSecret);
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

    const isSmartTokenCustody = parsed.metadata?.custodyMode === 'smart-token';
    if (isSmartTokenCustody) {
      // P2-6: en custodia Smart Token el paquete NO debe contener ninguna
      // CEK envuelta por el Oracle (una segunda copia anularía la custodia).
      if (parsed.wrappedKeyBase64 || parsed.ivKeyBase64) {
        return {
          isValidEnvelope: false,
          error: 'Paquete smart-token-custody con CEK envuelta por el Oracle. Formato no autorizado.',
        };
      }
      if (
        !parsed.smartTokenCustody ||
        parsed.smartTokenCustody.version !== 1 ||
        typeof parsed.smartTokenCustody.artifactId !== 'string' ||
        !parsed.smartTokenCustody.artifactId
      ) {
        return {
          isValidEnvelope: false,
          error: 'Paquete smart-token-custody sin referencia de custodia Smart Token válida.',
        };
      }
    } else {
      if (parsed.smartTokenCustody) {
        return {
          isValidEnvelope: false,
          error: 'Paquete con referencia de custodia Smart Token pero sin modo smart-token.',
        };
      }
      if (!parsed.wrappedKeyBase64 || !parsed.ivKeyBase64) {
        return {
          isValidEnvelope: false,
          error: 'El paquete no contiene CEK envuelto. Formato antiguo o incompleto.',
        };
      }
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

    if (
      parsed.csgSeal !== undefined &&
      (typeof parsed.csgSeal !== 'object' || parsed.csgSeal === null)
    ) {
      return {
        isValidEnvelope: false,
        error: 'Sello CSG corrupto: el campo csgSeal no es un documento de sello válido.',
      };
    }

    if (parsed.envelopeEpoch === undefined) {
      parsed.envelopeEpoch = TDCP_ENVELOPE_WRAP_EPOCH;
    }

    if (!Number.isInteger(parsed.metadata?.kdfIterations) || parsed.metadata.kdfIterations < 100_000 || parsed.metadata.kdfIterations > 2_000_000) {
      return { isValidEnvelope: false, error: 'Paquete con kdfIterations ausente o fuera de rango.' };
    }

    try {
      // Optimization: calculate decoded byte length with zero buffer allocations via base64ToByteLength
      const ivLength = base64ToByteLength(parsed.ivBase64);
      const saltLength = base64ToByteLength(parsed.saltBase64);
      const keyIvLength = parsed.ivKeyBase64 ? base64ToByteLength(parsed.ivKeyBase64) : 0;
      if (ivLength !== 12 || saltLength < 16) {
        return { isValidEnvelope: false, error: 'Longitudes criptográficas inválidas (IV/salt).' };
      }
      if (!isSmartTokenCustody && keyIvLength !== 12) {
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

/**
 * Canonical envelope string: the exact bytes the CSG package seal covers
 * (and the string integrityHash hashes). It lists every security-relevant
 * envelope field in a fixed order — structure + full content — and
 * deliberately excludes `csgSeal` itself (the seal is computed over it).
 * A package serialized, parsed and re-serialized keeps the same canonical
 * string because JSON round-trips preserve key order and the factory writes
 * fields in this fixed order.
 */
export function canonicalPackageEnvelopeString(pkg: TDCPPackage): string {
  return JSON.stringify({
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
    // Solo cuando está presente: los paquetes oracle existentes mantienen
    // su hash intacto; la referencia de custodia queda ligada al sobre.
    ...(pkg.smartTokenCustody ? { smartTokenCustody: pkg.smartTokenCustody } : {}),
  });
}

/** Canonical envelope bytes sealed by CSG at protect time. */
export function canonicalPackageEnvelopeBytes(pkg: TDCPPackage): Uint8Array {
  return new TextEncoder().encode(canonicalPackageEnvelopeString(pkg));
}

export async function computePackageIntegrityHash(pkg: TDCPPackage): Promise<string> {
  // Unkeyed envelope integrity is a corruption/tamper signal only; AES-GCM
  // remains the authenticity boundary for ciphertext. Keep the canonical
  // representation explicit so security-relevant metadata cannot drift.
  return computeSHA256(canonicalPackageEnvelopeString(pkg));
}

export { arrayBufferToBase64 };
