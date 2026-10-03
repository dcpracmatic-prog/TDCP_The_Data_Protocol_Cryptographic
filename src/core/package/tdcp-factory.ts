/**
 * The Data Cryptographic Protocol (TDCP)
 * Official package factory — the only way the application creates a TDCPPackage.
 *
 * UI components must call this. They must not call AES-GCM or PBKDF2 directly.
 */

import type { AuthorizationOracle } from '../../oracle/authorization-oracle.ts';
import type { AuthorizationAuthority } from '../../authority/types.ts';
import { InProcessAuthority } from '../../authority/in-process-authority.ts';
import type { PolicyLevel } from '../authorization/types.ts';
import type { EdgeSpec } from '../../channel/policy-binding.ts';
import {
  generateRandomBytes,
  generateRandomId,
  deriveRootKeyFromSecret,
  encryptAESGCM,
  generateContentEncryptionKey,
  arrayBufferToBase64,
  wipeBuffer,
  TDCP_DEFAULT_PBKDF2_ITERATIONS,
} from '../crypto/primitives.ts';
import {
  TDCP_MAGIC_HEADER,
  TDCP_CURRENT_VERSION,
  TDCP_ENVELOPE_WRAP_EPOCH,
  createAADBytes,
  deriveKeyWrappingKey,
  computePackageIntegrityHash,
} from './package-format.ts';
import type { TDCPPackage } from './package-format.ts';
import { splitIntoABCFragments } from './ultra-critical.ts';

export interface CreateTDCPPackageInput {
  plaintext: ArrayBuffer;
  password: string;
  originalFileName: string;
  mimeType: string;
  policyLevel: PolicyLevel;
  allowExtraction: boolean;
  expirationDays?: number;
  /** Override policy createdAt (tests: simulated age). */
  policyCreatedAt?: number;
  viewOnce?: boolean;
  watermarkRequired?: boolean;
  blurMode?: boolean;
  /**
   * Verified user ids (resolved by the issuer backend) allowed to open the
   * document besides its owner. Only enforced by a remote Authority with
   * TDCP_USER_AUTH=required; the owner is always the signed-in caller.
   */
  allowedUserIds?: string[];
  /** Opening requires a verified USB-HSM (implicit for CRITICAL/ULTRA_CRITICAL). */
  requireUsbHsm?: boolean;
  /** Optional explicit data-plane edges; otherwise A→B is bound to plaintext size. */
  channelEdges?: EdgeSpec[];
  /** Preferred: Authorization Authority (in-process or remote). */
  authority?: AuthorizationAuthority;
  /** @deprecated Prefer `authority`. Kept for existing callers/tests. */
  oracle?: AuthorizationOracle;
}

/**
 * Creates a TDCPPackage, registers its policy in the Oracle, and wraps the CEK
 * under (password root key XOR Oracle document wrap secret).
 *
 * The returned bytes contain ciphertext only. Copying them does not copy
 * authorization, wrap secrets, or grants.
 */
export async function createTDCPPackage(input: CreateTDCPPackageInput): Promise<TDCPPackage> {
  const createdAt = input.policyCreatedAt ?? Date.now();
  const plaintextBytes = new Uint8Array(input.plaintext);
  const defaultChannelEdges: EdgeSpec[] = [
    { source: 'A', destination: 'B', expectedBytes: plaintextBytes.byteLength, allowed: true },
  ];

  const authority =
    input.authority ??
    (input.oracle ? new InProcessAuthority(input.oracle) : null);
  if (!authority) {
    throw new Error('AUTHORITY_REQUIRED: createTDCPPackage requires authority or oracle');
  }

  // Reserve the identity before producing ciphertext. A random-ID collision
  // must not make a legitimate issuance fail; retry only the reservation.
  let documentId = '';
  let packageId = '';
  let oracleWrapSecret: Uint8Array | undefined;
  for (let attempt = 0; attempt < 4; attempt += 1) {
    documentId = generateRandomId('DOC');
    packageId = generateRandomId('PKG');
    try {
      oracleWrapSecret = await authority.registerDocumentPolicy({
        documentId,
        packageId,
        policyLevel: input.policyLevel,
        allowExtraction: input.allowExtraction,
        expirationDays: input.expirationDays,
        viewOnce: input.viewOnce,
        createdAt,
        ...(input.requireUsbHsm ? { requireUsbHsm: true } : {}),
        channelEdges: input.channelEdges ?? defaultChannelEdges,
        ...(input.allowedUserIds && input.allowedUserIds.length > 0
          ? { allowedUserIds: input.allowedUserIds }
          : {}),
      });
      break;
    } catch (err) {
      if (!(err instanceof Error) || err.message !== 'DOCUMENT_ALREADY_REGISTERED' || attempt === 3) {
        throw err;
      }
    }
  }
  if (!oracleWrapSecret) throw new Error('AUTHORITY_REGISTRATION_FAILED');

  const salt = generateRandomBytes(32);
  const iv = generateRandomBytes(12);

  const cek = await generateContentEncryptionKey();
  const rawCek = new Uint8Array(await crypto.subtle.exportKey('raw', cek));

  const aad = createAADBytes(documentId, packageId, TDCP_CURRENT_VERSION, {
    policyLevel: input.policyLevel,
    allowExtraction: input.allowExtraction,
    expirationDays: input.expirationDays,
    viewOnce: input.viewOnce,
    kdfIterations: TDCP_DEFAULT_PBKDF2_ITERATIONS,
  });
  let ciphertextBase64 = '';
  let ultraCritical: TDCPPackage['ultraCritical'];

  if (input.policyLevel === 'ULTRA_CRITICAL') {
    const mid = Math.ceil(plaintextBytes.byteLength / 2);
    const halfA = plaintextBytes.slice(0, mid);
    const halfB = plaintextBytes.slice(mid);
    const ivA = generateRandomBytes(12);
    const ivB = generateRandomBytes(12);
    const encA = await encryptAESGCM(cek, halfA, ivA, aad);
    const encB = await encryptAESGCM(cek, halfB, ivB, aad);
    ultraCritical = await splitIntoABCFragments(
      documentId,
      packageId,
      input.originalFileName,
      input.mimeType || 'application/octet-stream',
      encA,
      ivA,
      encB,
      ivB,
      plaintextBytes.byteLength
    );
    wipeBuffer(halfA);
    wipeBuffer(halfB);
  } else {
    const ciphertext = await encryptAESGCM(cek, plaintextBytes, iv, aad);
    ciphertextBase64 = arrayBufferToBase64(ciphertext);
  }

  const rootKey = await deriveRootKeyFromSecret(
    input.password,
    salt,
    TDCP_DEFAULT_PBKDF2_ITERATIONS
  );
  const kwk = await deriveKeyWrappingKey(
    rootKey,
    salt,
    documentId,
    TDCP_ENVELOPE_WRAP_EPOCH,
    oracleWrapSecret
  );
  const ivKey = generateRandomBytes(12);
  const wrappedKeyBytes = await encryptAESGCM(kwk, rawCek, ivKey);
  wipeBuffer(rawCek);

  const pkg: TDCPPackage = {
    magicHeader: TDCP_MAGIC_HEADER,
    version: TDCP_CURRENT_VERSION,
    algorithm: 'AES-256-GCM / HKDF-SHA256',
    documentId,
    packageId,
    saltBase64: arrayBufferToBase64(salt),
    ivBase64: arrayBufferToBase64(iv),
    ciphertextBase64,
    aadBase64: arrayBufferToBase64(aad),
    metadata: {
      originalFileName: input.originalFileName,
      mimeType: input.mimeType || 'application/octet-stream',
      originalSizeBytes: plaintextBytes.byteLength,
      createdAt,
      policyLevel: input.policyLevel,
      expirationDays: input.expirationDays,
      viewOnce: input.viewOnce,
      watermarkRequired: input.watermarkRequired,
      allowExtraction: input.allowExtraction,
      blurMode: input.blurMode,
      kdfIterations: TDCP_DEFAULT_PBKDF2_ITERATIONS,
      documentId,
      packageId,
    },
    integrityHash: '',
    wrappedKeyBase64: arrayBufferToBase64(wrappedKeyBytes),
    ivKeyBase64: arrayBufferToBase64(ivKey),
    envelopeEpoch: TDCP_ENVELOPE_WRAP_EPOCH,
    ultraCritical,
  };

  pkg.integrityHash = await computePackageIntegrityHash(pkg);
  return pkg;
}
