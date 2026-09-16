/**
 * The Data Cryptographic Protocol (TDCP)
 * ULTRA_CRITICAL A/B/C Maximum Protection Architecture
 * 
 * Objective:
 * Splits high-value assets into three cryptographically bound components:
 * - Fragment A: Encrypted chunk 1 (bound to Hash(B) and Hash(C))
 * - Fragment B: Encrypted chunk 2 (bound to Hash(A) and Hash(C))
 * - Manifest C: Topology and render manifest (bound to Hash(A) and Hash(B))
 * 
 * Properties:
 * - A alone: Inutilizable (incomplete ciphertext & lacks manifest)
 * - B alone: Inutilizable (incomplete ciphertext & lacks manifest)
 * - A + B: Insuficiente (missing authenticated topology manifest C)
 * - C alone: Insuficiente (zero payload, only topology & policy)
 * - A + B + C without valid signed Oracle grant: Cryptographically locked (cannot derive ephemeral keys)
 * - A + B + C + valid grant + matching device + valid epoch: Controlled RAM reconstruction
 */

import { computeSHA256, arrayBufferToBase64, base64ToArrayBuffer, wipeBuffer } from '../crypto/primitives.ts';

export interface FragmentA {
  fragmentType: 'FRAGMENT_A';
  documentId: string;
  chunkIndex: 0;
  totalChunks: 2;
  ciphertextBase64: string;
  ivBase64: string;
  boundHashB: string; // SHA-256 of Fragment B ciphertext
  boundHashC: string; // SHA-256 of Manifest C
}

export interface FragmentB {
  fragmentType: 'FRAGMENT_B';
  documentId: string;
  chunkIndex: 1;
  totalChunks: 2;
  ciphertextBase64: string;
  ivBase64: string;
  boundHashA: string; // SHA-256 of Fragment A ciphertext
  boundHashC: string; // SHA-256 of Manifest C
}

export interface ManifestC {
  manifestType: 'MANIFEST_C';
  documentId: string;
  packageId: string;
  originalFileName: string;
  mimeType: string;
  totalSizeBytes: number;
  policyLevel: 'ULTRA_CRITICAL';
  boundHashA: string; // SHA-256 of Fragment A
  boundHashB: string; // SHA-256 of Fragment B
  jointIntegrityDigest: string; // SHA-256(HashA + HashB)
  renderDirective: 'CONTROLLED_RAM_STREAM_ONLY';
}

export interface UltraCriticalABCBundle {
  fragmentA: FragmentA;
  fragmentB: FragmentB;
  manifestC: ManifestC;
}

/**
 * Splits plaintext into cryptographically bound Fragment A and Fragment B, and generates Manifest C
 */
export async function splitIntoABCFragments(
  documentId: string,
  packageId: string,
  originalFileName: string,
  mimeType: string,
  encryptedBufferA: ArrayBuffer,
  ivA: Uint8Array,
  encryptedBufferB: ArrayBuffer,
  ivB: Uint8Array,
  totalOriginalSize: number
): Promise<UltraCriticalABCBundle> {
  const cipherBase64A = arrayBufferToBase64(encryptedBufferA);
  const cipherBase64B = arrayBufferToBase64(encryptedBufferB);

  const hashA = await computeSHA256(cipherBase64A);
  const hashB = await computeSHA256(cipherBase64B);
  const jointIntegrity = await computeSHA256(`${hashA}::${hashB}`);

  // Construct Manifest C
  const manifestC: ManifestC = {
    manifestType: 'MANIFEST_C',
    documentId,
    packageId,
    originalFileName,
    mimeType,
    totalSizeBytes: totalOriginalSize,
    policyLevel: 'ULTRA_CRITICAL',
    boundHashA: hashA,
    boundHashB: hashB,
    jointIntegrityDigest: jointIntegrity,
    renderDirective: 'CONTROLLED_RAM_STREAM_ONLY'
  };

  const hashC = await computeSHA256(JSON.stringify(manifestC));

  // Construct Fragment A
  const fragmentA: FragmentA = {
    fragmentType: 'FRAGMENT_A',
    documentId,
    chunkIndex: 0,
    totalChunks: 2,
    ciphertextBase64: cipherBase64A,
    ivBase64: arrayBufferToBase64(ivA),
    boundHashB: hashB,
    boundHashC: hashC
  };

  // Construct Fragment B
  const fragmentB: FragmentB = {
    fragmentType: 'FRAGMENT_B',
    documentId,
    chunkIndex: 1,
    totalChunks: 2,
    ciphertextBase64: cipherBase64B,
    ivBase64: arrayBufferToBase64(ivB),
    boundHashA: hashA,
    boundHashC: hashC
  };

  return { fragmentA, fragmentB, manifestC };
}

/**
 * Validates the cross-binding integrity of Fragment A, Fragment B, and Manifest C
 */
export async function verifyABCInterlockingIntegrity(
  fragmentA: FragmentA,
  fragmentB: FragmentB,
  manifestC: ManifestC
): Promise<{ isValid: boolean; reason?: string }> {
  if (fragmentA.documentId !== manifestC.documentId || fragmentB.documentId !== manifestC.documentId) {
    return { isValid: false, reason: 'Discrepancia de Document ID entre fragmentos A, B y Manifiesto C' };
  }

  const actualHashA = await computeSHA256(fragmentA.ciphertextBase64);
  const actualHashB = await computeSHA256(fragmentB.ciphertextBase64);
  const actualHashC = await computeSHA256(JSON.stringify(manifestC));

  // Check Fragment A cross-hashes
  if (fragmentA.boundHashB !== actualHashB || fragmentA.boundHashC !== actualHashC) {
    return { isValid: false, reason: 'Fragmento A no coincide con los hashes de B o C (Manipulación detectada)' };
  }

  // Check Fragment B cross-hashes
  if (fragmentB.boundHashA !== actualHashA || fragmentB.boundHashC !== actualHashC) {
    return { isValid: false, reason: 'Fragmento B no coincide con los hashes de A o C (Manipulación detectada)' };
  }

  // Check Manifest C cross-hashes
  if (manifestC.boundHashA !== actualHashA || manifestC.boundHashB !== actualHashB) {
    return { isValid: false, reason: 'Manifiesto C no coincide con las firmas cruzadas de A o B' };
  }

  const expectedJoint = await computeSHA256(`${actualHashA}::${actualHashB}`);
  if (manifestC.jointIntegrityDigest !== expectedJoint) {
    return { isValid: false, reason: 'Digest conjunto A/B adulterado en el Manifiesto C' };
  }

  return { isValid: true };
}
