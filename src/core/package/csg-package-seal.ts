/**
 * CSG package seal (P2-5): the CSG Notario seal glued to the .pkg itself.
 *
 * What it is, in plain terms:
 * - At PROTECT, the whole package (structure + full content: ciphertext,
 *   AAD, metadata, wrapped CEK, ultra-critical fragments) is sealed by the
 *   CSG sidecar (NotarioProtegido, Ed25519 + SHA3-256) and the seal is stored
 *   INSIDE the .pkg, in the `csgSeal` field. The seal travels with the file;
 *   no separate .csg.json file is needed for the package seal.
 * - At OPEN, the Gatekeeper verifies the seal BEFORE decrypting anything.
 *   If the content was altered, opening fails closed (no grant is consumed,
 *   nothing is decrypted).
 *
 * What it is NOT:
 * - It does NOT replace AES-GCM authentication of the .pkg (that still
 *   verifies the ciphertext tag at decrypt time) and it does NOT replace the
 *   Gatekeeper grant (copying the package still does not copy authorization).
 *   It is one more integrity layer, on top of those two.
 * - A package seal is only a REAL CSG seal when it comes from the remote
 *   Notario sidecar. This module NEVER falls back to the local development
 *   seal (`tdcp.csg-local.v1`) for a package seal: silently substituting a
 *   locally generated seal would fake a CSG guarantee that was never checked.
 *
 * Sidecar unavailable — the decision (fail closed, never fake):
 * - Seal mode `required` (used when the operator explicitly asked for CSG):
 *   protect THROWS and no package is produced; open of a sealed package
 *   FAILS CLOSED. Nothing is half-sealed.
 * - Seal mode `optional` (default at protect): if the sidecar is not
 *   configured or does not answer, the package is created WITHOUT a seal
 *   (legacy shape) and the caller is told so (`sealed: false` + reason).
 *   The package still opens later via the current path, documented as
 *   "without CSG guarantee".
 * - A package that HAS a seal but whose seal cannot be verified (sidecar
 *   down, corrupt seal, unknown schema) NEVER opens: `valid: false`,
 *   status `unverifiable` or `sealed-invalid`. Fail closed.
 * - Legacy packages without any seal keep opening (`status: 'absent'`,
 *   `valid: null`) — backwards compatible by design, documented as having
 *   no CSG guarantee.
 */

import { canonicalPackageEnvelopeBytes, type TDCPPackage } from './package-format.ts';
import {
  csgClientFromEnv,
  type CsgClient,
} from '../../protection/csg-client.ts';
import {
  verifyCsgSeal,
  isRemoteCsgSeal,
  isLocalCsgSeal,
  type CsgSealDocument,
} from '../../protection/csg-seal.ts';

/** Label stamped on package seals so they are distinguishable in the Notario log. */
export const CSG_PACKAGE_SEAL_LABEL = 'tdcp-pkg';

/**
 * - `required`: the operator asked for CSG. Sidecar down or seal rejected
 *   => protect throws, no package is produced.
 * - `optional`: best effort. Sidecar missing/down => package without seal.
 * - `off`: never seal (explicit opt-out).
 */
export type CsgPackageSealMode = 'required' | 'optional' | 'off';

export type CsgPackageSealStatus =
  | 'sealed-valid'
  | 'sealed-invalid'
  | 'unverifiable'
  | 'absent';

export interface SealPackageResult {
  sealed: boolean;
  mode: CsgPackageSealMode;
  seal?: CsgSealDocument;
  /** Machine-readable reason when not sealed (e.g. CSG_SIDECAR_NOT_CONFIGURED). */
  reason?: string;
}

export interface VerifyPackageSealResult {
  status: CsgPackageSealStatus;
  /**
   * true = seal verified; false = seal present but invalid/unverifiable
   * (fail closed); null = no seal at all (legacy package).
   */
  valid: boolean | null;
  reason: string;
}

/**
 * Seal a finished package (integrityHash already computed) with the remote
 * CSG Notario. Returns the seal to store in `pkg.csgSeal`.
 *
 * Only the remote sidecar counts as a CSG package seal. There is no local
 * fallback here by design (see module header).
 */
export async function sealPackage(
  pkg: TDCPPackage,
  mode: CsgPackageSealMode,
  client?: CsgClient | null
): Promise<SealPackageResult> {
  if (mode === 'off') {
    return { sealed: false, mode, reason: 'CSG_SEAL_DISABLED' };
  }
  const csg = client ?? csgClientFromEnv();
  if (!csg) {
    if (mode === 'required') {
      throw new Error(
        'CSG_SIDECAR_UNAVAILABLE: no CSG sidecar configured (CSG_SEAL_URL / VITE_CSG_SEAL_URL). ' +
          'The package was NOT created: a required CSG seal cannot be faked. Start the sidecar or use seal mode optional/off.'
      );
    }
    return { sealed: false, mode, reason: 'CSG_SIDECAR_NOT_CONFIGURED' };
  }
  try {
    const seal = await csg.seal(canonicalPackageEnvelopeBytes(pkg), {
      label: CSG_PACKAGE_SEAL_LABEL,
      attributes: {
        documentId: pkg.documentId,
        packageId: pkg.packageId,
        integrityHash: pkg.integrityHash.slice(0, 32),
        sealedOver: 'tdcp-pkg-canonical-envelope-v1',
      },
      proyecto_id: 'tdcp',
      evento_id: `TDCP-PKG-${pkg.packageId}`,
    });
    if (!seal.aceptado) {
      throw new Error(`CSG seal rejected by Notario: ${seal.razon || 'not accepted'}`);
    }
    return { sealed: true, mode, seal };
  } catch (err) {
    if (mode === 'required') {
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(`CSG_SEAL_FAILED: ${message}`);
    }
    return {
      sealed: false,
      mode,
      reason: `CSG_SEAL_FAILED: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

/** Attach a seal to a package (returns a new object; the original is untouched). */
export function attachPackageSeal(pkg: TDCPPackage, seal: CsgSealDocument): TDCPPackage {
  return { ...pkg, csgSeal: seal };
}

/**
 * Verify the seal embedded in a package against its current canonical
 * envelope bytes. Call BEFORE any decryption (the Gatekeeper does this).
 *
 * - No seal => `{ status: 'absent', valid: null }` (legacy; caller decides).
 * - Remote seal + sidecar unreachable => unverifiable, valid false: FAIL CLOSED.
 * - Corrupt / unknown-schema / mismatched seal => sealed-invalid, valid false.
 */
export async function verifyPackageSeal(
  pkg: TDCPPackage,
  client?: CsgClient | null
): Promise<VerifyPackageSealResult> {
  const seal = pkg.csgSeal;
  if (!seal) {
    return {
      status: 'absent',
      valid: null,
      reason: 'CSG_SEAL_ABSENT_LEGACY',
    };
  }
  if (!isRemoteCsgSeal(seal) && !isLocalCsgSeal(seal)) {
    return {
      status: 'sealed-invalid',
      valid: false,
      reason: 'UNKNOWN_SEAL_SCHEMA',
    };
  }
  if (isRemoteCsgSeal(seal) && !seal.aceptado) {
    return {
      status: 'sealed-invalid',
      valid: false,
      reason: 'SEAL_NOT_ACCEPTED_BY_NOTARIO',
    };
  }
  const resolvedClient = client ?? csgClientFromEnv();
  const result = await verifyCsgSeal(
    canonicalPackageEnvelopeBytes(pkg),
    seal,
    resolvedClient ?? undefined
  );
  if (result.valid) {
    return { status: 'sealed-valid', valid: true, reason: 'OK' };
  }
  if (result.reason === 'CSG_SIDECAR_REQUIRED_FOR_REMOTE_SEAL' || result.reason === 'REMOTE_VERIFY_ERROR') {
    return {
      status: 'unverifiable',
      valid: false,
      reason:
        'CSG_SIDECAR_REQUIRED_FOR_REMOTE_SEAL: the package carries a CSG seal but the sidecar is unreachable; opening is denied rather than trusting an unverified seal.',
    };
  }
  return { status: 'sealed-invalid', valid: false, reason: result.reason };
}
