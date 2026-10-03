/**
 * Unified CSG seal entry point for TDCP UI / runtime.
 *
 * Prefer remote Notario (CSG_SEAL_URL / VITE_CSG_SEAL_URL sidecar).
 * Fall back to local ECDSA-P256 development seal when the sidecar is unset.
 */

import {
  createLocalCsgSeal,
  verifyLocalCsgSeal,
  type CsgLocalSeal,
} from './csg-local-seal.ts';
import {
  csgClientFromEnv,
  type CsgRemoteSeal,
  type CsgVerifyReport,
} from './csg-client.ts';

/** Portable seal document used by Encrypt/Decrypt panels. */
export type CsgSealDocument = CsgLocalSeal | CsgRemoteSeal;

export function isRemoteCsgSeal(s: CsgSealDocument): s is CsgRemoteSeal {
  return (
    typeof s === 'object' &&
    s !== null &&
    ('evento_id' in s || (s as { schema?: string }).schema === 'csg.sello.v1')
  );
}

export function isLocalCsgSeal(s: CsgSealDocument): s is CsgLocalSeal {
  return (
    typeof s === 'object' &&
    s !== null &&
    (s as { schema?: string }).schema === 'tdcp.csg-local.v1'
  );
}

/**
 * Create an integrity seal over content bytes.
 * Uses remote CSG sidecar when configured; otherwise local development seal.
 */
export async function createCsgSeal(
  content: ArrayBuffer | Uint8Array,
  options?: {
    label?: string;
    attributes?: Record<string, string>;
    proyecto_id?: string;
    evento_id?: string;
  }
): Promise<CsgSealDocument> {
  const client = csgClientFromEnv();
  if (client) {
    try {
      const remote = await client.seal(content, {
        label: options?.label,
        attributes: options?.attributes,
        proyecto_id: options?.proyecto_id,
        evento_id: options?.evento_id,
      });
      return remote;
    } catch (err) {
      console.warn(
        '[CSG] Remote seal failed, falling back to local development seal:',
        err instanceof Error ? err.message : err
      );
    }
  }
  return createLocalCsgSeal(content, {
    label: options?.label,
    attributes: options?.attributes,
  });
}

/**
 * Verify a seal against recovered content bytes.
 */
export async function verifyCsgSeal(
  content: ArrayBuffer | Uint8Array,
  seal: CsgSealDocument
): Promise<{ valid: boolean; reason: string; report?: CsgVerifyReport }> {
  if (isRemoteCsgSeal(seal)) {
    const client = csgClientFromEnv();
    if (client) {
      try {
        const report = await client.verify(content, seal);
        return {
          valid: report.todo_valido,
          reason: report.todo_valido ? 'OK' : 'REMOTE_VERIFY_FAILED',
          report,
        };
      } catch (err) {
        return {
          valid: false,
          reason: err instanceof Error ? err.message : 'REMOTE_VERIFY_ERROR',
        };
      }
    }
    // Offline best-effort: check hash field if present
    if (seal.hash_contenido) {
      const u8 = content instanceof Uint8Array ? content : new Uint8Array(content);
      // SHA-256 fallback for offline (sidecar uses SHA3; offline cannot recompute SHA3 easily without lib)
      // Require remote for full verify of csg.sello.v1
      return {
        valid: false,
        reason: 'CSG_SIDECAR_REQUIRED_FOR_REMOTE_SEAL',
      };
    }
    return { valid: false, reason: 'UNSUPPORTED_REMOTE_SEAL' };
  }

  if (isLocalCsgSeal(seal)) {
    const r = await verifyLocalCsgSeal(content, seal);
    return { valid: r.valid, reason: r.reason };
  }

  return { valid: false, reason: 'UNKNOWN_SEAL_SCHEMA' };
}

export function sealDownloadName(baseFileName: string, seal: CsgSealDocument): string {
  if (isRemoteCsgSeal(seal)) {
    return `${baseFileName}.csg-sello.json`;
  }
  return `${baseFileName}.csg.json`;
}

export function sealSummary(seal: CsgSealDocument): string[] {
  if (isRemoteCsgSeal(seal)) {
    return [
      `CSG Notario sello evento_id=${seal.evento_id}`,
      `aceptado=${seal.aceptado} hash=${(seal.hash_contenido || '').slice(0, 16)}…`,
      seal.notario_pub ? `notario_pub ${seal.notario_pub.slice(0, 16)}…` : 'notario remoto',
    ];
  }
  return [
    `CSG local sealId=${seal.sealId}`,
    `digest SHA-256 ${seal.contentDigest.slice(0, 16)}…`,
    seal.note,
  ];
}

/**
 * CSG attestation for an authorized operation. Seals authorization context
 * (grant + PolicyBinding + device + operation), not plaintext content.
 */
export async function createCsgOperationSeal(input: {
  documentId: string;
  packageId: string;
  grantId: string;
  grantHash: string;
  policyHash: string;
  deviceId: string;
  operationId: string;
  operation: string;
  expiresAt: number;
  edges: Array<{ source: string; destination: string; expectedBytes: number; allowed: boolean }>;
}): Promise<CsgSealDocument> {
  const canonical = JSON.stringify({
    schema: 'TDCP_CSG_OPERATION_ATTEST_v1',
    documentId: input.documentId,
    packageId: input.packageId,
    grantId: input.grantId,
    grantHash: input.grantHash,
    policyHash: input.policyHash,
    deviceId: input.deviceId,
    operationId: input.operationId,
    operation: input.operation,
    expiresAt: input.expiresAt,
    edges: [...input.edges].sort((a, b) =>
      `${a.source}->${a.destination}`.localeCompare(`${b.source}->${b.destination}`),
    ),
  });
  const client = csgClientFromEnv();
  if (client) {
    return client.seal(new TextEncoder().encode(canonical), {
      label: 'tdcp-operation-attestation',
      attributes: {
        grantId: input.grantId,
        policyHash: input.policyHash,
        operationId: input.operationId,
      },
      proyecto_id: 'tdcp',
      evento_id: `TDCP-OP-${input.operationId}`,
    });
  }
  if (
    (typeof process !== 'undefined' ? process.env?.TDCP_CSG_ATTEST_REQUIRED : undefined) ===
    'true'
  ) {
    throw new Error('CSG_REMOTE_REQUIRED_FOR_OPERATION_ATTESTATION');
  }
  return createLocalCsgSeal(new TextEncoder().encode(canonical), {
    label: 'tdcp-operation-attestation',
    attributes: {
      grantId: input.grantId,
      policyHash: input.policyHash,
      operationId: input.operationId,
    },
  });
}
