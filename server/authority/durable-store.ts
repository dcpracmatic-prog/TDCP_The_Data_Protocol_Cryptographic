/**
 * Durable Authority state (JSON files under dataDir).
 *
 * DEVELOPMENT / MVP stub: persists revoke, replay, policies, wrap secrets,
 * and an extractable ECDSA P-256 JWK so restart preserves control-plane state.
 *
 * HONESTY: This is NOT an HSM/KMS. Production MUST replace signing + wrap-secret
 * storage with HSM/KMS or platform Secure Key Store (see docs/AUTHORITY.md).
 */

import { mkdirSync, readFileSync, writeFileSync, existsSync, renameSync } from 'node:fs';
import { join } from 'node:path';
import type { DocumentRevocationState } from '../../src/core/authorization/types.ts';
import type { RegisteredDocumentPolicy } from '../../src/oracle/authorization-oracle.ts';
import type { ConsumedOperationRecord } from '../../src/core/replay/replay-cache.ts';

export interface DurableAuthoritySnapshot {
  version: 1;
  keyId: string;
  /** Extractable JWK for development durability only. */
  signingPrivateJwk: JsonWebKey | null;
  signingPublicJwk: JsonWebKey | null;
  policies: RegisteredDocumentPolicy[];
  /** documentId → base64 wrap secret */
  wrapSecretsBase64: Record<string, string>;
  revocation: DocumentRevocationState[];
  consumedOperations: ConsumedOperationRecord[];
  consumedGrantIds: string[];
  activeChallenges: Array<{ challenge: string; registeredAt: number }>;
}

const EMPTY: DurableAuthoritySnapshot = {
  version: 1,
  keyId: 'AUTHORITY-KEY-P256-DURABLE-DEV',
  signingPrivateJwk: null,
  signingPublicJwk: null,
  policies: [],
  wrapSecretsBase64: {},
  revocation: [],
  consumedOperations: [],
  consumedGrantIds: [],
  activeChallenges: [],
};

function atomicWriteJson(path: string, data: unknown): void {
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
  renameSync(tmp, path);
}

export class DurableJsonAuthorityStore {
  public readonly dataDir: string;
  private readonly snapshotPath: string;

  constructor(dataDir: string) {
    this.dataDir = dataDir;
    this.snapshotPath = join(dataDir, 'authority-state.json');
    mkdirSync(dataDir, { recursive: true });
  }

  public load(): DurableAuthoritySnapshot {
    if (!existsSync(this.snapshotPath)) {
      return structuredClone(EMPTY);
    }
    try {
      const raw = readFileSync(this.snapshotPath, 'utf8');
      const parsed = JSON.parse(raw) as DurableAuthoritySnapshot;
      if (parsed.version !== 1) return structuredClone(EMPTY);
      return {
        ...structuredClone(EMPTY),
        ...parsed,
        policies: parsed.policies ?? [],
        wrapSecretsBase64: parsed.wrapSecretsBase64 ?? {},
        revocation: parsed.revocation ?? [],
        consumedOperations: parsed.consumedOperations ?? [],
        consumedGrantIds: parsed.consumedGrantIds ?? [],
        activeChallenges: parsed.activeChallenges ?? [],
      };
    } catch {
      return structuredClone(EMPTY);
    }
  }

  public save(snapshot: DurableAuthoritySnapshot): void {
    atomicWriteJson(this.snapshotPath, snapshot);
  }
}
