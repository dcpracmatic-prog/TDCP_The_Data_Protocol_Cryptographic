/**
 * Durable Authority state (JSON files under dataDir).
 *
 * Persists revoke, replay, policies, wrap secrets, and signing key material.
 * Private signing JWK is stored encrypted at rest when TDCP_AUTHORITY_KEY_PASSPHRASE
 * (or TDCP_AUTHORITY_KEY_FILE) is set — AES-256-GCM, no AWS KMS.
 *
 * HONESTY: This is still not an HSM. Production should prefer non-extractable
 * platform keys when available; encrypted file is a local hardening step.
 */

import type { UsbHsmDeviceRecord } from './usb-hsm.ts';
import { mkdirSync, readFileSync, writeFileSync, existsSync, renameSync } from 'node:fs';
import { join } from 'node:path';
import type { DocumentRevocationState } from '../../src/core/authorization/types.ts';
import type { RegisteredDocumentPolicy } from '../../src/oracle/authorization-oracle.ts';
import type { ConsumedOperationRecord } from '../../src/core/replay/replay-cache.ts';
import type { EncryptedPrivateKeyBlob } from './encrypted-key-store.ts';
import {
  decryptPrivateJwk,
  encryptPrivateJwk,
  isEncryptedPrivateKeyBlob,
  readAuthorityKeyPassphrase,
} from './encrypted-key-store.ts';

export interface DurableAuthoritySnapshot {
  version: 1;
  keyId: string;
  /**
   * Legacy plaintext private JWK (development). Prefer signingPrivateJwkEnc.
   * Cleared when passphrase is configured and key is re-persisted.
   */
  signingPrivateJwk: JsonWebKey | null;
  /** AES-GCM encrypted private JWK blob (preferred at rest). */
  signingPrivateJwkEnc: EncryptedPrivateKeyBlob | null;
  signingPublicJwk: JsonWebKey | null;
  policies: RegisteredDocumentPolicy[];
  /** documentId → base64 wrap secret */
  wrapSecretsBase64: Record<string, string>;
  revocation: DocumentRevocationState[];
  consumedOperations: ConsumedOperationRecord[];
  consumedGrantIds: string[];
  activeChallenges: Array<{ challenge: string; registeredAt: number }>;
  challengeSubjects: Array<{ challenge: string; subjectUserId: string }>;
  /** Enrolled USB-HSM public keys + lifecycle (never private keys). */
  usbHsmDevices: UsbHsmDeviceRecord[];
}

const EMPTY: DurableAuthoritySnapshot = {
  version: 1,
  keyId: 'AUTHORITY-KEY-P256-DURABLE-DEV',
  signingPrivateJwk: null,
  signingPrivateJwkEnc: null,
  signingPublicJwk: null,
  policies: [],
  wrapSecretsBase64: {},
  revocation: [],
  consumedOperations: [],
  consumedGrantIds: [],
  activeChallenges: [],
  challengeSubjects: [],
  usbHsmDevices: [],
};

/** Caps to avoid unbounded JSON growth on disk (I/O overflow). */
const MAX_PERSIST_CONSUMED = 20_000;
const MAX_PERSIST_CHALLENGES = 5_000;
const MAX_PERSIST_GRANTS = 20_000;

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
      const parsed = JSON.parse(raw) as DurableAuthoritySnapshot & {
        signingPrivateJwkEnc?: EncryptedPrivateKeyBlob | null;
      };
      if (parsed.version !== 1) return structuredClone(EMPTY);
      return {
        ...structuredClone(EMPTY),
        ...parsed,
        signingPrivateJwkEnc: parsed.signingPrivateJwkEnc ?? null,
        policies: parsed.policies ?? [],
        wrapSecretsBase64: parsed.wrapSecretsBase64 ?? {},
        revocation: parsed.revocation ?? [],
        consumedOperations: (parsed.consumedOperations ?? []).slice(-MAX_PERSIST_CONSUMED),
        consumedGrantIds: (parsed.consumedGrantIds ?? []).slice(-MAX_PERSIST_GRANTS),
        activeChallenges: (parsed.activeChallenges ?? []).slice(-MAX_PERSIST_CHALLENGES),
        challengeSubjects: (parsed.challengeSubjects ?? []).slice(-MAX_PERSIST_CHALLENGES),
        usbHsmDevices: parsed.usbHsmDevices ?? [],
      };
    } catch {
      return structuredClone(EMPTY);
    }
  }

  public save(snapshot: DurableAuthoritySnapshot): void {
    const capped: DurableAuthoritySnapshot = {
      ...snapshot,
      consumedOperations: snapshot.consumedOperations.slice(-MAX_PERSIST_CONSUMED),
      consumedGrantIds: snapshot.consumedGrantIds.slice(-MAX_PERSIST_GRANTS),
      activeChallenges: snapshot.activeChallenges.slice(-MAX_PERSIST_CHALLENGES),
      challengeSubjects: snapshot.challengeSubjects.slice(-MAX_PERSIST_CHALLENGES),
    };
    atomicWriteJson(this.snapshotPath, capped);
  }

  /** Resolve private JWK from encrypted blob or legacy plaintext. */
  public resolvePrivateJwk(snapshot: DurableAuthoritySnapshot): JsonWebKey | null {
    const passphrase = readAuthorityKeyPassphrase();
    if (snapshot.signingPrivateJwkEnc && isEncryptedPrivateKeyBlob(snapshot.signingPrivateJwkEnc)) {
      if (!passphrase) {
        throw new Error(
          'TDCP_AUTHORITY_KEY_PASSPHRASE (or TDCP_AUTHORITY_KEY_FILE) required to decrypt signing key'
        );
      }
      return decryptPrivateJwk(snapshot.signingPrivateJwkEnc, passphrase);
    }
    return snapshot.signingPrivateJwk;
  }

  /**
   * Persist private key: encrypt when passphrase is set; otherwise plaintext (dev warning).
   */
  public sealPrivateJwk(
    snapshot: DurableAuthoritySnapshot,
    privateJwk: JsonWebKey,
    publicJwk: JsonWebKey
  ): DurableAuthoritySnapshot {
    const passphrase = readAuthorityKeyPassphrase();
    if (passphrase) {
      return {
        ...snapshot,
        signingPrivateJwk: null,
        signingPrivateJwkEnc: encryptPrivateJwk(privateJwk, passphrase),
        signingPublicJwk: publicJwk,
      };
    }
    if (typeof process !== 'undefined' && process.env.NODE_ENV !== 'test') {
      console.warn(
        '[tdcp-authority] Signing private JWK stored in plaintext. Set TDCP_AUTHORITY_KEY_PASSPHRASE to encrypt at rest.'
      );
    }
    return {
      ...snapshot,
      signingPrivateJwk: privateJwk,
      signingPrivateJwkEnc: null,
      signingPublicJwk: publicJwk,
    };
  }

  /** Write a tiny probe file to verify the data dir is writable. */
  public probeWritable(): boolean {
    const probe = join(this.dataDir, '.write-probe');
    writeFileSync(probe, String(Date.now()), { mode: 0o600 });
    return existsSync(probe);
  }
}
