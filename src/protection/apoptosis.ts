/**
 * The Data Cryptographic Protocol (TDCP)
 * Controlled Runtime & Cryptographic Apoptosis Lifecycle
 * 
 * JAVASCRIPT MEMORY LIMITATIONS & SECURITY DISCLOSURE:
 * JavaScript runs within a garbage-collected virtual machine. The runtime does NOT
 * provide operating-system level physical memory locking (mlock) or guaranteed physical
 * RAM overwriting for primitive values or immutable string intern pools.
 * 
 * Therefore, "Apoptosis" in TDCP represents a strict defense-in-depth protocol lifecycle:
 * 1. Explicit byte-level overwrite of mutable TypedArrays (Uint8Array/ArrayBuffer) with CSPRNG entropy and zeroes.
 * 2. Unmapping and revoking Blob URLs via URL.revokeObjectURL().
 * 3. Clearing DOM node references and nullifying pointer references.
 * 4. Cryptographic invalidation of session nonces and ephemeral key derivation contexts.
 * 5. Automatic session timer termination.
 */

import { wipeBuffer } from '../core/crypto/primitives.ts';

export interface EphemeralSessionResources {
  sessionId: string;
  buffers: (ArrayBuffer | Uint8Array)[];
  objectUrls: string[];
  cryptoKeys: (CryptoKey | null)[];
  timerId?: any;
  onApoptosis?: () => void;
}

export class ControlledRuntimeSession {
  private resources: EphemeralSessionResources;
  private isTerminated: boolean = false;

  constructor(sessionId: string, timeoutMs: number = 300000) {
    this.resources = {
      sessionId,
      buffers: [],
      objectUrls: [],
      cryptoKeys: []
    };

    if (timeoutMs > 0) {
      this.resources.timerId = setTimeout(() => {
        this.terminate('SESSION_LIFECYCLE_TIMEOUT');
      }, timeoutMs);
    }
  }

  public registerBuffer(buf: ArrayBuffer | Uint8Array): void {
    if (this.isTerminated) return;
    this.resources.buffers.push(buf);
  }

  public registerObjectUrl(url: string): void {
    if (this.isTerminated) return;
    this.resources.objectUrls.push(url);
  }

  public registerCryptoKey(key: CryptoKey): void {
    if (this.isTerminated) return;
    this.resources.cryptoKeys.push(key);
  }

  public setOnApoptosis(callback: () => void): void {
    this.resources.onApoptosis = callback;
  }

  /**
   * Executes the Cryptographic Apoptosis cycle:
   * Overwrites typed arrays, revokes URLs, and invalidates session resources.
   */
  public terminate(reason: string = 'NORMAL_CLOSURE'): void {
    if (this.isTerminated) return;
    this.isTerminated = true;

    if (this.resources.timerId) {
      clearTimeout(this.resources.timerId);
      this.resources.timerId = undefined;
    }

    // 1. Wipe mutable byte buffers
    for (const buf of this.resources.buffers) {
      wipeBuffer(buf);
    }
    this.resources.buffers = [];

    // 2. Revoke memory Blob URLs
    for (const url of this.resources.objectUrls) {
      try {
        URL.revokeObjectURL(url);
      } catch {}
    }
    this.resources.objectUrls = [];

    // 3. Clear key handles
    this.resources.cryptoKeys = [];

    // 4. Trigger caller notification
    if (this.resources.onApoptosis) {
      try {
        this.resources.onApoptosis();
      } catch {}
    }
  }

  public isAlive(): boolean {
    return !this.isTerminated;
  }
}
