/**
 * The Data Cryptographic Protocol (TDCP)
 * Cryptographic Anti-Replay Cache & Challenge Registry
 *
 * Guarantees:
 * - One-time operation ID consumption
 * - Nonce/challenge freshness verification
 * - Bounded memory and bounded durable export (no unbounded growth)
 */

export interface ConsumedOperationRecord {
  operationId: string;
  challenge: string;
  grantId: string;
  documentId: string;
  deviceId: string;
  consumedAt: number;
}

export interface AntiReplayRegistryOptions {
  /** Challenge lifetime (default 60s). */
  challengeTtlMs?: number;
  /** How long consumed operation records are retained for replay checks (default 24h). */
  consumedTtlMs?: number;
  /** Hard cap on consumed operations map size (default 50_000). */
  maxConsumed?: number;
  /** Hard cap on active challenges map size (default 10_000). */
  maxActiveChallenges?: number;
}

const DEFAULT_CHALLENGE_TTL_MS = 60_000;
const DEFAULT_CONSUMED_TTL_MS = 24 * 60 * 60 * 1000;
const DEFAULT_MAX_CONSUMED = 50_000;
const DEFAULT_MAX_ACTIVE = 10_000;

export class AntiReplayRegistry {
  private consumedOperations: Map<string, ConsumedOperationRecord> = new Map();
  /** challenge → registeredAt */
  private activeChallenges: Map<string, number> = new Map();
  /** Secondary index: challenge → operationId (O(1) replay by challenge). */
  private challengeToOperation: Map<string, string> = new Map();

  private readonly challengeTtlMs: number;
  private readonly consumedTtlMs: number;
  private readonly maxConsumed: number;
  private readonly maxActiveChallenges: number;
  private pruneCounter = 0;

  constructor(options: AntiReplayRegistryOptions = {}) {
    this.challengeTtlMs = options.challengeTtlMs ?? DEFAULT_CHALLENGE_TTL_MS;
    this.consumedTtlMs = options.consumedTtlMs ?? DEFAULT_CONSUMED_TTL_MS;
    this.maxConsumed = options.maxConsumed ?? DEFAULT_MAX_CONSUMED;
    this.maxActiveChallenges = options.maxActiveChallenges ?? DEFAULT_MAX_ACTIVE;
  }

  /**
   * Registers a fresh challenge issued by the trusted control-plane flow for an upcoming request
   */
  public registerFreshChallenge(challenge: string, registeredAt = Date.now()): void {
    if (!challenge || !Number.isFinite(registeredAt)) {
      throw new Error('INVALID_CHALLENGE_REGISTRATION');
    }
    this.maybePrune(registeredAt);
    if (this.activeChallenges.size >= this.maxActiveChallenges) {
      this.pruneActiveChallenges(registeredAt);
    }
    if (this.activeChallenges.size >= this.maxActiveChallenges) {
      // Drop oldest active challenge to stay within bound
      const oldest = this.activeChallenges.keys().next().value;
      if (oldest !== undefined) this.activeChallenges.delete(oldest);
    }
    this.activeChallenges.set(challenge, registeredAt);
  }

  public issueFreshChallenge(generate: () => string, now = Date.now()): string {
    const challenge = generate();
    this.registerFreshChallenge(challenge, now);
    return challenge;
  }

  /**
   * Verifies if a challenge is fresh and valid
   */
  public isValidChallenge(challenge: string, now = Date.now()): boolean {
    const registeredAt = this.activeChallenges.get(challenge);
    if (registeredAt === undefined) return false;
    const age = now - registeredAt;
    if (age < 0 || age > this.challengeTtlMs) {
      this.activeChallenges.delete(challenge);
      return false;
    }
    return true;
  }

  /**
   * Checks if an operation_id or challenge has already been consumed
   */
  public isReplayed(operationId: string, challenge: string): boolean {
    if (this.consumedOperations.has(operationId)) {
      return true;
    }
    if (this.challengeToOperation.has(challenge)) {
      return true;
    }
    if (!this.isValidChallenge(challenge)) {
      return false;
    }
    return false;
  }

  /**
   * Consumes the operation atomically, invalidating the challenge and operation ID forever
   * (within retention bounds).
   */
  public consumeOperation(record: ConsumedOperationRecord): boolean {
    if (this.isReplayed(record.operationId, record.challenge)) {
      return false; // Replay attempt rejected
    }

    this.activeChallenges.delete(record.challenge);
    this.consumedOperations.set(record.operationId, record);
    this.challengeToOperation.set(record.challenge, record.operationId);

    if (this.consumedOperations.size > this.maxConsumed) {
      this.evictOldestConsumed(this.consumedOperations.size - this.maxConsumed);
    }
    this.maybePrune(record.consumedAt);
    return true;
  }

  /** Bounded export for durable persistence (avoids unbounded JSON on disk). */
  public exportConsumed(now = Date.now()): ConsumedOperationRecord[] {
    this.pruneConsumed(now);
    return Array.from(this.consumedOperations.values());
  }

  public exportActiveChallenges(now = Date.now()): Array<{ challenge: string; registeredAt: number }> {
    this.pruneActiveChallenges(now);
    return Array.from(this.activeChallenges.entries()).map(([challenge, registeredAt]) => ({
      challenge,
      registeredAt,
    }));
  }

  public hydrateConsumed(records: ConsumedOperationRecord[], now = Date.now()): void {
    for (const rec of records) {
      if (!rec?.operationId) continue;
      if (now - rec.consumedAt > this.consumedTtlMs) continue;
      this.consumedOperations.set(rec.operationId, rec);
      if (rec.challenge) this.challengeToOperation.set(rec.challenge, rec.operationId);
    }
    if (this.consumedOperations.size > this.maxConsumed) {
      this.evictOldestConsumed(this.consumedOperations.size - this.maxConsumed);
    }
  }

  public hydrateActiveChallenges(
    entries: Array<{ challenge: string; registeredAt: number }>,
    now = Date.now()
  ): void {
    for (const ch of entries) {
      if (!ch?.challenge) continue;
      if (now - ch.registeredAt > this.challengeTtlMs) continue;
      this.activeChallenges.set(ch.challenge, ch.registeredAt);
    }
    if (this.activeChallenges.size > this.maxActiveChallenges) {
      this.pruneActiveChallenges(now);
    }
  }

  public clear(): void {
    this.consumedOperations.clear();
    this.activeChallenges.clear();
    this.challengeToOperation.clear();
  }

  public stats(): {
    consumed: number;
    activeChallenges: number;
    maxConsumed: number;
    maxActiveChallenges: number;
  } {
    return {
      consumed: this.consumedOperations.size,
      activeChallenges: this.activeChallenges.size,
      maxConsumed: this.maxConsumed,
      maxActiveChallenges: this.maxActiveChallenges,
    };
  }

  private maybePrune(now: number): void {
    this.pruneCounter += 1;
    if (this.pruneCounter % 64 === 0) {
      this.pruneActiveChallenges(now);
      this.pruneConsumed(now);
    }
  }

  private pruneActiveChallenges(now: number): void {
    for (const [challenge, registeredAt] of this.activeChallenges) {
      if (now - registeredAt > this.challengeTtlMs) {
        this.activeChallenges.delete(challenge);
      }
    }
  }

  private pruneConsumed(now: number): void {
    for (const [id, rec] of this.consumedOperations) {
      if (now - rec.consumedAt > this.consumedTtlMs) {
        this.consumedOperations.delete(id);
        if (rec.challenge) this.challengeToOperation.delete(rec.challenge);
      }
    }
  }

  private evictOldestConsumed(count: number): void {
    if (count <= 0) return;
    const entries = Array.from(this.consumedOperations.entries()).sort(
      (a, b) => a[1].consumedAt - b[1].consumedAt
    );
    for (let i = 0; i < count && i < entries.length; i++) {
      const [id, rec] = entries[i];
      this.consumedOperations.delete(id);
      if (rec.challenge) this.challengeToOperation.delete(rec.challenge);
    }
  }
}
