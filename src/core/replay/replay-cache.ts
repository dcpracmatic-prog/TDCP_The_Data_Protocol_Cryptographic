/**
 * The Data Cryptographic Protocol (TDCP)
 * Cryptographic Anti-Replay Cache & Challenge Registry
 * 
 * Guarantees:
 * - One-time operation ID consumption
 * - Nonce/challenge freshness verification
 * - In-memory and authoritative tracking
 */

export interface ConsumedOperationRecord {
  operationId: string;
  challenge: string;
  grantId: string;
  documentId: string;
  deviceId: string;
  consumedAt: number;
}

export class AntiReplayRegistry {
  private consumedOperations: Map<string, ConsumedOperationRecord> = new Map();
  private activeChallenges: Map<string, number> = new Map();
  private readonly challengeTtlMs = 60_000;

  /**
   * Registers a fresh challenge issued by the trusted control-plane flow for an upcoming request
   */
  public registerFreshChallenge(challenge: string, registeredAt = Date.now()): void {
    if (!challenge || !Number.isFinite(registeredAt)) {
      throw new Error('INVALID_CHALLENGE_REGISTRATION');
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
    if (!this.isValidChallenge(challenge)) {
      return false;
    }
    for (const record of this.consumedOperations.values()) {
      if (record.challenge === challenge) {
        return true;
      }
    }
    return false;
  }

  /**
   * Consumes the operation atomically, invalidating the challenge and operation ID forever
   */
  public consumeOperation(record: ConsumedOperationRecord): boolean {
    if (this.isReplayed(record.operationId, record.challenge)) {
      return false; // Replay attempt rejected
    }

    this.activeChallenges.delete(record.challenge);
    this.consumedOperations.set(record.operationId, record);
    return true;
  }

  public clear(): void {
    this.consumedOperations.clear();
    this.activeChallenges.clear();
  }
}
