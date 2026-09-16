/**
 * Simple in-memory sliding-window rate limiter (per key).
 * Process-local guardrail; prefer edge / reverse-proxy limits in production.
 */

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterMs: number;
}

export class InMemoryRateLimiter {
  private readonly hits = new Map<string, number[]>();
  private readonly windowMs: number;
  private readonly maxHits: number;

  constructor(options?: { windowMs?: number; maxHits?: number }) {
    this.windowMs = options?.windowMs ?? 60_000;
    this.maxHits = options?.maxHits ?? 120;
  }

  public check(key: string, now = Date.now()): RateLimitResult {
    const cutoff = now - this.windowMs;
    const prev = this.hits.get(key) ?? [];
    const recent = prev.filter((t) => t > cutoff);
    if (recent.length >= this.maxHits) {
      this.hits.set(key, recent);
      const oldest = recent[0] ?? now;
      return {
        allowed: false,
        remaining: 0,
        retryAfterMs: Math.max(0, oldest + this.windowMs - now),
      };
    }
    recent.push(now);
    this.hits.set(key, recent);
    return {
      allowed: true,
      remaining: Math.max(0, this.maxHits - recent.length),
      retryAfterMs: 0,
    };
  }

  public reset(): void {
    this.hits.clear();
  }
}

export function clientKey(req: {
  socket?: { remoteAddress?: string };
  headers: Record<string, string | string[] | undefined>;
}): string {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.trim()) {
    return xff.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || 'unknown';
}
