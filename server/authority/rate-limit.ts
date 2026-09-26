/**
 * Rate limiting for Authority HTTP.
 *
 * - InMemoryRateLimiter: process-local sliding window
 * - FileRateLimiter: shared directory on local disk / NFS (multi-process, no managed SaaS)
 *
 * IP identity: prefer socket remoteAddress unless TDCP_TRUST_PROXY=1.
 */

import {
  mkdirSync,
  readFileSync,
  writeFileSync,
  existsSync,
  renameSync,
  readdirSync,
  unlinkSync,
  openSync,
  closeSync,
  fsyncSync,
} from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterMs: number;
}

export interface RateLimiter {
  check(key: string, now?: number): RateLimitResult | Promise<RateLimitResult>;
  reset?(): void;
}

export class InMemoryRateLimiter implements RateLimiter {
  private readonly hits = new Map<string, number[]>();
  private readonly windowMs: number;
  private readonly maxHits: number;
  private readonly maxKeys: number;
  private pruneCounter = 0;

  constructor(options?: { windowMs?: number; maxHits?: number; maxKeys?: number }) {
    this.windowMs = options?.windowMs ?? 60_000;
    this.maxHits = options?.maxHits ?? 120;
    this.maxKeys = options?.maxKeys ?? 20_000;
  }

  public check(key: string, now = Date.now()): RateLimitResult {
    this.maybePrune(now);
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
    if (this.hits.size > this.maxKeys) {
      this.evictStaleKeys(cutoff);
    }
    return {
      allowed: true,
      remaining: Math.max(0, this.maxHits - recent.length),
      retryAfterMs: 0,
    };
  }

  public reset(): void {
    this.hits.clear();
  }

  private maybePrune(now: number): void {
    this.pruneCounter += 1;
    if (this.pruneCounter % 128 === 0) {
      this.evictStaleKeys(now - this.windowMs);
    }
  }

  private evictStaleKeys(cutoff: number): void {
    for (const [k, times] of this.hits) {
      const recent = times.filter((t) => t > cutoff);
      if (recent.length === 0) this.hits.delete(k);
      else this.hits.set(k, recent);
    }
    // Hard cap: drop arbitrary excess keys
    while (this.hits.size > this.maxKeys) {
      const first = this.hits.keys().next().value;
      if (first === undefined) break;
      this.hits.delete(first);
    }
  }
}

/**
 * File-backed sliding window shared across processes on the same host or shared volume.
 * No Redis/Memcached/AWS — only local filesystem (or NFS-compatible share).
 *
 * Layout: `{dir}/{sha256(key).slice(0,32)}.json` with `{ hits: number[] }`
 * Uses rename for atomic replace; best-effort under concurrent writers.
 */
export class FileRateLimiter implements RateLimiter {
  private readonly dir: string;
  private readonly windowMs: number;
  private readonly maxHits: number;

  constructor(options: { dir: string; windowMs?: number; maxHits?: number }) {
    this.dir = options.dir;
    this.windowMs = options.windowMs ?? 60_000;
    this.maxHits = options.maxHits ?? 120;
    mkdirSync(this.dir, { recursive: true });
  }

  public check(key: string, now = Date.now()): RateLimitResult {
    const path = this.pathFor(key);
    const cutoff = now - this.windowMs;
    let recent: number[] = [];
    try {
      if (existsSync(path)) {
        const raw = readFileSync(path, 'utf8');
        const parsed = JSON.parse(raw) as { hits?: number[] };
        recent = (parsed.hits ?? []).filter((t) => typeof t === 'number' && t > cutoff);
      }
    } catch {
      recent = [];
    }

    if (recent.length >= this.maxHits) {
      this.writeAtomic(path, recent);
      const oldest = recent[0] ?? now;
      return {
        allowed: false,
        remaining: 0,
        retryAfterMs: Math.max(0, oldest + this.windowMs - now),
      };
    }

    recent.push(now);
    this.writeAtomic(path, recent);
    return {
      allowed: true,
      remaining: Math.max(0, this.maxHits - recent.length),
      retryAfterMs: 0,
    };
  }

  /** Opportunistic cleanup of stale files (call from a timer or admin path). */
  public sweep(now = Date.now()): number {
    let removed = 0;
    const cutoff = now - this.windowMs * 2;
    let names: string[] = [];
    try {
      names = readdirSync(this.dir);
    } catch {
      return 0;
    }
    for (const name of names) {
      if (!name.endsWith('.json')) continue;
      const p = join(this.dir, name);
      try {
        const raw = readFileSync(p, 'utf8');
        const parsed = JSON.parse(raw) as { hits?: number[] };
        const recent = (parsed.hits ?? []).filter((t) => t > cutoff);
        if (recent.length === 0) {
          unlinkSync(p);
          removed += 1;
        }
      } catch {
        /* ignore */
      }
    }
    return removed;
  }

  private pathFor(key: string): string {
    const hash = createHash('sha256').update(key, 'utf8').digest('hex').slice(0, 32);
    return join(this.dir, `${hash}.json`);
  }

  private writeAtomic(path: string, hits: number[]): void {
    const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
    try {
      writeFileSync(tmp, JSON.stringify({ hits }), { mode: 0o600 });
      const fd = openSync(tmp, 'r+');
      try {
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      renameSync(tmp, path);
    } catch {
      try {
        unlinkSync(tmp);
      } catch {
        /* ignore */
      }
    }
  }
}

export type ClientKeyOptions = {
  /**
   * When true, trust X-Forwarded-For / X-Real-IP (only behind a trusted reverse proxy).
   * Default false — use socket remoteAddress to avoid spoofed client IPs.
   */
  trustProxy?: boolean;
};

/**
 * Resolve a stable client identity for rate limiting.
 * - Default: TCP peer address (socket.remoteAddress), normalized.
 * - If trustProxy: leftmost X-Forwarded-For or X-Real-IP, then socket.
 */
export function clientKey(
  req: {
    socket?: { remoteAddress?: string };
    headers: Record<string, string | string[] | undefined>;
  },
  options: ClientKeyOptions = {}
): string {
  const trustProxy =
    options.trustProxy ??
    (typeof process !== 'undefined' &&
      (process.env.TDCP_TRUST_PROXY === '1' ||
        process.env.TDCP_TRUST_PROXY === 'true' ||
        process.env.TDCP_TRUST_PROXY === 'yes'));

  if (trustProxy) {
    const xff = headerFirst(req.headers['x-forwarded-for']);
    if (xff) {
      const first = xff.split(',')[0]?.trim();
      const normalized = normalizeIp(first);
      if (normalized) return normalized;
    }
    const xri = headerFirst(req.headers['x-real-ip']);
    const n = normalizeIp(xri);
    if (n) return n;
  }

  const peer = normalizeIp(req.socket?.remoteAddress);
  return peer || 'unknown';
}

function headerFirst(value: string | string[] | undefined): string | undefined {
  if (typeof value === 'string' && value.trim()) return value.trim();
  if (Array.isArray(value) && value[0]) return String(value[0]).trim();
  return undefined;
}

/** Strip IPv4-mapped IPv6, zone ids, and optional :port on IPv4. */
export function normalizeIp(raw: string | undefined | null): string | null {
  if (!raw) return null;
  let s = raw.trim().toLowerCase();
  if (!s) return null;

  // [ipv6]:port
  if (s.startsWith('[')) {
    const end = s.indexOf(']');
    if (end > 1) s = s.slice(1, end);
  }

  // IPv4 with :port (not IPv6)
  if (/^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(s)) {
    s = s.replace(/:\d+$/, '');
  }

  // Remove zone id (fe80::1%lo0)
  const zone = s.indexOf('%');
  if (zone >= 0) s = s.slice(0, zone);

  if (s.startsWith('::ffff:')) {
    s = s.slice('::ffff:'.length);
  }

  return s || null;
}

export function createAuthorityRateLimiter(options?: {
  windowMs?: number;
  maxHits?: number;
  dataDir?: string;
  mode?: 'memory' | 'file';
}): RateLimiter {
  const mode =
    options?.mode ??
    ((process.env.TDCP_AUTHORITY_RATE_MODE || 'memory').toLowerCase() === 'file'
      ? 'file'
      : 'memory');
  const windowMs =
    options?.windowMs ?? Number(process.env.TDCP_AUTHORITY_RATE_WINDOW_MS || 60_000);
  const maxHits = options?.maxHits ?? Number(process.env.TDCP_AUTHORITY_RATE_MAX || 120);

  if (mode === 'file') {
    const base =
      options?.dataDir ||
      process.env.TDCP_AUTHORITY_DATA_DIR ||
      join(process.cwd(), 'data', 'authority');
    return new FileRateLimiter({
      dir: join(base, 'rate-limit'),
      windowMs,
      maxHits,
    });
  }
  return new InMemoryRateLimiter({ windowMs, maxHits });
}
