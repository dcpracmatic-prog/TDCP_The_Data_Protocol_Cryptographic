/**
 * Browser-side source of the end-user identity token sent to the Authority.
 *
 * `authContext` installs a fetcher on sign-in (Better Auth `/api/auth/token`)
 * and clears it on sign-out. Tokens are cached in memory only (never in
 * localStorage) and refreshed 30 s before they expire.
 */

type TokenFetcher = () => Promise<string | null>;

let fetcher: TokenFetcher | null = null;
let cached: { token: string; exp: number } | null = null;
let inflight: Promise<string | null> | null = null;

function readExp(token: string): number {
  try {
    const part = token.split('.')[1] ?? '';
    const json = atob(part.replace(/-/g, '+').replace(/_/g, '/'));
    const exp = (JSON.parse(json) as { exp?: number }).exp;
    return typeof exp === 'number' ? exp * 1000 : 0;
  } catch {
    return 0;
  }
}

export function setUserTokenSource(next: TokenFetcher | null): void {
  fetcher = next;
  cached = null;
  inflight = null;
}

export function hasUserTokenSource(): boolean {
  return fetcher !== null;
}

export async function getUserToken(): Promise<string | null> {
  if (!fetcher) return null;
  if (cached && cached.exp - Date.now() > 30_000) return cached.token;
  if (inflight) return inflight;
  const current = fetcher;
  inflight = (async () => {
    try {
      const token = await current();
      if (fetcher !== current) return null; // signed out meanwhile
      cached = token ? { token, exp: readExp(token) } : null;
      return token;
    } finally {
      inflight = null;
    }
  })();
  return inflight;
}
