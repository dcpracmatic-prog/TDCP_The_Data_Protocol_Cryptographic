import { useEffect, useState } from 'react';
import { Activity, Wifi, WifiOff } from 'lucide-react';
import { readAuthorityUrlFromEnv } from '../authority/resolve-authority.ts';
import { tdcpRuntime } from '../runtime/tdcp-runtime.ts';

type HealthState = 'checking' | 'connected' | 'offline' | 'in-process';

export interface AuthorityHealthSnapshot {
  state: HealthState;
  url: string | null;
  adminAuthMode?: string;
  lastError?: string;
  checkedAt?: number;
}

/**
 * Poll Authority /health when a remote URL is configured.
 * Honest: Connected ≠ HSM / production-grade custody.
 */
export function useAuthorityHealth(pollMs = 5000): AuthorityHealthSnapshot {
  const configuredUrl = readAuthorityUrlFromEnv() ?? null;
  const kind = tdcpRuntime.authority.kind;
  const [snap, setSnap] = useState<AuthorityHealthSnapshot>(() => ({
    state: configuredUrl && kind === 'HTTP_REMOTE' ? 'checking' : 'in-process',
    url: configuredUrl,
  }));

  useEffect(() => {
    let cancelled = false;
    if (!configuredUrl || kind !== 'HTTP_REMOTE') {
      setSnap({ state: 'in-process', url: configuredUrl });
      return;
    }

    const tick = async () => {
      try {
        const res = await fetch(`${configuredUrl}/health`, { cache: 'no-store' });
        const body = (await res.json().catch(() => null)) as {
          ok?: boolean;
          adminAuthMode?: string;
        } | null;
        if (cancelled) return;
        if (res.ok && body?.ok) {
          setSnap({
            state: 'connected',
            url: configuredUrl,
            adminAuthMode: body.adminAuthMode,
            checkedAt: Date.now(),
          });
        } else {
          setSnap({
            state: 'offline',
            url: configuredUrl,
            lastError: `HTTP ${res.status}`,
            checkedAt: Date.now(),
          });
        }
      } catch (err) {
        if (cancelled) return;
        setSnap({
          state: 'offline',
          url: configuredUrl,
          lastError: err instanceof Error ? err.message : String(err),
          checkedAt: Date.now(),
        });
      }
    };

    void tick();
    const id = window.setInterval(() => void tick(), pollMs);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [configuredUrl, kind, pollMs]);

  return snap;
}


/** Compact chip for the app top bar (hamburger shell). */
export function AuthorityStatusChip({ className = '' }: { className?: string }) {
  const health = useAuthorityHealth();

  if (health.state === 'connected') {
    return (
      <span
        className={`inline-flex items-center gap-1.5 rounded-full border border-emerald-500/40 bg-emerald-500/15 px-2.5 py-0.5 text-[10px] font-bold tracking-wide text-emerald-200 uppercase ${className}`}
      >
        <Wifi className="h-3 w-3" /> Authority Connected
      </span>
    );
  }
  if (health.state === 'offline') {
    return (
      <span
        className={`inline-flex items-center gap-1.5 rounded-full border border-red-500/40 bg-red-500/15 px-2.5 py-0.5 text-[10px] font-bold tracking-wide text-red-200 uppercase ${className}`}
      >
        <WifiOff className="h-3 w-3" /> Authority Offline
      </span>
    );
  }
  if (health.state === 'checking') {
    return (
      <span
        className={`inline-flex items-center gap-1.5 rounded-full border border-amber-500/40 bg-amber-500/15 px-2.5 py-0.5 text-[10px] font-bold tracking-wide text-amber-100 uppercase ${className}`}
      >
        <Activity className="h-3 w-3 animate-pulse" /> Checking…
      </span>
    );
  }
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border border-amber-500/40 bg-amber-500/10 px-2.5 py-0.5 text-[10px] font-bold tracking-wide text-amber-100 uppercase ${className}`}
    >
      In-process Oracle
    </span>
  );
}

/** Always-visible MVP / Authority honesty banner + connection chip. */
export function AuthorityStatusBar() {
  const health = useAuthorityHealth();
  const providers = tdcpRuntime.getProviderStatus();
  const remoteUrl = health.url || providers.authorityUrl;

  let bannerText: string;
  if (health.state === 'connected' && remoteUrl) {
    bannerText = `MVP operativo — Authority remoto en ${remoteUrl} (file signing — not HSM)`;
  } else if (health.state === 'offline' && remoteUrl) {
    bannerText = `MVP operativo — Authority remoto OFFLINE (${remoteUrl}); Oracle in-process si Authority caído para paneles locales`;
  } else if (health.state === 'checking' && remoteUrl) {
    bannerText = `MVP operativo — comprobando Authority en ${remoteUrl}…`;
  } else {
    bannerText =
      'MVP / Demo — Oracle in-process (sin TDCP_AUTHORITY_URL). No es frontera de producción.';
  }

  return (
    <div className="mb-3 flex flex-col gap-2 rounded-xl border border-white/10 bg-black/50 px-3 py-2.5 md:flex-row md:items-center md:justify-between">
      <div className="min-w-0 space-y-1">
        <p className="text-[11px] font-semibold leading-snug text-white/85">{bannerText}</p>
        <p className="text-[10px] leading-snug text-white/45">
          Copiar el archivo no copia el derecho a usarlo · Copying the file does not copy the right to
          use it.
        </p>
      </div>
      <div className="shrink-0">
        <AuthorityStatusChip />
      </div>
    </div>
  );
}

export default AuthorityStatusBar;
