import { useEffect, useState } from 'react';
import { Activity, Wifi, WifiOff } from 'lucide-react';
import { readAuthorityUrlFromEnv } from '../authority/resolve-authority.ts';
import { tdcpRuntime } from '../runtime/tdcp-runtime.ts';
import { probeSmartTokenHealth } from '../protection/smart-token-local.ts';
import { useUiPrefs } from '../lib/ui-prefs.tsx';

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
        const res = await fetch(`${configuredUrl}/healthz`, { cache: 'no-store' });
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


/** Chip: Smart-Token-Prod API (isolated repo) connectivity. */
export function SmartTokenStatusChip({ className = '' }: { className?: string }) {
  const [label, setLabel] = useState('STP…');
  const [tone, setTone] = useState<'ok' | 'warn' | 'bad' | 'off'>('warn');

  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      const h = await probeSmartTokenHealth();
      if (cancelled) return;
      if (!h.configured) {
        setLabel('STP not configured');
        setTone('off');
        return;
      }
      if (!h.reachable) {
        setLabel('STP offline');
        setTone('bad');
        return;
      }
      if (h.smartTokenAvailable === false) {
        setLabel('STP crypto down');
        setTone('bad');
        return;
      }
      setLabel('STP connected');
      setTone('ok');
    };
    void tick();
    const id = window.setInterval(() => void tick(), 8000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  const toneClass =
    tone === 'ok'
      ? 'border-cyan-500/40 bg-cyan-500/15 text-cyan-100'
      : tone === 'bad'
        ? 'border-red-500/40 bg-red-500/15 text-red-200'
        : tone === 'off'
          ? 'border-white/15 bg-white/5 text-white/45'
          : 'border-amber-500/40 bg-amber-500/15 text-amber-100';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[10px] font-bold tracking-wide uppercase ${toneClass} ${className}`}
      title="Smart-Token-Prod API (VITE_SMART_TOKEN_API_URL)"
    >
      {tone === 'ok' ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
      {label}
    </span>
  );
}

/** Status bar: minimal by default; technical chips only in developer mode. */
export function AuthorityStatusBar() {
  const health = useAuthorityHealth();
  const providers = tdcpRuntime.getProviderStatus();
  const remoteUrl = health.url || providers.authorityUrl;
  const { developerMode } = useUiPrefs();

  // Pilot UX: one short status line, no jargon unless developer mode
  let bannerText: string;
  if (health.state === 'connected') {
    bannerText = developerMode && remoteUrl
      ? `Conectado · ${remoteUrl}`
      : 'Sistema listo';
  } else if (health.state === 'offline') {
    bannerText = 'Sin conexión con el servidor de autorización';
  } else if (health.state === 'checking') {
    bannerText = 'Conectando…';
  } else {
    bannerText = developerMode ? 'Modo local (sin Authority remoto)' : 'Sistema listo';
  }

  return (
    <div className="mb-2 flex shrink-0 items-center justify-between gap-2 rounded-lg border border-white/10 bg-black/40 px-2.5 py-1.5">
      <p
        className="min-w-0 truncate text-[11px] font-medium leading-tight text-white/75"
        title="Copiar el archivo no copia el derecho a usarlo"
      >
        {bannerText}
      </p>
      {developerMode && (
        <div className="hidden shrink-0 items-center gap-1.5 sm:flex">
          <SmartTokenStatusChip />
          <AuthorityStatusChip />
        </div>
      )}
    </div>
  );
}

export default AuthorityStatusBar;
