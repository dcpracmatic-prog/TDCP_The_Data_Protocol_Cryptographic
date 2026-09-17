import { useEffect, useState } from 'react';
import { Server, AlertTriangle } from 'lucide-react';
import { readAuthorityUrlFromEnv } from '../authority/resolve-authority.ts';
import { useAuthorityHealth } from './AuthorityStatusBar.tsx';

interface ParsedMetrics {
  grantsIssued?: number;
  grantsDenied?: number;
  revokes?: number;
  httpErrors?: number;
  adminUnauthorized?: number;
}

function parsePrometheus(text: string): ParsedMetrics {
  const get = (name: string): number | undefined => {
    const m = text.match(new RegExp(`^${name}\\s+(\\d+(?:\\.\\d+)?)`, 'm'));
    return m ? Number(m[1]) : undefined;
  };
  return {
    grantsIssued: get('tdcp_authority_grants_issued'),
    grantsDenied: get('tdcp_authority_grants_denied'),
    revokes: get('tdcp_authority_revokes'),
    httpErrors: get('tdcp_authority_http_errors'),
    adminUnauthorized: get('tdcp_authority_admin_unauthorized'),
  };
}

/** Ops strip for Monitor: Authority health + parseable /metrics counters. */
export default function AuthorityOpsStrip() {
  const health = useAuthorityHealth(8000);
  const url = health.url ?? readAuthorityUrlFromEnv() ?? null;
  const [metrics, setMetrics] = useState<ParsedMetrics | null>(null);
  const [metricsError, setMetricsError] = useState<string | null>(null);

  useEffect(() => {
    if (!url || health.state !== 'connected') {
      setMetrics(null);
      return;
    }
    let cancelled = false;
    const load = async () => {
      try {
        const res = await fetch(`${url}/metrics`, { cache: 'no-store' });
        const text = await res.text();
        if (cancelled) return;
        if (!res.ok) {
          setMetricsError(`metrics HTTP ${res.status}`);
          return;
        }
        setMetrics(parsePrometheus(text));
        setMetricsError(null);
      } catch (err) {
        if (!cancelled) {
          setMetricsError(err instanceof Error ? err.message : String(err));
        }
      }
    };
    void load();
    const id = window.setInterval(() => void load(), 8000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [url, health.state]);

  return (
    <div className="shrink-0 rounded-xl border border-cyan-500/25 bg-cyan-500/5 p-3">
      <div className="mb-2 flex items-center gap-2 text-[11px] font-bold tracking-wider text-cyan-200 uppercase">
        <Server className="h-3.5 w-3.5" /> Ops — Authority
      </div>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <div className="rounded-lg border border-white/10 bg-black/30 px-2.5 py-2">
          <div className="text-[9px] font-bold tracking-wider text-white/40 uppercase">Health</div>
          <div
            className={`mt-0.5 font-mono text-xs font-bold ${
              health.state === 'connected'
                ? 'text-emerald-400'
                : health.state === 'offline'
                  ? 'text-red-400'
                  : 'text-amber-300'
            }`}
          >
            {health.state === 'connected'
              ? 'Connected'
              : health.state === 'offline'
                ? 'Offline'
                : health.state === 'checking'
                  ? 'Checking'
                  : 'In-process'}
          </div>
        </div>
        <div className="rounded-lg border border-white/10 bg-black/30 px-2.5 py-2">
          <div className="text-[9px] font-bold tracking-wider text-white/40 uppercase">Grants +</div>
          <div className="mt-0.5 font-mono text-xs font-bold text-white">
            {metrics?.grantsIssued ?? '—'}
          </div>
        </div>
        <div className="rounded-lg border border-white/10 bg-black/30 px-2.5 py-2">
          <div className="text-[9px] font-bold tracking-wider text-white/40 uppercase">Denied</div>
          <div className="mt-0.5 font-mono text-xs font-bold text-amber-300">
            {metrics?.grantsDenied ?? '—'}
          </div>
        </div>
        <div className="rounded-lg border border-white/10 bg-black/30 px-2.5 py-2">
          <div className="text-[9px] font-bold tracking-wider text-white/40 uppercase">HTTP 5xx</div>
          <div className="mt-0.5 font-mono text-xs font-bold text-pink-300">
            {metrics?.httpErrors ?? '—'}
          </div>
        </div>
      </div>
      {(health.lastError || metricsError) && (
        <p className="mt-2 flex items-start gap-1.5 text-[10px] text-amber-200/90">
          <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" />
          {health.lastError || metricsError}
        </p>
      )}
      {!url && (
        <p className="mt-2 text-[10px] text-white/40">
          Sin URL remota — métricas Authority no aplicables (Oracle in-process).
        </p>
      )}
    </div>
  );
}
