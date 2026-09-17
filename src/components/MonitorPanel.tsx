import { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  ShieldAlert,
  Ban,
  CheckCircle,
  AlertTriangle,
  ShieldCheck,
  Download,
  Search,
  RefreshCw,
  Hash,
  Lock,
  Database,
  Clock,
} from 'lucide-react';
import { tdcpRuntime, TDCP_AUDIT_UPDATED_EVENT } from '../runtime/tdcp-runtime.ts';
import type { AuditEvent } from '../audit/audit-event.ts';
import type { DocumentRevocationState } from '../core/authorization/types.ts';
import AuthorityOpsStrip from './AuthorityOpsStrip.tsx';
import CollapsibleSection from './CollapsibleSection.tsx';

export default function MonitorPanel() {
  const [activeTab, setActiveTab] = useState<'audit' | 'killswitch'>('audit');
  const [monitorKey, setMonitorKey] = useState('');
  const [status, setStatus] = useState<{ type: 'success' | 'error'; message: string } | null>(null);
  const [revoked, setRevoked] = useState<DocumentRevocationState[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditEvent[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [isVerifyingChain, setIsVerifyingChain] = useState(false);
  const [verificationResult, setVerificationResult] = useState<{
    tested: boolean;
    valid: boolean;
    count: number;
    error?: string;
  } | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const load = async () => {
    setAuditLogs(await tdcpRuntime.auditSink.getEvents());
    setRevoked(tdcpRuntime.listRevoked());
  };

  useEffect(() => {
    void load();
    const onUpdate = () => {
      void load();
    };
    window.addEventListener(TDCP_AUDIT_UPDATED_EVENT, onUpdate);
    return () => window.removeEventListener(TDCP_AUDIT_UPDATED_EVENT, onUpdate);
  }, []);

  const handleKillSwitch = async () => {
    const raw = monitorKey.replace('MONITOR-', '').trim();
    if (raw.length < 5) {
      setStatus({ type: 'error', message: 'Clave de monitoreo inválida (MONITOR-DOC-...).' });
      return;
    }
    const policy = tdcpRuntime.oracle.getDocumentPolicy(raw);
    if (!policy) {
      setStatus({
        type: 'error',
        message: 'El Oracle no conoce ese documentId. localStorage no revoca nada.',
      });
      return;
    }
    const state = tdcpRuntime.revokeDocument(raw, 'Kill-switch del operador');
    setStatus({
      type: 'success',
      message: `Documento ${raw} revocado. epoch=${state.currentEpoch}. Grants anteriores inválidos.`,
    });
    setMonitorKey('');
    await load();
  };

  const restore = async (documentId: string) => {
    const state = tdcpRuntime.restoreDocument(documentId);
    setStatus({
      type: 'success',
      message: `Restaurado ${documentId}. epoch=${state.currentEpoch} (grants viejos siguen muertos).`,
    });
    await load();
  };

  const handleVerifyChain = async () => {
    setIsVerifyingChain(true);
    const res = await tdcpRuntime.auditSink.verifyIntegrity();
    setVerificationResult({
      tested: true,
      valid: res.isValid,
      count: res.checkedCount,
      error: res.error,
    });
    setIsVerifyingChain(false);
  };

  const handleExportJSON = async () => {
    const events = await tdcpRuntime.auditSink.getEvents();
    const blob = new Blob([JSON.stringify(events, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'tdcp-tamper-evident-audit.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredLogs = useMemo(() => {
    const q = searchQuery.toLowerCase();
    return auditLogs.filter((e) => {
      if (!q) return true;
      return (
        e.eventId.toLowerCase().includes(q) ||
        e.documentId.toLowerCase().includes(q) ||
        e.operation.toLowerCase().includes(q) ||
        e.details.toLowerCase().includes(q)
      );
    });
  }, [auditLogs, searchQuery]);

  const stats = {
    total: auditLogs.length,
    success: auditLogs.filter((e) => e.result === 'SUCCESS').length,
    denied: auditLogs.filter((e) => e.result !== 'SUCCESS').length,
    revoked: revoked.length,
  };

  return (
    <div className="flex h-full min-h-0 flex-col gap-5">
      <div className="glass-panel flex flex-1 flex-col overflow-hidden p-5 md:p-6">
        <div className="mb-5 flex shrink-0 flex-col items-start justify-between gap-3 border-b border-white/10 pb-4 md:flex-row md:items-center">
          <div>
            <h2 className="flex items-center gap-2 text-xl font-bold text-pink-400">
              <Activity className="h-5 w-5" /> Auditoría y revocación
            </h2>
            <p className="mt-0.5 text-xs text-white/50">
              {tdcpRuntime.auditSink.integrityClaim}. Oracle epoch es la autoridad del kill-switch.
            </p>
          </div>
          <span className="flex items-center gap-1.5 rounded-full border border-pink-500/30 bg-pink-500/10 px-2.5 py-1 font-mono text-[10px] text-pink-300">
            <Lock className="h-3.5 w-3.5" /> no localStorage de seguridad
          </span>
        </div>

        <div className="mb-4 grid shrink-0 grid-cols-1 gap-3 md:grid-cols-2">
          <CollapsibleSection
            title="Ops Authority"
            subtitle="Salud remota · métricas"
            accent="cyan"
            defaultOpen={false}
          >
            <AuthorityOpsStrip />
          </CollapsibleSection>
          <CollapsibleSection
            title="Resumen"
            subtitle="Contadores de la sesión"
            accent="pink"
            defaultOpen={false}
          >
            <div className="grid grid-cols-2 gap-3">

          <div className="rounded-xl border border-white/10 bg-black/30 p-3">
            <span className="text-[10px] font-bold tracking-wider text-white/40 uppercase">Eventos</span>
            <div className="mt-1 font-mono text-lg font-bold text-white">{stats.total}</div>
          </div>
          <div className="rounded-xl border border-white/10 bg-black/30 p-3">
            <span className="text-[10px] font-bold tracking-wider text-white/40 uppercase">Éxitos</span>
            <div className="mt-1 font-mono text-lg font-bold text-emerald-400">{stats.success}</div>
          </div>
          <div className="rounded-xl border border-white/10 bg-black/30 p-3">
            <span className="text-[10px] font-bold tracking-wider text-white/40 uppercase">Denegados</span>
            <div className="mt-1 font-mono text-lg font-bold text-amber-400">{stats.denied}</div>
          </div>
          <div className="rounded-xl border border-white/10 bg-black/30 p-3">
            <span className="text-[10px] font-bold tracking-wider text-white/40 uppercase">Revocados</span>
            <div className="mt-1 font-mono text-lg font-bold text-pink-400">{stats.revoked}</div>
          </div>
        
            </div>
          </CollapsibleSection>
        </div>

<div className="mb-4 flex shrink-0 items-center justify-between gap-3 border-b border-white/10 pb-3">
          <div className="flex items-center gap-2 rounded-xl border border-white/10 bg-black/40 p-1">
            <button
              type="button"
              onClick={() => setActiveTab('audit')}
              className={`flex cursor-pointer items-center gap-2 rounded-lg px-3.5 py-1.5 text-xs font-bold ${
                activeTab === 'audit'
                  ? 'border border-pink-500/40 bg-pink-500/20 text-pink-300'
                  : 'text-white/60'
              }`}
            >
              <Database className="h-3.5 w-3.5" /> Audit sink
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('killswitch')}
              className={`flex cursor-pointer items-center gap-2 rounded-lg px-3.5 py-1.5 text-xs font-bold ${
                activeTab === 'killswitch'
                  ? 'border border-pink-500/40 bg-pink-500/20 text-pink-300'
                  : 'text-white/60'
              }`}
            >
              <Ban className="h-3.5 w-3.5" /> Kill-switch (epoch)
            </button>
          </div>
          {activeTab === 'audit' && (
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleVerifyChain}
                disabled={isVerifyingChain}
                className="flex cursor-pointer items-center gap-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs font-bold text-emerald-300"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${isVerifyingChain ? 'animate-spin' : ''}`} />
                Verificar cadena
              </button>
              <button
                type="button"
                onClick={handleExportJSON}
                className="flex cursor-pointer items-center gap-1.5 rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-xs font-bold text-white/80"
              >
                <Download className="h-3.5 w-3.5" /> JSON
              </button>
            </div>
          )}
        </div>

        {activeTab === 'audit' && (
          <div className="flex min-h-0 flex-1 flex-col">
            {verificationResult && (
              <div
                className={`mb-3 flex shrink-0 items-center gap-2 rounded-xl border p-2.5 text-xs ${
                  verificationResult.valid
                    ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                    : 'border-rose-500/30 bg-rose-500/10 text-rose-300'
                }`}
              >
                {verificationResult.valid ? (
                  <CheckCircle className="h-4 w-4" />
                ) : (
                  <AlertTriangle className="h-4 w-4" />
                )}
                {verificationResult.valid
                  ? `Cadena tamper-evident válida (${verificationResult.count} eventos). No es un ledger inmutable.`
                  : verificationResult.error}
              </div>
            )}
            <div className="relative mb-3 shrink-0">
              <Search className="absolute top-1/2 left-3 h-3.5 w-3.5 -translate-y-1/2 text-white/40" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Buscar documentId, operación, evento..."
                className="w-full rounded-lg border border-white/10 bg-black/40 py-1.5 pr-3 pl-9 text-xs text-white outline-none"
              />
            </div>
            <div className="flex-1 space-y-2 overflow-y-auto pr-1">
              {filteredLogs.length === 0 ? (
                <div className="flex h-48 flex-col items-center justify-center rounded-xl border border-dashed border-white/10 bg-black/20 p-6 text-center">
                  <Database className="mb-2 h-8 w-8 text-white/20" />
                  <p className="text-xs text-white/50">Sin eventos todavía.</p>
                </div>
              ) : (
                filteredLogs
                  .slice()
                  .reverse()
                  .map((entry) => (
                    <button
                      key={entry.eventId}
                      type="button"
                      onClick={() => setSelectedId(selectedId === entry.eventId ? null : entry.eventId)}
                      className="w-full rounded-xl border border-white/10 bg-black/40 p-3 text-left hover:bg-white/5"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <span
                            className={`rounded border px-2 py-0.5 font-mono text-[10px] font-bold ${
                              entry.result === 'SUCCESS'
                                ? 'border-emerald-500/30 text-emerald-400'
                                : 'border-amber-500/30 text-amber-300'
                            }`}
                          >
                            {entry.result}
                          </span>
                          <span className="font-mono text-xs font-bold text-indigo-300">{entry.operation}</span>
                          <span className="font-mono text-xs text-white/60">{entry.documentId}</span>
                        </div>
                        <span className="flex items-center gap-1 font-mono text-[11px] text-white/40">
                          <Clock className="h-3 w-3" />
                          {new Date(entry.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                      <p className="mt-1.5 line-clamp-2 text-xs text-white/80">{entry.details}</p>
                      {selectedId === entry.eventId && (
                        <div className="mt-3 space-y-1 rounded-lg border border-pink-500/20 bg-black/70 p-3 font-mono text-[11px] text-white/70">
                          <div className="flex items-center gap-1 text-pink-300">
                            <Hash className="h-3.5 w-3.5" /> {entry.eventHash}
                          </div>
                          <div>prev: {entry.previousEventHash}</div>
                          <div>grant: {entry.authorizationId || 'NONE'}</div>
                          <div>device: {entry.deviceId}</div>
                          <div>credential: {entry.credentialId}</div>
                        </div>
                      )}
                    </button>
                  ))
              )}
            </div>
          </div>
        )}

        {activeTab === 'killswitch' && (
          <div className="flex-1 overflow-y-auto">
            <div className="mx-auto w-full max-w-6xl space-y-6 py-2">
              <div className="mb-2 text-center md:text-left">
                <div className="mx-auto mb-3 flex h-14 w-14 items-center justify-center rounded-full border border-pink-500/50 bg-pink-500/20 md:mx-0">
                  <ShieldAlert className="h-7 w-7 text-pink-400" />
                </div>
                <h3 className="mb-1.5 text-lg font-bold text-white">Revocación por epoch</h3>
                <p className="mx-auto max-w-md text-xs leading-relaxed text-white/60 md:mx-0">
                  El Oracle incrementa authorizationEpoch e isRevoked=true. localStorage no es autoridad.
                </p>
              </div>
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2 md:items-start">
                <div className="space-y-4">
                  <div className="glass-card space-y-4 border-l-2 border-l-pink-500 p-6">
                    <label className="mb-2 block text-xs font-bold text-white/50 uppercase">
                      MONITOR-DOC-... (documentId)
                    </label>
                    <input
                      type="text"
                      value={monitorKey}
                      onChange={(e) => setMonitorKey(e.target.value)}
                      placeholder="MONITOR-DOC-..."
                      className="w-full rounded-lg border border-white/10 bg-black/40 p-3.5 font-mono text-sm text-pink-300 outline-none"
                    />
                    <button
                      onClick={handleKillSwitch}
                      className="flex w-full cursor-pointer items-center justify-center gap-2 rounded-lg border border-pink-500/50 bg-pink-500/20 p-4 font-bold tracking-wider text-pink-300 uppercase"
                    >
                      <Ban className="h-5 w-5" /> Revocar (epoch++)
                    </button>
                  </div>
                  {status && (
                    <div
                      className={`flex items-start gap-3 rounded-lg border p-4 ${
                        status.type === 'success'
                          ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
                          : 'border-red-500/30 bg-red-500/10 text-red-400'
                      }`}
                    >
                      {status.type === 'success' ? (
                        <CheckCircle className="mt-0.5 h-5 w-5 shrink-0" />
                      ) : (
                        <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" />
                      )}
                      <p className="text-xs leading-relaxed">{status.message}</p>
                    </div>
                  )}
                </div>
                <div className="space-y-3">
                  {revoked.length > 0 ? (
                    <div className="glass-card space-y-3 border border-white/10 p-5">
                      {revoked.map((item) => (
                        <div
                          key={item.documentId}
                          className="flex items-center justify-between rounded border border-white/5 bg-black/30 p-2.5 text-xs"
                        >
                          <div>
                            <div className="font-mono font-bold text-pink-300">{item.documentId}</div>
                            <div className="text-[10px] text-white/40">
                              epoch {item.currentEpoch} · {item.revocationReason}
                            </div>
                          </div>
                          <button
                            onClick={() => restore(item.documentId)}
                            className="cursor-pointer rounded border border-white/10 px-2 py-1 text-[11px] text-white/70 hover:text-white"
                          >
                            Restaurar (epoch++)
                          </button>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="glass-card flex h-full min-h-32 items-center justify-center border border-dashed border-white/10 p-5 text-center text-xs text-white/40">
                      Sin documentos revocados en esta sesión.
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
