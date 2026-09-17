import { useState } from 'react';
import { FlaskConical, CheckCircle, XCircle, ShieldAlert, Play } from 'lucide-react';
import { runTDCPTestSuite, type TestCaseResult, type TestSuiteSummary } from '../test/tdcp-test-runner.ts';
import CollapsibleSection from './CollapsibleSection.tsx';

const CATEGORIES = [
  'CRYPTOGRAPHIC',
  'AUTHORIZATION',
  'ANTI-REPLAY',
  'REVOCATION',
  'DEVICE BINDING',
  'CREDENTIAL BINDING',
  'AUDIT',
  'STORAGE',
  'ULTRA_CRITICAL',
] as const;

function mapCategory(c: TestCaseResult['category']): (typeof CATEGORIES)[number] {
  switch (c) {
    case 'CRYPTO':
      return 'CRYPTOGRAPHIC';
    case 'AUTHORIZATION':
      return 'AUTHORIZATION';
    case 'REPLAY':
      return 'ANTI-REPLAY';
    case 'REVOCATION':
      return 'REVOCATION';
    case 'TAMPER':
      return 'AUDIT';
    case 'ULTRA_CRITICAL':
      return 'ULTRA_CRITICAL';
    case 'STORAGE':
      return 'STORAGE';
    default:
      return 'AUTHORIZATION';
  }
}

export default function ValidationPanel() {
  const [running, setRunning] = useState(false);
  const [summary, setSummary] = useState<TestSuiteSummary | null>(null);
  const [progress, setProgress] = useState('');

  const run = async () => {
    setRunning(true);
    setSummary(null);
    setProgress('Ejecutando pruebas reales contra Gatekeeper / Oracle...');
    try {
      const result = await runTDCPTestSuite((current, total, r) => {
        setProgress(`[${current}/${total}] ${r.status} · ${r.name}`);
      });
      setSummary(result);
    } catch (err: unknown) {
      setProgress(err instanceof Error ? err.message : String(err));
    } finally {
      setRunning(false);
    }
  };

  const grouped = CATEGORIES.map((cat) => {
    const tests = summary?.results.filter((r) => {
      if (cat === 'DEVICE BINDING') return r.name.toLowerCase().includes('dispositivo') || r.name.toLowerCase().includes('device');
      if (cat === 'CREDENTIAL BINDING') return r.name.toLowerCase().includes('credencial') || r.name.toLowerCase().includes('credential');
      if (cat === 'ANTI-REPLAY') return r.category === 'REPLAY' || r.name.toLowerCase().includes('replay');
      return mapCategory(r.category) === cat;
    });
    const pass = tests?.filter((t) => t.status === 'PASS').length ?? 0;
    const total = tests?.length ?? 0;
    return { cat, tests: tests ?? [], pass, total };
  });

  return (
    <div className="flex h-full min-h-0 flex-col gap-5">
      <div className="glass-panel flex flex-1 flex-col overflow-hidden p-5 md:p-6">
        <div className="mb-4 flex flex-col gap-3 border-b border-white/10 pb-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="flex items-center gap-2 text-xl font-bold text-amber-300">
              <FlaskConical className="h-5 w-5" /> Validación TDCP
            </h2>
            <p className="mt-1 max-w-xl text-xs text-white/50">
              Cada resultado sale de una prueba ejecutada. Este panel no afirma “100% secure”,
              “100% compliant” ni “impossible to extract”. El navegador no es un enclave.
            </p>
          </div>
          <button
            type="button"
            disabled={running}
            onClick={run}
            className="flex cursor-pointer items-center gap-2 rounded-lg border border-amber-500/40 bg-amber-500/15 px-4 py-2 text-xs font-bold text-amber-200 uppercase disabled:opacity-50"
          >
            <Play className="h-4 w-4" />
            {running ? 'Ejecutando...' : 'Correr suite'}
          </button>
        </div>

        {progress && <p className="mb-3 font-mono text-[11px] text-white/50">{progress}</p>}

        {summary && (
          <div className="mb-4 rounded-xl border border-white/10 bg-black/30 p-3 text-xs text-white/70">
            {summary.passedCount}/{summary.totalTests} PASS · {summary.failedCount} FAIL · {summary.totalDurationMs} ms
            <span className="mt-1 block text-[11px] text-white/40">
              Proveedores MOCK en este runtime: NFC, dispositivo, biometría, Oracle key store en RAM (DEVELOPMENT ONLY).
            </span>
          </div>
        )}

        <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto">
          {grouped.map(({ cat, tests, pass, total }) => (
            <div key={cat} className="rounded-xl border border-white/10 bg-black/30 p-3">
              <div className="mb-2 flex items-center justify-between">
                <span className="text-[11px] font-bold tracking-wider text-white/70 uppercase">{cat}</span>
                <span className="font-mono text-[11px] text-white/40">
                  {total ? `${pass}/${total}` : '—'}
                </span>
              </div>
              {tests.length === 0 ? (
                <p className="text-[11px] text-white/30">Sin casos en esta corrida.</p>
              ) : (
                <ul className="space-y-1.5">
                  {tests.map((t) => (
                    <li key={t.id} className="flex items-start gap-2 text-[11px]">
                      {t.status === 'PASS' ? (
                        <CheckCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400" />
                      ) : (
                        <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-rose-400" />
                      )}
                      <span className="text-white/80">
                        {t.name}
                        <span className="mt-0.5 block text-white/40">{t.actualResult}</span>
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ))}
        </div>

        <CollapsibleSection
          title="Limitaciones"
          subtitle="Alcance honesto del navegador"
          accent="amber"
          defaultOpen={false}
        >
          <div className="mt-3 flex items-start gap-2 rounded-lg border border-white/10 bg-black/40 p-3 text-[11px] text-white/50">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
          Limitaciones del navegador: sin HSM, sin mlock, sin NFC de hardware en este preview, WebAuthn sin
          credencial enrolada. Un atacante con DevTools en el mismo origen sigue viendo RAM. TDCP aquí es
          control de autorización de aplicación, no un enclave.
        </div>
        </CollapsibleSection>
      </div>
    </div>
  );
}
