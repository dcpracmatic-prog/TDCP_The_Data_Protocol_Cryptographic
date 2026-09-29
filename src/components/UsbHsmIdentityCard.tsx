import { useCallback, useEffect, useState } from 'react';
import { KeyRound, Plus, RefreshCw, ShieldAlert, ShieldCheck, Trash2, Usb } from 'lucide-react';
import { TDCP_SESSION_EVENT, tdcpRuntime } from '../runtime/tdcp-runtime.ts';
import { UsbHsmProver } from '../identity/usb-hsm-provider.ts';
import type { UsbHsmDeviceInfo, UsbHsmStatus } from '../core/authorization/usb-hsm.ts';

const STATUS_STYLE: Record<UsbHsmStatus, string> = {
  ACTIVE: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200',
  SUSPENDED: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  REVOKED: 'border-rose-500/40 bg-rose-500/10 text-rose-200',
  REPLACED: 'border-white/15 bg-white/5 text-white/50',
};

const STATUS_LABEL: Record<UsbHsmStatus, string> = {
  ACTIVE: 'Activa',
  SUSPENDED: 'Suspendida',
  REVOKED: 'Revocada',
  REPLACED: 'Reemplazada',
};

const ERROR_TEXT: Record<string, string> = {
  USB_HSM_NOT_HARDWARE_BOUND:
    'Esa credencial es una passkey sincronizada en la nube, no un HSM. Usa una llave USB con elemento seguro.',
  USB_HSM_NOT_USB: 'El autenticador no es una llave USB (p. ej. Windows Hello o Touch ID).',
  USB_HSM_LIMIT: 'Alcanzaste el límite de llaves por cuenta. Revoca una antes de añadir otra.',
  EMAIL_NOT_VERIFIED: 'Confirma tu correo antes de registrar un USB-HSM.',
  USB_HSM_REGISTRATION_EXPIRED: 'El registro expiró. Vuelve a intentarlo.',
  USB_HSM_REGISTRATION_INVALID:
    'La llave no pasó la verificación (requiere PIN/huella en la llave y el dominio correcto).',
  USB_HSM_CLONE_SUSPECTED:
    'Esta llave se suspendió por posible clonación. Reemplázala por una nueva.',
};

function describeError(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  const code = Object.keys(ERROR_TEXT).find((c) => raw.includes(c));
  return code ? ERROR_TEXT[code]! : raw;
}

function fmt(ts: number | null): string {
  return ts ? new Date(ts).toLocaleString() : '—';
}

/** "Mi USB-HSM": turn a USB security key into the account's hardware ID. */
export default function UsbHsmIdentityCard() {
  const [prover, setProver] = useState(() => tdcpRuntime.usbHsm);
  useEffect(() => {
    const sync = () => setProver(tdcpRuntime.usbHsm);
    sync();
    window.addEventListener(TDCP_SESSION_EVENT, sync);
    return () => window.removeEventListener(TDCP_SESSION_EVENT, sync);
  }, []);
  const [devices, setDevices] = useState<UsbHsmDeviceInfo[]>([]);
  const [label, setLabel] = useState('Mi llave USB');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ kind: 'ok' | 'error'; text: string } | null>(null);

  const refresh = useCallback(async () => {
    if (!prover) return;
    try {
      setDevices(await prover.list());
    } catch (err) {
      setMessage({ kind: 'error', text: describeError(err) });
    }
  }, [prover]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const run = async (fn: () => Promise<string>) => {
    setBusy(true);
    setMessage(null);
    try {
      setMessage({ kind: 'ok', text: await fn() });
      await refresh();
    } catch (err) {
      setMessage({ kind: 'error', text: describeError(err) });
    } finally {
      setBusy(false);
    }
  };

  const enroll = (replaceDeviceId?: string) =>
    run(async () => {
      const d = await prover!.enroll(label, replaceDeviceId);
      return `Llave registrada como tu ID: ${d.deviceId}`;
    });

  const change = (d: UsbHsmDeviceInfo, action: 'revoke' | 'suspend' | 'reactivate') => {
    if (action === 'revoke' && !window.confirm(`¿Revocar ${d.label}? No podrá volver a abrir documentos.`)) return;
    void run(async () => {
      await prover!.changeStatus(d.deviceId, action);
      return action === 'revoke' ? 'Llave revocada.' : action === 'suspend' ? 'Llave suspendida.' : 'Llave reactivada.';
    });
  };

  const active = devices.filter((d) => d.status === 'ACTIVE');

  return (
    <section className="mb-5 space-y-3 rounded-xl border border-cyan-500/25 bg-cyan-500/5 p-3" data-testid="usb-hsm-card">
      <div className="flex items-center justify-between gap-2">
        <h3 className="flex items-center gap-2 text-xs font-bold text-white">
          <Usb className="h-4 w-4 text-cyan-300" /> Mi USB-HSM (ID físico)
        </h3>
        {prover && (
          <span className={`rounded-full border px-2 py-0.5 text-[10px] ${active.length ? STATUS_STYLE.ACTIVE : STATUS_STYLE.SUSPENDED}`}>
            {active.length ? `${active.length} activa(s)` : 'Sin llave'}
          </span>
        )}
      </div>
      <p className="text-[11px] leading-relaxed text-white/55">
        Tu llave USB genera dentro de su chip una clave que <strong className="text-white/80">nunca sale</strong> del
        dispositivo; el Authority guarda solo la clave pública ligada a tu cuenta. Los documentos
        CRITICAL / ULTRA_CRITICAL o marcados "Exigir USB-HSM" solo se abren tocando la llave y con su PIN.
        Requiere una llave FIDO2 (YubiKey, Nitrokey, SoloKey, Feitian, Token2…): una memoria USB
        genérica no tiene elemento seguro y no sirve como HSM.
      </p>

      {!prover ? (
        <p className="rounded-lg border border-white/10 bg-black/30 p-2 text-[11px] text-white/50">
          Inicia sesión con un Authority remoto (VITE_AUTH_ENABLED + VITE_TDCP_AUTHORITY_URL) para registrar tu USB-HSM.
        </p>
      ) : !UsbHsmProver.isSupported() ? (
        <p className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-2 text-[11px] text-amber-200">
          Este navegador no soporta WebAuthn.
        </p>
      ) : (
        <>
          <div className="flex flex-col gap-2 sm:flex-row">
            <input
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              maxLength={60}
              placeholder="Nombre de la llave"
              aria-label="Nombre de la llave"
              className="min-w-0 flex-1 rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-xs text-white outline-none focus:border-cyan-500/50"
            />
            <button
              type="button"
              disabled={busy}
              onClick={() => void enroll()}
              className="flex items-center justify-center gap-1.5 rounded-lg bg-cyan-600 px-3 py-2 text-xs font-bold text-white hover:bg-cyan-500 disabled:opacity-50"
            >
              <Plus className="h-3.5 w-3.5" /> {busy ? 'Toca tu llave…' : 'Registrar USB como mi ID'}
            </button>
          </div>

          {message && (
            <p
              role="status"
              className={`rounded-lg border p-2 text-[11px] ${message.kind === 'ok' ? STATUS_STYLE.ACTIVE : STATUS_STYLE.REVOKED}`}
            >
              {message.text}
            </p>
          )}

          <ul className="space-y-2">
            {devices.length === 0 && (
              <li className="text-[11px] text-white/40">Aún no tienes llaves registradas.</li>
            )}
            {devices.map((d) => (
              <li key={d.deviceId} className="rounded-lg border border-white/10 bg-black/30 p-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex min-w-0 items-center gap-2">
                    {d.status === 'ACTIVE' ? (
                      <ShieldCheck className="h-4 w-4 shrink-0 text-emerald-300" />
                    ) : d.status === 'SUSPENDED' ? (
                      <ShieldAlert className="h-4 w-4 shrink-0 text-amber-300" />
                    ) : (
                      <KeyRound className="h-4 w-4 shrink-0 text-white/40" />
                    )}
                    <div className="min-w-0">
                      <div className="truncate text-xs font-bold text-white">{d.label}</div>
                      <div className="truncate font-mono text-[10px] text-white/45">{d.deviceId}</div>
                    </div>
                  </div>
                  <span className={`rounded-full border px-2 py-0.5 text-[10px] ${STATUS_STYLE[d.status]}`}>
                    {STATUS_LABEL[d.status]}
                  </span>
                </div>
                <div className="mt-1 text-[10px] text-white/40">
                  Alta {fmt(d.createdAt)} · Último uso {fmt(d.lastUsedAt)}
                </div>
                {(d.status === 'ACTIVE' || d.status === 'SUSPENDED') && (
                  <div className="mt-2 flex flex-wrap gap-2">
                    {d.status === 'ACTIVE' ? (
                      <button type="button" disabled={busy} onClick={() => change(d, 'suspend')} className="rounded border border-white/15 px-2 py-1 text-[10px] text-white/70 hover:bg-white/5">
                        Suspender
                      </button>
                    ) : (
                      <button type="button" disabled={busy} onClick={() => change(d, 'reactivate')} className="rounded border border-white/15 px-2 py-1 text-[10px] text-white/70 hover:bg-white/5">
                        Reactivar
                      </button>
                    )}
                    <button type="button" disabled={busy} onClick={() => void enroll(d.deviceId)} className="flex items-center gap-1 rounded border border-white/15 px-2 py-1 text-[10px] text-white/70 hover:bg-white/5">
                      <RefreshCw className="h-3 w-3" /> Reemplazar por otra llave
                    </button>
                    <button type="button" disabled={busy} onClick={() => change(d, 'revoke')} className="flex items-center gap-1 rounded border border-rose-500/30 px-2 py-1 text-[10px] text-rose-200 hover:bg-rose-500/10">
                      <Trash2 className="h-3 w-3" /> Revocar
                    </button>
                  </div>
                )}
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}
