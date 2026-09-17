import { useEffect, useRef, useState } from 'react';
import {
  Lock,
  Unlock,
  Activity,
  ShieldCheck,
  LogOut,
  Copy,
  Check,
  Fingerprint,
  FlaskConical,
  Menu,
  X,
} from 'lucide-react';
import EncryptPanel from './components/EncryptPanel.tsx';
import DecryptPanel from './components/DecryptPanel.tsx';
import MonitorPanel from './components/MonitorPanel.tsx';
import ValidationPanel from './components/ValidationPanel.tsx';
import GoogleDriveBar from './components/GoogleDriveBar.tsx';
import AuthScreen from './components/AuthScreen.tsx';
import AuthorityStatusBar, { AuthorityStatusChip } from './components/AuthorityStatusBar.tsx';
import CollapsibleSection from './components/CollapsibleSection.tsx';
import { GoogleAuthProvider } from './lib/googleDriveContext.tsx';
import { AuthProvider, useAuth } from './lib/authContext.tsx';
import { tdcpRuntime } from './runtime/tdcp-runtime.ts';

function DcpCrystalIcon({ className = 'w-10 h-10' }: { className?: string }) {
  return (
    <div className={`relative flex items-center justify-center ${className} drop-shadow-[0_0_15px_rgba(168,85,247,0.5)]`}>
      <svg viewBox="0 0 100 100" className="h-full w-full fill-none">
        <defs>
          <linearGradient id="crystalGrad1" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#c084fc" />
            <stop offset="50%" stopColor="#818cf8" />
            <stop offset="100%" stopColor="#3b82f6" />
          </linearGradient>
          <linearGradient id="crystalGrad2" x1="100%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#e879f9" />
            <stop offset="100%" stopColor="#6366f1" />
          </linearGradient>
          <radialGradient id="centerGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#ffffff" stopOpacity="0.9" />
            <stop offset="40%" stopColor="#c084fc" stopOpacity="0.6" />
            <stop offset="100%" stopColor="#4f46e5" stopOpacity="0" />
          </radialGradient>
        </defs>
        <polygon points="50,4 92,26 92,74 50,96 8,74 8,26" fill="url(#crystalGrad1)" fillOpacity="0.25" stroke="#a855f7" strokeWidth="2" />
        <polygon points="50,4 92,26 70,50 50,30" fill="url(#crystalGrad2)" fillOpacity="0.6" />
        <polygon points="92,26 92,74 70,50" fill="url(#crystalGrad1)" fillOpacity="0.75" />
        <polygon points="92,74 50,96 50,70 70,50" fill="url(#crystalGrad2)" fillOpacity="0.6" />
        <polygon points="50,96 8,74 30,50 50,70" fill="url(#crystalGrad1)" fillOpacity="0.7" />
        <polygon points="8,74 8,26 30,50" fill="url(#crystalGrad2)" fillOpacity="0.75" />
        <polygon points="8,26 50,4 50,30 30,50" fill="url(#crystalGrad1)" fillOpacity="0.6" />
        <polygon points="50,22 76,36 76,64 50,78 24,64 24,36" fill="#1e1b4b" fillOpacity="0.85" stroke="#c084fc" strokeWidth="1.5" />
        <circle cx="50" cy="50" r="18" fill="url(#centerGlow)" />
      </svg>
    </div>
  );
}

type Tab = 'Decrypt' | 'Encrypt' | 'Monitor' | 'Validate';

const NAV_ITEMS: Array<{
  name: Tab;
  label: string;
  desc: string;
  icon: typeof Unlock;
}> = [
  { name: 'Decrypt', label: 'Gatekeeper', desc: 'Único camino de apertura', icon: Unlock },
  { name: 'Encrypt', label: 'Crear paquete', desc: 'TDCPPackage + Oracle', icon: Lock },
  { name: 'Monitor', label: 'Auditoría', desc: 'Tamper-evident local', icon: Activity },
  { name: 'Validate', label: 'Validación', desc: 'Pruebas reales', icon: FlaskConical },
];

function MainDCPApp() {
  const { currentUser, isLoading, logout } = useAuth();
  const [activeTab, setActiveTab] = useState<Tab>('Decrypt');
  const [copiedId, setCopiedId] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const providers = tdcpRuntime.getProviderStatus();

  useEffect(() => {
    if (!menuOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMenuOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [menuOpen]);

  if (isLoading) {
    return (
      <div className="relative flex min-h-dvh w-full flex-col items-center justify-center bg-slate-950 text-white">
        <div className="mesh-bg" />
        <DcpCrystalIcon className="mb-4 h-16 w-16 animate-pulse" />
        <p className="font-mono text-xs tracking-widest text-white/50 uppercase">Iniciando TDCP Gatekeeper...</p>
      </div>
    );
  }

  if (!currentUser) {
    return <AuthScreen />;
  }

  const handleCopyUserId = () => {
    void navigator.clipboard.writeText(currentUser.id);
    setCopiedId(true);
    setTimeout(() => setCopiedId(false), 2000);
  };

  const selectTab = (tab: Tab) => {
    setActiveTab(tab);
    setMenuOpen(false);
  };

  const activeLabel = NAV_ITEMS.find((i) => i.name === activeTab)?.label ?? activeTab;

  return (
    <>
      <div className="mesh-bg" />
      <div className="flex h-dvh w-full flex-col overflow-hidden text-white">
        {/* Compact top bar — logo + Authority chip + Menu */}
        <header className="glass-panel relative z-40 mx-3 mt-3 flex shrink-0 items-center justify-between gap-3 rounded-2xl px-3 py-2.5 md:mx-6 md:mt-4 md:px-4">
          <div className="flex min-w-0 items-center gap-2.5 md:gap-3.5">
            <DcpCrystalIcon className="h-9 w-9 shrink-0 md:h-10 md:w-10" />
            <div className="flex min-w-0 flex-col">
              <span className="bg-gradient-to-r from-pink-300 via-purple-300 to-indigo-300 bg-clip-text text-sm font-black tracking-wider text-transparent md:text-base">
                TDCP SECURE
              </span>
              <span className="truncate font-mono text-[9px] tracking-widest text-white/50 uppercase">
                {activeLabel} · Package ≠ authorization
              </span>
            </div>
          </div>

          <div className="flex shrink-0 items-center gap-2 md:gap-3">
            <AuthorityStatusChip className="hidden sm:inline-flex" />
            <button
              type="button"
              onClick={() => setMenuOpen((o) => !o)}
              aria-expanded={menuOpen}
              aria-controls="tdcp-nav-drawer"
              className="flex cursor-pointer items-center gap-2 rounded-xl border border-white/15 bg-white/5 px-3 py-2 text-xs font-bold tracking-wider text-white uppercase hover:bg-white/10"
            >
              {menuOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
              <span className="hidden sm:inline">Menú</span>
            </button>
          </div>
        </header>

        {/* Slide-over drawer */}
        {menuOpen && (
          <div className="fixed inset-0 z-50 flex justify-end">
            <button
              type="button"
              aria-label="Cerrar menú"
              className="absolute inset-0 bg-black/60 backdrop-blur-sm"
              onClick={() => setMenuOpen(false)}
            />
            <aside
              id="tdcp-nav-drawer"
              ref={menuRef}
              className="glass-panel relative z-10 flex h-full w-full max-w-sm flex-col justify-between overflow-y-auto border-l border-white/10 p-5 shadow-2xl"
              role="dialog"
              aria-modal="true"
              aria-label="Menú de navegación TDCP"
            >
              <div>
                <div className="mb-4 flex items-center justify-between border-b border-white/10 pb-3">
                  <div className="flex items-center gap-3">
                    <DcpCrystalIcon className="h-9 w-9 shrink-0" />
                    <div className="flex flex-col">
                      <span className="text-sm font-black tracking-wider text-white">Menú</span>
                      <span className="font-mono text-[9px] text-white/40 uppercase">Navegación</span>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => setMenuOpen(false)}
                    className="cursor-pointer rounded-lg p-2 text-white/50 hover:bg-white/10 hover:text-white"
                    aria-label="Cerrar"
                  >
                    <X className="h-4 w-4" />
                  </button>
                </div>

                <div className="mb-4 space-y-2 rounded-xl border border-purple-500/30 bg-black/40 p-3">
                  <div className="flex items-center justify-between">
                    <div className="flex min-w-0 items-center gap-2">
                      <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-purple-500/40 bg-purple-500/20 text-xs font-bold text-purple-300">
                        {currentUser.name.charAt(0).toUpperCase()}
                      </div>
                      <div className="min-w-0">
                        <div className="truncate text-xs font-bold text-white">{currentUser.name}</div>
                        <div className="truncate text-[10px] text-white/40">{currentUser.email}</div>
                      </div>
                    </div>
                    <button
                      onClick={logout}
                      title="Cerrar sesión / salir demo"
                      className="shrink-0 cursor-pointer rounded-lg p-1.5 text-white/40 hover:bg-white/10 hover:text-red-400"
                    >
                      <LogOut className="h-3.5 w-3.5" />
                    </button>
                  </div>
                  <div className="flex items-center justify-between border-t border-white/5 pt-1.5 text-[10px]">
                    <div className="flex min-w-0 items-center gap-1 truncate font-mono font-bold text-purple-300">
                      <Fingerprint className="h-3 w-3 shrink-0 text-purple-400" />
                      <span className="truncate">{currentUser.id}</span>
                    </div>
                    <button
                      onClick={handleCopyUserId}
                      className="flex cursor-pointer items-center gap-1 rounded bg-white/5 px-1.5 py-0.5 text-[9px] text-white/60 hover:bg-white/10"
                    >
                      {copiedId ? <Check className="h-2.5 w-2.5 text-emerald-400" /> : <Copy className="h-2.5 w-2.5" />}
                      {copiedId ? 'Copiado' : 'Copiar'}
                    </button>
                  </div>
                </div>

                <nav className="space-y-2">
                  {NAV_ITEMS.map((item) => {
                    const isActive = activeTab === item.name;
                    return (
                      <button
                        key={item.name}
                        type="button"
                        onClick={() => selectTab(item.name)}
                        className={`flex w-full cursor-pointer items-center gap-3.5 rounded-xl px-4 py-3 text-left transition-all ${
                          isActive
                            ? 'active-pill font-semibold text-pink-200 shadow-[0_0_20px_rgba(236,72,153,0.25)]'
                            : 'text-white/80 opacity-70 hover:bg-white/5 hover:opacity-100'
                        }`}
                      >
                        <div
                          className={`rounded-lg p-2 ${isActive ? 'bg-pink-500/20 text-pink-400' : 'bg-white/5 text-white/60'}`}
                        >
                          <item.icon className="h-4 w-4" />
                        </div>
                        <div className="flex flex-col">
                          <span className="text-xs font-bold tracking-wide uppercase">{item.label}</span>
                          <span className="text-[10px] font-normal text-white/40 normal-case">{item.desc}</span>
                        </div>
                      </button>
                    );
                  })}
                </nav>
              </div>

              <div className="mt-6 space-y-3">
                <div className="sm:hidden">
                  <AuthorityStatusChip />
                </div>
                <div className="glass-card border border-white/10 bg-black/40 p-4">
                  <div className="mb-2 flex items-center justify-between text-[10px] font-bold tracking-wider text-white/50 uppercase">
                    <span className="flex items-center gap-1.5 text-emerald-400">
                      <ShieldCheck className="h-3.5 w-3.5" /> Gatekeeper
                    </span>
                    <span className="font-mono text-white/40">v2.5 SEC</span>
                  </div>
                  <div className="mb-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-2 py-1.5 text-[9px] font-bold leading-snug tracking-wide text-amber-100 uppercase">
                    {providers.authorityKind === 'HTTP_REMOTE'
                      ? 'MVP — remote Authority (not HSM)'
                      : providers.modeBadge || 'MVP / Demo — Oracle in-browser'}
                  </div>
                  <div className="space-y-1.5 text-[11px] text-white/60">
                    <div className="flex items-center justify-between">
                      <span>Control plane</span>
                      <span className="font-mono font-bold text-amber-300">
                        {providers.authorityKind === 'HTTP_REMOTE' ? 'REMOTE' : 'IN-PROCESS'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>Oracle keys</span>
                      <span className="font-mono font-bold text-amber-300">DEV ONLY</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>NFC / Device / Bio</span>
                      <span className="font-mono font-bold text-amber-300">MOCK</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>Audit</span>
                      <span className="font-mono font-bold text-emerald-400">tamper-evident</span>
                    </div>
                  </div>
                  <div className="mt-3 flex items-center gap-2 border-t border-white/10 pt-2">
                    <div className="h-2 w-2 animate-pulse rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
                    <span className="text-[10px] font-medium text-emerald-300/90">{providers.oracleKeyStore}</span>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={logout}
                  className="flex w-full cursor-pointer items-center justify-center gap-2 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-2.5 text-xs font-bold tracking-wider text-red-300 uppercase hover:bg-red-500/20"
                >
                  <LogOut className="h-3.5 w-3.5" /> Cerrar sesión / salir demo
                </button>
                <p className="text-center text-[10px] tracking-tight text-white/30">
                  The Data Cryptographic Protocol © 2026
                </p>
              </div>
            </aside>
          </div>
        )}

        {/* Full-width main content */}
        <div className="mx-3 mt-3 mb-3 flex min-h-0 flex-1 flex-col overflow-hidden md:mx-6 md:mb-4 md:mt-4">
          <main className="flex min-h-0 flex-1 flex-col overflow-hidden">
            <AuthorityStatusBar />
            <div className="mb-3 shrink-0">
              <CollapsibleSection
                title="Almacenamiento"
                subtitle="Google Drive · carpetas compartidas"
                accent="indigo"
                defaultOpen={false}
              >
                <GoogleDriveBar />
              </CollapsibleSection>
            </div>
            <div className="min-h-0 flex-1 overflow-x-hidden overflow-y-auto">
              <div className="mx-auto w-full max-w-6xl pb-4">
                {activeTab === 'Decrypt' && <DecryptPanel />}
                {activeTab === 'Encrypt' && <EncryptPanel />}
                {activeTab === 'Monitor' && <MonitorPanel />}
                {activeTab === 'Validate' && <ValidationPanel />}
              </div>
            </div>
          </main>
        </div>
      </div>
    </>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <GoogleAuthProvider>
        <MainDCPApp />
      </GoogleAuthProvider>
    </AuthProvider>
  );
}
