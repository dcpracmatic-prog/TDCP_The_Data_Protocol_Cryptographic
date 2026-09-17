import { useEffect, useRef, useState } from 'react';
import {
  Unlock,
  ShieldAlert,
  Download,
  KeyRound,
  EyeOff,
  Zap,
  FileText,
  Image as ImageIcon,
  Music,
  Video,
  Info,
  Archive,
  CheckCircle,
  ShieldCheck,
  HardDrive,
  FolderOpen,
  Shield,
  Fingerprint,
  Cpu,
  CreditCard,
} from 'lucide-react';
import { useGoogleAuth } from '../lib/googleDriveContext.tsx';
import DriveFolderBrowser from './DriveFolderBrowser.tsx';
import CollapsibleSection from './CollapsibleSection.tsx';
import { tdcpRuntime } from '../runtime/tdcp-runtime.ts';
import type { TDCPPackage } from '../core/package/package-format.ts';
import type { TDCPRequestedOperation } from '../core/authorization/types.ts';
import type { ForensicWatermarkData } from '../protection/watermark.ts';
import type { ControlledRuntimeSession } from '../protection/apoptosis.ts';

type ViewerType = 'image' | 'video' | 'audio' | 'pdf' | 'text' | 'download' | 'error';

export default function DecryptPanel() {
  const { isSignedIn, openFilePicker } = useGoogleAuth();
  const [file, setFile] = useState<File | null>(null);
  const [pkg, setPkg] = useState<TDCPPackage | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);
  const [password, setPassword] = useState('');
  const [operation, setOperation] = useState<TDCPRequestedOperation>('RENDER_RAM');
  const [logs, setLogs] = useState('>_ ESPERANDO PAQUETE TDCP. No hay ruta password → AES.');
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [showDriveBrowser, setShowDriveBrowser] = useState(false);
  const [isWindowBlurred, setIsWindowBlurred] = useState(false);
  const [credentialReady, setCredentialReady] = useState(false);
  const [deviceReady, setDeviceReady] = useState(false);
  const [result, setResult] = useState<{
    type: ViewerType;
    content?: string;
    manifesto?: TDCPPackage['metadata'];
    watermark?: ForensicWatermarkData;
    grantId?: string;
  } | null>(null);

  const currentObjectUrlRef = useRef<string | null>(null);
  const sessionRef = useRef<ControlledRuntimeSession | null>(null);

  useEffect(() => {
    const handleBlur = () => {
      if (result && result.type !== 'error') setIsWindowBlurred(true);
    };
    const handleFocus = () => setIsWindowBlurred(false);
    window.addEventListener('blur', handleBlur);
    window.addEventListener('focus', handleFocus);
    return () => {
      window.removeEventListener('blur', handleBlur);
      window.removeEventListener('focus', handleFocus);
    };
  }, [result]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && (e.key === 'p' || e.key === 's')) e.preventDefault();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const loadPackage = async (incoming: File) => {
    setFile(incoming);
    setPkg(null);
    setParseError(null);
    setResult(null);
    const raw = await incoming.arrayBuffer();
    const parsed = await tdcpRuntime.parsePackage(raw);
    if (!parsed.isValidEnvelope || !parsed.package) {
      setParseError(parsed.error || 'No es un TDCPPackage.');
      setLogs(`Paquete rechazado: ${parsed.error}`);
      return;
    }
    setPkg(parsed.package);
    setLogs(
      `TDCPPackage válido.\nDOC=${parsed.package.documentId}\nPKG=${parsed.package.packageId}\nPOL=${parsed.package.metadata.policyLevel}\nEl archivo no autoriza. Siga: operación → credencial → dispositivo → Gatekeeper.`
    );
  };

  const tapCredential = async () => {
    try {
      const cred = await tdcpRuntime.nfcProvider.readCredential();
      setCredentialReady(true);
      setLogs((prev) => prev + `\n[NFC] ${tdcpRuntime.nfcProvider.providerName}\n     credentialId=${cred.credentialId} (${cred.isSimulated ? 'DEMO' : 'HW'})`);
    } catch (err: unknown) {
      setLogs((prev) => prev + `\n[NFC FAIL] ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const bindDevice = async () => {
    try {
      const device = await tdcpRuntime.deviceProvider.getDeviceIdentity();
      setDeviceReady(true);
      setLogs(
        (prev) =>
          prev +
          `\n[DEVICE] ${tdcpRuntime.deviceProvider.providerName}\n     deviceId=${device.deviceId} hardware=${device.hardwareBacked}`
      );
    } catch (err: unknown) {
      setLogs((prev) => prev + `\n[DEVICE FAIL] ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const processUnlock = async () => {
    if (!pkg) {
      setLogs('Error: seleccione un TDCPPackage.');
      return;
    }
    if (!credentialReady || !deviceReady) {
      setLogs('Error: credencial y dispositivo deben obtenerse ANTES del Gatekeeper. No hay bypass.');
      return;
    }

    setIsUnlocking(true);
    if (currentObjectUrlRef.current) {
      URL.revokeObjectURL(currentObjectUrlRef.current);
      currentObjectUrlRef.current = null;
    }
    sessionRef.current?.terminate('NEW_UNLOCK');
    setResult(null);
    setLogs((prev) => prev + '\n[GATEKEEPER] DCPGatekeeper.executeUnlock() — único camino de descifrado.');

    try {
      const unlock = await tdcpRuntime.unlock({
        pkg,
        password,
        requestedOperation: operation,
      });

      if (!unlock.success || !unlock.plaintextBuffer) {
        setLogs(
          (prev) =>
            prev +
            `\n[DENIED] ${unlock.errorCode || 'AUTHORIZATION_DENIED'}\n${unlock.errorMessage || 'Sin grant.'}`
        );
        return;
      }

      sessionRef.current = unlock.session ?? null;
      const manifesto = pkg.metadata;
      const fileBinary = unlock.plaintextBuffer;
      const fileBlob = new Blob([fileBinary], { type: manifesto.mimeType });
      const objectUrl = URL.createObjectURL(fileBlob);
      currentObjectUrlRef.current = objectUrl;
      sessionRef.current?.registerObjectUrl(objectUrl);

      const fileType = manifesto.mimeType || '';
      const fileName = (manifesto.originalFileName || '').toLowerCase();
      let type: ViewerType = 'error';
      let content: string | undefined = objectUrl;

      if (fileType.startsWith('image/') || /\.(jpg|jpeg|png|gif|webp|svg|bmp)$/i.test(fileName)) {
        type = 'image';
      } else if (fileType.startsWith('video/') || /\.(mp4|webm|ogv|mov)$/i.test(fileName)) {
        type = 'video';
      } else if (fileType.startsWith('audio/') || /\.(mp3|wav|ogg|m4a|aac|flac)$/i.test(fileName)) {
        type = 'audio';
      } else if (fileType === 'application/pdf' || fileName.endsWith('.pdf')) {
        type = 'pdf';
      } else if (
        fileType.startsWith('text/') ||
        fileType === 'application/json' ||
        /\.(txt|json|md|csv|xml|js|ts|html|css)$/i.test(fileName)
      ) {
        type = 'text';
        content = new TextDecoder().decode(fileBinary);
      } else if (unlock.grant?.allowExtraction || manifesto.allowExtraction) {
        type = 'download';
      } else {
        type = 'error';
        content = undefined;
      }

      if (operation !== 'EXTRACT' && type === 'download') {
        type = 'error';
        content = undefined;
      }

      setResult({
        type,
        content,
        manifesto,
        watermark: unlock.watermark,
        grantId: unlock.grant?.grantId,
      });
      setLogs(
        (prev) =>
          prev +
          `\n[GRANT] ${unlock.grant?.grantId} epoch=${unlock.grant?.authorizationEpoch}` +
          `\n[RUNTIME] ${fileBinary.byteLength} bytes en sesión controlada. Apoptosis al cerrar.`
      );
    } catch (err: unknown) {
      setLogs((prev) => prev + `\n[ERROR] ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsUnlocking(false);
    }
  };

  const closeViewer = () => {
    sessionRef.current?.terminate('USER_CLOSED_VIEWER');
    sessionRef.current = null;
    if (currentObjectUrlRef.current) {
      URL.revokeObjectURL(currentObjectUrlRef.current);
      currentObjectUrlRef.current = null;
    }
    setResult(null);
    setFile(null);
    setPkg(null);
    setPassword('');
    setCredentialReady(false);
    setDeviceReady(false);
    setIsWindowBlurred(false);
    setLogs('>_ VISOR CERRADO. Sesión terminada (apoptosis).');
  };

  return (
    <div className="flex h-full min-h-0 select-none flex-col gap-6" onContextMenu={(e) => e.preventDefault()}>
      <div className="glass-panel relative flex flex-1 flex-col overflow-y-auto p-6">
        <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <h2 className="flex items-center gap-2 text-xl font-bold text-indigo-400">
            <Unlock className="h-5 w-5" /> TDCP · Gatekeeper
          </h2>
          <div className="flex w-fit items-center gap-2 rounded-full border border-indigo-500/30 bg-indigo-500/10 px-3 py-1 text-[11px] text-indigo-300">
            <ShieldCheck className="h-3.5 w-3.5" /> Sin bypass de contraseña
          </div>
        </div>

        {!result ? (
          <div className="mx-auto mt-2 grid w-full max-w-6xl grid-cols-1 gap-4 md:grid-cols-2 md:items-start">
            <div className="flex flex-col gap-4">
            <CollapsibleSection
              title="1. Apertura"
              subtitle="Paquete · operación · factores · unlock"
              accent="indigo"
              defaultOpen
            >
              <div className="space-y-5">
                <div>
                  <div className="mb-2 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                    <label className="text-xs font-bold text-white/50 uppercase">TDCPPackage (.pkg)</label>
                    {isSignedIn && (
                      <div className="flex flex-wrap items-center gap-2">
                        <button
                          type="button"
                          onClick={() => {
                            openFilePicker((fileBlob, fileName) => {
                              void loadPackage(new File([fileBlob], fileName, { type: 'application/octet-stream' }));
                            });
                          }}
                          className="flex cursor-pointer items-center gap-1 rounded border border-indigo-500/40 bg-indigo-500/20 px-2.5 py-1 text-[11px] text-indigo-300"
                        >
                          <HardDrive className="h-3 w-3" /> Drive
                        </button>
                        <button
                          type="button"
                          onClick={() => setShowDriveBrowser(!showDriveBrowser)}
                          className="flex cursor-pointer items-center gap-1 rounded border border-emerald-500/40 bg-emerald-500/20 px-2.5 py-1 text-[11px] text-emerald-300"
                        >
                          <FolderOpen className="h-3 w-3" /> Carpeta
                        </button>
                      </div>
                    )}
                  </div>
                  {showDriveBrowser && (
                    <div className="mb-4">
                      <DriveFolderBrowser
                        onSelectDriveFileForDecrypt={(fileBlob, fileName) => {
                          void loadPackage(new File([fileBlob], fileName, { type: 'application/octet-stream' }));
                          setShowDriveBrowser(false);
                        }}
                      />
                    </div>
                  )}
                  <input
                    type="file"
                    accept=".pkg,application/octet-stream"
                    onChange={(e) => {
                      const f = e.target.files?.[0];
                      if (f) void loadPackage(f);
                    }}
                    className="w-full cursor-pointer text-sm file:mr-4 file:rounded-lg file:border-0 file:bg-indigo-500/20 file:px-4 file:py-2 file:text-sm file:font-semibold file:text-indigo-400"
                  />
                  {file && pkg && (
                    <div className="mt-2 break-all rounded border border-white/5 bg-black/30 p-2 font-mono text-xs text-indigo-300/80">
                      {file.name} · {pkg.metadata.policyLevel} · {pkg.documentId}
                    </div>
                  )}
                  {parseError && <p className="mt-2 text-xs text-rose-400">{parseError}</p>}
                </div>

                <div>
                  <label className="mb-2 block text-xs font-bold text-white/50 uppercase">Operación solicitada</label>
                  <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                    {(['READ', 'RENDER_RAM', 'EXTRACT', 'AUDIT_EXPORT'] as TDCPRequestedOperation[]).map((op) => (
                      <button
                        key={op}
                        type="button"
                        onClick={() => setOperation(op)}
                        className={`rounded-lg border px-2 py-2 text-[10px] font-bold ${
                          operation === op
                            ? 'border-indigo-500/60 bg-indigo-500/20 text-indigo-200'
                            : 'border-white/10 bg-black/30 text-white/50'
                        }`}
                      >
                        {op}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  <button
                    type="button"
                    onClick={tapCredential}
                    className={`flex items-center justify-center gap-2 rounded-lg border p-3 text-xs font-bold ${
                      credentialReady
                        ? 'border-emerald-500/50 bg-emerald-500/15 text-emerald-300'
                        : 'border-white/10 bg-white/5 text-white/70'
                    }`}
                  >
                    <CreditCard className="h-4 w-4" />
                    {credentialReady ? 'Credencial leída' : 'Leer credencial NFC'}
                  </button>
                  <button
                    type="button"
                    onClick={bindDevice}
                    className={`flex items-center justify-center gap-2 rounded-lg border p-3 text-xs font-bold ${
                      deviceReady
                        ? 'border-emerald-500/50 bg-emerald-500/15 text-emerald-300'
                        : 'border-white/10 bg-white/5 text-white/70'
                    }`}
                  >
                    <Cpu className="h-4 w-4" />
                    {deviceReady ? 'Dispositivo ligado' : 'Identidad de dispositivo'}
                  </button>
                </div>

                <div>
                  <label className="mb-2 flex items-center gap-2 text-xs font-bold text-white/50 uppercase">
                    <KeyRound className="h-4 w-4" /> Factor de contraseña (insuficiente sola)
                  </label>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Factor adicional — el Gatekeeper decide"
                    className="w-full rounded border border-white/10 bg-white/5 p-3 font-mono text-sm text-white outline-none focus:border-indigo-500/50"
                  />
                </div>

                {pkg && (pkg.metadata.policyLevel === 'CRITICAL' || pkg.metadata.policyLevel === 'ULTRA_CRITICAL') && (
                  <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-[11px] text-amber-200">
                    <Fingerprint className="mt-0.5 h-4 w-4 shrink-0" />
                    {pkg.metadata.policyLevel} exige biometría de presencia dentro del Gatekeeper
                    (MockBiometricProvider · DEVELOPMENT ONLY).
                  </div>
                )}

                <button
                  disabled={isUnlocking || !pkg}
                  onClick={processUnlock}
                  className="flex w-full cursor-pointer items-center justify-center gap-2 rounded-lg border border-indigo-500/50 bg-indigo-500/20 p-4 font-bold tracking-wider text-indigo-300 uppercase hover:bg-indigo-500/30 disabled:opacity-50"
                >
                  <Unlock className="h-5 w-5" />
                  {isUnlocking ? 'Oracle + Gatekeeper...' : 'Solicitar grant y abrir en runtime'}
                </button>
              </div>
            </CollapsibleSection>
            </div>

            <div className="flex flex-col gap-4">
            <CollapsibleSection
              title="Camino real"
              subtitle="Flujo de autorización · formatos"
              accent="cyan"
              defaultOpen={false}
            >
              <p className="text-xs leading-relaxed text-white/60">
                Paquete → operación → credencial → dispositivo → Oracle → grant firmado de un solo uso →
                Gatekeeper verifica → clave efímera → AES-GCM → runtime controlado → auditoría → apoptosis.
                No existe password → JavaScript local → AES → plaintext.
              </p>
              <div className="mt-3 grid grid-cols-1 gap-2 text-xs sm:grid-cols-2">
                <div className="flex items-center gap-2 rounded border border-white/5 bg-white/5 p-2 text-white/80">
                  <FileText className="h-4 w-4 text-indigo-400" /> Documentos
                </div>
                <div className="flex items-center gap-2 rounded border border-white/5 bg-white/5 p-2 text-white/80">
                  <ImageIcon className="h-4 w-4 text-emerald-400" /> Imágenes
                </div>
                <div className="flex items-center gap-2 rounded border border-white/5 bg-white/5 p-2 text-white/80">
                  <Music className="h-4 w-4 text-pink-400" /> Audio
                </div>
                <div className="flex items-center gap-2 rounded border border-white/5 bg-white/5 p-2 text-white/80">
                  <Video className="h-4 w-4 text-purple-400" /> Video
                </div>
              </div>
              <div className="mt-3 flex items-start gap-2 rounded bg-black/30 p-2.5 text-[11px] text-white/50">
                <Archive className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-400/80" />
                EXTRACT sólo si el Oracle emitió un grant con allowExtraction.
              </div>
            </CollapsibleSection>
            </div>
          </div>
        ) : (
          <div className="relative flex h-full flex-col overflow-hidden rounded-xl border border-indigo-500/30 bg-black/50">
            {isWindowBlurred && (
              <div className="absolute inset-0 z-50 flex flex-col items-center justify-center bg-black/90 p-6 text-center backdrop-blur-2xl">
                <ShieldCheck className="mb-3 h-16 w-16 animate-pulse text-indigo-400" />
                <h4 className="mb-1 text-lg font-bold text-white">Velo de visor</h4>
                <p className="max-w-sm text-xs text-white/60">La ventana perdió el foco. El plaintext no se pinta.</p>
              </div>
            )}
            <div className="z-30 flex items-center justify-between border-b border-indigo-500/30 bg-indigo-950/60 p-3">
              <div className="flex items-center gap-3">
                <ShieldAlert className="h-5 w-5 text-indigo-400" />
                <div>
                  <h3 className="flex items-center gap-2 text-sm font-bold text-white">
                    {result.manifesto?.originalFileName}
                    <span className="rounded border border-emerald-500/40 bg-emerald-500/20 px-1.5 py-0.5 font-mono text-[10px] text-emerald-300">
                      GRANT {result.grantId?.slice(0, 14)}
                    </span>
                  </h3>
                  <div className="mt-1 flex flex-wrap gap-2">
                    {result.watermark && (
                      <span className="flex items-center gap-1 rounded border border-emerald-500/50 bg-emerald-500/25 px-2 py-0.5 text-[9px] font-bold text-emerald-300 uppercase">
                        <Shield className="h-3 w-3" /> {result.watermark.displayText.slice(0, 48)}…
                      </span>
                    )}
                    {result.manifesto?.viewOnce && (
                      <span className="flex items-center gap-1 rounded border border-red-500/30 bg-red-500/20 px-1.5 py-0.5 text-[9px] font-bold text-red-300 uppercase">
                        <Zap className="h-3 w-3" /> Vista única consumida en Oracle
                      </span>
                    )}
                    {result.manifesto?.blurMode && (
                      <span className="flex items-center gap-1 rounded border border-indigo-500/30 bg-indigo-500/20 px-1.5 py-0.5 text-[9px] font-bold text-indigo-300 uppercase">
                        <EyeOff className="h-3 w-3" /> Anti-fisgones
                      </span>
                    )}
                  </div>
                </div>
              </div>
              <div className="flex gap-2">
                {operation === 'EXTRACT' && result.type === 'download' && result.content && (
                  <a
                    href={result.content}
                    download={result.manifesto?.originalFileName}
                    className="flex items-center gap-2 rounded border border-emerald-500/50 bg-emerald-500/20 px-3 py-1.5 text-xs font-bold text-emerald-400"
                  >
                    <Download className="h-4 w-4" /> Extraer
                  </a>
                )}
                <button
                  onClick={closeViewer}
                  className="cursor-pointer rounded border border-red-500/50 bg-red-500/20 px-4 py-1.5 text-xs font-bold text-red-400 uppercase"
                >
                  Apoptosis y cerrar
                </button>
              </div>
            </div>

            <div className="relative flex flex-1 items-center justify-center overflow-auto p-4">
              <div
                className={`relative flex h-full w-full items-center justify-center transition-all duration-300 ${
                  result.manifesto?.blurMode ? 'opacity-30 blur-xl hover:opacity-100 hover:blur-none' : ''
                }`}
              >
                {result.type === 'image' && (
                  <img src={result.content} className="pointer-events-none relative z-10 max-h-full max-w-full rounded object-contain" alt="" draggable={false} />
                )}
                {result.type === 'video' && (
                  <video src={result.content} controls controlsList="nodownload noplaybackrate" className="relative z-10 max-h-full max-w-full rounded bg-black" />
                )}
                {result.type === 'audio' && (
                  <div className="w-full max-w-md rounded-xl border border-white/10 bg-white/5 p-8 text-center">
                    <audio src={result.content} controls controlsList="nodownload" className="w-full" />
                  </div>
                )}
                {result.type === 'text' && (
                  <div className="relative z-10 h-full w-full overflow-y-auto rounded-lg border border-white/10 bg-white/5 p-6 text-left">
                    <pre className="font-mono text-sm whitespace-pre-wrap text-white/80">{result.content}</pre>
                  </div>
                )}
                {result.type === 'pdf' && (
                  <iframe src={`${result.content}#toolbar=0`} className="relative z-10 h-full w-full rounded border-none bg-white" title="PDF" />
                )}
                {result.type === 'download' && (
                  <div className="relative z-10 rounded-xl border border-white/10 bg-white/5 p-8 text-center">
                    <h3 className="mb-2 text-xl font-bold">Grant EXTRACT emitido</h3>
                    <a
                      href={result.content}
                      download={result.manifesto?.originalFileName}
                      className="inline-block rounded-lg border border-emerald-500/50 bg-emerald-500/20 px-6 py-3 font-bold text-emerald-400 uppercase"
                    >
                      Extraer archivo
                    </a>
                  </div>
                )}
                {result.type === 'error' && (
                  <div className="relative z-10 rounded-xl border border-pink-500/30 bg-pink-500/10 p-8 text-center text-pink-400">
                    <ShieldAlert className="mx-auto mb-4 h-16 w-16" />
                    <h3 className="mb-2 text-xl font-bold">EXTRACCIÓN DENEGADA</h3>
                    <p className="mx-auto max-w-md text-sm opacity-80">
                      El grant no autoriza EXTRACT o el formato no es renderizable en RAM.
                    </p>
                  </div>
                )}
              </div>

              {result.watermark && result.type !== 'error' && (
                <div className="pointer-events-none absolute inset-0 z-30 flex -rotate-12 flex-wrap content-center justify-center gap-x-10 gap-y-12 overflow-hidden p-4 select-none">
                  {Array.from({ length: 24 }).map((_, i) => (
                    <div key={i} className="flex flex-col items-center p-2 text-center font-mono">
                      <span className="text-[10px] font-extrabold tracking-widest text-emerald-400 uppercase">
                        TDCP FORENSIC
                      </span>
                      <span className="text-[11px] font-bold text-emerald-300">{result.watermark?.deviceId}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      <div className="glass-card mx-auto h-28 w-full max-w-6xl overflow-y-auto border-l-2 border-l-indigo-500 bg-black/40 p-4 font-mono text-[11px] whitespace-pre-wrap text-white/60">
        {logs}
      </div>
    </div>
  );
}
