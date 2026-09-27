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
import {
  readSmartTokenApiConfig,
  allowSoftSmartToken,
  softSmartTokenOpen,
  type SoftSmartTokenArtifact,
} from '../protection/smart-token-local.ts';
import { SmartTokenClient } from '../../sdk/typescript/src/smart-token-client.ts';
import {
  verifyCsgSeal,
  type CsgSealDocument,
} from '../protection/csg-seal.ts';

type ViewerType = 'image' | 'video' | 'audio' | 'pdf' | 'text' | 'download' | 'error';

/** Independent Smart Token mode (does not go through Gatekeeper). */
type StpRemoteRef = {
  schema: 'tdcp.stp-remote-ref.v1';
  artifact_id: string;
  filename?: string;
  status?: string;
  developmentOnly?: boolean;
};

type ArtifactKind = 'tdcp' | 'smart_token';

export default function DecryptPanel() {
  const { isSignedIn, openFilePicker } = useGoogleAuth();
  const [file, setFile] = useState<File | null>(null);
  const [pkg, setPkg] = useState<TDCPPackage | null>(null);
  const [stpRef, setStpRef] = useState<StpRemoteRef | null>(null);
  const [softStok, setSoftStok] = useState<SoftSmartTokenArtifact | null>(null);
  const [artifactKind, setArtifactKind] = useState<ArtifactKind | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);
  const [password, setPassword] = useState('');
  const [operation, setOperation] = useState<TDCPRequestedOperation>('RENDER_RAM');
  const [logs, setLogs] = useState(
    '>_ ESPERANDO artefacto. TDCP .pkg → Gatekeeper obligatorio. Smart Token .stok.json → modo independiente.'
  );
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [showDriveBrowser, setShowDriveBrowser] = useState(false);
  const [isWindowBlurred, setIsWindowBlurred] = useState(false);
  const [credentialReady, setCredentialReady] = useState(false);
  const [deviceReady, setDeviceReady] = useState(false);
  const [csgSealFile, setCsgSealFile] = useState<CsgSealDocument | null>(null);
  const [result, setResult] = useState<{
    type: ViewerType;
    content?: string;
    manifesto?: TDCPPackage['metadata'];
    watermark?: ForensicWatermarkData;
    grantId?: string;
    csgValid?: boolean;
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
    setStpRef(null);
    setSoftStok(null);
    setArtifactKind(null);
    setParseError(null);
    setResult(null);
    setCredentialReady(false);
    setDeviceReady(false);
    const raw = await incoming.arrayBuffer();
    const name = (incoming.name || '').toLowerCase();

    // 1) Smart Token remote reference (.stok.json) — independent mode
    if (name.endsWith('.stok.json') || name.endsWith('.stok')) {
      try {
        const text = new TextDecoder().decode(raw);
        const json = JSON.parse(text) as Partial<StpRemoteRef>;
        if (json.schema === 'tdcp.stp-remote-ref.v1' && typeof json.artifact_id === 'string') {
          const ref: StpRemoteRef = {
            schema: 'tdcp.stp-remote-ref.v1',
            artifact_id: json.artifact_id,
            filename: json.filename,
            status: json.status,
            developmentOnly: json.developmentOnly,
          };
          setStpRef(ref);
          setArtifactKind('smart_token');
          setLogs(
            `Smart Token (modo independiente).\n` +
              `artifact_id=${ref.artifact_id}\n` +
              `filename=${ref.filename ?? '—'}\n` +
              `NO pasa por Gatekeeper. Master se envía solo a la API confiable configurada en la app (VITE_SMART_TOKEN_API_URL).\n` +
              `Cualquier URL embebida en el JSON se ignora.`
          );
          return;
        }
        if ((json as { schema?: string }).schema === 'tdcp.soft-stok.v1') {
          if (!allowSoftSmartToken()) {
            setParseError(
              'Soft Smart Token desactivado (VITE_TDCP_ALLOW_SOFT_STP=0). Use API Smart Token real.'
            );
            setLogs('Rechazado: soft Smart Token no permitido en esta build.');
            return;
          }
          const soft = json as SoftSmartTokenArtifact;
          setSoftStok(soft);
          setArtifactKind('smart_token');
          setLogs(
            `Soft Smart Token (demo AES-GCM).\nartifactId=${soft.artifactId}\n` +
              `NO usa Gatekeeper ni API remota. Solo para free/demo.`
          );
          return;
        }
      } catch {
        // fall through to TDCP parse
      }
    }

    // 2) TDCP package — Gatekeeper mandatory
    const parsed = await tdcpRuntime.parsePackage(raw);
    if (!parsed.isValidEnvelope || !parsed.package) {
      setParseError(parsed.error || 'No es un TDCPPackage ni un Smart Token .stok.json válido.');
      setLogs(`Artefacto rechazado: ${parsed.error || 'formato desconocido'}`);
      return;
    }
    setPkg(parsed.package);
    setArtifactKind('tdcp');
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
    // --- Smart Token independent path ---
    if (artifactKind === 'smart_token' && softStok) {
      if (!password || password.length < 8) {
        setLogs('Error: el master Soft Smart Token debe tener al menos 8 caracteres.');
        return;
      }
      setIsUnlocking(true);
      setResult(null);
      try {
        const plain = await softSmartTokenOpen(softStok, password);
        let csgValid: boolean | undefined;
        if (csgSealFile) {
          const verify = await verifyCsgSeal(plain, csgSealFile);
          csgValid = verify.valid;
          setLogs((prev) => prev + `\n[CSG] ${verify.valid ? 'OK' : verify.reason}`);
        }
        const bytes = new Uint8Array(plain);
        let textGuess = '';
        try {
          textGuess = new TextDecoder().decode(bytes.slice(0, Math.min(bytes.length, 2000)));
        } catch {
          textGuess = '';
        }
        const isText = /^[\x09\x0a\x0d\x20-\x7e\u00a0-\uffff]*$/.test(textGuess.slice(0, 200));
        if (currentObjectUrlRef.current) {
          URL.revokeObjectURL(currentObjectUrlRef.current);
          currentObjectUrlRef.current = null;
        }
        if (isText) {
          setResult({ type: 'text', content: new TextDecoder().decode(plain), csgValid });
        } else {
          const url = URL.createObjectURL(new Blob([plain]));
          currentObjectUrlRef.current = url;
          setResult({ type: 'download', content: url, csgValid });
        }
        setLogs((prev) => prev + '\n[STP-SOFT] Abierto en memoria (demo).');
      } catch (err: unknown) {
        setLogs((prev) => prev + `\n[STP-SOFT FAIL] ${err instanceof Error ? err.message : String(err)}`);
        setResult({ type: 'error' });
      } finally {
        setIsUnlocking(false);
      }
      return;
    }

    if (artifactKind === 'smart_token' && stpRef) {
      if (!password || password.length < 8) {
        setLogs('Error: el master Smart Token debe tener al menos 8 caracteres.');
        return;
      }
      const api = readSmartTokenApiConfig();
      if (!api) {
        setLogs(
          'Error: no hay API Smart Token confiable configurada (VITE_SMART_TOKEN_API_URL). ' +
            'El master no se envía a ninguna URL embebida en el JSON.'
        );
        return;
      }

      setIsUnlocking(true);
      if (currentObjectUrlRef.current) {
        URL.revokeObjectURL(currentObjectUrlRef.current);
        currentObjectUrlRef.current = null;
      }
      setResult(null);
      setLogs(
        (prev) =>
          prev +
          `\n[STP] Abriendo artifact_id=${stpRef.artifact_id} en API confiable ${api.baseUrl} (modo independiente, sin Gatekeeper).`
      );

      try {
        const client = new SmartTokenClient({
          baseUrl: api.baseUrl,
          apiKey: api.apiKey,
          fetchImpl: globalThis.fetch.bind(globalThis),
        });
        const openResult = await client.open(stpRef.artifact_id, password);
        if (!openResult.ok || !openResult.plaintext) {
          setLogs(
            (prev) =>
              prev +
              `\n[STP DENIED] status=${openResult.status ?? '—'} ${typeof openResult.body === 'string' ? openResult.body : ''}`
          );
          return;
        }

        const fileBinary = openResult.plaintext;
        let csgValid: boolean | undefined;
        if (csgSealFile) {
          const verify = await verifyCsgSeal(new Uint8Array(fileBinary), csgSealFile);
          csgValid = verify.valid;
          setLogs(
            (prev) =>
              prev +
              `\n[CSG] Verificación del sello sobre bytes recuperados: ${verify.valid ? 'OK' : verify.reason}`
          );
        }

        const fileName = (stpRef.filename || 'artifact.bin').toLowerCase();
        const fileBlob = new Blob([fileBinary]);
        const objectUrl = URL.createObjectURL(fileBlob);
        currentObjectUrlRef.current = objectUrl;

        let type: ViewerType = 'download';
        let content: string | undefined = objectUrl;
        if (/\.(jpg|jpeg|png|gif|webp|svg|bmp)$/i.test(fileName)) type = 'image';
        else if (/\.(mp4|webm|ogv|mov)$/i.test(fileName)) type = 'video';
        else if (/\.(mp3|wav|ogg|m4a|aac|flac)$/i.test(fileName)) type = 'audio';
        else if (fileName.endsWith('.pdf')) type = 'pdf';
        else if (/\.(txt|json|md|csv|xml|js|ts|html|css)$/i.test(fileName)) {
          type = 'text';
          content = new TextDecoder().decode(fileBinary);
        }

        setResult({
          type,
          content,
          manifesto: {
            originalFileName: stpRef.filename || 'artifact.bin',
            mimeType: fileBlob.type || 'application/octet-stream',
          } as TDCPPackage['metadata'],
          csgValid,
        });
        setLogs(
          (prev) =>
            prev +
            `\n[STP OK] ${fileBinary.byteLength} bytes recuperados desde API confiable.` +
            (csgValid !== undefined ? `\n[CSG] sello=${csgValid ? 'válido' : 'inválido'}` : '')
        );
      } catch (err: unknown) {
        setLogs((prev) => prev + `\n[STP ERROR] ${err instanceof Error ? err.message : String(err)}`);
      } finally {
        setIsUnlocking(false);
      }
      return;
    }

    // --- TDCP Gatekeeper path (mandatory for .pkg) ---
    if (!pkg) {
      setLogs('Error: seleccione un TDCPPackage (.pkg) o un Smart Token (.stok.json).');
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
    setLogs((prev) => prev + '\n[GATEKEEPER] DCPGatekeeper.executeUnlock() — único camino de descifrado TDCP.');

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
    setStpRef(null);
    setSoftStok(null);
    setArtifactKind(null);
    setPassword('');
    setCredentialReady(false);
    setDeviceReady(false);
    setCsgSealFile(null);
    setIsWindowBlurred(false);
    setLogs(
      '>_ VISOR CERRADO. Sesión terminada (apoptosis). Esperando TDCP .pkg o Smart Token .stok.json.'
    );
  };

  return (
    <div className="flex h-full min-h-0 select-none flex-col gap-2" onContextMenu={(e) => e.preventDefault()}>
      <div className="glass-panel relative flex min-h-0 flex-1 flex-col overflow-y-auto p-3 md:p-4">
        <div className="mb-2 flex flex-col gap-1.5 sm:flex-row sm:items-center sm:justify-between">
          <h2 className="flex items-center gap-2 text-base font-bold text-indigo-400">
            <Unlock className="h-4 w-4" />
            {artifactKind === 'smart_token'
              ? 'Smart Token · modo independiente'
              : 'TDCP · Gatekeeper'}
          </h2>
          <div className="flex w-fit items-center gap-1.5 rounded-full border border-indigo-500/30 bg-indigo-500/10 px-2.5 py-0.5 text-[10px] text-indigo-300">
            <ShieldCheck className="h-3 w-3" />
            {artifactKind === 'smart_token'
              ? 'Master → API confiable'
              : 'Sin bypass de contraseña'}
          </div>
        </div>

        {!result ? (
          <div className="grid w-full grid-cols-1 gap-3 lg:grid-cols-2 lg:items-start">
            <div className="flex flex-col gap-3">
            <CollapsibleSection
              title="1. Apertura"
              subtitle="Paquete · operación · factores · unlock"
              accent="indigo"
              defaultOpen
            >
              <div className="space-y-3">
                <div>
                  <div className="mb-1.5 flex flex-col gap-1.5 sm:flex-row sm:items-center sm:justify-between">
                    <label className="text-[11px] font-bold text-white/50 uppercase">
                      Artefacto (.pkg TDCP · .stok.json Smart Token)
                    </label>
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
                    accept=".pkg,.stok.json,.stok,application/json,application/octet-stream"
                    onChange={(e) => {
                      const f = e.target.files?.[0];
                      if (f) void loadPackage(f);
                    }}
                    className="w-full cursor-pointer text-sm file:mr-4 file:rounded-lg file:border-0 file:bg-indigo-500/20 file:px-4 file:py-2 file:text-sm file:font-semibold file:text-indigo-400"
                  />
                  {file && pkg && (
                    <div className="mt-2 break-all rounded border border-white/5 bg-black/30 p-2 font-mono text-xs text-indigo-300/80">
                      {file.name} · TDCP · {pkg.metadata.policyLevel} · {pkg.documentId}
                    </div>
                  )}
                  {file && stpRef && (
                    <div className="mt-2 break-all rounded border border-cyan-500/20 bg-cyan-500/10 p-2 font-mono text-xs text-cyan-300/90">
                      {file.name} · Smart Token · {stpRef.artifact_id}
                    </div>
                  )}
                  {parseError && <p className="mt-2 text-xs text-rose-400">{parseError}</p>}

                  <div className="mt-3">
                    <label className="mb-1.5 block text-[11px] font-bold text-white/50 uppercase">
                      Sello CSG opcional (.csg.json / .csg-sello.json)
                    </label>
                    <input
                      type="file"
                      accept=".json,.csg.json,application/json"
                      onChange={async (e) => {
                        const f = e.target.files?.[0];
                        if (!f) {
                          setCsgSealFile(null);
                          return;
                        }
                        try {
                          const text = await f.text();
                          const json = JSON.parse(text) as CsgSealDocument;
                          setCsgSealFile(json);
                          setLogs(
                            (prev) =>
                              prev +
                              `\n[CSG] Sello cargado (${'evento_id' in json ? (json as { evento_id: string }).evento_id : (json as { sealId?: string }).sealId ?? 'ok'})`
                          );
                        } catch {
                          setCsgSealFile(null);
                          setLogs((prev) => prev + '\n[CSG] No se pudo leer el sello JSON.');
                        }
                      }}
                      className="w-full cursor-pointer text-sm file:mr-4 file:rounded-lg file:border-0 file:bg-cyan-500/20 file:px-4 file:py-2 file:text-sm file:font-semibold file:text-cyan-300"
                    />
                    {csgSealFile && (
                      <p className="mt-1 text-[10px] text-cyan-300/80">
                        Sello listo — se verificará contra los bytes recuperados al abrir.
                      </p>
                    )}
                  </div>
                </div>

                {artifactKind !== 'smart_token' && (
                  <>
                    <div>
                      <label className="mb-1.5 block text-[11px] font-bold text-white/50 uppercase">Operación solicitada</label>
                      <div className="grid grid-cols-2 gap-1.5">
                        {(['READ', 'RENDER_RAM', 'EXTRACT', 'AUDIT_EXPORT'] as TDCPRequestedOperation[]).map((op) => (
                          <button
                            key={op}
                            type="button"
                            onClick={() => setOperation(op)}
                            className={`rounded-lg border px-2 py-1.5 text-[10px] font-bold ${
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

                    <div className="grid grid-cols-2 gap-1.5">
                      <button
                        type="button"
                        onClick={tapCredential}
                        className={`flex items-center justify-center gap-1.5 rounded-lg border p-2 text-[11px] font-bold ${
                          credentialReady
                            ? 'border-emerald-500/50 bg-emerald-500/15 text-emerald-300'
                            : 'border-white/10 bg-white/5 text-white/70'
                        }`}
                      >
                        <CreditCard className="h-3.5 w-3.5" />
                        {credentialReady ? 'Credencial OK' : 'Credencial NFC'}
                      </button>
                      <button
                        type="button"
                        onClick={bindDevice}
                        className={`flex items-center justify-center gap-1.5 rounded-lg border p-2 text-[11px] font-bold ${
                          deviceReady
                            ? 'border-emerald-500/50 bg-emerald-500/15 text-emerald-300'
                            : 'border-white/10 bg-white/5 text-white/70'
                        }`}
                      >
                        <Cpu className="h-3.5 w-3.5" />
                        {deviceReady ? 'Dispositivo OK' : 'Dispositivo'}
                      </button>
                    </div>
                  </>
                )}

                <div>
                  <label className="mb-1.5 flex items-center gap-2 text-[11px] font-bold text-white/50 uppercase">
                    <KeyRound className="h-3.5 w-3.5" />
                    {artifactKind === 'smart_token'
                      ? 'Master Smart Token (request-scoped)'
                      : 'Factor de contraseña (insuficiente sola)'}
                  </label>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={
                      artifactKind === 'smart_token'
                        ? 'Master — solo a API confiable de la app'
                        : 'Factor adicional — el Gatekeeper decide'
                    }
                    className="w-full rounded border border-white/10 bg-white/5 p-2.5 font-mono text-sm text-white outline-none focus:border-indigo-500/50"
                  />
                </div>

                {artifactKind === 'smart_token' && (
                  <div className="flex items-start gap-2 rounded-lg border border-cyan-500/30 bg-cyan-500/10 p-3 text-[11px] text-cyan-200">
                    <Info className="mt-0.5 h-4 w-4 shrink-0" />
                    Modo Smart Token independiente: no usa Gatekeeper. El master se envía únicamente
                    a la URL configurada en la aplicación (VITE_SMART_TOKEN_API_URL). URLs embebidas
                    en el JSON se ignoran.
                  </div>
                )}

                {pkg && (pkg.metadata.policyLevel === 'CRITICAL' || pkg.metadata.policyLevel === 'ULTRA_CRITICAL') && (
                  <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-[11px] text-amber-200">
                    <Fingerprint className="mt-0.5 h-4 w-4 shrink-0" />
                    {pkg.metadata.policyLevel} exige biometría de presencia dentro del Gatekeeper
                    (MockBiometricProvider · DEVELOPMENT ONLY).
                  </div>
                )}

                <button
                  disabled={
                    isUnlocking ||
                    (artifactKind === 'smart_token' ? !stpRef : !pkg)
                  }
                  onClick={processUnlock}
                  className="flex w-full cursor-pointer items-center justify-center gap-2 rounded-lg border border-indigo-500/50 bg-indigo-500/20 p-3 text-sm font-bold tracking-wider text-indigo-300 uppercase hover:bg-indigo-500/30 disabled:opacity-50"
                >
                  <Unlock className="h-4 w-4" />
                  {isUnlocking
                    ? artifactKind === 'smart_token'
                      ? 'Abriendo Smart Token…'
                      : 'Oracle + Gatekeeper...'
                    : artifactKind === 'smart_token'
                      ? 'Abrir Smart Token (API confiable)'
                      : 'Solicitar grant y abrir en runtime'}
                </button>
              </div>
            </CollapsibleSection>
            </div>

            <div className="flex flex-col gap-3">
            <CollapsibleSection
              title="2. Resultado / estado"
              subtitle="Checklist de factores · paquete"
              accent="emerald"
              defaultOpen
            >
              <div className="grid grid-cols-2 gap-1.5 text-[11px]">
                <div className={`rounded-lg border p-2 ${pkg ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200' : 'border-white/10 bg-black/30 text-white/45'}`}>
                  <div className="text-[9px] font-bold tracking-wider uppercase opacity-70">Paquete</div>
                  <div className="mt-0.5 truncate font-mono font-semibold">{pkg ? pkg.metadata.policyLevel : '—'}</div>
                </div>
                <div className={`rounded-lg border p-2 ${operation ? 'border-indigo-500/40 bg-indigo-500/10 text-indigo-200' : 'border-white/10 bg-black/30 text-white/45'}`}>
                  <div className="text-[9px] font-bold tracking-wider uppercase opacity-70">Operación</div>
                  <div className="mt-0.5 truncate font-mono font-semibold">{operation}</div>
                </div>
                <div className={`rounded-lg border p-2 ${credentialReady ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200' : 'border-amber-500/30 bg-amber-500/5 text-amber-200/80'}`}>
                  <div className="text-[9px] font-bold tracking-wider uppercase opacity-70">Credencial</div>
                  <div className="mt-0.5 font-semibold">{credentialReady ? 'Lista' : 'Pendiente'}</div>
                </div>
                <div className={`rounded-lg border p-2 ${deviceReady ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200' : 'border-amber-500/30 bg-amber-500/5 text-amber-200/80'}`}>
                  <div className="text-[9px] font-bold tracking-wider uppercase opacity-70">Dispositivo</div>
                  <div className="mt-0.5 font-semibold">{deviceReady ? 'Ligado' : 'Pendiente'}</div>
                </div>
              </div>
              {pkg && (
                <div className="mt-2 break-all rounded border border-white/5 bg-black/30 p-2 font-mono text-[10px] text-white/60">
                  DOC={pkg.documentId}
                  <br />
                  PKG={pkg.packageId}
                </div>
              )}
              <div className="mt-2 grid grid-cols-2 gap-1.5 text-[10px]">
                <div className="flex items-center gap-1.5 rounded bg-black/20 p-1.5 text-white/70">
                  <FileText className="h-3 w-3 text-indigo-400" /> Docs
                </div>
                <div className="flex items-center gap-1.5 rounded bg-black/20 p-1.5 text-white/70">
                  <ImageIcon className="h-3 w-3 text-emerald-400" /> Imágenes
                </div>
                <div className="flex items-center gap-1.5 rounded bg-black/20 p-1.5 text-white/70">
                  <Music className="h-3 w-3 text-pink-400" /> Audio
                </div>
                <div className="flex items-center gap-1.5 rounded bg-black/20 p-1.5 text-white/70">
                  <Video className="h-3 w-3 text-purple-400" /> Video
                </div>
              </div>
            </CollapsibleSection>

            <details className="glass-card border-l-2 border-l-cyan-500 overflow-hidden">
              <summary className="flex cursor-pointer list-none items-center justify-between gap-2 px-3 py-2 text-[11px] font-bold tracking-wider text-cyan-300 uppercase select-none [&::-webkit-details-marker]:hidden">
                Camino real · formato
                <Info className="h-3.5 w-3.5 text-white/40" />
              </summary>
              <div className="space-y-2 border-t border-white/5 px-3 py-3">
                <p className="text-[11px] leading-relaxed text-white/55">
                  Paquete → operación → credencial → dispositivo → Oracle → grant de un solo uso →
                  Gatekeeper → clave efímera → AES-GCM → runtime → auditoría → apoptosis.
                  No existe password → JS local → AES → plaintext.
                </p>
                <div className="flex items-start gap-2 rounded bg-black/30 p-2 text-[10px] text-white/45">
                  <Archive className="mt-0.5 h-3 w-3 shrink-0 text-amber-400/80" />
                  EXTRACT sólo con grant allowExtraction del Oracle.
                </div>
              </div>
            </details>
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

      <div className="glass-card h-16 shrink-0 overflow-y-auto border-l-2 border-l-indigo-500 bg-black/40 p-2 font-mono text-[10px] leading-snug whitespace-pre-wrap text-white/55">
        {logs}
      </div>
    </div>
  );
}
