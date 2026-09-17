import React, { useState, useEffect } from 'react';
import { useAuth, extractDriveFolderId } from '../lib/authContext.tsx';
import { 
  Lock, KeyRound, Mail, User, ShieldCheck, Sparkles, RefreshCw, 
  ArrowRight, ShieldAlert, CheckCircle2, HelpCircle, Eye, EyeOff, Fingerprint, ChevronRight,
  HardDrive, FolderOpen, Link as LinkIcon
} from 'lucide-react';

// Glowing Hexagonal Crystal Emblem matching DCP icon
function DcpCrystalIcon({ className = "w-14 h-14", svgStyle }: { className?: string; svgStyle?: React.CSSProperties }) {
  return (
    <div className={`relative flex items-center justify-center ${className} drop-shadow-[0_0_25px_rgba(168,85,247,0.6)]`}>
      <svg viewBox="0 0 100 100" className="w-full h-full fill-none" style={svgStyle}>
        <defs>
          <linearGradient id="authCrystalGrad1" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#c084fc" />
            <stop offset="50%" stopColor="#818cf8" />
            <stop offset="100%" stopColor="#3b82f6" />
          </linearGradient>
          <linearGradient id="authCrystalGrad2" x1="100%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#e879f9" />
            <stop offset="100%" stopColor="#6366f1" />
          </linearGradient>
          <radialGradient id="authCenterGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#ffffff" stopOpacity="0.9" />
            <stop offset="40%" stopColor="#c084fc" stopOpacity="0.6" />
            <stop offset="100%" stopColor="#4f46e5" stopOpacity="0" />
          </radialGradient>
        </defs>

        <polygon 
          points="50,4 92,26 92,74 50,96 8,74 8,26" 
          fill="url(#authCrystalGrad1)" 
          fillOpacity="0.25" 
          stroke="#a855f7" 
          strokeWidth="2" 
        />
        <polygon points="50,4 92,26 70,50 50,30" fill="url(#authCrystalGrad2)" fillOpacity="0.6" />
        <polygon points="92,26 92,74 70,50" fill="url(#authCrystalGrad1)" fillOpacity="0.75" />
        <polygon points="92,74 50,96 50,70 70,50" fill="url(#authCrystalGrad2)" fillOpacity="0.6" />
        <polygon points="50,96 8,74 30,50 50,70" fill="url(#authCrystalGrad1)" fillOpacity="0.7" />
        <polygon points="8,74 8,26 30,50" fill="url(#authCrystalGrad2)" fillOpacity="0.75" />
        <polygon points="8,26 50,4 50,30 30,50" fill="url(#authCrystalGrad1)" fillOpacity="0.6" />
        <polygon points="50,22 76,36 76,64 50,78 24,64 24,36" fill="#1e1b4b" fillOpacity="0.85" stroke="#c084fc" strokeWidth="1.5" />
        <circle cx="50" cy="50" r="18" fill="url(#authCenterGlow)" />
      </svg>
    </div>
  );
}

const SECURITY_QUESTIONS = [
  '¿Cuál fue el nombre de tu primera mascota?',
  '¿En qué ciudad naciste?',
  '¿Cuál es el modelo de tu primer vehículo?',
  '¿Cuál es tu libro o película favorita?',
  '¿Palabra clave secreta de seguridad?'
];

export default function AuthScreen() {
  const { login, register, recoverPassword, generateCustomUserId, enterDemoSession } = useAuth();
  const [mode, setMode] = useState<'login' | 'register' | 'recover'>('login');

  // Form States
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [name, setName] = useState('');
  const [customId, setCustomId] = useState('');
  const [driveFolderLink, setDriveFolderLink] = useState('');
  const [securityQuestion, setSecurityQuestion] = useState(SECURITY_QUESTIONS[0]);
  const [securityAnswer, setSecurityAnswer] = useState('');
  const [newPassword, setNewPassword] = useState('');

  // UI state
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Auto initialize custom user ID when switching to register
  useEffect(() => {
    if (mode === 'register' && !customId) {
      setCustomId(generateCustomUserId());
    }
  }, [mode]);

  const handleRegenerateId = () => {
    setCustomId(generateCustomUserId());
  };

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setSuccessMsg(null);
    setIsSubmitting(true);

    try {
      const res = await login(email, password);
      if (!res.success) {
        setErrorMsg(res.error || 'Error al iniciar sesión.');
      }
    } catch {
      setErrorMsg('Error inesperado al validar credenciales.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRegisterSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setSuccessMsg(null);

    if (password !== confirmPassword) {
      setErrorMsg('Las contraseñas no coinciden.');
      return;
    }

    if (!driveFolderLink.trim()) {
      setErrorMsg('Por favor ingresa el enlace de la carpeta de Google Drive donde se guardará tu información.');
      return;
    }

    const { folderId } = extractDriveFolderId(driveFolderLink);
    if (!folderId) {
      setErrorMsg('El enlace de la carpeta de Google Drive no es válido. Debe tener el formato https://drive.google.com/drive/folders/...');
      return;
    }

    if (!securityAnswer.trim()) {
      setErrorMsg('Por favor introduce una respuesta de seguridad para recuperar tu cuenta.');
      return;
    }

    setIsSubmitting(true);
    try {
      const res = await register({
        name,
        email,
        customId,
        password,
        securityQuestion,
        securityAnswer,
        driveFolderLink
      });

      if (!res.success) {
        setErrorMsg(res.error || 'Error al registrar la cuenta.');
      }
    } catch {
      setErrorMsg('Error inesperado al crear la cuenta.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRecoverSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setSuccessMsg(null);

    if (newPassword !== confirmPassword) {
      setErrorMsg('Las nuevas contraseñas no coinciden.');
      return;
    }

    setIsSubmitting(true);
    try {
      const res = await recoverPassword({
        email,
        securityAnswer,
        newPassword
      });

      if (res.success) {
        setSuccessMsg('¡Contraseña actualizada exitosamente! Ya puedes iniciar sesión con tu nueva clave.');
        setTimeout(() => {
          setMode('login');
          setPassword('');
          setConfirmPassword('');
          setNewPassword('');
          setSuccessMsg(null);
        }, 2200);
      } else {
        setErrorMsg(res.error || 'No se pudo recuperar la contraseña.');
      }
    } catch {
      setErrorMsg('Error inesperado al procesar la recuperación.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-4 md:p-6 select-none relative overflow-hidden">
      {/* Background Glows */}
      <div className="mesh-bg"></div>

      <div 
        className="max-w-md w-full glass-panel p-6 md:p-8 relative z-10 shadow-[0_0_50px_rgba(0,0,0,0.8)] border border-white/10"
        style={{
          minHeight: '550px',
          maxHeight: '92vh',
          overflowY: 'auto',
          borderStyle: 'ridge',
          borderWidth: '0px',
          borderRadius: '0px'
        }}
      >
        {/* Brand Header */}
        <div 
          className="flex flex-col items-center text-center mb-6 border-white/20"
          style={{
            height: '130px',
            borderRadius: '45px',
            borderStyle: 'inset',
            borderWidth: '1px'
          }}
        >
          <DcpCrystalIcon className="w-14 h-14 mb-3" svgStyle={{ marginLeft: '-200px', marginTop: '14px' }} />
          <h1 
            className="text-2xl font-black tracking-wider bg-clip-text text-transparent bg-gradient-to-r from-pink-300 via-purple-300 to-indigo-300"
            style={{
              marginLeft: '50px',
              marginRight: '0px',
              marginTop: '-49px'
            }}
          >
            DCP SECURE
          </h1>
          <p 
            className="text-[10px] uppercase tracking-widest text-white/50 font-bold"
            style={{
              marginTop: '15px',
              marginLeft: '0px'
            }}
          >
            The Data Cryptographic Protocol
          </p>
          <div className="mt-2 inline-flex items-center gap-1.5 px-3 py-0.5 rounded-full bg-purple-500/10 border border-purple-500/30 text-[10px] text-purple-300">
            <ShieldCheck className="w-3 h-3 text-purple-400" /> Autenticación Obligatoria de Acceso
          </div>
          <div className="mt-2 max-w-sm space-y-1.5 text-center">
            <div className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/40 bg-emerald-500/10 px-3 py-0.5 text-[10px] font-bold tracking-wide text-emerald-200 uppercase">
              MVP operativo — demo entry
            </div>
            <p className="text-[10px] leading-relaxed text-white/45">
              Use <span className="font-semibold text-white/70">Continuar en modo demo (MVP)</span> to reach
              Encrypt / Decrypt / Monitor without Firebase. Local account shell still available.
              Crypto and Gatekeeper are never bypassed.
            </p>
          </div>
        </div>

        {/* Tab Selector */}
        <div className="flex rounded-xl bg-black/40 p-1 mb-6 border border-white/5">
          <button
            type="button"
            onClick={() => { setMode('login'); setErrorMsg(null); setSuccessMsg(null); }}
            className={`flex-1 py-2 text-xs font-bold rounded-lg transition-all cursor-pointer ${
              mode === 'login' 
                ? 'bg-purple-600/30 text-purple-200 border border-purple-500/40 shadow-[0_0_15px_rgba(168,85,247,0.2)]' 
                : 'text-white/40 hover:text-white/80'
            }`}
          >
            Iniciar Sesión
          </button>
          <button
            type="button"
            onClick={() => { setMode('register'); setErrorMsg(null); setSuccessMsg(null); }}
            className={`flex-1 py-2 text-xs font-bold rounded-lg transition-all cursor-pointer ${
              mode === 'register' 
                ? 'bg-pink-600/30 text-pink-200 border border-pink-500/40 shadow-[0_0_15px_rgba(244,114,182,0.2)]' 
                : 'text-white/40 hover:text-white/80'
            }`}
          >
            Crear Cuenta
          </button>
          <button
            type="button"
            onClick={() => { setMode('recover'); setErrorMsg(null); setSuccessMsg(null); }}
            className={`flex-1 py-2 text-xs font-bold rounded-lg transition-all cursor-pointer ${
              mode === 'recover' 
                ? 'bg-indigo-600/30 text-indigo-200 border border-indigo-500/40 shadow-[0_0_15px_rgba(99,102,241,0.2)]' 
                : 'text-white/40 hover:text-white/80'
            }`}
          >
            Recuperar
          </button>
        </div>

        {/* Status Alerts */}
        {errorMsg && (
          <div className="mb-4 p-3 rounded-lg bg-red-500/15 border border-red-500/40 text-red-300 text-xs flex items-start gap-2 animate-fade-in">
            <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
            <span>{errorMsg}</span>
          </div>
        )}

        {successMsg && (
          <div className="mb-4 p-3 rounded-lg bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 text-xs flex items-start gap-2 animate-fade-in">
            <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" />
            <span>{successMsg}</span>
          </div>
        )}

        {/* MVP demo gate — local session only */}
        <div className="mb-5 space-y-2">
          <button
            type="button"
            disabled={isSubmitting}
            onClick={() => {
              setErrorMsg(null);
              enterDemoSession();
            }}
            className="w-full cursor-pointer rounded-xl border border-emerald-500/50 bg-gradient-to-r from-emerald-600/30 via-teal-600/25 to-cyan-600/30 px-4 py-3 text-xs font-black uppercase tracking-wider text-emerald-100 shadow-[0_0_24px_rgba(16,185,129,0.25)] transition-all hover:from-emerald-600/50 hover:to-cyan-600/50 disabled:opacity-50"
          >
            Continuar en modo demo (MVP)
          </button>
          <p className="text-center text-[9px] leading-relaxed text-white/40">
            EN: Enter product panels with a local demo session · ES: Entra a Encrypt/Decrypt/Monitor sin IdP externo.
            Does not weaken crypto.
          </p>
        </div>

        {/* 1. FORMULARIO DE INICIO DE SESIÓN */}
        {mode === 'login' && (
          <form onSubmit={handleLoginSubmit} className="space-y-4">
            <div>
              <label className="block text-[11px] uppercase font-bold text-white/60 mb-1.5 flex items-center gap-1.5">
                <Mail className="w-3.5 h-3.5 text-purple-400" /> Correo Electrónico
              </label>
              <input
                type="email"
                required
                value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="ejemplo@protocolo-dcp.com"
                className="w-full bg-black/40 border border-white/10 rounded-lg px-3.5 py-2.5 text-xs text-white placeholder:text-white/30 focus:border-purple-500/50 outline-none"
              />
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-[11px] uppercase font-bold text-white/60 flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5 text-purple-400" /> Contraseña de Cuenta
                </label>
                <button
                  type="button"
                  onClick={() => setMode('recover')}
                  className="text-[10px] text-purple-300 hover:text-purple-200 underline cursor-pointer"
                >
                  ¿Olvidaste tu contraseña?
                </button>
              </div>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder="Introduce tu contraseña"
                  className="w-full bg-black/40 border border-white/10 rounded-lg px-3.5 py-2.5 pr-10 text-xs text-white placeholder:text-white/30 focus:border-purple-500/50 outline-none"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-2.5 text-white/40 hover:text-white"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full mt-2 bg-gradient-to-r from-purple-600/40 via-indigo-600/40 to-pink-600/40 hover:from-purple-600/60 hover:to-pink-600/60 text-white font-bold uppercase tracking-wider py-3 px-4 rounded-xl border border-purple-500/50 text-xs flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(168,85,247,0.25)] transition-all cursor-pointer disabled:opacity-50"
            >
              {isSubmitting ? (
                <RefreshCw className="w-4 h-4 animate-spin" />
              ) : (
                <>
                  <KeyRound className="w-4 h-4" />
                  <span>Acceder al Protocolo DCP</span>
                  <ChevronRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>
        )}

        {/* 2. FORMULARIO DE CREAR CUENTA */}
        {mode === 'register' && (
          <form onSubmit={handleRegisterSubmit} className="space-y-3.5 max-h-[440px] overflow-y-auto pr-1">
            <div>
              <label className="block text-[11px] uppercase font-bold text-white/60 mb-1 flex items-center gap-1.5">
                <User className="w-3.5 h-3.5 text-pink-400" /> Nombre Completo o Alias
              </label>
              <input
                type="text"
                required
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="Ej. CriptoOperador Alfa"
                className="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-xs text-white placeholder:text-white/30 focus:border-pink-500/50 outline-none"
              />
            </div>

            <div>
              <label className="block text-[11px] uppercase font-bold text-white/60 mb-1 flex items-center gap-1.5">
                <Mail className="w-3.5 h-3.5 text-pink-400" /> Correo Electrónico
              </label>
              <input
                type="email"
                required
                value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="tu-correo@seguro.com"
                className="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-xs text-white placeholder:text-white/30 focus:border-pink-500/50 outline-none"
              />
            </div>

            {/* ID DE USUARIO PERSONALIZADO */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-[11px] uppercase font-bold text-white/60 flex items-center gap-1.5">
                  <Fingerprint className="w-3.5 h-3.5 text-pink-400" /> ID de Usuario Personalizado
                </label>
                <button
                  type="button"
                  onClick={handleRegenerateId}
                  className="text-[10px] text-pink-300 hover:text-pink-200 flex items-center gap-1 bg-pink-500/10 px-1.5 py-0.5 rounded border border-pink-500/30 cursor-pointer"
                >
                  <Sparkles className="w-2.5 h-2.5" /> Generar Cripto-ID
                </button>
              </div>
              <input
                type="text"
                required
                value={customId}
                onChange={e => setCustomId(e.target.value.toUpperCase())}
                placeholder="DCP-USR-XXXX-XXXX"
                className="w-full bg-black/40 border border-pink-500/30 font-mono text-pink-300 font-bold rounded-lg px-3 py-2 text-xs placeholder:text-white/30 focus:border-pink-500 outline-none"
              />
              <span className="text-[9px] text-white/40 block mt-0.5">
                Puedes personalizar este ID o usar el generador criptoseguro.
              </span>
            </div>

            {/* ENLACE DE CARPETA DE GOOGLE DRIVE */}
            <div className="p-3 rounded-xl bg-indigo-950/40 border border-indigo-500/40 space-y-1.5 shadow-[0_0_15px_rgba(99,102,241,0.15)]">
              <div className="flex items-center justify-between">
                <label className="text-[11px] uppercase font-bold text-indigo-300 flex items-center gap-1.5">
                  <HardDrive className="w-3.5 h-3.5 text-indigo-400" /> Carpeta en Google Drive (Destino)
                </label>
                <span className="text-[9px] bg-indigo-500/20 text-indigo-300 px-1.5 py-0.5 rounded font-mono border border-indigo-500/40 uppercase font-bold">
                  Requerido
                </span>
              </div>
              <div className="relative">
                <input
                  type="url"
                  required
                  value={driveFolderLink}
                  onChange={e => setDriveFolderLink(e.target.value)}
                  placeholder="https://drive.google.com/drive/folders/1aBcDeFg..."
                  className="w-full bg-black/60 border border-indigo-500/40 rounded-lg px-3 py-2 pr-8 text-xs text-indigo-100 placeholder:text-white/30 focus:border-indigo-400 outline-none"
                />
                <LinkIcon className="w-3.5 h-3.5 text-indigo-400/60 absolute right-2.5 top-2.5 pointer-events-none" />
              </div>
              <p className="text-[10px] text-white/60 leading-relaxed">
                Pega el enlace de la carpeta de Google Drive donde se guardarán y sincronizarán tus paquetes cifrados.
              </p>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="block text-[11px] uppercase font-bold text-white/60 mb-1 flex items-center gap-1">
                  <Lock className="w-3 h-3 text-pink-400" /> Contraseña
                </label>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder="Mínimo 6 caracteres"
                  className="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-xs text-white placeholder:text-white/30 focus:border-pink-500/50 outline-none"
                />
              </div>
              <div>
                <label className="block text-[11px] uppercase font-bold text-white/60 mb-1 flex items-center gap-1">
                  <Lock className="w-3 h-3 text-pink-400" /> Confirmar
                </label>
                <input
                  type="password"
                  required
                  value={confirmPassword}
                  onChange={e => setConfirmPassword(e.target.value)}
                  placeholder="Repetir clave"
                  className="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-xs text-white placeholder:text-white/30 focus:border-pink-500/50 outline-none"
                />
              </div>
            </div>

            {/* PREGUNTA DE SEGURIDAD PARA RECUPERACIÓN */}
            <div className="pt-2 border-t border-white/10 space-y-2">
              <div className="flex items-center gap-1.5 text-[11px] font-bold text-pink-300">
                <HelpCircle className="w-3.5 h-3.5" /> Clave de Respaldo / Recuperación
              </div>
              <select
                value={securityQuestion}
                onChange={e => setSecurityQuestion(e.target.value)}
                className="w-full bg-black/50 border border-white/10 rounded-lg px-2.5 py-1.5 text-[11px] text-white/80 focus:border-pink-500/50 outline-none"
              >
                {SECURITY_QUESTIONS.map((q, idx) => (
                  <option key={idx} value={q} className="bg-slate-900 text-white text-xs">
                    {q}
                  </option>
                ))}
              </select>
              <input
                type="text"
                required
                value={securityAnswer}
                onChange={e => setSecurityAnswer(e.target.value)}
                placeholder="Tu respuesta secreta de recuperación"
                className="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-xs text-white placeholder:text-white/30 focus:border-pink-500/50 outline-none"
              />
            </div>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full mt-2 bg-pink-500/25 hover:bg-pink-500/35 text-pink-200 font-bold uppercase tracking-wider py-2.5 px-4 rounded-xl border border-pink-500/50 text-xs flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(244,114,182,0.25)] transition-all cursor-pointer disabled:opacity-50"
            >
              {isSubmitting ? (
                <RefreshCw className="w-4 h-4 animate-spin" />
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4" />
                  <span>Crear Cuenta Soberana DCP</span>
                </>
              )}
            </button>
          </form>
        )}

        {/* 3. FORMULARIO DE RECUPERAR CONTRASEÑA */}
        {mode === 'recover' && (
          <form onSubmit={handleRecoverSubmit} className="space-y-3.5">
            <div>
              <label className="block text-[11px] uppercase font-bold text-white/60 mb-1 flex items-center gap-1.5">
                <Mail className="w-3.5 h-3.5 text-indigo-400" /> Correo Registrado
              </label>
              <input
                type="email"
                required
                value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="ejemplo@protocolo-dcp.com"
                className="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-xs text-white placeholder:text-white/30 focus:border-indigo-500/50 outline-none"
              />
            </div>

            <div>
              <label className="block text-[11px] uppercase font-bold text-white/60 mb-1 flex items-center gap-1.5">
                <HelpCircle className="w-3.5 h-3.5 text-indigo-400" /> Respuesta Secreta de Recuperación
              </label>
              <input
                type="text"
                required
                value={securityAnswer}
                onChange={e => setSecurityAnswer(e.target.value)}
                placeholder="Ingresa la respuesta que guardaste al registrarte"
                className="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-xs text-white placeholder:text-white/30 focus:border-indigo-500/50 outline-none"
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="block text-[11px] uppercase font-bold text-white/60 mb-1 flex items-center gap-1">
                  <Lock className="w-3 h-3 text-indigo-400" /> Nueva Clave
                </label>
                <input
                  type="password"
                  required
                  value={newPassword}
                  onChange={e => setNewPassword(e.target.value)}
                  placeholder="Mínimo 6 caracteres"
                  className="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-xs text-white placeholder:text-white/30 focus:border-indigo-500/50 outline-none"
                />
              </div>
              <div>
                <label className="block text-[11px] uppercase font-bold text-white/60 mb-1 flex items-center gap-1">
                  <Lock className="w-3 h-3 text-indigo-400" /> Confirmar
                </label>
                <input
                  type="password"
                  required
                  value={confirmPassword}
                  onChange={e => setConfirmPassword(e.target.value)}
                  placeholder="Repetir clave"
                  className="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-xs text-white placeholder:text-white/30 focus:border-indigo-500/50 outline-none"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full mt-2 bg-indigo-500/25 hover:bg-indigo-500/35 text-indigo-200 font-bold uppercase tracking-wider py-2.5 px-4 rounded-xl border border-indigo-500/50 text-xs flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(99,102,241,0.25)] transition-all cursor-pointer disabled:opacity-50"
            >
              {isSubmitting ? (
                <RefreshCw className="w-4 h-4 animate-spin" />
              ) : (
                <>
                  <KeyRound className="w-4 h-4" />
                  <span>Restablecer y Actualizar Contraseña</span>
                </>
              )}
            </button>
          </form>
        )}

        {/* Security Footer Note */}
        <div className="mt-6 pt-4 border-t border-white/10 text-center">
          <p className="text-[10px] text-white/40 flex items-center justify-center gap-1">
            <Lock className="w-3 h-3 text-purple-400" /> Cifrado Soberano SHA-256 / AES-256 en RAM Aislada
          </p>
        </div>
      </div>
    </div>
  );
}
