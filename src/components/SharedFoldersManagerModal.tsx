import React, { useState } from 'react';
import { useAuth, SharedDriveFolder, extractDriveFolderId } from '../lib/authContext.tsx';
import { useGoogleAuth } from '../lib/googleDriveContext.tsx';
import { 
  FolderPlus, FolderCheck, ExternalLink, Trash2, Edit3, Check, X, 
  HardDrive, Star, AlertCircle, CheckCircle2, Link as LinkIcon, Users, 
  HelpCircle, ShieldCheck, Sparkles, RefreshCw
} from 'lucide-react';

interface SharedFoldersManagerModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function SharedFoldersManagerModal({ isOpen, onClose }: SharedFoldersManagerModalProps) {
  const { 
    currentUser, 
    addSharedFolder, 
    editSharedFolder, 
    deleteSharedFolder, 
    setDefaultFolder 
  } = useAuth();

  const { 
    isSignedIn, 
    openFolderPicker, 
    fetchFolderContents 
  } = useGoogleAuth();

  const [showAddForm, setShowAddForm] = useState(false);
  const [editingFolderId, setEditingFolderId] = useState<string | null>(null);

  // Form State
  const [folderName, setFolderName] = useState('');
  const [folderLink, setFolderLink] = useState('');
  const [folderDesc, setFolderDesc] = useState('');
  const [isDefault, setIsDefault] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [successNotice, setSuccessNotice] = useState<string | null>(null);

  // Edit State
  const [editName, setEditName] = useState('');
  const [editLink, setEditLink] = useState('');
  const [editDesc, setEditDesc] = useState('');
  const [editIsDefault, setEditIsDefault] = useState(false);
  const [editError, setEditError] = useState<string | null>(null);

  // Delete State
  const [folderToDelete, setFolderToDelete] = useState<SharedDriveFolder | null>(null);

  if (!isOpen) return null;

  const folders = currentUser?.sharedFolders || (currentUser?.driveFolderId ? [
    {
      id: currentUser.driveFolderId,
      name: currentUser.driveFolderName || 'Carpeta Principal',
      link: currentUser.driveFolderLink || `https://drive.google.com/drive/folders/${currentUser.driveFolderId}`,
      description: 'Carpeta predeterminada',
      isDefault: true,
      addedAt: currentUser.createdAt
    }
  ] : []);

  const handleOpenAdd = () => {
    setFolderName('');
    setFolderLink('');
    setFolderDesc('');
    setIsDefault(folders.length === 0);
    setFormError(null);
    setShowAddForm(true);
  };

  const handleAddFolder = (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    if (!folderLink.trim()) {
      setFormError('Por favor ingresa el enlace de la carpeta de Google Drive.');
      return;
    }

    const { folderId } = extractDriveFolderId(folderLink);
    if (!folderId) {
      setFormError('Enlace o ID de Google Drive inválido. Ejemplo: https://drive.google.com/drive/folders/1ABC...');
      return;
    }

    const res = addSharedFolder({
      name: folderName.trim() || 'Carpeta Compartida',
      linkOrId: folderLink.trim(),
      description: folderDesc.trim(),
      isDefault
    });

    if (!res.success) {
      setFormError(res.error || 'Error al guardar la carpeta');
      return;
    }

    setSuccessNotice(`Carpeta "${folderName || 'Carpeta Compartida'}" agregada correctamente.`);
    setTimeout(() => setSuccessNotice(null), 3000);
    setShowAddForm(false);
  };

  const handleStartEdit = (folder: SharedDriveFolder) => {
    setEditingFolderId(folder.id);
    setEditName(folder.name);
    setEditLink(folder.link);
    setEditDesc(folder.description || '');
    setEditIsDefault(!!folder.isDefault || currentUser?.driveFolderId === folder.id);
    setEditError(null);
  };

  const handleSaveEdit = (folderId: string) => {
    setEditError(null);
    if (!editLink.trim()) {
      setEditError('El enlace es obligatorio');
      return;
    }

    const res = editSharedFolder(folderId, {
      name: editName,
      linkOrId: editLink,
      description: editDesc,
      isDefault: editIsDefault
    });

    if (!res.success) {
      setEditError(res.error || 'Error al actualizar');
      return;
    }

    setSuccessNotice('Carpeta actualizada con éxito');
    setTimeout(() => setSuccessNotice(null), 3000);
    setEditingFolderId(null);
  };

  const confirmDelete = () => {
    if (!folderToDelete) return;
    const res = deleteSharedFolder(folderToDelete.id);
    if (!res.success) {
      setFormError(res.error || 'No se pudo eliminar la carpeta');
    } else {
      setSuccessNotice(`Carpeta "${folderToDelete.name}" eliminada.`);
      setTimeout(() => setSuccessNotice(null), 3000);
    }
    setFolderToDelete(null);
  };

  const handleSelectActive = (folderId: string) => {
    setDefaultFolder(folderId);
    if (isSignedIn) {
      fetchFolderContents(folderId);
    }
    setSuccessNotice('Carpeta seleccionada como destino activo de trabajo.');
    setTimeout(() => setSuccessNotice(null), 3000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fade-in">
      <div className="bg-[#0f111a] border border-indigo-500/30 rounded-2xl w-full max-w-2xl max-h-[90vh] flex flex-col shadow-[0_0_50px_rgba(99,102,241,0.25)] overflow-hidden">
        
        {/* Header */}
        <div className="p-5 border-b border-white/10 flex items-center justify-between bg-white/[0.02]">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-indigo-500/20 border border-indigo-500/40 flex items-center justify-center text-indigo-400">
              <HardDrive className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white">Carpetas Compartidas de Google Drive</h3>
                <span className="text-[10px] bg-indigo-500/20 text-indigo-300 px-2 py-0.5 rounded-full font-mono font-bold border border-indigo-500/30">
                  {folders.length} {folders.length === 1 ? 'Carpeta' : 'Carpetas'}
                </span>
              </div>
              <p className="text-xs text-white/50">
                Gestiona tus carpetas compartidas para almacenar, sincronizar y organizar tus paquetes DCP cifrados.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-white/10 rounded-lg text-white/40 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Success Notice Banner */}
        {successNotice && (
          <div className="px-5 py-2.5 bg-emerald-500/20 border-b border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2 animate-fade-in">
            <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
            <span className="font-medium">{successNotice}</span>
          </div>
        )}

        {/* Content Area */}
        <div className="p-5 overflow-y-auto space-y-5 flex-1 custom-scrollbar">
          
          {/* Action Bar */}
          <div className="flex items-center justify-between gap-3">
            <div className="text-xs text-white/70 flex items-center gap-1.5">
              <Users className="w-4 h-4 text-indigo-400" />
              <span>Carpetas vinculadas a tu cuenta (<b>{currentUser?.email}</b>)</span>
            </div>
            
            {!showAddForm && (
              <button
                type="button"
                onClick={handleOpenAdd}
                className="bg-indigo-600 hover:bg-indigo-500 text-white px-3.5 py-1.5 rounded-lg text-xs font-bold flex items-center gap-1.5 transition-all shadow-[0_0_15px_rgba(99,102,241,0.3)] cursor-pointer"
              >
                <FolderPlus className="w-4 h-4" />
                <span>Agregar Nueva Carpeta</span>
              </button>
            )}
          </div>

          {/* Formulario Agregar Nueva Carpeta */}
          {showAddForm && (
            <form onSubmit={handleAddFolder} className="p-4 rounded-xl bg-indigo-950/40 border border-indigo-500/40 space-y-3.5 animate-fade-in">
              <div className="flex items-center justify-between border-b border-indigo-500/20 pb-2">
                <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-300 flex items-center gap-2">
                  <FolderPlus className="w-4 h-4" /> Nueva Carpeta Compartida
                </h4>
                <button
                  type="button"
                  onClick={() => setShowAddForm(false)}
                  className="text-white/40 hover:text-white text-xs"
                >
                  Cancelar
                </button>
              </div>

              {formError && (
                <div className="p-2.5 rounded-lg bg-red-500/20 border border-red-500/40 text-red-300 text-xs flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  <span>{formError}</span>
                </div>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] uppercase font-bold text-white/70 mb-1">
                    Nombre / Etiqueta de la Carpeta
                  </label>
                  <input
                    type="text"
                    required
                    value={folderName}
                    onChange={e => setFolderName(e.target.value)}
                    placeholder="Ej. Proyectos Confidenciales"
                    className="w-full bg-black/50 border border-white/15 rounded-lg px-3 py-2 text-xs text-white placeholder:text-white/30 focus:border-indigo-400 outline-none"
                  />
                </div>

                <div>
                  <label className="block text-[11px] uppercase font-bold text-white/70 mb-1">
                    Enlace de Google Drive
                  </label>
                  <div className="relative">
                    <input
                      type="url"
                      required
                      value={folderLink}
                      onChange={e => setFolderLink(e.target.value)}
                      placeholder="https://drive.google.com/drive/folders/..."
                      className="w-full bg-black/50 border border-white/15 rounded-lg px-3 py-2 pr-8 text-xs text-white placeholder:text-white/30 focus:border-indigo-400 outline-none"
                    />
                    <LinkIcon className="w-3.5 h-3.5 text-white/30 absolute right-2.5 top-2.5 pointer-events-none" />
                  </div>
                </div>
              </div>

              <div>
                <label className="block text-[11px] uppercase font-bold text-white/70 mb-1">
                  Descripción o Notas (Opcional)
                </label>
                <input
                  type="text"
                  value={folderDesc}
                  onChange={e => setFolderDesc(e.target.value)}
                  placeholder="Ej. Carpeta compartida con auditoría externa"
                  className="w-full bg-black/50 border border-white/15 rounded-lg px-3 py-2 text-xs text-white placeholder:text-white/30 focus:border-indigo-400 outline-none"
                />
              </div>

              <div className="flex items-center justify-between pt-1">
                <label className="flex items-center gap-2 cursor-pointer text-xs text-white/80">
                  <input
                    type="checkbox"
                    checked={isDefault}
                    onChange={e => setIsDefault(e.target.checked)}
                    className="w-4 h-4 rounded bg-black/40 text-indigo-500"
                  />
                  <span>Establecer como carpeta activa predeterminada</span>
                </label>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setShowAddForm(false)}
                    className="px-3 py-1.5 rounded-lg text-xs font-semibold text-white/60 hover:text-white bg-white/5 hover:bg-white/10"
                  >
                    Cancelar
                  </button>
                  <button
                    type="submit"
                    className="bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-1.5 rounded-lg text-xs font-bold flex items-center gap-1.5 transition-all shadow-[0_0_12px_rgba(99,102,241,0.3)] cursor-pointer"
                  >
                    <Check className="w-3.5 h-3.5" />
                    <span>Guardar Carpeta</span>
                  </button>
                </div>
              </div>
            </form>
          )}

          {/* Lista de Carpetas Guardadas */}
          <div className="space-y-3">
            {folders.length === 0 ? (
              <div className="p-8 text-center border border-dashed border-white/15 rounded-xl space-y-2">
                <HardDrive className="w-8 h-8 text-white/30 mx-auto" />
                <p className="text-sm font-semibold text-white/80">No hay carpetas compartidas registradas</p>
                <p className="text-xs text-white/40">Haz clic en "Agregar Nueva Carpeta" para vincular una carpeta de Google Drive.</p>
              </div>
            ) : (
              folders.map(folder => {
                const isActive = currentUser?.driveFolderId === folder.id || folder.isDefault;
                const isEditing = editingFolderId === folder.id;

                if (isEditing) {
                  return (
                    <div key={folder.id} className="p-4 rounded-xl bg-indigo-950/50 border border-indigo-400/50 space-y-3 animate-fade-in shadow-[0_0_20px_rgba(99,102,241,0.2)]">
                      <div className="flex items-center justify-between border-b border-white/10 pb-2">
                        <span className="text-xs font-bold text-indigo-300 flex items-center gap-1.5">
                          <Edit3 className="w-3.5 h-3.5" /> Editando Carpeta
                        </span>
                        <button onClick={() => setEditingFolderId(null)} className="text-white/40 hover:text-white text-xs">
                          Cancelar
                        </button>
                      </div>

                      {editError && (
                        <div className="p-2 rounded bg-red-500/20 text-red-300 text-xs">
                          {editError}
                        </div>
                      )}

                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                        <div>
                          <label className="text-[10px] uppercase font-bold text-white/60 block mb-1">Nombre</label>
                          <input
                            type="text"
                            value={editName}
                            onChange={e => setEditName(e.target.value)}
                            className="w-full bg-black/60 border border-white/20 rounded px-2.5 py-1.5 text-xs text-white outline-none focus:border-indigo-400"
                            required
                          />
                        </div>
                        <div>
                          <label className="text-[10px] uppercase font-bold text-white/60 block mb-1">Enlace / URL Drive</label>
                          <input
                            type="url"
                            value={editLink}
                            onChange={e => setEditLink(e.target.value)}
                            className="w-full bg-black/60 border border-white/20 rounded px-2.5 py-1.5 text-xs text-white outline-none focus:border-indigo-400"
                            required
                          />
                        </div>
                      </div>

                      <div>
                        <label className="text-[10px] uppercase font-bold text-white/60 block mb-1">Descripción / Notas</label>
                        <input
                          type="text"
                          value={editDesc}
                          onChange={e => setEditDesc(e.target.value)}
                          className="w-full bg-black/60 border border-white/20 rounded px-2.5 py-1.5 text-xs text-white outline-none focus:border-indigo-400"
                        />
                      </div>

                      <div className="flex items-center justify-between pt-1">
                        <label className="flex items-center gap-2 cursor-pointer text-xs text-white/80">
                          <input
                            type="checkbox"
                            checked={editIsDefault}
                            onChange={e => setEditIsDefault(e.target.checked)}
                            className="w-3.5 h-3.5 rounded text-indigo-500"
                          />
                          <span>Marcar como carpeta predeterminada</span>
                        </label>

                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => setEditingFolderId(null)}
                            className="px-2.5 py-1 rounded bg-white/10 text-white/70 hover:text-white text-xs"
                          >
                            Descartar
                          </button>
                          <button
                            type="button"
                            onClick={() => handleSaveEdit(folder.id)}
                            className="px-3 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs flex items-center gap-1"
                          >
                            <Check className="w-3.5 h-3.5" />
                            <span>Guardar Cambios</span>
                          </button>
                        </div>
                      </div>
                    </div>
                  );
                }

                return (
                  <div 
                    key={folder.id} 
                    className={`p-3.5 rounded-xl border transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
                      isActive 
                        ? 'bg-indigo-950/30 border-indigo-500/60 shadow-[0_0_20px_rgba(99,102,241,0.15)]' 
                        : 'bg-black/40 border-white/10 hover:border-white/20'
                    }`}
                  >
                    <div className="flex items-start gap-3 min-w-0">
                      <div className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 mt-0.5 ${
                        isActive 
                          ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40' 
                          : 'bg-white/5 text-white/50 border border-white/10'
                      }`}>
                        {isActive ? <FolderCheck className="w-5 h-5" /> : <HardDrive className="w-5 h-5" />}
                      </div>

                      <div className="min-w-0 space-y-0.5">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-bold text-white truncate max-w-[220px]">
                            {folder.name}
                          </span>
                          {isActive && (
                            <span className="text-[10px] bg-emerald-500/20 text-emerald-300 font-bold px-2 py-0.5 rounded-full border border-emerald-500/40 flex items-center gap-1 shadow-[0_0_10px_rgba(16,185,129,0.2)]">
                              <Star className="w-3 h-3 fill-emerald-400" /> Activa
                            </span>
                          )}
                        </div>

                        {folder.description && (
                          <p className="text-[11px] text-white/50 truncate max-w-sm">
                            {folder.description}
                          </p>
                        )}

                        <div className="flex items-center gap-2 text-[10px] text-white/40 font-mono">
                          <span className="truncate max-w-[150px]">ID: {folder.id}</span>
                          <span>•</span>
                          <a
                            href={folder.link}
                            target="_blank"
                            rel="noreferrer"
                            className="text-indigo-400 hover:text-indigo-300 flex items-center gap-1 underline underline-offset-2"
                          >
                            <span>Abrir en Drive</span>
                            <ExternalLink className="w-2.5 h-2.5" />
                          </a>
                        </div>
                      </div>
                    </div>

                    {/* Acciones de Tarjeta */}
                    <div className="flex items-center gap-1.5 self-end sm:self-center shrink-0">
                      {!isActive && (
                        <button
                          type="button"
                          onClick={() => handleSelectActive(folder.id)}
                          className="bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 border border-indigo-500/40 px-2.5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1 transition-colors cursor-pointer"
                          title="Usar como carpeta de destino activo"
                        >
                          <Star className="w-3 h-3" />
                          <span>Activar</span>
                        </button>
                      )}

                      <button
                        type="button"
                        onClick={() => handleStartEdit(folder)}
                        className="p-1.5 hover:bg-white/10 rounded-lg text-white/60 hover:text-white border border-white/5 transition-colors cursor-pointer"
                        title="Editar carpeta"
                      >
                        <Edit3 className="w-3.5 h-3.5" />
                      </button>

                      {folders.length > 1 && (
                        <button
                          type="button"
                          onClick={() => setFolderToDelete(folder)}
                          className="p-1.5 hover:bg-red-500/20 rounded-lg text-white/40 hover:text-red-400 border border-white/5 transition-colors cursor-pointer"
                          title="Eliminar carpeta"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Diálogo de Confirmación de Eliminación */}
          {folderToDelete && (
            <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 animate-fade-in">
              <div className="flex items-center gap-2.5">
                <AlertCircle className="w-5 h-5 text-red-400 shrink-0" />
                <div>
                  <div className="text-xs font-bold text-white">¿Eliminar "{folderToDelete.name}"?</div>
                  <div className="text-[11px] text-white/60">Se desvinculará de tus carpetas compartidas de DCP.</div>
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() => setFolderToDelete(null)}
                  className="px-3 py-1.5 rounded-lg bg-white/10 hover:bg-white/20 text-white text-xs font-semibold cursor-pointer"
                >
                  Cancelar
                </button>
                <button
                  type="button"
                  onClick={confirmDelete}
                  className="px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-700 text-white text-xs font-bold shadow-lg shadow-red-600/30 cursor-pointer"
                >
                  Confirmar Eliminación
                </button>
              </div>
            </div>
          )}

          {/* Guía de Permisos Compartidos */}
          <div className="p-3.5 rounded-xl bg-white/[0.02] border border-white/10 space-y-1.5">
            <div className="flex items-center gap-1.5 text-xs font-bold text-white/80">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span>¿Cómo funciona el acceso compartido?</span>
            </div>
            <p className="text-[11px] text-white/50 leading-relaxed">
              Cualquier carpeta de Google Drive que haya sido compartida contigo (o que tú compartas con tu equipo) puede ser agregada pegando su enlace. Al activarla como carpeta de trabajo, todos los paquetes cifrados se depositarán y sincronizarán en esa ubicación específica.
            </p>
          </div>

        </div>

        {/* Footer */}
        <div className="p-4 border-t border-white/10 flex items-center justify-between bg-white/[0.02]">
          <span className="text-[11px] text-white/40">
            DCP Data Cryptographic Protocol · Almacenamiento Criptográfico Seguro
          </span>
          <button
            onClick={onClose}
            className="bg-white/10 hover:bg-white/20 text-white px-4 py-1.5 rounded-lg text-xs font-bold transition-colors cursor-pointer"
          >
            Cerrar
          </button>
        </div>

      </div>
    </div>
  );
}
