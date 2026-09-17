import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';

export interface SharedDriveFolder {
  id: string; // Folder ID in Google Drive
  name: string; // Custom label
  link: string; // Full web link
  description?: string;
  isDefault?: boolean;
  addedAt: number;
}

export interface DCPUser {
  id: string; // Custom User ID (e.g. DCP-ID-7849-AF)
  name: string;
  email: string;
  passwordHash: string;
  securityQuestion: string;
  securityAnswerHash: string;
  driveFolderLink?: string;
  driveFolderId?: string;
  driveFolderName?: string;
  sharedFolders?: SharedDriveFolder[];
  createdAt: number;
  lastLogin: number;
}

export function extractDriveFolderId(urlOrId: string): { folderId: string; cleanUrl: string } {
  const trimmed = urlOrId.trim();
  if (!trimmed) return { folderId: '', cleanUrl: '' };
  const matchFolder = trimmed.match(/\/folders\/([a-zA-Z0-9_-]+)/);
  if (matchFolder && matchFolder[1]) {
    return { folderId: matchFolder[1], cleanUrl: trimmed };
  }
  const matchId = trimmed.match(/[?&]id=([a-zA-Z0-9_-]+)/);
  if (matchId && matchId[1]) {
    return { folderId: matchId[1], cleanUrl: trimmed };
  }
  if (/^[a-zA-Z0-9_-]{15,}$/.test(trimmed)) {
    return { folderId: trimmed, cleanUrl: `https://drive.google.com/drive/folders/${trimmed}` };
  }
  return { folderId: trimmed, cleanUrl: trimmed };
}

interface AuthContextType {
  currentUser: DCPUser | null;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<{ success: boolean; error?: string }>;
  register: (data: {
    name: string;
    email: string;
    customId: string;
    password: string;
    securityQuestion: string;
    securityAnswer: string;
    driveFolderLink: string;
  }) => Promise<{ success: boolean; error?: string }>;
  updateUserFolder: (folderLink: string, folderId: string, folderName?: string) => void;
  addSharedFolder: (folder: { name: string; linkOrId: string; description?: string; isDefault?: boolean }) => { success: boolean; error?: string; folder?: SharedDriveFolder };
  editSharedFolder: (folderId: string, updates: { name?: string; linkOrId?: string; description?: string; isDefault?: boolean }) => { success: boolean; error?: string };
  deleteSharedFolder: (folderId: string) => { success: boolean; error?: string };
  setDefaultFolder: (folderId: string) => void;
  recoverPassword: (data: {
    email: string;
    securityAnswer: string;
    newPassword: string;
  }) => Promise<{ success: boolean; error?: string }>;
  logout: () => void;
  enterDemoSession: () => void;
  generateCustomUserId: (prefix?: string) => string;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Hash helper for client-side sovereign account authentication
async function hashSecret(secret: string): Promise<string> {
  const enc = new TextEncoder().encode(secret.trim().toLowerCase());
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', enc);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

const STORAGE_USERS_KEY = 'dcp_registered_users_db';
const STORAGE_SESSION_KEY = 'dcp_active_auth_session';

export function AuthProvider({ children }: { children: ReactNode }) {
  const [currentUser, setCurrentUser] = useState<DCPUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Load session from storage on boot
  useEffect(() => {
    try {
      const savedSession = localStorage.getItem(STORAGE_SESSION_KEY);
      if (savedSession) {
        const user = JSON.parse(savedSession);
        setCurrentUser(user);
      }
    } catch (e) {
      console.warn('Failed to parse saved auth session:', e);
    } finally {
      setIsLoading(false);
    }
  }, []);

  const getUsersDB = (): Record<string, DCPUser> => {
    try {
      const raw = localStorage.getItem(STORAGE_USERS_KEY);
      return raw ? JSON.parse(raw) : {};
    } catch {
      return {};
    }
  };

  const saveUsersDB = (db: Record<string, DCPUser>) => {
    localStorage.setItem(STORAGE_USERS_KEY, JSON.stringify(db));
  };

  // Generate unique custom ID
  const generateCustomUserId = (prefix: string = 'DCP-USR'): string => {
    const array = new Uint8Array(4);
    window.crypto.getRandomValues(array);
    const hex = Array.from(array, byte => byte.toString(16).padStart(2, '0').toUpperCase()).join('');
    return `${prefix}-${hex.slice(0, 4)}-${hex.slice(4, 8)}`;
  };

  const login = async (email: string, password: string): Promise<{ success: boolean; error?: string }> => {
    const cleanEmail = email.trim().toLowerCase();
    if (!cleanEmail || !password) {
      return { success: false, error: 'Por favor, ingresa correo y contraseña.' };
    }

    const users = getUsersDB();
    const user = users[cleanEmail];

    if (!user) {
      return { success: false, error: 'Usuario no encontrado. Verifica tu correo o crea una cuenta.' };
    }

    const inputHash = await hashSecret(password);
    if (user.passwordHash !== inputHash) {
      return { success: false, error: 'Contraseña incorrecta. Inténtalo de nuevo.' };
    }

    // Update last login
    user.lastLogin = Date.now();
    users[cleanEmail] = user;
    saveUsersDB(users);

    // Save session
    localStorage.setItem(STORAGE_SESSION_KEY, JSON.stringify(user));
    setCurrentUser(user);

    return { success: true };
  };

  const register = async (data: {
    name: string;
    email: string;
    customId: string;
    password: string;
    securityQuestion: string;
    securityAnswer: string;
    driveFolderLink: string;
  }): Promise<{ success: boolean; error?: string }> => {
    const cleanEmail = data.email.trim().toLowerCase();
    const cleanName = data.name.trim();
    const customId = data.customId.trim().toUpperCase() || generateCustomUserId();
    const driveFolderInput = data.driveFolderLink?.trim() || '';

    if (!cleanEmail || !cleanName || !data.password) {
      return { success: false, error: 'Todos los campos requeridos deben ser completados.' };
    }

    if (!cleanEmail.includes('@') || !cleanEmail.includes('.')) {
      return { success: false, error: 'Por favor, introduce un correo electrónico válido.' };
    }

    if (!driveFolderInput) {
      return { success: false, error: 'Por favor ingresa el enlace de tu carpeta de Google Drive donde se guardará tu información.' };
    }

    const { folderId, cleanUrl } = extractDriveFolderId(driveFolderInput);
    if (!folderId) {
      return { success: false, error: 'El enlace de la carpeta de Google Drive no es válido. Ingresa un enlace tipo https://drive.google.com/drive/folders/...' };
    }

    if (data.password.length < 6) {
      return { success: false, error: 'La contraseña debe contener al menos 6 caracteres.' };
    }

    const users = getUsersDB();

    // Check if email already registered
    if (users[cleanEmail]) {
      return { success: false, error: 'Este correo electrónico ya está registrado.' };
    }

    // Check if custom ID is taken
    const idTaken = Object.values(users).some(u => u.id.toUpperCase() === customId.toUpperCase());
    if (idTaken) {
      return { success: false, error: `El ID de usuario "${customId}" ya está en uso. Por favor elige otro o genera uno nuevo.` };
    }

    const passwordHash = await hashSecret(data.password);
    const securityAnswerHash = await hashSecret(data.securityAnswer);

    const initialSharedFolders: SharedDriveFolder[] = [
      {
        id: folderId,
        name: 'Carpeta Principal',
        link: cleanUrl,
        description: 'Carpeta predeterminada asignada en el registro',
        isDefault: true,
        addedAt: Date.now()
      }
    ];

    const newUser: DCPUser = {
      id: customId,
      name: cleanName,
      email: cleanEmail,
      passwordHash,
      securityQuestion: data.securityQuestion,
      securityAnswerHash,
      driveFolderLink: cleanUrl,
      driveFolderId: folderId,
      driveFolderName: 'Carpeta Principal',
      sharedFolders: initialSharedFolders,
      createdAt: Date.now(),
      lastLogin: Date.now()
    };

    users[cleanEmail] = newUser;
    saveUsersDB(users);

    // Auto login
    localStorage.setItem(STORAGE_SESSION_KEY, JSON.stringify(newUser));
    setCurrentUser(newUser);

    return { success: true };
  };

  const updateUserFolder = (folderLink: string, folderId: string, folderName?: string) => {
    if (!currentUser) return;
    const users = getUsersDB();
    const user = users[currentUser.email];
    if (user) {
      user.driveFolderLink = folderLink;
      user.driveFolderId = folderId;
      if (folderName) user.driveFolderName = folderName;
      
      // Also update or add in sharedFolders
      let folders = user.sharedFolders ? [...user.sharedFolders] : [];
      const existingIdx = folders.findIndex(f => f.id === folderId);
      if (existingIdx >= 0) {
        folders[existingIdx] = {
          ...folders[existingIdx],
          link: folderLink,
          name: folderName || folders[existingIdx].name,
          isDefault: true
        };
      } else {
        folders.push({
          id: folderId,
          name: folderName || 'Carpeta Compartida',
          link: folderLink,
          isDefault: true,
          addedAt: Date.now()
        });
      }
      user.sharedFolders = folders;

      users[currentUser.email] = user;
      saveUsersDB(users);
      localStorage.setItem(STORAGE_SESSION_KEY, JSON.stringify(user));
      setCurrentUser({ ...user });
    }
  };

  const addSharedFolder = (folder: { name: string; linkOrId: string; description?: string; isDefault?: boolean }): { success: boolean; error?: string; folder?: SharedDriveFolder } => {
    if (!currentUser) return { success: false, error: 'Debes iniciar sesión' };
    const { folderId, cleanUrl } = extractDriveFolderId(folder.linkOrId);
    if (!folderId) {
      return { success: false, error: 'El enlace o ID de la carpeta de Google Drive no es válido.' };
    }
    const cleanName = folder.name?.trim() || 'Carpeta Compartida';

    const users = getUsersDB();
    const user = users[currentUser.email];
    if (!user) return { success: false, error: 'Usuario no encontrado' };

    let folders = user.sharedFolders ? [...user.sharedFolders] : [];
    if (folders.some(f => f.id === folderId)) {
      return { success: false, error: 'Esta carpeta de Google Drive ya está agregada en tu lista.' };
    }

    if (folder.isDefault) {
      folders = folders.map(f => ({ ...f, isDefault: false }));
      user.driveFolderId = folderId;
      user.driveFolderLink = cleanUrl;
      user.driveFolderName = cleanName;
    }

    const newSharedFolder: SharedDriveFolder = {
      id: folderId,
      name: cleanName,
      link: cleanUrl,
      description: folder.description?.trim() || '',
      isDefault: folder.isDefault || folders.length === 0,
      addedAt: Date.now()
    };

    folders.push(newSharedFolder);
    user.sharedFolders = folders;

    if (newSharedFolder.isDefault) {
      user.driveFolderId = folderId;
      user.driveFolderLink = cleanUrl;
      user.driveFolderName = cleanName;
    }

    users[currentUser.email] = user;
    saveUsersDB(users);
    localStorage.setItem(STORAGE_SESSION_KEY, JSON.stringify(user));
    setCurrentUser({ ...user });

    return { success: true, folder: newSharedFolder };
  };

  const editSharedFolder = (folderId: string, updates: { name?: string; linkOrId?: string; description?: string; isDefault?: boolean }): { success: boolean; error?: string } => {
    if (!currentUser) return { success: false, error: 'Debes iniciar sesión' };
    const users = getUsersDB();
    const user = users[currentUser.email];
    if (!user || !user.sharedFolders) return { success: false, error: 'Carpeta no encontrada' };

    const folderIndex = user.sharedFolders.findIndex(f => f.id === folderId);
    if (folderIndex === -1) return { success: false, error: 'Carpeta no encontrada en tu lista' };

    let newFolderId = folderId;
    let newLink = user.sharedFolders[folderIndex].link;

    if (updates.linkOrId) {
      const parsed = extractDriveFolderId(updates.linkOrId);
      if (!parsed.folderId) {
        return { success: false, error: 'Enlace de Google Drive inválido.' };
      }
      newFolderId = parsed.folderId;
      newLink = parsed.cleanUrl;
    }

    let folders = [...user.sharedFolders];
    if (updates.isDefault) {
      folders = folders.map(f => ({ ...f, isDefault: false }));
    }

    const updatedFolder: SharedDriveFolder = {
      ...folders[folderIndex],
      id: newFolderId,
      name: updates.name?.trim() || folders[folderIndex].name,
      link: newLink,
      description: updates.description !== undefined ? updates.description.trim() : folders[folderIndex].description,
      isDefault: updates.isDefault !== undefined ? updates.isDefault : folders[folderIndex].isDefault
    };

    folders[folderIndex] = updatedFolder;
    user.sharedFolders = folders;

    if (updatedFolder.isDefault || user.driveFolderId === folderId) {
      user.driveFolderId = updatedFolder.id;
      user.driveFolderLink = updatedFolder.link;
      user.driveFolderName = updatedFolder.name;
    }

    users[currentUser.email] = user;
    saveUsersDB(users);
    localStorage.setItem(STORAGE_SESSION_KEY, JSON.stringify(user));
    setCurrentUser({ ...user });

    return { success: true };
  };

  const deleteSharedFolder = (folderId: string): { success: boolean; error?: string } => {
    if (!currentUser) return { success: false, error: 'Debes iniciar sesión' };
    const users = getUsersDB();
    const user = users[currentUser.email];
    if (!user || !user.sharedFolders) return { success: false, error: 'Carpeta no encontrada' };

    if (user.sharedFolders.length <= 1) {
      return { success: false, error: 'Debes mantener al menos una carpeta de destino en tu cuenta.' };
    }

    const wasDefault = user.driveFolderId === folderId || user.sharedFolders.find(f => f.id === folderId)?.isDefault;
    const folders = user.sharedFolders.filter(f => f.id !== folderId);

    if (wasDefault && folders.length > 0) {
      folders[0].isDefault = true;
      user.driveFolderId = folders[0].id;
      user.driveFolderLink = folders[0].link;
      user.driveFolderName = folders[0].name;
    }

    user.sharedFolders = folders;
    users[currentUser.email] = user;
    saveUsersDB(users);
    localStorage.setItem(STORAGE_SESSION_KEY, JSON.stringify(user));
    setCurrentUser({ ...user });

    return { success: true };
  };

  const setDefaultFolder = (folderId: string) => {
    if (!currentUser) return;
    const users = getUsersDB();
    const user = users[currentUser.email];
    if (!user || !user.sharedFolders) return;

    const target = user.sharedFolders.find(f => f.id === folderId);
    if (!target) return;

    user.sharedFolders = user.sharedFolders.map(f => ({
      ...f,
      isDefault: f.id === folderId
    }));

    user.driveFolderId = target.id;
    user.driveFolderLink = target.link;
    user.driveFolderName = target.name;

    users[currentUser.email] = user;
    saveUsersDB(users);
    localStorage.setItem(STORAGE_SESSION_KEY, JSON.stringify(user));
    setCurrentUser({ ...user });
  };

  const recoverPassword = async (data: {
    email: string;
    securityAnswer: string;
    newPassword: string;
  }): Promise<{ success: boolean; error?: string }> => {
    const cleanEmail = data.email.trim().toLowerCase();
    if (!cleanEmail || !data.securityAnswer || !data.newPassword) {
      return { success: false, error: 'Por favor, completa todos los campos de recuperación.' };
    }

    if (data.newPassword.length < 6) {
      return { success: false, error: 'La nueva contraseña debe contener al menos 6 caracteres.' };
    }

    const users = getUsersDB();
    const user = users[cleanEmail];

    if (!user) {
      return { success: false, error: 'No existe una cuenta registrada con este correo.' };
    }

    const answerHash = await hashSecret(data.securityAnswer);
    if (user.securityAnswerHash !== answerHash) {
      return { success: false, error: 'La respuesta de seguridad es incorrecta.' };
    }

    // Update password
    user.passwordHash = await hashSecret(data.newPassword);
    users[cleanEmail] = user;
    saveUsersDB(users);

    return { success: true };
  };

  const logout = () => {
    localStorage.removeItem(STORAGE_SESSION_KEY);
    setCurrentUser(null);
  };

  /** Local MVP demo gate — does not call Firebase/Gemini and does not weaken crypto. */
  const enterDemoSession = () => {
    const demoUser: DCPUser = {
      id: 'DCP-DEMO-MVP-0001',
      name: 'Demo MVP',
      email: 'demo@tdcp.local',
      passwordHash: '',
      securityQuestion: 'demo',
      securityAnswerHash: '',
      driveFolderLink: '',
      driveFolderId: '',
      sharedFolders: [],
      createdAt: Date.now(),
      lastLogin: Date.now(),
    };
    localStorage.setItem(STORAGE_SESSION_KEY, JSON.stringify(demoUser));
    setCurrentUser(demoUser);
  };

  return (
    <AuthContext.Provider
      value={{
        currentUser,
        isLoading,
        login,
        register,
        updateUserFolder,
        addSharedFolder,
        editSharedFolder,
        deleteSharedFolder,
        setDefaultFolder,
        recoverPassword,
        logout,
        enterDemoSession,
        generateCustomUserId
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
