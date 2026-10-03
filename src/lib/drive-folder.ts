/** Shared Google Drive folder helpers used by the server-side account API. */

export interface SharedDriveFolder {
  id: string;
  name: string;
  link: string;
  description?: string;
  isDefault?: boolean;
  addedAt: number;
}

/** Canonical TDCP custom-user-id shape: uppercase letters, digits and hyphens. */
export const CUSTOM_ID_PATTERN = /^[A-Z0-9-]{4,40}$/;

export function generateCustomUserId(prefix = 'DCP-USR'): string {
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0').toUpperCase()).join('');
  return `${prefix}-${hex.slice(0, 4)}-${hex.slice(4, 8)}`;
}

/**
 * Accept only a Google Drive folder URL or a bare folder id. Returns null for
 * arbitrary text so callers cannot accidentally persist non-folder URLs.
 */
export function parseDriveFolderStrict(input: string): { folderId: string; cleanUrl: string } | null {
  const value = input.trim();
  if (!value) return null;

  if (/^[A-Za-z0-9_-]{10,}$/.test(value)) {
    return {
      folderId: value,
      cleanUrl: `https://drive.google.com/drive/folders/${value}`,
    };
  }

  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.hostname.toLowerCase() !== 'drive.google.com') return null;

    const match = url.pathname.match(/^\/drive\/folders\/([A-Za-z0-9_-]+)\/?$/);
    if (match?.[1]) {
      return { folderId: match[1], cleanUrl: url.toString() };
    }

    const id = url.searchParams.get('id');
    if (id && /^[A-Za-z0-9_-]{10,}$/.test(id)) {
      return { folderId: id, cleanUrl: url.toString() };
    }
  } catch {
    return null;
  }

  return null;
}
