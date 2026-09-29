/**
 * TDCP account data (profile + Drive folders), persisted in Postgres/Supabase.
 *
 * Every handler runs behind `authMiddleware`, so `context.userId` is the
 * VERIFIED Better Auth session user — never a client-supplied id — and every
 * query is scoped by it.
 */
import { createServerFn } from '@tanstack/react-start';
import { z } from 'zod';
import { authMiddleware } from './auth/middleware.ts';
import {
  CUSTOM_ID_PATTERN,
  generateCustomUserId,
  parseDriveFolderStrict,
  type SharedDriveFolder,
} from './drive-folder.ts';

export interface AccountState {
  profile: { customId: string; createdAt: number } | null;
  folders: SharedDriveFolder[];
}

type FolderRow = {
  folder_id: string;
  name: string;
  link: string;
  description: string;
  is_default: boolean;
  added_at: string | Date;
};

async function sql() {
  const { getSql } = await import('./db.ts');
  return getSql();
}

async function loadAccount(userId: string): Promise<AccountState> {
  const db = await sql();
  const profiles = await db<{ custom_id: string; created_at: string | Date }>`
    select custom_id, created_at from tdcp_profile where user_id = ${userId}`;
  const rows = await db<FolderRow>`
    select folder_id, name, link, description, is_default, added_at
      from tdcp_drive_folder where user_id = ${userId}
      order by is_default desc, added_at asc`;
  return {
    profile: profiles[0]
      ? { customId: profiles[0].custom_id, createdAt: new Date(profiles[0].created_at).getTime() }
      : null,
    folders: rows.map((r) => ({
      id: r.folder_id,
      name: r.name,
      link: r.link,
      description: r.description,
      isDefault: r.is_default,
      addedAt: new Date(r.added_at).getTime(),
    })),
  };
}

async function makeDefault(userId: string, folderId: string): Promise<void> {
  const db = await sql();
  await db`update tdcp_drive_folder set is_default = false where user_id = ${userId} and is_default`;
  await db`update tdcp_drive_folder set is_default = true where user_id = ${userId} and folder_id = ${folderId}`;
}

function requireFolder(linkOrId: string) {
  const parsed = parseDriveFolderStrict(linkOrId);
  if (!parsed) throw new Error('El enlace o ID de la carpeta de Google Drive no es válido.');
  return parsed;
}

const text = (max: number) => z.string().trim().max(max);

export const getAccount = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .handler(async ({ context }) => loadAccount(context.userId));

export const createProfile = createServerFn({ method: 'POST' })
  .middleware([authMiddleware])
  .validator(z.object({ customId: text(40).optional(), driveFolderLink: text(500).optional() }))
  .handler(async ({ context, data }) => {
    const db = await sql();
    const existing = await db`select 1 from tdcp_profile where user_id = ${context.userId}`;
    if (existing.length) return loadAccount(context.userId);

    const customId = (data.customId || generateCustomUserId()).toUpperCase();
    if (!CUSTOM_ID_PATTERN.test(customId)) {
      throw new Error('El ID de usuario solo admite A-Z, 0-9 y guiones (4 a 40 caracteres).');
    }
    const taken = await db`select 1 from tdcp_profile where custom_id = ${customId}`;
    if (taken.length) {
      throw new Error(`El ID de usuario "${customId}" ya está en uso. Elige otro o genera uno nuevo.`);
    }
    await db`insert into tdcp_profile (user_id, custom_id) values (${context.userId}, ${customId})`;

    if (data.driveFolderLink) {
      const { folderId, cleanUrl } = requireFolder(data.driveFolderLink);
      await db`insert into tdcp_drive_folder (user_id, folder_id, name, link, description, is_default)
               values (${context.userId}, ${folderId}, 'Carpeta Principal', ${cleanUrl},
                       'Carpeta predeterminada asignada en el registro', true)`;
    }
    return loadAccount(context.userId);
  });

export const addDriveFolder = createServerFn({ method: 'POST' })
  .middleware([authMiddleware])
  .validator(
    z.object({
      name: text(120).optional(),
      linkOrId: text(500),
      description: text(500).optional(),
      isDefault: z.boolean().optional(),
    }),
  )
  .handler(async ({ context, data }) => {
    const db = await sql();
    const { folderId, cleanUrl } = requireFolder(data.linkOrId);
    const count = await db<{ n: number }>`
      select count(*)::int as n from tdcp_drive_folder where user_id = ${context.userId}`;
    if ((count[0]?.n ?? 0) >= 50) throw new Error('Límite de 50 carpetas alcanzado.');
    const dup = await db`select 1 from tdcp_drive_folder where user_id = ${context.userId} and folder_id = ${folderId}`;
    if (dup.length) throw new Error('Esta carpeta de Google Drive ya está agregada en tu lista.');

    await db`insert into tdcp_drive_folder (user_id, folder_id, name, link, description, is_default)
             values (${context.userId}, ${folderId}, ${data.name || 'Carpeta Compartida'}, ${cleanUrl},
                     ${data.description || ''}, false)`;
    if (data.isDefault || (count[0]?.n ?? 0) === 0) await makeDefault(context.userId, folderId);
    return loadAccount(context.userId);
  });

export const editDriveFolder = createServerFn({ method: 'POST' })
  .middleware([authMiddleware])
  .validator(
    z.object({
      folderId: text(200),
      name: text(120).optional(),
      linkOrId: text(500).optional(),
      description: text(500).optional(),
      isDefault: z.boolean().optional(),
    }),
  )
  .handler(async ({ context, data }) => {
    const db = await sql();
    const current = await db<FolderRow>`
      select folder_id, name, link, description, is_default, added_at
        from tdcp_drive_folder where user_id = ${context.userId} and folder_id = ${data.folderId}`;
    if (!current[0]) throw new Error('Carpeta no encontrada en tu lista.');

    let newId = data.folderId;
    let newLink = current[0].link;
    if (data.linkOrId) {
      const parsed = requireFolder(data.linkOrId);
      newId = parsed.folderId;
      newLink = parsed.cleanUrl;
      if (newId !== data.folderId) {
        const dup = await db`select 1 from tdcp_drive_folder where user_id = ${context.userId} and folder_id = ${newId}`;
        if (dup.length) throw new Error('Esa carpeta ya está en tu lista.');
      }
    }
    await db`update tdcp_drive_folder
                set folder_id = ${newId},
                    name = ${data.name || current[0].name},
                    link = ${newLink},
                    description = ${data.description ?? current[0].description}
              where user_id = ${context.userId} and folder_id = ${data.folderId}`;
    if (data.isDefault) await makeDefault(context.userId, newId);
    return loadAccount(context.userId);
  });

export const deleteDriveFolder = createServerFn({ method: 'POST' })
  .middleware([authMiddleware])
  .validator(z.object({ folderId: text(200) }))
  .handler(async ({ context, data }) => {
    const db = await sql();
    const all = await db<{ folder_id: string; is_default: boolean }>`
      select folder_id, is_default from tdcp_drive_folder
       where user_id = ${context.userId} order by added_at asc`;
    const target = all.find((f) => f.folder_id === data.folderId);
    if (!target) throw new Error('Carpeta no encontrada.');
    if (all.length <= 1) throw new Error('Debes mantener al menos una carpeta de destino en tu cuenta.');
    await db`delete from tdcp_drive_folder where user_id = ${context.userId} and folder_id = ${data.folderId}`;
    if (target.is_default) {
      const next = all.find((f) => f.folder_id !== data.folderId);
      if (next) await makeDefault(context.userId, next.folder_id);
    }
    return loadAccount(context.userId);
  });

export const setDefaultDriveFolder = createServerFn({ method: 'POST' })
  .middleware([authMiddleware])
  .validator(z.object({ folderId: text(200) }))
  .handler(async ({ context, data }) => {
    const db = await sql();
    const exists = await db`select 1 from tdcp_drive_folder where user_id = ${context.userId} and folder_id = ${data.folderId}`;
    if (!exists.length) throw new Error('Carpeta no encontrada.');
    await makeDefault(context.userId, data.folderId);
    return loadAccount(context.userId);
  });

/** Upsert used by the Google Drive picker ("use this folder as default"). */
export const upsertDefaultDriveFolder = createServerFn({ method: 'POST' })
  .middleware([authMiddleware])
  .validator(z.object({ linkOrId: text(500), name: text(120).optional() }))
  .handler(async ({ context, data }) => {
    const db = await sql();
    const { folderId, cleanUrl } = requireFolder(data.linkOrId);
    const exists = await db`select 1 from tdcp_drive_folder where user_id = ${context.userId} and folder_id = ${folderId}`;
    if (exists.length) {
      await db`update tdcp_drive_folder set link = ${cleanUrl}, name = coalesce(${data.name ?? null}, name)
                where user_id = ${context.userId} and folder_id = ${folderId}`;
    } else {
      await db`insert into tdcp_drive_folder (user_id, folder_id, name, link)
               values (${context.userId}, ${folderId}, ${data.name || 'Carpeta Compartida'}, ${cleanUrl})`;
    }
    await makeDefault(context.userId, folderId);
    return loadAccount(context.userId);
  });

// ── Sharing: resolve recipients for the Authority ACL ──────────────────────────
// Documents are shared by email or TDCP id (DCP-USR-…). The Authority only
// stores opaque user ids, so the issuer resolves them here. Recipients must
// already have an account. Capped at 25 per call to limit account probing.

export interface ShareRecipient {
  input: string;
  userId: string;
  label: string;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export const resolveShareRecipients = createServerFn({ method: 'POST' })
  .middleware([authMiddleware])
  .validator(z.object({ recipients: z.array(text(254)).max(25) }))
  .handler(async ({ data, context }) => {
    const db = await sql();
    // With a real mailer (production), only VERIFIED emails can be targeted, so
    // nobody can pre-register someone else's address to receive their documents.
    const { mailerConfigured } = await import('./auth/mailer.server.ts');
    const requireVerified = mailerConfigured();
    const resolved: ShareRecipient[] = [];
    const notFound: string[] = [];
    const seen = new Set<string>();
    for (const raw of data.recipients) {
      const input = raw.trim();
      if (!input) continue;
      let row: { id: string; email: string } | undefined;
      if (EMAIL_RE.test(input)) {
        const rows = await db<{ id: string; email: string }>`
          select id, email from "user"
           where lower(email) = ${input.toLowerCase()}
             and ("emailVerified" = true or ${!requireVerified})
           limit 1`;
        row = rows[0];
      } else if (CUSTOM_ID_PATTERN.test(input.toUpperCase())) {
        const rows = await db<{ id: string; email: string }>`
          select u.id, u.email from tdcp_profile p join "user" u on u.id = p.user_id
           where p.custom_id = ${input.toUpperCase()} limit 1`;
        row = rows[0];
      }
      if (!row) {
        notFound.push(input);
        continue;
      }
      if (row.id === context.userId || seen.has(row.id)) continue;
      seen.add(row.id);
      resolved.push({ input, userId: row.id, label: row.email });
    }
    return { resolved, notFound };
  });
