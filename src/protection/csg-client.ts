/**
 * HTTP client for the CSG / Sello de Integridad sidecar (self-hosted).
 *
 * Talks to CSG_SEAL_URL (or VITE_CSG_SEAL_URL in the browser).
 * Produces seals compatible with server/csg-sidecar (Ed25519 + SHA3-256,
 * field names aligned with sello_integridad Rust crate).
 *
 * Never holds the CSG damage master; the sidecar owns Notario state.
 */

export interface CsgRemoteSeal {
  schema: string;
  evento_id: string;
  aceptado: boolean;
  razon: string;
  timestamp: number;
  hash_contenido: string;
  firmante_pub: string;
  sello_anterior: string;
  cuerpo_hash: string;
  firma_notario: string;
  label?: string;
  attributes?: Record<string, string>;
  notario_pub?: string;
  developmentOnly?: boolean;
}

export interface CsgVerifyReport {
  todo_valido: boolean;
  checks: {
    content_digest_match: boolean;
    cuerpo_no_alterado: boolean;
    firma_notario_valida: boolean;
    aceptado: boolean;
  };
  hash_contenido?: string;
  schema?: string;
}

export interface CsgClientOptions {
  baseUrl: string;
  fetchImpl?: typeof fetch;
}

function joinUrl(base: string, path: string): string {
  const b = base.replace(/\/+$/, '');
  const p = path.startsWith('/') ? path : `/${path}`;
  return `${b}${p}`;
}

function toBase64(buf: ArrayBuffer | Uint8Array): string {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]!);
  return btoa(s);
}

export class CsgClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: CsgClientOptions) {
    if (!opts.baseUrl?.trim()) {
      throw new Error('CsgClient: baseUrl is required');
    }
    this.baseUrl = opts.baseUrl.trim().replace(/\/+$/, '');
    this.fetchImpl = opts.fetchImpl ?? globalThis.fetch.bind(globalThis);
  }

  async healthz(): Promise<{ ok: boolean; service?: string; estructura_rota?: boolean }> {
    const res = await this.fetchImpl(joinUrl(this.baseUrl, '/healthz'));
    if (!res.ok) throw new Error(`CSG healthz failed: HTTP ${res.status}`);
    return (await res.json()) as { ok: boolean; service?: string; estructura_rota?: boolean };
  }

  async status(): Promise<Record<string, unknown>> {
    const res = await this.fetchImpl(joinUrl(this.baseUrl, '/v1/status'));
    if (!res.ok) throw new Error(`CSG status failed: HTTP ${res.status}`);
    return (await res.json()) as Record<string, unknown>;
  }

  /**
   * Seal content bytes via the remote Notario.
   * Returns a CSG sello document (JSON-serializable).
   */
  async seal(
    content: ArrayBuffer | Uint8Array,
    options?: {
      label?: string;
      attributes?: Record<string, string>;
      proyecto_id?: string;
      evento_id?: string;
    }
  ): Promise<CsgRemoteSeal> {
    const body = {
      content_base64: toBase64(content),
      label: options?.label ?? 'tdcp-integrity',
      attributes: options?.attributes ?? {},
      proyecto_id: options?.proyecto_id ?? 'tdcp',
      evento_id: options?.evento_id,
    };
    const res = await this.fetchImpl(joinUrl(this.baseUrl, '/v1/seal'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`CSG seal failed: HTTP ${res.status} ${text}`);
    }
    return (await res.json()) as CsgRemoteSeal;
  }

  async verify(
    content: ArrayBuffer | Uint8Array,
    sello: CsgRemoteSeal | Record<string, unknown>
  ): Promise<CsgVerifyReport> {
    const body = {
      content_base64: toBase64(content),
      sello,
    };
    const res = await this.fetchImpl(joinUrl(this.baseUrl, '/v1/verify'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`CSG verify failed: HTTP ${res.status} ${text}`);
    }
    return (await res.json()) as CsgVerifyReport;
  }
}

/**
 * Resolve CSG sidecar URL from Vite (browser) or Node env.
 * Returns null when unset (callers fall back to local development seal).
 */
export function readCsgApiConfig(): { baseUrl: string } | null {
  const env =
    typeof import.meta !== 'undefined'
      ? (import.meta as ImportMeta & { env?: Record<string, string> }).env
      : undefined;
  const fromVite = (env?.VITE_CSG_SEAL_URL || '').trim();
  const fromProcess =
    typeof process !== 'undefined' ? (process.env?.CSG_SEAL_URL || '').trim() : '';
  const baseUrl = fromVite || fromProcess;
  if (!baseUrl) return null;
  return { baseUrl };
}

export function csgClientFromEnv(): CsgClient | null {
  const cfg = readCsgApiConfig();
  if (!cfg) return null;
  return new CsgClient({ baseUrl: cfg.baseUrl });
}
