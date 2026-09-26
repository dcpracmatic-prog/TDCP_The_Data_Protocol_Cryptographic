/**
 * Minimal free client for a self-hosted Smart Token Prod HTTP API.
 * Does not vendor crypto; does not store master secrets.
 * See docs/CSG_SMART_TOKEN_BRIDGE.md.
 */

export type SmartTokenClientOptions = {
  /** Base URL of the Smart Token API (e.g. http://127.0.0.1:8000). */
  baseUrl: string;
  /** Bearer token matching SMART_TOKEN_API_KEY on the API process. */
  apiKey: string;
  /** Optional fetch implementation (defaults to global fetch). */
  fetchImpl?: typeof fetch;
};

export type SmartTokenHealth = {
  ok: boolean;
  storage_backend?: string;
  smart_token_available?: boolean;
};

export type SmartTokenProtectResult = {
  artifact_id: string;
  filename?: string | null;
  status: string;
};

export type SmartTokenOpenResult =
  | { ok: true; plaintext: ArrayBuffer; status: string }
  | { ok: false; status: number; body: string };

function joinUrl(base: string, path: string): string {
  const b = base.replace(/\/+$/, '');
  const p = path.startsWith('/') ? path : `/${path}`;
  return `${b}${p}`;
}

export class SmartTokenClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: SmartTokenClientOptions) {
    if (!options.baseUrl) {
      throw new Error('SmartTokenClient: baseUrl is required');
    }
    this.baseUrl = options.baseUrl;
    this.apiKey = options.apiKey ?? '';
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  private authHeaders(extra?: Record<string, string>): HeadersInit {
    const h: Record<string, string> = { ...(extra ?? {}) };
    if (this.apiKey) {
      h.Authorization = `Bearer ${this.apiKey}`;
    }
    return h;
  }

  async healthz(): Promise<SmartTokenHealth> {
    const res = await this.fetchImpl(joinUrl(this.baseUrl, '/healthz'));
    if (!res.ok) {
      throw new Error(`SmartToken healthz failed: HTTP ${res.status}`);
    }
    return (await res.json()) as SmartTokenHealth;
  }

  /**
   * Protect a file. Master is sent only in this request header and must not be
   * persisted by TDCP.
   */
  async protect(
    file: Blob | File,
    masterSecret: string,
    filename?: string
  ): Promise<SmartTokenProtectResult> {
    if (!masterSecret) {
      throw new Error('SmartTokenClient.protect: masterSecret is required');
    }
    const form = new FormData();
    form.append('file', file, filename ?? (file instanceof File ? file.name : 'artifact.bin'));

    const res = await this.fetchImpl(joinUrl(this.baseUrl, '/v1/artifacts'), {
      method: 'POST',
      headers: this.authHeaders({
        'X-Smart-Token-Master': masterSecret,
      }),
      body: form,
    });

    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`SmartToken protect failed: HTTP ${res.status} ${text}`);
    }
    return (await res.json()) as SmartTokenProtectResult;
  }

  /**
   * Open an artifact. Returns DENIED (ok: false) without throwing when the API
   * responds 403 with opaque body. Master is request-scoped only.
   */
  async open(artifactId: string, masterSecret: string): Promise<SmartTokenOpenResult> {
    if (!masterSecret) {
      throw new Error('SmartTokenClient.open: masterSecret is required');
    }
    const res = await this.fetchImpl(
      joinUrl(this.baseUrl, `/v1/artifacts/${encodeURIComponent(artifactId)}/open`),
      {
        method: 'POST',
        headers: this.authHeaders({
          'X-Smart-Token-Master': masterSecret,
        }),
      }
    );

    if (res.status === 403) {
      const body = await res.text().catch(() => 'DENIED');
      return { ok: false, status: 403, body };
    }
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`SmartToken open failed: HTTP ${res.status} ${text}`);
    }

    const status = res.headers.get('X-Smart-Token-Status') ?? 'OPEN';
    const plaintext = await res.arrayBuffer();
    return { ok: true, plaintext, status };
  }

  async friction(artifactId: string): Promise<unknown> {
    const res = await this.fetchImpl(
      joinUrl(this.baseUrl, `/v1/artifacts/${encodeURIComponent(artifactId)}/friction`),
      {
        method: 'GET',
        headers: this.authHeaders(),
      }
    );
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`SmartToken friction failed: HTTP ${res.status} ${text}`);
    }
    return res.json();
  }
}

/** Factory from environment (optional vars; empty key is allowed for healthz-only probes). */
export function smartTokenClientFromEnv(
  env: Record<string, string | undefined> = typeof process !== 'undefined' ? process.env : {}
): SmartTokenClient | null {
  const baseUrl = env.SMART_TOKEN_API_URL?.trim();
  if (!baseUrl) return null;
  return new SmartTokenClient({
    baseUrl,
    apiKey: env.SMART_TOKEN_API_KEY?.trim() ?? '',
  });
}
