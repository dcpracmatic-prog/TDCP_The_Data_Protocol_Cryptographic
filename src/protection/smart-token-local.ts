/**
 * Smart Token configuration for TDCP (pre-production).
 *
 * Smart Token Prod lives in a separate repository and runs as an isolated HTTP API.
 * TDCP never vendors its crypto core and never stores the master secret.
 *
 * Required browser env (Vercel / Vite):
 *   VITE_SMART_TOKEN_API_URL  — trusted base URL of the API (no trailing slash)
 *   VITE_SMART_TOKEN_API_KEY  — Bearer matching SMART_TOKEN_API_KEY on the API
 *
 * Soft/demo AES path has been removed for pre-production.
 */

import { SmartTokenClient } from '../../sdk/typescript/src/smart-token-client.ts';

export type SmartTokenApiConfig = {
  baseUrl: string;
  apiKey: string;
};

function readViteEnv(): Record<string, string | undefined> {
  if (typeof import.meta === 'undefined') return {};
  return (import.meta as ImportMeta & { env?: Record<string, string> }).env ?? {};
}

/**
 * Resolve the trusted Smart Token API from the app build env.
 * Returns null if not configured — STP modes must fail closed.
 */
export function readSmartTokenApiConfig(): SmartTokenApiConfig | null {
  const env = readViteEnv();
  const baseUrl = (env.VITE_SMART_TOKEN_API_URL || env.SMART_TOKEN_API_URL || '').trim();
  if (!baseUrl) return null;
  return {
    baseUrl: baseUrl.replace(/\/+$/, ''),
    apiKey: (env.VITE_SMART_TOKEN_API_KEY || env.SMART_TOKEN_API_KEY || '').trim(),
  };
}

/** Pre-production: soft path is disabled. Always false. */
export function allowSoftSmartToken(): boolean {
  return false;
}

/**
 * Construct a client for the configured API, or throw a clear pre-prod error.
 */
export function requireSmartTokenClient(): SmartTokenClient {
  const cfg = readSmartTokenApiConfig();
  if (!cfg) {
    throw new Error(
      'Smart Token no está configurado. Defina VITE_SMART_TOKEN_API_URL y VITE_SMART_TOKEN_API_KEY ' +
        'apuntando al servicio Smart-Token-Prod (repo aislado). Configure VITE_SMART_TOKEN_API_URL y VITE_SMART_TOKEN_API_KEY.'
    );
  }
  if (!cfg.apiKey) {
    throw new Error(
      'VITE_SMART_TOKEN_API_KEY está vacío. El API exige Authorization: Bearer <SMART_TOKEN_API_KEY>.'
    );
  }
  return new SmartTokenClient({
    baseUrl: cfg.baseUrl,
    apiKey: cfg.apiKey,
    fetchImpl: globalThis.fetch.bind(globalThis),
  });
}

/** Non-throwing probe for UI status chips. */
export async function probeSmartTokenHealth(): Promise<{
  configured: boolean;
  reachable: boolean;
  smartTokenAvailable?: boolean;
  storageBackend?: string;
  baseUrl?: string;
  error?: string;
}> {
  const cfg = readSmartTokenApiConfig();
  if (!cfg) {
    return { configured: false, reachable: false, error: 'VITE_SMART_TOKEN_API_URL no configurada' };
  }
  try {
    const client = new SmartTokenClient({
      baseUrl: cfg.baseUrl,
      apiKey: cfg.apiKey,
      fetchImpl: globalThis.fetch.bind(globalThis),
    });
    const health = await client.healthz();
    return {
      configured: true,
      reachable: true,
      smartTokenAvailable: health.smart_token_available,
      storageBackend: health.storage_backend,
      baseUrl: cfg.baseUrl,
    };
  } catch (err: unknown) {
    return {
      configured: true,
      reachable: false,
      baseUrl: cfg.baseUrl,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
