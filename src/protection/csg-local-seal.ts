/**
 * Local CSG-compatible integrity seal (browser / free tier).
 *
 * This is NOT the full Rust NotarioProtegido crate. It produces a portable
 * seal document (digest + ECDSA-P256 signature) that can be verified offline.
 * When a CSG_SEAL_URL sidecar exists, callers may swap to remote sealing.
 */

export interface CsgLocalSeal {
  schema: 'tdcp.csg-local.v1';
  sealId: string;
  algorithm: 'ECDSA-P256-SHA256';
  contentDigest: string;
  contentDigestAlg: 'SHA-256';
  label: string;
  createdAt: number;
  /** SPKI public key base64 (verify). */
  publicKeySpkiBase64: string;
  /** DER signature base64. */
  signatureBase64: string;
  /** Optional attached metadata (artifact ids, modes). */
  attributes: Record<string, string>;
  developmentOnly: true;
  note: string;
}

function b64(buf: ArrayBuffer | Uint8Array): string {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]!);
  return btoa(s);
}

function fromB64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function sha256Hex(data: ArrayBuffer | Uint8Array): Promise<string> {
  const u8 = data instanceof Uint8Array ? data : new Uint8Array(data);
  const dig = await crypto.subtle.digest('SHA-256', u8.buffer as ArrayBuffer);
  return [...new Uint8Array(dig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Canonical bytes signed: digest || label || createdAt || sorted attrs */
function canonicalToSign(
  contentDigest: string,
  label: string,
  createdAt: number,
  attributes: Record<string, string>
): Uint8Array {
  const keys = Object.keys(attributes).sort();
  const attrStr = keys.map((k) => `${k}=${attributes[k]}`).join('&');
  return new TextEncoder().encode(`${contentDigest}|${label}|${createdAt}|${attrStr}`);
}

export async function createLocalCsgSeal(
  content: ArrayBuffer | Uint8Array,
  options?: {
    label?: string;
    attributes?: Record<string, string>;
  }
): Promise<CsgLocalSeal> {
  const label = options?.label ?? 'tdcp-integrity';
  const attributes = options?.attributes ?? {};
  const contentDigest = await sha256Hex(content);
  const createdAt = Date.now();
  const sealId = `csg-local-${createdAt.toString(16)}-${contentDigest.slice(0, 8)}`;

  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  const spki = await crypto.subtle.exportKey('spki', keyPair.publicKey);
  const toSign = canonicalToSign(contentDigest, label, createdAt, attributes);
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    keyPair.privateKey,
    toSign.buffer as ArrayBuffer
  );

  return {
    schema: 'tdcp.csg-local.v1',
    sealId,
    algorithm: 'ECDSA-P256-SHA256',
    contentDigest,
    contentDigestAlg: 'SHA-256',
    label,
    createdAt,
    publicKeySpkiBase64: b64(spki),
    signatureBase64: b64(signature),
    attributes,
    developmentOnly: true,
    note: 'Local CSG-compatible seal. Replace with CSG NotarioProtegido sidecar for production conatus/damage_log.',
  };
}

export async function verifyLocalCsgSeal(
  content: ArrayBuffer | Uint8Array,
  seal: CsgLocalSeal
): Promise<{ valid: boolean; reason: string }> {
  if (seal.schema !== 'tdcp.csg-local.v1') {
    return { valid: false, reason: 'UNSUPPORTED_SCHEMA' };
  }
  const digest = await sha256Hex(content);
  if (digest !== seal.contentDigest) {
    return { valid: false, reason: 'CONTENT_DIGEST_MISMATCH' };
  }
  try {
    const spki = fromB64(seal.publicKeySpkiBase64);
    const key = await crypto.subtle.importKey(
      'spki',
      spki.buffer as ArrayBuffer,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    const toSign = canonicalToSign(seal.contentDigest, seal.label, seal.createdAt, seal.attributes);
    const sig = fromB64(seal.signatureBase64);
    const ok = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      sig.buffer as ArrayBuffer,
      toSign.buffer as ArrayBuffer
    );
    return ok ? { valid: true, reason: 'OK' } : { valid: false, reason: 'SIGNATURE_INVALID' };
  } catch {
    return { valid: false, reason: 'VERIFY_ERROR' };
  }
}
