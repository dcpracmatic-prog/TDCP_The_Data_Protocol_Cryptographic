/**
 * Admin auth modes: token (legacy), OIDC JWT, mTLS cert helper, oidc+mtls.
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Server } from 'node:http';
import { generateKeyPair, exportJWK, SignJWT, type JSONWebKeySet } from 'jose';
import { startAuthorityHttpServer } from '../../server/authority/http-server.ts';
import {
  checkMtlsClientCert,
  clearOidcJwksCache,
  extractBearerToken,
  isAdminPath,
  loadAdminAuthConfigFromEnv,
  readAdminAuthModeFromEnv,
  requireAdminAuth,
  verifyOidcAdminJwt,
  type ClientCertInfo,
} from '../../server/authority/admin-auth.ts';

describe('admin-auth helpers', () => {
  it('detects admin paths', () => {
    assert.equal(isAdminPath('POST', '/v1/documents/register'), true);
    assert.equal(isAdminPath('GET', '/v1/documents'), true);
    assert.equal(isAdminPath('POST', '/v1/revoke'), true);
    assert.equal(isAdminPath('POST', '/v1/restore'), true);
    assert.equal(isAdminPath('GET', '/v1/revoked'), true);
    assert.equal(isAdminPath('POST', '/v1/challenge'), false);
    assert.equal(isAdminPath('POST', '/v1/authorize'), false);
    assert.equal(isAdminPath('GET', '/v1/public-key'), false);
  });

  it('reads mode from env (default token)', () => {
    assert.equal(readAdminAuthModeFromEnv({}), 'token');
    assert.equal(readAdminAuthModeFromEnv({ TDCP_AUTHORITY_ADMIN_AUTH: 'oidc' }), 'oidc');
    assert.equal(readAdminAuthModeFromEnv({ TDCP_AUTHORITY_ADMIN_AUTH: 'MTLS' }), 'mtls');
    assert.equal(
      readAdminAuthModeFromEnv({ TDCP_AUTHORITY_ADMIN_AUTH: 'oidc+mtls' }),
      'oidc+mtls'
    );
    assert.throws(() => readAdminAuthModeFromEnv({ TDCP_AUTHORITY_ADMIN_AUTH: 'ldap' }));
  });

  it('disables static token when mode is not token', () => {
    const cfg = loadAdminAuthConfigFromEnv({
      TDCP_AUTHORITY_ADMIN_AUTH: 'oidc',
      TDCP_AUTHORITY_ADMIN_TOKEN: 'should-be-ignored',
      TDCP_OIDC_ISSUER: 'https://issuer.example',
      TDCP_OIDC_AUDIENCE: 'tdcp-authority',
    });
    assert.equal(cfg.mode, 'oidc');
    assert.equal(cfg.token, undefined);
    assert.equal(cfg.oidc?.issuer, 'https://issuer.example');
  });
});

describe('mTLS cert check helper', () => {
  it('rejects missing cert', () => {
    const r = checkMtlsClientCert(null);
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.error, 'MTLS_CLIENT_CERT_REQUIRED');
  });

  it('rejects unauthorized cert', () => {
    const info: ClientCertInfo = {
      authorized: false,
      authorizationError: 'DEPTH_ZERO_SELF_SIGNED_CERT',
      rawPresent: true,
      cn: 'evil',
    };
    const r = checkMtlsClientCert(info);
    assert.equal(r.ok, false);
    if (!r.ok) {
      assert.equal(r.status, 401);
      assert.match(r.error, /MTLS_UNAUTHORIZED/);
    }
  });

  it('accepts authorized cert without CN allowlist', () => {
    const info: ClientCertInfo = {
      authorized: true,
      rawPresent: true,
      cn: 'any-client',
    };
    const r = checkMtlsClientCert(info, {});
    assert.equal(r.ok, true);
  });

  it('enforces CN allowlist (403 when not listed)', () => {
    const info: ClientCertInfo = {
      authorized: true,
      rawPresent: true,
      cn: 'other',
    };
    const deny = checkMtlsClientCert(info, { allowedCns: ['tdcp-admin'] });
    assert.equal(deny.ok, false);
    if (!deny.ok) {
      assert.equal(deny.status, 403);
      assert.equal(deny.error, 'MTLS_CN_NOT_ALLOWED');
    }

    const ok = checkMtlsClientCert(
      { authorized: true, rawPresent: true, cn: 'tdcp-admin' },
      { allowedCns: ['tdcp-admin'] }
    );
    assert.equal(ok.ok, true);
  });

  it('matches SAN DNS names in allowlist', () => {
    const info: ClientCertInfo = {
      authorized: true,
      rawPresent: true,
      cn: 'unused',
      subjectAltNames: ['DNS:tdcp-admin.example'],
    };
    const r = checkMtlsClientCert(info, { allowedCns: ['tdcp-admin.example'] });
    assert.equal(r.ok, true);
  });
});

describe('OIDC JWT admin auth', () => {
  const issuer = 'https://oidc.test.tdcp';
  const audience = 'tdcp-authority-admin';
  let jwks: JSONWebKeySet;
  let privateKey: CryptoKey;

  before(async () => {
    clearOidcJwksCache();
    const { privateKey: pk, publicKey } = await generateKeyPair('RS256');
    privateKey = pk;
    const pub = await exportJWK(publicKey);
    pub.kid = 'test-kid-1';
    pub.alg = 'RS256';
    pub.use = 'sig';
    jwks = { keys: [pub] };
  });

  after(() => {
    clearOidcJwksCache();
  });

  async function mint(claims: Record<string, unknown>, opts?: { exp?: number }) {
    return new SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: 'test-kid-1' })
      .setIssuer(issuer)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime(opts?.exp ?? '5m')
      .sign(privateKey);
  }

  const oidcCfg = () => ({
    issuer,
    audience,
    adminClaim: 'tdcp_admin',
    localJwks: jwks,
  });

  it('rejects missing JWT', async () => {
    const r = await verifyOidcAdminJwt(undefined, oidcCfg());
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.error, 'OIDC_TOKEN_REQUIRED');
  });

  it('rejects invalid JWT', async () => {
    const r = await verifyOidcAdminJwt('not.a.jwt', oidcCfg());
    assert.equal(r.ok, false);
    if (!r.ok) {
      assert.equal(r.status, 401);
      assert.equal(r.error, 'OIDC_TOKEN_INVALID');
    }
  });

  it('rejects JWT without admin claim', async () => {
    const token = await mint({ sub: 'user-1' });
    const r = await verifyOidcAdminJwt(token, oidcCfg());
    assert.equal(r.ok, false);
    if (!r.ok) {
      assert.equal(r.status, 403);
      assert.equal(r.error, 'OIDC_ADMIN_CLAIM_MISSING');
    }
  });

  it('accepts JWT with tdcp_admin boolean claim', async () => {
    const token = await mint({ sub: 'admin-1', tdcp_admin: true });
    const r = await verifyOidcAdminJwt(token, oidcCfg());
    assert.equal(r.ok, true);
  });

  it('accepts JWT with admin role in roles array', async () => {
    const token = await mint({ sub: 'admin-2', roles: ['reader', 'tdcp_admin'] });
    const r = await verifyOidcAdminJwt(token, oidcCfg());
    assert.equal(r.ok, true);
  });

  it('accepts JWT with admin scope', async () => {
    const token = await mint({ sub: 'admin-3', scope: 'openid tdcp_admin' });
    const r = await verifyOidcAdminJwt(token, oidcCfg());
    assert.equal(r.ok, true);
  });

  it('rejects wrong audience', async () => {
    const token = await new SignJWT({ tdcp_admin: true })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-kid-1' })
      .setIssuer(issuer)
      .setAudience('wrong-aud')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);
    const r = await verifyOidcAdminJwt(token, oidcCfg());
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.error, 'OIDC_TOKEN_INVALID');
  });
});

describe('OIDC mode over HTTP admin routes', () => {
  let server: Server;
  let baseUrl: string;
  let dataDir: string;
  let adminJwt: string;
  let jwks: JSONWebKeySet;
  const issuer = 'https://oidc.http.tdcp';
  const audience = 'tdcp-http-admin';

  before(async () => {
    const { privateKey, publicKey } = await generateKeyPair('RS256');
    const pub = await exportJWK(publicKey);
    pub.kid = 'http-kid';
    pub.alg = 'RS256';
    jwks = { keys: [pub] };
    adminJwt = await new SignJWT({ tdcp_admin: true, sub: 'http-admin' })
      .setProtectedHeader({ alg: 'RS256', kid: 'http-kid' })
      .setIssuer(issuer)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime('10m')
      .sign(privateKey);

    dataDir = mkdtempSync(join(tmpdir(), 'tdcp-oidc-'));
    const started = await startAuthorityHttpServer({
      dataDir,
      host: '127.0.0.1',
      port: 0,
      tls: null,
      adminAuth: {
        mode: 'oidc',
        // Intentionally set a token that must NOT be accepted in oidc mode
        token: 'static-token-must-not-work',
        oidc: {
          issuer,
          audience,
          adminClaim: 'tdcp_admin',
          localJwks: jwks,
        },
      },
      rateLimit: { windowMs: 60_000, maxHits: 1000 },
    });
    server = started.server;
    const addr = server.address();
    if (!addr || typeof addr === 'string') throw new Error('no port');
    baseUrl = `http://127.0.0.1:${addr.port}`;
  });

  after(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
    rmSync(dataDir, { recursive: true, force: true });
  });

  it('rejects missing JWT with 401 OIDC_TOKEN_REQUIRED', async () => {
    const res = await fetch(`${baseUrl}/v1/documents`, { method: 'GET' });
    assert.equal(res.status, 401);
    const body = (await res.json()) as { error?: string };
    assert.equal(body.error, 'OIDC_TOKEN_REQUIRED');
  });

  it('rejects static Bearer admin token in oidc mode', async () => {
    const res = await fetch(`${baseUrl}/v1/documents`, {
      method: 'GET',
      headers: { authorization: 'Bearer static-token-must-not-work' },
    });
    assert.equal(res.status, 401);
    const body = (await res.json()) as { error?: string };
    assert.equal(body.error, 'OIDC_TOKEN_INVALID');
  });

  it('accepts valid OIDC admin JWT for register', async () => {
    const res = await fetch(`${baseUrl}/v1/documents/register`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${adminJwt}`,
      },
      body: JSON.stringify({
        documentId: 'DOC-OIDC-1',
        packageId: 'PKG-OIDC-1',
        policyLevel: 'STANDARD',
        allowExtraction: false,
        createdAt: Date.now(),
      }),
    });
    assert.equal(res.status, 200);
    const body = (await res.json()) as { wrapSecretBase64?: string };
    assert.ok(body.wrapSecretBase64);
  });

  it('keeps public challenge unauthenticated', async () => {
    const res = await fetch(`${baseUrl}/v1/challenge`, { method: 'POST' });
    assert.equal(res.status, 200);
  });
});

describe('token mode still works (regression)', () => {
  let server: Server;
  let baseUrl: string;
  let dataDir: string;
  const adminToken = 'token-mode-regression';

  before(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'tdcp-token-'));
    const started = await startAuthorityHttpServer({
      dataDir,
      host: '127.0.0.1',
      port: 0,
      adminAuth: { mode: 'token', token: adminToken },
    });
    server = started.server;
    const addr = server.address();
    if (!addr || typeof addr === 'string') throw new Error('no port');
    baseUrl = `http://127.0.0.1:${addr.port}`;
  });

  after(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
    rmSync(dataDir, { recursive: true, force: true });
  });

  it('Bearer token authorizes admin list', async () => {
    const deny = await fetch(`${baseUrl}/v1/documents`);
    assert.equal(deny.status, 401);

    const ok = await fetch(`${baseUrl}/v1/documents`, {
      headers: { authorization: `Bearer ${adminToken}` },
    });
    assert.equal(ok.status, 200);
  });

  it('legacy requireAdminAuth(req, tokenString) still works', async () => {
    const fakeReq = {
      headers: { authorization: `Bearer ${adminToken}` },
      socket: {},
    } as unknown as import('node:http').IncomingMessage;
    const r = await requireAdminAuth(fakeReq, adminToken);
    assert.equal(r.ok, true);
    assert.equal(extractBearerToken(fakeReq), adminToken);
  });
});

describe('mtls mode over plain HTTP rejects (no client cert)', () => {
  let server: Server;
  let baseUrl: string;
  let dataDir: string;

  before(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'tdcp-mtls-http-'));
    const started = await startAuthorityHttpServer({
      dataDir,
      host: '127.0.0.1',
      port: 0,
      tls: null,
      adminAuth: {
        mode: 'mtls',
        mtls: { allowedCns: ['tdcp-admin-dev'] },
      },
    });
    server = started.server;
    const addr = server.address();
    if (!addr || typeof addr === 'string') throw new Error('no port');
    baseUrl = `http://127.0.0.1:${addr.port}`;
  });

  after(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
    rmSync(dataDir, { recursive: true, force: true });
  });

  it('returns 401 MTLS_CLIENT_CERT_REQUIRED on admin routes without TLS', async () => {
    const res = await fetch(`${baseUrl}/v1/revoked`);
    assert.equal(res.status, 401);
    const body = (await res.json()) as { error?: string };
    assert.equal(body.error, 'MTLS_CLIENT_CERT_REQUIRED');
  });
});
