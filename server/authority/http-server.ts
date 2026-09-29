/**
 * Node HTTP(S) Authorization Authority service.
 *
 * Public (Gatekeeper): challenge, authorize, wrap-secret release, policy/revocation get, public-key
 * Admin (token | OIDC JWT | mTLS | oidc+mtls): register, revoke, restore, list documents/revoked
 * Ops: /health, /ready, /metrics
 *
 * HONESTY: Durable file store + WebCrypto ECDSA is an MVP stub, not HSM.
 * Admin auth hardening is not a full enterprise IdP product — see docs/ADMIN_AUTH.md.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import type { TlsOptions } from 'node:tls';
import { arrayBufferToBase64 } from '../../src/core/crypto/primitives.ts';
import { DocumentAlreadyRegisteredError, DurableAuthorityService } from './service.ts';
import {
  USER_TOKEN_HEADER,
  createUserTokenVerifier,
  loadUserAuthConfigFromEnv,
  type UserAuthConfig,
  type VerifiedUser,
} from './user-auth.ts';
import type { RegisteredDocumentPolicy } from '../../src/oracle/authorization-oracle.ts';
import { UsbHsmError, type UsbHsmConfig } from './usb-hsm.ts';
import { usbHsmChallenge } from '../../src/core/authorization/usb-hsm.ts';
import {
  isAdminPath,
  requireAdminAuth,
  loadAdminAuthConfigFromEnv,
  type AdminAuthConfig,
} from './admin-auth.ts';
import { buildTlsOptions, readTlsEnv } from './tls-options.ts';
import { clientKey, createAuthorityRateLimiter } from './rate-limit.ts';
import { AuthorityMetrics } from './metrics.ts';
import { logRequest } from './request-log.ts';

/**
 * CORS. With TDCP_CORS_ORIGINS set (comma-separated), only those origins are
 * reflected; otherwise the MVP behavior (reflect any origin) is kept.
 * Never uses credentials: auth travels in explicit headers, not cookies.
 */
const corsAllowList = (process.env.TDCP_CORS_ORIGINS || '')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

function corsHeaders(req: IncomingMessage): Record<string, string> {
  const origin = req.headers.origin || '*';
  let allowOrigin = origin === 'null' ? '*' : origin;
  if (corsAllowList.length > 0) {
    allowOrigin = corsAllowList.includes(origin) ? origin : corsAllowList[0];
  }
  return {
    'access-control-allow-origin': allowOrigin,
    'access-control-allow-methods': 'GET, POST, OPTIONS',
    'access-control-allow-headers': `content-type, authorization, ${USER_TOKEN_HEADER}`,
    'access-control-max-age': '86400',
    vary: 'Origin',
  };
}

function sendJson(res: ServerResponse, status: number, body: unknown, req?: IncomingMessage): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    ...(req ? corsHeaders(req) : {}),
  });
  res.end(payload);
}

function sendText(
  res: ServerResponse,
  status: number,
  body: string,
  contentType: string,
  req?: IncomingMessage
): void {
  res.writeHead(status, {
    'content-type': contentType,
    'cache-control': 'no-store',
    ...(req ? corsHeaders(req) : {}),
  });
  res.end(body);
}

class HttpError extends Error {
  public readonly status: number;
  public readonly code: string;
  constructor(status: number, code: string) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

const MAX_BODY_BYTES = 256 * 1024;

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buf.byteLength;
    if (size > MAX_BODY_BYTES) throw new HttpError(413, 'PAYLOAD_TOO_LARGE');
    chunks.push(buf);
  }
  if (chunks.length === 0) return null;
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new HttpError(400, 'BAD_JSON');
  }
}

/** Public view of a policy: the ACL is only visible to its owner. */
function redactPolicy(policy: RegisteredDocumentPolicy, userId: string | undefined) {
  if (policy.ownerUserId && policy.ownerUserId === userId) return policy;
  const { allowedUserIds: _acl, ownerUserId, ...rest } = policy;
  void _acl;
  return { ...rest, hasOwner: Boolean(ownerUserId), isOwner: false };
}

function matchPath(url: string, pattern: RegExp): RegExpMatchArray | null {
  const path = url.split('?')[0] || '/';
  return path.match(pattern);
}

function requestPath(url: string): string {
  return url.split('?')[0] || '/';
}

function isRateLimitedPath(method: string, path: string): boolean {
  if (method === 'POST' && /^\/v1\/challenge\/?$/.test(path)) return true;
  if (method === 'POST' && /^\/v1\/challenge\/validate\/?$/.test(path)) return true;
  if (method === 'POST' && /^\/v1\/authorize\/?$/.test(path)) return true;
  if (method === 'POST' && /^\/v1\/documents\/?$/.test(path)) return true;
  if (method === 'POST' && /^\/v1\/documents\/[^/]+\/(acl|revoke|restore)\/?$/.test(path)) return true;
  if (method === 'POST' && /^\/v1\/me\/usb-hsm(\/.*)?$/.test(path)) return true;
  return false;
}

export interface AuthorityHttpServerOptions {
  port?: number;
  host?: string;
  dataDir: string;
  service?: DurableAuthorityService;
  /** @deprecated Prefer adminAuth. Kept for existing tests (token mode). */
  adminToken?: string;
  /** Full admin auth config. If omitted, loaded from env (or token-mode from adminToken). */
  adminAuth?: AdminAuthConfig;
  /** TLS options; if set, serves HTTPS. Built from env when omitted and cert files present. */
  tls?: TlsOptions | null;
  rateLimit?: { windowMs?: number; maxHits?: number };
  metrics?: AuthorityMetrics;
  /** End-user auth for Gatekeeper endpoints. Loaded from env when omitted. */
  userAuth?: UserAuthConfig;
  /** WebAuthn RP config for USB-HSM. Loaded from env when omitted. */
  usbHsm?: UsbHsmConfig;
}

/** Paths that need a verified end user when TDCP_USER_AUTH=required. */
function isUserPath(method: string, path: string): boolean {
  if (method === 'POST' && /^\/v1\/challenge\/?$/.test(path)) return true;
  if (method === 'POST' && /^\/v1\/authorize\/?$/.test(path)) return true;
  if (method === 'POST' && /^\/v1\/wrap-secret\/release\/?$/.test(path)) return true;
  if (method === 'POST' && /^\/v1\/view-once\/commit\/?$/.test(path)) return true;
  if (method === 'POST' && /^\/v1\/documents\/?$/.test(path)) return true;
  if (method === 'GET' && /^\/v1\/me\/documents\/?$/.test(path)) return true;
  if (method === 'POST' && /^\/v1\/documents\/[^/]+\/(acl|revoke|restore)\/?$/.test(path)) return true;
  if (/^\/v1\/me\/usb-hsm(\/.*)?$/.test(path)) return true;
  return false;
}

export async function startAuthorityHttpServer(options: AuthorityHttpServerOptions) {
  const userAuthConfig = options.userAuth ?? loadUserAuthConfigFromEnv();
  const userAuth = createUserTokenVerifier(userAuthConfig);
  const service =
    options.service ??
    new DurableAuthorityService({
      dataDir: options.dataDir,
      requireSubject: userAuth.mode === 'required',
      usbHsm: options.usbHsm,
    });
  await service.initialize();
  if (userAuth.mode === 'required' && !service.isSubjectRequired()) {
    throw new Error('TDCP_USER_AUTH=required but the injected service does not require a subject');
  }
  if (userAuth.mode !== 'required') {
    console.warn(
      '[tdcp-authority] TDCP_USER_AUTH=off: Gatekeeper endpoints are anonymous. ' +
        'Set TDCP_USER_AUTH=required + TDCP_USER_JWKS_URL in production.'
    );
  }

  const host = options.host ?? '0.0.0.0';
  const port = options.port ?? Number(process.env.TDCP_AUTHORITY_PORT || 8787);

  let adminAuth: AdminAuthConfig;
  if (options.adminAuth) {
    adminAuth = options.adminAuth;
  } else if (options.adminToken !== undefined) {
    adminAuth = { mode: 'token', token: options.adminToken };
  } else {
    adminAuth = loadAdminAuthConfigFromEnv();
  }

  let tls: TlsOptions | null | undefined = options.tls;
  if (tls === undefined) {
    try {
      tls = buildTlsOptions(readTlsEnv(process.env as Record<string, string | undefined>, adminAuth.mode));
    } catch (err) {
      // Fail loudly at listen time for misconfigured TLS in production modes
      if (adminAuth.mode === 'mtls' || adminAuth.mode === 'oidc+mtls') {
        throw err;
      }
      console.warn(
        `[tdcp-authority] TLS config skipped: ${err instanceof Error ? err.message : String(err)}`
      );
      tls = null;
    }
  }

  const metrics = options.metrics ?? new AuthorityMetrics();
  const limiter = createAuthorityRateLimiter({
    windowMs:
      options.rateLimit?.windowMs ??
      Number(process.env.TDCP_AUTHORITY_RATE_WINDOW_MS || 60_000),
    maxHits:
      options.rateLimit?.maxHits ?? Number(process.env.TDCP_AUTHORITY_RATE_MAX || 120),
    dataDir: options.dataDir,
  });

  const handler = async (req: IncomingMessage, res: ServerResponse) => {
    const started = Date.now();
    const method = req.method || 'GET';
    const url = req.url || '/';
    const path = requestPath(url);
    const client = clientKey(req);
    metrics.httpRequests += 1;

    const finish = (status: number, errorCode?: string) => {
      logRequest({
        ts: new Date().toISOString(),
        level: status >= 500 ? 'error' : status >= 400 ? 'warn' : 'info',
        msg: 'request',
        method,
        path,
        status,
        durationMs: Date.now() - started,
        client,
        errorCode,
      });
    };

    try {
      if (method === 'OPTIONS') {
        res.writeHead(204, {
          ...corsHeaders(req),
          'content-length': '0',
        });
        res.end();
        finish(204);
        return;
      }

      if (method === 'GET' && (path === '/health' || path === '/healthz')) {
        sendJson(
          res,
          200,
          {
            ok: true,
            service: 'tdcp-authority',
            developmentOnly: true,
            adminAuthMode: adminAuth.mode,
            userAuthMode: userAuth.mode,
            tls: Boolean(tls),
            mvp: true,
          },
          req
        );
        finish(200);
        return;
      }

      if (method === 'GET' && (path === '/ready' || path === '/readyz')) {
        const readiness = service.getReadiness();
        const status = readiness.ready ? 200 : 503;
        sendJson(
          res,
          status,
          {
            ...readiness,
            service: 'tdcp-authority',
            adminAuthMode: adminAuth.mode,
          },
          req
        );
        finish(status, readiness.ready ? undefined : 'NOT_READY');
        return;
      }

      if (method === 'GET' && path === '/metrics') {
        sendText(
          res,
          200,
          metrics.renderPrometheus(),
          'text/plain; version=0.0.4; charset=utf-8',
          req
        );
        finish(200);
        return;
      }

      if (isAdminPath(method, path)) {
        const auth = await requireAdminAuth(req, adminAuth);
        if (!auth.ok) {
          metrics.adminUnauthorized += 1;
          sendJson(res, auth.status, { error: auth.error }, req);
          finish(auth.status, auth.error);
          return;
        }
      }

      let user: VerifiedUser | null = null;
      if (isUserPath(method, path)) {
        const ua = await userAuth.authenticate(req);
        if (!ua.ok) {
          sendJson(res, ua.status, { error: ua.error, rejectionCode: ua.error }, req);
          finish(ua.status, ua.error);
          return;
        }
        user = ua.user;
      } else if (userAuth.mode === 'required' && req.headers[USER_TOKEN_HEADER]) {
        // Optional identity on read endpoints (policy ACL visibility).
        const ua = await userAuth.authenticate(req);
        if (ua.ok) user = ua.user;
      }

      if (isRateLimitedPath(method, path)) {
        const rl = await Promise.resolve(
          limiter.check(user ? `usr:${user.userId}` : `pub:${client}`)
        );
        if (!rl.allowed) {
          metrics.rateLimited += 1;
          res.writeHead(429, {
            'content-type': 'application/json; charset=utf-8',
            'retry-after': String(Math.ceil(rl.retryAfterMs / 1000) || 1),
            'cache-control': 'no-store',
            ...corsHeaders(req),
          });
          res.end(JSON.stringify({ error: 'RATE_LIMITED', retryAfterMs: rl.retryAfterMs }));
          finish(429, 'RATE_LIMITED');
          return;
        }
      }

      if (method === 'GET' && /^\/v1\/public-key\/?$/.test(path)) {
        sendJson(res, 200, await service.getPublicInfo(), req);
        finish(200);
        return;
      }

      if (method === 'POST' && /^\/v1\/challenge\/validate\/?$/.test(path)) {
        const body = (await readJson(req)) as { challenge?: string };
        const valid = await service.isValidChallenge(body?.challenge || '');
        sendJson(res, 200, { valid }, req);
        finish(200);
        return;
      }

      if (method === 'POST' && matchPath(url, /^\/v1\/challenge\/?$/)) {
        const challenge = await service.issueChallenge(user?.userId);
        sendJson(res, 200, { challenge }, req);
        finish(200);
        return;
      }

      if (method === 'POST' && /^\/v1\/documents\/register\/?$/.test(path)) {
        const policy = (await readJson(req)) as Parameters<
          DurableAuthorityService['registerDocumentPolicy']
        >[0];
        const secret = await service.registerDocumentPolicy(policy);
        sendJson(res, 200, { wrapSecretBase64: arrayBufferToBase64(secret) }, req);
        finish(200);
        return;
      }

      // User-owned registration: owner = verified caller.
      if (method === 'POST' && /^\/v1\/documents\/?$/.test(path)) {
        if (!user) {
          sendJson(res, 403, { error: 'USER_AUTH_DISABLED' }, req);
          finish(403, 'USER_AUTH_DISABLED');
          return;
        }
        const policy = (await readJson(req)) as RegisteredDocumentPolicy;
        const secret = await service.registerOwnedDocument(policy, user.userId);
        sendJson(res, 200, { wrapSecretBase64: arrayBufferToBase64(secret) }, req);
        finish(200);
        return;
      }

      // ── USB-HSM: enroll / list / lifecycle (owner-scoped) ──────────────────
      if (/^\/v1\/me\/usb-hsm(\/.*)?$/.test(path)) {
        if (!user) {
          sendJson(res, 403, { error: 'USER_AUTH_DISABLED' }, req);
          finish(403, 'USER_AUTH_DISABLED');
          return;
        }
        const registry = service.getUsbHsm();
        if (method === 'GET' && /^\/v1\/me\/usb-hsm\/?$/.test(path)) {
          sendJson(res, 200, { devices: registry.listForUser(user.userId) }, req);
          finish(200);
          return;
        }
        if (method === 'POST' && /^\/v1\/me\/usb-hsm\/registration-options\/?$/.test(path)) {
          const body = ((await readJson(req)) ?? {}) as { label?: string; replaceDeviceId?: string };
          const options = await registry.registrationOptions(user, {
            label: typeof body.label === 'string' ? body.label : undefined,
            replaceDeviceId: typeof body.replaceDeviceId === 'string' ? body.replaceDeviceId : undefined,
          });
          sendJson(res, 200, options, req);
          finish(200);
          return;
        }
        if (method === 'POST' && /^\/v1\/me\/usb-hsm\/register\/?$/.test(path)) {
          const body = (await readJson(req)) as { response?: unknown };
          if (!body?.response) throw new HttpError(400, 'BAD_REQUEST');
          const device = await registry.completeRegistration(
            user.userId,
            body.response as Parameters<typeof registry.completeRegistration>[1]
          );
          sendJson(res, 200, device, req);
          finish(200);
          return;
        }
        if (method === 'POST' && /^\/v1\/me\/usb-hsm\/authentication-options\/?$/.test(path)) {
          sendJson(res, 200, {
            rpId: registry.config.rpId,
            allowCredentials: registry.allowCredentials(user.userId),
          }, req);
          finish(200);
          return;
        }
        const m = matchPath(url, /^\/v1\/me\/usb-hsm\/([^/]+)\/(revoke|suspend|reactivate)\/?$/);
        if (method === 'POST' && m) {
          const device = registry.changeStatus(
            user.userId,
            decodeURIComponent(m[1]),
            m[2] as 'revoke' | 'suspend' | 'reactivate'
          );
          sendJson(res, 200, device, req);
          finish(200);
          return;
        }
        sendJson(res, 404, { error: 'NOT_FOUND' }, req);
        finish(404, 'NOT_FOUND');
        return;
      }

      if (method === 'GET' && /^\/v1\/me\/documents\/?$/.test(path)) {
        const policies = await service.listPoliciesForUser(user?.userId ?? '');
        sendJson(res, 200, { policies: policies.map((p) => redactPolicy(p, user?.userId)) }, req);
        finish(200);
        return;
      }

      {
        const m = matchPath(url, /^\/v1\/documents\/([^/]+)\/(acl|revoke|restore)\/?$/);
        if (method === 'POST' && m) {
          const documentId = decodeURIComponent(m[1]);
          const action = m[2];
          const policy = await service.getDocumentPolicy(documentId);
          if (!policy || !user || policy.ownerUserId !== user.userId) {
            // Same answer for "missing" and "not yours" — no document enumeration.
            sendJson(res, 404, { error: 'DOCUMENT_NOT_FOUND' }, req);
            finish(404, 'DOCUMENT_NOT_FOUND');
            return;
          }
          const body = ((await readJson(req)) ?? {}) as {
            allowedUserIds?: unknown;
            reason?: string;
          };
          if (action === 'acl') {
            const updated = await service.updateDocumentAcl(documentId, body.allowedUserIds);
            sendJson(res, 200, updated, req);
          } else if (action === 'revoke') {
            const reason = typeof body.reason === 'string' ? body.reason.slice(0, 200) : undefined;
            const state = await service.revokeDocument(documentId, reason, `user:${user.userId}`);
            metrics.revokes += 1;
            sendJson(res, 200, state, req);
          } else {
            const state = await service.restoreDocument(documentId);
            metrics.restores += 1;
            sendJson(res, 200, state, req);
          }
          finish(200);
          return;
        }
      }

      if (method === 'GET' && matchPath(url, /^\/v1\/documents\/?$/)) {
        sendJson(res, 200, { policies: await service.listRegisteredPolicies() }, req);
        finish(200);
        return;
      }

      {
        const m = matchPath(url, /^\/v1\/documents\/([^/]+)\/policy\/?$/);
        if (method === 'GET' && m) {
          const policy = await service.getDocumentPolicy(decodeURIComponent(m[1]));
          if (!policy) {
            sendJson(res, 404, { error: 'DOCUMENT_NOT_REGISTERED' }, req);
            finish(404, 'DOCUMENT_NOT_REGISTERED');
            return;
          }
          sendJson(res, 200, redactPolicy(policy, user?.userId), req);
          finish(200);
          return;
        }
      }

      {
        const m = matchPath(url, /^\/v1\/documents\/([^/]+)\/revocation\/?$/);
        if (method === 'GET' && m) {
          sendJson(
            res,
            200,
            await service.getDocumentRevocationState(decodeURIComponent(m[1])),
            req
          );
          finish(200);
          return;
        }
      }

      if (method === 'POST' && /^\/v1\/authorize\/?$/.test(path)) {
        const request = (await readJson(req)) as Parameters<
          DurableAuthorityService['processAuthorizationRequest']
        >[0];
        if (!request || typeof request !== 'object') throw new HttpError(400, 'BAD_REQUEST');
        // Never trust a client-supplied subject: overwrite with the verified one.
        delete (request as { subjectUserId?: string }).subjectUserId;
        delete (request as { verifiedUsbHsm?: unknown }).verifiedUsbHsm;
        if (user) request.subjectUserId = user.userId;

        // USB-HSM: verify the hardware signature over this exact request.
        if (user && request.usbHsmAssertion) {
          try {
            const expected = await usbHsmChallenge({
              challenge: String(request.challenge),
              documentId: String(request.documentId),
              packageId: String(request.packageId),
              operationId: String(request.operationId),
              requestedOperation: request.requestedOperation,
            });
            const hsm = await service
              .getUsbHsm()
              .verifyAssertion(user.userId, request.usbHsmAssertion, expected);
            if (request.deviceId !== hsm.deviceId || request.credentialId !== hsm.deviceId) {
              throw new UsbHsmError('USB_HSM_DEVICE_MISMATCH');
            }
            request.verifiedUsbHsm = hsm;
          } catch (err) {
            const code = err instanceof UsbHsmError ? err.code : 'USB_HSM_ASSERTION_INVALID';
            metrics.grantsDenied += 1;
            sendJson(res, 200, {
              granted: false,
              rejectionCode: code,
              rejectionReason: `${code}: la firma del USB-HSM no es válida para esta solicitud.`,
            }, req);
            finish(200, code);
            return;
          }
        }
        delete (request as { usbHsmAssertion?: unknown }).usbHsmAssertion;
        // Without a USB-HSM the only credential is the verified account itself.
        if (user && !request.verifiedUsbHsm) {
          request.credentialId = `ACCOUNT-${user.userId}`;
        }
        const result = await service.processAuthorizationRequest(request);
        if (result.granted) metrics.grantsIssued += 1;
        else metrics.grantsDenied += 1;
        sendJson(res, 200, result, req);
        finish(200);
        return;
      }

      if (method === 'POST' && /^\/v1\/wrap-secret\/release\/?$/.test(path)) {
        const body = (await readJson(req)) as {
          grant: Parameters<DurableAuthorityService['releaseDocumentWrapSecretForGrant']>[0];
        };
        if (!body?.grant) throw new HttpError(400, 'BAD_REQUEST');
        // A grant issued to a USB-HSM dies with the key (revoked/suspended since).
        if (
          user &&
          typeof body.grant.deviceId === 'string' &&
          body.grant.deviceId.startsWith('USBHSM-') &&
          !service.getUsbHsm().isActiveDevice(user.userId, body.grant.deviceId)
        ) {
          sendJson(res, 200, { wrapSecretBase64: null }, req);
          finish(200, 'USB_HSM_INACTIVE');
          return;
        }
        const secret = await service.releaseDocumentWrapSecretForGrant(body.grant, user?.userId);
        sendJson(res, 200, {
          wrapSecretBase64: secret ? arrayBufferToBase64(secret) : null,
        }, req);
        finish(200);
        return;
      }

      if (method === 'POST' && /^\/v1\/view-once\/commit\/?$/.test(path)) {
        const body = (await readJson(req)) as { documentId: string; grantId: string };
        const committed = await service.commitViewOnce(
          body?.documentId,
          body?.grantId,
          user?.userId
        );
        sendJson(res, 200, { committed }, req);
        finish(200);
        return;
      }

      if (method === 'POST' && /^\/v1\/revoke\/?$/.test(path)) {
        const body = (await readJson(req)) as {
          documentId: string;
          reason?: string;
          revokedBy?: string;
        };
        const state = await service.revokeDocument(
          body.documentId,
          body.reason,
          body.revokedBy
        );
        metrics.revokes += 1;
        sendJson(res, 200, state, req);
        finish(200);
        return;
      }

      if (method === 'POST' && /^\/v1\/restore\/?$/.test(path)) {
        const body = (await readJson(req)) as { documentId: string };
        const state = await service.restoreDocument(body.documentId);
        metrics.restores += 1;
        sendJson(res, 200, state, req);
        finish(200);
        return;
      }

      if (method === 'GET' && /^\/v1\/revoked\/?$/.test(path)) {
        sendJson(res, 200, { revoked: await service.listRevoked() }, req);
        finish(200);
        return;
      }

      sendJson(res, 404, { error: 'NOT_FOUND' }, req);
      finish(404, 'NOT_FOUND');
    } catch (err) {
      if (err instanceof HttpError) {
        sendJson(res, err.status, { error: err.code }, req);
        finish(err.status, err.code);
        return;
      }
      if (err instanceof UsbHsmError) {
        const status = err.code === 'USB_HSM_NOT_FOUND' ? 404 : 400;
        sendJson(res, status, { error: err.code, message: err.message }, req);
        finish(status, err.code);
        return;
      }
      if (err instanceof DocumentAlreadyRegisteredError) {
        sendJson(res, 409, { error: 'DOCUMENT_ALREADY_REGISTERED' }, req);
        finish(409, 'DOCUMENT_ALREADY_REGISTERED');
        return;
      }
      metrics.httpErrors += 1;
      // Log details server-side only; never leak internals to clients.
      console.error('[tdcp-authority] internal error', err);
      sendJson(res, 500, { error: 'INTERNAL_ERROR' }, req);
      finish(500, 'INTERNAL');
    }
  };

  const server: Server = tls
    ? createHttpsServer(tls, handler)
    : createServer(handler);

  await new Promise<void>((resolve) => {
    server.listen(port, host, () => resolve());
  });

  return {
    server,
    service,
    port,
    host,
    metrics,
    adminAuth,
    adminAuthMode: adminAuth.mode,
    adminTokenConfigured: adminAuth.mode === 'token' && Boolean(adminAuth.token),
    userAuthMode: userAuth.mode,
    tlsEnabled: Boolean(tls),
  };
}
