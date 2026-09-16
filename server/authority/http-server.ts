/**
 * Node HTTP Authorization Authority service.
 *
 * Public (Gatekeeper): challenge, authorize, wrap-secret release, policy/revocation get, public-key
 * Admin (Bearer TDCP_AUTHORITY_ADMIN_TOKEN): register, revoke, restore, list documents/revoked
 * Ops: /health, /ready, /metrics
 *
 * HONESTY: Durable file store + WebCrypto ECDSA is an MVP stub, not HSM.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { arrayBufferToBase64 } from '../../src/core/crypto/primitives.ts';
import { DurableAuthorityService } from './service.ts';
import { isAdminPath, requireAdminAuth, readAdminTokenFromEnv } from './admin-auth.ts';
import { InMemoryRateLimiter, clientKey } from './rate-limit.ts';
import { AuthorityMetrics } from './metrics.ts';
import { logRequest } from './request-log.ts';

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(payload);
}

function sendText(res: ServerResponse, status: number, body: string, contentType: string): void {
  res.writeHead(status, {
    'content-type': contentType,
    'cache-control': 'no-store',
  });
  res.end(body);
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  if (chunks.length === 0) return null;
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
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
  return false;
}

export interface AuthorityHttpServerOptions {
  port?: number;
  host?: string;
  dataDir: string;
  service?: DurableAuthorityService;
  adminToken?: string;
  rateLimit?: { windowMs?: number; maxHits?: number };
  metrics?: AuthorityMetrics;
}

export async function startAuthorityHttpServer(options: AuthorityHttpServerOptions) {
  const service = options.service ?? new DurableAuthorityService(options.dataDir);
  await service.initialize();

  const host = options.host ?? '0.0.0.0';
  const port = options.port ?? Number(process.env.TDCP_AUTHORITY_PORT || 8787);
  const adminToken =
    options.adminToken !== undefined ? options.adminToken : readAdminTokenFromEnv();
  const metrics = options.metrics ?? new AuthorityMetrics();
  const limiter = new InMemoryRateLimiter({
    windowMs:
      options.rateLimit?.windowMs ??
      Number(process.env.TDCP_AUTHORITY_RATE_WINDOW_MS || 60_000),
    maxHits:
      options.rateLimit?.maxHits ?? Number(process.env.TDCP_AUTHORITY_RATE_MAX || 120),
  });

  const server = createServer(async (req, res) => {
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
      if (method === 'GET' && (path === '/health' || path === '/healthz')) {
        sendJson(res, 200, {
          ok: true,
          service: 'tdcp-authority',
          developmentOnly: true,
        });
        finish(200);
        return;
      }

      if (method === 'GET' && (path === '/ready' || path === '/readyz')) {
        const readiness = service.getReadiness();
        const status = readiness.ready ? 200 : 503;
        sendJson(res, status, { ...readiness, service: 'tdcp-authority' });
        finish(status, readiness.ready ? undefined : 'NOT_READY');
        return;
      }

      if (method === 'GET' && path === '/metrics') {
        sendText(
          res,
          200,
          metrics.renderPrometheus(),
          'text/plain; version=0.0.4; charset=utf-8'
        );
        finish(200);
        return;
      }

      if (isAdminPath(method, path)) {
        const auth = requireAdminAuth(req, adminToken);
        if (!auth.ok) {
          metrics.adminUnauthorized += 1;
          sendJson(res, auth.status, { error: auth.error });
          finish(auth.status, auth.error);
          return;
        }
      }

      if (isRateLimitedPath(method, path)) {
        const rl = limiter.check(`pub:${client}`);
        if (!rl.allowed) {
          metrics.rateLimited += 1;
          res.writeHead(429, {
            'content-type': 'application/json; charset=utf-8',
            'retry-after': String(Math.ceil(rl.retryAfterMs / 1000) || 1),
            'cache-control': 'no-store',
          });
          res.end(JSON.stringify({ error: 'RATE_LIMITED', retryAfterMs: rl.retryAfterMs }));
          finish(429, 'RATE_LIMITED');
          return;
        }
      }

      if (method === 'GET' && path.startsWith('/v1/public-key')) {
        sendJson(res, 200, await service.getPublicInfo());
        finish(200);
        return;
      }

      if (method === 'POST' && path.startsWith('/v1/challenge/validate')) {
        const body = (await readJson(req)) as { challenge?: string };
        const valid = await service.isValidChallenge(body?.challenge || '');
        sendJson(res, 200, { valid });
        finish(200);
        return;
      }

      if (method === 'POST' && matchPath(url, /^\/v1\/challenge\/?$/)) {
        const challenge = await service.issueChallenge();
        sendJson(res, 200, { challenge });
        finish(200);
        return;
      }

      if (method === 'POST' && path.startsWith('/v1/documents/register')) {
        const policy = (await readJson(req)) as Parameters<
          DurableAuthorityService['registerDocumentPolicy']
        >[0];
        const secret = await service.registerDocumentPolicy(policy);
        sendJson(res, 200, { wrapSecretBase64: arrayBufferToBase64(secret) });
        finish(200);
        return;
      }

      if (method === 'GET' && matchPath(url, /^\/v1\/documents\/?$/)) {
        sendJson(res, 200, { policies: await service.listRegisteredPolicies() });
        finish(200);
        return;
      }

      {
        const m = matchPath(url, /^\/v1\/documents\/([^/]+)\/policy\/?$/);
        if (method === 'GET' && m) {
          const policy = await service.getDocumentPolicy(decodeURIComponent(m[1]));
          if (!policy) {
            sendJson(res, 404, { error: 'DOCUMENT_NOT_REGISTERED' });
            finish(404, 'DOCUMENT_NOT_REGISTERED');
            return;
          }
          sendJson(res, 200, policy);
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
            await service.getDocumentRevocationState(decodeURIComponent(m[1]))
          );
          finish(200);
          return;
        }
      }

      if (method === 'POST' && path.startsWith('/v1/authorize')) {
        const request = (await readJson(req)) as Parameters<
          DurableAuthorityService['processAuthorizationRequest']
        >[0];
        const result = await service.processAuthorizationRequest(request);
        if (result.granted) metrics.grantsIssued += 1;
        else metrics.grantsDenied += 1;
        sendJson(res, 200, result);
        finish(200);
        return;
      }

      if (method === 'POST' && path.startsWith('/v1/wrap-secret/release')) {
        const body = (await readJson(req)) as {
          grant: Parameters<DurableAuthorityService['releaseDocumentWrapSecretForGrant']>[0];
        };
        const secret = await service.releaseDocumentWrapSecretForGrant(body.grant);
        sendJson(res, 200, {
          wrapSecretBase64: secret ? arrayBufferToBase64(secret) : null,
        });
        finish(200);
        return;
      }

      if (method === 'POST' && path.startsWith('/v1/view-once/commit')) {
        const body = (await readJson(req)) as { documentId: string; grantId: string };
        const committed = await service.commitViewOnce(body.documentId, body.grantId);
        sendJson(res, 200, { committed });
        finish(200);
        return;
      }

      if (method === 'POST' && path.startsWith('/v1/revoke')) {
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
        sendJson(res, 200, state);
        finish(200);
        return;
      }

      if (method === 'POST' && path.startsWith('/v1/restore')) {
        const body = (await readJson(req)) as { documentId: string };
        const state = await service.restoreDocument(body.documentId);
        metrics.restores += 1;
        sendJson(res, 200, state);
        finish(200);
        return;
      }

      if (method === 'GET' && path.startsWith('/v1/revoked')) {
        sendJson(res, 200, { revoked: await service.listRevoked() });
        finish(200);
        return;
      }

      sendJson(res, 404, { error: 'NOT_FOUND' });
      finish(404, 'NOT_FOUND');
    } catch (err) {
      metrics.httpErrors += 1;
      const message = err instanceof Error ? err.message : String(err);
      sendJson(res, 500, { error: message });
      finish(500, 'INTERNAL');
    }
  });

  await new Promise<void>((resolve) => {
    server.listen(port, host, () => resolve());
  });

  return {
    server,
    service,
    port,
    host,
    metrics,
    adminTokenConfigured: Boolean(adminToken),
  };
}
