/**
 * Node HTTP Authorization Authority service.
 *
 * Endpoints (JSON):
 *   GET  /health
 *   GET  /v1/public-key
 *   POST /v1/challenge
 *   POST /v1/challenge/validate
 *   POST /v1/documents/register
 *   GET  /v1/documents
 *   GET  /v1/documents/:id/policy
 *   GET  /v1/documents/:id/revocation
 *   POST /v1/authorize
 *   POST /v1/wrap-secret/release
 *   POST /v1/view-once/commit
 *   POST /v1/revoke
 *   POST /v1/restore
 *   GET  /v1/revoked
 *
 * HONESTY: Durable file store + WebCrypto ECDSA is an MVP stub, not HSM.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { arrayBufferToBase64 } from '../../src/core/crypto/primitives.ts';
import { DurableAuthorityService } from './service.ts';

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(payload);
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

export interface AuthorityHttpServerOptions {
  port?: number;
  host?: string;
  dataDir: string;
  service?: DurableAuthorityService;
}

export async function startAuthorityHttpServer(options: AuthorityHttpServerOptions) {
  const service = options.service ?? new DurableAuthorityService(options.dataDir);
  await service.initialize();

  const host = options.host ?? '0.0.0.0';
  const port = options.port ?? Number(process.env.TDCP_AUTHORITY_PORT || 8787);

  const server = createServer(async (req, res) => {
    try {
      const method = req.method || 'GET';
      const url = req.url || '/';

      if (method === 'GET' && (url === '/health' || url === '/healthz')) {
        return sendJson(res, 200, { ok: true, service: 'tdcp-authority', developmentOnly: true });
      }

      if (method === 'GET' && url.startsWith('/v1/public-key')) {
        return sendJson(res, 200, await service.getPublicInfo());
      }

      if (method === 'POST' && url.startsWith('/v1/challenge/validate')) {
        const body = (await readJson(req)) as { challenge?: string };
        const valid = await service.isValidChallenge(body?.challenge || '');
        return sendJson(res, 200, { valid });
      }

      if (method === 'POST' && matchPath(url, /^\/v1\/challenge\/?$/)) {
        const challenge = await service.issueChallenge();
        return sendJson(res, 200, { challenge });
      }

      if (method === 'POST' && url.startsWith('/v1/documents/register')) {
        const policy = (await readJson(req)) as Parameters<
          DurableAuthorityService['registerDocumentPolicy']
        >[0];
        const secret = await service.registerDocumentPolicy(policy);
        return sendJson(res, 200, { wrapSecretBase64: arrayBufferToBase64(secret) });
      }

      if (method === 'GET' && matchPath(url, /^\/v1\/documents\/?$/)) {
        return sendJson(res, 200, { policies: await service.listRegisteredPolicies() });
      }

      {
        const m = matchPath(url, /^\/v1\/documents\/([^/]+)\/policy\/?$/);
        if (method === 'GET' && m) {
          const policy = await service.getDocumentPolicy(decodeURIComponent(m[1]));
          if (!policy) {
            return sendJson(res, 404, { error: 'DOCUMENT_NOT_REGISTERED' });
          }
          return sendJson(res, 200, policy);
        }
      }

      {
        const m = matchPath(url, /^\/v1\/documents\/([^/]+)\/revocation\/?$/);
        if (method === 'GET' && m) {
          return sendJson(res, 200, await service.getDocumentRevocationState(decodeURIComponent(m[1])));
        }
      }

      if (method === 'POST' && url.startsWith('/v1/authorize')) {
        const request = (await readJson(req)) as Parameters<
          DurableAuthorityService['processAuthorizationRequest']
        >[0];
        return sendJson(res, 200, await service.processAuthorizationRequest(request));
      }

      if (method === 'POST' && url.startsWith('/v1/wrap-secret/release')) {
        const body = (await readJson(req)) as { grant: Parameters<
          DurableAuthorityService['releaseDocumentWrapSecretForGrant']
        >[0] };
        const secret = await service.releaseDocumentWrapSecretForGrant(body.grant);
        return sendJson(res, 200, {
          wrapSecretBase64: secret ? arrayBufferToBase64(secret) : null,
        });
      }

      if (method === 'POST' && url.startsWith('/v1/view-once/commit')) {
        const body = (await readJson(req)) as { documentId: string; grantId: string };
        const committed = await service.commitViewOnce(body.documentId, body.grantId);
        return sendJson(res, 200, { committed });
      }

      if (method === 'POST' && url.startsWith('/v1/revoke')) {
        const body = (await readJson(req)) as {
          documentId: string;
          reason?: string;
          revokedBy?: string;
        };
        return sendJson(
          res,
          200,
          await service.revokeDocument(body.documentId, body.reason, body.revokedBy)
        );
      }

      if (method === 'POST' && url.startsWith('/v1/restore')) {
        const body = (await readJson(req)) as { documentId: string };
        return sendJson(res, 200, await service.restoreDocument(body.documentId));
      }

      if (method === 'GET' && url.startsWith('/v1/revoked')) {
        return sendJson(res, 200, { revoked: await service.listRevoked() });
      }

      sendJson(res, 404, { error: 'NOT_FOUND' });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      sendJson(res, 500, { error: message });
    }
  });

  await new Promise<void>((resolve) => {
    server.listen(port, host, () => resolve());
  });

  return { server, service, port, host };
}
