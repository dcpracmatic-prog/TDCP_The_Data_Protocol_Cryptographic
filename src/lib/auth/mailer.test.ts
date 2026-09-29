import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mailerConfig, sendPasswordResetEmail, sendVerificationEmail } from './mailer.server.ts';

const KEYS = ['RESEND_API_KEY', 'EMAIL_FROM', 'TDCP_MAIL_FROM', 'NODE_ENV'] as const;
let saved: Record<string, string | undefined> = {};

function fakeFetch(status = 200) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const impl = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return new Response('{"id":"x"}', { status });
  }) as unknown as typeof fetch;
  return { calls, impl };
}

describe('Resend mailer', () => {
  beforeEach(() => {
    saved = Object.fromEntries(KEYS.map((k) => [k, process.env[k]]));
    for (const k of KEYS) delete process.env[k];
  });
  afterEach(() => {
    for (const k of KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  it('uses RESEND_API_KEY + EMAIL_FROM', async () => {
    process.env.RESEND_API_KEY = 're_test_123';
    process.env.EMAIL_FROM = 'TDCP <no-reply@tdcp.example>';
    const f = fakeFetch();
    const ok = await sendPasswordResetEmail({ to: 'ana@example.com', name: 'Ana <b>', url: 'https://app/reset?token=abc' }, f.impl);
    assert.equal(ok, true);
    assert.equal(f.calls.length, 1);
    assert.equal(f.calls[0].url, 'https://api.resend.com/emails');
    const headers = f.calls[0].init.headers as Record<string, string>;
    assert.equal(headers.authorization, 'Bearer re_test_123');
    const body = JSON.parse(String(f.calls[0].init.body));
    assert.equal(body.from, 'TDCP <no-reply@tdcp.example>');
    assert.deepEqual(body.to, ['ana@example.com']);
    assert.match(body.html, /reset\?token=abc/);
    assert.match(body.text, /reset\?token=abc/);
    assert.ok(!body.html.includes('<b>'), 'name must be HTML-escaped');
  });

  it('accepts TDCP_MAIL_FROM as legacy alias, EMAIL_FROM wins', () => {
    process.env.RESEND_API_KEY = 'k';
    process.env.TDCP_MAIL_FROM = 'old@x';
    assert.equal(mailerConfig()?.from, 'old@x');
    process.env.EMAIL_FROM = 'new@x';
    assert.equal(mailerConfig()?.from, 'new@x');
  });

  it('sends verification emails', async () => {
    process.env.RESEND_API_KEY = 'k';
    process.env.EMAIL_FROM = 'a@b.c';
    const f = fakeFetch();
    assert.equal(await sendVerificationEmail({ to: 'x@y.z', url: 'https://app/verify?t=1' }, f.impl), true);
    assert.equal(JSON.parse(String(f.calls[0].init.body)).subject, 'TDCP — Confirma tu correo');
  });

  it('reports Resend errors without throwing', async () => {
    process.env.RESEND_API_KEY = 'k';
    process.env.EMAIL_FROM = 'a@b.c';
    const f = fakeFetch(422);
    assert.equal(await sendVerificationEmail({ to: 'x@y.z', url: 'u' }, f.impl), false);
  });

  it('does not call Resend when unconfigured', async () => {
    const f = fakeFetch();
    assert.equal(await sendPasswordResetEmail({ to: 'x@y.z', url: 'u' }, f.impl), false);
    assert.equal(f.calls.length, 0);
  });
});
