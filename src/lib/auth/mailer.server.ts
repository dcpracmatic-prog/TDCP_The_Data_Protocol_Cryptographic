/**
 * Transactional email for account flows (server-only), via Resend.
 *
 * Env (production platform):
 *   RESEND_API_KEY  — Resend API key
 *   EMAIL_FROM      — verified sender, e.g. "TDCP <no-reply@tu-dominio.com>"
 *                     (TDCP_MAIL_FROM accepted as a legacy alias)
 *
 * Without a mailer: in development the link is printed to the server console;
 * in production nothing is logged (the link is a credential) and an error is
 * reported instead.
 */

function env(key: string): string | undefined {
  const v = process.env[key]?.trim();
  return v || undefined;
}

export function mailerConfig(): { apiKey: string; from: string } | null {
  const apiKey = env("RESEND_API_KEY");
  const from = env("EMAIL_FROM") ?? env("TDCP_MAIL_FROM");
  return apiKey && from ? { apiKey, from } : null;
}

export function mailerConfigured(): boolean {
  return mailerConfig() !== null;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string,
  );
}

function layout(title: string, bodyHtml: string, cta: { url: string; label: string }): string {
  const url = escapeHtml(cta.url);
  return `<!doctype html><html lang="es"><body style="margin:0;background:#f4f5f7;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#1f2328">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="padding:32px 12px"><tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;background:#ffffff;border-radius:12px;padding:32px">
<tr><td style="font-size:13px;font-weight:700;letter-spacing:.08em;color:#6b46c1">TDCP</td></tr>
<tr><td style="padding-top:12px;font-size:20px;font-weight:700">${escapeHtml(title)}</td></tr>
<tr><td style="padding-top:12px;font-size:15px;line-height:1.55">${bodyHtml}</td></tr>
<tr><td style="padding-top:24px"><a href="${url}" style="display:inline-block;background:#4f46e5;color:#ffffff;text-decoration:none;font-weight:600;padding:12px 20px;border-radius:8px">${escapeHtml(cta.label)}</a></td></tr>
<tr><td style="padding-top:20px;font-size:12px;line-height:1.5;color:#57606a">Si el botón no funciona, copia este enlace en tu navegador:<br><span style="word-break:break-all">${url}</span></td></tr>
<tr><td style="padding-top:20px;font-size:12px;color:#57606a">Si no fuiste tú, ignora este correo.</td></tr>
</table></td></tr></table></body></html>`;
}

export interface SendMailInput {
  to: string;
  subject: string;
  html: string;
  text: string;
  /** Used only for the dev console fallback. */
  devLabel: string;
  devUrl: string;
}

/** Low-level send; returns true when Resend accepted the message. */
export async function sendMail(input: SendMailInput, fetchImpl: typeof fetch = fetch): Promise<boolean> {
  const cfg = mailerConfig();
  if (!cfg) {
    if (process.env.NODE_ENV !== "production") {
      console.info(`[auth] (dev) ${input.devLabel} para ${input.to}: ${input.devUrl}`);
    } else {
      console.error(`[auth] RESEND_API_KEY / EMAIL_FROM no configurados: no se pudo enviar "${input.subject}".`);
    }
    return false;
  }
  try {
    const res = await fetchImpl("https://api.resend.com/emails", {
      method: "POST",
      headers: { authorization: `Bearer ${cfg.apiKey}`, "content-type": "application/json" },
      body: JSON.stringify({
        from: cfg.from,
        to: [input.to],
        subject: input.subject,
        html: input.html,
        text: input.text,
      }),
    });
    if (!res.ok) {
      // Never log the link; the status is enough to diagnose (401 key, 403/422 sender domain).
      console.error(`[auth] Resend respondió ${res.status} al enviar "${input.subject}".`);
      return false;
    }
    return true;
  } catch (err) {
    console.error(`[auth] Error de red con Resend: ${err instanceof Error ? err.message : String(err)}`);
    return false;
  }
}

export async function sendPasswordResetEmail(
  opts: { to: string; name?: string | null; url: string },
  fetchImpl?: typeof fetch,
): Promise<boolean> {
  const greeting = opts.name ? `Hola ${escapeHtml(opts.name)},` : "Hola,";
  return sendMail(
    {
      to: opts.to,
      subject: "TDCP — Restablecer contraseña",
      html: layout(
        "Restablecer contraseña",
        `<p>${greeting}</p><p>Recibimos una solicitud para restablecer la contraseña de tu cuenta TDCP. El enlace es válido durante 30 minutos y al usarlo se cerrarán tus demás sesiones.</p>`,
        { url: opts.url, label: "Restablecer contraseña" },
      ),
      text: `${opts.name ? `Hola ${opts.name},` : "Hola,"}\n\nRestablece tu contraseña de TDCP (válido 30 minutos):\n${opts.url}\n\nSi no fuiste tú, ignora este correo.`,
      devLabel: "Enlace de restablecimiento",
      devUrl: opts.url,
    },
    fetchImpl,
  );
}

export async function sendVerificationEmail(
  opts: { to: string; name?: string | null; url: string },
  fetchImpl?: typeof fetch,
): Promise<boolean> {
  const greeting = opts.name ? `Hola ${escapeHtml(opts.name)},` : "Hola,";
  return sendMail(
    {
      to: opts.to,
      subject: "TDCP — Confirma tu correo",
      html: layout(
        "Confirma tu correo",
        `<p>${greeting}</p><p>Confirma que este correo es tuyo para que otras personas puedan compartir documentos TDCP contigo usando esta dirección.</p>`,
        { url: opts.url, label: "Confirmar correo" },
      ),
      text: `${opts.name ? `Hola ${opts.name},` : "Hola,"}\n\nConfirma tu correo de TDCP:\n${opts.url}\n\nSi no fuiste tú, ignora este correo.`,
      devLabel: "Enlace de verificación",
      devUrl: opts.url,
    },
    fetchImpl,
  );
}
