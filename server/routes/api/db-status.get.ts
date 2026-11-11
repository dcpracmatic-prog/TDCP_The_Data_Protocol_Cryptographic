import { getDbStatus } from "../../../src/lib/db.ts";

/**
 * GET /api/db-status — which database backend is serving this deploy.
 *
 * Nitro auto-registers this file as a server route (`serverDir: "./server"`,
 * see vite.config.ts), same as `server/middleware/grok-pwa.ts`. Plain default
 * export on purpose: no h3 import needed.
 *
 * Returns `{ backend: "postgres" | "pglite", databaseConfigured, production,
 * ready }` and nothing else: no host, no user, no password, no URL. Arturo
 * checks this after a Vercel redeploy — it must say
 * `backend: "postgres", ready: true`. `ready: false` means the `select 1`
 * ping did not answer.
 */
export default async function dbStatusRoute() {
  return Response.json(await getDbStatus());
}
