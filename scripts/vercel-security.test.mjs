import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { productionConfigurationErrors } from "./check-vercel-production-env.mjs";

test("Vercel deployment has mandatory transport and browser isolation headers", async () => {
  const config = JSON.parse(await readFile(new URL("../vercel.json", import.meta.url), "utf8"));
  const allHeaders = config.headers[0].headers;
  const header = (name) => allHeaders.find((item) => item.key === name)?.value;

  assert.match(header("Strict-Transport-Security"), /max-age=63072000/);
  assert.equal(header("X-Content-Type-Options"), "nosniff");
  assert.equal(header("X-Frame-Options"), "DENY");
  assert.equal(header("Cross-Origin-Opener-Policy"), "same-origin");
  assert.equal(header("Cross-Origin-Resource-Policy"), "same-origin");
  assert.match(header("Permissions-Policy"), /camera=\(\)/);
  assert.match(header("Permissions-Policy"), /usb=\(\)/);
});

test("Vercel production configuration fails closed without auth and a remote Authority", () => {
  const secure = {
    DATABASE_URL: "postgresql://user:password@db.example.test:5432/tdcp",
    BETTER_AUTH_SECRET: "a".repeat(32),
    BETTER_AUTH_URL: "https://app.example.test",
    VITE_TDCP_AUTHORITY_URL: "https://authority.example.test",
    VITE_AUTH_ENABLED: "true",
  };
  assert.deepEqual(productionConfigurationErrors(secure), []);
  assert.deepEqual(productionConfigurationErrors({ ...secure, VITE_TDCP_AUTHORITY_URL: "http://localhost:8787" }), [
    "VITE_TDCP_AUTHORITY_URL must use https",
  ]);
  assert.ok(productionConfigurationErrors({}).length >= 5);
});
