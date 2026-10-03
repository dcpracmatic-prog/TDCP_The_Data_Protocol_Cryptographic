/**
 * Refuse to build an insecure Vercel production deployment.
 *
 * Vercel builds execute with production secrets available, while a browser
 * bundle only receives VITE_ variables. Requiring the public Authority URL
 * here prevents a deployment from silently falling back to the in-browser
 * Oracle, which is explicitly not a production security boundary.
 */
function required(name, value) {
  if (!value?.trim()) return `${name} must be configured`;
  return null;
}

function httpsUrl(name, value) {
  const missing = required(name, value);
  if (missing) return missing;
  try {
    if (new URL(value).protocol !== "https:") return `${name} must use https`;
  } catch {
    return `${name} must be a valid URL`;
  }
  return null;
}

export function productionConfigurationErrors(env = process.env) {
  const errors = [
    required("DATABASE_URL", env.DATABASE_URL),
    required("BETTER_AUTH_SECRET", env.BETTER_AUTH_SECRET),
    httpsUrl("BETTER_AUTH_URL", env.BETTER_AUTH_URL),
    httpsUrl("VITE_TDCP_AUTHORITY_URL", env.VITE_TDCP_AUTHORITY_URL),
  ].filter(Boolean);

  if (env.VITE_AUTH_ENABLED !== "true") {
    errors.push("VITE_AUTH_ENABLED must be exactly true");
  }
  if ((env.BETTER_AUTH_SECRET?.trim().length ?? 0) < 32) {
    errors.push("BETTER_AUTH_SECRET must contain at least 32 characters");
  }
  return errors;
}

if (process.env.VERCEL === "1") {
  const errors = productionConfigurationErrors();
  if (errors.length > 0) {
    console.error("[tdcp] Refusing insecure Vercel deployment:\n- " + errors.join("\n- "));
    process.exit(1);
  }
}
