-- Better Auth `jwt` plugin key store. Signs the short-lived identity tokens
-- the TDCP Authority verifies (see src/lib/auth/server.ts, docs/AUTHORITY_USER_AUTH.md).
-- privateKey is encrypted with BETTER_AUTH_SECRET by Better Auth.
create table if not exists "jwks" (
  "id"         text primary key,
  "publicKey"  text not null,
  "privateKey" text not null,
  "createdAt"  timestamptz not null,
  "expiresAt"  timestamptz
);

-- Never expose signing keys through the Supabase Data API.
alter table "jwks" enable row level security;
