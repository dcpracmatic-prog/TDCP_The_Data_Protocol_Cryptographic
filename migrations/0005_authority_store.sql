-- 0005_authority_store.sql — Durable Authorization Authority state in Postgres (P0-1).
--
-- Replaces the gitignored `authority-state.json` file when the Authority runs with
-- TDCP_AUTHORITY_STORE=postgres (see server/authority/postgres-store.ts and
-- docs/AUTHORITY.md). The file store stays as the local-dev fallback.
--
-- SECURITY SEMANTICS ARE UNCHANGED: Gatekeeper is still the only unlock path;
-- grants are single-use; revocation works by epochs; challenges are anti-replay;
-- view-once is enforced by the Authority. This file only moves WHERE the state
-- lives (durable rows instead of one JSON file). No crypto primitive changes.
-- The signing private JWK is stored exactly as the file store kept it: plaintext
-- only in dev, AES-256-GCM encrypted (signing_private_jwk_enc) when
-- TDCP_AUTHORITY_KEY_PASSPHRASE is set. This is still NOT HSM-grade.
--
-- Applied by scripts/migrate.mjs on deploy (recorded in _migrations) and by the
-- PGLite fallback in src/lib/db.ts on startup; the Postgres Authority store also
-- applies it idempotently at startup via ensureSchema(). Every statement is
-- IF NOT EXISTS, so re-running this file is a safe no-op.
--
-- Row Level Security is enabled with NO policies on every table below (same
-- convention as 0003_enable_rls.sql): the Supabase Data API sees nothing, while
-- the server connection (table owner) is unaffected.

-- Singleton row (id = 1): key id + signing key material.
create table if not exists authority_meta (
  id integer primary key check (id = 1),
  key_id text not null,
  signing_private_jwk jsonb,
  signing_private_jwk_enc jsonb,
  signing_public_jwk jsonb,
  updated_at timestamptz not null default now()
);

-- One row per registered document policy (whole policy as JSONB).
create table if not exists authority_policies (
  document_id text primary key,
  policy jsonb not null,
  updated_at timestamptz not null default now()
);

-- One row per document wrap secret (base64; released only after a verified grant).
create table if not exists authority_wrap_secrets (
  document_id text primary key,
  wrap_secret_b64 text not null,
  updated_at timestamptz not null default now()
);

-- Revocation / epoch state, one row per document. is_revoked + current_epoch are
-- real columns (indexed) so "list revoked" never scans JSONB.
create table if not exists authority_revocation (
  document_id text primary key,
  is_revoked boolean not null,
  current_epoch integer not null,
  state jsonb not null,
  updated_at timestamptz not null default now()
);
create index if not exists authority_revocation_revoked_idx
  on authority_revocation (is_revoked, current_epoch);

-- Anti-replay: every consumed operation (operationId is the primary key, so a
-- replayed operation collides instead of being stored twice).
create table if not exists authority_consumed_operations (
  operation_id text primary key,
  challenge text not null,
  grant_id text not null,
  document_id text not null,
  device_id text not null,
  consumed_at bigint not null
);
create index if not exists authority_consumed_operations_grant_idx
  on authority_consumed_operations (grant_id);
create index if not exists authority_consumed_operations_document_idx
  on authority_consumed_operations (document_id);
create index if not exists authority_consumed_operations_challenge_idx
  on authority_consumed_operations (challenge);

-- Single-use grants: grantId is the primary key, so a grant can only be
-- consumed once at the storage layer too.
create table if not exists authority_consumed_grants (
  grant_id text primary key,
  consumed_at timestamptz not null default now()
);

-- Active (unexpired) challenges for anti-replay freshness checks.
create table if not exists authority_challenges (
  challenge text primary key,
  registered_at bigint not null
);
create index if not exists authority_challenges_registered_idx
  on authority_challenges (registered_at);

-- Challenge -> verified end-user binding (TDCP_USER_AUTH=required).
create table if not exists authority_challenge_subjects (
  challenge text primary key,
  subject_user_id text not null
);
create index if not exists authority_challenge_subjects_user_idx
  on authority_challenge_subjects (subject_user_id);

-- Enrolled USB-HSM devices (public keys + lifecycle only, never private keys).
create table if not exists authority_usb_hsm_devices (
  device_id text primary key,
  record jsonb not null,
  updated_at timestamptz not null default now()
);

-- Never expose Authority state through the Supabase Data API.
alter table authority_meta enable row level security;
alter table authority_policies enable row level security;
alter table authority_wrap_secrets enable row level security;
alter table authority_revocation enable row level security;
alter table authority_consumed_operations enable row level security;
alter table authority_consumed_grants enable row level security;
alter table authority_challenges enable row level security;
alter table authority_challenge_subjects enable row level security;
alter table authority_usb_hsm_devices enable row level security;
