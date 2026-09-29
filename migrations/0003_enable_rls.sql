-- Supabase exposes the `public` schema through its Data API (PostgREST) to the
-- `anon` / `authenticated` roles. These tables hold password hashes, session
-- tokens and per-user data, so enable Row Level Security with NO policies:
-- the Data API gets nothing, while this app's server connection (the table
-- owner, `postgres`) is unaffected. Harmless on plain Postgres / PGLite.

alter table "user"            enable row level security;
alter table "session"         enable row level security;
alter table "account"         enable row level security;
alter table "verification"    enable row level security;
alter table tdcp_profile      enable row level security;
alter table tdcp_drive_folder enable row level security;
