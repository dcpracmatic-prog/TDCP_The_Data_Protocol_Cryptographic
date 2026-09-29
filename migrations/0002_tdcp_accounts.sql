-- TDCP account profile + Google Drive destination folders.
-- One row per Better Auth user. Every query is scoped server-side by the
-- verified session user id (see src/lib/accounts.functions.ts).

create table if not exists tdcp_profile (
  user_id     text primary key references "user" ("id") on delete cascade,
  custom_id   text not null unique,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create table if not exists tdcp_drive_folder (
  user_id     text not null references "user" ("id") on delete cascade,
  folder_id   text not null,
  name        text not null,
  link        text not null,
  description text not null default '',
  is_default  boolean not null default false,
  added_at    timestamptz not null default now(),
  primary key (user_id, folder_id)
);

-- At most one default folder per user.
create unique index if not exists tdcp_drive_folder_one_default
  on tdcp_drive_folder (user_id) where is_default;
