-- One row per userId; latest code overwrites previous until it expires or is verified.
create table if not exists verifications (
  user_id      text primary key,
  code         text not null,
  verified     boolean not null default false,
  created_at   timestamptz not null default now(),
  expires_at   timestamptz not null
);

create index if not exists verifications_expires_idx on verifications(expires_at);
