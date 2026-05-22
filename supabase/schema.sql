-- ZeroTrace — Supabase schema
-- Run this in the Supabase dashboard → SQL Editor → New query → Run.
-- It creates the shared tables and permissive policies for the public anon key.
-- (Tighten the RLS policies later once you have real Supabase Auth in place.)

-- ============ Registered analyst accounts ============
create table if not exists public.users (
  id           text primary key,
  username     text not null,
  email        text not null,
  discord_id   text,
  pass         text,                 -- demo only; replace with real auth later
  key          text,
  suspended    boolean default false,
  force_2fa    boolean default false,
  force_pw     boolean default false,
  digest_freq  text default 'off',
  coins        bigint default 0,
  created_at   timestamptz default now()
);

-- ============ License keys ============
create table if not exists public.license_keys (
  id            text primary key,
  key           text unique not null,
  label         text,
  plan          text,
  duration_days int,
  status        text default 'Active',
  used_by       text,
  created_at    timestamptz default now(),
  expires_at    timestamptz
);

-- ============ Pins / scans ============
create table if not exists public.pins (
  id          text primary key,
  pin         text,
  name        text,
  game        text,
  status      text default 'Pending',
  result      text,
  owner_id    text,
  discord_id  text,
  detections  int default 0,
  cheats      jsonb default '[]'::jsonb,
  payload     jsonb default '{}'::jsonb,   -- full scan report + extras
  created_at  timestamptz default now()
);

-- ============ Casino wallets (coins, stats) ============
create table if not exists public.wallets (
  owner_key        text primary key,
  balance          bigint default 0,
  xp               bigint default 0,
  wagered          bigint default 0,
  won              bigint default 0,
  biggest_win      bigint default 0,
  achievements     jsonb default '[]'::jsonb,
  last_daily_bonus bigint default 0,
  daily_streak     int default 0,
  history          jsonb default '[]'::jsonb,
  updated_at       timestamptz default now()
);

-- ============ Discount codes ============
create table if not exists public.discount_codes (
  id         text primary key,
  code       text unique not null,
  percent    int not null,
  max_uses   int default 0,
  uses       int default 0,
  expires_at timestamptz,
  active     boolean default true,
  source     text default 'admin',
  created_at timestamptz default now()
);

-- ============ Single-row global settings (announcement, maintenance, jackpot) ============
create table if not exists public.app_state (
  id         int primary key default 1,
  data       jsonb default '{}'::jsonb,
  updated_at timestamptz default now()
);
insert into public.app_state (id, data) values (1, '{}'::jsonb)
  on conflict (id) do nothing;

-- ============ Enable RLS + permissive anon policies (demo) ============
-- NOTE: these allow the public anon key full read/write. Fine for a closed
-- demo; replace with proper auth-based policies before a real launch.
do $$
declare t text;
begin
  foreach t in array array['users','license_keys','pins','wallets','discount_codes','app_state']
  loop
    execute format('alter table public.%I enable row level security;', t);
    execute format('drop policy if exists "anon_all_%1$s" on public.%1$s;', t);
    execute format($p$create policy "anon_all_%1$s" on public.%1$s for all using (true) with check (true);$p$, t);
  end loop;
end $$;
