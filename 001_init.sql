-- ============================================================
-- AIChartPRO — Supabase Database Schema
-- Run this in the Supabase SQL Editor or via supabase db push
-- ============================================================

-- ── PROFILES ──────────────────────────────────────────────
-- Extends auth.users with app-specific fields.
-- SECURITY: Users can read their own row but CANNOT directly
-- update plan, plan_expires_at, or analyses_used — those
-- columns are write-protected and only modified by Edge
-- Functions running with the service role key.
create table if not exists public.profiles (
  id               uuid primary key references auth.users(id) on delete cascade,
  name             text not null default '',
  plan             text not null default 'free'
    check (plan in ('free','beginner','pro')),
  plan_expires_at  timestamptz,                      -- null = free (no expiry)
  analyses_used    int  not null default 0,
  analyses_reset   timestamptz not null default now(),
  disclaimer_accepted boolean not null default false, -- first-use legal acknowledgement
  joined_at        timestamptz not null default now()
);

alter table public.profiles enable row level security;

-- Users may read only their own row
create policy "Users can view own profile"
  on public.profiles for select
  using (auth.uid() = id);

-- Users may update ONLY their display name and disclaimer flag.
-- Plan, quota, and expiry are managed exclusively by Edge Functions
-- via the service role key and cannot be tampered with from the browser.
create policy "Users can update own safe fields"
  on public.profiles for update
  using (auth.uid() = id)
  with check (
    auth.uid() = id
    -- Prevent client-side elevation of plan or quota
    and plan             = (select plan             from public.profiles where id = auth.uid())
    and plan_expires_at  is not distinct from (select plan_expires_at from public.profiles where id = auth.uid())
    and analyses_used    = (select analyses_used    from public.profiles where id = auth.uid())
    and analyses_reset   is not distinct from (select analyses_reset  from public.profiles where id = auth.uid())
  );

-- Auto-create profile row whenever a new user signs up
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer as $$
begin
  insert into public.profiles (id, name)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'name', split_part(new.email,'@',1))
  );
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();


-- ── WATCHLISTS ─────────────────────────────────────────────
-- All plans: users manage their own watchlist rows only.
create table if not exists public.watchlists (
  id        uuid primary key default gen_random_uuid(),
  user_id   uuid not null references public.profiles(id) on delete cascade,
  symbol    text not null,
  added_at  timestamptz not null default now(),
  unique(user_id, symbol)
);

alter table public.watchlists enable row level security;

create policy "Users manage own watchlist"
  on public.watchlists for all
  using  (auth.uid() = user_id)
  with check (auth.uid() = user_id);


-- ── ALERTS ─────────────────────────────────────────────────
-- Beginner + Pro: users manage their own alerts only.
-- Free users are blocked at the Edge Function level (plan check)
-- before they can reach any alert-writing path.
create table if not exists public.alerts (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references public.profiles(id) on delete cascade,
  symbol     text not null,
  condition  text not null check (condition in ('above','below')),
  price      numeric not null,
  triggered  boolean not null default false,
  created_at timestamptz not null default now()
);

alter table public.alerts enable row level security;

create policy "Users manage own alerts"
  on public.alerts for all
  using  (auth.uid() = user_id)
  with check (auth.uid() = user_id);


-- ── JOURNAL (Pro only — enforced at DB level via RLS) ──────
-- Even if a user manipulates the browser UI, the database
-- will reject any read or write if the caller's plan != 'pro'.
create table if not exists public.journal_entries (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references public.profiles(id) on delete cascade,
  symbol      text not null,
  direction   text not null check (direction in ('LONG','SHORT')),
  entry_price numeric not null,
  exit_price  numeric,
  size        numeric,
  signal      text check (signal in ('BUY','SELL','HOLD','NONE')),
  notes       text,
  pnl         numeric generated always as (
                case when exit_price is not null and size is not null
                then (exit_price - entry_price) / entry_price * size *
                     case when direction = 'SHORT' then -1 else 1 end
                else null end
              ) stored,
  created_at  timestamptz not null default now()
);

alter table public.journal_entries enable row level security;

-- RLS: caller must own the row AND have an active Pro plan.
-- plan_expires_at null-check is intentional: free rows have no expiry column.
create policy "Pro users manage own journal"
  on public.journal_entries for all
  using (
    auth.uid() = user_id
    and exists (
      select 1 from public.profiles p
      where p.id = auth.uid()
        and p.plan = 'pro'
        and (p.plan_expires_at is null or p.plan_expires_at > now())
    )
  )
  with check (
    auth.uid() = user_id
    and exists (
      select 1 from public.profiles p
      where p.id = auth.uid()
        and p.plan = 'pro'
        and (p.plan_expires_at is null or p.plan_expires_at > now())
    )
  );


-- ── ANALYSIS HISTORY ───────────────────────────────────────
-- Written only by the analyze Edge Function (service role).
-- Users can read their own history; they cannot insert or
-- modify rows directly (no INSERT/UPDATE policy for anon role).
create table if not exists public.analysis_history (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references public.profiles(id) on delete cascade,
  symbol      text not null,
  timeframe   text not null,
  signal      text,
  confidence  int,
  result_json jsonb,
  created_at  timestamptz not null default now()
);

alter table public.analysis_history enable row level security;

-- SELECT only — inserts are done by the service role in the Edge Function
create policy "Users view own analysis history"
  on public.analysis_history for select
  using (auth.uid() = user_id);

-- No public INSERT policy. Service role bypasses RLS entirely.


-- ── SUBSCRIPTIONS ──────────────────────────────────────────
-- Audit trail of plan purchases. Users can only SELECT their
-- own rows. All inserts happen via the Edge Function's service
-- role — there is no public INSERT policy.
create table if not exists public.subscriptions (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid not null references public.profiles(id) on delete cascade,
  plan          text not null check (plan in ('beginner','pro')),
  price_usd     numeric not null,
  duration_days int not null,
  started_at    timestamptz not null default now(),
  expires_at    timestamptz not null,
  created_at    timestamptz not null default now()
);

alter table public.subscriptions enable row level security;

-- Read-only for the account owner
create policy "Users view own subscriptions"
  on public.subscriptions for select
  using (auth.uid() = user_id);

-- No public INSERT policy. Edge Function uses service role key.


-- ── HELPER: plan_is_active() ───────────────────────────────
-- Reusable function that returns true when a profile row has
-- a given plan and the expiry hasn't passed.  Used internally
-- by RLS policies so the logic lives in one place.
create or replace function public.plan_is_active(p public.profiles, required_plan text)
returns boolean language sql stable security definer as $$
  select
    p.plan = required_plan
    and (p.plan_expires_at is null or p.plan_expires_at > now());
$$;


-- ── PORTFOLIO POSITIONS ────────────────────────────────────
-- Users track their own open/closed positions.
-- P&L is computed in the client; only raw data is stored.
create table if not exists public.portfolio_positions (
  id             uuid primary key default gen_random_uuid(),
  user_id        uuid not null references public.profiles(id) on delete cascade,
  symbol         text not null,
  direction      text not null check (direction in ('LONG','SHORT')),
  avg_entry      numeric not null,
  quantity       numeric not null,
  current_price  numeric,                        -- user-supplied or from live feed
  notes          text,
  created_at     timestamptz not null default now()
);

alter table public.portfolio_positions enable row level security;

create policy "Users manage own portfolio"
  on public.portfolio_positions for all
  using  (auth.uid() = user_id)
  with check (auth.uid() = user_id);


-- ── TRADING GOALS ──────────────────────────────────────────
-- User-defined objectives. Progress is computed in the client
-- by querying journal_entries and profiles — no AI involved.
create table if not exists public.trading_goals (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid not null references public.profiles(id) on delete cascade,
  name          text not null,
  type          text not null check (type in ('win_rate','total_pnl','total_trades','analyses','streak')),
  target_value  numeric not null,
  deadline      date,
  created_at    timestamptz not null default now()
);

alter table public.trading_goals enable row level security;

create policy "Users manage own goals"
  on public.trading_goals for all
  using  (auth.uid() = user_id)
  with check (auth.uid() = user_id);


-- ── TRADING PLANS ──────────────────────────────────────────
-- Pre-trade plans. R:R ratio is computed in the client from
-- entry_price, stop_loss, take_profit — pure arithmetic.
create table if not exists public.trading_plans (
  id             uuid primary key default gen_random_uuid(),
  user_id        uuid not null references public.profiles(id) on delete cascade,
  symbol         text not null,
  name           text not null,
  direction      text not null check (direction in ('LONG','SHORT')),
  entry_price    numeric not null,
  stop_loss      numeric not null,
  take_profit    numeric not null,
  position_size  numeric,
  max_risk_pct   numeric,
  timeframe      text,
  status         text not null default 'active' check (status in ('active','triggered','closed')),
  rr_ratio       numeric,                        -- stored for display; computed client-side
  notes          text,
  created_at     timestamptz not null default now()
);

alter table public.trading_plans enable row level security;

create policy "Users manage own trading plans"
  on public.trading_plans for all
  using  (auth.uid() = user_id)
  with check (auth.uid() = user_id);


-- ── ACHIEVEMENTS ───────────────────────────────────────────
-- Milestone records. Rows are inserted by the browser when
-- a threshold is crossed (no AI, no server function needed).
-- Uniqueness prevents duplicate awards.
create table if not exists public.achievements (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid not null references public.profiles(id) on delete cascade,
  achievement_id  text not null,
  earned_at       timestamptz not null default now(),
  unique(user_id, achievement_id)
);

alter table public.achievements enable row level security;

create policy "Users manage own achievements"
  on public.achievements for all
  using  (auth.uid() = user_id)
  with check (auth.uid() = user_id);
