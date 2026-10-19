-- Musify Supabase schema (run once in Supabase SQL editor)

create extension if not exists pg_trgm;

create table if not exists public.songs (
  song_id        text primary key,
  title          text not null,
  artist_id      text not null,
  artist_name    text not null,
  genre          text not null default 'Pop',
  mood           text not null default 'Chill',
  language       text default 'English',
  explicit       boolean default false,
  credits        text default '',
  lyrics         text default '',
  cover_url      text,
  audio_url      text not null,
  duration_sec   integer default 0,
  streams        bigint default 0,
  is_published   boolean default true,
  is_featured    boolean default false,
  created_at     timestamp with time zone default now()
);
create index if not exists songs_title_trgm    on public.songs using gin (title gin_trgm_ops);
create index if not exists songs_artist_idx    on public.songs (artist_name);
create index if not exists songs_artist_id_idx on public.songs (artist_id);
create index if not exists songs_genre_idx     on public.songs (genre);
create index if not exists songs_created_idx   on public.songs (created_at desc);
create index if not exists songs_streams_idx   on public.songs (streams desc);

-- Stream logs: scalable, indexed for fast aggregation
create table if not exists public.stream_logs (
  id               uuid primary key default gen_random_uuid(),
  user_id          text,
  track_id         text not null,
  listened_at      timestamp with time zone not null default now(),
  duration_seconds integer not null,
  client_ip        text
);
create index if not exists stream_logs_track_idx     on public.stream_logs (track_id);
create index if not exists stream_logs_listened_idx  on public.stream_logs (listened_at desc);
create index if not exists stream_logs_track_time    on public.stream_logs (track_id, listened_at desc);
create index if not exists stream_logs_user_track    on public.stream_logs (user_id, track_id, listened_at desc);

alter table public.songs       enable row level security;
alter table public.stream_logs enable row level security;
create policy if not exists "songs_public_read"        on public.songs       for select using (true);
create policy if not exists "stream_logs_public_read"  on public.stream_logs for select using (true);
