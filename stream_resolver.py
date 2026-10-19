"""YouTube-only stream resolver + search for Mysify.

SoundCloud has been fully removed (June 2026) — every external track is
now resolved via YouTube's audio streams (`yt-dlp` under the hood).

Public API
----------
    search_external(query, limit)  -> list[dict]         (fast — extract_flat)
    resolve_stream_url(track_id, source_url) -> dict     (single fresh URL)

Both include an in-memory LRU cache so repeat queries within 5 min are
served instantly (~ms) instead of paying the yt-dlp cost every time.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs

log = logging.getLogger("stream_resolver")

# ─────────────── Optional Mongo write-through cache ───────────────
# Set from server.py at startup via `stream_resolver.set_db(db)` so this
# module stays importable without pulling in the motor client directly.
_mongo_db = None  # type: Any


def set_db(db) -> None:
    """Wire the Mongo `db` handle from server.py so resolved URLs survive
    backend redeploys. Passing `None` disables the write-through cache."""
    global _mongo_db
    _mongo_db = db


# ─────────────── URL expiry parsing ───────────────
# googlevideo URLs carry the signed expiry either in the `expire` query
# param (older) or the `expire/<unix>` path segment (newer). Parsing the
# real expiry lets us refresh only when we're close to it, instead of
# blindly refreshing every 45 min.

def _parse_url_expiry(url: str) -> Optional[int]:
    """Return the unix-seconds at which `url` becomes invalid, or None."""
    if not url:
        return None
    try:
        # `expire=<unix>` query param
        q = parse_qs(urlparse(url).query)
        exp = q.get("expire", [None])[0]
        if exp and exp.isdigit():
            return int(exp)
        # `.../expire/<unix>/...` path segment
        m = re.search(r"/expire/(\d{10})(?:/|$)", url)
        if m:
            return int(m.group(1))
    except Exception:
        pass
    return None


async def _mongo_get(key: str) -> dict | None:
    if _mongo_db is None:
        return None
    try:
        doc = await _mongo_db.stream_cache.find_one({"key": key})
        if not doc:
            return None
        # `expires_at` was migrated from unix float → BSON datetime for the
        # Mongo TTL index. Handle both to stay backwards-compatible.
        exp = doc.get("expires_at")
        now_ts = time.time()
        if isinstance(exp, datetime):
            exp_ts = exp.replace(tzinfo=timezone.utc).timestamp() if exp.tzinfo is None else exp.timestamp()
        elif isinstance(exp, (int, float)):
            exp_ts = float(exp)
        else:
            exp_ts = 0
        if exp_ts <= now_ts:
            await _mongo_db.stream_cache.delete_one({"key": key})
            return None
        return doc.get("payload")
    except Exception as e:
        log.warning("stream_cache get failed key=%s err=%s", key, e)
        return None


async def _mongo_set(key: str, payload: dict, ttl_sec: int) -> None:
    if _mongo_db is None:
        return
    try:
        # Store as BSON datetime so the Mongo TTL index at `expires_at`
        # can auto-delete stale docs. `ttl_sec` is already capped below
        # the signed-URL lifetime by the caller.
        from datetime import timedelta
        expiry_dt = datetime.now(timezone.utc) + timedelta(seconds=ttl_sec)
        await _mongo_db.stream_cache.update_one(
            {"key": key},
            {"$set": {
                "key": key,
                "payload": payload,
                "expires_at": expiry_dt,
                "updated_at": datetime.now(timezone.utc),
            }},
            upsert=True,
        )
    except Exception as e:
        log.warning("stream_cache set failed key=%s err=%s", key, e)


async def migrate_stream_cache_expires_at(db) -> None:
    """One-shot: convert legacy `expires_at` unix-float values to BSON
    datetimes so the TTL index at `expires_at` fires. Safe to call every
    startup — idempotent (skips docs already using datetime).
    """
    try:
        cur = db.stream_cache.find({"expires_at": {"$type": "double"}}, {"_id": 1, "expires_at": 1})
        ops: list = []
        async for doc in cur:
            try:
                dt = datetime.fromtimestamp(float(doc["expires_at"]), tz=timezone.utc)
                ops.append((doc["_id"], dt))
            except Exception:
                continue
        for _id, dt in ops:
            await db.stream_cache.update_one({"_id": _id}, {"$set": {"expires_at": dt}})
        if ops:
            log.info("stream_cache: migrated %d rows expires_at → datetime", len(ops))
        # Also normalise int-typed unix seconds.
        cur2 = db.stream_cache.find({"expires_at": {"$type": "long"}}, {"_id": 1, "expires_at": 1})
        async for doc in cur2:
            try:
                dt = datetime.fromtimestamp(float(doc["expires_at"]), tz=timezone.utc)
                await db.stream_cache.update_one({"_id": doc["_id"]}, {"$set": {"expires_at": dt}})
            except Exception:
                continue
    except Exception as e:
        log.warning("stream_cache migration failed: %s", e)


# ─────────────── LRU cache (in-memory) ───────────────
# Search results have a 5-minute TTL; resolved stream URLs have a 45-minute
# TTL (YouTube's `expire` param is usually 6h but we're conservative).
_SEARCH_CACHE: dict[str, tuple[float, list[dict[str, Any]]]] = {}
_STREAM_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_SEARCH_TTL = 300     # 5 min
_STREAM_TTL = 45 * 60  # 45 min


def _cache_get(cache: dict, key: str, ttl: int) -> Any:
    hit = cache.get(key)
    if not hit:
        return None
    ts, val = hit
    if time.time() - ts > ttl:
        cache.pop(key, None)
        return None
    return val


def _cache_set(cache: dict, key: str, val: Any, max_entries: int = 200) -> None:
    if len(cache) >= max_entries:
        # Evict oldest ~25% of entries so the cache doesn't grow unbounded.
        drop = sorted(cache.items(), key=lambda kv: kv[1][0])[: max_entries // 4]
        for k, _ in drop:
            cache.pop(k, None)
    cache[key] = (time.time(), val)


# ─────────────── yt-dlp sync helpers (run in worker thread) ───────────────

def _extract_sync(source_url: str) -> dict[str, Any]:
    """Fetch a single YouTube URL's best-audio format. Returns yt-dlp info dict.

    Uses the `ios` + `android_music` player clients which emulate YouTube
    Music's own mobile apps — these consistently serve clean M4A/AAC
    streams that bypass most 403 / signature-cipher paths the web client
    hits, and are the yt-dlp community's recommended "zero-ban" default
    for server-side extraction (June 2026).
    """
    from yt_dlp import YoutubeDL  # type: ignore

    opts = {
        # Hard preference for progressive M4A/AAC audio — instantaneous
        # buffering on native TrackPlayer / ExoPlayer, no manifest parsing.
        "format": "bestaudio[ext=m4a][acodec^=mp4a]/bestaudio[ext=m4a]/bestaudio/best",
        "quiet": True,
        "no_warnings": True,
        "skip_download": True,
        "socket_timeout": 5,
        "outtmpl": "-",
        "noplaylist": True,
        "writesubtitles": False,
        "writethumbnail": False,
        # Cut yt-dlp's extractor retries — we handle fallback ourselves.
        "extractor_retries": 1,
        "retries": 1,
        # ★ Modern YouTube extractor client stack (Oct 2026):
        # `tv_embedded` → unauthenticated clients that still serve audio
        # without the server needing a PO token, `mweb` → good fallback
        # for region-locked uploads. Keeping `ios` on the list too for
        # cases where YT's auction briefly flips back.
        "extractor_args": {
            "youtube": {
                "player_client": ["tv_embedded", "mweb", "ios"],
                # Skip the fragmented DASH manifest — we want the direct
                # progressive URL only.
                "skip": ["dash", "hls"],
            }
        },
    }
    with YoutubeDL(opts) as ydl:
        info = ydl.extract_info(source_url, download=False)
    return info or {}


def _ytsearch_first_sync(query: str, index: int = 1) -> dict[str, Any]:
    """Run `ytsearchN:` for a query and return the picked (last) entry.
    Used both for standalone search fallback and for freshening a
    resolver-picked URL that turns out DRM-locked."""
    from yt_dlp import YoutubeDL  # type: ignore

    opts = {
        "format": "bestaudio[ext=m4a][acodec^=mp4a]/bestaudio[ext=m4a]/bestaudio/best",
        "quiet": True,
        "no_warnings": True,
        "skip_download": True,
        "socket_timeout": 5,
        "outtmpl": "-",
        "noplaylist": True,
        "default_search": f"ytsearch{index}",
        "ignoreerrors": True,
        "extractor_retries": 1,
        "retries": 1,
        "extractor_args": {
            "youtube": {
                "player_client": ["tv_embedded", "mweb", "ios"],
                "skip": ["dash", "hls"],
            }
        },
    }
    with YoutubeDL(opts) as ydl:
        info = ydl.extract_info(f"ytsearch{index}:{query}", download=False)
    if info and "entries" in info:
        entries = info.get("entries") or []
        if entries:
            return entries[-1] or {}
    return info or {}


def _search_sync(query: str, limit: int) -> list[dict[str, Any]]:
    """Fast YouTube search using `extract_flat`. Never resolves stream URLs —
    those are fetched on-demand when the user actually taps play."""
    from yt_dlp import YoutubeDL  # type: ignore

    spec = f"ytsearch{limit}:{query}"
    opts = {
        "quiet": True,
        "no_warnings": True,
        "skip_download": True,
        "socket_timeout": 5,
        "outtmpl": "-",
        "noplaylist": False,
        # `in_playlist` returns just id / title / url / duration / thumbnail —
        # ~5-10× faster than the full extractor loop.
        "extract_flat": "in_playlist",
        "extractor_retries": 1,
        "retries": 1,
    }
    with YoutubeDL(opts) as ydl:
        info = ydl.extract_info(spec, download=False)
    entries = (info or {}).get("entries") or []
    out: list[dict[str, Any]] = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        # Prefer canonical webpage_url; fall back to building it from id.
        url = e.get("webpage_url") or e.get("original_url") or e.get("url")
        if isinstance(url, str) and not url.startswith(("http://", "https://")):
            if e.get("id"):
                url = f"https://www.youtube.com/watch?v={e['id']}"
        if not isinstance(url, str) or not url.startswith("http"):
            continue
        # Best available thumbnail (last = highest res in yt-dlp's list).
        thumb = None
        thumbs = e.get("thumbnails") or []
        if thumbs and isinstance(thumbs, list) and isinstance(thumbs[-1], dict):
            thumb = thumbs[-1].get("url")
        if not thumb:
            thumb = e.get("thumbnail")
        # Fallback: build the well-known YouTube i.ytimg.com URL from id so
        # every result has a visible cover.
        if not thumb and e.get("id"):
            thumb = f"https://i.ytimg.com/vi/{e['id']}/hqdefault.jpg"
        title = e.get("title") or "Untitled"
        artist = (
            e.get("uploader")
            or e.get("channel")
            or e.get("creator")
            or "Unknown"
        )
        duration = e.get("duration")
        out.append({
            "source_url": url,
            "title": str(title),
            "artist": str(artist),
            "duration": int(duration) if isinstance(duration, (int, float)) else None,
            "thumbnail": thumb,
            "provider": "youtube",
        })
    return out


# ─────────────── URL / classification helpers ───────────────

def _classify_stream_format(url: str, info: dict[str, Any]) -> str:
    """Return 'hls' or 'mp3' so react-native-track-player can set `type` right."""
    proto = (info.get("protocol") or "").lower()
    if "m3u8" in proto or "hls" in proto:
        return "hls"
    lower = (url or "").split("?")[0].lower()
    if lower.endswith(".m3u8") or ".m3u8" in lower:
        return "hls"
    ext = (info.get("ext") or "").lower()
    if ext in {"m4a", "mp3", "aac", "opus", "webm", "ogg"}:
        return "mp3"
    return "mp3"


def _pick_url(info: dict[str, Any]) -> Optional[str]:
    top = info.get("url")
    if isinstance(top, str) and top.startswith(("http://", "https://")):
        return top
    for candidate in info.get("requested_formats", []) or []:
        u = candidate.get("url")
        if isinstance(u, str) and u.startswith("http"):
            return u
    for candidate in info.get("formats", []) or []:
        u = candidate.get("url")
        if isinstance(u, str) and u.startswith("http"):
            return u
    return None


# ─────────────── Public async API ───────────────

# Single-flight coalescing: multiple concurrent resolve requests for the
# same source_url share the same in-flight future so yt-dlp only runs once.
_inflight: dict[str, asyncio.Future[dict[str, Any]]] = {}


async def resolve_stream_url(
    track_id: str,
    source_url: str,
    *,
    timeout: float = 8.0,
    fallback_query: str | None = None,
) -> dict[str, Any]:
    """Extract a fresh playable YouTube audio URL. Always returns a dict.

    SoundCloud has been REMOVED (June 2026). If `source_url` is anything
    other than a YouTube URL we skip direct extraction and go straight to
    a `ytsearch` on `fallback_query` (title + artist) — this preserves
    playback for tracks whose stored `source_url` still points at legacy
    SoundCloud content.

    Cache: same source_url is cached until its googlevideo `expire` param
    is within 5 min of firing (fall back to a 45-min hard cap in-memory).
    Mongo mirror lasts up to 5h30m (below YouTube's ~6h signature window).
    """
    # ── Single-flight ──
    # If another coroutine is already resolving this exact source_url,
    # await its result instead of firing yt-dlp again.
    if source_url:
        fut = _inflight.get(source_url)
        if fut is not None and not fut.done():
            try:
                return await asyncio.wait_for(asyncio.shield(fut), timeout=timeout + 2)
            except asyncio.TimeoutError:
                pass  # fall through to fresh attempt

    loop = asyncio.get_running_loop()
    my_future: asyncio.Future[dict[str, Any]] | None = None
    if source_url:
        my_future = loop.create_future()
        _inflight[source_url] = my_future

    try:
        result = await _resolve_stream_url_impl(
            track_id, source_url, timeout=timeout, fallback_query=fallback_query,
        )
        if my_future is not None and not my_future.done():
            my_future.set_result(result)
        return result
    except Exception as e:
        if my_future is not None and not my_future.done():
            my_future.set_exception(e)
        raise
    finally:
        # Always clear the in-flight entry so a failed lookup doesn't
        # perma-lock subsequent callers.
        if source_url and _inflight.get(source_url) is my_future:
            _inflight.pop(source_url, None)


async def _resolve_stream_url_impl(
    track_id: str,
    source_url: str,
    *,
    timeout: float,
    fallback_query: str | None,
) -> dict[str, Any]:
    if not source_url or not isinstance(source_url, str):
        if not fallback_query:
            return {"error": "stream_unavailable", "detail": "No source URL or search hint."}
        source_url = ""

    if source_url:
        cached = _cache_get(_STREAM_CACHE, source_url, _STREAM_TTL)
        if cached and _cache_still_fresh(cached):
            return cached
        # Warm from Mongo cache (survives redeploys)
        m = await _mongo_get(source_url)
        if m and isinstance(m, dict) and m.get("url") and _cache_still_fresh(m):
            _cache_set(_STREAM_CACHE, source_url, m)
            return m

    async def _do_extract(url: str) -> dict[str, Any]:
        return await asyncio.wait_for(
            asyncio.get_running_loop().run_in_executor(None, _extract_sync, url),
            timeout=timeout,
        )

    async def _do_ytsearch(query: str, index: int) -> dict[str, Any]:
        return await asyncio.wait_for(
            asyncio.get_running_loop().run_in_executor(None, _ytsearch_first_sync, query, index),
            timeout=timeout,
        )

    info: dict[str, Any] = {}
    primary_err: str | None = None
    lower = source_url.lower()
    is_youtube = (
        "youtube.com/" in lower or "youtu.be/" in lower or "music.youtube.com" in lower
    )
    if source_url and is_youtube:
        # Up to 2 attempts on the direct extractor — a single yt-dlp
        # network hiccup shouldn't dead-end a searched track.
        for attempt in range(2):
            try:
                info = await _do_extract(source_url)
                if info:
                    break
            except asyncio.TimeoutError:
                primary_err = "Extractor timed out."
                log.warning("resolve timeout track_id=%s attempt=%s", track_id, attempt + 1)
            except Exception as e:
                primary_err = str(e)[:240]
                log.warning(
                    "resolve failed track_id=%s attempt=%s src=%s err=%s",
                    track_id, attempt + 1, source_url, e,
                )
            if attempt == 0:
                await asyncio.sleep(0.4)  # brief backoff before retry
    else:
        primary_err = "Non-YouTube source — routing through YouTube search."

    url = _pick_url(info) if info else None

    # Fallback: ytsearch by title/artist, up to 2 hits, when the direct
    # extract failed or the source is legacy. Two hits so a DRM-locked
    # top result doesn't kill the whole song.
    if not url and (fallback_query or info.get("title")):
        query = fallback_query or (info.get("title") or "").strip()
        if query:
            # Artist-alternative chain (June 2026 spec): bias toward
            # verified clean audio sources — YouTube Topic channels and
            # "Official Audio" uploads almost never 403. Try the plain
            # query first, then artist-alternative variants.
            fallback_queries = [query]
            # If the query already contains "topic" or "official" we're
            # golden; otherwise append variants to boost hit rate.
            lq = query.lower()
            if "topic" not in lq and "official" not in lq:
                fallback_queries.append(f"{query} official audio")
                fallback_queries.append(f"{query} topic")
            tried_url: str | None = None
            is_artist_alt = False
            for q_i, fq in enumerate(fallback_queries):
                for idx in (1, 2):
                    try:
                        info = await _do_ytsearch(fq, idx)
                        picked = _pick_url(info)
                        if picked:
                            tried_url = picked
                            is_artist_alt = q_i > 0
                            break
                    except Exception as e:
                        log.warning(
                            "ytsearch fallback failed track_id=%s q=%s idx=%s err=%s",
                            track_id, fq, idx, e,
                        )
                if tried_url:
                    break
            url = tried_url
            if is_artist_alt:
                info = {**(info or {}), "is_artist_alternative": True}

    if not url:
        detail = primary_err or "Extractor returned no URL."
        return {"error": "stream_unavailable", "detail": detail}

    # Compute the real expiry from the resolved URL so cache TTLs mirror
    # YouTube's own signature clock instead of a blind 45-min guess.
    expiry_unix = _parse_url_expiry(url)
    now_ts = time.time()
    # Refresh 5 min before real expiry to avoid mid-play stalls. Cap Mongo
    # cache to 5h30m (below the observed ~6h signature window).
    lifetime = max(60, int(expiry_unix - now_ts) - 300) if expiry_unix else 5 * 60 * 60 + 30 * 60
    lifetime = min(lifetime, 5 * 60 * 60 + 30 * 60)

    payload = {
        "url": url,
        "stream_format": _classify_stream_format(url, info),
        "expires_in": info.get("duration"),
        "expires_at_unix": expiry_unix,   # used by _cache_still_fresh
        "title": info.get("title"),
        "extractor": info.get("extractor") or "youtube",
        # Signals to the client that we had to substitute an alternative
        # track from the same artist (user spec: zero broken songs).
        "is_artist_alternative": bool(info.get("is_artist_alternative")),
    }
    if source_url:
        _cache_set(_STREAM_CACHE, source_url, payload)
        await _mongo_set(source_url, payload, ttl_sec=lifetime)
    return payload


def _cache_still_fresh(payload: dict) -> bool:
    """True when the cached URL has more than 5 min of signed life left.
    Falls back to `_STREAM_TTL`-based freshness when no `expires_at_unix`
    is stored (legacy cache entries)."""
    exp = payload.get("expires_at_unix")
    if isinstance(exp, (int, float)) and exp > 0:
        return (exp - time.time()) > 300  # 5 min buffer
    return True  # legacy entries: trust the in-memory / Mongo TTL


async def search_external(
    query: str,
    *,
    provider: str = "youtube",  # legacy arg — always yt now
    limit: int = 15,
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    """Fast YouTube-only search. Caches results for 5 minutes.

    `provider` is accepted but ignored (kept for API-shape compatibility).
    """
    _ = provider  # kept for backwards compatibility with existing callers
    if not query or not query.strip():
        return []
    limit = max(1, min(int(limit or 10), 25))
    cache_key = f"{query.strip().lower()}::{limit}"
    cached = _cache_get(_SEARCH_CACHE, cache_key, _SEARCH_TTL)
    if cached is not None:
        return cached
    try:
        loop = asyncio.get_running_loop()
        results = await asyncio.wait_for(
            loop.run_in_executor(None, _search_sync, query.strip(), limit),
            timeout=timeout,
        )
        _cache_set(_SEARCH_CACHE, cache_key, results)
        return results
    except asyncio.TimeoutError:
        log.warning("search timeout q=%s ts=%s",
                    query, datetime.now(timezone.utc).isoformat())
        return []
    except Exception as e:
        log.warning("search failed q=%s err=%s ts=%s",
                    query, e, datetime.now(timezone.utc).isoformat())
        return []
