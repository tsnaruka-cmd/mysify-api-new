"""Musify backend — FastAPI + MongoDB.

Routes mounted under /api. Auth: JWT (email/password) + Emergent Google Auth session.
Audio: external URL for seed songs, GridFS for artist uploads served via /api/songs/{id}/stream.
"""

from __future__ import annotations

import asyncio
import io
import logging
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import bcrypt
import httpx
import jwt
from dotenv import load_dotenv
from fastapi import (
    APIRouter,
    Body,
    Depends,
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    Query,
    Request,
    UploadFile,
)
from fastapi.responses import StreamingResponse
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorGridFSBucket
from pydantic import BaseModel, EmailStr, Field
from starlette.middleware.cors import CORSMiddleware

# Play Billing (Google Play subscriptions) — router + startup helper
import play_billing
# Fresh-stream-URL resolver (yt-dlp / soundcloud) for tracks with external
# source URLs whose direct-play URLs expire per session.
import stream_resolver

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

MONGO_URL = os.environ["MONGO_URL"]
DB_NAME = os.environ["DB_NAME"]
# JWT_SECRET must come from the environment in production. A local dev
# fallback is only used when running with a stub — deploy pipelines inject
# the real value. A missing production secret is caught at request time by
# the token codepath, not silently accepted.
JWT_SECRET = os.environ.get("JWT_SECRET") or os.environ.get("DEV_JWT_SECRET") or "dev-only-not-for-prod"
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@musify.app")
ADMIN_DEFAULT_PASSWORD = os.environ.get("ADMIN_DEFAULT_PASSWORD") or os.environ.get("DEV_ADMIN_PASSWORD") or ""

EMERGENT_PUSH_BASE_URL = "https://integrations.emergentagent.com"
EMERGENT_PUSH_KEY = os.environ.get("EMERGENT_PUSH_KEY", "placeholder")
_push_client = httpx.AsyncClient(
    base_url=EMERGENT_PUSH_BASE_URL,
    headers={"X-Push-Key": EMERGENT_PUSH_KEY},
    timeout=10.0,
)

# ─────── Cloudflare R2 (song audio storage) ───────
R2_ENDPOINT = os.environ.get("R2_ENDPOINT", "")
R2_ACCESS_KEY_ID = os.environ.get("R2_ACCESS_KEY_ID", "")
R2_SECRET_ACCESS_KEY = os.environ.get("R2_SECRET_ACCESS_KEY", "")
R2_BUCKET = os.environ.get("R2_BUCKET", "mysifysongstroage")
R2_PUBLIC_BASE = os.environ.get("R2_PUBLIC_BASE", "").rstrip("/")

_r2_client = None
if R2_ENDPOINT and R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY:
    try:
        import boto3
        from botocore.config import Config as _BotoConfig
        _r2_client = boto3.client(
            "s3",
            endpoint_url=R2_ENDPOINT,
            aws_access_key_id=R2_ACCESS_KEY_ID,
            aws_secret_access_key=R2_SECRET_ACCESS_KEY,
            region_name="auto",
            config=_BotoConfig(signature_version="s3v4", s3={"addressing_style": "path"}),
        )
    except Exception as _e:
        _r2_client = None


def r2_upload_bytes(key: str, data: bytes, content_type: str) -> str:
    """Upload bytes to R2 and return the public URL."""
    if not _r2_client:
        raise RuntimeError("R2 client not configured")
    _r2_client.put_object(
        Bucket=R2_BUCKET, Key=key, Body=data,
        ContentType=content_type or "application/octet-stream",
        CacheControl="public, max-age=31536000, immutable",
    )
    if R2_PUBLIC_BASE:
        return f"{R2_PUBLIC_BASE}/{key}"
    return f"{R2_ENDPOINT}/{R2_BUCKET}/{key}"


def r2_delete_key(key: str) -> bool:
    if not _r2_client:
        return False
    try:
        _r2_client.delete_object(Bucket=R2_BUCKET, Key=key)
        return True
    except Exception as e:
        log.warning("r2 delete failed key=%s: %s", key, e)
        return False


def r2_key_from_url(url: str) -> Optional[str]:
    if not url:
        return None
    if R2_PUBLIC_BASE and url.startswith(R2_PUBLIC_BASE + "/"):
        return url[len(R2_PUBLIC_BASE) + 1:]
    if R2_ENDPOINT and url.startswith(R2_ENDPOINT + "/" + R2_BUCKET + "/"):
        return url[len(R2_ENDPOINT) + len(R2_BUCKET) + 2:]
    return None
client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]
# Wire the shared Mongo handle into the resolver so it can persist
# resolved stream URLs across backend redeploys.
stream_resolver.set_db(db)
gridfs = AsyncIOMotorGridFSBucket(db, bucket_name="audio")

app = FastAPI(title="Musify API")
api = APIRouter(prefix="/api")


# Root-level health check — the platform's container probe hits bare
# "/health" (no "/api" prefix). Without this it 404s forever and the
# deployment is treated as unhealthy, which was triggering periodic
# restarts and the intermittent slow cold-start home load users reported.
# /api/health (below, under the `api` router) remains for in-app use.
@app.get("/health")
async def root_health():
    return {"ok": True}

# ── Gzip compression for big JSON payloads (1 lakh DAU optimisation) ──
from starlette.middleware.gzip import GZipMiddleware  # noqa: E402
app.add_middleware(GZipMiddleware, minimum_size=512)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("musify")


# ──────────────────────────── helpers ────────────────────────────

def now() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str = "id") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def hash_pwd(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_pwd(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def make_jwt(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "iat": int(now().timestamp()),
        "exp": int((now() + timedelta(days=30)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def decode_jwt(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload.get("sub")
    except Exception:
        return None


def public_user(u: dict) -> dict:
    if not u:
        return {}
    return {
        "id": u["user_id"],
        "email": u["email"],
        "name": u.get("name", ""),
        "avatar": u.get("avatar"),
        "role": u.get("role", "user"),
        "is_premium": u.get("is_premium", False),
        "upi_id": u.get("upi_id"),
        "bio": u.get("bio", ""),
        "followers": u.get("followers", 0),
        "monthly_listeners": u.get("monthly_listeners", 0),
        "instagram": u.get("instagram"),
        "twitter": u.get("twitter"),
        "youtube": u.get("youtube"),
    }


async def current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()

    # 1) JWT (email/password)
    sub = decode_jwt(token)
    if sub:
        u = await db.users.find_one({"user_id": sub}, {"_id": 0, "password_hash": 0})
        if u:
            return u

    # 2) Emergent session token
    sess = await db.user_sessions.find_one({"session_token": token}, {"_id": 0})
    if sess:
        exp = sess.get("expires_at")
        if isinstance(exp, datetime):
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp < now():
                raise HTTPException(status_code=401, detail="Session expired")
        u = await db.users.find_one({"user_id": sess["user_id"]}, {"_id": 0, "password_hash": 0})
        if u:
            return u

    raise HTTPException(status_code=401, detail="Invalid token")


async def require_role(user: dict, roles: list[str]) -> dict:
    if user.get("role") not in roles:
        raise HTTPException(status_code=403, detail="Forbidden")
    return user


# ──────────────────────────── models ────────────────────────────

class SignupBody(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)
    name: str = Field(min_length=1, max_length=80)


class LoginBody(BaseModel):
    email: EmailStr
    password: str


class GoogleSessionBody(BaseModel):
    session_id: str


class ProfileUpdate(BaseModel):
    name: Optional[str] = None
    bio: Optional[str] = None
    avatar: Optional[str] = None
    avatar_base64: Optional[str] = None  # data URL or raw base64 PNG/JPEG (frontend uploads here)
    upi_id: Optional[str] = None
    instagram: Optional[str] = None
    twitter: Optional[str] = None
    youtube: Optional[str] = None


class EditSongBody(BaseModel):
    title: Optional[str] = None
    genre: Optional[str] = None
    mood: Optional[str] = None
    language: Optional[str] = None
    explicit: Optional[bool] = None
    credits: Optional[str] = None
    lyrics: Optional[str] = None
    cover_url: Optional[str] = None
    cover_base64: Optional[str] = None
    is_published: Optional[bool] = None


class PlanBody(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    price: float = Field(ge=0, le=100000)
    currency: str = "INR"
    period: str = "monthly"   # monthly | yearly | lifetime
    features: list[str] = []
    is_active: bool = True
    sort_order: int = 0


class PlaylistLayout(BaseModel):
    style: str = Field(default="vertical_list")  # vertical_list | vertical_grid | horizontal_carousel
    rows: int = Field(default=1, ge=1, le=10)
    columns: int = Field(default=1, ge=1, le=6)


class PlaylistCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    description: str = ""
    is_public: bool = True
    layout: Optional[PlaylistLayout] = None


class PlaylistLayoutUpdate(BaseModel):
    style: str = Field(min_length=1, max_length=32)
    rows: int = Field(default=1, ge=1, le=10)
    columns: int = Field(default=1, ge=1, le=6)


class PlaylistSongOp(BaseModel):
    song_id: str


class TipBody(BaseModel):
    amount: int = Field(ge=1, le=100000)


class FeatureBody(BaseModel):
    is_featured: bool


class ApproveArtistBody(BaseModel):
    user_id: str
    approve: bool


class ChangePasswordBody(BaseModel):
    current_password: Optional[str] = None  # optional for admin-forced change
    new_password: str = Field(min_length=6)


class TogglePremiumBody(BaseModel):
    user_id: str
    is_premium: bool
    plan: Optional[str] = "admin_granted"


class RegisterPushBody(BaseModel):
    user_id: str
    platform: str
    device_token: str


class StreamLogBody(BaseModel):
    track_id: str
    duration_seconds: int = Field(ge=0, le=3600)
    total_seconds: Optional[int] = Field(default=None, ge=0, le=7200)


class ExternalSongUpsert(BaseModel):
    """External-search track being upserted into `db.songs` so the app's
    likes / playlists / recently-played all key off `song_id` uniformly.
    Songs land with `is_published=False` and `is_external=True` so they
    do NOT surface in trending / new-release / discovery feeds — only in
    the user's private collections."""
    song_id: str = Field(min_length=3, max_length=64)
    title: str = Field(min_length=1, max_length=200)
    artist_name: str = Field(default="Unknown", max_length=200)
    cover_url: str = Field(default="", max_length=1024)
    source_url: str = Field(min_length=1, max_length=2048)
    duration_sec: int = Field(default=0, ge=0, le=10800)
    provider: str = Field(default="youtube", max_length=32)  # SoundCloud fully removed (June 2026)


async def send_push(recipients: list[str], data: dict, idempotency_key: Optional[str] = None) -> None:
    """Relay to Emergent push service. Non-blocking — caller wraps in try/except."""
    if not recipients:
        return
    payload: dict = {"recipients": recipients[:100], "data": data}
    if idempotency_key:
        payload["$idempotency_key"] = idempotency_key
    resp = await _push_client.post("/api/v1/push/trigger", json=payload)
    if resp.status_code == 401:
        raise HTTPException(500, "EMERGENT_PUSH_KEY missing or invalid")
    if resp.status_code >= 500:
        raise HTTPException(502, "Push provider unavailable")
    resp.raise_for_status()


# ──────────────────────────── auth ────────────────────────────

async def _build_session_for(user_id: str) -> str:
    """Create a long-lived bearer token (JWT) for the given user."""
    return make_jwt(user_id)


def _role_for_email(email: str) -> str:
    return "admin" if email.lower() == ADMIN_EMAIL.lower() else "user"


@api.post("/auth/signup")
async def auth_signup(body: SignupBody):
    email = body.email.lower()
    existing = await db.users.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    uid = new_id("user")
    doc = {
        "user_id": uid,
        "email": email,
        "name": body.name,
        "password_hash": hash_pwd(body.password),
        "role": _role_for_email(email),
        "is_premium": False,
        "avatar": None,
        "bio": "",
        "upi_id": None,
        "followers": 0,
        "monthly_listeners": 0,
        "created_at": now(),
    }
    await db.users.insert_one(doc)
    token = await _build_session_for(uid)
    doc.pop("password_hash", None)
    doc.pop("_id", None)
    return {"token": token, "user": public_user(doc)}


@api.post("/auth/login")
async def auth_login(body: LoginBody):
    email = body.email.lower()
    u = await db.users.find_one({"email": email})
    if not u or not u.get("password_hash") or not verify_pwd(body.password, u["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    # Keep admin role enforced for the admin email
    if email == ADMIN_EMAIL.lower() and u.get("role") != "admin":
        await db.users.update_one({"user_id": u["user_id"]}, {"$set": {"role": "admin"}})
        u["role"] = "admin"
    token = await _build_session_for(u["user_id"])
    u.pop("password_hash", None)
    u.pop("_id", None)
    return {"token": token, "user": public_user(u)}


@api.post("/auth/google/session")
async def auth_google_session(body: GoogleSessionBody):
    """Exchange Emergent OAuth session_id for our app session token."""
    async with httpx.AsyncClient(timeout=15) as hc:
        r = await hc.get(
            "https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data",
            headers={"X-Session-ID": body.session_id},
        )
        if r.status_code != 200:
            raise HTTPException(status_code=401, detail="Invalid session")
        data = r.json()

    email = (data.get("email") or "").lower()
    if not email:
        raise HTTPException(status_code=400, detail="Bad session payload")

    u = await db.users.find_one({"email": email})
    if not u:
        uid = new_id("user")
        doc = {
            "user_id": uid,
            "email": email,
            "name": data.get("name") or email.split("@")[0],
            "avatar": data.get("picture"),
            "role": _role_for_email(email),
            "is_premium": False,
            "bio": "",
            "upi_id": None,
            "followers": 0,
            "monthly_listeners": 0,
            "created_at": now(),
        }
        await db.users.insert_one(doc)
        u = doc
    else:
        # Lift to admin if matches admin email
        if email == ADMIN_EMAIL.lower() and u.get("role") != "admin":
            await db.users.update_one({"user_id": u["user_id"]}, {"$set": {"role": "admin"}})
            u["role"] = "admin"

    # Persist session for Emergent token compatibility
    session_token = data.get("session_token") or secrets.token_urlsafe(32)
    await db.user_sessions.insert_one(
        {
            "session_token": session_token,
            "user_id": u["user_id"],
            "created_at": now(),
            "expires_at": now() + timedelta(days=7),
        }
    )
    u.pop("_id", None)
    return {"token": session_token, "user": public_user(u)}


@api.get("/auth/me")
async def auth_me(user: dict = Depends(current_user)):
    return {"user": public_user(user)}


@api.post("/auth/logout")
async def auth_logout(authorization: Optional[str] = Header(None)):
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        await db.user_sessions.delete_one({"session_token": token})
    return {"ok": True}


@api.put("/me")
async def update_me(body: ProfileUpdate, user: dict = Depends(current_user)):
    patch = {k: v for k, v in body.dict(exclude_unset=True).items() if v is not None}
    # Convert base64 avatar → data URL string. Frontend may already send a data URL.
    if "avatar_base64" in patch:
        b64 = patch.pop("avatar_base64") or ""
        if b64.startswith("data:"):
            patch["avatar"] = b64
        elif b64:
            patch["avatar"] = f"data:image/jpeg;base64,{b64}"
    if patch:
        await db.users.update_one({"user_id": user["user_id"]}, {"$set": patch})
    u = await db.users.find_one({"user_id": user["user_id"]}, {"_id": 0, "password_hash": 0})
    return {"user": public_user(u)}


@api.post("/me/change-password")
async def change_password(body: ChangePasswordBody, user: dict = Depends(current_user)):
    full = await db.users.find_one({"user_id": user["user_id"]})
    if not full:
        raise HTTPException(404, "User not found")
    # Google-only users have no password_hash — allow setting one.
    if full.get("password_hash"):
        if not body.current_password or not verify_pwd(body.current_password, full["password_hash"]):
            raise HTTPException(401, "Current password is incorrect")
    await db.users.update_one(
        {"user_id": user["user_id"]},
        {"$set": {"password_hash": hash_pwd(body.new_password)}},
    )
    return {"ok": True}


@api.post("/me/push-token")
async def register_push_token(body: RegisterPushBody, user: dict = Depends(current_user)):
    """Register a device push token for the current user (relays to Emergent push)."""
    if body.user_id != user["user_id"]:
        raise HTTPException(403, "user_id mismatch")
    # Persist locally regardless so admin can see registered devices.
    await db.push_tokens.update_one(
        {"user_id": body.user_id, "platform": body.platform},
        {"$set": {"device_token": body.device_token, "updated_at": now()}},
        upsert=True,
    )
    # Short-circuit upstream call if the key is the placeholder (pre-deploy state).
    if EMERGENT_PUSH_KEY == "placeholder":
        return {"status": "stored_local_only", "reason": "push_key_not_configured"}
    try:
        resp = await _push_client.post(
            "/api/v1/push/users/register",
            json={"user_id": body.user_id, "platform": body.platform, "device_token": body.device_token},
        )
        if resp.status_code >= 500:
            raise HTTPException(502, "Push provider unavailable")
        resp.raise_for_status()
    except HTTPException:
        raise
    except Exception as e:
        log.warning("push register failed (non-blocking): %s", e)
    return {"status": "registered"}


@api.get("/me/download/{song_id}")
async def download_song(song_id: str, user: dict = Depends(current_user)):
    """Premium-only: returns a direct, downloadable URL to the audio."""
    if not user.get("is_premium") and user.get("role") not in ("artist", "admin"):
        raise HTTPException(403, "Premium required to download")
    s = await db.songs.find_one({"song_id": song_id}, {"_id": 0})
    if not s:
        raise HTTPException(404, "Not found")
    url = s.get("audio_url") or (f"/api/songs/{song_id}/stream" if s.get("audio_kind") == "gridfs" else None)
    if not url:
        raise HTTPException(404, "No downloadable source")
    return {"url": url, "title": s["title"], "artist": s["artist_name"]}


# ──────────────────────────── catalog / songs ────────────────────────────

async def _enrich_song(s: dict) -> dict:
    """Strip _id; ensure stream_url is set for both seed and uploaded songs.

    Also lazily migrates any legacy inline-base64 `cover_url` (from songs
    uploaded before R2 covers existed) to R2 the first time the song is
    read. Serving the raw base64 blob in list responses (e.g. /api/home)
    was adding several MB per song to every page load -- this makes it a
    one-time, self-healing fix instead of a one-off data migration.
    """
    s.pop("_id", None)
    if s.get("audio_kind") == "gridfs":
        s["stream_url"] = f"/api/songs/{s['song_id']}/stream"
    cover = s.get("cover_url") or ""
    if cover.startswith("data:") and _r2_client is not None:
        try:
            import base64
            header, _, b64data = cover.partition(",")
            ext = "png" if "png" in header else "jpg"
            raw = base64.b64decode(b64data)
            key = f"covers/{s['song_id']}.{ext}"
            uploaded = r2_upload_bytes(key, raw, "image/png" if ext == "png" else "image/jpeg")
            await db.songs.update_one({"song_id": s["song_id"]}, {"$set": {"cover_url": uploaded}})
            s["cover_url"] = uploaded
        except Exception as e:
            log.warning("lazy cover migration failed for %s: %s", s.get("song_id"), e)
    return s


@api.get("/songs")
async def list_songs(
    limit: int = Query(20, ge=1, le=50),
    skip: int = Query(0, ge=0),
    genre: Optional[str] = None,
    artist_id: Optional[str] = None,
    sort: str = Query("recent", regex="^(recent|trending|streams)$"),
):
    q: dict = {"is_published": True}
    if genre:
        q["genre"] = genre
    if artist_id:
        q["artist_id"] = artist_id
    sort_field = {"recent": "created_at", "trending": "trending_score", "streams": "streams"}[sort]
    cur = db.songs.find(q).sort(sort_field, -1).skip(skip).limit(limit)
    return {"items": [await _enrich_song(s) async for s in cur]}


@api.get("/songs/trending")
async def trending_songs(limit: int = Query(8, ge=1, le=200)):
    """Top N most-played songs (default 8). Max 200 for view-all pages."""
    items = await db.songs.find(
        {"is_published": True}
    ).sort([("play_count", -1), ("trending_score", -1), ("created_at", -1)]).limit(limit).to_list(length=limit)
    return {"items": [await _enrich_song(s) for s in items]}


@api.get("/songs/new-releases")
async def new_release_songs(limit: int = Query(10, ge=1, le=200)):
    cur = db.songs.find({"is_published": True}).sort("created_at", -1).limit(limit)
    return {"items": [await _enrich_song(s) async for s in cur]}


@api.get("/songs/recommended")
async def recommended_songs(limit: int = Query(10, ge=1, le=500)):
    cur = db.songs.aggregate([
        {"$match": {"is_published": True}},
        {"$sample": {"size": limit}},
    ])
    return {"items": [await _enrich_song(s) async for s in cur]}


@api.get("/songs/featured")
async def featured_songs():
    cur = db.songs.find({"is_published": True, "is_featured": True}).limit(10)
    return {"items": [await _enrich_song(s) async for s in cur]}


@api.get("/songs/from-followed")
async def from_followed_songs(limit: int = Query(10, ge=1, le=200), user: dict = Depends(current_user)):
    """Same data as /api/home's `from_followed`, but with a raisable limit --
    used by the Home section's tap-to-play so the queue isn't capped at the
    10-song Home preview (same full-list pattern as /categories/{id}?full=true
    and /songs/trending?limit=). Must stay registered before the /songs/{song_id}
    catch-all below, or that route swallows this path first."""
    items = await _home_from_followed(user["user_id"], limit=limit)
    return {"items": items}


@api.get("/songs/{song_id}")
async def get_song(song_id: str):
    s = await db.songs.find_one({"song_id": song_id})
    if not s:
        raise HTTPException(404, "Not found")
    return await _enrich_song(s)


def _build_proxy_url(
    song_id: str,
    src: Optional[str] = None,
    title: Optional[str] = None,
    artist: Optional[str] = None,
) -> str:
    """Build a relative `/api/streams/proxy/...` URL for the frontend.

    The frontend prepends BACKEND_URL. We pass `src`, `title`, `artist` as
    query params so the proxy can resolve without an extra DB roundtrip
    (even for ext_ songs that aren't persisted yet).
    """
    from urllib.parse import quote
    base = f"/api/streams/proxy/{quote(song_id or 'external', safe='')}"
    qp: list[str] = []
    if src:
        qp.append(f"src={quote(src, safe='')}")
    if title:
        qp.append(f"title={quote(title, safe='')}")
    if artist:
        qp.append(f"artist={quote(artist, safe='')}")
    return base + ("?" + "&".join(qp) if qp else "")


@api.get("/streams/resolve/{song_id}")
async def resolve_stream(song_id: str, user: dict = Depends(current_user)):
    """Resolve a playable URL for a track.

    Self-hosted tracks (R2 upload or GridFS) are returned directly — they
    never need the external YouTube resolver, even if a stale/legacy
    source_url or external_url also happens to be stored on the doc.
    Only tracks with no local audio fall through to source_url / ytsearch
    resolution.

    External tracks (yt-dlp) now return BOTH `url` (raw googlevideo) and
    `proxy_url` (same bytes streamed via /api/streams/proxy). The client
    SHOULD play `proxy_url` first — googlevideo signs URLs by IP so the
    raw link often 403s on the phone even though it works on the server.
    `url` is kept as a fallback for low-bandwidth / cost-sensitive paths.
    """
    _ = user
    s = await db.songs.find_one(
        {"song_id": song_id},
        {"_id": 0, "source_url": 1, "external_url": 1, "title": 1, "artist_name": 1,
         "audio_url": 1, "audio_kind": 1},
    )
    if not s:
        return {"error": "stream_unavailable", "detail": "Track not found."}
    local_url = s.get("audio_url") or (
        f"/api/songs/{song_id}/stream" if s.get("audio_kind") == "gridfs" else None
    )
    if local_url:
        return {
            "url": local_url,
            "stream_format": "mp3",
            "expires_in": None,
            "title": s.get("title"),
            "extractor": "local",
        }
    src = s.get("source_url") or s.get("external_url") or ""
    fallback_q = " ".join(filter(None, [s.get("title"), s.get("artist_name")])) or None
    # Even if there's no source_url, allow YouTube-search fallback so the
    # track can still be played if we have a title / artist.
    if not src and not fallback_q:
        return {"error": "stream_unavailable", "detail": "No source or search hint."}
    r = await stream_resolver.resolve_stream_url(song_id, src, fallback_query=fallback_q)
    if isinstance(r, dict) and r.get("url") and not r.get("error"):
        r = {**r, "proxy_url": _build_proxy_url(
            song_id, src=src, title=s.get("title"), artist=s.get("artist_name"),
        )}
    return r


@api.get("/streams/resolve-url")
async def resolve_stream_by_url(
    url: str = Query(..., min_length=1),
    title: str | None = Query(None),
    artist: str | None = Query(None),
    user: dict = Depends(current_user),
):
    """Resolve any external source URL into a fresh direct-play URL.

    `title` and `artist` are optional — if provided they're used as the
    ytsearch fallback query when SoundCloud rejects the URL with DRM /
    preview / geo restrictions.

    Response includes `proxy_url` for the IP-safe backend proxy path (see
    `/api/streams/proxy/{song_id}` — the frontend should prefer this URL
    for playback, falling back to the raw `url` only on error).
    """
    _ = user
    fallback_q = " ".join(filter(None, [title, artist])).strip() or None
    r = await stream_resolver.resolve_stream_url("external", url, fallback_query=fallback_q)
    if isinstance(r, dict) and r.get("url") and not r.get("error"):
        r = {**r, "proxy_url": _build_proxy_url(
            "external", src=url, title=title, artist=artist,
        )}
    return r


# ─────────────── Server-side streaming proxy ───────────────
# Routes the audio bytes through the backend so the user's phone never
# needs to touch googlevideo directly. This fixes two long-standing issues:
#   1. YouTube's signed URLs are IP-bound to whoever fetched them → the
#      phone would 403 on direct playback when the resolver ran server-side.
#   2. Some tracks are region-locked on the client's network but reachable
#      from the server; the proxy makes those playable too.
#
# Supports HTTP Range (206) so the native player can scrub freely without
# downloading the whole file. The upstream Range header is forwarded as-is,
# and the response status / Content-Range / Accept-Ranges headers are
# echoed back to the client so React Native's AVPlayer / ExoPlayer treats
# the proxy exactly like a regular progressive audio source.

_PROXY_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
)


async def _resolve_direct_url_for_proxy(
    song_id: str, src: Optional[str], title: Optional[str], artist: Optional[str]
) -> str:
    source_url = src or ""
    if not source_url:
        s = await db.songs.find_one(
            {"song_id": song_id},
            {"_id": 0, "source_url": 1, "external_url": 1, "title": 1, "artist_name": 1},
        )
        if s:
            source_url = s.get("source_url") or s.get("external_url") or ""
            title = title or s.get("title")
            artist = artist or s.get("artist_name")
    fallback_q = " ".join(filter(None, [title, artist])).strip() or None
    r = await stream_resolver.resolve_stream_url(
        song_id, source_url, fallback_query=fallback_q
    )
    if r.get("error") or not r.get("url"):
        raise HTTPException(404, r.get("detail", "Stream unavailable"))
    return r["url"]


@api.get("/streams/proxy/{song_id}")
async def streams_proxy(
    song_id: str,
    request: Request,
    src: Optional[str] = Query(None),
    title: Optional[str] = Query(None),
    artist: Optional[str] = Query(None),
):
    """Server-side streaming proxy. The audio stays IP-bound to this host
    which has already fetched the signed URL from YouTube, bypassing the
    client's 403 Forbidden on direct playback."""
    direct_url = await _resolve_direct_url_for_proxy(song_id, src, title, artist)

    fwd_headers = {
        "User-Agent": _PROXY_UA,
        "Accept": "*/*",
        "Accept-Encoding": "identity",   # don't let upstream gzip audio
    }
    client_range = request.headers.get("range")
    if client_range:
        fwd_headers["Range"] = client_range

    # Open the upstream stream, keep it alive while we yield chunks.
    client = httpx.AsyncClient(
        timeout=httpx.Timeout(30.0, connect=10.0, read=60.0),
        follow_redirects=True,
    )
    upstream = await client.stream("GET", direct_url, headers=fwd_headers).__aenter__()

    # Echo through status + the headers the native player actually looks at.
    passthrough: dict[str, str] = {}
    for k in (
        "content-type", "content-length", "accept-ranges",
        "content-range", "cache-control", "etag", "last-modified",
    ):
        v = upstream.headers.get(k)
        if v:
            passthrough[k] = v
    # Ensure the player knows seek is supported even if upstream omitted it.
    passthrough.setdefault("accept-ranges", "bytes")
    status_code = upstream.status_code

    async def iter_body():
        try:
            async for chunk in upstream.aiter_raw(chunk_size=64 * 1024):
                if chunk:
                    yield chunk
        finally:
            try: await upstream.aclose()
            except Exception: pass
            try: await client.aclose()
            except Exception: pass

    return StreamingResponse(
        iter_body(),
        status_code=status_code,
        media_type=passthrough.get("content-type", "audio/mp4"),
        headers=passthrough,
    )


@api.get("/search/external")
async def search_external(
    q: str = Query(..., min_length=1),
    provider: str = Query("youtube"),
    limit: int = Query(15, ge=1, le=25),
    user: dict = Depends(current_user),
):
    """Search YouTube for tracks matching `q` (SoundCloud removed June 2026).
    Returns lightweight track dicts:
        {source_url, title, artist, duration, thumbnail, provider}
    Cached for 5 minutes in-process for repeat queries.
    """
    _ = user, provider  # provider arg retained for backwards compat only
    # Over-fetch a bit so we still return a healthy list after the music-
    # only filter (drops movies / TV episodes / long-form videos > 10 min).
    raw = await stream_resolver.search_external(q, provider="youtube", limit=limit * 2)
    MAX_DURATION_SEC = 10 * 60  # 10 minutes — music-only cap
    MIN_DURATION_SEC = 30        # under 30s is almost never a song
    items: list[dict] = []
    for it in raw:
        d = it.get("duration")
        # Drop live streams / premieres (no duration) AND long-form videos.
        if not isinstance(d, (int, float)) or d <= 0:
            continue
        if d < MIN_DURATION_SEC or d > MAX_DURATION_SEC:
            continue
        items.append(it)
        if len(items) >= limit:
            break
    return {"items": items, "provider": "youtube", "q": q}


@api.post("/songs/{song_id}/play")
async def record_play(song_id: str, user: dict = Depends(current_user)):
    s = await db.songs.find_one({"song_id": song_id}, {"_id": 0})
    if not s:
        raise HTTPException(404, "Not found")
    await db.songs.update_one(
        {"song_id": song_id},
        {"$inc": {"streams": 1, "trending_score": 1}, "$set": {"last_played_at": now()}},
    )
    await db.play_events.insert_one(
        {
            "play_id": new_id("play"),
            "song_id": song_id,
            "user_id": user["user_id"],
            "artist_id": s.get("artist_id"),
            "played_at": now(),
        }
    )
    # Recently played: keep last 30
    await db.recently_played.delete_many({"user_id": user["user_id"], "song_id": song_id})
    await db.recently_played.insert_one(
        {"user_id": user["user_id"], "song_id": song_id, "played_at": now()}
    )
    return {"ok": True}


@api.post("/songs/{song_id}/like")
async def toggle_like(song_id: str, user: dict = Depends(current_user)):
    existing = await db.likes.find_one({"user_id": user["user_id"], "song_id": song_id})
    if existing:
        await db.likes.delete_one({"_id": existing["_id"]})
        return {"liked": False}
    await db.likes.insert_one(
        {"user_id": user["user_id"], "song_id": song_id, "liked_at": now()}
    )
    return {"liked": True}


@api.post("/songs/external/upsert")
async def upsert_external_song(body: ExternalSongUpsert, user: dict = Depends(current_user)):
    """Persist an external (SoundCloud / YouTube search-hit) track into
    `db.songs` so it can be liked, added to playlists, or surfaced in
    Recently Played. Marked `is_external=True` + `is_published=False`
    so it does NOT leak into public discovery feeds.

    Idempotent: same `song_id` upserts. Caller MUST send the `ext_<hash>`
    id it already assigned on the client.
    """
    _ = user  # any authenticated user can upsert an ext song
    if not body.song_id.startswith("ext_"):
        raise HTTPException(400, "external song_id must start with 'ext_'")
    doc = {
        "song_id": body.song_id,
        "title": body.title,
        "artist_id": "external",
        "artist_name": body.artist_name or "Unknown",
        "genre": "External",
        "mood": "",
        "language": "",
        "lyrics": "",
        "cover_url": body.cover_url or "",
        "audio_url": "",
        "stream_url": "",
        "source_url": body.source_url,
        "external_url": body.source_url,   # legacy alias
        "duration_sec": int(body.duration_sec or 0),
        "streams": 0,
        "likes": 0,
        "is_published": False,
        "is_external": True,
        "provider": body.provider,
        "updated_at": now(),
    }
    await db.songs.update_one(
        {"song_id": body.song_id},
        {"$set": doc, "$setOnInsert": {"created_at": now()}},
        upsert=True,
    )
    return {"ok": True, "song_id": body.song_id}


# ─────────────────── Follow Artist ───────────────────
# NOTE: The active follow / follow-status / me/following endpoints are
# defined in the "follow / unfollow" section further down (line ~2005+).
# They use `follows.follower_id`, prevent self-follows, and maintain the
# denormalised `users.followers` counter. Kept the alias route below so
# the mobile client can hit either `/follow` or `/follow-status` for GET.

@api.get("/artists/{artist_id}/follow")
async def get_follow_state_get(artist_id: str, user: dict = Depends(current_user)):
    """GET alias for /follow-status — same shape."""
    existing = await db.follows.find_one(
        {"follower_id": user["user_id"], "artist_id": artist_id}
    )
    cnt = await db.follows.count_documents({"artist_id": artist_id})
    return {"following": bool(existing), "followers": cnt}


# ─────────────────── Admin Categories / Playlists ───────────────────
# Categories appear on the Home tab (below "Trending") in the order they
# were created (`sort_order`), together with any songs the admin has added.
class CategoryCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    cover_url: str = Field(default="", max_length=1024)
    description: str = Field(default="", max_length=400)
    sort_order: int = Field(default=0, ge=-1000, le=1000)
    # How this section's songs render on the Home tab.
    layout_style: str = Field(default="horizontal", pattern="^(horizontal|vertical)$")
    # Grid dimensions used when `layout_style == 'vertical'`. Ignored for
    # horizontal (which is a single-row scroller). Admin can pick e.g. 3 rows
    # × 2 columns to get a 6-tile grid preview on Home.
    rows: int = Field(default=3, ge=1, le=10)
    columns: int = Field(default=1, ge=1, le=4)


class CategoryUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=80)
    cover_url: Optional[str] = Field(default=None, max_length=1024)
    description: Optional[str] = Field(default=None, max_length=400)
    sort_order: Optional[int] = Field(default=None, ge=-1000, le=1000)
    is_active: Optional[bool] = None
    layout_style: Optional[str] = Field(default=None, pattern="^(horizontal|vertical)$")
    rows: Optional[int] = Field(default=None, ge=1, le=10)
    columns: Optional[int] = Field(default=None, ge=1, le=4)


class CategorySongsOp(BaseModel):
    song_ids: list[str] = Field(min_length=1, max_length=200)


def _ensure_admin(user: dict) -> None:
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin only")


@api.post("/admin/system/purge-dummy-data")
async def admin_purge_dummy_data(user: dict = Depends(current_user)):
    """Admin-only manual purge of the demo/seed songs (audio_kind=='url').

    Migrated out of the startup path (June 2026) so deploys can no longer
    delete records unattended. Idempotent: safe to call any time.
    """
    _ensure_admin(user)
    await _purge_dummy_data()
    return {"ok": True}


async def _playlist_summaries(ids: list[str]) -> list[dict]:
    """Lightweight cards for admin playlists attached to a category or an
    artist profile (e.g. a "Mix" tile). Cover falls back to the first song's
    art so a freshly created playlist never renders blank."""
    if not ids:
        return []
    m: dict[str, dict] = {}
    async for p in db.playlists.find({"playlist_id": {"$in": ids}}, {"_id": 0}):
        m[p["playlist_id"]] = p
    first_ids = [
        m[i]["song_ids"][0] for i in ids
        if i in m and not m[i].get("cover") and m[i].get("song_ids")
    ]
    covers: dict[str, str] = {}
    if first_ids:
        async for s in db.songs.find({"song_id": {"$in": first_ids}}, {"_id": 0, "song_id": 1, "cover_url": 1}):
            covers[s["song_id"]] = s.get("cover_url") or ""
    out: list[dict] = []
    for i in ids:
        p = m.get(i)
        if not p:
            continue
        sids = p.get("song_ids") or []
        out.append({
            "playlist_id": i,
            "name": p.get("name", ""),
            "description": p.get("description", ""),
            "cover": p.get("cover") or (covers.get(sids[0]) if sids else None),
            "song_count": len(sids),
        })
    return out


async def _enrich_category(cat: dict, include_songs: bool = True, limit: Optional[int] = 10) -> dict:
    cat.pop("_id", None)
    cat.setdefault("layout_style", "horizontal")  # categories created before this field existed
    cat.setdefault("rows", 3)                     # default vertical dims — 3×1 (six tiles)
    cat.setdefault("columns", 1)
    if include_songs:
        all_ids = cat.get("song_ids", []) or []
        # `limit=10` caps the embedded Home preview for payload size; the
        # category "View all" screen passes limit=None to fetch every song.
        ids = all_ids[:limit] if limit is not None else all_ids
        if ids:
            cur = db.songs.find({"song_id": {"$in": ids}})
            m: dict[str, dict] = {}
            async for s in cur:
                m[s["song_id"]] = await _enrich_song(s)
            cat["songs"] = [m[i] for i in ids if i in m]
        else:
            cat["songs"] = []
    cat["playlists"] = await _playlist_summaries(cat.get("playlist_ids") or [])
    return cat


async def _to_enriched_songs(cur) -> list[dict]:
    return [await _enrich_song(s) async for s in cur]


async def _to_enriched_categories(cur) -> list[dict]:
    return [await _enrich_category(c) async for c in cur]


@api.get("/categories")
async def list_categories(limit: int = Query(20, ge=1, le=50)):
    """Public — used by the Home tab to render curated admin sections."""
    cur = db.categories.find({"is_active": {"$ne": False}}).sort([
        ("sort_order", 1), ("created_at", -1)
    ]).limit(limit)
    return {"items": [await _enrich_category(c) async for c in cur]}


@api.get("/categories/{category_id}")
async def get_category(category_id: str, full: bool = Query(False)):
    """`full=true` is used by the Home section's "View all" screen to fetch
    every song in the category, instead of the 10-song Home preview cap."""
    c = await db.categories.find_one({"category_id": category_id})
    if not c:
        raise HTTPException(404, "Not found")
    return await _enrich_category(c, limit=None if full else 10)


@api.get("/admin/categories")
async def admin_list_categories(user: dict = Depends(current_user)):
    _ensure_admin(user)
    cur = db.categories.find({}).sort([("sort_order", 1), ("created_at", -1)])
    return {"items": [await _enrich_category(c, include_songs=False) async for c in cur]}


async def _home_recent_songs(user_id: str) -> list[dict]:
    rp_cur = db.recently_played.find({"user_id": user_id}).sort([("played_at", -1)]).limit(18)
    rp_ids: list[str] = []
    async for r in rp_cur:
        sid = r.get("song_id")
        if sid and sid not in rp_ids:
            rp_ids.append(sid)
    if not rp_ids:
        return []
    songs_cur = db.songs.find({"song_id": {"$in": rp_ids}})
    m: dict[str, dict] = {}
    async for s in songs_cur:
        m[s["song_id"]] = await _enrich_song(s)
    return [m[i] for i in rp_ids if i in m]


async def _home_from_followed(user_id: str, limit: int = 10) -> list[dict]:
    following_cur = db.follows.find({"follower_id": user_id})
    followed_ids = [f["artist_id"] async for f in following_cur]
    if not followed_ids:
        return []
    f_cur = db.songs.find({
        "is_published": True,
        "artist_id": {"$in": followed_ids},
    }).sort([("created_at", -1)]).limit(limit)
    return [await _enrich_song(s) async for s in f_cur]


@api.get("/home")
async def home_feed(user: dict = Depends(current_user)):
    """One-shot Home feed. Reduces 6 round-trips → 1 for the mobile client.

    All independent sections are fetched concurrently (asyncio.gather)
    instead of one after another — the previous sequential `await` chain
    across 7 Mongo round-trips was the main driver of the multi-second
    Home load users reported (each round-trip's latency added up instead
    of overlapping).
    """
    trending_cur = db.songs.find({"is_published": True}).sort([("streams", -1)]).limit(8)
    new_cur = db.songs.find({"is_published": True}).sort([("created_at", -1)]).limit(8)
    rec_cur = db.songs.find({"is_published": True}).sort([("streams", -1)]).limit(10)
    artists_cur = db.users.find(
        {"role": "artist", "is_featured": True}
    ).limit(8)
    cats_cur = db.categories.find({"is_active": {"$ne": False}}).sort([
        ("sort_order", 1), ("created_at", -1)
    ]).limit(20)

    (
        trending, new_releases, recommended, featured_artists_raw,
        categories, recent_songs, from_followed,
    ) = await asyncio.gather(
        _to_enriched_songs(trending_cur),
        _to_enriched_songs(new_cur),
        _to_enriched_songs(rec_cur),
        artists_cur.to_list(length=8),
        _to_enriched_categories(cats_cur),
        _home_recent_songs(user["user_id"]),
        _home_from_followed(user["user_id"]),
    )
    featured_artists = [public_user(u) for u in featured_artists_raw]

    return {
        "trending": trending,
        "new_releases": new_releases,
        "recommended": recommended,
        "featured_artists": featured_artists,
        "recently_played": recent_songs,
        "categories": categories,
        "from_followed": from_followed,
    }


@api.get("/admin/categories/list-only")
async def admin_list_categories_lite(user: dict = Depends(current_user)):
    """Same as /admin/categories but faster (no song enrichment) — used by
    the drag-reorder UI to render the list without waiting on song data."""
    _ensure_admin(user)
    cur = db.categories.find({}).sort([("sort_order", 1), ("created_at", -1)])
    return {"items": [await _enrich_category(c, include_songs=False) async for c in cur]}


class CategoryReorder(BaseModel):
    ordered_ids: list[str] = Field(min_length=1, max_length=200)


@api.post("/admin/categories/reorder")
async def admin_reorder_categories(
    body: CategoryReorder, user: dict = Depends(current_user),
):
    """Bulk-set `sort_order` on a list of categories. Position in the array
    is written back as `sort_order` so the client can just send the new
    order after a drag-and-drop reorder."""
    _ensure_admin(user)
    from pymongo import UpdateOne  # local import to keep top clean
    ops = [
        UpdateOne(
            {"category_id": cid},
            {"$set": {"sort_order": i, "updated_at": now()}},
        )
        for i, cid in enumerate(body.ordered_ids)
    ]
    if not ops:
        return {"ok": True, "updated": 0}
    result = await db.categories.bulk_write(ops)
    return {"ok": True, "updated": result.modified_count}


@api.post("/admin/categories")
async def admin_create_category(body: CategoryCreate, user: dict = Depends(current_user)):
    _ensure_admin(user)
    doc = {
        "category_id": new_id("cat"),
        "name": body.name.strip(),
        "cover_url": body.cover_url,
        "description": body.description,
        "sort_order": body.sort_order,
        "layout_style": body.layout_style,
        "rows": body.rows,
        "columns": body.columns,
        "is_active": True,
        "song_ids": [],
        "created_at": now(),
        "updated_at": now(),
    }
    await db.categories.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api.patch("/admin/categories/{category_id}")
async def admin_update_category(
    category_id: str, body: CategoryUpdate, user: dict = Depends(current_user),
):
    _ensure_admin(user)
    updates = {k: v for k, v in body.dict(exclude_unset=True).items() if v is not None}
    if not updates:
        return {"ok": True, "updated": 0}
    updates["updated_at"] = now()
    r = await db.categories.update_one({"category_id": category_id}, {"$set": updates})
    if r.matched_count == 0:
        raise HTTPException(404, "Not found")
    return {"ok": True, "updated": r.modified_count}


@api.delete("/admin/categories/{category_id}")
async def admin_delete_category(category_id: str, user: dict = Depends(current_user)):
    _ensure_admin(user)
    r = await db.categories.delete_one({"category_id": category_id})
    if r.deleted_count == 0:
        raise HTTPException(404, "Not found")
    return {"ok": True}


@api.post("/admin/categories/{category_id}/songs/add")
async def admin_category_add_songs(
    category_id: str, body: CategorySongsOp, user: dict = Depends(current_user),
):
    _ensure_admin(user)
    r = await db.categories.update_one(
        {"category_id": category_id},
        {"$addToSet": {"song_ids": {"$each": body.song_ids}}, "$set": {"updated_at": now()}},
    )
    if r.matched_count == 0:
        raise HTTPException(404, "Not found")
    return {"ok": True, "added": len(body.song_ids)}


@api.post("/admin/categories/{category_id}/songs/remove")
async def admin_category_remove_songs(
    category_id: str, body: CategorySongsOp, user: dict = Depends(current_user),
):
    _ensure_admin(user)
    r = await db.categories.update_one(
        {"category_id": category_id},
        {"$pull": {"song_ids": {"$in": body.song_ids}}, "$set": {"updated_at": now()}},
    )
    if r.matched_count == 0:
        raise HTTPException(404, "Not found")
    return {"ok": True}


@api.get("/me/likes")
async def my_likes(user: dict = Depends(current_user), limit: int = 100):
    cur = db.likes.find({"user_id": user["user_id"]}).sort("liked_at", -1).limit(min(limit, 500))
    ids = [item["song_id"] async for item in cur]
    if not ids:
        return {"items": []}
    cur2 = db.songs.find({"song_id": {"$in": ids}})
    songs = {s["song_id"]: await _enrich_song(s) async for s in cur2}
    return {"items": [songs[i] for i in ids if i in songs]}


@api.get("/me/recently-played")
async def my_recent(user: dict = Depends(current_user), limit: int = 20):
    cur = db.recently_played.find({"user_id": user["user_id"]}).sort("played_at", -1).limit(limit)
    ids = [r["song_id"] async for r in cur]
    if not ids:
        return {"items": []}
    cur2 = db.songs.find({"song_id": {"$in": ids}})
    songs = {s["song_id"]: await _enrich_song(s) async for s in cur2}
    return {"items": [songs[i] for i in ids if i in songs]}


# ──────────────────────────── search ────────────────────────────

@api.get("/search")
async def search(q: str = Query(..., min_length=1), limit: int = 20):
    rx = {"$regex": q, "$options": "i"}
    songs_cur = db.songs.find(
        {"is_published": True, "$or": [{"title": rx}, {"artist_name": rx}, {"genre": rx}]}
    ).limit(limit)
    artists_cur = db.users.find(
        {"role": "artist", "$or": [{"name": rx}, {"bio": rx}]},
        {"_id": 0, "password_hash": 0},
    ).limit(limit)
    pls_cur = db.playlists.find({"is_public": True, "name": rx}, {"_id": 0}).limit(limit)
    return {
        "songs": [await _enrich_song(s) async for s in songs_cur],
        "artists": [public_user(a) async for a in artists_cur],
        "playlists": [p async for p in pls_cur],
    }


@api.get("/search/trending")
async def trending_searches():
    # Top genres by song count + trending terms
    cur = db.songs.aggregate([
        {"$match": {"is_published": True}},
        {"$group": {"_id": "$genre", "n": {"$sum": "$streams"}}},
        {"$sort": {"n": -1}},
        {"$limit": 8},
    ])
    return {"items": [r["_id"] async for r in cur if r["_id"]]}


# ──────────────────────────── artists ────────────────────────────

@api.get("/artists/featured")
async def featured_artists(limit: int = Query(8, ge=1, le=500)):
    cur = db.users.find(
        {"role": "artist"}, {"_id": 0, "password_hash": 0}
    ).sort("monthly_listeners", -1).limit(limit)
    return {"items": [public_user(a) async for a in cur]}


@api.get("/artists/{artist_id}")
async def get_artist(artist_id: str):
    a = await db.users.find_one({"user_id": artist_id}, {"_id": 0, "password_hash": 0})
    if not a or a.get("role") != "artist":
        raise HTTPException(404, "Artist not found")
    # Admin-curated songs (e.g. YouTube tracks attached to an admin-created
    # artist profile) come first, then the artist's own uploads by streams.
    curated_ids = a.get("curated_song_ids") or []
    curated: list[dict] = []
    if curated_ids:
        cm = {s["song_id"]: s async for s in db.songs.find({"song_id": {"$in": curated_ids}})}
        curated = [await _enrich_song(cm[i]) for i in curated_ids if i in cm]
    seen = {s["song_id"] for s in curated}
    songs_cur = db.songs.find({"artist_id": artist_id, "is_published": True}).sort("streams", -1)
    songs = curated + [await _enrich_song(s) async for s in songs_cur if s["song_id"] not in seen]
    # Live monthly listeners — unique users who streamed any of this artist's
    # songs in the last 30 days. Reflects reality in real time.
    threshold = now() - timedelta(days=30)
    try:
        ml_pipeline = [
            {"$match": {"listened_at": {"$gte": threshold}, "artist_id": artist_id}},
            {"$group": {"_id": "$user_id"}},
            {"$count": "unique"},
        ]
        ml_result = await db.stream_logs.aggregate(ml_pipeline).to_list(length=1)
        live_monthly = ml_result[0]["unique"] if ml_result else 0
    except Exception:
        live_monthly = 0
    # Currently-listening count (last 90 seconds, unique users)
    try:
        live_pipeline = [
            {"$match": {"listened_at": {"$gte": now() - timedelta(seconds=90)}, "artist_id": artist_id}},
            {"$group": {"_id": "$user_id"}},
            {"$count": "unique"},
        ]
        live_result = await db.stream_logs.aggregate(live_pipeline).to_list(length=1)
        live_now = live_result[0]["unique"] if live_result else 0
    except Exception:
        live_now = 0
    profile = public_user(a)
    profile["monthly_listeners"] = live_monthly  # override static with live count
    profile["live_listeners"] = live_now
    playlists = await _playlist_summaries(a.get("playlist_ids") or [])
    return {"artist": profile, "songs": songs, "playlists": playlists}


# ──────────────────────────── playlists ────────────────────────────

@api.get("/playlists")
async def list_playlists(mine: bool = False, user: dict = Depends(current_user)):
    q = {"owner_id": user["user_id"]} if mine else {"is_public": True}
    cur = db.playlists.find(q, {"_id": 0}).sort("updated_at", -1).limit(50)
    return {"items": [p async for p in cur]}


@api.post("/playlists")
async def create_playlist(body: PlaylistCreate, user: dict = Depends(current_user)):
    layout = body.layout.dict() if body.layout else {"style": "vertical_list", "rows": 1, "columns": 1}
    doc = {
        "playlist_id": new_id("pl"),
        "name": body.name,
        "description": body.description,
        "is_public": body.is_public,
        "owner_id": user["user_id"],
        "owner_name": user.get("name", ""),
        "song_ids": [],
        "cover": None,
        "layout": layout,
        "created_at": now(),
        "updated_at": now(),
    }
    await db.playlists.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api.put("/playlists/{pid}/layout")
async def update_playlist_layout(
    pid: str, body: PlaylistLayoutUpdate, user: dict = Depends(current_user),
):
    """Owner-only. Accepts style: vertical_list | vertical_grid | horizontal_carousel."""
    p = await db.playlists.find_one({"playlist_id": pid})
    if not p:
        raise HTTPException(404, "Not found")
    if p.get("owner_id") != user["user_id"] and user.get("role") != "admin":
        raise HTTPException(403, "Not your playlist")
    allowed = {"vertical_list", "vertical_grid", "horizontal_carousel"}
    if body.style not in allowed:
        raise HTTPException(400, f"style must be one of {sorted(allowed)}")
    layout = {"style": body.style, "rows": body.rows, "columns": body.columns}
    await db.playlists.update_one(
        {"playlist_id": pid},
        {"$set": {"layout": layout, "updated_at": now()}},
    )
    return {"ok": True, "layout": layout}


@api.get("/playlists/{pid}")
async def get_playlist(pid: str):
    p = await db.playlists.find_one({"playlist_id": pid}, {"_id": 0})
    if not p:
        raise HTTPException(404, "Not found")
    # Back-fill a default layout on legacy playlists.
    if not isinstance(p.get("layout"), dict):
        p["layout"] = {"style": "vertical_list", "rows": 1, "columns": 1}
    ids = p.get("song_ids", [])
    if ids:
        cur = db.songs.find({"song_id": {"$in": ids}})
        m = {s["song_id"]: await _enrich_song(s) async for s in cur}
        p["songs"] = [m[i] for i in ids if i in m]
    else:
        p["songs"] = []
    return p


@api.post("/playlists/{pid}/add")
async def playlist_add(pid: str, body: PlaylistSongOp, user: dict = Depends(current_user)):
    p = await db.playlists.find_one({"playlist_id": pid})
    if not p:
        raise HTTPException(404, "Not found")
    if p["owner_id"] != user["user_id"] and not _is_admin(user):
        raise HTTPException(403, "Not your playlist")
    await db.playlists.update_one(
        {"playlist_id": pid},
        {"$addToSet": {"song_ids": body.song_id}, "$set": {"updated_at": now()}},
    )
    return {"ok": True}


@api.post("/playlists/{pid}/remove")
async def playlist_remove(pid: str, body: PlaylistSongOp, user: dict = Depends(current_user)):
    p = await db.playlists.find_one({"playlist_id": pid})
    if not p or (p["owner_id"] != user["user_id"] and not _is_admin(user)):
        raise HTTPException(403, "Forbidden")
    await db.playlists.update_one(
        {"playlist_id": pid},
        {"$pull": {"song_ids": body.song_id}, "$set": {"updated_at": now()}},
    )
    return {"ok": True}


@api.delete("/playlists/{pid}")
async def delete_playlist(pid: str, user: dict = Depends(current_user)):
    p = await db.playlists.find_one({"playlist_id": pid})
    if not p or (p["owner_id"] != user["user_id"] and not _is_admin(user)):
        raise HTTPException(403, "Forbidden")
    await db.playlists.delete_one({"playlist_id": pid})
    await _detach_playlist_everywhere(pid)
    return {"ok": True}


# ──────────────────── admin bulk-add: all songs by artist ────────────────────

@api.get("/admin/artists/search")
async def admin_artist_search(
    q: str = Query(..., min_length=1),
    limit: int = Query(15, ge=1, le=30),
    user: dict = Depends(current_user),
):
    """Fuzzy-search both internal artist profiles (role=artist users) and
    distinct `artist_name` values on songs, so the admin can pick either
    an artist account or a plain song-tagged name for bulk-add.

    Returns a merged list of {artist_id?, name, song_count} rows ordered
    by song count desc.
    """
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    rx = {"$regex": re.escape(q.strip()), "$options": "i"}
    # 1) Artist accounts
    users_cur = db.users.find(
        {"role": "artist", "$or": [{"name": rx}, {"email": rx}]},
        {"_id": 0, "user_id": 1, "name": 1},
    ).limit(limit)
    artist_rows: list[dict] = []
    async for a in users_cur:
        cnt = await db.songs.count_documents({"artist_id": a["user_id"]})
        artist_rows.append({
            "artist_id": a["user_id"],
            "name": a.get("name") or "Unknown",
            "song_count": cnt,
            "source": "profile",
        })
    # 2) Distinct song.artist_name hits (covers external YouTube uploads)
    pipeline = [
        {"$match": {"artist_name": rx}},
        {"$group": {"_id": "$artist_name", "song_count": {"$sum": 1}}},
        {"$sort": {"song_count": -1}},
        {"$limit": limit},
    ]
    name_rows: list[dict] = []
    async for row in db.songs.aggregate(pipeline):
        nm = row.get("_id") or "Unknown"
        # Skip if already represented by an artist profile row with the
        # exact same name (de-dup).
        if any(ar["name"].lower() == nm.lower() for ar in artist_rows):
            continue
        name_rows.append({
            "artist_id": None,
            "name": nm,
            "song_count": int(row.get("song_count") or 0),
            "source": "tag",
        })
    merged = sorted(artist_rows + name_rows, key=lambda r: -r["song_count"])[: limit]
    return {"items": merged}


class BulkAddArtistBody(BaseModel):
    artist_id: Optional[str] = None
    artist_name: Optional[str] = None
    limit: int = Field(default=100, ge=1, le=500)


@api.post("/admin/playlists/{pid}/add-artist-songs")
async def admin_bulk_add_artist_songs(
    pid: str,
    body: BulkAddArtistBody,
    user: dict = Depends(current_user),
):
    """Admin: Add EVERY matching song by a given artist to a playlist in
    one shot. Match is by `artist_id` first (strict), falling back to a
    case-insensitive `artist_name` match so YouTube-sourced uploads
    without an attached profile still work.

    Deduped against the playlist's existing `song_ids` so repeat clicks
    are idempotent. Returns `{added, total_matched, song_ids}`.
    """
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    if not body.artist_id and not body.artist_name:
        raise HTTPException(400, "Provide artist_id or artist_name")
    p = await db.playlists.find_one({"playlist_id": pid}, {"_id": 0, "song_ids": 1})
    if not p:
        raise HTTPException(404, "Playlist not found")

    q: dict = {}
    if body.artist_id:
        q["artist_id"] = body.artist_id
    elif body.artist_name:
        q["artist_name"] = {
            "$regex": f"^{re.escape(body.artist_name.strip())}$",
            "$options": "i",
        }
    # Only published songs are added — admin bulk-add shouldn't surface
    # draft uploads.
    q.setdefault("is_published", True)

    cur = db.songs.find(q, {"_id": 0, "song_id": 1}).sort("created_at", -1).limit(body.limit)
    found_ids = [s["song_id"] async for s in cur if s.get("song_id")]
    if not found_ids:
        return {"added": 0, "total_matched": 0, "song_ids": []}
    existing = set(p.get("song_ids") or [])
    new_ids = [sid for sid in found_ids if sid not in existing]
    if new_ids:
        await db.playlists.update_one(
            {"playlist_id": pid},
            {"$push": {"song_ids": {"$each": new_ids}}, "$set": {"updated_at": now()}},
        )
    return {
        "added": len(new_ids),
        "total_matched": len(found_ids),
        "song_ids": new_ids,
    }


# ─────────── admin catalog: artist profiles + playlists inside sections ───────────
# Admin can create an artist profile (e.g. "Amanraj Gill") without that artist
# having an account, attach songs to it, and create playlists (e.g. "Mix")
# inside a Home category or an artist profile. Tapping a playlist tile opens
# /playlist/[id], whose Play button queues every song in it.

class AdminArtistCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    avatar: str = Field(default="", max_length=1024)
    bio: str = Field(default="", max_length=1000)
    is_featured: bool = True


class AdminArtistUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=80)
    avatar: Optional[str] = Field(default=None, max_length=1024)
    bio: Optional[str] = Field(default=None, max_length=1000)
    is_featured: Optional[bool] = None


class AdminArtistAddByName(BaseModel):
    # Defaults to the artist's own name; override for alternate spellings.
    name: Optional[str] = Field(default=None, max_length=80)


class AdminPlaylistCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=400)
    cover: str = Field(default="", max_length=1024)


class PlaylistIdBody(BaseModel):
    playlist_id: str


async def _detach_playlist_everywhere(pid: str) -> None:
    await db.categories.update_many({"playlist_ids": pid}, {"$pull": {"playlist_ids": pid}})
    await db.users.update_many({"playlist_ids": pid}, {"$pull": {"playlist_ids": pid}})


async def _artist_or_404(artist_id: str) -> dict:
    a = await db.users.find_one(
        {"user_id": artist_id, "role": "artist"}, {"_id": 0, "password_hash": 0},
    )
    if not a:
        raise HTTPException(404, "Artist not found")
    return a


async def _admin_artist_row(a: dict) -> dict:
    curated = a.get("curated_song_ids") or []
    own = await db.songs.count_documents({"artist_id": a["user_id"], "song_id": {"$nin": curated}})
    row = public_user(a)
    row.update({
        "is_featured": bool(a.get("is_featured")),
        "managed_by_admin": bool(a.get("managed_by_admin")),
        "song_count": own + len(curated),
        "curated_count": len(curated),
        "playlist_count": len(a.get("playlist_ids") or []),
    })
    return row


@api.get("/admin/artists")
async def admin_list_artists(q: str = "", user: dict = Depends(current_user)):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    query: dict = {"role": "artist"}
    if q.strip():
        query["name"] = {"$regex": re.escape(q.strip()), "$options": "i"}
    cur = db.users.find(query, {"_id": 0, "password_hash": 0}).sort("name", 1).limit(200)
    return {"items": [await _admin_artist_row(a) async for a in cur]}


@api.post("/admin/artists")
async def admin_create_artist(body: AdminArtistCreate, user: dict = Depends(current_user)):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    uid = new_id("user")
    doc = {
        "user_id": uid,
        # Admin-made profiles never log in: the placeholder satisfies the
        # unique email index and, with no password_hash, /auth/login rejects it.
        "email": f"{uid}@artists.mysify.invalid",
        "name": body.name.strip(),
        "role": "artist",
        "managed_by_admin": True,
        "is_premium": False,
        "avatar": body.avatar.strip() or None,
        "bio": body.bio.strip(),
        "upi_id": None,
        "followers": 0,
        "monthly_listeners": 0,
        "is_featured": body.is_featured,
        "curated_song_ids": [],
        "playlist_ids": [],
        "created_at": now(),
    }
    await db.users.insert_one(doc)
    doc.pop("_id", None)
    return await _admin_artist_row(doc)


@api.patch("/admin/artists/{artist_id}")
async def admin_update_artist(
    artist_id: str, body: AdminArtistUpdate, user: dict = Depends(current_user),
):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    await _artist_or_404(artist_id)
    updates = {k: v for k, v in body.dict(exclude_unset=True).items() if v is not None}
    if "name" in updates:
        updates["name"] = updates["name"].strip()
    if "avatar" in updates:
        updates["avatar"] = updates["avatar"].strip() or None
    if updates:
        await db.users.update_one({"user_id": artist_id}, {"$set": updates})
    return await _admin_artist_row(await _artist_or_404(artist_id))


@api.get("/admin/artists/{artist_id}/songs")
async def admin_artist_curated_songs(artist_id: str, user: dict = Depends(current_user)):
    """Songs the admin attached to this profile (not the artist's own uploads)."""
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    a = await _artist_or_404(artist_id)
    ids = a.get("curated_song_ids") or []
    m = {s["song_id"]: s async for s in db.songs.find({"song_id": {"$in": ids}})}
    return {"songs": [await _enrich_song(m[i]) for i in ids if i in m]}


@api.post("/admin/artists/{artist_id}/songs/add")
async def admin_artist_add_songs(
    artist_id: str, body: CategorySongsOp, user: dict = Depends(current_user),
):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    await _artist_or_404(artist_id)
    await db.users.update_one(
        {"user_id": artist_id},
        {"$addToSet": {"curated_song_ids": {"$each": body.song_ids}}},
    )
    return {"ok": True, "added": len(body.song_ids)}


@api.post("/admin/artists/{artist_id}/songs/remove")
async def admin_artist_remove_songs(
    artist_id: str, body: CategorySongsOp, user: dict = Depends(current_user),
):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    await _artist_or_404(artist_id)
    await db.users.update_one(
        {"user_id": artist_id},
        {"$pull": {"curated_song_ids": {"$in": body.song_ids}}},
    )
    return {"ok": True}


@api.post("/admin/artists/{artist_id}/songs/add-by-name")
async def admin_artist_add_songs_by_name(
    artist_id: str, body: AdminArtistAddByName, user: dict = Depends(current_user),
):
    """Attach every catalogue song whose artist tag contains this name
    (covers "Amanraj Gill", "Amanraj Gill - Topic", "X, Amanraj Gill")."""
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    a = await _artist_or_404(artist_id)
    name = (body.name or a.get("name") or "").strip()
    if not name:
        raise HTTPException(400, "Artist name is empty")
    existing = set(a.get("curated_song_ids") or [])
    cur = db.songs.find(
        {
            "artist_name": {"$regex": re.escape(name), "$options": "i"},
            "artist_id": {"$ne": artist_id},
            # YouTube tracks are stored unpublished by design (is_external);
            # an unpublished first-party upload means admin-banned/draft.
            "$or": [{"is_published": True}, {"is_external": True}],
        },
        {"_id": 0, "song_id": 1},
    ).sort("streams", -1).limit(500)
    found = [s["song_id"] async for s in cur if s.get("song_id")]
    new_ids = [i for i in found if i not in existing]
    if new_ids:
        await db.users.update_one(
            {"user_id": artist_id},
            {"$push": {"curated_song_ids": {"$each": new_ids}}},
        )
    return {"added": len(new_ids), "total_matched": len(found)}


async def _create_attached_playlist(
    coll, key_field: str, key: str, owner_name: str, body: AdminPlaylistCreate,
) -> dict:
    pid = new_id("pl")
    doc = {
        "playlist_id": pid,
        "name": body.name.strip(),
        "description": body.description.strip(),
        # Not public: these live inside their section, not in the public
        # playlist feed. GET /playlists/{pid} does not check visibility.
        "is_public": False,
        "is_system": True,
        # Owned by the section itself so it never clutters the admin's own
        # Library; admins can still edit it (see playlist_add/remove).
        "owner_id": key,
        "owner_name": owner_name,
        "song_ids": [],
        "cover": body.cover.strip() or None,
        "layout": {"style": "vertical_list", "rows": 1, "columns": 1},
        "created_at": now(),
        "updated_at": now(),
    }
    await db.playlists.insert_one(doc)
    await coll.update_one({key_field: key}, {"$push": {"playlist_ids": pid}})
    doc.pop("_id", None)
    return doc


@api.post("/admin/categories/{category_id}/playlists")
async def admin_category_create_playlist(
    category_id: str, body: AdminPlaylistCreate, user: dict = Depends(current_user),
):
    _ensure_admin(user)
    c = await db.categories.find_one({"category_id": category_id}, {"_id": 0, "name": 1})
    if not c:
        raise HTTPException(404, "Not found")
    return await _create_attached_playlist(db.categories, "category_id", category_id, c.get("name", ""), body)


@api.post("/admin/categories/{category_id}/playlists/remove")
async def admin_category_remove_playlist(
    category_id: str, body: PlaylistIdBody, user: dict = Depends(current_user),
):
    _ensure_admin(user)
    await db.playlists.delete_one({"playlist_id": body.playlist_id, "owner_id": category_id})
    await _detach_playlist_everywhere(body.playlist_id)
    return {"ok": True}


@api.post("/admin/artists/{artist_id}/playlists")
async def admin_artist_create_playlist(
    artist_id: str, body: AdminPlaylistCreate, user: dict = Depends(current_user),
):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    a = await _artist_or_404(artist_id)
    return await _create_attached_playlist(db.users, "user_id", artist_id, a.get("name", ""), body)


@api.post("/admin/artists/{artist_id}/playlists/remove")
async def admin_artist_remove_playlist(
    artist_id: str, body: PlaylistIdBody, user: dict = Depends(current_user),
):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    await db.playlists.delete_one({"playlist_id": body.playlist_id, "owner_id": artist_id})
    await _detach_playlist_everywhere(body.playlist_id)
    return {"ok": True}


# ──────────────────────────── artist dashboard ────────────────────────────

@api.post("/artist/upload")
async def artist_upload(
    title: str = Form(...),
    genre: str = Form("Pop"),
    mood: str = Form("Chill"),
    language: str = Form("English"),
    explicit: bool = Form(False),
    credits: str = Form(""),
    lyrics: str = Form(""),
    cover_url: str = Form(""),
    file: UploadFile = File(...),
    cover: Optional[UploadFile] = File(None),
    user: dict = Depends(current_user),
):
    if user.get("role") not in ("artist", "admin"):
        raise HTTPException(403, "Become an artist first")
    audio_bytes = await file.read()
    if len(audio_bytes) > 50 * 1024 * 1024:
        raise HTTPException(400, "Max file size 50MB")
    sid = new_id("song")
    audio_kind = "gridfs"
    audio_grid_id: Optional[str] = None
    public_audio_url: Optional[str] = None
    public_cover_url: Optional[str] = cover_url or None

    # 1) Prefer Cloudflare R2 (new primary storage)
    if _r2_client is not None:
        try:
            ext = (file.filename or "audio.mp3").rsplit(".", 1)[-1].lower()
            if ext not in ("mp3", "m4a", "aac", "wav", "ogg", "flac"):
                ext = "mp3"
            audio_key = f"songs/{sid}.{ext}"
            public_audio_url = r2_upload_bytes(audio_key, audio_bytes, file.content_type or "audio/mpeg")
            audio_kind = "r2"

            if cover is not None:
                cover_bytes = await cover.read()
                if cover_bytes:
                    cover_ext = (cover.filename or "cover.jpg").rsplit(".", 1)[-1].lower()
                    if cover_ext not in ("jpg", "jpeg", "png", "webp"):
                        cover_ext = "jpg"
                    cover_key = f"covers/{sid}.{cover_ext}"
                    public_cover_url = r2_upload_bytes(cover_key, cover_bytes, cover.content_type or "image/jpeg")
        except Exception as e:
            log.warning("R2 upload failed, falling back to GridFS: %s", e)
            audio_kind = "gridfs"
            public_audio_url = None

    # 2) Last-resort: GridFS in MongoDB
    if audio_kind == "gridfs":
        grid_id = await gridfs.upload_from_stream(
            file.filename or "audio.mp3", audio_bytes,
            metadata={"content_type": file.content_type or "audio/mpeg"},
        )
        audio_grid_id = str(grid_id)

    if not public_cover_url:
        public_cover_url = "https://images.unsplash.com/photo-1632478179654-0b8a89119fc5?w=600"

    doc = {
        "song_id": sid,
        "title": title,
        "artist_id": user["user_id"],
        "artist_name": user.get("name", ""),
        "genre": genre,
        "mood": mood,
        "language": language,
        "explicit": explicit,
        "credits": credits,
        "lyrics": lyrics,
        "cover_url": public_cover_url,
        "duration_sec": 0,
        "audio_kind": audio_kind,
        "audio_grid_id": audio_grid_id,
        "audio_url": public_audio_url,
        "audio_content_type": file.content_type or "audio/mpeg",
        "audio_size": len(audio_bytes),
        "stream_url": public_audio_url,
        "streams": 0,
        "trending_score": 0,
        "is_published": True,
        "is_featured": False,
        "created_at": now(),
    }
    await db.songs.insert_one(doc)

    doc.pop("_id", None)
    # 3) Fanout: notify followers + all users (in-app + push). Best-effort.

    asyncio.create_task(_fanout_new_song_notification(doc))
    return await _enrich_song(doc)


@api.get("/songs/{song_id}/stream")
async def stream_song(song_id: str, request: Request):
    s = await db.songs.find_one({"song_id": song_id}, {"_id": 0})
    if not s:
        raise HTTPException(404, "Not found")
    if s.get("audio_kind") != "gridfs":
        raise HTTPException(400, "Song not stored on server")
    from bson import ObjectId
    try:
        oid = ObjectId(s["audio_grid_id"])
    except Exception:
        raise HTTPException(500, "Bad grid id")
    info = await db["audio.files"].find_one({"_id": oid})
    if not info:
        raise HTTPException(404, "Missing audio")
    size = info["length"]
    ctype = s.get("audio_content_type", "audio/mpeg")
    range_header = request.headers.get("range") or request.headers.get("Range")
    start, end = 0, size - 1
    status = 200
    if range_header and range_header.startswith("bytes="):
        try:
            spec = range_header.replace("bytes=", "").split("-")
            start = int(spec[0]) if spec[0] else 0
            end = int(spec[1]) if len(spec) > 1 and spec[1] else size - 1
            status = 206
        except Exception:
            pass
    stream = await gridfs.open_download_stream(oid)

    async def gen():
        if start > 0:
            # naive seek by reading & discarding (GridFS supports seek too)
            stream.seek(start)
        remaining = end - start + 1
        chunk = 64 * 1024
        while remaining > 0:
            data = await stream.read(min(chunk, remaining))
            if not data:
                break
            remaining -= len(data)
            yield data

    headers = {
        "Accept-Ranges": "bytes",
        "Content-Length": str(end - start + 1),
        "Content-Range": f"bytes {start}-{end}/{size}",
        "Cache-Control": "public, max-age=3600",
    }
    return StreamingResponse(gen(), status_code=status, media_type=ctype, headers=headers)


@api.get("/artist/dashboard")
async def artist_dashboard(user: dict = Depends(current_user)):
    if user.get("role") not in ("artist", "admin"):
        raise HTTPException(403, "Forbidden")
    songs_cur = db.songs.find({"artist_id": user["user_id"]}).sort("streams", -1)
    songs = [await _enrich_song(s) async for s in songs_cur]
    total_streams = sum(s.get("streams", 0) for s in songs)
    # Real-time monthly listeners: unique users who streamed any of this artist's
    # songs in the last 30 days. Updates live — no need to wait for a full month.
    threshold_30d = now() - timedelta(days=30)
    ml_pipeline = [
        {"$match": {"listened_at": {"$gte": threshold_30d}, "artist_id": user["user_id"]}},
        {"$group": {"_id": "$user_id"}},
        {"$count": "unique"},
    ]
    ml_result = await db.stream_logs.aggregate(ml_pipeline).to_list(length=1)
    monthly = ml_result[0]["unique"] if ml_result else 0
    tips = await db.tips.aggregate([
        {"$match": {"to_artist_id": user["user_id"]}},
        {"$group": {"_id": None, "n": {"$sum": "$amount"}}},
    ]).to_list(1)
    tip_total = tips[0]["n"] if tips else 0
    stream_earnings = round(total_streams * RATE_PER_STREAM, 2)  # ₹0.09 / qualified stream → ₹1800 per 20k

    # Per-song 30-day analytics: unique listeners + plays_30d for each of this
    # artist's songs. Runs a single aggregation over stream_logs.
    per_song_stats: dict[str, dict] = {}
    if songs:
        song_ids = [s["song_id"] for s in songs]
        ps_pipeline = [
            {"$match": {"listened_at": {"$gte": threshold_30d}, "track_id": {"$in": song_ids}}},
            {"$group": {
                "_id": "$track_id",
                "plays_30d": {"$sum": 1},
                "listeners": {"$addToSet": "$user_id"},
            }},
            {"$project": {"plays_30d": 1, "unique_listeners_30d": {"$size": "$listeners"}}},
        ]
        async for r in db.stream_logs.aggregate(ps_pipeline):
            per_song_stats[r["_id"]] = {
                "plays_30d": r["plays_30d"],
                "unique_listeners_30d": r["unique_listeners_30d"],
            }
    # Attach per-song stats + accurate earnings for the frontend.
    for s in songs:
        stats = per_song_stats.get(s["song_id"], {"plays_30d": 0, "unique_listeners_30d": 0})
        s["plays_30d"] = stats["plays_30d"]
        s["unique_listeners_30d"] = stats["unique_listeners_30d"]
        s["earnings"] = round((s.get("streams", 0) or 0) * RATE_PER_STREAM, 2)

    # 30-day daily plays timeline (for a small chart on the dashboard).
    daily_pipeline = [
        {"$match": {"listened_at": {"$gte": threshold_30d}, "artist_id": user["user_id"]}},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$listened_at"}},
            "count": {"$sum": 1},
        }},
        {"$sort": {"_id": 1}},
    ]
    daily = await db.stream_logs.aggregate(daily_pipeline).to_list(length=31)
    plays_30d_series = [{"date": d["_id"], "count": d["count"]} for d in daily]
    total_plays_30d = sum(d["count"] for d in daily)

    return {
        "total_streams": total_streams,
        "total_plays_30d": total_plays_30d,
        "monthly_listeners": monthly,
        "tip_total": tip_total,
        "stream_earnings": stream_earnings,
        "total_earnings": stream_earnings + tip_total,
        "rate_per_stream": RATE_PER_STREAM,
        "rate_display": "₹1,800 per 20,000 streams",
        "withdrawal_min_streams": WITHDRAWAL_MIN_STREAMS,
        "can_withdraw": total_streams >= WITHDRAWAL_MIN_STREAMS,
        "plays_30d": plays_30d_series,
        "songs": songs,
    }


@api.post("/artist/withdraw")
async def artist_withdraw(amount: int = Form(...), user: dict = Depends(current_user)):
    if user.get("role") not in ("artist", "admin"):
        raise HTTPException(403, "Forbidden")
    if not user.get("upi_id"):
        raise HTTPException(400, "Add UPI ID first")
    # Anti-abuse gate: artist must have accrued at least WITHDRAWAL_MIN_STREAMS
    # (10,000) real streams across their catalogue before requesting a payout.
    total_streams_agg = await db.songs.aggregate([
        {"$match": {"artist_id": user["user_id"]}},
        {"$group": {"_id": None, "n": {"$sum": "$streams"}}},
    ]).to_list(1)
    total_streams = total_streams_agg[0]["n"] if total_streams_agg else 0
    if total_streams < WITHDRAWAL_MIN_STREAMS:
        raise HTTPException(400, f"Need {WITHDRAWAL_MIN_STREAMS:,} total streams to withdraw. You have {total_streams:,}.")
    doc = {
        "withdrawal_id": new_id("wd"),
        "user_id": user["user_id"],
        "amount": amount,
        "upi_id": user["upi_id"],
        "status": "requested",
        "created_at": now(),
    }
    await db.withdrawals.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api.get("/admin/withdrawals")
async def admin_list_withdrawals(status: Optional[str] = None, user: dict = Depends(current_user)):
    """List artist withdrawal requests. Filter by status (requested/paid/rejected)."""
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    q: dict = {}
    if status:
        q["status"] = status
    cur = db.withdrawals.find(q, {"_id": 0}).sort("created_at", -1).limit(200)
    items = await cur.to_list(200)
    # Enrich with artist info
    ids = [w["user_id"] for w in items]
    artists = {}
    if ids:
        async for u in db.users.find({"user_id": {"$in": ids}}, {"_id": 0, "user_id": 1, "name": 1, "email": 1, "upi_id": 1}):
            artists[u["user_id"]] = u
    for w in items:
        a = artists.get(w["user_id"]) or {}
        w["artist_name"] = a.get("name") or "Unknown"
        w["artist_email"] = a.get("email") or ""
        w["artist_upi_id"] = a.get("upi_id") or w.get("upi_id")
    return {"items": items}


@api.post("/admin/withdrawals/{wd_id}/resolve")
async def admin_resolve_withdrawal(
    wd_id: str,
    status: str = Form(...),
    note: str = Form(""),
    user: dict = Depends(current_user),
):
    """Mark a withdrawal as paid or rejected."""
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    if status not in ("paid", "rejected", "requested"):
        raise HTTPException(400, "Invalid status")
    res = await db.withdrawals.update_one(
        {"withdrawal_id": wd_id},
        {"$set": {"status": status, "admin_note": note, "resolved_at": now(), "resolved_by": user["user_id"]}},
    )
    if res.matched_count == 0:
        raise HTTPException(404, "Withdrawal not found")
    return {"ok": True, "status": status}


# ──────────────────────────── tips / premium ────────────────────────────

@api.post("/songs/{song_id}/tip", deprecated=True)
async def tip_artist_deprecated(song_id: str, user: dict = Depends(current_user)):
    """DEPRECATED — tipping system removed. Returns 410 Gone."""
    raise HTTPException(410, "Tipping has been removed from the platform")


@api.post("/me/subscribe")
async def subscribe(plan: str = Form("monthly"), user: dict = Depends(current_user)):
    until = now() + timedelta(days=30 if plan == "monthly" else 365)
    await db.users.update_one(
        {"user_id": user["user_id"]},
        {"$set": {"is_premium": True, "has_had_premium": True, "premium_until": until, "premium_plan": plan}},
    )
    return {"ok": True, "premium_until": until.isoformat(), "plan": plan}


# ──────────────────────────── admin ────────────────────────────

def _is_admin(u: dict) -> bool:
    return u.get("role") == "admin" or u.get("email", "").lower() == ADMIN_EMAIL.lower()


@api.get("/admin/stats")
async def admin_stats(user: dict = Depends(current_user)):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    total_users = await db.users.count_documents({})
    total_artists = await db.users.count_documents({"role": "artist"})
    total_songs = await db.songs.count_documents({})
    total_streams_pipeline = await db.songs.aggregate([
        {"$group": {"_id": None, "n": {"$sum": "$streams"}}}
    ]).to_list(1)
    total_streams = total_streams_pipeline[0]["n"] if total_streams_pipeline else 0
    daily = await db.play_events.count_documents({"played_at": {"$gte": now() - timedelta(days=1)}})
    monthly = await db.play_events.count_documents({"played_at": {"$gte": now() - timedelta(days=30)}})
    active = await db.play_events.aggregate([
        {"$match": {"played_at": {"$gte": now() - timedelta(days=7)}}},
        {"$group": {"_id": "$user_id"}},
        {"$count": "n"},
    ]).to_list(1)
    active_users = active[0]["n"] if active else 0
    tip_total = await db.tips.aggregate([
        {"$group": {"_id": None, "n": {"$sum": "$amount"}}}
    ]).to_list(1)
    tips = tip_total[0]["n"] if tip_total else 0
    # 7-day streams series
    series: list[dict] = []
    for i in range(6, -1, -1):
        start = now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=i)
        end = start + timedelta(days=1)
        n = await db.play_events.count_documents({"played_at": {"$gte": start, "$lt": end}})
        series.append({"day": start.strftime("%a"), "streams": n})
    # Top songs
    top_cur = db.songs.find({"is_published": True}).sort("streams", -1).limit(5)
    top_songs = [await _enrich_song(s) async for s in top_cur]
    # Top genres
    top_genres = await db.songs.aggregate([
        {"$group": {"_id": "$genre", "streams": {"$sum": "$streams"}}},
        {"$sort": {"streams": -1}},
        {"$limit": 5},
    ]).to_list(5)
    return {
        "total_users": total_users,
        "active_users_7d": active_users,
        "total_artists": total_artists,
        "total_songs": total_songs,
        "total_streams": total_streams,
        "daily_streams": daily,
        "monthly_streams": monthly,
        "tip_revenue": tips,
        "stream_series_7d": series,
        "top_songs": top_songs,
        "top_genres": [{"genre": g["_id"], "streams": g["streams"]} for g in top_genres if g["_id"]],
    }


@api.get("/admin/users")
async def admin_users(user: dict = Depends(current_user), limit: int = 50):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    cur = db.users.find({}, {"_id": 0, "password_hash": 0}).sort("created_at", -1).limit(limit)
    return {"items": [public_user(u) async for u in cur]}


@api.post("/admin/artists/approve")
async def admin_approve_artist(body: ApproveArtistBody, user: dict = Depends(current_user)):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    role = "artist" if body.approve else "user"
    await db.users.update_one({"user_id": body.user_id}, {"$set": {"role": role}})
    return {"ok": True, "role": role}


@api.post("/admin/songs/{song_id}/feature")
async def admin_feature_song(song_id: str, body: FeatureBody, user: dict = Depends(current_user)):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    r = await db.songs.update_one({"song_id": song_id}, {"$set": {"is_featured": body.is_featured}})
    if r.matched_count == 0:
        raise HTTPException(404, "Song not found")
    return {"ok": True}


@api.post("/admin/songs/{song_id}/trending")
async def admin_trending_song(song_id: str, body: dict = Body(...), user: dict = Depends(current_user)):
    """Admin toggles a song's `is_trending` flag for the curated Trending row."""
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    flag = bool(body.get("is_trending", False))
    r = await db.songs.update_one({"song_id": song_id}, {"$set": {"is_trending": flag}})
    if r.matched_count == 0:
        raise HTTPException(404, "Song not found")
    return {"ok": True, "is_trending": flag}


@api.post("/admin/songs/{song_id}/ban")
async def admin_ban_song(song_id: str, user: dict = Depends(current_user)):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    await db.songs.update_one({"song_id": song_id}, {"$set": {"is_published": False}})
    return {"ok": True}


@api.post("/admin/users/premium")
async def admin_toggle_premium(body: TogglePremiumBody, user: dict = Depends(current_user)):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    patch: dict = {"is_premium": body.is_premium}
    if body.is_premium:
        patch["has_had_premium"] = True   # lifetime ad-free flag
        patch["premium_until"] = now() + timedelta(days=365)
        patch["premium_plan"] = body.plan or "admin_granted"
    else:
        patch["premium_plan"] = None
    r = await db.users.update_one({"user_id": body.user_id}, {"$set": patch})
    if r.matched_count == 0:
        raise HTTPException(404, "User not found")
    return {"ok": True, "is_premium": body.is_premium}


@api.post("/admin/notify")
async def admin_notify(title: str = Form(...), body: str = Form(""), user: dict = Depends(current_user)):
    """Queue a broadcast notification. Real push delivered via Emergent push (batched)."""
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    doc = {
        "notif_id": new_id("notif"),
        "title": title,
        "body": body,
        "status": "queued",
        "queued_at": now(),
        "delivered_to": 0,
    }
    await db.notifications.insert_one(doc)
    asyncio.create_task(_dispatch_notify(doc["notif_id"], title, body))
    doc.pop("_id", None)
    return doc


async def _dispatch_notify(notif_id: str, title: str, body: str):
    """Batched dispatch: chunks of 100 user IDs to Emergent push, spaced to throttle."""
    cur = db.users.find({}, {"_id": 0, "user_id": 1})
    all_ids: list[str] = [u["user_id"] async for u in cur]
    delivered = 0
    failed = 0
    chunk_size = 100
    chunks = [all_ids[i:i + chunk_size] for i in range(0, len(all_ids), chunk_size)]
    for idx, chunk in enumerate(chunks):
        try:
            await send_push(
                recipients=chunk,
                data={"title": title, "message": body or " "},
                idempotency_key=f"{notif_id}-chunk{idx}",
            )
            delivered += len(chunk)
        except Exception as e:
            failed += len(chunk)
            log.warning("push chunk %d failed (non-blocking): %s", idx, e)
        # Throttle: 1 second between chunks (~100 users/sec)
        if idx < len(chunks) - 1:
            await asyncio.sleep(1)
    await db.notifications.update_one(
        {"notif_id": notif_id},
        {"$set": {
            "status": "delivered" if failed == 0 else "partial",
            "delivered_to": delivered,
            "failed_count": failed,
            "delivered_at": now(),
        }},
    )


# ──────────────────────────── genres ────────────────────────────

GENRES = ["Hip-Hop", "Lo-Fi", "Indie", "EDM", "Rock", "Pop", "R&B", "Punjabi"]


@api.get("/genres")
async def list_genres():
    out = []
    covers = [
        "https://images.unsplash.com/photo-1540039155733-5bb30b53aa14?w=600",
        "https://images.unsplash.com/photo-1429962714451-bb934ecdc4ec?w=600",
        "https://images.pexels.com/photos/32399568/pexels-photo-32399568.jpeg?w=600",
        "https://images.unsplash.com/photo-1671713912667-5947b830235d?w=600",
        "https://images.unsplash.com/photo-1644855640845-ab57a047320e?w=600",
        "https://images.unsplash.com/photo-1632478179654-0b8a89119fc5?w=600",
        "https://images.unsplash.com/photo-1519326773765-3ae3b02c44cc?w=600",
        "https://images.unsplash.com/photo-1595971294624-80bcf0d7eb24?w=600",
    ]
    palette = ["#1ED760", "#E22134", "#FFA42B", "#7C5CFA", "#FF6BD6", "#3DA9FC", "#16C79A", "#FFCB6B"]
    for i, g in enumerate(GENRES):
        out.append({"genre": g, "cover": covers[i % len(covers)], "color": palette[i % len(palette)]})
    return {"items": out}


@api.get("/health")
async def health():
    return {"ok": True, "service": "musify", "time": now().isoformat()}


# ──────────────────────────── stream counter (Spotify-style) ────────────────────────────
# In-memory micro-batch buffer flushed every 60s to keep DB writes O(unique tracks).
# Hourly per-user cap prevents loop fraud.

QUALIFY_SECONDS = 30       # Continuous listen threshold to count 1 stream (lowered from 50s → 30s per product spec)
WITHDRAWAL_MIN_STREAMS = 10000  # Artist must accrue ≥10,000 all-time streams before their first withdrawal.
HOURLY_FRAUD_CAP = 10
FLUSH_INTERVAL_SEC = 60
RATE_PER_STREAM = 0.09       # ₹ per qualified stream (artist payout) — ₹1800 per 20,000 streams

_stream_buffer: dict[str, int] = {}        # song_id -> pending count
_user_track_window: dict[tuple[str, str], list[float]] = {}  # (user_id, track_id) -> ts list
_buffer_lock = asyncio.Lock()


async def _flush_stream_buffer():
    """Background worker: flush accumulated stream counts to Mongo."""
    while True:
        try:
            await asyncio.sleep(FLUSH_INTERVAL_SEC)
            async with _buffer_lock:
                if not _stream_buffer:
                    continue
                snapshot = dict(_stream_buffer)
                _stream_buffer.clear()
            for song_id, n in snapshot.items():
                try:
                    await db.songs.update_one(
                        {"song_id": song_id},
                        {"$inc": {"streams": n, "trending_score": n}, "$set": {"last_played_at": now()}},
                    )
                except Exception as e:
                    log.warning("flush song %s failed: %s", song_id, e)
        except asyncio.CancelledError:
            break
        except Exception as e:
            log.warning("flush loop error: %s", e)


@api.post("/streams/log", status_code=202)
async def stream_log(body: StreamLogBody, request: Request, user: dict = Depends(current_user)):
    """Records a stream event in the background. Returns 202 immediately.

    Qualified stream rule: duration_seconds >= 30 (continuous play).
    Hourly fraud cap: max 10 streams per (user, track) within any 60-min window.
    """
    if body.duration_seconds < QUALIFY_SECONDS:
        return {"accepted": False, "reason": "did_not_qualify"}

    user_id = user["user_id"]
    key = (user_id, body.track_id)
    now_ts = now().timestamp()
    one_hour_ago = now_ts - 3600
    window = [t for t in _user_track_window.get(key, []) if t > one_hour_ago]
    if len(window) >= HOURLY_FRAUD_CAP:
        return {"accepted": False, "reason": "hourly_cap_reached"}
    window.append(now_ts)
    _user_track_window[key] = window

    client_ip = request.client.host if request.client else None
    asyncio.create_task(_record_stream_async(user_id, body.track_id, body.duration_seconds, client_ip))
    return {"accepted": True}


async def _record_stream_async(user_id: str, track_id: str, duration_seconds: int, client_ip: Optional[str]):
    """Append to stream_logs (Mongo), recently_played, and increment buffer."""
    try:
        s = await db.songs.find_one({"song_id": track_id}, {"_id": 0, "artist_id": 1})
        artist_id = s.get("artist_id") if s else None

        # Stream log into Mongo
        await db.stream_logs.insert_one({
            "user_id": user_id,
            "track_id": track_id,
            "artist_id": artist_id,
            "listened_at": now(),
            "duration_seconds": duration_seconds,
            "client_ip": client_ip,
        })

        # Buffer increment (counted_view / micro-batched)
        async with _buffer_lock:
            _stream_buffer[track_id] = _stream_buffer.get(track_id, 0) + 1

        # play_events (per-listener history) + recently_played
        await db.play_events.insert_one({
            "play_id": new_id("play"),
            "song_id": track_id,
            "user_id": user_id,
            "artist_id": artist_id,
            "played_at": now(),
        })
        await db.recently_played.delete_many({"user_id": user_id, "song_id": track_id})
        await db.recently_played.insert_one(
            {"user_id": user_id, "song_id": track_id, "played_at": now()}
        )
    except Exception as e:
        log.warning("record stream failed: %s", e)


# ──────────────────────────── delete + admin search ────────────────────────────

@api.delete("/songs/{song_id}")
async def delete_song(song_id: str, user: dict = Depends(current_user)):
    s = await db.songs.find_one({"song_id": song_id}, {"_id": 0})
    if not s:
        raise HTTPException(404, "Not found")
    if user.get("role") != "admin" and s.get("artist_id") != user["user_id"]:
        raise HTTPException(403, "You can only delete your own songs")
    # Delete from GridFS if applicable
    if s.get("audio_kind") == "gridfs" and s.get("audio_grid_id"):
        try:
            from bson import ObjectId
            await gridfs.delete(ObjectId(s["audio_grid_id"]))
        except Exception as e:
            log.warning("gridfs delete failed: %s", e)
    await db.songs.delete_one({"song_id": song_id})
    await db.likes.delete_many({"song_id": song_id})
    await db.recently_played.delete_many({"song_id": song_id})
    await db.playlists.update_many({}, {"$pull": {"song_ids": song_id}})
    return {"ok": True}


@api.get("/admin/songs")
async def admin_list_songs(
    user: dict = Depends(current_user), q: str = "", limit: int = 100, skip: int = 0,
):
    """Paged so the admin Songs tab can walk the WHOLE catalogue ("Load
    more") instead of stopping at the first 100 rows."""
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    query: dict = {}
    if q:
        rx = {"$regex": re.escape(q), "$options": "i"}
        query = {"$or": [{"title": rx}, {"artist_name": rx}, {"genre": rx}]}
    limit = max(1, min(limit, 500))
    total = await db.songs.count_documents(query)
    cur = db.songs.find(query).sort("created_at", -1).skip(max(0, skip)).limit(limit)
    return {"items": [await _enrich_song(s) async for s in cur], "total": total}


@api.get("/admin/users/search")
async def admin_search_users(q: str = "", user: dict = Depends(current_user), limit: int = 50):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    query: dict = {}
    if q:
        rx = {"$regex": q, "$options": "i"}
        query = {"$or": [{"name": rx}, {"email": rx}]}
    cur = db.users.find(query, {"_id": 0, "password_hash": 0}).sort("created_at", -1).limit(limit)
    return {"items": [public_user(u) async for u in cur]}


@api.post("/admin/seed/clear")
async def admin_clear_seed(user: dict = Depends(current_user)):
    """Delete dummy seed songs + dummy artists. Keeps admin + demo users."""
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    # Songs with audio_kind == 'url' are seeded (external SoundHelix URLs)
    seed_songs = await db.songs.find({"audio_kind": "url"}, {"_id": 0, "song_id": 1}).to_list(500)
    seed_ids = [s["song_id"] for s in seed_songs]
    if seed_ids:
        await db.songs.delete_many({"song_id": {"$in": seed_ids}})
        await db.likes.delete_many({"song_id": {"$in": seed_ids}})
        await db.recently_played.delete_many({"song_id": {"$in": seed_ids}})
        await db.playlists.update_many({}, {"$pull": {"song_ids": {"$in": seed_ids}}})
    # Dummy artist accounts (artistN@musify.app)
    res = await db.users.delete_many({"email": {"$regex": r"^artist\d+@musify\.app$"}})
    # Demo-owned dummy playlists with no remaining songs
    await db.playlists.delete_many({"song_ids": {"$size": 0}})
    return {"songs_removed": len(seed_ids), "artists_removed": res.deleted_count}


# ──────────────────────────── follow / unfollow ────────────────────────────

@api.post("/artists/{artist_id}/follow")
async def follow_artist(artist_id: str, user: dict = Depends(current_user)):
    """Toggle follow on an artist. Updates artist.followers counter atomically."""
    artist = await db.users.find_one({"user_id": artist_id}, {"_id": 0, "role": 1, "name": 1})
    if not artist:
        raise HTTPException(404, "Artist not found")
    if artist_id == user["user_id"]:
        raise HTTPException(400, "Cannot follow yourself")
    existing = await db.follows.find_one({"follower_id": user["user_id"], "artist_id": artist_id})
    if existing:
        await db.follows.delete_one({"_id": existing["_id"]})
        await db.users.update_one({"user_id": artist_id}, {"$inc": {"followers": -1}})
        return {"following": False}
    await db.follows.insert_one({
        "follower_id": user["user_id"],
        "artist_id": artist_id,
        "created_at": now(),
    })
    await db.users.update_one({"user_id": artist_id}, {"$inc": {"followers": 1}})
    return {"following": True}


@api.get("/artists/{artist_id}/follow-status")
async def follow_status(artist_id: str, user: dict = Depends(current_user)):
    existing = await db.follows.find_one({"follower_id": user["user_id"], "artist_id": artist_id})
    cnt = await db.follows.count_documents({"artist_id": artist_id})
    return {"following": bool(existing), "followers": cnt}


@api.get("/me/following")
async def my_following(user: dict = Depends(current_user)):
    cur = db.follows.find({"follower_id": user["user_id"]}, {"_id": 0, "artist_id": 1})
    ids = [f["artist_id"] async for f in cur]
    artists: list[dict] = []
    if ids:
        ucur = db.users.find({"user_id": {"$in": ids}}, {"_id": 0, "password_hash": 0})
        artists = [public_user(u) async for u in ucur]
    return {"items": artists}


# ──────────────────────────── edit song (artist / admin) ────────────────────────────

@api.patch("/songs/{song_id}")
async def edit_song(song_id: str, body: EditSongBody, user: dict = Depends(current_user)):
    s = await db.songs.find_one({"song_id": song_id}, {"_id": 0})
    if not s:
        raise HTTPException(404, "Not found")
    if user.get("role") != "admin" and s.get("artist_id") != user["user_id"]:
        raise HTTPException(403, "You can only edit your own songs")

    patch: dict = {k: v for k, v in body.dict(exclude_unset=True).items() if v is not None}

    # cover_base64 → upload to R2, or inline as a data URL if R2 isn't configured
    if "cover_base64" in patch:
        cb = patch.pop("cover_base64") or ""
        if cb:
            uploaded = None
            if _r2_client is not None:
                try:
                    import base64
                    raw = cb.split(",", 1)[1] if cb.startswith("data:") else cb
                    cover_bytes = base64.b64decode(raw)
                    cover_key = f"covers/{song_id}-{int(now().timestamp())}.jpg"
                    uploaded = r2_upload_bytes(cover_key, cover_bytes, "image/jpeg")
                except Exception as e:
                    log.warning("cover upload failed: %s", e)
            patch["cover_url"] = uploaded or (cb if cb.startswith("data:") else f"data:image/jpeg;base64,{cb}")

    if patch:
        await db.songs.update_one({"song_id": song_id}, {"$set": patch})
    out = await db.songs.find_one({"song_id": song_id}, {"_id": 0})
    return await _enrich_song(out)


# ──────────────────────────── user notifications feed ────────────────────────────

@api.get("/me/notifications")
async def my_notifications(user: dict = Depends(current_user), limit: int = 50):
    """Recent in-app notifications: personal (target_user_id) + broadcasts."""
    cur = db.notifications.find(
        {"$or": [{"target_user_id": user["user_id"]}, {"audience": "all"}]},
        {"_id": 0},
    ).sort("queued_at", -1).limit(min(limit, 200))
    items = await cur.to_list(limit)
    return {"items": items}


@api.get("/me/notifications/unread")
async def my_notifications_unread(user: dict = Depends(current_user)):
    """Number of notifications received AFTER the user's last `seen_at` timestamp.

    Used by the header bell badge across the app. Returns 0 if the user has
    never opened /notifications (we treat first-time as 'all seen') to avoid
    spurious badges after signup.
    """
    read = await db.notification_reads.find_one({"user_id": user["user_id"]}, {"_id": 0})
    seen_at = (read or {}).get("seen_at")
    if not seen_at:
        # Prime the seen timestamp to NOW so returning users start clean.
        await db.notification_reads.update_one(
            {"user_id": user["user_id"]},
            {"$set": {"seen_at": now()}},
            upsert=True,
        )
        return {"unread": 0}
    q = {
        "queued_at": {"$gt": seen_at},
        "$or": [{"target_user_id": user["user_id"]}, {"audience": "all"}],
    }
    n = await db.notifications.count_documents(q)
    return {"unread": int(n)}


@api.post("/me/notifications/seen")
async def mark_notifications_seen(user: dict = Depends(current_user)):
    await db.notification_reads.update_one(
        {"user_id": user["user_id"]},
        {"$set": {"seen_at": now()}},
        upsert=True,
    )
    return {"ok": True}


async def _fanout_new_song_notification(song: dict):
    """Insert per-follower in-app notifications (one per follower, no broadcast
    duplicate). Best-effort push via Emergent push (skipped if key is placeholder)."""
    try:
        artist_id = song.get("artist_id")
        title = f"New from {song.get('artist_name', 'an artist')}"
        body = song.get("title", "Tap to listen")
        cover = song.get("cover_url")
        # Per-follower targeted in-app notifications only. NO broadcast doc —
        # a broadcast + per-follower doc was causing followers to see this
        # notification twice (once as audience='all', once as target_user_id).
        follower_ids: list[str] = []
        if artist_id:
            async for f in db.follows.find({"artist_id": artist_id}, {"_id": 0, "follower_id": 1}):
                follower_ids.append(f["follower_id"])
        if follower_ids:
            docs = [{
                "notif_id": new_id("notif"),
                "target_user_id": fid,
                "title": title,
                "body": body,
                "song_id": song.get("song_id"),
                "cover_url": cover,
                "artist_id": artist_id,
                "queued_at": now(),
                "status": "queued",
            } for fid in follower_ids]
            await db.notifications.insert_many(docs)
        # Push (best-effort, batched) — send to followers only to match the in-app fan-out.
        if EMERGENT_PUSH_KEY != "placeholder" and follower_ids:
            for i in range(0, len(follower_ids), 100):
                try:
                    await send_push(
                        recipients=follower_ids[i:i + 100],
                        data={"title": title, "message": body, "song_id": song.get("song_id", "")},
                        idempotency_key=f"newsong-{song.get('song_id')}-{i}",
                    )
                except Exception as e:
                    log.warning("push fanout chunk failed: %s", e)
    except Exception as e:
        log.warning("fanout failed: %s", e)


# ──────────────────────────── admin moderation v2 ────────────────────────────

@api.delete("/admin/users/{user_id}")
async def admin_delete_user(user_id: str, user: dict = Depends(current_user)):
    """Hard-delete a user account. If artist, also deletes their songs/likes."""
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    if user_id == user["user_id"]:
        raise HTTPException(400, "Cannot delete yourself")
    target = await db.users.find_one({"user_id": user_id}, {"_id": 0, "email": 1, "role": 1})
    if not target:
        raise HTTPException(404, "User not found")
    if target.get("email", "").lower() == ADMIN_EMAIL.lower():
        raise HTTPException(400, "Cannot delete the platform admin")
    # If artist: clean up their songs first
    song_ids: list[str] = []
    async for s in db.songs.find({"artist_id": user_id}, {"_id": 0, "song_id": 1}):
        song_ids.append(s["song_id"])
    if song_ids:
        await db.songs.delete_many({"song_id": {"$in": song_ids}})
        await db.likes.delete_many({"song_id": {"$in": song_ids}})
        await db.recently_played.delete_many({"song_id": {"$in": song_ids}})
        await db.playlists.update_many({}, {"$pull": {"song_ids": {"$in": song_ids}}})
    await db.users.delete_one({"user_id": user_id})
    await db.likes.delete_many({"user_id": user_id})
    await db.recently_played.delete_many({"user_id": user_id})
    await db.follows.delete_many({"$or": [{"follower_id": user_id}, {"artist_id": user_id}]})
    await db.playlists.delete_many({"owner_id": user_id})
    return {"ok": True, "user_id": user_id, "songs_removed": len(song_ids)}


@api.delete("/admin/artists/{artist_id}")
async def admin_delete_artist(artist_id: str, user: dict = Depends(current_user)):
    """Same as delete_user, but enforces role == artist for safety."""
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    target = await db.users.find_one({"user_id": artist_id}, {"_id": 0, "role": 1})
    if not target:
        raise HTTPException(404, "Artist not found")
    if target.get("role") != "artist":
        raise HTTPException(400, "Target user is not an artist")
    return await admin_delete_user(artist_id, user)


# ──────────────────────────── subscription plans CRUD ────────────────────────────

@api.get("/plans")
async def list_plans():
    cur = db.subscription_plans.find({"is_active": True}, {"_id": 0}).sort("sort_order", 1)
    return {"items": await cur.to_list(50)}


@api.get("/admin/plans")
async def admin_list_plans(user: dict = Depends(current_user)):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    cur = db.subscription_plans.find({}, {"_id": 0}).sort("sort_order", 1)
    return {"items": await cur.to_list(100)}


@api.post("/admin/plans")
async def admin_create_plan(body: PlanBody, user: dict = Depends(current_user)):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    doc = {"plan_id": new_id("plan"), "created_at": now(), **body.dict()}
    await db.subscription_plans.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api.put("/admin/plans/{plan_id}")
async def admin_update_plan(plan_id: str, body: PlanBody, user: dict = Depends(current_user)):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    res = await db.subscription_plans.update_one({"plan_id": plan_id}, {"$set": body.dict()})
    if res.matched_count == 0:
        raise HTTPException(404, "Plan not found")
    out = await db.subscription_plans.find_one({"plan_id": plan_id}, {"_id": 0})
    return out


@api.delete("/admin/plans/{plan_id}")
async def admin_delete_plan(plan_id: str, user: dict = Depends(current_user)):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    res = await db.subscription_plans.delete_one({"plan_id": plan_id})
    if res.deleted_count == 0:
        raise HTTPException(404, "Plan not found")
    return {"ok": True}


# ──────────────────────────── support contact (admin-editable, public read) ────────────────────────────

@api.get("/support")
async def get_support_info():
    """Public — shown on Privacy/Terms screens."""
    doc = await db.app_settings.find_one({"key": "support"}, {"_id": 0}) or {}
    return {
        "email": doc.get("email") or "support@mysify.app",
        "phone": doc.get("phone") or "",
        "address": doc.get("address") or "",
    }


@api.post("/admin/support")
async def admin_set_support(
    email: str = Form(""),
    phone: str = Form(""),
    address: str = Form(""),
    user: dict = Depends(current_user),
):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    await db.app_settings.update_one(
        {"key": "support"},
        {"$set": {"key": "support", "email": email, "phone": phone, "address": address, "updated_at": now()}},
        upsert=True,
    )
    return {"ok": True, "email": email, "phone": phone, "address": address}


# ──────────────────────────── premium payment (QR + submissions) ────────────────────────────

@api.get("/payment-qr")
async def get_payment_qr():
    """Public — base64 QR image users scan to pay for premium."""
    doc = await db.app_settings.find_one({"key": "payment_qr"}, {"_id": 0}) or {}
    return {
        "image": doc.get("image") or "",
        "upi_id": doc.get("upi_id") or "",
        "note": doc.get("note") or "",
        "updated_at": doc.get("updated_at"),
    }


@api.post("/admin/payment-qr")
async def admin_set_payment_qr(
    body: dict = Body(...),
    user: dict = Depends(current_user),
):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    image = (body.get("image") or "").strip()
    upi_id = (body.get("upi_id") or "").strip()
    note = (body.get("note") or "").strip()
    if image and not image.startswith("data:image/"):
        raise HTTPException(400, "image must be base64 data URL (data:image/...;base64,...)")
    await db.app_settings.update_one(
        {"key": "payment_qr"},
        {"$set": {"key": "payment_qr", "image": image, "upi_id": upi_id, "note": note, "updated_at": now()}},
        upsert=True,
    )
    return {"ok": True, "image": image, "upi_id": upi_id, "note": note}


@api.post("/premium/submit")
async def premium_submit(
    body: dict = Body(...),
    user: dict = Depends(current_user),
):
    """User submits a payment screenshot + reference for admin review."""
    plan_id = (body.get("plan_id") or "").strip()
    screenshot = (body.get("screenshot") or "").strip()
    reference = (body.get("reference") or "").strip()
    if not plan_id or not screenshot or not reference:
        raise HTTPException(400, "plan_id, screenshot, reference required")
    if not screenshot.startswith("data:image/"):
        raise HTTPException(400, "screenshot must be base64 data URL")
    plan = await db.subscription_plans.find_one({"plan_id": plan_id}, {"_id": 0})
    if not plan:
        raise HTTPException(404, "Plan not found")
    doc = {
        "submission_id": new_id("pay"),
        "user_id": user["user_id"],
        "user_name": user.get("name", ""),
        "user_email": user.get("email", ""),
        "plan_id": plan_id,
        "plan_name": plan.get("name", ""),
        "plan_price": plan.get("price", 0),
        "plan_period": plan.get("period", ""),
        "screenshot": screenshot,
        "reference": reference,
        "status": "pending",
        "admin_note": "",
        "created_at": now(),
        "resolved_at": None,
    }
    await db.premium_submissions.insert_one(doc)
    doc.pop("_id", None)
    return {"ok": True, "submission_id": doc["submission_id"], "status": "pending"}


@api.get("/me/premium-submissions")
async def my_premium_submissions(user: dict = Depends(current_user)):
    cur = db.premium_submissions.find({"user_id": user["user_id"]}, {"_id": 0, "screenshot": 0}).sort("created_at", -1).limit(20)
    return {"items": [s async for s in cur]}


@api.get("/admin/premium-submissions")
async def admin_list_premium_submissions(
    status: str = Query("all", regex="^(all|pending|approved|rejected)$"),
    user: dict = Depends(current_user),
):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    q: dict = {} if status == "all" else {"status": status}
    cur = db.premium_submissions.find(q, {"_id": 0}).sort("created_at", -1).limit(200)
    return {"items": [s async for s in cur]}


@api.post("/admin/premium-submissions/{submission_id}/resolve")
async def admin_resolve_premium_submission(
    submission_id: str,
    body: dict = Body(...),
    user: dict = Depends(current_user),
):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    status = (body.get("status") or "").strip()
    note = (body.get("admin_note") or "").strip()
    if status not in ("approved", "rejected"):
        raise HTTPException(400, "status must be 'approved' or 'rejected'")
    sub = await db.premium_submissions.find_one({"submission_id": submission_id})
    if not sub:
        raise HTTPException(404, "Submission not found")
    await db.premium_submissions.update_one(
        {"submission_id": submission_id},
        {"$set": {"status": status, "admin_note": note, "resolved_at": now()}},
    )
    if status == "approved":
        await db.users.update_one(
            {"user_id": sub["user_id"]},
            {"$set": {
                "is_premium": True,
                "has_had_premium": True,
                "premium_plan": sub.get("plan_id"),
                "premium_period": sub.get("plan_period"),
                "premium_started_at": now(),
            }},
        )
        # send in-app notification (matches schema used by /api/me/notifications)
        try:
            await db.notifications.insert_one({
                "notif_id": new_id("notif"),
                "target_user_id": sub["user_id"],
                "audience": "user",
                "title": "Premium activated",
                "body": f"Your {sub.get('plan_name')} subscription is now active. Enjoy ad-free music!",
                "type": "premium_approved",
                "queued_at": now(),
                "read": False,
            })
        except Exception:
            pass
    return {"ok": True, "status": status}


# ──────────────────────────── Admin: Ads (image + text shown to free users) ────────────────────────────

@api.get("/active-ad")
async def get_active_ad(authorization: Optional[str] = Header(None)):
    """Returns the next enabled ad in rotation, or null. Premium users always get null.

    Rotation is sequence-based: ads sorted by `sequence` (ascending) then `created_at`.
    The client tells us which ad it just showed via the `?last=` query param so we can
    return the next one. If `last` is missing, we return the first enabled ad.
    """
    user = None
    try:
        if authorization:
            user = await current_user(authorization)
    except Exception:
        user = None
    # Show ads to every non-premium user (regardless of role or past premium history).
    if user and user.get("is_premium"):
        return {"ad": None}

    # Multi-ad collection first
    enabled = await db.ads.find(
        {"enabled": True},
        {"_id": 0},
    ).sort([("sequence", 1), ("created_at", 1)]).to_list(length=50)

    if enabled:
        return {"ad": enabled[0], "ads": enabled}

    # Legacy single-ad fallback
    doc = await db.app_settings.find_one({"key": "active_ad"}, {"_id": 0}) or {}
    if not doc.get("enabled"):
        return {"ad": None, "ads": []}
    legacy_ad = {
        "ad_id": "legacy",
        "media_type": "image" if doc.get("image") else ("audio" if doc.get("audio") else "image"),
        "image": doc.get("image") or "",
        "audio": doc.get("audio") or "",
        "video": "",
        "title": doc.get("title") or "",
        "body": doc.get("body") or "",
        "cta_label": doc.get("cta_label") or "",
        "cta_url": doc.get("cta_url") or "",
        "appear_every_minutes": int(doc.get("trigger_minutes") or 15),
        "auto_close_seconds": 0,
        "skip_after_seconds": int(doc.get("skip_after_seconds") or 5),
        "sequence": 0,
        "enabled": True,
    }
    return {"ad": legacy_ad, "ads": [legacy_ad]}




# ──────────────────────────── Streak system ────────────────────────────
# Schema:
#   db.streaks: {user_id, current_streak, longest_streak, last_qualified_date (YYYY-MM-DD),
#                today_listened_ms, today_date}
#   db.streak_rewards: {reward_id, days, type ('voucher'|'premium_days'),
#                       value (str voucher code or int days), label, description, enabled}

import datetime as _dt

STREAK_DAILY_QUALIFY_MS = 20 * 60 * 1000  # 20 minutes
STREAK_DAILY_CAP_MS = 8 * 60 * 60 * 1000  # 8 hours — anti-inflation cap per user per UTC day


def _today_key() -> str:
    """Consistent UTC calendar day. Uses the same `now()` helper as the rest of the
    server so day-boundaries never drift with server timezone or DST changes."""
    return now().date().isoformat()


def _yesterday_key() -> str:
    return (now().date() - _dt.timedelta(days=1)).isoformat()


async def _get_or_init_streak(user_id: str) -> dict:
    doc = await db.streaks.find_one({"user_id": user_id}, {"_id": 0})
    if not doc:
        doc = {
            "user_id": user_id,
            "current_streak": 0,
            "longest_streak": 0,
            "last_qualified_date": None,
            "today_listened_ms": 0,
            "today_date": _today_key(),
        }
        await db.streaks.insert_one(dict(doc))
    return doc


async def _maybe_reset_streak_window(streak: dict) -> dict:
    """If today is a new day, reset today_listened_ms. If user missed yesterday, reset streak.

    When a streak RESETS (user missed a day), we persist every reward the
    user had already unlocked into `claimed_reward_ids` so the streak
    screen no longer dangles those tiers — they must aim for the NEXT
    tier instead of re-farming the lowest one.
    """
    today = _today_key()
    if streak.get("today_date") != today:
        # Rolled to a new day → check missed-day reset.
        last = streak.get("last_qualified_date")
        if last and last != today and last != _yesterday_key():
            # User missed at least one day → restart streak.
            prev_streak = int(streak.get("current_streak") or 0)
            update = {
                "today_date": today,
                "today_listened_ms": 0,
                "current_streak": 0,
            }
            if prev_streak > 0:
                # Snapshot every tier they had already unlocked so they
                # can't re-win it after breaking the streak.
                try:
                    unlocked = await db.streak_rewards.find(
                        {"enabled": True, "days": {"$lte": prev_streak}},
                        {"_id": 0, "reward_id": 1},
                    ).to_list(length=200)
                    unlocked_ids = [r["reward_id"] for r in unlocked if r.get("reward_id")]
                    if unlocked_ids:
                        existing = streak.get("claimed_reward_ids") or []
                        merged = list(dict.fromkeys([*existing, *unlocked_ids]))
                        update["claimed_reward_ids"] = merged
                        streak["claimed_reward_ids"] = merged
                except Exception as e:
                    log.warning("streak claimed_reward_ids snapshot failed: %s", e)
            streak["current_streak"] = 0
            streak["today_date"] = today
            streak["today_listened_ms"] = 0
            await db.streaks.update_one(
                {"user_id": streak["user_id"]},
                {"$set": update},
            )
        else:
            streak["today_date"] = today
            streak["today_listened_ms"] = 0
            await db.streaks.update_one(
                {"user_id": streak["user_id"]},
                {"$set": {
                    "today_date": today,
                    "today_listened_ms": 0,
                }},
            )
    return streak


@api.post("/streak/heartbeat")
async def streak_heartbeat(body: dict = Body(...), user: dict = Depends(current_user)):
    """Player calls this every ~30s while music is playing. Accepts `ms_played` since last heartbeat.

    Anti-inflation caps applied in order:
      1. Per-call cap: 5 min (drops implausible bursts from a single heartbeat).
      2. Per-day cap: 8 h of listened-time credited per UTC calendar day — extra
         calls after that will simply be clamped, so rapid repeated calls can't
         run the counter past the cap. Streaks still qualify at 20 min/day.
    """
    ms = int(body.get("ms_played") or 0)
    # Per-call clamp
    if ms <= 0:
        ms = 0
    if ms > 5 * 60 * 1000:
        ms = 5 * 60 * 1000
    streak = await _get_or_init_streak(user["user_id"])
    streak = await _maybe_reset_streak_window(streak)

    today = _today_key()
    prev_total = int(streak.get("today_listened_ms") or 0)
    # Per-UTC-day cap — clamp added ms so total never exceeds STREAK_DAILY_CAP_MS.
    remaining = max(0, STREAK_DAILY_CAP_MS - prev_total)
    ms_credited = min(ms, remaining)
    new_total = prev_total + ms_credited
    qualifies_now = (
        new_total >= STREAK_DAILY_QUALIFY_MS
        and streak.get("last_qualified_date") != today
    )

    update = {"today_listened_ms": new_total, "today_date": today}
    if qualifies_now:
        new_current = (streak.get("current_streak") or 0) + 1
        update["current_streak"] = new_current
        update["longest_streak"] = max(streak.get("longest_streak") or 0, new_current)
        update["last_qualified_date"] = today

    await db.streaks.update_one({"user_id": user["user_id"]}, {"$set": update})
    return {
        "ok": True,
        "today_listened_ms": new_total,
        "ms_credited": ms_credited,
        "capped": ms_credited < ms,
        "qualified_today": qualifies_now or streak.get("last_qualified_date") == today,
        "current_streak": update.get("current_streak", streak.get("current_streak", 0)),
        "longest_streak": update.get("longest_streak", streak.get("longest_streak", 0)),
        "newly_qualified": qualifies_now,
    }


@api.get("/me/streak")
async def get_my_streak(user: dict = Depends(current_user)):
    streak = await _get_or_init_streak(user["user_id"])
    streak = await _maybe_reset_streak_window(streak)
    # Reward progress + next milestone
    rewards = await db.streak_rewards.find(
        {"enabled": True}, {"_id": 0}
    ).sort("days", 1).to_list(length=50)
    cur = streak.get("current_streak", 0)
    # Previously-claimed tiers (snapshotted on streak break) stay hidden
    # forever so users can't re-win the easy tiers over and over — they
    # must push PAST their old streak to see new rewards.
    claimed_ids = set(streak.get("claimed_reward_ids") or [])
    # Visibility window (June 2026 spec): unlocked rewards stay visible on
    # the user's streak page for 4 days after unlock; "fresh" for the first
    # 2 days (frontend highlights them). Older unlocked rewards are hidden
    # so the list keeps rotating.
    visible: list[dict] = []
    for r in rewards:
        if r.get("reward_id") in claimed_ids:
            continue  # already won in a previous streak run — permanently hidden
        days = int(r.get("days") or 0)
        unlocked = cur >= days
        if unlocked:
            days_since_unlock = cur - days  # rough proxy: one streak day per real day
            if days_since_unlock >= 4:
                continue  # past visibility window — hide
            r = {**r, "fresh": days_since_unlock < 2}
        visible.append(r)
    # Next/last reward calcs ignore the claimed set so the "next milestone"
    # pointer always leaps to the next tier the user hasn't won yet.
    unclaimed = [r for r in rewards if r.get("reward_id") not in claimed_ids]
    next_reward = next((r for r in unclaimed if r["days"] > cur), None)
    last_reward = next((r for r in reversed(unclaimed) if r["days"] <= cur), None)
    return {
        "current_streak": cur,
        "longest_streak": streak.get("longest_streak", 0),
        "today_listened_ms": streak.get("today_listened_ms", 0),
        "qualify_ms_target": STREAK_DAILY_QUALIFY_MS,
        "qualified_today": streak.get("last_qualified_date") == _today_key(),
        "rewards": visible,
        "next_reward": next_reward,
        "last_unlocked": last_reward,
    }


@api.get("/streak/rewards")
async def public_list_rewards():
    """Public read of enabled rewards (so the home/streak UI can show milestones)."""
    rewards = await db.streak_rewards.find(
        {"enabled": True}, {"_id": 0}
    ).sort("days", 1).to_list(length=50)
    return {"items": rewards}


# ─────────────────────────── Vouchers ───────────────────────────
# Voucher codes are admin-curated freebies (partner discount codes, promo
# codes, etc). They surface on the streak screen and are visible ONLY to
# users who are BOTH premium AND have qualified today's streak. Non-premium
# users, or premium users who haven't listened enough today, don't see them.

def _voucher_min_streak_default() -> int:
    return 1  # unlock as soon as today's streak is qualified


@api.get("/vouchers/me")
async def get_my_vouchers(user: dict = Depends(current_user)):
    """Vouchers visible to the current user.

    Gated by:
      • is_premium = True  (Play-Billing / admin grant / etc.)
      • today's streak has been qualified (played enough today)
    """
    u = await db.users.find_one({"user_id": user["user_id"]}, {"is_premium": 1, "premium_until": 1})
    is_premium = bool(u and u.get("is_premium"))
    if is_premium and u.get("premium_until"):
        pu = u["premium_until"]
        if isinstance(pu, datetime) and pu.tzinfo is None:
            pu = pu.replace(tzinfo=timezone.utc)
        if isinstance(pu, datetime) and pu < now():
            is_premium = False

    streak = await db.streaks.find_one({"user_id": user["user_id"]}, {"_id": 0}) or {}
    streak = await _maybe_reset_streak_window(streak)
    qualified_today = streak.get("last_qualified_date") == _today_key()
    current_streak = int(streak.get("current_streak", 0))

    if not is_premium or not qualified_today:
        return {
            "items": [],
            "is_premium": is_premium,
            "qualified_today": qualified_today,
            "current_streak": current_streak,
            "reason": (
                "premium_required" if not is_premium
                else "streak_not_qualified_today"
            ),
        }

    vouchers = await db.vouchers.find(
        {"enabled": True},
        {"_id": 0},
    ).sort("created_at", -1).to_list(length=100)
    # Filter by min_streak on the row
    visible = [v for v in vouchers if int(v.get("min_streak", 1)) <= current_streak]
    return {
        "items": visible,
        "is_premium": True,
        "qualified_today": True,
        "current_streak": current_streak,
    }


@api.get("/admin/vouchers")
async def admin_list_vouchers(user: dict = Depends(current_user)):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    items = await db.vouchers.find({}, {"_id": 0}).sort("created_at", -1).to_list(length=200)
    return {"items": items}


@api.post("/admin/vouchers")
async def admin_create_voucher(body: dict = Body(...), user: dict = Depends(current_user)):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    title = str(body.get("title", "")).strip()
    code = str(body.get("code", "")).strip()
    description = str(body.get("description", "")).strip()
    brand = str(body.get("brand", "")).strip()
    color = str(body.get("color", "#3FA7FF")).strip()
    if not title or not code:
        raise HTTPException(400, "title and code are required")
    min_streak = int(body.get("min_streak") or _voucher_min_streak_default())
    doc = {
        "voucher_id": str(uuid.uuid4()),
        "title": title,
        "code": code,
        "description": description,
        "brand": brand,
        "color": color,
        "min_streak": max(1, min_streak),
        "enabled": bool(body.get("enabled", True)),
        "created_at": now(),
        "created_by": user["user_id"],
    }
    await db.vouchers.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api.patch("/admin/vouchers/{voucher_id}")
async def admin_update_voucher(voucher_id: str, body: dict = Body(...), user: dict = Depends(current_user)):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    allowed = {"title", "code", "description", "brand", "color", "min_streak", "enabled"}
    patch = {k: body[k] for k in list(body.keys()) if k in allowed}
    if "min_streak" in patch:
        patch["min_streak"] = max(1, int(patch["min_streak"] or 1))
    if not patch:
        raise HTTPException(400, "No editable fields provided")
    res = await db.vouchers.update_one({"voucher_id": voucher_id}, {"$set": patch})
    if res.matched_count == 0:
        raise HTTPException(404, "Voucher not found")
    return {"ok": True}


@api.delete("/admin/vouchers/{voucher_id}")
async def admin_delete_voucher(voucher_id: str, user: dict = Depends(current_user)):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    res = await db.vouchers.delete_one({"voucher_id": voucher_id})
    if res.deleted_count == 0:
        raise HTTPException(404, "Voucher not found")
    return {"ok": True}


@api.get("/admin/streak-rewards")
async def admin_list_rewards(user: dict = Depends(current_user)):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    items = await db.streak_rewards.find({}, {"_id": 0}).sort("days", 1).to_list(length=100)
    return {"items": items}


@api.get("/admin/streaks")
async def admin_list_all_user_streaks(user: dict = Depends(current_user)):
    """Admin view of every user's current streak stats."""
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    streaks = await db.streaks.find({}, {"_id": 0}).sort("current_streak", -1).to_list(length=500)
    # Enrich with basic user info
    out = []
    for s in streaks:
        u = await db.users.find_one(
            {"user_id": s["user_id"]}, {"_id": 0, "name": 1, "email": 1, "avatar": 1, "role": 1},
        )
        out.append({
            "user_id": s["user_id"],
            "name": (u or {}).get("name") or "—",
            "email": (u or {}).get("email") or "—",
            "avatar": (u or {}).get("avatar"),
            "role": (u or {}).get("role") or "user",
            "current_streak": s.get("current_streak", 0),
            "longest_streak": s.get("longest_streak", 0),
            "today_listened_ms": s.get("today_listened_ms", 0),
            "last_qualified_date": s.get("last_qualified_date"),
        })
    return {"items": out, "total": len(out)}


@api.post("/admin/notifications/broadcast")
async def admin_broadcast_notification(body: dict = Body(...), user: dict = Depends(current_user)):
    """Admin sends an in-app + native push notification to all users (or a specific role)."""
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    title = (body.get("title") or "").strip()
    message = (body.get("message") or body.get("body") or "").strip()
    audience = (body.get("audience") or "all").lower()
    deeplink = (body.get("deeplink") or "").strip()
    if not title or not message:
        raise HTTPException(400, "title and message are required")

    query: dict = {}
    if audience in {"user", "artist", "admin"}:
        query["role"] = audience
    users_cur = db.users.find(query, {"_id": 0, "user_id": 1})
    now_iso = now()
    inserted = 0
    recipient_ids: list[str] = []
    async for u in users_cur:
        await db.notifications.insert_one({
            "notif_id": f"n_{uuid.uuid4().hex[:14]}",
            "target_user_id": u["user_id"],
            "audience": audience,
            "title": title,
            "message": message,
            "deeplink": deeplink or None,
            "queued_at": now_iso,
            "sent_by": user["user_id"],
            "read": False,
        })
        recipient_ids.append(u["user_id"])
        inserted += 1

    # Fan out real push in chunks of 100.
    push_data = {"title": title, "message": message}
    if deeplink:
        push_data["action_url"] = deeplink
    push_ok = 0
    for i in range(0, len(recipient_ids), 100):
        chunk = recipient_ids[i:i+100]
        try:
            await send_push(chunk, push_data)
            push_ok += len(chunk)
        except Exception as e:
            log.warning("push broadcast chunk failed: %s", e)
    return {"ok": True, "sent_to": inserted, "pushed": push_ok, "audience": audience}


# ──────────────────────────── Push notifications (Emergent-managed) ────────────────────────────
# (Push client, RegisterPushBody, and send_push helper are defined earlier in
# this file — see ~line 51 and ~line 332. This anchor section is intentionally
# empty; the /api/me/push-token endpoint at line 501 wraps the shared helpers.)


# ──────────────────────────── Live listeners (Now Playing) ────────────────────────────

@api.get("/analytics/live-listeners")
async def live_listeners_count():
    """Number of unique users who logged a stream in the last 90 seconds — public live counter."""
    threshold = now() - timedelta(seconds=90)
    try:
        pipeline = [
            {"$match": {"listened_at": {"$gte": threshold}}},
            {"$group": {"_id": "$user_id"}},
            {"$count": "unique"}
        ]
        result = await db.stream_logs.aggregate(pipeline).to_list(length=1)
        n = result[0]["unique"] if result else 0
    except Exception:
        n = 0
    return {"listeners": n, "as_of": now()}


@api.get("/analytics/song/{song_id}/live-listeners")
async def song_live_listeners(song_id: str):
    """Unique users listening to a specific song in the last 90 seconds."""
    threshold = now() - timedelta(seconds=90)
    try:
        pipeline = [
            {"$match": {"listened_at": {"$gte": threshold}, "track_id": song_id}},
            {"$group": {"_id": "$user_id"}},
            {"$count": "unique"}
        ]
        result = await db.stream_logs.aggregate(pipeline).to_list(length=1)
        n = result[0]["unique"] if result else 0
    except Exception:
        n = 0
    return {"listeners": n, "song_id": song_id, "as_of": now()}


@api.get("/analytics/artist/{artist_id}/monthly-listeners")
async def artist_monthly_listeners(artist_id: str):
    """Unique users who listened to any song by this artist in the last 30 days.

    Real-time — updates instantly as new streams are logged. Public endpoint so
    it can appear on the artist profile without auth."""
    threshold = now() - timedelta(days=30)
    try:
        pipeline = [
            {"$match": {"listened_at": {"$gte": threshold}, "artist_id": artist_id}},
            {"$group": {"_id": "$user_id"}},
            {"$count": "unique"}
        ]
        result = await db.stream_logs.aggregate(pipeline).to_list(length=1)
        n = result[0]["unique"] if result else 0
    except Exception:
        n = 0
    return {"monthly_listeners": n, "artist_id": artist_id, "as_of": now()}


@api.get("/admin/analytics/overview")
async def admin_analytics_overview(user: dict = Depends(current_user)):
    """Real live analytics — no mock numbers."""
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    threshold_live = now() - timedelta(seconds=90)
    threshold_today = now().replace(hour=0, minute=0, second=0, microsecond=0)
    threshold_month = now() - timedelta(days=30)

    total_users = await db.users.count_documents({})
    total_artists = await db.users.count_documents({"role": "artist"})
    total_songs = await db.songs.count_documents({})
    total_plays = await db.stream_logs.count_documents({})
    plays_today = await db.stream_logs.count_documents({"listened_at": {"$gte": threshold_today}})
    plays_month = await db.stream_logs.count_documents({"listened_at": {"$gte": threshold_month}})

    live_pipeline = [
        {"$match": {"listened_at": {"$gte": threshold_live}}},
        {"$group": {"_id": "$user_id"}},
        {"$count": "unique"}
    ]
    live_result = await db.stream_logs.aggregate(live_pipeline).to_list(length=1)
    live_listeners = live_result[0]["unique"] if live_result else 0

    # Premium user count
    premium_users = await db.users.count_documents({"is_premium": True})

    # 30-day timeline
    daily_pipeline = [
        {"$match": {"listened_at": {"$gte": threshold_month}}},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$listened_at"}},
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}},
    ]
    daily = await db.stream_logs.aggregate(daily_pipeline).to_list(length=31)

    return {
        "total_users": total_users,
        "total_artists": total_artists,
        "total_songs": total_songs,
        "total_plays": total_plays,
        "plays_today": plays_today,
        "plays_month": plays_month,
        "live_listeners": live_listeners,
        "premium_users": premium_users,
        "plays_30d": [{"date": d["_id"], "count": d["count"]} for d in daily],
        "as_of": now(),
    }


@api.get("/admin/analytics/songs")
async def admin_analytics_songs(user: dict = Depends(current_user), limit: int = 20):
    """Top songs by total play count (all time). Admin only."""
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    limit = max(1, min(100, limit))
    pipeline = [
        {"$group": {"_id": "$track_id", "plays": {"$sum": 1}, "listeners": {"$addToSet": "$user_id"}}},
        {"$project": {"plays": 1, "unique_listeners": {"$size": "$listeners"}}},
        {"$sort": {"plays": -1}},
        {"$limit": limit},
    ]
    rows = await db.stream_logs.aggregate(pipeline).to_list(length=limit)
    out = []
    for r in rows:
        song = await db.songs.find_one({"song_id": r["_id"]}, {"_id": 0}) if r["_id"] else None
        if not song:
            continue
        out.append({
            "song_id": r["_id"],
            "title": song.get("title", "Unknown"),
            "artist_name": song.get("artist_name", "Unknown"),
            "artist_id": song.get("artist_id"),
            "cover_url": song.get("cover_url"),
            "plays": r["plays"],
            "unique_listeners": r["unique_listeners"],
        })
    return {"items": out}


@api.get("/admin/analytics/artists")
async def admin_analytics_artists(user: dict = Depends(current_user), limit: int = 20):
    """Top artists by total play count (all time). Admin only."""
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    limit = max(1, min(100, limit))
    pipeline = [
        {"$match": {"artist_id": {"$ne": None}}},
        {"$group": {"_id": "$artist_id", "plays": {"$sum": 1}, "listeners": {"$addToSet": "$user_id"}}},
        {"$project": {"plays": 1, "unique_listeners": {"$size": "$listeners"}}},
        {"$sort": {"plays": -1}},
        {"$limit": limit},
    ]
    rows = await db.stream_logs.aggregate(pipeline).to_list(length=limit)
    out = []
    for r in rows:
        artist = await db.users.find_one({"user_id": r["_id"]}, {"_id": 0, "password_hash": 0}) if r["_id"] else None
        if not artist:
            continue
        out.append({
            "artist_id": r["_id"],
            "name": artist.get("name", "Unknown"),
            "email": artist.get("email"),
            "avatar_url": artist.get("avatar_url"),
            "plays": r["plays"],
            "unique_listeners": r["unique_listeners"],
        })
    return {"items": out}


@api.get("/admin/analytics/users")
async def admin_analytics_users(user: dict = Depends(current_user), limit: int = 20):
    """Top users by play activity (last 30 days). Admin only."""
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    limit = max(1, min(100, limit))
    threshold = now() - timedelta(days=30)
    pipeline = [
        {"$match": {"listened_at": {"$gte": threshold}}},
        {"$group": {"_id": "$user_id", "plays": {"$sum": 1}}},
        {"$sort": {"plays": -1}},
        {"$limit": limit},
    ]
    rows = await db.stream_logs.aggregate(pipeline).to_list(length=limit)
    out = []
    for r in rows:
        u = await db.users.find_one({"user_id": r["_id"]}, {"_id": 0, "password_hash": 0}) if r["_id"] else None
        if not u:
            continue
        out.append({
            "user_id": r["_id"],
            "name": u.get("name", "Unknown"),
            "email": u.get("email"),
            "role": u.get("role"),
            "is_premium": bool(u.get("is_premium")),
            "plays_30d": r["plays"],
        })
    return {"items": out}


@api.post("/admin/streak-rewards")
async def admin_create_reward(body: dict = Body(...), user: dict = Depends(current_user)):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    days = int(body.get("days") or 0)
    if days <= 0:
        raise HTTPException(400, "days must be >= 1")
    reward_type = (body.get("type") or "voucher").strip().lower()
    if reward_type not in {"voucher", "premium_days"}:
        raise HTTPException(400, "type must be voucher or premium_days")
    doc = {
        "reward_id": f"rw_{uuid.uuid4().hex[:12]}",
        "days": days,
        "type": reward_type,
        "value": str(body.get("value") or "").strip(),
        "label": (body.get("label") or "").strip() or f"{days}-day streak",
        "description": (body.get("description") or "").strip(),
        # Optional admin-provided redirect URL — surfaces as a "Redeem now"
        # button on the user's streak page when the reward is unlocked AND
        # this reward is still within its 4-day visibility window.
        "redirect_url": (body.get("redirect_url") or "").strip(),
        "enabled": bool(body.get("enabled", True)),
        "created_at": now(),
    }
    await db.streak_rewards.insert_one(doc)
    doc.pop("_id", None)
    return {"ok": True, "reward": doc}


@api.put("/admin/streak-rewards/{reward_id}")
async def admin_update_reward(reward_id: str, body: dict = Body(...), user: dict = Depends(current_user)):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    update = {}
    for k in ("days", "type", "value", "label", "description", "enabled", "redirect_url"):
        if k in body:
            update[k] = body[k]
    if "days" in update:
        update["days"] = int(update["days"] or 0)
        if update["days"] <= 0:
            raise HTTPException(400, "days must be >= 1")
    if "type" in update and update["type"] not in {"voucher", "premium_days"}:
        raise HTTPException(400, "invalid type")
    r = await db.streak_rewards.update_one({"reward_id": reward_id}, {"$set": update})
    if r.matched_count == 0:
        raise HTTPException(404, "Reward not found")
    doc = await db.streak_rewards.find_one({"reward_id": reward_id}, {"_id": 0})
    return {"ok": True, "reward": doc}


@api.delete("/admin/streak-rewards/{reward_id}")
async def admin_delete_reward(reward_id: str, user: dict = Depends(current_user)):
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    r = await db.streak_rewards.delete_one({"reward_id": reward_id})
    if r.deleted_count == 0:
        raise HTTPException(404, "Reward not found")
    return {"ok": True, "deleted": reward_id}




# ──────────────────────────── AdMob rules (admin-configurable) ────────────────────────────
# Frontend AdManager fetches this config at boot and every 5 min. Admin can
# tune when the interstitial fires (time window + skip threshold) without
# needing a new app build.

def _default_admob_config() -> dict:
    return {
        "interstitial_interval_minutes": 20,   # active-usage minutes between interstitials
        "interstitial_per_window": 2,          # max shows per interval
        "skip_threshold": 8,                   # song skips before a skip-triggered interstitial
        "enabled": True,
    }


@api.get("/admob/config")
async def get_admob_config():
    """PUBLIC — frontend AdManager reads this every 5 min to pick up admin changes."""
    doc = await db.app_settings.find_one({"key": "admob_config"}, {"_id": 0}) or {}
    cfg = _default_admob_config()
    cfg.update({k: v for k, v in doc.items() if k != "key"})
    # Coerce types
    cfg["interstitial_interval_minutes"] = max(1, int(cfg.get("interstitial_interval_minutes") or 20))
    cfg["interstitial_per_window"] = max(1, int(cfg.get("interstitial_per_window") or 2))
    cfg["skip_threshold"] = max(1, int(cfg.get("skip_threshold") or 8))
    cfg["enabled"] = bool(cfg.get("enabled", True))
    return cfg




@api.post("/admin/wipe")
async def admin_wipe_data(
    target: str = Form(...),
    user: dict = Depends(current_user),
):
    """Admin-only destructive wipe for specific collections.

    target ∈ {streams, plays, recently_played, tips, withdrawals, notifications, all_users, all_songs, everything}
      - streams           → empty stream_logs + reset songs.streams counter
      - plays             → empty play_events
      - recently_played   → empty recently_played
      - tips              → empty tips collection
      - withdrawals       → empty withdrawals collection
      - notifications     → empty notifications + notification_reads
      - all_users         → delete ALL non-admin users + their data (DANGEROUS)
      - all_songs         → delete ALL songs (DANGEROUS)
      - everything        → factory reset (preserves only the platform admin)
    """
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    out: dict[str, int] = {}
    valid = {"streams", "plays", "recently_played", "tips", "withdrawals",
             "notifications", "all_users", "all_songs", "everything"}
    if target not in valid:
        raise HTTPException(400, f"target must be one of {sorted(valid)}")

    if target in ("streams", "everything"):
        r = await db.stream_logs.delete_many({})
        out["stream_logs"] = r.deleted_count
        await db.songs.update_many({}, {"$set": {"streams": 0, "trending_score": 0}})
    if target in ("plays", "everything"):
        r = await db.play_events.delete_many({})
        out["play_events"] = r.deleted_count
    if target in ("recently_played", "everything"):
        r = await db.recently_played.delete_many({})
        out["recently_played"] = r.deleted_count
    if target in ("tips", "everything"):
        r = await db.tips.delete_many({})
        out["tips"] = r.deleted_count
    if target in ("withdrawals", "everything"):
        r = await db.withdrawals.delete_many({})
        out["withdrawals"] = r.deleted_count
    if target in ("notifications", "everything"):
        r = await db.notifications.delete_many({})
        out["notifications"] = r.deleted_count
        await db.notification_reads.delete_many({})
    if target in ("all_songs", "everything"):
        r = await db.songs.delete_many({})
        out["songs"] = r.deleted_count
        await db.likes.delete_many({})
        await db.playlists.delete_many({})
    if target in ("all_users", "everything"):
        r = await db.users.delete_many({"email": {"$ne": ADMIN_EMAIL}})
        out["users"] = r.deleted_count
        await db.follows.delete_many({})
        # also wipe per-user counters
        await db.likes.delete_many({})
        await db.recently_played.delete_many({})
        await db.tips.delete_many({})
        await db.withdrawals.delete_many({})
        await db.push_tokens.delete_many({})
    return {"ok": True, "target": target, "removed": out}


# ──────────────────────────── dedicated artist + listening hours ────────────────────────────

@api.post("/admin/users/{user_id}/dedicated")
async def admin_set_dedicated(
    user_id: str,
    is_dedicated: bool = Form(...),
    user: dict = Depends(current_user),
):
    """Mark an artist as 'dedicated' — only dedicated artists appear on
    listener profile Top Artists. Listening data still recorded for every
    artist; this flag only controls visibility."""
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    target = await db.users.find_one({"user_id": user_id}, {"_id": 0, "role": 1})
    if not target:
        raise HTTPException(404, "User not found")
    if target.get("role") != "artist":
        raise HTTPException(400, "Target user is not an artist")
    await db.users.update_one({"user_id": user_id}, {"$set": {"is_dedicated_artist": bool(is_dedicated)}})
    return {"ok": True, "is_dedicated_artist": bool(is_dedicated)}


def _period_match(period: str) -> dict:
    if period == "month":
        start = now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        return {"listened_at": {"$gte": start}}
    if period == "week":
        return {"listened_at": {"$gte": now() - timedelta(days=7)}}
    return {}


@api.get("/me/listening-hours")
async def my_listening_hours(
    user: dict = Depends(current_user),
    period: str = "all",
    limit: int = 30,
):
    """Top dedicated artists by hours the current user has listened."""
    match: dict = {"user_id": user["user_id"], "artist_id": {"$ne": None}, **_period_match(period)}
    pipeline = [
        {"$match": match},
        {"$group": {"_id": "$artist_id", "seconds": {"$sum": "$duration_seconds"},
                    "plays": {"$sum": 1}, "last_at": {"$max": "$listened_at"}}},
        {"$sort": {"seconds": -1}},
        {"$limit": min(limit, 100)},
    ]
    rows = await db.stream_logs.aggregate(pipeline, allowDiskUse=False).to_list(100)
    artist_ids = [r["_id"] for r in rows]
    if not artist_ids:
        return {"items": []}
    artists: dict = {}
    async for u in db.users.find(
        {"user_id": {"$in": artist_ids}, "is_dedicated_artist": True},
        {"_id": 0, "password_hash": 0},
    ):
        artists[u["user_id"]] = u
    items = []
    for r in rows:
        a = artists.get(r["_id"])
        if not a:
            continue
        items.append({
            "artist": public_user(a),
            "seconds": int(r["seconds"]),
            "hours": round(r["seconds"] / 3600.0, 2),
            "minutes": round(r["seconds"] / 60.0, 1),
            "plays": r["plays"],
        })
    return {"items": items}


@api.get("/admin/listening-hours")
async def admin_listening_hours(
    period: str = "all",
    limit: int = 50,
    user: dict = Depends(current_user),
):
    """Top artists across ALL listeners (no dedicated filter)."""
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    match: dict = {"artist_id": {"$ne": None}, **_period_match(period)}
    pipeline = [
        {"$match": match},
        {"$group": {"_id": "$artist_id", "seconds": {"$sum": "$duration_seconds"},
                    "plays": {"$sum": 1}, "last_at": {"$max": "$listened_at"}}},
        {"$sort": {"seconds": -1}},
        {"$limit": min(limit, 200)},
    ]
    rows = await db.stream_logs.aggregate(pipeline, allowDiskUse=False).to_list(200)
    ids = [r["_id"] for r in rows]
    artists: dict = {}
    if ids:
        async for u in db.users.find({"user_id": {"$in": ids}}, {"_id": 0, "password_hash": 0}):
            artists[u["user_id"]] = u
    items = []
    for r in rows:
        a = artists.get(r["_id"]) or {}
        items.append({
            "artist_id": r["_id"],
            "artist_name": a.get("name") or "Unknown",
            "is_dedicated_artist": bool(a.get("is_dedicated_artist", False)),
            "seconds": int(r["seconds"]),
            "hours": round(r["seconds"] / 3600.0, 2),
            "plays": r["plays"],
            "last_at": r["last_at"],
        })
    return {"items": items}


@api.get("/admin/listening-hours/artist/{artist_id}")
async def admin_artist_top_listeners(
    artist_id: str,
    period: str = "all",
    limit: int = 50,
    user: dict = Depends(current_user),
):
    """Top listeners for a specific artist."""
    if not _is_admin(user):
        raise HTTPException(403, "Admin only")
    match: dict = {"artist_id": artist_id, **_period_match(period)}
    pipeline = [
        {"$match": match},
        {"$group": {"_id": "$user_id", "seconds": {"$sum": "$duration_seconds"},
                    "plays": {"$sum": 1}, "last_at": {"$max": "$listened_at"}}},
        {"$sort": {"seconds": -1}},
        {"$limit": min(limit, 200)},
    ]
    rows = await db.stream_logs.aggregate(pipeline, allowDiskUse=False).to_list(200)
    ids = [r["_id"] for r in rows]
    users_by_id: dict = {}
    if ids:
        async for u in db.users.find({"user_id": {"$in": ids}}, {"_id": 0, "password_hash": 0}):
            users_by_id[u["user_id"]] = u
    items = []
    for r in rows:
        u = users_by_id.get(r["_id"]) or {}
        items.append({
            "user_id": r["_id"],
            "name": u.get("name") or "Unknown",
            "email": u.get("email") or "",
            "seconds": int(r["seconds"]),
            "hours": round(r["seconds"] / 3600.0, 2),
            "plays": r["plays"],
            "last_at": r["last_at"],
        })
    artist = await db.users.find_one({"user_id": artist_id}, {"_id": 0, "password_hash": 0})
    return {"artist": public_user(artist) if artist else None, "items": items}


# ──────────────────────────── seed ────────────────────────────

SAMPLE_AUDIO = [
    "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-1.mp3",
    "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-2.mp3",
    "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-3.mp3",
    "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-4.mp3",
    "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-5.mp3",
    "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-6.mp3",
    "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-7.mp3",
    "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-8.mp3",
    "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-9.mp3",
    "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-10.mp3",
    "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-11.mp3",
    "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-12.mp3",
]
COVERS = [
    "https://images.unsplash.com/photo-1632478179654-0b8a89119fc5?w=600",
    "https://images.unsplash.com/photo-1671713912667-5947b830235d?w=600",
    "https://images.unsplash.com/photo-1644855640845-ab57a047320e?w=600",
    "https://images.unsplash.com/photo-1540039155733-5bb30b53aa14?w=600",
    "https://images.unsplash.com/photo-1429962714451-bb934ecdc4ec?w=600",
    "https://images.pexels.com/photos/32399568/pexels-photo-32399568.jpeg?w=600",
]
ARTISTS = [
    {"name": "Kairo Wolfe", "avatar": "https://images.unsplash.com/photo-1519326773765-3ae3b02c44cc?w=400", "bio": "Underground hip-hop from Mumbai's late-night corners.", "monthly_listeners": 84200},
    {"name": "Lena Voss", "avatar": "https://images.unsplash.com/photo-1595971294624-80bcf0d7eb24?w=400", "bio": "Indie-electronic. Bedroom producer, big stages.", "monthly_listeners": 56100},
    {"name": "Subway Saints", "avatar": "https://images.pexels.com/photos/14456993/pexels-photo-14456993.jpeg?w=400", "bio": "Lo-fi trio. Recorded on cassette, mixed on instinct.", "monthly_listeners": 31400},
    {"name": "Anaya Roy", "avatar": "https://images.unsplash.com/photo-1595971294624-80bcf0d7eb24?w=400&q=80", "bio": "R&B vocalist. Honey, gravel, and city rain.", "monthly_listeners": 42800},
]
SONG_TITLES = [
    ("Midnight Refrain", "Hip-Hop", "Dark"),
    ("Velvet Smoke", "R&B", "Sensual"),
    ("Pier 7 Sunrise", "Lo-Fi", "Chill"),
    ("Neon Pulse", "EDM", "Energetic"),
    ("Cassette Heart", "Indie", "Nostalgic"),
    ("Wolfe Hour", "Hip-Hop", "Hype"),
    ("Static Garden", "Indie", "Dreamy"),
    ("Brass Dialogue", "Pop", "Uplift"),
    ("Glasshouse", "Rock", "Raw"),
    ("Saraab", "Punjabi", "Romantic"),
    ("Low Tide", "Lo-Fi", "Calm"),
    ("Bombay 3AM", "Hip-Hop", "Reflective"),
]


async def seed_db():
    # ─── Always ensure platform admin + demo user exist ───
    if not await db.users.find_one({"email": ADMIN_EMAIL}):
        await db.users.insert_one({
            "user_id": new_id("user"),
            "email": ADMIN_EMAIL,
            "name": "Musify Admin",
            "password_hash": hash_pwd(ADMIN_DEFAULT_PASSWORD),
            "role": "admin",
            "is_premium": True,
            "avatar": None, "bio": "Platform admin", "upi_id": None,
            "followers": 0, "monthly_listeners": 0,
            "created_at": now(),
        })
    if not await db.users.find_one({"email": "demo@musify.app"}):
        await db.users.insert_one({
            "user_id": new_id("user"),
            "email": "demo@musify.app",
            "name": "Demo Listener",
            "password_hash": hash_pwd("Demo@123"),
            "role": "user",
            "is_premium": False,
            "avatar": None, "bio": "", "upi_id": None,
            "followers": 0, "monthly_listeners": 0,
            "created_at": now(),
        })
    # ─── Dummy songs / dummy artist accounts disabled per product owner ───
    # Existing seed data is wiped automatically by _purge_dummy_data() at startup.
    log.info("seed: admin+demo users ensured; dummy songs/artists not seeded")


async def _purge_dummy_data():
    """One-time purge of all dummy songs/artist accounts. Runs every startup —
    cheap if nothing matches. Leaves admin+demo users and any real uploads intact.
    """
    try:
        # 1) Wipe songs with audio_kind == 'url' (only the SoundHelix-seeded ones).
        seed_songs = await db.songs.find({"audio_kind": "url"}, {"_id": 0, "song_id": 1}).to_list(1000)
        seed_ids = [s["song_id"] for s in seed_songs]
        if seed_ids:
            await db.songs.delete_many({"song_id": {"$in": seed_ids}})
            await db.likes.delete_many({"song_id": {"$in": seed_ids}})
            await db.recently_played.delete_many({"song_id": {"$in": seed_ids}})
            await db.play_events.delete_many({"song_id": {"$in": seed_ids}})
            await db.playlists.update_many({}, {"$pull": {"song_ids": {"$in": seed_ids}}})
            log.info("purged %d dummy songs", len(seed_ids))
        # 2) Wipe the seed artist accounts (artist1..4@musify.app). Only if they have
        # ZERO real songs remaining (so we don't kill an artist who actually uploaded).
        seed_emails = [f"artist{i}@musify.app" for i in range(1, 5)]
        seed_artists = await db.users.find(
            {"email": {"$in": seed_emails}}, {"_id": 0, "user_id": 1, "email": 1}
        ).to_list(20)
        purged_artists = 0
        for a in seed_artists:
            remaining = await db.songs.count_documents({"artist_id": a["user_id"]})
            if remaining == 0:
                await db.users.delete_one({"user_id": a["user_id"]})
                await db.follows.delete_many({
                    "$or": [{"artist_id": a["user_id"]}, {"follower_id": a["user_id"]}]
                })
                purged_artists += 1
        if purged_artists:
            log.info("purged %d dummy artist accounts", purged_artists)
        # 3) Drop the demo playlists that referenced wiped songs (now empty)
        await db.playlists.delete_many({
            "owner_id": {"$exists": True},
            "name": {"$in": ["Late Night Drives", "Underground Heat"]},
        })
    except Exception as e:
        log.warning("_purge_dummy_data failed: %s", e)


async def _UNUSED_seed_songs_legacy():
    """Legacy dummy-song seeder. Kept for reference only — never called."""
    artist_ids: list[str] = []
    for i, a in enumerate(ARTISTS):
        email = f"artist{i+1}@musify.app"
        existing = await db.users.find_one({"email": email})
        if existing:
            artist_ids.append(existing["user_id"])
            continue
        uid = new_id("user")
        await db.users.insert_one({
            "user_id": uid,
            "email": email,
            "name": a["name"],
            "password_hash": hash_pwd("Artist@123"),
            "role": "artist",
            "is_premium": False,
            "avatar": a["avatar"], "bio": a["bio"], "upi_id": f"{a['name'].lower().replace(' ','')}@upi",
            "followers": a["monthly_listeners"] // 4,
            "monthly_listeners": a["monthly_listeners"],
            "created_at": now(),
        })
        artist_ids.append(uid)

    # Songs
    import random
    for i, (title, genre, mood) in enumerate(SONG_TITLES):
        artist_idx = i % len(artist_ids)
        artist_id = artist_ids[artist_idx]
        artist_name = ARTISTS[artist_idx]["name"]
        streams = random.randint(8000, 250000)
        doc = {
            "song_id": new_id("song"),
            "title": title,
            "artist_id": artist_id,
            "artist_name": artist_name,
            "genre": genre,
            "mood": mood,
            "language": "Hindi" if genre == "Punjabi" else "English",
            "explicit": random.random() < 0.3,
            "credits": f"Written by {artist_name}",
            "lyrics": f"[Verse 1]\nThe city hums under {title.lower()},\nA pulse beneath the neon haze.\n\n[Chorus]\nWe ride the dark, we chase the dawn,\nUntil the streetlights fade away.",
            "cover_url": COVERS[i % len(COVERS)],
            "duration_sec": random.randint(150, 280),
            "audio_kind": "url",
            "audio_url": SAMPLE_AUDIO[i % len(SAMPLE_AUDIO)],
            "stream_url": SAMPLE_AUDIO[i % len(SAMPLE_AUDIO)],
            "streams": streams,
            "trending_score": streams + random.randint(0, 1000),
            "is_published": True,
            "is_featured": i < 3,
            "created_at": now() - timedelta(days=random.randint(0, 60)),
        }
        await db.songs.insert_one(doc)

    # Sample playlists owned by demo user
    demo = await db.users.find_one({"email": "demo@musify.app"})
    songs_all = await db.songs.find({}, {"_id": 0, "song_id": 1}).to_list(20)
    if demo and songs_all:
        await db.playlists.insert_one({
            "playlist_id": new_id("pl"),
            "name": "Late Night Drives",
            "description": "Underground beats for empty highways.",
            "is_public": True,
            "owner_id": demo["user_id"],
            "owner_name": demo["name"],
            "song_ids": [s["song_id"] for s in songs_all[:6]],
            "cover": COVERS[0],
            "created_at": now(),
            "updated_at": now(),
        })
        await db.playlists.insert_one({
            "playlist_id": new_id("pl"),
            "name": "Underground Heat",
            "description": "Fresh from the city's basements.",
            "is_public": True,
            "owner_id": demo["user_id"],
            "owner_name": demo["name"],
            "song_ids": [s["song_id"] for s in songs_all[3:10]],
            "cover": COVERS[2],
            "created_at": now(),
            "updated_at": now(),
        })

    log.info("seed: complete")


@app.on_event("startup")
async def on_startup():
    # Indexes
    await db.users.create_index("email", unique=True)
    await db.users.create_index("user_id", unique=True)
    await db.user_sessions.create_index("session_token", unique=True)
    await db.user_sessions.create_index("expires_at", expireAfterSeconds=0)
    await db.songs.create_index("song_id", unique=True)
    await db.songs.create_index("artist_id")
    await db.songs.create_index("genre")
    await db.songs.create_index("title")
    await db.play_events.create_index([("user_id", 1), ("played_at", -1)])
    await db.recently_played.create_index([("user_id", 1), ("played_at", -1)])
    await db.likes.create_index([("user_id", 1), ("song_id", 1)], unique=True)
    await db.playlists.create_index("owner_id")
    await db.push_tokens.create_index([("user_id", 1), ("platform", 1)], unique=True)
    await db.follows.create_index([("follower_id", 1), ("artist_id", 1)], unique=True)
    await db.follows.create_index("artist_id")
    await db.stream_logs.create_index([("user_id", 1), ("listened_at", -1)])
    # Perf indexes for listening-hours aggregations (≤100k DAU scale).
    await db.stream_logs.create_index([("artist_id", 1), ("listened_at", -1)])
    await db.stream_logs.create_index([("user_id", 1), ("artist_id", 1)])
    await db.play_events.create_index([("user_id", 1), ("played_at", -1)])
    await db.play_events.create_index([("song_id", 1), ("played_at", -1)])
    await db.songs.create_index([("artist_id", 1), ("created_at", -1)])
    await db.songs.create_index([("genre", 1), ("streams", -1)])
    # Play Billing unique-token index (idempotent — no-op if exists).
    await play_billing.create_indexes(db)
    await db.songs.create_index([("is_featured", -1), ("trending_score", -1)])
    await db.recently_played.create_index([("user_id", 1), ("played_at", -1)])
    await db.users.create_index([("role", 1), ("is_dedicated_artist", 1)])
    await db.users.create_index([("email", 1)], unique=True)
    await db.notifications.create_index([("queued_at", -1)])
    await db.notifications.create_index("target_user_id")
    await db.subscription_plans.create_index("plan_id", unique=True)
    # Streak system
    await db.streaks.create_index("user_id", unique=True)
    await db.streak_rewards.create_index("reward_id", unique=True)
    await db.streak_rewards.create_index([("enabled", 1), ("days", 1)])
    # Curated trending fast lookup
    await db.songs.create_index([("is_published", 1), ("is_trending", 1), ("trending_score", -1)])
    # Backs /api/home + /api/songs/trending + /api/songs/new-releases, whose
    # sorts previously had no matching index and fell back to an in-memory
    # collection scan on every Home load.
    await db.songs.create_index([("is_published", 1), ("streams", -1)])
    await db.songs.create_index([("is_published", 1), ("created_at", -1)])
    # Ads — multi-ad rotation
    await db.ads.create_index("ad_id", unique=True)
    await db.ads.create_index([("enabled", 1), ("sequence", 1)])
    # Premium submissions & payment tracking
    await db.premium_submissions.create_index([("user_id", 1), ("submitted_at", -1)])
    await db.premium_submissions.create_index([("status", 1), ("submitted_at", -1)])
    await db.app_settings.create_index("key", unique=True)
    # stream_cache — resolver URL cache (survives redeploys). TTL index on
    # `expires_at` (BSON datetime) auto-purges expired signed URLs so the
    # collection never grows unbounded. `key` unique index backs upserts.
    await db.stream_cache.create_index("key", unique=True)
    try:
        await db.stream_cache.create_index("expires_at", expireAfterSeconds=0)
    except Exception as _e:
        log.warning("stream_cache TTL index create failed: %s", _e)
    # Best-effort: migrate any legacy expires_at unix numbers → BSON date
    # so the TTL index above can fire on them.
    await stream_resolver.migrate_stream_cache_expires_at(db)
    await seed_db()
    # NOTE: `_purge_dummy_data()` used to run here to wipe the SoundHelix
    # seed songs. That's a destructive delete on every startup which is
    # incompatible with production deploys (and could nuke real records
    # if seed shape ever changes). The purge is now an OPT-IN admin-only
    # endpoint — see POST /api/admin/system/purge-dummy-data.
    await _seed_default_plans()
    # Idempotently enforce admin password on each startup so deploy can rotate it
    await db.users.update_one(
        {"email": ADMIN_EMAIL},
        {"$set": {"password_hash": hash_pwd(ADMIN_DEFAULT_PASSWORD), "role": "admin", "is_premium": True}},
    )
    # Start the streams flusher worker (background)
    asyncio.create_task(_flush_stream_buffer())
    # Daily yt-dlp self-upgrade — keeps the extractor in sync with YouTube
    # signature-cipher updates without a redeploy. See _auto_update_yt_dlp_loop.
    asyncio.create_task(_auto_update_yt_dlp_loop())


async def _auto_update_yt_dlp_loop() -> None:
    """Every 24h, upgrade yt-dlp to the latest nightly build in-place."""
    import subprocess
    while True:
        try:
            # Wait a minute after startup so boot isn't blocked.
            await asyncio.sleep(60)
            loop = asyncio.get_running_loop()
            def _upgrade() -> tuple[int, str]:
                res = subprocess.run(
                    ["pip", "install", "-U", "--pre", "--quiet", "yt-dlp[default]"],
                    capture_output=True, text=True, timeout=120,
                )
                return res.returncode, (res.stderr or res.stdout or "").strip()
            rc, msg = await loop.run_in_executor(None, _upgrade)
            if rc == 0:
                log.info("yt-dlp nightly self-upgrade OK")
            else:
                log.warning("yt-dlp self-upgrade failed rc=%s msg=%s", rc, msg[:200])
        except Exception as e:
            log.warning("yt-dlp self-upgrade loop error: %s", e)
        # Next tick in 24h.
        await asyncio.sleep(24 * 60 * 60)


async def _seed_default_plans():
    """Seed three default plans (Free, Premium Monthly, Premium Yearly) once."""
    if await db.subscription_plans.count_documents({}) > 0:
        return
    defaults = [
        {"plan_id": "plan_free", "name": "Free", "price": 0, "currency": "INR",
         "period": "monthly", "features": ["Ad-supported", "Standard quality", "Skip 6 times/hour"],
         "is_active": True, "sort_order": 1, "created_at": now()},
        {"plan_id": "plan_premium_m", "name": "Premium Monthly", "price": 119, "currency": "INR",
         "period": "monthly", "features": ["No ads", "Lossless audio", "Unlimited skips", "Offline downloads"],
         "is_active": True, "sort_order": 2, "created_at": now()},
        {"plan_id": "plan_premium_y", "name": "Premium Yearly", "price": 999, "currency": "INR",
         "period": "yearly", "features": ["Everything in Monthly", "Save ₹429/year", "Family plan eligible"],
         "is_active": True, "sort_order": 3, "created_at": now()},
    ]
    try:
        await db.subscription_plans.insert_many(defaults)
        log.info("seeded %d default plans", len(defaults))
    except Exception as e:
        log.warning("plan seed failed: %s", e)


app.include_router(api)

# ── Google Play Billing (subscriptions) ──
# Router lives in play_billing.py; wires against this app's DB + JWT auth.
app.include_router(play_billing.build_router(db=db, current_user=current_user))

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("shutdown")
async def on_shutdown():
    client.close()
