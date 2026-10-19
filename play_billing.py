"""Google Play Billing verification for Mysify.

Verifies subscription purchase tokens with the Google Play Developer API
and grants premium entitlement in MongoDB. This module is a self-contained
router mounted onto the FastAPI app in `server.py`.

Env vars required in production:
    GOOGLE_APPLICATION_CREDENTIALS  Path to service-account JSON on disk
                                    (see docs/play_billing_setup.md).
    GOOGLE_PLAY_PACKAGE             Android package id (matches Play Console).

If the service-account file is missing, `/api/premium/verify` returns 503
with a clear error — this lets the app ship the paywall UI even before the
credentials are in place, and every other route (auth, playback, admin) is
unaffected.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel

log = logging.getLogger("play_billing")

# ── Config ─────────────────────────────────────────────
PRODUCT_ID = os.environ.get("GOOGLE_PLAY_PRODUCT", "mysify_premium_monthly")
BASE_PLAN_ID = os.environ.get("GOOGLE_PLAY_BASE_PLAN", "monthly-59")
PACKAGE_NAME = os.environ.get("GOOGLE_PLAY_PACKAGE", "app.emergent.artisthubmusic26fa4e6c6")
CREDENTIALS_PATH = os.environ.get(
    "GOOGLE_APPLICATION_CREDENTIALS",
    "/app/backend/play-service-account.json",
)
SCOPES = ["https://www.googleapis.com/auth/androidpublisher"]

# ── Lazy Google client (only initialised on first call, so missing creds
# don't crash server startup) ─────────────────────────────
_google_session = None
_google_error: Optional[str] = None


def _get_google_session():
    """Build (once) an AuthorizedSession for the Play Developer API.

    Returns None + sets `_google_error` if credentials aren't available.
    """
    global _google_session, _google_error
    if _google_session is not None:
        return _google_session
    if _google_error is not None:
        return None
    if not os.path.exists(CREDENTIALS_PATH):
        _google_error = (
            f"Google service-account JSON not found at {CREDENTIALS_PATH}. "
            "Play Billing verification is disabled until the file is provided."
        )
        log.warning(_google_error)
        return None
    try:
        from google.auth.transport.requests import AuthorizedSession
        from google.oauth2 import service_account

        creds = service_account.Credentials.from_service_account_file(
            CREDENTIALS_PATH, scopes=SCOPES
        )
        _google_session = AuthorizedSession(creds)
        log.info("Play Billing verifier initialised (product=%s, base=%s)", PRODUCT_ID, BASE_PLAN_ID)
        return _google_session
    except Exception as e:  # pragma: no cover — surfaces at first purchase
        _google_error = f"Failed to load service account: {e}"
        log.error(_google_error)
        return None


def _entitlement(resource: dict) -> tuple[bool, Optional[datetime]]:
    """Given the subscriptionsv2.get JSON, decide if user is entitled."""
    state = resource.get("subscriptionState")
    active_states = {"SUBSCRIPTION_STATE_ACTIVE", "SUBSCRIPTION_STATE_IN_GRACE_PERIOD"}
    expiry: Optional[datetime] = None
    matched_plan = False
    for item in resource.get("lineItems", []):
        if item.get("productId") != PRODUCT_ID:
            continue
        raw_expiry = item.get("expiryTime")
        if raw_expiry:
            expiry = datetime.fromisoformat(raw_expiry.replace("Z", "+00:00"))
        offer = item.get("offerDetails") or {}
        if offer.get("basePlanId") == BASE_PLAN_ID:
            matched_plan = True
    active = (
        matched_plan
        and state in active_states
        and expiry is not None
        and expiry > datetime.now(timezone.utc)
    )
    return active, expiry


class VerifyBody(BaseModel):
    product_id: str
    base_plan_id: str
    purchase_token: str


def build_router(*, db, current_user) -> APIRouter:
    """Constructs the /api/premium router with the app's DB + auth wired in."""
    router = APIRouter(prefix="/api/premium", tags=["premium"])

    async def _verify_google(token: str) -> dict:
        session = _get_google_session()
        if session is None:
            raise HTTPException(
                status_code=503,
                detail=(
                    _google_error
                    or "Google Play verification is not configured on the server."
                ),
            )
        url = (
            "https://androidpublisher.googleapis.com/androidpublisher/v3/"
            f"applications/{PACKAGE_NAME}/purchases/subscriptionsv2/tokens/{token}"
        )
        resp = session.get(url, timeout=15)
        if resp.status_code != 200:
            log.warning("Google verify HTTP %s: %s", resp.status_code, resp.text[:400])
            raise HTTPException(status_code=400, detail="Purchase could not be verified with Google Play")
        try:
            return resp.json()
        except Exception:
            raise HTTPException(status_code=502, detail="Malformed response from Google Play")

    async def _acknowledge(token: str) -> None:
        session = _get_google_session()
        if session is None:
            return
        url = (
            "https://androidpublisher.googleapis.com/androidpublisher/v3/"
            f"applications/{PACKAGE_NAME}/purchases/subscriptions/"
            f"{PRODUCT_ID}/tokens/{token}:acknowledge"
        )
        try:
            r = session.post(url, json={}, timeout=15)
            if r.status_code not in (200, 204):
                log.warning("acknowledge failed %s: %s", r.status_code, r.text[:400])
        except Exception as e:
            log.warning("acknowledge exception: %s", e)

    @router.post("/verify")
    async def verify_purchase(body: VerifyBody, user: dict = Depends(current_user)):
        if body.product_id != PRODUCT_ID or body.base_plan_id != BASE_PLAN_ID:
            raise HTTPException(400, "Unexpected product or base plan")
        if not body.purchase_token or len(body.purchase_token) > 4096:
            raise HTTPException(400, "Invalid purchase token")

        resource = await _verify_google(body.purchase_token)

        # Prevent a token from being attached to multiple accounts.
        owner = await db.premium_purchases.find_one({"purchase_token": body.purchase_token})
        if owner and owner.get("user_id") != user["user_id"]:
            raise HTTPException(409, "This purchase belongs to a different account")

        active, expiry = _entitlement(resource)
        if not active:
            raise HTTPException(
                status_code=402,
                detail=f"Subscription is not active (state={resource.get('subscriptionState')})",
            )

        ts = datetime.now(timezone.utc)
        await db.premium_purchases.update_one(
            {"purchase_token": body.purchase_token},
            {
                "$set": {
                    "user_id": user["user_id"],
                    "product_id": PRODUCT_ID,
                    "base_plan_id": BASE_PLAN_ID,
                    "expiry_time": expiry,
                    "google_state": resource.get("subscriptionState"),
                    "updated_at": ts,
                },
                "$setOnInsert": {"created_at": ts},
            },
            upsert=True,
        )
        await db.users.update_one(
            {"user_id": user["user_id"]},
            {
                "$set": {
                    "is_premium": True,
                    "has_had_premium": True,
                    "premium_until": expiry,
                    "premium_plan": "monthly",
                    "premium_purchase_token": body.purchase_token,
                    "premium_updated_at": ts,
                }
            },
        )

        # Acknowledge (fire-and-forget style — logs on failure). Renewals
        # don't need this; only the initial purchase.
        if resource.get("acknowledgementState") == "ACKNOWLEDGEMENT_STATE_PENDING":
            await _acknowledge(body.purchase_token)

        return {
            "ok": True,
            "is_premium": True,
            "expires_at": expiry.isoformat() if expiry else None,
        }

    @router.get("/status")
    async def premium_status(user: dict = Depends(current_user)):
        u = await db.users.find_one(
            {"user_id": user["user_id"]},
            {"is_premium": 1, "premium_until": 1, "premium_plan": 1},
        )
        expiry = (u or {}).get("premium_until")
        # Handle tz-naive expiry from older admin grants.
        if isinstance(expiry, datetime) and expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        active = bool(
            u
            and u.get("is_premium")
            and (expiry is None or expiry > datetime.now(timezone.utc))
        )
        return {
            "is_premium": active,
            "expires_at": expiry.isoformat() if isinstance(expiry, datetime) else None,
            "plan": (u or {}).get("premium_plan"),
            "product_id": PRODUCT_ID,
            "base_plan_id": BASE_PLAN_ID,
        }

    return router


async def create_indexes(db) -> None:
    """Called from server startup — ensures the token uniqueness index."""
    try:
        await db.premium_purchases.create_index("purchase_token", unique=True)
    except Exception as e:  # index conflicts are non-fatal
        log.warning("premium_purchases index setup: %s", e)
