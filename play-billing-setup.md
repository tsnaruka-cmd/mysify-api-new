# Play Billing setup — action items after receiving service-account JSON

## 1. Drop the service-account JSON on the server

Place the downloaded JSON key at:

    /app/backend/play-service-account.json

(Or set `GOOGLE_APPLICATION_CREDENTIALS` env var to a different path and
`GOOGLE_PLAY_PACKAGE` to the Play Console package name.)

The backend reads this file lazily on the first `/api/premium/verify`
call, so no restart is required for the file to take effect — but a
restart doesn't hurt.

    sudo supervisorctl restart backend

## 2. Verify from the app

1. Publish the app from Emergent → generate a fresh Android build.
2. Install from the Play internal-test track on a device signed in as a
   Google account that's on the licence-tester list.
3. Open the app → Profile → Go Premium → tap **"Subscribe with Google
   Play"**. The Play Billing sheet should open with the Mysify Premium
   Monthly plan.
4. Complete the purchase (licence testers see a "TEST" watermark).
5. Confirm on the backend:
   ```
   curl -H "Authorization: Bearer <jwt>" \
        https://<your-domain>/api/premium/status
   ```
   Expected: `{ "is_premium": true, "expires_at": "<ISO>" }`

## 3. What each env var means

| Variable                          | Default                                             |
| --------------------------------- | --------------------------------------------------- |
| `GOOGLE_APPLICATION_CREDENTIALS` | `/app/backend/play-service-account.json`            |
| `GOOGLE_PLAY_PACKAGE`             | `app.emergent.artisthubmusic26fa4e6c6`             |
| `GOOGLE_PLAY_PRODUCT`             | `mysify_premium_monthly`                            |
| `GOOGLE_PLAY_BASE_PLAN`           | `p1m`                                               |

## 4. Renewals / cancellations

For MVP we grant `is_premium` on purchase and store `premium_until` from
Google's `expiryTime`. Renewals will re-hit `/api/premium/verify` on the
next app-open (paywall calls verify again if the user isn't premium yet).

For real-time renewal/cancel handling, wire up Google Real-Time Developer
Notifications later — see the top of `play_billing.py`.

## 5. Fallback while credentials are missing

Until the JSON file is in place, `/api/premium/verify` returns HTTP 503
with a clear message. The paywall UI still shows the "Subscribe with
Google Play" button on native Android builds — but attempting to
subscribe will surface the 503 error. Once you drop the file in, the same
button just starts working (no code changes needed).
