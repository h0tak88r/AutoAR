# Dashboard authentication (Supabase)

When the AutoAR HTTP API is exposed on the public internet, enable JWT verification so only signed-in users can call `/api/*`, `/scan/*`, `/keyhack/*`, `/internal/*`, `/metrics`, `/docs`, and `GET /scans`.

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SUPABASE_URL` | Yes (for login UI + asymmetric JWTs) | Project URL, e.g. `https://xxxx.supabase.co`. Used to fetch **JWKS** at `{SUPABASE_URL}/auth/v1/.well-known/jwks.json` for **RS256** / **ES256** access tokens (Supabase “new JWT signing keys”). |
| `SUPABASE_JWT_SECRET` | For **HS256** (legacy) | **JWT Secret** from Supabase → Project Settings → API. Used to verify **HS256** tokens. If the project only issues **ES256/RS256** keys, verification is still done via **JWKS**; keep this set if you also rely on legacy symmetric signing. |
| `SUPABASE_ANON_KEY` | Yes (for login UI) | **anon** / **publishable** key from Supabase → Settings → API. Safe to expose to the browser via `/api/config`. **Never** put the `service_role` / `sb_secret_*` key here. |
| `SUPABASE_SECRET_KEY` | Server-only | Privileged key for server-side Supabase APIs if you add them later — **never** expose to the UI or `/api/config`. |
| `CORS_ALLOWED_ORIGINS` | If UI is on another origin | Comma-separated list, e.g. `https://dash.example.com`. If unset, `Access-Control-Allow-Origin: *` is used (development only). |

## Supabase project setup

1. Enable **Email** provider (or another provider) under Authentication → Providers.
2. Create a user under **Authentication → Users** (or enable sign-ups).
3. Copy **JWT Secret** (if using legacy HS256), **Project URL**, and **anon public** key into your server environment.

## Behaviour

- `GET /api/config` stays **public** so the SPA can read `auth_enabled` and Supabase URL/key before login.
- `GET /health` stays **public** for uptime checks.
- The UI loads `@supabase/supabase-js` from CDN, signs in with email/password, and sends `Authorization: Bearer <access_token>` on API calls.
- The Go API verifies access tokens as follows:
  - **HS256:** HMAC with `SUPABASE_JWT_SECRET` (optionally after base64-decoding the secret, matching Supabase’s storage format).
  - **RS256 / ES256:** asymmetric keys loaded from **JWKS** at `{SUPABASE_URL}/auth/v1/.well-known/jwks.json` (required for projects using Supabase’s new signing keys).

If neither `SUPABASE_JWT_SECRET` nor `SUPABASE_URL` is set, protected routes do not enforce JWT (local development only).

## Local development

Leave `SUPABASE_JWT_SECRET` and `SUPABASE_URL` unset: the dashboard can run without a login gate (API auth middleware is a no-op).
