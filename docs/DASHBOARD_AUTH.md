# Dashboard authentication (Supabase)

When the AutoAR HTTP API is exposed on the public internet, enable JWT verification so only signed-in users can call `/api/*`, `/scan/*`, `/keyhack/*`, `/internal/*`, `/metrics`, `/docs`, and `GET /scans`.

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SUPABASE_JWT_SECRET` | For production | **JWT Secret** from Supabase → Project Settings → API (same value used to sign user JWTs). If unset, the API does **not** require auth (local development). |
| `SUPABASE_URL` | Yes (for login UI) | Project URL, e.g. `https://xxxx.supabase.co` |
| `SUPABASE_ANON_KEY` | Yes (for login UI) | **anon** / **public** key from Supabase → Settings → API. Safe to expose to the browser. **Never** put the `service_role` key here. |
| `CORS_ALLOWED_ORIGINS` | If UI is on another origin | Comma-separated list, e.g. `https://dash.example.com`. If unset, `Access-Control-Allow-Origin: *` is used (development only). |

## Supabase project setup

1. Enable **Email** provider (or another provider) under Authentication → Providers.
2. Create a user under **Authentication → Users** (or enable sign-ups).
3. Copy **JWT Secret**, **Project URL**, and **anon public** key into your server environment.

## Behaviour

- `GET /api/config` stays **public** so the SPA can read `auth_enabled` and Supabase URL/key before login.
- `GET /health` stays **public** for uptime checks.
- The UI loads `@supabase/supabase-js` from CDN, signs in with email/password, and sends `Authorization: Bearer <access_token>` on API calls.
- The Go API verifies the HS256 signature using `SUPABASE_JWT_SECRET`.

## Local development

Leave `SUPABASE_JWT_SECRET` unset: the dashboard works without a login panel.
