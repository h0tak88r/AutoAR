# Dashboard Authentication

When the AutoAR HTTP API is exposed on the public internet, you should enable authentication so only authorized users can access the dashboard and API.

AutoAR uses a native Go-based authentication system with JWT (JSON Web Tokens) and DB-backed users with two roles: **admin** (full access) and **viewer** (read-only).

## Enable Authentication

Either set the `DASHBOARD_USER` and `DASHBOARD_PASSWORD` environment variables (they seed the first admin), or create the first user in **Settings ▸ Users**:

```env
DASHBOARD_USER=admin
DASHBOARD_PASSWORD=your_strong_password_here
```

On boot, if the users table is empty and the env pair is set, that account is created as the first **admin** (bcrypt-hashed). From then on manage accounts in Settings ▸ Users; the env pair is only a seed and can be removed.

If no users exist and the env pair is **not** set, the dashboard runs without login ("Insecure Mode"), which is only for local development — see [Bind safety](#bind-safety).

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DASHBOARD_USER` | For the seed admin | Username of the initial admin, seeded into the users table on boot when it is empty. |
| `DASHBOARD_PASSWORD` | For the seed admin | Password for the seeded admin. 8–72 bytes (bcrypt limit). A longer value can't be seeded: the server logs an error and stays in legacy env-login mode until you shorten it. |
| `AUTOAR_JWT_SECRET` | Recommended | HS256 signing secret, **at least 32 bytes** (e.g. `openssl rand -hex 32`). A shorter value is refused (logged as an error) and the DB secret is used instead. If unset, a random 32-byte secret is generated and stored in the `settings` table (`local_auth_jwt_secret`) so tokens survive restarts — which also means **anyone holding a DB backup can mint admin tokens**. Setting `AUTOAR_JWT_SECRET` keeps the signing key out of the database and its backups. It is never derived from a password. Changing it signs everyone out. |
| `AUTOAR_TRUSTED_PROXIES` | Behind a reverse proxy | Comma-separated IPs/CIDRs of your reverse proxy (e.g. `172.18.0.0/16` for Traefik on a Docker network). Only then is `X-Forwarded-For` trusted. Without it every client appears as the proxy's IP, so the audit log shows the proxy IP and login throttling can't tell clients apart. Never list ranges that untrusted clients can connect from. |
| `AUTOAR_API_AUTH_DISABLED` | Optional | `true` turns authentication off entirely, even when users exist (debugging on a trusted, isolated network only). |
| `CORS_ALLOWED_ORIGINS` | Optional | Comma-separated list of allowed origins. Defaults to `*` if unset. |

## How it Works

1. **Login:** The browser sends a POST request to `/api/auth/login` with your credentials.
2. **Token Issue:** If valid, the server returns a signed HS256 JWT valid for 24 hours.
3. **Authorization:** Every subsequent API request includes the `Authorization: Bearer <token>` header. A `?token=` query parameter is accepted **only** on `GET` for the scan log stream (`/api/scans/:id/logs/stream`) and result downloads (`/api/scans/:id/results/download`, `/scan/:scan_id/download`), where a header can't be set.
4. **Validation:** The server checks the signature, expiry and issuer, then loads the user from the DB on every request — a disabled or deleted user, or a role change, takes effect immediately.

### Roles

- Only the exact role `admin` may change anything or open admin-only data (users, audit log, platform accounts and secret reveals, monitors, R2 browser, report templates, system metrics, scope debug, `/metrics`).
- Every other role is **read-only**. A viewer can still sign out and change their own password (Settings ▸ Users is the only Settings tab a viewer sees).
- There is always at least one enabled admin: the first user is created as an admin whatever role was requested, and demoting, disabling or deleting the last enabled admin is refused.
- Adding the first DB user while running on the `DASHBOARD_USER`/`DASHBOARD_PASSWORD` pair migrates that env admin into the users table first, so it isn't locked out.
- Usernames: letters, digits, `.`, `_`, `@`, `-` (1–64). Passwords: 8–72 bytes.

### Sessions and sign-out

- **Sign out** ends all sessions of *your* account only (every device). Other users are unaffected.
- Changing your password ends your other sessions; the dashboard receives a fresh token and stays signed in.
- An admin resetting a password, disabling a user or changing their role ends that user's sessions.
- Revocation is stored per user (`users.tokens_valid_after`, unix seconds) and survives restarts. Precision is one second: a token issued in the same second as the revocation stays valid.
- Tokens obtained while no login was configured ("open" mode) stop working as soon as authentication is turned on.

### Brute-force protection

- Failed logins are counted per **(username, client IP)**: after 5 failures that pair is locked for 30 s, doubling per further failure up to 15 minutes. One client hammering one account can't lock out other accounts.
- Wrong *current password* attempts on `/api/auth/change-password` are throttled the same way per user, and audited.
- Login and change-password bodies are capped at 8 KB; usernames from failed logins are stored in the audit log truncated to 64 characters.
- An unknown username costs the same bcrypt work as a real one, so response timing doesn't reveal which usernames exist.

### Pre-login configuration

`GET /api/config` is public because the login screen needs it, but while authentication is enforced a request without a valid token only receives `{version, auth_enabled, auth_provider}`. The full (still secret-free) configuration requires a session; the dashboard re-fetches it after sign-in.

### Fail closed

The users table is read at boot (whichever of `DB_HOST` / `DATABASE_URL` configures the database). If it can't be read — e.g. the database isn't up yet — authentication stays **enforced** and logins return `503` until the database is reachable; the server re-checks every 30 seconds, so no restart is needed. It never falls back to "no users → open access" or to the env password.

## Bind safety

The server refuses to start on a non-loopback `API_HOST` (e.g. `0.0.0.0`) when no login is configured — no DB users and no env pair. The check runs after the database is read, so users created in Settings count even if the env pair was removed. Fix it by setting `DASHBOARD_USER`/`DASHBOARD_PASSWORD`, or bind to `127.0.0.1` and add users in Settings ▸ Users. `AUTOAR_API_AUTH_DISABLED=true` overrides the check (no authentication at all).

## Audit log

Admins can read the activity log in Settings ▸ Audit. It records sign-ins (and failures), sign-outs, password changes, user changes (which fields changed), settings saves (the setting **keys** changed, never values), platform-account saves/toggles/deletes, and every secret reveal (the key or account name only, never the value).

## Local Development

For local use, you can leave the auth variables unset and bind to `127.0.0.1`. The dashboard will detect this and bypass the login screen.
