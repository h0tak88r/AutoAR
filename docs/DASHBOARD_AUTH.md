# Dashboard Authentication

When the AutoAR HTTP API is exposed on the public internet, you should enable authentication so only authorized users can access the dashboard and API.

AutoAR uses a native Go-based authentication system with JWT (JSON Web Tokens).

## Enable Authentication

To enable authentication, simply set the `DASHBOARD_USER` and `DASHBOARD_PASSWORD` environment variables in your `.env` file.

```env
DASHBOARD_USER=admin
DASHBOARD_PASSWORD=your_strong_password_here
```

If these variables are **not** set, the dashboard will operate in "Insecure Mode" (no login required), which is recommended only for local development.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DASHBOARD_USER` | Yes (for auth) | The username required to log in. |
| `DASHBOARD_PASSWORD` | Yes (for auth) | The password required to log in. |
| `AUTOAR_JWT_SECRET` | Optional | Custom secret key for signing JWTs. If unset, it's derived from `DASHBOARD_PASSWORD`. |
| `AUTOAR_API_AUTH_DISABLED` | Optional | Set to `true` to explicitly disable auth even if credentials are set (useful for debugging). |
| `CORS_ALLOWED_ORIGINS` | Optional | Comma-separated list of allowed origins. Defaults to `*` if unset. |

## How it Works

1. **Login:** The browser sends a POST request to `/api/auth/login` with your credentials.
2. **Token Issue:** If valid, the server returns a signed HS256 JWT valid for 24 hours.
3. **Authorization:** Every subsequent API request includes the `Authorization: Bearer <token>` header.
4. **Validation:** The Go backend validates the token using the secret key before processing the request.

## Local Development

For local use, you can leave the auth variables unset. The dashboard will automatically detect this and bypass the login screen.
