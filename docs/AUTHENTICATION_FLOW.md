# VIP Request Portal - Authentication Flow

## Overview
The portal authenticates admins using their **real F5 credentials**. There is no
hard-coded `admin/admin123` user. On login, the backend authenticates the same
user/password against every configured F5 environment (DMZ, DC, ...), collects
the per-environment F5 auth tokens, and returns a single opaque **portal token**
to the frontend. That portal token is then used as `Authorization: Bearer <token>`
on every protected request — including `/f5/add-port`.

This is a **login-only** model: F5 (plus AD-group membership) authorizes the
login, everyone who logs in is an admin, and there are no operator / anonymous /
read-only roles and no trusted headers. Two things run outside the interactive
login: an optional **read-only service account** (Fernet-encrypted) that only
pulls data for the background cache pre-warm and the cert-replace API's VIP
discovery, and the **HTTP Basic cert API** `POST /api/v1/replace-cert`, where the
caller sends their own F5 credentials and F5 authorizes the change.

---

## Where to log in (frontend)

- Anonymous users see a **Login** entry in the sidebar (`Sidebar.tsx`) that
  routes to `/admin`.
- `Admin.tsx` shows a username/password form when no portal token is present in
  `localStorage` (`admin_token` key).
- Successful login flips `AuthContext` role to `admin`, the sidebar then exposes
  the full admin nav (Admin Queue, Audit Log, etc.), and `AddPort.tsx` /
  other protected pages can call the backend.

---

## Flow Diagram

```
┌──────────────────────────────────────────────────────────────┐
│ USER (anonymous)                                             │
│ Clicks "Login" in sidebar → /admin                           │
│ Enters F5 username & password                                │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
        ┌─────────────────────────────────┐
        │ Admin.tsx -> handleLogin()      │
        │ APIService.adminLogin(u, p)     │
        └──────────────┬──────────────────┘
                       │
                       ▼
        ┌─────────────────────────────────┐
        │ POST /admin/login               │
        │ Body: { username, password }    │
        └──────────────┬──────────────────┘
                       │
                       ▼
        ┌──────────────────────────────────────────────┐
        │ app.py :: AdminLoginHandler.post()           │
        │ For each env in F5_ENVIRONMENTS:             │
        │   - resolve active node URL                  │
        │   - authenticate_with_f5(url, u, p)          │
        │   - store { name, url, token } per env       │
        │ If at least one env authenticated:           │
        │   - create_admin_token(envs, username)       │
        │   - put in TOKEN_STORE[portal_token]         │
        │   - return portal_token + per-env results    │
        │ Else: 401                                    │
        └──────────────┬───────────────────────────────┘
                       │
                       ▼
        ┌──────────────────────────────────────────────┐
        │ Response:                                    │
        │ {                                            │
        │   "success": true,                           │
        │   "token": "<portal_token>",                 │
        │   "environments": [                          │
        │     { id, name, url, authenticated, error? } │
        │   ]                                          │
        │ }                                            │
        └──────────────┬───────────────────────────────┘
                       │
                       ▼
        ┌──────────────────────────────────────────────┐
        │ api.service.ts :: adminLogin()               │
        │ - localStorage.setItem('admin_token', token) │
        │ - return result to Admin.tsx                 │
        └──────────────┬───────────────────────────────┘
                       │
                       ▼
        ┌──────────────────────────────────────────────┐
        │ Admin.tsx                                    │
        │ - setIsAuthenticated(true)                   │
        │ - refreshAuth() → /me returns role=admin     │
        │ - Sidebar now shows full admin nav           │
        └──────────────────────────────────────────────┘
```

### Using the token (example: Add Port)

```
┌──────────────────────────────────────────────────────────────┐
│ Admin opens /add-port, fills port + pool members, submits    │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
        ┌──────────────────────────────────────────────┐
        │ api.service.ts                               │
        │ - getAdminToken() from localStorage          │
        │ - POST /f5/add-port                          │
        │   Header: Authorization: Bearer <token>      │
        │   Body:   { vip_name, vip_ip, target,        │
        │            port, pool_members, ... }         │
        └──────────────┬───────────────────────────────┘
                       │
                       ▼
        ┌──────────────────────────────────────────────┐
        │ app.py :: F5AddPortHandler.post()            │
        │ - require_auth() → token_data                │
        │ - get_token_environment(token_data, target)  │
        │   yields the F5 token + URL for that target  │
        │ - create_f5_add_port_resources(...)          │
        │ - audit_log + JSON response                  │
        └──────────────────────────────────────────────┘
```

---

## Implementation Details

### Backend (`app.py`)

#### Token store
```python
TOKEN_STORE = {}  # { portal_token: { "username": str,
                  #                   "environments": {
                  #                     env_id: { "name", "url", "token" }
                  #                   } } }
```

#### Key functions
- `authenticate_with_f5(url, username, password) -> str` (`app.py:1010`)
  POSTs to `/mgmt/shared/authn/login` with `loginProviderName: "tmos"` and
  returns the F5 auth token.
- `create_admin_token(environments, username) -> str` (`app.py:1078`)
  Generates a random portal token and stores per-env F5 tokens against it.
- `validate_token(token) -> dict | None` (`app.py:1095`)
- `clear_token(token)` (`app.py:1102`)
- `get_token_environment(token_data, target) -> (env, env_session)`
  (`app.py:1110`)

#### `BaseHandler` helpers
- `get_auth_token()` — pulls `Bearer <token>` from the `Authorization` header.
- `require_auth()` — validates the portal token and returns the token data;
  responds `401` if missing/invalid.

#### Endpoints
- **`POST /admin/login`** (`AdminLoginHandler`)
  - Request: `{ "username": "...", "password": "..." }`
  - Response: `{ success, token, environments[], message }`
  - Authenticates per environment, returns the portal token.
- **`POST /admin/logout`** (`AdminLogoutHandler`)
  - Header: `Authorization: Bearer <portal_token>`
  - Clears the token from `TOKEN_STORE`.
- **`GET /me`** (`CurrentUserHandler`)
  - With a valid portal token → `role: "admin"`.
  - Otherwise → `404` (not logged in).
- **`POST /f5/add-port`**, **`POST /vipcreation`**, **`POST /vipcreation/notify`**,
  **`POST /f5/replace-cert`**, ... — all call `require_auth()` and pick the
  right F5 token via `get_token_environment(token_data, target)`.

### Frontend (`src/services/api.service.ts`)

| Method | Behavior |
|---|---|
| `adminLogin(username, password)` | `POST /admin/login`; saves token to `localStorage.admin_token`. |
| `getAdminToken()` | Reads `localStorage.admin_token`. |
| `adminLogout()` | `POST /admin/logout` with token; clears storage. |
| `whoami()` | `GET /me` with token; used by `AuthContext`. |
| `submitVIPRequest(...)`, `f5AddPort(...)`, ... | Attach `Authorization: Bearer <token>`; throw on missing token. |

### Frontend (UI)

- `Sidebar.tsx` — `Login` entry visible to `role: 'anonymous'`, linking to `/admin`.
- `Admin.tsx` — renders the login form when there is no token, otherwise the
  request-queue dashboard.
- `AuthContext.tsx` — calls `/me`; downstream pages (`AddPort.tsx`, `Status.tsx`,
  `ReplaceCert.tsx`, `Audit.tsx`) check `role` to gate features.

---

## Why "Add Port" returned 401

If you opened `/f5/add-port` without first logging in, no `admin_token` was in
`localStorage`, so the frontend either prompted for login or sent the request
without `Authorization: Bearer …`, which `F5AddPortHandler.require_auth()`
rejected with `401 Unauthorized`. The fix is to log in first via the sidebar's
**Login** entry, which stores the portal token used by every protected call.

---

## Security Notes

### Currently implemented
- Portal token stored in `localStorage` (still accessible to JS — see open item below).
- `TOKEN_STORE` is in-process memory — tokens are lost on server restart.
- **Portal token TTL**: defaults to 8h (`ADMIN_TOKEN_TTL`). `validate_token` evicts expired tokens.
- **Login throttle**: per-IP failure tracking on `/admin/login`. After
  `LOGIN_MAX_ATTEMPTS` (default 10) failures inside `LOGIN_WINDOW_SECONDS`
  (default 900), the IP is locked out for `LOGIN_LOCKOUT_SECONDS` (default 900).
  Successful login resets the counter.
- **CORS allow-list**: `ALLOWED_ORIGINS` env var. Only listed origins get the
  `Access-Control-Allow-Origin` header. Empty list falls back to `*` and logs a
  warning at startup.
- **No header trust / no roles**: the portal does not trust any identity headers
  (APM `X-Authenticated-User`/role, `X-Forwarded-For`, etc.) and keeps no IP
  allowlist — your firewall handles IP filtering. The only authentication is the
  F5-login portal token, and everyone who logs in is an admin.
- **PFX filename sanitization**: uploaded filenames are passed through
  `safe_pfx_filename()` — basename only, whitelist of `[A-Za-z0-9._-]`, capped
  at 128 chars, forced `.pfx` extension. Blocks path traversal on disk and on
  the F5 upload path.
- **Email hygiene**: requester emails are validated against an RFC-5322-lite
  regex; CRLF stripped from subjects/names to block header injection. Admin
  Cc and From addresses come from env (`ADMIN_CC_EMAIL`, `EMAIL_FROM`,
  `USER_EMAIL_DOMAIN`) instead of being hardcoded.
- F5 tokens are kept server-side only; the browser only ever sees the opaque portal token.

### Still open (next round)
1. **TLS verification on F5 calls** — every `requests.*(verify=False)` call
   trusts any TLS certificate. Once we have the F5 CA bundle, switch to
   `verify=/path/to/f5_ca.pem`.
2. **HttpOnly cookie for the portal token** instead of `localStorage` (mitigates XSS exfiltration).
3. **Refresh tokens** for shorter-lived access tokens.
4. **Persist `TOKEN_STORE` and `LOGIN_ATTEMPTS`** in Redis if running multi-replica.
5. **Audit log tamper protection** — HMAC/sequence-number chain on `audit.jsonl`.
6. **F5 IP allocator races** — `VIPIPAllocator` uses per-request in-memory state; switch to a shared lock or DB.

---

## Testing

### Login
```bash
curl -X POST http://localhost:8889/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username":"<f5-user>","password":"<f5-pass>"}'
```
Response includes `token`. Export it:
```bash
TOKEN=...
```

### Add port (requires the Bearer header)
```bash
curl -X POST http://localhost:8889/f5/add-port \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "vip_name": "myapp.example.org",
    "vip_ip": "10.20.10.5",
    "target": "dmz",
    "port": "8443",
    "pool_members": [{"ip_address":"10.10.10.10"}],
    "monitor_type": "tcp",
    "ssl_enabled": false
  }'
```

### Missing/invalid token
```bash
curl -X POST http://localhost:8889/f5/add-port \
  -H "Authorization: Bearer invalid_token" -d '{}'
# → 401 { "success": false, "error": "Unauthorized: Invalid or missing token" }
```

### Logout
```bash
curl -X POST http://localhost:8889/admin/logout \
  -H "Authorization: Bearer $TOKEN"
```

---

## Credentials

There are no hard-coded portal credentials. Log in with any valid F5 user that
can authenticate to at least one configured environment. Configure environments
via `F5_ENVIRONMENTS_JSON` or the legacy `F5_DMZ_URL` / `F5_LAN_URL` env vars
(see `CONFIGURATION.md`).
