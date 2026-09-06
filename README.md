# BasaD F5 VIP Portal

Self-service portal for requesting, approving, and managing F5 BIG-IP VIPs.
Backend is a Tornado app that talks to F5 iControl REST; frontend is a Vite +
React app served alongside it.

Auth is **login-only**: users sign in with their own F5 credentials (F5 + AD
group authorizes), and everyone who logs in is an admin — no APM header trust,
no IP allowlist. An optional read-only service account pulls data for the cache,
and cert replacement can be automated via the HTTP Basic `POST /api/v1/replace-cert`.

## Layout

```
.
├── app.py                  Tornado backend (handlers, F5 client, email, audit)
├── ip_allocator.py         Per-environment VIP IP picker
├── requirements.txt        Python deps
├── scripts/
│   ├── install.py                  First-time setup wizard (.env + JSON + service account)
│   ├── configure_environments.py   Build/edit f5_environments.json interactively
│   └── encrypt_service_account.py  Encrypt the read-only data-pull service account
├── frontend/               Vite + React app (Tailwind, shadcn/ui)
│   ├── src/                Pages, components, services, contexts
│   └── package.json
├── docs/                   AUTHENTICATION_FLOW, CONFIGURATION, F5_API_INTEGRATION, TORNADO_API_SPEC
├── data/                   Runtime state (created on boot; gitignored)
│   ├── vip_requests.json
│   ├── vip_uploads/
│   ├── audit.jsonl
│   └── node_history.jsonl
├── .env.example            Environment variables with descriptions
├── f5_environments.example.json
├── run.sh / run.ps1        Launch backend + frontend
└── setup.sh / setup.ps1    Install deps + wire up (delegates to scripts/install.py)
```

## Requirements

- **Python 3.10 or newer.** The code uses PEP 604 unions (`str | None`)
  throughout; on 3.9 it fails at import with a `TypeError` pointing at a type
  annotation rather than at the version.
- Node 18+ for the frontend.
- Network reach to the F5 management addresses on 443, from wherever the
  backend runs.

## Quick start

```bash
# 1. First-time setup — interactive wizard that creates .env,
#    f5_environments.json, and (optionally) the encrypted service account.
python scripts/install.py

# 2. Launch backend (Tornado :8889) + frontend (Vite :8080)
./run.sh           # or .\run.ps1 on Windows
```

The wizard re-runs safely — it offers to update existing values rather than
overwriting them.

### Start it with the launcher, not `python app.py`

**`app.py` does not read `.env`.** It only calls `os.getenv`, so the file is
loaded by `run.sh` / `run.ps1`, which export it into the environment before
starting the backend. Running `python app.py` directly ignores every value in
`.env` — you get "No F5 environments configured" with no hint as to why.

To run the backend on its own, export the variables yourself first:

```bash
set -a; . ./.env; set +a
python app.py
```

The backend port is **hardcoded to 8889** (`app.py`, bottom of file) and is not
configurable by environment variable.

### Serving the built frontend

`./run.sh build` (or `.\run.ps1 -Build`) compiles the frontend into
`frontend/dist/`, but **Tornado does not serve it** — the backend registers no
static-file handler, only the API routes. Point a web server (nginx, IIS,
Caddy) at `frontend/dist/` and proxy the API paths to `:8889`, or keep using
the Vite dev server for local work.

## Configuration

Every setting is documented in `.env.example`. The most important ones:

| Variable | Purpose |
|---|---|
| `F5_ENVIRONMENTS_FILE` | Path to `f5_environments.json` (multi-environment config). |
| `ALLOWED_ORIGINS` | Comma-separated CORS allow-list. Empty = `*` (dev only). |
| `ADMIN_TOKEN_TTL` | Portal token lifetime in seconds (default 28800 = 8h). |
| `LOGIN_MAX_ATTEMPTS` / `LOGIN_WINDOW_SECONDS` / `LOGIN_LOCKOUT_SECONDS` | Login brute-force throttle. |
| `FERNET_KEY` / `FERNET_KEY_FILE` | Key that decrypts the read-only service account. |
| `F5_SERVICE_ACCOUNT_FILE` | Encrypted read-only service account (cache pre-warm + cert API). |
| `APP_DEBUG` | Tornado debug mode; keep `false` in QA/production. |
| `SMTP_HOST` / `SMTP_PORT` / `EMAIL_FROM` / `ADMIN_CC_EMAIL` / `USER_EMAIL_DOMAIN` | Email config. |
| `DATA_DIR` | Where runtime state goes (default `./data`). |

See `docs/CONFIGURATION.md` for the long-form explanation and
`docs/AUTHENTICATION_FLOW.md` for the auth/security model.

## Tests

`test_irule_snat.py` covers iRule parsing/building, SNAT resolution and pool
naming, the SNAT mapping table, and iRule versioning.

It does `import app` at module scope, so the environment config must resolve
before it will start. The example config is enough — no F5 is contacted:

```bash
F5_ENVIRONMENTS_FILE=f5_environments.example.json python test_irule_snat.py
```

Without that variable it exits immediately with "No F5 environments
configured". It prints `All checks passed.` on success.

For end-to-end checks against a live F5, see the "Testing" section of
`docs/AUTHENTICATION_FLOW.md` for the curl smoke tests.
