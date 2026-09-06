# Sanitized export

This is a genericized copy of the F5 VIP Portal. Nothing in the repo points at
a real environment — every hostname, domain and address range below is a
placeholder. Before it will run you must supply what was deliberately stripped:

1. `f5_environments.json` — not included. Build it from
   `f5_environments.example.json`, or run `python scripts/configure_environments.py`.
2. `.env` — not included. Copy `.env.example` and fill it in, or run
   `python scripts/install.py`.
3. `FERNET_KEY` + encrypted service account — not included, and optional.
   Generate with `python scripts/encrypt_service_account.py`. Without it the
   app runs fine; you lose the cache pre-warm and the HTTP Basic
   `POST /api/v1/replace-cert` endpoint. The Replace SSL Cert page in the UI
   still works, because that runs as the logged-in user's own F5 token.

## Two things that will waste your time if you don't know them

**`app.py` never reads `.env`.** It only calls `os.getenv`. The file is loaded
by `run.sh` / `run.ps1`, which export it before starting the backend. If you
run `python app.py` directly, every setting in `.env` is ignored and you get
"No F5 environments configured" with no explanation. Either use the launcher,
or export the variables yourself (`set -a; . ./.env; set +a`).

**Tornado does not serve the frontend.** There is no static-file handler — API
routes only. `./run.sh build` compiles `frontend/dist/`, but something else has
to serve it. In development the Vite dev server on `:8080` serves the SPA and
proxies the API to `:8889`.

## Placeholders in the source

All overridable by environment variable unless noted:

| Placeholder | Where to change it |
|---|---|
| `example.org` | `USER_EMAIL_DOMAIN` |
| `vip-portal@example.org` | `EMAIL_FROM` |
| `vip-portal.example.org:5443` | `ALLOWED_ORIGINS` (and the notification email body) |
| `smtp.example.org` | `VITE_EMAIL_SMTP_HOST` |
| `corp.example.org`, `.internal.example.org` | hardcoded domain list in `frontend/src/pages/VIPRequest.tsx` |
| `vip-portal.example.org` in `allowedHosts` | `frontend/vite.config.ts` — the Vite dev server rejects any other hostname |

The VIP, SNAT and pool-member ranges in the docs, tests and
`f5_environments.example.json` (`10.20.x`, `172.20.x`) are illustrative RFC1918
examples. Replace them with your own in `f5_environments.json`; nothing in the
code depends on those particular values.

`TEAM_NOTIFY_EMAILS` defaults to empty — set it or team notifications are
skipped silently.

The backend port is hardcoded to 8889 and is not configurable by environment
variable.

See `THIRD-PARTY-NOTICES.md` for the provenance of `frontend/src/components/ui/`.
