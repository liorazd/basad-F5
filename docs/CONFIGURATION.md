# F5 VIP Portal - Configuration Guide

All configuration lives in `.env` (copy from `.env.example`). The easiest way to
create it is the interactive installer:

```bash
python scripts/install.py        # or run setup.sh / setup.ps1, which chains into it
```

The installer writes `.env`, can build `f5_environments.json`, and can encrypt
the read-only service account.

---

## Authentication model (login-only)

There is **no hard-coded password** and no `F5_USERNAME`/`F5_PASSWORD`. Users log
in on the admin page with their **own F5 credentials**; the backend authenticates
those against every configured F5 environment, and F5 (plus AD-group membership)
decides whether the login succeeds. On success the backend returns an opaque
**portal token** that gates every subsequent request (`Authorization: Bearer
<token>`). The per-environment F5 tokens are held server-side only.

Everyone who successfully logs in is an admin — there are no operator / anonymous
/ read-only roles, no APM header trust, and no IP allowlist (your firewall owns
IP filtering). See `AUTHENTICATION_FLOW.md` for the request-by-request flow.

Automated certificate replacement is available without the UI via the HTTP Basic
API `POST /api/v1/replace-cert` — the caller sends their own F5 username/password
and F5 authorizes the change (see `openapi-replace-cert.yaml`).

---

## F5 environments

Point the backend at a JSON file describing every F5 cluster:

```
F5_ENVIRONMENTS_FILE=f5_environments.json
```

Build/edit it with `python scripts/configure_environments.py`. Each environment
has an `id`, `name`, `url`, optional `nodes` (for active-node detection), and
SNAT/member-network settings. A legacy two-environment fallback
(`F5_DMZ_URL` / `F5_LAN_URL` + related vars) is still supported if you prefer not
to use the JSON file.

---

## SNAT mapping

The portal gives each VIP it creates its own SNAT pool where it can, so back-end
servers see a predictable source address. Which address comes from the environment's
`snat_mappings` — **one entry per VIP range**, so an environment with several
`vip_networks` pins each range to its own SNAT range:

```json
{
  "id": "internal",
  "vip_networks":  ["172.20.210.0/24", "172.20.211.0/24"],
  "snat_mappings": [
    { "vip_cidr": "172.20.210.0/24", "snat_network": "172.20.7.0/24" },
    { "vip_cidr": "172.20.211.0/24", "snat_network": "172.20.8.0/28" }
  ]
}
```

Two forms are accepted per entry:

| Form | Meaning |
|---|---|
| `"snat_network": "172.20.7.0/24"` | Host-preserving remap — the VIP's host bits are mirrored onto the SNAT range, so `172.20.210.157` SNATs as `172.20.7.157`. |
| `"snat_ip": "10.20.3.1"` | One fixed address shared by every VIP in the range. |

### How an address is chosen

For each new VIP (and each added port), in order:

1. **Host-preserving mirror** — the same last octet in the mapped SNAT range.
   Deterministic, so re-running against an existing VIP reuses its pool instead
   of creating a second one.
2. **Next free address** — when the mirrored host doesn't fit (the SNAT range is
   smaller than the VIP range, e.g. a `/28` against a `/24`), the lowest address
   in the range that no SNAT pool already holds. `.0`, `.1` and `.255` are never
   handed out.
3. **Automap** — when no mapping covers the VIP, or the mapped range is full, or
   the pool can't be created. The VIP is still created; it just SNATs from the
   F5's own self-IP.

A SNAT range smaller than its VIP range is allowed — it only limits how many
VIPs can hold a dedicated address before step 3 kicks in, and the backend logs a
warning at startup saying how many that is.

Pools are reused, never duplicated: an address already carried by an existing
SNAT pool reuses that pool whatever it's named. If a pool with the name we'd
generate (`snat_172_20_7_5`) exists holding a *different* address, that address
is treated as taken and the next candidate is tried.

Automap fallbacks are visible without reading logs — the create/add-port
responses carry `snat: "automap"` and `snat_fallback_reason`, and the audit entry
records the same. The Add Port page previews the SNAT address before you submit.

---

## Read-only service account (optional)

A single **read-only** F5 service account is used only to pull data: the
background cache pre-warm and the cert-replace API's VIP discovery. It never
writes — interactive changes run as the logged-in user's own F5 token.

```
FERNET_KEY=                         # or FERNET_KEY_FILE=/etc/f5-portal/fernet.key
F5_SERVICE_ACCOUNT_FILE=f5_service_account.enc
```

Generate the key and encrypt the account:

```bash
python scripts/encrypt_service_account.py
```

Leave `FERNET_KEY` blank to disable the pre-warm/discovery features; interactive
users still work via their own login.

---

## Key environment variables

| Variable | Purpose |
|---|---|
| `F5_ENVIRONMENTS_FILE` | Path to the multi-environment JSON file. |
| `FERNET_KEY` / `FERNET_KEY_FILE` | Decrypts the read-only service account. |
| `F5_SERVICE_ACCOUNT_FILE` | Encrypted read-only service account. |
| `ALLOWED_ORIGINS` | CORS allow-list. Empty falls back to `*` (not recommended). |
| `APP_DEBUG` | Tornado debug mode. Keep `false` in QA/production. |
| `ADMIN_TOKEN_TTL` | Portal token lifetime in seconds (default 28800 = 8h). |
| `LOGIN_MAX_ATTEMPTS` / `LOGIN_WINDOW_SECONDS` / `LOGIN_LOCKOUT_SECONDS` | Per-IP `/admin/login` brute-force throttle. |
| `F5_BG_REFRESH_SECS` | Cache pre-warm interval (default 600 = 10 min). |
| `SERVICE_SESSION_TTL` | Service-account session cache TTL (default 1800). |
| `SMTP_HOST` / `SMTP_PORT` / `EMAIL_FROM` / `TEAM_NOTIFY_EMAILS` | Email notifications. |
| `USER_EMAIL_DOMAIN` | Domain used to build `<user>@<domain>` for logged-in users. |
| `DATA_DIR` / `F5_CACHE_DIR` | Runtime state + cache locations. |

See `.env.example` for the full, commented list.

---

## Running

```bash
./run.sh            # dev: Vite (:8080) + Tornado (:8889)
./run.sh build      # production: build frontend, then run the backend
```

(`run.ps1` is the PowerShell equivalent.)

---

## Security notes

- F5 tokens are kept server-side; the browser only ever holds the opaque portal
  token. Portal tokens expire (`ADMIN_TOKEN_TTL`) and are evicted on validation.
- `/admin/login` is brute-force throttled per source IP.
- F5 iControl calls currently use `verify=False` (self-signed mgmt certs). On a
  trusted management network this is acceptable; switch to a CA bundle when
  available.
- Keep `APP_DEBUG` off and set `ALLOWED_ORIGINS` before production.
- Prefer `FERNET_KEY_FILE` (0600, outside the repo) over `FERNET_KEY` in `.env`.

---

## Troubleshooting

- **"F5 authentication failed for every configured environment"** — the F5
  username/password were rejected (or the account isn't in the required AD
  group), or no configured F5 is reachable. Verify credentials and connectivity.
- **401 on a protected call** — no valid portal token; log in again.
- **Cache/status empty** — the read-only service account (or `FERNET_KEY`) isn't
  configured, so the background pre-warm is disabled.
- **A new VIP came up with automap instead of a SNAT pool** — check
  `snat_fallback_reason` in the response or audit entry. Either no
  `snat_mappings` entry covers that VIP range (the common case: the environment
  was created without one), or the mapped SNAT range has no free addresses left.
