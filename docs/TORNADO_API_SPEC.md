# F5 VIP Portal - API Reference

The Tornado backend listens on port `8889` (see `app.py :: make_app`). This
document lists the current endpoints and their auth. It supersedes the original
pre-build spec.

## Authentication

Two schemes:

- **Portal token (interactive UI + most endpoints).** Log in via `POST
  /admin/login` with your F5 username/password; the response contains an opaque
  portal token. Send it on every protected call as
  `Authorization: Bearer <portal_token>`. Everyone who logs in is an admin; there
  are no other roles and no trusted identity headers. See `AUTHENTICATION_FLOW.md`.
- **HTTP Basic (cert-replace automation only).** `POST /api/v1/replace-cert`
  takes `Authorization: Basic <base64(f5_user:f5_pass)>`; the app authenticates to
  F5 as that user and F5 authorizes the change. See `openapi-replace-cert.yaml`.

Unauthenticated request-submission forms (`/viprequest`, `/vipcreation`,
`/f5/add-port/request`) identify the requester by the email in the body.

---

## Auth / session

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/admin/login` | none | Authenticate F5 creds → portal token. |
| POST | `/admin/logout` | Bearer | Invalidate the portal token. |
| GET | `/me` | Bearer (optional) | `{role:"admin"}` if logged in, else 404. |

## VIP inventory & status (Bearer)

| Method | Path | Purpose |
|---|---|---|
| GET | `/f5/vips` | List VIPs across environments (pools, iRules, client-SSL + bound cert). |
| GET | `/f5/vips/stream` | Same, streamed as NDJSON (serves from cache when warm). |
| GET | `/f5/status` | Pool/member health snapshot. |
| GET | `/f5/status/stream` | Streamed status. |
| GET | `/f5/pool/stats` | Point-in-time traffic counters for a pool. |
| GET | `/f5/node-history` | Recent up/down transitions for a member. |

## VIP / port changes (Bearer, F5 writes)

| Method | Path | Purpose |
|---|---|---|
| POST | `/f5/add-port` | Add a port to an existing VIP (VS or switch-iRule mode). |
| POST | `/vipcreation` | Create a VIP (admin-executed). |
| GET/POST | `/f5/irule/versions`, `/f5/irule/rollback` | List / roll back versioned switch iRules. |

## Certificate management

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/f5/replace-cert` | Bearer (admin) | Replace/create a client-SSL cert from the UI. |
| POST | `/api/v1/replace-cert` | Basic | Automated additive cert replace (new cert object + repoint). |
| GET | `/f5/cert-info` | Bearer | Current cert on a client-SSL profile. |
| POST | `/f5/parse-pfx` | Bearer | Parse a PFX locally to preview its metadata. |

## Requests, notifications, audit

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/viprequest`, `/f5/add-port/request` | requester email | Submit a request for admin approval (no F5 write). |
| GET/POST | `/viprequest/list`, `/viprequest/decline`, `/viprequest/clear` | Bearer | Manage the request queue. |
| POST | `/vipcreation/notify` | Bearer | Send an outbound email notification. |
| GET | `/audit` | Bearer | Audit log (filter `type=admin|api|requester`). |
| POST | `/audit/revert` | Bearer | Revert a revertible action (e.g. repoint a cert). |
| POST | `/cache/clear` | Bearer | Wipe the server-side data cache. |

---

## Response shape

Handlers return JSON. Success is `{"success": true, ...}`; failure is
`{"success": false, "error": "..."}` with an appropriate HTTP status
(`400` bad input, `401` missing/invalid token, `404` not found, `409` conflict,
`429` throttled, `500`/`503` server/F5 error).

## Notes

- F5 auth tokens are held server-side and attached as `X-F5-Auth-Token` on F5
  iControl calls; the browser only ever holds the opaque portal token.
- All inputs (IPs, ports, emails, filenames) are validated/sanitized; see the
  Security Notes in `AUTHENTICATION_FLOW.md`.
