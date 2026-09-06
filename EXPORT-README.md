# Sanitized export

This is a genericized copy of the F5 VIP Portal. Before it will run you must
supply the things that were deliberately stripped:

1. `f5_environments.json` - not included. Build it from
   `f5_environments.example.json`, or run `python scripts/configure_environments.py`.
2. `.env` - not included. Copy `.env.example` and fill it in, or run
   `python scripts/install.py`.
3. `FERNET_KEY` + encrypted service account - not included. Regenerate with
   `python scripts/encrypt_service_account.py`. Do not reuse the old key.
4. `frontend/package-lock.json` - removed because a dependency was dropped.
   Run `npm install` in `frontend/` to regenerate it.
5. `LICENSE` - fill in `<COPYRIGHT HOLDER>`.

Placeholders left in the source, all overridable by environment variable:

| Placeholder | Variable |
|---|---|
| `example.org` | `USER_EMAIL_DOMAIN` |
| `vip-portal@example.org` | `EMAIL_FROM` |
| `vip-portal.example.org:5443` | `ALLOWED_ORIGINS` (and the notification email body) |
| `smtp.example.org` | `VITE_EMAIL_SMTP_HOST` |
| `corp.example.org`, `.internal.example.org` | hardcoded domain list in `frontend/src/pages/VIPRequest.tsx` |

`TEAM_NOTIFY_EMAILS` now defaults to empty - set it or team notifications are
skipped. The allowed dev host is set in `frontend/vite.config.ts`.

See `THIRD-PARTY-NOTICES.md` for the provenance of `frontend/src/components/ui/`.