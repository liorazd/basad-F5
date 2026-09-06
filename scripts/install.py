"""
First-time setup wizard for the F5 VIP Portal.

Walks the operator through every value that lives in `.env.example`, then
optionally chains into the two existing helpers:

    scripts/configure_environments.py    -> f5_environments.json
    scripts/encrypt_service_account.py   -> Fernet-encrypted service account

Re-running is safe: existing `.env` values are shown as the default, so
hitting Enter keeps them. Type `-` to clear an optional value.

    python scripts/install.py
"""
from __future__ import annotations

import getpass
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
ENV_PATH = BASE_DIR / ".env"
ENV_EXAMPLE = BASE_DIR / ".env.example"
SCRIPTS_DIR = Path(__file__).resolve().parent


# ───────────────────────── validators ─────────────────────────

def v_url(v: str) -> str | None:
    if not v:
        return None
    if not (v.startswith("http://") or v.startswith("https://")):
        return "Must start with http:// or https://"
    return None


def v_int(v: str) -> str | None:
    if not v:
        return None
    try:
        int(v)
    except ValueError:
        return "Must be a whole number"
    return None


_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def v_email(v: str) -> str | None:
    if not v:
        return None
    if not _EMAIL_RE.match(v):
        return "Not a valid email address"
    return None


def v_email_list(v: str) -> str | None:
    if not v:
        return None
    for part in v.split(","):
        part = part.strip()
        if part and not _EMAIL_RE.match(part):
            return f"'{part}' is not a valid email"
    return None


def v_origins(v: str) -> str | None:
    if not v:
        return None
    for part in v.split(","):
        part = part.strip()
        if not part:
            continue
        if part != "*" and not part.startswith(("http://", "https://")):
            return f"'{part}' must be a full origin (http://host:port)"
    return None


def v_bool(v: str) -> str | None:
    if not v:
        return None
    if v.lower() not in ("true", "false", "yes", "no", "1", "0"):
        return "Use true or false"
    return None


# ───────────────────────── schema ─────────────────────────
# Keep in sync with .env.example. Each section is one screen of the wizard.

SCHEMA: list[dict] = [
    {
        "name": "F5 environments",
        "intro": "Point the backend at the JSON file describing every F5 cluster.\n"
                 "You'll build/edit that JSON in the next step.",
        "vars": [
            {"name": "F5_ENVIRONMENTS_FILE",
             "default": "f5_environments.json",
             "description": "Path to the multi-environment JSON file."},
        ],
    },
    {
        "name": "Frontend overrides",
        "intro": "Only set these if the built frontend is served from a different\n"
                 "host than the backend. Skip in local dev.",
        "skip_by_default": True,
        "vars": [
            {"name": "VITE_BACKEND_URL",
             "description": "Backend URL the built frontend should call.",
             "validator": v_url},
            {"name": "VITE_EMAIL_SMTP_HOST",
             "description": "SMTP host shown to users in the request form."},
            {"name": "VITE_EMAIL_SMTP_PORT",
             "description": "SMTP port shown to users in the request form.",
             "validator": v_int},
        ],
    },
    {
        "name": "Read-only service account (data pull)",
        "intro": "A READ-ONLY F5 account used only to pull data: the background cache\n"
                 "pre-warm and the cert-replace API's VIP discovery. It never writes.\n"
                 "Interactive users authenticate on the admin page with their own F5\n"
                 "credentials (F5 + AD group decides access) and get a token -- no admin\n"
                 "username/password is stored here. Leave FERNET_KEY blank to skip the\n"
                 "pre-warm/discovery features entirely.",
        "vars": [
            {"name": "FERNET_KEY",
             "description": "44-char base64-urlsafe key that decrypts the service account.\n"
                            "The encrypt_service_account.py step (below) can generate one.\n"
                            "Prefer FERNET_KEY_FILE for production.",
             "secret": True},
            {"name": "FERNET_KEY_FILE",
             "description": "Path to a 0600 file holding the key, kept outside the repo.\n"
                            "Used when FERNET_KEY is blank, so the key stays off the env."},
            {"name": "F5_SERVICE_ACCOUNT_FILE",
             "default": "f5_service_account.enc",
             "description": "Encrypted read-only service account file (created below)."},
        ],
    },
    {
        "name": "Email / SMTP",
        "intro": "Outbound notifications. Leave SMTP_HOST blank to disable email.",
        "vars": [
            {"name": "SMTP_HOST",
             "description": "Outbound SMTP relay (e.g. 127.0.0.1)."},
            {"name": "SMTP_PORT",
             "description": "SMTP relay port.",
             "validator": v_int},
            {"name": "EMAIL_FROM",
             "description": "From address on outgoing notifications.",
             "validator": v_email},
            {"name": "TEAM_NOTIFY_EMAILS",
             "description": "Comma-separated list emailed on every new VIP request.",
             "validator": v_email_list},
            {"name": "ADMIN_CC_EMAIL",
             "description": "Optional CC on every notification (audit copy).",
             "validator": v_email},
            {"name": "USER_EMAIL_DOMAIN",
             "default": "example.org",
             "description": "Domain used to build '<user>@<domain>' for APM-identified users."},
            {"name": "REQUESTER_NOTIFY_ENABLED",
             "default": "true",
             "description": "Send confirmation email to the requester.",
             "validator": v_bool},
        ],
    },
    {
        "name": "Security hardening",
        "intro": "See docs/AUTHENTICATION_FLOW.md for the rationale behind these.",
        "vars": [
            {"name": "ALLOWED_ORIGINS",
             "description": "CORS allow-list (comma-separated origins).\n"
                            "Leave blank only in dev -- production must list real origins.",
             "validator": v_origins},
            {"name": "ADMIN_TOKEN_TTL",
             "default": "28800",
             "description": "Portal token lifetime in seconds (default 8h, 0 = no expiry).",
             "validator": v_int},
            {"name": "LOGIN_MAX_ATTEMPTS",
             "default": "10",
             "description": "Failed /admin/login attempts per source IP before lockout.",
             "validator": v_int},
            {"name": "LOGIN_WINDOW_SECONDS",
             "default": "900",
             "description": "Rolling window for counting failed login attempts (seconds).",
             "validator": v_int},
            {"name": "LOGIN_LOCKOUT_SECONDS",
             "default": "900",
             "description": "Lockout duration after exceeding the limit (seconds).",
             "validator": v_int},
            {"name": "APP_DEBUG",
             "default": "false",
             "description": "Tornado debug mode. Keep false in QA/production -- when on it\n"
                            "leaks tracebacks to clients and enables autoreload.",
             "validator": v_bool},
        ],
    },
    {
        "name": "Background pre-warm scheduler",
        "intro": "Optional. The backend pre-fetches VIP list + status on a timer so\n"
                 "users don't wait on F5. It uses the encrypted READ service account\n"
                 "above by default; the username/password below are a legacy plaintext\n"
                 "fallback, used only if no encrypted read account is available.",
        "skip_by_default": True,
        "vars": [
            {"name": "F5_BG_USERNAME",
             "description": "Legacy fallback F5 username for the pre-warm worker.\n"
                            "Leave blank when using the encrypted read service account."},
            {"name": "F5_BG_PASSWORD",
             "description": "Password for the legacy pre-warm F5 account.",
             "secret": True},
            {"name": "F5_BG_REFRESH_SECS",
             "default": "600",
             "description": "Seconds between refreshes (minimum 15, default 600 = 10 min).\n"
                            "Cache is considered stale after 2x this value.",
             "validator": v_int},
        ],
    },
    {
        "name": "Runtime storage",
        "intro": "Where the backend writes the audit log, request store, and uploads.",
        "vars": [
            {"name": "DATA_DIR",
             "description": "Directory for runtime state. Default: ./data alongside app.py."},
        ],
    },
]


# ───────────────────────── UI helpers ─────────────────────────

def hr() -> None:
    print("-" * 64)


def banner(title: str) -> None:
    print()
    hr()
    print(f"  {title}")
    hr()


def confirm(question: str, default: bool = False) -> bool:
    suffix = " [Y/n] " if default else " [y/N] "
    try:
        raw = input(question + suffix).strip().lower()
    except EOFError:
        return default
    if not raw:
        return default
    return raw in ("y", "yes")


def prompt_value(spec: dict, current: str | None) -> str | None:
    """Prompt for one variable. Enter keeps current/default; '-' clears."""
    name = spec["name"]
    print()
    print(f"  {name}")
    for line in spec.get("description", "").splitlines():
        print(f"    {line}")

    default = current if current not in (None, "") else spec.get("default", "")
    is_secret = spec.get("secret", False)
    shown = "(empty)" if not default else ("***" if is_secret else default)

    # getpass.getpass on Windows always reads from the console, which deadlocks
    # under stdin redirection (scripted runs, CI). Fall back to plain input().
    interactive_secret = is_secret and sys.stdin.isatty()

    validator = spec.get("validator")
    while True:
        try:
            if is_secret and default:
                raw = input(f"    > [{shown}] (press Enter to keep, '-' to clear) ").strip()
            elif interactive_secret:
                raw = getpass.getpass("    > (hidden, leave blank to skip) ").strip()
            elif is_secret:
                raw = input("    > (leave blank to skip) ").strip()
            else:
                raw = input(f"    > [{shown}] ").strip()
        except EOFError:
            return default or None

        if raw == "":
            return default or None
        if raw == "-":
            return None
        if validator:
            err = validator(raw)
            if err:
                print(f"    !! {err}")
                continue
        return raw


# ───────────────────────── .env I/O ─────────────────────────

def load_env(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    out: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def write_env(path: Path, values: dict[str, str]) -> None:
    """Write .env grouped by SCHEMA sections so the file stays readable."""
    lines: list[str] = []
    lines.append("# F5 VIP Portal configuration -- generated by scripts/install.py")
    lines.append("# Re-run the installer to update values, or edit this file directly.")
    lines.append("")

    seen: set[str] = set()
    for section in SCHEMA:
        lines.append(f"# --- {section['name']} ---")
        for spec in section["vars"]:
            key = spec["name"]
            seen.add(key)
            desc_first = spec.get("description", "").splitlines()[0] if spec.get("description") else ""
            if desc_first:
                lines.append(f"# {desc_first}")
            val = values.get(key)
            if val:
                lines.append(f"{key}={val}")
            else:
                lines.append(f"# {key}={spec.get('default', '')}")
            lines.append("")

    extras = {k: v for k, v in values.items() if k not in seen}
    if extras:
        lines.append("# --- Extras (set manually, preserved by the installer) ---")
        for k, v in sorted(extras.items()):
            lines.append(f"{k}={v}")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except (OSError, NotImplementedError):
        pass


# ───────────────────────── prerequisite checks ─────────────────────────

def check_python() -> None:
    major, minor = sys.version_info[:2]
    if (major, minor) < (3, 10):
        print(f"  ! Python {major}.{minor} detected -- 3.10+ recommended.")
    else:
        print(f"  ok Python {major}.{minor}")


def check_node() -> None:
    npm = shutil.which("npm")
    node = shutil.which("node")
    if not node or not npm:
        print("  ! Node.js / npm not found on PATH.")
        print("    The backend still runs, but the frontend will not build.")
        return
    try:
        out = subprocess.run([node, "--version"], capture_output=True, text=True, check=True)
        print(f"  ok Node {out.stdout.strip()}")
    except (subprocess.SubprocessError, FileNotFoundError):
        print("  ! Could not execute node --version.")


# ───────────────────────── chained helpers ─────────────────────────

def maybe_run_env_wizard(env_file_setting: str) -> None:
    env_file = Path(env_file_setting) if env_file_setting else Path("f5_environments.json")
    if not env_file.is_absolute():
        env_file = BASE_DIR / env_file

    exists = env_file.exists()
    if exists:
        question = f"\n{env_file.name} already exists. Re-run the environment wizard (will overwrite)?"
        default = False
    else:
        question = f"\n{env_file.name} not found. Run the environment wizard now?"
        default = True

    if not confirm(question, default=default):
        return

    cmd = [sys.executable, str(SCRIPTS_DIR / "configure_environments.py"), str(env_file)]
    subprocess.run(cmd, check=False)


def maybe_run_service_account(env_values: dict[str, str]) -> None:
    fernet = env_values.get("FERNET_KEY", "")
    if not fernet:
        if not confirm("\nGenerate FERNET_KEY and encrypt the read-only service account now?", default=False):
            return
    else:
        if not confirm("\nEncrypt (or rotate) the read-only F5 service account now?", default=False):
            return

    env = os.environ.copy()
    if fernet:
        env["FERNET_KEY"] = fernet

    print("\n--- read-only service account (data pull only) ---")
    acct_file = env_values.get("F5_SERVICE_ACCOUNT_FILE") or "f5_service_account.enc"
    acct_path = Path(acct_file)
    if not acct_path.is_absolute():
        acct_path = BASE_DIR / acct_path
    subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "encrypt_service_account.py"), str(acct_path)],
        env=env, check=False,
    )


# ───────────────────────── main ─────────────────────────

def main() -> int:
    banner("F5 VIP Portal -- installer")
    print()
    print("  This wizard will:")
    print("    1. Check Python and Node versions")
    print("    2. Write .env (existing values are shown as defaults)")
    print("    3. Optionally build/edit f5_environments.json")
    print("    4. Optionally encrypt your F5 service account")
    print()
    print("  Re-run at any time. Existing values are kept unless you change them.")

    banner("prerequisites")
    check_python()
    check_node()

    existing = load_env(ENV_PATH)
    if existing:
        print(f"\n  Found {ENV_PATH}. Each prompt will show your current value as the default.")
        print("  Press Enter to keep it, type a new value to change, or '-' to clear.")
    else:
        print(f"\n  No {ENV_PATH.name} found -- starting fresh.")

    new_env: dict[str, str] = {}
    for section in SCHEMA:
        banner(section["name"])
        for line in section.get("intro", "").splitlines():
            print(f"  {line}")

        if section.get("skip_by_default") and not any(existing.get(s["name"]) for s in section["vars"]):
            if not confirm(f"\n  Configure {section['name']}?", default=False):
                continue

        for spec in section["vars"]:
            value = prompt_value(spec, existing.get(spec["name"]))
            if value:
                new_env[spec["name"]] = value

    for key, val in existing.items():
        if key not in new_env and not any(spec["name"] == key for sec in SCHEMA for spec in sec["vars"]):
            new_env[key] = val

    write_env(ENV_PATH, new_env)
    banner("wrote .env")
    print(f"  {ENV_PATH}")
    print(f"  {len([v for v in new_env.values() if v])} value(s) set")

    maybe_run_env_wizard(new_env.get("F5_ENVIRONMENTS_FILE", "f5_environments.json"))
    maybe_run_service_account(new_env)

    banner("done")
    print("  Next steps:")
    print("    ./run.sh           # or .\\run.ps1 on Windows")
    print()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nAborted.")
        raise SystemExit(130)
