# -*- coding: utf-8 -*-
import json
import ipaddress
import logging
import uuid
import secrets
import os
import re
import time
import base64
import socket
import threading
import asyncio
from datetime import datetime
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import tornado.ioloop
import tornado.web
from tornado.concurrent import run_on_executor
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning
import smtplib
from email.mime.text import MIMEText
try:
    from cryptography.hazmat.primitives.serialization import pkcs12 as crypto_pkcs12  # type: ignore
except Exception:
    crypto_pkcs12 = None

try:
    from cryptography.fernet import Fernet  # type: ignore
except Exception:
    Fernet = None

from ip_allocator import VIPIPAllocator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
api_logger = logging.getLogger("api")

# F5 appliances commonly use self-signed certificates. We still pass
# verify=False explicitly where needed, but this removes the repeated SSL noise.
urllib3.disable_warnings(InsecureRequestWarning)

# Simple in-memory token store (user -> F5 token mapping)
# Maps admin tokens to their F5 tokens and details
TOKEN_STORE = {}  # {admin_token: {"dmz_token": "...", "dmz_url": "...", "dc_token": "...", "dc_url": "...", "username": "..."}}

# Storage for pending VIP requests (JSON + uploaded files).
# Runtime state lives under ./data so source tree stays clean.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.getenv("DATA_DIR", os.path.join(BASE_DIR, "data"))
os.makedirs(DATA_DIR, exist_ok=True)
VIP_REQUEST_STORE = os.path.join(DATA_DIR, "vip_requests.json")
VIP_UPLOAD_DIR = os.path.join(DATA_DIR, "vip_uploads")
os.makedirs(VIP_UPLOAD_DIR, exist_ok=True)

SENSITIVE_QUERY_KEYS = {
    "token",
    "password",
    "passphrase",
    "pfx_password",
    "secret",
    "key",
}


def _mask_url_for_log(url: str) -> str:
    try:
        split = urlsplit(url)
        if not split.query:
            return url
        query = []
        for key, value in parse_qsl(split.query, keep_blank_values=True):
            if key.lower() in SENSITIVE_QUERY_KEYS:
                query.append((key, "***"))
            else:
                query.append((key, value))
        return urlunsplit((split.scheme, split.netloc, split.path, urlencode(query), split.fragment))
    except Exception:
        return url


def _log_http_response(method: str, url: str, status_code: int | str, elapsed_ms: float | None = None) -> None:
    if elapsed_ms is None:
        api_logger.info("HTTP %s %s -> %s", method.upper(), _mask_url_for_log(url), status_code)
    else:
        api_logger.info("HTTP %s %s -> %s %.1fms", method.upper(), _mask_url_for_log(url), status_code, elapsed_ms)


def request_with_log(method: str, url: str, **kwargs) -> requests.Response:
    start = time.perf_counter()
    try:
        response = requests.request(method, url, **kwargs)
        _log_http_response(method, url, response.status_code, (time.perf_counter() - start) * 1000)
        return response
    except Exception as e:
        _log_http_response(method, url, f"ERROR {type(e).__name__}", (time.perf_counter() - start) * 1000)
        raise


class LoggingSession(requests.Session):
    def send(self, request, **kwargs):
        start = time.perf_counter()
        try:
            response = super().send(request, **kwargs)
            _log_http_response(request.method, request.url, response.status_code, (time.perf_counter() - start) * 1000)
            return response
        except Exception as e:
            _log_http_response(request.method, request.url, f"ERROR {type(e).__name__}", (time.perf_counter() - start) * 1000)
            raise

def _get_env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _normalize_url(url: str) -> str:
    return url.strip().rstrip("/")


def _parse_url_list(raw_value: str, fallback: str | None = None) -> list[str]:
    values = [_normalize_url(part) for part in (raw_value or "").split(",") if part.strip()]
    if values:
        return values
    if fallback:
        return [_normalize_url(fallback)]
    return []

def _slugify_environment_id(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (value or "").strip().lower()).strip("-")
    return slug or "environment"


def _parse_network_list(raw_value) -> list[str]:
    if isinstance(raw_value, list):
        return [str(item).strip() for item in raw_value if str(item).strip()]
    if isinstance(raw_value, str):
        return [part.strip() for part in raw_value.split(",") if part.strip()]
    return []


def _validate_networks(networks: list[str], env_name: str, field: str = "member network") -> list[str]:
    validated = []
    for cidr in networks:
        try:
            ipaddress.IPv4Network(cidr, strict=False)
        except Exception as e:
            raise RuntimeError(f"Invalid {field} '{cidr}' in environment '{env_name}': {e}")
        validated.append(cidr)
    return validated


def _validate_snat_mappings(raw, env_name: str) -> list[dict]:
    """Normalize and validate the per-env SNAT mapping table. Each entry maps
    a VIP cidr to the SNAT source it must use. Two forms are supported:

      * Fixed IP (legacy):     {"vip_cidr": "10.20.1.0/24", "snat_ip": "10.20.3.1"}
        Every VIP in the range uses the same single SNAT address.

      * Host-preserving remap: {"vip_cidr": "172.20.63.0/24", "snat_network": "172.20.7.0/24"}
        The VIP's host bits are mirrored onto snat_network, so 172.20.63.157
        SNATs as 172.20.7.157.

    Exactly one of snat_ip / snat_network is required per entry.

    One entry per VIP range: an environment with several vip_networks gets
    several mappings, each pinning its own range to its own SNAT range.

    A snat_network smaller than its vip_cidr is allowed — the mirrored host
    simply won't fit for most VIPs, and allocate_snat_ip() falls back to the
    next free address in the range (then to automap once the range is full).
    We only warn at load time so the operator knows the range is undersized.
    """
    if raw is None or raw == "":
        return []
    if not isinstance(raw, list):
        raise RuntimeError(f"snat_mappings in environment '{env_name}' must be an array")
    validated = []
    for idx, item in enumerate(raw):
        if not isinstance(item, dict):
            raise RuntimeError(f"snat_mappings[{idx}] in '{env_name}' must be an object")
        cidr = str(item.get("vip_cidr") or "").strip()
        snat_ip = str(item.get("snat_ip") or "").strip()
        snat_network = str(item.get("snat_network") or "").strip()
        if not cidr:
            raise RuntimeError(f"snat_mappings[{idx}] in '{env_name}' requires vip_cidr")
        if bool(snat_ip) == bool(snat_network):
            raise RuntimeError(
                f"snat_mappings[{idx}] in '{env_name}' requires exactly one of "
                f"snat_ip or snat_network"
            )
        try:
            vip_net = ipaddress.IPv4Network(cidr, strict=False)
        except Exception as e:
            raise RuntimeError(f"snat_mappings[{idx}] vip_cidr '{cidr}' is invalid: {e}")
        if snat_ip:
            try:
                ipaddress.IPv4Address(snat_ip)
            except Exception as e:
                raise RuntimeError(f"snat_mappings[{idx}] snat_ip '{snat_ip}' is invalid: {e}")
            validated.append({"vip_cidr": cidr, "snat_ip": snat_ip})
        else:
            try:
                snat_net = ipaddress.IPv4Network(snat_network, strict=False)
            except Exception as e:
                raise RuntimeError(
                    f"snat_mappings[{idx}] snat_network '{snat_network}' is invalid: {e}"
                )
            if snat_net.prefixlen > vip_net.prefixlen:
                logger.warning(
                    "snat_mappings[%d] in '%s': snat_network %s (/%d) is smaller than "
                    "vip_cidr %s (/%d) — only %d of %d VIPs can keep their host octet; "
                    "the rest take the next free address in the range, and VIPs created "
                    "after it fills up use automap.",
                    idx, env_name, snat_network, snat_net.prefixlen,
                    cidr, vip_net.prefixlen,
                    snat_net.num_addresses, vip_net.num_addresses,
                )
            validated.append({"vip_cidr": cidr, "snat_network": snat_network})
    return validated


def _normalize_environment(raw_env: dict, index: int) -> dict:
    if not isinstance(raw_env, dict):
        raise RuntimeError(f"Environment entry #{index + 1} must be an object")
    env_name = (raw_env.get("name") or raw_env.get("id") or f"Environment {index + 1}").strip()
    env_id = _slugify_environment_id(raw_env.get("id") or env_name)
    platform = str(raw_env.get("platform") or "f5").strip().lower()
    if platform != "f5":
        raise RuntimeError(
            f"Environment '{env_name}' has unsupported platform '{platform}'. "
            f"Only 'f5' is supported."
        )
    url = _normalize_url(str(raw_env.get("url") or "").strip())
    if not url:
        raise RuntimeError(f"Environment '{env_name}' is missing a url")
    nodes = _parse_url_list(",".join(raw_env.get("nodes", [])) if isinstance(raw_env.get("nodes"), list) else str(raw_env.get("nodes") or ""), fallback=url)
    member_networks = _validate_networks(_parse_network_list(raw_env.get("member_networks")), env_name)
    vip_networks = _validate_networks(_parse_network_list(raw_env.get("vip_networks")), env_name, field="vip network")
    snat_mappings = _validate_snat_mappings(raw_env.get("snat_mappings"), env_name)
    return {
        "id": env_id,
        "name": env_name,
        "platform": platform,
        "url": url,
        "nodes": nodes,
        "member_networks": member_networks,
        "vip_networks": vip_networks,
        "snat_mappings": snat_mappings,
    }


def _load_environment_file(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception as e:
        raise RuntimeError(f"Failed to load F5 environments file '{path}': {e}")
    if not isinstance(payload, list):
        raise RuntimeError(f"F5 environments file '{path}' must contain a JSON array")
    return [_normalize_environment(item, idx) for idx, item in enumerate(payload)]


def _load_legacy_environments() -> list[dict]:
    legacy_specs = [
        {
            "id": "dmz",
            "name": _get_env("F5_DMZ_NAME", "DMZ") or "DMZ",
            "url": _get_env("F5_DMZ_URL"),
            "nodes": _parse_url_list(_get_env("F5_DMZ_NODES")),
            "member_networks": _parse_network_list(_get_env("F5_DMZ_MEMBER_NETWORKS", "10.0.0.0/8")),
            "vip_networks": _parse_network_list(_get_env("F5_DMZ_VIP_NETWORKS", "10.20.10.0/24,10.20.11.0/24")),
        },
        {
            "id": "lan",
            "name": _get_env("F5_LAN_NAME", "LAN") or "LAN",
            "url": _get_env("F5_LAN_URL"),
            "nodes": _parse_url_list(_get_env("F5_LAN_NODES")),
            "member_networks": _parse_network_list(_get_env("F5_LAN_MEMBER_NETWORKS", "172.16.0.0/12")),
            "vip_networks": _parse_network_list(_get_env("F5_LAN_VIP_NETWORKS", "172.20.210.0/24,172.20.211.0/24")),
        },
    ]
    normalized = []
    for idx, spec in enumerate(legacy_specs):
        if not spec["url"]:
            continue
        spec["nodes"] = spec["nodes"] or [spec["url"]]
        normalized.append(_normalize_environment(spec, idx))
    return normalized


def load_f5_environments() -> tuple[list[dict], str]:
    env_file = _get_env("F5_ENVIRONMENTS_FILE", os.path.join(BASE_DIR, "f5_environments.json"))
    env_file = env_file if os.path.isabs(env_file) else os.path.join(BASE_DIR, env_file)
    environments = _load_environment_file(env_file)
    source = f"file:{env_file}"
    if not environments:
        environments = _load_legacy_environments()
        source = "legacy-env-vars"
    if not environments:
        raise RuntimeError(
            "No F5 environments configured. Create f5_environments.json via setup, "
            "or set the legacy F5_DMZ_URL/F5_LAN_URL environment variables."
        )
    seen_ids = set()
    for env in environments:
        env_id = env["id"]
        if env_id in seen_ids:
            raise RuntimeError(f"Duplicate F5 environment id '{env_id}'")
        seen_ids.add(env_id)
    return environments, source


F5_ENVIRONMENTS, F5_ENVIRONMENTS_SOURCE = load_f5_environments()
F5_ENVIRONMENTS_BY_ID = {env["id"]: env for env in F5_ENVIRONMENTS}


def public_environment(env: dict) -> dict:
    return {
        "id": env["id"],
        "name": env["name"],
        "platform": env.get("platform", "f5"),
        "url": env["url"],
        "nodes": env["nodes"],
        "member_networks": env["member_networks"],
        "vip_networks": env.get("vip_networks", []),
        "snat_mappings": env.get("snat_mappings", []),
    }


def public_environment_list() -> list[dict]:
    return [public_environment(env) for env in F5_ENVIRONMENTS]


def resolve_snat_ip(env: dict, vip_ip: str) -> str | None:
    """The SNAT IP this VIP deterministically maps to, or None.

    Deterministic only: a fixed snat_ip, or the host-preserving mirror onto
    snat_network (172.20.63.157 -> 172.20.7.157). Returns None when no mapping
    covers the IP, or when the host octet doesn't fit the SNAT range — callers
    that can query the device should use allocate_snat_ip() instead, which
    handles the doesn't-fit case by picking a free address.

    Mirrored by the frontend's SNAT preview.
    """
    if not vip_ip:
        return None
    snat_ip, reason = allocate_snat_ip(env, vip_ip)
    if reason in ("fixed", "host_preserving"):
        return snat_ip
    if reason in ("sequential", "range_full"):
        logger.warning(
            "SNAT remap for %s does not fit its snat_network; falling back to automap",
            vip_ip,
        )
    return None


# Last octets never handed out as a SNAT address: .0 (network), .1 (gateway),
# .255 (broadcast). Same convention VIPIPAllocator uses for VIP IPs.
SNAT_RESERVED_OCTETS = {0, 1, 255}


def _snat_mapping_for_ip(env: dict, vip_ip: str):
    """The first snat_mappings entry whose vip_cidr covers this VIP, as
    (mapping, vip_network). (None, None) when nothing covers it."""
    try:
        addr = ipaddress.IPv4Address(vip_ip)
    except Exception:
        return None, None
    for mapping in env.get("snat_mappings") or []:
        try:
            vip_net = ipaddress.IPv4Network(mapping["vip_cidr"], strict=False)
        except Exception:
            continue
        if addr in vip_net:
            return mapping, vip_net
    return None, None


def allocate_snat_ip(
    env: dict,
    vip_ip: str,
    used_ips: set[str] | None = None,
    blocked_ips: set[str] | None = None,
) -> tuple[str | None, str]:
    """Pick the SNAT address for this VIP. Returns (snat_ip, reason); snat_ip is
    None when the caller must fall back to automap.

    `used_ips` is the set of addresses already claimed by SNAT pools on the
    device — pass F5Client.snat_ips_in_use(). Omit it and only the deterministic
    host-preserving result is considered.

    `blocked_ips` are addresses this caller has already tried and can't have
    (a pool name collision on a foreign address); they are never returned.

    Order of preference, inside the mapping that covers this VIP:
      1. Fixed snat_ip           -> that address, always (the whole range shares it).
      2. Host-preserving mirror  -> 172.20.63.157 -> 172.20.7.157, when the host
                                    octet fits in snat_network. Already claimed is
                                    fine: it is this VIP's own pool being reused.
      3. Next free address       -> lowest unclaimed host in snat_network, for VIPs
                                    whose host octet does not fit (snat_network
                                    smaller than vip_cidr).
      4. None                    -> no mapping covers the VIP, or the range is full.
    """
    used = used_ips or set()
    blocked = blocked_ips or set()
    mapping, vip_net = _snat_mapping_for_ip(env, vip_ip)
    if not mapping:
        return None, "no_mapping"
    if mapping.get("snat_ip"):
        # A fixed address has no alternative — blocked means automap.
        if mapping["snat_ip"] in blocked:
            return None, "conflict"
        return mapping["snat_ip"], "fixed"

    try:
        snat_net = ipaddress.IPv4Network(mapping["snat_network"], strict=False)
        addr = ipaddress.IPv4Address(vip_ip)
    except Exception:
        return None, "no_mapping"

    host = int(addr) - int(vip_net.network_address)
    mirrored = ipaddress.IPv4Address(int(snat_net.network_address) + host)
    if (
        mirrored in snat_net
        and mirrored.packed[-1] not in SNAT_RESERVED_OCTETS
        and str(mirrored) not in blocked
    ):
        return str(mirrored), "host_preserving"

    # Host octet doesn't fit the (smaller) SNAT range — take the lowest address
    # nobody else is using. This is where a range can genuinely run out.
    for candidate in snat_net.hosts():
        if candidate.packed[-1] in SNAT_RESERVED_OCTETS:
            continue
        if str(candidate) in used or str(candidate) in blocked:
            continue
        return str(candidate), "sequential"

    return None, "range_full"


def snat_pool_name_for_ip(snat_ip: str) -> str:
    """Deterministic SNAT-pool name from the SNAT IP (F5 doesn't accept dots
    in object names everywhere, and dashes read better in the GUI)."""
    return "snat_" + snat_ip.replace(".", "_")


# Human-readable explanation per allocate_snat_ip() reason, for logs, the API
# response and the audit trail.
SNAT_FALLBACK_REASONS = {
    "no_mapping": "no snat_mappings entry covers this VIP range",
    "range_full": "every address in the mapped SNAT range is already in use",
    "conflict": "the mapped SNAT address is held by a conflicting SNAT pool",
    "unavailable": "the SNAT pool could not be created on this device",
}


def resolve_snat_pool_for_vip(
    f5: "F5Client", env: dict, vip_ip: str, env_label: str = "", max_attempts: int = 32
) -> tuple[str | None, str]:
    """Resolve the SNAT pool a VIP should use, creating it if needed.

    Returns (snat_pool_path, reason). A None path is not an error — it means the
    caller should let F5 use automap, and `reason` (a SNAT_FALLBACK_REASONS key)
    says why. Never raises for SNAT reasons alone: a VIP that can't get a
    dedicated SNAT address still gets created.
    """
    try:
        used = f5.snat_ips_in_use()
    except F5AuthError:
        raise
    except Exception as e:
        logger.warning("Could not read SNAT pools from %s: %s", env_label or "F5", e)
        used = set()

    blocked: set[str] = set()
    for _ in range(max_attempts):
        snat_ip, reason = allocate_snat_ip(env, vip_ip, used, blocked)
        if not snat_ip:
            logger.warning(
                "No SNAT pool for VIP %s in env '%s' (%s) — using automap",
                vip_ip, env_label, SNAT_FALLBACK_REASONS.get(reason, reason),
            )
            return None, reason
        try:
            path = f5.ensure_snat_pool(snat_pool_name_for_ip(snat_ip), snat_ip)
        except SnatPoolConflict as e:
            logger.warning("SNAT candidate %s unusable: %s", snat_ip, e)
            blocked.add(snat_ip)
            continue
        except Exception as e:
            logger.warning(
                "Failed to create SNAT pool for %s (%s) — using automap: %s",
                vip_ip, snat_ip, e,
            )
            return None, "unavailable"
        logger.info(
            "Using SNAT pool %s -> %s for VIP %s (%s)", path, snat_ip, vip_ip, reason
        )
        return path, reason

    logger.warning(
        "Exhausted SNAT candidates for VIP %s in env '%s' — using automap", vip_ip, env_label
    )
    return None, "range_full"


def get_environment_by_id(target: str) -> dict:
    env = F5_ENVIRONMENTS_BY_ID.get((target or "").strip().lower())
    if not env:
        valid = ", ".join(env["id"] for env in F5_ENVIRONMENTS)
        raise tornado.web.HTTPError(400, reason=f"Invalid target '{target}'. Valid targets: {valid}")
    return env


def get_environment_active_url(env: dict) -> str:
    return get_active_f5_url(env["nodes"]) or env["url"]

# Admin portal password


# Email notification settings for team alerts (on save-only)
SMTP_HOST = os.getenv("SMTP_HOST", "127.0.0.1")
SMTP_PORT = int(os.getenv("SMTP_PORT", "1040"))
TEAM_NOTIFY_EMAILS = [e.strip() for e in os.getenv("TEAM_NOTIFY_EMAILS", "").split(",") if e.strip()]
REQUESTER_NOTIFY_ENABLED = os.getenv("REQUESTER_NOTIFY_ENABLED", "true").lower() == "true"
ADMIN_CC_EMAIL = os.getenv("ADMIN_CC_EMAIL", "").strip()
USER_EMAIL_DOMAIN = os.getenv("USER_EMAIL_DOMAIN", "example.org").strip().lstrip("@")
EMAIL_FROM = os.getenv("EMAIL_FROM", "vip-portal@example.org").strip()

# CORS allow-list. Comma-separated origins (e.g. "https://portal.example:5443").
# If empty we fall back to "*" but log a warning.
ALLOWED_ORIGINS = {
    o.strip()
    for o in os.getenv("ALLOWED_ORIGINS", "").split(",")
    if o.strip()
}
if not ALLOWED_ORIGINS:
    logger.warning(
        "ALLOWED_ORIGINS env var is empty; CORS will respond with '*'. "
        "Set ALLOWED_ORIGINS to a comma-separated list of trusted origins in production."
    )

# Portal token lifetime in seconds (default 8h).
# Where an unrouted browser navigation gets sent instead of a bare 404 page.
APP_ROOT_PATH = os.getenv("APP_ROOT_PATH", "/").strip() or "/"

ADMIN_TOKEN_TTL = int(os.getenv("ADMIN_TOKEN_TTL", str(8 * 60 * 60)))
# Safety window before the real TTL fires. The frontend uses this to force a
# logout slightly early so a user never gets a 401 mid-action. Defaults to
# 5 minutes, clamped so it never eats the entire token lifetime.
_safety_default = min(300, max(0, ADMIN_TOKEN_TTL // 3))
ADMIN_TOKEN_SAFETY_MARGIN_SECS = int(
    os.getenv("ADMIN_TOKEN_SAFETY_MARGIN_SECS", str(_safety_default))
)
if ADMIN_TOKEN_TTL > 0 and ADMIN_TOKEN_SAFETY_MARGIN_SECS >= ADMIN_TOKEN_TTL:
    ADMIN_TOKEN_SAFETY_MARGIN_SECS = max(0, ADMIN_TOKEN_TTL - 30)

# Background pre-warm scheduler credentials. When both are set, the app
# periodically logs into every configured F5 with these creds and pre-fetches
# VIP list + status. Stream handlers serve from cache while fresh so end
# users don't wait on the F5 round trips.
# Legacy plaintext fallback (deprecated). Prefer the Fernet-encrypted read
# service account: when it is available the pre-warm loop uses that instead of
# these, so no plaintext F5 password needs to live in the environment.
F5_BG_USERNAME = os.getenv("F5_BG_USERNAME", "").strip()
F5_BG_PASSWORD = os.getenv("F5_BG_PASSWORD", "")
# Default cadence: pull fresh F5 data every 10 minutes.
F5_BG_REFRESH_SECS = max(15, int(os.getenv("F5_BG_REFRESH_SECS", "600")))
# Cache is considered fresh for 2x refresh interval. After that we fall
# through to a live F5 call rather than show stale data.
F5_BG_STALE_AFTER_SECS = F5_BG_REFRESH_SECS * 2

# Where the in-memory cache also gets persisted to disk so it survives
# restarts and fills in even when the bg scheduler is off (admin live
# fetches write here too). Empty string disables disk persistence.
F5_CACHE_DIR = os.getenv(
    "F5_CACHE_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache"),
).strip()

# Login brute-force throttling (per client IP).
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "10"))
LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "900"))  # 15 min
LOGIN_LOCKOUT_SECONDS = int(os.getenv("LOGIN_LOCKOUT_SECONDS", "900"))  # 15 min
LOGIN_ATTEMPTS: dict[str, dict] = {}  # {ip: {"fails": [ts, ...], "lock_until": ts}}

# RFC 5322 (lite) regex — good enough to reject CRLF/spaces and obvious junk.
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def is_valid_email(addr: str) -> bool:
    if not addr or len(addr) > 254:
        return False
    if "\r" in addr or "\n" in addr:
        return False
    return bool(_EMAIL_RE.match(addr.strip()))


def _strip_crlf(s: str) -> str:
    """Remove CR/LF so user-supplied strings can't inject email or log headers."""
    if not s:
        return ""
    return s.replace("\r", " ").replace("\n", " ").strip()


def login_throttle_check(client_ip: str) -> tuple[bool, int]:
    """Return (allowed, retry_after_seconds). Cleans up expired window entries."""
    if not client_ip:
        return True, 0
    now = time.time()
    entry = LOGIN_ATTEMPTS.get(client_ip)
    if not entry:
        return True, 0
    lock_until = entry.get("lock_until", 0)
    if lock_until > now:
        return False, int(lock_until - now)
    # Drop fails outside the window.
    fails = [ts for ts in entry.get("fails", []) if now - ts <= LOGIN_WINDOW_SECONDS]
    entry["fails"] = fails
    return True, 0


def login_throttle_record_failure(client_ip: str) -> None:
    if not client_ip:
        return
    now = time.time()
    entry = LOGIN_ATTEMPTS.setdefault(client_ip, {"fails": [], "lock_until": 0})
    entry["fails"] = [ts for ts in entry["fails"] if now - ts <= LOGIN_WINDOW_SECONDS]
    entry["fails"].append(now)
    if len(entry["fails"]) >= LOGIN_MAX_ATTEMPTS:
        entry["lock_until"] = now + LOGIN_LOCKOUT_SECONDS
        logger.warning(
            "Login brute-force lockout for %s until %s (%d fails in window)",
            client_ip,
            datetime.fromtimestamp(entry["lock_until"]).isoformat(),
            len(entry["fails"]),
        )


def login_throttle_record_success(client_ip: str) -> None:
    LOGIN_ATTEMPTS.pop(client_ip, None)


# Safe characters for stored PFX filenames (prevents path traversal).
_PFX_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_pfx_filename(raw_name: str) -> str:
    """Strip directory parts and unsafe chars. Always returns a non-empty .pfx name."""
    base = os.path.basename((raw_name or "").strip())
    base = base.replace("\x00", "")
    base = _PFX_SAFE_FILENAME_RE.sub("_", base)
    base = base.strip("._")[:128]
    if not base:
        base = "upload.pfx"
    if not base.lower().endswith(".pfx"):
        base += ".pfx"
    return base


# Encrypted service account file + Fernet master key.
# Hardening: the key may be supplied via FERNET_KEY_FILE (a 0600 file kept out
# of the repo and off the process env / shell history) instead of FERNET_KEY in
# .env. The decrypted service-account password is NEVER held at module scope;
# it is decrypted on demand right before an F5 (re)authentication and scrubbed
# afterwards (see _get_service_session), so plaintext creds are not resident for
# the process lifetime.
FERNET_KEY = os.getenv("FERNET_KEY", "").strip()
FERNET_KEY_FILE = os.getenv("FERNET_KEY_FILE", "").strip()
if not FERNET_KEY and FERNET_KEY_FILE:
    try:
        with open(FERNET_KEY_FILE, "r", encoding="utf-8") as _kf:
            FERNET_KEY = _kf.read().strip()
        logger.info("Loaded FERNET_KEY from file %s", FERNET_KEY_FILE)
    except Exception as _e:
        logger.error("Failed to read FERNET_KEY_FILE %s: %s", FERNET_KEY_FILE, _e)
SERVICE_ACCOUNT_FILE = os.getenv(
    "F5_SERVICE_ACCOUNT_FILE",
    os.path.join(BASE_DIR, "f5_service_account.enc"),
)

# F5 service-account session cache: label -> session dict. Only short-lived F5
# tokens are cached here (for the read-only pre-warm + cert-API discovery),
# never the service-account password.
READ_SESSIONS = {}
SERVICE_SESSION_TTL = int(os.getenv("SERVICE_SESSION_TTL", "1800"))  # 30 min


def _service_account_path() -> str:
    """Path to the encrypted read-only service account (data-pull only)."""
    return SERVICE_ACCOUNT_FILE


def _scrub(account: dict | None) -> None:
    """Best-effort overwrite of a decrypted password so it does not linger.
    (CPython cannot guarantee zeroing of the immutable str, but dropping the
    reference and overwriting keeps the plaintext from staying resident.)"""
    if not account:
        return
    try:
        pw = account.get("password")
        if pw:
            account["password"] = "\x00" * len(pw)
    except Exception:
        pass


def _decrypt_service_account(path: str, label: str) -> dict | None:
    """Decrypt an encrypted service-account file ON DEMAND and return
    {"username","password"}. The plaintext is NOT cached at module scope;
    callers must use it immediately and call _scrub() when done."""
    if not path or not os.path.exists(path):
        return None
    if not FERNET_KEY or Fernet is None:
        return None
    plaintext = None
    try:
        key = FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY
        f = Fernet(key)
        with open(path, "rb") as fh:
            encrypted = fh.read()
        plaintext = bytearray(f.decrypt(encrypted))
        data = json.loads(bytes(plaintext).decode())
        if not data.get("username") or not data.get("password"):
            logger.error("%s service account file missing username/password", label)
            return None
        return {"username": data["username"], "password": data["password"]}
    except Exception as e:
        logger.error("Failed to decrypt %s service account: %s", label, e)
        return None
    finally:
        if plaintext is not None:
            for i in range(len(plaintext)):
                plaintext[i] = 0


def _service_account_available() -> bool:
    """True if a key + an encrypted read-only service account file exist."""
    if not FERNET_KEY or Fernet is None:
        return False
    path = _service_account_path()
    return bool(path) and os.path.exists(path)


def load_service_account():
    """Validate the read-only service account at startup WITHOUT retaining any
    plaintext credential in memory. Real decryption happens on demand."""
    if not FERNET_KEY:
        logger.warning("FERNET_KEY not set; read-only service account disabled (cache pre-warm + cert-API discovery)")
        return
    if Fernet is None:
        logger.warning("cryptography.fernet not available; read-only service account disabled")
        return
    rd = _decrypt_service_account(_service_account_path(), "Read-only")
    if rd:
        logger.info(
            "Read-only service account OK (user=%s); cache pre-warm + cert-API discovery enabled",
            rd["username"],
        )
        _scrub(rd)
    else:
        logger.warning("Read-only service account unavailable; cache pre-warm + cert-API discovery disabled")


load_service_account()


# ---------------------------
# Node state-change history (member up/down tracking)
# ---------------------------
NODE_STATE_FILE = os.getenv("NODE_HISTORY_FILE", os.path.join(DATA_DIR, "node_history.jsonl"))
NODE_STATE = {}  # key -> {"state": "up"|"down"|"unknown", "since": iso}


def load_node_state():
    """Replay node_history.jsonl into NODE_STATE so 'since' survives restarts."""
    global NODE_STATE
    if not os.path.exists(NODE_STATE_FILE):
        return
    try:
        with open(NODE_STATE_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except Exception:
                    continue
                if entry.get("event") != "transition":
                    continue
                key = entry.get("key")
                to_state = entry.get("to")
                ts = entry.get("ts")
                if key and to_state and ts:
                    NODE_STATE[key] = {"state": to_state, "since": ts}
    except Exception as e:
        logger.warning("load_node_state error: %s", e)


def record_node_transition(key: str, from_state: str, to_state: str, ts: str, details: dict | None = None) -> None:
    entry = {
        "event": "transition",
        "ts": ts,
        "key": key,
        "from": from_state,
        "to": to_state,
    }
    if details:
        entry["details"] = details
    try:
        with open(NODE_STATE_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception as e:
        logger.warning("record_node_transition error: %s", e)


def update_node_state(key: str, new_state: str, details: dict | None = None) -> dict:
    """Record a transition if state changed; return {state, since}."""
    now = datetime.utcnow().isoformat() + "Z"
    prev = NODE_STATE.get(key)
    if prev and prev["state"] == new_state:
        return {"state": new_state, "since": prev["since"]}
    if prev:
        record_node_transition(key, prev["state"], new_state, now, details)
    else:
        record_node_transition(key, "unknown", new_state, now, details)
    NODE_STATE[key] = {"state": new_state, "since": now}
    return {"state": new_state, "since": now}


def node_history(key: str, limit: int = 50) -> list:
    """Return the recent transitions for a given key, most-recent-first."""
    if not os.path.exists(NODE_STATE_FILE):
        return []
    out = []
    try:
        with open(NODE_STATE_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except Exception:
                continue
            if entry.get("key") == key:
                out.append(entry)
                if len(out) >= limit:
                    break
    except Exception as e:
        logger.warning("node_history error: %s", e)
    return out


load_node_state()


# ---------------------------
# Audit log (append-only JSONL) + revert support
# ---------------------------
AUDIT_FILE = os.getenv("AUDIT_FILE", os.path.join(DATA_DIR, "audit.jsonl"))


def audit_log(
    action: str,
    target: str = "",
    user: str = "",
    user_type: str = "admin",
    result: str = "success",
    details: dict | None = None,
    client_ip: str = "",
    revertible: bool = False,
) -> dict:
    """Append a single audit entry as a JSON line. Returns the written entry."""
    entry = {
        "id": str(uuid.uuid4()),
        "ts": datetime.utcnow().isoformat() + "Z",
        "user": user,
        "user_type": user_type,
        "action": action,
        "target": target,
        "result": result,
        "client_ip": client_ip,
        "revertible": bool(revertible),
        "reverted": False,
        "reverted_at": None,
        "reverted_by": None,
        "details": details or {},
    }
    try:
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception as e:
        logger.warning("Failed to write audit log: %s", e)
    return entry


def audit_list(user_type: str | None = None, limit: int = 200, search: str = "") -> list:
    """Return audit entries most-recent-first, optionally filtered."""
    if not os.path.exists(AUDIT_FILE):
        return []
    try:
        with open(AUDIT_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        logger.warning("Failed to read audit log: %s", e)
        return []
    search_l = search.lower() if search else ""
    out = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except Exception:
            continue
        if user_type and entry.get("user_type") != user_type:
            continue
        if search_l and search_l not in json.dumps(entry, default=str).lower():
            continue
        out.append(entry)
        if len(out) >= limit:
            break
    return out


def audit_find(entry_id: str) -> dict | None:
    """Find a single audit entry by id (linear scan; OK for our scale)."""
    if not os.path.exists(AUDIT_FILE):
        return None
    try:
        with open(AUDIT_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except Exception:
                    continue
                if entry.get("id") == entry_id:
                    return entry
    except Exception as e:
        logger.warning("audit_find error: %s", e)
    return None


def audit_mark_reverted(entry_id: str, reverted_by: str) -> bool:
    """Rewrite the audit file with the matching entry marked reverted."""
    if not os.path.exists(AUDIT_FILE):
        return False
    try:
        with open(AUDIT_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        rewritten = []
        found = False
        for line in lines:
            stripped = line.strip()
            if not stripped:
                rewritten.append(line)
                continue
            try:
                entry = json.loads(stripped)
            except Exception:
                rewritten.append(line)
                continue
            if entry.get("id") == entry_id and not entry.get("reverted"):
                entry["reverted"] = True
                entry["reverted_at"] = datetime.utcnow().isoformat() + "Z"
                entry["reverted_by"] = reverted_by
                rewritten.append(json.dumps(entry, default=str) + "\n")
                found = True
            else:
                rewritten.append(line)
        if found:
            with open(AUDIT_FILE, "w", encoding="utf-8") as f:
                f.writelines(rewritten)
        return found
    except Exception as e:
        logger.warning("audit_mark_reverted error: %s", e)
        return False


def _get_service_session(label: str, cache: dict) -> dict:
    """Return a cached read-only F5 session (short-lived tokens only). The
    service-account password is decrypted on demand here and scrubbed before
    returning, so it is never held resident once the F5 tokens are obtained."""
    mode_label = "Read-only"
    sess = cache.get(label)
    if sess and sess.get("expires", 0) > time.time():
        return sess

    account = _decrypt_service_account(_service_account_path(), mode_label)
    if not account:
        raise RuntimeError(f"{mode_label} service account not configured")

    try:
        environments = {}
        for env in F5_ENVIRONMENTS:
            active_url = get_environment_active_url(env)
            try:
                environments[env["id"]] = {
                    "name": env["name"],
                    "url": active_url,
                    "token": authenticate_with_f5(
                        active_url,
                        account["username"],
                        account["password"],
                        # Outlive the cached service session so a reused entry
                        # never carries a token the device already expired.
                        extend_to=SERVICE_SESSION_TTL + 300,
                    ),
                }
            except Exception as e:
                logger.warning("%s service-account auth failed for %s: %s", mode_label, env["name"], e)

        if not environments:
            raise RuntimeError(f"{mode_label} service-account authentication failed for every configured F5 environment")

        sess = {
            "username": label,
            "environments": environments,
            "expires": time.time() + SERVICE_SESSION_TTL,
        }
        cache[label] = sess
        return sess
    finally:
        # Drop the plaintext password ASAP; only the F5 tokens are retained.
        _scrub(account)
        del account


def get_read_session(label: str) -> dict:
    """Return a cached read-only F5 session (cache pre-warm + cert-API discovery)."""
    return _get_service_session(label, READ_SESSIONS)


logger.info(
    "Loaded %d F5 environment(s) from %s: %s",
    len(F5_ENVIRONMENTS),
    F5_ENVIRONMENTS_SOURCE,
    ", ".join(f"{env['name']}[{env['id']}]={env['url']}" for env in F5_ENVIRONMENTS),
)
logger.info("F5 credentials are supplied by the user at login")


# ---------------------------
# VIP request persistence
# ---------------------------

# ---------------------------
# VIP request persistence
# ---------------------------

def load_vip_requests() -> list:
    if not os.path.exists(VIP_REQUEST_STORE):
        return []
    try:
        with open(VIP_REQUEST_STORE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error("Failed to load VIP request store: %s", e)
        return []


def save_vip_requests(requests: list) -> None:
    try:
        with open(VIP_REQUEST_STORE, "w", encoding="utf-8") as f:
            json.dump(requests, f, indent=2)
    except Exception as e:
        logger.error("Failed to save VIP request store: %s", e)


def add_vip_request(entry: dict) -> dict:
    requests = load_vip_requests()
    requests.append(entry)
    save_vip_requests(requests)
    return entry


def update_vip_request_status(req_id: str, status: str, extra: dict | None = None) -> dict | None:
    requests = load_vip_requests()
    updated = None
    for r in requests:
        if r.get("id") == req_id:
            r["status"] = status
            if extra:
                r.update(extra)
            updated = r
            break
    if updated:
        save_vip_requests(requests)
    return updated


def get_vip_request(req_id: str) -> dict | None:
    for r in load_vip_requests():
        if r.get("id") == req_id:
            return r
    return None


def clear_vip_requests(delete_uploads: bool = True) -> None:
    """Clear stored VIP requests and optionally uploaded PFX files."""
    save_vip_requests([])
    if delete_uploads:
        try:
            for fname in os.listdir(VIP_UPLOAD_DIR):
                fpath = os.path.join(VIP_UPLOAD_DIR, fname)
                if os.path.isfile(fpath):
                    os.remove(fpath)
        except Exception as e:
            logger.warning("Failed to clear upload directory %s: %s", VIP_UPLOAD_DIR, e)


def send_team_notification(vip_record: dict, smtp_host: str | None = None, smtp_port: int | None = None) -> None:
    """Send a simple email to the team when a VIP request is stored."""
    if not TEAM_NOTIFY_EMAILS:
        logger.info("TEAM_NOTIFY_EMAILS not configured; skipping team notification")
        return
    smtp_host = smtp_host or SMTP_HOST
    smtp_port = smtp_port or SMTP_PORT
    try:
        # Strip CRLF to prevent SMTP header injection via VIP name.
        display_name = _strip_crlf(vip_record.get("vip_name_original") or vip_record.get("vip_name") or "")
        subject = f"New VIP Request: {display_name}"
        body_lines = [
            f"VIP Name: {display_name}",
            f"Sanitized Name: {vip_record.get('vip_name')}",
            f"Requester Email: {vip_record.get('email')}",
            f"Ports: {', '.join(vip_record.get('ports', []))}",
            f"SSL: {vip_record.get('ssl_enabled')}",
            f"Pool Members: {vip_record.get('pool_members')}",
            f"Request ID: {vip_record.get('id')}",
            f"Created At: {vip_record.get('created_at')}",
            f"please submit the form in the portal: https://vip-portal.example.org:5443/",
        ]
        body = "\n".join(body_lines)

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = EMAIL_FROM
        if ADMIN_CC_EMAIL:
            msg["Cc"] = ADMIN_CC_EMAIL
        msg["To"] = ", ".join(TEAM_NOTIFY_EMAILS)

        recipients = list(TEAM_NOTIFY_EMAILS)
        if ADMIN_CC_EMAIL:
            recipients.append(ADMIN_CC_EMAIL)
        # local_hostname sets the EHLO/HELO name; the relay approves us by this IP.
        with smtplib.SMTP(smtp_host, smtp_port, local_hostname="[192.0.2.50]") as server:
            server.sendmail(msg["From"], recipients, msg.as_string())

        logger.info("Team notification email sent to %s", TEAM_NOTIFY_EMAILS)
    except Exception as e:
        logger.warning("Failed to send team notification email via %s:%s -> %s: %s", smtp_host, smtp_port, TEAM_NOTIFY_EMAILS, e)


def send_requester_notification(vip_record: dict, smtp_host: str | None = None, smtp_port: int | None = None) -> None:
    """Email the requester confirming receipt of the VIP request."""
    if not REQUESTER_NOTIFY_ENABLED:
        return
    to_email = vip_record.get("email")
    if not to_email:
        return
    if not is_valid_email(to_email):
        logger.warning("Refusing to send requester notification to invalid address: %r", to_email)
        return
    smtp_host = smtp_host or SMTP_HOST
    smtp_port = smtp_port or SMTP_PORT
    try:
        display_name = _strip_crlf(vip_record.get("vip_name_original") or vip_record.get("vip_name") or "")
        subject = f"VIP Request Received: {display_name}"
        body_lines = [
            "Your VIP request has been received and is pending approval.",
            f"VIP: {display_name}",
            f"Ports: {', '.join(vip_record.get('ports', []))}",
            f"SSL: {vip_record.get('ssl_enabled')}",
            f"Request ID: {vip_record.get('id')}",
        ]
        body = "\n".join(body_lines)

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = EMAIL_FROM
        msg["To"] = to_email

        # local_hostname sets the EHLO/HELO name; the relay approves us by this IP.
        with smtplib.SMTP(smtp_host, smtp_port, local_hostname="[192.0.2.50]") as server:
            server.sendmail(msg["From"], [to_email], msg.as_string())

        logger.info("Requester notification email sent to %s", to_email)
    except Exception as e:
        logger.warning("Failed to send requester notification email via %s:%s -> %s: %s", smtp_host, smtp_port, to_email, e)


def validate_pfx_password(pfx_bytes: bytes, password: str) -> None:
    """
    Validate PFX password locally (if cryptography is available).
    Raises ValueError on failure.
    """
    if not crypto_pkcs12:
        return
    try:
        crypto_pkcs12.load_key_and_certificates(pfx_bytes, password.encode() if password else None)
    except Exception as e:
        raise ValueError("Invalid PFX password or corrupted PFX file") from e


def _x509_to_metadata(cert) -> dict:
    """Convert a cryptography x509 cert into a JSON-safe metadata dict."""
    from cryptography.x509.oid import NameOID, ExtensionOID

    def _name_to_str(name):
        try:
            return name.rfc4514_string()
        except Exception:
            return str(name)

    def _cn(name):
        try:
            attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
            return attrs[0].value if attrs else ""
        except Exception:
            return ""

    sans: list = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for n in ext.value:
            try:
                sans.append(n.value if hasattr(n, "value") else str(n))
            except Exception:
                sans.append(str(n))
    except Exception:
        pass

    try:
        not_after = cert.not_valid_after_utc.isoformat()
    except AttributeError:
        not_after = cert.not_valid_after.isoformat()
    try:
        not_before = cert.not_valid_before_utc.isoformat()
    except AttributeError:
        not_before = cert.not_valid_before.isoformat()

    return {
        "commonName": _cn(cert.subject),
        "subject": _name_to_str(cert.subject),
        "issuer": _name_to_str(cert.issuer),
        "notBefore": not_before,
        "notAfter": not_after,
        "sans": sans,
        "serialNumber": format(cert.serial_number, "x"),
    }


def parse_pfx_cert_info(pfx_bytes: bytes, password: str) -> dict:
    """Parse a PFX and return cert metadata."""
    if not crypto_pkcs12:
        raise RuntimeError("cryptography library not available")
    try:
        _key, cert, _chain = crypto_pkcs12.load_key_and_certificates(
            pfx_bytes, password.encode() if password else None
        )
    except Exception as e:
        raise ValueError(f"Invalid PFX or password: {e}")
    if cert is None:
        raise ValueError("PFX contains no certificate")
    return _x509_to_metadata(cert)


def f5_cert_response_to_dict(f5_cert: dict) -> dict:
    """Convert F5's /mgmt/tm/sys/file/ssl-cert response into our metadata format."""
    sans_raw = f5_cert.get("subjectAlternativeName", "") or ""
    sans = []
    if sans_raw:
        for part in sans_raw.split(","):
            part = part.strip()
            if part:
                sans.append(part)
    subject = f5_cert.get("subject", "")
    cn = ""
    for piece in subject.split(","):
        piece = piece.strip()
        if piece.upper().startswith("CN="):
            cn = piece[3:]
            break
    exp_date = f5_cert.get("expirationDate")
    not_after_iso = ""
    if exp_date:
        try:
            not_after_iso = datetime.utcfromtimestamp(int(exp_date)).isoformat() + "Z"
        except Exception:
            not_after_iso = f5_cert.get("expirationString", "") or ""
    return {
        "commonName": cn,
        "subject": subject,
        "issuer": f5_cert.get("issuer", ""),
        "notBefore": f5_cert.get("createTime", ""),
        "notAfter": not_after_iso or f5_cert.get("expirationString", ""),
        "sans": sans,
        "name": f5_cert.get("name", ""),
        "fullPath": f5_cert.get("fullPath", ""),
    }


def sanitize_vip_name(name: str) -> str:
    """
    Normalize pasted host/url input into a VIP-safe name.
    Removes protocol prefixes and any path/query/fragment parts, then keeps
    only letters, digits, and dots after lowercasing and removing hyphens.
    """
    name = re.sub(r"^https?://", "", name.strip(), flags=re.IGNORECASE)
    name = re.split(r"[/?#]", name, maxsplit=1)[0]
    name = name.lower()
    name = name.replace("-", "")
    return re.sub(r"[^a-z0-9\.]", "", name)


# ---------------------------
# Cert-replace-by-VIP helpers (DNS -> IP, FQDN naming, VIP discovery)
# ---------------------------

def looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except Exception:
        return False


def resolve_vip_to_ip(value: str) -> str:
    """Accept an IP or a DNS name and return an IPv4 address string.
    Raises ValueError if a hostname cannot be resolved."""
    v = (value or "").strip()
    # Strip scheme/path if a URL was pasted.
    v = re.sub(r"^https?://", "", v, flags=re.IGNORECASE)
    v = re.split(r"[/?#]", v, maxsplit=1)[0]
    v = v.strip().rstrip(".")
    if not v:
        raise ValueError("Empty VIP address")
    if looks_like_ip(v):
        return v
    try:
        return socket.gethostbyname(v)
    except Exception as e:
        raise ValueError(f"Could not resolve '{v}' to an IP: {e}")


def cert_object_name(fqdn: str, expire_year) -> str:
    """Build the F5 cert/key object name: <fqdn>_<year>. Wildcards (*.x) become
    'wildcard.x' and any char F5 disallows in an object name is normalized."""
    f = (fqdn or "").strip().lower().rstrip(".")
    if f.startswith("*."):
        f = "wildcard." + f[2:]
    f = f.replace("*", "wildcard")
    f = re.sub(r"[^a-z0-9\.\-]", "_", f)
    year = re.sub(r"[^0-9]", "", str(expire_year))
    return f"{f}_{year}" if year else f


def _vs_destination_ip(vs: dict) -> str | None:
    m = re.match(r"^/[^/]+/([0-9.]+):(\d+|any)$", vs.get("destination", "") or "")
    return m.group(1) if m else None


def find_vip_clientssl_by_ip(ip: str, only_target: str | None = None, profile_hint: str | None = None) -> dict:
    """Using the READ-ONLY service account, locate the VIP whose destination IP
    matches `ip` and the client-SSL profile bound to it.

    Returns {"env_id","env_name","base_url","vs_names",
             "clientssl_profiles":[fullPath,...],"profile": chosen-or-None}.
    Raises RuntimeError with a clear message when nothing/too-much matches."""
    sess = get_read_session("cert-api-discovery")  # read service account
    environments = sess.get("environments", {})
    if not environments:
        raise RuntimeError("Read-only service account has no authenticated F5 environments")

    matches = []  # list of dicts per env that has a VS on this IP
    for env_id, es in environments.items():
        if only_target and env_id != only_target:
            continue
        base_url = es.get("url")
        token = es.get("token")
        if not base_url or not token:
            continue
        f5 = F5Client(base_url=base_url, username="x", password="x", verify_ssl=False)
        f5.token = token
        f5.session.headers.update({"X-F5-Auth-Token": token})
        try:
            virtuals = f5.list_virtuals()
        except Exception as e:
            logger.warning("discovery: list_virtuals failed for %s: %s", env_id, e)
            continue
        vs_on_ip = [vs for vs in virtuals if _vs_destination_ip(vs) == ip]
        if not vs_on_ip:
            continue
        # Which profiles on those VSs are client-SSL profiles?
        try:
            clientssl_names = set()
            for prof in f5.list_clientssl_profiles():
                for k in (prof.get("name"), prof.get("fullPath")):
                    if k:
                        clientssl_names.add(k)
        except Exception as e:
            logger.warning("discovery: list_clientssl_profiles failed for %s: %s", env_id, e)
            clientssl_names = set()

        found_profiles = []
        vs_names = []
        for vs in vs_on_ip:
            vs_names.append(vs.get("name", ""))
            for p in (vs.get("profilesReference", {}) or {}).get("items", []) or []:
                pn = p.get("name")
                pfp = p.get("fullPath") or (f"/Common/{pn}" if pn else "")
                if pn in clientssl_names or pfp in clientssl_names:
                    if pfp and pfp not in found_profiles:
                        found_profiles.append(pfp)
        matches.append({
            "env_id": env_id,
            "env_name": es.get("name", env_id),
            "base_url": base_url,
            "vs_names": vs_names,
            "clientssl_profiles": found_profiles,
        })

    if not matches:
        raise RuntimeError(f"No virtual server found for IP {ip} in the configured F5 environment(s)")
    if len(matches) > 1:
        envs = ", ".join(m["env_id"] for m in matches)
        raise RuntimeError(f"IP {ip} matched virtual servers in multiple environments ({envs}); pass 'target' to disambiguate")

    match = matches[0]
    profiles = match["clientssl_profiles"]
    chosen = None
    if profile_hint:
        hint = profile_hint if profile_hint.startswith("/") else f"/Common/{profile_hint}"
        if hint in profiles or profile_hint in [p.split("/")[-1] for p in profiles]:
            chosen = hint if hint in profiles else next(p for p in profiles if p.split("/")[-1] == profile_hint)
        else:
            raise RuntimeError(f"profile '{profile_hint}' is not a client-SSL profile on VIP {ip} (found: {profiles or 'none'})")
    elif len(profiles) == 1:
        chosen = profiles[0]
    elif len(profiles) == 0:
        raise RuntimeError(f"VIP {ip} has no client-SSL profile to replace")
    else:
        raise RuntimeError(f"VIP {ip} has multiple client-SSL profiles {profiles}; pass 'profile' to choose one")

    match["profile"] = chosen
    return match


# ---------------------------
# iRule text manipulation + versioning (pure helpers, no F5 calls)
# ---------------------------
# These power the "port 0 / port-list + switch iRule" add-port path: a single
# virtual server listens on all ports and a `switch [TCP::local_port]` iRule
# dispatches each port to its own pool. Adding a port means inserting a new
# switch case (not creating another VS). Versioning keeps each edit as its own
# F5 object (<vip>_irule_vN) so an admin can roll back.

_IRULE_LOCAL_PORT_RE = re.compile(r"switch\b[^\n{]*\[TCP::local_port\]", re.IGNORECASE)


def _find_switch_block(body: str) -> tuple[int | None, int | None]:
    """Locate the `switch ... [TCP::local_port] { ... }` block. Returns the
    (open_brace_index, close_brace_index) of the block body, or (None, None).
    Brace matching is naive (it doesn't skip braces inside quotes/comments),
    which is fine for the controlled iRule shape we generate and read."""
    m = _IRULE_LOCAL_PORT_RE.search(body)
    if not m:
        return None, None
    brace_start = body.find("{", m.end())
    if brace_start == -1:
        return None, None
    depth = 0
    for i in range(brace_start, len(body)):
        c = body[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return brace_start, i
    return None, None


def parse_switch_ports(body: str) -> set[str]:
    """Return the set of ports already cased in the switch on [TCP::local_port]."""
    start, end = _find_switch_block(body)
    if start is None:
        return set()
    inner = body[start + 1:end]
    return {m.group(1) for m in re.finditer(r'(?m)^\s*"?(\d+)"?\s*\{', inner)}


def add_switch_case(body: str, port, pool_path: str) -> str:
    """Insert a `"<port>" { pool <pool_path> }` case immediately before the
    `default` arm of the [TCP::local_port] switch, preserving indentation.

    Raises if the iRule has no such switch, has no default arm, or already has a
    case for this port — so we never silently corrupt or duplicate a rule."""
    port = str(port)
    start, end = _find_switch_block(body)
    if start is None:
        raise RuntimeError("iRule has no switch on [TCP::local_port]; cannot add a port case")
    if port in parse_switch_ports(body):
        raise RuntimeError(f"Port {port} already has a case in the iRule")
    inner = body[start + 1:end]
    dm = re.search(r'(?m)^([ \t]*)default\b[^\n]*\{', inner)
    if not dm:
        raise RuntimeError("iRule switch has no default arm; refusing to edit")
    indent = dm.group(1)
    case_text = f'{indent}"{port}" {{\n{indent}    pool {pool_path}\n{indent}}}\n'
    insert_at = start + 1 + dm.start()
    return body[:insert_at] + case_text + body[insert_at:]


def parse_switch_cases(body: str) -> list[dict]:
    """Parse a [TCP::local_port] switch into ordered dispatch entries:
    [{"port": "443", "pool": "/Common/x-443-pool", "condition": "TCP::local_port == 443"}].
    The `default` arm is included (port="default") when it routes to a pool, so
    the status view can show the fallback too. Used by the status page to map
    each port to the pool the iRule sends it to."""
    start, end = _find_switch_block(body)
    if start is None:
        return []
    inner = body[start + 1:end]
    cases = []
    for m in re.finditer(r'(?ms)^\s*"?(\d+)"?\s*\{(.*?)\}', inner):
        label, block = m.group(1), m.group(2)
        pm = re.search(r'\bpool\s+(\S+)', block)
        cases.append({
            "port": label,
            "pool": (pm.group(1) if pm else ""),
            "condition": f"TCP::local_port == {label}",
        })
    dm = re.search(r'(?ms)^\s*default\s*\{(.*?)\}', inner)
    if dm:
        pm = re.search(r'\bpool\s+(\S+)', dm.group(1))
        if pm:
            cases.append({
                "port": "default",
                "pool": pm.group(1),
                "condition": "no port match (default)",
            })
    return cases


def _pool_key(value: str) -> str:
    """Bare pool name from a path/name (mirrors F5StatusHandler.pool_key)."""
    return (value or "").strip().lstrip("/").split("/")[-1]


def _nearest_irule_condition(body: str, pos: int) -> str:
    """Best-effort: describe the branch a `pool` statement sits in, for non-switch
    iRules (standard if/elseif/else). Looks back from `pos` for the closest
    if/elseif/else and returns a short human-readable condition string."""
    prefix = body[:pos]
    best_idx = -1
    best = ""
    for m in re.finditer(r'(?:\}\s*)?(else\s+if|elseif|if)\s*\{([^{}]*)\}', prefix):
        if m.start() > best_idx:
            best_idx = m.start()
            best = f"if {m.group(2).strip()}"
    # An `else {` after the last if/elseif means the pool is in the else branch.
    em = None
    for m in re.finditer(r'\}\s*else\s*\{', prefix):
        em = m
    if em is not None and em.start() > best_idx:
        return "else (no match above)"
    return best or "via iRule"


def parse_irule_dispatch(body: str) -> list[dict]:
    """Return every pool an iRule can route to, with a best-effort condition.
    Switch [TCP::local_port] cases keep their precise port + condition; any other
    `pool <name>` reference (if/elseif/else or standalone) is reported with
    port="" and the nearest branch condition. Lets the status view show pools
    that aren't selected by a port switch."""
    cases = parse_switch_cases(body)
    covered = {_pool_key(c["pool"]) for c in cases if c["pool"]}
    # `pool` selects a pool; ignore "pool" appearing as a word elsewhere by
    # requiring a following object-name-ish token.
    for m in re.finditer(r'\bpool\s+(/?[\w.\-/]+)', body):
        pool = m.group(1).rstrip(";")
        pk = _pool_key(pool)
        if not pk or pk in covered:
            continue
        covered.add(pk)
        cases.append({
            "port": "",
            "pool": pool,
            "condition": _nearest_irule_condition(body, m.start()),
        })
    return cases


def build_switch_irule(cases: list[tuple], default_pool: str | None = None) -> str:
    """Build a fresh CLIENT_ACCEPTED switch iRule from (port, pool_path) cases.
    Used to seed v1 when a port-0 VIP has no iRule yet. If default_pool is set,
    unmatched ports fall through to it; otherwise they are logged and rejected."""
    lines = ["when CLIENT_ACCEPTED {", "    switch -glob [TCP::local_port] {"]
    for port, pool in cases:
        lines.append(f'        "{port}" {{')
        lines.append(f'            pool {pool}')
        lines.append("        }")
    lines.append("        default {")
    if default_pool:
        lines.append(f"            pool {default_pool}")
    else:
        lines.append('            log local0. "no pool for [TCP::local_port]"')
        lines.append("            reject")
    lines.append("        }")
    lines.append("    }")
    lines.append("}")
    return "\n".join(lines)


def irule_base_name(vip_name: str) -> str:
    """Base name for a VIP's versioned iRule objects: <vip>_irule."""
    return f"{vip_name}_irule"


def irule_version_of(name: str, base: str) -> int | None:
    """Extract N from a <base>_vN object name/path, or None if it doesn't match."""
    bare = name.split("/")[-1]
    m = re.match(re.escape(base) + r"_v(\d+)$", bare)
    return int(m.group(1)) if m else None


def next_irule_version(existing_names, base: str) -> int:
    """Given existing iRule object names, return the next version number for
    <base>_vN (1 if none exist yet)."""
    max_n = 0
    for nm in existing_names:
        n = irule_version_of(nm, base)
        if n is not None:
            max_n = max(max_n, n)
    return max_n + 1


# ---------------------------
# Helpers & validation
# ---------------------------

def is_valid_ipv4(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except Exception:
        return False


def is_valid_port(port: str) -> bool:
    try:
        p = int(port)
        return 1 <= p <= 65535
    except Exception:
        return False


def detect_f5_target(pool_members: list) -> tuple:
    """
    Auto-detect the F5 environment based on pool member IP addresses.

    Returns: (target: str, f5_url: str)
    Raises: RuntimeError if IPs don't match any known network
    """
    if not pool_members:
        raise RuntimeError("No pool members provided for F5 target detection")

    env_networks = []
    for env in F5_ENVIRONMENTS:
        networks = [ipaddress.IPv4Network(cidr, strict=False) for cidr in env.get("member_networks", [])]
        if networks:
            env_networks.append((env, networks))

    if not env_networks:
        raise RuntimeError(
            "No member_networks are configured for any F5 environment. "
            "Add them to f5_environments.json so the backend can auto-detect a target."
        )

    detected_target = None

    for member in pool_members:
        ip_str = member.get("ip_address", "")
        try:
            ip = ipaddress.IPv4Address(ip_str)

            matches = [env for env, networks in env_networks if any(ip in network for network in networks)]
            if not matches:
                known = ", ".join(
                    f"{env['name']}({', '.join(env.get('member_networks', []))})"
                    for env in F5_ENVIRONMENTS
                    if env.get("member_networks")
                )
                raise RuntimeError(
                    f"Pool member IP {ip_str} does not match any configured environment network. "
                    f"Known networks: {known}"
                )
            if len(matches) > 1:
                raise RuntimeError(
                    f"Pool member IP {ip_str} matches multiple environments: "
                    + ", ".join(env["name"] for env in matches)
                )

            match = matches[0]
            if detected_target and detected_target["id"] != match["id"]:
                raise RuntimeError(
                    "Mixed pool members across environments: "
                    f"{detected_target['name']} and {match['name']}. Cannot auto-detect target."
                )
            detected_target = match
        except ipaddress.AddressValueError:
            raise RuntimeError(f"Invalid IP address: {ip_str}")

    if not detected_target:
        raise RuntimeError("Could not detect F5 target from pool members")

    f5_url = get_environment_active_url(detected_target)
    logger.info("Auto-detected F5 target: %s (%s) -> %s", detected_target["id"], detected_target["name"], f5_url)

    return detected_target["id"], f5_url


# ---------------------------
# Token management helpers
# ---------------------------

# Hard cap BIG-IP puts on an auth token's timeout (10 hours).
F5_TOKEN_MAX_TIMEOUT = 36000


class F5AuthError(RuntimeError):
    """The F5 rejected our auth token (expired/revoked). Callers should
    surface this as a 401 so the user re-logs in instead of seeing empty
    data."""


class SnatPoolConflict(RuntimeError):
    """A SNAT pool with the name we want already exists but points at a
    different address. Never fatal: the SNAT resolver treats the address as
    taken and moves on to the next candidate (or automap)."""


def extend_f5_token_timeout(f5_url: str, f5_token: str, seconds: int) -> None:
    """Extend an F5 auth token's lifetime on the device. Tokens from
    /mgmt/shared/authn/login default to the device's token timeout (often 20
    minutes or less) regardless of the portal session TTL, so without this the
    stored per-environment tokens die long before the portal token does.
    Best-effort: on failure the device default applies."""
    timeout = max(60, min(int(seconds), F5_TOKEN_MAX_TIMEOUT))
    try:
        resp = request_with_log(
            "PATCH",
            f"{f5_url.rstrip('/')}/mgmt/shared/authz/tokens/{f5_token}",
            json={"timeout": timeout},
            headers={"X-F5-Auth-Token": f5_token},
            verify=False,
            timeout=10,
        )
        if resp.status_code == 200:
            logger.info("Extended F5 token lifetime to %ds", timeout)
        else:
            logger.warning(
                "Could not extend F5 token lifetime (%s): %.200s — device default TTL applies",
                resp.status_code,
                resp.text,
            )
    except requests.RequestException as e:
        logger.warning("F5 token lifetime extension failed: %s — device default TTL applies", e)


def authenticate_with_f5(f5_url: str, username: str, password: str, extend_to: int | None = None) -> str:
    """
    Authenticate with F5 and get a token.
    Returns the F5 token if successful.
    extend_to: desired token lifetime in seconds; the device default (often
    20 min or less) is used when None.
    """
    try:
        login_url = f"{f5_url.rstrip('/')}/mgmt/shared/authn/login"
        payload = {
            "username": username,
            "password": password,
            "loginProviderName": "tmos"
        }
        
        response = request_with_log(
            "POST",
            login_url,
            json=payload,
            verify=False,  # Self-signed certs
            timeout=10
        )
        if response.status_code not in (200, 201):
            logger.error("F5 login failed: %s - %s", response.status_code, response.text)
            raise RuntimeError(f"F5 authentication failed: {response.status_code}")
        
        data = response.json()
        # F5 returns token in response.token field
        f5_token = data.get("token", {}).get("token") or data.get("token")
        
        if not f5_token:
            logger.error("No token in F5 response: %s", data)
            raise RuntimeError("F5 did not return a token")
        
        logger.info("Successfully authenticated with F5")
        if extend_to:
            extend_f5_token_timeout(f5_url, f5_token, extend_to)
        return f5_token

    except requests.RequestException as e:
        logger.error("F5 connection error: %s", e)
        raise RuntimeError(f"Failed to connect to F5: {str(e)}")

def get_active_f5_url(f5_nodes: list[str], timeout: int = 5) -> str | None:
    """
    Iterate F5 nodes and return the first active one.
    Uses /mgmt/tm/sys/failover and checks for 'active' in apiAnonymous output.
    """
    for node_url in f5_nodes:
        try:
            resp = request_with_log(
                "GET",
                f"{node_url.rstrip('/')}/mgmt/tm/sys/failover",
                verify=False,
                timeout=timeout,
            )
            if resp.status_code != 200:
                logger.warning("Failover check failed for %s: %s", node_url, resp.status_code)
                continue
            data = resp.json()
            api_raw = data.get("apiRawValues", {}).get("apiAnonymous", "")
            if "active" in api_raw.lower():
                logger.info("Active F5 detected: %s", node_url)
                return node_url
        except Exception as e:
            logger.warning("Failover check error for %s: %s", node_url, e)
    return None

def generate_token() -> str:
    """Generate a secure random token."""
    return secrets.token_urlsafe(32)

def create_admin_token(environments: dict, username: str, role: str = "admin") -> str:
    """
    Create and store a portal token linked to the authenticated F5 environments.
    Returns the portal token. Portal login is admin-only; the role stays on the
    token so every authorization check has it.
    """
    portal_token = generate_token()
    TOKEN_STORE[portal_token] = {
        "environments": environments,
        "username": username,
        "role": role,
        "created_at": time.time(),
    }
    logger.info(
        "Created portal token for user %s across environments: %s (ttl=%ds)",
        username,
        ", ".join(sorted(environments.keys())),
        ADMIN_TOKEN_TTL,
    )
    return portal_token

def validate_token(token: str) -> dict | None:
    """
    Check if a token is valid and not expired.
    Returns token data (environments, username, created_at) if valid, None otherwise.
    Expired tokens are removed from the store.
    """
    data = TOKEN_STORE.get(token)
    if not data:
        return None
    if ADMIN_TOKEN_TTL > 0:
        created = data.get("created_at", 0)
        if time.time() - created > ADMIN_TOKEN_TTL:
            logger.info(
                "Token expired for user %s (age %ds > ttl %ds)",
                data.get("username"),
                int(time.time() - created),
                ADMIN_TOKEN_TTL,
            )
            TOKEN_STORE.pop(token, None)
            return None
    return data

def clear_token(token: str) -> None:
    """Invalidate a token."""
    if token in TOKEN_STORE:
        data = TOKEN_STORE[token]
        del TOKEN_STORE[token]
        logger.info("Token cleared for user: %s", data.get("username"))


def get_token_environment(token_data: dict, target: str) -> tuple[dict, dict]:
    env = get_environment_by_id(target)
    env_session = (token_data.get("environments") or {}).get(env["id"]) or {}
    return env, env_session


def iter_token_environments(token_data: dict, only_target: str | None = None):
    environments = [get_environment_by_id(only_target)] if only_target else F5_ENVIRONMENTS
    env_sessions = token_data.get("environments") or {}
    for env in environments:
        yield env, (env_sessions.get(env["id"]) or {})


class BaseHandler(tornado.web.RequestHandler):
    # Allow only configured origins. If ALLOWED_ORIGINS is empty we fall back to
    # "*" (legacy behavior, logged at startup) so existing deployments don't break.
    def set_default_headers(self):
        origin = self.request.headers.get("Origin", "")
        if ALLOWED_ORIGINS:
            if origin in ALLOWED_ORIGINS:
                self.set_header("Access-Control-Allow-Origin", origin)
                self.set_header("Vary", "Origin")
                self.set_header("Access-Control-Allow-Credentials", "true")
            # else: do not set ACAO header → browser blocks the response.
        else:
            self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def prepare(self):
        self._request_started_at = time.perf_counter()

    def on_finish(self):
        started_at = getattr(self, "_request_started_at", None)
        elapsed_ms = (time.perf_counter() - started_at) * 1000 if started_at else None
        path = _mask_url_for_log(self.request.uri)
        client_ip = self.get_client_ip()
        if elapsed_ms is None:
            api_logger.info("Tornado %s %s -> %s client=%s", self.request.method, path, self.get_status(), client_ip)
        else:
            api_logger.info(
                "Tornado %s %s -> %s %.1fms client=%s",
                self.request.method,
                path,
                self.get_status(),
                elapsed_ms,
                client_ip,
            )

    def options(self, *args, **kwargs):
        self.set_status(204)
        self.finish()
    
    def get_auth_token(self) -> str | None:
        """Extract Bearer token from Authorization header."""
        auth_header = self.request.headers.get("Authorization", "")
        logger.debug("Authorization header: %s", auth_header)
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]  # Remove "Bearer " prefix
            logger.debug("Extracted token: %s...", token[:20] if token else None)
            return token
        logger.debug("No Bearer token found in Authorization header")
        return None

    def get_f5_basic_credentials(self) -> tuple[str, str] | None:
        """Parse `Authorization: Basic <base64(user:pass)>` into (username,
        password). These are the caller's OWN F5 credentials; the app uses them
        to authenticate to F5 and perform the write as that user. Returns None
        when the header is missing or malformed."""
        auth_header = self.request.headers.get("Authorization", "")
        if not auth_header.lower().startswith("basic "):
            return None
        try:
            raw = base64.b64decode(auth_header[6:].strip()).decode("utf-8")
        except Exception:
            return None
        if ":" not in raw:
            return None
        username, password = raw.split(":", 1)
        if not username or not password:
            return None
        return username, password

    def require_auth(self) -> dict | None:
        """
        Validate token and return token data if authorized, else respond with 401.
        Returns: {"f5_token": "...", "f5_url": "...", "username": "..."}
        """
        token = self.get_auth_token()
        logger.debug("Token from header: %s", token[:20] if token else None)
        logger.debug("TOKEN_STORE keys: %s", list(TOKEN_STORE.keys()))
        token_data = validate_token(token) if token else None
        
        if not token_data:
            logger.warning("Token validation failed for: %s", token[:20] if token else "None")
            self.set_status(401)
            self.write({"success": False, "error": "Unauthorized: Invalid or missing token"})
            return None
        
        logger.debug("Token validated for user: %s", token_data.get("username"))
        return token_data

    # ---------------------------
    # Authentication (F5-login portal token only)
    # ---------------------------
    def get_client_ip(self) -> str:
        """Originating IP for audit logging (the real TCP peer)."""
        return self.request.remote_ip or ""

    def require_auth_unified(self):
        """Authenticate the caller via their F5-login portal token.

        Returns (role, token_data) with role 'admin', or None (and writes a 401)
        on failure. F5 (plus AD-group membership) authorizes the login itself.
        """
        token = self.get_auth_token()
        token_data = validate_token(token) if token else None
        if not token_data:
            self.set_status(401)
            self.write({"success": False, "error": "Unauthorized: please log in with your F5 credentials"})
            return None
        return (token_data.get("role") or "admin", token_data)

    def require_f5_reader(self):
        """Read-only F5 inventory (VIP list, status) also requires a valid login."""
        return self.require_auth_unified()

    def require_admin(self) -> dict | None:
        """Require a valid F5-login token (every logged-in user is an admin)."""
        result = self.require_auth_unified()
        if not result:
            return None
        _role, data = result
        return data


class AdminLoginHandler(BaseHandler):
    """
    POST /admin/login
    Content-Type: application/json
    
    {
      "username": "admin",
      "password": "userpassword"
    }
    
    Returns: { "success": true, "token": "...", "environments": [...] }
    """
    async def post(self):
        client_ip = self.get_client_ip()
        allowed, retry_after = login_throttle_check(client_ip)
        if not allowed:
            self.set_status(429)
            self.set_header("Retry-After", str(retry_after))
            self.write({
                "success": False,
                "error": f"Too many failed login attempts. Try again in {retry_after}s.",
            })
            return
        try:
            data = json.loads(self.request.body.decode("utf-8"))
            username = data.get("username", "").strip()
            password = data.get("password", "").strip()

            if not username or not password:
                login_throttle_record_failure(client_ip)
                self.set_status(400)
                self.write({"success": False, "error": "Username and password required"})
                return

            authenticated_environments = {}
            environment_results = []

            for env in F5_ENVIRONMENTS:
                active_url = get_environment_active_url(env)
                platform = env.get("platform", "f5")
                env_result = {
                    "id": env["id"],
                    "name": env["name"],
                    "platform": platform,
                    "url": active_url,
                    "configured_url": env["url"],
                    "authenticated": False,
                }
                try:
                    logger.info("Attempting %s authentication for user %s on %s", platform, username, env["name"])
                    # Align the F5 token's lifetime with the portal session so
                    # the stored token doesn't die at the device default
                    # (~20 min) while the portal token lives ADMIN_TOKEN_TTL.
                    env_token = authenticate_with_f5(
                        active_url,
                        username,
                        password,
                        extend_to=ADMIN_TOKEN_TTL if ADMIN_TOKEN_TTL > 0 else F5_TOKEN_MAX_TIMEOUT,
                    )
                    authenticated_environments[env["id"]] = {
                        "name": env["name"],
                        "url": active_url,
                        "platform": "f5",
                        "token": env_token,
                    }
                    env_result["authenticated"] = True
                except Exception as e:
                    logger.warning("%s auth failed for %s: %s", env["name"], username, e)
                    env_result["error"] = str(e)
                environment_results.append(env_result)

            if not authenticated_environments:
                login_throttle_record_failure(client_ip)
                self.set_status(401)
                self.write({"success": False, "error": "F5 authentication failed for every configured environment"})
                return

            # F5 (plus AD-group membership) already authorized this login, so any
            # user who authenticates is an admin -- there is no separate allowlist.
            login_throttle_record_success(client_ip)
            assigned_role = "admin"
            portal_token = create_admin_token(authenticated_environments, username, assigned_role)
            logger.info(
                "%s %s logged in to environments: %s",
                assigned_role,
                username,
                ", ".join(sorted(authenticated_environments.keys())),
            )

            audit_log(
                action="admin.login",
                target=username,
                user=username,
                user_type="admin",
                result="success",
                client_ip=self.get_client_ip(),
                revertible=False,
                details={
                    "environments": [
                        {"id": env["id"], "name": env["name"], "authenticated": env["authenticated"]}
                        for env in environment_results
                    ]
                },
            )
            expires_at = (
                int(time.time() + ADMIN_TOKEN_TTL) if ADMIN_TOKEN_TTL > 0 else None
            )
            effective_expires_at = (
                int(expires_at - ADMIN_TOKEN_SAFETY_MARGIN_SECS)
                if expires_at is not None
                else None
            )
            self.write({
                "success": True,
                "token": portal_token,
                "environments": environment_results,
                "expires_at": expires_at,
                "effective_expires_at": effective_expires_at,
                "ttl": ADMIN_TOKEN_TTL if ADMIN_TOKEN_TTL > 0 else None,
                "safety_margin": ADMIN_TOKEN_SAFETY_MARGIN_SECS,
                "message": "Login successful"
            })
        except RuntimeError as e:
            login_throttle_record_failure(client_ip)
            logger.warning("F5 authentication failed: %s", e)
            self.set_status(401)
            self.write({"success": False, "error": str(e)})
        except json.JSONDecodeError:
            login_throttle_record_failure(client_ip)
            self.set_status(400)
            self.write({"success": False, "error": "Invalid JSON in request body"})
        except Exception as e:
            logger.exception("Login error")
            self.set_status(500)
            self.write({"success": False, "error": "Server error during login"})


class AdminLogoutHandler(BaseHandler):
    """
    POST /admin/logout
    Authorization: Bearer <token>
    
    Invalidates the token.
    """
    async def post(self):
        token = self.get_auth_token()
        if token:
            clear_token(token)
        
        self.write({
            "success": True,
            "message": "Logged out successfully"
        })


# ---------------------------
# Simple F5 REST client
# ---------------------------


class F5Client:
    """
    Very simple wrapper around F5 iControl REST.

    You will probably want to expand/adjust this to match your real
    F5 naming conventions, partitions, profiles, etc.
    """

    def __init__(self, base_url: str, username: str, password: str, verify_ssl: bool = False):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.session = LoggingSession()
        self.token = None

    def login(self):
        """
        Get an auth token from F5 (for modern BIG-IP versions).
        If your deployment uses basic auth only, you can skip this
        and just use user/pass in each request.
        """
        url = f"{self.base_url}/mgmt/shared/authn/login"
        payload = {
            "username": self.username,
            "password": self.password,
            "loginProviderName": "tmos"
        }
        resp = self.session.post(url, json=payload, verify=self.verify_ssl)
        resp.raise_for_status()
        data = resp.json()
        self.token = data['token']['token']
        self.session.headers.update({"X-F5-Auth-Token": self.token})

    def ensure_login(self):
        if not self.token:
            self.login()

    def virtual_exists(self, name: str, partition: str = "Common") -> bool:
        """Return True if a virtual server with the given name exists in the partition."""
        self.ensure_login()
        safe_name = name.replace("/", "~")
        url = f"{self.base_url}/mgmt/tm/ltm/virtual/~{partition}~{safe_name}"
        try:
            resp = self.session.get(url, verify=self.verify_ssl)
            return resp.status_code == 200
        except Exception as e:
            logger.warning("virtual_exists check failed for %s: %s", name, e)
            return False

    def list_virtuals(self, partition: str = "Common") -> list:
        """List virtual servers in the given partition.

        Expands attached profiles inline so the caller can see which client-SSL
        (and other) profiles are bound to each VS without N additional GETs.
        """
        self.ensure_login()
        url = f"{self.base_url}/mgmt/tm/ltm/virtual"
        params = {"expandSubcollections": "true"}
        try:
            resp = self.session.get(url, params=params, verify=self.verify_ssl)
            if resp.status_code == 401:
                raise F5AuthError(f"F5 session expired or rejected on {self.base_url}")
            if resp.status_code != 200:
                logger.warning(
                    "list_virtuals failed: %s %s body=%.300s",
                    resp.status_code,
                    url,
                    (resp.text or "").replace("\n", " "),
                )
                # Some older F5 builds reject expandSubcollections — retry without it.
                if resp.status_code == 400 and "expandSubcollections" in (resp.text or ""):
                    logger.info("Retrying list_virtuals without expandSubcollections")
                    resp2 = self.session.get(url, verify=self.verify_ssl)
                    if resp2.status_code == 200:
                        items = resp2.json().get("items", [])
                        return [item for item in items if item.get("partition", partition) == partition]
                return []
            items = resp.json().get("items", [])
            return [item for item in items if item.get("partition", partition) == partition]
        except F5AuthError:
            raise
        except Exception as e:
            logger.warning("list_virtuals error: %s", e)
            return []

    def list_allocated_vip_ips(self) -> set:
        """Every IP already used by a virtual server — for the IP allocator."""
        ips = set()
        self.ensure_login()
        url = f"{self.base_url}/mgmt/tm/ltm/virtual"
        try:
            resp = self.session.get(url, verify=self.verify_ssl)
            if resp.status_code != 200:
                logger.warning("list_allocated_vip_ips failed: %s", resp.status_code)
                return ips
            for item in resp.json().get("items", []):
                destination = item.get("destination", "")
                if "/" in destination:
                    ip_part = destination.split("/")[-1].split(":")[0]
                    try:
                        ipaddress.IPv4Address(ip_part)
                        ips.add(ip_part)
                    except ipaddress.AddressValueError:
                        pass
        except Exception as e:
            logger.warning("list_allocated_vip_ips error: %s", e)
        return ips

    def list_pools(self, partition: str = "Common") -> list:
        """List pools once so callers can read pool config without per-pool GETs."""
        self.ensure_login()
        url = f"{self.base_url}/mgmt/tm/ltm/pool"
        try:
            resp = self.session.get(url, verify=self.verify_ssl)
            if resp.status_code != 200:
                logger.warning("list_pools failed: %s", resp.status_code)
                return []
            items = resp.json().get("items", [])
            return [item for item in items if item.get("partition", partition) == partition]
        except Exception as e:
            logger.warning("list_pools error: %s", e)
            return []

    def get_clientssl_profile(self, name: str, partition: str = "Common") -> dict | None:
        """Fetch a client-SSL profile. Accepts bare name or /partition/name."""
        self.ensure_login()
        n = name.lstrip("/")
        if "/" in n:
            parts = n.split("/")
            part, bare = parts[0], parts[-1]
        else:
            part, bare = partition, n
        url = f"{self.base_url}/mgmt/tm/ltm/profile/client-ssl/~{part}~{bare}"
        try:
            resp = self.session.get(url, verify=self.verify_ssl)
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            logger.warning("get_clientssl_profile error for %s: %s", name, e)
        return None

    def get_ssl_cert(self, name: str, partition: str = "Common") -> dict | None:
        """Fetch SSL cert metadata. Accepts bare name or /partition/name."""
        self.ensure_login()
        n = name.lstrip("/")
        if "/" in n:
            parts = n.split("/")
            part, bare = parts[0], parts[-1]
        else:
            part, bare = partition, n
        url = f"{self.base_url}/mgmt/tm/sys/file/ssl-cert/~{part}~{bare}"
        try:
            resp = self.session.get(url, verify=self.verify_ssl)
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            logger.warning("get_ssl_cert error for %s: %s", name, e)
        return None

    def list_clientssl_profiles(self) -> list:
        """List every client-SSL profile in ONE call (name/fullPath + cert/key),
        so the cache can map each VIP's profile to its bound certificate without
        per-profile round trips."""
        self.ensure_login()
        url = f"{self.base_url}/mgmt/tm/ltm/profile/client-ssl"
        try:
            resp = self.session.get(url, verify=self.verify_ssl)
            if resp.status_code != 200:
                logger.warning("list_clientssl_profiles failed: %s", resp.status_code)
                return []
            return resp.json().get("items", []) or []
        except Exception as e:
            logger.warning("list_clientssl_profiles error: %s", e)
            return []

    def list_ssl_certs(self) -> list:
        """List every installed SSL cert in ONE call (metadata incl. expiry)."""
        self.ensure_login()
        url = f"{self.base_url}/mgmt/tm/sys/file/ssl-cert"
        try:
            resp = self.session.get(url, verify=self.verify_ssl)
            if resp.status_code != 200:
                logger.warning("list_ssl_certs failed: %s", resp.status_code)
                return []
            return resp.json().get("items", []) or []
        except Exception as e:
            logger.warning("list_ssl_certs error: %s", e)
            return []

    def update_clientssl_profile_cert(
        self,
        profile_name: str,
        cert_name: str,
        key_name: str,
        partition: str = "Common",
    ) -> dict:
        """PATCH a client-SSL profile to point at new cert/key."""
        self.ensure_login()
        n = profile_name.lstrip("/")
        if "/" in n:
            parts = n.split("/")
            part, bare = parts[0], parts[-1]
        else:
            part, bare = partition, n
        if not cert_name.startswith("/"):
            cert_name = f"/{partition}/{cert_name}"
        if not key_name.startswith("/"):
            key_name = f"/{partition}/{key_name}"
        url = f"{self.base_url}/mgmt/tm/ltm/profile/client-ssl/~{part}~{bare}"
        payload = {"cert": cert_name, "key": key_name}
        resp = self.session.patch(url, json=payload, verify=self.verify_ssl)
        if resp.status_code not in (200, 201):
            raise RuntimeError(
                f"Failed to update client-SSL profile {profile_name}: "
                f"{resp.status_code} {resp.text}"
            )
        try:
            return resp.json()
        except Exception:
            return {}

    def attach_profile_to_vs(
        self,
        vs_name: str,
        profile_name: str,
        context: str = "clientside",
        partition: str = "Common",
    ) -> dict:
        """Attach a profile to a virtual server. Idempotent: 409 is treated as success."""
        self.ensure_login()
        vs_bare = vs_name.lstrip("/").split("/")[-1]
        prof_bare = profile_name.lstrip("/").split("/")[-1]
        url = f"{self.base_url}/mgmt/tm/ltm/virtual/~{partition}~{vs_bare}/profiles"
        payload = {"name": prof_bare, "context": context}
        resp = self.session.post(url, json=payload, verify=self.verify_ssl)
        if resp.status_code in (200, 201):
            try:
                return resp.json()
            except Exception:
                return {}
        if resp.status_code == 409:
            logger.info("Profile %s already attached to %s", profile_name, vs_name)
            return {}
        raise RuntimeError(
            f"Failed to attach profile {profile_name} to {vs_name}: "
            f"{resp.status_code} {resp.text}"
        )

    def detach_profile_from_vs(
        self,
        vs_name: str,
        profile_name: str,
        partition: str = "Common",
    ) -> bool:
        """Remove a profile from a VS. Returns True if removed (or already absent)."""
        self.ensure_login()
        vs_bare = vs_name.lstrip("/").split("/")[-1]
        prof_bare = profile_name.lstrip("/").split("/")[-1]
        url = f"{self.base_url}/mgmt/tm/ltm/virtual/~{partition}~{vs_bare}/profiles/~{partition}~{prof_bare}"
        try:
            resp = self.session.delete(url, verify=self.verify_ssl)
            if resp.status_code in (200, 204):
                return True
            if resp.status_code == 404:
                return True
            logger.warning("detach_profile_from_vs %s from %s: %s %s", profile_name, vs_name, resp.status_code, resp.text)
            return False
        except Exception as e:
            logger.warning("detach_profile_from_vs error: %s", e)
            return False

    def delete_virtual(self, name: str, partition: str = "Common") -> bool:
        """Delete a virtual server. Treats 404 as success."""
        self.ensure_login()
        bare = name.lstrip("/").split("/")[-1]
        url = f"{self.base_url}/mgmt/tm/ltm/virtual/~{partition}~{bare}"
        resp = self.session.delete(url, verify=self.verify_ssl)
        if resp.status_code in (200, 204, 404):
            return True
        raise RuntimeError(f"Failed to delete VS {name}: {resp.status_code} {resp.text}")

    def delete_pool(self, name: str, partition: str = "Common") -> bool:
        """Delete a pool. Treats 404 as success."""
        self.ensure_login()
        bare = name.lstrip("/").split("/")[-1]
        url = f"{self.base_url}/mgmt/tm/ltm/pool/~{partition}~{bare}"
        resp = self.session.delete(url, verify=self.verify_ssl)
        if resp.status_code in (200, 204, 404):
            return True
        raise RuntimeError(f"Failed to delete pool {name}: {resp.status_code} {resp.text}")

    def delete_monitor(self, name: str, monitor_type: str = "tcp", partition: str = "Common") -> bool:
        """Delete a monitor. Treats 404 as success."""
        self.ensure_login()
        bare = name.lstrip("/").split("/")[-1]
        url = f"{self.base_url}/mgmt/tm/ltm/monitor/{monitor_type}/~{partition}~{bare}"
        resp = self.session.delete(url, verify=self.verify_ssl)
        if resp.status_code in (200, 204, 404):
            return True
        raise RuntimeError(f"Failed to delete monitor {name}: {resp.status_code} {resp.text}")

    def delete_clientssl_profile(self, name: str, partition: str = "Common") -> bool:
        """Delete a client-SSL profile. Treats 404 as success."""
        self.ensure_login()
        bare = name.lstrip("/").split("/")[-1]
        url = f"{self.base_url}/mgmt/tm/ltm/profile/client-ssl/~{partition}~{bare}"
        resp = self.session.delete(url, verify=self.verify_ssl)
        if resp.status_code in (200, 204, 404):
            return True
        raise RuntimeError(f"Failed to delete client-ssl profile {name}: {resp.status_code} {resp.text}")

    def delete_irule(self, name: str, partition: str = "Common") -> bool:
        """Delete an LTM iRule. Treats 404 as success. Fails (by F5) if the rule
        is still attached to a virtual server, so callers must detach first."""
        self.ensure_login()
        bare = name.lstrip("/").split("/")[-1]
        url = f"{self.base_url}/mgmt/tm/ltm/rule/~{partition}~{bare}"
        resp = self.session.delete(url, verify=self.verify_ssl)
        if resp.status_code in (200, 204, 404):
            return True
        raise RuntimeError(f"Failed to delete iRule {name}: {resp.status_code} {resp.text}")

    def get_pool_members_stats(self, pool_name: str, partition: str = "Common") -> list:
        """Return pool members with their health state (up/down/unknown).

        Captures three flavors of identity since F5 versions differ on which
        fields they populate in `nestedStats.entries`:
          - name  : tmName from stats, falls back to the URL key tail and finally <addr>:<port>
          - ip    : addr from stats, falls back to parsing the name
          - port  : port from stats, falls back to parsing the name
        """
        self.ensure_login()
        bare = pool_name.lstrip("/").split("/")[-1]
        url = f"{self.base_url}/mgmt/tm/ltm/pool/~{partition}~{bare}/members/stats"
        try:
            resp = self.session.get(url, verify=self.verify_ssl)
            if resp.status_code != 200:
                return []
            data = resp.json()
            members = []
            for full_key, item in (data.get("entries") or {}).items():
                stats = (item.get("nestedStats") or {}).get("entries") or {}

                def _val(k):
                    v = stats.get(k) or {}
                    # F5 returns strings under "description" and numbers under "value"
                    return v.get("description", v.get("value", ""))

                name = _val("tmName")
                addr = _val("addr")
                port = _val("port")
                if not name:
                    # F5 stats entry keys look like
                    # https://localhost/mgmt/tm/ltm/pool/~Common~mypool/members/~Common~10.0.0.5:443/stats
                    # Pull the segment between the last "/members/" and "/stats".
                    try:
                        tail = full_key.rsplit("/members/", 1)[1]
                        tail = tail.rsplit("/stats", 1)[0]
                        # F5 partition-encodes with ~Common~name:port
                        if tail.startswith("~"):
                            tail = tail.lstrip("~").split("~", 1)[-1]
                        name = tail
                    except Exception:
                        name = ""
                # Backfill addr/port from name if missing (typical when the
                # node was named by IP, so name == "<ip>:<port>")
                if (not addr) and ":" in name:
                    head = name.rsplit(":", 1)[0]
                    if head and head.replace(".", "").isdigit():
                        addr = head
                if (not port) and ":" in name:
                    tail = name.rsplit(":", 1)[1]
                    if tail.isdigit():
                        port = tail
                # Last-resort name synthesis so the UI never renders an empty row.
                if not name and addr:
                    name = f"{addr}:{port}" if port else str(addr)

                availability = (_val("status.availabilityState") or "unknown").lower()
                enabled = (_val("status.enabledState") or "unknown").lower()
                reason = _val("status.statusReason")
                if availability == "available":
                    state = "up"
                elif availability == "offline":
                    state = "down"
                else:
                    state = "unknown"
                members.append({
                    "name": name,
                    "ip": str(addr) if addr else "",
                    "port": str(port) if port else "",
                    "availability": availability,
                    "enabled": enabled,
                    "state": state,
                    "reason": reason,
                })
            return members
        except Exception as e:
            logger.warning("get_pool_members_stats error for %s: %s", pool_name, e)
            return []

    def get_pool_members_traffic_stats(self, pool_name: str, partition: str = "Common") -> dict:
        """Return point-in-time traffic counters per pool member plus a pool
        rollup. Used by the pool stats graph. Counters come from the same
        members/stats endpoint as health, under serverside.*."""
        self.ensure_login()
        bare = pool_name.lstrip("/").split("/")[-1]
        url = f"{self.base_url}/mgmt/tm/ltm/pool/~{partition}~{bare}/members/stats"
        members = []
        try:
            resp = self.session.get(url, verify=self.verify_ssl)
            if resp.status_code != 200:
                return {"pool": pool_name, "ts": datetime.utcnow().isoformat() + "Z", "members": [], "totals": {}}
            data = resp.json()
            for full_key, item in (data.get("entries") or {}).items():
                stats = (item.get("nestedStats") or {}).get("entries") or {}

                def _num(k):
                    v = stats.get(k) or {}
                    raw = v.get("value", v.get("description", 0))
                    try:
                        return int(raw)
                    except (TypeError, ValueError):
                        return 0

                def _str(k):
                    v = stats.get(k) or {}
                    return v.get("description", v.get("value", ""))

                name = _str("tmName")
                if not name:
                    try:
                        tail = full_key.rsplit("/members/", 1)[1].rsplit("/stats", 1)[0]
                        if tail.startswith("~"):
                            tail = tail.lstrip("~").split("~", 1)[-1]
                        name = tail
                    except Exception:
                        name = ""
                availability = (_str("status.availabilityState") or "unknown").lower()
                state = "up" if availability == "available" else "down" if availability == "offline" else "unknown"
                members.append({
                    "name": name,
                    "ip": str(_str("addr") or ""),
                    "port": str(_str("port") or ""),
                    "state": state,
                    "curConns": _num("serverside.curConns"),
                    "totConns": _num("serverside.totConns"),
                    "maxConns": _num("serverside.maxConns"),
                    "pktsIn": _num("serverside.pktsIn"),
                    "pktsOut": _num("serverside.pktsOut"),
                    "bitsIn": _num("serverside.bitsIn"),
                    "bitsOut": _num("serverside.bitsOut"),
                })
        except Exception as e:
            logger.warning("get_pool_members_traffic_stats error for %s: %s", pool_name, e)
            return {"pool": pool_name, "ts": datetime.utcnow().isoformat() + "Z", "members": [], "totals": {}}

        totals = {}
        for k in ("curConns", "totConns", "pktsIn", "pktsOut", "bitsIn", "bitsOut"):
            totals[k] = sum(m[k] for m in members)
        return {
            "pool": pool_name,
            "ts": datetime.utcnow().isoformat() + "Z",
            "members": members,
            "totals": totals,
        }

    def get_pool_monitor(self, pool_name: str, partition: str = "Common") -> str:
        """Return the monitor full path attached to the pool, if any."""
        self.ensure_login()
        bare = pool_name.lstrip("/").split("/")[-1]
        url = f"{self.base_url}/mgmt/tm/ltm/pool/~{partition}~{bare}"
        try:
            resp = self.session.get(url, verify=self.verify_ssl)
            if resp.status_code == 200:
                return (resp.json().get("monitor") or "").strip()
        except Exception as e:
            logger.warning("get_pool_monitor error for %s: %s", pool_name, e)
        return ""

    def find_node_by_ip(self, ip_address: str, partition: str = "Common") -> dict | None:
        """
        Return an existing F5 node matching the given IP in the target partition.
        """
        self.ensure_login()
        url = f"{self.base_url}/mgmt/tm/ltm/node"
        params = {
            "$select": "name,address,partition,fullPath",
            "$filter": f"address eq {ip_address}",
        }

        resp = self.session.get(url, params=params, verify=self.verify_ssl)
        if resp.status_code != 200:
            logger.warning("Failed to query existing node for %s: %s %s", ip_address, resp.status_code, resp.text)
            return None

        items = resp.json().get("items", [])
        for item in items:
            if item.get("address") == ip_address and item.get("partition", partition) == partition:
                return item
        return None

    def _build_pool_member_payload(self, member: dict, partition: str = "Common") -> dict:
        """
        Reuse an existing node by name when the IP already exists on BIG-IP.
        Otherwise create the member from the raw IP address.
        """
        ip_address = member["ip_address"]
        port = str(member.get("port", "0"))
        existing_node = self.find_node_by_ip(ip_address, partition=partition)

        if existing_node:
            node_ref = existing_node.get("fullPath") or f"/{partition}/{existing_node['name']}"
            logger.info("Reusing existing node %s for IP %s in pool member", node_ref, ip_address)
            return {"name": f"{node_ref}:{port}"}

        return {
            "name": f"{ip_address}:{port}",
            "address": ip_address,
        }

    def create_pool(self, name: str, members: list, monitor_name: str = None, partition: str = "Common"):
        """
        members: list of dicts: {"ip_address": "...", "port": "8080"}
        monitor_name: optional monitor to attach to pool
        """
        self.ensure_login()
        url = f"{self.base_url}/mgmt/tm/ltm/pool"
        pool_name = f"/{partition}/{name}"

        payload = {
            "name": name,
            "partition": partition,
            "loadBalancingMode": "least-connections-member",
            "members": [self._build_pool_member_payload(m, partition=partition) for m in members]
        }

        # Attach monitor if provided
        if monitor_name:
            payload["monitor"] = monitor_name

        resp = self.session.post(url, json=payload, verify=self.verify_ssl)
        if resp.status_code not in (200, 201):
            raise RuntimeError(f"Failed to create pool: {resp.status_code} {resp.text}")
        return pool_name

    def create_monitor(
        self,
        name: str,
        monitor_type: str = "https",
        port: int = 443,
        partition: str = "Common",
        send: str | None = None,
        recv: str | None = None,
    ):
        """Create an HTTPS monitor with mandatory send/recv strings.

        The portal does not configure TCP-only monitors anymore — every pool
        must have an end-to-end HTTPS health check. `send` is built from the
        health-check URI and `recv` is the substring the response must
        contain. Both are required when monitor_type is 'https'.

        TCP is kept as an escape hatch for internal use but is intentionally
        not exposed in the request forms.
        """
        self.ensure_login()

        if monitor_type == "tcp":
            url = f"{self.base_url}/mgmt/tm/ltm/monitor/tcp"
            payload = {
                "name": name,
                "partition": partition,
                "destination": f"*:{port}",
                "interval": 5,
                "timeout": 16,
            }
        else:
            if not send or not recv:
                raise RuntimeError(
                    "HTTPS monitor requires both send (health URI) and recv (expected response) strings"
                )
            url = f"{self.base_url}/mgmt/tm/ltm/monitor/https"
            payload = {
                "name": name,
                "partition": partition,
                "destination": f"*:{port}",
                "interval": 5,
                "timeout": 16,
                "send": send,
                "recv": recv,
            }

        resp = self.session.post(url, json=payload, verify=self.verify_ssl)
        if resp.status_code not in (200, 201):
            logger.warning(f"Monitor {name} may already exist: {resp.status_code}")
            return f"/{partition}/{name}"
        return f"/{partition}/{name}"

    def list_snat_pools(self, partition: str = "Common") -> list:
        """List SNAT pools once so the SNAT allocator can see what's taken
        without a GET per candidate address."""
        self.ensure_login()
        url = f"{self.base_url}/mgmt/tm/ltm/snatpool"
        try:
            resp = self.session.get(url, verify=self.verify_ssl)
            if resp.status_code == 401:
                raise F5AuthError(f"F5 session expired or rejected on {self.base_url}")
            if resp.status_code != 200:
                logger.warning("list_snat_pools failed: %s", resp.status_code)
                return []
            items = resp.json().get("items", [])
            return [item for item in items if item.get("partition", partition) == partition]
        except F5AuthError:
            raise
        except Exception as e:
            logger.warning("list_snat_pools error: %s", e)
            return []

    def snat_ips_in_use(self, partition: str = "Common") -> set:
        """Every IPv4 address already a member of some SNAT pool. Members come
        back as paths (/Common/172.20.7.5); non-IP members (named SNAT
        translation objects) are ignored."""
        ips = set()
        for pool in self.list_snat_pools(partition):
            for member in pool.get("members") or []:
                candidate = str(member).split("/")[-1]
                try:
                    ipaddress.IPv4Address(candidate)
                except Exception:
                    continue
                ips.add(candidate)
        return ips

    def find_snat_pool_for_ip(self, snat_ip: str, partition: str = "Common") -> str | None:
        """Path of an existing SNAT pool that already carries this address, or
        None. Lets us reuse a pool somebody named differently instead of
        creating a second pool for the same IP."""
        for pool in self.list_snat_pools(partition):
            for member in pool.get("members") or []:
                if str(member).split("/")[-1] == snat_ip:
                    return f"/{pool.get('partition', partition)}/{pool.get('name')}"
        return None

    def ensure_snat_pool(self, name: str, snat_ip: str, partition: str = "Common") -> str:
        """Create a SNAT pool with a single SNAT IP member, or reuse the
        existing one. Returns the full pool path.

        Reuse is verified, not assumed: a pool already holding this address is
        reused whatever its name, and a name collision whose members are a
        *different* address raises SnatPoolConflict so the caller can pick
        another address rather than silently SNATing to the wrong source.
        """
        self.ensure_login()
        existing = self.find_snat_pool_for_ip(snat_ip, partition)
        if existing:
            logger.info("Reusing existing SNAT pool %s for %s", existing, snat_ip)
            return existing

        url = f"{self.base_url}/mgmt/tm/ltm/snatpool"
        payload = {
            "name": name,
            "partition": partition,
            "members": [f"/{partition}/{snat_ip}"],
        }
        resp = self.session.post(url, json=payload, verify=self.verify_ssl)
        if resp.status_code in (200, 201):
            return f"/{partition}/{name}"

        # Name is taken (409, or 400 on some versions). It isn't ours — the
        # by-IP lookup above already came back empty — so read it and say so.
        get_url = f"{self.base_url}/mgmt/tm/ltm/snatpool/~{partition}~{name}"
        check = self.session.get(get_url, verify=self.verify_ssl)
        if check.status_code == 200:
            members = [str(m).split("/")[-1] for m in (check.json().get("members") or [])]
            if snat_ip in members:
                return f"/{partition}/{name}"
            raise SnatPoolConflict(
                f"SNAT pool {name} already exists with members {members or '[]'}, "
                f"not {snat_ip}"
            )
        raise RuntimeError(
            f"Failed to create SNAT pool {name} ({snat_ip}): {resp.status_code} {resp.text}"
        )

    def upload_file(self, filename: str, data: bytes):
        """Upload a file to the F5 REST file-transfer area and return the remote path."""
        self.ensure_login()
        # F5 requires the filename in the URL path, not just the base path
        url = f"{self.base_url}/mgmt/shared/file-transfer/uploads/{filename}"
        
        # Ensure data is bytes, not string
        if isinstance(data, str):
            data = data.encode('latin1')
        
        logger.info("upload_file: filename=%s, data type=%s, data size=%d bytes", 
                   filename, type(data).__name__, len(data))
        
        # F5 requires Content-Range header for file uploads
        file_size = len(data)
        headers = {
            'Content-Range': f'0-{file_size - 1}/{file_size}',
            'Content-Type': 'application/octet-stream'
        }
        
        logger.info("upload_file: Content-Range header: %s", headers['Content-Range'])
        logger.info("upload_file: Sending %d bytes to %s", file_size, url)
        
        # Create a raw request to send binary data without any encoding
        # Use prepare_request to avoid requests library automatic encoding
        req = requests.Request('POST', url, data=data, headers=headers)
        prepared = self.session.prepare_request(req)
        
        logger.info("upload_file: Prepared request Content-Length: %s", prepared.headers.get('Content-Length', 'not set'))
        
        resp = self.session.send(prepared, verify=self.verify_ssl)
        
        if resp.status_code not in (200, 201):
            logger.error("upload_file failed: %s %s", resp.status_code, resp.text)
            raise RuntimeError(f"Failed to upload file to F5: {resp.status_code} {resp.text}")

        # Uploaded files are available under /var/config/rest/downloads/<filename>
        remote_path = f"/var/config/rest/downloads/{filename}"
        logger.info("File uploaded successfully to %s", remote_path)
        return remote_path

    def import_pkcs12(self, remote_path: str, name: str, passphrase: str, partition: str = "Common", object_name: str | None = None):
        """Import a PKCS12 file that was uploaded to the F5 into a certificate and key.
        Returns tuple (cert_name, key_name) as created on the F5.

        If `object_name` is given it is used verbatim as the cert/key object name
        (important for dotted FQDNs like "app.example.com_2027", where
        os.path.splitext would wrongly strip ".com_2027"). Otherwise the base
        name is derived from `name` via splitext (legacy behavior).
        """
        self.ensure_login()
        # Use install command on the correct PKCS12 endpoint
        url = f"{self.base_url}/mgmt/tm/sys/crypto/pkcs12"
        name_base = object_name if object_name else os.path.splitext(name)[0]
        payload = {
            "command": "install",
            "name": name_base,  # F5 will create cert/key under this base name
            "from-local-file": remote_path,
            "passphrase": passphrase,
        }
        resp = self.session.post(url, json=payload, verify=self.verify_ssl)
        if resp.status_code not in (200, 201):
            logger.error("PKCS12 import failed: %s %s", resp.status_code, resp.text)
            raise RuntimeError(f"Failed to import PKCS12 on F5: {resp.status_code} {resp.text}")

        # The import creates cert/key with base name (no extension)
        cert_name = name_base
        key_name = name_base
        return cert_name, key_name

    def create_clientssl_profile(self, name: str, cert_name: str, key_name: str, partition: str = "Common"):
        """Create a client-ssl profile that references the given cert and key."""
        self.ensure_login()
        url = f"{self.base_url}/mgmt/tm/ltm/profile/client-ssl"
        
        # Ensure cert/key names have partition prefix if not already present
        if not cert_name.startswith('/'):
            cert_name = f"/{partition}/{cert_name}"
        if not key_name.startswith('/'):
            key_name = f"/{partition}/{key_name}"
        
        payload = {
            "name": name,
            "partition": partition,
            # cert/key fields reference the full path
            "cert": cert_name,
            "key": key_name,
        }
        resp = self.session.post(url, json=payload, verify=self.verify_ssl)
        if resp.status_code in (200, 201):
            return f"/{partition}/{name}"
        if resp.status_code == 409:
            # Already exists, treat as usable
            logger.info("Client SSL profile %s already exists, reusing", name)
            return f"/{partition}/{name}"
        raise RuntimeError(f"Failed to create client SSL profile {name}: {resp.status_code} {resp.text}")

    def create_serverssl_profile(self, name: str, server_name: str, partition: str = "Common"):
        """Create a server-ssl profile with SNI serverName set."""
        self.ensure_login()
        url = f"{self.base_url}/mgmt/tm/ltm/profile/server-ssl"
        payload = {
            "name": name,
            "partition": partition,
            "serverName": server_name,
            "sniDefault": "true",
        }
        resp = self.session.post(url, json=payload, verify=self.verify_ssl)
        if resp.status_code in (200, 201):
            return f"/{partition}/{name}"
        if resp.status_code == 409:
            logger.info("Server SSL profile %s already exists, reusing", name)
            return f"/{partition}/{name}"
        raise RuntimeError(f"Failed to create server SSL profile {name}: {resp.status_code} {resp.text}")

    def create_virtual_server(
        self,
        name: str,
        destination_ip: str,
        ports: list,
        pool_name: str,
        ssl_enabled: bool,
        clientssl_profile: str | None = None,
        serverssl_profile: str | None = None,
        snat_pool_path: str | None = None,
        partition: str = "Common",
    ):
        """
        Creates 1 VS per port for simplicity: <name>_80, <name>_443 etc.
        Returns the VS IP (destination_ip).

        snat_pool_path: the full path of the SNAT pool to use (e.g.
            /Common/snat_172_20_7_1), as resolved by resolve_snat_pool_for_vip.
            None means the environment had no SNAT address to give this VIP
            (no mapping, or the mapped range is full) and the VS is created
            with automap instead.
        """
        self.ensure_login()
        url = f"{self.base_url}/mgmt/tm/ltm/virtual"

        for port in ports:
            # `name` is expected to be the full VS name already (e.g. vip-80-vip)
            vs_name = f"{name}"
            payload = {
                "name": vs_name,
                "partition": partition,
                "destination": f"/{partition}/{destination_ip}:{port}",
                "mask": "255.255.255.255",
                "ipProtocol": "tcp",
                "pool": pool_name,
            }
            if snat_pool_path:
                payload["sourceAddressTranslation"] = {
                    "type": "snat",
                    "pool": snat_pool_path,
                }
            else:
                payload["sourceAddressTranslation"] = {"type": "automap"}

            # If you have specific profiles (tcp/http/clientssl/serverssl),
            # add them here.
            profiles = [{"name": "tcp"}]
            if ssl_enabled:
                profiles.append({"name": "http"})
                if clientssl_profile:
                    profiles.append({"name": clientssl_profile})
                else:
                    profiles.append({"name": "clientssl"})  # fallback to generic
                if serverssl_profile:
                    profiles.append({"name": serverssl_profile})
                else:
                    profiles.append({"name": "serverssl"})  # default server SSL profile

            payload["profiles"] = profiles

            resp = self.session.post(url, json=payload, verify=self.verify_ssl)
            if resp.status_code not in (200, 201):
                raise RuntimeError(f"Failed to create VS {vs_name}: {resp.status_code} {resp.text}")

        return destination_ip

    # ---------------------------
    # Virtual-server reads + iRule management
    # ---------------------------
    def get_virtual(self, name: str, partition: str = "Common") -> dict | None:
        """Fetch the full virtual-server object (destination, pool, rules,
        attached profiles). Returns None if it does not exist. `name` may be a
        bare name or a /partition/name path."""
        self.ensure_login()
        n = name.lstrip("/")
        if "/" in n:
            parts = n.split("/")
            part, bare = parts[0], parts[-1]
        else:
            part, bare = partition, n
        url = f"{self.base_url}/mgmt/tm/ltm/virtual/~{part}~{bare}"
        try:
            resp = self.session.get(url, params={"expandSubcollections": "true"}, verify=self.verify_ssl)
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            logger.warning("get_virtual error for %s: %s", name, e)
        return None

    def get_virtual_rules(self, name: str, partition: str = "Common") -> list[str]:
        """Return the iRule paths attached to a virtual server, in order."""
        vs = self.get_virtual(name, partition)
        if not vs:
            return []
        return list(vs.get("rules") or [])

    def irule_exists(self, name: str, partition: str = "Common") -> bool:
        return self.get_irule(name, partition) is not None

    def get_irule(self, name: str, partition: str = "Common") -> dict | None:
        """Fetch an LTM iRule. The Tcl body is in the `apiAnonymous` field.
        Accepts a bare name or /partition/name path."""
        self.ensure_login()
        n = name.lstrip("/")
        if "/" in n:
            parts = n.split("/")
            part, bare = parts[0], parts[-1]
        else:
            part, bare = partition, n
        url = f"{self.base_url}/mgmt/tm/ltm/rule/~{part}~{bare}"
        try:
            resp = self.session.get(url, verify=self.verify_ssl)
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            logger.warning("get_irule error for %s: %s", name, e)
        return None

    def list_irules(self, partition: str = "Common") -> list:
        """List LTM iRules in the partition (name + apiAnonymous body)."""
        self.ensure_login()
        url = f"{self.base_url}/mgmt/tm/ltm/rule"
        try:
            resp = self.session.get(url, verify=self.verify_ssl)
            if resp.status_code != 200:
                logger.warning("list_irules failed: %s", resp.status_code)
                return []
            items = resp.json().get("items", [])
            return [item for item in items if item.get("partition", partition) == partition]
        except Exception as e:
            logger.warning("list_irules error: %s", e)
            return []

    def create_irule(self, name: str, body: str, partition: str = "Common") -> str:
        """Create an LTM iRule. BIG-IP compiles the Tcl on create and returns a
        4xx with the compiler error if the syntax is bad — that rejection is our
        syntax validation. Returns the full /partition/name path."""
        self.ensure_login()
        url = f"{self.base_url}/mgmt/tm/ltm/rule"
        payload = {"name": name, "partition": partition, "apiAnonymous": body}
        resp = self.session.post(url, json=payload, verify=self.verify_ssl)
        if resp.status_code not in (200, 201):
            raise RuntimeError(f"Failed to create iRule {name}: {resp.status_code} {resp.text}")
        return f"/{partition}/{name}"

    def set_virtual_rules(self, name: str, rule_paths: list[str], partition: str = "Common") -> None:
        """Re-point a virtual server's attached iRules (used to activate a new
        version or roll back to a prior one)."""
        self.ensure_login()
        safe_name = name.replace("/", "~")
        url = f"{self.base_url}/mgmt/tm/ltm/virtual/~{partition}~{safe_name}"
        resp = self.session.patch(url, json={"rules": rule_paths}, verify=self.verify_ssl)
        if resp.status_code not in (200, 201):
            raise RuntimeError(
                f"Failed to set rules on VS {name}: {resp.status_code} {resp.text}"
            )

    # ---------------------------
    # Traffic-matching-criteria + port-lists (BIG-IP 17.x port-list VIPs)
    # ---------------------------
    # On 17.1.x a "port-list" virtual server doesn't carry the ports on its
    # destination. Instead the VS references a traffic-matching-criteria (TMC)
    # object, which in turn references an ltm port-list holding the ports:
    #   ltm virtual V { destination /Common/IP:any  traffic-matching-criteria V_TMC }
    #   ltm traffic-matching-criteria V_TMC { destination-address-inline IP
    #                                          destination-port-list V_ports ... }
    #   ltm port-list V_ports { ports { 443 {} 8080 {} } }
    def get_traffic_matching_criteria(self, name: str, partition: str = "Common") -> dict | None:
        self.ensure_login()
        n = (name or "").lstrip("/")
        if "/" in n:
            parts = n.split("/")
            part, bare = parts[0], parts[-1]
        else:
            part, bare = partition, n
        url = f"{self.base_url}/mgmt/tm/ltm/traffic-matching-criteria/~{part}~{bare}"
        try:
            resp = self.session.get(url, verify=self.verify_ssl)
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            logger.warning("get_traffic_matching_criteria error for %s: %s", name, e)
        return None

    def list_traffic_matching_criteria(self, partition: str = "Common") -> list:
        self.ensure_login()
        url = f"{self.base_url}/mgmt/tm/ltm/traffic-matching-criteria"
        try:
            resp = self.session.get(url, verify=self.verify_ssl)
            if resp.status_code != 200:
                return []
            items = resp.json().get("items", [])
            return [i for i in items if i.get("partition", partition) == partition]
        except Exception as e:
            logger.warning("list_traffic_matching_criteria error: %s", e)
            return []

    def get_port_list(self, name: str, partition: str = "Common") -> dict | None:
        self.ensure_login()
        n = (name or "").lstrip("/")
        if "/" in n:
            parts = n.split("/")
            part, bare = parts[0], parts[-1]
        else:
            part, bare = partition, n
        url = f"{self.base_url}/mgmt/tm/ltm/port-list/~{part}~{bare}"
        try:
            resp = self.session.get(url, verify=self.verify_ssl)
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            logger.warning("get_port_list error for %s: %s", name, e)
        return None

    def port_list_ports(self, port_list: dict) -> list[str]:
        """Extract the port values from a port-list object's `ports` collection.
        F5 returns ports as [{"name": "443"}, {"name": "8080-8090"}, ...]."""
        out = []
        for p in (port_list or {}).get("ports", []) or []:
            val = str(p.get("name", "")).strip()
            if val:
                out.append(val)
        return out

    def add_port_to_port_list(self, name: str, port, partition: str = "Common") -> bool:
        """Add a single port to an ltm port-list (idempotent). Returns True if the
        list was changed, False if the port was already present."""
        self.ensure_login()
        port = str(port)
        pl = self.get_port_list(name, partition)
        if pl is None:
            raise RuntimeError(f"port-list {name} not found")
        existing = self.port_list_ports(pl)
        if port in existing:
            return False
        bare = (pl.get("fullPath") or name).lstrip("/").split("/")[-1]
        url = f"{self.base_url}/mgmt/tm/ltm/port-list/~{partition}~{bare}"
        new_ports = [{"name": p} for p in existing] + [{"name": port}]
        resp = self.session.patch(url, json={"ports": new_ports}, verify=self.verify_ssl)
        if resp.status_code not in (200, 201):
            raise RuntimeError(
                f"Failed to add port {port} to port-list {name}: {resp.status_code} {resp.text}"
            )
        return True

    def remove_port_from_port_list(self, name: str, port, partition: str = "Common") -> bool:
        """Remove a single port from an ltm port-list (used on revert). Returns
        True if the list was changed, False if the port wasn't present."""
        self.ensure_login()
        port = str(port)
        pl = self.get_port_list(name, partition)
        if pl is None:
            return False
        existing = self.port_list_ports(pl)
        if port not in existing:
            return False
        bare = (pl.get("fullPath") or name).lstrip("/").split("/")[-1]
        url = f"{self.base_url}/mgmt/tm/ltm/port-list/~{partition}~{bare}"
        new_ports = [{"name": p} for p in existing if p != port]
        # F5 rejects an empty `ports` collection; leave the last port in place.
        if not new_ports:
            return False
        resp = self.session.patch(url, json={"ports": new_ports}, verify=self.verify_ssl)
        if resp.status_code not in (200, 201):
            raise RuntimeError(
                f"Failed to remove port {port} from port-list {name}: {resp.status_code} {resp.text}"
            )
        return True


# ---------------------------
# Tornado Handlers
# ---------------------------

class VIPCreationHandler(BaseHandler):
    """
    POST /vipcreation
    Authorization: Bearer <token>
    Content-Type: multipart/form-data

    Expected form fields described in the spec document.
    Requires valid admin token in Authorization header.
    """

    executor = ThreadPoolExecutor(max_workers=10)

    # Set per-request by _handle_f5 when the VIP had to fall back to automap.
    _snat_fallback = None

    @run_on_executor
    def _handle_f5(self, params):
        """
        Run the F5 work in a thread so the Tornado handler can be async.
        Uses auto-detected F5 URL from pool member IP analysis.
        Uses F5 tokens from login.
        Creates per-port resources with naming: vip_name-port-pool, vip_name-port-vip, vip_name-port-monitor
        """

        raw_vip_name = params.get("vip_name_original") or params["vip_name"]
        vip_name = sanitize_vip_name(raw_vip_name)
        ports = params["ports"]
        ssl_enabled = params["ssl_enabled"]
        pool_members = params["pool_members"]
        f5_target = params["f5_target"]  # "dc" or "dmz"

        # ------------- Required HTTPS health-check fields -------------
        monitor_uri = (params.get("monitor_uri") or "").strip()
        monitor_recv = (params.get("monitor_recv") or "").strip()
        if not monitor_uri or not monitor_recv:
            raise RuntimeError(
                "Health-check URI and expected response are required for every VIP — "
                "the form should not allow submission without them."
            )
        if not monitor_uri.startswith("/"):
            monitor_uri = "/" + monitor_uri
        # F5 expects a CRLF-delimited HTTP request as the `send` string.
        monitor_send = f"GET {monitor_uri} HTTP/1.1\\r\\nHost: {raw_vip_name}\\r\\nConnection: close\\r\\n\\r\\n"

        # Use the auto-detected F5 URL from pool member IP classification
        f5_base_url = params.get("f5_url")
        if not f5_base_url:
            raise RuntimeError("No F5 URL provided - auto-detection failed.")

        f5_token = params.get("f5_token")

        # Use provided token; avoid re-auth
        f5 = F5Client(
            base_url=f5_base_url,
            username="token_user",
            password="token_pass",
            verify_ssl=False  # change to True if you have valid certs
        )
        if f5_token:
            f5.token = f5_token
            f5.session.headers.update({"X-F5-Auth-Token": f5_token})

        # Pre-flight: would any of the per-port VS names collide with existing
        # virtual servers on F5? If so, surface a specific error so the admin
        # can rename via the UI before any resources are created.
        existing_vs = []
        for port in ports:
            port_str = str(port)
            vs_name_check = f"{vip_name}-{port_str}-vip"
            if f5.virtual_exists(vs_name_check):
                existing_vs.append(vs_name_check)
        if existing_vs:
            raise RuntimeError(f"DUPLICATE_VIP_NAME: {','.join(existing_vs)}")

        # 1. Allocate IP for the VIP using smart allocator (environment-specific)
        env_cfg = F5_ENVIRONMENTS_BY_ID.get(f5_target.lower()) or {}
        allocator = VIPIPAllocator(f5, environment=f5_target, vip_networks=env_cfg.get("vip_networks", []))
        vip_ip = allocator.allocate_ip()
        logger.info("Allocated VIP IP: %s for %s (%s)", vip_ip, vip_name, f5_target)

        # 1a. Resolve the SNAT pool for the allocated VIP IP from env config.
        # No pool available (no mapping, or the mapped range is full) is not a
        # failure — the VS falls back to automap.
        snat_pool_path, snat_reason = resolve_snat_pool_for_vip(
            f5, env_cfg, vip_ip, env_label=f5_target
        )
        if not snat_pool_path:
            self._snat_fallback = SNAT_FALLBACK_REASONS.get(snat_reason, snat_reason)

        # 1b. Handle PFX upload, import, and clientssl profile creation (if SSL enabled)
        clientssl_profile_path = None
        serverssl_profile_path = None
        if ssl_enabled and params.get("pfx_file_body"):
            try:
                pfx_file_body = params["pfx_file_body"]
                pfx_file_name = params.get("pfx_file_name", "cert.pfx")
                pfx_password = params.get("pfx_password", "")
                sni_required = params.get("require_sni", False)
                profile_base = os.path.splitext(vip_name)[0]

                # Validate PFX password locally (best-effort)
                try:
                    validate_pfx_password(pfx_file_body, pfx_password)
                except ValueError as ve:
                    raise RuntimeError(str(ve))

                logger.info(
                    "Starting PFX workflow: upload file %s (%d bytes); pfx_file_body type=%s",
                    pfx_file_name,
                    len(pfx_file_body),
                    type(pfx_file_body).__name__,
                )

                # Debug: show first 20 bytes (repr) to see if it looks like binary or base64
                if len(pfx_file_body) > 0:
                    first_bytes = pfx_file_body[:20] if isinstance(pfx_file_body, bytes) else str(pfx_file_body)[:20]
                    logger.info("First 20 bytes (repr): %s", repr(first_bytes))

                # Ensure pfx_file_body is bytes, not string
                if isinstance(pfx_file_body, str):
                    logger.warning("PFX body is string, encoding to bytes")
                    pfx_file_body = pfx_file_body.encode('latin1')

                logger.info("Uploading PFX: %s with size %d bytes", pfx_file_name, len(pfx_file_body))

                # Step 1: Upload PFX to F5
                remote_path = f5.upload_file(pfx_file_name, pfx_file_body)
                logger.info("Uploaded PFX to F5: %s", remote_path)

                # Step 2: Import PKCS12 into cert + key
                cert_name = f"{vip_name}-cert"
                key_name = f"{vip_name}-key"
                imported_cert_name, imported_key_name = f5.import_pkcs12(
                    remote_path=remote_path,
                    name=profile_base,  # F5 will derive cert and key names from this
                    passphrase=pfx_password,
                )
                logger.info("Imported PKCS12: cert=%s, key=%s", imported_cert_name, imported_key_name)

                # Step 3: Create clientssl profile
                clientssl_profile_name = f"{profile_base}-client-ssl"
                clientssl_profile_path = f5.create_clientssl_profile(
                    name=clientssl_profile_name,
                    cert_name=imported_cert_name,
                    key_name=imported_key_name,
                )
                logger.info("Created clientssl profile: %s", clientssl_profile_path)

                if sni_required:
                    # Profile name = the cert's actual Common Name so the SNI
                    # match on the backend works for real. Fall back to the
                    # VIP hostname if we can't parse the PFX.
                    try:
                        cert_meta = parse_pfx_cert_info(pfx_file_body, pfx_password)
                        cn = (cert_meta.get("commonName") or "").strip()
                    except Exception as e:
                        logger.warning("Could not parse PFX CN, falling back to VIP name: %s", e)
                        cn = ""
                    server_name = cn or raw_vip_name
                    serverssl_profile_name = sanitize_vip_name(server_name)
                    serverssl_profile_path = f5.create_serverssl_profile(
                        name=serverssl_profile_name,
                        server_name=server_name,
                    )
                    logger.info(
                        "Created serverssl profile %s for SNI CN=%s",
                        serverssl_profile_path, server_name,
                    )

            except Exception as e:
                logger.error("PFX workflow error: %s", e)
                raise RuntimeError(f"Failed to upload/import PFX: {str(e)}")

        # 2. Create per-port pools, monitors, and virtual servers
        for port in ports:
            port_str = str(port)
            
            # Build resource names: vip_name-port-{pool|vip|monitor}
            pool_name = f"{vip_name}-{port_str}-pool"
            vs_name = f"{vip_name}-{port_str}-vip"
            monitor_name = f"{vip_name}-{port_str}-monitor"
            
            logger.info("Creating resources for port %s: pool=%s, vs=%s, monitor=%s", 
                       port_str, pool_name, vs_name, monitor_name)
            
            # Create HTTPS monitor — URI + expected response are mandatory.
            f5.create_monitor(
                name=monitor_name,
                monitor_type="https",
                port=int(port_str),
                send=monitor_send,
                recv=monitor_recv,
            )

            # Create pool members with the port (F5 expects port in member definition)
            pool_members_with_port = [
                {"ip_address": pm["ip_address"], "port": port_str}
                for pm in pool_members
            ]

            # Create pool with monitor attached
            pool_full_name = f5.create_pool(
                name=pool_name,
                members=pool_members_with_port,
                monitor_name=f"/Common/{monitor_name}"
            )

            # Create virtual server for this port. If SSL is on, the default
            # /Common/serverssl is attached automatically by create_virtual_server
            # unless we override with a SNI-specific serverssl_profile_path.
            f5.create_virtual_server(
                name=vs_name,
                destination_ip=vip_ip,
                ports=[int(port_str)],
                pool_name=pool_full_name,
                ssl_enabled=ssl_enabled,
                clientssl_profile=clientssl_profile_path if clientssl_profile_path else None,
                serverssl_profile=serverssl_profile_path if serverssl_profile_path else None,
                snat_pool_path=snat_pool_path,
            )
        
        return vip_ip

    async def post(self):
        # Log request details for debugging
        logger.info("=== VIPCreationHandler.post() ===")
        logger.info("Request Content-Type: %s", self.request.headers.get("Content-Type", "not set"))
        logger.info("Request arguments: %s", list(self.request.arguments.keys()))
        logger.info("Request files: %s", list(self.request.files.keys()))

        # Set by _handle_f5 when the VIP had to fall back to automap; surfaced
        # in the response and the audit entry so nobody has to read the logs to
        # find out a VIP isn't SNATing from its own address.
        self._snat_fallback = None
        
        try:
            # If a stored request ID is provided, load it; otherwise parse incoming form
            stored_request_id = self.get_argument("request_id", None)
            save_only = self.get_argument("save_only", "false").lower() == "true"
            # Admin can override the VIP name (e.g., from duplicate-name dialog).
            override_vip_name = self.get_argument("override_vip_name", None)

            # Require auth except for new save-only submissions
            token_data = None
            if stored_request_id or not save_only:
                token_data = self.require_auth()
                if not token_data:
                    return
            f5_token = None
            f5_url = None

            if stored_request_id:
                stored = get_vip_request(stored_request_id)
                if not stored:
                    raise tornado.web.HTTPError(404, reason="Stored VIP request not found")

                if stored.get("request_type") == "add_port":
                    vip_name = sanitize_vip_name(stored.get("vip_name") or "")
                    vip_ip = (stored.get("vip_ip") or "").strip()
                    target = (stored.get("f5_target") or stored.get("target") or "").lower()
                    port = str((stored.get("ports") or [""])[0])
                    pool_members = stored.get("pool_members") or []
                    if not vip_name or not vip_ip or not target or not port:
                        raise tornado.web.HTTPError(400, reason="Stored add-port request is missing required fields")

                    _env, env_session = get_token_environment(token_data, target)
                    f5_token = env_session.get("token")
                    f5_url = env_session.get("url")
                    if not f5_token or not f5_url:
                        raise tornado.web.HTTPError(401, reason=f"Missing F5 token for target {target}")

                    result = await asyncio.get_running_loop().run_in_executor(
                        None,
                        create_f5_add_port_resources,
                        {
                            "vip_name": vip_name,
                            "vip_ip": vip_ip,
                            "target": target,
                            "port": port,
                            "pool_members": pool_members,
                            "monitor_type": "https",
                            "monitor_uri": stored.get("monitor_uri", ""),
                            "monitor_recv": stored.get("monitor_recv", ""),
                            "ssl_enabled": stored.get("ssl_enabled", False),
                            "clientssl_profile": stored.get("clientssl_profile"),
                            "f5_url": f5_url,
                            "f5_token": f5_token,
                        },
                    )
                    update_vip_request_status(stored_request_id, "approved", {"assigned_ip": vip_ip})
                    audit_log(
                        action="vipport.approve",
                        target=f"{vip_name}:{port}",
                        user=token_data.get("username", "?"),
                        user_type="admin",
                        result="success",
                        client_ip=self.get_client_ip(),
                        revertible=True,
                        details={
                            "target": target,
                            "mode": result.get("mode"),
                            "vs_name": result.get("vs_name"),
                            "pool_name": result.get("pool_name"),
                            "monitor_name": result.get("monitor_name"),
                            "monitor_type": "https",
                            "vip_ip": vip_ip,
                            "port": port,
                            "request_id": stored_request_id,
                            "irule_name": result.get("irule_name"),
                            "irule_version": result.get("irule_version"),
                            "irule_from_version": result.get("irule_from_version"),
                            "port_list": result.get("port_list"),
                        },
                    )
                    self.write({"success": True, "ip": vip_ip, "message": "Add-port request approved", **result})
                    return

                vip_name = stored["vip_name"]
                email = stored["email"]
                ports = stored["ports"]
                pool_members = stored["pool_members"]
                ssl_flag = stored.get("ssl_enabled", False)
                sni_flag = stored.get("require_sni", False)
                pfx_file_body = None
                pfx_file_name = safe_pfx_filename(stored.get("pfx_file_name") or "")
                pfx_password = stored.get("pfx_password", "")

                # load PFX bytes from saved file if SSL
                if ssl_flag and stored.get("pfx_saved_path"):
                    try:
                        with open(stored["pfx_saved_path"], "rb") as f:
                            pfx_file_body = f.read()
                    except Exception as e:
                        raise tornado.web.HTTPError(500, reason=f"Failed to read stored PFX: {str(e)}")

                # reuse detected target if present
                detected_target = stored.get("f5_target")
                detected_f5_url = stored.get("f5_url")
                if not detected_target or not detected_f5_url:
                    detected_target, detected_f5_url = detect_f5_target(pool_members)
            else:
                # ------------- Parse basic fields -------------
                vip_name = self.get_argument("vip_name")
                email = self.get_argument("email").strip()
                if not is_valid_email(email):
                    raise tornado.web.HTTPError(400, reason="Invalid requester email address")
                if "\r" in vip_name or "\n" in vip_name:
                    raise tornado.web.HTTPError(400, reason="VIP name contains illegal characters")

                ports_raw = self.get_argument("ports")   # JSON string
                pool_members_raw = self.get_argument("pool_members")  # JSON string

                ssl_flag = self.get_argument("ssl", "false").lower() == "true"
                sni_flag = self.get_argument("require_sni", "false").lower() == "true"
                monitor_uri = (self.get_argument("monitor_uri", "") or "").strip()
                monitor_recv = (self.get_argument("monitor_recv", "") or "").strip()
                if not monitor_uri or not monitor_recv:
                    raise tornado.web.HTTPError(
                        400,
                        reason="monitor_uri (health-check path) and monitor_recv (expected response) are required",
                    )
                pfx_file_body = None
                pfx_file_name = None
                pfx_password = ""

                # ------------- Parse JSON fields -------------
                try:
                    ports = json.loads(ports_raw)
                    if not isinstance(ports, list):
                        raise ValueError
                except Exception:
                    raise tornado.web.HTTPError(400, reason="Invalid 'ports' JSON")

                try:
                    pool_members = json.loads(pool_members_raw)
                    if not isinstance(pool_members, list):
                        raise ValueError
                except Exception:
                    raise tornado.web.HTTPError(400, reason="Invalid 'pool_members' JSON")

                # ------------- Validate ports & pool members -------------
                for p in ports:
                    if not is_valid_port(str(p)):
                        raise tornado.web.HTTPError(400, reason=f"Invalid port: {p}")

                for member in pool_members:
                    ip = member.get("ip_address")
                    if not ip or not is_valid_ipv4(ip):
                        raise tornado.web.HTTPError(400, reason=f"Invalid pool member IP: {ip}")

                # ------------- Auto-detect F5 target from pool member IPs -----------
                try:
                    detected_target, detected_f5_url = detect_f5_target(pool_members)
                    logger.info("VIP %s: Auto-detected target=%s, F5_URL=%s", vip_name, detected_target, detected_f5_url)
                except RuntimeError as e:
                    raise tornado.web.HTTPError(400, reason=f"Cannot determine F5 target: {str(e)}")

                # ------------- SSL / PFX capture (optional) -------------
                if ssl_flag:
                    uploaded_fields = list(self.request.files.keys())
                    logger.info("Uploaded multipart fields: %s", uploaded_fields)
                    files = self.request.files.get("pfx_file")
                    if not files or not files[0]:
                        logger.warning("Missing 'pfx_file' in request.files; available fields: %s", uploaded_fields)
                        raise tornado.web.HTTPError(400, reason="pfx_file is required when ssl=true")
                    pfx_info = files[0]
                    pfx_file_body = pfx_info["body"]
                    pfx_file_name = safe_pfx_filename(pfx_info.get("filename", ""))
                    pfx_password = self.get_argument("pfx_password", "")

                # ------------- Store only, skip F5 -------------
                if save_only:
                    request_id = str(uuid.uuid4())
                    pfx_saved_path = None
                    if ssl_flag and pfx_file_body and pfx_file_name:
                        pfx_saved_path = os.path.join(VIP_UPLOAD_DIR, f"{request_id}_{pfx_file_name}")
                        with open(pfx_saved_path, "wb") as f:
                            f.write(pfx_file_body)

                    smtp_host_arg = self.get_argument("smtp_host", SMTP_HOST)
                    smtp_port_arg = int(self.get_argument("smtp_port", SMTP_PORT))

                    safe_vip_name = sanitize_vip_name(vip_name)
                    record = {
                        "id": request_id,
                        "vip_name": safe_vip_name,
                        "vip_name_original": vip_name,
                        "email": email,
                        "ports": [str(p) for p in ports],
                        "ssl_enabled": ssl_flag,
                        "require_sni": sni_flag,
                        "monitor_type": "https",
                        "monitor_uri": monitor_uri,
                        "monitor_recv": monitor_recv,
                        "pool_members": pool_members,
                        "pfx_file_name": pfx_file_name,
                        "pfx_password": pfx_password,
                        "pfx_saved_path": pfx_saved_path,
                        "f5_target": detected_target,
                        "f5_url": detected_f5_url,
                        "status": "pending",
                        "created_at": datetime.utcnow().isoformat(),
                        "smtp_host": smtp_host_arg,
                        "smtp_port": smtp_port_arg,
                    }
                    add_vip_request(record)
                    send_team_notification(record, smtp_host_arg, smtp_port_arg)
                    send_requester_notification(record, smtp_host_arg, smtp_port_arg)
                    audit_log(
                        action="vip.request",
                        target=vip_name,
                        user=email or "anonymous",
                        user_type="requester",
                        result="success",
                        client_ip=self.get_client_ip(),
                        revertible=False,
                        details={"request_id": request_id, "ports": [str(p) for p in ports]},
                    )
                    self.write({"success": True, "id": request_id, "message": "VIP request stored for admin approval"})
                    return

                # ------------- SSL / PFX file (optional) -------------
                pfx_file_body = None
                pfx_file_name = None
                pfx_password = None

                if ssl_flag:
                    # Log available uploaded file fields for debugging
                    uploaded_fields = list(self.request.files.keys())
                    logger.info("Uploaded multipart fields: %s", uploaded_fields)

                    files = self.request.files.get("pfx_file")
                    if not files or not files[0]:
                        logger.warning("Missing 'pfx_file' in request.files; available fields: %s", uploaded_fields)
                        raise tornado.web.HTTPError(400, reason="pfx_file is required when ssl=true")

                    pfx_file_info = files[0]
                    pfx_file_body = pfx_file_info["body"]
                    pfx_file_name = safe_pfx_filename(pfx_file_info.get("filename", ""))
                    pfx_password = self.get_argument("pfx_password", "")

                    logger.info("Received PFX file %s (%d bytes); pfx_password provided=%s", pfx_file_name, len(pfx_file_body), bool(pfx_password))

            # ------------- Call the load balancer in a thread (auto-detected target) -----
            if token_data:
                _env, env_session = get_token_environment(token_data, detected_target)
                f5_token = env_session.get("token")
                f5_url = env_session.get("url")

                if not f5_token or not f5_url:
                    raise tornado.web.HTTPError(
                        401,
                        reason=f"Missing F5 token for target {detected_target}",
                    )

            # If admin supplied an override (e.g., from the duplicate-rename dialog),
            # it becomes the new VIP name. _handle_f5 will sanitize on its side too.
            effective_raw_name = override_vip_name or (raw_name if 'raw_name' in locals() else vip_name)
            effective_vip_name = sanitize_vip_name(override_vip_name) if override_vip_name else vip_name
            # Pull monitor fields either from the in-progress form or from the
            # stored request being approved. The form-args branch above already
            # validated them; for the stored branch they live in the saved record.
            effective_monitor_uri = locals().get("monitor_uri") or (stored.get("monitor_uri") if stored_request_id and 'stored' in locals() and stored else "")
            effective_monitor_recv = locals().get("monitor_recv") or (stored.get("monitor_recv") if stored_request_id and 'stored' in locals() and stored else "")
            if not effective_monitor_uri or not effective_monitor_recv:
                raise tornado.web.HTTPError(
                    400,
                    reason="Stored VIP request is missing monitor_uri / monitor_recv — re-submit the request with the health-check URI and expected response",
                )

            params = {
                "vip_name": effective_vip_name,
                "email": email,
                "ports": [str(p) for p in ports],
                "ssl_enabled": ssl_flag,
                "require_sni": sni_flag,
                "monitor_uri": effective_monitor_uri,
                "monitor_recv": effective_monitor_recv,
                "pool_members": pool_members,
                "f5_url": f5_url or detected_f5_url,  # Use token-specific URL if available
                "f5_target": detected_target,  # environment id for subnet selection
                "f5_token": f5_token,
                "vip_name_original": effective_raw_name,
            }
            # Include PFX bytes and metadata if present so the background handler can use them.
            if pfx_file_body:
                params.update({
                    "pfx_file_body": pfx_file_body,
                    "pfx_file_name": pfx_file_name,
                    "pfx_password": pfx_password,
                })

            vip_ip = await self._handle_f5(params)

            # ------------- Response -------------
            if stored_request_id:
                update_vip_request_status(stored_request_id, "approved", {"assigned_ip": vip_ip})

            # Build resource names for audit + revert recipe.
            _vname = params["vip_name"]
            _ports = params["ports"]
            _vs_suffix, _grp_suffix, _mon_suffix = ("vip", "pool", "monitor")
            audit_log(
                action="vip.approve" if stored_request_id else "vip.create",
                target=_vname,
                user=(token_data.get("username", "?") if token_data else "requester"),
                user_type=("admin" if token_data else "requester"),
                result="success",
                client_ip=self.get_client_ip(),
                revertible=True,
                details={
                    "target": params.get("f5_target"),
                    "platform": params.get("platform", "f5"),
                    "vs_names": [f"{_vname}-{p}-{_vs_suffix}" for p in _ports],
                    "pool_names": [f"{_vname}-{p}-{_grp_suffix}" for p in _ports],
                    "monitor_names": [f"{_vname}-{p}-{_mon_suffix}" for p in _ports],
                    "monitor_type": "https",
                    "monitor_uri": effective_monitor_uri,
                    "vip_ip": vip_ip,
                    "request_id": stored_request_id,
                    "snat": "automap" if self._snat_fallback else "pool",
                    "snat_fallback_reason": self._snat_fallback,
                },
            )

            self.write({
                "success": True,
                "ip": vip_ip,
                "message": "VIP created successfully",
                "snat": "automap" if self._snat_fallback else "pool",
                "snat_fallback_reason": self._snat_fallback,
            })

        except tornado.web.HTTPError as e:
            logger.exception("Client error creating VIP")
            self.set_status(e.status_code)
            self.write({
                "success": False,
                "error": e.reason
            })
        except Exception as e:
            err_str = str(e)
            if "DUPLICATE_VIP_NAME" in err_str:
                names_part = err_str.split("DUPLICATE_VIP_NAME:", 1)[1].strip() if "DUPLICATE_VIP_NAME:" in err_str else ""
                existing = [n.strip() for n in names_part.split(",") if n.strip()]
                logger.info("Duplicate VIP name(s) detected: %s", existing)
                self.set_status(409)
                self.write({
                    "success": False,
                    "error": f"A VIP with this name already exists on F5: {', '.join(existing) or names_part}",
                    "code": "duplicate_vip_name",
                    "existing": existing,
                })
            else:
                logger.exception("Server error creating VIP")
                self.set_status(500)
                self.write({
                    "success": False,
                    "error": err_str
                })


class EmailNotificationHandler(BaseHandler):
    """
    POST /vipcreation/notify
    Authorization: Bearer <token>
    Content-Type: application/json

    {
      "to": "user@example.com",
      "subject": "VIP Request Status",
      "body": "Email body content",
      "smtp_host": "localhost",
      "smtp_port": 1040
    }
    
    Requires valid admin token.
    """

    executor = ThreadPoolExecutor(max_workers=5)

    @run_on_executor
    def _send_email(self, to_email, subject, body, smtp_host, smtp_port):
        if not is_valid_email(to_email):
            raise ValueError(f"Refusing to send to invalid email: {to_email!r}")
        msg = MIMEText(body)
        msg["Subject"] = _strip_crlf(subject)
        msg["From"] = EMAIL_FROM
        msg["To"] = to_email

        # local_hostname sets the EHLO/HELO name; the relay approves us by this IP.
        with smtplib.SMTP(smtp_host, smtp_port, local_hostname="[192.0.2.50]") as server:
            server.send_message(msg)

    async def post(self):
        # -------- Require authentication --------
        token_data = self.require_auth()
        if not token_data:
            return
        
        try:
            data = json.loads(self.request.body.decode("utf-8"))

            to_email = data["to"]
            subject = data["subject"]
            body = data["body"]
            smtp_host = data.get("smtp_host", "localhost")
            smtp_port = int(data.get("smtp_port", 25))

            await self._send_email(to_email, subject, body, smtp_host, smtp_port)

            self.write({
                "success": True,
                "message": "Email sent successfully"
            })

        except KeyError as e:
            self.set_status(400)
            self.write({
                "success": False,
                "error": f"Missing field: {e}"
            })
        except Exception as e:
            logger.exception("Error sending email")
            self.set_status(500)
            self.write({
                "success": False,
                "error": str(e)
            })


class VIPRequestListHandler(BaseHandler):
    """
    GET /viprequest/list
    Authorization: Bearer <token>
    Returns all stored VIP requests (pending/approved).
    """
    def get(self):
        token_data = self.require_auth()
        if not token_data:
            return

        self.write({
            "success": True,
            "items": load_vip_requests()
        })


class VIPRequestDeclineHandler(BaseHandler):
    """
    POST /viprequest/decline
    Authorization: Bearer <token>
    Body: { "id": "...", "reason": "..." }
    """
    def post(self):
        token_data = self.require_auth()
        if not token_data:
            return
        try:
            data = json.loads(self.request.body.decode("utf-8"))
            req_id = data.get("id")
            reason = data.get("reason", "")
            if not req_id:
                raise tornado.web.HTTPError(400, reason="Missing id")
            prev = get_vip_request(req_id)
            prev_status = (prev or {}).get("status", "pending")
            updated = update_vip_request_status(req_id, "declined", {"decline_reason": reason})
            if not updated:
                raise tornado.web.HTTPError(404, reason="Request not found")
            audit_log(
                action="vip.decline",
                target=(updated.get("vip_name_original") or updated.get("vip_name") or req_id),
                user=token_data.get("username", "?"),
                user_type="admin",
                result="success",
                client_ip=self.get_client_ip(),
                revertible=True,
                details={"request_id": req_id, "prev_status": prev_status, "reason": reason},
            )
            self.write({"success": True, "message": "Request declined"})
        except tornado.web.HTTPError as e:
            self.set_status(e.status_code)
            self.write({"success": False, "error": e.reason})
        except Exception as e:
            logger.exception("Decline error")
            self.set_status(500)
            self.write({"success": False, "error": str(e)})


class VIPRequestClearHandler(BaseHandler):
    """
    POST /viprequest/clear
    Authorization: Bearer <token>
    Clears all stored VIP requests and uploaded PFX files.
    """
    def post(self):
        token_data = self.require_auth()
        if not token_data:
            return
        try:
            clear_vip_requests(delete_uploads=True)
            audit_log(
                action="vip.clearall",
                target="all",
                user=token_data.get("username", "?"),
                user_type="admin",
                result="success",
                client_ip=self.get_client_ip(),
                revertible=False,
                details={},
            )
            self.write({"success": True, "message": "All VIP requests cleared"})
        except Exception as e:
            logger.exception("Error clearing VIP requests")
            self.set_status(500)
            self.write({"success": False, "error": str(e)})


class CurrentUserHandler(BaseHandler):
    """
    GET /me
    Returns the currently-authenticated user (role "admin") when a valid
    F5-login Bearer token is supplied, otherwise 200 with role "anonymous".

    Not-logged-in is a normal state for this endpoint, not an error: it is the
    first call the SPA makes on every page load. Answering 404 made every cold
    start log a failed request and forced the client to treat "no session yet"
    and "route missing" as the same thing.
    """
    def get(self):
        self.set_header("Cache-Control", "no-store")

        # 1) Admin via stored Bearer token
        token = self.get_auth_token()
        if token:
            token_data = validate_token(token)
            if token_data:
                uname = token_data.get("username") or ""
                created = token_data.get("created_at", 0)
                expires_at = (
                    int(created + ADMIN_TOKEN_TTL) if ADMIN_TOKEN_TTL > 0 and created else None
                )
                effective_expires_at = (
                    int(expires_at - ADMIN_TOKEN_SAFETY_MARGIN_SECS)
                    if expires_at is not None
                    else None
                )
                self.write({
                    "success": True,
                    "username": uname,
                    "email": f"{uname}@{USER_EMAIL_DOMAIN}",
                    "role": token_data.get("role") or "admin",
                    "expires_at": expires_at,
                    "effective_expires_at": effective_expires_at,
                })
                return

        # No valid login token -> anonymous, which is a successful answer.
        self.write({
            "success": True,
            "username": "",
            "email": "",
            "role": "anonymous",
            "expires_at": None,
            "effective_expires_at": None,
        })


class F5VIPListHandler(BaseHandler):
    """
    GET /f5/vips
    Authorization: Bearer <token>

    Lists virtual servers from every authenticated F5 environment,
    grouped by VIP root name. Naming convention
    assumed: <root>-<port>-vip. VS that don't match the convention are
    returned with their raw name as the root.
    """
    executor = ThreadPoolExecutor(max_workers=4)

    @staticmethod
    def collect_env_vips(env, env_session):
        target = env["id"]
        base_url = env_session.get("url")
        token = env_session.get("token")
        results = []
        if not base_url or not token:
            return results
        try:
            f5 = F5Client(base_url=base_url, username="x", password="x", verify_ssl=False)
            f5.token = token
            f5.session.headers.update({"X-F5-Auth-Token": token})
            virtuals = f5.list_virtuals()
        except F5AuthError:
            # Propagate so the handler answers 401 and the frontend re-logs in
            # instead of rendering an empty VIP list.
            raise
        except Exception as e:
            logger.warning("Failed to list VIPs from %s: %s", target, e)
            return results

        groups = {}
        for vs in virtuals:
            name = vs.get("name", "")
            destination = vs.get("destination", "")
            m = re.match(r"^/[^/]+/([0-9.]+):(\d+|any)$", destination)
            if not m:
                continue
            ip = m.group(1)
            port = m.group(2)
            rules = list(vs.get("rules") or [])
            # iRule mode: one VS handles all ports (:0/:any) or a port-list, and
            # a switch [TCP::local_port] iRule dispatches each port to its pool.
            is_all_ports = port in ("0", "any") or bool(vs.get("trafficMatchingCriteria"))
            vs_mode = "irule" if is_all_ports else "vs"
            root_match = re.match(r"^(.+)-(\d+)-vip$", name)
            root = root_match.group(1) if root_match else name
            key = (root, ip)
            if key not in groups:
                groups[key] = {
                    "name": root,
                    "ip": ip,
                    "target": target,
                    "target_name": env["name"],
                    "ports": [],
                    "mode": "vs",
                    "rules": [],
                }
            profile_names = []
            profiles_data = vs.get("profilesReference", {}).get("items", []) or []
            for p in profiles_data:
                pname = p.get("name")
                if pname:
                    profile_names.append(pname)
            groups[key]["ports"].append({
                "port": port,
                "vsName": name,
                "pool": vs.get("pool", ""),
                "profiles": profile_names,
                "rules": rules,
                "mode": vs_mode,
            })
            # A VIP is iRule-mode if any of its VSs dispatch via a switch iRule.
            if vs_mode == "irule":
                groups[key]["mode"] = "irule"
                if rules:
                    groups[key]["rules"] = rules

        # Enrich each port with its client-SSL profile + the bound certificate
        # (CN / expiry / issuer / SANs) using two bulk calls, so the cache
        # carries "the right cert" and its status with no per-profile round
        # trips. Best-effort: on any failure we still return the VIP inventory.
        try:
            clientssl_by_name = {}
            for prof in f5.list_clientssl_profiles():
                entry = {"cert": prof.get("cert", "") or "", "key": prof.get("key", "") or ""}
                for k in (prof.get("name"), prof.get("fullPath")):
                    if k:
                        clientssl_by_name.setdefault(k, entry)
            cert_by_path = {}
            for c in f5.list_ssl_certs():
                info = f5_cert_response_to_dict(c)
                for k in (c.get("name"), c.get("fullPath")):
                    if k:
                        cert_by_path.setdefault(k, info)
        except Exception as e:
            logger.warning("cert enrichment failed for %s: %s", target, e)
            clientssl_by_name, cert_by_path = {}, {}

        def _lookup_cert(ref):
            if not ref:
                return None
            return cert_by_path.get(ref) or cert_by_path.get(ref.split("/")[-1])

        for grp in groups.values():
            for port in grp["ports"]:
                ssl_profiles = []
                for pname in port.get("profiles", []):
                    prof = clientssl_by_name.get(pname) or clientssl_by_name.get(f"/Common/{pname}")
                    if not prof:
                        continue
                    cert_ref = prof.get("cert", "")
                    cinfo = _lookup_cert(cert_ref)
                    ssl_profiles.append({
                        "profile": pname,
                        "cert": cert_ref,
                        "key": prof.get("key", ""),
                        "commonName": (cinfo or {}).get("commonName", ""),
                        "notAfter": (cinfo or {}).get("notAfter", ""),
                        "issuer": (cinfo or {}).get("issuer", ""),
                        "sans": (cinfo or {}).get("sans", []),
                    })
                if ssl_profiles:
                    port["clientssl"] = ssl_profiles

        results.extend(groups.values())
        return results

    @run_on_executor
    def _list_vips(self, token_data, only_target=None):
        env_targets = list(iter_token_environments(token_data, only_target))
        results = []
        with ThreadPoolExecutor(max_workers=min(8, max(1, len(env_targets)))) as pool:
            futures = [pool.submit(self.collect_env_vips, env, env_session) for env, env_session in env_targets]
            for future in as_completed(futures):
                results.extend(future.result())
        results.sort(key=lambda x: x["name"])
        return results

    async def get(self):
        result = self.require_f5_reader()
        if not result:
            return
        _role, token_data = result
        try:
            only_target = (self.get_argument("target", "") or "").lower() or None
            if only_target:
                get_environment_by_id(only_target)
            vips = await self._list_vips(token_data=token_data, only_target=only_target)
            self.write({"success": True, "vips": vips, "target": only_target or "all"})
        except tornado.web.HTTPError as e:
            self.set_status(e.status_code)
            self.write({"success": False, "error": e.reason})
        except F5AuthError as e:
            self.set_status(401)
            self.write({"success": False, "error": f"F5 session expired — please log in again ({e})"})
        except Exception as e:
            logger.exception("Failed to list VIPs")
            self.set_status(500)
            self.write({"success": False, "error": str(e)})


class F5VIPListStreamHandler(BaseHandler):
    """
    GET /f5/vips/stream

    Streams VIP groups as NDJSON batches so the frontend can populate the
    picker while slower environments are still loading.
    """
    executor = ThreadPoolExecutor(max_workers=8)

    async def _write_event(self, event: str, **payload):
        self.write(json.dumps({"event": event, **payload}) + "\n")
        await self.flush()

    async def get(self):
        result = self.require_f5_reader()
        if not result:
            return
        _role, token_data = result
        try:
            only_target = (self.get_argument("target", "") or "").lower() or None
            if only_target:
                get_environment_by_id(only_target)
            env_targets = list(iter_token_environments(token_data, only_target))
            self.set_header("Content-Type", "application/x-ndjson; charset=utf-8")
            self.set_header("Cache-Control", "no-cache")
            self.set_header("X-Accel-Buffering", "no")
            await self._write_event("start", target=only_target or "all", environments=len(env_targets))

            # Pre-warm cache hits short-circuit the F5 round trip per env.
            live_targets = []
            for env, env_session in env_targets:
                cached = bg_cached_vips(env["id"])
                if cached is not None:
                    await self._write_event("batch", vips=cached, cached=True)
                else:
                    live_targets.append((env, env_session))

            loop = asyncio.get_running_loop()

            async def _fetch_env_vips(env, env_session):
                vips = await loop.run_in_executor(
                    self.executor,
                    F5VIPListHandler.collect_env_vips,
                    env,
                    env_session,
                )
                return env, vips

            tasks = [_fetch_env_vips(env, env_session) for env, env_session in live_targets]
            for task in asyncio.as_completed(tasks):
                env, vips = await task
                vips.sort(key=lambda x: x["name"])
                await self._write_event("batch", vips=vips)
                update_cache_vips(env["id"], vips)
            await self._write_event("done")
        except tornado.web.HTTPError as e:
            if self._finished:
                return
            self.set_status(e.status_code)
            self.write({"success": False, "error": e.reason})
        except F5AuthError as e:
            if self._finished:
                return
            if self._headers_written:
                # Streaming already began (200 sent) — flag the expiry in-band
                # so the frontend can drop the session and re-login.
                await self._write_event("error", error=str(e), auth_expired=True)
            else:
                self.set_status(401)
                self.write({"success": False, "error": f"F5 session expired — please log in again ({e})"})
        except Exception as e:
            logger.exception("Failed to stream VIPs")
            if self._finished:
                return
            if self._headers_written:
                await self._write_event("error", error=str(e))
            else:
                self.set_status(500)
                self.write({"success": False, "error": str(e)})



def _vs_destination_ip_port(vs: dict) -> tuple[str | None, str | None]:
    """Parse a virtual server's destination into (ip, port). port may be a
    numeric string, "0"/"any" for all-ports, or None when unparseable."""
    m = re.match(r"^/[^/]+/([0-9.]+):(\d+|any)$", vs.get("destination", ""))
    if not m:
        return None, None
    return m.group(1), m.group(2)


def _tmc_destination_ip(f5: "F5Client", tmc_path: str) -> str | None:
    """Resolve a traffic-matching-criteria's inline destination address (the VIP
    IP for a 17.x port-list virtual server)."""
    crit = f5.get_traffic_matching_criteria(tmc_path)
    if not crit:
        return None
    addr = (crit.get("destinationAddressInline") or "").strip()
    # strip a trailing mask if present (e.g. "172.20.63.157/32")
    return addr.split("/")[0] or None


def _vs_persistence(vs: dict) -> str:
    """Return the persistence profile name attached to a VS (or its fallback),
    or "" if none. Used to flag stateful VIPs in the status view."""
    persist = vs.get("persist") or []
    if isinstance(persist, list) and persist:
        name = (persist[0] or {}).get("name") or ""
        if name:
            return name
    fb = vs.get("fallbackPersistence")
    if fb:
        return _pool_key(fb)
    return ""


def find_existing_snat_pool(f5: "F5Client", vip_ip: str, virtuals: list | None = None) -> str | None:
    """The SNAT pool already bound to a virtual server on this VIP IP, or None
    when there is none (new VIP, or the existing VS uses automap).

    Add-port must reuse it rather than resolve a fresh address: when the mapped
    SNAT range is too small for host-preserving allocation, resolving again
    would hand the new port a different source address than the ports already
    on the VIP.
    """
    for vs in (f5.list_virtuals() if virtuals is None else virtuals):
        ip, _ = _vs_destination_ip_port(vs)
        if ip != vip_ip:
            tmc = vs.get("trafficMatchingCriteria")
            if not (tmc and _tmc_destination_ip(f5, tmc) == vip_ip):
                continue
        sat = vs.get("sourceAddressTranslation") or {}
        if sat.get("type") == "snat" and sat.get("pool"):
            return sat["pool"]
    return None


def find_all_ports_vs(f5: "F5Client", vip_ip: str, virtuals: list | None = None) -> dict | None:
    """Return the virtual server on this IP that handles traffic via a switch
    iRule rather than one VS per port: i.e. it listens on all ports (dest :0 /
    :any) or uses a destination port-list (trafficMatchingCriteria). Returns
    None for the classic discrete-port layout (one VS per port).

    Pass `virtuals` to reuse an already-fetched list_virtuals() result."""
    for vs in (f5.list_virtuals() if virtuals is None else virtuals):
        ip, port = _vs_destination_ip_port(vs)
        if ip == vip_ip and port in ("0", "any"):
            return vs
        # Port-list VS: the IP lives on the TMC, not the VS destination.
        tmc = vs.get("trafficMatchingCriteria")
        if tmc and _tmc_destination_ip(f5, tmc) == vip_ip:
            return vs
    return None


def create_f5_add_port_resources(params: dict) -> dict:
    vip_name = params["vip_name"]
    vip_ip = params["vip_ip"]
    port_str = str(params["port"])
    pool_members = params["pool_members"]
    ssl_enabled = bool(params.get("ssl_enabled", False))
    clientssl_profile = params.get("clientssl_profile")
    target = (params.get("target") or "").lower()

    # HTTPS monitor is mandatory — every new pool must have a real health check.
    monitor_uri = (params.get("monitor_uri") or "").strip()
    monitor_recv = (params.get("monitor_recv") or "").strip()
    if not monitor_uri or not monitor_recv:
        raise RuntimeError(
            "Health-check URI and expected response are required to add a port"
        )
    if not monitor_uri.startswith("/"):
        monitor_uri = "/" + monitor_uri
    monitor_send = f"GET {monitor_uri} HTTP/1.1\\r\\nHost: {vip_name}\\r\\nConnection: close\\r\\n\\r\\n"

    # SNAT: host-preserving remap when a mapping covers this VIP, the next free
    # address in the mapped range when it doesn't fit, otherwise automap rather
    # than failing the request.
    env_cfg = F5_ENVIRONMENTS_BY_ID.get(target) or {}

    f5 = F5Client(
        base_url=params["f5_url"], username="x", password="x", verify_ssl=False
    )
    f5.token = params["f5_token"]
    f5.session.headers.update({"X-F5-Auth-Token": params["f5_token"]})

    # One listing shared by the SNAT lookup and the layout probe below.
    virtuals = f5.list_virtuals()

    # Whatever the VIP's existing ports SNAT from, this port SNATs from too.
    snat_pool_path = find_existing_snat_pool(f5, vip_ip, virtuals)
    if snat_pool_path:
        logger.info("Reusing VIP %s's existing SNAT pool %s", vip_ip, snat_pool_path)
        snat_reason = "existing"
    else:
        snat_pool_path, snat_reason = resolve_snat_pool_for_vip(
            f5, env_cfg, vip_ip, env_label=target
        )
    snat_fallback = None if snat_pool_path else SNAT_FALLBACK_REASONS.get(snat_reason, snat_reason)

    pool_name = f"{vip_name}-{port_str}-pool"
    monitor_name = f"{vip_name}-{port_str}-monitor"

    # Decide the mode from the VIP's actual layout: a single all-ports / port-list
    # VS with a switch iRule, or the classic one-VS-per-port arrangement.
    all_ports_vs = find_all_ports_vs(f5, vip_ip, virtuals)

    if all_ports_vs is not None:
        result = _add_port_via_irule(
            f5, all_ports_vs, vip_name, vip_ip, port_str, pool_members,
            pool_name, monitor_name, monitor_send, monitor_recv, snat_pool_path,
        )
        result["snat_fallback_reason"] = snat_fallback
        return result

    # ---- discrete-port mode: one new VS per port (classic behavior) ----
    vs_name = f"{vip_name}-{port_str}-vip"
    if f5.virtual_exists(vs_name):
        raise RuntimeError(f"DUPLICATE_VIP_NAME: {vs_name}")

    f5.create_monitor(
        name=monitor_name,
        monitor_type="https",
        port=int(port_str),
        send=monitor_send,
        recv=monitor_recv,
    )

    pool_members_with_port = [
        {"ip_address": pm["ip_address"], "port": port_str}
        for pm in pool_members
    ]
    pool_full_name = f5.create_pool(
        name=pool_name,
        members=pool_members_with_port,
        monitor_name=f"/Common/{monitor_name}",
    )

    # On add-port we always attach the F5 default /Common/serverssl when SSL
    # is on — generating a SNI-specific server-ssl profile would require the
    # cert's CN, which the form here lets the user pick by client-ssl profile
    # name only. SNI add-port still works because create_virtual_server falls
    # back to /Common/serverssl when serverssl_profile is None.
    f5.create_virtual_server(
        name=vs_name,
        destination_ip=vip_ip,
        ports=[int(port_str)],
        pool_name=pool_full_name,
        ssl_enabled=ssl_enabled,
        clientssl_profile=clientssl_profile if ssl_enabled else None,
        snat_pool_path=snat_pool_path,
    )

    return {
        "mode": "vs",
        "vs_name": vs_name,
        "pool_name": pool_full_name,
        "monitor_name": monitor_name,
        "vip_ip": vip_ip,
        "snat_pool": snat_pool_path,
        "snat_fallback_reason": snat_fallback,
    }


def _add_port_via_irule(
    f5, all_ports_vs, vip_name, vip_ip, port_str, pool_members,
    pool_name, monitor_name, monitor_send, monitor_recv, snat_pool_path,
) -> dict:
    """Add a port to an all-ports / port-list VIP: create the pool, then add a
    `switch [TCP::local_port]` case as a NEW versioned iRule and re-point the VS
    at it. The previous version is left on the device for rollback."""
    vs_name = all_ports_vs.get("name")

    # Port-list VIPs (BIG-IP 17.x traffic-matching-criteria) carry their ports on
    # an ltm port-list, not the VS destination. Resolve that list now; we add the
    # new port to it at the very end, once the pool + iRule case exist, so the
    # port only goes live after it has somewhere to go.
    port_list_path = None
    tmc_path = all_ports_vs.get("trafficMatchingCriteria")
    if tmc_path:
        crit = f5.get_traffic_matching_criteria(tmc_path)
        port_list_path = (crit or {}).get("destinationPortList") or None
        if not port_list_path:
            raise RuntimeError(
                f"VIP {vip_name} ({vip_ip}) uses traffic-matching-criteria {tmc_path} "
                f"with no destination port-list; cannot add a port automatically."
            )
        existing_ports = f5.port_list_ports(f5.get_port_list(port_list_path) or {})
        if port_str in existing_ports:
            raise RuntimeError(
                f"Port {port_str} is already in the port-list ({port_list_path}) for {vip_name}"
            )

    # ---- pre-flight: find the active switch iRule and reject duplicate ports ----
    rules = list(all_ports_vs.get("rules") or [])
    active_rule_path = None
    active_body = None
    for rp in rules:
        ir = f5.get_irule(rp)
        body = (ir or {}).get("apiAnonymous") or ""
        if "[TCP::local_port]" in body:
            active_rule_path = rp
            active_body = body
            break

    if active_body is not None and port_str in parse_switch_ports(active_body):
        raise RuntimeError(
            f"Port {port_str} is already handled by this VIP's iRule ({active_rule_path})"
        )

    base = irule_base_name(vip_name)
    existing_versions = [
        r["name"] for r in f5.list_irules()
        if irule_version_of(r.get("name", ""), base) is not None
    ]

    # ---- create the pool (+monitor) for the new port ----
    f5.create_monitor(
        name=monitor_name,
        monitor_type="https",
        port=int(port_str),
        send=monitor_send,
        recv=monitor_recv,
    )
    pool_members_with_port = [
        {"ip_address": pm["ip_address"], "port": port_str} for pm in pool_members
    ]
    pool_full_name = f5.create_pool(
        name=pool_name,
        members=pool_members_with_port,
        monitor_name=f"/Common/{monitor_name}",
    )

    # ---- build + create the next iRule version, then re-point the VS ----
    new_version = next_irule_version(existing_versions, base)
    from_version = irule_version_of(active_rule_path or "", base)

    # If a switch iRule exists but isn't yet under our versioning scheme,
    # snapshot it as the current version so rollback has a target.
    if active_body is not None and from_version is None:
        f5.create_irule(f"{base}_v{new_version}", active_body)
        from_version = new_version
        new_version += 1

    if active_body is None:
        # All-ports VS with no switch iRule yet: seed one, sending unmatched
        # ports to the VS's existing default pool (if any).
        default_pool = all_ports_vs.get("pool") or None
        new_body = build_switch_irule([(port_str, pool_full_name)], default_pool)
    else:
        new_body = add_switch_case(active_body, port_str, pool_full_name)

    new_irule_name = f"{base}_v{new_version}"
    new_path = f5.create_irule(new_irule_name, new_body)  # F5 validates the Tcl here

    new_rules = [r for r in rules if r != active_rule_path] + [new_path]
    f5.set_virtual_rules(vs_name, new_rules)

    # Finally, for a port-list VIP, open the new port on the VS now that the
    # iRule routes it. (All-ports :0 VIPs already accept every port.)
    if port_list_path:
        f5.add_port_to_port_list(port_list_path, port_str)

    return {
        "mode": "irule",
        "vs_name": vs_name,
        "pool_name": pool_full_name,
        "monitor_name": monitor_name,
        "vip_ip": vip_ip,
        "snat_pool": snat_pool_path,
        "irule_name": new_irule_name,
        "irule_version": new_version,
        "irule_from_version": from_version,
        "port_list": port_list_path,
    }


class F5AddPortHandler(BaseHandler):
    """
    POST /f5/add-port
    Authorization: Bearer <token>
    Content-Type: application/json

    Body:
    {
      "vip_name": "myapp.example.org",
      "vip_ip": "10.20.10.5",
      "target": "dmz" | "dc",
      "port": "8443",
      "pool_members": [{"ip_address": "10.10.10.10"}, ...],
      "monitor_type": "tcp" | "https",   // optional, default tcp
      "ssl_enabled": false,               // optional
      "clientssl_profile": "/Common/x"    // optional, reuse existing profile
    }

    Creates new pool/monitor/VS on the SAME VIP IP using the existing
    naming convention <vip_name>-<port>-{pool,vip,monitor}.
    """
    executor = ThreadPoolExecutor(max_workers=4)

    @run_on_executor
    def _add_port(self, params):
        return create_f5_add_port_resources(params)

    async def post(self):
        token_data = self.require_auth()
        if not token_data:
            return
        try:
            data = json.loads(self.request.body.decode("utf-8"))
            vip_name_raw = (data.get("vip_name") or "").strip()
            vip_name = sanitize_vip_name(vip_name_raw)
            vip_ip = (data.get("vip_ip") or "").strip()
            target = (data.get("target") or "").lower()
            port = data.get("port")
            pool_members = data.get("pool_members") or []

            if not vip_name or not vip_ip or not target or not port:
                raise tornado.web.HTTPError(400, reason="Missing or invalid required fields")
            if not is_valid_ipv4(vip_ip):
                raise tornado.web.HTTPError(400, reason=f"Invalid VIP IP: {vip_ip}")
            if not is_valid_port(str(port)):
                raise tornado.web.HTTPError(400, reason=f"Invalid port: {port}")
            if not pool_members:
                raise tornado.web.HTTPError(400, reason="At least one pool member is required")
            for pm in pool_members:
                ip = pm.get("ip_address")
                if not ip or not is_valid_ipv4(ip):
                    raise tornado.web.HTTPError(400, reason=f"Invalid pool member IP: {ip}")

            _env, env_session = get_token_environment(token_data, target)
            f5_token = env_session.get("token")
            f5_url = env_session.get("url")
            if not f5_token or not f5_url:
                raise tornado.web.HTTPError(401, reason=f"No F5 token for target {target}")

            monitor_uri = (data.get("monitor_uri") or "").strip()
            monitor_recv = (data.get("monitor_recv") or "").strip()
            if not monitor_uri or not monitor_recv:
                raise tornado.web.HTTPError(
                    400,
                    reason="monitor_uri (health-check path) and monitor_recv (expected response) are required",
                )

            result = await self._add_port({
                "vip_name": vip_name,
                "vip_ip": vip_ip,
                "target": target,
                "port": port,
                "pool_members": pool_members,
                "monitor_type": "https",
                "monitor_uri": monitor_uri,
                "monitor_recv": monitor_recv,
                "ssl_enabled": data.get("ssl_enabled", False),
                "clientssl_profile": data.get("clientssl_profile"),
                "f5_url": f5_url,
                "f5_token": f5_token,
            })

            audit_log(
                action="vipport.add",
                target=f"{vip_name}:{port}",
                user=token_data.get("username", "?"),
                user_type="admin",
                result="success",
                client_ip=self.get_client_ip(),
                revertible=True,
                details={
                    "target": target,
                    "mode": result.get("mode"),
                    "vs_name": result.get("vs_name"),
                    "pool_name": result.get("pool_name"),
                    "monitor_name": result.get("monitor_name"),
                    "monitor_type": "https",
                    "vip_ip": vip_ip,
                    "port": str(port),
                    # iRule-mode rollback metadata (absent in discrete-VS mode)
                    "irule_name": result.get("irule_name"),
                    "irule_version": result.get("irule_version"),
                    "irule_from_version": result.get("irule_from_version"),
                    "port_list": result.get("port_list"),
                },
            )
            self.write({"success": True, **result})
        except tornado.web.HTTPError as e:
            self.set_status(e.status_code)
            self.write({"success": False, "error": e.reason})
        except json.JSONDecodeError:
            self.set_status(400)
            self.write({"success": False, "error": "Invalid JSON body"})
        except Exception as e:
            err_str = str(e)
            if "DUPLICATE_VIP_NAME" in err_str:
                names_part = err_str.split("DUPLICATE_VIP_NAME:", 1)[1].strip() if "DUPLICATE_VIP_NAME:" in err_str else ""
                self.set_status(409)
                self.write({
                    "success": False,
                    "error": f"A VIP with this name already exists: {names_part}",
                    "code": "duplicate_vip_name",
                    "existing": [n.strip() for n in names_part.split(",") if n.strip()],
                })
            else:
                logger.exception("add-port error")
                self.set_status(500)
                self.write({"success": False, "error": err_str})


class F5AddPortRequestHandler(BaseHandler):
    """
    POST /f5/add-port/request

    Stores an add-port request for admin approval. This does not write to F5.
    """
    def post(self):
        try:
            data = json.loads(self.request.body.decode("utf-8"))
            vip_name_raw = (data.get("vip_name") or "").strip()
            vip_name = sanitize_vip_name(vip_name_raw)
            vip_ip = (data.get("vip_ip") or "").strip()
            target = (data.get("target") or "").lower()
            port = str(data.get("port") or "").strip()
            pool_members = data.get("pool_members") or []
            requester = (data.get("email") or "").strip()

            if requester and not is_valid_email(requester):
                raise tornado.web.HTTPError(400, reason="Invalid requester email address")
            if vip_name_raw and ("\r" in vip_name_raw or "\n" in vip_name_raw):
                raise tornado.web.HTTPError(400, reason="VIP name contains illegal characters")

            if not vip_name or not vip_ip or not target or not port:
                raise tornado.web.HTTPError(400, reason="Missing or invalid required fields")
            if not requester:
                raise tornado.web.HTTPError(400, reason="Requester email is required")
            get_environment_by_id(target)
            if not is_valid_ipv4(vip_ip):
                raise tornado.web.HTTPError(400, reason=f"Invalid VIP IP: {vip_ip}")
            if not is_valid_port(port):
                raise tornado.web.HTTPError(400, reason=f"Invalid port: {port}")
            if not pool_members:
                raise tornado.web.HTTPError(400, reason="At least one pool member is required")
            for pm in pool_members:
                ip = pm.get("ip_address")
                if not ip or not is_valid_ipv4(ip):
                    raise tornado.web.HTTPError(400, reason=f"Invalid pool member IP: {ip}")

            monitor_uri = (data.get("monitor_uri") or "").strip()
            monitor_recv = (data.get("monitor_recv") or "").strip()
            if not monitor_uri or not monitor_recv:
                raise tornado.web.HTTPError(
                    400,
                    reason="monitor_uri (health-check path) and monitor_recv (expected response) are required",
                )

            request_id = str(uuid.uuid4())
            record = {
                "id": request_id,
                "request_type": "add_port",
                "vip_name": vip_name,
                "vip_name_original": vip_name_raw,
                "vip_ip": vip_ip,
                "email": requester,
                "ports": [port],
                "ssl_enabled": bool(data.get("ssl_enabled", False)),
                "clientssl_profile": data.get("clientssl_profile"),
                "monitor_type": "https",
                "monitor_uri": monitor_uri,
                "monitor_recv": monitor_recv,
                "pool_members": pool_members,
                "f5_target": target,
                "status": "pending",
                "created_at": datetime.utcnow().isoformat(),
            }
            add_vip_request(record)
            send_team_notification(record, SMTP_HOST, SMTP_PORT)
            send_requester_notification(record, SMTP_HOST, SMTP_PORT)
            audit_log(
                action="vipport.request",
                target=f"{vip_name}:{port}",
                user=requester or "anonymous",
                user_type="requester",
                result="success",
                client_ip=self.get_client_ip(),
                revertible=False,
                details={"request_id": request_id, "target": target, "vip_ip": vip_ip, "port": port},
            )
            self.write({"success": True, "id": request_id, "message": "Add-port request stored for admin approval"})
        except tornado.web.HTTPError as e:
            self.set_status(e.status_code)
            self.write({"success": False, "error": e.reason})
        except json.JSONDecodeError:
            self.set_status(400)
            self.write({"success": False, "error": "Invalid JSON body"})
        except Exception as e:
            logger.exception("add-port request error")
            self.set_status(500)
            self.write({"success": False, "error": str(e)})


def list_irule_versions(f5: "F5Client", vip_name: str, vip_ip: str) -> dict:
    """Enumerate the <vip>_irule_vN objects on the device and report which one
    the all-ports VS is currently using, so an admin can pick a rollback target."""
    base = irule_base_name(vip_name)
    versions = []
    for r in f5.list_irules():
        n = irule_version_of(r.get("name", ""), base)
        if n is not None:
            versions.append({
                "version": n,
                "name": r.get("name"),
                "path": r.get("fullPath") or f"/Common/{r.get('name')}",
            })
    versions.sort(key=lambda v: v["version"])

    vs = find_all_ports_vs(f5, vip_ip)
    active_version = None
    if vs:
        for rp in (vs.get("rules") or []):
            n = irule_version_of(rp, base)
            if n is not None:
                active_version = n
                break
    return {
        "base": base,
        "versions": versions,
        "active_version": active_version,
        "vs_name": vs.get("name") if vs else None,
    }


def rollback_irule(f5: "F5Client", vip_name: str, vip_ip: str, to_version: int) -> dict:
    """Re-point the all-ports VS at a prior iRule version. Other (non-versioned)
    rules attached to the VS are preserved; the single versioned slot is swapped."""
    base = irule_base_name(vip_name)
    target_name = f"{base}_v{to_version}"
    if not f5.irule_exists(target_name):
        raise RuntimeError(f"iRule version v{to_version} ({target_name}) does not exist")
    vs = find_all_ports_vs(f5, vip_ip)
    if not vs:
        raise RuntimeError(f"No all-ports iRule virtual server found for {vip_name} ({vip_ip})")

    target_path = f"/Common/{target_name}"
    new_rules = []
    replaced = False
    for rp in (vs.get("rules") or []):
        if irule_version_of(rp, base) is not None:
            if not replaced:
                new_rules.append(target_path)
                replaced = True
            # drop any other versioned rules (there should only be one)
        else:
            new_rules.append(rp)
    if not replaced:
        new_rules.append(target_path)

    f5.set_virtual_rules(vs.get("name"), new_rules)
    return {"vs_name": vs.get("name"), "active_version": to_version, "irule_name": target_name}


class F5IRuleVersionsHandler(BaseHandler):
    """
    GET /f5/irule/versions?vip_name=<name>&vip_ip=<ip>&target=<env-id>

    Lists the versioned switch iRules (<vip>_irule_vN) for an all-ports VIP and
    the version the VS is currently using. Requires a valid login.
    """
    executor = ThreadPoolExecutor(max_workers=4)

    @run_on_executor
    def _versions(self, f5_url, f5_token, vip_name, vip_ip):
        f5 = F5Client(base_url=f5_url, username="x", password="x", verify_ssl=False)
        f5.token = f5_token
        f5.session.headers.update({"X-F5-Auth-Token": f5_token})
        return list_irule_versions(f5, vip_name, vip_ip)

    async def get(self):
        token_data = self.require_auth()
        if not token_data:
            return
        try:
            vip_name = sanitize_vip_name((self.get_argument("vip_name", "") or "").strip())
            vip_ip = (self.get_argument("vip_ip", "") or "").strip()
            target = (self.get_argument("target", "") or "").lower()
            if not vip_name or not vip_ip or not target:
                raise tornado.web.HTTPError(400, reason="vip_name, vip_ip and target are required")
            if not is_valid_ipv4(vip_ip):
                raise tornado.web.HTTPError(400, reason=f"Invalid VIP IP: {vip_ip}")
            _env, env_session = get_token_environment(token_data, target)
            f5_token = env_session.get("token")
            f5_url = env_session.get("url")
            if not f5_token or not f5_url:
                raise tornado.web.HTTPError(401, reason=f"No F5 token for target {target}")
            result = await self._versions(f5_url, f5_token, vip_name, vip_ip)
            self.write({"success": True, **result})
        except tornado.web.HTTPError as e:
            self.set_status(e.status_code)
            self.write({"success": False, "error": e.reason})
        except Exception as e:
            logger.exception("irule versions error")
            self.set_status(500)
            self.write({"success": False, "error": str(e)})


class F5IRuleRollbackHandler(BaseHandler):
    """
    POST /f5/irule/rollback
    Body: {"vip_name": "...", "vip_ip": "...", "target": "lan", "to_version": 2}

    Re-points an all-ports VIP's virtual server at a prior iRule version.
    Requires a valid login.
    """
    executor = ThreadPoolExecutor(max_workers=4)

    @run_on_executor
    def _rollback(self, f5_url, f5_token, vip_name, vip_ip, to_version):
        f5 = F5Client(base_url=f5_url, username="x", password="x", verify_ssl=False)
        f5.token = f5_token
        f5.session.headers.update({"X-F5-Auth-Token": f5_token})
        return rollback_irule(f5, vip_name, vip_ip, to_version)

    async def post(self):
        token_data = self.require_auth()
        if not token_data:
            return
        try:
            data = json.loads(self.request.body.decode("utf-8"))
            vip_name = sanitize_vip_name((data.get("vip_name") or "").strip())
            vip_ip = (data.get("vip_ip") or "").strip()
            target = (data.get("target") or "").lower()
            to_version = data.get("to_version")
            if not vip_name or not vip_ip or not target or to_version is None:
                raise tornado.web.HTTPError(400, reason="vip_name, vip_ip, target and to_version are required")
            if not is_valid_ipv4(vip_ip):
                raise tornado.web.HTTPError(400, reason=f"Invalid VIP IP: {vip_ip}")
            try:
                to_version = int(to_version)
            except (TypeError, ValueError):
                raise tornado.web.HTTPError(400, reason="to_version must be an integer")
            _env, env_session = get_token_environment(token_data, target)
            f5_token = env_session.get("token")
            f5_url = env_session.get("url")
            if not f5_token or not f5_url:
                raise tornado.web.HTTPError(401, reason=f"No F5 token for target {target}")

            result = await self._rollback(f5_url, f5_token, vip_name, vip_ip, to_version)
            audit_log(
                action="irule.rollback",
                target=f"{vip_name}->v{to_version}",
                user=token_data.get("username", "?"),
                user_type="admin",
                result="success",
                client_ip=self.get_client_ip(),
                revertible=False,
                details={"target": target, "vip_ip": vip_ip, **result},
            )
            self.write({"success": True, **result})
        except tornado.web.HTTPError as e:
            self.set_status(e.status_code)
            self.write({"success": False, "error": e.reason})
        except json.JSONDecodeError:
            self.set_status(400)
            self.write({"success": False, "error": "Invalid JSON body"})
        except Exception as e:
            logger.exception("irule rollback error")
            self.set_status(500)
            self.write({"success": False, "error": str(e)})


class F5CertInfoHandler(BaseHandler):
    """
    GET /f5/cert-info?target=<environment-id>&profile=<full-path>

    Returns metadata (CN, SAN, expiration, issuer) for the cert bound to
    the given client-SSL profile.
    """
    executor = ThreadPoolExecutor(max_workers=4)

    @run_on_executor
    def _get_cert_info(self, base_url, token, profile_path):
        f5 = F5Client(base_url=base_url, username="x", password="x", verify_ssl=False)
        f5.token = token
        f5.session.headers.update({"X-F5-Auth-Token": token})

        profile = f5.get_clientssl_profile(profile_path)
        if not profile:
            raise RuntimeError(f"Client-SSL profile not found: {profile_path}")

        cert_ref = profile.get("cert") or ""
        if not cert_ref:
            raise RuntimeError(f"Profile {profile_path} has no cert reference")

        cert = f5.get_ssl_cert(cert_ref)
        if not cert:
            raise RuntimeError(f"Cert not found: {cert_ref}")

        info = f5_cert_response_to_dict(cert)
        info["profile"] = profile.get("fullPath", profile_path)
        info["certRef"] = cert_ref
        info["keyRef"] = profile.get("key", "")
        return info

    async def get(self):
        result = self.require_auth_unified()
        if not result:
            return
        _role, token_data = result
        try:
            target = (self.get_argument("target", "") or "").lower()
            profile = self.get_argument("profile", "")
            if not profile:
                raise tornado.web.HTTPError(400, reason="Missing profile")
            _env, env_session = get_token_environment(token_data, target)
            base_url = env_session.get("url")
            token = env_session.get("token")
            if not base_url or not token:
                raise tornado.web.HTTPError(401, reason=f"No F5 token for target {target}")

            info = await self._get_cert_info(base_url, token, profile)
            self.write({"success": True, "info": info})
        except tornado.web.HTTPError as e:
            self.set_status(e.status_code)
            self.write({"success": False, "error": e.reason})
        except Exception as e:
            logger.exception("cert-info error")
            self.set_status(500)
            self.write({"success": False, "error": str(e)})


class F5ParsePfxHandler(BaseHandler):
    """
    POST /f5/parse-pfx (multipart)
    Fields: pfx_file (binary), pfx_password (string)

    Parses the uploaded PFX locally (without uploading to F5) and returns
    cert metadata. Used by the UI to show new-cert info next to current
    cert before the admin commits.
    """
    async def post(self):
        result = self.require_auth_unified()
        if not result:
            return
        _role, token_data = result
        try:
            files = self.request.files.get("pfx_file")
            if not files or not files[0]:
                raise tornado.web.HTTPError(400, reason="pfx_file required")
            pfx_body = files[0]["body"]
            password = self.get_argument("pfx_password", "")
            try:
                info = parse_pfx_cert_info(pfx_body, password)
            except ValueError as ve:
                raise tornado.web.HTTPError(400, reason=str(ve))
            self.write({"success": True, "info": info})
        except tornado.web.HTTPError as e:
            self.set_status(e.status_code)
            self.write({"success": False, "error": e.reason})
        except Exception as e:
            logger.exception("parse-pfx error")
            self.set_status(500)
            self.write({"success": False, "error": str(e)})


class F5ReplaceCertHandler(BaseHandler):
    """
    POST /f5/replace-cert (multipart)

    Fields:
      target: "dmz" | "dc"
      vip_name: VIP root name (e.g. "myapp.example.org")
      pfx_file: PFX binary
      pfx_password: PFX password
      mode: "replace" | "create"
      profile: full path of existing profile  (mode=replace)
      attach_vs: VS name to attach to         (mode=create)

    Replace mode: imports the new PFX as a new cert+key and PATCHes the
    existing client-SSL profile to point at them.

    Create mode: imports the new PFX, creates a new client-SSL profile
    named <vip_name>-clientssl, and attaches it to the specified VS.
    """
    executor = ThreadPoolExecutor(max_workers=4)

    @run_on_executor
    def _replace_or_create(self, params):
        base_url = params["f5_url"]
        token = params["f5_token"]
        vip_name = params["vip_name"]
        mode = params["mode"]
        pfx_bytes = params["pfx_bytes"]
        pfx_password = params["pfx_password"]
        profile_path = params.get("profile")
        attach_vs = params.get("attach_vs")

        f5 = F5Client(base_url=base_url, username="x", password="x", verify_ssl=False)
        f5.token = token
        f5.session.headers.update({"X-F5-Auth-Token": token})

        try:
            validate_pfx_password(pfx_bytes, pfx_password)
        except ValueError as ve:
            raise RuntimeError(str(ve))

        ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        upload_name = f"{vip_name}-{ts}.pfx"
        remote_path = f5.upload_file(upload_name, pfx_bytes)

        cert_name, key_name = f5.import_pkcs12(
            remote_path=remote_path,
            name=upload_name,
            passphrase=pfx_password,
        )

        if mode == "replace":
            if not profile_path:
                raise RuntimeError("Missing profile for replace mode")
            # Capture old cert/key BEFORE we change anything, so revert can put them back.
            old_profile = f5.get_clientssl_profile(profile_path) or {}
            old_cert_ref = old_profile.get("cert") or ""
            old_key_ref = old_profile.get("key") or ""
            f5.update_clientssl_profile_cert(
                profile_name=profile_path,
                cert_name=cert_name,
                key_name=key_name,
            )
            return {
                "mode": "replace",
                "profile": profile_path,
                "cert": f"/Common/{cert_name}",
                "key": f"/Common/{key_name}",
                "old_cert": old_cert_ref,
                "old_key": old_key_ref,
            }
        else:
            profile_name = f"{vip_name}-clientssl"
            new_profile_path = f5.create_clientssl_profile(
                name=profile_name,
                cert_name=cert_name,
                key_name=key_name,
            )
            attached_to = None
            if attach_vs:
                f5.attach_profile_to_vs(
                    vs_name=attach_vs,
                    profile_name=profile_name,
                )
                attached_to = attach_vs
            return {
                "mode": "create",
                "profile": new_profile_path,
                "cert": f"/Common/{cert_name}",
                "key": f"/Common/{key_name}",
                "attached_to": attached_to,
            }

    async def post(self):
        # Interactive cert changes are admin-only. Automated cert changes go
        # through the Basic-auth API at /api/v1/replace-cert.
        result = self.require_auth_unified()
        if not result:
            return
        _role, token_data = result
        if _role != "admin":
            self.set_status(403)
            self.write({
                "success": False,
                "error": "Certificate changes are available to admins (log in with your F5 account) or via the /api/v1/replace-cert API.",
            })
            return
        try:
            target = (self.get_argument("target", "") or "").lower()
            vip_name_raw = self.get_argument("vip_name", "")
            vip_name = sanitize_vip_name(vip_name_raw)
            mode = (self.get_argument("mode", "replace") or "replace").lower()
            profile = self.get_argument("profile", "") if mode == "replace" else None
            attach_vs = self.get_argument("attach_vs", "") if mode == "create" else None

            files = self.request.files.get("pfx_file")
            if not files or not files[0]:
                raise tornado.web.HTTPError(400, reason="pfx_file required")
            pfx_body = files[0]["body"]
            pfx_password = self.get_argument("pfx_password", "")

            if not vip_name:
                raise tornado.web.HTTPError(400, reason="vip_name required")
            if mode not in ("replace", "create"):
                raise tornado.web.HTTPError(400, reason="mode must be 'replace' or 'create'")
            if mode == "replace" and not profile:
                raise tornado.web.HTTPError(400, reason="profile required for replace mode")
            if mode == "create" and not attach_vs:
                raise tornado.web.HTTPError(400, reason="attach_vs required for create mode")

            _env, env_session = get_token_environment(token_data, target)
            f5_token = env_session.get("token")
            f5_url = env_session.get("url")
            if not f5_token or not f5_url:
                raise tornado.web.HTTPError(401, reason=f"No F5 token for target {target}")

            result = await self._replace_or_create({
                "f5_url": f5_url,
                "f5_token": f5_token,
                "vip_name": vip_name,
                "mode": mode,
                "pfx_bytes": pfx_body,
                "pfx_password": pfx_password,
                "profile": profile,
                "attach_vs": attach_vs,
            })

            # Build revertible audit entry
            audit_details = {
                "target": target,
                "vip_name": vip_name,
                "mode": result.get("mode"),
                "profile": result.get("profile"),
                "cert": result.get("cert"),
                "key": result.get("key"),
            }
            if result.get("mode") == "replace":
                audit_details["old_cert"] = result.get("old_cert")
                audit_details["old_key"] = result.get("old_key")
            else:
                audit_details["attached_to"] = result.get("attached_to")

            audit_log(
                action=("cert.replace" if result.get("mode") == "replace" else "cert.create"),
                target=result.get("profile") or vip_name,
                user=token_data.get("username", "?"),
                user_type="admin",
                result="success",
                client_ip=self.get_client_ip(),
                revertible=True,
                details=audit_details,
            )
            self.write({"success": True, **result})
        except tornado.web.HTTPError as e:
            self.set_status(e.status_code)
            self.write({"success": False, "error": e.reason})
        except Exception as e:
            logger.exception("replace-cert error")
            self.set_status(500)
            self.write({"success": False, "error": str(e)})


class CertReplaceApiHandler(BaseHandler):
    """
    POST /api/v1/replace-cert   (multipart/form-data)

    Replace the certificate on the client-SSL profile bound to a VIP.

    Auth: HTTP Basic with the caller's OWN F5 credentials. The app authenticates
    to F5 as that user and performs the write as them (F5 RBAC governs what they
    may change). Discovery of the VIP + profile is done separately with the
    read-only service account, so the write account only needs cert permissions.

    Form fields:
      vip           (str,  required) DNS name or IP of the VIP
      pfx_file      (file, required) PKCS#12 (.pfx/.p12) bundle
      pfx_password  (str,  required) password protecting the PFX
      expire_year   (str,  required) year used in the cert object name
      target        (str,  optional) environment id, to disambiguate
      profile       (str,  optional) client-SSL profile, to disambiguate

    Flow: resolve DNS->IP -> find the VIP by IP + its client-SSL profile (read
    account) -> parse the PFX for the FQDN (CN) -> upload + import the PKCS12 as
    "<fqdn>_<year>" -> PATCH the profile to the new cert/key as the Basic user.
    """
    executor = ThreadPoolExecutor(max_workers=4)

    @run_on_executor
    def _do_replace(self, base_url, f5_user, f5_pass, profile_path, pfx_bytes, pfx_password, object_name):
        # Authenticate to F5 as the calling user (their creds, their RBAC).
        try:
            user_token = authenticate_with_f5(base_url, f5_user, f5_pass)
        except Exception as e:
            raise PermissionError(f"F5 authentication failed for user '{f5_user}': {e}")

        f5 = F5Client(base_url=base_url, username="x", password="x", verify_ssl=False)
        f5.token = user_token
        f5.session.headers.update({"X-F5-Auth-Token": user_token})

        # Non-destructive idempotency: if the deterministic name is already taken,
        # append a short timestamp rather than deleting a possibly-referenced cert.
        final_name = object_name
        if f5.get_ssl_cert(final_name):
            final_name = f"{object_name}_{datetime.utcnow().strftime('%H%M%S')}"

        upload_name = f"{final_name}.pfx"
        remote_path = f5.upload_file(upload_name, pfx_bytes)
        cert_name, key_name = f5.import_pkcs12(
            remote_path=remote_path,
            name=upload_name,
            passphrase=pfx_password,
            object_name=final_name,
        )

        old_profile = f5.get_clientssl_profile(profile_path) or {}
        old_cert_ref = old_profile.get("cert") or ""
        old_key_ref = old_profile.get("key") or ""
        f5.update_clientssl_profile_cert(
            profile_name=profile_path,
            cert_name=cert_name,
            key_name=key_name,
        )
        return {
            "cert": f"/Common/{cert_name}",
            "key": f"/Common/{key_name}",
            "old_cert": old_cert_ref,
            "old_key": old_key_ref,
        }

    @run_on_executor
    def _prepare(self, vip_in, pfx_bytes, pfx_password, target, profile_hint):
        """Blocking pre-work, run off the IOLoop: validate the PFX, derive the
        FQDN, resolve DNS->IP, and discover the VIP + client-SSL profile via the
        read-only account. Raises ValueError for bad input (-> 400) and
        RuntimeError for discovery/service problems (-> 404/503)."""
        validate_pfx_password(pfx_bytes, pfx_password)
        info = parse_pfx_cert_info(pfx_bytes, pfx_password)
        fqdn = (info.get("commonName") or "").strip()
        if not fqdn and not looks_like_ip(vip_in):
            fqdn = vip_in  # fall back to the DNS name the caller supplied
        if not fqdn:
            raise ValueError("Could not determine FQDN from the certificate; supply a DNS name as 'vip'")
        ip = resolve_vip_to_ip(vip_in)
        disc = find_vip_clientssl_by_ip(ip, only_target=target, profile_hint=profile_hint)
        return fqdn, ip, disc

    async def post(self):
        creds = self.get_f5_basic_credentials()
        if not creds:
            self.set_header("WWW-Authenticate", 'Basic realm="F5 Cert Replace API"')
            self.set_status(401)
            self.write({"success": False, "error": "Missing or invalid HTTP Basic credentials (send your F5 username/password)."})
            return
        f5_user, f5_pass = creds
        try:
            vip_in = (self.get_argument("vip", "") or "").strip()
            pfx_password = self.get_argument("pfx_password", "")
            expire_year = (self.get_argument("expire_year", "") or "").strip()
            target = (self.get_argument("target", "") or "").strip().lower() or None
            profile_hint = (self.get_argument("profile", "") or "").strip() or None

            if not vip_in:
                raise tornado.web.HTTPError(400, reason="vip is required")
            if not expire_year:
                raise tornado.web.HTTPError(400, reason="expire_year is required")
            files = self.request.files.get("pfx_file")
            if not files or not files[0]:
                raise tornado.web.HTTPError(400, reason="pfx_file is required")
            pfx_bytes = files[0]["body"]
            if not pfx_password:
                raise tornado.web.HTTPError(400, reason="pfx_password is required")

            # 1-3) Validate PFX, derive FQDN, resolve DNS->IP, and discover the
            # VIP + client-SSL profile. All blocking work runs off the IOLoop.
            try:
                fqdn, ip, disc = await self._prepare(vip_in, pfx_bytes, pfx_password, target, profile_hint)
            except ValueError as ve:
                raise tornado.web.HTTPError(400, reason=str(ve))
            except RuntimeError as re_:
                msg = str(re_)
                code = 503 if "service account" in msg.lower() else 404
                raise tornado.web.HTTPError(code, reason=msg)

            object_name = cert_object_name(fqdn, expire_year)

            # 4) Perform the write as the Basic-auth (F5) user.
            try:
                result = await self._do_replace(
                    disc["base_url"], f5_user, f5_pass, disc["profile"],
                    pfx_bytes, pfx_password, object_name,
                )
            except PermissionError as pe:
                self.set_status(401)
                self.write({"success": False, "error": str(pe)})
                return

            audit_log(
                action="cert.replace",
                target=disc["profile"],
                user=f5_user,
                user_type="api",
                result="success",
                client_ip=self.get_client_ip(),
                revertible=True,
                details={
                    "api": "replace-cert",
                    "vip_input": vip_in,
                    "vip_ip": ip,
                    "env": disc["env_id"],
                    "fqdn": fqdn,
                    "expire_year": expire_year,
                    "profile": disc["profile"],
                    "cert": result.get("cert"),
                    "key": result.get("key"),
                    "old_cert": result.get("old_cert"),
                    "old_key": result.get("old_key"),
                },
            )
            self.write({
                "success": True,
                "vip": vip_in,
                "vip_ip": ip,
                "environment": disc["env_id"],
                "fqdn": fqdn,
                "profile": disc["profile"],
                **result,
            })
        except tornado.web.HTTPError as e:
            self.set_status(e.status_code)
            self.write({"success": False, "error": e.reason})
        except Exception as e:
            logger.exception("replace-cert API error")
            self.set_status(500)
            self.write({"success": False, "error": str(e)})


class AuditHandler(BaseHandler):
    """
    GET /audit?type=admin|api|requester&search=...&limit=200
    Requires login. Returns most-recent-first audit entries from audit.jsonl.
    """
    def get(self):
        admin_data = self.require_admin()
        if not admin_data:
            return
        try:
            user_type = (self.get_argument("type", "") or "").strip().lower() or None
            if user_type and user_type not in ("admin", "api", "requester"):
                user_type = None
            search = self.get_argument("search", "") or ""
            try:
                limit = int(self.get_argument("limit", "200"))
            except Exception:
                limit = 200
            limit = max(1, min(limit, 1000))
            entries = audit_list(user_type=user_type, limit=limit, search=search)
            self.write({"success": True, "entries": entries})
        except Exception as e:
            logger.exception("audit list error")
            self.set_status(500)
            self.write({"success": False, "error": str(e)})


class RevertHandler(BaseHandler):
    """
    POST /audit/revert  (JSON body: {"id": "<audit-entry-id>"})
    Admin-only. Looks up the audit entry by id and performs the inverse
    F5 operation (delete VS/pool/monitor, swap back cert+key, etc.).
    Writes a new audit entry recording the revert.
    """
    executor = ThreadPoolExecutor(max_workers=4)

    @run_on_executor
    def _do_revert(self, entry: dict, token_data: dict) -> dict:
        action = entry.get("action", "")
        details = entry.get("details", {}) or {}
        target = (details.get("target") or "").lower()

        _env, env_session = get_token_environment(token_data, target)
        f5_token = env_session.get("token")
        f5_url = env_session.get("url")
        if not f5_token or not f5_url:
            raise RuntimeError(f"No F5 token available for target '{target}'")

        f5 = F5Client(base_url=f5_url, username="x", password="x", verify_ssl=False)
        f5.token = f5_token
        f5.session.headers.update({"X-F5-Auth-Token": f5_token})

        result = {"action": action, "undone": []}

        if (action == "vipport.add" or action == "vipport.approve") and details.get("mode") == "irule":
            # iRule-mode add: the VS is shared (all-ports) — DON'T delete it.
            # Re-point it to the prior iRule version (or strip the rule we added
            # when there was no prior), then remove the new pool/monitor/iRule.
            vip_ip = details.get("vip_ip")
            entry_target = entry.get("target", "")
            vip_name = entry_target.rsplit(":", 1)[0] if ":" in entry_target else entry_target
            base = irule_base_name(vip_name)
            from_version = details.get("irule_from_version")
            new_irule = details.get("irule_name")
            try:
                if from_version:
                    rb = rollback_irule(f5, vip_name, vip_ip, int(from_version))
                    result["undone"].append(f"irule->v{from_version} on {rb.get('vs_name')}")
                else:
                    vs_obj = find_all_ports_vs(f5, vip_ip)
                    if vs_obj:
                        kept = [r for r in (vs_obj.get("rules") or []) if irule_version_of(r, base) is None]
                        f5.set_virtual_rules(vs_obj.get("name"), kept)
                        result["undone"].append("irule-detached")
            except Exception as e:
                result["undone"].append(f"irule-repoint-error:{e}")
            # Close the port on a port-list VIP before removing its pool.
            port_list = details.get("port_list")
            port_val = details.get("port")
            if port_list and port_val:
                try:
                    f5.remove_port_from_port_list(port_list, port_val)
                    result["undone"].append(f"port-list:{port_list}-{port_val}")
                except Exception as e:
                    result["undone"].append(f"port-list-error:{port_list}:{e}")
            # Now the new pool/iRule are unreferenced and safe to delete.
            if new_irule:
                try:
                    f5.delete_irule(new_irule)
                    result["undone"].append(f"irule:{new_irule}")
                except Exception as e:
                    result["undone"].append(f"irule-error:{new_irule}:{e}")
            pool = details.get("pool_name")
            mon = details.get("monitor_name")
            if pool:
                try:
                    f5.delete_pool(pool)
                    result["undone"].append(f"pool:{pool}")
                except Exception as e:
                    result["undone"].append(f"pool-error:{pool}:{e}")
            if mon:
                try:
                    f5.delete_monitor(mon, monitor_type="https")
                    result["undone"].append(f"monitor:{mon}")
                except Exception as e:
                    result["undone"].append(f"monitor-error:{mon}:{e}")
            req_id = details.get("request_id")
            if req_id:
                update_vip_request_status(req_id, "pending", {"assigned_ip": None})
                result["undone"].append(f"request:{req_id}->pending")
            return result

        if action == "vip.approve" or action == "vipport.add" or action == "vipport.approve":
            vs_names = details.get("vs_names") or ([details["vs_name"]] if details.get("vs_name") else [])
            pool_names = details.get("pool_names") or ([details["pool_name"]] if details.get("pool_name") else [])
            monitor_names = details.get("monitor_names") or ([details["monitor_name"]] if details.get("monitor_name") else [])
            monitor_type = details.get("monitor_type", "tcp")
            for vs in vs_names:
                try:
                    f5.delete_virtual(vs)
                    result["undone"].append(f"vs:{vs}")
                except Exception as e:
                    result["undone"].append(f"vs-error:{vs}:{e}")
            for pool in pool_names:
                try:
                    f5.delete_pool(pool)
                    result["undone"].append(f"pool:{pool}")
                except Exception as e:
                    result["undone"].append(f"pool-error:{pool}:{e}")
            for mon in monitor_names:
                try:
                    f5.delete_monitor(mon, monitor_type=monitor_type)
                    result["undone"].append(f"monitor:{mon}")
                except Exception as e:
                    result["undone"].append(f"monitor-error:{mon}:{e}")
            # If it was a stored VIP request, flip the status back to pending so admin can re-approve.
            req_id = details.get("request_id")
            if req_id:
                update_vip_request_status(req_id, "pending", {"assigned_ip": None})
                result["undone"].append(f"request:{req_id}->pending")
            return result

        if action == "vip.decline":
            req_id = details.get("request_id")
            prev = details.get("prev_status", "pending")
            if not req_id:
                raise RuntimeError("Missing request_id in audit entry")
            update_vip_request_status(req_id, prev, {"decline_reason": None})
            result["undone"].append(f"request:{req_id}->{prev}")
            return result

        if action == "cert.replace":
            profile = details.get("profile")
            old_cert = details.get("old_cert")
            old_key = details.get("old_key")
            if not profile or not old_cert or not old_key:
                raise RuntimeError("Missing profile/old_cert/old_key in audit entry")
            f5.update_clientssl_profile_cert(
                profile_name=profile,
                cert_name=old_cert,
                key_name=old_key,
            )
            result["undone"].append(f"profile:{profile} -> {old_cert}/{old_key}")
            return result

        if action == "cert.create":
            profile = details.get("profile")
            attach_vs = details.get("attached_to")
            if attach_vs and profile:
                f5.detach_profile_from_vs(vs_name=attach_vs, profile_name=profile)
                result["undone"].append(f"detach:{profile} from {attach_vs}")
            if profile:
                try:
                    f5.delete_clientssl_profile(profile)
                    result["undone"].append(f"profile:{profile} deleted")
                except Exception as e:
                    result["undone"].append(f"profile-error:{profile}:{e}")
            return result

        raise RuntimeError(f"Don't know how to revert action '{action}'")

    async def post(self):
        admin_data = self.require_admin()
        if not admin_data:
            return
        try:
            data = json.loads(self.request.body.decode("utf-8")) if self.request.body else {}
            entry_id = (data.get("id") or "").strip()
            if not entry_id:
                raise tornado.web.HTTPError(400, reason="audit entry id required")
            entry = audit_find(entry_id)
            if not entry:
                raise tornado.web.HTTPError(404, reason="audit entry not found")
            if entry.get("reverted"):
                raise tornado.web.HTTPError(409, reason="entry already reverted")
            if not entry.get("revertible"):
                raise tornado.web.HTTPError(400, reason="entry is not revertible")

            result = await self._do_revert(entry, admin_data)
            audit_mark_reverted(entry_id, admin_data.get("username", "?"))
            # Record a follow-up audit entry for the revert itself
            audit_log(
                action="revert",
                target=entry.get("target", ""),
                user=admin_data.get("username", "?"),
                user_type="admin",
                result="success",
                client_ip=self.get_client_ip(),
                revertible=False,
                details={"reverted_id": entry_id, "of_action": entry.get("action"), "outcome": result},
            )
            self.write({"success": True, **result})
        except tornado.web.HTTPError as e:
            self.set_status(e.status_code)
            self.write({"success": False, "error": e.reason})
        except Exception as e:
            logger.exception("revert error")
            self.set_status(500)
            self.write({"success": False, "error": str(e)})


class CacheClearHandler(BaseHandler):
    """
    POST /cache/clear
    Admin-only. Wipes the in-memory and on-disk F5 cache so the next page
    load goes live against every F5 environment.
    """
    def post(self):
        admin_data = self.require_admin()
        if not admin_data:
            return
        try:
            cleared = clear_all_caches()
            audit_log(
                action="cache.clear",
                target="",
                user=admin_data.get("username", "?"),
                user_type="admin",
                result="success",
                client_ip=self.get_client_ip(),
                revertible=False,
                details={"envs_cleared": cleared},
            )
            self.write({"success": True, "envs_cleared": cleared})
        except Exception as e:
            logger.exception("cache clear error")
            self.set_status(500)
            self.write({"success": False, "error": str(e)})


class F5StatusHandler(BaseHandler):
    """
    GET /f5/status[?target=<environment-id>]

    Read-only health snapshot for every virtual server in the active F5(s).
    For each VS we return: name, IP, port, pool, monitor, and per-member
    state (up/down/unknown) with the timestamp of the last transition for
    that member.

    Members are keyed by "<target>:<pool>:<member-name>" so transitions are
    tracked separately per environment.
    """
    executor = ThreadPoolExecutor(max_workers=4)

    @staticmethod
    def pool_key(value: str) -> str:
        return (value or "").strip().lstrip("/").split("/")[-1]

    @classmethod
    def load_status_base(cls, env, env_session):
        target = env["id"]
        base_url = env_session.get("url")
        token = env_session.get("token")
        if not base_url or not token:
            return None
        f5 = F5Client(base_url=base_url, username="x", password="x", verify_ssl=False)
        f5.token = token
        f5.session.headers.update({"X-F5-Auth-Token": token})
        virtuals = f5.list_virtuals()
        pools = f5.list_pools()

        monitor_by_pool = {}
        for pool_item in pools:
            key = cls.pool_key(pool_item.get("fullPath") or pool_item.get("name", ""))
            if key:
                monitor_by_pool[key] = (pool_item.get("monitor") or "").strip()

        referenced_pools = {
            cls.pool_key(vs.get("pool") or "")
            for vs in virtuals
            if cls.pool_key(vs.get("pool") or "")
        }

        # iRule / port-list dispatch: for each all-ports (:0/:any) or
        # traffic-matching-criteria VS, map the switch [TCP::local_port] cases to
        # their pools so the status view can show port -> pool -> condition (the
        # per-port pools live in the iRule, not on vs.pool, so they'd otherwise
        # be invisible). One list_irules / list_traffic_matching_criteria call
        # each — no per-object round trips.
        irule_body_by_path = {}
        for r in f5.list_irules():
            nm = r.get("name")
            body = r.get("apiAnonymous") or ""
            if nm:
                irule_body_by_path[nm] = body
                irule_body_by_path[f"/Common/{nm}"] = body
            fp = r.get("fullPath")
            if fp:
                irule_body_by_path[fp] = body

        tmc_addr_by_path = {}
        for c in f5.list_traffic_matching_criteria():
            nm = c.get("name")
            addr = (c.get("destinationAddressInline") or "").split("/")[0]
            if nm:
                tmc_addr_by_path[nm] = addr
                tmc_addr_by_path[f"/Common/{nm}"] = addr
            fp = c.get("fullPath")
            if fp:
                tmc_addr_by_path[fp] = addr

        dispatch_by_vs = {}
        for vs in virtuals:
            rules = vs.get("rules") or []
            if not rules:
                continue  # no iRule -> nothing extra to surface
            md = re.match(r"^/[^/]+/([0-9.]+):(\d+|any)$", vs.get("destination", ""))
            ip_dest = md.group(1) if md else None
            port_dest = md.group(2) if md else None
            tmc = vs.get("trafficMatchingCriteria")
            is_all_ports = (port_dest in ("0", "any")) or bool(tmc)
            vip_ip = (tmc_addr_by_path.get(tmc) if tmc else ip_dest) or ip_dest or ""

            # Collect every pool any attached iRule can route to — switch cases
            # AND standard if/else pool references — so additional pools coded in
            # the iRule are visible, not just port-switched ones.
            cases = []
            seen = set()
            for rp in rules:
                body = irule_body_by_path.get(rp, "")
                if not body:
                    continue
                for cse in parse_irule_dispatch(body):
                    dedup = (cse["port"], cls.pool_key(cse["pool"]))
                    if dedup in seen:
                        continue
                    seen.add(dedup)
                    cases.append(cse)
            if cases:
                dispatch_by_vs[vs.get("name", "")] = {
                    "ip": vip_ip,
                    "cases": cases,
                    "is_all_ports": is_all_ports,
                }
                for cse in cases:
                    pk = cls.pool_key(cse["pool"])
                    if pk:
                        referenced_pools.add(pk)

        return {
            "env": env,
            "target": target,
            "target_name": env["name"],
            "f5": f5,
            "virtuals": virtuals,
            "monitor_by_pool": monitor_by_pool,
            "referenced_pools": sorted(referenced_pools),
            "dispatch_by_vs": dispatch_by_vs,
        }

    @classmethod
    def build_status_entries(cls, base, pool_name: str, members_status: list):
        results = []
        target = base["target"]
        target_name = base["target_name"]
        monitor_by_pool = base["monitor_by_pool"]
        dispatch_by_vs = base.get("dispatch_by_vs", {})

        def enrich_members(pool: str) -> list:
            out = []
            for md in members_status:
                member_name = md.get("name", "")
                key = f"{target}:{pool}:{member_name}"
                state = md.get("state", "unknown")
                st = update_node_state(
                    key,
                    state,
                    details={"target": target, "pool": pool, "member": member_name, "reason": md.get("reason", "")},
                )
                out.append({**md, "key": key, "since": st["since"]})
            return out

        def rollup(enriched: list) -> str:
            # Roll up: up if any member up; down if any down; otherwise unknown.
            states = {member["state"] for member in enriched}
            if "up" in states:
                return "up"
            if "down" in states:
                return "down"
            if states:
                return "unknown"
            return "no-members"

        for vs in base["virtuals"]:
            name = vs.get("name", "")
            dispatch = dispatch_by_vs.get(name)
            is_all_ports = bool(dispatch and dispatch.get("is_all_ports"))
            vs_pool = (vs.get("pool") or "").strip()
            persist = _vs_persistence(vs)

            # Classic row from the VS's own pool/destination. Skipped for an
            # all-ports VS (its per-port pools live entirely in the iRule).
            if not is_all_ports and cls.pool_key(vs_pool) == pool_name and pool_name:
                m = re.match(r"^/[^/]+/([0-9.]+):(\d+)$", vs.get("destination", ""))
                if m:
                    enriched = enrich_members(vs_pool)
                    results.append({
                        "vsName": name,
                        "ip": m.group(1),
                        "port": m.group(2),
                        "pool": vs_pool,
                        "monitor": monitor_by_pool.get(pool_name, ""),
                        "target": target,
                        "target_name": target_name,
                        "members": enriched,
                        "summary": rollup(enriched),
                        "mode": "vs",
                        "condition": None,
                        "persist": persist,
                    })

            # iRule-dispatched pools (switch cases + if/else pools). For a classic
            # VS these are EXTRA pools beyond its own; for an all-ports VS they are
            # the only pools. The VS's own pool is skipped here to avoid a dup row.
            if dispatch:
                for cse in dispatch["cases"]:
                    pool = cse["pool"]
                    if cls.pool_key(pool) != pool_name:
                        continue
                    if not is_all_ports and cls.pool_key(pool) == cls.pool_key(vs_pool):
                        continue
                    enriched = enrich_members(pool)
                    results.append({
                        "vsName": name,
                        "ip": dispatch["ip"] or vs.get("destination", ""),
                        "port": cse["port"],
                        "pool": pool,
                        "monitor": monitor_by_pool.get(pool_name, ""),
                        "target": target,
                        "target_name": target_name,
                        "members": enriched,
                        "summary": rollup(enriched),
                        "mode": "irule",
                        "condition": cse["condition"],
                        "persist": persist,
                    })

            # Pool-less VS with no iRule pools: keep it visible (e.g. forwarding
            # VS), matching prior behavior. Emitted only on the "" pool pass.
            if pool_name == "" and not vs_pool and not dispatch:
                m = re.match(r"^/[^/]+/([0-9.]+):(\d+|any)$", vs.get("destination", ""))
                if m:
                    results.append({
                        "vsName": name,
                        "ip": m.group(1),
                        "port": m.group(2),
                        "pool": "",
                        "monitor": "",
                        "target": target,
                        "target_name": target_name,
                        "members": [],
                        "summary": "no-members",
                        "mode": "vs",
                        "condition": None,
                        "persist": persist,
                    })
        return results

    @run_on_executor
    def _gather(self, token_data, only_target=None):
        env_targets = list(iter_token_environments(token_data, only_target))

        def collect_env(env, env_session):
            try:
                base = self.load_status_base(env, env_session)
            except Exception as e:
                logger.warning("Status: failed to list virtuals from %s: %s", env["id"], e)
                return []
            if not base:
                return []

            member_stats_by_pool = {}
            referenced_pools = base["referenced_pools"]
            if referenced_pools:
                with ThreadPoolExecutor(max_workers=min(12, len(referenced_pools))) as pool_executor:
                    futures = {
                        pool_executor.submit(base["f5"].get_pool_members_stats, pool_name): pool_name
                        for pool_name in referenced_pools
                    }
                    for future in as_completed(futures):
                        pool_name = futures[future]
                        try:
                            member_stats_by_pool[pool_name] = future.result()
                        except Exception as e:
                            logger.warning("Status: failed to load members for %s/%s: %s", base["target"], pool_name, e)
                            member_stats_by_pool[pool_name] = []

            results = []
            all_pool_keys = set(referenced_pools)
            if any(not self.pool_key(vs.get("pool") or "") for vs in base["virtuals"]):
                all_pool_keys.add("")
            for pool_name in sorted(all_pool_keys):
                results.extend(self.build_status_entries(base, pool_name, member_stats_by_pool.get(pool_name, [])))
            return results

        results = []
        with ThreadPoolExecutor(max_workers=min(8, max(1, len(env_targets)))) as env_executor:
            futures = [env_executor.submit(collect_env, env, env_session) for env, env_session in env_targets]
            for future in as_completed(futures):
                results.extend(future.result())
        results.sort(key=lambda x: (x["vsName"]))
        return results

    async def get(self):
        result = self.require_auth_unified()
        if not result:
            return
        _role, token_data = result
        try:
            only_target = (self.get_argument("target", "") or "").lower() or None
            if only_target:
                get_environment_by_id(only_target)
            entries = await self._gather(token_data=token_data, only_target=only_target)
            self.write({"success": True, "entries": entries})
        except tornado.web.HTTPError as e:
            self.set_status(e.status_code)
            self.write({"success": False, "error": e.reason})
        except Exception as e:
            logger.exception("status error")
            self.set_status(500)
            self.write({"success": False, "error": str(e)})


class F5PoolStatsHandler(BaseHandler):
    """
    GET /f5/pool/stats?target=<env-id>&pool=<pool-name>

    Point-in-time traffic counters for a pool's members (current connections,
    total connections, packets, bits) plus a pool rollup. The frontend polls /
    refreshes this to draw the live flow graph.
    """
    executor = ThreadPoolExecutor(max_workers=8)

    @run_on_executor
    def _stats(self, f5_url, f5_token, pool):
        f5 = F5Client(base_url=f5_url, username="x", password="x", verify_ssl=False)
        f5.token = f5_token
        f5.session.headers.update({"X-F5-Auth-Token": f5_token})
        return f5.get_pool_members_traffic_stats(pool)

    async def get(self):
        result = self.require_auth_unified()
        if not result:
            return
        _role, token_data = result
        try:
            target = (self.get_argument("target", "") or "").lower()
            pool = (self.get_argument("pool", "") or "").strip()
            if not target or not pool:
                raise tornado.web.HTTPError(400, reason="target and pool are required")
            get_environment_by_id(target)  # raises 400 on an unknown target
            _env, env_session = get_token_environment(token_data, target)
            f5_url = env_session.get("url")
            f5_token = env_session.get("token")
            if not f5_token or not f5_url:
                raise tornado.web.HTTPError(401, reason=f"No F5 token for target {target}")
            stats = await self._stats(f5_url, f5_token, pool)
            self.write({"success": True, **stats})
        except tornado.web.HTTPError as e:
            self.set_status(e.status_code)
            self.write({"success": False, "error": e.reason})
        except Exception as e:
            logger.exception("pool stats error")
            self.set_status(500)
            self.write({"success": False, "error": str(e)})


class F5StatusStreamHandler(BaseHandler):
    """
    GET /f5/status/stream[?target=<environment-id>]

    Streams status rows as NDJSON batches. The first rows can render while
    slower pool member checks continue in the background.
    """
    executor = ThreadPoolExecutor(max_workers=16)

    async def _write_event(self, event: str, **payload):
        self.write(json.dumps({"event": event, **payload}) + "\n")
        await self.flush()

    async def _load_pool_members(self, base, pool_name: str):
        loop = asyncio.get_running_loop()
        try:
            members = await loop.run_in_executor(
                self.executor,
                base["f5"].get_pool_members_stats,
                pool_name,
            )
        except Exception as e:
            logger.warning("Status stream: failed to load members for %s/%s: %s", base["target"], pool_name, e)
            members = []
        return pool_name, members

    async def get(self):
        result = self.require_auth_unified()
        if not result:
            return
        _role, token_data = result
        try:
            only_target = (self.get_argument("target", "") or "").lower() or None
            if only_target:
                get_environment_by_id(only_target)
            env_targets = list(iter_token_environments(token_data, only_target))
            self.set_header("Content-Type", "application/x-ndjson; charset=utf-8")
            self.set_header("Cache-Control", "no-cache")
            self.set_header("X-Accel-Buffering", "no")
            await self._write_event("start", target=only_target or "all", environments=len(env_targets))

            # Pre-warm cache: emit per-env "environment" + cached "batch"
            # events, then skip the live F5 work for those envs.
            live_targets = []
            for env, env_session in env_targets:
                cached = bg_cached_status(env["id"])
                if cached is None:
                    live_targets.append((env, env_session))
                    continue
                envinfo = cached["envinfo"]
                await self._write_event(
                    "environment",
                    target=env["id"],
                    target_name=env["name"],
                    pools=envinfo.get("pools", 0),
                    virtuals=envinfo.get("virtuals", 0),
                    cached=True,
                )
                for pool_name, entries in cached["batches"]:
                    filtered = entries
                    if not filtered:
                        continue
                    await self._write_event(
                        "batch",
                        entries=filtered,
                        target=env["id"],
                        pool=pool_name,
                        cached=True,
                    )

            loop = asyncio.get_running_loop()

            base_tasks = [
                loop.run_in_executor(self.executor, F5StatusHandler.load_status_base, env, env_session)
                for env, env_session in live_targets
            ]

            for base_task in asyncio.as_completed(base_tasks):
                try:
                    base = await base_task
                except Exception as e:
                    logger.warning("Status stream: failed to load environment base data: %s", e)
                    await self._write_event("error", error=str(e))
                    continue
                if not base:
                    continue

                await self._write_event(
                    "environment",
                    target=base["target"],
                    target_name=base["target_name"],
                    pools=len(base["referenced_pools"]),
                    virtuals=len(base["virtuals"]),
                )

                cache_batches: list = []
                no_pool_entries = []
                if any(not F5StatusHandler.pool_key(vs.get("pool") or "") for vs in base["virtuals"]):
                    no_pool_entries = F5StatusHandler.build_status_entries(base, "", [])
                    if no_pool_entries:
                        await self._write_event("batch", entries=no_pool_entries, target=base["target"])
                        cache_batches.append(("", no_pool_entries))

                pool_tasks = [
                    self._load_pool_members(base, pool_name)
                    for pool_name in base["referenced_pools"]
                ]
                for pool_task in asyncio.as_completed(pool_tasks):
                    pool_name, members = await pool_task
                    entries = F5StatusHandler.build_status_entries(base, pool_name, members)
                    if entries:
                        await self._write_event("batch", entries=entries, target=base["target"], pool=pool_name)
                        cache_batches.append((pool_name, entries))

                update_cache_status(
                    base["target"],
                    {"pools": len(base["referenced_pools"]), "virtuals": len(base["virtuals"])},
                    cache_batches,
                )

            await self._write_event("done")
        except tornado.web.HTTPError as e:
            if self._finished:
                return
            self.set_status(e.status_code)
            self.write({"success": False, "error": e.reason})
        except Exception as e:
            logger.exception("status stream error")
            if self._finished:
                return
            if self._headers_written:
                await self._write_event("error", error=str(e))
            else:
                self.set_status(500)
                self.write({"success": False, "error": str(e)})


class NodeHistoryHandler(BaseHandler):
    """
    GET /f5/node-history?key=<target:pool:member>&limit=50
    Returns the recent up/down transitions for a given pool member.
    """
    def get(self):
        result = self.require_auth_unified()
        if not result:
            return
        try:
            key = self.get_argument("key", "")
            if not key:
                raise tornado.web.HTTPError(400, reason="key required")
            try:
                limit = int(self.get_argument("limit", "50"))
            except Exception:
                limit = 50
            limit = max(1, min(limit, 500))
            self.write({"success": True, "entries": node_history(key, limit=limit)})
        except tornado.web.HTTPError as e:
            self.set_status(e.status_code)
            self.write({"success": False, "error": e.reason})
        except Exception as e:
            logger.exception("node-history error")
            self.set_status(500)
            self.write({"success": False, "error": str(e)})




# ---------------------------
# Background pre-warm cache
# ---------------------------
# Single-process in-memory cache. Shape:
#   _BG_CACHE[env_id] = {
#       "vips": [...],            # output of collect_env_vips, sorted
#       "vips_ts": float,
#       "status_envinfo": {"pools": int, "virtuals": int},
#       "status_batches": [(pool_name, [entries])],
#       "status_ts": float,
#   }
# Writes happen on a background ThreadPoolExecutor; reads happen on the
# IOLoop thread inside stream handlers. Single-thread writer per env makes
# dict.replace atomic; readers grab a reference and never mutate.
_BG_CACHE: dict[str, dict] = {}
_BG_CACHE_LOCK = threading.Lock()


def _cache_file_path(env_id: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_\-]", "_", env_id)
    return os.path.join(F5_CACHE_DIR, f"env_{safe}.json")


def _persist_cache_entry(env_id: str, entry: dict) -> None:
    if not F5_CACHE_DIR:
        return
    try:
        os.makedirs(F5_CACHE_DIR, exist_ok=True)
        path = _cache_file_path(env_id)
        tmp_path = f"{path}.tmp"
        payload = {"env_id": env_id, **entry}
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, default=str)
        os.replace(tmp_path, path)
    except Exception as e:
        logger.warning("cache: failed to persist %s: %s", env_id, e)


def _load_persisted_caches() -> None:
    if not F5_CACHE_DIR or not os.path.isdir(F5_CACHE_DIR):
        return
    loaded = 0
    for name in os.listdir(F5_CACHE_DIR):
        if not (name.startswith("env_") and name.endswith(".json")):
            continue
        path = os.path.join(F5_CACHE_DIR, name)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            env_id = data.pop("env_id", None) or name[4:-5]
            if env_id:
                _BG_CACHE[env_id] = data
                loaded += 1
        except Exception as e:
            logger.warning("cache: failed to load %s: %s", path, e)
    if loaded:
        logger.info("cache: hydrated %d env(s) from %s", loaded, F5_CACHE_DIR)


def update_cache_vips(env_id: str, vips: list) -> None:
    with _BG_CACHE_LOCK:
        entry = dict(_BG_CACHE.get(env_id) or {})
        entry["vips"] = vips
        entry["vips_ts"] = time.time()
        _BG_CACHE[env_id] = entry
        snapshot = dict(entry)
    _persist_cache_entry(env_id, snapshot)


def update_cache_status(env_id: str, envinfo: dict, batches: list) -> None:
    with _BG_CACHE_LOCK:
        entry = dict(_BG_CACHE.get(env_id) or {})
        entry["status_envinfo"] = envinfo
        entry["status_batches"] = batches
        entry["status_ts"] = time.time()
        _BG_CACHE[env_id] = entry
        snapshot = dict(entry)
    _persist_cache_entry(env_id, snapshot)


def _bg_entry_fresh(entry: dict | None, kind: str) -> bool:
    if not entry:
        return False
    ts = entry.get(f"{kind}_ts")
    if not ts:
        return False
    return (time.time() - float(ts)) <= F5_BG_STALE_AFTER_SECS


def bg_cached_vips(env_id: str) -> list | None:
    entry = _BG_CACHE.get(env_id)
    return entry["vips"] if _bg_entry_fresh(entry, "vips") else None


def bg_cached_status(env_id: str) -> dict | None:
    entry = _BG_CACHE.get(env_id)
    if not _bg_entry_fresh(entry, "status"):
        return None
    return {
        "envinfo": entry.get("status_envinfo") or {"pools": 0, "virtuals": 0},
        "batches": entry.get("status_batches") or [],
    }


def clear_all_caches() -> int:
    """Wipe the in-memory cache and remove every per-env JSON on disk. Returns
    the number of env entries cleared."""
    with _BG_CACHE_LOCK:
        cleared = len(_BG_CACHE)
        _BG_CACHE.clear()
    if F5_CACHE_DIR and os.path.isdir(F5_CACHE_DIR):
        for name in os.listdir(F5_CACHE_DIR):
            if name.startswith("env_") and (name.endswith(".json") or name.endswith(".json.tmp")):
                try:
                    os.remove(os.path.join(F5_CACHE_DIR, name))
                except Exception as e:
                    logger.warning("cache: failed to remove %s: %s", name, e)
    return cleared


def _bg_get_account() -> dict | None:
    """Credentials for the pre-warm loop. Prefers the Fernet-encrypted read
    service account (decrypted on demand); falls back to the legacy plaintext
    F5_BG_USERNAME/PASSWORD only if no encrypted account is available."""
    if _service_account_available():
        acct = _decrypt_service_account(_service_account_path(), "Read-only")
        if acct:
            return acct
    if F5_BG_USERNAME and F5_BG_PASSWORD:
        return {"username": F5_BG_USERNAME, "password": F5_BG_PASSWORD}
    return None


def _bg_prewarm_enabled() -> bool:
    return _service_account_available() or bool(F5_BG_USERNAME and F5_BG_PASSWORD)


def _bg_refresh_env(env: dict) -> None:
    active_url = get_environment_active_url(env)
    account = _bg_get_account()
    if not account:
        return
    try:
        token = authenticate_with_f5(active_url, account["username"], account["password"])
    except Exception as e:
        logger.warning("pre-warm: auth to %s failed: %s", env.get("name", env["id"]), e)
        return
    finally:
        _scrub(account)
        del account
    env_session = {"name": env["name"], "url": active_url, "token": token}

    try:
        vips = F5VIPListHandler.collect_env_vips(env, env_session)
        vips.sort(key=lambda x: x["name"])
        update_cache_vips(env["id"], vips)
    except Exception as e:
        logger.warning("pre-warm: vips for %s failed: %s", env["name"], e)

    try:
        base = F5StatusHandler.load_status_base(env, env_session)
        if base:
            batches: list[tuple[str, list[dict]]] = []
            if any(not F5StatusHandler.pool_key(vs.get("pool") or "") for vs in base["virtuals"]):
                no_pool = F5StatusHandler.build_status_entries(base, "", [])
                if no_pool:
                    batches.append(("", no_pool))
            for pool_name in base["referenced_pools"]:
                try:
                    members = base["f5"].get_pool_members_stats(pool_name)
                except Exception as e:
                    logger.warning("pre-warm: pool %s/%s: %s", env["name"], pool_name, e)
                    members = []
                entries = F5StatusHandler.build_status_entries(base, pool_name, members)
                if entries:
                    batches.append((pool_name, entries))
            update_cache_status(
                env["id"],
                {"pools": len(base["referenced_pools"]), "virtuals": len(base["virtuals"])},
                batches,
            )
    except Exception as e:
        logger.warning("pre-warm: status for %s failed: %s", env["name"], e)


_bg_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="bg-prewarm")


def _bg_tick() -> None:
    for env in F5_ENVIRONMENTS:
        _bg_executor.submit(_bg_refresh_env, env)


def start_bg_prewarm() -> None:
    if not _bg_prewarm_enabled():
        logger.info(
            "pre-warm scheduler disabled (no encrypted read service account and no "
            "F5_BG_USERNAME/PASSWORD fallback). Cache will fill from live requests only."
        )
        return
    src = "encrypted read service account" if _service_account_available() else "legacy F5_BG_* env creds"
    logger.info(
        "pre-warm scheduler ON via %s: %d env(s) every %ds (stale after %ds)",
        src, len(F5_ENVIRONMENTS), F5_BG_REFRESH_SECS, F5_BG_STALE_AFTER_SECS,
    )
    # Fire once immediately so the first user request is warm.
    _bg_tick()
    cb = tornado.ioloop.PeriodicCallback(_bg_tick, F5_BG_REFRESH_SECS * 1000)
    cb.start()


# ---------------------------
# Tornado app setup
# ---------------------------

class NotFoundHandler(tornado.web.RequestHandler):
    """Catch-all for unrouted paths.

    A browser landing here (an APM access-policy landing URI, a bookmarked
    client-side route, a stale link) used to get Tornado's built-in 404 page,
    which looks like the app is down. Send navigations to the app root instead
    and keep a JSON 404 for API clients, which must not be redirected.

    The root itself never redirects -- that would loop.
    """

    def _wants_html(self) -> bool:
        return "text/html" in self.request.headers.get("Accept", "")

    async def prepare(self):
        self.set_header("Cache-Control", "no-store")
        if self._wants_html() and self.request.path not in ("/", ""):
            self.redirect(APP_ROOT_PATH, permanent=False)
            return
        self.set_status(404)
        self.write({"success": False, "error": "Not found"})
        # prepare() must finish the request itself; otherwise Tornado goes on to
        # call get()/post(), which the base class answers with a 405.
        self.finish()


def make_app():
    return tornado.web.Application(
        [
            (r"/admin/login", AdminLoginHandler),
            (r"/admin/logout", AdminLogoutHandler),
            (r"/viprequest/list", VIPRequestListHandler),
            (r"/viprequest/decline", VIPRequestDeclineHandler),
            (r"/viprequest/clear", VIPRequestClearHandler),
            (r"/viprequest", VIPCreationHandler),
            (r"/vipcreation", VIPCreationHandler),
            (r"/vipcreation/notify", EmailNotificationHandler),
            (r"/me", CurrentUserHandler),
            (r"/f5/vips/stream", F5VIPListStreamHandler),
            (r"/f5/vips", F5VIPListHandler),
            (r"/f5/add-port", F5AddPortHandler),
            (r"/f5/add-port/request", F5AddPortRequestHandler),
            (r"/f5/irule/versions", F5IRuleVersionsHandler),
            (r"/f5/irule/rollback", F5IRuleRollbackHandler),
            (r"/f5/cert-info", F5CertInfoHandler),
            (r"/f5/parse-pfx", F5ParsePfxHandler),
            (r"/f5/replace-cert", F5ReplaceCertHandler),
            (r"/api/v1/replace-cert", CertReplaceApiHandler),
            (r"/f5/status/stream", F5StatusStreamHandler),
            (r"/f5/pool/stats", F5PoolStatsHandler),
            (r"/f5/status", F5StatusHandler),
            (r"/f5/node-history", NodeHistoryHandler),
            (r"/audit", AuditHandler),
            (r"/audit/revert", RevertHandler),
            (r"/cache/clear", CacheClearHandler),
        ],
        # Debug mode serves full tracebacks to clients and enables autoreload;
        # keep it OFF unless APP_DEBUG is explicitly set. Default is production-safe.
        debug=os.getenv("APP_DEBUG", "").strip().lower() in ("1", "true", "yes"),
        max_body_size=50 * 1024 * 1024,
        default_handler_class=NotFoundHandler,
    )


if __name__ == "__main__":
    port = 8889
    logger.info("Starting Tornado F5 VIP API on http://0.0.0.0:%d", port)
    app = make_app()
    app.listen(port)
    _load_persisted_caches()
    start_bg_prewarm()
    tornado.ioloop.IOLoop.current().start()
