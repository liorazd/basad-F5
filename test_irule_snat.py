"""Pure-helper tests for the iRule-aware add-port + host-preserving SNAT work.
Runs without F5 — imports helpers from app.py and asserts behavior directly.
Run with: python test_irule_snat.py
"""
import os
import tempfile

# Redirect DATA_DIR/cache to a sandbox BEFORE importing app.py.
SANDBOX = tempfile.mkdtemp(prefix="irule-test-")
os.environ["DATA_DIR"] = SANDBOX
os.environ["F5_CACHE_DIR"] = ""
os.environ["AUDIT_FILE"] = os.path.join(SANDBOX, "audit.jsonl")
os.environ.setdefault("TEAM_NOTIFY_EMAILS", "")

import app  # noqa: E402

failures = []


def check(label, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {label}{(' — ' + detail) if detail and not condition else ''}")
    if not condition:
        failures.append(label)


def section(name):
    print(f"\n=== {name} ===")


def raises(fn):
    try:
        fn()
        return False
    except Exception:
        return True


# ------------------------------------------------------------
section("1. SNAT host-preserving remap")
env = {
    "snat_mappings": app._validate_snat_mappings(
        [
            {"vip_cidr": "172.20.63.0/24", "snat_network": "172.20.7.0/24"},
            {"vip_cidr": "10.20.1.0/24", "snat_ip": "10.20.3.1"},
        ],
        "test",
    )
}
check("remap mirrors host octet (.157 -> 172.20.7.157)",
      app.resolve_snat_ip(env, "172.20.63.157") == "172.20.7.157")
check("remap mirrors host octet (.20 -> 172.20.7.20)",
      app.resolve_snat_ip(env, "172.20.63.20") == "172.20.7.20")
check("fixed snat_ip still works",
      app.resolve_snat_ip(env, "10.20.1.55") == "10.20.3.1")
check("uncovered VIP -> None (automap fallback)",
      app.resolve_snat_ip(env, "192.168.1.1") is None)

section("2. SNAT mapping validation")
check("rejects both snat_ip and snat_network",
      raises(lambda: app._validate_snat_mappings(
          [{"vip_cidr": "1.1.1.0/24", "snat_ip": "2.2.2.2", "snat_network": "3.3.3.0/24"}], "t")))
check("rejects neither snat_ip nor snat_network",
      raises(lambda: app._validate_snat_mappings([{"vip_cidr": "1.1.1.0/24"}], "t")))
check("accepts snat_network smaller than vip_cidr (warns, allocates sequentially)",
      app._validate_snat_mappings(
          [{"vip_cidr": "10.0.0.0/16", "snat_network": "11.0.0.0/24"}], "t")[0]["snat_network"] == "11.0.0.0/24")
check("accepts larger snat_network than vip_cidr",
      app._validate_snat_mappings(
          [{"vip_cidr": "10.0.1.0/24", "snat_network": "11.0.0.0/16"}], "t")[0]["snat_network"] == "11.0.0.0/16")

section("2b. Per-range mapping: each vip_network gets its own snat range")
multi = {
    "vip_networks": ["172.20.210.0/24", "172.20.211.0/24", "172.20.212.0/24"],
    "snat_mappings": app._validate_snat_mappings(
        [
            {"vip_cidr": "172.20.210.0/24", "snat_network": "172.20.7.0/24"},
            {"vip_cidr": "172.20.211.0/24", "snat_network": "172.20.8.0/28"},
            {"vip_cidr": "172.20.212.0/24", "snat_ip": "172.20.9.1"},
        ],
        "multi",
    ),
}
check("range 1 -> snat range 1", app.resolve_snat_ip(multi, "172.20.210.50") == "172.20.7.50")
check("range 2 -> snat range 2", app.allocate_snat_ip(multi, "172.20.211.5")[0] == "172.20.8.5")
check("range 3 -> fixed snat ip", app.resolve_snat_ip(multi, "172.20.212.99") == "172.20.9.1")
check("VIP outside every range -> automap", app.resolve_snat_ip(multi, "172.20.213.5") is None)
check("ranges don't bleed into each other",
      app.resolve_snat_ip(multi, "172.20.210.50") != app.resolve_snat_ip(multi, "172.20.211.50"))

section("2c. allocate_snat_ip: sequential fallback + automap")
small = {
    "snat_mappings": app._validate_snat_mappings(
        [{"vip_cidr": "172.20.211.0/24", "snat_network": "172.20.8.0/28"}], "t"
    )
}
# 172.20.8.0/28 usable: .2 - .14 (.0 network, .1 gateway, .15 broadcast)
check("host octet that fits is preserved",
      app.allocate_snat_ip(small, "172.20.211.9") == ("172.20.8.9", "host_preserving"))
check("host octet that doesn't fit -> next free",
      app.allocate_snat_ip(small, "172.20.211.157") == ("172.20.8.2", "sequential"))
check("next free skips addresses already in SNAT pools",
      app.allocate_snat_ip(small, "172.20.211.157", {"172.20.8.2", "172.20.8.3"})
      == ("172.20.8.4", "sequential"))
check("reserved .0/.1/.255 never handed out",
      app.allocate_snat_ip(small, "172.20.211.1")[0] not in ("172.20.8.0", "172.20.8.1"))
FULL = {f"172.20.8.{i}" for i in range(2, 15)}
check("full range -> automap",
      app.allocate_snat_ip(small, "172.20.211.157", FULL) == (None, "range_full"))
check("full range still reuses a fitting host octet",
      app.allocate_snat_ip(small, "172.20.211.9", FULL) == ("172.20.8.9", "host_preserving"))
check("no mapping -> automap with reason",
      app.allocate_snat_ip(small, "10.9.9.9") == (None, "no_mapping"))
check("blocked mirrored address falls through to sequential",
      app.allocate_snat_ip(small, "172.20.211.9", set(), {"172.20.8.9"})
      == ("172.20.8.2", "sequential"))
check("blocked fixed snat_ip -> automap",
      app.allocate_snat_ip(multi, "172.20.212.99", set(), {"172.20.9.1"}) == (None, "conflict"))
check("every fallback reason has a message",
      all(r in app.SNAT_FALLBACK_REASONS for r in ("no_mapping", "range_full", "conflict", "unavailable")))

section("2d. resolve_snat_pool_for_vip against a fake F5")


class FakeF5:
    """Minimal stand-in: an in-memory SNAT-pool table with the same reuse and
    name-collision semantics as F5Client."""

    def __init__(self, pools=None):
        self.pools = dict(pools or {})  # name -> [member ips]
        self.created = []

    def snat_ips_in_use(self):
        return {ip for members in self.pools.values() for ip in members}

    def ensure_snat_pool(self, name, snat_ip, partition="Common"):
        for pool_name, members in self.pools.items():
            if snat_ip in members:
                return f"/{partition}/{pool_name}"
        if name in self.pools:
            raise app.SnatPoolConflict(f"{name} holds {self.pools[name]}, not {snat_ip}")
        self.pools[name] = [snat_ip]
        self.created.append(name)
        return f"/{partition}/{name}"


f5 = FakeF5()
path, reason = app.resolve_snat_pool_for_vip(f5, multi, "172.20.210.50", "dc")
check("creates the mirrored pool", (path, reason) == ("/Common/snat_172_20_7_50", "host_preserving"))
path2, _ = app.resolve_snat_pool_for_vip(f5, multi, "172.20.210.50", "dc")
check("second call reuses, doesn't duplicate", path2 == path and len(f5.created) == 1)

renamed = FakeF5({"legacy_pool": ["172.20.7.50"]})
path3, _ = app.resolve_snat_pool_for_vip(renamed, multi, "172.20.210.50", "dc")
check("reuses an existing pool holding the IP under another name",
      path3 == "/Common/legacy_pool" and renamed.created == [])

conflict = FakeF5({"snat_172_20_8_2": ["10.0.0.9"]})
path4, reason4 = app.resolve_snat_pool_for_vip(conflict, small, "172.20.211.157", "dc")
check("name collision on a foreign IP skips to the next address",
      (path4, reason4) == ("/Common/snat_172_20_8_3", "sequential"), detail=f"{path4} {reason4}")

exhausted = FakeF5({f"p{i}": [f"172.20.8.{i}"] for i in range(2, 15)})
path5, reason5 = app.resolve_snat_pool_for_vip(exhausted, small, "172.20.211.157", "dc")
check("exhausted range -> automap, no exception", (path5, reason5) == (None, "range_full"))


class BlindF5(FakeF5):
    def snat_ips_in_use(self):
        raise RuntimeError("device unreachable")


path6, reason6 = app.resolve_snat_pool_for_vip(BlindF5(), multi, "172.20.210.50", "dc")
check("unreadable SNAT inventory still creates the deterministic pool",
      (path6, reason6) == ("/Common/snat_172_20_7_50", "host_preserving"))


class BrokenF5(FakeF5):
    def ensure_snat_pool(self, name, snat_ip, partition="Common"):
        raise RuntimeError("500 from device")


path7, reason7 = app.resolve_snat_pool_for_vip(BrokenF5(), multi, "172.20.210.50", "dc")
check("pool creation failure -> automap, no exception", (path7, reason7) == (None, "unavailable"))

section("2e. add-port reuses the VIP's existing SNAT pool")
VIRTUALS = [
    {
        "name": "app-443-vip",
        "destination": "/Common/172.20.211.157:443",
        "sourceAddressTranslation": {"type": "snat", "pool": "/Common/snat_172_20_8_5"},
    },
    {
        "name": "other-80-vip",
        "destination": "/Common/172.20.211.9:80",
        "sourceAddressTranslation": {"type": "snat", "pool": "/Common/snat_172_20_8_9"},
    },
    {
        "name": "automap-vip",
        "destination": "/Common/172.20.211.20:80",
        "sourceAddressTranslation": {"type": "automap"},
    },
]
check("finds the pool bound to this VIP's VS",
      app.find_existing_snat_pool(None, "172.20.211.157", VIRTUALS) == "/Common/snat_172_20_8_5")
check("doesn't pick up another VIP's pool",
      app.find_existing_snat_pool(None, "172.20.211.9", VIRTUALS) == "/Common/snat_172_20_8_9")
check("automap VS -> None (resolve fresh)",
      app.find_existing_snat_pool(None, "172.20.211.20", VIRTUALS) is None)
check("unknown VIP -> None",
      app.find_existing_snat_pool(None, "172.20.211.99", VIRTUALS) is None)
# The reason this matters: .157 doesn't fit /28, so a fresh resolve would hand
# the new port .2 — a different source than the VIP's existing ports.
check("fresh resolve would have differed (regression guard)",
      app.allocate_snat_ip(small, "172.20.211.157")[0] == "172.20.8.2")

# ------------------------------------------------------------
SAMPLE = """when CLIENT_ACCEPTED {
    switch -glob [TCP::local_port] {
        "443" {
            pool webapp1.example.org-443-pool
        }
        "24" {
            pool webapp1.example.org-24-pool
        }
        default {
            log local0. "no port found"
            reject
        }
    }
}"""

section("3. parse_switch_ports")
ports = app.parse_switch_ports(SAMPLE)
check("finds existing cased ports", ports == {"443", "24"}, detail=str(ports))
check("empty set when no switch", app.parse_switch_ports("when HTTP_REQUEST { }") == set())

section("4. add_switch_case")
edited = app.add_switch_case(SAMPLE, "8443", "/Common/webapp1.example.org-8443-pool")
check("new port appears after edit", "8443" in app.parse_switch_ports(edited))
check("keeps existing ports", {"443", "24"}.issubset(app.parse_switch_ports(edited)))
check("new case sits before default",
      edited.index('"8443"') < edited.index("default"))
check("default arm preserved", "reject" in edited)
check("rejects duplicate port",
      raises(lambda: app.add_switch_case(SAMPLE, "443", "/Common/x")))
check("rejects iRule without switch",
      raises(lambda: app.add_switch_case("when HTTP_REQUEST { }", "80", "/Common/x")))
check("rejects switch without default",
      raises(lambda: app.add_switch_case(
          'when CLIENT_ACCEPTED { switch [TCP::local_port] { "443" { pool a } } }', "80", "/Common/x")))

section("4b. parse_switch_cases (status mapping)")
cases = app.parse_switch_cases(SAMPLE)
case_ports = [c["port"] for c in cases]
check("maps each port to a case", case_ports == ["443", "24"], detail=str(case_ports))
check("captures pool per case",
      cases[0]["pool"] == "webapp1.example.org-443-pool", detail=str(cases[0]))
check("condition mentions TCP::local_port", "TCP::local_port" in cases[0]["condition"])
DEFAULTED = SAMPLE.replace('log local0. "no port found"\n            reject',
                           "pool /Common/fallback-pool")
dcases = app.parse_switch_cases(DEFAULTED)
check("default arm with pool becomes a case",
      any(c["port"] == "default" and c["pool"] == "/Common/fallback-pool" for c in dcases),
      detail=str(dcases))

section("4c. parse_irule_dispatch (non-switch pools)")
IFRULE = '''when HTTP_REQUEST {
  if { [HTTP::uri] starts_with "/api" } {
    pool /Common/api_pool
  } elseif { [HTTP::host] equals "img" } {
    pool img_pool
  } else {
    pool web_pool
  }
}'''
disp = app.parse_irule_dispatch(IFRULE)
pools = {d["pool"] for d in disp}
check("captures all if/elseif/else pools",
      pools == {"/Common/api_pool", "img_pool", "web_pool"}, detail=str(pools))
check("if-branch condition captured",
      any("/api" in d["condition"] for d in disp))
check("else-branch labeled",
      any(d["pool"] == "web_pool" and "else" in d["condition"] for d in disp))
mixed = app.parse_irule_dispatch(SAMPLE + "\nwhen HTTP_REQUEST { if { 1 } { pool extra_pool } }")
check("switch + extra pool both present",
      {"443", "24"}.issubset({d["port"] for d in mixed})
      and any(d["pool"] == "extra_pool" for d in mixed))

section("5. build_switch_irule")
built = app.build_switch_irule([("443", "/Common/p443")], default_pool="/Common/def")
check("built rule has the case", "443" in app.parse_switch_ports(built))
check("built rule routes default to pool", "pool /Common/def" in built)
check("add_switch_case works on built rule",
      "80" in app.parse_switch_ports(app.add_switch_case(built, "80", "/Common/p80")))
built_reject = app.build_switch_irule([("443", "/Common/p443")])
check("no default pool -> reject", "reject" in built_reject)

section("6. iRule versioning")
check("base name", app.irule_base_name("app.example.org") == "app.example.org_irule")
check("version_of matches", app.irule_version_of("app_irule_v3", "app_irule") == 3)
check("version_of path form", app.irule_version_of("/Common/app_irule_v2", "app_irule") == 2)
check("version_of non-match -> None", app.irule_version_of("app_irule", "app_irule") is None)
check("next version from none is 1", app.next_irule_version([], "app_irule") == 1)
check("next version bumps max",
      app.next_irule_version(["app_irule_v1", "app_irule_v2", "other"], "app_irule") == 3)

# ------------------------------------------------------------
section("Summary")
if failures:
    print(f"\n{len(failures)} FAILURE(S): {failures}")
    raise SystemExit(1)
print("\nAll checks passed.")
