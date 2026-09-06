import ipaddress
import json
import os
import re
import sys
import urllib.parse
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = BASE_DIR / "f5_environments.json"


def prompt(text: str, default: str | None = None, required: bool = False) -> str:
    while True:
        suffix = f" [{default}]" if default else ""
        value = input(f"{text}{suffix}: ").strip()
        if value:
            return value
        if default is not None:
            return default
        if not required:
            return ""
        print("This value is required.")


def url_problem(value: str) -> str | None:
    """Describe why an F5 base URL is unusable, or return None when it is fine.

    The backend joins these with '/mgmt/tm/...', so anything past the host is a
    mistake. The non-empty path check is what catches two URLs pasted into one
    field ('https://a.https://b' parses as host 'a.https' with path '//b').
    """
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in ("http", "https"):
        return "must start with http:// or https://"
    if not parsed.netloc:
        return "is missing a host"
    if parsed.path.strip("/"):
        return (
            f"should be a bare host with no path, but has '{parsed.path}' "
            "(two URLs in one field? separate them with a comma)"
        )
    if parsed.query or parsed.fragment:
        return "should not carry a query string or fragment"
    try:
        parsed.port
    except ValueError as e:
        return f"has an invalid port ({e})"
    if not parsed.hostname:
        return "is missing a host"
    return None


def prompt_url(text: str, required: bool = False) -> str:
    while True:
        value = prompt(text, "", required=required).strip().rstrip("/")
        if not value:
            return ""
        problem = url_problem(value)
        if problem is None:
            return value
        print(f"  '{value}' {problem}.")


def prompt_node_urls(primary: str) -> list[str]:
    while True:
        raw = prompt(
            "Cluster node URLs, comma-separated (leave blank to reuse the primary URL)",
            "",
            required=False,
        )
        nodes = [part.strip().rstrip("/") for part in raw.split(",") if part.strip()]
        if not nodes:
            return [primary]
        bad = [(n, url_problem(n)) for n in nodes]
        bad = [(n, why) for n, why in bad if why]
        if not bad:
            return nodes
        for n, why in bad:
            print(f"  '{n}' {why}.")
        print(
            "  Example: https://f5-a.example.org,https://f5-b.example.org"
        )


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "environment"


def prompt_count() -> int:
    while True:
        raw = prompt("How many F5 environments does this org have", "2", required=True)
        try:
            count = int(raw)
        except ValueError:
            print("Enter a whole number.")
            continue
        if count < 1:
            print("At least one environment is required.")
            continue
        return count


def prompt_snat_mappings(vip_networks: list[str]) -> list[dict]:
    """Ask for the SNAT source backing each VIP subnet.

    Mirrors the two forms _validate_snat_mappings() accepts in app.py: a bare
    address becomes snat_ip (every VIP in the range shares it), a CIDR becomes
    snat_network (the VIP's host bits are mirrored onto that range). Blank
    leaves the range unmapped, which means those VIPs fall back to automap.
    """
    if not vip_networks:
        return []
    print(
        "\n  SNAT source per VIP subnet. Enter an address (10.20.3.1) to pin every VIP\n"
        "  in the range to one SNAT address, or a CIDR (10.20.4.0/24) to mirror the\n"
        "  VIP's host octet onto that range. Blank leaves the range on automap."
    )
    mappings = []
    for cidr in vip_networks:
        try:
            vip_net = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError as e:
            print(f"  Skipping SNAT for '{cidr}': not a valid CIDR ({e}).")
            continue
        while True:
            answer = prompt(f"  SNAT source for {cidr}", "", required=False)
            if not answer:
                break
            if "/" in answer:
                try:
                    snat_net = ipaddress.IPv4Network(answer, strict=False)
                except ValueError as e:
                    print(f"  '{answer}' is not a valid CIDR ({e}).")
                    continue
                if snat_net.prefixlen > vip_net.prefixlen:
                    print(
                        f"  Note: {answer} is smaller than {cidr} - only "
                        f"{snat_net.num_addresses} of {vip_net.num_addresses} VIPs can keep "
                        "their host octet; the rest take the next free address in the "
                        "range, then automap once it fills up."
                    )
                mappings.append({"vip_cidr": cidr, "snat_network": answer})
            else:
                try:
                    ipaddress.IPv4Address(answer)
                except ValueError as e:
                    print(f"  '{answer}' is not a valid IPv4 address ({e}).")
                    continue
                mappings.append({"vip_cidr": cidr, "snat_ip": answer})
            break
    return mappings


def prompt_environment(index: int, used_ids: set[str]) -> dict:
    print(f"\nEnvironment #{index + 1}")
    name = prompt("Display name", required=True)
    default_id = slugify(name)
    while True:
        env_id = slugify(prompt("Stable id", default_id, required=True))
        if env_id in used_ids:
            print(f"'{env_id}' is already used. Pick a different id.")
            continue
        used_ids.add(env_id)
        break
    url = prompt_url("Primary F5 URL (for example https://f5.example.org)", required=True)
    nodes = prompt_node_urls(url)
    networks_raw = prompt(
        "Pool-member networks for auto-detect, comma-separated CIDR (leave blank to disable auto-detect for this environment)",
        "",
        required=False,
    )
    vip_networks_raw = prompt(
        "VIP allocation subnets, comma-separated CIDR in preference order (for example 10.20.10.0/24,10.20.11.0/24)",
        "",
        required=False,
    )
    member_networks = [part.strip() for part in networks_raw.split(",") if part.strip()]
    vip_networks = [part.strip() for part in vip_networks_raw.split(",") if part.strip()]
    snat_mappings = prompt_snat_mappings(vip_networks)
    return {
        "id": env_id,
        "name": name,
        "url": url,
        "nodes": nodes,
        "member_networks": member_networks,
        "vip_networks": vip_networks,
        "snat_mappings": snat_mappings,
    }


def main() -> int:
    output_arg = sys.argv[1] if len(sys.argv) > 1 else ""
    output_path = Path(output_arg) if output_arg else DEFAULT_OUTPUT
    if not output_path.is_absolute():
        output_path = BASE_DIR / output_path

    print(f"Writing environment config to: {output_path}")
    count = prompt_count()
    used_ids: set[str] = set()
    environments = [prompt_environment(i, used_ids) for i in range(count)]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(environments, f, indent=2)
        f.write("\n")

    print(f"\nSaved {len(environments)} environment(s) to {output_path}")
    print("The backend will read this file on startup.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
