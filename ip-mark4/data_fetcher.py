"""
data_fetcher.py - talks to the public data sources.

Design rule: EVERY function returns the same "source result" shape:
    {"source": name, "status": "live"|"mock"|"mock_fallback"|"unavailable",
     "fetched_at": timestamp, "data": ..., "error": str|None}
Why: the classifier copies source/status/fetched_at into the audit log,
so provenance (who said it, when, live or mock) comes for free.
This file does NOT import streamlit, so evaluate.py can reuse it.
"""
import csv
import datetime as dt
import json
from pathlib import Path

import requests

DATA_DIR = Path(__file__).parent / "data"
TIMEOUT = 20  # seconds; a slow API must never freeze the demo

ONIONOO_URL = "https://onionoo.torproject.org/details"
VPN_LIST_URL = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt"
IPINFO_URL = "https://api.ipinfo.io/lite/{ip}"
ATLAS_URL = "https://api.ip-atlas.io/json/{ip}"  # free anonymous tier, no key
APPLE_RELAY_URL = "https://mask-api.icloud.com/egress-ip-ranges.csv"  # Apple iCloud Private Relay egress list
APPLE_PROVIDER = "Apple iCloud Private Relay"


def _now():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _mock():
    # Offline snapshot: our safety net for bad Wi-Fi during the demo.
    with open(DATA_DIR / "mock_data.json") as f:
        return json.load(f)


def _result(source, status, data, fetched_at=None, error=None):
    return {"source": source, "status": status, "data": data,
            "fetched_at": fetched_at or _now(), "error": error}


def load_asn_lists():
    with open(DATA_DIR / "hosting_asns.json") as f:
        return json.load(f)


def load_tunnel_ranges():
    """Published tunnel/relay provider ranges from data/tunnel_ranges.json (a static, hand-verified file).
    Returns the standard source-result shape; data = list of tuples (cidr, provider, source_url, as_of, meta).
    status: "static_file" (loaded) | "unavailable" (file missing or unreadable)."""
    path = DATA_DIR / "tunnel_ranges.json"
    try:
        with open(path, encoding="utf-8") as f:
            j = json.load(f)
    except (OSError, ValueError) as e:
        return _result("Tunnel/relay provider ranges", "unavailable", [], error=str(e))
    rows = [(cidr, name, p.get("source_url", ""), p.get("as_of", ""), "")
            for name, p in (j.get("providers") or {}).items() for cidr in p.get("ranges") or []]
    return _result("Tunnel/relay provider ranges", "static_file", rows, fetched_at=j.get("as_of"))


def _parse_apple_csv(lines, as_of):
    """Apple egress CSV lines 'cidr,country,region,city,' -> rows (cidr, provider, url, as_of, 'GB London').
    csv module, so quoted city names containing commas survive. Blank lines are skipped; anything else is kept
    and left for prepare_tunnel to validate and count."""
    rows = []
    for rec in csv.reader(lines):
        if not rec or not rec[0].strip():
            continue
        place = " ".join(x.strip() for x in (rec[1:2] + rec[3:4]) if x.strip())
        rows.append((rec[0].strip(), APPLE_PROVIDER, APPLE_RELAY_URL, as_of, place))
    return rows


def fetch_apple_relay(force_mock=False):
    """Apple's published iCloud Private Relay egress ranges (about 12 MB CSV, a quarter of a million rows)
    -> source-result with data = rows. These are ranges traffic LEAVES from, so they suit source-IP matching."""
    error = None
    if not force_mock:
        try:
            with requests.get(APPLE_RELAY_URL, timeout=TIMEOUT, stream=True) as resp:
                resp.raise_for_status()
                resp.encoding = "utf-8"
                now = _now()
                rows = _parse_apple_csv(resp.iter_lines(decode_unicode=True), now[:10])
            if not rows:
                raise ValueError("Apple egress list was empty")
            return _result("Apple iCloud Private Relay egress list", "live", rows, now)
        except Exception as e:
            error = str(e)
    m = _mock()
    rows = [(c, APPLE_PROVIDER, APPLE_RELAY_URL, m["fetched_at"][:10], f"{cc} {city}".strip())
            for c, cc, city in m.get("apple_relay", [])]
    return _result("Apple iCloud Private Relay egress list (mock snapshot)",
                   "mock" if force_mock else "mock_fallback", rows, m["fetched_at"], error)


def merge_tunnel_sources(*sources):
    """Combine several tunnel-range sources into ONE source-result for the classifier.
    status = least trustworthy component (mock_fallback > mock > unavailable > live > static_file), so a
    mock Apple list can never be reported as live. Each hit still carries its own provider/source URL/as_of."""
    order = ["mock_fallback", "mock", "unavailable", "live", "static_file"]
    status = min((s["status"] for s in sources), key=lambda x: order.index(x) if x in order else 0)
    live = next((s for s in sources if s["status"] == "live"), sources[0])
    return _result(" + ".join(s["source"] for s in sources), status, [r for s in sources for r in s["data"]],
                   live["fetched_at"], "; ".join(s["error"] for s in sources if s.get("error")) or None)


def fetch_tor_exits(force_mock=False):
    """Official Tor Project Onionoo API -> {ip: relay info}."""
    error = None
    if not force_mock:
        try:
            resp = requests.get(
                ONIONOO_URL,
                # running+Exit flag = only relays that are up AND allowed to exit traffic.
                # 'fields' keeps the download small.
                params={"running": "true", "flag": "Exit",
                        "fields": "nickname,fingerprint,exit_addresses,or_addresses,last_seen"},
                timeout=TIMEOUT)
            resp.raise_for_status()
            index = {}
            for relay in resp.json().get("relays", []):
                info = {"nickname": relay.get("nickname"),
                        "fingerprint": relay.get("fingerprint"),
                        "last_seen": relay.get("last_seen")}
                # exit_addresses = the IPs traffic actually leaves from -> strongest evidence
                for ip in relay.get("exit_addresses", []):
                    index[ip] = {**info, "match_type": "exit_address"}
                # or_addresses = where the relay listens; weaker (exit IP may differ)
                for addr in relay.get("or_addresses", []):
                    ip = addr.rsplit(":", 1)[0].strip("[]")
                    index.setdefault(ip, {**info, "match_type": "or_address"})
            return _result("Tor Project Onionoo", "live", index)
        except Exception as e:  # any failure -> fall back, never crash
            error = str(e)
    m = _mock()
    return _result("Tor Project Onionoo (mock snapshot)",
                   "mock" if force_mock else "mock_fallback",
                   m["tor_exits"], m["fetched_at"], error)


def fetch_vpn_ranges(force_mock=False):
    """Community-maintained list of VPN CIDR ranges -> list of strings."""
    error = None
    if not force_mock:
        try:
            resp = requests.get(VPN_LIST_URL, timeout=TIMEOUT)
            resp.raise_for_status()
            cidrs = [l.strip() for l in resp.text.splitlines()
                     if l.strip() and not l.startswith("#")]
            return _result("X4BNet VPN range list", "live", cidrs)
        except Exception as e:
            error = str(e)
    m = _mock()
    return _result("X4BNet VPN range list (mock snapshot)",
                   "mock" if force_mock else "mock_fallback",
                   m["vpn_ranges"], m["fetched_at"], error)


def fetch_ip_info(ip, token=None, force_mock=False):
    """IPinfo Lite (free, needs a token) -> {asn, as_name, country_code}."""
    error = None
    if token and not force_mock:
        try:
            resp = requests.get(IPINFO_URL.format(ip=ip), params={"token": token},
                                timeout=TIMEOUT)
            resp.raise_for_status()
            j = resp.json()
            return _result("IPinfo Lite", "live",
                           {"asn": j.get("asn", ""), "as_name": j.get("as_name", ""),
                            "country_code": j.get("country_code", "")})
        except Exception as e:
            error = str(e)
    m = _mock()
    if ip in m["ip_info"]:
        return _result("IPinfo Lite (mock snapshot)",
                       "mock" if force_mock else "mock_fallback",
                       m["ip_info"][ip], m["fetched_at"], error)
    # No token and not in mock: say so honestly -> classifier will lean Unknown.
    return _result("IPinfo Lite", "unavailable", {}, error=error or "no API token set")


def fetch_ip_atlas(ip, force_mock=False):
    """IP-Atlas -> {asn, org, is_datacenter, is_vpn}. Free tier is rate-limited, so we
    never crash on errors: a failure just means 'no evidence from this source'."""
    error = None
    if not force_mock:
        try:
            resp = requests.get(ATLAS_URL.format(ip=ip), timeout=TIMEOUT)
            resp.raise_for_status()
            j = resp.json()
            return _result("IP-Atlas", "live",
                           {"asn": j.get("asn"), "org": j.get("org"),
                            "is_datacenter": j.get("is_datacenter"), "is_vpn": j.get("is_vpn")})
        except Exception as e:
            error = str(e)
    m = _mock()
    if ip in m.get("ip_atlas", {}):
        return _result("IP-Atlas (mock snapshot)", "mock" if force_mock else "mock_fallback",
                       m["ip_atlas"][ip], m["fetched_at"], error)
    return _result("IP-Atlas", "unavailable", {}, error=error or "no data")
