"""
build_labelled_set.py - build a labelled test set of IPs from PUBLISHED provider sources.

Every row records the URL it came from and the time it was retrieved, so a wrong label can be traced.
Run this on your own machine (it needs internet access):

    python build_labelled_set.py --per-class 30 --seed 42 --out labelled_ips.csv

Labels match classifier.py exactly, because evaluate.py compares strings.

  Known Tor Exit                   Tor Project Onionoo: running relays with the Exit flag, exit_addresses
  Known Hosted VPN/Proxy Endpoint  NordVPN server list (station IPs), Mullvad WireGuard relay list (ipv4_addr_in)
  Known Tunnel/Relay Endpoint      Apple iCloud Private Relay egress CSV (random host inside each published range)
  Unknown                          AWS published ip-ranges.json. Hosting, not VPN: must stay Unknown.
                                   note = hosting_not_vpn, which evaluate.py uses for its trap check

NOT included: an "ordinary / residential" class. No provider publishes a verified list of clean residential
IPs, so there is no honest source for it. Add those rows by hand, with a source you can cite.

Limitations:
  * The Apple class is what the tunnel rule itself reads, so it is a sanity check, not an independent test.
  * Provider server lists are provider claims. A server's advertised location may not be where it is.
  * These lists change. The retrieved_at column is the only record of when a label was true.
  * IPv4 only. IPv6 sources exist but are not sampled here.
"""
import argparse
import csv
import datetime as dt
import ipaddress
import random
import sys

import requests

TIMEOUT = 30
LABEL_TOR = "Known Tor Exit"
LABEL_VPN = "Known Hosted VPN/Proxy Endpoint"
LABEL_TUN = "Known Tunnel/Relay Endpoint"
LABEL_UNK = "Unknown"
COLUMNS = ["ip", "true_label", "source_url", "retrieved_at", "note"]

URLS = {
    "tor": "https://onionoo.torproject.org/details?running=true&flag=Exit&fields=exit_addresses",
    "nord": "https://api.nordvpn.com/v1/servers",
    "mullvad": "https://api.mullvad.net/app/v1/relays",
    "apple": "https://mask-api.icloud.com/egress-ip-ranges.csv",
    "aws": "https://ip-ranges.amazonaws.com/ip-ranges.json",
}


# ---------- parsing: one function per source, each returns plain values -------------------------------
def parse_tor(j):
    """Onionoo details -> exit IPv4 addresses (unique, sorted)."""
    seen = set()
    for relay in j.get("relays", []):
        for ip in relay.get("exit_addresses", []):
            if _is_v4(ip):
                seen.add(ip)
    return sorted(seen)


def parse_nord(j):
    """NordVPN /v1/servers -> one station IP per online server."""
    return sorted({s["station"] for s in j if s.get("station") and s.get("status", "online") == "online"
                   and _is_v4(s["station"])})


def parse_mullvad(j):
    """Mullvad /app/v1/relays -> IPv4 of WireGuard relays."""
    relays = (j.get("wireguard") or {}).get("relays", [])
    return sorted({r["ipv4_addr_in"] for r in relays if _is_v4(r.get("ipv4_addr_in", ""))})


def parse_apple(lines):
    """Apple egress CSV ('cidr,country,region,city,') -> IPv4 networks. Quoted commas handled by csv."""
    nets = []
    for rec in csv.reader(lines):
        if rec and rec[0].strip() and ":" not in rec[0]:
            try:
                nets.append(ipaddress.ip_network(rec[0].strip(), strict=False))
            except ValueError:
                continue
    return nets


def parse_aws(j):
    """AWS ip-ranges.json -> IPv4 prefixes (all services; hosting is the point)."""
    nets = []
    for p in j.get("prefixes", []):
        try:
            nets.append(ipaddress.ip_network(p["ip_prefix"], strict=False))
        except (KeyError, ValueError):
            continue
    return nets


def _is_v4(s):
    try:
        return ipaddress.ip_address(s).version == 4
    except ValueError:
        return False


# ---------- sampling -------------------------------------------------------------------------------------
def sample_points(pool, n, rng):
    """n distinct points from a list of individual IPs."""
    return rng.sample(pool, min(n, len(pool)))


def sample_ranges(networks, n, rng):
    """n distinct random hosts, each inside a randomly chosen network (no bias toward big prefixes).
    Networks of /31 or smaller use every address, so a single-address range is still represented."""
    out, seen, tries = [], set(), 0
    while len(out) < n and networks and tries < n * 20:
        tries += 1
        net = rng.choice(networks)
        count = net.num_addresses
        if count <= 2:
            ip = str(net.network_address)
        else:
            ip = str(ipaddress.ip_address(int(net.network_address) + rng.randrange(1, count - 1)))
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


# ---------- assembly (pure: takes parsed data, returns rows) ---------------------------------------------
def build_rows(parsed, per_class, seed, retrieved_at):
    """parsed: dict with keys tor, nord, mullvad (lists of IPs), apple, aws (lists of networks).
    Missing keys are skipped and reported in the returned warnings. Returns (rows, warnings)."""
    rng = random.Random(seed)
    rows, warnings, used = [], [], set()

    def add(ips, label, url, note, name):
        kept = 0
        for ip in ips:
            if ip in used:
                continue
            used.add(ip)
            rows.append({"ip": ip, "true_label": label, "source_url": url,
                         "retrieved_at": retrieved_at, "note": note})
            kept += 1
        if kept < per_class:
            warnings.append(f"{name}: only {kept} of {per_class} unique IPs available")

    if "tor" in parsed:
        add(sample_points(parsed["tor"], per_class, rng), LABEL_TOR, URLS["tor"],
            "Tor exit address (Onionoo, running + Exit)", "Tor")
    else:
        warnings.append("Tor: source missing, class skipped")

    vpn_pool = sorted(set(parsed.get("nord", []) + parsed.get("mullvad", [])))
    if vpn_pool:
        picks = sample_points(vpn_pool, per_class, rng)
        for ip in picks:
            if ip in set(parsed.get("nord", [])):
                src, note = URLS["nord"], "NordVPN server station IP (provider claim)"
            else:
                src, note = URLS["mullvad"], "Mullvad WireGuard relay IP (provider claim)"
            if ip in used:
                continue
            used.add(ip)
            rows.append({"ip": ip, "true_label": LABEL_VPN, "source_url": src,
                         "retrieved_at": retrieved_at, "note": note})
        if len(picks) < per_class:
            warnings.append(f"VPN: only {len(picks)} of {per_class} available")
    else:
        warnings.append("VPN: NordVPN and Mullvad sources missing or empty, class skipped")

    if "apple" in parsed:
        add(sample_ranges(parsed["apple"], per_class, rng), LABEL_TUN, URLS["apple"],
            "Apple iCloud Private Relay egress range (sanity check: same list the rule uses)", "Apple")
    else:
        warnings.append("Apple: source missing, class skipped")

    if "aws" in parsed:
        add(sample_ranges(parsed["aws"], per_class, rng), LABEL_UNK, URLS["aws"],
            "hosting_not_vpn: AWS cloud range, must not be labelled VPN", "AWS")
    else:
        warnings.append("AWS: source missing, class skipped")

    return rows, warnings


def write_csv(rows, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)


# ---------- network fetch (runs on your machine) ---------------------------------------------------------
def fetch_all():
    """Download each source. A failed source is reported and skipped, never fatal."""
    parsed, warnings = {}, []

    def get(name, parse, **kw):
        try:
            r = requests.get(URLS[name], timeout=TIMEOUT, **kw)
            r.raise_for_status()
            return parse(r)
        except Exception as e:  # any failure just removes that source
            warnings.append(f"{name}: fetch failed ({e})")
            return None

    v = get("tor", lambda r: parse_tor(r.json()))
    if v is not None: parsed["tor"] = v
    v = get("nord", lambda r: parse_nord(r.json()))
    if v is not None: parsed["nord"] = v
    v = get("mullvad", lambda r: parse_mullvad(r.json()))
    if v is not None: parsed["mullvad"] = v
    v = get("apple", lambda r: parse_apple(r.iter_lines(decode_unicode=True)), stream=True)
    if v is not None: parsed["apple"] = v
    v = get("aws", lambda r: parse_aws(r.json()))
    if v is not None: parsed["aws"] = v
    return parsed, warnings


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--per-class", type=int, default=30)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="labelled_ips.csv")
    args = ap.parse_args(argv)

    parsed, warnings = fetch_all()
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows, more = build_rows(parsed, args.per_class, args.seed, stamp)
    warnings += more
    write_csv(rows, args.out)

    counts = {}
    for r in rows:
        counts[r["true_label"]] = counts.get(r["true_label"], 0) + 1
    for label, n in counts.items():
        print(f"{n:4d}  {label}")
    for w in warnings:
        print("WARNING:", w, file=sys.stderr)
    print(f"wrote {len(rows)} rows to {args.out} (retrieved {stamp})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
