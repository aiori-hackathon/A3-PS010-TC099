"""
whitelist.py - whitelist parsing and matching. Pure Python: no streamlit, no sqlite.

An entry is a dict:  {id, cidr, label, added_at, enabled}
  cidr      canonical network string, e.g. "10.0.0.5/32", "192.168.1.0/24", "2001:db8::/32"
  added_at  ISO 8601 UTC, e.g. "2026-10-11T09:14:02Z"
  enabled   bool

Matching is a bitmask compare: (address & netmask) == network_address, same IP version only.
It is never a string prefix match ("10.1" must not match "10.10.0.1").
"""
import ipaddress
import json
import re

MAX_LABEL = 80
_PLEN = re.compile(r"[0-9]{1,3}")


# ---------- parsing / validation ------------------------------------------------
def parse_entry(token):
    """Validate one whitelist entry. Returns (canonical_cidr, None) or (None, reason).

    A bare address becomes /32 (IPv4) or /128 (IPv6). Host bits set in a CIDR are
    REJECTED with the corrected network named, never silently masked.
    """
    t = (token or "").strip()
    if not t:
        return None, "Empty entry"
    if re.search(r"\s", t):
        return None, "Contains whitespace; separate entries with a comma or a new line"
    if "%" in t:
        return None, "Zone identifiers (%) are not supported"
    addr_s, slash, plen_s = t.partition("/")
    try:
        ip = ipaddress.ip_address(addr_s)
    except ValueError as e:
        return None, str(e)
    if slash:
        if not _PLEN.fullmatch(plen_s):
            return None, f"Prefix length '{plen_s}' is not a number"
        plen = int(plen_s)
        if plen > ip.max_prefixlen:
            return None, f"Prefix /{plen} is longer than /{ip.max_prefixlen} for IPv{ip.version}"
    else:
        plen = ip.max_prefixlen
    try:
        return str(ipaddress.ip_network(f"{ip}/{plen}", strict=True)), None
    except ValueError:
        net = ipaddress.ip_network(f"{ip}/{plen}", strict=False)
        return None, f"Host bits set; network address is {net}"


def parse_ip(text):
    """Validate a single address for the Check IP box. Returns (ip_address, None) or (None, reason)."""
    t = (text or "").strip()
    if not t:
        return None, "Empty input"
    if "/" in t:
        return None, "CIDR ranges are not accepted here; enter a single address"
    if re.search(r"\s", t):
        return None, "Contains whitespace"
    if "%" in t:
        return None, "Zone identifiers (%) are not supported"
    try:
        return ipaddress.ip_address(t), None
    except ValueError as e:
        return None, str(e)


def split_tokens(raw):
    """Comma- or newline-separated bulk paste -> list of non-empty tokens."""
    return [t.strip() for t in re.split(r"[,\n\r]+", raw or "") if t.strip()]


def parse_bulk(raw, existing_cidrs=()):
    """Parse a bulk paste. Returns (accepted_cidrs, rejected[(token, reason)]).
    Nothing is dropped silently: every token ends up in exactly one list."""
    tokens = split_tokens(raw)
    if not tokens:
        return [], [("", "No entries provided")]
    seen, ok, bad = set(existing_cidrs), [], []
    for tok in tokens:
        cidr, reason = parse_entry(tok)
        if reason:
            bad.append((tok, reason))
        elif cidr in seen:
            bad.append((tok, f"{cidr} is already listed"))
        else:
            seen.add(cidr)
            ok.append(cidr)
    return ok, bad


def parse_import(text, existing_cidrs=()):
    """Import a JSON export (list of {cidr,label,enabled,added_at} or strings) or a newline list.
    Returns (accepted[dict], rejected[(token, reason)])."""
    text = (text or "").strip()
    if not text:
        return [], [("", "File is empty")]
    try:
        data = json.loads(text)
    except ValueError:
        ok, bad = parse_bulk(text, existing_cidrs)
        return [{"cidr": c, "label": "", "enabled": True, "added_at": None} for c in ok], bad
    if isinstance(data, dict):
        data = data.get("entries")
    if not isinstance(data, list):
        return [], [("", "JSON must be a list of entries or an object with an 'entries' list")]
    seen, ok, bad = set(existing_cidrs), [], []
    for item in data:
        if isinstance(item, str):
            item = {"cidr": item}
        if not isinstance(item, dict) or not isinstance(item.get("cidr"), str):
            bad.append((json.dumps(item)[:60], "Entry has no 'cidr' string"))
            continue
        cidr, reason = parse_entry(item["cidr"])
        if reason:
            bad.append((item["cidr"], reason))
        elif cidr in seen:
            bad.append((item["cidr"], f"{cidr} is already listed"))
        else:
            seen.add(cidr)
            label = item.get("label")
            ts = item.get("added_at")
            ok.append({"cidr": cidr,
                       "label": label.strip()[:MAX_LABEL] if isinstance(label, str) else "",
                       "enabled": item.get("enabled") is not False,
                       "added_at": ts if isinstance(ts, str) else None})
    return ok, bad


# ---------- matching ---------------------------------------------------------------
def net_contains(net, addr):
    """Bitmask compare. Different IP versions never match."""
    if net.version != addr.version:
        return False
    return (int(addr) & int(net.netmask)) == int(net.network_address)


def _candidates(addr):
    """An IPv4-mapped IPv6 address (::ffff:a.b.c.d) is also tried as the IPv4 address."""
    mapped = getattr(addr, "ipv4_mapped", None)
    return [addr] + ([mapped] if mapped else [])


def find_matches(addr, entries):
    """All ENABLED entries containing addr, most specific (longest prefix) first."""
    hits = []
    for e in entries:
        if not e.get("enabled"):
            continue
        net = ipaddress.ip_network(e["cidr"], strict=False)
        if any(net_contains(net, a) for a in _candidates(addr)):
            hits.append((net.prefixlen, e))
    hits.sort(key=lambda h: (-h[0], h[1].get("added_at") or ""))
    return [e for _, e in hits]


def check_ip(text, entries):
    """Returns {state, ip, reason, match, others}.
    state: "whitelisted" | "unlisted" | "invalid".
    match = most specific enabled entry; others = remaining (less specific) enabled matches."""
    addr, reason = parse_ip(text)
    if reason:
        return {"state": "invalid", "ip": (text or "").strip(), "reason": reason, "match": None, "others": []}
    hits = find_matches(addr, entries)
    if hits:
        return {"state": "whitelisted", "ip": str(addr), "reason": None, "match": hits[0], "others": hits[1:]}
    return {"state": "unlisted", "ip": str(addr), "reason": None, "match": None, "others": []}


# ---------- export -------------------------------------------------------------------
def export_json(entries):
    keep = ("cidr", "label", "added_at", "enabled")
    return json.dumps([{k: e[k] for k in keep} for e in entries], indent=2)


def export_lines(entries):
    """One CIDR per line (labels are only kept by the JSON export)."""
    return "\n".join(e["cidr"] for e in entries) + ("\n" if entries else "")
