"""RT rule tests. Uses SYNTHETIC ranges from RFC 5737 documentation space; no real provider data."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import classifier as C
import data_fetcher as D

EMPTY = {"source": "IP-Atlas", "status": "unavailable", "fetched_at": "n/a", "data": {}}
TOR = {"source": "Tor", "status": "mock", "fetched_at": "t", "data": {"198.51.100.10": {
    "nickname": "x", "fingerprint": "f", "last_seen": "s", "match_type": "exit_address"}}}
VPN = C.prepare_vpn({"source": "VPN", "status": "mock", "fetched_at": "t", "data": ["203.0.113.0/24"]})
LISTS = {"hosting": {"AS24940": "Hetzner"}, "vpn_providers": {"AS9009": "M247"}, "hosting_keywords": ["hosting"]}


def tunnel(ranges):
    rows = [(c, p, "https://example.test/ranges", "2026-10-13", "") for c, p in ranges]
    return C.prepare_tunnel({"source": "Tunnel/relay provider ranges", "status": "static_file",
                             "fetched_at": "2026-10-13", "data": rows})


def info(asn="", name=""):
    return {"source": "IPinfo", "status": "mock", "fetched_at": "t", "data": {"asn": asn, "as_name": name}}


def run(ip, tun, asn="", name="", atlas=None):
    return C.classify_ip(ip, TOR, VPN, info(asn, name), LISTS, atlas, tun)


def test_match_single_source_is_medium():
    r = run("192.0.2.77", tunnel([("192.0.2.64/26", "demo-relay")]))
    assert r["label"] == C.LABEL_TUN and r["rule_fired"] == "RT" and r["confidence"] == "Medium"
    assert "demo-relay" in r["reason"] and r["path"][-1] == "TUN"


def test_corroborated_is_high():
    r = run("192.0.2.77", tunnel([("192.0.2.64/26", "demo-relay")]), asn="AS24940", name="Hetzner")
    assert r["confidence"] == "High"


def test_boundaries():
    t = tunnel([("192.0.2.64/26", "demo")])
    assert run("192.0.2.64", t)["label"] == C.LABEL_TUN
    assert run("192.0.2.127", t)["label"] == C.LABEL_TUN
    assert run("192.0.2.128", t)["label"] == C.LABEL_UNK
    assert run("192.0.2.63", t)["label"] == C.LABEL_UNK


def test_precedence_tor_then_tunnel_then_vpn():
    t = tunnel([("198.51.100.0/24", "demo"), ("203.0.113.0/24", "demo")])
    assert run("198.51.100.10", t)["rule_fired"] == "R1"      # Tor wins over everything
    assert run("203.0.113.9", t)["rule_fired"] == "RT"        # published tunnel range beats the generic VPN list
    assert run("203.0.113.9", tunnel([]))["rule_fired"] == "R2"  # VPN list alone still labels it VPN


def test_apple_relay_inside_live_vpn_list_is_tunnel_not_vpn():
    """Regression (batch run): Apple relay IPs sit inside the live X4BNet VPN list, so R2 used to win
    and RT never ran. RT now runs first, so the more specific published label is kept."""
    vpn_live = C.prepare_vpn({"source": "X4BNet", "status": "live", "fetched_at": "t", "data": ["172.224.226.0/24"]})
    t = tunnel([("172.224.226.0/27", "Apple iCloud Private Relay")])
    r = C.classify_ip("172.224.226.5", TOR, vpn_live, info(), LISTS, None, t)
    assert r["label"] == C.LABEL_TUN and r["rule_fired"] == "RT"
    ev_names = [e["question"].split(":")[0] for e in r["evidence"]]
    assert "RT" in ev_names and "R2" not in ev_names   # RT ran, R2 never reached


def test_hosting_alone_is_not_tunnel():
    r = run("192.0.2.200", tunnel([("192.0.2.64/26", "demo")]), asn="AS24940", name="Hetzner")
    assert r["label"] == C.LABEL_UNK and r["rule_fired"] == "R4"


def test_empty_or_missing_list_matches_nothing_and_says_so():
    for t in (tunnel([]), None):
        r = run("192.0.2.77", t)
        ev = [e for e in r["evidence"] if e["question"].startswith("RT:")][0]
        assert r["label"] == C.LABEL_UNK and ev["result"] == "no match" and "no tunnel ranges" in ev["detail"]


def test_bad_and_too_broad_ranges_are_skipped_and_reported():
    t = tunnel([("0.0.0.0/0", "typo"), ("10.0.0.0/7", "typo"), ("not-a-cidr", "x"), ("::/0", "typo"),
                ("192.0.2.64/26", "ok"), ("192.0.2.65/26", "host-bits")])
    assert t["count"] == 1 and "skipped" in t["error"]
    assert run("8.8.8.8", t)["label"] == C.LABEL_UNK


def test_most_specific_provider_reported():
    t = tunnel([("192.0.2.0/24", "broad"), ("192.0.2.64/26", "narrow")])
    assert "narrow" in run("192.0.2.70", t)["reason"]


def test_ipv6():
    r = run("2001:db8::5", tunnel([("2001:db8::/32", "v6demo")]))
    assert r["label"] == C.LABEL_TUN


def test_shipped_file_loads_and_is_empty():
    r = D.load_tunnel_ranges()
    assert r["status"] == "static_file" and r["data"] == []


# ---- Apple iCloud Private Relay: rows below are the REAL first lines of Apple's egress-ip-ranges.csv ----
APPLE_LINES = """172.224.226.0/27,GB,GB-EN,London,
172.224.226.32/31,GB,GB-SC,Aberdeen,
172.224.226.34/31,GB,GB-EN,Oxford,
172.224.226.50/31,GB,GB-EN,Cambridge,
""".splitlines()


def test_apple_csv_parse_and_match():
    rows = D._parse_apple_csv(APPLE_LINES, "2026-10-13")
    assert len(rows) == 4 and rows[0][0] == "172.224.226.0/27" and rows[0][4] == "GB London"
    t = C.prepare_tunnel({"source": "Apple", "status": "live", "fetched_at": "t", "data": rows})
    assert t["count"] == 4 and t["skipped_count"] == 0
    r = run("172.224.226.5", t)
    assert r["label"] == C.LABEL_TUN and r["rule_fired"] == "RT" and "Apple iCloud Private Relay" in r["reason"]
    ev = [e for e in r["evidence"] if e["question"].startswith("RT:")][0]
    assert "172.224.226.0/27" in ev["detail"] and "GB London" in ev["detail"] and "mask-api.icloud.com" in ev["detail"]
    assert run("172.224.226.33", t)["label"] == C.LABEL_TUN          # inside 172.224.226.32/31
    assert run("172.224.226.36", t)["label"] == C.LABEL_UNK          # not in these four rows
    assert run("172.224.226.64", t)["label"] == C.LABEL_UNK


def test_apple_csv_quoted_city_blank_lines_and_junk():
    rows = D._parse_apple_csv(['', '10.9.8.0/24,US,US-CA,"Washington, D.C.",', 'garbage-line', '203.0.113.0/25,US,US-NY,New York,'], "d")
    assert len(rows) == 3 and rows[0][4] == "US Washington, D.C."
    t = C.prepare_tunnel({"source": "Apple", "status": "live", "fetched_at": "t", "data": rows})
    assert t["count"] == 1 and t["skipped_count"] == 2   # private range and junk are counted, not matched


def test_apple_mock_snapshot_and_merge_status_never_looks_live():
    apple = D.fetch_apple_relay(force_mock=True)
    assert apple["status"] == "mock" and len(apple["data"]) == 11
    merged = D.merge_tunnel_sources(D.load_tunnel_ranges(), apple)
    assert merged["status"] == "mock" and len(merged["data"]) == 11
    live = {"source": "L", "status": "live", "fetched_at": "t", "data": []}
    fileish = {"source": "F", "status": "static_file", "fetched_at": "d", "data": []}
    assert D.merge_tunnel_sources(fileish, live)["status"] == "live"
    assert D.merge_tunnel_sources(fileish, {**live, "status": "mock_fallback"})["status"] == "mock_fallback"


def test_lookup_is_most_specific_and_exact_across_prefix_lengths():
    t = tunnel([("172.224.226.0/27", "wide"), ("172.224.226.4/31", "narrow")])
    assert "narrow" in run("172.224.226.5", t)["reason"] and "wide" in run("172.224.226.9", t)["reason"]
    assert run("172.224.226.32", t)["label"] == C.LABEL_UNK


def test_flow_dot_contains_rt_and_highlights_path():
    dot = C.build_flow_dot(["start", "R1", "RT", "TUN"])
    assert "RT -> TUN" in dot and "R1 -> RT" in dot and "RT -> R2" in dot
    assert 'RT [label="RT: Published tunnel' in dot and 'R2 [label="R2: In VPN' in dot


def test_non_public_space_rejected_with_reason():
    """Regression: a research answer listed CGNAT (100.64/12, 100.96/12) as 'Cloudflare' ranges."""
    bad = ["100.64.0.0/12", "100.96.0.0/12", "100.64.0.0/10", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
           "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "fc00::/7", "fe80::/10", "ff00::/8", "::1/128"]
    t = tunnel([(c, "x") for c in bad])
    assert t["count"] == 0 and t["skipped_count"] == len(bad)
    why = dict(t["skipped"])
    assert all(r in ("non-public address space", "too broad") for r in why.values())
    for cgnat in ("100.64.0.0/12", "100.96.0.0/12", "100.64.0.0/10", "10.0.0.0/8", "192.168.0.0/16"):
        assert why[cgnat] == "non-public address space", cgnat
    assert run("100.70.1.1", t)["label"] == C.LABEL_UNK  # an ordinary CGNAT customer is not a tunnel


def test_skip_reasons_distinguished_and_public_kept():
    t = tunnel([("0.0.0.0/0", "a"), ("zzz", "b"), ("10.1.0.0/16", "c"), ("192.0.2.64/26", "ok")])
    assert dict(t["skipped"]) == {"0.0.0.0/0": "too broad", "zzz": "malformed", "10.1.0.0/16": "non-public address space"}
    assert t["count"] == 1


def test_range_overlapping_private_space_rejected_even_if_mostly_public():
    assert tunnel([("100.0.0.0/8", "x")])["count"] == 0   # /8 contains 100.64.0.0/10


# ---- live fetch path, exercised with a fake HTTP response (the sandbox cannot reach Apple) ----
class _FakeResp:
    def __init__(self, lines, fail=False):
        self._lines, self._fail, self.encoding = lines, fail, None
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def raise_for_status(self):
        if self._fail:
            raise RuntimeError("503 Service Unavailable")
    def iter_lines(self, decode_unicode=False): return iter(self._lines)


def test_fetch_apple_live_ok(monkeypatch):
    monkeypatch.setattr(D.requests, "get", lambda *a, **k: _FakeResp(APPLE_LINES))
    r = D.fetch_apple_relay(force_mock=False)
    assert r["status"] == "live" and len(r["data"]) == 4 and r["error"] is None


def test_fetch_apple_http_error_falls_back_to_mock_and_says_why(monkeypatch):
    monkeypatch.setattr(D.requests, "get", lambda *a, **k: _FakeResp([], fail=True))
    r = D.fetch_apple_relay(force_mock=False)
    assert r["status"] == "mock_fallback" and "503" in r["error"] and len(r["data"]) == 11


def test_fetch_apple_empty_body_falls_back(monkeypatch):
    monkeypatch.setattr(D.requests, "get", lambda *a, **k: _FakeResp(["", ""]))
    r = D.fetch_apple_relay(force_mock=False)
    assert r["status"] == "mock_fallback" and "empty" in r["error"]


def test_fetch_apple_network_exception_falls_back(monkeypatch):
    def boom(*a, **k): raise D.requests.ConnectionError("no route")
    monkeypatch.setattr(D.requests, "get", boom)
    assert D.fetch_apple_relay(force_mock=False)["status"] == "mock_fallback"


def test_snapshot_status_is_stated_in_reason():
    t = C.prepare_tunnel({"source": "Apple (mock snapshot)", "status": "mock_fallback", "fetched_at": "t",
                          "data": [("192.0.2.64/26", "Apple iCloud Private Relay", "u", "d", "GB London")]})
    r = run("192.0.2.77", t)
    assert "not live" in r["reason"] and "mock_fallback" in r["reason"]
    live = C.prepare_tunnel({"source": "Apple", "status": "live", "fetched_at": "t",
                             "data": [("192.0.2.64/26", "Apple iCloud Private Relay", "u", "d", "")]})
    assert "not live" not in run("192.0.2.77", live)["reason"]
