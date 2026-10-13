import ipaddress
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import whitelist as wl


def E(cidr, enabled=True, label="", added="2026-10-11T00:00:00Z"):
    return {"id": cidr, "cidr": cidr, "label": label, "added_at": added, "enabled": enabled}


def test_parse_single_and_cidr():
    assert wl.parse_entry("10.0.0.5") == ("10.0.0.5/32", None)
    assert wl.parse_entry("192.168.1.0/24") == ("192.168.1.0/24", None)
    assert wl.parse_entry("2001:db8::/32") == ("2001:db8::/32", None)
    assert wl.parse_entry("2001:DB8::1") == ("2001:db8::1/128", None)


def test_rejects_with_reason():
    for bad in ["300.1.1.1", "10.0.0.0/33", "10.0.0.0/x", "192.168.1.5/24", "foo", "10.0.0.1 office",
                "fe80::1%eth0", "2001:db8::/129", "010.0.0.1", "10.0.0"]:
        cidr, reason = wl.parse_entry(bad)
        assert cidr is None and reason, bad
    assert "192.168.1.0/24" in wl.parse_entry("192.168.1.5/24")[1]


def test_not_string_prefix():
    es = [E("10.1.0.0/16")]
    assert wl.check_ip("10.10.0.1", es)["state"] == "unlisted"
    assert wl.check_ip("10.1.200.9", es)["state"] == "whitelisted"
    assert wl.check_ip("10.2.0.1", es)["state"] == "unlisted"


def test_boundaries_v4():
    es = [E("192.168.1.0/24")]
    assert wl.check_ip("192.168.1.0", es)["state"] == "whitelisted"
    assert wl.check_ip("192.168.1.255", es)["state"] == "whitelisted"
    assert wl.check_ip("192.168.2.0", es)["state"] == "unlisted"
    assert wl.check_ip("192.168.0.255", es)["state"] == "unlisted"


def test_v6_and_version_isolation():
    es = [E("2001:db8::/32")]
    assert wl.check_ip("2001:db8:ffff::1", es)["state"] == "whitelisted"
    assert wl.check_ip("2001:db9::1", es)["state"] == "unlisted"
    assert wl.check_ip("0.0.0.0", [E("::/0")])["state"] == "unlisted"
    assert wl.check_ip("::1", [E("0.0.0.0/0")])["state"] == "unlisted"


def test_ipv4_mapped_v6():
    assert wl.check_ip("::ffff:10.0.0.5", [E("10.0.0.0/8")])["state"] == "whitelisted"


def test_disabled_never_matches():
    es = [E("10.0.0.0/8", enabled=False)]
    assert wl.check_ip("10.0.0.1", es)["state"] == "unlisted"


def test_most_specific_wins():
    es = [E("10.0.0.0/8", label="corp"), E("10.0.0.0/24", label="lab"), E("10.0.0.5/32", label="host"),
          E("10.0.0.0/16", enabled=False, label="off")]
    r = wl.check_ip("10.0.0.5", es)
    assert r["match"]["cidr"] == "10.0.0.5/32"
    assert [o["cidr"] for o in r["others"]] == ["10.0.0.0/24", "10.0.0.0/8"]
    assert wl.check_ip("10.0.9.9", es)["match"]["cidr"] == "10.0.0.0/8"


def test_invalid_check():
    for bad in ["", "999.1.1.1", "10.0.0.0/8", "abc"]:
        r = wl.check_ip(bad, [])
        assert r["state"] == "invalid" and r["reason"]


def test_bulk_nothing_dropped():
    ok, bad = wl.parse_bulk("10.0.0.1, 10.0.0.1\n300.0.0.1,2001:db8::/32\n", existing_cidrs=["2001:db8::/32"])
    assert ok == ["10.0.0.1/32"]
    assert len(bad) == 3 and all(r for _, r in bad)


def test_import_json_and_lines():
    ok, bad = wl.parse_import('[{"cidr":"10.0.0.0/8","label":"corp","enabled":false},"1.2.3.4",{"x":1}]')
    assert [o["cidr"] for o in ok] == ["10.0.0.0/8", "1.2.3.4/32"] and ok[0]["enabled"] is False and len(bad) == 1
    ok, bad = wl.parse_import("10.0.0.0/8\nbogus")
    assert len(ok) == 1 and len(bad) == 1


def test_roundtrip_export():
    es = [E("10.0.0.0/8", label="corp")]
    ok, bad = wl.parse_import(wl.export_json(es))
    assert ok[0]["cidr"] == "10.0.0.0/8" and ok[0]["label"] == "corp" and not bad


def test_matches_stdlib_on_random():
    import random
    rnd = random.Random(7)
    for _ in range(2000):
        plen = rnd.randint(0, 32)
        net = ipaddress.ip_network((rnd.getrandbits(32), plen), strict=False)
        a = ipaddress.ip_address(rnd.getrandbits(32))
        assert wl.net_contains(net, a) == (a in net)
    for _ in range(2000):
        plen = rnd.randint(0, 128)
        net = ipaddress.ip_network((rnd.getrandbits(128), plen), strict=False)
        a = ipaddress.ip_address(rnd.getrandbits(128))
        assert wl.net_contains(net, a) == (a in net)
