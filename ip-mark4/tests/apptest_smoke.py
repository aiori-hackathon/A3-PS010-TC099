"""Headless UI smoke test: python tests/apptest_smoke.py  (uses Streamlit AppTest, offline mock mode)."""
import os, sys, tempfile
from pathlib import Path
from streamlit.testing.v1 import AppTest
ROOT = Path(__file__).parent.parent
os.chdir(ROOT)
os.environ["AUDIT_DB"] = os.path.join(tempfile.mkdtemp(), "smoke_audit.db")  # never touch the real audit.db
sys.path.insert(0, str(ROOT))
at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=120)
at.run()
at.sidebar.checkbox[0].set_value(True).run()  # offline demo mode
assert not at.exception, [e.value for e in at.exception]
print("tabs:", [t.label for t in at.tabs])

def btn(label):
    return [b for b in at.button if b.label == label][0]
def fsub(label):
    return [b for b in at.button if b.label == label][0]
def md():
    return "\n".join(m.value for m in at.markdown)

at.text_area(key="wl_raw").set_value("10.0.0.0/8, 10.0.0.5\n192.168.1.5/24\n300.1.1.1\n2001:db8::/32")
at.text_input(key="wl_label").set_value("office egress")
fsub("Add to whitelist").click().run()
assert not at.exception, [e.value for e in at.exception]
print("raw after add (rejects stay):", repr(at.text_area(key="wl_raw").value))
assert "3 added. 2 rejected." in md(), "feedback missing"
assert "Host bits set; network address is 192.168.1.0/24" in md()
assert "300.1.1.1" in md()

for ip, expect in [("10.0.0.5", "Whitelisted"), ("11.0.0.1", "Not whitelisted"), ("2001:db8::7", "Whitelisted"),
                   ("10.0.0", "Invalid IP"), ("10.0.0.0/8", "Invalid IP")]:
    at.text_input(key="wl_check").set_value(ip).run()
    html = md()
    assert expect in html, (ip, expect)
    print(f"check {ip:14s} -> {expect}")
at.text_input(key="wl_check").set_value("10.0.0.5").run()
assert "Most specific match" in md() and "10.0.0.5/32" in md(), "specific match"

# disable the /32 -> falls back to /8 ; the toggle is keyed by entry id
from audit import wl_list
ents = {e["cidr"]: e for e in wl_list()}
at.toggle(key=f"en_{ents['10.0.0.5/32']['id']}").set_value(False).run()
assert "10.0.0.0/8" in md() and "Most specific match" in md()
at.toggle(key=f"en_{ents['10.0.0.0/8']['id']}").set_value(False).run()
assert "Not whitelisted" in md(), "disabled must not match"
print("toggle OK")

# inline edit with bad then good value
wid = ents["10.0.0.0/8"]["id"]
[b for b in at.button if b.key == f"ed_{wid}"][0].click().run()
at.text_input(key=f"e_cidr_{wid}").set_value("10.0.0.1/8")
[b for b in at.button if b.key == f"sv_{wid}"][0].click().run()
assert "Host bits set" in md()
at.text_input(key=f"e_cidr_{wid}").set_value("172.16.0.0/12")
[b for b in at.button if b.key == f"sv_{wid}"][0].click().run()
assert any(e["cidr"] == "172.16.0.0/12" for e in wl_list()), "edit not saved"
print("edit OK")

# delete
[b for b in at.button if b.key == f"del_{wid}"][0].click().run()
assert not any(e["cidr"] == "172.16.0.0/12" for e in wl_list())
print("delete OK")

# single IP classify still works and shows whitelist line
at.text_input(key="single_ip").set_value("203.0.113.5").run()
btn("Classify").click().run()
assert not at.exception, [e.value for e in at.exception]
assert "VPN/PROXY" in md() and "Whitelist:" in md()
for ip, expect in [("192.0.2.10", "NO EVIDENCE"), ("8.8.8.8", "HOSTING ONLY")]:
    at.text_input(key="single_ip").set_value(ip).run()
    btn("Classify").click().run()
    assert expect in md() and "UNKNOWN</span>" not in md().upper(), (ip, expect)
at.text_input(key="single_ip").set_value("172.224.226.5").run()
btn("Classify").click().run()
assert "TUNNEL/RELAY" in md() and "Apple iCloud Private Relay" in md() and "RT" in md()
print("tunnel UI OK")
print("classify OK")
print("ALL OK")
