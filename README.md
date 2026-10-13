# Team Argus: Evidence-Based IP Network-Type Classifier (PS-010)

Classifies an IP as **Known Tor Exit**, **Known Hosted VPN/Proxy Endpoint**, **Known Tunnel/Relay Endpoint**
or **Unknown**, and records the evidence behind each answer. Returns Unknown when evidence is insufficient.

## Setup

```
python -m pip install -r requirements.txt
```

Optional: set an IPinfo Lite token (free) for live ASN data.

```
$env:IPINFO_TOKEN="your_token_here"        # PowerShell
export IPINFO_TOKEN=your_token_here        # macOS / Linux
```

## Run

```
streamlit run app.py                       # web app: Single IP, Batch CSV, Whitelist IP, Audit log
python -m pytest tests -q                  # 49 tests, no network needed
python evaluate.py labelled_ips.csv --live # per-class precision, recall, coverage (needs network)
python evaluate.py                         # offline, uses the bundled mock snapshot and test_ips.csv
python build_labelled_set.py --per-class 30 --seed 42 --out labelled_ips.csv   # builds the labelled set
```

Tick **Offline demo mode** in the app to use the bundled mock snapshot instead of live sources.

## Rules

Rules run in this order and stop at the first match.

| Rule | Test | Label | Confidence |
|---|---|---|---|
| R1 | IP is a running Tor exit (Onionoo) | Known Tor Exit | High for exit address, Medium for relay address |
| RT | IP is inside a range a provider publishes for its relay service (Apple iCloud Private Relay) | Known Tunnel/Relay Endpoint | Medium; High if ASN or IP-Atlas corroborate |
| R2 | IP is inside a known VPN range list (X4BNet) | Known Hosted VPN/Proxy Endpoint | Medium; High if ASN or IP-Atlas corroborate |
| R3 | ASN is a known VPN provider, or IP-Atlas flags VPN | Known Hosted VPN/Proxy Endpoint | Medium; High if both agree |
| R4 | Hosting ASN or datacentre flag only | Unknown (HOSTING ONLY) | Low |
| none | No source produced evidence | Unknown (NO EVIDENCE) | Medium if ASN known, else Low |

Hosting alone is never treated as VPN. Ranges broader than /8 (IPv4) or /16 (IPv6), and ranges in private,
carrier-grade NAT, loopback, link-local, multicast or reserved space, are rejected and counted, never matched.

## Whitelist

The **Whitelist IP** tab stores trusted IPv4, IPv6 and CIDR ranges in the `whitelist` table of `audit.db`.
Matching uses exact bitmask comparison, not string prefixes. Disabled entries never match, and the most
specific enabled range is reported. The whitelist does not change a classification; it is shown alongside it.

## Data sources

| Source | Use | Retrieved |
|---|---|---|
| Tor Project Onionoo | Tor exit list | Live |
| X4BNet VPN range list | VPN ranges | Live |
| Apple iCloud Private Relay egress CSV | Tunnel/relay ranges | Live (offline snapshot of 11 rows) |
| IPinfo Lite | ASN and network name | Live, needs token |
| IP-Atlas | VPN and datacentre flags | Live |
| `data/hosting_asns.json` | Hosting networks and VPN provider ASNs | Curated, dated 2026-09-29 |
| `data/tunnel_ranges.json` | Other published tunnel ranges | Empty by design |

Every result records the source, its status (`live`, `mock`, `mock_fallback`, `unavailable`), and the fetch time.
A result that relies on a snapshot says so in its reason text.

## Evaluation

The final run used `labelled_ips.csv` (120 IPs, 30 per class, retrieved 2026-10-13T16:49:20Z). All 120 IPs
returned live data from both IPinfo and IP-Atlas.

| Class | Precision | Recall | F1 | Coverage |
|---|---|---|---|---|
| Known Tor Exit | 1.00 | 1.00 | 1.00 | 0.25 |
| Known Hosted VPN/Proxy Endpoint | 1.00 | 0.73 | 0.85 | 0.18 |
| Known Tunnel/Relay Endpoint | 1.00 | 1.00 | 1.00 | 0.25 |
| Unknown | 0.79 | 1.00 | 0.88 | 0.32 |

Hosting-but-not-VPN trap: 0 false VPN calls out of 30 hosting IPs.

Read these with care. Tor and Tunnel samples come from the same feeds the rules read, so those scores are not
independent tests. The VPN misses are VPN servers on rented hosting (AS25369, AS62240), which the rules
correctly treat as hosting only. Samples are small (30 per class), so one miss moves recall by about 3 points.

## Limitations

- VPN servers on third-party hosting cannot be identified from ASN and range data alone.
- No verified clean-residential class, so Unknown precision is a soft figure.
- Labels are only true as of their retrieval date. Re-run `build_labelled_set.py` before reusing results.
- Cloudflare Tunnel and ngrok cannot be detected from published ranges.
- Residential VPN users cannot be distinguished from ordinary home traffic.

## Layout

```
app.py                  Streamlit UI (tabs: Single IP, Batch CSV, Whitelist IP, Audit log)
classifier.py           Rule engine: R1, RT, R2, R3, R4 (no network calls)
data_fetcher.py         Source fetchers; every source returns the same result shape
audit.py                SQLite audit log and whitelist storage
whitelist.py            Whitelist parsing and bitmask matching (pure Python)
whitelist_ui.py         Whitelist tab
theme.py                Dark console styling and status pills
evaluate.py             Per-class precision, recall, coverage
build_labelled_set.py   Builds a labelled set from published provider sources
data/                   hosting_asns.json, tunnel_ranges.json, mock_data.json
tests/                  49 tests (whitelist, tunnel rule, labelled-set builder, UI smoke test)
```
