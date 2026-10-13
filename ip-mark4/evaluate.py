"""
evaluate.py - per-class precision / recall / coverage using scikit-learn.

Usage:
    python evaluate.py                                 # offline, reads test_ips.csv (your original 10 IPs)
    python evaluate.py labelled_ips.csv                # offline, any labelled file
    python evaluate.py labelled_ips.csv --live         # live APIs (set IPINFO_TOKEN first)

Offline results use the bundled mock snapshot, so they only test the RULES, not real data.
For a real accuracy check use --live on a labelled file built from published sources.
"""
import os
import sys
import time

import pandas as pd
from sklearn.metrics import precision_recall_fscore_support

from classifier import LABELS, LABEL_UNK, LABEL_VPN, classify_ip, prepare_tunnel, prepare_vpn
from data_fetcher import (fetch_apple_relay, fetch_ip_atlas, fetch_ip_info, fetch_tor_exits, fetch_vpn_ranges,
                          load_asn_lists, load_tunnel_ranges, merge_tunnel_sources)

args = [a for a in sys.argv[1:] if not a.startswith("--")]
live = "--live" in sys.argv
mock = not live
token = os.getenv("IPINFO_TOKEN")
path = args[0] if args else "test_ips.csv"
ATLAS_DELAY = 1.1  # IP-Atlas free tier is roughly 60 requests/min; a faster loop gets rate-limited silently

df = pd.read_csv(path)
tor, vpn, lists = fetch_tor_exits(mock), prepare_vpn(fetch_vpn_ranges(mock)), load_asn_lists()
tunnel = prepare_tunnel(merge_tunnel_sources(load_tunnel_ranges(), fetch_apple_relay(mock)))

predicted, statuses = [], {"info": [], "atlas": []}
for ip in df["ip"]:
    info = fetch_ip_info(ip, token, mock)
    atlas = fetch_ip_atlas(ip, mock)
    if live:
        time.sleep(ATLAS_DELAY)
    statuses["info"].append(info["status"])
    statuses["atlas"].append(atlas["status"])
    predicted.append(classify_ip(ip, tor, vpn, info, lists, atlas, tunnel)["label"])
df["predicted"] = predicted

# A live run is only meaningful if the per-IP sources actually answered. Report it, don't hide it.
if live:
    for name, vals in statuses.items():
        ok = sum(v == "live" for v in vals)
        print(f"{name}: {ok}/{len(vals)} IPs answered live")
        if ok < len(vals):
            print(f"  WARNING: {len(vals) - ok} IPs fell back or were unavailable; those results are not live")
    print()

p, r, f1, support = precision_recall_fscore_support(
    df["true_label"], df["predicted"], labels=LABELS, zero_division=0)
n = len(df)
predicted_counts = df["predicted"].value_counts()

report = pd.DataFrame({
    "class": LABELS, "precision": p.round(2), "recall": r.round(2), "f1": f1.round(2),
    "true_count": support,
    "coverage": [round(predicted_counts.get(l, 0) / n, 2) for l in LABELS]})
print(report.to_string(index=False))

print(f"\nOverall coverage (answered, not Unknown): {(df['predicted'] != LABEL_UNK).mean():.0%}")

if "note" in df:
    trap = df[df["note"].str.contains("hosting_not_vpn", na=False)]
    if len(trap):
        false_pos = (trap["predicted"] == LABEL_VPN).sum()
        print(f"Hosting-but-not-VPN trap: {false_pos} false VPN calls out of {len(trap)} IPs")

out = "evaluation_output.csv" if path == "test_ips.csv" else f"evaluation_output_{os.path.splitext(os.path.basename(path))[0]}.csv"
df.to_csv(out, index=False)
print(f"Saved row-level results to {out}")
