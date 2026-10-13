"""
app.py - Streamlit UI.  Run with:  streamlit run app.py
Tabs: Single IP | Batch CSV | Whitelist IP | Audit log
"""
import os
import time
import uuid
from pathlib import Path

import pandas as pd
import streamlit as st

import theme
import whitelist as wl
import whitelist_ui
from audit import log_classification, read_table, wl_list
from classifier import LABEL_TOR, LABEL_TUN, LABEL_UNK, LABEL_VPN, build_flow_dot, classify_ip, prepare_tunnel, prepare_vpn
from data_fetcher import (fetch_apple_relay, fetch_ip_atlas, fetch_ip_info, fetch_tor_exits, fetch_vpn_ranges,
                          load_asn_lists, load_tunnel_ranges, merge_tunnel_sources)
from theme import esc, mono, pill

st.set_page_config(page_title="IP Network-Type Classifier",
                   page_icon=str(Path(__file__).parent / "assets" / "favicon.png"), layout="wide")
theme.inject()


# ---- Cached API calls --------------------------------------------------------
# Why cache: Onionoo and IPinfo have rate limits, and reruns on every click would
# hammer them mid-demo. ttl=3600 -> refetch at most once per hour.
@st.cache_data(ttl=3600, show_spinner="Fetching Tor exit list...")
def cached_tor(force_mock):
    return fetch_tor_exits(force_mock)


@st.cache_data(ttl=3600, show_spinner="Fetching VPN range list...")
def cached_vpn(force_mock):
    return fetch_vpn_ranges(force_mock)


@st.cache_resource(ttl=3600, show_spinner="Fetching Apple Private Relay egress list (about 12 MB)...")
def cached_tunnel(force_mock):
    """Apple's list is ~270k ranges: fetch AND index once per hour (cache_resource keeps the object, no pickling)."""
    file_src, apple = load_tunnel_ranges(), fetch_apple_relay(force_mock)
    return file_src, apple, prepare_tunnel(merge_tunnel_sources(file_src, apple))


@st.cache_data(ttl=3600, show_spinner=False)
def cached_info(ip, token, force_mock):
    return fetch_ip_info(ip, token, force_mock)


@st.cache_data(ttl=3600, show_spinner=False)
def cached_atlas(ip, force_mock):
    return fetch_ip_atlas(ip, force_mock)


# ---- Sidebar -----------------------------------------------------------------
st.sidebar.header("Settings")
force_mock = st.sidebar.checkbox("Offline demo mode (use mock snapshot)", value=False,
                                 help="Tick this if the venue Wi-Fi is bad.")
token = st.sidebar.text_input("IPinfo Lite token", value=os.getenv("IPINFO_TOKEN", ""),
                              type="password", help="Free token from ipinfo.io. Without it, only mock IPs get ASN data.")

tor, lists = cached_tor(force_mock), load_asn_lists()
vpn = prepare_vpn(cached_vpn(force_mock))  # parse CIDRs once per run
tunnel_file, apple, tunnel = cached_tunnel(force_mock)


def _src_pill(s):
    if s["status"] == "live":
        return pill("neutral", "LIVE")
    if s["status"] == "static_file":
        return pill("mute", f'FILE, {len(s.get("data") or [])} RANGES')
    return pill("unlisted", s["status"].replace("_", " "))


st.sidebar.markdown("**Data sources**")
for s in (tor, vpn, apple, tunnel_file):
    st.sidebar.markdown(f'<div style="margin:.6rem 0 .1rem">{_src_pill(s)}</div>'
                        f'<div style="font-size:.9rem">{esc(s["source"])}</div>'
                        f'<div class="entry-meta">fetched {esc(s["fetched_at"])}</div>', unsafe_allow_html=True)


if apple["status"] != "live" and apple.get("error"):
    st.sidebar.markdown(f'<div class="entry-meta">Apple fetch error: {esc(apple["error"])[:300]}</div>',
                        unsafe_allow_html=True)
if tunnel.get("skipped_count"):
    st.sidebar.markdown(f'<div class="entry-meta">Tunnel ranges skipped: {tunnel["skipped_count"]} '
                        f'(malformed, too broad or non-public)</div>', unsafe_allow_html=True)


def run_one(ip, run_id=""):
    """Fetch info for one IP, classify, and write the audit log."""
    info = cached_info(ip.strip(), token, force_mock)
    atlas = cached_atlas(ip.strip(), force_mock)
    res = classify_ip(ip, tor, vpn, info, lists, atlas, tunnel)
    log_classification(res, run_id)  # every decision is logged, no exceptions
    return res


def evidence_df(res):
    df = pd.DataFrame(res["evidence"])
    if df.empty:
        return df
    return df.rename(columns={"source": "Source", "question": "Rule / question", "result": "Result",
                              "detail": "Detail", "data_status": "Data status",
                              "source_timestamp": "Source timestamp"})


def label_pill(res):
    if res["rule_fired"] == "INVALID":
        return pill("invalid", "INVALID")
    if res["label"] == LABEL_TOR:
        return pill("neutral", "TOR EXIT")
    if res["label"] == LABEL_VPN:
        return pill("neutral", "VPN/PROXY")
    if res["label"] == LABEL_TUN:
        return pill("neutral", "TUNNEL/RELAY")
    # Unknown is "no positive evidence", not a warning: neutral pill, says which kind of nothing it is.
    return pill("mute", "HOSTING ONLY" if res["rule_fired"] == "R4" else "NO EVIDENCE")


def kv(cells):
    inner = "".join(f'<div><div class="k">{k}</div><div class="v">{v}</div></div>' for k, v in cells)
    return f'<div class="kv">{inner}</div>'


# ---- Header: product left, status right ----------------------------------------
live_n = sum(s["status"] == "live" for s in (tor, vpn, apple))
wl_entries = wl_list()
st.markdown(
    '<div class="console"><div><h1>Evidence-Based IP Network-Type Classifier</h1>'
    '<p class="lede">Tor exit &middot; Hosted VPN/Proxy &middot; Tunnel/Relay &middot; Unknown. Every answer comes with its evidence.</p></div>'
    f'<div class="status">{pill("neutral" if live_n == 3 else "unlisted", f"{live_n}/3 sources live")}'
    f'{pill("mute", f"{sum(e["enabled"] for e in wl_entries)} whitelist ranges on")}</div></div>',
    unsafe_allow_html=True)

tab1, tab2, tab_wl, tab3 = st.tabs(["Single IP", "Batch CSV", "Whitelist IP", "Audit log"])

# ---- Tab 1: single IP ----------------------------------------------------------
with tab1:
    ip = st.text_input("IP address", placeholder="e.g. 8.8.8.8", key="single_ip")
    if st.button("Classify", type="primary") and ip:
        res = run_one(ip)
        st.markdown(kv([("Classification", label_pill(res)), ("Confidence", esc(res["confidence"])),
                        ("Rule fired", esc(res["rule_fired"]))]), unsafe_allow_html=True)
        st.markdown(f'<div class="note"><b>Why:</b> {esc(res["reason"])} &nbsp;|&nbsp; <b>ASN:</b> '
                    f'{mono(res["asn"] or "n/a")} {esc(res["as_name"])}</div>', unsafe_allow_html=True)
        if res["rule_fired"] != "INVALID":
            w = wl.check_ip(res["ip"], wl_entries)
            if w["state"] == "whitelisted":
                m = w["match"]
                wtxt = f'{pill("ok", "OK")} whitelisted by {mono(m["cidr"])} {esc(m["label"])}'
            else:
                wtxt = f'{pill("unlisted", "UNLISTED")} no enabled whitelist range contains {mono(res["ip"])}'
            st.markdown(f'<div class="note" role="status" aria-live="polite"><b>Whitelist:</b> {wtxt}</div>',
                        unsafe_allow_html=True)
        left, right = st.columns([7, 5], gap="large")
        with left:
            st.subheader("Evidence table")
            st.dataframe(evidence_df(res), hide_index=True)
        with right:
            st.subheader("Decision flow")
            st.graphviz_chart(build_flow_dot(res["path"]))

# ---- Tab 2: batch --------------------------------------------------------------
with tab2:
    st.write("Upload a CSV with a column named **ip**.")
    up = st.file_uploader("CSV file", type="csv")
    if up is not None and st.button("Classify batch", type="primary"):
        ips = pd.read_csv(up)["ip"].dropna().astype(str).tolist()[:100]  # cap protects rate limits
        run_id, rows = uuid.uuid4().hex[:8], []
        bar = st.progress(0.0)
        for i, one in enumerate(ips):
            r = run_one(one, run_id)
            if not force_mock:
                time.sleep(1.0)  # IP-Atlas free tier ~60 req/min: stay under it
            rows.append({"ip": r["ip"], "label": r["label"], "confidence": r["confidence"],
                         "rule_fired": r["rule_fired"], "reason": r["reason"],
                         "asn": r["asn"], "as_name": r["as_name"],
                         "evidence_summary": " | ".join(f"{e['question'].split(':')[0]}={e['result']}"
                                                        for e in r["evidence"])})
            bar.progress((i + 1) / len(ips))
        # session_state: the download button triggers a rerun that would otherwise erase results
        st.session_state["batch_df"] = pd.DataFrame(rows)
        st.session_state["run_id"] = run_id

    if "batch_df" in st.session_state:
        out = st.session_state["batch_df"]
        st.markdown(f'<div class="note" role="status" aria-live="polite">Run {mono(st.session_state["run_id"])}: '
                    f'{len(out)} IPs classified, coverage {(out["label"] != LABEL_UNK).mean():.0%} (non-Unknown)</div>',
                    unsafe_allow_html=True)
        st.dataframe(out, hide_index=True)
        st.bar_chart(out["label"].value_counts(), color="#8A93A0")
        st.download_button("Download classified CSV", out.to_csv(index=False),
                           "classified_ips.csv", "text/csv")

# ---- Tab 3: whitelist ------------------------------------------------------------
with tab_wl:
    whitelist_ui.render()

# ---- Tab 4: audit log ------------------------------------------------------------
with tab3:
    log = read_table("SELECT * FROM classifications ORDER BY id DESC LIMIT 200")
    st.dataframe(log, hide_index=True)
    if not log.empty:
        pick = st.number_input("Show evidence for classification id", min_value=1,
                               value=int(log["id"].iloc[0]), step=1)
        st.dataframe(read_table("SELECT source, question, result, detail, data_status, source_timestamp "
                                "FROM evidence WHERE classification_id = ?", (int(pick),)), hide_index=True)
