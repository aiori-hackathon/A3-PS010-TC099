"""
whitelist_ui.py - the Whitelist tab. All writes happen in callbacks (they run BEFORE the script reruns),
so the Check IP result and the list below always reflect the latest state.
Persistence: SQLite `whitelist` table in audit.db via audit.py (same pattern as the audit log).
"""
import datetime as dt

import streamlit as st

import audit
import whitelist as wl
from theme import esc, mono, pill


def _now():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---- callbacks ----------------------------------------------------------------------
def _cb_add():
    existing = {e["cidr"] for e in audit.wl_list()}
    ok, bad = wl.parse_bulk(st.session_state.get("wl_raw", ""), existing)
    label = st.session_state.get("wl_label", "").strip()[: wl.MAX_LABEL]
    ts = _now()
    for cidr in ok:
        audit.wl_add(cidr, label, ts)
    st.session_state["wl_feedback"] = {"added": len(ok), "rejected": bad}
    # keep rejected tokens in the box so they can be fixed in place
    st.session_state["wl_raw"] = "\n".join(t for t, _ in bad if t)
    if not bad:
        st.session_state["wl_label"] = ""


def _cb_import():
    f = st.session_state.get("wl_file")
    if f is None:
        st.session_state["wl_feedback"] = {"added": 0, "rejected": [("", "Choose a .json or .txt file first")]}
        return
    existing = {e["cidr"] for e in audit.wl_list()}
    ok, bad = wl.parse_import(f.getvalue().decode("utf-8", errors="replace"), existing)
    ts = _now()
    for item in ok:
        audit.wl_add(item["cidr"], item["label"], item["added_at"] or ts, item["enabled"])
    st.session_state["wl_feedback"] = {"added": len(ok), "rejected": bad}


def _cb_toggle(wid):
    audit.wl_update(wid, enabled=st.session_state[f"en_{wid}"])


def _cb_delete(wid):
    audit.wl_delete(wid)
    if st.session_state.get("wl_edit") == wid:
        st.session_state["wl_edit"] = None
    st.session_state["wl_feedback"] = {"added": 0, "rejected": [], "deleted": True}


def _cb_edit(wid, cidr, label):
    st.session_state["wl_edit"] = wid
    st.session_state["wl_edit_err"] = None
    st.session_state[f"e_cidr_{wid}"] = cidr
    st.session_state[f"e_label_{wid}"] = label


def _cb_cancel():
    st.session_state["wl_edit"] = None
    st.session_state["wl_edit_err"] = None


def _cb_save(wid):
    cidr, reason = wl.parse_entry(st.session_state.get(f"e_cidr_{wid}", ""))
    if not reason:
        clash = [e for e in audit.wl_list() if e["cidr"] == cidr and e["id"] != wid]
        if clash:
            reason = f"{cidr} is already listed"
    if reason:
        st.session_state["wl_edit_err"] = (wid, reason)
        return
    audit.wl_update(wid, cidr=cidr, label=st.session_state.get(f"e_label_{wid}", "").strip()[: wl.MAX_LABEL])
    st.session_state["wl_edit"] = None
    st.session_state["wl_edit_err"] = None


# ---- renderers ----------------------------------------------------------------------
def _big(ip):
    return f'<span class="mono big">{esc(ip)}</span>'


def check_html(res):
    """Check IP result. Always rendered inside a role=status / aria-live=polite region."""
    if res is None:
        return ('<div class="readout" role="status" aria-live="polite" aria-atomic="true">'
                '<span class="muted">Enter an IP address to check it against enabled ranges.</span></div>')
    st_ = res["state"]
    if st_ == "whitelisted":
        m = res["match"]
        lbl = f" &mdash; {esc(m['label'])}" if m["label"] else ""
        more = ""
        if res["others"]:
            more = (f'<div class="detail">Also inside {len(res["others"])} broader enabled range'
                    f'{"s" if len(res["others"]) > 1 else ""}: '
                    + ", ".join(mono(o["cidr"]) for o in res["others"][:4]) + "</div>")
        return (f'<div class="readout readout--ok" role="status" aria-live="polite" aria-atomic="true">'
                f'<div class="row">{pill("ok", "OK")}<span class="state">Whitelisted</span>{_big(res["ip"])}</div>'
                f'<div class="detail">Most specific match: {mono(m["cidr"])}{lbl}</div>{more}</div>')
    if st_ == "unlisted":
        return (f'<div class="readout readout--unlisted" role="status" aria-live="polite" aria-atomic="true">'
                f'<div class="row">{pill("unlisted", "UNLISTED")}<span class="state">Not whitelisted</span>'
                f'{_big(res["ip"])}</div>'
                f'<div class="detail">Valid address. No enabled range contains it.</div></div>')
    return (f'<div class="readout readout--invalid" role="status" aria-live="polite" aria-atomic="true">'
            f'<div class="row">{pill("invalid", "INVALID")}<span class="state">Invalid IP</span>'
            f'{_big(res["ip"])}</div>'
            f'<div class="detail">{esc(res["reason"])}</div></div>')


def feedback_html(fb):
    """Add / import outcome. Rejected entries are listed with their reason; nothing is dropped silently."""
    if not fb:
        return '<div role="status" aria-live="polite" aria-atomic="true"></div>'
    bad = fb.get("rejected", [])
    if fb.get("deleted") and not bad:
        head = "Entry deleted."
    else:
        head = f"{fb['added']} added. {len(bad)} rejected." if bad else f"{fb['added']} added."
    kind = "invalid" if bad else ("ok" if fb["added"] else "neutral")
    items = "".join(f'<li>{mono(t) if t else ""} {esc(r)}</li>' for t, r in bad)
    body = f'<ul class="reasons">{items}</ul>' if items else ""
    icon = pill(kind, "REJECTED" if bad else "ADDED" if fb["added"] else "DONE")
    return (f'<div class="readout readout--{kind}" role="status" aria-live="polite" aria-atomic="true">'
            f'<div class="row">{icon}<span>{head}</span></div>{body}</div>')


def render():
    entries = audit.wl_list()
    enabled_n = sum(e["enabled"] for e in entries)

    st.markdown("### Whitelist IP")
    st.markdown(f'<p class="lede">Trusted ranges. {len(entries)} listed, {enabled_n} enabled. '
                'Disabled ranges never match. Overlaps resolve to the most specific range.</p>',
                unsafe_allow_html=True)

    left, right = st.columns([5, 7], gap="large")

    # ---------------- left: check + add (sparse) ----------------
    with left:
        st.text_input("Check IP", key="wl_check", placeholder="e.g. 192.168.1.40 or 2001:db8::1")
        raw = st.session_state.get("wl_check", "")
        st.markdown(check_html(wl.check_ip(raw, entries) if raw.strip() else None), unsafe_allow_html=True)

        st.markdown('<div class="ruler"></div>', unsafe_allow_html=True)
        st.markdown("#### Add ranges")
        with st.form("wl_add_form", border=True):
            st.text_area("IPv4, IPv6 or CIDR. Comma or new line separated.", key="wl_raw", height=120,
                         placeholder="10.0.0.5\n192.168.1.0/24\n2001:db8::/32")
            st.text_input("Label (optional, applied to every entry added)", key="wl_label", max_chars=wl.MAX_LABEL,
                          placeholder="e.g. office egress")
            st.form_submit_button("Add to whitelist", type="primary", on_click=_cb_add, width="stretch")
        st.markdown(feedback_html(st.session_state.get("wl_feedback")), unsafe_allow_html=True)

        st.markdown('<div class="ruler"></div>', unsafe_allow_html=True)
        st.markdown("#### Import and export")
        st.file_uploader("Import .json (as exported) or .txt (one CIDR per line)", type=["json", "txt"],
                         key="wl_file")
        st.button("Import file", on_click=_cb_import, width="stretch")
        c1, c2 = st.columns(2)
        c1.download_button("Export JSON", wl.export_json(entries), "whitelist.json", "application/json",
                           disabled=not entries, width="stretch")
        c2.download_button("Export list", wl.export_lines(entries), "whitelist.txt", "text/plain",
                           disabled=not entries, width="stretch")

    # ---------------- right: entries (dense) ----------------
    with right:
        st.markdown("#### Entries")
        if not entries:
            st.markdown('<div class="note">No ranges listed. Every valid IP reports UNLISTED. '
                        'Add a range, or import a file.</div>', unsafe_allow_html=True)
        for e in entries:
            wid = e["id"]
            st.markdown('<hr class="hair">', unsafe_allow_html=True)
            if st.session_state.get("wl_edit") == wid:
                _edit_row(e)
                continue
            a, b, c, d, f = st.columns([4, 4, 2, 2, 2], vertical_alignment="center", gap="small")
            with a:
                st.code(e["cidr"], language=None)  # built-in copy-to-clipboard button
            with b:
                label = esc(e["label"]) if e["label"] else '<span class="muted">no label</span>'
                st.markdown(f'<div class="entry-meta"><b>{label}</b>{esc(e["added_at"])}</div>',
                            unsafe_allow_html=True)
            with c:
                st.toggle(f"Enabled: {e['cidr']}", value=e["enabled"], key=f"en_{wid}",
                          on_change=_cb_toggle, args=(wid,), label_visibility="collapsed",
                          help=f"Enable or disable {e['cidr']}")
            with d:
                st.button("Edit", key=f"ed_{wid}", on_click=_cb_edit, args=(wid, e["cidr"], e["label"]),
                          width="stretch", help=f"Edit {e['cidr']}")
            with f:
                st.button("Delete", key=f"del_{wid}", on_click=_cb_delete, args=(wid,),
                          width="stretch", help=f"Delete {e['cidr']}")


def _edit_row(e):
    wid = e["id"]
    st.text_input("CIDR", key=f"e_cidr_{wid}")
    st.text_input("Label", key=f"e_label_{wid}", max_chars=wl.MAX_LABEL)
    err = st.session_state.get("wl_edit_err")
    if err and err[0] == wid:
        st.markdown(f'<div class="readout readout--invalid" role="alert">{pill("invalid", "INVALID")} '
                    f'{esc(err[1])}</div>', unsafe_allow_html=True)
    s, c = st.columns(2)
    s.button("Save", key=f"sv_{wid}", type="primary", on_click=_cb_save, args=(wid,), width="stretch")
    c.button("Cancel", key=f"cn_{wid}", on_click=_cb_cancel, width="stretch")
