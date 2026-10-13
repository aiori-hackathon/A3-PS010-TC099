"""
theme.py - the "cyber-safe" visual system for Streamlit: palette tokens, CSS, status pills.

Colour rules (IEC 60073 style, one meaning each):
  green  #4ADE80  ALLOWED / whitelisted only
  amber  #F59E0B  UNLISTED (whitelist) / mock or fallback data / warnings
  muted  #8A93A0  classifier Unknown (no positive evidence): neutral, not a warning
  red    #EF4444  DENIED / invalid only
  ink    #E6EAF0  everything else (neutral)
"""
import html

BASE, SURFACE, HAIRLINE = "#0E1116", "#161A20", "#262C35"
INK, MUTED = "#E6EAF0", "#8A93A0"
OK, WARN, DENY = "#4ADE80", "#F59E0B", "#EF4444"

# 16x16 icons, 2px stroke, square caps, drawn for this project
_ICONS = {
    "ok": '<path d="M3 8.5 6.5 12 13 4"/>',
    "unlisted": '<path d="M8 3v6M8 12.5v.5"/>',
    "invalid": '<path d="M3.5 3.5l9 9M12.5 3.5l-9 9"/>',
    "neutral": '<path d="M4 4h8v8H4z"/>',
    "mute": '<path d="M3 8h10"/>',
}


def esc(x):
    return html.escape(str(x), quote=True)


def pill(kind, text):
    """Status pill: icon + text label, so state never relies on colour alone."""
    return (f'<span class="pill pill--{kind}"><svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">'
            f'{_ICONS.get(kind, _ICONS["neutral"])}</svg>{esc(text)}</span>')


def mono(x):
    return f'<span class="mono">{esc(x)}</span>'


_RULER = ("data:image/svg+xml;utf8,%3Csvg xmlns='http://www.w3.org/2000/svg' width='8' height='8'%3E"
          "%3Cpath d='M0.5 0v8' stroke='%23262C35'/%3E%3C/svg%3E")

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans+Condensed:wght@500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap');
:root{
  --base:#0E1116; --surface:#161A20; --hair:#262C35; --ink:#E6EAF0; --muted:#8A93A0;
  --ok:#4ADE80; --warn:#F59E0B; --deny:#EF4444;
  --sans:'IBM Plex Sans','Helvetica Neue',Arial,sans-serif;
  --disp:'IBM Plex Sans Condensed','IBM Plex Sans','Arial Narrow',Arial,sans-serif;
  --mono:'IBM Plex Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  --t:150ms ease-out;
}
html{scrollbar-color:var(--hair) var(--base);scrollbar-width:thin}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-track{background:var(--base)}
::-webkit-scrollbar-thumb{background:var(--hair);border:2px solid var(--base)}
::-webkit-scrollbar-thumb:hover{background:var(--muted)}

.stApp,.stApp p,.stApp li,.stApp label,.stApp input,.stApp textarea,.stApp button,.stApp [data-testid="stCaptionContainer"]{font-family:var(--sans)}
.stApp code,.stApp pre,.stApp [data-testid="stCode"] *,.mono{font-family:var(--mono)!important}
[data-testid="stAppViewContainer"] .block-container{max-width:1240px;padding:1.25rem 1.5rem 4rem}
#MainMenu,footer,[data-testid="stDecoration"],[data-testid="stToolbar"]{display:none!important}
[data-testid="stHeader"]{background:transparent}
[data-testid="stSidebar"]{background:var(--surface);border-right:1px solid var(--hair)}
[data-testid="stSidebar"] h2{font-family:var(--disp);font-weight:600;font-size:1.05rem;letter-spacing:.01em}

/* type tiers: display / body / mono-data */
h1,h2,h3{font-family:var(--disp)!important;font-weight:600!important;letter-spacing:0!important;color:var(--ink)}
h1{font-size:2.1rem!important;line-height:1.1!important;padding:0!important}
h2,h3{font-size:1.25rem!important}
.lede{color:var(--muted);max-width:62ch;margin:.35rem 0 0}
.mono{font-feature-settings:"zero" 1;font-variant-numeric:tabular-nums}
.muted{color:var(--muted)}

/* console header: product left, status right */
.console{display:flex;flex-wrap:wrap;gap:1rem 2rem;justify-content:space-between;align-items:flex-end;
  padding:0 0 1rem;border-bottom:1px solid var(--hair);margin-bottom:1.25rem}
.console .status{display:flex;flex-wrap:wrap;gap:.5rem;justify-content:flex-end;align-items:center;font:500 12px var(--mono);color:var(--muted)}
.ruler{height:8px;margin:.25rem 0 1rem;background:url("RULER") repeat-x;border-top:1px solid var(--hair)}

/* pills */
.pill{display:inline-flex;align-items:center;gap:6px;height:24px;padding:0 8px;border:1px solid currentColor;
  font:600 11px/1 var(--mono);letter-spacing:.08em;text-transform:uppercase;white-space:nowrap;transition:color var(--t),border-color var(--t),background var(--t)}
.pill svg{width:12px;height:12px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:square;stroke-linejoin:miter}
.pill--ok{color:var(--ok)} .pill--unlisted{color:var(--warn)} .pill--invalid{color:var(--deny)}
.pill--neutral{color:var(--ink)} .pill--mute{color:var(--muted)}

/* readouts (state panels) */
.readout{border:1px solid var(--hair);border-left:4px solid var(--muted);background:var(--surface);padding:.9rem 1rem;
  min-height:44px;animation:settle 150ms ease-out}
.readout--ok{border-left-color:var(--ok)} .readout--unlisted{border-left-color:var(--warn)} .readout--invalid{border-left-color:var(--deny)}
.readout .row{display:flex;flex-wrap:wrap;gap:.5rem .9rem;align-items:center}
.readout .big{font:600 1.25rem/1.2 var(--mono);overflow-wrap:anywhere}
.readout .state{font:600 .8rem var(--mono);letter-spacing:.08em;text-transform:uppercase}
.readout .detail{margin-top:.5rem;color:var(--muted);font-size:.9rem;overflow-wrap:anywhere}
.readout .detail .mono{color:var(--ink)}
@keyframes settle{from{opacity:.55;transform:translateY(2px)}to{opacity:1;transform:none}}

.kv{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));border:1px solid var(--hair);background:var(--surface)}
.kv>div{padding:.75rem 1rem;border-right:1px solid var(--hair);min-width:0}
.kv>div:last-child{border-right:0}
.kv .k{color:var(--muted);font-size:.8rem;margin-bottom:.35rem}
.kv .v{font:500 1rem var(--mono);overflow-wrap:anywhere}
.note{border:1px solid var(--hair);border-left:4px solid var(--muted);padding:.7rem 1rem;margin:.75rem 0;background:var(--surface);overflow-wrap:anywhere}
.reasons{margin:.5rem 0 0;padding:0;list-style:none}
.reasons li{padding:.35rem 0;border-top:1px solid var(--hair);font-size:.9rem;overflow-wrap:anywhere}
.reasons li .mono{color:var(--deny)}
.entry-meta{font:400 12px/1.5 var(--mono);color:var(--muted);overflow-wrap:anywhere}
.entry-meta b{display:block;font:500 14px var(--sans);color:var(--ink)}
hr.hair{border:0;border-top:1px solid var(--hair);margin:.35rem 0}

/* controls */
.stButton>button,[data-testid="stDownloadButton"]>button,[data-testid="stFormSubmitButton"]>button{
  min-height:44px;min-width:44px;border-radius:2px;border:1px solid var(--hair);background:var(--surface);color:var(--ink);
  font:500 13px var(--mono);letter-spacing:.04em;transition:border-color var(--t),background var(--t),color var(--t)}
.stButton>button:hover,[data-testid="stDownloadButton"]>button:hover,[data-testid="stFormSubmitButton"]>button:hover{border-color:var(--ink);background:var(--surface);color:var(--ink)}
.stButton>button:active{background:var(--hair)}
button[kind="primary"],button[data-testid="stBaseButton-primary"],button[data-testid="stBaseButton-primaryFormSubmit"]{
  background:var(--ink)!important;color:var(--base)!important;border-color:var(--ink)!important;font-weight:600}
button[kind="primary"]:hover,button[data-testid="stBaseButton-primary"]:hover,button[data-testid="stBaseButton-primaryFormSubmit"]:hover{background:#fff!important}
button:disabled{opacity:.45}
[data-baseweb="input"],[data-baseweb="textarea"],[data-baseweb="base-input"]{border-radius:2px!important;background:var(--surface)!important;border-color:var(--hair)!important;transition:border-color var(--t)}
[data-baseweb="input"] input,[data-baseweb="textarea"] textarea{min-height:44px}
.st-key-wl_check input,.st-key-wl_raw textarea,.st-key-single_ip input,[class*="st-key-e_cidr"] input{font-family:var(--mono)!important}
[data-testid="stTextInput"] label p,[data-testid="stTextArea"] label p,[data-testid="stFileUploader"] label p{font-size:.85rem;color:var(--muted)}
[data-baseweb="tab-list"]{border-bottom:1px solid var(--hair);gap:0}
[data-baseweb="tab"]{min-height:44px;font:500 13px var(--mono)!important;letter-spacing:.04em;padding:0 1.1rem}
[data-baseweb="tab-highlight"]{background:var(--ink)!important;height:3px!important}
[data-baseweb="tab-border"]{background:var(--hair)!important}
[data-testid="stToggle"] label{min-height:44px;align-items:center}
[data-testid="stToggle"] label p{font:500 12px var(--mono);letter-spacing:.06em}
[data-testid="stCode"]{border:1px solid var(--hair)}
[data-testid="stForm"]{border:1px solid var(--hair);border-radius:2px;background:transparent}
[data-testid="stFileUploaderDropzone"]{border-radius:2px;border:1px dashed var(--muted);background:var(--surface)}
[data-testid="stDataFrame"]{border:1px solid var(--hair)}

/* focus: visible, same everywhere */
:focus-visible{outline:2px solid var(--ink)!important;outline-offset:2px!important}
[data-baseweb="input"]:focus-within,[data-baseweb="textarea"]:focus-within{outline:2px solid var(--ink)!important;outline-offset:2px!important;border-color:var(--ink)!important}

@media (max-width:640px){
  [data-testid="stAppViewContainer"] .block-container{padding:1rem .9rem 3rem}
  h1{font-size:1.7rem!important}
  .kv{grid-template-columns:1fr}.kv>div{border-right:0;border-bottom:1px solid var(--hair)}.kv>div:last-child{border-bottom:0}
  .console .status{justify-content:flex-start}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
</style>
""".replace("RULER", _RULER)


def inject():
    import streamlit as st
    st.markdown(CSS, unsafe_allow_html=True)
