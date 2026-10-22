"""PermissionGuard AI — Streamlit dashboard.

Run:  .venv/bin/streamlit run app.py

All displayed values come from real scan results (or clearly labelled
synthetic demo fixtures). Nothing is hardcoded as if it were a scan.
"""
from __future__ import annotations

import glob
import hashlib
import io
import json as _json
import os
import sys
import tempfile
import traceback
from html import escape as _escape

import streamlit as st
import plotly.graph_objects as go

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.knowledgebase import load_knowledgebase
from src.models import AssessmentStatus, Finding, ScanResult, Severity
from src.mobsfevidence import build_evidence
from src.pandaspreload import preload_pandas
from src.pipeline import ScanError, run_scan, save_upload
from src.purposeanalyzer import infer_category, list_categories
from src.reportgenerator import to_csv, to_json, to_pdf
from src.safetips import tip_for
from src.scancache import ScanCache, sha256_bytes
from src.storage import ScanStore

# Load pandas once per process, before any st.dataframe call can trigger
# Streamlit's lazy (and thread-unsafe) import. See src/pandaspreload.py.
preload_pandas()

# ---------------------------------------------------------------------------
# page config & styles
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="PermGuard",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
<style>
    @import url("https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&display=swap");
    /* Hide Streamlit top header, 3 dots menu, status widget, and toolbar */
    #MainMenu { display: none !important; }
    header[data-testid="stHeader"] { display: none !important; height: 0 !important; visibility: hidden !important; }
    div[data-testid="stToolbar"] { display: none !important; }
    div[data-testid="stDecoration"] { display: none !important; }
    div[data-testid="stStatusWidget"] { display: none !important; }
    .stDeployButton { display: none !important; }

    /* Pin navbar directly to the absolute top of the screen */
    .block-container {
        padding-top: 0.2rem !important;
        padding-bottom: 2rem !important;
    }
    div[data-testid="stMetric"] {
        background: #ffffff; border: 1px solid #e0e0e0; border-radius: 8px;
        padding: 12px 16px; box-shadow: 0 1px 3px rgba(0,0,0,.06);
    }
    .pg-badge {
        display:inline-block; padding:4px 12px; border-radius:999px;
        font-weight:600; font-size:.82rem; color:#fff;
    }
    .pg-title { font-size:1.55rem; font-weight:700; color:#1A237E; margin:0; }
    .pg-sub { color:#546E7A; font-size:.9rem; margin:0 0 10px 0; }
    .pg-card {
        background:#fff; border:1px solid #e0e0e0; border-radius:8px;
        padding:14px 16px; margin-bottom:10px;
    }
    .pg-disc {
        background:#FFF8E1; border:1px solid #F9A825; border-radius:8px;
        padding:12px 14px; font-size:.83rem; color:#5D4037;
    }
    .pg-sev-CRITICAL { color:#B71C1C; font-weight:700; }
    .pg-sev-HIGH { color:#E65100; font-weight:700; }
    .pg-sev-MEDIUM { color:#F9A825; font-weight:700; }
    .pg-sev-LOW { color:#9E9D24; font-weight:700; }
    .pg-sev-INFO { color:#1565C0; font-weight:700; }
    div[data-testid="stExpander"] { background:#fff; border:1px solid #e8e8e8;
        border-radius:8px; }
</style>
""",
    unsafe_allow_html=True,
)



st.markdown(
    """
<style>
    /* ================= site shell: dark navbar + pages ================= */
    body:has(.pg-dark-site),
    body:has(.pg-dark-site) [data-testid="stAppViewContainer"],
    body:has(.pgnav-brand) {
        font-family: "IBM Plex Sans", "Segoe UI", sans-serif !important;
    }
    [data-testid="stLogo"],
    [data-testid="stHeader"] img,
    [data-testid="stHeader"] [data-testid="stDecoration"],
    [data-testid="stHeaderActionElements"] { display:none !important; }

    .pgnav-brand {
        display:flex; align-items:center; gap:.55rem; padding:.4rem 0;
        color:#f4f7fb; font-weight:700; font-size:1.05rem; letter-spacing:-.02em;
    }
    .pgnav-brand svg, .pgnav-brand img { display:none !important; }
    .pgnav-ver {
        font-size:.68rem; font-weight:600; letter-spacing:.02em;
        color:#7ee8d4; background:#123445; padding:.12rem .42rem;
        border-radius:.35rem;
    }
    .pgnav-link {
        display:block; text-align:center; color:#93a4b8; font-size:.84rem;
        font-weight:500; padding:.55rem .25rem; line-height:1.25rem;
    }
    .pgnav-link.pgnav-active { color:#fff; font-weight:600; }

    div[data-testid="stHorizontalBlock"]:has(.pgnav-brand) {
        background:#07111e;
        border:none; border-radius:0;
        padding:.35rem .4rem; align-items:center; gap:.2rem;
        margin-bottom:0;
        box-shadow:0 1px 0 #122033;
    }
    div[data-testid="stHorizontalBlock"]:has(.pgnav-brand) [data-testid="stButton"] button {
        background:transparent !important; border:none !important;
        box-shadow:none !important; color:#93a4b8 !important;
        font-size:.84rem !important; font-weight:500 !important;
        height:auto !important; min-height:0 !important;
        padding:.5rem .3rem !important; border-radius:.45rem !important;
        width:100%;
    }
    div[data-testid="stHorizontalBlock"]:has(.pgnav-brand) [data-testid="stButton"] button:hover {
        color:#fff !important; background:transparent !important;
    }
    div[data-testid="stHorizontalBlock"]:has(.pgnav-brand)
        > div[data-testid="stColumn"]:last-child [data-testid="stButton"] button {
        background:#1fd6b2 !important; color:#04231c !important; font-weight:700 !important;
        border-radius:.55rem !important; padding:.5rem 1.05rem !important;
        width:auto !important; margin-left:auto;
    }
    div[data-testid="stHorizontalBlock"]:has(.pgnav-brand)
        > div[data-testid="stColumn"]:last-child [data-testid="stButton"] button:hover {
        background:#3ee6c5 !important; box-shadow:none !important;
    }

    body:has(.pg-dark-site) { background:#07111e; }
    body:has(.pg-dark-site) [data-testid="stAppViewContainer"] {
        background:#07111e;
    }
    /* Sidebar stays collapsed by default; used only for optional MobSF settings. */
    body:has(.pg-dark-site) [data-testid="stSidebar"] {
        background:#0b1726 !important;
    }
    body:has(.pg-dark-site) [data-testid="stSidebar"] * { color:#d4d4d8; }
    body:has(.pg-dark-site) [data-testid="stCaptionContainer"],
    body:has(.pg-dark-site) [data-testid="stMarkdown"] p,
    body:has(.pg-dark-site) [data-testid="stMarkdown"] li,
    body:has(.pg-dark-site) [data-testid="stMarkdown"] h1,
    body:has(.pg-dark-site) [data-testid="stMarkdown"] h2,
    body:has(.pg-dark-site) [data-testid="stMarkdown"] h3,
    body:has(.pg-dark-site) [data-testid="stMarkdown"] a { color:#d4d4d8; }
    body:has(.pg-dark-site) [data-testid="stMarkdown"] a { color:#93c5fd; }

    div[data-testid="stHorizontalBlock"]:has(.pg-hero) { align-items:center; }
    div[data-testid="stHorizontalBlock"]:has(.pg-hero) [data-testid="stButton"] button {
        background:#1fd6b2 !important; color:#04231c !important; border:none !important;
        border-radius:.55rem !important; font-weight:700 !important;
        font-size:.875rem !important; padding:.65rem 1.2rem !important;
        height:auto !important; min-height:0 !important; width:auto !important;
        box-shadow:none !important;
    }
    div[data-testid="stHorizontalBlock"]:has(.pg-hero) [data-testid="stButton"] button:hover {
        background:#3ee6c5 !important; box-shadow:none !important;
    }
    div[data-testid="stHorizontalBlock"]:has(.pg-hero)
        div[data-testid="stHorizontalBlock"]
        > div[data-testid="stColumn"]:last-child [data-testid="stButton"] button {
        background:transparent !important; color:#c5d4e4 !important;
        border:none !important; font-weight:600 !important;
    }
    div[data-testid="stHorizontalBlock"]:has(.pg-hero)
        div[data-testid="stHorizontalBlock"]
        > div[data-testid="stColumn"]:last-child [data-testid="stButton"] button:hover {
        color:#fff !important; background:transparent !important;
    }

    /* stats row: "read more" = underlined text link */
    div[data-testid="stHorizontalBlock"]:has(.pg-stats-copy)
        [data-testid="stButton"] button {
        background:transparent !important; border:none !important; color:#fff !important;
        text-decoration:underline !important; text-underline-offset:4px !important;
        font-weight:500 !important; font-size:.9rem !important;
        height:auto !important; min-height:0 !important; padding:.3rem 0 !important;
        width:auto !important; box-shadow:none !important;
    }

    div[data-testid="stHorizontalBlock"]:has(.pg-cta-band)
        [data-testid="stButton"] button {
        background:#1fd6b2 !important; color:#04231c !important; border:none !important;
        border-radius:.55rem !important; font-weight:700 !important;
        font-size:.875rem !important; padding:.65rem 1.3rem !important;
        height:auto !important; min-height:0 !important; width:auto !important;
    }
    div[data-testid="stHorizontalBlock"]:has(.pg-cta-band)
        > div[data-testid="stColumn"]:last-child [data-testid="stButton"] button {
        background:transparent !important; color:#c5d4e4 !important;
        border:none !important;
    }
    div[data-testid="stHorizontalBlock"]:has(.pg-cta-band)
        > div[data-testid="stColumn"]:last-child [data-testid="stButton"] button:hover {
        color:#fff !important; background:transparent !important;
    }

    /* contact form inputs on dark */
    body:has(.pg-dark-site) [data-testid="stTextInput"] input,
    body:has(.pg-dark-site) [data-testid="stTextArea"] textarea {
        background:#171717 !important; border:1px solid #3f3f46 !important;
        color:#fafafa !important;
    }
    body:has(.pg-dark-site) [data-testid="stTextInput"] label,
    body:has(.pg-dark-site) [data-testid="stTextArea"] label,
    body:has(.pg-dark-site) [data-testid="stForm"] label { color:#a1a1aa !important; }
    body:has(.pg-dark-site) [data-testid="stForm"] [data-testid="stButton"] button {
        background:#1fd6b2 !important; color:#04231c !important; border:none !important;
        border-radius:.55rem !important; font-weight:700 !important; padding:.6rem 1.3rem !important;
        height:auto !important; min-height:0 !important; width:auto !important;
    }
    body:has(.pg-dark-site) a[data-testid="stLinkButton"] {
        background:#1fd6b2 !important; color:#04231c !important; border:none !important;
        border-radius:.55rem !important; font-weight:700 !important;
        padding:.65rem 1.3rem !important; display:inline-flex !important; width:auto !important;
    }

    .pg-eyebrow { font-size:.78rem; font-weight:600; color:#6ee7d2; margin:0; }
    .pg-h1 { font-size:clamp(2.05rem, 4.6vw, 3.55rem); font-weight:700; line-height:1.12;
             margin:.7rem 0 1rem; color:#f4f7fb; }
    .pg-h1 .pg-type {
        display:inline-block; max-width:0; overflow:hidden; white-space:nowrap;
        vertical-align:bottom; border-right:2px solid #1fd6b2;
    }
    .pg-h1 .pg-type-a {
        animation: pgType 2.1s steps(26,end) forwards, pgCaret .7s step-end 3,
                    pgHideCaret .01s 2.2s forwards;
    }
    .pg-h1 .pg-type-b {
        color:#1fd6b2;
        animation: pgType 2s steps(24,end) 2.15s forwards, pgCaret .7s step-end 2.15s 6,
                    pgHideCaret .01s 6.4s forwards;
    }
    @keyframes pgType { from { max-width:0 } to { max-width:100% } }
    @keyframes pgCaret { 50% { border-color:transparent } }
    @keyframes pgHideCaret { to { border-right-color:transparent } }
    .pg-h2 { font-size:clamp(1.45rem, 2.8vw, 2.15rem); font-weight:700; line-height:1.2;
             margin:.35rem 0 1.1rem; color:#f4f7fb; }
    .pg-lead { color:#9aafc4; font-size:1.02rem; line-height:1.65; max-width:34rem; }
    .pg-dark-card {
        background:#0c1a2b; border:1px solid #163049; border-radius:1rem;
        padding:1.15rem 1.2rem;
    }
    .pg-preview-head {
        display:flex; justify-content:space-between; align-items:center;
        margin-bottom:.85rem; font-size:.78rem; color:#8aa0b6;
    }
    .pg-find-row {
        display:flex; justify-content:space-between; gap:.8rem;
        padding:.7rem 0; color:#d5e0ec; font-size:.84rem;
    }
    .pg-find-row b { display:block; color:#f4f7fb; font-size:.82rem; letter-spacing:.02em; }
    .pg-find-row span { color:#8aa0b6; font-size:.78rem; }
    .pg-tag { font-size:.7rem; font-weight:700; padding:.18rem .5rem; border-radius:.35rem; }
    .pg-tag-red { color:#fda4a4; background:#3a1a22; }
    .pg-tag-amber { color:#fcd34d; background:#3a2d12; }
    .pg-tag-green { color:#6ee7b7; background:#123528; }
    .pg-preview-foot { color:#8aa0b6; font-size:.75rem; margin-top:.15rem; }
    .pg-mini { display:flex; gap:1rem; color:#8aa0b6; font-size:.82rem; margin:.9rem 0 0; }
    .pg-stat { text-align:left; background:#0c1a2b; border:1px solid #163049;
               border-radius:.9rem; padding:1rem 1.05rem; }
    .pg-stat b { display:block; font-size:1.85rem; font-weight:700; color:#f4f7fb;
                 line-height:1.1; }
    .pg-stat span { font-size:.8rem; color:#8aa0b6; }
    .pg-step { background:#0c1a2b; border:1px solid #163049; border-radius:.9rem;
               padding:1.15rem 1.1rem; }
    .pg-step em { font-style:normal; font-size:.78rem; font-weight:700; color:#6ee7d2; }
    .pg-step h4 { color:#f4f7fb; font-size:1rem; margin:.45rem 0 .4rem; }
    .pg-step p { color:#8aa0b6; font-size:.86rem; line-height:1.55; margin:0; }
    .pg-check { color:#c5d4e4; font-size:.88rem; font-weight:500; padding:.2rem 0; }
    .pg-foot { margin-top:2.2rem; padding-top:1.1rem;
               font-size:.78rem; color:#7b91a8; line-height:1.7; }
    .pg-contact-tile {
        background:#111113; border:1px solid #262626; border-radius:1rem;
        padding:1.1rem 1.2rem; margin-bottom:.8rem;
    }
    .pg-contact-tile b { color:#fafafa; font-size:.92rem; }
    .pg-contact-tile p { color:#a1a1aa; font-size:.85rem; margin:.35rem 0 0; }
    .pg-about-block h3 { color:#fafafa; font-size:1.05rem; margin:1.4rem 0 .5rem; }
    .pg-about-block p, .pg-about-block li { color:#a1a1aa; font-size:.92rem;
                                            line-height:1.7; }

    /* sticky navbar pinned to the very top */
    div[data-testid="stHorizontalBlock"]:has(.pgnav-brand) {
        position: sticky !important;
        top: 0 !important;
        z-index: 9999 !important;
        margin-top: 0 !important;
    }
    body:has(.pg-dark-site) .block-container { padding-top:0 !important; }
    body:has(.pg-dark-site) div[data-testid="stHorizontalBlock"]:has(.pgnav-brand) {
        border-radius:0; margin-bottom:1.25rem;
    }
    /* hamburger trigger = first column popover on the tool page */
    div[data-testid="stHorizontalBlock"]:has(.pgnav-brand)
        > div[data-testid="stColumn"]:first-child [data-testid="stPopover"] > button {
        background:transparent !important; border:none !important;
        box-shadow:none !important; color:#fafafa !important;
        font-size:1.25rem !important; font-weight:700 !important;
        height:auto !important; min-height:0 !important;
        width:auto !important; padding:.35rem .6rem !important;
        border-radius:.5rem !important; margin-right:auto;
    }
    div[data-testid="stHorizontalBlock"]:has(.pgnav-brand)
        > div[data-testid="stColumn"]:first-child [data-testid="stPopover"] > button:hover {
        background:rgba(255,255,255,.07) !important;
    }
    /* dropdown menu card (tool sections) */
    div[data-testid="stPopoverBody"] { min-width:15rem; }
    div[data-testid="stPopoverBody"] [data-testid="stButton"] button {
        background:transparent !important; border:none !important;
        box-shadow:none !important; color:#18181b !important;
        font-size:.88rem !important; font-weight:500 !important;
        height:auto !important; min-height:0 !important; width:100% !important;
        padding:.55rem .8rem !important; border-radius:.5rem !important;
        text-align:left !important; justify-content:flex-start !important;
    }
    div[data-testid="stPopoverBody"] [data-testid="stButton"] button:hover {
        background:#f4f4f5 !important;
    }
    div[data-testid="stPopoverBody"] button p {
        text-align:left !important; margin:0 !important;
    }
    .pg-menu-head { font-size:.72rem; font-weight:700; letter-spacing:.1em;
                    color:#71717a; padding:.2rem .8rem .5rem; }
    .pg-menu-active { font-size:.88rem; font-weight:700; color:#0a0a0a;
                      padding:.55rem .8rem; border-left:3px solid #4ade80;
                      background:#f4f4f5; border-radius:0 .5rem .5rem 0; }

    .pg-foot { margin-top:2.4rem; padding-top:1.5rem; }
    .pg-foot-brand { color:#f4f7fb; font-weight:700; font-size:1rem;
                     letter-spacing:-.01em; padding:.3rem 0; }
    .pg-foot-tag { color:#7b91a8; font-size:.82rem; margin:.2rem 0 0; }
    div[data-testid="stHorizontalBlock"]:has(.pg-foot-brand) { align-items:start; }
    div[data-testid="stHorizontalBlock"]:has(.pg-foot-brand)
        [data-testid="stButton"] button {
        background:transparent !important; border:none !important;
        box-shadow:none !important; color:#a1a1aa !important;
        font-size:.82rem !important; font-weight:500 !important;
        height:auto !important; min-height:0 !important;
        padding:.3rem 0 !important; width:auto !important;
    }
    div[data-testid="stHorizontalBlock"]:has(.pg-foot-brand)
        [data-testid="stButton"] button:hover { color:#fff !important; }
    .pg-foot-base { margin-top:1.1rem; padding-top:.2rem; font-size:.76rem; color:#6b8299;
                    line-height:1.7; }

    /* tool page polish (light theme) */
    .pg-title { font-size:1.55rem; font-weight:700; letter-spacing:-.01em;
                margin:0 0 .2rem 0; color:#1A237E; }
    div[data-testid="stMetric"] { border-top:3px solid #3949AB; border-radius:10px; }
    [data-testid="stBaseButton-primary"] {
        background:linear-gradient(to right,#1A237E,#3949AB) !important;
        border:none !important; border-radius:10px !important;
        font-weight:600 !important;
        box-shadow:0 6px 16px rgba(26,35,126,.25) !important;
    }
    [data-testid="stBaseButton-primary"]:hover { filter:brightness(1.12) !important; }
    button[data-testid="stBaseButton-secondary"] { border-radius:10px !important; }
    div[data-testid="stTabs"] button { font-weight:600 !important; }

    /* dropdown (expander) polish */
    div[data-testid="stExpander"] {
        border:1px solid #DDE2F2 !important; border-radius:12px !important;
        background:#fff !important;
        box-shadow:0 2px 8px rgba(26,35,126,.06) !important;
    }
    div[data-testid="stExpander"] summary {
        font-weight:700 !important; color:#1A237E !important;
        font-size:.92rem !important; padding:.3rem 0 !important;
    }
    div[data-testid="stExpander"] summary:hover { color:#3949AB !important; }

    /* demo APK dropdown keeps the highlighted indigo look */
    div[data-testid="stExpander"]:has(.pg-demo-marker) {
        border:1px solid #C5CAE9 !important;
        background:linear-gradient(to right,#EEF1FD,#F7F9FF) !important;
        box-shadow:0 2px 10px rgba(26,35,126,.10) !important;
    }
    div[data-testid="stExpander"]:has(.pg-demo-marker)
        [data-testid="stDownloadButton"] button {
        width:100% !important; justify-content:flex-start !important;
        text-align:left !important; border:1px solid #C5CAE9 !important;
        border-radius:10px !important; background:#fff !important;
        color:#1A237E !important; font-weight:600 !important;
        padding:.55rem .9rem !important; height:auto !important;
        min-height:0 !important;
        box-shadow:0 1px 4px rgba(26,35,126,.08) !important;
    }
    div[data-testid="stExpander"]:has(.pg-demo-marker)
        [data-testid="stDownloadButton"] button:hover {
        background:#EEF1FD !important; border-color:#3949AB !important;
    }
    div[data-testid="stExpander"]:has(.pg-demo-marker)
        [data-testid="stDownloadButton"] button::before {
        content:"↓  "; font-weight:800;
    }

    /* report download buttons (overview quick row + export tab) */
    div[data-testid="stDownloadButton"] button {
        border-radius:10px !important; border:1px solid #C5CAE9 !important;
        background:#fff !important; color:#1A237E !important;
        font-weight:600 !important;
    }
    div[data-testid="stDownloadButton"] button:hover {
        border-color:#3949AB !important; background:#EEF1FD !important;
    }

    /* overview hero — score at top, equal-height cards */
    .pg-ovhero { display:flex; gap:.9rem; flex-wrap:wrap; align-items:stretch;
                 margin:.2rem 0 .5rem; }
    .pg-ovcard {
        flex:1 1 165px;
        background:linear-gradient(160deg,#F8FAFF 0%,#EEF1FD 100%);
        border:1px solid #DDE2F2;
        border-radius:14px; padding:14px 16px; display:flex;
        flex-direction:column; justify-content:center;
        box-shadow:0 2px 8px rgba(26,35,126,.07);
        transition:all .2s ease;
    }
    .pg-scorecard {
        flex:1.7 1 235px; border:none; color:#fff;
        background:linear-gradient(135deg,#1A237E 0%,#3949AB 65%,#3F51B5 100%);
        box-shadow:0 8px 22px rgba(26,35,126,.28);
    }
    .pg-sc-top { display:flex; justify-content:space-between; align-items:center;
                 gap:.5rem; }
    .pg-sclabel { font-size:.66rem; letter-spacing:.1em; text-transform:uppercase;
                   font-weight:700; opacity:.9; }
    .pg-scnum { font-size:2.9rem; font-weight:800; line-height:1; margin:.45rem 0 .65rem; }
    .pg-scnum span { font-size:1rem; font-weight:600; opacity:.75; }
    .pg-scbar { height:9px; border-radius:999px; background:rgba(255,255,255,.22);
                overflow:hidden; }
    .pg-scfill { height:100%; border-radius:999px;
                 background:linear-gradient(to right,#FFD54F,#FF8A65,#E53935); }
    .pg-sczones { display:flex; justify-content:space-between; font-size:.62rem;
                  opacity:.78; margin-top:.35rem; letter-spacing:.05em;
                  text-transform:uppercase; }
    .pg-cnum { font-size:2rem; font-weight:800; color:#1A237E; line-height:1.1; }
    .pg-clabel { font-size:.78rem; color:#546E7A; margin-top:.2rem; line-height:1.35; }
    .pg-chiprow { display:flex; flex-wrap:wrap; gap:.3rem; margin-top:.55rem; }
    .pg-sevchip { font-size:.68rem; font-weight:700; padding:.18rem .55rem;
                  border-radius:999px; display:inline-flex; align-items:center; }
    .pg-ovmeta { flex:1.3 1 195px; font-size:.8rem; color:#546E7A; gap:.28rem;
                 word-break:break-word; }
    .pg-ovmeta b { color:#1A237E; font-size:.95rem; }
    .pg-ovmeta code { font-size:.72rem; color:#4255A4; background:#fff;
                      border:1px solid #DDE2F2;
                      padding:.1rem .4rem; border-radius:5px;
                      align-self:flex-start; }

    /* Dynamic Theme for Hero Row: risk score color + matching faded tint for other boxes */
    /* HIGH RISK: Crimson/Ruby gradient scorecard + subtle rose/red faded boxes */
    .pg-theme-high .pg-scorecard {
        background: linear-gradient(135deg, #9A3412 0%, #EA580C 60%, #F97316 100%) !important;
        box-shadow: 0 8px 24px rgba(234, 88, 12, 0.25) !important;
    }
    .pg-theme-high .pg-ovcard:not(.pg-scorecard) {
        background: linear-gradient(160deg, #FFFBEB 0%, #FEF3C7 100%) !important;
        border: 1px solid #FCD34D !important;
        box-shadow: 0 2px 10px rgba(234, 88, 12, 0.08) !important;
    }
    .pg-theme-high .pg-cnum { color: #9A3412 !important; }
    .pg-theme-high .pg-clabel { color: #9A3412 !important; font-weight: 500; }
    .pg-theme-high .pg-ovmeta b { color: #9A3412 !important; }
    .pg-theme-high .pg-ovmeta span { color: #9A3412 !important; }
    .pg-theme-high .pg-ovmeta code {
        background: #FEF2F2 !important; border-color: #FECACA !important; color: #9A3412 !important;
    }

    /* MEDIUM RISK: Amber/Orange gradient scorecard + subtle amber faded boxes */
    .pg-theme-medium .pg-scorecard {
        background: linear-gradient(135deg, #78350F 0%, #D97706 60%, #F59E0B 100%) !important;
        box-shadow: 0 8px 24px rgba(217, 119, 6, 0.35) !important;
    }
    .pg-theme-medium .pg-ovcard:not(.pg-scorecard) {
        background: linear-gradient(160deg, #FFFBEB 0%, #FEF3C7 100%) !important;
        border: 1px solid #FDE68A !important;
        box-shadow: 0 2px 10px rgba(217, 119, 6, 0.08) !important;
    }
    .pg-theme-medium .pg-cnum { color: #92400E !important; }
    .pg-theme-medium .pg-clabel { color: #78350F !important; font-weight: 500; }
    .pg-theme-medium .pg-ovmeta b { color: #78350F !important; }
    .pg-theme-medium .pg-ovmeta span { color: #78350F !important; }
    .pg-theme-medium .pg-ovmeta code {
        background: #FFFBEB !important; border-color: #FDE68A !important; color: #92400E !important;
    }

    /* LOW RISK: Emerald gradient scorecard + subtle green faded boxes */
    .pg-theme-low .pg-scorecard {
        background: linear-gradient(135deg, #064E3B 0%, #059669 60%, #10B981 100%) !important;
        box-shadow: 0 8px 24px rgba(5, 150, 105, 0.35) !important;
    }
    .pg-theme-low .pg-ovcard:not(.pg-scorecard) {
        background: linear-gradient(160deg, #ECFDF5 0%, #D1FAE5 100%) !important;
        border: 1px solid #A7F3D0 !important;
        box-shadow: 0 2px 10px rgba(5, 150, 105, 0.08) !important;
    }
    .pg-theme-low .pg-cnum { color: #065F46 !important; }
    .pg-theme-low .pg-clabel { color: #047857 !important; font-weight: 500; }
    .pg-theme-low .pg-ovmeta b { color: #047857 !important; }
    .pg-theme-low .pg-ovmeta span { color: #065F46 !important; }
    .pg-theme-low .pg-ovmeta code {
        background: #ECFDF5 !important; border-color: #A7F3D0 !important; color: #065F46 !important;
    }

    /* Enhanced "Why this score" container & contributor cards */
    .pg-why-container {
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 14px;
        padding: 18px 20px;
        margin: 1.2rem 0 1.5rem;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.04);
    }
    .pg-why-head {
        display: flex;
        justify-content: space-between;
        align-items: center;
        border-bottom: 1px solid #E2E8F0;
        padding-bottom: 0.8rem;
        margin-bottom: 1rem;
        flex-wrap: wrap;
        gap: 0.5rem;
    }
    .pg-why-title {
        font-size: 1.18rem;
        font-weight: 800;
        color: #0F172A;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    .pg-why-subtitle {
        font-size: 0.83rem;
        color: #64748B;
        margin-top: 0.15rem;
    }
    .pg-contrib-header {
        font-weight: 700;
        font-size: 0.88rem;
        color: #FFFFFF !important;
        background: #0F172A;
        padding: 5px 12px;
        border-radius: 6px;
        display: inline-block;
        margin-bottom: 0.65rem;
        letter-spacing: 0.02em;
    }
    .pg-contrib-card {
        background: #F8FAFC;
        border: 1px solid #E2E8F0;
        border-radius: 10px;
        padding: 10px 14px;
        margin-bottom: 0.55rem;
        display: flex;
        align-items: center;
        gap: 0.75rem;
        transition: transform 0.15s, box-shadow 0.15s;
    }
    .pg-contrib-card:hover {
        transform: translateY(-1px);
        box-shadow: 0 2px 8px rgba(0,0,0,0.06);
    }
    .pg-contrib-card .lbl {
        flex: 1;
        font-size: 0.84rem;
        font-weight: 600;
        color: #1E293B;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .pg-contrib-card .bar-wrap {
        flex: 0 0 24%;
        height: 8px;
        border-radius: 999px;
        background: #E2E8F0;
        overflow: hidden;
    }
    .pg-contrib-card .bar-fill {
        height: 100%;
        border-radius: 999px;
    }
    .pg-contrib-card .pts {
        flex: 0 0 4.2rem;
        text-align: right;
        font-size: 0.85rem;
        font-weight: 800;
        color: #0F172A;
    }
    .pg-why-summary-row {
        display: flex;
        gap: 0.75rem;
        flex-wrap: wrap;
        margin-top: 1rem;
        padding-top: 1rem;
        border-top: 1px dashed #CBD5E1;
    }
    .pg-why-metric-pill {
        background: #F1F5F9;
        border: 1px solid #CBD5E1;
        border-radius: 8px;
        padding: 0.5rem 0.85rem;
        font-size: 0.82rem;
        color: #1E293B;
        display: flex;
        align-items: center;
        gap: 0.4rem;
    }
    .pg-why-metric-pill b {
        color: #0F172A;
    }
    .pg-why-disclaimer {
        font-size: 0.81rem;
        color: #475569;
        line-height: 1.55;
        background: #F8FAFC;
        border-left: 3px solid #64748B;
        padding: 0.65rem 0.95rem;
        border-radius: 0 8px 8px 0;
        margin-top: 0.85rem;
    }

    /* Findings Dark-Header Dropdowns + White Readable Content */
    .pg-find-details {
        border-radius: 12px;
        margin: 0.75rem 0;
        overflow: hidden;
        box-shadow: 0 3px 12px rgba(15, 23, 42, 0.08);
        border: 1px solid #1E293B;
        background: #FFFFFF;
        transition: box-shadow 0.2s ease;
    }
    .pg-find-details:hover {
        box-shadow: 0 6px 18px rgba(15, 23, 42, 0.12);
    }
    .pg-find-summary {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 0.85rem 1.15rem;
        background: #0F172A; /* Sleek black/dark slate header */
        color: #F8FAFC;
        cursor: pointer;
        user-select: none;
        list-style: none;
        transition: background 0.2s, filter 0.2s;
        border-left: 6px solid #DC2626;
    }
    .pg-find-summary::-webkit-details-marker {
        display: none;
    }
    .pg-find-summary:hover {
        background: #1E293B;
    }
    .pg-find-summary .summary-left {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        flex: 1;
        min-width: 0;
    }
    .pg-find-summary .summary-title {
        font-weight: 700;
        font-size: 0.95rem;
        color: #F8FAFC;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .pg-find-summary .summary-right {
        display: flex;
        align-items: center;
        gap: 0.55rem;
        flex-shrink: 0;
    }
    .pg-find-summary .summary-rule {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 0.72rem;
        color: #94A3B8;
        background: rgba(255, 255, 255, 0.08);
        padding: 0.2rem 0.5rem;
        border-radius: 6px;
        border: 1px solid rgba(255, 255, 255, 0.12);
    }
    .pg-find-summary .summary-status {
        font-size: 0.7rem;
        font-weight: 700;
        color: #E2E8F0;
        background: #334155;
        padding: 0.2rem 0.55rem;
        border-radius: 999px;
    }
    .pg-find-summary .summary-chevron {
        color: #94A3B8;
        font-size: 0.75rem;
        transition: transform 0.25s ease;
        margin-left: 0.35rem;
    }
    .pg-find-details[open] > .pg-find-summary .summary-chevron {
        transform: rotate(180deg);
    }
    .pg-find-details[open] > .pg-find-summary {
        border-bottom: 1px solid #1E293B;
    }

    /* Inside Dropdown Body: Crisp, high-contrast readable white container */
    .pg-find-body {
        background: #FFFFFF !important;
        color: #0F172A !important;
        padding: 1.25rem 1.4rem;
        font-size: 0.92rem;
        line-height: 1.6;
    }
    .pg-find-desc {
        font-size: 0.93rem;
        color: #1E293B;
        line-height: 1.65;
        margin-bottom: 0.95rem;
        white-space: pre-line;
    }
    .pg-find-box {
        border-radius: 9px;
        padding: 0.85rem 1.1rem;
        margin-bottom: 0.85rem;
        font-size: 0.88rem;
    }
    .pg-box-investigate {
        background: #EFF6FF;
        border: 1px solid #BFDBFE;
        border-left: 4px solid #2563EB;
        color: #1E3A8A;
    }
    .pg-box-investigate b {
        color: #1E40AF;
    }
    .pg-box-perms {
        background: #F8FAFC;
        border: 1px solid #E2E8F0;
    }
    .pg-box-perms-title {
        font-weight: 700;
        font-size: 0.78rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #475569;
        margin-bottom: 0.45rem;
    }
    .pg-perm-badge {
        display: inline-block;
        background: #FFFFFF;
        border: 1px solid #CBD5E1;
        color: #0F172A;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 0.78rem;
        font-weight: 600;
        padding: 0.2rem 0.55rem;
        border-radius: 6px;
        margin: 0.2rem 0.35rem 0.2rem 0;
        box-shadow: 0 1px 2px rgba(0,0,0,0.03);
    }
    .pg-box-evidence {
        background: #F8FAFC;
        border: 1px solid #E2E8F0;
        border-left: 4px solid #64748B;
        color: #0F172A;
    }
    .pg-box-evidence b {
        color: #334155;
    }
    .pg-box-evidence code {
        display: block;
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 6px;
        padding: 0.5rem 0.75rem;
        font-size: 0.82rem;
        color: #0F172A;
        margin-top: 0.4rem;
        white-space: pre-wrap;
        word-break: break-all;
    }
    .pg-box-action {
        background: #F0FDF4;
        border: 1px solid #BBF7D0;
        border-left: 4px solid #16A34A;
        color: #14532D;
    }
    .pg-box-action b {
        color: #166534;
    }
    .pg-action-subitem {
        background: #FFFFFF;
        border: 1px solid #DCFCE7;
        border-radius: 6px;
        padding: 0.5rem 0.75rem;
        margin-top: 0.5rem;
        font-size: 0.83rem;
    }
    .pg-justifier-pill {
        display: inline-flex;
        align-items: center;
        background: #DCFCE7;
        border: 1px solid #86EFAC;
        color: #166534;
        font-size: 0.78rem;
        font-weight: 600;
        padding: 0.2rem 0.55rem;
        border-radius: 6px;
    }
    .pg-resolve-pill {
        display: inline-flex;
        align-items: center;
        background: #FEF9C3;
        border: 1px solid #FDE047;
        color: #854D0E;
        font-size: 0.78rem;
        font-weight: 600;
        padding: 0.2rem 0.55rem;
        border-radius: 6px;
    }
    .pg-box-limitation {
        background: #FFFBEB;
        border: 1px solid #FDE68A;
        border-left: 4px solid #D97706;
        color: #78350F;
        font-size: 0.83rem;
    }
    .pg-find-footer {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 0.6rem;
        flex-wrap: wrap;
        border-top: 1px dashed #E2E8F0;
        padding-top: 0.75rem;
        margin-top: 0.5rem;
        font-size: 0.78rem;
        color: #64748B;
    }
</style>
""",
    unsafe_allow_html=True,
)

# Shared PermGuard dark design tokens. These overrides also cover Streamlit's
# native widgets used by the real analyzer and report workflow below.
st.markdown("""
<style>
:root { color-scheme: dark; }
html { scroll-behavior: smooth; scroll-padding-top: 5.5rem; }
body:has(.pg-dark-site), body:has(.pg-dark-site) [data-testid="stAppViewContainer"] { background:#08090c !important; color:#f4f6fa !important; }
body:has(.pg-dark-site) .block-container { max-width:1200px; padding:0 2rem 3rem !important; }
body:has(.pg-dark-site) [data-testid="stMarkdown"] p, body:has(.pg-dark-site) [data-testid="stMarkdown"] li,
body:has(.pg-dark-site) [data-testid="stMarkdown"] h1, body:has(.pg-dark-site) [data-testid="stMarkdown"] h2,
body:has(.pg-dark-site) [data-testid="stMarkdown"] h3, body:has(.pg-dark-site) [data-testid="stCaptionContainer"] { color:#d5d9e2; }
body:has(.pg-dark-site) [data-testid="stTextInput"] input, body:has(.pg-dark-site) [data-testid="stTextArea"] textarea,
body:has(.pg-dark-site) [data-testid="stSelectbox"] [data-baseweb="select"] > div,
body:has(.pg-dark-site) [data-testid="stFileUploader"] section { background:#101319 !important; color:#f4f6fa !important; border-color:#292e39 !important; }
body:has(.pg-dark-site) [data-testid="stMetric"], body:has(.pg-dark-site) [data-testid="stExpander"],
body:has(.pg-dark-site) [data-testid="stForm"], body:has(.pg-dark-site) [data-testid="stTabs"] [data-baseweb="tab-panel"] { background:#101319 !important; border:1px solid #252a34 !important; color:#f4f6fa !important; border-radius:12px; }
body:has(.pg-dark-site) [data-testid="stBaseButton-primary"], body:has(.pg-dark-site) [data-testid="stFormSubmitButton"] button { background:#58a6ff !important; color:#07111e !important; border:0 !important; border-radius:8px !important; }
body:has(.pg-dark-site) [data-testid="stBaseButton-secondary"], body:has(.pg-dark-site) [data-testid="stDownloadButton"] button { background:#151922 !important; color:#dce3ef !important; border:1px solid #303644 !important; border-radius:8px !important; }
.pg-dark-site { position:fixed; inset:0; z-index:-2; pointer-events:none; background:#08090c; }
.pg-stars { position:fixed; inset:0; z-index:-1; pointer-events:none; opacity:.48; background-image:radial-gradient(1px 1px at 8% 17%,#dceaff 48%,transparent 100%),radial-gradient(1px 1px at 36% 61%,#91bfff 48%,transparent 100%),radial-gradient(1.3px 1.3px at 73% 29%,#fff 48%,transparent 100%),radial-gradient(1px 1px at 89% 77%,#aacaff 48%,transparent 100%),radial-gradient(1px 1px at 56% 88%,#dceaff 48%,transparent 100%); background-size:230px 210px,310px 290px,390px 350px,270px 260px,340px 310px; animation:pgTwinkle 8s ease-in-out infinite alternate; }
@keyframes pgTwinkle { to { opacity:.65; } }
@media(prefers-reduced-motion:reduce) { html{scroll-behavior:auto} .pg-stars{animation:none} *{transition:none!important;animation-duration:.01ms!important;animation-iteration-count:1!important} }
/* page-wide grid background (static, CSS-only) */
.pg-dark-site { --grid-size:48px; --grid-line:rgba(143,176,212,0.18); --grid-glow:rgba(143,176,212,0.14); overflow:hidden; }
body:has(.pg-dark-site) .stApp, body:has(.pg-dark-site) [data-testid="stAppViewContainer"], body:has(.pg-dark-site) [data-testid="stMain"] { background:transparent !important; }
body:has(.pg-dark-site) { background:#08090c !important; }
.pg-dark-site::before { content:""; position:absolute; inset:0; pointer-events:none;
  background-image:linear-gradient(to right,var(--grid-line) 1px,transparent 1px),linear-gradient(to bottom,var(--grid-line) 1px,transparent 1px);
  background-size:var(--grid-size) var(--grid-size);
  -webkit-mask-image:radial-gradient(ellipse 90% 90% at 50% 40%,#000 35%,transparent 100%);
  mask-image:radial-gradient(ellipse 90% 90% at 50% 40%,#000 35%,transparent 100%); }
.pg-dark-site::after { content:""; position:absolute; inset:0; z-index:-1; pointer-events:none;
  background:radial-gradient(ellipse 50% 50% at 50% 30%,var(--grid-glow) 0%,transparent 70%); }

.pg-nav { position:sticky; top:0; z-index:9999; display:flex; align-items:center; justify-content:space-between; gap:1rem; margin:0 -2rem 4rem; padding:.8rem 2rem; background:rgba(8,9,12,.88); backdrop-filter:blur(16px); border-bottom:1px solid #242832; }
.pg-nav a { color:#aeb5c2 !important; text-decoration:none; padding:.55rem .65rem; font-size:.95rem; }
.pg-nav a:hover,.pg-nav a:focus-visible { color:#75b7ff !important; }
.pg-brand { color:#f4f6fa !important; font-size:1.1rem; font-weight:700; letter-spacing:-.03em; }
.pg-nav .pg-nav-cta { color:#07111e !important; background:#58a6ff; border-radius:7px; font-weight:650; padding:.6rem .9rem; }
.pg-section { scroll-margin-top:5.5rem; padding:3.4rem 0; border-bottom:1px solid rgba(255,255,255,.07); }
.pg-hero-section { min-height:390px; display:flex; align-items:center; padding-top:0; }
.pg-eyebrow { color:#78baff !important; font-size:.78rem; font-weight:700; letter-spacing:.13em; }
.pg-h1 { color:#f4f6fa !important; font-size:clamp(2.8rem,6vw,5rem); line-height:1.02; letter-spacing:-.055em; max-width:850px; margin:.8rem 0 1.2rem; }
.pg-lead { color:#a6adba !important; font-size:1.1rem; line-height:1.65; max-width:650px; }
.pg-trust { display:flex; gap:1.5rem; flex-wrap:wrap; color:#aeb5c2; font-size:.86rem; margin-top:2rem; }
.pg-trust span:before { content:'•'; color:#78baff; margin-right:.5rem; }
.pg-section h2 { color:#f4f6fa !important; font-size:clamp(1.8rem,3.4vw,2.7rem); letter-spacing:-.035em; }
.pg-h1 { animation:pgHeadlineReveal .9s cubic-bezier(.2,.7,.25,1) both; }
@keyframes pgHeadlineReveal { from { opacity:0; transform:translateY(12px); clip-path:inset(0 0 35% 0); } to { opacity:1; transform:translateY(0); clip-path:inset(0); } }
.pg-step { height:100%; background:#101319; border:1px solid #252a34; border-radius:12px; padding:1.3rem; transition:transform .18s,border-color .18s; }
.pg-step:hover { transform:translateY(-3px); border-color:#40536c; }
.pg-step em { color:#78baff; font-style:normal; font-weight:700; font-size:.8rem; }
.pg-step h4 { color:#f4f6fa; margin:.7rem 0 .45rem; }
.pg-step p,.pg-principle { color:#a6adba; line-height:1.6; }
@media(max-width:700px){ body:has(.pg-dark-site) .block-container{padding:0 1rem 2rem!important}.pg-nav{margin:0 -1rem 2.4rem;padding:.75rem 1rem;flex-wrap:wrap}.pg-nav .pg-links{order:3;width:100%;display:flex;overflow:auto}.pg-nav .pg-links a{white-space:nowrap;font-size:.83rem}.pg-hero-section{min-height:340px}.pg-section{padding:2.2rem 0} }
/* navbar: fixed at very top, translucent; hero fills the full screen */
.pg-nav { position:fixed !important; top:0; left:0; right:0; margin:0 !important; z-index:9999; padding:.8rem max(2rem,calc((100vw - 1200px)/2 + 2rem)); background:rgba(8,9,12,.45) !important; -webkit-backdrop-filter:blur(14px); backdrop-filter:blur(14px); border-bottom:1px solid rgba(143,176,212,.14); }
.pg-hero-section { min-height:100vh !important; min-height:100svh !important; box-sizing:border-box; padding:6rem 0 3rem !important; align-items:center; }
.pg-hero-section > div { width:100%; }
/* each block = its own full-screen frame */
.pg-frame { min-height:100vh; min-height:100svh; display:flex !important; align-items:center; justify-content:center; padding:6rem 0 3rem !important; box-sizing:border-box; border-bottom:none; }
.pg-frame > div { width:100%; display:flex; flex-direction:column; align-items:center; }
.pg-frame-contact { min-height:auto; padding-bottom:1rem !important; }
.pg-frame-footer { min-height:60vh; }
.pg-steps { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:1.2rem; width:100%; max-width:960px; margin-top:2.2rem; }
@media(max-width:700px){ .pg-steps{grid-template-columns:1fr} }
.pg-hero-section { padding-bottom:9rem !important; }
/* centre-aligned content across all sections */
.pg-section, .pg-hero-section, .pg-hero-section > div { width:100%; max-width:100%; margin-left:auto; margin-right:auto; box-sizing:border-box; text-align:center; }
.pg-hero-section { display:flex !important; flex-direction:column; align-items:center !important; justify-content:center !important; }
.pg-hero-section > div { display:flex; flex-direction:column; align-items:center; justify-content:center; }
.pg-h1 { max-width:900px; } .pg-lead { max-width:560px; }
body:has(.pg-dark-site) [data-testid="stMarkdown"], body:has(.pg-dark-site) [data-testid="stMarkdown"] > div { width:100% !important; text-align:center; }
body:has(.pg-dark-site) [data-testid="stForm"] { max-width:640px; margin:0 auto; }
.pg-hero-section { justify-content:center; text-align:center; }
.pg-hero-section > div { display:flex; flex-direction:column; align-items:center; }
.pg-h1, .pg-lead { margin-left:auto !important; margin-right:auto !important; text-align:center; }
.pg-section { text-align:center; }
.pg-step { text-align:center; }
body:has(.pg-dark-site) .pg-lead, body:has(.pg-dark-site) .pg-principle, body:has(.pg-dark-site) .pg-sub, body:has(.pg-dark-site) .pg-title, body:has(.pg-dark-site) .pg-eyebrow, body:has(.pg-dark-site) [data-testid="stMarkdown"] h2 { text-align:center !important; margin-left:auto; margin-right:auto; }
@media(max-width:700px){ .pg-nav{padding:.75rem 1rem !important} .pg-hero-section{padding:8rem 0 2rem !important} }
body:has(.pg-dark-site) .pg-ovcard:not(.pg-scorecard), body:has(.pg-dark-site) .pg-why-container,
body:has(.pg-dark-site) .pg-contrib-card, body:has(.pg-dark-site) .pg-find-details,
body:has(.pg-dark-site) .pg-why-disclaimer,
body:has(.pg-dark-site) .pg-why-metric-pill { background:#101319 !important; color:#d5d9e2 !important; border-color:#292e39 !important; box-shadow:none !important; }
body:has(.pg-dark-site) .pg-ovcard:not(.pg-scorecard) *, 
body:has(.pg-dark-site) .pg-why-container *, body:has(.pg-dark-site) .pg-contrib-card * { color:#d5d9e2 !important; }
body:has(.pg-dark-site) .pg-find-summary { background:#151922 !important; color:#f4f6fa !important; }

body:has(.pg-dark-site) [data-testid="stMetric"] label, body:has(.pg-dark-site) [data-testid="stMetric"] [data-testid="stMetricValue"] { color:#f4f6fa !important; }
body:has(.pg-dark-site) [data-testid="stTabs"] button { color:#c5ccda !important; }
body:has(.pg-dark-site) [data-testid="stTabs"] button[aria-selected="true"] { color:#78baff !important; }

/* Analyze Card Component */
.pg-card-wrapper { max-width: 680px; margin: 0 auto 0.4rem; text-align: left; }
.pg-card-topbar { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.35rem; }
.pg-card-eyebrow { color: #8fb0d4 !important; font-size: 0.76rem !important; font-weight: 700 !important; letter-spacing: 0.12em !important; text-transform: uppercase !important; }
.pg-local-badge { display: inline-flex; align-items: center; gap: 0.4rem; padding: 4px 11px; border-radius: 999px; background: rgba(22, 33, 54, 0.7); border: 1px solid #233553; font-size: 0.78rem; color: #a5bada; font-weight: 500; }
.pg-card-title { color: #ffffff !important; font-size: 1.85rem !important; font-weight: 700 !important; letter-spacing: -0.025em !important; margin: 0.2rem 0 1.2rem 0 !important; line-height: 1.2 !important; text-align: left !important; }

div[data-testid="stVerticalBlock"]:has(.pg-analyze-marker),
div[data-testid="stVerticalBlockBorderWrapper"]:has(.pg-analyze-marker),
.st-emotion-cache-1ndxyp5,
.stVerticalBlock.e1a2occc3 {
  max-width: 680px !important;
  margin-left: auto !important;
  margin-right: auto !important;
  background: transparent !important;
  border: none !important;
  border-radius: 0 !important;
  box-shadow: none !important;
  padding: 0 !important;
  text-align: left !important;
}

div:has(.pg-analyze-marker) [data-testid="stFileUploader"] { margin-bottom: 0.6rem !important; }
div:has(.pg-analyze-marker) [data-testid="stFileUploader"] section {
  background: #090e1a !important;
  border: 1.5px dashed #233148 !important;
  border-radius: 12px !important;
  padding: 1.8rem 1.2rem !important;
  text-align: center !important;
  transition: border-color .2s, background .2s !important;
}
div:has(.pg-analyze-marker) [data-testid="stFileUploader"] section:hover {
  border-color: #486692 !important;
  background: #0c1424 !important;
}
div:has(.pg-analyze-marker) [data-testid="stFileUploader"] section [data-testid="stBaseButton-secondary"] {
  background: #152238 !important;
  border: 1px solid #2a3c5a !important;
  color: #c9d8ea !important;
  border-radius: 8px !important;
  font-size: 0.85rem !important;
  padding: 0.4rem 1rem !important;
}

.pg-drop-prompt { text-align: center; margin-bottom: -10px; }
.pg-drop-icon { width: 44px; height: 44px; background: #141f33; border-radius: 10px; display: inline-flex; align-items: center; justify-content: center; margin-bottom: 8px; }
.pg-drop-title { color: #ffffff; font-size: 1.15rem; font-weight: 700; margin-bottom: 2px; }
.pg-drop-sub { color: #6c7f9b; font-size: 0.82rem; margin-bottom: 12px; }

.pg-field-label { display: flex; align-items: center; gap: 0.4rem; color: #e2eaf5; font-size: 0.88rem; font-weight: 600; margin-bottom: 0.35rem; text-align: left; }
.pg-info-icon { display: inline-flex; align-items: center; justify-content: center; width: 14px; height: 14px; border-radius: 50%; background: #1c2b44; color: #8fb0d4; font-size: 0.65rem; font-weight: 700; cursor: help; }
.pg-field-help { color: #6a7e9b; font-size: 0.76rem; margin-top: 0.28rem; margin-bottom: 0.65rem; line-height: 1.4; text-align: left; }

div:has(.pg-analyze-marker) [data-testid="stSelectbox"] [data-baseweb="select"] > div {
  background: #090e1a !important;
  border: 1px solid #1c283d !important;
  border-radius: 8px !important;
  color: #dbe4ef !important;
  font-size: 0.95rem !important;
  min-height: 44px !important;
}
div:has(.pg-analyze-marker) [data-testid="stSelectbox"] [data-baseweb="select"] > div:hover {
  border-color: #3b5072 !important;
}
div:has(.pg-analyze-marker) [data-testid="stSelectbox"] label { display: none !important; }

div:has(.pg-analyze-marker) [data-testid="stExpander"] {
  background: #090e1a !important;
  border: 1px solid #1c283d !important;
  border-radius: 10px !important;
  margin: 0.6rem 0 1.2rem 0 !important;
  overflow: hidden !important;
}
div:has(.pg-analyze-marker) [data-testid="stExpander"] summary {
  color: #d5dfed !important;
  font-weight: 600 !important;
  font-size: 0.94rem !important;
  padding: 0.75rem 1rem !important;
}
div:has(.pg-analyze-marker) [data-testid="stExpander"] summary:hover { color: #ffffff !important; }
div:has(.pg-analyze-marker) [data-testid="stExpander"] [data-testid="stExpanderDetails"] {
  background: #070c16 !important;
  padding: 1.1rem !important;
  border-top: 1px solid #162033 !important;
}

div:has(.pg-analyze-marker) [data-testid="stBaseButton-primary"] {
  background: linear-gradient(135deg, #a4c4e8 0%, #82a8d1 100%) !important;
  color: #08101e !important;
  font-weight: 700 !important;
  font-size: 1.05rem !important;
  padding: 0.85rem 1.5rem !important;
  border-radius: 10px !important;
  border: none !important;
  box-shadow: 0 4px 18px rgba(130, 168, 209, 0.28) !important;
  transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
  margin-top: 0.4rem !important;
}
div:has(.pg-analyze-marker) [data-testid="stBaseButton-primary"]:hover {
  background: linear-gradient(135deg, #b9d5f5 0%, #90b3db 100%) !important;
  box-shadow: 0 6px 24px rgba(143, 176, 212, 0.45) !important;
  transform: translateY(-1px) !important;
}

.pg-samples-title { font-size: 0.78rem; color: #71849e; font-weight: 500; text-align: left; margin: 0.2rem 0 0.4rem; }
div:has(.pg-analyze-marker) [data-testid="stBaseButton-secondary"] {
  background: #111a2b !important;
  border: 1px solid #202d44 !important;
  color: #b5c7db !important;
  font-size: 0.78rem !important;
  padding: 0.25rem 0.5rem !important;
  border-radius: 6px !important;
}
div:has(.pg-analyze-marker) [data-testid="stBaseButton-secondary"]:hover {
  border-color: #40577a !important;
  color: #ffffff !important;
}
.pg-sample-active-chip {
  background: rgba(143, 176, 212, 0.12);
  border: 1px solid rgba(143, 176, 212, 0.3);
  color: #a4c4e8;
  border-radius: 6px;
  padding: 6px 12px;
  font-size: 0.8rem;
  margin: 0.3rem 0 0.8rem 0;
  text-align: left;
}
.pg-active-policy-chip {
  background: rgba(82, 196, 26, 0.1);
  border: 1px solid rgba(82, 196, 26, 0.25);
  color: #79d651;
  border-radius: 6px;
  padding: 6px 12px;
  font-size: 0.8rem;
  margin-top: 0.6rem;
  text-align: left;
}
    .pg-policy-desc {
  font-size: 0.8rem;
  color: #8da0b8;
  margin-bottom: 0.8rem;
  text-align: left;
}
.pg-optional-badge {
  display:inline-block; padding:3px 10px; border-radius:999px;
  font-size:.72rem; font-weight:700; letter-spacing:.02em;
  background:#123445; color:#7ee8d4; border:1px solid #1fd6b2;
}
.pg-agree-both { color:#43A047; font-weight:700; }
.pg-agree-pg { color:#E65100; font-weight:700; }
.pg-agree-mf { color:#1565C0; font-weight:700; }
</style>
""", unsafe_allow_html=True)

_SEV_HEX = {
    "CRITICAL": "#B71C1C", "HIGH": "#E65100", "MEDIUM": "#F9A825",
    "LOW": "#FDD835", "INFO": "#90CAF9",
}
_LEVEL_HEX = {"HIGH": "#EA580C", "MEDIUM": "#F9A825", "LOW": "#43A047"}
_STATUS_LABEL = {
    "PASS": "Passed",
    "POTENTIAL_CONCERN": "Action Needed",
    "NEEDS_REVIEW": "Needs Review",
    "INSUFFICIENT_EVIDENCE": "Needs Check",
    "NOT_APPLICABLE": "Not Applicable",
    "FAIL": "Policy Violation",
}
_DISCLAIMER = st.session_state.get("disclaimer", "") or (
    "This report is an automated, evidence-based assessment. It is not an "
    "official Google Play compliance determination, an OWASP certification, "
    "or proof that an application is malicious. Manifest analysis alone "
    "cannot establish actual runtime behaviour."
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
@st.cache_resource(show_spinner=False)
def _kb():
    return load_knowledgebase()


@st.cache_resource(show_spinner=False)
def _store():
    cfg = _kb().appconfig or {}
    db = (cfg.get("storage") or {}).get("db_path", "data/scans.db")
    return ScanStore(db)


@st.cache_resource(show_spinner=False)
def _scan_cache():
    return ScanCache()


_ROOT = os.path.dirname(os.path.abspath(__file__))
_SAMPLE_MOBSF = {
    "flashlight_overprivileged.apk": os.path.join(_ROOT, "samples", "flashlight_mobsf.json"),
    "calculator.apk": os.path.join(_ROOT, "samples", "calculator_mobsf.json"),
}


def _phone_safety(results: list[ScanResult]) -> tuple[float, float]:
    """Aggregate phone safety from PermGuard scores only (100 − mean risk)."""
    scores = [r.risk.score for r in results]
    avg_risk = sum(scores) / len(scores)
    safety = max(0.0, min(100.0, 100.0 - avg_risk))
    return safety, avg_risk


def _load_json_file(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return _json.load(fh)


def _mobsf_json_for(filename: str, uploaded_json: dict | None, use_bundled: bool) -> tuple[dict | None, str]:
    """Pick a saved/sample MobSF report so demos work without Docker."""
    if uploaded_json:
        report_name = str(uploaded_json.get("file_name") or "")
        if not report_name or report_name == filename or len(uploaded_json) > 2:
            return uploaded_json, "saved_json"
    if use_bundled:
        path = _SAMPLE_MOBSF.get(os.path.basename(filename))
        if path and os.path.isfile(path):
            return _load_json_file(path), "sample"
    return None, ""


def _collect_jobs(uploaded, chosen_sample: str | None, folder_path: str) -> list[tuple[str, bytes]]:
    jobs: list[tuple[str, bytes]] = []
    files = uploaded if isinstance(uploaded, list) else ([uploaded] if uploaded is not None else [])
    for f in files:
        if f is None:
            continue
        jobs.append((f.name, f.getvalue()))
    if not jobs and chosen_sample:
        demo_path = os.path.join(_ROOT, "data", "sampleapps", chosen_sample)
        if os.path.isfile(demo_path):
            with open(demo_path, "rb") as fh:
                jobs.append((chosen_sample, fh.read()))
    folder = (folder_path or "").strip().strip('"')
    if folder and os.path.isdir(folder):
        for path in sorted(glob.glob(os.path.join(folder, "*.apk"))):
            with open(path, "rb") as fh:
                jobs.append((os.path.basename(path), fh.read()))
    # de-dup by name keep first
    seen = set()
    uniq = []
    for name, data in jobs:
        if name in seen:
            continue
        seen.add(name)
        uniq.append((name, data))
    return uniq


def _render_mobsf_evidence(ev: dict) -> None:
    st.markdown(
        '<span class="pg-optional-badge">Optional — external cross-check</span>',
        unsafe_allow_html=True,
    )
    st.caption(
        "Supporting evidence only. MobSF output never adds, subtracts, or "
        "modifies the PermGuard score (that avoids double-counting overlapping findings)."
    )
    score = ev.get("mobsf_score")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("MobSF score", "—" if score is None else score)
    c2.metric("Dangerous perms (MobSF)", len(ev.get("dangerous_permissions") or []))
    c3.metric("Manifest issues", len(ev.get("manifest_issues") or []))
    c4.metric("Trackers", (ev.get("trackers") or {}).get("count", 0))
    st.caption(ev.get("mobsf_score_label") or "MobSF score is shown as-is and is not blended.")

    dang = ev.get("dangerous_permissions") or []
    if dang:
        st.subheader("Dangerous permissions (MobSF)")
        st.dataframe(
            [{"Permission": p["name"], "Status": p["status"], "Info": p.get("info", "")} for p in dang],
            width="stretch", hide_index=True,
        )
    issues = ev.get("manifest_issues") or []
    if issues:
        st.subheader("Manifest issues")
        for item in issues:
            st.markdown(f"- **{_escape(str(item.get('title')))}** ({_escape(str(item.get('severity') or 'info'))}) — {_escape(str(item.get('description') or ''))}")
    exported = ev.get("exported_components") or []
    if exported:
        st.subheader("Exported components")
        for item in exported:
            st.markdown(f"- `{item.get('type')}` `{item.get('name')}`")
    trackers = (ev.get("trackers") or {}).get("items") or []
    if trackers:
        st.subheader("Trackers")
        for t in trackers:
            st.markdown(f"- {_escape(t.get('name') or '')} ({_escape(t.get('categories') or '')})")

    agree = ev.get("agreement") or []
    if agree:
        st.subheader("Permission agreement")
        st.caption("“Confirmed by MobSF” means both tools flagged it — it is not extra PermGuard risk.")
        cls = {
            "confirmed by MobSF": "pg-agree-both",
            "only PermGuard": "pg-agree-pg",
            "only MobSF": "pg-agree-mf",
        }
        for row in agree:
            klass = cls.get(row["agreement"], "")
            st.markdown(
                f"- `{_escape(row['permission'])}` — "
                f'<span class="{klass}">{_escape(row["agreement"])}</span>',
                unsafe_allow_html=True,
            )

    dyn = ev.get("experimental_dynamic")
    if dyn:
        st.subheader("Experimental dynamic analysis")
        st.caption("Experimental — never affects the PermGuard score.")
        if not dyn.get("ok"):
            st.info(dyn.get("error") or "Dynamic analysis did not run.")
        else:
            st.markdown("**Runtime-used permissions:** " + (", ".join(dyn.get("runtime_used") or []) or "—"))
            st.markdown("**Declared only (not seen at runtime):** " + (", ".join(dyn.get("declared_only") or []) or "—"))


def _app_card(result: ScanResult) -> None:
    m = result.metadata
    verdicts = {c.permission: c for c in result.purpose_compatibility}
    title = m.app_label or m.filename or result.scan_id
    with st.expander(
        f"{title} — PermGuard {result.risk.score:.0f}/100 {result.risk.level.value}",
        expanded=False,
    ):
        st.caption(f"{m.package_name or '—'} · {len(m.permissions)} permissions · scan {result.scan_id}")
        if result.cached:
            st.caption("Served from local APK-hash cache.")
        for p in m.permissions:
            c = verdicts.get(p.name)
            v = c.verdict if c else "UNDETERMINED"
            st.markdown(f"**{p.name}** — {v} · {p.sensitivity.value}")
            st.caption(tip_for(p, c))


def _badge(level: str) -> str:
    color = _LEVEL_HEX.get(level, "#546E7A")
    return f'<span class="pg-badge" style="background:{color}">{level} RISK</span>'


def _sev_span(sev: str) -> str:
    return f'<span class="pg-sev-{sev}">{sev}</span>'


def _render_finding_accordion_html(f: Finding) -> str:
    sev = f.severity.value
    sev_color = _SEV_HEX.get(sev, "#90CAF9")
    status_text = _STATUS_LABEL.get(f.assessment_status.value, f.assessment_status.value)

    # Description and "Why it deserves investigation" parsing
    desc_text = f.description or ""
    investigation_html = ""
    if "Why it deserves investigation:" in desc_text:
        parts = desc_text.split("Why it deserves investigation:", 1)
        main_desc = parts[0].strip()
        inv_text = parts[1].strip()
        investigation_html = (
            '<div class="pg-find-box pg-box-investigate">'
            '<b>Why this situation is risky:</b> '
            f'{_escape(inv_text)}'
            '</div>'
        )
    else:
        main_desc = desc_text

    # Affected permissions as badges
    perms_html = ""
    if f.affected_permissions:
        chips = "".join(
            f'<span class="pg-perm-badge">{_escape(p)}</span>'
            for p in f.affected_permissions
        )
        perms_html = (
            '<div class="pg-find-box pg-box-perms">'
            f'<div class="pg-box-perms-title">Permissions involved ({len(f.affected_permissions)})</div>'
            f'<div>{chips}</div>'
            '</div>'
        )

    # Evidence card
    evidence_html = ""
    if f.evidence:
        evidence_html = (
            '<div class="pg-find-box pg-box-evidence">'
            '<b>What was detected in the app:</b>'
            f'<code>{_escape(f.evidence)}</code>'
            '</div>'
        )

    # Recommended action / remediation parsing
    action_html = ""
    if f.recommended_action:
        act_raw = f.recommended_action
        legit = ""
        resolve = ""
        if "Legitimate justifiers:" in act_raw:
            p1, rest = act_raw.split("Legitimate justifiers:", 1)
            act_main = p1.strip()
            if "Evidence that would resolve this:" in rest:
                p2, p3 = rest.split("Evidence that would resolve this:", 1)
                legit = p2.strip()
                resolve = p3.strip()
            else:
                legit = rest.strip()
        elif "Evidence that would resolve this:" in act_raw:
            p1, p2 = act_raw.split("Evidence that would resolve this:", 1)
            act_main = p1.strip()
            resolve = p2.strip()
        else:
            act_main = act_raw.strip()

        sub_items = []
        if legit:
            items = [j.strip() for j in legit.split(";") if j.strip()]
            if len(items) > 1:
                chips = "".join(f'<span class="pg-justifier-pill">• {_escape(j)}</span>' for j in items)
                sub_items.append(
                    '<div class="pg-action-subitem">'
                    '<div style="font-weight:700;margin-bottom:0.35rem;color:#166534;">Allowed only for legitimate cases:</div>'
                    f'<div style="display:flex;flex-wrap:wrap;gap:0.4rem;">{chips}</div>'
                    '</div>'
                )
            else:
                sub_items.append(
                    '<div class="pg-action-subitem">'
                    '<b>Allowed only for legitimate cases:</b> '
                    f'{_escape(legit)}'
                    '</div>'
                )
        if resolve:
            items = [r.strip() for r in resolve.split(",") if r.strip()]
            if len(items) > 1:
                chips = "".join(f'<span class="pg-resolve-pill">• {_escape(r)}</span>' for r in items)
                sub_items.append(
                    '<div class="pg-action-subitem" style="border-color:#FEF08A;background:#FEFCE8;color:#713F12;">'
                    '<div style="font-weight:700;margin-bottom:0.35rem;color:#854D0E;">How to verify or resolve this:</div>'
                    f'<div style="display:flex;flex-wrap:wrap;gap:0.4rem;">{chips}</div>'
                    '</div>'
                )
            else:
                sub_items.append(
                    '<div class="pg-action-subitem" style="border-color:#FEF08A;background:#FEFCE8;color:#713F12;">'
                    '<b>How to verify or resolve this:</b> '
                    f'{_escape(resolve)}'
                    '</div>'
                )

        action_html = (
            '<div class="pg-find-box pg-box-action">'
            '<b>What you should do:</b> '
            f'{_escape(act_main)}'
            + "".join(sub_items) +
            '</div>'
        )

    # Limitations callout
    limit_html = ""
    if f.limitations:
        limit_html = (
            '<div class="pg-find-box pg-box-limitation">'
            '<b>Important Note:</b> '
            f'{_escape(f.limitations)}'
            '</div>'
        )

    # Source documentation links
    src_html = ""
    if f.source_urls:
        links = " · ".join(
            f'<a href="{_escape(u)}" target="_blank" style="color:#2563EB;text-decoration:underline;">Docs ↗</a>'
            for u in f.source_urls if u
        )
        src_html = f'<span>Sources: {links}</span>'

    # Build dropdown details
    return (
        f'<details class="pg-find-details">'
        f'<summary class="pg-find-summary" style="border-left: 6px solid {sev_color};">'
        f'<div class="summary-left">'
        f'<span class="pg-sevchip" style="background:{sev_color};color:#fff;font-weight:800;letter-spacing:0.04em;">{sev}</span>'
        f'<span class="summary-title">{_escape(f.title)}</span>'
        f'</div>'
        f'<div class="summary-right">'
        f'<span class="summary-status">{_escape(status_text)}</span>'
        f'<span class="summary-rule">{_escape(f.rule_id)}</span>'
        f'<span class="summary-chevron">▼</span>'
        f'</div>'
        f'</summary>'
        f'<div class="pg-find-body">'
        f'<div class="pg-find-desc">{_escape(main_desc)}</div>'
        f'{investigation_html}'
        f'{perms_html}'
        f'{evidence_html}'
        f'{action_html}'
        f'{limit_html}'
        f'<div class="pg-find-footer">'
        f'<span>Confidence: <b>{f.confidence.value}</b> · Framework: <b>{_escape(f.source_framework)}</b></span>'
        f'{src_html}'
        f'</div>'
        f'</div>'
        f'</details>'
    )



def _history_charts(rows: list[dict]):
    if not rows:
        return
    rows = rows[:25]
    labels = [
        (r["app_label"] or r["package_name"] or r["filename"] or r["scan_id"])[:28]
        for r in rows
    ][::-1]
    scores = [r["risk_score"] for r in rows][::-1]
    colors = [_LEVEL_HEX.get(r["risk_level"], "#90CAF9") for r in rows][::-1]
    fig = go.Figure(go.Bar(
        x=scores, y=labels, orientation="h",
        marker_color=colors,
        text=[f"{s:.0f}" for s in scores], textposition="outside",
    ))
    fig.update_layout(
        height=max(240, len(rows) * 30), xaxis_range=[0, 105],
        title="Risk score by analysed app (higher = more over-privileged)",
        margin=dict(l=10, r=30, t=40, b=10), template="plotly_dark",
    )
    st.plotly_chart(fig, width="stretch")


def _severity_gauge(result: ScanResult):
    counts = result.severity_counts
    fig = go.Figure(go.Pie(
        labels=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        values=[counts.get(k, 0) for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]],
        hole=0.55,
        marker_colors=[_SEV_HEX[k] for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]],
        textinfo="label+value",
    ))
    fig.update_layout(
        title="Finding severity distribution", height=320,
        margin=dict(l=10, r=10, t=40, b=10), template="plotly_dark",
        showlegend=False,
    )
    st.plotly_chart(fig, width="stretch")


def _score_gauge(result: ScanResult):
    score = result.risk.score
    color = _LEVEL_HEX.get(result.risk.level.value, "#F9A825")
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=score,
        number={"suffix": "/100", "font": {"size": 40}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1},
            "bar": {"color": color},
            "steps": [
                {"range": [0, 30], "color": "#E8F5E9"},
                {"range": [30, 60], "color": "#FFF8E1"},
                {"range": [60, 100], "color": "#FFEBEE"},
            ],
            "threshold": {
                "line": {"color": color, "width": 5},
                "thickness": 0.85, "value": score,
            },
        },
    ))
    fig.update_layout(
        height=270, margin=dict(l=20, r=20, t=50, b=10),
        title=f"Overall risk — {result.risk.level.value}", template="plotly_dark",
    )
    st.plotly_chart(fig, width="stretch")


# ---------------------------------------------------------------------------
# Single-page marketing shell; the existing analyzer remains below this page.
# ---------------------------------------------------------------------------
from urllib.parse import quote as _urlquote
import re as _re

if "site_page" not in st.session_state:
    st.session_state.site_page = "home"
if "tool_page" not in st.session_state:
    st.session_state.tool_page = "Overview"

_TOOL_TABS = (
    "Overview", "Permission Inventory", "Policy Analysis",
    "Risk Analysis", "Remediation", "Comparison", "Export",
)

def _goto_tool(target: str) -> None:
    st.session_state.tool_page = target

def _render_navbar() -> None:
    st.markdown(
        '<div class="pg-nav"><a class="pg-brand" href="#home">PermGuard</a>'
        '<div class="pg-links"><a href="#home">Home</a><a href="#how-it-works">How It Works</a>'
        '<a href="#analyze">Analyze</a><a href="#about">About Us</a><a href="#contact">Contact</a></div>'
        '<a class="pg-nav-cta" href="#analyze">Analyze App</a></div>',
        unsafe_allow_html=True,
    )

def _render_home() -> None:
    st.markdown('<div class="pg-dark-site"></div><div class="pg-stars" aria-hidden="true"></div><span id="home"></span>', unsafe_allow_html=True)
    _render_navbar()
    st.markdown(
        '<section class="pg-section pg-hero-section"><div>'
        '<p class="pg-eyebrow">ANDROID PRIVACY INTELLIGENCE</p>'
        '<h1 class="pg-h1">Your apps request access.<br>Know what they really need.</h1>'
        '<p class="pg-lead">See which Android permissions an app really needs.</p>'
        '</div></section>', unsafe_allow_html=True,
    )
    _steps = (('01','Choose an app report','Upload an APK or report.'),
              ('02','Evaluate permissions','Check permissions against policy.'),
              ('03','Understand the risk','Get a clear risk score.'))
    _cards = ''.join(f'<div class="pg-step"><em>{n}</em><h4>{t}</h4><p>{d}</p></div>' for n,t,d in _steps)
    st.markdown('<section class="pg-section pg-frame" id="how-it-works"><div><p class="pg-eyebrow">THREE CLEAR STEPS</p><h2>Clarity before access.</h2>'
                f'<div class="pg-steps">{_cards}</div></div></section>', unsafe_allow_html=True)

_render_home()

# ---------------------------------------------------------------------------
# tool dispatch (sidebar removed — hamburger menu in the navbar drives this)
# ---------------------------------------------------------------------------
if "tool_page" not in st.session_state:
    st.session_state.tool_page = "Overview"
tool_page = st.session_state.tool_page

kb = _kb()
if kb.errors:
    st.error("Knowledge base errors:\n" + "\n".join(kb.errors))
store = _store()
categories = list_categories(kb)

if "result" not in st.session_state:
    st.session_state.result = None
if "results" not in st.session_state:
    st.session_state.results = []
if "mobsf_notice" not in st.session_state:
    st.session_state.mobsf_notice = ""
if "disclaimer" not in st.session_state:
    st.session_state.disclaimer = _DISCLAIMER

# ---- Optional MobSF settings (sidebar). Default mode never needs this. ----
with st.sidebar:
    st.markdown("**Analysis mode**")
    mobsf_mode = st.radio(
        "Mode",
        ["Offline mode (default)", "Add MobSF cross-check (optional)"],
        index=0,
        label_visibility="collapsed",
        help="Offline mode is complete on its own. MobSF is supporting evidence only and never changes the PermGuard score.",
    )
    mobsf_enabled = mobsf_mode.startswith("Add MobSF")
    mobsf_url = "http://localhost:8000"
    mobsf_key = ""
    mobsf_ok_msg = ""
    saved_mobsf_doc = None
    use_bundled_mobsf = False
    experimental_dyn = False
    if mobsf_enabled:
        st.caption("Optional — external cross-check. Leave this off for zero-setup demos.")
        mobsf_url = st.text_input("MobSF URL", value="http://localhost:8000")
        mobsf_key = st.text_input("MobSF API key", type="password", help="MobSF UI → API Docs")
        if st.button("Test connection"):
            from mobsf_client import MobSFSettings, test_connection
            ok, msg = test_connection(MobSFSettings(base_url=mobsf_url, api_key=mobsf_key))
            if ok:
                st.success(msg)
            else:
                st.warning(msg)
        saved_mobsf_file = st.file_uploader(
            "Or load a saved MobSF report JSON (demo without Docker)",
            type=["json"],
            key="mobsf_saved_json",
        )
        if saved_mobsf_file is not None:
            try:
                saved_mobsf_doc = _json.loads(saved_mobsf_file.getvalue().decode("utf-8"))
                st.caption(f"Loaded {saved_mobsf_file.name}")
            except Exception:
                st.warning("Could not parse that JSON. Offline analysis will still run.")
                saved_mobsf_doc = None
        use_bundled_mobsf = st.checkbox(
            "Use bundled sample MobSF reports when the APK matches",
            value=True,
            help="samples/flashlight_mobsf.json and samples/calculator_mobsf.json",
        )
        experimental_dyn = st.checkbox(
            "Experimental: MobSF dynamic analysis (emulator)",
            value=False,
            help="Requires a running emulator attached to MobSF. Never affects the PermGuard score.",
        )
    else:
        st.caption("Offline mode — 100% local, no MobSF required.")

result: ScanResult | None = st.session_state.result
results_list: list[ScanResult] = st.session_state.get("results") or ([] if result is None else [result])

if tool_page not in _TOOL_TABS:
    tool_page = "Overview"
st.session_state.tool_page = tool_page


# ===========================================================================
# OVERVIEW
# ===========================================================================
if tool_page == "Overview":
    st.markdown('<span id="analyze"></span>', unsafe_allow_html=True)

    if result is None:
        # Top Eyebrow & Badge row + Heading matching design reference
        st.markdown(
            """
            <div class="pg-card-wrapper">
                <div class="pg-card-topbar">
                    <span class="pg-card-eyebrow">START A PRIVATE SCAN</span>
                    <span class="pg-local-badge">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                        </svg>
                        Local only
                    </span>
                </div>
                <h2 class="pg-card-title">Analyze your APK</h2>
            </div>
            """,
            unsafe_allow_html=True,
        )

        with st.container():
            st.markdown('<div class="pg-analyze-marker"></div>', unsafe_allow_html=True)

            # Dropzone prompt and icon
            st.markdown(
                """
                <div class="pg-drop-prompt">
                    <div class="pg-drop-icon">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#8fb0d4" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                            <polyline points="17 8 12 3 7 8"></polyline>
                            <line x1="12" y1="3" x2="12" y2="15"></line>
                        </svg>
                    </div>
                    <div class="pg-drop-title">Drop Your APK Here</div>
                    <div class="pg-drop-sub">or click to browse · APK files only</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            uploaded = st.file_uploader(
                "Upload APK",
                type=["apk", "aab", "xml", "json", "csv"],
                label_visibility="collapsed",
                key="apk_uploader",
                accept_multiple_files=True,
                help="Upload one or many APKs. Files are validated, parsed in memory, and deleted after analysis. Default mode is 100% offline.",
            )
            folder_path = st.text_input(
                "Or scan a local folder of APKs",
                value="",
                placeholder=r"C:\apk_samples   or  /path/to/apks",
                help="Optional batch: every *.apk in this folder is analysed. Leave blank for a single upload.",
            )

            # Quick sample apps selector
            st.markdown(
                '<div class="pg-samples-title">Or test with a sample app:</div>',
                unsafe_allow_html=True,
            )
            s_cols = st.columns(5)
            sample_apps = [
                ("Calculator", "calculator.apk", "calculator"),
                ("Flashlight", "flashlight_overprivileged.apk", "flashlight"),
                ("Navigation", "navigation.apk", "navigation"),
                ("Voice Recorder", "voice_recorder.apk", "voice_recorder"),
                ("Photo Editor", "photo_editor.apk", "photo_editor"),
            ]
            for idx, (label, fname, cat) in enumerate(sample_apps):
                with s_cols[idx]:
                    if st.button(label, key=f"smp_{fname}", use_container_width=True):
                        st.session_state.chosen_sample = fname
                        st.session_state.chosen_cat = cat

            chosen_sample = st.session_state.get("chosen_sample", None)
            if chosen_sample and uploaded is None:
                st.markdown(
                    f'<div class="pg-sample-active-chip">Selected sample: <b>{chosen_sample}</b></div>',
                    unsafe_allow_html=True,
                )

            # Two-column row: App Category & Environment
            col_left, col_right = st.columns(2)
            with col_left:
                st.markdown(
                    '<div class="pg-field-label">App Category <span class="pg-info-icon" title="Defines which permissions are expected and necessary for this application type">ⓘ</span></div>',
                    unsafe_allow_html=True,
                )
                cat_keys_list = list(categories.keys())
                # Insert Auto as first option
                if 'auto' not in cat_keys_list:
                    cat_keys_list = ['auto'] + cat_keys_list
                # Update categories for Auto
                if 'auto' not in categories:
                    categories['auto'] = 'Auto (Automatic Detection)'
                pref_cat = st.session_state.get("chosen_cat", "auto")
                try:
                    default_idx = cat_keys_list.index(pref_cat) if pref_cat in cat_keys_list else 0
                except ValueError:
                    default_idx = 0

                cat_key = st.selectbox(
                    "App Category",
                    cat_keys_list,
                    index=default_idx,
                    format_func=lambda k: categories.get(k, k).split(" / ")[0] if k != 'auto' else 'Auto',
                    label_visibility="collapsed",
                    key="sel_category",
                )
                st.markdown('<div class="pg-field-help">Defines which permissions are necessary.</div>', unsafe_allow_html=True)

            with col_right:
                st.markdown(
                    '<div class="pg-field-label">Environment <span class="pg-info-icon" title="Deployment context and environment criticality">ⓘ</span></div>',
                    unsafe_allow_html=True,
                )
                env_choice = st.selectbox(
                    "Environment",
                    ["Mildly critical", "Standard (Low risk)", "High criticality (Sensitive)"],
                    index=0,
                    label_visibility="collapsed",
                    key="sel_env",
                )
                st.markdown('<div class="pg-field-help">Adjusts risk for the deployment context.</div>', unsafe_allow_html=True)
                environment = "high" if "High" in env_choice else "low"

            # Criticality Row
            st.markdown(
                '<div class="pg-field-label">Criticality <span class="pg-info-icon" title="Standard: adds policy, OWASP and combinations">ⓘ</span></div>',
                unsafe_allow_html=True,
            )
            crit_choice = st.selectbox(
                "Criticality",
                ["Medium", "Auto (Triage)", "Deep (Full static analysis)"],
                index=0,
                label_visibility="collapsed",
                key="sel_crit",
            )
            st.markdown('<div class="pg-field-help">Standard: adds policy, OWASP and combinations.</div>', unsafe_allow_html=True)
            scan_mode = "deep" if "Deep" in crit_choice else ("auto" if "Auto" in crit_choice else "basic")

            # Organisation Policy Accordion
            with st.expander("Organisation Policy", expanded=False):
                st.markdown('<div class="pg-policy-desc">Select an enterprise policy preset, upload custom YAML/JSON rules, or toggle compliance controls.</div>', unsafe_allow_html=True)
                p_col1, p_col2 = st.columns([1, 1])
                with p_col1:
                    preset_policy = st.selectbox(
                        "Policy Profile Preset",
                        [
                            "Default Baseline Policy",
                            "Strict Healthcare / HIPAA",
                            "Financial / Banking (PCI-DSS)",
                            "Defense & Critical Infrastructure",
                            "Custom Policy (Upload below)",
                        ],
                        index=0,
                        key="policy_preset_sel",
                    )
                with p_col2:
                    policy_file = st.file_uploader(
                        "Upload custom policy (.yaml, .json)",
                        type=["yaml", "yml", "json"],
                        key="upload_org_policy",
                        help="Upload organization rules with denied and review permission lists.",
                    )

                st.markdown('<div style="font-size:0.83rem; font-weight:600; color:#dbe4ef; margin:0.6rem 0 0.3rem 0;">Quick Policy Enforcements:</div>', unsafe_allow_html=True)
                t_col1, t_col2 = st.columns(2)
                with t_col1:
                    rule_no_sms = st.checkbox("Deny SMS & Call Log permissions", value=True, help="Flag any SMS or Call Log permission as CRITICAL policy violation.")
                    rule_flag_bg = st.checkbox("Flag Background Location", value=True, help="Require explicit justification for background location.")
                with t_col2:
                    rule_restrict_media = st.checkbox("Restrict Camera & Microphone", value=False, help="Disallow camera/mic unless core to category.")
                    max_tier_sel = st.selectbox("Sensitivity Ceiling", ["CRITICAL", "HIGH", "MODERATE", "LOW"], index=0)

                active_policy_name = policy_file.name if policy_file else preset_policy
                st.markdown(
                    f'<div class="pg-active-policy-chip">✓ Enforcing: <b>{active_policy_name}</b> (org_policy layer active)</div>',
                    unsafe_allow_html=True,
                )

            # Analyze Permissions Button
            run = st.button("Analyze Permissions", type="primary", use_container_width=True)

            if run:
                jobs = _collect_jobs(uploaded, chosen_sample, folder_path)
                if not jobs:
                    st.error("Please upload an APK file, select a sample app, or point to a folder of APKs.")
                else:
                    try:
                        import copy
                        import yaml
                        import json

                        scan_kb = copy.copy(kb)
                        scan_kb.orgpolicy = copy.deepcopy(kb.orgpolicy) if isinstance(kb.orgpolicy, dict) else {}
                        scan_kb.orgpolicy["enabled"] = True

                        p_dict = scan_kb.orgpolicy.get("policy", {})
                        if policy_file is not None:
                            try:
                                content_str = policy_file.getvalue().decode("utf-8")
                                if policy_file.name.endswith(".json"):
                                    parsed = json.loads(content_str)
                                else:
                                    parsed = yaml.safe_load(content_str)
                                if isinstance(parsed, dict):
                                    p_dict = parsed.get("policy", parsed)
                                    p_dict["name"] = p_dict.get("name", policy_file.name)
                            except Exception as pe:
                                st.warning(f"Could not parse custom policy file: {pe}. Using baseline.")
                        elif "Healthcare" in preset_policy:
                            p_dict["name"] = "Strict Healthcare / HIPAA"
                            p_dict["denied_permissions"] = list(set(p_dict.get("denied_permissions", []) + [
                                "android.permission.READ_SMS", "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS",
                                "android.permission.READ_CALL_LOG", "android.permission.ACCESS_FINE_LOCATION",
                                "android.permission.RECORD_AUDIO", "android.permission.CAMERA"
                            ]))
                            p_dict["max_sensitivity_tier"] = "MODERATE"
                        elif "Financial" in preset_policy:
                            p_dict["name"] = "Financial / Banking (PCI-DSS)"
                            p_dict["denied_permissions"] = list(set(p_dict.get("denied_permissions", []) + [
                                "android.permission.READ_SMS", "android.permission.SEND_SMS",
                                "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.SYSTEM_ALERT_WINDOW"
                            ]))
                            p_dict["max_sensitivity_tier"] = "HIGH"
                        elif "Defense" in preset_policy:
                            p_dict["name"] = "Defense & Critical Infrastructure"
                            p_dict["denied_permissions"] = list(set(p_dict.get("denied_permissions", []) + [
                                "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION",
                                "android.permission.CAMERA", "android.permission.RECORD_AUDIO"
                            ]))
                            p_dict["max_sensitivity_tier"] = "LOW"

                        if rule_no_sms:
                            for p in ["android.permission.READ_SMS", "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS", "android.permission.READ_CALL_LOG"]:
                                if p not in p_dict.get("denied_permissions", []):
                                    p_dict.setdefault("denied_permissions", []).append(p)
                        if rule_flag_bg:
                            if "android.permission.ACCESS_BACKGROUND_LOCATION" not in p_dict.get("review_permissions", []):
                                p_dict.setdefault("review_permissions", []).append("android.permission.ACCESS_BACKGROUND_LOCATION")
                        if rule_restrict_media:
                            for p in ["android.permission.CAMERA", "android.permission.RECORD_AUDIO"]:
                                if p not in p_dict.get("denied_permissions", []):
                                    p_dict.setdefault("denied_permissions", []).append(p)
                        p_dict["max_sensitivity_tier"] = max_tier_sel
                        scan_kb.orgpolicy["policy"] = p_dict

                        cache = _scan_cache()
                        batch: list[ScanResult] = []
                        notices: list[str] = []
                        n_jobs = len(jobs)
                        table_slot = st.empty()

                        with st.status("Running PermGuard analysis…", expanded=True) as status:
                            bar = st.progress(0)
                            for i, (target_name, target_bytes) in enumerate(jobs):
                                digest = sha256_bytes(target_bytes)
                                status.write(f"**{i + 1}/{n_jobs}** `{target_name}` — upload / hash")
                                cached = cache.get(digest, cat_key, scan_mode, environment)
                                if cached is not None:
                                    status.write("Cache hit — restoring PermGuard result (score unchanged).")
                                    res = cached
                                    res.cached = True
                                else:
                                    status.write("Offline engine: extract → classify → score")
                                    path = save_upload(
                                        target_bytes, target_name,
                                        os.path.join(tempfile.gettempdir(), "permguard_uploads"),
                                    )
                                    res = run_scan(
                                        path=path,
                                        original_filename=target_name,
                                        purpose_category=cat_key,
                                        purpose_description=f"Category: {cat_key}",
                                        scan_mode=scan_mode,
                                        environment=environment,
                                        kb=scan_kb,
                                    )
                                    res.cached = False
                                    cache.put(res, digest, cat_key, scan_mode, environment)

                                # MobSF is supporting evidence only — score is already final.
                                live_configured = bool(mobsf_enabled and mobsf_url.strip() and mobsf_key.strip())
                                demo_report, demo_src = _mobsf_json_for(
                                    target_name, saved_mobsf_doc, bool(mobsf_enabled and use_bundled_mobsf),
                                )
                                if mobsf_enabled and (live_configured or demo_report):
                                    mobsf_report = None
                                    source = demo_src
                                    file_hash = ""
                                    if live_configured:
                                        status.write("MobSF: upload → scan → report (optional)")
                                        from mobsf_client import MobSFSettings, run_static_crosscheck, run_dynamic_crosscheck
                                        job = run_static_crosscheck(
                                            MobSFSettings(base_url=mobsf_url, api_key=mobsf_key),
                                            target_name,
                                            target_bytes,
                                            progress=lambda msg, pct: status.write(msg),
                                        )
                                        if job.ok:
                                            mobsf_report = job.report
                                            source = "live"
                                            file_hash = job.hash
                                        else:
                                            notices.append(f"{target_name}: MobSF unreachable — {job.error}. Offline result kept.")
                                            if demo_report:
                                                mobsf_report = demo_report
                                                source = demo_src or "sample"
                                                status.write("Using saved/sample MobSF JSON instead.")
                                    if mobsf_report is None and demo_report:
                                        status.write("Loading saved/sample MobSF JSON (demo, no server).")
                                        mobsf_report = demo_report
                                        source = demo_src or "saved_json"

                                    if mobsf_report is not None:
                                        dyn_payload = None
                                        if experimental_dyn and live_configured and file_hash:
                                            status.write("Experimental: MobSF dynamic analysis")
                                            ok_d, dyn_rep, dyn_err = run_dynamic_crosscheck(
                                                MobSFSettings(base_url=mobsf_url, api_key=mobsf_key),
                                                file_hash,
                                            )
                                            dyn_payload = {"ok": ok_d, "report": dyn_rep, "error": dyn_err}
                                        res.supporting_evidence = build_evidence(
                                            mobsf_report,
                                            res,
                                            source=source,
                                            experimental_dynamic=dyn_payload,
                                        )
                                elif mobsf_enabled and not live_configured and not demo_report:
                                    # Not configured — hide evidence, no error panel.
                                    res.supporting_evidence = None

                                batch.append(res)
                                store.save(res)
                                bar.progress(int((i + 1) / n_jobs * 100))
                                table_slot.dataframe(
                                    [{
                                        "App": r.metadata.app_label or r.metadata.filename,
                                        "PermGuard": r.risk.score,
                                        "Level": r.risk.level.value,
                                        "Perms": len(r.metadata.permissions),
                                        "Cache": "yes" if r.cached else "no",
                                        "MobSF": "yes" if (r.supporting_evidence or {}).get("used") else "—",
                                    } for r in batch],
                                    width="stretch", hide_index=True,
                                )
                            status.update(label="Analysis complete", state="complete")

                        st.session_state.results = batch
                        st.session_state.result = batch[-1]
                        st.session_state.mobsf_notice = " ".join(notices)
                        st.rerun()
                    except ScanError as exc:
                        st.error(f"**Analysis could not run:** {exc}")
                    except Exception as exc:
                        st.error(f"Unexpected error: {exc}")
                        with st.expander("Details"):
                            st.code(traceback.format_exc())

    else:
        batch = st.session_state.get("results") or [result]
        if len(batch) > 1:
            labels = [
                f"{(x.metadata.app_label or x.metadata.filename)} — {x.risk.score:.0f}/100"
                for x in batch
            ]
            pick = st.selectbox("Viewing app", list(range(len(batch))), format_func=lambda i: labels[i])
            r = batch[pick]
            st.session_state.result = r
        else:
            r = result
        notice = st.session_state.get("mobsf_notice") or ""
        if notice:
            st.info(notice)
        ev_used = any((x.supporting_evidence or {}).get("used") for x in batch)
        tab_names = ["Summary", "Apps", "Details"]
        if ev_used:
            tab_names.append("Evidence")
        result_tabs = st.tabs(tab_names)
        tab_summary, tab_apps, tab_details = result_tabs[0], result_tabs[1], result_tabs[2]
        tab_evidence = result_tabs[3] if ev_used else None

        m = r.metadata
        sc = r.severity_counts
        score = r.risk.score
        level = r.risk.level.value
        lvl_color = _LEVEL_HEX.get(level, "#546E7A")
        over = sum(1 for c in r.purpose_compatibility
                   if c.verdict == "UNEXPECTED")
        chips = "".join(
            f'<span class="pg-sevchip" style="background:'
            f'{_SEV_HEX.get(k, "#90CAF9")};color:'
            f'{"#fff" if k in ("CRITICAL", "HIGH") else "#212121"}">'
            f'{sc.get(k, 0)} {k}</span>'
            for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            if sc.get(k)
        ) or ('<span class="pg-sevchip" style="background:#E8F5E9;'
              'color:#2E7D32">no findings</span>')

        theme_cls = f"pg-theme-{level.lower()}" if level.lower() in ("high", "medium", "low") else "pg-theme-medium"
        with tab_summary:
            st.markdown(
                f'<div class="pg-ovhero {theme_cls}">'
                '<div class="pg-ovcard pg-scorecard">'
                '<div class="pg-sc-top">'
                '<span class="pg-sclabel">Risk score &mdash; higher = worse</span>'
                f'<span class="pg-badge" style="background:rgba(255,255,255,0.22);border:1px solid rgba(255,255,255,0.38);color:#fff;font-weight:800;letter-spacing:0.06em;">'
                f'{level} RISK</span>'
                '</div>'
                f'<div class="pg-scnum">{score:.0f}<span>/100</span></div>'
                '<div class="pg-scbar"><div class="pg-scfill" style="width:'
                f'{min(score, 100):.0f}%"></div></div>'
                '<div class="pg-sczones"><span>0 safe</span><span>30</span>'
                '<span>60</span><span>100 critical</span></div>'
                '</div>'
                '<div class="pg-ovcard">'
                f'<div class="pg-cnum">{over}</div>'
                '<div class="pg-clabel">permissions not needed for the '
                'declared purpose</div></div>'
                '<div class="pg-ovcard">'
                f'<div class="pg-cnum">{len(r.recommendations)}</div>'
                '<div class="pg-clabel">Recommended Actions</div></div>'
'</div>',
                unsafe_allow_html=True,
            )



            dl1, dl2, dl3 = st.columns(3)
            pdf_key = f"pdf_bytes_{r.scan_id}"
            with dl1:
                if pdf_key in st.session_state:
                    st.download_button(
                        ":material/download: Download PDF",
                        st.session_state[pdf_key],
                        file_name=f"permguard_{r.scan_id}.pdf",
                        mime="application/pdf",
                        width="stretch",
                        key="ov_dl_pdf",
                    )
                elif st.button("Prepare PDF", width="stretch",
                               key="ov_gen_pdf"):
                    with st.spinner("Building PDF report…"):
                        pdf_dir = os.path.join(tempfile.gettempdir(),
                                               "permguard_reports")
                        os.makedirs(pdf_dir, exist_ok=True)
                        path = to_pdf(r, os.path.join(pdf_dir,
                                                      f"{r.scan_id}.pdf"))
                        with open(path, "rb") as fh:
                            st.session_state[pdf_key] = fh.read()
                    st.rerun()
            with dl2:
                st.download_button(
                    ":material/download: Download JSON", to_json(r),
                    file_name=f"permguard_{r.scan_id}.json",
                    mime="application/json", width="stretch",
                    key="ov_dl_json",
                )
            with dl3:
                st.download_button(
                    ":material/download: Download CSV", to_csv(r),
                    file_name=f"permguard_{r.scan_id}.csv",
                    mime="text/csv", width="stretch",
                    key="ov_dl_csv",
                )

            # Enhanced "Why this score" container with Pie/Donut Chart & Contributor Progress Cards
            st.markdown(
                '<div id="report-details" class="pg-why-container">'
                '<div class="pg-why-head">'
                '<div>'
                '<div class="pg-why-title">Why this score & Risk Breakdown</div>'
                '<div class="pg-why-subtitle">Visual breakdown of scoring contributions, severity distribution, and policy flags</div>'
                '</div>'
                f'<div class="pg-badge" style="background:{lvl_color};font-size:.85rem;padding:6px 14px;">{level} RISK ({score:.0f}/100)</div>'
                '</div>',
                unsafe_allow_html=True,
            )

            col_why = st.columns(1)
            why_col1 = col_why[0]
            with why_col1:
                # Severity Donut Chart
                sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                labels = [k for k in sev_order if sc.get(k, 0) > 0]
                values = [sc[k] for k in labels]
                colors = [_SEV_HEX[k] for k in labels]
                total_findings_count = sum(values)

                fig_donut = go.Figure(go.Pie(
                    labels=labels,
                    values=values,
                    hole=0.62,
                    marker_colors=colors,
                    textinfo="value",
                    hoverinfo="label+value+percent",
                    textfont=dict(size=13, color="#ffffff"),
                    sort=False,
                ))
                fig_donut.update_layout(
                    height=265,
                    margin=dict(l=10, r=10, t=10, b=10),
                    template="plotly_dark",
                    showlegend=True,
                    legend=dict(
                        orientation="h",
                        yanchor="bottom",
                        y=-0.22,
                        xanchor="center",
                        x=0.5,
                        font=dict(size=11),
                    ),
                    annotations=[
                        dict(
                            text=f"<b>{total_findings_count}</b><br><span style='font-size:11px;color:#64748B;'>Findings</span>",
                            x=0.5, y=0.5,
                            font_size=18,
                            showarrow=False,
                        )
                    ],
                )
                st.plotly_chart(fig_donut, use_container_width=True, config={"displayModeBar": False}, key="donut_chart")



            # Structured explanation and highlights below columns (no emojis)
            summary_pills = (
                f'<div class="pg-why-summary-row">'
                f'<div class="pg-why-metric-pill"><span>Risk: {score:.0f}/100 ({level})</span></div>'
                f'<div class="pg-why-metric-pill"><span>Total Scored Findings: {len(r.risk.breakdown)} across {len(m.permissions)} permissions</span></div>'
                f'<div class="pg-why-metric-pill"><span>Over-Privilege: {over} unneeded permissions</span></div>'
                f'</div>'
            )



            disclaimer_html = ""
            st.markdown(summary_pills + disclaimer_html + '</div>', unsafe_allow_html=True)

        with tab_apps:
            if len(batch) > 1:
                safety, avg_risk = _phone_safety(batch)
                s1, s2, s3 = st.columns(3)
                s1.metric("Phone safety score", f"{safety:.0f}/100")
                s2.metric("Mean PermGuard risk", f"{avg_risk:.0f}/100")
                s3.metric("Apps scanned", len(batch))
                st.caption(
                    "Phone safety = 100 − average PermGuard risk across this batch. "
                    "MobSF is not included in this number."
                )
            st.dataframe(
                [{
                    "App": x.metadata.app_label or x.metadata.filename,
                    "Package": x.metadata.package_name or "—",
                    "PermGuard": x.risk.score,
                    "Level": x.risk.level.value,
                    "Permissions": len(x.metadata.permissions),
                    "Unexpected": sum(1 for c in x.purpose_compatibility if c.verdict == "UNEXPECTED"),
                    "Cached": "yes" if x.cached else "no",
                } for x in batch],
                width="stretch", hide_index=True,
            )
            for x in batch:
                _app_card(x)

        with tab_details:
            st.subheader("Findings & Security Situations")
            actionable = [
                f for f in r.findings
                if f.assessment_status not in (
                    AssessmentStatus.PASS, AssessmentStatus.NOT_APPLICABLE,
                    AssessmentStatus.INSUFFICIENT_EVIDENCE)
            ]
            actionable.sort(key=lambda f: (
                {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[f.severity.value],
                f.rule_id))
            if not actionable:
                st.success("No issues detected — permissions match the declared purpose.")
            else:
                f_col1, f_col2 = st.columns([2, 1])
                with f_col1:
                    st.caption(
                        f"**{len(actionable)} situation(s) detected.** Click any situation below to see what happened and what you should do."
                    )
                with f_col2:
                    sev_map = {
                        "ALL": "All Situations",
                        "CRITICAL": "Critical Situations",
                        "HIGH": "High Risk Situations",
                        "MEDIUM": "Medium Risk Situations",
                        "LOW": "Low Risk Situations",
                        "INFO": "Informational Notices",
                    }
                    sev_options = ["ALL"] + [s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if any(f.severity.value == s for f in actionable)]
                    selected_sev = st.selectbox(
                        "Filter situations",
                        sev_options,
                        format_func=lambda s: sev_map.get(s, s),
                        index=0,
                        key="ov_sev_filter",
                        label_visibility="collapsed"
                    )

                filtered = actionable if selected_sev == "ALL" else [f for f in actionable if f.severity.value == selected_sev]
                findings_html = "".join(_render_finding_accordion_html(f) for f in filtered)
                st.markdown(findings_html, unsafe_allow_html=True)

            st.divider()
            st.caption(f"Scan finished {r.scan_finished_at} · mode {r.scan_mode} · "
                       f"depth {r.scan_depth_used}")
            st.markdown(f'<div class="pg-disc"><b>Disclaimer:</b> {_DISCLAIMER}</div>',
                            unsafe_allow_html=True)

        if tab_evidence is not None:
            with tab_evidence:
                st.markdown("### Supporting Evidence (MobSF)")
                active_ev = r.supporting_evidence or {}
                if active_ev.get("used"):
                    _render_mobsf_evidence(active_ev)
                else:
                    st.caption("This app has no MobSF evidence. Other apps in the batch may.")

        if st.button("New scan"):
            st.session_state.result = None
            st.session_state.results = []
            st.session_state.mobsf_notice = ""
            st.rerun()


# ===========================================================================
# PERMISSION INVENTORY
# ===========================================================================
elif tool_page == "Permission Inventory":
    st.markdown('<p class="pg-title">Permission Inventory</p>',
                unsafe_allow_html=True)
    if result is None:
        st.info("Run a scan first (Overview tab).")
    else:
        r = result
        m = r.metadata
        verdicts = {c.permission: c.verdict for c in r.purpose_compatibility}
        compat_by_perm = {c.permission: c for c in r.purpose_compatibility}

        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total permissions", len(m.permissions))
        sens = {}
        for p in m.permissions:
            sens[p.sensitivity.value] = sens.get(p.sensitivity.value, 0) + 1
        c2.metric("Critical sensitivity", sens.get("CRITICAL", 0))
        c3.metric("High sensitivity", sens.get("HIGH", 0))
        c4.metric("Unexpected for purpose",
                  sum(1 for v in verdicts.values() if v == "UNEXPECTED"))
        c5.metric("Unknown to knowledge base",
                  sum(1 for p in m.permissions if not p.known_to_android))

        st.caption(
            "Sensitivity = PermissionGuard's privacy-risk tier (NOT the same as "
            "Android's official protection level, shown separately)."
        )
        st.divider()

        v_filter = st.multiselect(
            "Filter by purpose verdict",
            ["JUSTIFIED", "PLAUSIBLE", "UNEXPECTED", "UNDETERMINED"],
            default=[],
        )
        for p in sorted(m.permissions, key=lambda x: (
                {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3, "NONE": 4}
                [x.sensitivity.value], x.name)):
            v = verdicts.get(p.name, "UNDETERMINED")
            if v_filter and v not in v_filter:
                continue
            c = compat_by_perm.get(p.name)
            vcolor = {"JUSTIFIED": "#43A047", "PLAUSIBLE": "#F9A825",
                      "UNEXPECTED": "#B71C1C", "UNDETERMINED": "#78909C"}[v]
            with st.container(border=True):
                a, b = st.columns([4, 1])
                with a:
                    st.markdown(
                        f"**{p.name}** "
                        f'<span class="pg-badge" style="background:{vcolor};font-size:.7rem">'
                        f'{v}</span> '
                        f'<span class="pg-badge" style="background:'
                        f'{_SEV_HEX.get(p.sensitivity.value, "#90CAF9")};'
                        f'font-size:.7rem;color:#212121">{p.sensitivity.value}</span>',
                        unsafe_allow_html=True,
                    )
                    st.caption(p.description or "No description available.")
                    cols = st.columns([1, 1, 1])
                    cols[0].markdown(
                        f"<small>Android protection: **{p.protection_level.value}**"
                        f" · {p.runtime_category.value}</small>", unsafe_allow_html=True)
                    cols[1].markdown(
                        f"<small>Data: {p.data_or_functionality or '—'}</small>",
                        unsafe_allow_html=True)
                    cols[2].markdown(
                        f"<small>Source: {p.source}"
                        f"{' · not in KB' if not p.known_to_android else ''}</small>",
                        unsafe_allow_html=True)
                    if c and c.rationale:
                        st.markdown(f"<small><b>Why:</b> {c.rationale}</small>",
                                    unsafe_allow_html=True)
                    if p.alternatives:
                        st.markdown(
                            f"<small><b>Less intrusive:</b> {'; '.join(p.alternatives[:2])}</small>",
                            unsafe_allow_html=True)
                with b:
                    if p.doc_urls:
                        st.link_button("Android docs ↗", p.doc_urls[0],
                                       width="stretch")

        st.divider()
        with st.expander("Declared components (escalation-relevant)"):
            if m.components:
                for comp in m.components:
                    exp = comp.exported
                    flag = "exported" if exp else ("not exported" if exp is False else "default")
                    perm = f" · gated by `{comp.permission}`" if comp.permission else ""
                    st.markdown(
                        f"- **{comp.type}** `{comp.name}` — {flag}{perm}"
                        + (f" · actions: {', '.join(comp.actions[:3])}" if comp.actions else "")
                    )
            else:
                st.caption("No components declared.")


# ===========================================================================
# POLICY ANALYSIS
# ===========================================================================
elif tool_page == "Policy Analysis":
    st.markdown('<p class="pg-title">Policy Analysis</p>', unsafe_allow_html=True)
    st.markdown(
        '<p class="pg-sub">Google Play policy, OWASP-informed checks, and your '
        'organisation\'s policy — kept clearly separate. <b>NEEDS REVIEW / '
        'INSUFFICIENT EVIDENCE</b> mean the APK alone cannot prove compliance.</p>',
        unsafe_allow_html=True,
    )
    if result is None:
        st.info("Run a scan first (Overview tab).")
    else:
        r = result
        groups = [
            ("google_play", "Google Play Policy",
             "Official policy requirements (support.google.com)"),
            ("owasp_informed", "OWASP-informed Checks",
             "Application-specific rules informed by OWASP MASVS-PRIVACY / "
             "MASWE-0066 — NOT official OWASP automated tests"),
            ("org_policy", "Organisational Policy",
             "Your organisation's configured rules (config/orgpolicy.yaml)"),
            ("combination", "Suspicious Combinations",
             "Indicators for further review — NOT proof of malicious behaviour"),
        ]
        tabs = st.tabs([g[1].split(" ", 1)[1] for g in groups])
        for tab, (fw, title, blurb) in zip(tabs, groups):
            with tab:
                st.caption(blurb)
                items = [f for f in r.findings if f.source_framework == fw]
                if not items:
                    st.success("No findings from this framework.")
                    continue
                items.sort(key=lambda f: (
                    {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
                    [f.severity.value], f.rule_id))
                status_counts: dict[str, int] = {}
                for f in items:
                    k = f.assessment_status.value
                    status_counts[k] = status_counts.get(k, 0) + 1
                st.caption(" · ".join(
                    f"{_STATUS_LABEL.get(k, k)}: {v}"
                    for k, v in sorted(status_counts.items())
                ))
                findings_html = "".join(_render_finding_accordion_html(f) for f in items)
                st.markdown(findings_html, unsafe_allow_html=True)



# ===========================================================================
# RISK ANALYSIS
# ===========================================================================
elif tool_page == "Risk Analysis":
    st.markdown('<p class="pg-title">Risk Analysis</p>', unsafe_allow_html=True)
    if result is None:
        st.info("Run a scan first (Overview tab).")
    else:
        r = result
        c1, c2 = st.columns([1, 1])
        with c1:
            _score_gauge(r)
        with c2:
            _severity_gauge(r)

        st.markdown(f"**Method:** {r.risk.method}")
        if r.risk.capped_findings:
            for note in r.risk.capped_findings:
                st.warning(f"Score floor applied — {note}")
        if r.risk.deduplicated_findings:
            st.caption(
                "Anti-double-counting: these correlated findings were counted "
                "once at their highest weight: "
                + "; ".join(r.risk.deduplicated_findings[:6])
            )

        st.subheader("Score contributions (every point explained)")
        bd_rows = []
        for b in r.risk.breakdown:
            bd_rows.append({
                "Rule": b.rule_id,
                "Finding": b.label[:70],
                "Severity": b.severity.value,
                "Raw": b.raw_points,
                "Applied": b.applied_points,
                "Why": b.reason[:120],
            })
        st.dataframe(bd_rows, width="stretch", height=320,
                     hide_index=True)
        st.caption(
            f"Thresholds: LOW 0–{r.risk.thresholds.get('low_max', 29):.0f} · "
            f"MEDIUM 30–{r.risk.thresholds.get('medium_max', 59):.0f} · "
            f"HIGH 60–100 · raw total before clamp/floor: "
            f"{r.risk.thresholds.get('raw_total', '—')}"
        )

        st.subheader("Suspicious permission combinations")
        combos = [f for f in r.findings if f.category == "combination"]
        if not combos:
            st.success("No suspicious combinations detected.")
        else:
            combos_html = "".join(_render_finding_accordion_html(f) for f in combos)
            st.markdown(combos_html, unsafe_allow_html=True)

        st.subheader("Confidence & uncertainty")
        conf = {}
        for f in r.findings:
            conf[f.confidence.value] = conf.get(f.confidence.value, 0) + 1
        st.bar_chart(conf) if conf else st.caption("—")
        needs = [f for f in r.findings if f.assessment_status in (
            AssessmentStatus.NEEDS_REVIEW, AssessmentStatus.INSUFFICIENT_EVIDENCE)]
        if needs:
            st.warning(
                f"{len(needs)} finding(s) depend on evidence outside the APK "
                "(store listing, Data Safety form, in-app disclosures, runtime "
                "behaviour) and are reported as NEEDS REVIEW / INSUFFICIENT "
                "EVIDENCE rather than as violations."
            )


# ===========================================================================
# REMEDIATION
# ===========================================================================
elif tool_page == "Remediation":
    st.markdown('<p class="pg-title">Remediation — Prioritised Actions</p>',
                unsafe_allow_html=True)
    if result is None:
        st.info("Run a scan first (Overview tab).")
    elif not result.recommendations:
        st.success("No corrective actions required.")
    else:
        r = result
        st.caption(
            "Ordered by impact: REVOKE (remove) → RESTRICT → REPLACE (with a "
            "less-intrusive alternative) → REVIEW / DOCUMENT."
        )
        counts: dict[str, int] = {}
        for rec in r.recommendations:
            counts[rec["action"]] = counts.get(rec["action"], 0) + 1
        cols = st.columns(len(counts))
        for col, (act, n) in zip(cols, sorted(counts.items())):
            col.metric(act, n)

        st.divider()
        for rec in r.recommendations:
            color = {"REVOKE": "#B71C1C", "RESTRICT": "#E65100",
                     "REPLACE": "#F9A825", "REVIEW": "#1565C0",
                     "DOCUMENT": "#6A1B9A"}.get(rec["action"], "#546E7A")
            with st.container(border=True):
                st.markdown(
                    f'<span class="pg-badge" style="background:{color}">'
                    f'{rec["action"]}</span> &nbsp; '
                    f'<b>{rec["order"]}. {rec["title"]}</b> &nbsp; '
                    f'<small style="color:#78909C">({rec["severity"]})</small>',
                    unsafe_allow_html=True,
                )
                if rec.get("detail"):
                    st.markdown(f"<small>{rec['detail'][:500]}</small>",
                                unsafe_allow_html=True)
                if rec.get("affected_permissions"):
                    st.caption("Permissions: " + ", ".join(rec["affected_permissions"]))
                if rec.get("alternatives"):
                    st.markdown(
                        f"**Less-intrusive alternative:** "
                        f"{'; '.join(rec['alternatives'][:3])}"
                    )
                fr = rec.get("finding_ref", {})
                if fr:
                    st.caption(
                        f"Traceability: {fr.get('rule_id')} · "
                        f"{fr.get('source_framework')} · {fr.get('status')}"
                    )

        needs = [f for f in r.findings
                 if f.assessment_status in (AssessmentStatus.NEEDS_REVIEW,
                                            AssessmentStatus.INSUFFICIENT_EVIDENCE)]
        if needs:
            st.divider()
            st.subheader("Manual review requirements")
            st.caption(
                "These cannot be resolved from the APK alone and need human "
                "evidence — flag them for your review process:"
            )
            for f in needs:
                st.markdown(f"- **{f.rule_id}** — {f.title}")


# ===========================================================================
# COMPARISON
# ===========================================================================
elif tool_page == "Comparison":
    st.markdown('<p class="pg-title">Compare Analysed Applications</p>',
                unsafe_allow_html=True)
    rows = store.list_scans()
    if not rows:
        st.info("No stored scans yet. Run an analysis — each scan is saved "
                "locally so you can compare apps here.")
    else:
        st.caption(
            f"{len(rows)} scan(s) stored locally in `data/scans.db` "
            "(gitignored)."
        )
        _history_charts(rows)

        c1, c2, c3 = st.columns([2, 1, 1])
        with c1:
            min_score = st.slider("Minimum risk score", 0, 100, 0)
        with c2:
            level_f = st.multiselect("Risk level", ["LOW", "MEDIUM", "HIGH"],
                                     default=[])
        with c3:
            sev_f = st.multiselect("Has findings",
                                   ["CRITICAL", "HIGH"], default=[])

        filtered = [r for r in rows if (r["risk_score"] or 0) >= min_score]
        if level_f:
            filtered = [r for r in filtered if r["risk_level"] in level_f]
        if sev_f:
            if "CRITICAL" in sev_f:
                filtered = [r for r in filtered if (r["critical_count"] or 0) > 0]
            if "HIGH" in sev_f:
                filtered = [r for r in filtered if (r["high_count"] or 0) > 0]

        st.dataframe(
            [{
                "Scan": r["scan_id"],
                "When": (r["scanned_at"] or "")[:19],
                "App": r["app_label"] or r["package_name"] or r["filename"],
                "Category": r["category"],
                "Score": r["risk_score"],
                "Level": r["risk_level"],
                "Depth": r["scan_depth"],
                "Perms": r["permission_count"],
                "Findings": r["finding_count"],
                "Critical": r["critical_count"],
                "High": r["high_count"],
            } for r in filtered],
            width="stretch", hide_index=True,
        )
        st.caption(
            "Compare a legitimate app against an over-privileged one: the "
            "score gap shows how much excessive privilege changes the risk."
        )
        with st.expander("Delete a specific scan"):
            sid = st.selectbox("Scan ID", [r["scan_id"] for r in rows])
            if st.button("Delete selected scan"):
                store.delete(sid)
                st.success("Deleted.")
                st.rerun()
        st.divider()
        if st.button("Delete all stored scans", key="del_all"):
            n = store.delete_all()
            st.success(f"Deleted {n} stored scan(s).")
            st.rerun()


# ===========================================================================
# EXPORT
# ===========================================================================
else:  #  Export
    st.markdown('<p class="pg-title">Export Report</p>', unsafe_allow_html=True)
    if result is None:
        st.info("Run a scan first (Overview tab).")
    else:
        r = result
        st.markdown(
            '<div class="pg-disc"><b>Disclaimer:</b> ' + _DISCLAIMER + '</div>',
            unsafe_allow_html=True,
        )
        st.caption(
            f"Report includes: executive summary, metadata, permission "
            f"inventory, purpose-compatibility, Google Play assessment, "
            f"OWASP-informed findings, org-policy results, combinations, "
            f"score breakdown, evidence & source links, confidence/"
            f"uncertainty, prioritised corrective actions, testing "
            f"limitations, rule versions ({', '.join(r.rule_versions.values())})."
        )

        c1, c2, c3 = st.columns(3)
        with c1:
            
            
            if st.button("Generate PDF", type="primary",
                         width="stretch"):
                with st.spinner("Building PDF…"):
                    tmp = os.path.join(tempfile.gettempdir(), "permguard_reports")
                    path = to_pdf(r, os.path.join(tmp, f"{r.scan_id}.pdf"))
                    with open(path, "rb") as fh:
                        st.download_button(
                            ":material/download: Download PDF", fh.read(),
                            file_name=f"permguard_{r.scan_id}.pdf",
                            mime="application/pdf",
                            width="stretch",
                        )
                st.success("PDF ready — click to download.")
        with c2:
            
            
            st.download_button(
                ":material/download: Download JSON", to_json(r),
                file_name=f"permguard_{r.scan_id}.json",
                mime="application/json", width="stretch",
            )
        with c3:
            
            
            st.download_button(
                ":material/download: Download CSV", to_csv(r),
                file_name=f"permguard_{r.scan_id}.csv",
                mime="text/csv", width="stretch",
            )

        st.divider()
        st.subheader("Preview — PDF content order")
        st.markdown(
            """
1. **Header** — title, timestamp, scan ID, depth
2. **Score badge** — 0–100 + risk level + app metadata
3. **Executive summary** — severity counters + score explanation
4. **Purpose & compatibility** — unexpected permissions with rationale
5. **Findings, priority-ordered** — CRITICAL → HIGH → MEDIUM → LOW → PASSED
   (colour chip, framework, rule ID, confidence, evidence, action)
6. **Prioritised corrective actions** — revoke/restrict/replace/review + alternatives
7. **Score breakdown** — every contribution and why
8. **Sources, versions & testing limitations**
9. **Disclaimer**
        """
        )


# Same-page About and Contact sections follow the analyzer and report workflow.
st.markdown('<section class="pg-section pg-frame" id="about"><div><p class="pg-eyebrow">ABOUT PERMGUARD</p><h2>Privacy should be understandable.</h2><p class="pg-lead">PermGuard turns technical permission data into clear, useful privacy insights.</p></section>',unsafe_allow_html=True)
st.markdown('<section class="pg-section pg-frame pg-frame-contact" id="contact"><div><p class="pg-eyebrow">CONTACT</p><h2>Questions about privacy?</h2><p class="pg-lead">Feedback or questions? Send us a message.</p></div></section>',unsafe_allow_html=True)
with st.form("contact_form"):
    name=st.text_input("Name")
    email=st.text_input("Email")
    message=st.text_area("Message",height=120)
    submitted=st.form_submit_button("Send Message")
if submitted:
    if not name.strip() or not _re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+",email.strip()) or not message.strip():
        st.error("Enter your name, a valid email address, and a message.")
    else:
        st.info("The contact form is validated, but no message service is configured for this project yet. Your message has not been sent.")
st.markdown('<footer class="pg-section pg-frame pg-frame-footer"><div><b>PermGuard</b><p class="pg-principle">Android permission analysis, made understandable.</p><p><a href="#home">Home</a> · <a href="#about">About Us</a> · <a href="#contact">Contact</a> · <a href="#analyze">Analyze</a></p><small>Copyright 2026 PermGuard.</small></div></footer>',unsafe_allow_html=True)
