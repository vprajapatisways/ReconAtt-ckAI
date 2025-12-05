"""
ui_theme.py — Minimal Black & White Theme (apply_theme + style_dataframe)

This file provides:
 - apply_theme(): injects a minimal black & white theme, adds a Dark Mode toggle in the sidebar,
   and renders the header with a shield SVG logo and your branding text.
 - style_dataframe(df, height=300): renders a pandas DataFrame into styled HTML for consistent table visuals.
"""

import streamlit as st
import base64
import pandas as pd
import html

# Inline simple shield SVG (monochrome) as data URI
_SHIELD_SVG = """
<svg xmlns='http://www.w3.org/2000/svg' width='64' height='64' viewBox='0 0 24 24' fill='none' stroke='none'>
  <path d='M12 2l6 3v5c0 4-3 7-6 8-3-1-6-4-6-8V5l6-3z' fill='#ffffff' opacity='0.95'/>
  <circle cx='12' cy='11' r='2' fill='#000000'/>
</svg>
"""
_SHIELD_URI = "data:image/svg+xml;base64," + base64.b64encode(_SHIELD_SVG.encode("utf-8")).decode("utf-8")

_CSS_TEMPLATE = """
<style>
:root {
    --bg: #000000;
    --card: #0f0f0f;
    --text: #ffffff;
    --muted: #bfbfbf;
    --border: #222222;
    --accent: #ffffff;
}

/* Page background */
html, body, [class*="stApp"] {
    background: var(--bg) !important;
    color: var(--text) !important;
    font-family: "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}

div.block-container { padding-top: 1.2rem; padding-left:1.2rem; padding-right:1.2rem; }

/* Header block */
.ui-brand {
    display:flex;
    align-items:center;
    gap:14px;
    background: var(--card);
    padding:12px 16px;
    border-radius:8px;
    border: 1px solid var(--border);
    box-shadow: 0 6px 18px rgba(0,0,0,0.6);
}
.ui-brand img { width:56px; height:56px; border-radius:8px; }
.ui-brand h1 { margin:0; font-size:20px; color:var(--text); }
.ui-brand p { margin:0; font-size:13px; color:var(--muted); }

/* Table wrapper */
.table-wrap {
    background: var(--card);
    border-radius:8px;
    padding:8px;
    border: 1px solid var(--border);
}

/* Table styles */
.cyber-table { width:100%; border-collapse: collapse; font-size:14px; }
.cyber-table thead th {
    color: var(--text);
    background: transparent;
    padding:10px;
    border-bottom:1px solid var(--border);
    text-align:left;
}
.cyber-table tbody td {
    color: var(--text);
    padding:10px;
    border-bottom:1px solid var(--border);
}

/* Row hover */
.cyber-table tbody tr:hover td {
    background: #121212;
}

/* High risk left bar */
.cyber-table tbody tr.high-risk td {
    border-left: 4px solid #ff4444;
    background: #1a0000;
}

/* Metric style override */
.stMetric { color: var(--text) !important; }
</style>
"""

_LIGHT_CSS = """
<style>
:root { --bg:#ffffff; --card:#ffffff; --text:#111111; --muted:#666666; --border:#e6e6e6; }
html, body, [class*="stApp"] { background: var(--bg) !important; color: var(--text) !important; }
.ui-brand { background: var(--card); border:1px solid var(--border); }
.table-wrap { background: var(--card); border:1px solid var(--border); }
.cyber-table thead th { background: #f7f7f7; color: var(--text); }
.cyber-table tbody td { color: var(--text); }
</style>
"""

def _inject_css(dark: bool = True):
    if dark:
        st.markdown(_CSS_TEMPLATE, unsafe_allow_html=True)
    else:
        st.markdown(_LIGHT_CSS, unsafe_allow_html=True)

def apply_theme(title_text: str = "Refined Nmap / CVE Report — MITRE ATT&CK", owner_text: str = "Vaibhav Security Dashboard"):
    """
    Injects theme CSS and renders the header. Call this after login (once) in your main app.
    """
    if "dark_mode" not in st.session_state:
        st.session_state.dark_mode = True

    with st.sidebar:
        st.markdown("### Theme")
        st.session_state.dark_mode = st.checkbox("Dark mode (black & white)", value=st.session_state.dark_mode, key="ui_theme_dark_mode")

    return

    # Header with logo and branding
    logo_html = f"<img src='{_SHIELD_URI}' alt='logo' />"
    header_html = f"""
    <div class='ui-brand'>
        {logo_html}
        <div>
            <h1>{html.escape(title_text)}</h1>
            <p class='small'>{html.escape(owner_text)}</p>
        </div>
    </div>
    """
    st.markdown(header_html, unsafe_allow_html=True)
    st.write("")

def style_dataframe(df: pd.DataFrame, height: int = 300):
    """
    Render a pandas DataFrame with simple black & white styles.
    """
    if df is None or df.empty:
        st.write("(no data)")
        return

    # Build HTML rows
    rows = []
    for _, r in df.iterrows():
        risk = str(r.get('risk') or "").upper()
        cls = "high-risk" if risk == "HIGH" else ""
        cells = "".join([f"<td>{html.escape(str(r.get(c, '')))}</td>" for c in df.columns])
        rows.append(f"<tr class='{cls}'>{cells}</tr>")

    thead = "<thead><tr>" + "".join([f"<th>{html.escape(str(c))}</th>" for c in df.columns]) + "</tr></thead>"
    tbody = "<tbody>" + "".join(rows) + "</tbody>"
    table_html = f"<div class='table-wrap'><table class='cyber-table'>{thead}{tbody}</table></div>"

    wrapper = f"<div style='max-height:{height}px; overflow:auto; padding-right:6px;'>{table_html}</div>"
    st.components.v1.html(wrapper, height=min(height + 40, 800), scrolling=True)
