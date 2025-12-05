#!/usr/bin/env python3
"""app_streamlit.py — Clean Streamlit dashboard (rewritten)

Features:
- Simple login using auth.json (SHA256 hashed passwords). Falls back to admin/admin if missing.
- Clean white UI (no custom color themes).
- Improved table rendering via nice_table() (zebra rows, spacing).
- Shows summary, prioritized testing path (with MITRE IDs), hosts & services, and actions.
- Safe Streamlit rerun handling for different versions.
- Loads refined_report.json by default or allows upload.
"""

import streamlit as st
import argparse
from pathlib import Path
import json
import hashlib
import pandas as pd
from datetime import datetime

# ---------------- CLI args ----------------
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('-i', '--input', default='refined_report.json', help='Refined JSON report file')
known_args, _ = parser.parse_known_args()
INPUT_FILE = known_args.input

# ---------------- Auth helpers ----------------
AUTH_FILE = Path(__file__).parent / 'auth.json'

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode('utf-8')).hexdigest()

def load_auth():
    if AUTH_FILE.exists():
        try:
            return json.loads(AUTH_FILE.read_text(encoding='utf-8'))
        except Exception:
            return None
    return None

def default_demo_auth():
    return {'users': {'admin': sha256_hex('admin')}}  # admin/admin fallback

_auth_cfg = load_auth() or default_demo_auth()

def authenticate(username: str, password: str) -> bool:
    if not username or not password:
        return False
    users = _auth_cfg.get('users', {})
    hashed = users.get(username)
    if not hashed:
        return False
    return sha256_hex(password) == hashed

# ---------------- Session state init ----------------
st.set_page_config(page_title='Refined Scan Report — MITRE', layout='wide')
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'user' not in st.session_state:
    st.session_state.user = ''

# ---------------- Nice table renderer ----------------
def nice_table(df: pd.DataFrame, height: int = 300):
    """Render a clean table: padded cells, zebra rows, hover — uses st.dataframe for interactivity."""
    st.markdown(
        """
        <style>
        .nice-table table { border-collapse: separate; border-spacing: 0 6px; width: 100%; }
        .nice-table th { background-color: #f7f7f7; font-weight:700; padding:8px 10px; border-bottom:1px solid #ddd; text-align:left; }
        .nice-table td { padding:8px 10px; background: #fff; border-bottom:1px solid #eee; color: #111; }
        .nice-table tr:nth-child(even) td { background: #fbfbfb; }
        .nice-table tr:hover td { background: #f0f0f0; }
        </style>
        """, unsafe_allow_html=True)
    st.markdown('<div class="nice-table">', unsafe_allow_html=True)
    try:
        st.dataframe(df, height=height, use_container_width=True)
    except Exception:
        st.table(df)
    st.markdown('</div>', unsafe_allow_html=True)

# ---------------- Login UI ----------------
def login_form():
    st.markdown("## Refined Scan Report — MITRE (Login)")
    with st.form('login_form'):
        username = st.text_input('Username')
        password = st.text_input('Password', type='password')
        submit = st.form_submit_button('Sign in')
        if submit:
            if authenticate(username, password):
                st.session_state.authenticated = True
                st.session_state.user = username
                try:
                    st.experimental_rerun()
                except Exception:
                    # best-effort fallback: set a session flag and stop
                    try:
                        import time
                        st.session_state['_refresh'] = int(time.time())
                    except Exception:
                        pass
                    st.stop()
            else:
                st.error('Invalid username or password')

if not st.session_state.authenticated:
    login_form()
    st.stop()

# ---------------- Load report ----------------
def load_report(path: str):
    p = Path(path)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding='utf-8'))
        except Exception:
            return None
    return None

report = load_report(INPUT_FILE)
if report is None:
    st.warning(f'Could not load {INPUT_FILE}. You may upload a refined_report.json below.')
    uploaded = st.file_uploader('Upload refined_report.json', type=['json'])
    if uploaded is not None:
        try:
            report = json.load(uploaded)
            st.success('Report loaded from upload.')
        except Exception as e:
            st.error(f'Failed to parse uploaded JSON: {e}')
            st.stop()
    else:
        st.stop()
else:
    st.success(f'Loaded report: {INPUT_FILE}')

# ---------------- Header & summary ----------------
st.title('Refined Nmap / CVE Report — MITRE ATT&CK')
summary = report.get('summary', {})
generated_at = summary.get('generated_at', report.get('generated_at', 'n/a'))
host_count = summary.get('host_count', len(report.get('hosts', [])))
service_counts = summary.get('service_counts', {})

c1, c2, c3, c4 = st.columns([2,1,1,1])
c1.metric('Hosts', host_count)
c2.metric('High', service_counts.get('high', 0))
c3.metric('Medium', service_counts.get('medium', 0))
c4.metric('Low', service_counts.get('low', 0))

st.markdown(f"**Signed in as:** {st.session_state.user}  Generated: {generated_at}")
st.markdown('---')

# ---------------- Sidebar controls ----------------
with st.sidebar:
    st.header('Controls')
    min_risk = st.selectbox('Minimum risk', ['INFO','LOW','MEDIUM','HIGH'], index=1)
    search = st.text_input('Search (host/product/service)')
    show_playbooks = st.checkbox('Show MITRE playbooks', value=False, key='show_playbooks')
    # ensure consistent session state access
    try:
        st.session_state['show_playbooks'] = st.session_state.get('show_playbooks', False)
    except Exception:
        pass
    st.markdown('---')
    st.caption('Use this dashboard for triage only.')

# ---------------- Prioritized Testing Path ----------------
st.subheader('Prioritized Testing Path')
tp = report.get('testing_path', []) or []
df_tp = pd.DataFrame(tp)
if df_tp.empty:
    st.info('No testing_path entries found.')
else:
    # ensure columns exist
    for col in ['host','port','product','version','risk','risk_score','mitre_attack']:
        if col not in df_tp.columns:
            df_tp[col] = None

    # compute MITRE summary column robustly
    def mitre_summary(row):
        m = row.get('mitre_attack') if isinstance(row, dict) else row
        try:
            if isinstance(row, pd.Series):
                m = row.get('mitre_attack')
        except Exception:
            pass
        if m is None:
            return ''
        if isinstance(m, list):
            return ', '.join([str(x.get('id','')) for x in m if isinstance(x, dict)])
        if isinstance(m, str):
            return m
        return ''

    df_tp['MITRE'] = df_tp.apply(lambda r: mitre_summary(r), axis=1)

    # basic filtering
    if search:
        df_tp = df_tp[df_tp.apply(lambda r: search.lower() in str(r.values).lower(), axis=1)]

    risk_order = {'INFO':0,'LOW':1,'MEDIUM':2,'HIGH':3}
    df_tp['risk_rank'] = df_tp['risk'].map(risk_order).fillna(0).astype(int)
    df_tp = df_tp[df_tp['risk_rank'] >= risk_order.get(min_risk,1)]
    df_tp = df_tp.sort_values(by='risk_score', ascending=False)

    display_cols = ['host','port','product','version','risk','risk_score','MITRE']
    nice_table(df_tp[display_cols].reset_index(drop=True), height=360)

# ---------------- Hosts & Services ----------------
st.markdown('---')
st.subheader('Hosts and Services')

hosts = report.get('hosts', []) or []
for host in hosts:
    host_ip = host.get('ip')
    hostnames = ', '.join(host.get('hostnames',[]) or [])
    with st.expander(f"{host_ip} — {hostnames}"):
        services = host.get('services',[]) or []
        if services:
            svc_rows = []
            for s in services:
                svc_rows.append({
                    'port': s.get('port'),
                    'service': s.get('service_name'),
                    'product': s.get('product') or '',
                    'version': s.get('version') or '',
                    'risk': s.get('risk'),
                    'score': s.get('risk_score'),
                    'likely_vulnerable': bool(s.get('likely_vulnerable', False))
                })
            df_svcs = pd.DataFrame(svc_rows)
            nice_table(df_svcs, height=240)
        else:
            st.write('No services on this host.')

        # host-specific actions
        host_actions = [a for a in report.get('actions',[]) if a.get('target_host') == host_ip]
        if host_actions:
            st.markdown('**Top recommended actions for this host**')
            for p in ['High','Medium','Low']:
                items = [a for a in host_actions if a.get('priority')==p and a.get('do_or_not')=='Do']
                if not items:
                    continue
                st.markdown(f'**{p} priority**')
                for a in items:
                    with st.expander(f"{a.get('title')} — {a.get('service_name')}"):
                        st.write(f"Priority: {a.get('priority')}")
                        st.write(f"Risk: {a.get('risk')} (score {a.get('risk_score')})")
                        st.write(a.get('details'))
                        if a.get('mitre_attack'):
                            st.markdown('MITRE ATT&CK:')
                            for m in a.get('mitre_attack'):
                                st.write(f"- {m.get('id')} — {m.get('name')} ({m.get('tactic')})")
                                # Show detailed playbook steps when the sidebar checkbox is enabled
                                show_flag = st.session_state.get('show_playbooks', False)
                                if show_flag and m.get('playbook'):
                                    st.markdown('**Playbook (steps):**')
                                    for idx, step in enumerate(m.get('playbook', []), start=1):
                                        st.write(f"{idx}. {step}")
        st.markdown('---')

# ---------------- Actions & Download ----------------
st.subheader('All Actions')
actions_all = report.get('actions',[]) or []
if actions_all:
    df_actions = pd.DataFrame(actions_all)
    cols = ['target_host','target_port','service_name','title','priority','do_or_not','risk','risk_score']
    df_show = df_actions.reindex(columns=cols).fillna('')
    nice_table(df_show, height=300)
    st.download_button('Download actions JSON', data=json.dumps(actions_all, indent=2),
                       file_name=f"actions_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json",
                       mime='application/json')
else:
    st.info('No actions present in the report.')

st.caption('Triage dashboard only — do not attempt exploitation without authorization.')