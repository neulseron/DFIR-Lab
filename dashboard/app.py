# dashboard/app.py

import streamlit as st

from components import render_sidebar

from views.home import render_home
from views.timeline import render_timeline
from views.ioc import render_ioc
from views.evidence import render_evidence
from views.report import render_report

st.set_page_config(
    page_title="Windows Endpoint DFIR Lab",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------
# Session State
# -----------------------------

if "case_id" not in st.session_state:
    st.session_state.case_id = "CASE-001"

if "data_root" not in st.session_state:
    st.session_state.data_root = "data"

if "selected_evidence_id" not in st.session_state:
    st.session_state.selected_evidence_id = None

if "selected_ioc" not in st.session_state:
    st.session_state.selected_ioc = None


# -----------------------------
# Sidebar Navigation
# -----------------------------

menu = render_sidebar()

# -----------------------------
# Page Router
# -----------------------------

if menu == "홈":
    render_home()
elif menu == "타임라인":
    render_timeline()
elif menu == "IOC":
    render_ioc()
elif menu == "증거":
    render_evidence()
elif menu == "리포트":
    render_report()
else:
    render_home()