# dashboard/components/sidebar.py

from pathlib import Path

import streamlit as st


def render_sidebar() -> str:
    st.sidebar.title("DFIR Analysis Lab")

    st.sidebar.caption("Windows Endpoint Forensic Analysis")

    st.sidebar.divider()

    # Case 설정
    case_id = st.sidebar.text_input(
        "Case ID",
        value=st.session_state.get("case_id", "CASE-001"),
    )
    st.session_state.case_id = case_id.strip() or "CASE-001"

    data_root = st.sidebar.text_input(
        "Data Root",
        value=st.session_state.get("data_root", "data"),
    )
    st.session_state.data_root = data_root.strip() or "data"

    processed_dir = Path(st.session_state.data_root) / "processed" / st.session_state.case_id
    raw_dir = Path(st.session_state.data_root) / "raw" / st.session_state.case_id

    st.sidebar.markdown("### Case Path")
    st.sidebar.code(str(processed_dir), language="text")

    # 파일 존재 여부 표시
    st.sidebar.markdown("### Data Status")

    status_files = {
        "events": processed_dir / "events.jsonl",
        "evidence": processed_dir / "evidence.json",
        "iocs": processed_dir / "iocs.json",
        "timeline": processed_dir / "timeline.json",
        "report": processed_dir / "report.md",
        "metadata": raw_dir / "case_metadata.json",
    }

    for name, path in status_files.items():
        if path.exists():
            st.sidebar.success(f"{name}")
        else:
            st.sidebar.warning(f"{name}")

    st.sidebar.divider()

    menu = st.sidebar.radio(
        "Menu",
        ["홈", "타임라인", "IOC", "증거", "리포트"],
        index=0,
    )

    st.sidebar.divider()

    st.sidebar.markdown("### Analysis Flow")
    st.sidebar.markdown(
        """
        1. Event Normalize  
        2. Evidence Mapping  
        3. IOC Extraction  
        4. Timeline Build  
        5. Report Generate  
        """
    )

    return menu