# dashboard/views/home.py

import streamlit as st

from .common import (
    get_case_id,
    get_raw_dir,
    get_processed_dir,
    load_json,
    show_missing_file_warning,
)


def render_home():
    st.title("Windows Endpoint DFIR Dashboard")

    case_id = get_case_id()
    raw_dir = get_raw_dir()
    processed_dir = get_processed_dir()

    metadata = load_json(raw_dir / "case_metadata.json", default={})
    timeline = load_json(processed_dir / "timeline.json", default={})
    iocs = load_json(processed_dir / "iocs.json", default={})
    evidence = load_json(processed_dir / "evidence.json", default=[])

    if not timeline:
        show_missing_file_warning("timeline.json")
        return

    timeline_summary = timeline.get("summary", {})
    ioc_summary = iocs.get("summary", {})

    st.caption(f"Case ID: `{case_id}`")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Timeline Events", timeline_summary.get("total_events", 0))
    col2.metric("Evidence Items", len(evidence))
    col3.metric("IOC Candidates", ioc_summary.get("total", 0))
    col4.metric("Host", metadata.get("host", "-"))

    st.divider()

    st.subheader("Case Information")

    info_col1, info_col2 = st.columns(2)

    with info_col1:
        st.markdown("#### Collection")
        st.write(f"**User:** {metadata.get('user', '-')}")
        st.write(f"**Export Time:** {metadata.get('export_time', '-')}")
        st.write(f"**Start Time:** {metadata.get('start_time', timeline_summary.get('first_seen', '-'))}")
        st.write(f"**End Time:** {metadata.get('end_time', timeline_summary.get('last_seen', '-'))}")

    with info_col2:
        st.markdown("#### Summary")
        st.write(f"**First Seen:** {timeline_summary.get('first_seen', '-')}")
        st.write(f"**Last Seen:** {timeline_summary.get('last_seen', '-')}")
        st.write(f"**Sources:** {timeline_summary.get('by_source', {})}")
        st.write(f"**Severity:** {timeline_summary.get('by_severity', {})}")

    st.divider()

    st.subheader("Stage Summary")

    stage_summary = timeline.get("stage_summary", [])

    if stage_summary:
        st.dataframe(stage_summary, use_container_width=True)
    else:
        st.info("Stage summary가 없습니다.")