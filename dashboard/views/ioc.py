# dashboard/views/ioc.py

import pandas as pd
import streamlit as st

from .common import get_processed_dir, load_json, show_missing_file_warning


def render_ioc():
    st.title("IOC")

    path = get_processed_dir() / "iocs.json"
    data = load_json(path, default={})

    if not data:
        show_missing_file_warning("iocs.json")
        return

    summary = data.get("summary", {})
    iocs = data.get("iocs", [])

    col1, col2, col3 = st.columns(3)

    col1.metric("Total IOC", summary.get("total", 0))
    col2.write("**By Type**")
    col2.json(summary.get("by_type", {}))
    col3.write("**By Severity**")
    col3.json(summary.get("by_severity", {}))

    st.divider()

    if not iocs:
        st.info("추출된 IOC가 없습니다.")
        return

    df = pd.DataFrame(iocs)

    col1, col2 = st.columns(2)

    type_filter = col1.multiselect(
        "IOC Type",
        sorted(df["type"].dropna().unique()) if "type" in df.columns else [],
    )

    severity_filter = col2.multiselect(
        "Severity",
        sorted(df["severity"].dropna().unique()) if "severity" in df.columns else [],
    )

    filtered = df.copy()

    if type_filter:
        filtered = filtered[filtered["type"].isin(type_filter)]

    if severity_filter:
        filtered = filtered[filtered["severity"].isin(severity_filter)]

    display_columns = [
        "type",
        "value",
        "severity",
        "first_seen",
        "last_seen",
        "count",
        "related_evidence_ids",
    ]

    display_columns = [c for c in display_columns if c in filtered.columns]

    st.dataframe(
        filtered[display_columns],
        use_container_width=True,
        hide_index=True,
    )

    st.divider()

    st.subheader("IOC Detail")

    if not filtered.empty:
        selected_value = st.selectbox(
            "IOC Value",
            filtered["value"].astype(str).tolist(),
        )

        selected_row = filtered[filtered["value"].astype(str) == selected_value].iloc[0].to_dict()
        st.json(selected_row)