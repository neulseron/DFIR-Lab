# dashboard/views/timeline.py

import streamlit as st

from .common import load_timeline_df, show_missing_file_warning
from components import render_badge_table


def render_timeline():
    st.title("Timeline")

    df = load_timeline_df()

    if df.empty:
        show_missing_file_warning("timeline.csv")
        return

    st.caption("시간순으로 재구성한 DFIR 타임라인입니다.")

    col1, col2, col3 = st.columns(3)

    stage_filter = col1.multiselect(
        "Stage",
        sorted(df["stage"].dropna().unique()) if "stage" in df.columns else [],
    )

    severity_filter = col2.multiselect(
        "Severity",
        sorted(df["severity"].dropna().unique()) if "severity" in df.columns else [],
    )

    source_filter = col3.multiselect(
        "Source",
        sorted(df["source"].dropna().unique()) if "source" in df.columns else [],
    )

    filtered = df.copy()

    if stage_filter:
        filtered = filtered[filtered["stage"].isin(stage_filter)]

    if severity_filter:
        filtered = filtered[filtered["severity"].isin(severity_filter)]

    if source_filter:
        filtered = filtered[filtered["source"].isin(source_filter)]

    st.metric("Filtered Timeline Events", len(filtered))

    columns = [
        "order",
        "timestamp",
        "stage",
        "severity",
        "action",
        "source",
        "event_id",
        "evidence_id",
    ]

    display_columns = [c for c in columns if c in filtered.columns]

    rows = filtered[display_columns].to_dict("records")
    render_badge_table(
        rows=rows,
        columns=display_columns,
        badge_columns={"severity"},
        right_columns={"order", "event_id"},
        column_widths={
            "order": "55px",
            "timestamp": "170px",
            "stage": "150px",
            "severity": "95px",
            "action": "260px",
            "source": "90px",
            "event_id": "80px",
            "evidence_id": "105px",
            "ioc_refs": "260px",
            "mitre_tactic": "150px",
            "mitre_technique": "140px",
        },
    )

    st.divider()

    st.subheader("Timeline Detail")

    if "evidence_id" in filtered.columns and not filtered.empty:
        selected = st.selectbox(
            "Evidence ID",
            filtered["evidence_id"].dropna().unique(),
        )

        row = filtered[filtered["evidence_id"] == selected].iloc[0].to_dict()

        st.json(row)