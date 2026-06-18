# dashboard/views/evidence.py

import streamlit as st

from .common import load_evidence_df, show_missing_file_warning
from components import render_badge_table, evidence_type_label


def render_evidence():
    st.title("Evidence")

    df = load_evidence_df()

    if df.empty:
        show_missing_file_warning("evidence.json")
        return

    st.caption("정규화 이벤트를 포렌식 증거 관점으로 분류한 결과입니다.")

    col1, col2, col3 = st.columns(3)

    type_filter = col1.multiselect(
        "Evidence Type",
        sorted(df["evidence_type"].dropna().unique()) if "evidence_type" in df.columns else [],
    )

    stage_filter = col2.multiselect(
        "Attack Stage",
        sorted(df["attack_stage"].dropna().unique()) if "attack_stage" in df.columns else [],
    )

    severity_filter = col3.multiselect(
        "Severity",
        sorted(df["severity"].dropna().unique()) if "severity" in df.columns else [],
    )

    filtered = df.copy()

    if type_filter:
        filtered = filtered[filtered["evidence_type"].isin(type_filter)]

    if stage_filter:
        filtered = filtered[filtered["attack_stage"].isin(stage_filter)]

    if severity_filter:
        filtered = filtered[filtered["severity"].isin(severity_filter)]

    st.metric("Filtered Evidence", len(filtered))

    display_columns = [
        "evidence_id",
        "title",
        "evidence_type",
        "source",
        "event_id",
        "timestamp",
        "attack_stage",
        "severity",
    ]

    display_columns = [c for c in display_columns if c in filtered.columns]

    rows = filtered[display_columns].to_dict("records")
    render_badge_table(
        rows=rows,
        columns=display_columns,
        badge_columns={"severity"},
        column_renderers={
            "evidence_type": evidence_type_label,
        },
        column_widths={
            "evidence_id": "105px",
            "title": "220px",
            "evidence_type": "150px",
            "source": "90px",
            "event_id": "80px",
            "timestamp": "170px",
            "attack_stage": "150px",
            "severity": "95px",
            "summary": "360px",
        },
    )

    st.divider()

    st.subheader("Evidence Detail")

    if "evidence_id" in filtered.columns and not filtered.empty:
        selected = st.selectbox(
            "Evidence ID",
            filtered["evidence_id"].dropna().unique(),
        )

        row = filtered[filtered["evidence_id"] == selected].iloc[0].to_dict()

        st.markdown(f"### {row.get('title', '-')}")
        st.write(f"**Forensic Meaning:** {row.get('forensic_meaning', '-')}")
        st.write(f"**MITRE:** {row.get('mitre_tactic', '-')} / {row.get('mitre_technique', '-')}")
        st.write(f"**Summary:** {row.get('summary', '-')}")

        st.markdown("#### Rule Match Explanation")
        st.write(f"**Rule ID:** {row.get('rule_id', '-')}")
        st.write(f"**Matched Reason:** {row.get('matched_reason', '-')}")
        st.write(f"**Matched Fields:** {row.get('matched_fields', '-')}")
        st.write(f"**Matched Keywords:** {row.get('matched_keywords', '-')}")

        match_details = row.get("match_details", [])
        if isinstance(match_details, list) and match_details:
            st.dataframe(match_details, use_container_width=True)

        with st.expander("Raw Evidence Fields"):
            st.json(row)