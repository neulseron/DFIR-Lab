# dashboard/views/hayabusa.py

import streamlit as st

from components import render_badge_table, stage_label, spacer, dashed_divider, soft_divider
from .common import (
    get_case_id,
    get_raw_dir,
    get_processed_dir,
    get_raw_hayabusa_csv_path,
    get_hayabusa_dir,
    get_hayabusa_findings_path,
    get_hayabusa_summary_path,
    get_hayabusa_timeline_matches_path,
    get_hayabusa_coverage_path,
    load_json,
    show_missing_file_warning,
)


def render_hayabusa():
    st.title("🛠️ Hayabusa")
    st.caption("Filter Window: (Timeline first_seen - 5min) ~ (Timeline last_seen + 5min)")

    st.divider()

    hayabusa_findings = load_json(get_hayabusa_findings_path(), default={})
    findings = hayabusa_findings.get("findings", [])
    summary = hayabusa_findings.get("summary", {})


    st.markdown("#### Filter Status")

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Raw Total", summary.get("raw_total", "-"))
    with c2:
        st.metric("Filtered Total", summary.get("filtered_total", summary.get("total", "-")))
    with c3:
        st.metric("Filter Applied", summary.get("filter_applied", "-"))
    with c4:
        st.metric("Margin", f"{summary.get('filter_margin_minutes', '-')} min")

    st.caption(
        f"Filter Range: {summary.get('filter_start', '-')} ~ {summary.get('filter_end', '-')}"
    )



    if findings:
        st.markdown("#### Hayabusa Findings")

        display_rows = []

        for item in findings[:300]:
            display_rows.append({
                "hayabusa_id": item.get("hayabusa_id"),
                "timestamp": item.get("timestamp"),
                "level": item.get("level"),
                "rule_title": item.get("rule_title"),
                "channel": item.get("channel"),
                "event_id": item.get("event_id"),
                "computer": item.get("computer"),
            })

        render_badge_table(
            rows=display_rows,
            columns=[
                "hayabusa_id",
                "timestamp",
                "level",
                "rule_title",
                "channel",
                "event_id",
                "computer",
            ],
            badge_columns={"level"},
            right_columns={"event_id"},
            column_widths={
                "hayabusa_id": "105px",
                "timestamp": "180px",
                "level": "95px",
                "rule_title": "360px",
                "channel": "150px",
                "event_id": "80px",
                "computer": "150px",
            },
        )



    
    coverage_path = get_processed_dir() / "hayabusa" / "hayabusa_coverage.json"
    coverage = load_json(coverage_path, default={})

    if coverage:
        st.markdown("#### Coverage Comparison")
        with st.expander("Both - 자체 룰과 Hayabusa 모두 탐지"):
            render_badge_table(
                rows=coverage.get("both", [])[:100],
                columns=[
                    "evidence_id",
                    "timestamp",
                    "severity",
                    "stage",
                    "action",
                    "hayabusa_match_count",
                    "hayabusa_rules",
                ],
                badge_columns={"severity"},
                right_columns={"hayabusa_match_count"},
                column_widths={
                    "evidence_id": "105px",
                    "timestamp": "180px",
                    "severity": "95px",
                    "stage": "150px",
                    "action": "320px",
                    "hayabusa_match_count": "90px",
                    "hayabusa_rules": "360px",
                },
            )

        with st.expander("Internal Only - 자체 룰만 탐지"):
            render_badge_table(
                rows=coverage.get("internal_only", [])[:100],
                columns=[
                    "evidence_id",
                    "timestamp",
                    "severity",
                    "stage",
                    "action",
                ],
                badge_columns={"severity"},
                column_widths={
                    "evidence_id": "105px",
                    "timestamp": "180px",
                    "severity": "95px",
                    "stage": "150px",
                    "action": "420px",
                },
            )

        with st.expander("Hayabusa Only - Hayabusa만 탐지"):
            render_badge_table(
                rows=coverage.get("hayabusa_only", [])[:100],
                columns=[
                    "hayabusa_id",
                    "timestamp",
                    "level",
                    "rule_title",
                    "channel",
                    "event_id",
                ],
                badge_columns={"level"},
                right_columns={"event_id"},
                column_widths={
                    "hayabusa_id": "105px",
                    "timestamp": "180px",
                    "level": "95px",
                    "rule_title": "380px",
                    "channel": "150px",
                    "event_id": "80px",
                },
            )