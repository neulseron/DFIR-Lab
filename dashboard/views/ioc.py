# dashboard/views/ioc.py

import pandas as pd
import streamlit as st

from .common import get_processed_dir, load_json, show_missing_file_warning
from components import render_badge_table, ioc_type_label


# --------------------------------------------------
# 요약 표시
# --------------------------------------------------

IOC_TYPE_LABELS = {
    "command": "⌨️ 명령어",
    "domain": "🌐 도메인",
    "file_path": "📄 파일 경로",
    "hash": "#️⃣ 해시",
    "ip": "🖥️ IP",
    "process": "⚙️ 프로세스",
    "url": "🔗 URL",
    "user": "👤 사용자",
}

SEVERITY_LABELS = {
    "High": "HIGH",
    "Medium": "MEDIUM",
    "Low": "LOW",
    "Informational": "INFO",
}

def render_summary_list(title: str, data: dict, label_map: dict = None):
    label_map = label_map or {}

    st.markdown(f"**{title}**")

    if not data:
        st.caption("데이터 없음")
        return

    # count 기준 내림차순 정렬
    sorted_items = sorted(
        data.items(),
        key=lambda x: x[1],
        reverse=True,
    )

    for key, count in sorted_items:
        label = label_map.get(key, key)

        st.markdown(
            f"""
            <div style="
                display:flex;
                justify-content:space-between;
                align-items:center;
                padding:6px 10px;
                margin-bottom:5px;
                border:1px solid #e5e7eb;
                border-radius:8px;
                background-color:#f9fafb;
            ">
                <span style="font-weight:600; color:#374151;">{label}</span>
                <span style="
                    font-weight:700;
                    color:#111827;
                    background-color:#ffffff;
                    border:1px solid #e5e7eb;
                    border-radius:999px;
                    padding:2px 8px;
                    min-width:32px;
                    text-align:center;
                ">{count}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )


# --------------------------------------------------
# IOC 렌더링
# --------------------------------------------------


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
    with col2:
        render_summary_list(
            title="By Type",
            data=summary.get("by_type", {}),
            label_map=IOC_TYPE_LABELS,
        )
    with col3:
        render_summary_list(
            title="By Severity",
            data=summary.get("by_severity", {}),
            label_map=SEVERITY_LABELS,
        )

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
        "count",
        "first_seen",
        "last_seen",
    ]

    display_columns = [c for c in display_columns if c in filtered.columns]

    rows = filtered[display_columns].to_dict("records")
    render_badge_table(
        rows=rows,
        columns=display_columns,
        badge_columns={"severity"},
        right_columns={"count"},
        column_renderers={
            "type": ioc_type_label,
        },
        column_widths={
            "type": "95px",
            "value": "360px",
            "severity": "95px",
            "first_seen": "170px",
            "last_seen": "170px",
            "count": "70px",
            "related_evidence_ids": "260px",
        },
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