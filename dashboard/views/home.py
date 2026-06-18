# dashboard/views/home.py
# streamlit run dashboard/app.py


import subprocess
import sys

import streamlit as st
from pathlib import Path
import pandas as pd

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


# --------------------------------------------------
# hayabusa
# --------------------------------------------------

def run_hayabusa_pipeline(project_root: Path, raw_dir: Path, processed_dir: Path, logs: list[str]):
    """
    data/raw/<CASE-ID>/hayabusa/hayabusa.csv가 있으면
    Hayabusa import → timeline correlation → coverage 계산을 수행한다.
    """

    raw_hayabusa_csv = raw_dir / "hayabusa" / "hayabusa.csv"

    if not raw_hayabusa_csv.exists():
        logs.append("\n===== hayabusa =====")
        logs.append(f"[SKIP] Hayabusa CSV not found: {raw_hayabusa_csv}")
        return

    hayabusa_dir = processed_dir / "hayabusa"
    hayabusa_dir.mkdir(parents=True, exist_ok=True)

    findings_path = hayabusa_dir / "hayabusa_findings.json"
    summary_path = hayabusa_dir / "hayabusa_summary.json"
    correlation_path = hayabusa_dir / "hayabusa_timeline_matches.json"
    coverage_path = hayabusa_dir / "hayabusa_coverage.json"

    timeline_path = processed_dir / "timeline.json"
    timeline_data = load_json(timeline_path, default={})
    timeline_summary = timeline_data.get("summary", {})

    case_start_time = timeline_summary.get("first_seen")
    case_end_time = timeline_summary.get("last_seen")
    logs.append("\n===== hayabusa filter range =====")
    logs.append(f"case_start_time: {case_start_time}")
    logs.append(f"case_end_time: {case_end_time}")

    importer_script = project_root / "analysis" / "hayabusa_importer.py"
    correlator_script = project_root / "analysis" / "hayabusa_correlator.py"
    coverage_script = project_root / "analysis" / "hayabusa_coverage.py"

    importer_cmd = [
        sys.executable,
        str(importer_script),
        "--csv", str(raw_hayabusa_csv),
        "--out-findings", str(findings_path),
        "--out-summary", str(summary_path),
    ]

    if case_start_time and case_end_time:
        importer_cmd.extend([
            "--start-time", str(case_start_time),
            "--end-time", str(case_end_time),
            "--time-margin-minutes", "5",
        ])

    commands = [importer_cmd]

    if timeline_path.exists():
        commands.append(
            [
                sys.executable,
                str(correlator_script),
                "--timeline", str(timeline_path),
                "--hayabusa", str(findings_path),
                "--out", str(correlation_path),
                "--window-seconds", "60",
            ]
        )

        commands.append(
            [
                sys.executable,
                str(coverage_script),
                "--correlation", str(correlation_path),
                "--hayabusa", str(findings_path),
                "--out", str(coverage_path),
            ]
        )

    for cmd in commands:
        result = subprocess.run(
            cmd,
            cwd=str(project_root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        script_name = Path(cmd[1]).name

        logs.append(f"\n===== {script_name} =====")

        if result.stdout:
            logs.append(result.stdout)

        if result.stderr:
            logs.append(result.stderr)

        if result.returncode != 0:
            raise RuntimeError(
                f"{script_name} 실행 실패\n\n" + "\n".join(logs)
            )


# --------------------------------------------------
# 위험도 계산
# --------------------------------------------------

def calculate_case_risk(evidence_items: list, iocs_data: dict, timeline_data: dict) -> dict:
    """
    포트폴리오/MVP용 Case 위험도 점수.
    실제 악성 여부 확정 점수가 아니라 분석 우선순위 점수로 사용한다.
    """

    evidence_weights = {
        "High": 18,
        "Medium": 8,
        "Low": 2,
        "Informational": 0,
    }

    ioc_weights = {
        "High": 6,
        "Medium": 3,
        "Low": 1,
        "Informational": 0,
    }

    evidence_score = 0
    evidence_breakdown = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
    }

    for ev in evidence_items:
        severity = ev.get("severity") or "Informational"
        evidence_breakdown[severity] = evidence_breakdown.get(severity, 0) + 1
        evidence_score += evidence_weights.get(severity, 0)

    # Evidence 점수가 너무 커지는 것을 방지
    evidence_score = min(evidence_score, 70)

    ioc_score = 0
    ioc_breakdown = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
    }

    for ioc in iocs_data.get("iocs", []):
        severity = ioc.get("severity") or "Informational"
        ioc_breakdown[severity] = ioc_breakdown.get(severity, 0) + 1
        ioc_score += ioc_weights.get(severity, 0)

    # IOC는 후보 지표이므로 점수 영향 제한
    ioc_score = min(ioc_score, 15)

    by_stage = timeline_data.get("summary", {}).get("by_stage", {})

    stage_bonus = 0
    stage_reasons = []

    if by_stage.get("Execution"):
        stage_bonus += 5
        stage_reasons.append("Execution stage observed")

    if by_stage.get("Discovery"):
        stage_bonus += 5
        stage_reasons.append("Discovery stage observed")

    if by_stage.get("Collection/Staging"):
        stage_bonus += 7
        stage_reasons.append("Collection/Staging stage observed")

    if by_stage.get("Network Activity") or by_stage.get("Command and Control"):
        stage_bonus += 8
        stage_reasons.append("Network/C2 related activity observed")

    if by_stage.get("Defense Evasion"):
        stage_bonus += 15
        stage_reasons.append("Defense Evasion activity observed")

    stage_bonus = min(stage_bonus, 25)

    total_score = min(100, evidence_score + ioc_score + stage_bonus)

    if total_score >= 80:
        level = "Critical"
        interpretation = "강한 침해 흐름 또는 고위험 증거가 확인되어 우선 분석이 필요합니다."
    elif total_score >= 60:
        level = "High"
        interpretation = "여러 단계의 의심 행위가 연결되어 높은 우선순위로 분석해야 합니다."
    elif total_score >= 30:
        level = "Medium"
        interpretation = "일부 의심 행위가 확인되었으며 추가 검토가 필요합니다."
    elif total_score > 0:
        level = "Low"
        interpretation = "낮은 수준의 이벤트가 관찰되었으나 명확한 침해 흐름은 제한적입니다."
    else:
        level = "None"
        interpretation = "위험도를 계산할 만한 증거가 부족합니다."

    return {
        "score": total_score,
        "level": level,
        "interpretation": interpretation,
        "evidence_score": evidence_score,
        "ioc_score": ioc_score,
        "stage_bonus": stage_bonus,
        "evidence_breakdown": evidence_breakdown,
        "ioc_breakdown": ioc_breakdown,
        "stage_reasons": stage_reasons,
    }


# --------------------------------------------------
# 분석 파일 재생성 
# --------------------------------------------------

def regenerate_analysis_files(case_id: str, data_root: str):
    """
    events.jsonl은 그대로 두고,
    evidence / iocs / timeline / report 파일만 재생성한다.
    """

    # home.py 위치: dashboard/views/home.py
    # project_root: DFIR-LAB/
    project_root = Path(__file__).resolve().parents[2]

    data_root_path = Path(data_root)
    if not data_root_path.is_absolute():
        data_root_path = (Path.cwd() / data_root_path).resolve()

    raw_dir = data_root_path / "raw" / case_id
    processed_dir = data_root_path / "processed" / case_id

    events_path = processed_dir / "events.jsonl"
    evidence_path = processed_dir / "evidence.json"
    iocs_path = processed_dir / "iocs.json"
    timeline_json_path = processed_dir / "timeline.json"
    timeline_csv_path = processed_dir / "timeline.csv"
    report_path = processed_dir / "report.md"
    metadata_path = raw_dir / "case_metadata.json"

    rules_path = project_root / "rules" / "evidence_rules.yaml"

    evidence_script = project_root / "analysis" / "evidence_mapper.py"
    ioc_script = project_root / "analysis" / "ioc_extractor.py"
    timeline_script = project_root / "analysis" / "timeline_builder.py"
    report_script = project_root / "analysis" / "report_generator.py"

    if not events_path.exists():
        raise FileNotFoundError(
            f"events.jsonl 파일이 없습니다: {events_path}\n"
            "먼저 normalize_events.py를 실행해야 합니다."
        )

    if not rules_path.exists():
        raise FileNotFoundError(f"evidence_rules.yaml 파일이 없습니다: {rules_path}")

    commands = [
        [
            sys.executable,
            str(evidence_script),
            "--events", str(events_path),
            "--rules", str(rules_path),
            "--out", str(evidence_path),
        ],
        [
            sys.executable,
            str(ioc_script),
            "--events", str(events_path),
            "--evidence", str(evidence_path),
            "--out", str(iocs_path),
        ],
        [
            sys.executable,
            str(timeline_script),
            "--evidence", str(evidence_path),
            "--iocs", str(iocs_path),
            "--out-json", str(timeline_json_path),
            "--out-csv", str(timeline_csv_path),
        ],
        [
            sys.executable,
            str(report_script),
            "--case-id", case_id,
            "--metadata", str(metadata_path),
            "--timeline", str(timeline_json_path),
            "--evidence", str(evidence_path),
            "--iocs", str(iocs_path),
            "--out", str(report_path),
        ],
    ]

    logs = []

    for cmd in commands:
        result = subprocess.run(
            cmd,
            cwd=str(project_root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        script_name = Path(cmd[1]).name

        logs.append(f"\n===== {script_name} =====")
        if result.stdout:
            logs.append(result.stdout)
        if result.stderr:
            logs.append(result.stderr)

        if result.returncode != 0:
            raise RuntimeError(
                f"{script_name} 실행 실패\n\n" + "\n".join(logs)
            )
        
    run_hayabusa_pipeline(
        project_root=project_root,
        raw_dir=raw_dir,
        processed_dir=processed_dir,
        logs=logs,
    )

    return "\n".join(logs)


# --------------------------------------------------
# 상단 요약카드 
# --------------------------------------------------

def render_status(item: dict):
    name = item.get("name", "-")
    exists = item.get("exists", False)
    path = item.get("path", "")

    status_icon = "🟢" if exists else "🔴"

    st.markdown(
        f"""
        <div style="
            display:flex;
            justify-content:space-between;
            align-items:center;
            padding:7px 10px;
            margin-bottom:6px;
            border:1px solid #e5e7eb;
            border-radius:8px;
            background-color:#f9fafb;
        ">
            <div style="display:flex; flex-direction:column;">
                <span style="font-weight:700; color:#374151;">{name}</span>
                <span style="font-size:0.75rem; color:#6b7280;">{path}</span>
            </div>
            {status_icon}
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_metric_card(title: str, value, delta: str = None, icon: str = "▶"):
    delta_html = ""
    if delta:
        delta_html = f"""
        <div style="
            margin-top:6px;
            font-size:0.85rem;
            font-weight:700;
            color:#4b5563;
        ">{delta}</div>
        """

    st.markdown(
        f"""
        <div style="
            border:1px solid #e5e7eb;
            border-radius:12px;
            padding:14px 16px;
            background-color:#ffffff;
            min-height:105px;
        ">
            <div style="
                font-size:1.02rem;
                font-weight:800;
                color:#374151;
                margin-bottom:8px;
                white-space:nowrap;
            ">{icon} {title}</div>
            <div style="
                font-size:1.65rem;
                font-weight:900;
                color:#111827;
                line-height:1.2;
                word-break:break-word;
            ">{value}</div>
            {delta_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


# --------------------------------------------------
# 홈 렌더링 
# --------------------------------------------------

def render_home():
    st.title("Windows Endpoint DFIR Dashboard")

    case_id = get_case_id()
    raw_dir = get_raw_dir()
    processed_dir = get_processed_dir()

    metadata = load_json(raw_dir / "case_metadata.json", default={})
    timeline = load_json(processed_dir / "timeline.json", default={})
    iocs = load_json(processed_dir / "iocs.json", default={})
    evidence = load_json(processed_dir / "evidence.json", default=[])
    hayabusa_summary = load_json(get_hayabusa_summary_path(), default={})
    hayabusa_findings = load_json(get_hayabusa_findings_path(), default={})

    if not timeline:
        show_missing_file_warning("timeline.json")
        return

    timeline_summary = timeline.get("summary", {})
    ioc_summary = iocs.get("summary", {})
    risk = calculate_case_risk(
        evidence_items=evidence,
        iocs_data=iocs,
        timeline_data=timeline,
    )

    st.markdown(f"## 📂 Case ID | `{case_id}`")

    status_title_col, regen_button_col = st.columns([7, 2])

    with status_title_col:
        st.markdown("### ▶ Data Status")

    with regen_button_col:
        regenerate_clicked = st.button(
            "분석 파일 재생성",
            use_container_width=True,
            help="events.jsonl은 유지하고 evidence, iocs, timeline, report 파일만 다시 생성합니다.",
        )

    if regenerate_clicked:
        try:
            with st.spinner("분석 파일을 재생성하는 중입니다..."):
                logs = regenerate_analysis_files(
                    case_id=st.session_state.case_id,
                    data_root=st.session_state.data_root,
                )

            st.success("분석 파일 재생성이 완료되었습니다.")

            with st.expander("실행 로그 보기", expanded=False):
                st.code(logs, language="text")

            st.rerun()

        except Exception as e:
            st.error("분석 파일 재생성 중 오류가 발생했습니다.")
            st.code(str(e), language="text")

    processed_dir = Path(st.session_state.data_root) / "processed" / st.session_state.case_id
    raw_dir = Path(st.session_state.data_root) / "raw" / st.session_state.case_id

    status_items = [
        {
            "name": "events",
            "exists": (processed_dir / "events.jsonl").exists(),
            "path": "processed/events.jsonl",
        },
        {
            "name": "evidence",
            "exists": (processed_dir / "evidence.json").exists(),
            "path": "processed/evidence.json",
        },
        {
            "name": "iocs",
            "exists": (processed_dir / "iocs.json").exists(),
            "path": "processed/iocs.json",
        },
        {
            "name": "timeline",
            "exists": (processed_dir / "timeline.json").exists(),
            "path": "processed/timeline.json",
        },
        {
            "name": "report",
            "exists": (processed_dir / "report.md").exists(),
            "path": "processed/report.md",
        },
        {
            "name": "metadata",
            "exists": (raw_dir / "case_metadata.json").exists(),
            "path": "raw/case_metadata.json",
        },
    ]

    status_col1, status_col2, status_col3, status_col4, status_col5, status_col6 = st.columns(6)

    with status_col1:
        render_status(status_items[0])
    with status_col2:
        render_status(status_items[1])
    with status_col3:
        render_status(status_items[2])
    with status_col4:
        render_status(status_items[3])
    with status_col5:
        render_status(status_items[4])
    with status_col6:
        render_status(status_items[5])

    spacer(20)
    dashed_divider()

    st.subheader("▶ Summary")

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        render_metric_card("Timeline Events", timeline_summary.get("total_events", 0), icon="🕒")

    with col2:
        render_metric_card("Evidence Items", len(evidence), icon="📁")

    with col3:
        render_metric_card("IOC Candidates", ioc_summary.get("total", 0), icon="🎯")

    with col4:
        render_metric_card("Host", metadata.get("host", "-"), icon="💻")

    with col5:
        render_metric_card("Case Risk", f"{risk['score']}/100", delta=risk["level"], icon="⚠️")

    spacer()

    st.subheader("▶ Case 정보")

    info_col1, info_col2, info_col3 = st.columns(3)

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
    
    with info_col3:
        st.markdown("#### Risk Score")
        st.metric("Case Risk Score", f"{risk['score']}/100", risk["level"])

        st.progress(risk["score"] / 100)

        st.write(f"**Interpretation:** {risk['interpretation']}")
        st.write(f"**Evidence Score:** {risk['evidence_score']}")
        st.write(f"**IOC Score:** {risk['ioc_score']}")
        st.write(f"**Stage Bonus:** {risk['stage_bonus']}")

        with st.expander("Risk Score Breakdown"):
            st.write("**Evidence Severity Count**")
            st.json(risk["evidence_breakdown"])

            st.write("**IOC Severity Count**")
            st.json(risk["ioc_breakdown"])

            st.write("**Stage Reasons**")
            if risk["stage_reasons"]:
                for reason in risk["stage_reasons"]:
                    st.write(f"- {reason}")
            else:
                st.write("- No stage bonus applied")


    st.subheader("▶ Stage Summary")

    stage_summary = timeline.get("stage_summary", [])

    if stage_summary:
        stage_rows = []

        for item in stage_summary:
            high_count = item.get("high_count", 0) or 0
            medium_count = item.get("medium_count", 0) or 0

            if high_count > 0:
                stage_severity = "High"
            elif medium_count > 0:
                stage_severity = "Medium"
            else:
                stage_severity = "Low"

            stage_rows.append({
                "stage": item.get("stage"),
                "severity": stage_severity,
                "count": item.get("count"),
                "first_seen": item.get("first_seen"),
                "last_seen": item.get("last_seen"),
                "high_count": high_count,
                "medium_count": medium_count,
                "representative_actions": "; ".join(item.get("representative_actions", [])),
            })

        render_badge_table(
            rows=stage_rows,
            columns=[
                "stage",
                "severity",
                "count",
                "first_seen",
                "last_seen",
                "high_count",
                "medium_count",
                "representative_actions",
            ],
            badge_columns={"severity"},
            right_columns={"count", "high_count", "medium_count"},
            column_renderers={
                "stage": stage_label,
            },
            column_widths={
                "stage": "170px",
                "severity": "95px",
                "count": "70px",
                "first_seen": "170px",
                "last_seen": "170px",
                "high_count": "80px",
                "medium_count": "95px",
                "representative_actions": "360px",
            },
        )
    else:
        st.info("Stage summary가 없습니다.")



    st.divider()

    st.subheader("🛠️ Hayabusa")
    spacer(30)

    hy_col1, hy_col2, hy_col3, hy_col4 = st.columns(4)

    with hy_col1:
        render_metric_card("Hayabusa Findings", hayabusa_summary.get("total", 0), icon="🦅")

    with hy_col2:
        render_metric_card("First Detection", hayabusa_summary.get("first_seen", "-"), icon="⏱️")

    with hy_col3:
        render_metric_card("Last Detection", hayabusa_summary.get("last_seen", "-"), icon="⏱️")

    with hy_col4:
        high_like = (
            hayabusa_summary.get("by_level", {}).get("Critical", 0)
            + hayabusa_summary.get("by_level", {}).get("High", 0)
        )
        render_metric_card("High+ Alerts", high_like, icon="🚨")

    spacer(50)

    coverage_path = get_processed_dir() / "hayabusa" / "hayabusa_coverage.json"
    coverage = load_json(coverage_path, default={})

    if coverage:
        st.markdown("#### Hayabusa Coverage Comparison")

        coverage_summary = coverage.get("summary", {})

        c1, c2, c3, c4, c5 = st.columns(5)

        with c1:
            render_metric_card("Both", coverage_summary.get("both", 0), icon="🔗")

        with c2:
            render_metric_card("Internal Only", coverage_summary.get("internal_only", 0), icon="🧩")

        with c3:
            render_metric_card("Hayabusa Only", coverage_summary.get("hayabusa_only", 0), icon="🦅")

        with c4:
            render_metric_card("Internal Total", coverage_summary.get("internal_total", 0), icon="📁")

        with c5:
            render_metric_card("Hayabusa Total", coverage_summary.get("hayabusa_total", 0), icon="📊")