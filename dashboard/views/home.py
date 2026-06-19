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
                "--window-seconds", "100",
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
    evidence / iocs / timeline 파일만 재생성한다.
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

    rules_path = project_root / "rules" / "evidence_rules.yaml"

    evidence_script = project_root / "analysis" / "evidence_mapper.py"
    ioc_script = project_root / "analysis" / "ioc_extractor.py"
    timeline_script = project_root / "analysis" / "timeline_builder.py"

    case_summary_path = processed_dir / "case_summary.json"
    case_summary_script = project_root / "analysis" / "case_summary_generator.py"
    hayabusa_coverage_path = processed_dir / "hayabusa" / "hayabusa_coverage.json"


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

    summary_cmd = [
        sys.executable,
        str(case_summary_script),
        "--case-id", case_id,
        "--timeline", str(timeline_json_path),
        "--evidence", str(evidence_path),
        "--iocs", str(iocs_path),
        "--out", str(case_summary_path),
    ]

    if hayabusa_coverage_path.exists():
        summary_cmd.extend([
            "--hayabusa-coverage", str(hayabusa_coverage_path),
        ])

    result = subprocess.run(
        summary_cmd,
        cwd=str(project_root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    logs.append("\n===== case_summary_generator.py =====")

    if result.stdout:
        logs.append(result.stdout)

    if result.stderr:
        logs.append(result.stderr)

    if result.returncode != 0:
        raise RuntimeError(
            "case_summary_generator.py 실행 실패\n\n" + "\n".join(logs)
        )

    return "\n".join(logs)


def regenerate_events_and_metadata(case_id: str, data_root: str):
    """
    raw CSV 로그를 다시 정규화하여
    events.jsonl, events_preview.json, case_metadata.json을 생성한다.
    """

    project_root = Path(__file__).resolve().parents[2]

    data_root_path = Path(data_root)
    if not data_root_path.is_absolute():
        data_root_path = (Path.cwd() / data_root_path).resolve()

    raw_dir = data_root_path / "raw" / case_id
    processed_dir = data_root_path / "processed" / case_id

    normalize_script = project_root / "analysis" / "normalize_events.py"

    if not raw_dir.exists():
        raise FileNotFoundError(f"raw 디렉터리가 없습니다: {raw_dir}")

    csv_files = list(raw_dir.glob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(
            f"raw 디렉터리에 CSV 로그가 없습니다: {raw_dir}\n"
            "Security.csv, Sysmon.csv, PowerShell.csv 등의 원본 CSV를 먼저 넣어주세요."
        )

    cmd = [
        sys.executable,
        str(normalize_script),
        "--case-id", case_id,
        "--raw-dir", str(raw_dir),
        "--out-dir", str(processed_dir),
    ]

    result = subprocess.run(
        cmd,
        cwd=str(project_root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    logs = []
    logs.append("\n===== normalize_events.py =====")

    if result.stdout:
        logs.append(result.stdout)

    if result.stderr:
        logs.append(result.stderr)

    if result.returncode != 0:
        raise RuntimeError(
            "normalize_events.py 실행 실패\n\n" + "\n".join(logs)
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
# CASE 요약
# --------------------------------------------------

def render_info_item(label: str, value, icon: str = "•"):
    value = value if value not in [None, ""] else "-"

    st.markdown(
        f"""
        <div style="
            display:flex;
            justify-content:space-between;
            align-items:flex-start;
            gap:12px;
            padding:8px 10px;
            margin-bottom:6px;
            border:1px solid #e5e7eb;
            border-radius:8px;
            background-color:#f9fafb;
        ">
            <span style="
                font-weight:700;
                color:#374151;
                white-space:nowrap;
                font-size:0.86rem;
            ">{icon} {label}</span>
            <span style="
                color:#111827;
                font-weight:600;
                text-align:right;
                word-break:break-word;
                font-size:0.86rem;
            ">{value}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_metadata_status(metadata_path: Path):
    exists = metadata_path.exists()

    if exists:
        st.markdown(
            """
            <div style="
                display:inline-flex;
                align-items:center;
                gap:6px;
                padding:4px 9px;
                border-radius:999px;
                background-color:#dcfce7;
                color:#166534;
                font-weight:800;
                font-size:0.78rem;
                margin-bottom:8px;
            ">
                🟢 metadata loaded
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.caption("case_metadata.json 파일이 아직 생성되지 않았습니다.")


def render_compact_count_list(title: str, data: dict, label_map: dict = None):
    label_map = label_map or {}

    st.markdown(f"**{title}**")

    if not data:
        st.caption("데이터 없음")
        return

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
                <span style="
                    font-weight:700;
                    color:#374151;
                    font-size:0.86rem;
                    overflow:hidden;
                    text-overflow:ellipsis;
                    white-space:nowrap;
                ">{label}</span>
                <span style="
                    font-weight:800;
                    color:#111827;
                    background-color:#ffffff;
                    border:1px solid #e5e7eb;
                    border-radius:999px;
                    padding:2px 8px;
                    min-width:32px;
                    text-align:center;
                    font-size:0.8rem;
                ">{count}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_case_ai_summary(summary_data: dict):
    st.subheader("🧠 케이스 흐름 요약")

    if not summary_data:
        st.info("case_summary.json 파일이 없습니다. 분석 파일 재생성을 실행해 주세요.")
        return

    if summary_data.get("llm_error"):
        st.caption(
            "LLM 호출에 실패하여 기본 규칙 기반 요약을 표시합니다. "
            f"Error: {summary_data.get('llm_error')}"
        )

    st.markdown(
        f"""
        <div style="
            border:1px solid #e5e7eb;
            border-radius:12px;
            padding:16px 18px;
            background-color:#ffffff;
            margin-bottom:14px;
        ">
            <div style="
                font-weight:900;
                color:#111827;
                font-size:1.05rem;
                margin-bottom:8px;
            ">침해 흐름 요약</div>
            <div style="
                color:#374151;
                line-height:1.65;
                font-size:0.95rem;
            ">{summary_data.get("summary", "-")}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### 관찰된 흐름")
        flow = summary_data.get("flow", [])
        if flow:
            for item in flow:
                st.markdown(f"- {item}")
        else:
            st.caption("흐름 요약이 없습니다.")

    with col2:
        st.markdown("#### 주의 깊게 볼 포인트")
        watch_points = summary_data.get("watch_points", [])
        if watch_points:
            for item in watch_points:
                st.markdown(f"- {item}")
        else:
            st.caption("주의 포인트가 없습니다.")

    col3, col4 = st.columns(2)

    with col3:
        st.markdown("#### 우선 확인 Evidence")
        priority = summary_data.get("priority_evidence", [])
        if priority:
            st.write(", ".join(priority))
        else:
            st.caption("우선 Evidence 정보가 없습니다.")

    with col4:
        st.markdown("#### 분석 한계")
        limitations = summary_data.get("limitations", [])
        if limitations:
            for item in limitations:
                st.markdown(f"- {item}")
        else:
            st.caption("분석 한계 정보가 없습니다.")

    st.caption(
        f"Generated At: {summary_data.get('generated_at', '-')} | "
        f"Model: {summary_data.get('model', '-')}"
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

    status_title_col, normalize_button_col, regen_button_col = st.columns([5, 2, 2])

    with status_title_col:
        st.markdown("### ▶ Data Status")

    with normalize_button_col:
        normalize_clicked = st.button(
            "이벤트 정규화",
            use_container_width=True,
            help=(
                "raw CSV 로그를 다시 읽어 events.jsonl, events_preview.json, "
                "case_metadata.json을 생성합니다."
            ),
        )

    with regen_button_col:
        regenerate_clicked = st.button(
            "분석 파일 재생성",
            use_container_width=True,
            help=(
                "기존 events.jsonl을 기준으로 evidence, iocs, timeline을 다시 생성하고, "
                "Hayabusa CSV가 있으면 Hayabusa findings, summary, timeline matches, coverage도 함께 생성합니다."
            ),
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

    if normalize_clicked:
        try:
            with st.spinner("이벤트 로그를 정규화하는 중입니다..."):
                logs = regenerate_events_and_metadata(
                    case_id=st.session_state.case_id,
                    data_root=st.session_state.data_root,
                )

            st.success("events.jsonl 및 case_metadata.json 생성이 완료되었습니다.")

            with st.expander("실행 로그 보기", expanded=False):
                st.code(logs, language="text")

            st.rerun()

        except Exception as e:
            st.error("이벤트 정규화 중 오류가 발생했습니다.")
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
    ]

    hayabusa_status_items = [
        {
            "name": "hayabusa.csv",
            "exists": (raw_dir / "hayabusa" / "hayabusa.csv").exists(),
            "path": get_raw_hayabusa_csv_path(),
        },
        {
            "name": "findings",
            "exists": (processed_dir / "hayabusa" / "hayabusa_findings.json").exists(),
            "path": get_hayabusa_findings_path(),
        },
        {
            "name": "summary",
            "exists": (processed_dir / "hayabusa" / "hayabusa_summary.json").exists(),
            "path": get_hayabusa_summary_path(),
        },
        {
            "name": "coverage",
            "exists": (processed_dir / "hayabusa" / "hayabusa_coverage.json").exists(),
            "path": get_hayabusa_coverage_path(),
        },
    ]

    status_cols = st.columns(4)

    for col, item in zip(status_cols, status_items):
        with col:
            render_status(item)

    st.caption("Hayabusa Files")

    hayabusa_cols = st.columns(4)

    for col, item in zip(hayabusa_cols, hayabusa_status_items):
        with col:
            render_status(item)


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
        st.markdown("#### 수집 정보")

        metadata_path = raw_dir / "case_metadata.json"
        render_metadata_status(metadata_path)

        render_info_item(
            "User",
            metadata.get("user", "-"),
            icon="👤",
        )

        render_info_item(
            "Export Time",
            metadata.get("export_time", "-"),
            icon="📤",
        )

        render_info_item(
            "Log Start",
            metadata.get("start_time", timeline_summary.get("first_seen", "-")),
            icon="🕒",
        )

        render_info_item(
            "Log End",
            metadata.get("end_time", timeline_summary.get("last_seen", "-")),
            icon="🕘",
        )

        exported_logs = metadata.get("exported_logs", [])

        if exported_logs:
            render_info_item(
                "Logs",
                ", ".join(exported_logs),
                icon="📁",
            )

    with info_col2:
        st.markdown("#### Summary")

        render_metric_card(
            "First Seen",
            timeline_summary.get("first_seen", "-"),
            icon="🕒",
        )

        spacer(10)

        render_metric_card(
            "Last Seen",
            timeline_summary.get("last_seen", "-"),
            icon="🕘",
        )

        spacer(14)

        summary_left, summary_right = st.columns(2)

        with summary_left:
            render_compact_count_list(
                "By Source",
                timeline_summary.get("by_source", {}),
            )

        with summary_right:
            render_compact_count_list(
                "By Severity",
                timeline_summary.get("by_severity", {}),
            )
    
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

    spacer(20)

    case_summary = load_json(processed_dir / "case_summary.json", default={})
    render_case_ai_summary(case_summary)



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