# dashboard/views/home.py
import subprocess
import sys

import streamlit as st
from pathlib import Path

from .common import (
    get_case_id,
    get_raw_dir,
    get_processed_dir,
    load_json,
    show_missing_file_warning,
)


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

    return "\n".join(logs)


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

    if not timeline:
        show_missing_file_warning("timeline.json")
        return

    timeline_summary = timeline.get("summary", {})
    ioc_summary = iocs.get("summary", {})

    st.markdown(f"## 📂 Case ID | `{case_id}`")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("▶ Timeline Events", timeline_summary.get("total_events", 0))
    col2.metric("▶ Evidence Items", len(evidence))
    col3.metric("▶ IOC Candidates", ioc_summary.get("total", 0))
    col4.metric("▶ Host", metadata.get("host", "-"))


    status_title_col, regen_button_col = st.columns([7, 2])

    with status_title_col:
        st.markdown("### Data Status")

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

    data1, data2, data3, data4, data5, data6 = st.columns(6)

    processed_dir = Path(st.session_state.data_root) / "processed" / st.session_state.case_id
    raw_dir = Path(st.session_state.data_root) / "raw" / st.session_state.case_id

    with data1:
        dataPath = processed_dir / "events.jsonl"
        status = dataPath.exists()
        st.markdown(f"events [{"🟢" if status else "🔴"}]")
    with data2:
        dataPath = processed_dir / "evidence.json"
        status = dataPath.exists()
        st.markdown(f"evidence [{"🟢" if status else "🔴"}]")
    with data3:
        dataPath = processed_dir / "iocs.json"
        status = dataPath.exists()
        st.markdown(f"iocs [{"🟢" if status else "🔴"}]")
    with data4:
        dataPath = processed_dir / "timeline.json"
        status = dataPath.exists()
        st.markdown(f"timeline [{"🟢" if status else "🔴"}]")
    with data5:
        dataPath = processed_dir / "report.md"
        status = dataPath.exists()
        st.markdown(f"report [{"🟢" if status else "🔴"}]")
    with data6:
        dataPath = raw_dir / "case_metadata.json"
        status = dataPath.exists()
        st.markdown(f"metadata [{"🟢" if status else "🔴"}]")


    st.divider()

    st.subheader("Case 정보")

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