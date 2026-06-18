# dashboard/components/sidebar.py

from pathlib import Path
import html


import streamlit as st
from streamlit_option_menu import option_menu



# --------------------------------------------------
# 공백/구분자
# --------------------------------------------------

def spacer(height: int = 16):
    st.markdown(
        f"<div style='height:{height}px;'></div>",
        unsafe_allow_html=True,
    )


def dashed_divider(margin: int = 24):
    st.markdown(
        f"""
        <hr style="
            border: none;
            border-top: 3px dashed #d1d5db;
            margin: {margin}px 0;
        ">
        """,
        unsafe_allow_html=True,
    )


def soft_divider(margin: int = 20):
    st.markdown(
        f"""
        <hr style="
            border: none;
            border-top: 1px solid #e5e7eb;
            margin: {margin}px 0;
        ">
        """,
        unsafe_allow_html=True,
    )


# --------------------------------------------------
# 타입 라벨 렌더러
# --------------------------------------------------

IOC_TYPE_STYLE = {
    "ip": ("🖥️", "IP", "#2563eb"),
    "domain": ("🌐", "도메인", "#0891b2"),
    "url": ("🔗", "URL", "#0f766e"),
    "file_path": ("📄", "파일 경로", "#7c3aed"),
    "process": ("⚙️", "프로세스", "#4b5563"),
    "command": ("⌨️", "명령어", "#b45309"),
    "hash": ("#️⃣", "해시", "#be123c"),
    "user": ("👤", "사용자", "#0369a1"),
}


EVIDENCE_TYPE_STYLE = {
    "Process Execution": ("⚙️", "프로세스 실행", "#4b5563"),
    "Script Execution": ("⌨️", "스크립트 실행", "#b45309"),
    "Discovery Command": ("🔎", "정보 수집", "#2563eb"),
    "File Activity": ("📄", "파일 활동", "#7c3aed"),
    "Network Connection": ("🌐", "네트워크 연결", "#0f766e"),
    "DNS Query": ("🔍", "DNS 질의", "#0891b2"),
    "Network Command": ("🔗", "네트워크 명령", "#0f766e"),
    "Archive Activity": ("📦", "압축 활동", "#9333ea"),
    "Logon": ("👤", "로그인", "#0369a1"),
    "Log Clearing": ("🧹", "로그 삭제", "#be123c"),
}

STAGE_STYLE = {
    "Initial Context": ("🚪", "초기 접속", "#64748b"),
    "Execution": ("▶️", "실행", "#dc2626"),
    "Discovery": ("🔎", "탐색", "#2563eb"),
    "Collection/Staging": ("📦", "수집/스테이징", "#7c3aed"),
    "Network Activity": ("🌐", "네트워크 활동", "#0f766e"),
    "Command and Control": ("📡", "C2 통신", "#be123c"),
    "Defense Evasion": ("🛡️", "방어 회피", "#b45309"),
    "Cleanup": ("🧹", "정리/삭제", "#4b5563"),
    "Unknown": ("❔", "미분류", "#6b7280"),
}


def type_label(value: str, style_map: dict) -> str:
    raw = str(value or "-")
    icon, label, color = style_map.get(raw, ("•", raw, "#374151"))

    return (
        f'<span style="'
        f'display:inline-flex; align-items:center; gap:6px; '
        f'border-left:4px solid {color}; '
        f'padding-left:8px; '
        f'font-weight:600; '
        f'color:#374151; '
        f'white-space:nowrap;'
        f'">'
        f'<span>{icon}</span>'
        f'<span>{html.escape(label)}</span>'
        f'</span>'
    )


def ioc_type_label(value: str) -> str:
    return type_label(value, IOC_TYPE_STYLE)


def evidence_type_label(value: str) -> str:
    return type_label(value, EVIDENCE_TYPE_STYLE)

def stage_label(value: str) -> str:
    return type_label(value, STAGE_STYLE)


# --------------------------------------------------
# 위험도 배지
# --------------------------------------------------

SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "info": 1,
    "none": 0,
    "-": 0,
}

SEVERITY_STYLE = {
    "critical": ("#fee2e2", "#7f1d1d", "CRITICAL"),
    "high": ("#ffedd5", "#9a3412", "HIGH"),
    "medium": ("#fef3c7", "#92400e", "MEDIUM"),
    "low": ("#dcfce7", "#166534", "LOW"),
    "informational": ("#e0f2fe", "#075985", "INFO"),
    "none": ("#f3f4f6", "#374151", "NONE"),
}


def normalize_severity(severity: str) -> str:
    severity = str(severity or "none").strip().lower()

    if severity == "info":
        severity = "informational"

    return severity if severity in SEVERITY_STYLE else "none"


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(normalize_severity(severity), 0)


def severity_text(severity: str) -> str:
    severity = normalize_severity(severity)
    return SEVERITY_STYLE[severity][2]


def severity_badge(severity: str) -> str:
    severity = normalize_severity(severity)
    bg, fg, label = SEVERITY_STYLE[severity]

    return (
        f'<span style="background-color:{bg}; color:{fg}; '
        f'padding:3px 10px; border-radius:999px; font-weight:700; '
        f'font-size:0.82rem; white-space:nowrap;">{label}</span>'
    )


def render_badge_table(
    rows,
    columns,
    badge_columns=None,
    right_columns=None,
    column_renderers=None,
    column_widths=None,
):
    """
    st.dataframe 대신 HTML table로 출력하기 위한 공통 함수.

    - badge_columns: severity_badge()를 적용할 컬럼
    - right_columns: 오른쪽 정렬할 컬럼
    - column_renderers: 컬럼별 커스텀 렌더러
    - column_widths: 컬럼별 너비 지정
      예: {"severity": "90px", "summary": "360px"}
    """
    badge_columns = set(badge_columns or [])
    right_columns = set(right_columns or [])
    column_renderers = column_renderers or {}
    column_widths = column_widths or {}

    if not rows:
        st.info("표시할 데이터가 없습니다.")
        return

    table_html = """
    <div style="width:100%; overflow-x:auto;">
    <table style="
        width:100%;
        border-collapse:collapse;
        margin-top:10px;
        font-size:0.9rem;
        table-layout:fixed;
    ">
        <thead>
            <tr style="background:#f9fafb;">
    """

    for col in columns:
        align = "right" if col in right_columns else "left"

        if col in badge_columns or col in column_renderers:
            align = "center"

        width = column_widths.get(col, "auto")
        width_style = f"width:{width};" if width != "auto" else ""

        table_html += (
            f"<th style='padding:8px; border:1px solid #e5e7eb; "
            f"text-align:{align}; color:#374151; {width_style} "
            f"white-space:nowrap;'>"
            f"{html.escape(str(col))}</th>"
        )

    table_html += """
            </tr>
        </thead>
        <tbody>
    """

    for row in rows:
        table_html += "<tr>"

        for col in columns:
            value = row.get(col, "-")
            align = "right" if col in right_columns else "left"

            if col in column_renderers:
                cell = column_renderers[col](value)
                align = "center"
            elif col in badge_columns:
                cell = severity_badge(value)
                align = "center"
            else:
                cell = html.escape(str(value if value is not None else "-"))

            width = column_widths.get(col, "auto")
            width_style = f"width:{width};" if width != "auto" else ""

            # 긴 텍스트 컬럼은 줄바꿈 허용
            if col in {"summary", "action", "value", "ioc_refs", "related_evidence_ids", "title"}:
                text_style = "white-space:normal; word-break:break-word;"
            else:
                text_style = "white-space:nowrap; overflow:hidden; text-overflow:ellipsis;"

            table_html += (
                f"<td style='padding:8px; border:1px solid #e5e7eb; "
                f"text-align:{align}; color:#374151; vertical-align:top; "
                f"{width_style} {text_style}'>"
                f"{cell}</td>"
            )

        table_html += "</tr>"

    table_html += """
        </tbody>
    </table>
    </div>
    """

    st.markdown(table_html, unsafe_allow_html=True)



# --------------------------------------------------
# --------------------------------------------------

def get_case_options(data_root: Path) -> list[str]:
    case_ids = set()

    raw_root = data_root / "raw"
    processed_root = data_root / "processed"

    for root in [raw_root, processed_root]:
        if root.exists():
            for path in root.iterdir():
                if path.is_dir():
                    case_ids.add(path.name)

    return sorted(case_ids)

# --------------------------------------------------
# 메뉴 버튼 UI
# --------------------------------------------------

def render_menu():
    with st.sidebar:
        return option_menu(
            None,
            ["CASE 요약", "타임라인", "IOC", "증거", "리포트", "Hayabusa"],
            icons=["house-door", "clock-history", "crosshair", "folder2-open", "file-earmark-text", "crosshair"],
            menu_icon=None,
            default_index=0,
            styles={
                "container": {
                    "padding": "0.5rem 0.4rem",
                    "background-color": "transparent",
                },
                "icon": {
                    "color": "#111827",
                    "font-size": "18px",
                },
                "nav-link": {
                    "font-size": "16px",
                    "font-weight": "600",
                    "text-align": "left",
                    "margin": "0px",
                    "padding": "10px 12px",
                    "border-radius": "8px",
                    "--hover-color": "#f3f4f6",
                    "color": "#111827",
                },
                "nav-link-selected": {
                    "background-color": "#e5e7eb",
                    "color": "#111827",
                    "font-weight": "700",
                },
            },
        )



# --------------------------------------------------
# 사이드바 랜더링
# --------------------------------------------------

def render_sidebar() -> str:
    st.sidebar.title("DFIR Analysis Lab")

    st.sidebar.caption("Windows Endpoint Forensic Analysis")

    st.sidebar.divider()

    # Case 설정
    data_root = Path(st.session_state.get("data_root", "data"))
    case_options = get_case_options(data_root)

    if case_options:
        current_case_id = st.session_state.get("case_id", case_options[0])

        if current_case_id in case_options:
            default_index = case_options.index(current_case_id)
        else:
            default_index = 0

        case_id = st.sidebar.selectbox(
            "Case ID",
            options=case_options,
            index=default_index,
        )

        st.session_state.case_id = case_id
    else:
        st.sidebar.warning("data/raw 또는 data/processed 하위에 케이스 폴더가 없습니다.")

        case_id = st.sidebar.text_input(
            "Case ID",
            value=st.session_state.get("case_id", "CASE-001"),
        )

        st.session_state.case_id = case_id.strip() or "CASE-001"

    st.sidebar.divider()

    menu = render_menu()

    return menu