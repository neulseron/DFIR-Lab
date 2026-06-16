# analysis/report_generator.py

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime


# -----------------------------
# Load / Write helpers
# -----------------------------

def load_json(path: Path, default: Any = None) -> Any:
    if not path or not path.exists():
        return default

    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_text(content: str, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        f.write(content)

    print(f"[+] Wrote {path}")


def md_escape(value: Any) -> str:
    if value is None:
        return "-"

    text = str(value)
    text = text.replace("|", "\\|")
    text = text.replace("\n", " ")
    text = text.replace("\r", " ")
    return text.strip() or "-"


def short(value: Any, limit: int = 160) -> str:
    if value is None:
        return "-"

    text = str(value).replace("\r", " ").replace("\n", " ").strip()

    if len(text) > limit:
        return text[:limit] + "..."

    return text or "-"


def table(headers: List[str], rows: List[List[Any]]) -> str:
    if not rows:
        return "_No data available._\n"

    out = []
    out.append("| " + " | ".join(headers) + " |")
    out.append("| " + " | ".join(["---"] * len(headers)) + " |")

    for row in rows:
        out.append("| " + " | ".join(md_escape(x) for x in row) + " |")

    return "\n".join(out) + "\n"


# -----------------------------
# Extract helpers
# -----------------------------

def get_top_timeline_rows(timeline_data: Dict[str, Any], limit: int = 15) -> List[Dict[str, Any]]:
    rows = timeline_data.get("timeline", [])

    severity_rank = {
        "High": 0,
        "Medium": 1,
        "Low": 2,
        "Informational": 3,
    }

    # 보고서에는 High/Medium 우선, 같은 등급이면 시간순
    sorted_rows = sorted(
        rows,
        key=lambda x: (
            severity_rank.get(x.get("severity"), 9),
            x.get("timestamp") or "",
        ),
    )

    return sorted_rows[:limit]


def get_timeline_rows_by_time(timeline_data: Dict[str, Any], limit: int = 20) -> List[Dict[str, Any]]:
    rows = timeline_data.get("timeline", [])

    sorted_rows = sorted(rows, key=lambda x: x.get("timestamp") or "")

    return sorted_rows[:limit]


def get_key_evidence(evidence_items: List[Dict[str, Any]], limit: int = 12) -> List[Dict[str, Any]]:
    severity_rank = {
        "High": 0,
        "Medium": 1,
        "Low": 2,
        "Informational": 3,
    }

    return sorted(
        evidence_items,
        key=lambda x: (
            severity_rank.get(x.get("severity"), 9),
            x.get("timestamp") or "",
        ),
    )[:limit]


def get_key_iocs(iocs_data: Dict[str, Any], limit: int = 20) -> List[Dict[str, Any]]:
    severity_rank = {
        "High": 0,
        "Medium": 1,
        "Low": 2,
        "Informational": 3,
    }

    return sorted(
        iocs_data.get("iocs", []),
        key=lambda x: (
            severity_rank.get(x.get("severity"), 9),
            x.get("type") or "",
            x.get("value") or "",
        ),
    )[:limit]


def build_mitre_summary(timeline_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = {}

    for row in timeline_rows:
        tactic = row.get("mitre_tactic") or "-"
        technique = row.get("mitre_technique") or "-"
        stage = row.get("stage") or "-"
        key = (tactic, technique, stage)

        if key not in seen:
            seen[key] = {
                "tactic": tactic,
                "technique": technique,
                "stage": stage,
                "count": 0,
                "examples": [],
            }

        seen[key]["count"] += 1

        action = row.get("action")
        if action and len(seen[key]["examples"]) < 3:
            seen[key]["examples"].append(action)

    return sorted(
        seen.values(),
        key=lambda x: (x["tactic"], x["technique"], x["stage"]),
    )


def infer_assessment(timeline_data: Dict[str, Any], iocs_data: Dict[str, Any]) -> str:
    by_stage = timeline_data.get("summary", {}).get("by_stage", {})
    ioc_summary = iocs_data.get("summary", {}).get("by_type", {})

    observed = []

    if by_stage.get("Execution"):
        observed.append("PowerShell 또는 명령 셸 기반 실행 흔적")
    if by_stage.get("Discovery"):
        observed.append("시스템·계정·네트워크 정보 수집 행위")
    if by_stage.get("Collection/Staging"):
        observed.append("임시 경로 파일 생성 및 압축 등 수집/스테이징 행위")
    if by_stage.get("Network Activity") or by_stage.get("Command and Control"):
        observed.append("외부 도메인/IP와의 네트워크 통신 흔적")

    if not observed:
        return (
            "수집된 로그에서 명확한 침해 행위 흐름은 확인되지 않았다. "
            "다만 본 분석은 제한된 로그 범위에 기반하므로 추가 증거 확보가 필요하다."
        )

    sentence = ", ".join(observed)

    return (
        f"수집된 로그에서는 {sentence}가 확인되었다. "
        "본 케이스는 실제 악성코드 감염이 아닌 안전한 행위 시뮬레이션이지만, "
        "DFIR 관점에서는 실행, 탐색, 수집/스테이징, 네트워크 활동으로 이어지는 "
        "기본 침해사고 분석 흐름을 재구성할 수 있었다."
    )


# -----------------------------
# Report sections
# -----------------------------

def section_header(title: str) -> str:
    return f"\n## {title}\n\n"


def build_report(
    case_id: str,
    metadata: Dict[str, Any],
    timeline_data: Dict[str, Any],
    evidence_items: List[Dict[str, Any]],
    iocs_data: Dict[str, Any],
) -> str:
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    timeline_summary = timeline_data.get("summary", {})
    stage_summary = timeline_data.get("stage_summary", [])
    ioc_summary = iocs_data.get("summary", {})

    timeline_rows = timeline_data.get("timeline", [])
    time_order_rows = get_timeline_rows_by_time(timeline_data, limit=25)
    key_evidence = get_key_evidence(evidence_items, limit=15)
    key_iocs = get_key_iocs(iocs_data, limit=25)
    mitre_summary = build_mitre_summary(timeline_rows)

    report = []

    report.append(f"# DFIR Analysis Report - {case_id}\n")
    report.append(f"- Generated At: {generated_at}\n")
    report.append("- Report Type: Windows Endpoint DFIR Simulation\n")

    report.append(section_header("1. Executive Summary"))
    report.append(
        "본 보고서는 Windows 10 엔드포인트에서 안전하게 재현한 의심 행위 시나리오를 대상으로, "
        "Sysmon, Windows Security, PowerShell 이벤트 로그를 분석하여 타임라인, IOC, 핵심 증거를 정리한 DFIR 분석 보고서이다.\n\n"
    )
    report.append(infer_assessment(timeline_data, iocs_data) + "\n\n")
    report.append(
        "본 케이스는 실제 악성코드 감염이 아니며, 악성코드에서 흔히 관찰되는 Discovery, File Activity, "
        "Network Activity, Staging 행위를 안전하게 시뮬레이션한 실습 결과이다.\n"
    )

    report.append(section_header("2. Case Information"))
    report.append(table(
        ["Field", "Value"],
        [
            ["Case ID", case_id],
            ["Host", metadata.get("host", "-")],
            ["User", metadata.get("user", "-")],
            ["Export Time", metadata.get("export_time", "-")],
            ["Log Start Time", metadata.get("start_time", timeline_summary.get("first_seen", "-"))],
            ["Log End Time", metadata.get("end_time", timeline_summary.get("last_seen", "-"))],
            ["First Seen", timeline_summary.get("first_seen", "-")],
            ["Last Seen", timeline_summary.get("last_seen", "-")],
        ],
    ))

    report.append(section_header("3. Evidence Collection Scope"))
    exported_logs = metadata.get("exported_logs", [])
    if exported_logs:
        report.append("수집 대상 로그는 다음과 같다.\n\n")
        for item in exported_logs:
            report.append(f"- {item}\n")
        report.append("\n")
    else:
        report.append(
            "- Sysmon Event Log\n"
            "- Windows Security Event Log\n"
            "- PowerShell Operational Event Log\n\n"
        )

    report.append(
        "CSV 파일은 분석 편의를 위한 파싱 결과이며, 원본 EVTX 파일은 원본 증거 보관 목적으로 별도 보존할 수 있다.\n"
    )

    report.append(section_header("4. Timeline Summary"))
    report.append(table(
        ["Metric", "Value"],
        [
            ["Total Timeline Events", timeline_summary.get("total_events", 0)],
            ["First Seen", timeline_summary.get("first_seen", "-")],
            ["Last Seen", timeline_summary.get("last_seen", "-")],
            ["Stage Count", json.dumps(timeline_summary.get("by_stage", {}), ensure_ascii=False)],
            ["Severity Count", json.dumps(timeline_summary.get("by_severity", {}), ensure_ascii=False)],
            ["Source Count", json.dumps(timeline_summary.get("by_source", {}), ensure_ascii=False)],
        ],
    ))

    report.append("\n### Stage Summary\n\n")
    report.append(table(
        ["Stage", "Count", "First Seen", "Last Seen", "High", "Medium", "Representative Actions"],
        [
            [
                s.get("stage"),
                s.get("count"),
                s.get("first_seen"),
                s.get("last_seen"),
                s.get("high_count"),
                s.get("medium_count"),
                "; ".join(s.get("representative_actions", [])),
            ]
            for s in stage_summary
        ],
    ))

    report.append(section_header("5. Key Timeline"))
    report.append(table(
        ["Time", "Stage", "Severity", "Action", "Evidence ID", "IOC Refs"],
        [
            [
                row.get("timestamp"),
                row.get("stage"),
                row.get("severity"),
                short(row.get("action"), 120),
                row.get("evidence_id"),
                short(row.get("ioc_refs"), 120),
            ]
            for row in time_order_rows
        ],
    ))

    report.append(section_header("6. IOC Summary"))
    report.append(table(
        ["Metric", "Value"],
        [
            ["Total IOCs", ioc_summary.get("total", 0)],
            ["IOC Types", json.dumps(ioc_summary.get("by_type", {}), ensure_ascii=False)],
            ["IOC Severity", json.dumps(ioc_summary.get("by_severity", {}), ensure_ascii=False)],
        ],
    ))

    report.append("\n### Key IOC Candidates\n\n")
    report.append(table(
        ["Type", "Value", "Severity", "First Seen", "Last Seen", "Count", "Related Evidence"],
        [
            [
                ioc.get("type"),
                short(ioc.get("value"), 100),
                ioc.get("severity"),
                ioc.get("first_seen"),
                ioc.get("last_seen"),
                ioc.get("count"),
                ", ".join(ioc.get("related_evidence_ids", [])[:5]),
            ]
            for ioc in key_iocs
        ],
    ))

    report.append(
        "\n> Note: 본 프로젝트에서 추출한 IOC는 로그 기반 분석 후보이며, 실제 악성 여부는 위협 인텔리전스, 샘플 분석, 네트워크 평판 조회 등을 통해 추가 검증이 필요하다.\n"
    )

    report.append(section_header("7. Evidence Highlights"))
    report.append(table(
        ["Evidence ID", "Time", "Source", "Event ID", "Title", "Stage", "Severity", "Summary"],
        [
            [
                ev.get("evidence_id"),
                ev.get("timestamp"),
                ev.get("source"),
                ev.get("event_id"),
                ev.get("title"),
                ev.get("attack_stage"),
                ev.get("severity"),
                short(ev.get("summary"), 140),
            ]
            for ev in key_evidence
        ],
    ))

    report.append(section_header("8. MITRE ATT&CK Mapping"))
    report.append(table(
        ["Tactic", "Technique", "Stage", "Count", "Example Actions"],
        [
            [
                item.get("tactic"),
                item.get("technique"),
                item.get("stage"),
                item.get("count"),
                "; ".join(item.get("examples", [])),
            ]
            for item in mitre_summary
        ],
    ))

    report.append(section_header("9. Analyst Assessment"))
    report.append(infer_assessment(timeline_data, iocs_data) + "\n\n")
    report.append(
        "특히 PowerShell 실행, 시스템 정보 수집 명령, 임시 경로 파일 생성, 압축 파일 생성, 외부 도메인 접속 흔적이 "
        "시간순으로 연결되어 있어 단일 엔드포인트에서 의심 행위 흐름을 재구성할 수 있었다.\n"
    )

    report.append(section_header("10. Recommendations"))
    report.append(
        "- PowerShell Script Block Logging 및 Module Logging 활성화 상태를 유지한다.\n"
        "- Sysmon Event ID 1, 3, 11, 22를 기반으로 프로세스 실행, 네트워크 연결, 파일 생성, DNS 조회를 지속적으로 수집한다.\n"
        "- `powershell.exe`, `cmd.exe`, `certutil.exe`, `bitsadmin.exe`, `rundll32.exe`, `mshta.exe` 등 LOLBin 실행에 대한 탐지 룰을 보강한다.\n"
        "- TEMP 경로 파일 생성, 압축 파일 생성, 외부 통신이 짧은 시간 안에 연속 발생하는 경우 상관분석 룰을 적용한다.\n"
        "- IOC는 평판 조회 및 네트워크 로그와 교차 검증하여 실제 악성 여부를 판단한다.\n"
        "- 향후 KAPE, Hayabusa, Chainsaw, Velociraptor 등과 연계하여 수집 범위와 분석 정확도를 확장한다.\n"
    )

    report.append(section_header("11. Limitations"))
    report.append(
        "- 본 케이스는 실제 악성코드 감염이 아닌 안전한 시뮬레이션 기반 분석이다.\n"
        "- 분석 대상은 Windows Event/Sysmon/PowerShell 로그에 한정되며, 메모리 이미지와 전체 디스크 이미지는 확보하지 않았다.\n"
        "- 삭제 파일 복구, 메모리 인젝션, 은닉 프로세스, 레지스트리 지속성 분석은 본 범위에 포함되지 않았다.\n"
        "- CSV 변환 과정에서 원본 EVTX의 일부 구조적 필드가 손실될 수 있으므로, 실제 조사에서는 원본 EVTX를 함께 보존해야 한다.\n"
        "- `example.com`은 테스트 목적지이며, 실제 악성 C2 도메인이 아니다.\n"
    )

    report.append(section_header("12. Appendix"))
    report.append("### Output Files\n\n")
    report.append(
        "- `events.jsonl`: normalized event records\n"
        "- `evidence.json`: mapped forensic evidence records\n"
        "- `iocs.json`: extracted IOC candidates\n"
        "- `timeline.json`: structured timeline data\n"
        "- `timeline.csv`: analyst-friendly timeline table\n"
        "- `report.md`: generated DFIR report\n"
    )

    return "".join(report)


# -----------------------------
# Main
# -----------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate DFIR markdown report from timeline, evidence, and IOC data"
    )
    parser.add_argument("--case-id", required=True, help="Case ID, e.g. CASE-001")
    parser.add_argument("--metadata", required=False, help="Path to case_metadata.json")
    parser.add_argument("--timeline", required=True, help="Path to timeline.json")
    parser.add_argument("--evidence", required=True, help="Path to evidence.json")
    parser.add_argument("--iocs", required=True, help="Path to iocs.json")
    parser.add_argument("--out", required=True, help="Output report.md path")

    args = parser.parse_args()

    case_id = args.case_id
    metadata = load_json(Path(args.metadata), default={}) if args.metadata else {}
    timeline_data = load_json(Path(args.timeline), default={})
    evidence_items = load_json(Path(args.evidence), default=[])
    iocs_data = load_json(Path(args.iocs), default={})

    report = build_report(
        case_id=case_id,
        metadata=metadata,
        timeline_data=timeline_data,
        evidence_items=evidence_items,
        iocs_data=iocs_data,
    )

    write_text(report, Path(args.out))


if __name__ == "__main__":
    main()