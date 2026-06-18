# analysis/timeline_builder.py

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Optional


# -----------------------------
# Load / Write helpers
# -----------------------------

def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(data: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f"[+] Wrote {path}")


def write_csv(rows: List[Dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "order",
        "timestamp",
        "stage",
        "action",
        "severity",
        "source",
        "event_id",
        "evidence_id",
        "rule_id",
        "title",
        "summary",
        "ioc_refs",
        "mitre_tactic",
        "mitre_technique",
        "forensic_meaning",
    ]

    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})

    print(f"[+] Wrote {path}")


# -----------------------------
# Timeline utilities
# -----------------------------

STAGE_ORDER = {
    "Initial Context": 0,
    "Execution": 10,
    "Discovery": 20,
    "Collection/Staging": 30,
    "Network Activity": 40,
    "Command and Control": 45,
    "Defense Evasion": 50,
    "Cleanup": 60,
    "Unknown": 99,
}

SEVERITY_ORDER = {
    "High": 0,
    "Medium": 1,
    "Low": 2,
    "Informational": 3,
    None: 9,
}


def normalize_stage(stage: Optional[str]) -> str:
    if not stage:
        return "Unknown"

    # 일부 룰에서 비슷한 표현이 들어와도 통일
    mapping = {
        "Collection": "Collection/Staging",
        "Staging": "Collection/Staging",
        "Network": "Network Activity",
        "C2": "Command and Control",
        "Logon": "Initial Context",
    }

    return mapping.get(stage, stage)


def short_text(value: Optional[str], limit: int = 220) -> str:
    if not value:
        return ""

    value = str(value).replace("\r", " ").replace("\n", " ").strip()

    if len(value) > limit:
        return value[:limit] + "..."

    return value


def build_action(evidence: Dict[str, Any]) -> str:
    """
    Evidence 정보를 사람이 읽기 쉬운 한국어 timeline action으로 변환한다.
    title 문자열에 의존하지 않고 rule_id, evidence_type, 주요 필드를 기준으로 생성한다.
    """
    rule_id = evidence.get("rule_id") or ""
    evidence_type = evidence.get("evidence_type") or ""
    image = evidence.get("image") or ""
    command_line = evidence.get("command_line") or ""
    target_filename = evidence.get("target_filename") or ""
    destination_ip = evidence.get("destination_ip") or ""
    destination_port = evidence.get("destination_port") or ""
    query_name = evidence.get("query_name") or ""
    title = evidence.get("title") or ""

    # Rule ID 기반 우선 처리
    if rule_id == "EV-SYSMON-001":
        if command_line:
            return f"PowerShell 프로세스 실행: {short_text(command_line, 120)}"
        return "PowerShell 프로세스 실행"

    if rule_id == "EV-SYSMON-002":
        if command_line:
            return f"명령 프롬프트 실행: {short_text(command_line, 120)}"
        return "명령 프롬프트 실행"

    if rule_id == "EV-SYSMON-003":
        if command_line:
            return f"시스템/계정 탐색 명령 실행: {short_text(command_line, 120)}"
        return "시스템/계정 탐색 명령 실행"

    if rule_id == "EV-SYSMON-004":
        if target_filename:
            return f"임시 경로 파일 생성: {target_filename}"
        return "임시 경로 파일 생성"

    if rule_id == "EV-SYSMON-005":
        if destination_ip:
            dest = destination_ip
            if destination_port:
                dest += f":{destination_port}"
            return f"네트워크 연결 발생: {dest}"
        return "네트워크 연결 발생"

    if rule_id == "EV-SYSMON-006":
        if query_name:
            return f"DNS 질의 발생: {query_name}"
        return "DNS 질의 발생"

    if rule_id == "EV-PS-001":
        if command_line:
            return f"PowerShell 스크립트 블록 기록: {short_text(command_line, 120)}"
        return "PowerShell 스크립트 블록 기록"

    if rule_id == "EV-PS-002":
        if command_line:
            return f"PowerShell 웹 요청 명령 실행: {short_text(command_line, 120)}"
        return "PowerShell 웹 요청 명령 실행"

    if rule_id == "EV-PS-003":
        if command_line:
            return f"PowerShell 압축 생성 명령 실행: {short_text(command_line, 120)}"
        return "PowerShell 압축 생성 명령 실행"

    if rule_id == "EV-SEC-001":
        if image:
            return f"Windows 보안 로그 기반 프로세스 생성: {image}"
        return "Windows 보안 로그 기반 프로세스 생성"

    if rule_id == "EV-SEC-002":
        user = evidence.get("user") or "-"
        return f"로그온 성공 이벤트 확인: {user}"

    if rule_id == "EV-SEC-003":
        return "보안 이벤트 로그 삭제 확인"

    # evidence_type 기반 보조 처리
    if evidence_type == "Process Execution":
        if image:
            return f"프로세스 실행 확인: {image}"
        return "프로세스 실행 확인"

    if evidence_type == "Script Execution":
        return "스크립트 실행 흔적 확인"

    if evidence_type == "Discovery Command":
        if command_line:
            return f"탐색 명령 확인: {short_text(command_line, 120)}"
        return "탐색 명령 확인"

    if evidence_type == "File Activity":
        if target_filename:
            return f"파일 활동 확인: {target_filename}"
        return "파일 활동 확인"

    if evidence_type == "Network Connection":
        if destination_ip:
            dest = destination_ip
            if destination_port:
                dest += f":{destination_port}"
            return f"네트워크 연결 확인: {dest}"
        return "네트워크 연결 확인"

    if evidence_type == "DNS Query":
        if query_name:
            return f"DNS 질의 확인: {query_name}"
        return "DNS 질의 확인"

    if evidence_type == "Network Command":
        if command_line:
            return f"네트워크 관련 명령 확인: {short_text(command_line, 120)}"
        return "네트워크 관련 명령 확인"

    if evidence_type == "Archive Activity":
        return "압축 파일 생성 활동 확인"

    if evidence_type == "Logon":
        return "로그온 이벤트 확인"

    if evidence_type == "Log Clearing":
        return "로그 삭제 이벤트 확인"

    # 최종 fallback
    if command_line:
        return f"명령 실행 확인: {short_text(command_line, 120)}"

    if image:
        return f"프로세스 확인: {image}"

    return title or "증거 이벤트 확인"


def load_ioc_index(iocs_data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    related_evidence_ids 기준으로 evidence_id → IOC 목록 인덱스 생성.
    """
    index: Dict[str, Dict[str, Any]] = {}

    for ioc in iocs_data.get("iocs", []):
        value = ioc.get("value")
        ioc_type = ioc.get("type")

        if not value or not ioc_type:
            continue

        for evidence_id in ioc.get("related_evidence_ids", []):
            if evidence_id not in index:
                index[evidence_id] = {
                    "values": [],
                    "details": [],
                }

            ref = f"{ioc_type}:{value}"

            if ref not in index[evidence_id]["values"]:
                index[evidence_id]["values"].append(ref)

            index[evidence_id]["details"].append(
                {
                    "type": ioc_type,
                    "value": value,
                    "severity": ioc.get("severity"),
                    "count": ioc.get("count"),
                }
            )

    return index


def build_timeline_rows(
    evidence_items: List[Dict[str, Any]],
    iocs_data: Dict[str, Any],
) -> List[Dict[str, Any]]:
    ioc_index = load_ioc_index(iocs_data)
    rows: List[Dict[str, Any]] = []

    sorted_evidence = sorted(
        evidence_items,
        key=lambda x: (
            x.get("timestamp") or "",
            STAGE_ORDER.get(normalize_stage(x.get("attack_stage")), 99),
            SEVERITY_ORDER.get(x.get("severity"), 9),
        ),
    )

    for idx, ev in enumerate(sorted_evidence, start=1):
        evidence_id = ev.get("evidence_id")
        stage = normalize_stage(ev.get("attack_stage"))
        ioc_refs = []

        if evidence_id in ioc_index:
            ioc_refs = ioc_index[evidence_id]["values"]

        row = {
            "order": idx,
            "timestamp": ev.get("timestamp"),
            "stage": stage,
            "action": build_action(ev),
            "severity": ev.get("severity"),
            "source": ev.get("source"),
            "event_id": ev.get("event_id"),
            "evidence_id": evidence_id,
            "rule_id": ev.get("rule_id"),
            "title": ev.get("title"),
            "summary": short_text(ev.get("summary"), 280),
            "ioc_refs": ", ".join(ioc_refs),
            "ioc_details": ioc_index.get(evidence_id, {}).get("details", []),
            "mitre_tactic": ev.get("mitre_tactic"),
            "mitre_technique": ev.get("mitre_technique"),
            "forensic_meaning": ev.get("forensic_meaning"),
            "raw": {
                "user": ev.get("user"),
                "image": ev.get("image"),
                "command_line": ev.get("command_line"),
                "parent_image": ev.get("parent_image"),
                "target_filename": ev.get("target_filename"),
                "destination_ip": ev.get("destination_ip"),
                "destination_port": ev.get("destination_port"),
                "query_name": ev.get("query_name"),
                "source_file": ev.get("source_file"),
            },
        }

        rows.append(row)

    return rows


def summarize_timeline(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_stage: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    by_source: Dict[str, int] = {}

    first_seen = None
    last_seen = None

    for row in rows:
        stage = row.get("stage") or "Unknown"
        severity = row.get("severity") or "Unknown"
        source = row.get("source") or "Unknown"
        ts = row.get("timestamp")

        by_stage[stage] = by_stage.get(stage, 0) + 1
        by_severity[severity] = by_severity.get(severity, 0) + 1
        by_source[source] = by_source.get(source, 0) + 1

        if ts:
            if first_seen is None or ts < first_seen:
                first_seen = ts
            if last_seen is None or ts > last_seen:
                last_seen = ts

    return {
        "total_events": len(rows),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "by_stage": by_stage,
        "by_severity": by_severity,
        "by_source": by_source,
    }


def build_stage_summary(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    대시보드 상단에 보여주기 좋은 단계별 요약.
    """
    grouped: Dict[str, List[Dict[str, Any]]] = {}

    for row in rows:
        stage = row.get("stage") or "Unknown"
        grouped.setdefault(stage, []).append(row)

    summaries = []

    for stage, items in grouped.items():
        items_sorted = sorted(items, key=lambda x: x.get("timestamp") or "")
        high_count = sum(1 for x in items if x.get("severity") == "High")
        medium_count = sum(1 for x in items if x.get("severity") == "Medium")

        representative_actions = [x.get("action") for x in items_sorted[:3] if x.get("action")]

        summaries.append(
            {
                "stage": stage,
                "order": STAGE_ORDER.get(stage, 99),
                "count": len(items),
                "first_seen": items_sorted[0].get("timestamp") if items_sorted else None,
                "last_seen": items_sorted[-1].get("timestamp") if items_sorted else None,
                "high_count": high_count,
                "medium_count": medium_count,
                "representative_actions": representative_actions,
            }
        )

    return sorted(summaries, key=lambda x: x.get("order", 99))


def filter_timeline_rows(rows: List[Dict[str, Any]], min_severity: Optional[str]) -> List[Dict[str, Any]]:
    """
    필요하면 Low/Informational을 줄이고 Medium 이상만 timeline에 넣을 수 있게 하는 옵션.
    """
    if not min_severity:
        return rows

    allowed_by_min = {
        "High": {"High"},
        "Medium": {"High", "Medium"},
        "Low": {"High", "Medium", "Low"},
        "Informational": {"High", "Medium", "Low", "Informational"},
    }

    allowed = allowed_by_min.get(min_severity, {"High", "Medium", "Low", "Informational"})

    filtered = [row for row in rows if row.get("severity") in allowed]

    # order 다시 부여
    for idx, row in enumerate(filtered, start=1):
        row["order"] = idx

    return filtered


# -----------------------------
# Main
# -----------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build DFIR timeline from evidence and IOC data"
    )
    parser.add_argument("--evidence", required=True, help="Path to evidence.json")
    parser.add_argument("--iocs", required=True, help="Path to iocs.json")
    parser.add_argument("--out-json", required=True, help="Output timeline.json path")
    parser.add_argument("--out-csv", required=True, help="Output timeline.csv path")
    parser.add_argument(
        "--min-severity",
        required=False,
        choices=["High", "Medium", "Low", "Informational"],
        help="Only include rows at or above this severity. Example: Medium",
    )

    args = parser.parse_args()

    evidence_path = Path(args.evidence)
    iocs_path = Path(args.iocs)
    out_json_path = Path(args.out_json)
    out_csv_path = Path(args.out_csv)

    evidence_items = load_json(evidence_path)
    iocs_data = load_json(iocs_path)

    rows = build_timeline_rows(evidence_items, iocs_data)
    rows = filter_timeline_rows(rows, args.min_severity)

    result = {
        "summary": summarize_timeline(rows),
        "stage_summary": build_stage_summary(rows),
        "timeline": rows,
    }

    write_json(result, out_json_path)
    write_csv(rows, out_csv_path)

    print("[+] Timeline summary:")
    print(json.dumps(result["summary"], ensure_ascii=False, indent=2))
    print("[+] Stage summary:")
    print(json.dumps(result["stage_summary"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()