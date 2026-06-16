# analysis/normalize_events.py

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Dict, Any, Optional, List


# -----------------------------
# Basic parsers
# -----------------------------

def find_first(pattern: str, text: str) -> Optional[str]:
    if not text:
        return None

    match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
    if not match:
        return None

    return match.group(1).strip()


def extract_sysmon_field(message: str, field_name: str) -> Optional[str]:
    """
    Sysmon CSV의 Message 필드는 보통 다음 형태를 포함한다.

    Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
    CommandLine: powershell ...
    ParentImage: C:\\Windows\\System32\\cmd.exe
    DestinationIp: 93.184.216.34
    QueryName: example.com

    이 함수는 Message 문자열에서 특정 필드 값을 추출한다.
    """
    if not message:
        return None

    pattern = rf"^{re.escape(field_name)}:\s*(.+)$"
    return find_first(pattern, message)


def extract_windows_event_field(message: str, label: str) -> Optional[str]:
    """
    Security / PowerShell 이벤트 Message에서 라벨 기반 값을 추출한다.
    Windows 이벤트 Message는 환경/언어에 따라 포맷이 다를 수 있어서
    처음에는 보조적으로만 사용한다.
    """
    if not message:
        return None

    pattern = rf"{re.escape(label)}:\s*(.+)"
    return find_first(pattern, message)


def normalize_source_name(filename: str, provider_name: str = "") -> str:
    name = f"{filename} {provider_name}".lower()

    if "sysmon" in name:
        return "Sysmon"
    if "powershell" in name:
        return "PowerShell"
    if "security" in name:
        return "Security"

    return provider_name or "Unknown"


def safe_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except Exception:
        return None


# -----------------------------
# Event normalizer
# -----------------------------

def normalize_row(row: Dict[str, str], source_file: Path, case_id: str) -> Dict[str, Any]:
    message = row.get("Message", "") or ""
    provider = row.get("ProviderName", "") or ""
    source = normalize_source_name(source_file.name, provider)
    event_id = safe_int(row.get("Id"))

    # 공통 필드
    normalized = {
        "case_id": case_id,
        "timestamp": row.get("TimeCreated"),
        "source": source,
        "provider": provider,
        "event_id": event_id,
        "level": row.get("LevelDisplayName"),
        "host": None,
        "user": None,

        # Process related
        "image": None,
        "command_line": None,
        "parent_image": None,
        "parent_command_line": None,
        "process_id": None,
        "parent_process_id": None,

        # File related
        "target_filename": None,

        # Network / DNS related
        "destination_ip": None,
        "destination_port": None,
        "query_name": None,

        # PowerShell
        "script_block_text": None,

        # Raw
        "raw_message": message,
        "source_file": source_file.name,
    }

    # -----------------------------
    # Sysmon parsing
    # -----------------------------
    if source == "Sysmon":
        normalized["user"] = extract_sysmon_field(message, "User")
        normalized["image"] = extract_sysmon_field(message, "Image")
        normalized["command_line"] = extract_sysmon_field(message, "CommandLine")
        normalized["parent_image"] = extract_sysmon_field(message, "ParentImage")
        normalized["parent_command_line"] = extract_sysmon_field(message, "ParentCommandLine")
        normalized["process_id"] = extract_sysmon_field(message, "ProcessId")
        normalized["parent_process_id"] = extract_sysmon_field(message, "ParentProcessId")

        # Sysmon Event ID 11: FileCreate
        normalized["target_filename"] = extract_sysmon_field(message, "TargetFilename")

        # Sysmon Event ID 3: Network Connection
        normalized["destination_ip"] = extract_sysmon_field(message, "DestinationIp")
        normalized["destination_port"] = extract_sysmon_field(message, "DestinationPort")

        # Sysmon Event ID 22: DNS Query
        normalized["query_name"] = extract_sysmon_field(message, "QueryName")

        # 일부 Sysmon 구성에서는 Computer/Hostname 필드가 Message에 들어갈 수 있음
        normalized["host"] = extract_sysmon_field(message, "Computer") or extract_sysmon_field(message, "Hostname")

    # -----------------------------
    # PowerShell parsing
    # -----------------------------
    elif source == "PowerShell":
        normalized["user"] = extract_windows_event_field(message, "User")
        normalized["script_block_text"] = (
            extract_windows_event_field(message, "ScriptBlock Text")
            or extract_windows_event_field(message, "ScriptBlockText")
        )

        # 한국어/영문 환경 모두에서 ScriptBlock 추출이 잘 안 될 수 있어서,
        # 4104 이벤트는 raw_message 자체를 분석 대상으로 보존한다.
        if event_id == 4104 and not normalized["script_block_text"]:
            normalized["script_block_text"] = message

        # PowerShell 로그 안에서 명령어가 보이면 command_line에도 복사
        if normalized["script_block_text"]:
            normalized["command_line"] = normalized["script_block_text"]

    # -----------------------------
    # Security parsing
    # -----------------------------
    elif source == "Security":
        # 4688 프로세스 생성 이벤트에서 자주 보이는 필드
        normalized["user"] = (
            extract_windows_event_field(message, "Account Name")
            or extract_windows_event_field(message, "SubjectUserName")
        )

        normalized["image"] = (
            extract_windows_event_field(message, "New Process Name")
            or extract_windows_event_field(message, "Process Name")
        )

        normalized["command_line"] = (
            extract_windows_event_field(message, "Process Command Line")
            or extract_windows_event_field(message, "Command Line")
        )

        normalized["parent_image"] = extract_windows_event_field(message, "Creator Process Name")

    return normalized


def read_csv_events(raw_dir: Path, case_id: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []

    csv_files = sorted(raw_dir.glob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {raw_dir}")

    for csv_file in csv_files:
        print(f"[+] Reading {csv_file}")

        with csv_file.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)

            for row in reader:
                event = normalize_row(row, csv_file, case_id)

                # timestamp 없는 이벤트는 분석 대상에서 제외하지 않고 보존할 수도 있지만,
                # 초반에는 타임라인 품질을 위해 제외한다.
                if not event.get("timestamp"):
                    continue

                events.append(event)

    events.sort(key=lambda x: x.get("timestamp") or "")

    return events


def write_jsonl(events: List[Dict[str, Any]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

    print(f"[+] Wrote {len(events)} events to {output_path}")


def write_preview_json(events: List[Dict[str, Any]], output_path: Path, limit: int = 20) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(events[:limit], f, ensure_ascii=False, indent=2)

    print(f"[+] Wrote preview to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Normalize Windows CSV event logs into DFIR events.jsonl"
    )
    parser.add_argument("--case-id", required=True, help="Case ID, e.g. CASE-001")
    parser.add_argument("--raw-dir", required=True, help="Raw CSV directory")
    parser.add_argument("--out-dir", required=True, help="Processed output directory")

    args = parser.parse_args()

    case_id = args.case_id
    raw_dir = Path(args.raw_dir)
    out_dir = Path(args.out_dir)

    events = read_csv_events(raw_dir, case_id)

    write_jsonl(events, out_dir / "events.jsonl")
    write_preview_json(events, out_dir / "events_preview.json")


if __name__ == "__main__":
    main()