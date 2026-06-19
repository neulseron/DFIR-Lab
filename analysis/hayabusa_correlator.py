import re
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default

    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(data: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f"[+] Wrote {path}")


def normalize_korean_ampm(text: str) -> str:
    """
    예:
    2026-06-16 오후 6:19:43 -> 2026-06-16 18:19:43
    2026-06-16 오전 9:01:02 -> 2026-06-16 09:01:02
    """
    pattern = r"(오전|오후)\s+(\d{1,2}):(\d{2}):(\d{2}(?:\.\d+)?)"
    match = re.search(pattern, text)

    if not match:
        return text

    ampm = match.group(1)
    hour = int(match.group(2))
    minute = match.group(3)
    second = match.group(4)

    if ampm == "오후" and hour < 12:
        hour += 12
    elif ampm == "오전" and hour == 12:
        hour = 0

    replacement = f"{hour:02d}:{minute}:{second}"

    return re.sub(pattern, replacement, text)


def parse_time(value: Any) -> Optional[datetime]:
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    text = normalize_korean_ampm(text)

    candidates = [
        "%Y-%m-%d %H:%M:%S.%f %z",
        "%Y-%m-%d %H:%M:%S %z",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
    ]

    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))

        # Hayabusa의 +09:00과 자체 Timeline의 timezone 없음 문제를 피하기 위해
        # local wall time 기준으로 timezone 제거
        if dt.tzinfo is not None:
            dt = dt.replace(tzinfo=None)

        return dt
    except Exception:
        pass

    for fmt in candidates:
        try:
            dt = datetime.strptime(text, fmt)

            if dt.tzinfo is not None:
                dt = dt.replace(tzinfo=None)

            return dt
        except Exception:
            continue

    return None


def seconds_diff(a: datetime, b: datetime) -> float:
    if a.tzinfo is not None and b.tzinfo is None:
        b = b.replace(tzinfo=a.tzinfo)
    elif a.tzinfo is None and b.tzinfo is not None:
        a = a.replace(tzinfo=b.tzinfo)

    return abs((a - b).total_seconds())



def normalize_text(value: Any) -> str:
    return str(value or "").strip().lower()


def normalize_event_id(value: Any) -> Optional[str]:
    if value is None:
        return None

    text = str(value).strip()

    if not text or text.lower() == "nan":
        return None

    if text.endswith(".0"):
        text = text[:-2]

    return text


def infer_timeline_behavior(row: Dict[str, Any]) -> str:
    """
    자체 Timeline/Evidence row를 넓은 행위 유형으로 분류한다.
    event_id보다 rule_id/stage/action을 우선 사용한다.
    """
    rule_id = normalize_text(row.get("rule_id"))
    stage = normalize_text(row.get("stage"))
    action = normalize_text(row.get("action"))
    title = normalize_text(row.get("title"))
    source = normalize_text(row.get("source"))
    event_id = normalize_event_id(row.get("event_id"))

    text = " ".join([rule_id, stage, action, title, source, str(event_id or "")])

    # PowerShell / script 계열
    if rule_id in {"ev-ps-001", "ev-ps-002", "ev-ps-003", "ev-sysmon-001"}:
        return "powershell"
    if "powershell" in text or "pwsh" in text or event_id in {"4103", "4104"}:
        return "powershell"

    # 로그온 컨텍스트
    if rule_id == "ev-sec-002" or event_id == "4624" or "logon" in text or "로그온" in text:
        return "logon"

    # 프로세스 실행
    if rule_id in {"ev-sysmon-002", "ev-sysmon-003", "ev-sec-001"}:
        return "process_execution"
    if "process execution" in text or "프로세스" in text or "cmd.exe" in text or event_id in {"1", "4688"}:
        return "process_execution"

    # 파일/스테이징
    if rule_id == "ev-sysmon-004":
        return "file_activity"
    if "file" in text or "temp" in text or "파일" in text or "staging" in text or event_id == "11":
        return "file_activity"

    # 네트워크/DNS
    if rule_id in {"ev-sysmon-005", "ev-sysmon-006", "ev-ps-002"}:
        return "network"
    if "network" in text or "dns" in text or "네트워크" in text or "질의" in text or event_id in {"3", "22"}:
        return "network"

    # 방어 회피
    if rule_id == "ev-sec-003" or event_id == "1102":
        return "defense_evasion"
    if "clear" in text or "삭제" in text or "evasion" in text:
        return "defense_evasion"

    # Discovery
    if "discovery" in text or "탐색" in text or "whoami" in text or "ipconfig" in text:
        return "discovery"

    return "unknown"


def infer_hayabusa_behavior(finding: Dict[str, Any]) -> str:
    """
    Hayabusa finding을 넓은 행위 유형으로 분류한다.
    rule_title/channel/event_id 기반으로 추정한다.
    """
    rule_title = normalize_text(finding.get("rule_title"))
    channel = normalize_text(finding.get("channel"))
    event_id = normalize_event_id(finding.get("event_id"))

    text = " ".join([rule_title, channel, str(event_id or "")])

    # PowerShell / script 계열
    if (
        "pwsh" in text
        or "powershell" in text
        or "script" in text
        or event_id in {"4103", "4104"}
    ):
        return "powershell"

    # 로그온 계열
    if "logon" in text or event_id == "4624":
        return "logon"

    # 프로세스 실행/종료/CMD
    if (
        "proc exec" in text
        or "process" in text
        or "proc terminated" in text
        or "cmd shell" in text
        or "shell" in text
        or event_id in {"1", "4688"}
    ):
        return "process_execution"

    # Credential 계열
    if (
        "credential" in text
        or "credman" in text
        or "credential manager" in text
        or event_id == "5379"
    ):
        return "credential_access"

    # 네트워크/DNS/다운로드
    if (
        "network" in text
        or "dns" in text
        or "download" in text
        or "web" in text
        or "http" in text
        or event_id in {"3", "22"}
    ):
        return "network"

    # 파일/압축/스테이징
    if (
        "file" in text
        or "archive" in text
        or "temp" in text
        or "created" in text
        or event_id == "11"
    ):
        return "file_activity"

    # 방어 회피
    if (
        "clear" in text
        or "log cleared" in text
        or "defense" in text
        or "evasion" in text
        or event_id == "1102"
    ):
        return "defense_evasion"

    # Discovery
    if (
        "discovery" in text
        or "enumerat" in text
        or "whoami" in text
        or "ipconfig" in text
    ):
        return "discovery"

    return "unknown"


def behaviors_are_similar(timeline_behavior: str, hayabusa_behavior: str) -> bool:
    """
    서로 비슷한 행위 유형인지 판단한다.
    너무 넓게 묶지 않도록 logon은 logon끼리만 매칭한다.
    """
    if timeline_behavior == "unknown" or hayabusa_behavior == "unknown":
        return False

    if timeline_behavior == hayabusa_behavior:
        return True

    similar_groups = [
        {"powershell", "process_execution"},
        {"discovery", "process_execution"},
        {"network", "powershell"},
        {"file_activity", "powershell"},
    ]

    for group in similar_groups:
        if timeline_behavior in group and hayabusa_behavior in group:
            return True

    return False


def severity_rank(level: Any) -> int:
    value = normalize_text(level)

    order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "informational": 4,
        "info": 4,
    }

    return order.get(value, 9)





def correlate(
    timeline_data: Dict[str, Any],
    hayabusa_data: Dict[str, Any],
    window_seconds: int = 60,
) -> Dict[str, Any]:
    timeline_rows = timeline_data.get("timeline", [])
    findings = hayabusa_data.get("findings", [])

    parsed_findings = []

    for finding in findings:
        ts = parse_time(finding.get("timestamp"))
        if not ts:
            continue

        parsed_findings.append({
            "timestamp_dt": ts,
            "finding": finding,
        })

    matches = []
    timeline_with_hayabusa = []

    for row in timeline_rows:

        # Informational 전체 제외
        if row.get("severity") == "Informational":
            new_row = dict(row)
            new_row["hayabusa_matches"] = []
            new_row["hayabusa_match_count"] = 0
            timeline_with_hayabusa.append(new_row)
            continue


        row_ts = parse_time(row.get("timestamp"))
        related = []

        if row_ts:
            timeline_behavior = infer_timeline_behavior(row)
            timeline_event_id = normalize_event_id(row.get("event_id"))

            candidates = []

            for item in parsed_findings:
                diff = seconds_diff(row_ts, item["timestamp_dt"])

                if diff > window_seconds:
                    continue

                finding = item["finding"]
                hayabusa_behavior = infer_hayabusa_behavior(finding)
                hayabusa_event_id = normalize_event_id(finding.get("event_id"))

                event_id_matched = (
                    timeline_event_id is not None
                    and hayabusa_event_id is not None
                    and timeline_event_id == hayabusa_event_id
                )

                behavior_matched = behaviors_are_similar(
                    timeline_behavior,
                    hayabusa_behavior,
                )

                if not behavior_matched:
                    continue

                if event_id_matched:
                    match_type = "time+event_id+behavior"
                    match_score = 0
                else:
                    match_type = "time+behavior"
                    match_score = 1

                candidates.append({
                    "hayabusa_id": finding.get("hayabusa_id"),
                    "timestamp": finding.get("timestamp"),
                    "level": finding.get("level"),
                    "rule_title": finding.get("rule_title"),
                    "channel": finding.get("channel"),
                    "event_id": finding.get("event_id"),
                    "time_diff_seconds": round(diff, 3),
                    "match_type": match_type,
                    "timeline_behavior": timeline_behavior,
                    "hayabusa_behavior": hayabusa_behavior,
                    "_sort_key": (
                        match_score,
                        severity_rank(finding.get("level")),
                        diff,
                    ),
                })

            candidates.sort(key=lambda x: x["_sort_key"])

            # 한 Evidence에 수백 개가 붙는 것을 막기 위해 상위 10개만 유지
            related = [
                {k: v for k, v in item.items() if k != "_sort_key"}
                for item in candidates[:10]
            ]

        new_row = dict(row)
        new_row["hayabusa_matches"] = related
        new_row["hayabusa_match_count"] = len(related)
        timeline_with_hayabusa.append(new_row)

        if related:
            matches.append({
                "evidence_id": row.get("evidence_id"),
                "timeline_timestamp": row.get("timestamp"),
                "timeline_action": row.get("action"),
                "matches": related,
            })

    return {
        "summary": {
            "window_seconds": window_seconds,
            "timeline_rows": len(timeline_rows),
            "hayabusa_findings": len(findings),
            "matched_timeline_rows": len(matches),
            "total_matches": sum(len(x.get("matches", [])) for x in matches),
        },
        "matches": matches,
        "timeline": timeline_with_hayabusa,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Correlate project timeline with Hayabusa findings by timestamp"
    )
    parser.add_argument("--timeline", required=True)
    parser.add_argument("--hayabusa", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--window-seconds", type=int, default=60)

    args = parser.parse_args()

    timeline_data = load_json(Path(args.timeline), default={})
    hayabusa_data = load_json(Path(args.hayabusa), default={})

    result = correlate(
        timeline_data=timeline_data,
        hayabusa_data=hayabusa_data,
        window_seconds=args.window_seconds,
    )

    write_json(result, Path(args.out))


if __name__ == "__main__":
    main()