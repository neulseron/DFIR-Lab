# analysis/hayabusa_importer.py

import re
import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import pandas as pd
from datetime import timedelta


COLUMN_ALIASES = {
    "timestamp": ["Timestamp", "timestamp", "datetime", "Date", "Time"],
    "level": ["Level", "level", "Severity", "severity", "AlertLevel"],
    "rule_title": ["RuleTitle", "Rule Title", "Title", "title", "Rule"],
    "rule_id": ["RuleID", "Rule ID", "rule_id", "SigmaRuleID"],
    "computer": ["Computer", "ComputerName", "Hostname", "host"],
    "channel": ["Channel", "LogName", "EventLog"],
    "event_id": ["EventID", "Event ID", "EID", "event_id"],
    "record_id": ["RecordID", "Record ID"],
    "details": ["Details", "Message", "EventData", "ExtraFieldInfo"],
}


def pick(row: Dict[str, Any], names: List[str]) -> Optional[Any]:
    for name in names:
        if name in row and pd.notna(row[name]):
            return row[name]
    return None


def normalize_level(value: Any) -> str:
    text = str(value or "").strip().lower()

    mapping = {
        "emergency": "Critical",
        "alert": "Critical",
        "critical": "Critical",
        "crit": "Critical",
        "high": "High",
        "med": "Medium",
        "medium": "Medium",
        "low": "Low",
        "informational": "Informational",
        "info": "Informational",
    }

    return mapping.get(text, str(value or "Unknown").strip() or "Unknown")


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


def parse_time(value: Any) -> Optional[pd.Timestamp]:
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    text = normalize_korean_ampm(text)

    try:
        ts = pd.to_datetime(text, errors="coerce")

        if pd.isna(ts):
            return None

        ts = pd.Timestamp(ts)

        # Hayabusa는 +09:00 같은 timezone이 붙어 있고,
        # 자체 timeline은 timezone이 없으므로 비교를 위해 local wall time 기준으로 timezone 제거
        if ts.tzinfo is not None:
            ts = ts.tz_localize(None)

        return ts

    except Exception:
        return None


def normalize_hayabusa_csv(
    csv_path: Path,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    margin_minutes: int = 5,
) -> Dict[str, Any]:
    df = pd.read_csv(csv_path)

    raw_total = len(df)
    findings = []


    start_ts = parse_time(start_time)
    end_ts = parse_time(end_time)

    if start_ts is not None:
        start_ts = start_ts - pd.Timedelta(minutes=margin_minutes)

    if end_ts is not None:
        end_ts = end_ts + pd.Timedelta(minutes=margin_minutes)


    for idx, row in df.iterrows():
        item = row.to_dict()

        timestamp_value = pick(item, COLUMN_ALIASES["timestamp"])
        finding_ts = parse_time(timestamp_value)

        if start_ts is not None and finding_ts is not None and finding_ts < start_ts:
            continue

        if end_ts is not None and finding_ts is not None and finding_ts > end_ts:
            continue

        finding = {
            "hayabusa_id": f"HY-{idx + 1:05d}",
            "timestamp": timestamp_value,
            "level": normalize_level(pick(item, COLUMN_ALIASES["level"])),
            "rule_title": pick(item, COLUMN_ALIASES["rule_title"]),
            "rule_id": pick(item, COLUMN_ALIASES["rule_id"]),
            "computer": pick(item, COLUMN_ALIASES["computer"]),
            "channel": pick(item, COLUMN_ALIASES["channel"]),
            "event_id": pick(item, COLUMN_ALIASES["event_id"]),
            "record_id": pick(item, COLUMN_ALIASES["record_id"]),
            "details": pick(item, COLUMN_ALIASES["details"]),
            "raw": item,
        }

        findings.append(finding)

    summary = summarize(findings)
    summary["raw_total"] = raw_total
    summary["filtered_total"] = len(findings)
    summary["filter_start"] = str(start_ts) if start_ts is not None else None
    summary["filter_end"] = str(end_ts) if end_ts is not None else None
    summary["filter_margin_minutes"] = margin_minutes
    summary["filter_applied"] = start_ts is not None and end_ts is not None

    return {
        "summary": summary,
        "findings": findings,
    }


def summarize(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_level = {}
    by_rule = {}
    by_channel = {}

    first_seen = None
    last_seen = None

    for item in findings:
        level = item.get("level") or "Unknown"
        rule = item.get("rule_title") or "Unknown"
        channel = item.get("channel") or "Unknown"
        ts = item.get("timestamp")

        by_level[level] = by_level.get(level, 0) + 1
        by_rule[rule] = by_rule.get(rule, 0) + 1
        by_channel[channel] = by_channel.get(channel, 0) + 1

        if ts:
            ts = str(ts)
            if first_seen is None or ts < first_seen:
                first_seen = ts
            if last_seen is None or ts > last_seen:
                last_seen = ts

    return {
        "total": len(findings),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "by_level": by_level,
        "by_rule": by_rule,
        "by_channel": by_channel,
    }


def write_json(data: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f"[+] Wrote {path}")


def main():
    parser = argparse.ArgumentParser(
        description="Import Hayabusa CSV timeline into DFIR dashboard format"
    )
    parser.add_argument("--csv", required=True, help="Hayabusa CSV path")
    parser.add_argument("--out-findings", required=True, help="Output findings JSON")
    parser.add_argument("--out-summary", required=True, help="Output summary JSON")
    parser.add_argument("--start-time", required=False, help="Case start time for filtering")
    parser.add_argument("--end-time", required=False, help="Case end time for filtering")
    parser.add_argument("--time-margin-minutes", type=int, default=5)

    args = parser.parse_args()

    result = normalize_hayabusa_csv(
        Path(args.csv),
        start_time=args.start_time,
        end_time=args.end_time,
        margin_minutes=args.time_margin_minutes,
    )

    write_json(result, Path(args.out_findings))
    write_json(result["summary"], Path(args.out_summary))


if __name__ == "__main__":
    main()