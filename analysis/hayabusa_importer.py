# analysis/hayabusa_importer.py

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd


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


def normalize_hayabusa_csv(csv_path: Path) -> Dict[str, Any]:
    df = pd.read_csv(csv_path)

    findings = []

    for idx, row in df.iterrows():
        item = row.to_dict()

        finding = {
            "hayabusa_id": f"HY-{idx + 1:05d}",
            "timestamp": pick(item, COLUMN_ALIASES["timestamp"]),
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

    args = parser.parse_args()

    result = normalize_hayabusa_csv(Path(args.csv))

    write_json(result, Path(args.out_findings))
    write_json(result["summary"], Path(args.out_summary))


if __name__ == "__main__":
    main()