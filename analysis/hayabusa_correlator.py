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


def parse_time(value: Any) -> Optional[datetime]:
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    candidates = [
        "%Y-%m-%d %H:%M:%S%.f %z",
        "%Y-%m-%d %H:%M:%S.%f %z",
        "%Y-%m-%d %H:%M:%S %z",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
    ]

    # fromisoformat 우선 시도
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except Exception:
        pass

    for fmt in candidates:
        try:
            return datetime.strptime(text, fmt)
        except Exception:
            continue

    return None


def seconds_diff(a: datetime, b: datetime) -> float:
    if a.tzinfo is not None and b.tzinfo is None:
        b = b.replace(tzinfo=a.tzinfo)
    elif a.tzinfo is None and b.tzinfo is not None:
        a = a.replace(tzinfo=b.tzinfo)

    return abs((a - b).total_seconds())


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
        row_ts = parse_time(row.get("timestamp"))
        related = []

        if row_ts:
            for item in parsed_findings:
                diff = seconds_diff(row_ts, item["timestamp_dt"])

                if diff <= window_seconds:
                    finding = item["finding"]
                    related.append({
                        "hayabusa_id": finding.get("hayabusa_id"),
                        "timestamp": finding.get("timestamp"),
                        "level": finding.get("level"),
                        "rule_title": finding.get("rule_title"),
                        "channel": finding.get("channel"),
                        "event_id": finding.get("event_id"),
                        "time_diff_seconds": round(diff, 3),
                    })

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