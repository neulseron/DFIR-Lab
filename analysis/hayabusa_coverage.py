import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


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


def build_coverage(correlation_data: Dict[str, Any], hayabusa_data: Dict[str, Any]) -> Dict[str, Any]:
    matches = correlation_data.get("matches", [])
    findings = hayabusa_data.get("findings", [])

    timeline_rows = correlation_data.get("timeline", [])
    timeline_rows = [
        row for row in timeline_rows
        if row.get("severity") != "Informational"
    ]

    matched_hayabusa_ids = set()
    matched_evidence_ids = set()

    both_rows = []
    internal_only_rows = []

    for row in timeline_rows:
        evidence_id = row.get("evidence_id")
        hayabusa_matches = row.get("hayabusa_matches", [])

        if hayabusa_matches:
            matched_evidence_ids.add(evidence_id)

            for m in hayabusa_matches:
                if m.get("hayabusa_id"):
                    matched_hayabusa_ids.add(m.get("hayabusa_id"))

            both_rows.append({
                "evidence_id": evidence_id,
                "timestamp": row.get("timestamp"),
                "severity": row.get("severity"),
                "stage": row.get("stage"),

                # 내부 기준
                "internal_type": row.get("evidence_type") or row.get("stage"),
                "internal_rule": row.get("title") or row.get("rule_id"),

                # Hayabusa 기준
                "hayabusa_rule_types": "; ".join(
                    sorted({
                        str(m.get("hayabusa_behavior"))
                        for m in hayabusa_matches
                        if m.get("hayabusa_behavior")
                    })
                ),
                "hayabusa_rules": "; ".join(
                    sorted({
                        str(m.get("rule_title"))
                        for m in hayabusa_matches
                        if m.get("rule_title")
                    })
                ),
            })
        else:
            internal_only_rows.append({
                "evidence_id": evidence_id,
                "timestamp": row.get("timestamp"),
                "severity": row.get("severity"),
                "stage": row.get("stage"),
                "action": row.get("action"),
            })

    hayabusa_only_rows = []

    for finding in findings:
        hayabusa_id = finding.get("hayabusa_id")

        if hayabusa_id not in matched_hayabusa_ids:
            hayabusa_only_rows.append({
                "hayabusa_id": hayabusa_id,
                "timestamp": finding.get("timestamp"),
                "level": finding.get("level"),
                "rule_title": finding.get("rule_title"),
                "channel": finding.get("channel"),
                "event_id": finding.get("event_id"),
            })

    summary = {
        "both": len(both_rows),
        "internal_only": len(internal_only_rows),
        "hayabusa_only": len(hayabusa_only_rows),
        "internal_total": len(timeline_rows),
        "hayabusa_total": len(findings),
    }

    return {
        "summary": summary,
        "both": both_rows,
        "internal_only": internal_only_rows,
        "hayabusa_only": hayabusa_only_rows,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Build detection coverage comparison between internal rules and Hayabusa"
    )
    parser.add_argument("--correlation", required=True)
    parser.add_argument("--hayabusa", required=True)
    parser.add_argument("--out", required=True)

    args = parser.parse_args()

    correlation_data = load_json(Path(args.correlation), default={})
    hayabusa_data = load_json(Path(args.hayabusa), default={})

    result = build_coverage(correlation_data, hayabusa_data)

    write_json(result, Path(args.out))


if __name__ == "__main__":
    main()