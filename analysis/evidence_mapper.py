# analysis/evidence_mapper.py

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    events = []

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))

    return events


def load_rules(path: Path) -> List[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    return data.get("rules", [])


def lower(value: Optional[str]) -> str:
    return (value or "").lower()


def contains_any(value: Optional[str], keywords: List[str]) -> bool:
    value_lower = lower(value)

    for keyword in keywords:
        if keyword.lower() in value_lower:
            return True

    return False


def find_matching_keywords(value: Optional[str], keywords: List[str]) -> List[str]:
    value_lower = lower(value)
    matched = []

    for keyword in keywords:
        if keyword.lower() in value_lower:
            matched.append(keyword)

    return matched


def explain_rule_match(event: Dict[str, Any], rule: Dict[str, Any]) -> tuple[bool, List[Dict[str, Any]]]:
    """
    룰 매칭 여부와 함께 어떤 조건이 어떤 필드에서 만족됐는지 설명한다.
    """
    details: List[Dict[str, Any]] = []

    if rule.get("source") and event.get("source") != rule.get("source"):
        return False, []

    if rule.get("event_id") is not None and event.get("event_id") != rule.get("event_id"):
        return False, []

    conditions = rule.get("conditions") or {}

    if conditions.get("always") is True:
        details.append({
            "condition": "always",
            "field": "-",
            "matched_value": "true",
            "description": "Rule condition is always true for this source/event_id."
        })
        return True, details

    if "image_contains" in conditions:
        matched = find_matching_keywords(event.get("image"), conditions["image_contains"])
        if not matched:
            return False, []

        details.append({
            "condition": "image_contains",
            "field": "image",
            "matched_value": ", ".join(matched),
            "description": f"Image field contains: {', '.join(matched)}"
        })

    if "command_contains" in conditions:
        command_sources = {
            "command_line": event.get("command_line") or "",
            "script_block_text": event.get("script_block_text") or "",
            "raw_message": event.get("raw_message") or "",
        }

        matched_any = []

        for field, value in command_sources.items():
            matched = find_matching_keywords(value, conditions["command_contains"])
            if matched:
                matched_any.extend(matched)
                details.append({
                    "condition": "command_contains",
                    "field": field,
                    "matched_value": ", ".join(matched),
                    "description": f"{field} contains: {', '.join(matched)}"
                })

        if not matched_any:
            return False, []

    if "target_filename_contains" in conditions:
        matched = find_matching_keywords(
            event.get("target_filename"),
            conditions["target_filename_contains"],
        )
        if not matched:
            return False, []

        details.append({
            "condition": "target_filename_contains",
            "field": "target_filename",
            "matched_value": ", ".join(matched),
            "description": f"Target filename contains: {', '.join(matched)}"
        })

    if conditions.get("destination_ip_exists") is True:
        if not field_exists(event, "destination_ip"):
            return False, []

        details.append({
            "condition": "destination_ip_exists",
            "field": "destination_ip",
            "matched_value": event.get("destination_ip"),
            "description": "Destination IP field exists."
        })

    if conditions.get("external_destination_ip") is True:
        ip = event.get("destination_ip")
        if not ip or is_private_ip(ip):
            return False, []

        details.append({
            "condition": "external_destination_ip",
            "field": "destination_ip",
            "matched_value": ip,
            "description": "Destination IP is not private/internal."
        })

    if conditions.get("query_name_exists") is True:
        if not field_exists(event, "query_name"):
            return False, []

        details.append({
            "condition": "query_name_exists",
            "field": "query_name",
            "matched_value": event.get("query_name"),
            "description": "DNS query name exists."
        })

    if conditions.get("script_block_exists") is True:
        if not field_exists(event, "script_block_text"):
            return False, []

        details.append({
            "condition": "script_block_exists",
            "field": "script_block_text",
            "matched_value": "exists",
            "description": "PowerShell script block text exists."
        })

    if conditions.get("image_exists") is True:
        if not field_exists(event, "image"):
            return False, []

        details.append({
            "condition": "image_exists",
            "field": "image",
            "matched_value": event.get("image"),
            "description": "Process image field exists."
        })

    return True, details


def field_exists(event: Dict[str, Any], field: str) -> bool:
    value = event.get(field)
    return value is not None and str(value).strip() != ""


def is_private_ip(ip: str) -> bool:
    if not ip:
        return False

    ip = ip.strip()

    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("172.16.")
        or ip.startswith("172.17.")
        or ip.startswith("172.18.")
        or ip.startswith("172.19.")
        or ip.startswith("172.20.")
        or ip.startswith("172.21.")
        or ip.startswith("172.22.")
        or ip.startswith("172.23.")
        or ip.startswith("172.24.")
        or ip.startswith("172.25.")
        or ip.startswith("172.26.")
        or ip.startswith("172.27.")
        or ip.startswith("172.28.")
        or ip.startswith("172.29.")
        or ip.startswith("172.30.")
        or ip.startswith("172.31.")
        or ip.startswith("127.")
        or ip == "::1"
    )


def event_matches_rule(event: Dict[str, Any], rule: Dict[str, Any]) -> bool:
    if rule.get("source") and event.get("source") != rule.get("source"):
        return False

    if rule.get("event_id") is not None and event.get("event_id") != rule.get("event_id"):
        return False

    conditions = rule.get("conditions") or {}

    if conditions.get("always") is True:
        return True

    # image_contains
    if "image_contains" in conditions:
        if not contains_any(event.get("image"), conditions["image_contains"]):
            return False

    # command_contains: command_line, script_block_text, raw_message를 함께 검사
    if "command_contains" in conditions:
        combined_command = " ".join(
            [
                event.get("command_line") or "",
                event.get("script_block_text") or "",
                event.get("raw_message") or "",
            ]
        )
        if not contains_any(combined_command, conditions["command_contains"]):
            return False

    # target_filename_contains
    if "target_filename_contains" in conditions:
        if not contains_any(event.get("target_filename"), conditions["target_filename_contains"]):
            return False

    # destination_ip_exists
    if conditions.get("destination_ip_exists") is True:
        if not field_exists(event, "destination_ip"):
            return False

    # external_destination_ip
    if conditions.get("external_destination_ip") is True:
        ip = event.get("destination_ip")
        if not ip or is_private_ip(ip):
            return False

    # query_name_exists
    if conditions.get("query_name_exists") is True:
        if not field_exists(event, "query_name"):
            return False

    # script_block_exists
    if conditions.get("script_block_exists") is True:
        if not field_exists(event, "script_block_text"):
            return False

    # image_exists
    if conditions.get("image_exists") is True:
        if not field_exists(event, "image"):
            return False

    return True


def build_evidence_item(
    event: Dict[str, Any],
    rule: Dict[str, Any],
    index: int,
    match_details: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    evidence_id = f"EV-{index:05d}"

    summary_parts = []

    if event.get("image"):
        summary_parts.append(f"Image={event.get('image')}")

    if event.get("command_line"):
        cmd = str(event.get("command_line"))
        if len(cmd) > 180:
            cmd = cmd[:180] + "..."
        summary_parts.append(f"CommandLine={cmd}")

    if event.get("target_filename"):
        summary_parts.append(f"TargetFile={event.get('target_filename')}")

    if event.get("destination_ip"):
        summary_parts.append(
            f"Destination={event.get('destination_ip')}:{event.get('destination_port') or ''}"
        )

    if event.get("query_name"):
        summary_parts.append(f"Query={event.get('query_name')}")

    summary = " | ".join(summary_parts) if summary_parts else rule.get("title", "Evidence observed")

    match_details = match_details or []
    matched_fields = sorted({item.get("field") for item in match_details if item.get("field") and item.get("field") != "-"})
    matched_keywords = sorted({item.get("matched_value") for item in match_details if item.get("matched_value")})
    matched_reason = "; ".join(
        item.get("description", "")
        for item in match_details
        if item.get("description")
    )

    
    return {
        "evidence_id": evidence_id,
        "case_id": event.get("case_id"),
        "timestamp": event.get("timestamp"),
        "source": event.get("source"),
        "event_id": event.get("event_id"),
        "rule_id": rule.get("rule_id"),
        "title": rule.get("title"),
        "evidence_type": rule.get("evidence_type"),
        "attack_stage": rule.get("attack_stage"),
        "severity": rule.get("severity"),
        "forensic_meaning": rule.get("forensic_meaning"),
        "summary": summary,
        "matched_reason": matched_reason,
        "matched_fields": matched_fields,
        "matched_keywords": matched_keywords,
        "match_details": match_details,

        # 원본 이벤트의 핵심 필드도 같이 보존
        "user": event.get("user"),
        "image": event.get("image"),
        "command_line": event.get("command_line"),
        "parent_image": event.get("parent_image"),
        "target_filename": event.get("target_filename"),
        "destination_ip": event.get("destination_ip"),
        "destination_port": event.get("destination_port"),
        "query_name": event.get("query_name"),
        "source_file": event.get("source_file"),
        "raw_message": event.get("raw_message"),
    }


def map_evidence(events: List[Dict[str, Any]], rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    evidence_items: List[Dict[str, Any]] = []
    index = 1

    for event in events:
        matched = False

        for rule in rules:
            is_matched, match_details = explain_rule_match(event, rule)

            if is_matched:
                evidence_items.append(
                    build_evidence_item(
                        event=event,
                        rule=rule,
                        index=index,
                        match_details=match_details,
                    )
                )
                index += 1
                matched = True

        # 아무 룰에도 안 걸린 이벤트도 보존하고 싶으면 아래를 활성화할 수 있음.
        # 초반에는 Evidence 품질을 위해 매칭된 이벤트만 저장.
        _ = matched

    evidence_items.sort(key=lambda x: x.get("timestamp") or "")

    return evidence_items


def write_json(data: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f"[+] Wrote {path}")


def print_summary(evidence_items: List[Dict[str, Any]]) -> None:
    by_type = {}
    by_stage = {}
    by_severity = {}

    for item in evidence_items:
        by_type[item.get("evidence_type")] = by_type.get(item.get("evidence_type"), 0) + 1
        by_stage[item.get("attack_stage")] = by_stage.get(item.get("attack_stage"), 0) + 1
        by_severity[item.get("severity")] = by_severity.get(item.get("severity"), 0) + 1

    print("[+] Evidence count:", len(evidence_items))
    print("[+] By evidence_type:", by_type)
    print("[+] By attack_stage:", by_stage)
    print("[+] By severity:", by_severity)


def main():
    parser = argparse.ArgumentParser(
        description="Map normalized events to DFIR evidence items"
    )
    parser.add_argument("--events", required=True, help="Path to events.jsonl")
    parser.add_argument("--rules", required=True, help="Path to evidence_rules.yaml")
    parser.add_argument("--out", required=True, help="Output evidence.json path")

    args = parser.parse_args()

    events_path = Path(args.events)
    rules_path = Path(args.rules)
    out_path = Path(args.out)

    events = load_jsonl(events_path)
    rules = load_rules(rules_path)

    evidence_items = map_evidence(events, rules)

    write_json(evidence_items, out_path)
    print_summary(evidence_items)


if __name__ == "__main__":
    main()