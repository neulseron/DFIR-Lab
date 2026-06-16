# analysis/ioc_extractor.py

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse


# -----------------------------
# Regex patterns
# -----------------------------

IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

URL_PATTERN = re.compile(
    r"\bhttps?://[^\s\"'<>]+",
    re.IGNORECASE
)

# 엄격하지 않은 도메인 패턴. URL, QueryName, raw_message에서 보조적으로 사용.
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
)

WINDOWS_PATH_PATTERN = re.compile(
    r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*"
)

HASH_PATTERN = re.compile(
    r"\b(?:MD5|SHA1|SHA256|IMPHASH)=([A-Fa-f0-9]{32,64})\b"
)

COMMAND_INTEREST_KEYWORDS = [
    "powershell",
    "cmd.exe",
    "whoami",
    "hostname",
    "ipconfig",
    "net user",
    "net localgroup",
    "tasklist",
    "invoke-webrequest",
    "compress-archive",
    "remove-item",
    "set-content",
    "new-item",
    "out-file",
    "curl",
    "wget",
    "bitsadmin",
    "certutil",
]


NOISE_DOMAINS = {
    "microsoft.com",
    "windows.com",
    "msftconnecttest.com",
    "msftncsi.com",
    "digicert.com",
    "akamaiedge.net",
    "akadns.net",
    "azureedge.net",
    "office.com",
    "live.com",
    "bing.com",
}


NOISE_PROCESSES = {
    "svchost.exe",
    "services.exe",
    "lsass.exe",
    "wininit.exe",
    "winlogon.exe",
    "csrss.exe",
    "smss.exe",
    "explorer.exe",
    "dwm.exe",
    "fontdrvhost.exe",
    "conhost.exe",
}


# -----------------------------
# Load helpers
# -----------------------------

def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    items = []

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                items.append(json.loads(line))

    return items


def load_json(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []

    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(data: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f"[+] Wrote {path}")


# -----------------------------
# Utility
# -----------------------------

def normalize_path_basename(path: Optional[str]) -> Optional[str]:
    if not path:
        return None

    value = path.strip().strip('"')
    if "\\" in value:
        return value.split("\\")[-1].lower()

    return value.lower()


def is_private_ip(ip: str) -> bool:
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
        or ip == "0.0.0.0"
    )


def is_noise_domain(domain: str) -> bool:
    domain = domain.lower().strip(".")

    for noise in NOISE_DOMAINS:
        if domain == noise or domain.endswith("." + noise):
            return True

    return False


def clean_url(url: str) -> str:
    return url.rstrip(").,;'\"")


def extract_domain_from_url(url: str) -> Optional[str]:
    try:
        parsed = urlparse(url)
        if parsed.hostname:
            return parsed.hostname.lower()
    except Exception:
        return None

    return None


def make_context(event: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "timestamp": event.get("timestamp"),
        "source": event.get("source"),
        "event_id": event.get("event_id"),
        "source_file": event.get("source_file"),
    }


def event_text_blob(event: Dict[str, Any]) -> str:
    fields = [
        event.get("image"),
        event.get("command_line"),
        event.get("parent_image"),
        event.get("parent_command_line"),
        event.get("target_filename"),
        event.get("destination_ip"),
        event.get("query_name"),
        event.get("script_block_text"),
        event.get("raw_message"),
        event.get("user"),
    ]

    return "\n".join([str(v) for v in fields if v])


def severity_for_ioc(ioc_type: str, value: str, event: Dict[str, Any]) -> str:
    """
    포트폴리오용 간단한 우선순위.
    실제 위협 평판이 아니라, 분석 우선순위 정도로 보면 됨.
    """
    value_lower = value.lower()

    if ioc_type == "ip":
        if is_private_ip(value):
            return "Low"
        return "Medium"

    if ioc_type == "domain":
        if is_noise_domain(value):
            return "Low"
        if value_lower in {"example.com"}:
            return "Low"
        return "Medium"

    if ioc_type == "url":
        if "example.com" in value_lower:
            return "Low"
        return "Medium"

    if ioc_type == "process":
        base = normalize_path_basename(value)
        if base in {"powershell.exe", "cmd.exe", "net.exe", "net1.exe"}:
            return "Medium"
        if base in NOISE_PROCESSES:
            return "Low"
        return "Low"

    if ioc_type == "command":
        suspicious = [
            "invoke-webrequest",
            "compress-archive",
            "executionpolicy bypass",
            "-enc",
            "downloadstring",
            "frombase64string",
        ]
        if any(k in value_lower for k in suspicious):
            return "Medium"
        return "Low"

    if ioc_type == "file_path":
        if "\\temp\\" in value_lower or "\\appdata\\local\\temp\\" in value_lower:
            return "Medium"
        return "Low"

    if ioc_type == "hash":
        return "Medium"

    if ioc_type == "user":
        return "Informational"

    return "Low"


# -----------------------------
# IOC Store
# -----------------------------

class IOCStore:
    def __init__(self) -> None:
        self._items: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def add(
        self,
        ioc_type: str,
        value: Optional[str],
        event: Dict[str, Any],
        source_field: str,
        note: Optional[str] = None,
    ) -> None:
        if not value:
            return

        value = str(value).strip().strip('"').strip("'")
        if not value:
            return

        # URL 끝의 특수문자 정리
        if ioc_type == "url":
            value = clean_url(value)

        # domain 소문자 처리
        if ioc_type == "domain":
            value = value.lower().strip(".")
            if not value or is_noise_domain(value):
                # 노이즈 도메인도 보고 싶으면 이 return을 제거하면 됨.
                return

        # process는 경로 또는 파일명 모두 허용
        if ioc_type == "process":
            base = normalize_path_basename(value)
            if base in NOISE_PROCESSES:
                # 너무 많은 OS 기본 프로세스는 제외
                return

        key = (ioc_type, value)

        context = make_context(event)

        if key not in self._items:
            self._items[key] = {
                "type": ioc_type,
                "value": value,
                "first_seen": event.get("timestamp"),
                "last_seen": event.get("timestamp"),
                "count": 1,
                "severity": severity_for_ioc(ioc_type, value, event),
                "sources": [
                    {
                        **context,
                        "source_field": source_field,
                    }
                ],
                "notes": [],
            }

            if note:
                self._items[key]["notes"].append(note)

            return

        item = self._items[key]
        item["count"] += 1

        ts = event.get("timestamp")
        if ts:
            if not item.get("first_seen") or ts < item["first_seen"]:
                item["first_seen"] = ts
            if not item.get("last_seen") or ts > item["last_seen"]:
                item["last_seen"] = ts

        # source는 너무 커지지 않게 최대 5개만 보관
        if len(item["sources"]) < 5:
            item["sources"].append(
                {
                    **context,
                    "source_field": source_field,
                }
            )

        if note and note not in item["notes"]:
            item["notes"].append(note)

    def to_list(self) -> List[Dict[str, Any]]:
        severity_order = {
            "High": 0,
            "Medium": 1,
            "Low": 2,
            "Informational": 3,
        }

        return sorted(
            self._items.values(),
            key=lambda x: (
                severity_order.get(x.get("severity"), 9),
                x.get("type") or "",
                x.get("first_seen") or "",
                x.get("value") or "",
            ),
        )


# -----------------------------
# Extraction logic
# -----------------------------

def extract_iocs_from_event(event: Dict[str, Any], store: IOCStore) -> None:
    # 1. 구조화 필드 기반 추출
    store.add("user", event.get("user"), event, "user")

    store.add("process", event.get("image"), event, "image")
    store.add("process", event.get("parent_image"), event, "parent_image")

    store.add("file_path", event.get("target_filename"), event, "target_filename")

    store.add("ip", event.get("destination_ip"), event, "destination_ip")

    if event.get("query_name"):
        store.add("domain", event.get("query_name"), event, "query_name")

    command_line = event.get("command_line") or ""
    script_block = event.get("script_block_text") or ""

    # 명령어 자체는 너무 많아질 수 있으니 관심 키워드가 있을 때만 저장
    for command_value, field in [
        (command_line, "command_line"),
        (script_block, "script_block_text"),
    ]:
        cmd_lower = command_value.lower()
        if any(keyword in cmd_lower for keyword in COMMAND_INTEREST_KEYWORDS):
            store.add("command", command_value, event, field)

    # 2. 텍스트 blob에서 보조 추출
    blob = event_text_blob(event)

    for ip in IPV4_PATTERN.findall(blob):
        store.add("ip", ip, event, "raw_text_regex")

    urls = URL_PATTERN.findall(blob)
    for url in urls:
        cleaned = clean_url(url)
        store.add("url", cleaned, event, "raw_text_regex")

        domain = extract_domain_from_url(cleaned)
        if domain:
            store.add("domain", domain, event, "url_host")

    for domain in DOMAIN_PATTERN.findall(blob):
        # 파일명 .exe 같은 것 제외 보정
        lower_domain = domain.lower()
        if lower_domain.endswith(".exe") or lower_domain.endswith(".dll"):
            continue
        store.add("domain", lower_domain, event, "raw_text_regex")

    for path in WINDOWS_PATH_PATTERN.findall(blob):
        # 너무 짧은 경로 제외
        if len(path) < 5:
            continue

        # process 경로일 가능성이 있는 경우 process와 file_path 둘 다 의미 있음
        if path.lower().endswith((".exe", ".ps1", ".bat", ".cmd", ".dll")):
            if path.lower().endswith(".exe"):
                store.add("process", path, event, "raw_text_regex")
            store.add("file_path", path, event, "raw_text_regex")
        else:
            store.add("file_path", path, event, "raw_text_regex")

    for h in HASH_PATTERN.findall(blob):
        store.add("hash", h, event, "raw_text_regex")


def add_evidence_links(iocs: List[Dict[str, Any]], evidence_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    IOC 값이 evidence summary/raw_message/주요 필드에 포함되면 관련 evidence_id를 연결한다.
    단순 문자열 매칭 기반.
    """
    for ioc in iocs:
        value = str(ioc.get("value") or "")
        related = []

        if not value:
            continue

        value_lower = value.lower()

        for ev in evidence_items:
            haystack = "\n".join(
                [
                    str(ev.get("summary") or ""),
                    str(ev.get("image") or ""),
                    str(ev.get("command_line") or ""),
                    str(ev.get("target_filename") or ""),
                    str(ev.get("destination_ip") or ""),
                    str(ev.get("query_name") or ""),
                    str(ev.get("raw_message") or ""),
                ]
            ).lower()

            if value_lower in haystack:
                related.append(ev.get("evidence_id"))

            if len(related) >= 10:
                break

        ioc["related_evidence_ids"] = [x for x in related if x]

    return iocs


def summarize_iocs(iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_type: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}

    for item in iocs:
        by_type[item["type"]] = by_type.get(item["type"], 0) + 1
        by_severity[item["severity"]] = by_severity.get(item["severity"], 0) + 1

    return {
        "total": len(iocs),
        "by_type": by_type,
        "by_severity": by_severity,
    }


# -----------------------------
# Main
# -----------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract IOC candidates from normalized DFIR events"
    )
    parser.add_argument("--events", required=True, help="Path to events.jsonl")
    parser.add_argument("--evidence", required=False, help="Path to evidence.json")
    parser.add_argument("--out", required=True, help="Output iocs.json path")
    parser.add_argument(
        "--include-noise",
        action="store_true",
        help="Reserved option. Currently common noisy domains/processes are filtered by default.",
    )

    args = parser.parse_args()

    events_path = Path(args.events)
    evidence_path = Path(args.evidence) if args.evidence else None
    out_path = Path(args.out)

    events = load_jsonl(events_path)
    evidence_items = load_json(evidence_path) if evidence_path else []

    store = IOCStore()

    for event in events:
        extract_iocs_from_event(event, store)

    iocs = store.to_list()
    iocs = add_evidence_links(iocs, evidence_items)

    result = {
        "summary": summarize_iocs(iocs),
        "iocs": iocs,
    }

    write_json(result, out_path)

    print("[+] IOC summary:")
    print(json.dumps(result["summary"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()