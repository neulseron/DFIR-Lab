# analysis/case_summary_generator.py

import argparse
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from dotenv import load_dotenv
load_dotenv()


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


def top_evidence(evidence_items: List[Dict[str, Any]], limit: int = 8) -> List[Dict[str, Any]]:
    severity_rank = {
        "High": 0,
        "Medium": 1,
        "Low": 2,
        "Informational": 3,
    }

    rows = sorted(
        evidence_items,
        key=lambda x: (
            severity_rank.get(x.get("severity"), 9),
            x.get("timestamp") or "",
        ),
    )

    return [
        {
            "evidence_id": item.get("evidence_id"),
            "timestamp": item.get("timestamp"),
            "title": item.get("title"),
            "stage": item.get("attack_stage"),
            "severity": item.get("severity"),
            "summary": item.get("summary"),
            "matched_reason": item.get("matched_reason"),
        }
        for item in rows[:limit]
    ]


def top_iocs(iocs_data: Dict[str, Any], limit: int = 10) -> List[Dict[str, Any]]:
    return [
        {
            "type": item.get("type"),
            "value": item.get("value"),
            "severity": item.get("severity"),
            "count": item.get("count"),
            "related_evidence_ids": item.get("related_evidence_ids", [])[:5],
        }
        for item in iocs_data.get("iocs", [])[:limit]
    ]


def build_input_context(
    case_id: str,
    timeline_data: Dict[str, Any],
    evidence_items: List[Dict[str, Any]],
    iocs_data: Dict[str, Any],
    hayabusa_coverage: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "case_id": case_id,
        "timeline_summary": timeline_data.get("summary", {}),
        "stage_summary": timeline_data.get("stage_summary", []),
        "key_evidence": top_evidence(evidence_items),
        "ioc_summary": iocs_data.get("summary", {}),
        "key_iocs": top_iocs(iocs_data),
        "hayabusa_coverage_summary": hayabusa_coverage.get("summary", {}),
        "hayabusa_both_examples": hayabusa_coverage.get("both", [])[:5],
        "internal_only_examples": hayabusa_coverage.get("internal_only", [])[:5],
        "hayabusa_only_examples": hayabusa_coverage.get("hayabusa_only", [])[:5],
    }


def fallback_summary(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    API 키가 없거나 LLM 호출 실패 시에도 대시보드가 깨지지 않도록 하는 기본 요약.
    """
    by_stage = context.get("timeline_summary", {}).get("by_stage", {})
    ioc_summary = context.get("ioc_summary", {})
    key_evidence = context.get("key_evidence", [])

    stages = [stage for stage, count in by_stage.items() if count]

    flow = []
    if "Initial Context" in by_stage:
        flow.append("로그온 또는 초기 사용자 세션 컨텍스트가 확인됩니다.")
    if "Execution" in by_stage:
        flow.append("PowerShell 또는 명령 셸 기반 실행 흔적이 확인됩니다.")
    if "Discovery" in by_stage:
        flow.append("시스템, 계정, 네트워크 정보를 확인하는 탐색 행위가 포함되어 있습니다.")
    if "Collection/Staging" in by_stage:
        flow.append("임시 경로 파일 생성 또는 압축 등 수집/스테이징 행위가 확인됩니다.")
    if "Network Activity" in by_stage or "Command and Control" in by_stage:
        flow.append("DNS 질의 또는 외부/내부 네트워크 연결 흔적이 확인됩니다.")
    if "Defense Evasion" in by_stage:
        flow.append("로그 삭제 등 방어 회피 성격의 고위험 이벤트가 포함되어 있습니다.")

    if not flow:
        flow.append("명확한 침해 흐름은 제한적으로 확인됩니다.")

    watch_points = [
        "PowerShell Script Block과 명령줄 인자를 우선 확인합니다.",
        "IOC 후보의 도메인, IP, URL이 실제 악성 인프라인지 평판 조회가 필요합니다.",
        "Temp 경로 파일 생성 및 압축 파일 생성이 실제 수집/스테이징인지 확인합니다.",
    ]

    if "Defense Evasion" in by_stage:
        watch_points.insert(0, "Security Event Log Cleared 이벤트는 단일 이벤트라도 우선 분석해야 합니다.")

    return {
        "summary": (
            f"이 케이스는 {', '.join(stages) if stages else '제한적인 단계'} 중심의 이벤트가 확인됩니다. "
            f"총 IOC 후보는 {ioc_summary.get('total', 0)}개이며, "
            "이벤트 간 시간 흐름을 기준으로 실행, 탐색, 수집/스테이징, 네트워크 활동 여부를 검토해야 합니다."
        ),
        "flow": flow,
        "watch_points": watch_points,
        "priority_evidence": [
            item.get("evidence_id")
            for item in key_evidence
            if item.get("evidence_id")
        ][:5],
        "limitations": [
            "본 요약은 Windows Event, Sysmon, PowerShell 로그 기반 분석 결과입니다.",
            "파일 원본, 메모리 이미지, 네트워크 패킷, 위협 인텔리전스 평판 조회 결과는 포함되지 않았습니다.",
        ],
        "model": "rule-based-fallback",
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def build_prompt(context: Dict[str, Any]) -> str:
    return f"""
너는 DFIR 분석 보조자다.
아래 케이스 데이터를 바탕으로 대시보드에 표시할 짧은 한국어 분석 요약을 생성하라.

조건:
- 실제 침해 확정처럼 단정하지 말 것.
- "확인됨", "관찰됨", "추가 검토 필요" 수준으로 표현할 것.
- 반복적인 통계 설명은 줄이고, 침해 흐름과 분석 포인트 중심으로 작성할 것.
- JSON만 출력할 것.
- JSON schema:
{{
  "summary": "전체 침해 흐름 2~4문장",
  "flow": ["시간 흐름 기반 핵심 단계 3~6개"],
  "watch_points": ["주의 깊게 봐야 할 점 3~6개"],
  "priority_evidence": ["중요 evidence_id 3~6개"],
  "limitations": ["분석 한계 1~3개"]
}}

케이스 데이터:
{json.dumps(context, ensure_ascii=False, indent=2)}
""".strip()


def generate_with_gemini(context: Dict[str, Any]) -> Dict[str, Any]:
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")

    if not api_key:
        raise RuntimeError("GEMINI_API_KEY or GOOGLE_API_KEY is not set")

    from google import genai

    client = genai.Client(api_key=api_key)

    response = client.models.generate_content(
        model=os.getenv("GEMINI_MODEL", "gemini-1.5-flash"),
        contents=build_prompt(context),
    )

    text = response.text.strip()

    # 모델이 ```json fence를 붙이는 경우 보정
    if text.startswith("```"):
        text = text.strip("`")
        text = text.replace("json\n", "", 1).strip()

    data = json.loads(text)
    data["model"] = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
    data["generated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return data


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate short LLM-based DFIR case summary"
    )
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--timeline", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--iocs", required=True)
    parser.add_argument("--hayabusa-coverage", required=False)
    parser.add_argument("--out", required=True)

    args = parser.parse_args()

    timeline_data = load_json(Path(args.timeline), default={})
    evidence_items = load_json(Path(args.evidence), default=[])
    iocs_data = load_json(Path(args.iocs), default={})
    hayabusa_coverage = (
        load_json(Path(args.hayabusa_coverage), default={})
        if args.hayabusa_coverage
        else {}
    )

    context = build_input_context(
        case_id=args.case_id,
        timeline_data=timeline_data,
        evidence_items=evidence_items,
        iocs_data=iocs_data,
        hayabusa_coverage=hayabusa_coverage,
    )

    try:
        result = generate_with_gemini(context)
    except Exception as e:
        result = fallback_summary(context)
        result["llm_error"] = str(e)

    write_json(result, Path(args.out))


if __name__ == "__main__":
    main()