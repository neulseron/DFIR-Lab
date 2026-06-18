# dashboard/views/common.py

import json
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st


def get_case_id() -> str:
    return st.session_state.get("case_id", "CASE-001")


def get_data_root() -> Path:
    return Path(st.session_state.get("data_root", "data"))


def get_raw_dir() -> Path:
    return get_data_root() / "raw" / get_case_id()


def get_processed_dir() -> Path:
    return get_data_root() / "processed" / get_case_id()


def load_json(path: Path, default: Any = None) -> Any:
    if default is None:
        default = {}

    if not path.exists():
        return default

    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_markdown(path: Path) -> str:
    if not path.exists():
        return ""

    return path.read_text(encoding="utf-8")


def load_timeline_df() -> pd.DataFrame:
    path = get_processed_dir() / "timeline.csv"

    if not path.exists():
        return pd.DataFrame()

    return pd.read_csv(path)


def load_evidence_df() -> pd.DataFrame:
    path = get_processed_dir() / "evidence.json"
    data = load_json(path, default=[])

    if not data:
        return pd.DataFrame()

    return pd.DataFrame(data)


def load_ioc_df() -> pd.DataFrame:
    path = get_processed_dir() / "iocs.json"
    data = load_json(path, default={})

    iocs = data.get("iocs", [])

    if not iocs:
        return pd.DataFrame()

    return pd.DataFrame(iocs)


def show_missing_file_warning(filename: str):
    st.warning(
        f"`{filename}` 파일을 찾을 수 없습니다. "
        "analysis 파이프라인을 먼저 실행했는지 확인하세요."
    )


# --------------------------------------------------
# Hayabusa
# --------------------------------------------------

def get_raw_hayabusa_dir() -> Path:
    return get_raw_dir() / "hayabusa"


def get_raw_hayabusa_csv_path() -> Path:
    return get_raw_hayabusa_dir() / "hayabusa.csv"


def get_hayabusa_dir() -> Path:
    return get_processed_dir() / "hayabusa"


def get_hayabusa_findings_path() -> Path:
    return get_hayabusa_dir() / "hayabusa_findings.json"


def get_hayabusa_summary_path() -> Path:
    return get_hayabusa_dir() / "hayabusa_summary.json"


def get_hayabusa_timeline_matches_path() -> Path:
    return get_hayabusa_dir() / "hayabusa_timeline_matches.json"


def get_hayabusa_coverage_path() -> Path:
    return get_hayabusa_dir() / "hayabusa_coverage.json"