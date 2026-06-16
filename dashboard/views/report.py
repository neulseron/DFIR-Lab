# dashboard/views/report.py

import streamlit as st

from .common import get_processed_dir, load_markdown, show_missing_file_warning


def render_report():
    st.title("Report")

    path = get_processed_dir() / "report.md"
    content = load_markdown(path)

    if not content:
        show_missing_file_warning("report.md")
        return

    st.download_button(
        label="Download report.md",
        data=content,
        file_name="report.md",
        mime="text/markdown",
    )

    st.divider()

    st.markdown(content)