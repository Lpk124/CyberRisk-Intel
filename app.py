from __future__ import annotations

import streamlit as st

from cyberrisk_intel.db.session import SessionFactory, init_database
from cyberrisk_intel.retrieval.index import rebuild_index
from cyberrisk_intel.services.seed import seed_demo
from cyberrisk_intel.ui.pages import (
    events_page,
    overview_page,
    policies_page,
    relations_page,
    reports_page,
    research_page,
    review_page,
    search_page,
    trends_page,
    vulnerability_page,
)

st.set_page_config(page_title="CyberRisk Intel", page_icon="🛡️", layout="wide")
init_database()

PAGES = {
    "风险态势总览": overview_page,
    "综合情报检索": search_page,
    "安全事件": events_page,
    "漏洞与 ATT&CK": vulnerability_page,
    "政策与治理": policies_page,
    "关系探索": relations_page,
    "趋势研究": trends_page,
    "RAG 研究助手": research_page,
    "复核与数据质量": review_page,
    "专题报告与场景示例": reports_page,
}

with st.sidebar:
    st.title("CyberRisk Intel")
    st.caption("Cyber Governance & Risk Intelligence")
    page_name = st.radio("导航", list(PAGES), label_visibility="collapsed")
    st.divider()
    if st.button("装载/刷新演示数据", width="stretch"):
        with SessionFactory.begin() as seed_session:
            seed_demo(seed_session)
            count = rebuild_index(seed_session)
        st.success(f"演示数据已装载，索引 {count} 个分块。")
        st.rerun()
    st.caption("政策/治理文件已达 30 条；事件样本用于验证工作流，不代表 100 个事件目标已完成。")

session = SessionFactory()
try:
    PAGES[page_name](session)
finally:
    session.close()
