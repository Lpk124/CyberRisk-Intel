from __future__ import annotations

import networkx as nx
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from cyberrisk_intel.analytics.graph import neighborhood
from cyberrisk_intel.analytics.landscape import (
    data_quality,
    event_source_coverage,
    monthly_events,
    overview_metrics,
    policy_document_distribution,
    policy_topic_timeline,
)
from cyberrisk_intel.db.models import (
    AttackTechnique,
    DemoScenario,
    EntityRelation,
    EventSource,
    Policy,
    RiskTheme,
    ScenarioAsset,
    ScenarioRisk,
    SecurityEvent,
    Source,
    Vulnerability,
)
from cyberrisk_intel.db.repository import ENTITY_MODELS, entity_label, get_entity, json_load
from cyberrisk_intel.retrieval.search import hybrid_search
from cyberrisk_intel.services.report import REPORT_TITLES, build_report, generate_report
from cyberrisk_intel.services.research import research
from cyberrisk_intel.services.review import pending_items, set_review_status

TYPE_LABELS = {
    "policy": "政策",
    "security_event": "安全事件",
    "vulnerability": "漏洞",
    "attack_technique": "ATT&CK 技术",
    "risk_theme": "风险主题",
    "industry": "行业",
    "control": "控制措施",
    "threat_pattern": "威胁模式",
}


def _csv(frame: pd.DataFrame) -> bytes:
    return frame.to_csv(index=False).encode("utf-8-sig")


def overview_page(session: Session) -> None:
    st.title("网络安全风险态势总览")
    st.caption("政策、公开事件、漏洞、攻击技术与治理措施的综合研究视图；样本量不等于真实发生率。")
    metrics = overview_metrics(session)
    cols = st.columns(5)
    for col, key, label in zip(
        cols,
        ["policies", "events", "vulnerabilities", "kev", "relations"],
        ["政策", "事件", "漏洞", "KEV", "已审计关系"],
        strict=True,
    ):
        col.metric(label, metrics[key])
    monthly = monthly_events(session)
    if monthly.empty:
        st.info("暂无事件数据。可在侧边栏装载可核验演示数据，或通过 CLI 同步公开数据。")
        return
    totals = monthly.groupby("month", as_index=False)["count"].sum()
    fig = px.bar(
        totals,
        x="month",
        y="count",
        text_auto=True,
        labels={"month": "月份", "count": "公开事件样本数"},
        title="公开安全事件样本时间分布",
    )
    fig.update_yaxes(rangemode="tozero")
    st.plotly_chart(fig, width="stretch")
    st.download_button("下载图表数据", _csv(totals), "monthly-events.csv", "text/csv")
    st.caption(
        f"数据快照：{metrics['generated_at']}｜筛选：全部已入库事件｜样本数：{metrics['events']}"
    )


def search_page(session: Session) -> None:
    st.title("综合情报检索")
    query = st.text_input("查询政策、事件、CVE、ATT&CK、风险或控制", "供应链 漏洞")
    selected = st.multiselect(
        "实体类型", list(TYPE_LABELS), format_func=lambda item: TYPE_LABELS[item]
    )
    if not query:
        return
    results = hybrid_search(session, query, entity_types=selected or None)
    st.caption(f"返回 {len(results)} 条已发布记录；排序为 FTS5 BM25 与可选向量检索的 RRF 融合。")
    for row in results:
        with st.expander(
            f"{row.rank}. [{TYPE_LABELS.get(row.entity_type, row.entity_type)}] {row.title}"
        ):
            st.write(row.excerpt)
            st.code(f"{row.entity_type}:{row.entity_id}")
            if row.source_id:
                source = session.get(Source, row.source_id)
                if source:
                    st.link_button("原始来源", source.url)


def events_page(session: Session) -> None:
    st.title("安全事件")
    events = list(
        session.scalars(
            select(SecurityEvent).order_by(
                func.coalesce(SecurityEvent.incident_date, SecurityEvent.disclosed_date).desc()
            )
        )
    )
    if not events:
        st.info("暂无安全事件。")
        return
    severity = st.multiselect("严重度", sorted({e.normalized_severity for e in events}))
    filtered = [e for e in events if not severity or e.normalized_severity in severity]
    frame = pd.DataFrame(
        [
            {
                "date": e.incident_date or e.disclosed_date,
                "end_date": e.incident_end_date,
                "date_basis": "事件日期" if e.incident_date else "披露日期",
                "title": e.title_zh or e.title,
                "organization": e.organization,
                "severity": e.normalized_severity,
                "region": e.region,
                "review": e.review_status,
            }
            for e in filtered
        ]
    )
    st.dataframe(frame, width="stretch", hide_index=True)
    st.download_button("下载事件数据", _csv(frame), "security-events.csv", "text/csv")
    chosen = st.selectbox("查看事件详情", filtered, format_func=lambda e: e.title_zh or e.title)
    st.write(chosen.summary_zh or chosen.summary)
    if chosen.incident_date:
        date_range = str(chosen.incident_date)
        if chosen.incident_end_date and chosen.incident_end_date != chosen.incident_date:
            date_range += f" 至 {chosen.incident_end_date}"
        st.caption(f"事件时间：{date_range}｜披露日期：{chosen.disclosed_date or '未知'}")
    else:
        st.caption(f"事件发生日期：未知｜披露日期：{chosen.disclosed_date or '未知'}")
    st.markdown(f"**根因：** {chosen.root_cause or '未知'}  \n**影响：** {chosen.impact or '未知'}")
    sources = session.execute(
        select(Source, EventSource)
        .join(EventSource, Source.id == EventSource.source_id)
        .where(EventSource.event_id == chosen.id)
    ).all()
    for source, evidence in sources:
        st.markdown(f"- [{source.name}]({source.url}) — {evidence.evidence_excerpt[:160]}")


def vulnerability_page(session: Session) -> None:
    st.title("漏洞与 ATT&CK")
    tab_vuln, tab_attack = st.tabs(["漏洞", "ATT&CK 技术"])
    with tab_vuln:
        vulns = list(session.scalars(select(Vulnerability).order_by(Vulnerability.cve_id)))
        frame = pd.DataFrame(
            [
                {
                    "CVE": v.cve_id,
                    "CVSS": v.cvss_score,
                    "KEV": v.is_kev,
                    "勒索关联": v.known_ransomware_use,
                    "说明": v.description,
                }
                for v in vulns
            ]
        )
        st.dataframe(frame, width="stretch", hide_index=True)
        if not frame.empty:
            st.download_button("下载漏洞数据", _csv(frame), "vulnerabilities.csv", "text/csv")
    with tab_attack:
        techniques = list(
            session.scalars(select(AttackTechnique).order_by(AttackTechnique.attack_id))
        )
        frame = pd.DataFrame(
            [
                {
                    "ID": t.attack_id,
                    "名称": t.name,
                    "战术": ", ".join(json_load(t.tactics_json)),
                    "已撤销": t.revoked,
                }
                for t in techniques
            ]
        )
        st.dataframe(frame, width="stretch", hide_index=True)


def policies_page(session: Session) -> None:
    st.title("政策与治理")
    policies = list(session.scalars(select(Policy).order_by(Policy.published_date.desc())))
    if not policies:
        st.info("暂无政策数据。")
        return
    chosen = st.selectbox("政策", policies, format_func=lambda p: p.title)
    st.write(chosen.summary)
    topics = ", ".join(json_load(chosen.topics_json))
    type_labels = {
        "law": "法律",
        "administrative_regulation": "行政法规",
        "departmental_rule": "部门规章",
        "normative_document": "规范性文件",
        "national_standard": "国家标准",
        "technical_framework": "技术框架",
        "other": "其他治理文件",
    }
    document_type = type_labels.get(chosen.document_type, chosen.document_type)
    st.caption(
        f"文种：{document_type}｜发布主体：{chosen.issuer}｜发布日期：{chosen.published_date}｜主题：{topics}"
    )
    if chosen.source:
        st.link_button("查看权威原文", chosen.source.url)
    relations = list(
        session.scalars(
            select(EntityRelation).where(
                EntityRelation.subject_type == "policy",
                EntityRelation.subject_id == chosen.id,
                EntityRelation.review_status == "published",
            )
        )
    )
    st.subheader("已复核的风险与控制关联")
    for relation in relations:
        target = get_entity(session, relation.object_type, relation.object_id)
        target_label = entity_label(relation.object_type, target)
        st.markdown(f"- **{relation.predicate}** → {target_label}  \n  {relation.evidence_excerpt}")


def _graph_figure(graph: nx.DiGraph) -> go.Figure:
    positions = nx.spring_layout(graph, seed=42)
    edge_x: list[float | None] = []
    edge_y: list[float | None] = []
    for source, target in graph.edges:
        x0, y0 = positions[source]
        x1, y1 = positions[target]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
    edge_trace = go.Scatter(
        x=edge_x, y=edge_y, mode="lines", hoverinfo="none", line={"width": 1, "color": "#94a3b8"}
    )
    color_map = {name: index for index, name in enumerate(TYPE_LABELS)}
    nodes = list(graph.nodes)
    node_trace = go.Scatter(
        x=[positions[n][0] for n in nodes],
        y=[positions[n][1] for n in nodes],
        mode="markers+text",
        text=[graph.nodes[n]["label"][:25] for n in nodes],
        textposition="top center",
        hovertext=[f"{graph.nodes[n]['entity_type']}<br>{graph.nodes[n]['label']}" for n in nodes],
        hoverinfo="text",
        marker={
            "size": 16,
            "color": [color_map.get(graph.nodes[n]["entity_type"], 9) for n in nodes],
            "colorscale": "Viridis",
            "line": {"width": 1, "color": "white"},
        },
    )
    return go.Figure(
        data=[edge_trace, node_trace],
        layout=go.Layout(
            showlegend=False,
            margin={"l": 10, "r": 10, "t": 20, "b": 10},
            xaxis={"visible": False},
            yaxis={"visible": False},
            height=620,
        ),
    )


def relations_page(session: Session) -> None:
    st.title("关系探索")
    entity_type = st.selectbox(
        "起点类型", list(ENTITY_MODELS), format_func=lambda x: TYPE_LABELS.get(x, x)
    )
    entities = list(session.scalars(select(ENTITY_MODELS[entity_type])))
    if not entities:
        st.info("该类型暂无实体。")
        return
    entity = st.selectbox("起点实体", entities, format_func=lambda x: entity_label(entity_type, x))
    depth = st.radio("跳数", [1, 2], horizontal=True)
    graph = neighborhood(session, entity_type, entity.id, depth=depth)
    st.plotly_chart(_graph_figure(graph), width="stretch")
    edge_frame = pd.DataFrame(
        [
            {
                "from": a,
                "predicate": data["predicate"],
                "to": b,
                "evidence": data["evidence"],
                "confidence": data["confidence"],
            }
            for a, b, data in graph.edges(data=True)
        ]
    )
    st.dataframe(edge_frame, hide_index=True, width="stretch")


def trends_page(session: Session) -> None:
    st.title("趋势研究与数据质量")
    st.subheader("安全事件趋势")
    monthly = monthly_events(session)
    if not monthly.empty:
        fig = px.line(
            monthly,
            x="month",
            y="count",
            color="severity",
            markers=True,
            labels={"month": "月份", "count": "样本数", "severity": "严重度"},
        )
        fig.update_yaxes(rangemode="tozero")
        st.plotly_chart(fig, width="stretch")
        st.download_button("下载趋势数据", _csv(monthly), "event-trends.csv", "text/csv")
    st.subheader("政策主题变化")
    policy_topics = policy_topic_timeline(session)
    if not policy_topics.empty:
        selected_topics = st.multiselect(
            "政策主题",
            sorted(policy_topics["topic"].unique()),
            default=list(
                policy_topics.groupby("topic")["count"]
                .sum()
                .nlargest(6)
                .index
            ),
        )
        filtered_topics = policy_topics[
            policy_topics["topic"].isin(selected_topics)
        ]
        fig = px.bar(
            filtered_topics,
            x="year",
            y="share",
            color="topic",
            barmode="group",
            custom_data=["count", "sample_size"],
            labels={"year": "发布年份", "share": "主题记录占比", "topic": "主题"},
            title="政策主题记录占比（同一文件可含多个主题）",
        )
        fig.update_yaxes(rangemode="tozero", tickformat=".0%")
        fig.update_traces(
            hovertemplate="年份=%{x}<br>占比=%{y:.1%}<br>记录数=%{customdata[0]}<br>当年主题记录总数=%{customdata[1]}<extra></extra>"
        )
        st.plotly_chart(fig, width="stretch")
        st.download_button(
            "下载政策主题数据", _csv(policy_topics), "policy-topic-trends.csv", "text/csv"
        )
    policy_types = policy_document_distribution(session)
    if not policy_types.empty:
        type_labels = {
            "law": "法律",
            "administrative_regulation": "行政法规",
            "departmental_rule": "部门规章",
            "normative_document": "规范性文件",
            "national_standard": "国家标准",
            "technical_framework": "技术框架",
            "other": "其他治理文件",
        }
        policy_types["文种"] = policy_types["document_type"].map(type_labels).fillna(
            policy_types["document_type"]
        )
        fig = px.bar(
            policy_types,
            x="文种",
            y="count",
            text_auto=True,
            labels={"count": "文件数"},
            title="政策与治理文件文种分布",
        )
        fig.update_yaxes(rangemode="tozero")
        st.plotly_chart(fig, width="stretch")
        st.download_button(
            "下载文种分布数据", _csv(policy_types), "policy-document-types.csv", "text/csv"
        )
    quality = data_quality(session)
    st.subheader("数据质量")
    st.dataframe(
        quality.style.format({"rate": "{:.1%}"}), hide_index=True, width="stretch"
    )
    coverage = event_source_coverage(session)
    st.subheader("事件来源覆盖")
    if not coverage.empty:
        st.dataframe(
            coverage.style.format({"share": "{:.1%}"}), hide_index=True, width="stretch"
        )
        st.download_button(
            "下载来源覆盖数据", _csv(coverage), "event-source-coverage.csv", "text/csv"
        )
        largest_share = float(coverage["share"].max())
        if largest_share > 0.4:
            st.warning(
                f"当前单一来源最多覆盖 {largest_share:.1%} 的事件记录；"
                "跨行业或跨地域结论需等待来源继续扩展。"
            )
    st.caption("公开样本存在来源覆盖和披露偏差；本页面只提供描述性分析，不进行因果推断。")


def research_page(session: Session) -> None:
    st.title("RAG 研究助手")
    st.caption("AI 是可选辅助。无密钥时使用确定性检索摘要；所有回答均显示实体引用。")
    question = st.text_area("研究问题", "供应链攻击通常涉及哪些风险和控制措施？")
    use_llm = st.checkbox("使用已配置的 OpenAI-compatible LLM")
    if st.button("检索并生成摘要", type="primary") and question:
        answer = research(session, question, use_llm=use_llm)
        st.markdown(answer.text)
        if answer.used_llm and not answer.citations_valid:
            st.error("引用校验失败，模型结论未发布。")
        st.subheader("检索证据")
        for item in answer.results:
            st.markdown(
                f"- `{item.entity_type}:{item.entity_id}` **{item.title}** — {item.excerpt[:180]}"
            )


def review_page(session: Session) -> None:
    st.title("复核与数据质量")
    items = pending_items(session)
    st.metric("待复核项", len(items))
    if not items:
        st.success("当前没有待复核项。")
        return
    entity_type, entity = st.selectbox(
        "待复核对象",
        items,
        format_func=lambda item: f"{item[0]} · {entity_label(item[0], item[1])}",
    )
    comment = st.text_area("复核意见")
    col1, col2 = st.columns(2)
    if col1.button("批准发布"):
        set_review_status(session, entity_type, entity.id, "published", comment=comment)
        session.commit()
        st.rerun()
    if col2.button("拒绝"):
        set_review_status(session, entity_type, entity.id, "rejected", comment=comment)
        session.commit()
        st.rerun()


def reports_page(session: Session) -> None:
    st.title("专题报告与场景示例")
    report_key: str = st.selectbox(
        "专题报告", list(REPORT_TITLES), format_func=lambda key: REPORT_TITLES[key]
    )
    content = build_report(session, report_key)
    st.markdown(content)
    st.download_button(
        "下载 Markdown", content.encode("utf-8"), f"{report_key}.md", "text/markdown"
    )
    if st.button("生成 Markdown 与 HTML 文件"):
        paths = generate_report(session, report_key)
        st.success("已生成：" + "、".join(str(path) for path in paths))
    st.divider()
    st.subheader("验证场景（不作为系统主体）")
    scenarios = list(session.scalars(select(DemoScenario)))
    for scenario in scenarios:
        with st.expander(scenario.name):
            st.write(scenario.description)
            st.code(scenario.data_flow)
            assets = session.scalars(
                select(ScenarioAsset).where(ScenarioAsset.scenario_id == scenario.id)
            )
            st.write("资产：" + "、".join(asset.name for asset in assets))
            risks = session.execute(
                select(ScenarioRisk, RiskTheme)
                .join(RiskTheme, ScenarioRisk.risk_theme_id == RiskTheme.id)
                .where(ScenarioRisk.scenario_id == scenario.id)
            ).all()
            for risk, theme in risks:
                summary = (
                    f"- {theme.name}: **{risk.current_level}** → "
                    f"剩余风险 **{risk.residual_level}**（演示估计，需复核）"
                )
                st.markdown(summary)
