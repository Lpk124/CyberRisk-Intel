from __future__ import annotations

from datetime import UTC, datetime
from html import escape
from pathlib import Path

from sqlalchemy.orm import Session

from cyberrisk_intel.analytics.landscape import (
    monthly_events,
    overview_metrics,
    relation_distribution,
)
from cyberrisk_intel.config import PROJECT_ROOT
from cyberrisk_intel.db.repository import entity_label, get_entity

REPORT_TITLES = {
    "ai-data-governance": "数据安全与 AI 安全风险及治理关注变化",
    "attack-vulnerability-trends": "勒索、供应链、API 等攻击事件与漏洞利用趋势",
}


def build_report(session: Session, report_key: str) -> str:
    if report_key not in REPORT_TITLES:
        raise KeyError(report_key)
    metrics = overview_metrics(session)
    monthly = monthly_events(session)
    relations = relation_distribution(session, "risk_theme")
    title = REPORT_TITLES[report_key]
    generated_at = datetime.now(UTC).isoformat()
    lines = [
        f"# {title}",
        "",
        f"> 生成时间：{generated_at}",
        "> 口径：仓库中已发布的演示/研究记录。公开样本不代表真实事件发生率。",
        "",
        "## 数据快照",
        "",
        f"- 政策：{metrics['policies']} 条",
        f"- 事件：{metrics['events']} 条",
        f"- 漏洞：{metrics['vulnerabilities']} 条（其中 KEV {metrics['kev']} 条）",
        f"- ATT&CK 技术：{metrics['attack_techniques']} 条",
        f"- 已审计关系：{metrics['relations']} 条",
        "",
        "## 描述性结果",
        "",
    ]
    if monthly.empty:
        lines.append("当前没有可供趋势分析的事件数据。")
    else:
        period = monthly.groupby("month")["count"].sum().sort_index()
        lines.extend(f"- {month}：{count} 个公开样本" for month, count in period.items())
    lines.extend(["", "## 风险关联", ""])
    if relations.empty:
        lines.append("当前没有已复核风险关联。")
    else:
        for row in relations.sort_values("count", ascending=False).head(10).itertuples():
            entity = get_entity(session, "risk_theme", row.entity_id)
            lines.append(f"- {entity_label('risk_theme', entity)}：{row.count} 条关系")
    lines.extend(
        [
            "",
            "## 方法与限制",
            "",
            "本报告只做描述性统计；未知值与零值不合并。来源覆盖随时间变化，"
            "不同时间段的样本数不可直接解释为攻击发生率，也不形成因果推断。",
            "",
            "## 可追溯性",
            "",
            "所有正式关系必须处于 `published` 状态并保留证据。原始来源请在系统实体详情页查看。",
        ]
    )
    return "\n".join(lines) + "\n"


def generate_report(
    session: Session, report_key: str, output_dir: Path | None = None
) -> tuple[Path, Path]:
    output_dir = output_dir or PROJECT_ROOT / "reports" / "generated"
    output_dir.mkdir(parents=True, exist_ok=True)
    content = build_report(session, report_key)
    md_path = output_dir / f"{report_key}.md"
    html_path = output_dir / f"{report_key}.html"
    md_path.write_text(content, encoding="utf-8")
    html_path.write_text(
        "<!doctype html><meta charset='utf-8'><title>CyberRisk Intel Report</title>"
        "<main style='max-width:900px;margin:auto;font:16px/1.65 system-ui'>"
        "<pre style='white-space:pre-wrap;font:inherit'>" + escape(content) + "</pre></main>",
        encoding="utf-8",
    )
    return md_path, html_path
