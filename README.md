# Cyber Governance & Risk Intelligence

CyberRisk Intel 是一个面向网络安全研究的本地优先系统。它把中国网络安全政策、全球公开安全事件、CVE/KEV、MITRE ATT&CK、风险主题与控制措施整理为可检索、可分析、可追溯的数据，而不是法律问答机器人或企业合规打分工具。

## 已实现的 V1 能力

- SQLAlchemy + SQLite 统一实体模型、来源、版本、复核记录与带证据关系。
- 30 条带官方来源的中国政策/治理文件，以及可复现扩展至至少 100 条的事件语料工作流。仓库内提交 12 条已发布演示事件；HHS OCR、California DOJ、Massachusetts OCABR 和 Washington AGO 适配器生成的记录默认进入待复核队列。
- 政策数据区分法律、行政法规、部门规章、规范性文件与技术框架，避免混淆约束效力。
- CISA KEV 全量 JSON、MITRE Enterprise ATT&CK STIX 2.1、单个 CVE JSON 5.x 的在线同步命令。
- SQLite FTS5/BM25、可选 Embedding、RRF 跨实体检索。
- Security Risk Landscape、数据质量、局部两跳关系图与 CSV 下载。
- 可选 OpenAI-compatible RAG；无 AI 配置时使用确定性摘要。引用 ID 不合法时拒绝发布模型结论。
- 人工复核队列、审计记录、三个独立场景示例和两份可复现专题报告。

## 快速开始

要求 Python 3.12，并推荐使用 [uv](https://docs.astral.sh/uv/)。

```powershell
uv sync --extra dev
uv run alembic upgrade head
uv run cyberrisk-intel seed-demo
uv run streamlit run app.py
```

打开终端显示的本地地址。也可以先进入空系统，再点击侧边栏“装载/刷新演示数据”。

`init-db` 仅用于不需要迁移历史的一次性本地试用。正式开发环境使用上面的
`alembic upgrade head`，不要在同一个空数据库上先后混用两种初始化方式。

```powershell
uv run cyberrisk-intel init-db
```

应用启动时会幂等创建 SQLite FTS5 索引表；当前迁移链已在独立空数据库上验证。

## 数据同步

```powershell
uv run cyberrisk-intel sync-kev
uv run cyberrisk-intel sync-attack
uv run cyberrisk-intel fetch-cve CVE-2024-3094
uv run cyberrisk-intel sync-hhs-breaches --limit 25
uv run cyberrisk-intel sync-california-breaches --limit 25
uv run cyberrisk-intel sync-massachusetts-breaches --limit 25 --year 2026
uv run cyberrisk-intel sync-washington-breaches --limit 13
uv run cyberrisk-intel reindex
uv run cyberrisk-intel generate-report ai-data-governance
```

在线命令会访问官方公开源。事件适配器默认限制单一来源批次规模，保留未知日期，不推断 CVE/ATT&CK，并把关系标为待复核。同步后运行 `reindex`。原始大文件和本地数据库默认不提交 Git。

Mass.gov 可能拒绝带透明研究客户端 User-Agent 的自动请求。此时可从官方报告页下载 PDF 后使用本地文件入口，仍会记录官方 URL、内容哈希和不可变快照：

```powershell
uv run cyberrisk-intel sync-massachusetts-breaches --year 2026 --limit 25 --file path/to/report.pdf
```

自有核验数据可按 `data/demo` 的 JSON 结构导入：

```powershell
uv run cyberrisk-intel ingest policies data/my-policies.json
uv run cyberrisk-intel ingest events data/my-events.json
uv run cyberrisk-intel reindex
```

详细字段约束见 `data/schemas/README.md`。导入以 `external_id` 幂等更新，并记录
`ingestion_run`；政策 `clauses` 会进入版本和条款表。

## 可选 AI 配置

```powershell
$env:CYBERRISK_LLM_BASE_URL="https://api.example.com/v1"
$env:CYBERRISK_LLM_API_KEY="..."
$env:CYBERRISK_LLM_MODEL="your-model"
$env:CYBERRISK_EMBEDDING_MODEL="your-embedding-model"
```

密钥只从环境变量读取。没有这些变量时，采集、数据库、检索、分析、关系图与报告都可运行。

## 研究边界

- 公开事件样本受披露、语言和来源覆盖影响，不代表真实发生率。
- KEV 表示已知在野利用信号，不表示任一本地资产必然受影响。
- 事件与 CVE/ATT&CK 的正式关系必须有证据并已复核；文本相似度只产生候选。
- `data/demo/policies.json` 已达到 30 条政策/治理文件目标，均保留主管部门来源；其摘要仍需按复核状态管理。
- 当前本地研究库已通过四个独立监管来源扩展至 103 条来源支持的事件记录，其中 12 条已发布、91 条待人工复核。数据库和原始快照不随 Git 提交，因此其他环境需运行同步命令复现。
- 跨监管辖区可能出现同一底层事件的多份通知。未经证据核验不自动合并，研究分析应筛选已复核记录或报告实体消歧状态。

架构、数据字典、研究方法、测试策略与第三方边界见 [docs](docs/系统架构.md)。

## 开发验证

```powershell
uv run ruff check .
uv run mypy src
uv run pytest --cov=cyberrisk_intel
```

本仓库代码采用 MIT License。第三方数据与项目的授权和归属见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
