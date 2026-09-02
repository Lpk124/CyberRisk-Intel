# JSON 导入规范

政策与事件导入文件均为 JSON 数组。可直接复制 `data/demo/policies.json` 或
`data/demo/events.json` 作为模板：

```powershell
uv run cyberrisk-intel ingest policies path/to/policies.json
uv run cyberrisk-intel ingest events path/to/events.json
uv run cyberrisk-intel reindex
```

每条事件必须至少包含一个 HTTP(S) 来源。政策 `clauses` 可为空；非空时，每项支持
`clause_ref`、`hierarchy_path`、`title` 和必需的 `body`。导入使用稳定 `external_id`
幂等更新，并在 `ingestion_run` 中记录发现、新增、更新和失败数量。

事件的 `incident_date`、`incident_end_date`、`disclosed_date` 均可为空；未知必须保持
`null`，不得用披露日期回填事件日期。`incident_end_date` 只有在来源明确给出时间范围时
填写。`cve_ids` 和 `attack_ids` 只允许录入有来源证据的标识。

政策 `document_type` 使用以下受控值：`law`、`administrative_regulation`、
`departmental_rule`、`normative_document`、`national_standard`、
`technical_framework` 或 `other`。该字段描述文件性质，不代表系统给出法律效力判断。
