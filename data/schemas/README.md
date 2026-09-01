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
