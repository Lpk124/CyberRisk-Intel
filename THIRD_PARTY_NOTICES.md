# Third-party notices and data boundaries

CyberRisk Intel 本身采用 MIT License。外部数据仍受各来源各自条款约束：

- MITRE ATT&CK：通过官方 `attack-stix-data` 导入，展示时应保留 MITRE 归属与来源链接。
- CISA KEV：通过 CISA 官方 JSON feed 同步。
- CVE List V5：按 CVE ID 获取 CVE Program 官方 JSON 记录，并保存版本来源。
- NIST CSF 2.0 / CISA CPG：本仓库演示控制是原创精简映射，不复制完整规范正文；正式导入时应保留官方归属。
- OpenCTI、MISP、CISO Assistant、VCDB 与 Legal RAG：仅借鉴公开的数据建模或研究思路，本仓库不复制其代码或数据。
- `data/demo` 中的政策和事件只保存简短事实摘要与来源 URL，不镜像大规模受版权保护正文。

重新分发同步后的原始数据前，应复核当时有效的来源许可与使用条款。
