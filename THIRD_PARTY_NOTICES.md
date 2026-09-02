# Third-party notices and data boundaries

CyberRisk Intel 本身采用 MIT License。外部数据仍受各来源各自条款约束：

- MITRE ATT&CK：通过官方 `attack-stix-data` 导入，展示时应保留 MITRE 归属与来源链接。
- CISA KEV：通过 CISA 官方 JSON feed 同步。
- CVE List V5：按 CVE ID 获取 CVE Program 官方 JSON 记录，并保存版本来源。
- HHS OCR Breach Portal：同步美国卫生与公众服务部公开的医疗信息泄露汇总；本地记录保留来源、抓取时间与复核状态。
- California DOJ Data Breach List：同步加州司法部长公开 CSV；通知机构不必然等于实际被攻击机构。
- Massachusetts OCABR Data Breach Notification Reports：解析官方年度 PDF；只采纳可完整解析的单行记录，跳过可能截断的换行记录。
- Washington AGO / data.wa.gov：连接官方事件汇总与个人信息类型明细两个开放数据集，并保留两个来源记录。
- NIST CSF 2.0 / CISA CPG：本仓库演示控制是原创精简映射，不复制完整规范正文；正式导入时应保留官方归属。
- OpenCTI、MISP、CISO Assistant、VCDB 与 Legal RAG：仅借鉴公开的数据建模或研究思路，本仓库不复制其代码或数据。
- `data/demo` 中的政策和事件只保存简短事实摘要与来源 URL，不镜像大规模受版权保护正文。

重新分发同步后的原始数据前，应复核当时有效的来源许可与使用条款。`data/raw` 与本地数据库默认不提交 Git。
