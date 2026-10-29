`nvd-cve-2021-44228.json` 是 2026-10-25 从官方 NVD API 2.0 获取的离线契约样本：
https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228

保留 ID、两个时间、状态、描述、完整 metrics（包括 SSVC）及 references。
省略与此测试无关的 CPE 配置等字段以控制大小。所有测试从本地文件读取，无真实 NVD 网络访问。
测试仅断言契约解析，不把当时的评分或状态当作未来始终不变的事实。
