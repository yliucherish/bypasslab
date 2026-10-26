# BypassLab 对抗矩阵报告

- 样本总数：130（攻击 102 / 良性 28）
- 攻击拦截率：**100.0%**（102/102）
- 良性误报率：**0.0%**（0/28）
- 执行错误：0

## 分类拦截率

| 类别 | 拦截/总数 | 拦截率 |
|---|---|---|
| benign | 0/28 | 0% |
| deserialization | 13/13 | 100% |
| path-traversal | 11/11 | 100% |
| rce | 14/14 | 100% |
| scanner | 8/8 | 100% |
| sqli | 25/25 | 100% |
| ssrf | 13/13 | 100% |
| xss | 18/18 | 100% |

## 命中规则分布

| 规则 | 次数 |
|---|---|
| BL-SQLI-001 | 13 |
| BL-SSRF-001 | 12 |
| BL-RCE-001 | 9 |
| BL-DESER-001 | 8 |
| BL-SCAN-001 | 8 |
| BL-TRAV-001 | 8 |
| BL-XSS-001 | 8 |
| BL-XSS-002 | 7 |
| BL-TRAV-002 | 5 |
| BL-DESER-002 | 4 |
| BL-RCE-002 | 4 |
| BL-XSS-003 | 3 |
| SEM-sql:comment-stripped+sql:tautology | 3 |
| BL-SQLI-002 | 2 |
| BL-SQLI-003 | 2 |
| BL-SQLI-004 | 2 |
| SEM-sql:quoted-eq+sql:tautology | 2 |
| BL-DESER-003 | 1 |
| SEM-sql:paren-tautology | 1 |
