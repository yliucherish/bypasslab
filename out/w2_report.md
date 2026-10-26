# BypassLab 对抗矩阵报告

- 样本总数：112（攻击 84 / 良性 28）
- 攻击拦截率：**100.0%**（84/84）
- 良性误报率：**0.0%**（0/28）
- 执行错误：0

## 分类拦截率

| 类别 | 拦截/总数 | 拦截率 |
|---|---|---|
| benign | 0/28 | 0% |
| deserialization | 10/10 | 100% |
| path-traversal | 10/10 | 100% |
| rce | 12/12 | 100% |
| scanner | 8/8 | 100% |
| sqli | 21/21 | 100% |
| ssrf | 8/8 | 100% |
| xss | 15/15 | 100% |

## 命中规则分布

| 规则 | 次数 |
|---|---|
| BL-SQLI-001 | 10 |
| BL-RCE-001 | 8 |
| BL-SCAN-001 | 8 |
| BL-SSRF-001 | 7 |
| BL-TRAV-001 | 7 |
| BL-DESER-001 | 6 |
| BL-XSS-001 | 6 |
| BL-XSS-002 | 6 |
| BL-TRAV-002 | 5 |
| BL-DESER-002 | 3 |
| BL-RCE-002 | 3 |
| BL-XSS-003 | 3 |
| SEM-sql:comment-stripped+sql:tautology | 3 |
| BL-SQLI-002 | 2 |
| BL-SQLI-003 | 2 |
| BL-SQLI-004 | 2 |
| SEM-sql:quoted-eq+sql:tautology | 2 |
| BL-DESER-003 | 1 |
