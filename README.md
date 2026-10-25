# BypassLab

> 一个用 Go 写的**反向代理式 WAF**，配套本地靶场与对抗驱动脚本：用于研究「攻击 → 拦截 → 绕过 → 补规则」的完整对抗循环。
> 全部测试仅针对本地靶场与自建环境。

![ci](https://github.com/YDcherish/bypasslab/actions/workflows/ci.yml/badge.svg)
![go](https://img.shields.io/badge/Go-1.22%2B-00ADD8)
![license](https://img.shields.io/badge/license-MIT-green)

---

## 为什么做这个项目

写过扫描器（VulnHunter）、写过检测引擎（SentinelWatch）之后，缺的是**对抗层**：
同一个 payload，为什么有的 WAF 拦得住、有的拦不住？规则加严到什么程度开始误伤业务？
这些问题只能靠"自己造一个 WAF，再自己打它"来回答。

BypassLab 就是这个实验台：WAF 与攻击方都是自己的代码，因此每一轮绕过都能追溯到**具体哪条规则被什么变了形绕过**，
也能量化"补规则之后拦截率涨了多少、误报有没有变多"。

## 架构

```
                    ┌──────────────── BypassLab ────────────────┐
client ──请求──▶    │  限流 → 归一化 → Layer1 正则 → Layer2 语义  │ ──放行──▶ upstream（靶场 echo）
                    │                    ↓ 命中                 │
                    │          403 + 规则ID + JSONL 审计日志      │
                    └───────────────────────────────────────────┘
                                              │
                                     logs/waf.jsonl
                                （可被 SentinelWatch 采集联动分析）
```

**双层检测**是核心设计：

| 层 | 作用 | 特点 |
|---|---|---|
| Layer 1 正则 | 12 条内置规则，覆盖 SQLi / XSS / RCE / 路径遍历 / 反序列化 / 扫描器指纹 | 快、可解释、易被变形绕过 |
| Layer 2 语义 | 16 个特征加权求和，达到阈值才拦（默认 5 分） | 慢一点、抗编码与拆分变形、误报可控 |

归一化层在两层之前做四件事（每一件都对应一类绕过手法）：
多轮 URL 解码 → HTML 实体解码 → 去 SQL 注释 → 压缩空白 / 折叠斜杠。

## 快速开始

需要 Go 1.22+，无第三方依赖。

```bash
# 终端 1：启动本地靶场（无任何过滤，仅用于授权测试）
go run ./cmd/echo -listen :9000

# 终端 2：启动 WAF，保护靶场
go run ./cmd/waf -listen :8080 -upstream http://127.0.0.1:9000 -log logs/waf.jsonl -rate 120

# 终端 3：跑基线验收（15 个用例：3 个正常 + 12 个攻击）
bash scripts/demo_w1.sh
```

正常请求：

```bash
curl -i "http://127.0.0.1:8080/api/orders?page=2&size=20"
# HTTP/1.1 200 OK  ← 转发到靶场
```

攻击请求：

```bash
curl -i "http://127.0.0.1:8080/product?id=1%20UNION%20SELECT%20password%20FROM%20users"
# HTTP/1.1 403 Forbidden
# X-BypassLab-Blocked: BL-SQLI-001
# {"blocked":true,"rule_id":"BL-SQLI-001","category":"sqli","severity":"high","layer":"regex"}
```

内部端点：`/__waf/health`（规则数、未启动时长、放行数）、`/__waf/stats`（按规则统计拦截数）。

## 内置规则（W1）

| 规则 ID | 名称 | 类别 | 等级 |
|---|---|---|---|
| BL-SQLI-001 | UNION 注入 | sqli | high |
| BL-SQLI-002 | 报错注入函数 | sqli | high |
| BL-SQLI-003 | 布尔 / 时间盲注 | sqli | critical |
| BL-XSS-001 | Script 标签 | xss | high |
| BL-XSS-002 | 事件处理器注入 | xss | high |
| BL-RCE-001 | 命令拼接 | rce | critical |
| BL-RCE-002 | 命令替换 | rce | critical |
| BL-TRAV-001 | 路径遍历 | path-traversal | high |
| BL-TRAV-002 | 敏感文件读取 | path-traversal | critical |
| BL-DESER-001 | JNDI 注入（Log4Shell 特征） | deserialization | critical |
| BL-DESER-002 | Fastjson autoType | deserialization | high |
| BL-SCAN-001 | 扫描器指纹 | scanner | medium |

语义层特征（Layer 2）：SQL 恒真式、时间盲注函数、元数据表、脚本标签、事件处理器、JS 伪协议、
shell 元字符、命令名、`../` 序列、敏感文件、Java 反序列化魔数、`@type`、内网 IP 等 16 项，权重 1–4。

## W1 验收数据（真实跑出来的，不是估的）

`bash scripts/demo_w1.sh` 结果：**通过 15 / 失败 0**

| 类型 | 用例 | 结果 |
|---|---|---|
| 正常请求 | 列表接口、JSON 业务体、含 `select` 的搜索词 | 3/3 放行（无误报） |
| SQLi | UNION、大小写变形、注释变形 `union/**/select`、换行变形、双重编码恒真式、时间盲注 | 6/6 拦截 |
| XSS / RCE / 遍历 | script 标签、`;cat /etc/passwd`、`../../etc/passwd` | 3/3 拦截 |
| 反序列化 / 扫描器 | `${jndi:ldap://...}`、Fastjson `@type`、sqlmap UA | 3/3 拦截 |

单元测试：`go test ./...` **13 个测试函数全绿**（归一化 5 组、规则逐条、语义层、误报控制、规则数漂移、
命中部位归因、代理端到端、限流、body 透传、审计计数）。

其中两个缺陷是跑基线时发现的，记录在此以免重犯：
1. **双计数导致假阳性归因**：早期把 `RequestURI` 计入 path 字段，导致 query 里的攻击被同时算作 path 命中，
   语义分被放大。修正后 query 攻击正确归因为 `query`。
2. **单字段恒真式漏报**：`?id=1' or 1=1` 仅积 4 分（阈值 5）→ 漏拦。修法不是降阈值（会误伤），
   而是把恒真式权重提到 4，叠加 comment 特征即达 5；单纯出现 `'or'` 仍不拦。

## 目录结构

```
bypasslab/
├── cmd/waf/          # WAF 启动入口（flag 配置）
├── cmd/echo/         # 本地靶场（无过滤回显，仅供授权测试）
├── internal/waf/     # 核心：归一化 / 规则引擎 / 审计 / 反向代理
├── scripts/demo_w1.sh# W1 基线验收脚本
├── logs/             # waf.jsonl 拦截日志（JSONL，可被 SentinelWatch 采集）
└── .github/workflows/ci.yml
```

## 路线图

- [x] **W1** WAF MVP：反向代理 + 12 条正则规则 + 16 项语义特征 + JSONL 审计 + 限流 + 15 用例基线
- [ ] **W2** 对抗驱动器：接入 VulnHunter payload 库，自动批量打 WAF 并记录放行/拦截
- [ ] **W3** 对抗循环 ×3：按放行样本补规则 → 复测 → 输出拦截率曲线
- [ ] **W4** 报告生成 + SentinelWatch 日志联动看板 + 开源发布

## 授权声明

本项目仅用于**本地靶场与自建环境**的安全研究。请勿将 WAF 规则或绕过手法用于未授权目标。
`cmd/echo` 是故意不设防的靶场，**不要部署到公网**。

## License

MIT
