# BypassLab SPEC

> 版本 v0.2（W2 完成）｜ 2026-10-26 ｜ 语言：Go 1.22+（零第三方依赖）

## 1. 项目定位

自研反向代理式 WAF + 本地靶场 + 对抗驱动脚本，用于实证研究「检测规则与绕过手法」的博弈关系。

补齐能力闭环中的**对抗层**：

| 维度 | 项目 |
|---|---|
| 攻击理解 | VulnHunter（扫描器） |
| 防御工程 | SentinelWatch（日志审计与入侵检测） |
| 漏洞原理 | cve-research（Log4Shell / Fastjson 复现） |
| **攻防对抗** | **BypassLab（本项目）** |

## 2. 范围

**W1 范围内**
- HTTP 反向代理，请求检查后转发；命中即 403 并返回规则 ID
- 请求归一化：多轮 URL 解码、HTML 实体解码、去 SQL 注释、压缩空白、折叠斜杠
- Layer 1：12 条正则规则（表见 README）
- Layer 2：16 项语义特征加权，阈值 5 分
- 结构化审计日志（JSONL，字段对齐 SentinelWatch 采集协议）
- 单 IP 每分钟令牌桶限流
- 内部端点 `/__waf/health`、`/__waf/stats`
- 13 个 Go 测试函数 + 15 用例基线脚本

**W1 范围外（后续周）**
- 规则热加载（YAML）与规则管理 API
- 自动化对抗驱动（批量 payload → 结果矩阵）
- 拦截率曲线与绕过手法分类报告
- SentinelWatch 看板联动

## 3. 模块设计

```
cmd/waf      flag 解析 → NewAudit → NewEngine(BuiltinRules) → NewProxy → ListenAndServe
cmd/echo     本地靶场：回显 method/path/query/body（故意不过滤）
internal/waf
  normalize.go  Normalize(raw) string；Request.Field(Target)
  engine.go     Rule / Match / Engine；BuiltinRules() 12 条；builtinSemanticChecks() 16 项
  audit.go      Event / Audit；Write 追加 JSONL 并累加计数；Stats 快照
  proxy.go      Config / Proxy；Handler 路由内部端点；serve 做限流→检查→转发；ClientIP
```

**关键接口约定**

| 接口 | 语义 |
|---|---|
| `Engine.Inspect(*Request) *Match` | 返回 nil 表示放行；否则含 RuleID / Layer / Target / Excerpt / Score |
| `Audit.Write(Event) error` | 追加一条 JSONL；`event_type` 为 `waf_block` 或 `waf_allow` |
| `Proxy.Handler() http.Handler` | 可直接挂 http.Server；内部端点优先于转发 |

**日志字段（与 SentinelWatch 协议对齐）**

```json
{"ts":"2026-10-25T04:39:06Z","event_type":"waf_block","src_ip":"127.0.0.1","method":"GET",
 "host":"127.0.0.1:8080","path":"/","query":"","rule_id":"BL-DESER-001","rule_name":"JNDI 注入（Log4Shell 特征）",
 "category":"deserialization","severity":"critical","action":"block","layer":"regex","target":"headers",
 "excerpt":"${jndi:ldap","latency_us":0,"status_code":403,"user_agent":"${jndi:ldap://...}"}
```

## 4. 验收标准（DoD）

W1 完成需同时满足：

- [x] `go vet ./...` 无告警、`go build ./...` 通过
- [x] `go test ./...` 全绿（13 个测试函数）
- [x] `bash scripts/demo_w1.sh` ≥ 15 用例，通过率 100%，正常请求零误报
- [x] 攻击响应携带 `X-BypassLab-Blocked` 头与 JSON body（含 rule_id / category / layer）
- [x] `logs/waf.jsonl` 每条记录含 `event_type / src_ip / rule_id / target / status_code`
- [x] `/__waf/health`、`/__waf/stats` 可用且统计准确（拦截 24 次时 by_rule 分项之和 = 24）
- [x] README 规则表与实际规则数一致（测试 `TestRuleCount` 守住 12 条）

## 5. 后续周计划

| 周 | 目标 | 验收 |
|---|---|---|
| W2 | 对抗驱动器：读 VulnHunter payload 库，批量打 WAF，输出「放行/拦截 + 命中规则」矩阵 | ✅ 已完成（2026-10-26）：108 条语料（84 攻击 + 24 良性），拦截率 79.8%、误报 0%，产出矩阵 CSV / 报告 MD / 17 条绕过清单 |
| W3 | 对抗循环 ×3：按放行样本补规则 → 复测 → 记录拦截率变化 | 三轮拦截率曲线（真实数据） |
| W4 | 报告生成（HTML）+ SentinelWatch 看板联动截图 + 博客第 5 篇 | 可发布仓库 + 博客完稿 |

## 6. 风险与红线

1. 所有测试仅针对 `cmd/echo` 本地靶场或自建环境；不对外网目标发起测试。
2. `cmd/echo` 无任何过滤，禁止部署公网。
3. 拦截率、误报率等数字必须来自 `scripts/` 下的可重跑脚本，不手填。

---

## 附录 A：面试问答要点（写代码时同步维护）

**Q：为什么用双层检测，而不是把正则写全？**
> 正则可解释、快，但绕过它的成本极低——`union/**/select`、`union%0Aselect`、双重编码都能过。
> 所以我保留正则为 Layer 1 负责"常见形态的快速拦截"，再加 Layer 2 做归一化后的特征加权。
> 基线里 6 个 SQLi 变体，变形那几个正是靠归一化 + 语义层拦下的。

**Q：语义层阈值怎么定的？会不会误报？**
> 阈值 5，权重按"单独出现是否足以定罪"来分。`select` 这种词在业务里很常见，权重不给；
> 恒真式给 4（强信号），注释剥离特征给 1，两者同时出现才拦。
> 基线里"搜索关键词含 select"这个用例就是专门守误报的，它必须放行。

**Q：为什么恒真式要给 4 分而不是降低阈值？**
> 降阈值会把很多只有单一弱特征（比如正常参数里出现 `'or'`）的请求一起拦掉，误报换检出率不划算。
> 提高强特征权重是更精确的做法：命中面没变，判定更准。这个修正就是跑基线时发现漏报后改的。

**Q：Go 的 RE2 不支持反向引用，你怎么做 1=1 判定？**
> 用 `(\d+)\s*=\s*(\d+)` 先抓候选对，再在 Go 里比较两侧字符串。
> 这样既保留 RE2 的线性时间保证（不会被 ReDoS 打爆），又能表达"两侧相同"的语义。

**Q：这个 WAF 能上生产吗？**
> 不能，也不打算。它是实验台：单机内存态限流、规则写死在代码里、没有 TLS 与集群共享状态。
> 它的价值是让"绕过—补规则"这件事可量化，而不是替代商业 WAF。

## 附录 C：W2 交付记录与实测数据（2026-10-26）

### C.1 交付物

| 组件 | 路径 | 说明 |
|---|---|---|
| 语料库 | `internal/payloads/corpus.go` | 108 条：84 攻击 + 24 良性对照；含 URL 编码 / 双重编码 / 大小写 / 注释拆分等变形 |
| 驱动器 | `internal/attack/driver.go` | 并发发送、拦截判定、统计汇总、CSV/报告输出 |
| 入口 | `cmd/attack/main.go` | `-target/-csv/-md/-c/-timeout` |
| 一键脚本 | `scripts/run_w2.sh` | 起靶场 + WAF → 跑矩阵 → 落产物 |
| 产物 | `out/w2_matrix.csv`、`out/w2_report.md` | 逐条明细 + 分类统计 + 绕过/误报清单 |

### C.2 关键设计决策

1. **拦截判定必须带规则头**：只看 403 会把上游自身的 403 算成拦截，实测会让拦截率虚高。
   实现为 `状态码==403 && X-BypassLab-Blocked != ""`，并有专门单测守住。
2. **必须含良性对照组**：只测攻击样本会掩盖误报。24 条良性样本覆盖「含 select/union 单词」「含引号/分号文本」
   「正常 URL 回调」等易误伤场景，当前误报 0，说明阈值没有过紧。
3. **语料要带变形**：同一语义的多形态（`union/**/select`、`union%0Aselect`、`%2527`）才能验证归一化层是否真的生效。

### C.3 实测结果

**拦截率 79.8%（67/84）｜ 误报率 0%（0/24）**

| 类别 | 拦截/总数 | 结论 |
|---|---|---|
| path-traversal | 10/10 | 正则与敏感文件名规则双保险 |
| scanner | 8/8 | UA 指纹稳定 |
| sqli | 18/21 | 缺 stacked、OUTFILE、引号包裹恒真式 |
| rce | 10/12 | 缺单竖线 `\|` 与系统命令解释器 |
| deserialization | 8/10 | 缺 `${lower:}` 展开、裸 Java 魔数 |
| xss | 12/15 | 缺 `javascript:` 伪协议、`ontoggle` |
| **ssrf** | **1/8** | **最大短板**：`ssrf:internal-ip` 权重 2，单特征不达阈值 |

### C.4 转入 W3 的 4 条修复项

| # | 缺口 | 根因 | 拟修法（W3） |
|---|---|---|---|
| 1 | SSRF 7/8 放行 | 语义层单特征权重 2 < 阈值 5 | 内网 IP / 元数据地址 / 危险协议给独立高权重（4–5），或加专用正则 |
| 2 | `\|whoami`、`;powershell` 放行 | 正则漏单竖线；命令名清单缺解释器 | 正则补 `\|`；命令名清单补 powershell / bash / cmd |
| 3 | `'1'='1'` 放行 | 恒真式判定只覆盖「数字=数字」 | 扩展为「引号包裹的相等项」也算恒真 |
| 4 | `${${lower:j}ndi:` 放行 | 归一化未展开 Log4Shell 的 `${lower:}` 语法 | 归一化层加 `${lower:x}`/`${upper:x}` 展开 |

> W3 的目标：补完这 4 项后重跑同一语料，拦截率应显著提升且**误报不增加**——这条约束比拦截率本身更重要。

## 附录 B：踩坑记录

1. **双计数导致归因错误**：`Request.RawPath` 曾拼入 `RequestURI`（含 query），使 query 攻击同时命中 path 字段、
   语义分翻倍。现象：日志里 `target` 恒为 `path`。修法：`RawPath` 只放 `EscapedPath`。
2. **单字段漏报**：`?id=1' or 1=1` 只积 4 分。修法：恒真式权重 3 → 4，而不是阈值 5 → 4。
3. **规则 ID 被撑长**：同一特征在多个字段命中时，`SEM-` 后的特征名重复出现。修法：`shortList` 去重后再截断。
4. **`taskkill` 与端口占用**：重启 WAF 前必须确认旧进程已退出，否则新进程绑定失败、请求打到旧代码上，
   表现为"测试结果与代码不一致"。排查时先看 `/__waf/health` 的 `uptime_sec`。
