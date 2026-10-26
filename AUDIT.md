# BypassLab 代码审查报告与修复规划（AUDIT）

> **执行状态：已落地（2026-10-26）**
> 分支 `audit/v1.1`，commits `99befe9`（代码+测试）/ `3cbc213`（数据重跑）/ `865d11a`（文档），tag `v1.1-audit`。
>
> | 项 | 状态 |
> |---|---|
> | P0-1 body 超限绕过 | ✅ 返回 413 + `BL-OVERSIZE`，驱动器侧计为拦截 |
> | P0-2 health 数据竞争 | ✅ 读侧 RLock；CI 改 `go test -race`；新增并发测试 |
> | P0-3 文档对齐 | ✅ 12→16 条、13→39 测试、令牌桶→滑动窗口 |
> | P1-1 归一化（含已知缺口） | ✅ 解码/实体解到不动点、Unicode/十六进制转义、IPv4 各种字面量归一（IPv6 映射未做） |
> | P1-2 限流 XFF + 内存 | ✅ `-trusted-proxies` + 惰性清理 |
> | P1-3 `waf_allow` 事件 | ✅ 已落地（`-log-allows`，默认开） |
> | P1-4 计分口径 | ✅ 按字段独立计分；裸 `' or '` 不再双计；引号恒真式允许末尾引号省略 |
> | P1-5 误报面 | ✅ 两类规则收窄 targets；良性语料 24→28（只增不删） |
> | P2-1 ~ P2-3、P2-5、P2-6、P2-7 | ✅ 全部完成（门槛已提到 95% + 误报 0） |
> | P2-4 权重外置 | ⚠️ 部分完成：阈值可用 `-semantic-threshold` 覆盖，特征权重表仍在代码里 |
>
> **数据变化**：W2 拦截率 79.8% → **100%（84/84）**；R3 硬语料 91.2% → **94.1%（96/102）**；误报全程 0（0/28）；
> 测试 13 → **39** 个函数。剩余 6 条 R3 绕过（IPv6 映射、`%c0%af`、MySQL 版本注释、注释还原、括号恒真式、
> `${env:}` 前缀）留在 SPEC 附录 D.4 作为 R4 输入。
>
> **v1.2 / v1.3 追加（2026-10-26 晚）**：本文件列的 P0/P1/P2 之后又做了两轮——
> ① v1.2 修完 R3 暴露的 6 条缺口（版本注释、注释拆词双版本匹配、括号恒真式、IPv6 映射、`${env:}`、`%c0%af`）；
> ② v1.3 按复审意见修 7 项（其中 N1 = 上一轮 `statusRecorder` 引入的 SSE/WebSocket 回归），
> 并新增 12 条**独立构造**的 R4 语料：修前 97.9%（又暴露 2 条），修后 100%。
> 测试 39 → 49 个。详见 SPEC 附录 F。
>
> **未执行（刻意保留）**：不设"最终版本"——R4 之后若再造新语料，一定还会有下一批。
> 这个项目的方法论就是：**永远保留一次"被自己的新语料打回原形"的记录**，而不是宣称收敛。

> 审查时间：2026-10-26　审查方式：全量源码通读 + CSV 产物逐行复核
> 适用范围：W1–W4 全部交付（cmd/ ×4、internal/ ×3、文档、CI、语料、报告）
> 本文档用途：交接给执行模型的**唯一事实来源**。所有结论已在当前代码上验证，修复计划只写思路与验收标准，不写具体代码。

---

## 0. 总评

W1–W4 全部真实落地，无造假。CSV 复核结果与文档宣称逐位一致：

| 指标 | 文档宣称 | CSV 实测 |
|---|---|---|
| W2 拦截率 | 79.8%（67/84） | 67/84 = 79.8%，误报 0 |
| R2 拦截率 | 100%（84/84） | 84/84，误报 0 |
| R3 拦截率 | 91.2%（含 18 条未见变形） | 93/102 = 91.2%，误报 0 |
| 规则数 | 16 条正则 + 16 项语义特征 | 16 + 16 |

**最大风险不在已自我披露的 9 条规则绕过，而在两个实现层缺陷**（body 截断转发、health 数据竞争）和若干文档漂移。必修项完成后，项目在「诚实度 + 工程完整度」上经得起逐行追问。

---

## 1. 完整性评估：文档 vs 代码

| 文档宣称 | 代码实际 | 结论 |
|---|---|---|
| 16 条正则 + 16 项语义 | 16 + 16 | ✅ 真实 |
| W2/R2/R3 数据 | 精确一致 | ✅ 真实 |
| 15 用例基线（3 正常 + 12 攻击） | demo_w1.sh 一致 | ✅ 真实 |
| 13 个测试函数 | waf 包恰 13 个，全仓实际 17 个 | ⚠️ 过时（未夸大） |
| README 架构表「12 条内置规则」、SPEC「BuiltinRules() 12 条」 | 代码 16 条，`TestRuleCount` 断言 16 | ❌ **文档漂移** |
| 契约 `event_type: waf_block / waf_allow` | 代码从不产生 `waf_allow` | ❌ **承诺未落地** |
| 「单 IP 每分钟令牌桶限流」 | 实现是滑动窗口计数器 | ⚠️ 名词不实，功能等价 |
| SentinelWatch 联动 | 只有字段契约，未联调 | ✅ 表述诚实（已自注待对端） |
| R3 剩余 9 条绕过 | 与代码缺口吻合 | ⚠️ 缺口清单不全（另有未承认的第 10 类） |

---

## 2. 缺陷清单（18 项）

### 高危

| # | 位置 | 问题 | 触发条件 |
|---|---|---|---|
| H1 | `proxy.go` `readBodyLimited` + `serve` | body 超 MaxBody(1MiB) 被**静默截断后转发**，Content-Length 未同步。后果双重：(a) 1MiB 之后的攻击载荷不经检查直通上游；(b) 上游按原 Content-Length 读取会挂起/报错 | POST >1MiB 且恶意内容在截断点之后 |
| H2 | `proxy.go` `/__waf/health` 闭包 | 无锁读 `p.passages`，与 `serve` 的 `p.mu.Lock` 写构成 data race | 并发期间访问 health（`go test -race` 必现） |

### 中危

| # | 位置 | 问题 | 触发条件 |
|---|---|---|---|
| M1 | `proxy.go` `ClientIP` + 限流 | 无条件信任 X-Forwarded-For 首值，伪造头部即绕过限流 | 每请求变换 XFF |
| M2 | `proxy.go` `rateLimiter.allow` | hits map 从不删除空闲 IP 的 key，内存随来源 IP 数无界增长 | 长跑 + 大量来源 IP |
| M3 | `normalize.go` | HTML 实体只解 1 轮，`&amp;lt;script&amp;gt;` 绕过 XSS 全部规则（**文档未承认的第 10 类绕过**） | 双重实体编码 payload |
| M4 | `normalize.go` | URL 解码硬上限 3 轮，4 层编码（如 `%25252527`）绕过 | 多层编码 payload |
| M5 | `engine.go` `inspectSemantic` | 语义分跨 5 个 target 累加，单字段弱特征可跨字段凑满阈值；`hitCat/hitTgt` 只记首个命中，归因不准 | query 4 分 + body 无关 1 分 |
| M6 | `engine.go` `isTautology` + `sql:comment-stripped` | `' or '` 子串同时触发 4 分 + 1 分，不含等式的正常文本（如搜索 `life ' or 'death`）也被拦；实际行为比 SPEC 宣称更松 | 文本含 `' or '` |
| M7 | BL-XSS-003 / BL-SCAN-001 | `javascript:` 与扫描器关键词作用于 body/query，正文讨论这些词被误拦；24 条良性语料未覆盖此类，「误报 0」结论对这两类不成立 | 正文含 `javascript:` / `nmap` 等词 |
| M8 | `cmd/report/main.go` `readCSV` | off-by-one：`len(rec) < 11` 但访问 `rec[11]`，11 列畸形行 panic | 手工/损坏的矩阵 CSV |

### 低危

| # | 位置 | 问题 |
|---|---|---|
| L1 | `proxy.go` `serve` | `waf_allow` 事件从未写入，与 SPEC/README 联动契约不符 |
| L2 | `driver.go` `send` | 429 响应无规则头被计为「放行」，WAF 开 `-rate` 跑语料会虚增绕过数 |
| L3 | `normalize.go` | `url.QueryUnescape` 把 path/UA 里的 `+` 解码成空格（对 query 正确，对 path/body 错误） |
| L4 | `cmd/report` `summarize` | 不读 error 列（索引 12），执行错误的样本计入绕过清单 |
| L5 | `engine.go` | 同一字段被重复 Normalize 最多 16 次（每规则一次）；contains 每特征重复 ToLower |
| L6 | README/SPEC | 规则数 12 vs 16、测试数 13 vs 17、「令牌桶」名词 |
| L7 | `proxy.go` `writeEvent` / `audit.go` | 审计写盘错误被吞（`_ =`）；每条裸写无 bufio |
| L8 | `cmd/waf` | 无优雅关停，`http.ErrServerClosed` 也走 `log.Fatalf` |

### 文档承认但未修的 R3 缺口（9 条，代码与文档一致）

归一化层：IP 字面量归一（十进制/十六进制/IPv6 映射）、超长编码、Unicode 转义（`\u003c`、`..%c0%af`）；规则层：注释还原（`un/**/ion`）、括号恒真式、`${env:FOO:-j}ndi` env 前缀。

---

## 3. 修复计划（交接执行用）

> 执行顺序建议：P0 → P1 → P2。每完成一组，跑 `go vet ./... && go test ./...`（P0 后加 `-race`），并重跑对应轮次语料出 CSV 复核。
> 全局约束：**不得为了通过测试而改测试断言**；所有修复必须新增针对性测试守住；README/SPEC 的改动与代码改动放在同一 commit。

### P0 必修（简历可信度相关，面试一问就穿）

#### P0-1 修 body 截断转发（H1）
- **思路**：二选一，推荐方案 A。
  - 方案 A（拒绝）：超限直接返回 413 Request Entity Too Large，写审计事件，不转发。简单、安全语义清晰。
  - 方案 B（原样转发）：读全量 body，仅对前 MaxBody 字节做检测，原样转发全文。实现复杂（大 body 内存占用），收益不明显。
- **涉及**：`proxy.go` 的 `readBodyLimited` 与 `serve` 中 body 回填逻辑。
- **验收**：新增测试「>1MiB body → 413 + 审计事件含 oversize 标记」；「恰好 1MiB 与 1MiB-1 的 body 正常转发且 Content-Length 正确」；R3 语料回归拦截率/误报不变。

#### P0-2 修 health 数据竞争 + CI 启用 race（H2）
- **思路**：health/stats 读取处加 `p.mu.RLock()`（已声明 RWMutex，读侧用上）；`.github/workflows/ci.yml` 的测试步骤改为 `go test -race ./...`。
- **涉及**：`proxy.go` Handler 闭包、ci.yml。
- **验收**：`go test -race ./...` 干净；新增并发测试（N 个 goroutine 请求 + 并发读 health/stats）。

#### P0-3 文档对齐（L6）
- **思路**：README 架构表 12→16、SPEC 的 BuiltinRules() 描述同步；测试数 13→17；「令牌桶」→「滑动窗口计数器」（或 P1-2 里顺手实现真令牌桶后保留原名，二选一，**推荐改名**，工作量最小）。
- **验收**：grep 全文不再有「12 条」「13 个测试」「令牌桶」残留表述。

### P1 建议修（显著提升项目深度）

#### P1-1 补 R4 归一化层（M3、M4 + 已知缺口）
- **思路**：
  - HTML 实体解码与 URL 解码均改为「循环至不动点」，各设上限（URL ≤8 轮、实体 ≤3 轮），超限记指标 `normalize_overflow`。
  - IP 字面量归一：把十进制/十六进制/IPv6 映射的 IP 字面量统一成点分十进制再进规则匹配。
  - Unicode 转义（`\u003c`、`\x3c` 风格）在归一化管道加一步展开。
  - 修复后把「双重实体、4 层编码」补进 hard 语料，重跑 R4，让拦截率曲线多一轮。
- **价值叙事**：「发现并修复自己没承认过的绕过」比「修完已列出的待办」故事性强，可续写博客第 6 篇。
- **涉及**：`normalize.go`、`payloads/hard.go`（新增语料）、README/SPEC 附录补 R4 记录。
- **验收**：`TestNormalize` 新增 ≥4 组断言（双重实体、4 层编码、十进制 IP、`\u003c`）；R4 报告数据进 SPEC 附录。

#### P1-2 限流器两项（M1、M2）
- **思路**：
  - `ClientIP` 增加 `TrustedProxies` 配置：仅当直接对端在可信代理列表内才采信 XFF，否则用 `RemoteAddr`。
  - hits map 加惰性过期清理（遍历时顺手删除整段窗口已过期的 key，或加定期清理 goroutine，注意加锁）。
  - 把「伪造 XFF 绕过限流 → 修复」写成一条对抗记录进 README，契合项目主线。
- **验收**：新增测试「伪造 XFF 不再绕过限流」「长跑模拟后 map 大小有界」。

#### P1-3 `waf_allow` 事件落地（L1）
- **思路**：放行路径也写 JSONL（支持采样率配置，默认全量或 100%）；报告器加「allow/block 流量比」展示。
- **验收**：运行 demo 脚本后 `logs/waf.jsonl` 中同时存在 `waf_allow` 与 `waf_block` 两类事件；契约与实现一致。

#### P1-4 语义层计分口径（M5、M6）
- **思路**（二选一，需在 SPEC 写清）：
  - 方案 A：按 target 独立计分，任一字段达阈值即拦，归因精确到字段。
  - 方案 B：保留跨字段累加但显式文档化，并把 `hitTgt` 改为记录全部命中字段。
  - 同时修 `' or '` 双重计分：从 `sql:comment-stripped` 的 contains 列表移除 `' or '`，让恒真式必须由等式判断给出分数。
- **验收**：新增误报面测试（含 `' or '` 的良性文本不拦）；SPEC 描述与代码逐字一致。

#### P1-5 误报面收敛（M7）
- **思路**：BL-XSS-003、BL-SCAN-001 的 targets 去掉 body（或 body 命中单独降权并文档化）；良性语料补 3-5 条「正文讨论 javascript:/nmap」样本。
- **验收**：新增良性样本不误报；原攻击语料拦截率不降。

### P2 可选增强

| 项 | 内容 | 验收 |
|---|---|---|
| P2-1 | 驱动器 429 口径：Blocked 判定加 `StatusCode==429 → 记 Error 而非放行`（L2） | 开 `-rate` 跑语料，报告 Errors 正确归类 |
| P2-2 | `readCSV` off-by-one 改 `len(rec) < 12`，并读 error 列与 driver 口径对齐（M8、L4） | 畸形 CSV 测试不再 panic；含 error 的轮次报告口径正确 |
| P2-3 | 测试加固：body 超限、4 层编码、双重实体、`' or '` 误报面各补断言；`TestCorpusRunsAgainstWAF` 门槛 75% → ≥95% 且误报 0（与实测挂钩） | 新断言全绿；回归门槛收紧后仍通过 |
| P2-4 | 规则权重外置（flag/常量表）+ 「调权重 → 重跑矩阵」实验记录 | 权重表可从命令行覆盖，附一次实验数据 |
| P2-5 | 优雅关停：`signal.NotifyContext` + `Shutdown`，`ErrServerClosed` 不再 fatal（L8） | SIGTERM 下进程干净退出 |
| P2-6 | 审计可靠性：写盘错误至少 `log.Printf` 一次；可选 bufio 缓冲 + flush（L7） | 磁盘满场景测试可见错误日志 |
| P2-7 | 性能去重：同请求内按 target 缓存 Normalize 结果（L5） | `go test -bench` 或 pprof 对比有提升 |

---

## 4. 给执行模型的注意事项

1. **先建分支**，每组 P0/P1 一个 commit，commit message 引用本文件条目编号（如 `fix(proxy): P0-1 reject oversized body`）。
2. **修 H1 时注意**：若选方案 A（413），要在驱动器侧同步处理——413 响应对攻击样本应记为「拦截」还是「错误」需要明确（建议：记为拦截，类别 `oversize`，并在 README 口径里写明）。
3. **任何改动拦截/放行语义的修复**（P1-4、P1-5、P1-1），都必须重跑全部三轮语料并更新 README/SPEC 的实测数字，**不允许出现新数据与旧表格并存**。
4. **不要动 `payloads/` 良性语料的判定基准来凑指标**；新增良性样本只能增加不能删除替换。
5. 完成后总验收：`go vet ./... && go test -race ./... && go build ./...` 干净；`scripts/run_w2.sh`、`scripts/run_w4.sh` 全链路复跑成功；README 宣称数字与最新 CSV 逐位一致。
6. 修完 P0+P1 后建议 git tag `v1.1-audit`，方便简历/博客引用版本。

---

*本报告由全量代码审查生成，所有缺陷均给出文件与函数级定位；数据经 CSV 独立复核。*
