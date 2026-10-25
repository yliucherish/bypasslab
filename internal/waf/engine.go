package waf

import (
	"regexp"
	"sort"
	"strings"
)

// Severity 表示命中规则的危害等级，用于告警分级与统计。
type Severity string

const (
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// Action 表示命中后的处置动作。
type Action string

const (
	ActionBlock Action = "block"
	ActionLog   Action = "log" // 只记录不拦截（用于观察期规则）
)

// Rule 是 Layer 1 的正则规则。
type Rule struct {
	ID       string
	Name     string
	Category string
	Severity Severity
	Action   Action
	Targets  []Target
	Pattern  string
	re       *regexp.Regexp
}

// Match 是一次命中的结果。
type Match struct {
	RuleID   string   `json:"rule_id"`
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Severity Severity `json:"severity"`
	Action   Action   `json:"action"`
	Layer    string   `json:"layer"` // regex | semantic
	Target   Target   `json:"target"`
	Excerpt  string   `json:"excerpt"` // 命中片段（截断后），便于人工复核
	Score    int      `json:"score,omitempty"`
}

// Engine 组合两层检测：
//
//	Layer 1：正则规则（快、可解释、易绕过）
//	Layer 2：语义评分（慢一点、抗变形、给出综合置信度）
//
// 任一层判定 block 即拦截；两层都放行才转发。
type Engine struct {
	rules          []Rule
	SemanticScore  int // 语义层拦截阈值
	semanticChecks []semanticCheck
}

type semanticCheck struct {
	name     string
	category string
	severity Severity
	weight   int
	fn       func(string) bool
}

// NewEngine 构建引擎；rules 为 nil 时使用内置规则集。
func NewEngine(rules []Rule) *Engine {
	e := &Engine{SemanticScore: 5}
	for _, r := range rules {
		e.AddRule(r)
	}
	if len(e.rules) == 0 {
		for _, r := range BuiltinRules() {
			e.AddRule(r)
		}
	}
	e.semanticChecks = builtinSemanticChecks()
	return e
}

// AddRule 编译并注册一条规则；正则非法时 panic（规则属于代码资产，启动即失败优于静默失效）。
func (e *Engine) AddRule(r Rule) {
	r.re = regexp.MustCompile("(?i)" + r.Pattern)
	e.rules = append(e.rules, r)
}

// Rules 返回已注册规则的副本，便于 /__waf/stats 或测试断言。
func (e *Engine) Rules() []Rule {
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

// Inspect 依次跑两层检测。返回 nil 表示放行。
func (e *Engine) Inspect(req *Request) *Match {
	if m := e.inspectRegex(req); m != nil && m.Action == ActionBlock {
		return m
	}
	if m := e.inspectSemantic(req); m != nil && m.Action == ActionBlock {
		return m
	}
	return nil
}

func (e *Engine) inspectRegex(req *Request) *Match {
	for _, r := range e.rules {
		for _, t := range r.Targets {
			field := req.Field(t)
			if field == "" {
				continue
			}
			if loc := r.re.FindStringIndex(field); loc != nil {
				return &Match{
					RuleID: r.ID, Name: r.Name, Category: r.Category,
					Severity: r.Severity, Action: r.Action, Layer: "regex",
					Target: t, Excerpt: excerpt(field[loc[0]:loc[1]]),
				}
			}
		}
	}
	return nil
}

// inspectSemantic 累加语义特征权重，达到阈值即判定拦截。
// 这样设计的原因是：单个特征词（如 select）在正常业务里也可能出现，
// 但 "select + union + 引号不闭合" 同时出现时，误报率会显著下降。
func (e *Engine) inspectSemantic(req *Request) *Match {
	var (
		score    int
		hitNames []string
		hitCat   string
		hitSev   Severity = SevLow
		hitTgt   Target
	)
	for _, t := range []Target{TargetPath, TargetQuery, TargetBody, TargetUA, TargetHeaders} {
		field := req.Field(t)
		if field == "" {
			continue
		}
		for _, c := range e.semanticChecks {
			if c.fn(field) {
				score += c.weight
				hitNames = append(hitNames, c.name)
				if hitCat == "" {
					hitCat = c.category
					hitTgt = t
				}
				if sevRank(c.severity) > sevRank(hitSev) {
					hitSev = c.severity
				}
			}
		}
	}
	if score >= e.SemanticScore {
		return &Match{
			RuleID: "SEM-" + strings.Join(shortList(hitNames, 3), "+"),
			Name:   "语义组合特征命中",
			Category: hitCat, Severity: hitSev, Action: ActionBlock,
			Layer: "semantic", Target: hitTgt, Score: score,
			Excerpt: excerpt(strings.Join(hitNames, ",")),
		}
	}
	return nil
}

func sevRank(s Severity) int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	default:
		return 1
	}
}

// shortList 去重并截断特征名，避免同一特征在多个字段重复命中时把规则 ID 撑长。
func shortList(in []string, n int) []string {
	seen := map[string]bool{}
	var uniq []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			uniq = append(uniq, s)
		}
	}
	sort.Strings(uniq)
	if len(uniq) > n {
		return uniq[:n]
	}
	return uniq
}

func excerpt(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}

// builtinSemanticChecks 是 Layer 2 的特征集。
// 权重设计原则：单独出现不足以判定（如 select），组合出现才累加。
func builtinSemanticChecks() []semanticCheck {
	contains := func(subs ...string) func(string) bool {
		return func(s string) bool {
			low := strings.ToLower(s)
			for _, sub := range subs {
				if strings.Contains(low, sub) {
					return true
				}
			}
			return false
		}
	}
	return []semanticCheck{
		{"sql:union", "sqli", SevHigh, 3, contains("union select", "union  select", "union/**/select")},
		// 恒真式权重 4：单独出现（1=1 / 'or'='or）已是强信号，
		// 叠加 comment-stripped(1) 即达阈值 5；而单纯出现 'or' 这类弱特征仍不足以拦截。
		{"sql:tautology", "sqli", SevHigh, 4, isTautology},
		{"sql:time-based", "sqli", SevCritical, 3, contains("sleep(", "benchmark(", "pg_sleep(", "waitfor delay")},
		{"sql:metadata", "sqli", SevMedium, 2, contains("information_schema", "sysobjects", "load_file(", "into outfile")},
		{"sql:comment-stripped", "sqli", SevMedium, 1, contains("or 1=1", "and 1=1", "' or '", "\" or \"")},
		{"xss:script-tag", "xss", SevHigh, 3, contains("<script", "<svg", "<iframe", "<img src=x")},
		{"xss:event-handler", "xss", SevHigh, 2, contains("onerror=", "onload=", "onclick=", "onfocus=")},
		{"xss:js-uri", "xss", SevMedium, 2, contains("javascript:", "data:text/html")},
		{"rce:shell-meta", "rce", SevCritical, 3, contains(";cat ", "&&cat ", "|whoami", "$(id)", "`id`")},
		{"rce:cmd-names", "rce", SevHigh, 2, contains("/bin/sh", "cmd.exe", "powershell", "wget http", "curl http")},
		{"traversal:dotdot", "path-traversal", SevHigh, 3, contains("../..", "..\\..")},
		{"traversal:sensitive-file", "path-traversal", SevCritical, 3, contains("/etc/passwd", "win.ini", "boot.ini", "web.config")},
		{"deser:java-magic", "deserialization", SevCritical, 3, contains("ro0ab", "aced0005", "jndi:ldap", "jndi:rmi")},
		{"deser:fastjson", "deserialization", SevHigh, 3, contains("@type", "autotype")},
		{"ssrf:internal-ip", "ssrf", SevHigh, 2, contains("127.0.0.1", "169.254.169.254", "localhost:", "0.0.0.0")},
	}
}

// reTautologyPair 匹配 `A=B` 形式的恒真式候选；Go 的 RE2 不支持反向引用，
// 因此"两侧是否相同"（1=1、2=2）放到 isTautology 里用字符串比较完成。
var reTautologyPair = regexp.MustCompile(`(\d+)\s*=\s*(\d+)`)

// isTautology 判定 SQL 恒真式（1=1 / 'or'='or），这是最经典的逻辑绕过特征。
func isTautology(s string) bool {
	low := strings.ToLower(s)
	for _, m := range reTautologyPair.FindAllStringSubmatch(low, -1) {
		if m[1] == m[2] {
			return true
		}
	}
	if strings.Contains(low, "'or'='or") || strings.Contains(low, `"or"="or`) ||
		strings.Contains(low, "' or '") || strings.Contains(low, `" or "`) {
		return true
	}
	return false
}

// BuiltinRules 返回 W1 内置的 12 条正则规则。
// 规则 ID 采用 BL-<类别>-<序号>，便于日志聚合与后续对抗报告统计。
func BuiltinRules() []Rule {
	all := []Target{TargetPath, TargetQuery, TargetBody, TargetHeaders}
	withUA := append([]Target{}, append(all, TargetUA)...)
	return []Rule{
		{ID: "BL-SQLI-001", Name: "UNION 注入", Category: "sqli", Severity: SevHigh, Action: ActionBlock,
			Targets: all, Pattern: `union\s+(all\s+)?select`},
		{ID: "BL-SQLI-002", Name: "报错注入函数", Category: "sqli", Severity: SevHigh, Action: ActionBlock,
			Targets: all, Pattern: `(extractvalue|updatexml|geometrycollection)\s*\(`},
		{ID: "BL-SQLI-003", Name: "布尔/时间盲注", Category: "sqli", Severity: SevCritical, Action: ActionBlock,
			Targets: all, Pattern: `(sleep|benchmark|pg_sleep)\s*\(\s*\d`},
		{ID: "BL-XSS-001", Name: "Script 标签", Category: "xss", Severity: SevHigh, Action: ActionBlock,
			Targets: all, Pattern: `<script[^>]*>`},
		{ID: "BL-XSS-002", Name: "事件处理器注入", Category: "xss", Severity: SevHigh, Action: ActionBlock,
			Targets: all, Pattern: `\bon(error|load|focus|mouseover|click)\s*=`},
		{ID: "BL-RCE-001", Name: "命令拼接", Category: "rce", Severity: SevCritical, Action: ActionBlock,
			Targets: all, Pattern: `(;|&&|\|\|)\s*(cat|ls|id|whoami|uname|ping|curl|wget|nc)\b`},
		{ID: "BL-RCE-002", Name: "命令替换", Category: "rce", Severity: SevCritical, Action: ActionBlock,
			Targets: all, Pattern: `(\$\([^)]{1,40}\)|` + "`[^`]{1,40}`" + `)`},
		{ID: "BL-TRAV-001", Name: "路径遍历", Category: "path-traversal", Severity: SevHigh, Action: ActionBlock,
			Targets: all, Pattern: `(\.\./|\.\.\\){2,}`},
		{ID: "BL-TRAV-002", Name: "敏感文件读取", Category: "path-traversal", Severity: SevCritical, Action: ActionBlock,
			Targets: all, Pattern: `(/etc/passwd|/etc/shadow|win\.ini|boot\.ini|\.\.%2f)`},
		{ID: "BL-DESER-001", Name: "JNDI 注入（Log4Shell 特征）", Category: "deserialization", Severity: SevCritical, Action: ActionBlock,
			Targets: all, Pattern: `\$\{jndi:(ldap|rmi|dns|iiop)`},
		{ID: "BL-DESER-002", Name: "Fastjson autoType", Category: "deserialization", Severity: SevHigh, Action: ActionBlock,
			Targets: all, Pattern: `"@type"\s*:\s*"`},
		{ID: "BL-SCAN-001", Name: "扫描器指纹", Category: "scanner", Severity: SevMedium, Action: ActionBlock,
			Targets: withUA, Pattern: `(sqlmap|nikto|nmap|masscan|nessus|acunetix|dirbuster|gobuster|nuclei|xray|zgrab)`},
	}
}
