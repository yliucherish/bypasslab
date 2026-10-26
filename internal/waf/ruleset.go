package waf

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"time"
)

// RuleSpec 是规则的可序列化形式，用于外部配置文件。
// 字段与 Rule 一一对应，但 Targets 用字符串以便人手写 JSON。
type RuleSpec struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Severity string   `json:"severity"`
	Action   string   `json:"action"`
	Targets  []string `json:"targets"`
	Pattern  string   `json:"pattern"`
}

// RuleSetFile 是规则配置文件的结构。
//
// 用 JSON 而不是 YAML，是为了守住「零第三方依赖」这条项目底线——
// encoding/json 是标准库，YAML 就得引入 gopkg.in/yaml.v3。
type RuleSetFile struct {
	Version           string     `json:"version"`
	SemanticThreshold int        `json:"semantic_threshold"`
	Rules             []RuleSpec `json:"rules"`
}

// BuildRuleSet 把内存中的规则导出成可保存的配置（用于生成默认配置文件）。
func BuildRuleSet(rules []Rule, threshold int) RuleSetFile {
	out := RuleSetFile{
		Version:           "1.0",
		SemanticThreshold: threshold,
		Rules:             make([]RuleSpec, 0, len(rules)),
	}
	for _, r := range rules {
		targets := make([]string, 0, len(r.Targets))
		for _, t := range r.Targets {
			targets = append(targets, string(t))
		}
		out.Rules = append(out.Rules, RuleSpec{
			ID: r.ID, Name: r.Name, Category: r.Category,
			Severity: string(r.Severity), Action: string(r.Action),
			Targets: targets, Pattern: r.Pattern,
		})
	}
	return out
}

// SaveRuleSet 把规则集写到文件（缩进格式，便于人工审阅与 diff）。
func SaveRuleSet(path string, rs RuleSetFile) error {
	b, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

// LoadRuleSet 读取并**严格校验**配置文件。
//
// 校验不通过时返回错误，调用方应保留旧规则继续服务——热加载最忌讳的是
// 「配置写错一个字符，WAF 直接裸奔或整站 500」。
func LoadRuleSet(path string) ([]Rule, int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	var rs RuleSetFile
	if err := json.Unmarshal(raw, &rs); err != nil {
		return nil, 0, fmt.Errorf("JSON 解析失败: %w", err)
	}
	rules, err := rs.toRules()
	if err != nil {
		return nil, 0, err
	}
	th := rs.SemanticThreshold
	if th <= 0 {
		th = 5
	}
	return rules, th, nil
}

func (rs RuleSetFile) toRules() ([]Rule, error) {
	if len(rs.Rules) == 0 {
		return nil, fmt.Errorf("规则列表为空，拒绝加载（防止 WAF 变透明）")
	}
	seen := make(map[string]bool, len(rs.Rules))
	out := make([]Rule, 0, len(rs.Rules))
	for i, s := range rs.Rules {
		if s.ID == "" {
			return nil, fmt.Errorf("第 %d 条规则缺少 id", i+1)
		}
		if s.Pattern == "" {
			return nil, fmt.Errorf("规则 %s 缺少 pattern", s.ID)
		}
		if seen[s.ID] {
			return nil, fmt.Errorf("规则 ID 重复: %s", s.ID)
		}
		seen[s.ID] = true

		if _, err := regexp.Compile("(?i)" + s.Pattern); err != nil {
			return nil, fmt.Errorf("规则 %s 的正则非法: %w", s.ID, err)
		}
		targets, err := parseTargets(s.Targets)
		if err != nil {
			return nil, fmt.Errorf("规则 %s: %w", s.ID, err)
		}
		sev, err := parseSeverity(s.Severity)
		if err != nil {
			return nil, fmt.Errorf("规则 %s: %w", s.ID, err)
		}
		act, err := parseAction(s.Action)
		if err != nil {
			return nil, fmt.Errorf("规则 %s: %w", s.ID, err)
		}
		r := Rule{
			ID: s.ID, Name: s.Name, Category: s.Category,
			Severity: sev, Action: act, Targets: targets, Pattern: s.Pattern,
		}
		r.re = regexp.MustCompile("(?i)" + s.Pattern)
		out = append(out, r)
	}
	return out, nil
}

func parseTargets(in []string) ([]Target, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("targets 不能为空")
	}
	valid := map[Target]bool{
		TargetPath: true, TargetQuery: true, TargetBody: true,
		TargetHeaders: true, TargetUA: true,
	}
	out := make([]Target, 0, len(in))
	for _, s := range in {
		t := Target(s)
		if !valid[t] {
			return nil, fmt.Errorf("非法 target %q（可选 path/query/body/headers/ua）", s)
		}
		out = append(out, t)
	}
	return out, nil
}

func parseSeverity(s string) (Severity, error) {
	switch Severity(s) {
	case SevLow, SevMedium, SevHigh, SevCritical:
		return Severity(s), nil
	}
	return "", fmt.Errorf("非法 severity %q（可选 low/medium/high/critical）", s)
}

func parseAction(s string) (Action, error) {
	switch Action(s) {
	case ActionBlock, ActionLog:
		return Action(s), nil
	}
	return "", fmt.Errorf("非法 action %q（可选 block/log）", s)
}

// RuleFileWatcher 轮询规则文件的修改时间，变化时重新加载。
//
// 为什么不用 fsnotify：那会引入第三方依赖。轮询 2 秒一次的成本可以忽略，
// 而「改完规则 2 秒内生效」对运维已经完全够用。
type RuleFileWatcher struct {
	Path     string
	Engine   *Engine
	Interval time.Duration
	OnError  func(error) // 加载失败时的回调（用来打日志，不影响旧规则继续生效）

	lastMod time.Time
}

// Start 启动后台轮询；调用方需要保证进程生命周期内不重复启动。
func (w *RuleFileWatcher) Start(stop <-chan struct{}) {
	if w.Interval <= 0 {
		w.Interval = 2 * time.Second
	}
	if st, err := os.Stat(w.Path); err == nil {
		w.lastMod = st.ModTime()
	}
	go func() {
		ticker := time.NewTicker(w.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				w.poll()
			}
		}
	}()
}

func (w *RuleFileWatcher) poll() {
	st, err := os.Stat(w.Path)
	if err != nil {
		w.report(fmt.Errorf("stat %s: %w", w.Path, err))
		return
	}
	if st.ModTime().Equal(w.lastMod) {
		return
	}
	w.lastMod = st.ModTime()

	rules, threshold, err := LoadRuleSet(w.Path)
	if err != nil {
		// 关键设计：校验失败不改变线上规则，只报告错误。
		w.report(err)
		return
	}
	w.Engine.SetRules(rules)
	w.Engine.SetThreshold(threshold)
}

func (w *RuleFileWatcher) report(err error) {
	if w.OnError != nil {
		w.OnError(err)
	}
}
