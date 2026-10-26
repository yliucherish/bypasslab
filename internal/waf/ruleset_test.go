package waf

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestRuleSetRoundTrip 导出 → 加载 → 规则仍可用。
func TestRuleSetRoundTrip(t *testing.T) {
	e := NewEngine(nil)
	rs := BuildRuleSet(e.Rules(), e.Threshold())
	dir := t.TempDir()
	p := filepath.Join(dir, "rules.json")
	if err := SaveRuleSet(p, rs); err != nil {
		t.Fatal(err)
	}
	rules, th, err := LoadRuleSet(p)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if len(rules) != len(e.Rules()) {
		t.Fatalf("规则数 %d, want %d", len(rules), len(e.Rules()))
	}
	if th != e.Threshold() {
		t.Fatalf("阈值 %d, want %d", th, e.Threshold())
	}
	// 加载后的规则必须仍然能拦
	e2 := NewEngine(nil)
	e2.SetRules(rules)
	if m := e2.Inspect(&Request{Query: "id=1 union select 1"}); m == nil {
		t.Fatal("外部配置加载后规则失效")
	}
}

// TestLoadRuleSetRejects 非法配置必须被拒绝——热加载最怕"写错一个字符就裸奔"。
func TestLoadRuleSetRejects(t *testing.T) {
	cases := []struct{ name, body string }{
		{"规则列表为空", `{"rules":[]}`},
		{"正则非法", `{"rules":[{"id":"A","pattern":"(","targets":["query"],"severity":"high","action":"block"}]}`},
		{"target 非法", `{"rules":[{"id":"A","pattern":"x","targets":["nope"],"severity":"high","action":"block"}]}`},
		{"severity 非法", `{"rules":[{"id":"A","pattern":"x","targets":["query"],"severity":"urgent","action":"block"}]}`},
		{"action 非法", `{"rules":[{"id":"A","pattern":"x","targets":["query"],"severity":"high","action":"drop"}]}`},
		{"ID 重复", `{"rules":[{"id":"A","pattern":"x","targets":["query"],"severity":"high","action":"block"},{"id":"A","pattern":"y","targets":["query"],"severity":"high","action":"block"}]}`},
		{"JSON 损坏", `{"rules":`},
	}
	for _, c := range cases {
		dir := t.TempDir()
		p := filepath.Join(dir, "rules.json")
		if err := os.WriteFile(p, []byte(c.body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := LoadRuleSet(p); err == nil {
			t.Errorf("[%s] 非法配置未被拒绝", c.name)
		}
	}
}

// TestHotReloadApplies 改文件后 poll 一次，引擎规则应更新。
func TestHotReloadApplies(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rules.json")

	one := RuleSetFile{Version: "1", SemanticThreshold: 5, Rules: []RuleSpec{{
		ID: "T-1", Name: "只留一条", Category: "sqli", Severity: "high",
		Action: "block", Targets: []string{"query"}, Pattern: `union\s+select`,
	}}}
	if err := SaveRuleSet(p, one); err != nil {
		t.Fatal(err)
	}

	e := NewEngine(nil)
	w := &RuleFileWatcher{Path: p, Engine: e}
	w.lastMod = time.Time{} // 强制触发一次
	w.poll()

	if got := len(e.Rules()); got != 1 {
		t.Fatalf("热加载后规则数 = %d, want 1", got)
	}
	if m := e.Inspect(&Request{Query: "id=1 union select 1"}); m == nil {
		t.Fatal("热加载的规则不生效")
	}
}

// TestHotReloadKeepsOldOnError 坏配置不能影响线上规则（这条比"能加载"更重要）。
func TestHotReloadKeepsOldOnError(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rules.json")
	good := RuleSetFile{Version: "1", SemanticThreshold: 5, Rules: []RuleSpec{{
		ID: "T-1", Name: "good", Category: "sqli", Severity: "high",
		Action: "block", Targets: []string{"query"}, Pattern: `union\s+select`,
	}}}
	if err := SaveRuleSet(p, good); err != nil {
		t.Fatal(err)
	}

	e := NewEngine(nil)
	var gotErr error
	w := &RuleFileWatcher{Path: p, Engine: e, OnError: func(err error) { gotErr = err }}
	w.lastMod = time.Time{}
	w.poll()
	before := len(e.Rules())

	// 故意写坏
	if err := os.WriteFile(p, []byte(`{"rules":[{"id":"","pattern":"x"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	w.lastMod = time.Time{}
	w.poll()

	if gotErr == nil {
		t.Fatal("坏配置未上报错误")
	}
	if after := len(e.Rules()); after != before {
		t.Fatalf("坏配置改变了线上规则: %d -> %d", before, after)
	}
	if m := e.Inspect(&Request{Query: "id=1 union select 1"}); m == nil {
		t.Fatal("坏配置导致原规则失效")
	}
}
