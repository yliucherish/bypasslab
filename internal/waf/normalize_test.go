package waf

import (
	"strings"
	"testing"
)

// TestNormalizeEncodingBypasses 覆盖 AUDIT P1-1 修掉的几类编码绕过：
// 双重 HTML 实体、4 层 URL 编码、Unicode / 十六进制转义、非常规 IP 字面量。
func TestNormalizeEncodingBypasses(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"双重 HTML 实体", "&amp;lt;script&amp;gt;", "<script>"},
		{"四层 URL 编码", "%25252527%25252520or%252525201%2525253D1", "' or 1=1"},
		{"Unicode 转义", `\u003cscript\u003e`, "<script>"},
		// AUDIT N2：\xXX 不再解码——正文里讨论转义写法会被误归一成标签而误拦；
		// 现有语料（W3-HARD-XSS-002）用的是 \u 形态，去掉 \x 不影响检出。
		{"十六进制转义保持原样", `\x3cscript\x3e`, `\x3cscript\x3e`},
		{"十进制 IP", "http://2130706433/admin", "http://127.0.0.1/admin"},
		{"十六进制 IP", "http://0x7f000001/admin", "http://127.0.0.1/admin"},
		{"八进制段 IP", "http://0177.0.0.1/admin", "http://127.0.0.1/admin"},
		{"两段简写 IP", "http://127.1/admin", "http://127.0.0.1/admin"},
	}
	for _, c := range cases {
		if got := Normalize(c.in); got != c.want {
			t.Errorf("[%s] Normalize(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

// TestPathPlusKeepsLiteral AUDIT L3：path/body 里的 `+` 是字面量，不能被解码成空格；
// 只有 query 里的 `+` 才代表空格。
func TestPathPlusKeepsLiteral(t *testing.T) {
	req := &Request{Path: "/a+b", RawPath: "/a+b"}
	if got := req.Field(TargetPath); strings.Contains(got, "a b") {
		t.Fatalf("path 里的 + 被错误解码成空格: %q", got)
	}
	q := &Request{Query: "q=a+b"}
	if got := q.Field(TargetQuery); !strings.Contains(got, "a b") {
		t.Fatalf("query 里的 + 应解码成空格: %q", got)
	}
}

// TestBareOrIsNotBlocked AUDIT M6：旧实现里裸 `' or '` 会被 tautology(4) + comment(1) 凑成 5 分。
// 修完后必须由等式判断（1=1 / 'x'='x'）给分，正常文本不应被拦。
func TestBareOrIsNotBlocked(t *testing.T) {
	e := NewEngine(nil)
	if m := e.Inspect(&Request{Query: "q=life%20'%20or%20'%20death"}); m != nil {
		t.Fatalf("含裸 ' or ' 的正常文本被误报: rule=%s score=%d", m.RuleID, m.Score)
	}
}

// TestTautologyStillBlocked 修完之后真正的恒真式仍必须拦。
// 注意：单独一个 4 分的恒真式（如数学式 2=2）不足以触发阈值 5，
// 需要配合注释剥离特征（1 or 1=1）或引号对特征（'1'='1'）——这正是文档宣称的口径。
func TestTautologyStillBlocked(t *testing.T) {
	e := NewEngine(nil)
	for _, q := range []string{"id=1' or 1=1--", "id=1 and 1=1", "name=1' and '1'='1'"} {
		if m := e.Inspect(&Request{Query: q}); m == nil {
			t.Errorf("恒真式未拦截: %q", q)
		}
	}
}

// TestBodyJavaScriptNotBlocked AUDIT M7：正文讨论 javascript: 属于正常内容。
func TestBodyJavaScriptNotBlocked(t *testing.T) {
	e := NewEngine(nil)
	if m := e.Inspect(&Request{Body: "这篇笔记讲 javascript:void(0) 的常见用法"}); m != nil {
		t.Fatalf("正文讨论 javascript: 被误报: rule=%s", m.RuleID)
	}
}

// TestScannerKeywordInBodyNotBlocked AUDIT M7：正文提到扫描器名字不该被拦。
func TestScannerKeywordInBodyNotBlocked(t *testing.T) {
	e := NewEngine(nil)
	if m := e.Inspect(&Request{Body: "工具对比：nmap 端口扫描、sqlmap 注入检测、nikto Web 检查"}); m != nil {
		t.Fatalf("正文提到扫描器名被误报: rule=%s", m.RuleID)
	}
}

// TestJSTargetStillBlockedInQuery 收窄到 path/query/headers 后，query 里的 javascript: 仍要拦。
func TestJSTargetStillBlockedInQuery(t *testing.T) {
	e := NewEngine(nil)
	if m := e.Inspect(&Request{Query: "redirect=javascript:alert(1)"}); m == nil {
		t.Fatal("query 里的 javascript: 未拦截")
	}
}

// TestSemanticScoreIsPerTarget AUDIT M5：语义分不再跨字段累加。
// query 的恒真式 4 分 + body 的无关弱特征（information_schema，2 分）在旧实现里
// 会累加成 6 分触发拦截，新实现各字段独立计分，都不到阈值 5，应放行。
func TestSemanticScoreIsPerTarget(t *testing.T) {
	e := NewEngine(nil)
	req := &Request{
		Query: "q=1=1",
		Body:  "读书笔记：information_schema 是 MySQL 自带的系统库",
	}
	if m := e.Inspect(req); m != nil {
		t.Fatalf("跨字段凑分导致误报: rule=%s score=%d target=%s", m.RuleID, m.Score, m.Target)
	}
}

// TestSemanticThresholdConfigurable AUDIT P2-4：阈值可从外部调整，便于做权重实验。
func TestSemanticThresholdConfigurable(t *testing.T) {
	e := NewEngine(nil)
	if e.Threshold() != 5 {
		t.Fatalf("默认阈值 = %d, want 5", e.Threshold())
	}
	e.SetThreshold(9)
	if e.Threshold() != 9 {
		t.Fatalf("SetThreshold 未生效: %d", e.Threshold())
	}
	// 9 分阈值下，4 分的恒真式单独不再命中（正则会命中，故用纯语义样本）
	if m := e.Inspect(&Request{Query: "q=1=1"}); m != nil {
		t.Fatalf("阈值 9 时 4 分样本仍被拦: score=%d", m.Score)
	}
	e.SetThreshold(3)
	if m := e.Inspect(&Request{Query: "q=1=1"}); m == nil {
		t.Fatal("阈值 3 时 4 分样本应被拦")
	}
}
