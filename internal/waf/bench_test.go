package waf

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

var benchPayload = "id=1%20UNION/**/SELECT%20password%20FROM%20users&next=%2527%2520or%25201%253D1&ua=Mozilla%2F5.0"

// BenchmarkNormalize 单次归一化（含 8 轮解码、实体、注释双版本）。
func BenchmarkNormalize(b *testing.B) {
	b.ReportAllocs()
	b.SetBytes(int64(len(benchPayload)))
	for i := 0; i < b.N; i++ {
		_ = Normalize(benchPayload)
	}
}

// BenchmarkEngineInspectBenign 正常请求的完整检测（16 条正则 + 16 项语义，5 个字段）。
func BenchmarkEngineInspectBenign(b *testing.B) {
	e := NewEngine(nil)
	req := &Request{
		Path:  "/api/orders",
		Query: "page=2&size=20&sort=created_at",
		Body:  `{"sku":"A-1","qty":2,"note":"deliver friday"}`,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if m := e.Inspect(req); m != nil {
			b.Fatalf("良性请求被误拦: %s", m.RuleID)
		}
	}
}

// BenchmarkEngineInspectAttack 攻击请求（第一层就该命中，测最快路径）。
func BenchmarkEngineInspectAttack(b *testing.B) {
	e := NewEngine(nil)
	req := &Request{Query: benchPayload}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if m := e.Inspect(req); m == nil {
			b.Fatal("攻击请求未被拦截")
		}
	}
}

// BenchmarkProxyEndToEnd 完整请求链路：限流 → 归一化 → 检测 → 审计 → 转发。
// 用 httptest.Recorder 直接打 handler，不含真实网络栈开销。
func BenchmarkProxyEndToEnd(b *testing.B) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	audit, err := NewAudit("") // 不落盘，只计数
	if err != nil {
		b.Fatal(err)
	}
	p, err := NewProxy(Config{Upstream: u, Engine: NewEngine(nil), Audit: audit})
	if err != nil {
		b.Fatal(err)
	}
	h := p.Handler()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/orders?page=2&size=20", nil))
	}
}
