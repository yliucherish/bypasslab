package waf

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func newTestProxy(t *testing.T) (*Proxy, *httptest.Server) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "hit")
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	audit, err := NewAudit("")
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProxy(Config{Upstream: u, Engine: NewEngine(nil), Audit: audit, MaxBody: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return p, upstream
}

// TestProxyBlocksInjection 端到端：恶意请求被 403 拦下，且响应里带规则 ID。
func TestProxyBlocksInjection(t *testing.T) {
	p, _ := newTestProxy(t)
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/product?id=1%20UNION%20SELECT%20password%20FROM%20users")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("状态码 = %d, want 403", resp.StatusCode)
	}
	if rid := resp.Header.Get("X-BypassLab-Blocked"); rid == "" {
		t.Fatal("缺少 X-BypassLab-Blocked 响应头")
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("响应非 JSON: %v", err)
	}
	if body["blocked"] != true {
		t.Fatalf("响应体 blocked 字段异常: %v", body)
	}
}

// TestProxyPassesBenign 正常请求应被转发到上游，并带上上游响应头。
func TestProxyPassesBenign(t *testing.T) {
	p, _ := newTestProxy(t)
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/orders?page=2&size=20")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d, want 200", resp.StatusCode)
	}
	if resp.Header.Get("X-Upstream") != "hit" {
		t.Fatal("未转发到上游")
	}
}

// TestProxyStatsAndHealth 验证内部端点可用。
func TestProxyStatsAndHealth(t *testing.T) {
	p, _ := newTestProxy(t)
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	for _, ep := range []string{"/__waf/health", "/__waf/stats"} {
		resp, err := http.Get(srv.URL + ep)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s 状态码 = %d", ep, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

// TestProxyAuditCounts 拦截后统计计数应增加，供后续对抗报告取数。
func TestProxyAuditCounts(t *testing.T) {
	p, _ := newTestProxy(t)
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	for i := 0; i < 3; i++ {
		resp, err := http.Get(srv.URL + "/x?f=../../etc/passwd")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	stats := p.cfg.Audit.Stats()
	if stats["total_blocks"].(int) != 3 {
		t.Fatalf("total_blocks = %v, want 3", stats["total_blocks"])
	}
	byRule, ok := stats["by_rule"].(map[string]int)
	if !ok || len(byRule) == 0 {
		t.Fatalf("by_rule 统计为空: %v", stats)
	}
}

// TestProxyRateLimit 限流生效后返回 429。
func TestProxyRateLimit(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	audit, _ := NewAudit("")
	p, err := NewProxy(Config{Upstream: u, Engine: NewEngine(nil), Audit: audit, RateLimit: 2})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	var last int
	for i := 0; i < 4; i++ {
		resp, err := http.Get(srv.URL + "/api/ping")
		if err != nil {
			t.Fatal(err)
		}
		last = resp.StatusCode
		resp.Body.Close()
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("最后一次状态码 = %d, want 429", last)
	}
}

// TestProxyPreservesBody 拦截检查读过 body 后，正常请求的 body 仍要传给上游。
func TestProxyPreservesBody(t *testing.T) {
	got := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := new(strings.Builder)
		buf := make([]byte, 256)
		n, _ := r.Body.Read(buf)
		b.Write(buf[:n])
		got <- b.String()
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	audit, _ := NewAudit("")
	p, _ := NewProxy(Config{Upstream: u, Engine: NewEngine(nil), Audit: audit})
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	payload := `{"order":"A-2026-1025","qty":2}`
	resp, err := http.Post(srv.URL+"/api/order", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if body := <-got; body != payload {
		t.Fatalf("上游收到 body = %q, want %q", body, payload)
	}
}
