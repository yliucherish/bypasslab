package waf

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newProxyWith 构造一个可定制配置的 WAF（保留默认上游），供加固测试复用。
func newProxyWith(t *testing.T, mut func(*Config)) (*Proxy, *int32) {
	t.Helper()
	var hits int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("X-Upstream", "hit")
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	audit, err := NewAudit("")
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Upstream: u, Engine: NewEngine(nil), Audit: audit}
	if mut != nil {
		mut(&cfg)
	}
	p, err := NewProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p, &hits
}

// TestOversizedBodyStreams v1.6 起：超 MaxBody 的 body 不再 413，
// 而是走流式分块检测 + 原样转发（大文件上传不被挡）。
func TestOversizedBodyStreams(t *testing.T) {
	p, hits := newProxyWith(t, func(c *Config) { c.MaxBody = 16 })
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	body := strings.Repeat("A", 64)
	resp, err := http.Post(srv.URL+"/api/upload", "text/plain", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d, want 200（超限 body 应流式转发）", resp.StatusCode)
	}
	// newProxyWith 的 hits 计的是请求数：超限 body 被完整转发（上游命中 1 次）
	if n := atomic.LoadInt32(hits); n != 1 {
		t.Fatalf("上游命中次数 = %d, want 1", n)
	}
}

// TestSneakyContentLengthTruncated 谎报 Content-Length（声明 ≤ MaxBody、实际更大）时，
// Go http.Server 会把 body 截断到声明长度——多余的字节既到不了检测层，也到不了上游。
// 用 newStreamProxy（按字节统计）验证：上游收到的字节数必须远小于实际发送量。
func TestSneakyContentLengthTruncated(t *testing.T) {
	_, srv, bytesHit := newStreamProxy(t, 16)

	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw := "POST /api/upload HTTP/1.1\r\nHost: test\r\nContent-Length: 8\r\n\r\n" + strings.Repeat("A", 64)
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	line, _ := br.ReadString('\n')
	if !strings.Contains(line, "200") {
		t.Fatalf("截断后的干净 body 不应被拦: %s", strings.TrimSpace(line))
	}
	// 实际发送 64 字节，上游收到的必须远小于此（标准库按 CL=8 截断）
	if n := atomic.LoadInt32(bytesHit); n >= 64 {
		t.Fatalf("多余字节透传到了上游（%d 字节）——谎报 Content-Length 不能让超额数据穿透", n)
	}
}

// TestProxyAcceptsBodyAtLimit 边界：恰好等于 MaxBody 时应正常转发。
func TestProxyAcceptsBodyAtLimit(t *testing.T) {
	p, hits := newProxyWith(t, func(c *Config) { c.MaxBody = 16 })
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/upload", "text/plain", strings.NewReader(strings.Repeat("B", 16)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("边界 body 状态码 = %d, want 200", resp.StatusCode)
	}
	if n := atomic.LoadInt32(hits); n != 1 {
		t.Fatalf("边界 body 未转发，上游命中 %d 次", n)
	}
}

// TestProxyWritesAllowEvents AUDIT P1-3：放行也要写 waf_allow 事件，兑现契约。
func TestProxyWritesAllowEvents(t *testing.T) {
	p, _ := newProxyWith(t, func(c *Config) { c.LogAllows = true })
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/orders?page=2")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	s := p.cfg.Audit.Stats()
	if s["total_allows"].(int) != 1 {
		t.Fatalf("total_allows = %v, want 1", s["total_allows"])
	}
	if s["total_blocks"].(int) != 0 {
		t.Fatalf("放行被计成拦截: %+v", s)
	}
}

// TestProxyAllowEventsOffByDefault 默认不记放行，避免日志被正常流量淹没。
func TestProxyAllowEventsOffByDefault(t *testing.T) {
	p, _ := newProxyWith(t, nil)
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/orders")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if s := p.cfg.Audit.Stats(); s["total_requests"].(int) != 0 {
		t.Fatalf("默认配置不应产生审计事件: %+v", s)
	}
}

// TestSpoofedXFFDoesNotBypassRateLimit AUDIT M1：
// 未配置可信代理时，伪造 X-Forwarded-For 不应绕过限流。
func TestSpoofedXFFDoesNotBypassRateLimit(t *testing.T) {
	p, _ := newProxyWith(t, func(c *Config) { c.RateLimit = 1 })
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	last := 0
	for i := 0; i < 4; i++ {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/ping", nil)
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.9.9.%d", i+1))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		last = resp.StatusCode
		resp.Body.Close()
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("伪造 XFF 绕过了限流，最后一次状态码 = %d", last)
	}
}

// TestTrustedProxyHonorsXFF 配了可信代理后，XFF 应被采信（不同来源各自计数）。
func TestTrustedProxyHonorsXFF(t *testing.T) {
	p, _ := newProxyWith(t, func(c *Config) {
		c.RateLimit = 1
		c.TrustedProxies = []string{"127.0.0.1/32", "::1/128"}
	})
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/ping", nil)
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.8.8.%d", i+1))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("可信代理场景下不同来源被限流: %d", resp.StatusCode)
		}
		resp.Body.Close()
	}
}

// TestRateLimiterSweepsIdleIPs AUDIT M2：空闲 IP 的 key 必须能被回收，不能无界增长。
func TestRateLimiterSweepsIdleIPs(t *testing.T) {
	l := newRateLimiter(1, 2*time.Millisecond)
	for i := 0; i < 10; i++ {
		if !l.allow(fmt.Sprintf("10.1.0.%d", i)) {
			t.Fatalf("首次请求被限流: 10.1.0.%d", i)
		}
	}
	if got := l.size(); got != 10 {
		t.Fatalf("初始条目 = %d, want 10", got)
	}
	time.Sleep(10 * time.Millisecond) // 让窗口全部过期
	l.mu.Lock()
	l.sweepLocked(time.Now())
	l.mu.Unlock()
	if got := l.size(); got != 0 {
		t.Fatalf("空闲 IP 未被回收，剩余条目 = %d", got)
	}
}

// TestProxyHealthUnderConcurrency AUDIT P0-2：
// 并发读 health/stats 与业务请求，配合 go test -race 捕获数据竞争。
func TestProxyHealthUnderConcurrency(t *testing.T) {
	p, _ := newProxyWith(t, nil)
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			resp, err := http.Get(srv.URL + "/api/ping")
			if err == nil {
				resp.Body.Close()
			}
		}()
		go func() {
			defer wg.Done()
			resp, err := http.Get(srv.URL + "/__waf/health")
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()
}
