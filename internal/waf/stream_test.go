package waf

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// newStreamProxy 起一个用于流式测试的 WAF（可指定 MaxBody）。
// 返回的 hits 记录上游累计收到的字节数。
func newStreamProxy(t *testing.T, maxBody int64) (*Proxy, *httptest.Server, *int32) {
	t.Helper()
	var hits int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		atomic.AddInt32(&hits, int32(n))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(up.Close)
	u, _ := url.Parse(up.URL)
	audit, err := NewAudit("")
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProxy(Config{Upstream: u, Engine: NewEngine(nil), Audit: audit, MaxBody: maxBody})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)
	return p, srv, &hits
}

// TestLargeBodyStreamsFully 大文件上传不再被 413 挡掉：2 MiB 干净 body 应完整到达上游。
func TestLargeBodyStreamsFully(t *testing.T) {
	p, srv, hits := newStreamProxy(t, 1<<20)
	_ = p

	body := bytes.Repeat([]byte("A"), 2<<20) // 2 MiB
	resp, err := http.Post(srv.URL+"/upload", "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d, want 200（大文件上传不应被拒）", resp.StatusCode)
	}
	if got := *hits; got != int32(len(body)) {
		t.Fatalf("上游收到 %d 字节, want %d（流式转发不完整）", got, len(body))
	}
	if s := p.cfg.Audit.Stats(); s["total_blocks"].(int) != 0 {
		t.Fatalf("干净大 body 不应产生拦截: %+v", s)
	}
}

// TestLargeBodyHiddenPayloadBlocked 藏在 2 MiB 中间的攻击载荷必须被流式检测抓到。
func TestLargeBodyHiddenPayloadBlocked(t *testing.T) {
	p, srv, _ := newStreamProxy(t, 1<<20)

	body := bytes.Repeat([]byte("A"), 1<<20)
	body = append(body, []byte("id=1 UNION SELECT password FROM users")...)
	body = append(body, bytes.Repeat([]byte("B"), 1<<20)...)

	resp, err := http.Post(srv.URL+"/upload", "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("藏在深层的攻击载荷未被流式检测拦截")
	}
	if s := p.cfg.Audit.Stats(); s["total_blocks"].(int) != 1 {
		t.Fatalf("流式命中未写审计: %+v", s)
	}
}

// TestPayloadAcrossChunkBoundary 攻击载荷横跨检测块边界时，
// 靠 streamOverlap 重叠窗口必须仍然能抓到。
func TestPayloadAcrossChunkBoundary(t *testing.T) {
	const maxBody = 16 << 10 // 16 KiB，迫使 64 KiB body 走流式
	p, srv, _ := newStreamProxy(t, maxBody)

	// 让 payload 的起点落在ReverseProxy 读取块（32 KiB）的边界附近
	head := bytes.Repeat([]byte("A"), 32*1024-len("id=1 UNI"))
	payload := []byte("id=1 UNION SELECT password FROM users")
	body := append(append([]byte{}, head...), payload...)
	body = append(body, bytes.Repeat([]byte("B"), 32*1024)...)

	resp, err := http.Post(srv.URL+"/upload", "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("跨块边界的 payload 未被拦截（重叠窗口失效）")
	}
	if m := p.cfg.Audit.Stats(); m["total_blocks"].(int) != 1 {
		t.Fatalf("跨块拦截未写审计: %+v", m)
	}
}

// TestChunkedBodyGoesStreaming 分块传输（Content-Length 未知）也应走流式检测。
func TestChunkedBodyGoesStreaming(t *testing.T) {
	_, srv, _ := newStreamProxy(t, 1<<20)

	// 用底层构造 chunked 请求（不带 Content-Length）
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/upload", io.NopCloser(
		strings.NewReader(strings.Repeat("id=1 UNION SELECT password FROM users", 1000))))
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("chunked body 里的攻击载荷未被拦截")
	}
}
