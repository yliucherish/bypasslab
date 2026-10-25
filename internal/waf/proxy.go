package waf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config 是 WAF 的运行参数。
type Config struct {
	Upstream  *url.URL
	Engine    *Engine
	Audit     *Audit
	MaxBody   int64 // 单请求最多检查的 body 字节数，默认 1 MiB
	RateLimit int   // 每 IP 每分钟允许的请求数，0 表示关闭
}

// Proxy 是一个反向代理式 WAF：
//
//	client → [限流 → 归一化 → 规则引擎 → 审计日志] → upstream
//
// 拦截时直接返回 403 并带上规则 ID，方便攻击方（以及自己的扫描器）知道被哪条规则终结。
type Proxy struct {
	cfg      Config
	rp       *httputil.ReverseProxy
	rl       *rateLimiter
	started  time.Time
	mu       sync.RWMutex
	passages int
}

// NewProxy 构建代理；Upstream 必填。
func NewProxy(cfg Config) (*Proxy, error) {
	if cfg.Upstream == nil {
		return nil, fmt.Errorf("upstream 不能为空")
	}
	if cfg.Engine == nil {
		cfg.Engine = NewEngine(nil)
	}
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = 1 << 20
	}
	p := &Proxy{cfg: cfg, started: time.Now()}
	p.rp = httputil.NewSingleHostReverseProxy(cfg.Upstream)
	p.rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		w.Header().Set("X-BypassLab-Error", "upstream-unreachable")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("bypasslab: upstream unreachable\n"))
	}
	if cfg.RateLimit > 0 {
		p.rl = newRateLimiter(cfg.RateLimit, time.Minute)
	}
	return p, nil
}

// Handler 返回可直接挂到 http.Server 的处理器。
func (p *Proxy) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/__waf/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":       "ok",
			"rules":        len(p.cfg.Engine.Rules()),
			"uptime_sec":   int(time.Since(p.started).Seconds()),
			"passages":     p.passages,
			"upstream":     p.cfg.Upstream.String(),
		})
	})
	mux.HandleFunc("/__waf/stats", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(p.cfg.Audit.Stats())
	})
	mux.HandleFunc("/", p.serve)
	return mux
}

func (p *Proxy) serve(w http.ResponseWriter, r *http.Request) {
	begin := time.Now()
	clientIP := ClientIP(r)

	if p.rl != nil && !p.rl.allow(clientIP) {
		p.writeEvent(r, clientIP, Event{
			EventType: "waf_block", RuleID: "RL-429", RuleName: "IP 频率限制",
			Category: "rate-limit", Severity: SevMedium, Action: ActionBlock,
			StatusCode: http.StatusTooManyRequests, LatencyUS: time.Since(begin).Microseconds(),
		})
		http.Error(w, "bypasslab: rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	body, err := readBodyLimited(r, p.cfg.MaxBody)
	if err != nil {
		http.Error(w, "bypasslab: body read error", http.StatusBadRequest)
		return
	}
	req := buildRequest(r, body)

	if m := p.cfg.Engine.Inspect(req); m != nil {
		p.writeEvent(r, clientIP, Event{
			EventType: "waf_block", RuleID: m.RuleID, RuleName: m.Name,
			Category: m.Category, Severity: m.Severity, Action: m.Action,
			Layer: m.Layer, Target: m.Target, Excerpt: m.Excerpt, Score: m.Score,
			StatusCode: http.StatusForbidden, LatencyUS: time.Since(begin).Microseconds(),
		})
		w.Header().Set("X-BypassLab-Blocked", m.RuleID)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"blocked":  true,
			"rule_id":  m.RuleID,
			"rule":     m.Name,
			"category": m.Category,
			"severity": m.Severity,
			"layer":    m.Layer,
		})
		return
	}

	p.mu.Lock()
	p.passages++
	p.mu.Unlock()

	// body 已被读走，回填供上游使用
	r.Body = io.NopCloser(bytes.NewReader(body))
	p.rp.ServeHTTP(w, r)
}

func (p *Proxy) writeEvent(r *http.Request, ip string, ev Event) {
	ev.Timestamp = time.Now().UTC()
	ev.ClientIP = ip
	ev.Method = r.Method
	ev.Host = r.Host
	ev.Path = r.URL.Path
	ev.Query = r.URL.RawQuery
	ev.UserAgent = r.UserAgent()
	_ = p.cfg.Audit.Write(ev)
}

func readBodyLimited(r *http.Request, limit int64) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	return io.ReadAll(io.LimitReader(r.Body, limit))
}

func buildRequest(r *http.Request, body []byte) *Request {
	headers := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		headers[strings.ToLower(k)] = strings.Join(v, ", ")
	}
	return &Request{
		Method: r.Method,
		Path:   r.URL.Path,
		// RawPath 只放"未解码的路径"，不放 RequestURI——否则 query 里的攻击会被误标成 path 命中
		RawPath: r.URL.EscapedPath() + " " + r.URL.RawPath,
		Query:   r.URL.RawQuery,
		Body:    string(body),
		Headers: headers,
		UA:      r.UserAgent(),
	}
}

// ClientIP 优先取 X-Forwarded-For 首个地址（部署在负载均衡后时），否则取 RemoteAddr。
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---- 极简令牌桶限流（W1 够用；W2 再换成滑动窗口 + 共享存储）----

type rateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string][]time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, hits: map[string][]time.Time{}}
}

func (l *rateLimiter) allow(ip string) bool {
	now := time.Now()
	cut := now.Add(-l.window)
	l.mu.Lock()
	defer l.mu.Unlock()
	list := l.hits[ip]
	keep := list[:0]
	for _, t := range list {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	if len(keep) >= l.limit {
		l.hits[ip] = keep
		return false
	}
	l.hits[ip] = append(keep, now)
	return true
}
