package waf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ErrBodyTooLarge 表示请求体超过 MaxBody，调用方应返回 413 而不是截断转发。
// （AUDIT P0-1：截断转发会让 MaxBody 之后的载荷完全绕过检测）
var ErrBodyTooLarge = errors.New("request body exceeds MaxBody")

// Config 是 WAF 的运行参数。
type Config struct {
	Upstream  *url.URL
	Engine    *Engine
	Audit     *Audit
	MaxBody   int64 // 单请求最多检查的 body 字节数，默认 1 MiB；超限直接 413
	RateLimit int   // 每 IP 每分钟允许的请求数，0 表示关闭

	// TrustedProxies 是可信代理的 IP/CIDR 列表。
	// 为空表示不信任任何客户端自带的 X-Forwarded-For（安全默认）；
	// 只有直接对端命中该列表时才采信 XFF，用于部署在负载均衡之后的场景。
	TrustedProxies []string

	// LogAllows 为 true 时放行请求也写 JSONL（event_type=waf_allow），
	// 与 SPEC 中 SentinelWatch 的数据契约保持一致。
	LogAllows bool
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
	trusted  []*net.IPNet
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
	trusted, err := parseTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		return nil, err
	}
	p := &Proxy{cfg: cfg, started: time.Now(), trusted: trusted}
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
			"status":          "ok",
			"rules":           len(p.cfg.Engine.Rules()),
			"uptime_sec":      int(time.Since(p.started).Seconds()),
			"passages":        p.passageCount(),
			"upstream":        p.cfg.Upstream.String(),
			"semantic_thresh": p.cfg.Engine.Threshold(),
			"trusted_proxies": len(p.trusted),
		})
	})
	mux.HandleFunc("/__waf/stats", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(p.cfg.Audit.Stats())
	})
	mux.HandleFunc("/", p.serve)
	return mux
}

// passageCount 读 passages 计数（AUDIT P0-2：读侧必须持 RLock，否则与 serve 的写构成 data race）。
func (p *Proxy) passageCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.passages
}

func (p *Proxy) serve(w http.ResponseWriter, r *http.Request) {
	begin := time.Now()
	clientIP := p.clientIP(r)

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
		// AUDIT P0-1：超限不再截断转发，直接 413，避免 MaxBody 之后的载荷绕过检测。
		if errors.Is(err, ErrBodyTooLarge) {
			p.writeEvent(r, clientIP, Event{
				EventType: "waf_block", RuleID: "BL-OVERSIZE", RuleName: "请求体超过检查上限",
				Category: "oversize", Severity: SevMedium, Action: ActionBlock,
				StatusCode: http.StatusRequestEntityTooLarge, LatencyUS: time.Since(begin).Microseconds(),
			})
			w.Header().Set("X-BypassLab-Blocked", "BL-OVERSIZE")
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"blocked":  true,
				"rule_id":  "BL-OVERSIZE",
				"rule":     "请求体超过检查上限",
				"category": "oversize",
				"max_body": p.cfg.MaxBody,
			})
			return
		}
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

	// AUDIT N1：只有需要记录放行状态码时才包装 ResponseWriter。
	// 包装器必须能被 http.ResponseController 沿 Unwrap 链解包，否则
	// SSE 流式响应会失去实时性、WebSocket 升级会因取不到 Hijacker 返回 502。
	if p.cfg.LogAllows {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		p.rp.ServeHTTP(rec, r)
		p.writeEvent(r, clientIP, Event{
			EventType: "waf_allow", Action: ActionPass,
			StatusCode: rec.status, LatencyUS: time.Since(begin).Microseconds(),
		})
		return
	}
	p.rp.ServeHTTP(w, r)
}

// statusRecorder 捕获上游最终状态码，供放行审计记录。
//
// Unwrap 让 http.ResponseController（Go 1.20+）能找回底层的 Flusher / Hijacker；
// Flush 兜住仍在使用类型断言的调用方。两者缺一都会让流式与升级类响应退化。
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

// Unwrap 暴露底层 ResponseWriter，供 ResponseController 解包。
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Flush 透传 Flush，保证 SSE / 流式响应不被包装器阻塞。
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.wroteHeader = true
	return s.ResponseWriter.Write(b)
}

func (p *Proxy) writeEvent(r *http.Request, ip string, ev Event) {
	ev.Timestamp = time.Now().UTC()
	ev.ClientIP = ip
	ev.Method = r.Method
	ev.Host = r.Host
	ev.Path = r.URL.Path
	ev.Query = r.URL.RawQuery
	ev.UserAgent = r.UserAgent()
	if err := p.cfg.Audit.Write(ev); err != nil {
		// AUDIT P2-6：写盘错误不再静默丢弃，至少留一条可观测的日志。
		log.Printf("bypasslab: 审计写入失败 rule=%s path=%s err=%v", ev.RuleID, ev.Path, err)
	}
}

// readBodyLimited 读取 body，超过 limit 时返回 ErrBodyTooLarge。
// 读 limit+1 字节即可判定超限，不把整个超大 body 读进内存。
func readBodyLimited(r *http.Request, limit int64) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > limit {
		return nil, ErrBodyTooLarge
	}
	return buf, nil
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
//
// 注意：这是"无条件信任 XFF"的旧行为，仅作为无配置时的便捷函数保留。
// Proxy 内部使用 clientIP，会按 TrustedProxies 决定是否采信 XFF（AUDIT M1）。
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	return remoteIP(r)
}

// clientIP 按 TrustedProxies 决定是否采信 X-Forwarded-For。
// 可信列表为空时只认 RemoteAddr，防止伪造 XFF 绕过限流。
func (p *Proxy) clientIP(r *http.Request) string {
	remote := remoteIP(r)
	if len(p.trusted) == 0 || !p.ipTrusted(remote) {
		return remote
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	return remote
}

func (p *Proxy) ipTrusted(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range p.trusted {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func parseTrustedProxies(spec []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, s := range spec {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, fmt.Errorf("非法可信代理地址: %s", s)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("非法可信代理网段 %s: %w", s, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// ---- 滑动窗口计数器限流（AUDIT：旧注释误称"令牌桶"）----

const (
	// cleanupThreshold 是触发惰性清理的 map 大小阈值，防止空闲 IP 的 key 无界增长。
	cleanupThreshold = 1024
	// cleanupInterval 限制清理频率，避免每个请求都遍历 map。
	cleanupInterval = time.Second
)

type rateLimiter struct {
	mu        sync.Mutex
	limit     int
	window    time.Duration
	hits      map[string][]time.Time
	lastSweep time.Time
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

	if len(l.hits) > cleanupThreshold && now.Sub(l.lastSweep) > cleanupInterval {
		l.sweepLocked(now)
	}
	return true
}

// sweepLocked 删除所有窗口已过期且无残留记录的 IP key（调用方需持锁）。
func (l *rateLimiter) sweepLocked(now time.Time) {
	cut := now.Add(-l.window)
	for ip, list := range l.hits {
		alive := 0
		for _, t := range list {
			if t.After(cut) {
				alive++
				break
			}
		}
		if alive == 0 {
			delete(l.hits, ip)
		}
	}
	l.lastSweep = now
}

// size 返回当前跟踪的 IP 数量（测试用，防止内存泄漏回归）。
func (l *rateLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.hits)
}
