// cmd/waf 启动 BypassLab 反向代理式 WAF。
//
// 用法：
//
//	go run ./cmd/waf -listen :8080 -upstream http://127.0.0.1:9000 -log logs/waf.jsonl -rate 120
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/yliucherish/bypasslab/internal/waf"
)

func main() {
	listen := flag.String("listen", ":8080", "WAF 监听地址")
	upstream := flag.String("upstream", "http://127.0.0.1:9000", "上游被保护服务地址")
	logPath := flag.String("log", "logs/waf.jsonl", "拦截日志（JSONL）路径，空字符串表示不落盘")
	rate := flag.Int("rate", 0, "每 IP 每分钟请求上限，0 表示关闭限流")
	maxBody := flag.Int64("max-body", 1<<20, "单请求最大检查 body 字节数，超限返回 413")
	trusted := flag.String("trusted-proxies", "", "可信代理 IP/CIDR，逗号分隔；为空表示不采信 X-Forwarded-For")
	logAllows := flag.Bool("log-allows", true, "放行请求也写 JSONL（event_type=waf_allow）")
	threshold := flag.Int("semantic-threshold", 0, "语义层拦截阈值，0 表示使用内置默认值（5）")
	flag.Parse()

	u, err := url.Parse(*upstream)
	if err != nil || u.Scheme == "" {
		log.Fatalf("上游地址非法: %s", *upstream)
	}

	audit, err := waf.NewAudit(*logPath)
	if err != nil {
		log.Fatalf("打开日志失败: %v", err)
	}
	defer audit.Close()

	engine := waf.NewEngine(nil)
	engine.SetThreshold(*threshold) // <=0 时保持默认阈值，不覆盖

	proxy, err := waf.NewProxy(waf.Config{
		Upstream:       u,
		Engine:         engine,
		Audit:          audit,
		MaxBody:        *maxBody,
		RateLimit:      *rate,
		TrustedProxies: splitCSV(*trusted),
		LogAllows:      *logAllows,
	})
	if err != nil {
		log.Fatalf("初始化 WAF 失败: %v", err)
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           proxy.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("BypassLab WAF 启动: listen=%s upstream=%s rules=%d threshold=%d rate=%d/min log_allows=%v",
		*listen, u.String(), len(engine.Rules()), engine.Threshold(), *rate, *logAllows)
	log.Printf("健康检查: http://127.0.0.1%s/__waf/health  统计: /__waf/stats", *listen)

	// AUDIT P2-5：优雅关停。旧实现里 http.ErrServerClosed 也会走 log.Fatalf，
	// 等于每次正常退出都打一条"服务退出"错误日志。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("优雅关停超时: %v", err)
		}
	}()

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("服务退出: %v", err)
	}
	log.Printf("BypassLab WAF 已退出")
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}
