// cmd/waf 启动 BypassLab 反向代理式 WAF。
//
// 用法：
//
//	go run ./cmd/waf -listen :8080 -upstream http://127.0.0.1:9000 -log logs/waf.jsonl -rate 120
package main

import (
	"flag"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/yliucherish/bypasslab/internal/waf"
)

func main() {
	listen := flag.String("listen", ":8080", "WAF 监听地址")
	upstream := flag.String("upstream", "http://127.0.0.1:9000", "上游被保护服务地址")
	logPath := flag.String("log", "logs/waf.jsonl", "拦截日志（JSONL）路径，空字符串表示不落盘")
	rate := flag.Int("rate", 0, "每 IP 每分钟请求上限，0 表示关闭限流")
	maxBody := flag.Int64("max-body", 1<<20, "单请求最大检查 body 字节数")
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
	proxy, err := waf.NewProxy(waf.Config{
		Upstream:  u,
		Engine:    engine,
		Audit:     audit,
		MaxBody:   *maxBody,
		RateLimit: *rate,
	})
	if err != nil {
		log.Fatalf("初始化 WAF 失败: %v", err)
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           proxy.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("BypassLab WAF 启动: listen=%s upstream=%s rules=%d rate=%d/min",
		*listen, u.String(), len(engine.Rules()), *rate)
	log.Printf("健康检查: http://127.0.0.1%s/__waf/health  统计: /__waf/stats", *listen)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("服务退出: %v", err)
	}
}
