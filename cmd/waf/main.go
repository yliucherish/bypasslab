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
	rulesPath := flag.String("rules", "", "规则配置文件（JSON）；为空则用内置规则；开启后自动热加载")
	dumpRules := flag.String("dump-rules", "", "把内置规则导出为 JSON 配置后退出（生成默认配置用）")
	flag.Parse()

	// 导出模式：只生成配置文件，不起服务
	if *dumpRules != "" {
		base := waf.NewEngine(nil)
		rs := waf.BuildRuleSet(base.Rules(), base.Threshold())
		if err := waf.SaveRuleSet(*dumpRules, rs); err != nil {
			log.Fatalf("导出规则失败: %v", err)
		}
		log.Printf("已导出 %d 条规则到 %s", len(rs.Rules), *dumpRules)
		return
	}

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
	if *rulesPath != "" {
		rules, th, err := waf.LoadRuleSet(*rulesPath)
		if err != nil {
			log.Fatalf("加载规则配置失败（%s）: %v", *rulesPath, err)
		}
		engine.SetRules(rules)
		engine.SetThreshold(th)
		log.Printf("已加载外部规则：%s（%d 条，阈值 %d）", *rulesPath, len(rules), th)
	} else {
		engine.SetThreshold(*threshold) // <=0 时保持默认阈值，不覆盖
	}

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

	// 规则热加载：轮询文件 mtime（不用 fsnotify，保持零第三方依赖）。
	// 校验失败只打日志、保留旧规则——绝不能让一条写错的规则把 WAF 变成透明代理。
	if *rulesPath != "" {
		watcher := &waf.RuleFileWatcher{
			Path:   *rulesPath,
			Engine: engine,
			OnError: func(err error) {
				log.Printf("规则热加载失败（保留旧规则继续服务）: %v", err)
			},
		}
		watcher.Start(ctx.Done())
		log.Printf("规则热加载已启用：%s（修改后约 2 秒生效）", *rulesPath)
	}

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
