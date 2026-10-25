// cmd/attack 批量把语料打向 BypassLab WAF，产出结果矩阵与报告。
//
// 用法：
//
//	go run ./cmd/attack -target http://127.0.0.1:8080 -csv out/w2_matrix.csv -md out/w2_report.md
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/yliucherish/bypasslab/internal/attack"
	"github.com/yliucherish/bypasslab/internal/payloads"
)

func main() {
	target := flag.String("target", "http://127.0.0.1:8080", "WAF 入口地址")
	csvOut := flag.String("csv", "out/w2_matrix.csv", "结果矩阵 CSV 路径")
	mdOut := flag.String("md", "out/w2_report.md", "Markdown 报告路径")
	conc := flag.Int("c", 8, "并发数")
	timeout := flag.Duration("timeout", 5*time.Second, "单请求超时")
	flag.Parse()

	cases := payloads.Corpus()
	if len(cases) == 0 {
		log.Fatal("语料库为空")
	}
	fmt.Printf("语料库：%d 条（攻击 %d / 良性 %d）\n", len(cases), countAttack(cases), len(cases)-countAttack(cases))

	d := attack.NewDriver(*target, *timeout)
	d.Concurrency = *conc
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	start := time.Now()
	results := d.Run(ctx, cases)
	elapsed := time.Since(start)

	sum := attack.Summarize(results)

	for _, dir := range []string{filepath.Dir(*csvOut), filepath.Dir(*mdOut)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Fatalf("创建输出目录失败: %v", err)
		}
	}
	if err := attack.WriteCSV(*csvOut, results); err != nil {
		log.Fatalf("写 CSV 失败: %v", err)
	}
	report := attack.Report(sum, results)
	if err := os.WriteFile(*mdOut, []byte(report), 0o644); err != nil {
		log.Fatalf("写报告失败: %v", err)
	}

	// 控制台摘要
	fmt.Printf("\n耗时 %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("攻击拦截率 %.1f%%（%d/%d）｜ 良性误报率 %.1f%%（%d/%d）｜ 错误 %d\n",
		sum.BlockRate()*100, sum.AttackBlocked, sum.Attacks,
		sum.FalsePositiveRate()*100, sum.BenignBlocked, sum.Benign, sum.Errors)
	if len(sum.Bypasses) > 0 {
		fmt.Printf("\n未拦截的攻击样本 %d 条（W3 补规则输入）：\n", len(sum.Bypasses))
		limit := len(sum.Bypasses)
		if limit > 15 {
			limit = 15
		}
		for _, r := range sum.Bypasses[:limit] {
			fmt.Printf("  - %-14s %-24s %s\n", r.Case.ID, r.Case.Name, truncate(r.Case.Query+r.Case.Body+r.Case.UA, 60))
		}
		if len(sum.Bypasses) > limit {
			fmt.Printf("  ... 其余 %d 条见报告\n", len(sum.Bypasses)-limit)
		}
	}
	if len(sum.FalsePositives) > 0 {
		fmt.Printf("\n误报 %d 条：\n", len(sum.FalsePositives))
		for _, r := range sum.FalsePositives {
			fmt.Printf("  - %-14s %-24s 命中 %s\n", r.Case.ID, r.Case.Name, r.RuleID)
		}
	}
	fmt.Printf("\n矩阵：%s\n报告：%s\n", *csvOut, *mdOut)
}

func countAttack(cs []payloads.Case) int {
	n := 0
	for _, c := range cs {
		if c.IsAttack {
			n++
		}
	}
	return n
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
