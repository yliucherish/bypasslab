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
	hard := flag.Bool("hard", false, "追加 W3 更难变形语料（用于检验泛化能力）")
	fresh := flag.Bool("new", false, "追加 W4 全新一批语料（不参考任何已知缺口清单，检验真实泛化）")
	holdout := flag.Bool("holdout", false, "运行冻结的 holdout 集（只报总数，刻意不报明细）")
	crs := flag.Bool("crs", false, "运行 OWASP CRS 回归测试转写集（第三方基准）")
	flag.Parse()

	// CRS 模式默认写独立文件，避免覆盖 R2 训练集矩阵（踩过一次：39% 数据盖掉了 100%）
	if *crs && *csvOut == "out/w2_matrix.csv" {
		*csvOut = "out/crs_matrix.csv"
		*mdOut = "out/crs_report.md"
	}

	var cases []payloads.Case
	switch {
	case *holdout:
		// 冻结集：不进任何主流程，也不打印绕过明细（看了就想修，那就退化成训练集了）
		cases = payloads.Holdout()
	case *crs:
		// 第三方基准：CRS 官方回归测试的转写集，正样本 + CRS 标记的负样本
		cases = append(payloads.CRSCases(), payloads.CRSNegativeCases()...)
	default:
		cases = payloads.Corpus()
		if *hard {
			cases = append(cases, payloads.HardCases()...)
		}
		if *fresh {
			cases = append(cases, payloads.HardCases2()...)
		}
	}
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

	// holdout 模式不落任何明细产物：CSV 与报告都会暴露"哪条漏了"，
	// 一旦看了就会想针对性修，holdout 立刻退化成训练集。
	if !*holdout {
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
	}

	// 控制台摘要
	fmt.Printf("\n耗时 %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("攻击拦截率 %.1f%%（%d/%d）｜ 良性误报率 %.1f%%（%d/%d）｜ 错误 %d\n",
		sum.BlockRate()*100, sum.AttackBlocked, sum.Attacks,
		sum.FalsePositiveRate()*100, sum.BenignBlocked, sum.Benign, sum.Errors)
	if len(sum.Bypasses) > 0 {
		if *holdout {
			// 纪律：不输出明细，避免"照着漏掉的样本改规则"，那会让 holdout 退化成训练集
			fmt.Printf("\nholdout 集按纪律不输出绕过明细（共 %d 条未拦截）。\n", len(sum.Bypasses))
			fmt.Printf("如需修复，请基于泛化思路改规则，而不是针对具体样本。\n")
		} else {
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
	}
	if len(sum.FalsePositives) > 0 {
		fmt.Printf("\n误报 %d 条：\n", len(sum.FalsePositives))
		for _, r := range sum.FalsePositives {
			fmt.Printf("  - %-14s %-24s 命中 %s\n", r.Case.ID, r.Case.Name, r.RuleID)
		}
	}
	if *holdout {
		fmt.Printf("\n（holdout 模式不生成矩阵与报告文件：明细本身就是训练资料）\n")
	} else {
		fmt.Printf("\n矩阵：%s\n报告：%s\n", *csvOut, *mdOut)
	}
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
