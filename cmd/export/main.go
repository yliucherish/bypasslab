// Package main 把 bypasslab 的全部攻击语料导出成一份 JSON。
//
// 为什么需要这个命令，而不是直接读 out/*.csv
// ------------------------------------------
// CSV 矩阵是给「WAF 拦截率」看的，它按列输出 id/category/payload/status/blocked，
// 但有两个硬限制让它在跨项目评测里不可用：
//
//  1. `truncate(payload, 200)`——载荷被截到 200 字符，长 payload 会失真；
//  2. 只留一个 `query_or_body` 字段，**丢掉 UA 与自定义 Header**。
//     而 Corpus 里的 JNDI 变体恰恰把载荷放在 User-Agent（W2-DESER-1..5），
//     CRS 的部分样本用自定义 header 作载体。只看 CSV 会把它们判成「空载荷」，
//     进而在下游评测里制造假漏检。
//
// 所以这里单独导出一份「原样、完整、带全部载体」的语料，供
// sentinelwatch/bench/run_crosscheck.py 这类跨项目评测消费。
//
// 用法：
//
//	go run ./cmd/export -out /tmp/bypasslab_corpus.json
//	go run ./cmd/export                       # 输出到 stdout
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/yliucherish/bypasslab/internal/payloads"
)

// exportCase 是 Case 的可序列化副本。字段名与 Python 侧约定一致（snake_case）。
type exportCase struct {
	ID       string            `json:"id"`
	Set      string            `json:"set"` // 语料来源：corpus / crs / holdout / ...
	Category string            `json:"category"`
	Name     string            `json:"name"`
	IsAttack bool              `json:"is_attack"`
	Method   string            `json:"method"`
	Path     string            `json:"path"`
	Query    string            `json:"query,omitempty"`
	Body     string            `json:"body,omitempty"`
	UA       string            `json:"ua,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
}

type bundle struct {
	Source string         `json:"source"`
	Total  int            `json:"total"`
	Sets   map[string]int `json:"sets"`
	Cases  []exportCase   `json:"cases"`
}

func main() {
	outPath := flag.String("out", "", "输出 JSON 路径（默认 stdout）")
	flag.Parse()

	sets := []struct {
		name  string
		cases []payloads.Case
	}{
		{"corpus", payloads.Corpus()},
		{"crs", payloads.CRSCases()},
		{"crs_negative", payloads.CRSNegativeCases()},
		{"hard", payloads.HardCases()},
		{"hard2", payloads.HardCases2()},
		{"holdout", payloads.Holdout()},
	}

	b := bundle{
		Source: "bypasslab/internal/payloads",
		Sets:   map[string]int{},
	}
	seen := map[string]string{}
	for _, s := range sets {
		b.Sets[s.name] = len(s.cases)
		for _, c := range s.cases {
			// 同 ID 出现在两个集里会让下游按 ID 聚合时静默合并两条样本，
			// 直接失败比"结果看起来正常但分母错了"要好。
			if prev, dup := seen[c.ID]; dup {
				fmt.Fprintf(os.Stderr, "重复 ID %s：同时出现在 %s 与 %s\n", c.ID, prev, s.name)
				os.Exit(1)
			}
			seen[c.ID] = s.name
			b.Cases = append(b.Cases, exportCase{
				ID:       c.ID,
				Set:      s.name,
				Category: c.Category,
				Name:     c.Name,
				IsAttack: c.IsAttack,
				Method:   c.Method,
				Path:     c.Path,
				Query:    c.Query,
				Body:     c.Body,
				UA:       c.UA,
				Headers:  c.Headers,
			})
		}
	}
	b.Total = len(b.Cases)

	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "序列化失败: %v\n", err)
		os.Exit(1)
	}

	if *outPath == "" {
		fmt.Println(string(data))
		return
	}
	if err := os.WriteFile(*outPath, append(data, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "写入 %s 失败: %v\n", *outPath, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "已导出 %d 条样本到 %s\n", b.Total, *outPath)
}
