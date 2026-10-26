// Package attack 是 W2 的对抗驱动器：把语料库批量打向 WAF，记录每条样本的
// 放行/拦截结果与命中规则，产出可直接分析的矩阵。
//
// 它在对抗循环中的位置：
//
//	语料 → [驱动器] → 结果矩阵 → 放行清单（绕过样本）→ 补规则（W3）→ 再跑 → 拦截率曲线
package attack

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yliucherish/bypasslab/internal/payloads"
)

// Result 是一条样本的执行结果。
type Result struct {
	Case       payloads.Case
	StatusCode int
	Blocked    bool   // 是否被 WAF 拦截（403 且带拦截标记）
	RuleID     string // 命中规则
	Layer      string // regex | semantic
	LatencyMS  int64
	Err        string
}

// Driver 负责批量发送请求。
type Driver struct {
	BaseURL     string
	Client      *http.Client
	Concurrency int
}

// NewDriver 构造驱动器；Concurrency<=0 时默认 8。
func NewDriver(baseURL string, timeout time.Duration) *Driver {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Driver{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Client: &http.Client{
			Timeout: timeout,
			// 不跟随跳转：WAF 或上游的 302 本身就是结果的一部分
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		Concurrency: 8,
	}
}

// Run 并发执行全部样本，保持输入顺序返回。
func (d *Driver) Run(ctx context.Context, cases []payloads.Case) []Result {
	results := make([]Result, len(cases))
	sem := make(chan struct{}, d.Concurrency)
	done := make(chan int, len(cases))

	for i, c := range cases {
		sem <- struct{}{}
		go func(i int, c payloads.Case) {
			defer func() { <-sem; done <- i }()
			results[i] = d.send(ctx, c)
		}(i, c)
	}
	for range cases {
		<-done
	}
	return results
}

func (d *Driver) send(ctx context.Context, c payloads.Case) Result {
	res := Result{Case: c}
	target := d.BaseURL + c.Path
	if c.Query != "" {
		target += "?" + c.Query
	}
	if _, err := url.Parse(target); err != nil {
		res.Err = "URL 非法: " + err.Error()
		return res
	}

	method := c.Method
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	if c.Body != "" {
		body = strings.NewReader(c.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	if c.Body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.UA != "" {
		req.Header.Set("User-Agent", c.UA)
	}

	start := time.Now()
	resp, err := d.Client.Do(req)
	res.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer resp.Body.Close()

	res.StatusCode = resp.StatusCode
	res.RuleID = resp.Header.Get("X-BypassLab-Blocked")

	// AUDIT P2-1：429 是限流响应，既不是"拦截"也不是"放行"。
	// 旧实现把它当放行计入分母，会让拦截率凭空下降；现在显式记为执行错误，
	// Summarize 不会把它算进攻击样本分母。
	if resp.StatusCode == http.StatusTooManyRequests {
		res.Err = "rate limited(429)：WAF 启用了 -rate，本轮矩阵不可用于拦截率统计"
		return res
	}

	// 拦截判定：403（规则命中）或 413（body 超限） + 带规则 ID 头。
	// 只看状态码会把上游自身的 403 误判成拦截（W2 的关键设计，有单测守住）。
	res.Blocked = (resp.StatusCode == http.StatusForbidden ||
		resp.StatusCode == http.StatusRequestEntityTooLarge) && res.RuleID != ""
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if strings.Contains(string(raw), `"layer":"semantic"`) {
		res.Layer = "semantic"
	} else if res.Blocked {
		res.Layer = "regex"
	}
	return res
}

// Summary 是对结果矩阵的统计。
type Summary struct {
	Total          int
	Attacks        int
	Benign         int
	AttackBlocked  int
	BenignBlocked  int
	Errors         int
	ByCategory     map[string]catStat
	ByRule         map[string]int
	Bypasses       []Result // 未被拦截的攻击样本
	FalsePositives []Result
}

type catStat struct {
	Total   int
	Blocked int
}

// Rate 返回拦截率（分母为 0 时返回 0）。
func (c catStat) Rate() float64 {
	if c.Total == 0 {
		return 0
	}
	return float64(c.Blocked) / float64(c.Total)
}

// Summarize 计算结果矩阵。
func Summarize(results []Result) Summary {
	s := Summary{ByCategory: map[string]catStat{}, ByRule: map[string]int{}, Total: len(results)}
	for _, r := range results {
		if r.Err != "" {
			s.Errors++
			continue
		}
		st := s.ByCategory[r.Case.Category]
		st.Total++
		if r.Blocked {
			st.Blocked++
			s.ByRule[r.RuleID]++
		}
		s.ByCategory[r.Case.Category] = st

		if r.Case.IsAttack {
			s.Attacks++
			if r.Blocked {
				s.AttackBlocked++
			} else {
				s.Bypasses = append(s.Bypasses, r)
			}
		} else {
			s.Benign++
			if r.Blocked {
				s.BenignBlocked++
				s.FalsePositives = append(s.FalsePositives, r)
			}
		}
	}
	return s
}

// BlockRate 返回攻击样本的整体拦截率。
func (s Summary) BlockRate() float64 {
	if s.Attacks == 0 {
		return 0
	}
	return float64(s.AttackBlocked) / float64(s.Attacks)
}

// FalsePositiveRate 返回良性样本的误报率。
func (s Summary) FalsePositiveRate() float64 {
	if s.Benign == 0 {
		return 0
	}
	return float64(s.BenignBlocked) / float64(s.Benign)
}

// WriteCSV 输出明细矩阵，供 W3 逐轮对比。
func WriteCSV(path string, results []Result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{"id", "category", "name", "is_attack", "method", "path", "query_or_body",
		"status", "blocked", "rule_id", "layer", "latency_ms", "error"}); err != nil {
		return err
	}
	for _, r := range results {
		payload := r.Case.Query
		if payload == "" {
			payload = r.Case.Body
		}
		if payload == "" {
			payload = r.Case.UA
		}
		if err := w.Write([]string{
			r.Case.ID, r.Case.Category, r.Case.Name, strconv.FormatBool(r.Case.IsAttack),
			r.Case.Method, r.Case.Path, truncate(payload, 200),
			strconv.Itoa(r.StatusCode), strconv.FormatBool(r.Blocked), r.RuleID, r.Layer,
			strconv.FormatInt(r.LatencyMS, 10), r.Err,
		}); err != nil {
			return err
		}
	}
	return w.Error()
}

// Report 生成人读的报告（Markdown），用于 README 与周报。
func Report(s Summary, results []Result) string {
	var b strings.Builder
	b.WriteString("# BypassLab 对抗矩阵报告\n\n")
	fmt.Fprintf(&b, "- 样本总数：%d（攻击 %d / 良性 %d）\n", s.Total, s.Attacks, s.Benign)
	fmt.Fprintf(&b, "- 攻击拦截率：**%.1f%%**（%d/%d）\n", s.BlockRate()*100, s.AttackBlocked, s.Attacks)
	fmt.Fprintf(&b, "- 良性误报率：**%.1f%%**（%d/%d）\n", s.FalsePositiveRate()*100, s.BenignBlocked, s.Benign)
	fmt.Fprintf(&b, "- 执行错误：%d\n\n", s.Errors)

	b.WriteString("## 分类拦截率\n\n| 类别 | 拦截/总数 | 拦截率 |\n|---|---|---|\n")
	cats := make([]string, 0, len(s.ByCategory))
	for k := range s.ByCategory {
		cats = append(cats, k)
	}
	sort.Strings(cats)
	for _, c := range cats {
		st := s.ByCategory[c]
		fmt.Fprintf(&b, "| %s | %d/%d | %.0f%% |\n", c, st.Blocked, st.Total, st.Rate()*100)
	}

	b.WriteString("\n## 命中规则分布\n\n| 规则 | 次数 |\n|---|---|\n")
	type kv struct {
		k string
		v int
	}
	var rules []kv
	for k, v := range s.ByRule {
		rules = append(rules, kv{k, v})
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].v != rules[j].v {
			return rules[i].v > rules[j].v
		}
		return rules[i].k < rules[j].k
	})
	for _, r := range rules {
		fmt.Fprintf(&b, "| %s | %d |\n", r.k, r.v)
	}

	if len(s.Bypasses) > 0 {
		fmt.Fprintf(&b, "\n## 绕过清单（%d 条，W3 补规则的输入）\n\n", len(s.Bypasses))
		b.WriteString("| 样本 | 类别 | 名称 | 载荷（截断） |\n|---|---|---|---|\n")
		for _, r := range s.Bypasses {
			p := r.Case.Query
			if p == "" {
				p = r.Case.Body
			}
			if p == "" {
				p = r.Case.UA
			}
			fmt.Fprintf(&b, "| %s | %s | %s | `%s` |\n", r.Case.ID, r.Case.Category, r.Case.Name, truncate(p, 60))
		}
	}
	if len(s.FalsePositives) > 0 {
		fmt.Fprintf(&b, "\n## 误报清单（%d 条）\n\n", len(s.FalsePositives))
		b.WriteString("| 样本 | 名称 | 命中规则 |\n|---|---|---|\n")
		for _, r := range s.FalsePositives {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", r.Case.ID, r.Case.Name, r.RuleID)
		}
	}
	_ = results
	return b.String()
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
