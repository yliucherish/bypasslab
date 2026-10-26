// cmd/report 把多轮对抗矩阵 CSV 渲染成一份自包含 HTML 报告（无外部依赖、无 CDN）。
//
// 用法：
//
//	go run ./cmd/report \
//	  -rounds "R1 基线:out/w2_matrix.csv,R2 补规则:out/w3_round2_matrix.csv,R3 换硬语料:out/w3_round3_matrix.csv" \
//	  -out out/w4_report.html
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"html/template"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// row 对应矩阵 CSV 的一行。
type row struct {
	ID       string
	Category string
	Name     string
	IsAttack bool
	Status   int
	Blocked  bool
	RuleID   string
	Layer    string
	Latency  int64
	Payload  string
	Err      string
}

// round 是一轮实验的统计结果。
type round struct {
	Label      string
	Total      int
	Attacks    int
	Blocked    int
	Benign     int
	FalsePos   int
	Errors     int
	ByCategory map[string][2]int // 类别 -> {拦截数, 总数}
	ByRule     map[string]int
	Bypasses   []row
	FPs        []row
}

func (r round) Rate() float64 {
	if r.Attacks == 0 {
		return 0
	}
	return float64(r.Blocked) / float64(r.Attacks)
}

func (r round) FPRate() float64 {
	if r.Benign == 0 {
		return 0
	}
	return float64(r.FalsePos) / float64(r.Benign)
}

func main() {
	rounds := flag.String("rounds", "R1:out/w2_matrix.csv,R2:out/w3_round2_matrix.csv,R3:out/w3_round3_matrix.csv",
		"轮次定义，格式 label:csv[,label:csv...]")
	out := flag.String("out", "out/w4_report.html", "输出 HTML 路径")
	flag.Parse()

	var rs []round
	for _, spec := range strings.Split(*rounds, ",") {
		parts := strings.SplitN(strings.TrimSpace(spec), ":", 2)
		if len(parts) != 2 {
			log.Fatalf("轮次格式错误: %q（应为 label:csv）", spec)
		}
		rows, err := readCSV(parts[1])
		if err != nil {
			log.Fatalf("读取 %s 失败: %v", parts[1], err)
		}
		rs = append(rs, summarize(parts[0], rows))
	}

	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		log.Fatal(err)
	}
	f, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	data := buildViewData(rs)
	if err := tpl.Execute(f, data); err != nil {
		log.Fatalf("渲染模板失败: %v", err)
	}
	fmt.Printf("报告已生成：%s（%d 轮）\n", *out, len(rs))
}

func readCSV(path string) ([]row, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	var out []row
	for i, rec := range records {
		// AUDIT P2-2：旧条件 len(rec) < 11 却访问 rec[11]，遇到 11 列畸形行会 panic。
		// 列序为 id,category,name,is_attack,method,path,query_or_body,status,blocked,
		// rule_id,layer,latency_ms,error（13 列）；error 列兼容缺失。
		if i == 0 || len(rec) < 12 {
			continue
		}
		status, _ := strconv.Atoi(rec[7])
		lat, _ := strconv.ParseInt(rec[11], 10, 64)
		errStr := ""
		if len(rec) > 12 {
			errStr = rec[12]
		}
		out = append(out, row{
			ID: rec[0], Category: rec[1], Name: rec[2],
			IsAttack: rec[3] == "true",
			Status:   status, Blocked: rec[8] == "true",
			RuleID: rec[9], Layer: rec[10], Payload: rec[6], Latency: lat,
			Err: errStr,
		})
	}
	return out, nil
}

func summarize(label string, rows []row) round {
	r := round{Label: label, ByCategory: map[string][2]int{}, ByRule: map[string]int{}}
	for _, x := range rows {
		// AUDIT L4：执行错误（超时 / 429 限流）的样本不进分母，
		// 否则会被当成"未被拦截"计入绕过清单，让报告的拦截率失真。
		if x.Err != "" {
			r.Errors++
			continue
		}
		r.Total++
		c := r.ByCategory[x.Category]
		c[1]++
		if x.Blocked {
			c[0]++
			r.ByRule[x.RuleID]++
		}
		r.ByCategory[x.Category] = c

		if x.IsAttack {
			r.Attacks++
			if x.Blocked {
				r.Blocked++
			} else {
				r.Bypasses = append(r.Bypasses, x)
			}
		} else {
			r.Benign++
			if x.Blocked {
				r.FalsePos++
				r.FPs = append(r.FPs, x)
			}
		}
	}
	return r
}

// ---------- 视图数据与 SVG 生成 ----------

type kpi struct {
	Title string
	Value string
	Hint  string
}

type barItem struct {
	Label string
	Value float64
	Text  string
}

type viewData struct {
	Generated string
	Latest    round
	Rounds    []round
	KPIs      []kpi
	LineSVG   template.HTML
	BarSVG    template.HTML
	RuleBars  []barItem
	Rounds3   bool
}

func buildViewData(rs []round) viewData {
	latest := rs[len(rs)-1]
	vd := viewData{
		Generated: timeNow(),
		Latest:    latest,
		Rounds:    rs,
		Rounds3:   len(rs) >= 2,
	}
	vd.KPIs = []kpi{
		{"攻击拦截率", fmt.Sprintf("%.1f%%", latest.Rate()*100), fmt.Sprintf("%d/%d 条攻击样本", latest.Blocked, latest.Attacks)},
		{"良性误报率", fmt.Sprintf("%.1f%%", latest.FPRate()*100), fmt.Sprintf("%d/%d 条良性样本", latest.FalsePos, latest.Benign)},
		{"样本总量", fmt.Sprintf("%d", latest.Total), "本轮语料条数"},
		{"剩余绕过", fmt.Sprintf("%d", len(latest.Bypasses)), "R4 补规则的输入"},
	}
	vd.LineSVG = lineChart(rs)
	vd.BarSVG = categoryBars(latest)

	// 规则命中 Top 8
	type kv struct {
		k string
		v int
	}
	var list []kv
	for k, v := range latest.ByRule {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].v != list[j].v {
			return list[i].v > list[j].v
		}
		return list[i].k < list[j].k
	})
	if len(list) > 8 {
		list = list[:8]
	}
	max := 1
	for _, it := range list {
		if it.v > max {
			max = it.v
		}
	}
	for _, it := range list {
		vd.RuleBars = append(vd.RuleBars, barItem{Label: it.k, Value: float64(it.v) / float64(max), Text: fmt.Sprintf("%d", it.v)})
	}
	return vd
}

// lineChart 画三轮拦截率折线（内联 SVG，无外部依赖）。
func lineChart(rs []round) template.HTML {
	const w, h = 720, 220
	const padL, padR, padT, padB = 52, 24, 26, 40
	n := len(rs)
	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %d %d" role="img" aria-label="拦截率随对抗轮次变化">`, w, h)
	// 网格与 Y 轴刻度（0/25/50/75/100%）
	for i := 0; i <= 4; i++ {
		y := padT + (h-padT-padB)*i/4
		fmt.Fprintf(&b, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#E3E8EF" stroke-width="1"/>`, padL, y, w-padR, y)
		fmt.Fprintf(&b, `<text x="%d" y="%d" text-anchor="end" font-size="11" fill="#6B7785">%d%%</text>`,
			padL-8, y+4, 100-i*25)
	}
	// 折线
	var pts []string
	for i, r := range rs {
		var x float64
		if n == 1 {
			x = float64(padL+w-padR) / 2
		} else {
			x = float64(padL) + float64(w-padL-padR)*float64(i)/float64(n-1)
		}
		y := float64(h-padB) - float64(h-padT-padB)*r.Rate()
		pts = append(pts, fmt.Sprintf("%.1f,%.1f", x, y))
	}
	fmt.Fprintf(&b, `<polyline points="%s" fill="none" stroke="#1F4E79" stroke-width="2.5"/>`, strings.Join(pts, " "))
	for i, p := range pts {
		xy := strings.Split(p, ",")
		fmt.Fprintf(&b, `<circle cx="%s" cy="%s" r="5" fill="#fff" stroke="#1F4E79" stroke-width="2.5"/>`, xy[0], xy[1])
		fmt.Fprintf(&b, `<text x="%s" y="%.1f" text-anchor="middle" font-size="12" font-weight="700" fill="#1F4E79">%.1f%%</text>`,
			xy[0], parseF(xy[1])-14, rs[i].Rate()*100)
		fmt.Fprintf(&b, `<text x="%s" y="%d" text-anchor="middle" font-size="11" fill="#6B7785">%s</text>`,
			xy[0], h-14, template.HTMLEscapeString(rs[i].Label))
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

// categoryBars 画本轮各类别拦截率（横向条形）。
func categoryBars(r round) template.HTML {
	type item struct {
		cat string
		hit int
		all int
	}
	var items []item
	for c, v := range r.ByCategory {
		if c == "benign" {
			continue
		}
		items = append(items, item{c, v[0], v[1]})
	}
	sort.Slice(items, func(i, j int) bool {
		ri := float64(items[i].hit) / float64(max1(items[i].all))
		rj := float64(items[j].hit) / float64(max1(items[j].all))
		if ri != rj {
			return ri < rj // 短板排前面
		}
		return items[i].cat < items[j].cat
	})

	const rowH, labelW, barW = 30, 150, 430
	h := rowH*len(items) + 16
	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 720 %d" role="img" aria-label="各类别拦截率">`, h)
	for i, it := range items {
		y := 10 + i*rowH
		rate := float64(it.hit) / float64(max1(it.all))
		wpx := int(rate * barW)
		color := "#C0392B"
		if rate >= 0.99 {
			color = "#1E8E5A"
		} else if rate >= 0.9 {
			color = "#D68910"
		}
		fmt.Fprintf(&b, `<text x="0" y="%d" font-size="12" fill="#333">%s</text>`, y+13, template.HTMLEscapeString(it.cat))
		fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="14" rx="3" fill="#F0F3F7"/>`, labelW, y+2, barW)
		fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="14" rx="3" fill="%s"/>`, labelW, y+2, wpx, color)
		fmt.Fprintf(&b, `<text x="%d" y="%d" font-size="12" fill="#333">%d/%d（%.0f%%）</text>`,
			labelW+barW+10, y+13, it.hit, it.all, rate*100)
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

func max1(i int) int {
	if i == 0 {
		return 1
	}
	return i
}

func parseF(s string) float64 {
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

func timeNow() string {
	return nowFunc().Format("2006-01-02 15:04")
}

// 便于测试替换
var nowFunc = func() time.Time { return time.Now() }

var tpl = template.Must(template.New("r").Funcs(template.FuncMap{
	"pct": func(f float64) string { return fmt.Sprintf("%.0f%%", f*100) },
	"snippet": func(s string) string {
		r := []rune(s)
		if len(r) > 70 {
			return string(r[:70]) + "…"
		}
		return s
	},
}).Parse(reportHTML))
