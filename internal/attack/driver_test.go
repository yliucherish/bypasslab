package attack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yliucherish/bypasslab/internal/payloads"
	"github.com/yliucherish/bypasslab/internal/waf"
)

// newTestWAF 起一个 in-process 的上游 + WAF，返回 WAF 的 URL。
func newTestWAF(t *testing.T, upstreamStatus int) string {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(upstreamStatus)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(upstream.Close)

	u, _ := url.Parse(upstream.URL)
	audit, err := waf.NewAudit("")
	if err != nil {
		t.Fatal(err)
	}
	p, err := waf.NewProxy(waf.Config{Upstream: u, Engine: waf.NewEngine(nil), Audit: audit})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)
	return srv.URL
}

// TestBlockedRequiresRuleHeader 上游自身返回 403 时不能被算成「WAF 拦截」。
func TestBlockedRequiresRuleHeader(t *testing.T) {
	// 上游固定返回 403，且不带 X-BypassLab-Blocked
	target := newTestWAF(t, http.StatusForbidden)
	d := NewDriver(target, 0)
	res := d.send(context.Background(), payloads.Case{
		ID: "T-1", Category: "benign", Name: "上游 403", Method: "GET", Path: "/ping", IsAttack: false,
	})
	if res.Blocked {
		t.Fatalf("上游 403 被误判为 WAF 拦截（rule=%q）", res.RuleID)
	}
	if res.StatusCode != 403 {
		t.Fatalf("状态码 = %d, want 403", res.StatusCode)
	}
}

// TestCorpusRunsAgainstWAF 用完整语料跑一遍 in-process WAF，验证统计与拦截判定。
func TestCorpusRunsAgainstWAF(t *testing.T) {
	target := newTestWAF(t, http.StatusOK)
	cases := payloads.Corpus()
	if len(cases) < 100 {
		t.Fatalf("语料库仅 %d 条，W2 要求 ≥100", len(cases))
	}
	d := NewDriver(target, 0)
	results := d.Run(context.Background(), cases)
	sum := Summarize(results)

	if sum.Errors != 0 {
		t.Fatalf("执行错误 %d 条，示例: %v", sum.Errors, firstErr(results))
	}
	if sum.Total != len(cases) || sum.Attacks+sum.Benign != sum.Total {
		t.Fatalf("统计不自洽: total=%d attacks=%d benign=%d", sum.Total, sum.Attacks, sum.Benign)
	}
	// v1.1 审计修复后基线（2026-10-26 实测）：112 条语料、拦截率 100%、误报 0。
	// AUDIT P2-3：门槛从 75% 提到 95%，并强制误报为 0——旧门槛低到规则退化到 80% 都不会红。
	if sum.BlockRate() < 0.95 {
		t.Fatalf("攻击拦截率 %.1f%% < 95%%，规则可能退化", sum.BlockRate()*100)
	}
	if sum.BenignBlocked != 0 {
		t.Fatalf("误报 %d 条，误报是硬约束（必须为 0）", sum.BenignBlocked)
	}
}

// TestWriteCSV 校验 CSV 的列数与行数。
func TestWriteCSV(t *testing.T) {
	target := newTestWAF(t, http.StatusOK)
	d := NewDriver(target, 0)
	results := d.Run(context.Background(), payloads.Corpus())

	dir := t.TempDir()
	path := filepath.Join(dir, "matrix.csv")
	if err := WriteCSV(path, results); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != len(results)+1 {
		t.Fatalf("CSV 行数 = %d, want %d（含表头）", len(lines), len(results)+1)
	}
	if !strings.HasPrefix(lines[0], "id,category,name,is_attack") {
		t.Fatalf("表头异常: %s", lines[0])
	}
}

// TestReportContainsKeySections 报告应包含三项核心指标与绕过清单。
func TestReportContainsKeySections(t *testing.T) {
	target := newTestWAF(t, http.StatusOK)
	d := NewDriver(target, 0)
	results := d.Run(context.Background(), payloads.Corpus())
	md := Report(Summarize(results), results)
	for _, want := range []string{"攻击拦截率", "良性误报率", "分类拦截率", "命中规则分布"} {
		if !strings.Contains(md, want) {
			t.Fatalf("报告缺少章节: %s", want)
		}
	}
}

func firstErr(rs []Result) string {
	for _, r := range rs {
		if r.Err != "" {
			return r.Case.ID + ": " + r.Err
		}
	}
	return ""
}

// TestRateLimitedIsErrorNotBypass AUDIT P2-1：429 既不是拦截也不是放行，
// 必须记为执行错误，否则会被算成"绕过"把拦截率压低。
func TestRateLimitedIsErrorNotBypass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	d := NewDriver(srv.URL, 0)
	res := d.send(context.Background(), payloads.Case{
		ID: "T-429", Category: "sqli", Name: "限流响应", Method: "GET", Path: "/p", Query: "id=1", IsAttack: true,
	})
	if res.Blocked {
		t.Fatal("429 被误判成拦截")
	}
	if res.Err == "" {
		t.Fatal("429 未被记为执行错误，会被当成绕过计入分母")
	}
	sum := Summarize([]Result{res})
	if sum.Errors != 1 || sum.Attacks != 0 {
		t.Fatalf("统计口径错误: errors=%d attacks=%d（429 不应进攻击分母）", sum.Errors, sum.Attacks)
	}
}

// TestOversizeBlockedCountsAsBlocked AUDIT P0-1 配套：413 + 规则头应算拦截。
func TestOversizeBlockedCountsAsBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-BypassLab-Blocked", "BL-OVERSIZE")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	}))
	defer srv.Close()

	d := NewDriver(srv.URL, 0)
	res := d.send(context.Background(), payloads.Case{
		ID: "T-BIG", Category: "sqli", Name: "超大 body", Method: "POST", Path: "/p", Body: "x", IsAttack: true,
	})
	if !res.Blocked {
		t.Fatalf("413 + 规则头未判定为拦截: status=%d rule=%q", res.StatusCode, res.RuleID)
	}
}
