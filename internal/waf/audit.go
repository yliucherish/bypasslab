package waf

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Event 是结构化拦截日志的一条记录。
// 设计目标：字段能被 SentinelWatch 直接采集（event_type + src_ip + 时间戳），
// 从而让两个项目形成"防御 → 检测"的数据链路。
type Event struct {
	Timestamp  time.Time `json:"ts"`
	EventType  string    `json:"event_type"` // waf_block | waf_allow
	ClientIP   string    `json:"src_ip"`
	Method     string    `json:"method"`
	Host       string    `json:"host"`
	Path       string    `json:"path"`
	Query      string    `json:"query,omitempty"`
	RuleID     string    `json:"rule_id,omitempty"`
	RuleName   string    `json:"rule_name,omitempty"`
	Category   string    `json:"category,omitempty"`
	Severity   Severity  `json:"severity,omitempty"`
	Action     Action    `json:"action,omitempty"`
	Layer      string    `json:"layer,omitempty"`
	Target     Target    `json:"target,omitempty"`
	Excerpt    string    `json:"excerpt,omitempty"`
	Score      int       `json:"score,omitempty"`
	LatencyUS  int64     `json:"latency_us"`
	StatusCode int       `json:"status_code"`
	UserAgent  string    `json:"user_agent,omitempty"`
}

// Audit 负责把事件写到 JSONL 文件，同时维护内存计数（供 /__waf/stats 使用）。
type Audit struct {
	mu     sync.Mutex
	file   *os.File
	counts map[string]int // rule_id -> 次数
	total  int
	blocks int
}

// NewAudit 打开（或创建）日志文件；path 为空时只做内存计数。
func NewAudit(path string) (*Audit, error) {
	a := &Audit{counts: map[string]int{}}
	if path == "" {
		return a, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	a.file = f
	return a, nil
}

// Write 追加一条事件并累加计数。
func (a *Audit) Write(ev Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.total++
	if ev.EventType == "waf_block" {
		a.blocks++
		if ev.RuleID != "" {
			a.counts[ev.RuleID]++
		}
	}
	if a.file == nil {
		return nil
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = a.file.Write(b)
	return err
}

// Stats 返回当前统计快照。
func (a *Audit) Stats() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	cp := make(map[string]int, len(a.counts))
	for k, v := range a.counts {
		cp[k] = v
	}
	return map[string]any{
		"total_requests": a.total,
		"total_blocks":   a.blocks,
		"by_rule":        cp,
	}
}

// Close 关闭日志文件。
func (a *Audit) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file != nil {
		return a.file.Close()
	}
	return nil
}
