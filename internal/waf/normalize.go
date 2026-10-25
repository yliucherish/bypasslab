// Package waf 实现 BypassLab 的核心：请求归一化、双层规则引擎、拦截日志与反向代理。
package waf

import (
	"html"
	"net/url"
	"regexp"
	"strings"
)

var (
	reSQLBlockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	reSQLLineComment  = regexp.MustCompile(`--[^\n]*`)
	reWhitespace      = regexp.MustCompile(`\s+`)
	reMultiSlash      = regexp.MustCompile(`/{2,}`)
	// Log4Shell 的 ${lower:x} / ${upper:x} 混淆：展开成真实字符，
	// 否则 ${${lower:j}ndi:...} 这类变形能绕过 jndi 特征。
	reLower = regexp.MustCompile(`\$\{lower:([^}]*)\}`)
	reUpper = regexp.MustCompile(`\$\{upper:([^}]*)\}`)
)

// Normalize 把原始输入压成"攻击者最可能想表达的形态"，用于对抗编码/注释类绕过。
//
// 处理顺序（每一层都可能导致绕过，缺一层就漏检）：
//  1. 多轮 URL 解码（应对 %25%32%35 这类多重编码）
//  2. HTML 实体解码（应对 &lt;script&gt;）
//  3. 展开 ${lower:x} / ${upper:x}（应对 Log4Shell 混淆）
//  4. 去除 SQL 注释（/* */ 与 --），注释是绕过 WAF 正则的经典手段
//  5. 压缩连续空白（UNION/**/SELECT → UNION SELECT）
//  6. 折叠重复斜杠（应对路径遍历 // 变形）
//
// 说明：W1 只做归一化，不做语义还原；语义判定在 engine 的 Layer 2 完成。
func Normalize(raw string) string {
	s := raw
	for i := 0; i < 3; i++ {
		decoded, err := url.QueryUnescape(s)
		if err != nil || decoded == s {
			break
		}
		s = decoded
	}
	s = html.UnescapeString(s)
	// 反复展开，直到不再变化（应对嵌套 ${lower:${lower:j}}）
	for i := 0; i < 3; i++ {
		before := s
		s = reLower.ReplaceAllStringFunc(s, func(m string) string {
			sub := reLower.FindStringSubmatch(m)
			return strings.ToLower(sub[1])
		})
		s = reUpper.ReplaceAllStringFunc(s, func(m string) string {
			sub := reUpper.FindStringSubmatch(m)
			return strings.ToUpper(sub[1])
		})
		if s == before {
			break
		}
	}
	s = reSQLBlockComment.ReplaceAllString(s, " ")
	s = reSQLLineComment.ReplaceAllString(s, " ")
	s = strings.ReplaceAll(s, "#", " ")
	s = reWhitespace.ReplaceAllString(s, " ")
	// 折叠重复斜杠前先保护 URL 协议分隔符：否则 http:// 会被折成 http:/，
	// 导致所有 SSRF 规则失效（W2 实测 SSRF 命中率 12% 的真因之一）。
	s = strings.ReplaceAll(s, "://", "\x00SCHEME\x00")
	s = reMultiSlash.ReplaceAllString(s, "/")
	s = strings.ReplaceAll(s, "\x00SCHEME\x00", "://")
	return strings.TrimSpace(s)
}

// Target 标识规则作用在请求的哪个部位。
type Target string

const (
	TargetPath    Target = "path"
	TargetQuery   Target = "query"
	TargetBody    Target = "body"
	TargetHeaders Target = "headers"
	TargetUA      Target = "ua"
)

// Request 是规则引擎看到的"待检请求"，与 net/http 解耦以便单测。
type Request struct {
	Method  string
	Path    string
	RawPath string            // 未解码的原始路径（含编码绕过线索）
	Query   string
	Body    string
	Headers map[string]string // 小写 key
	UA      string
}

// 分部位返回归一化后的文本，供规则匹配与语义评分使用。
func (r *Request) Field(t Target) string {
	switch t {
	case TargetPath:
		return Normalize(r.RawPath) + " " + Normalize(r.Path)
	case TargetQuery:
		return Normalize(r.Query)
	case TargetBody:
		return Normalize(r.Body)
	case TargetUA:
		return Normalize(r.UA)
	case TargetHeaders:
		var b strings.Builder
		for k, v := range r.Headers {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(Normalize(v))
			b.WriteString("\n")
		}
		return b.String()
	}
	return ""
}
