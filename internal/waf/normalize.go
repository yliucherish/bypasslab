// Package waf 实现 BypassLab 的核心：请求归一化、双层规则引擎、拦截日志与反向代理。
package waf

import (
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strconv"
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
	// AUDIT P1-1：Unicode / 十六进制转义（\u003c、\x3c）此前完全没有处理，
	// 是 hard 语料里 18 条变形中的一条绕过路径。
	reUnicodeEscape = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	reHexEscape     = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	// 用于 IP 字面量归一：只处理 URL 的 host 部分，避免误伤正文里的数字。
	reURLHost = regexp.MustCompile(`(?i)\b(https?|gopher|dict|ftp|file)://([^/\s?#]+)`)
)

const (
	// maxURLDecodeRounds 是 URL 解码轮数上限。AUDIT P1-1：旧值 3 轮会让 4 层编码
	// （%25252527）在第 3 轮后残留 %27 直接放行，这里放到 8 轮并改为解到不动点。
	maxURLDecodeRounds = 8
	// maxEntityRounds 是 HTML 实体解码轮数上限。旧值只解 1 轮，
	// &amp;lt;script&amp;gt; 会停在 &lt;script&gt; 从而绕过 XSS 规则。
	maxEntityRounds = 3
)

// Normalize 把原始输入压成"攻击者最可能想表达的形态"，用于对抗编码/注释类绕过。
//
// 处理顺序（每一层都可能导致绕过，缺一层就漏检）：
//  1. 多轮 URL 解码至不动点（应对 %25%32%35 这类多重编码），`+` 按空格处理（query 语义）
//  2. 多轮 HTML 实体解码至不动点（应对 &amp;lt;script&amp;gt;）
//  3. 展开 \u003c / \x3c 转义
//  4. 展开 ${lower:x} / ${upper:x}（应对 Log4Shell 混淆）
//  5. 去除 SQL 注释（/* */ 与 --），注释是绕过 WAF 正则的经典手段
//  6. 压缩连续空白（UNION/**/SELECT → UNION SELECT）
//  7. 折叠重复斜杠（应对路径遍历 // 变形）
//  8. IP 字面量归一（十进制 / 十六进制 / 八进制 / 简写 → 点分十进制）
//
// 说明：归一化不做语义还原；语义判定在 engine 的 Layer 2 完成。
func Normalize(raw string) string {
	return normalize(raw, true)
}

// normalize 是核心实现；plusAsSpace 区分 query（+ 代表空格）与 path/body/UA（+ 是字面量）。
// AUDIT L3：旧实现对所有部位都用 QueryUnescape，把 path 里的 "a+b" 误解成 "a b"。
func normalize(raw string, plusAsSpace bool) string {
	s := decodeURL(raw, plusAsSpace)
	s = decodeHTMLEntities(s)
	s = decodeEscapes(s)
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
	s = normalizeIPLiterals(s)
	return strings.TrimSpace(s)
}

// decodeURL 反复解码直到不再变化（有上限，防止病态输入）。
func decodeURL(s string, plusAsSpace bool) string {
	decode := url.PathUnescape
	if plusAsSpace {
		decode = url.QueryUnescape
	}
	for i := 0; i < maxURLDecodeRounds; i++ {
		d, err := decode(s)
		if err != nil || d == s {
			break
		}
		s = d
	}
	return s
}

// decodeHTMLEntities 反复解码直到不再变化（应对双重、三重实体编码）。
func decodeHTMLEntities(s string) string {
	for i := 0; i < maxEntityRounds; i++ {
		d := html.UnescapeString(s)
		if d == s {
			break
		}
		s = d
	}
	return s
}

// decodeEscapes 展开 \u003c 与 \x3c 形式转义。
func decodeEscapes(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	s = reUnicodeEscape.ReplaceAllStringFunc(s, func(m string) string {
		v, err := strconv.ParseUint(m[2:], 16, 32)
		if err != nil {
			return m
		}
		return string(rune(v))
	})
	s = reHexEscape.ReplaceAllStringFunc(s, func(m string) string {
		v, err := strconv.ParseUint(m[2:], 16, 32)
		if err != nil {
			return m
		}
		return string(rune(v))
	})
	return s
}

// normalizeIPLiterals 把 URL 中的非常规 IP 写法统一成点分十进制。
// 覆盖：2130706433（十进制）、0x7f000001（十六进制）、0177.0.0.1（八进制）、127.1（两段简写）。
// 这些写法都能被浏览器/HTTP 客户端解析成 127.0.0.1，但绕得过按点分十进制写的正则。
func normalizeIPLiterals(s string) string {
	if !strings.Contains(s, "://") {
		return s
	}
	return reURLHost.ReplaceAllStringFunc(s, func(m string) string {
		sub := reURLHost.FindStringSubmatch(m)
		if len(sub) < 3 {
			return m
		}
		host, port := splitHostPort(sub[2])
		ip, ok := parseIPLiteral(host)
		if !ok {
			return m
		}
		return sub[1] + "://" + ip + port
	})
}

// splitHostPort 拆分 host 与 :port（不处理 IPv6 字面量，可直接跳过的形式原样返回）。
func splitHostPort(host string) (string, string) {
	if strings.HasPrefix(host, "[") {
		return host, ""
	}
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		return host[:i], host[i:]
	}
	return host, ""
}

// parseIPLiteral 解析各种 IP 字面量写法。已是标准点分十进制时返回 false（无需替换）。
func parseIPLiteral(h string) (string, bool) {
	if h == "" || strings.HasPrefix(h, "[") {
		return "", false
	}
	low := strings.ToLower(h)

	// 单段：十进制 32 位整数 或 0x 十六进制
	if !strings.Contains(h, ".") {
		if strings.HasPrefix(low, "0x") {
			if v, err := strconv.ParseUint(low[2:], 16, 32); err == nil {
				return formatIPv4(uint32(v)), true
			}
			return "", false
		}
		if isDigits(h) && len(h) >= 8 {
			if v, err := strconv.ParseUint(h, 10, 32); err == nil {
				out := formatIPv4(uint32(v))
				if out != h {
					return out, true
				}
			}
		}
		return "", false
	}

	parts := strings.Split(h, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return "", false
	}
	nums := make([]uint64, 0, 4)
	for _, p := range parts {
		if p == "" {
			return "", false
		}
		pl := strings.ToLower(p)
		var (
			v   uint64
			err error
		)
		switch {
		case strings.HasPrefix(pl, "0x"):
			v, err = strconv.ParseUint(pl[2:], 16, 32)
		case len(p) > 1 && p[0] == '0':
			v, err = strconv.ParseUint(p[1:], 8, 32)
		default:
			v, err = strconv.ParseUint(p, 10, 32)
		}
		if err != nil {
			return "", false
		}
		nums = append(nums, v)
	}

	var ip uint32
	switch len(nums) {
	case 4:
		if nums[0] > 255 || nums[1] > 255 || nums[2] > 255 || nums[3] > 255 {
			return "", false
		}
		ip = uint32(nums[0])<<24 | uint32(nums[1])<<16 | uint32(nums[2])<<8 | uint32(nums[3])
	case 3:
		if nums[0] > 255 || nums[1] > 255 || nums[2] > 0xFFFF {
			return "", false
		}
		ip = uint32(nums[0])<<24 | uint32(nums[1])<<16 | uint32(nums[2])
	case 2:
		if nums[0] > 255 || nums[1] > 0xFFFFFF {
			return "", false
		}
		ip = uint32(nums[0])<<24 | uint32(nums[1])
	default:
		return "", false
	}
	out := formatIPv4(ip)
	if out == h {
		return "", false
	}
	return out, true
}

func formatIPv4(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
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
	RawPath string // 未解码的原始路径（含编码绕过线索）
	Query   string
	Body    string
	Headers map[string]string // 小写 key
	UA      string
}

// Field 分部位返回归一化后的文本，供规则匹配与语义评分使用。
// path / body / UA / headers 用不把 `+` 当空格的归一化（AUDIT L3 修复）。
func (r *Request) Field(t Target) string {
	switch t {
	case TargetPath:
		return normalize(r.RawPath, false) + " " + normalize(r.Path, false)
	case TargetQuery:
		return normalize(r.Query, true)
	case TargetBody:
		return normalize(r.Body, false)
	case TargetUA:
		return normalize(r.UA, false)
	case TargetHeaders:
		var b strings.Builder
		for k, v := range r.Headers {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(normalize(v, false))
			b.WriteString("\n")
		}
		return b.String()
	}
	return ""
}
