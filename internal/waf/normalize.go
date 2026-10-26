// Package waf 实现 BypassLab 的核心：请求归一化、双层规则引擎、拦截日志与反向代理。
package waf

import (
	"fmt"
	"html"
	"net"
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
	// MySQL 可执行注释：/*!50000union*/ 会被数据库执行，剥离注释时必须保留内部语句，
	// 否则攻击者把关键字藏进版本注释就能整体绕过（W3-HARD-SQLI-001）。
	reMySQLVersionComment = regexp.MustCompile(`(?s)/\*!\d*\s*(.*?)\*/`)
	// Log4Shell 的 ${lower:x} / ${upper:x} 混淆：展开成真实字符，
	// 否则 ${${lower:j}ndi:...} 这类变形能绕过 jndi 特征。
	reLower = regexp.MustCompile(`\$\{lower:([^}]*)\}`)
	reUpper = regexp.MustCompile(`\$\{upper:([^}]*)\}`)
	// ${env:FOO:-j} 取默认值，外层 ${...} 保留，
	// 使 ${${env:FOO:-j}ndi:ldap://} 还原成 ${jndi:ldap://}（W3-HARD-DESER-002）。
	reEnvDefault = regexp.MustCompile(`\$\{env:[^}:]*:-([^}]*)\}`)
	// AUDIT N2：只解 \uXXXX，不再解 \xXX。
	// \x3c 作为正文里的"转义写法讨论"出现时会被误归一成 <，进而被 XSS 规则误拦；
	// 现有语料（W3-HARD-XSS-002）用的是 \u 形态，去掉 \x 不影响检出。
	reUnicodeEscape = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	// IIS 超长 UTF-8 编码的斜杠与点号（%c0%af → /，%c0%ae → .），
	// 按字面替换，避免无效 UTF-8 字节流干扰后续解码（W3-HARD-TRAV-001）。
	reOverlongSlash = regexp.MustCompile(`(?i)%c0%af`)
	reOverlongDot   = regexp.MustCompile(`(?i)%c0%ae`)
	// 用于 IP 字面量归一：只处理 URL 的 host 部分，避免误伤正文里的数字。
	reURLHost = regexp.MustCompile(`(?i)\b(https?|gopher|dict|ftp|file)://([^/\s?#]+)`)
)

const (
	// maxURLDecodeRounds 是 URL 解码轮数上限。旧值 3 轮会让 4 层编码
	// （%25252527）在第 3 轮后残留 %27 直接放行，这里放到 8 轮并改为解到不动点。
	maxURLDecodeRounds = 8
	// maxEntityRounds 是 HTML 实体解码轮数上限。旧值只解 1 轮，
	// &amp;lt;script&amp;gt; 会停在 &lt;script&gt; 从而绕过 XSS 规则。
	maxEntityRounds = 3
)

// Normalize 把原始输入压成"攻击者最可能想表达的形态"，用于对抗编码/注释类绕过。
//
// 处理顺序（每一层都可能导致绕过，缺一层就漏检）：
//  1. 超长 UTF-8 斜杠/点号归一（%c0%af → /）
//  2. 多轮 URL 解码至不动点（应对 %25%32%35 这类多重编码），`+` 按空格处理（query 语义）
//  3. 多轮 HTML 实体解码至不动点（应对 &amp;lt;script&amp;gt;）
//  4. 展开 \uXXXX 转义
//  5. 再解一轮 HTML 实体（衔接 \u0026lt; 这类"转义解出实体"的组合）
//  6. 展开 ${env:X:-y} 默认值、${lower:} / ${upper:}
//  7. 展开 MySQL 可执行注释，再剥离普通 SQL 注释
//  8. 压缩连续空白、折叠重复斜杠
//  9. IP 字面量归一（十进制 / 十六进制 / 八进制 / 简写 / IPv6 映射 → 点分十进制）
//
// 说明：归一化不做语义还原；语义判定在 engine 的 Layer 2 完成。
func Normalize(raw string) string {
	return normalize(raw, true, false)
}

// normalize 是核心实现。
//
// plusAsSpace 区分 query（+ 代表空格）与 path/body/UA（+ 是字面量）。
// squashComments 决定块注释的处理方式：
//   - false：替换为空格，保住词边界（UNION/**/SELECT → UNION SELECT）
//   - true ：直接删除，把被拆开的关键字重新拼接（un/**/ion → union）
//
// 两种都是真实攻击手法，engine 侧同时匹配两份结果（见 normalizePair）。
func normalize(raw string, plusAsSpace bool, squashComments bool) string {
	s := raw
	s = reOverlongSlash.ReplaceAllString(s, "/")
	s = reOverlongDot.ReplaceAllString(s, ".")

	s = decodeURL(s, plusAsSpace)
	s = decodeHTMLEntities(s)
	s = decodeEscapes(s)
	// 转义可能解出新的 HTML 实体（\u0026lt; → &lt;），再解一轮衔接上。
	s = decodeHTMLEntities(s)

	s = reEnvDefault.ReplaceAllString(s, "$1")
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

	// 先露出 MySQL 可执行注释里的语句，再按需剥离普通注释。
	// 注意替换为 "$1" 而不是 " $1 "：注释常被用来切开关键字（/*!50000un*/ion），
	// 前后补空格会让 "un" 与 "ion" 断开，反而绕过检测（W4-NEW-SQLI-002）。
	s = reMySQLVersionComment.ReplaceAllString(s, "$1")
	blockRepl := " "
	if squashComments {
		blockRepl = ""
	}
	s = reSQLBlockComment.ReplaceAllString(s, blockRepl)
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

// normalizePair 返回"注释替换为空格"与"注释直接删除"两个版本。
//
// 性能优化：绝大多数请求根本不含块注释，此时两版结果必然相同，
// 所以先看原文有没有 `/*`，没有就只算一次——这一条把良性请求的检测耗时砍半。
func normalizePair(raw string, plusAsSpace bool) string {
	a := normalize(raw, plusAsSpace, false)
	if !strings.Contains(raw, "/*") {
		return a
	}
	b := normalize(raw, plusAsSpace, true)
	if a == b {
		return a
	}
	return a + "\n" + b
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

// decodeEscapes 展开 \u003c 形式转义（不解 \xXX，见 reUnicodeEscape 注释）。
func decodeEscapes(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	return reUnicodeEscape.ReplaceAllStringFunc(s, func(m string) string {
		v, err := strconv.ParseUint(m[2:], 16, 32)
		if err != nil {
			return m
		}
		return string(rune(v))
	})
}

// normalizeIPLiterals 把 URL 中的非常规 IP 写法统一成点分十进制。
// 覆盖：2130706433（十进制）、0x7f000001（十六进制）、0177.0.0.1（八进制）、
// 127.1（两段简写）、[::ffff:127.0.0.1]（IPv6 映射）。
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

		if strings.HasPrefix(host, "[") {
			// IPv6 字面量：只有 IPv4-mapped 形态才归一，纯 IPv6 保持原样（规则另有覆盖）。
			if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
				if v4 := ip.To4(); v4 != nil {
					return sub[1] + "://" + v4.String() + port
				}
			}
			return m
		}

		ip, ok := parseIPLiteral(host)
		if !ok {
			return m
		}
		return sub[1] + "://" + ip + port
	})
}

// splitHostPort 拆分 host 与 :port，兼容 [IPv6]:port 形式。
func splitHostPort(host string) (string, string) {
	if strings.HasPrefix(host, "[") {
		if i := strings.IndexByte(host, ']'); i > 0 {
			return host[:i+1], host[i+1:]
		}
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

	// 单段：0x 十六进制、前导 0 的八进制、或十进制 32 位整数
	if !strings.Contains(h, ".") {
		if strings.HasPrefix(low, "0x") {
			if v, err := strconv.ParseUint(low[2:], 16, 32); err == nil {
				return formatIPv4(uint32(v)), true
			}
			return "", false
		}
		// 前导 0 视为八进制（017700000001 = 2130706433 = 127.0.0.1）。
		// 浏览器与部分 HTTP 客户端都按这个语义解析（W4-NEW-SSRF-001）。
		if len(h) > 1 && h[0] == '0' && isDigits(h) {
			if v, err := strconv.ParseUint(h[1:], 8, 32); err == nil {
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
//
// 每个部位返回"注释替换为空格"与"注释直接删除"两个版本（换行分隔）：
// 攻击者两种手法都在用——UNION/**/SELECT 靠保空格还原，un/**/ion 靠删注释拼接还原，
// 规则命中任一版本即可。path / body / UA / headers 用不把 `+` 当空格的归一化。
func (r *Request) Field(t Target) string {
	switch t {
	case TargetPath:
		return normalizePair(r.RawPath, false) + " " + normalizePair(r.Path, false)
	case TargetQuery:
		return normalizePair(r.Query, true)
	case TargetBody:
		return normalizePair(r.Body, false)
	case TargetUA:
		return normalizePair(r.UA, false)
	case TargetHeaders:
		var b strings.Builder
		for k, v := range r.Headers {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(normalizePair(v, false))
			b.WriteString("\n")
		}
		return b.String()
	}
	return ""
}
