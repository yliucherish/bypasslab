package payloads

// HardCases2 是 W4 的"全新一批"语料：专门用来回答一个问题——
// **修完上一批缺口之后，拦截率 100% 到底说明什么？**
//
// 设计原则：这批样本不参考任何已知缺口清单，只按"同一语义还能怎么换写法"独立构造。
// 目的是让 R4 成为一次真正的泛化测试，而不是又一轮拟合。
// 如果这里仍然是 100%，那才说明规则层真的收敛了。
func HardCases2() []Case {
	return []Case{
		// ---- SQLi：分隔符与注释位置的新花样 ----
		q("W4-NEW-SQLI-001", "sqli", "换行分隔关键字", "id=1%20union%0Aselect%201", true),
		q("W4-NEW-SQLI-002", "sqli", "版本注释拆关键字", "id=1%20/*!50000un*/ion%20select%201", true),
		q("W4-NEW-SQLI-003", "sqli", "Tab 分隔关键字", "id=1%09union%09select%09user()", true),

		// ---- XSS：标签与属性的另一种写法 ----
		qp("W4-NEW-XSS-001", "xss", "属性内换行", "/comment", "c="+urlEnc("<img src=x\nonerror=alert(1)>"), true),
		qp("W4-NEW-XSS-002", "xss", "SVG 内嵌 script", "/comment", "c="+urlEnc("<svg><script>alert(1)</script></svg>"), true),
		qp("W4-NEW-XSS-003", "xss", "实体编码属性", "/comment", "c="+urlEnc("<img src=x &#111;nerror=alert(1)>"), true),

		// ---- RCE：命令分隔与参数拼接 ----
		qp("W4-NEW-RCE-001", "rce", "花括号参数展开", "/ping", "host="+urlEnc("1.1.1.1;{cat,/etc/passwd}"), true),
		qp("W4-NEW-RCE-002", "rce", "反引号内换行", "/ping", "host="+urlEnc("`cat\n/etc/passwd`"), true),

		// ---- SSRF：IP 的又一种数值写法 + 内网段 ----
		qp("W4-NEW-SSRF-001", "ssrf", "八进制单段 IP", "/fetch", "url="+urlEnc("http://017700000001:6379/"), true),
		qp("W4-NEW-SSRF-002", "ssrf", "内网 10 段", "/fetch", "url="+urlEnc("http://10.0.0.5:8080/admin"), true),

		// ---- 遍历：多余点斜杠与反斜杠 ----
		qp("W4-NEW-TRAV-001", "path-traversal", "多余点加斜杠", "/download", "f=....//....//etc/passwd", true),
		qp("W4-NEW-TRAV-002", "path-traversal", "反斜杠遍历", "/download", "f=..%5C..%5Cwindows%5Cwin.ini", true),
	}
}
