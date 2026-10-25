#!/usr/bin/env bash
# W1 验收脚本：对本地 WAF 跑一组固定 payload，输出 状态码 + 命中规则。
# 前置：bin/echo.exe 监听 :9000，bin/waf.exe 监听 :8080。
# 用法：bash scripts/demo_w1.sh
set -u
WAF="http://127.0.0.1:8080"
pass=0; fail=0

probe() {
  local name="$1"; local expect="$2"; local url="$3"; shift 3
  local out code rid
  out=$(curl -s -o /dev/null -D - "$@" "$url" 2>/dev/null)
  code=$(printf '%s' "$out" | head -1 | awk '{print $2}')
  rid=$(printf '%s' "$out" | grep -i '^X-BypassLab-Blocked:' | tr -d '\r' | awk '{print $2}')
  if [ "$code" = "$expect" ]; then
    pass=$((pass+1)); printf '  [OK]   %-34s %s  %s\n' "$name" "$code" "${rid:--}"
  else
    fail=$((fail+1)); printf '  [FAIL] %-34s got=%s want=%s\n' "$name" "$code" "$expect"
  fi
}

echo "== W1 基线：正常请求应放行 =="
probe "普通列表接口"        200 "$WAF/api/orders?page=2&size=20"
probe "JSON 业务体"         200 "$WAF/api/order" -H 'Content-Type: application/json' -d '{"sku":"A-1","qty":2}'
probe "搜素关键词含 select" 200 "$WAF/search?q=select+a+book"

echo "== W1 基线：攻击请求应拦截 =="
probe "UNION 注入"          403 "$WAF/product?id=1%20UNION%20SELECT%20password%20FROM%20users"
probe "大小写变形"          403 "$WAF/product?id=1%20UnIoN%20sElEcT%201"
probe "注释变形"            403 "$WAF/product?id=1%20union/**/select%201"
probe "换行变形"            403 "$WAF/product?id=1%20union%0Aselect%201"
probe "双重编码恒真式"      403 "$WAF/item?id=1%2527%2520or%25201%253D1"
probe "时间盲注"            403 "$WAF/item?id=1%20and%20sleep(5)"
probe "XSS script 标签"     403 "$WAF/comment?c=%3Cscript%3Ealert(1)%3C/script%3E"
probe "命令注入"            403 "$WAF/ping?host=1.1.1.1;cat%20/etc/passwd"
probe "路径遍历"            403 "$WAF/download?f=../../../../etc/passwd"
probe "Log4Shell 特征 UA"   403 "$WAF/" -A '${jndi:ldap://127.0.0.1:1389/a}'
probe "Fastjson autoType"   403 "$WAF/api/parse" -H 'Content-Type: application/json' -d '{"@type":"java.net.Inet4Address","val":"x"}'
probe "扫描器指纹 UA"       403 "$WAF/" -A 'sqlmap/1.7.2#stable'

echo
echo "结果：通过 $pass / 失败 $fail"
curl -s "$WAF/__waf/stats"; echo
