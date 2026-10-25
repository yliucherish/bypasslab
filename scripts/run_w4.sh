#!/usr/bin/env bash
# W4 一键复现：跑完三轮对抗 → 生成 HTML 报告
# 用法：bash scripts/run_w4.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== 1/5 编译 =="
go build -o bin/echo ./cmd/echo
go build -o bin/waf ./cmd/waf
go build -o bin/attack ./cmd/attack

echo "== 2/5 启动靶场(:9000) 与 WAF(:8080) =="
./bin/echo -listen :9000 >/dev/null 2>&1 &
ECHO_PID=$!
./bin/waf -listen :8080 -upstream http://127.0.0.1:9000 -log logs/waf.jsonl >/dev/null 2>&1 &
WAF_PID=$!
trap 'kill $ECHO_PID $WAF_PID 2>/dev/null || true' EXIT
sleep 2
curl -sf http://127.0.0.1:8080/__waf/health >/dev/null || { echo "WAF 未就绪"; exit 1; }

echo "== 3/5 第三轮语料（含 18 条未见变形）=="
./bin/attack -target http://127.0.0.1:8080 -hard \
  -csv out/w3_round3_matrix.csv -md out/w3_round3_report.md

echo "== 4/5 渲染 HTML 报告（三轮对比）=="
go run ./cmd/report \
  -rounds "R1 基线:out/w2_matrix.csv,R2 补规则:out/w3_round2_matrix.csv,R3 换硬语料:out/w3_round3_matrix.csv" \
  -out out/w4_report.html

echo "== 5/5 完成 =="
echo "报告：out/w4_report.html"
