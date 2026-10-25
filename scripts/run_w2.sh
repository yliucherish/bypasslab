#!/usr/bin/env bash
# W2 一键复现：启动靶场与 WAF → 跑对抗矩阵 → 落 CSV 与报告 → 收尾清理
# 用法：bash scripts/run_w2.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== 1/4 编译 =="
go build -o bin/echo ./cmd/echo
go build -o bin/waf ./cmd/waf
go build -o bin/attack ./cmd/attack

echo "== 2/4 启动靶场(:9000) 与 WAF(:8080) =="
./bin/echo -listen :9000 >/dev/null 2>&1 &
ECHO_PID=$!
./bin/waf -listen :8080 -upstream http://127.0.0.1:9000 -log logs/waf.jsonl >/dev/null 2>&1 &
WAF_PID=$!
trap 'kill $ECHO_PID $WAF_PID 2>/dev/null || true' EXIT
sleep 2

echo "== 3/4 健康检查 =="
curl -sf http://127.0.0.1:8080/__waf/health || { echo "WAF 未就绪"; exit 1; }
echo

echo "== 4/4 跑对抗矩阵 =="
./bin/attack -target http://127.0.0.1:8080 -csv out/w2_matrix.csv -md out/w2_report.md
