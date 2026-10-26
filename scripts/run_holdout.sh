#!/usr/bin/env bash
# 跑冻结的 holdout 集。
#
# 纪律（别改这个脚本，改了这套机制就没意义了）：
#   - 只输出总数，不落 CSV / 报告；
#   - 数字下降是正常现象，规则改动后应该重跑它验证泛化，而不是据此修规则；
#   - 这个脚本不属于任何 CI 或主流程，需要时手动跑。
#
# 用法：bash scripts/run_holdout.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== 编译 =="
go build -o bin/echo ./cmd/echo
go build -o bin/waf ./cmd/waf
go build -o bin/attack ./cmd/attack

echo "== 启动靶场(:9000) 与 WAF(:8080) =="
./bin/echo -listen :9000 >/dev/null 2>&1 &
ECHO_PID=$!
./bin/waf -listen :8080 -upstream http://127.0.0.1:9000 -log logs/holdout.jsonl >/dev/null 2>&1 &
WAF_PID=$!
trap 'kill $ECHO_PID $WAF_PID 2>/dev/null || true' EXIT
sleep 2
curl -sf http://127.0.0.1:8080/__waf/health >/dev/null || { echo "WAF 未就绪"; exit 1; }

echo "== holdout（冻结集，只报总数）=="
./bin/attack -target http://127.0.0.1:8080 -holdout
