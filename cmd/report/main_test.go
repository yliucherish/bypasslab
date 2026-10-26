package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReadCSVMalformedRowDoesNotPanic AUDIT P2-2：
// 旧实现用 len(rec) < 11 判长度却访问 rec[11]，遇到 11 列的畸形行会 index out of range。
func TestReadCSVMalformedRowDoesNotPanic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "matrix.csv")
	content := "id,category,name,is_attack,method,path,query_or_body,status,blocked,rule_id,layer,latency_ms,error\n" +
		"T-1,sqli,union,true,GET,/p,id=1,403,true,BL-SQLI-001,regex,12,\n" +
		"bad,row,only,11,cols,here,x,200,false,r,l\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	rows, err := readCSV(p)
	if err != nil {
		t.Fatalf("readCSV 报错: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("解析行数 = %d, want 1（11 列畸形行应被跳过而不是 panic）", len(rows))
	}
	if rows[0].ID != "T-1" || rows[0].Latency != 12 {
		t.Fatalf("首行解析错误: %+v", rows[0])
	}
}

// TestReadCSVKeepsErrorColumn AUDIT L4：error 列必须读出来，供 summarize 剔除。
func TestReadCSVKeepsErrorColumn(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "matrix.csv")
	content := "id,category,name,is_attack,method,path,query_or_body,status,blocked,rule_id,layer,latency_ms,error\n" +
		"T-2,sqli,x,true,GET,/p,q,0,false,,,0,rate limited(429)\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	rows, err := readCSV(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Err == "" {
		t.Fatalf("error 列未解析: %+v", rows)
	}
}

// TestSummarizeSkipsErroredRows AUDIT L4：执行错误的样本不能计入绕过清单。
func TestSummarizeSkipsErroredRows(t *testing.T) {
	rows := []row{
		{ID: "ok", Category: "sqli", IsAttack: true, Blocked: true, RuleID: "BL-1"},
		{ID: "err", Category: "sqli", IsAttack: true, Blocked: false, Err: "timeout"},
	}
	r := summarize("R", rows)
	if r.Errors != 1 {
		t.Fatalf("Errors = %d, want 1", r.Errors)
	}
	if r.Attacks != 1 || r.Blocked != 1 {
		t.Fatalf("分母含错误样本: attacks=%d blocked=%d", r.Attacks, r.Blocked)
	}
	if len(r.Bypasses) != 0 {
		t.Fatalf("错误样本被计入绕过清单: %+v", r.Bypasses)
	}
}
