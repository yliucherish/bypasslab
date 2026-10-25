// cmd/echo 是本地靶场：一个故意不做任何过滤的回显服务，只用于验证 WAF 行为。
// 不要把它部署到公网。
package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
)

func main() {
	listen := flag.String("listen", ":9000", "靶场监听地址")
	flag.Parse()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"echo":   true,
			"method": r.Method,
			"path":   r.URL.Path,
			"query":  r.URL.RawQuery,
			"body":   string(body),
			"note":   "BypassLab 本地靶场：无任何过滤，仅用于授权测试",
		})
	})
	log.Printf("靶场启动: listen=%s", *listen)
	log.Fatal(http.ListenAndServe(*listen, nil))
}
