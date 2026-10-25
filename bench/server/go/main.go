// Go's net/http for bench/server/run.py: GET /plaintext answers
// "Hello, World!", as bench/server/plaintext.mojo does. GOMAXPROCS sets the
// CPUs it uses.
//
//	go build -o bench/server/out/go_plaintext ./bench/server/go
//	GOMAXPROCS=1 bench/server/out/go_plaintext 127.0.0.1:8080
package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
)

func main() {
	addr := "127.0.0.1:8080"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	body := []byte("Hello, World!")
	mux := http.NewServeMux()
	mux.HandleFunc("/plaintext", func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h["Content-Type"] = []string{"text/plain"}
		h["Server"] = []string{"go"}
		w.Write(body)
	})
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("LISTEN %s pid=%d\n", ln.Addr(), os.Getpid())
	if err := http.Serve(ln, mux); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
