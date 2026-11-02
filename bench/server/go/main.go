// Go's net/http for bench/server/run.py: GET /plaintext answers
// "Hello, World!", as bench/server/plaintext.mojo does. One process;
// GOMAXPROCS sets the CPUs it uses. default.pgo is its PGO profile (see
// run.py's `pgo`).
//
//	go build -C bench/server/go -o ../out/go_plaintext .
//	GOMAXPROCS=1 bench/server/out/go_plaintext 127.0.0.1:8080
package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
)

func main() {
	profile()
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
	if cert := os.Getenv("TLS_CERT"); cert != "" { // (HTTPS: run.py's https scenarios)
		// (no session tickets, as mojo and nginx there: wrk keeps its
		// session across reconnects, so tickets would make the handshake
		// scenario measure resumptions)
		srv := &http.Server{Handler: mux, TLSConfig: &tls.Config{SessionTicketsDisabled: true}}
		err = srv.ServeTLS(ln, cert, os.Getenv("TLS_KEY"))
	} else {
		err = http.Serve(ln, mux)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
