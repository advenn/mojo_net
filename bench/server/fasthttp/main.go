// fasthttp for bench/server/run.py: GET /plaintext answers "Hello, World!",
// as bench/server/plaintext.mojo does. fasthttp is the fastest widely used
// Go HTTP server; this is the form TechEmpower's fasthttp entries run.
// WORKERS=1 serves from one process (GOMAXPROCS=1); WORKERS=n > 1 uses
// fasthttp's prefork, n processes (one per CPU of the affinity mask), each
// with GOMAXPROCS=1 and its own SO_REUSEPORT listener.
//
//	go build -C bench/server/fasthttp -o ../out/fasthttp_plaintext .
//	WORKERS=4 bench/server/out/fasthttp_plaintext 127.0.0.1:8080
package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/prefork"
)

var body = []byte("Hello, World!")

func handler(ctx *fasthttp.RequestCtx) {
	if string(ctx.Path()) == "/plaintext" {
		ctx.SetContentType("text/plain")
		ctx.SetBody(body)
		return
	}
	ctx.Error("not found\n", fasthttp.StatusNotFound)
}

func main() {
	profile()
	addr := "127.0.0.1:8080"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	workers, _ := strconv.Atoi(os.Getenv("WORKERS"))
	// (TLSConfig is used only by ServeTLS, for run.py's https scenarios: no
	// session tickets, as mojo and nginx there, since wrk keeps its session
	// across reconnects)
	s := &fasthttp.Server{Handler: handler, Name: "fasthttp", TLSConfig: &tls.Config{SessionTicketsDisabled: true}}
	serve := func(ln net.Listener) error {
		fmt.Printf("LISTEN %s pid=%d\n", ln.Addr(), os.Getpid())
		if cert := os.Getenv("TLS_CERT"); cert != "" { // (HTTPS: run.py's https scenarios)
			return s.ServeTLS(ln, cert, os.Getenv("TLS_KEY"))
		}
		return s.Serve(ln)
	}
	var err error
	if workers > 1 {
		runtime.GOMAXPROCS(workers) // (the number of children)
		p := prefork.New(s)
		p.Reuseport = true
		p.ServeFunc = serve
		err = p.ListenAndServe(addr)
	} else {
		runtime.GOMAXPROCS(1)
		var ln net.Listener
		if ln, err = net.Listen("tcp4", addr); err == nil {
			err = serve(ln)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
