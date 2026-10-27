package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime/pprof"
	"syscall"
)

// profile writes a CPU profile to $CPUPROFILE.<pid> until SIGTERM, for
// `run.py pgo`, which makes default.pgo (profile-guided optimization) from
// it. Without CPUPROFILE it does nothing.
func profile() {
	path := os.Getenv("CPUPROFILE")
	if path == "" {
		return
	}
	f, err := os.Create(fmt.Sprintf("%s.%d", path, os.Getpid()))
	if err == nil {
		err = pprof.StartCPUProfile(f)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		pprof.StopCPUProfile()
		f.Close()
		os.Exit(0)
	}()
}
