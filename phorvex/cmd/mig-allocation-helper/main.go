package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/phorvex/phorvex/internal/podresources"
)

func main() {
	var socket string
	var timeout time.Duration
	var idle bool
	flag.StringVar(&socket, "socket", "/var/lib/kubelet/pod-resources/kubelet.sock", "Fixed kubelet PodResources Unix socket path.")
	flag.DurationVar(&timeout, "timeout", podresources.DefaultTimeout, "List request deadline (maximum 30s).")
	flag.BoolVar(&idle, "idle", false, "Keep the trusted helper container alive; exec without this flag performs one read.")
	flag.Parse()
	if idle {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		<-ch
		return
	}
	s, err := podresources.Read(context.Background(), socket, timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	b, err := podresources.Encode(s)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(b); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
