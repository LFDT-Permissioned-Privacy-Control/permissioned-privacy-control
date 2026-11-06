package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"privacy-proxy/internal/policycli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(policycli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
