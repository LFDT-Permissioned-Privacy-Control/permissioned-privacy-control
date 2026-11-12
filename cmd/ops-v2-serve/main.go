// Command ops-v2-serve is the SQL-linked operational serving binary. The
// separate ops-v2 command remains the pure validation/authoring CLI.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"privacy-proxy/internal/operational/v2server"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stderr))
}
func run(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("ops-v2-serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", "", "pinned operational runtime JSON")
	sum := fs.String("sha256", "", "expected sha256: digest")
	err := fs.Parse(args)
	if err == flag.ErrHelp {
		fmt.Fprintln(stderr, "ops-v2-serve --config FILE --sha256 sha256:HEX (SQL-linked operational TLS server; no migrations)")
		return 0
	}
	if err != nil || fs.NArg() != 0 || *path == "" || *sum == "" {
		fmt.Fprintln(stderr, "ops-v2-serve requires --config FILE --sha256 sha256:HEX")
		return 2
	}
	config, err := v2server.ReadConfig(*path, *sum)
	if err != nil {
		fmt.Fprintln(stderr, "invalid pinned serving configuration")
		return 2
	}
	server, err := v2server.Open(ctx, config)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer server.Close()
	if err = server.Serve(ctx); err != nil {
		fmt.Fprintln(stderr, "operational listener failed")
		return 1
	}
	return 0
}
