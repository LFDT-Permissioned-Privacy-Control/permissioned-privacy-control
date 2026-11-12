// Command ops-v2-demo-init is an isolated offline demo tool. It is not shipped
// in the native production image and exposes no HTTP or identity-issuing route.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"privacy-proxy/internal/operational/v2demo"
	"strconv"
	"time"
)

func main() { os.Exit(run(os.Args[1:])) }
func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "expected init, repair-tls, configure or revision")
		return 2
	}
	command := args[0]
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	root := fs.String("root", "", "owned isolated demo root")
	wallet := fs.String("wallet-output", "", "exact demo wallet metadata directory")
	databases := fs.Bool("prepare-databases", false, "create isolated empty databases/roles before actual indexer migrations")
	transaction := fs.String("transaction", "", "actual mined transaction hash")
	block := fs.String("receipt-block", "", "actual decimal receipt block")
	contract := fs.String("contract", "", "actual demo application address")
	grant := fs.String("reader-grant", "", "revision only: on or off")
	if e := fs.Parse(args[1:]); e != nil {
		return 2
	}
	if fs.NArg() != 0 {
		return 2
	}
	allowed := map[string]map[string]bool{"init": {"root": true}, "repair-tls": {"root": true}, "configure": {"root": true, "wallet-output": true, "prepare-databases": true}, "revision": {"root": true, "wallet-output": true, "reader-grant": true}, "explorer-state": {"root": true}, "status": {"root": true}, "wait": {"root": true}, "check": {"root": true, "transaction": true, "receipt-block": true, "contract": true}}
	bad := allowed[command] == nil
	fs.Visit(func(f *flag.Flag) {
		if !allowed[command][f.Name] {
			bad = true
		}
	})
	if bad || (*databases && *wallet != "") {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var e error
	switch command {
	case "init":
		e = v2demo.Init(*root)
	case "repair-tls":
		e = v2demo.RepairTLS(*root)
	case "configure":
		if *databases {
			e = v2demo.PrepareDatabases(ctx, *root)
		} else {
			e = v2demo.Configure(ctx, *root, *wallet)
		}
	case "explorer-state":
		e = v2demo.ExplorerState(ctx, *root)
	case "status":
		status, err := v2demo.Status(ctx, *root)
		if err != nil {
			e = err
		} else {
			if json.NewEncoder(os.Stdout).Encode(status) != nil {
				return 1
			}
			return 0
		}
	case "wait":
		e = v2demo.Wait(ctx, *root)
	case "check":
		height, parse := strconv.ParseUint(*block, 10, 64)
		if parse != nil || strconv.FormatUint(height, 10) != *block {
			return 2
		}
		e = v2demo.Check(ctx, *root, *transaction, *contract, height)
	case "revision":
		if *grant != "on" && *grant != "off" {
			return 2
		}
		e = v2demo.Revision(ctx, *root, *wallet, *grant == "on")
	default:
		return 2
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, "isolated demo bootstrap failed:", e)
		return 1
	}
	fmt.Println("isolated demo", command, "complete")
	return 0
}
