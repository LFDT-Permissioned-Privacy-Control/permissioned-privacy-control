// Command ops-v2-wallet-migrate is an explicit offline wallet-schema and
// recovery tool. Runtime startup imports neither its credentials nor its DDL.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"

	"privacy-proxy/internal/operational/walletsql"
	w "privacy-proxy/internal/walletops"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "explicit wallet migration command required")
		return 2
	}
	command := args[0]
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	env := fs.String("dsn-env", "", "explicit environment variable containing offline DSN")
	app := fs.String("app-role", "", "pre-existing application role")
	reader := fs.String("reader-role", "", "pre-existing reader role")
	retention := fs.String("retention-role", "", "pre-existing retention role")
	origin := fs.String("origin", "", "trusted HTTPS service origin")
	environment := fs.String("environment", "", "selected environment")
	chain := fs.String("chain-id", "", "canonical decimal chain ID")
	genesis := fs.String("genesis-hash", "", "canonical genesis hash")
	deployment := fs.String("deployment-id", "", "stable deployment ID")
	generation := fs.String("generation", "", "explicit recovery generation UUID")
	coverage := fs.String("coverage-digest", "", "operator coverage attestation digest")
	ack := fs.Bool("acknowledge-complete", false, "attest complete tombstone reconciliation")
	file := fs.String("file", "", "bounded revocation batch")
	digest := fs.String("sha256", "", "expected exact batch digest")
	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprintln(stdout, "ops-v2-wallet-migrate migrate|bootstrap-empty|begin-recovery|import-revocations|finalize --dsn-env NAME [explicit roles/binding/generation/batch/coverage options]")
			return 0
		}
		fmt.Fprintln(stderr, "invalid wallet migration arguments")
		return 2
	}
	if fs.NArg() != 0 || !regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`).MatchString(*env) {
		fmt.Fprintln(stderr, "explicit DSN environment name required")
		return 2
	}
	dsn := os.Getenv(*env)
	if dsn == "" {
		fmt.Fprintln(stderr, "wallet migration DSN environment variable is empty")
		return 2
	}
	binding := w.ServiceBinding{ServiceOrigin: *origin, Environment: *environment, ChainID: *chain, GenesisHash: *genesis, DeploymentID: *deployment}
	var err error
	ctx := context.Background()
	var output any
	switch command {
	case "migrate":
		err = walletsql.Migrate(ctx, dsn, *app, *reader, *retention)
		output = map[string]any{"schemaVersion": 1, "sourceChecksum": walletsql.SchemaChecksum()}
	case "bootstrap-empty":
		err = walletsql.BootstrapEmpty(ctx, dsn, binding, *generation)
		output = map[string]any{"generation": *generation, "coverageDigest": walletsql.DigestString(walletsql.EmptyCoverage())}
	case "begin-recovery":
		err = walletsql.BeginRecovery(ctx, dsn, binding, *generation)
		output = map[string]any{"generation": *generation, "ready": false}
	case "import-revocations":
		var expected [32]byte
		expected, err = walletsql.Digest(*digest)
		if err == nil {
			var raw []byte
			raw, err = readBatch(*file)
			if err == nil {
				output, err = walletsql.ImportRevocations(ctx, dsn, binding, *generation, raw, expected)
			}
		}
	case "finalize":
		var sum [32]byte
		sum, err = walletsql.Digest(*coverage)
		if err == nil {
			err = walletsql.FinalizeRecovery(ctx, dsn, binding, w.ExpectedState{Generation: *generation, Coverage: sum}, *ack)
		}
		output = map[string]any{"generation": *generation, "coverageDigest": *coverage, "ready": true}
	default:
		fmt.Fprintln(stderr, "unknown wallet migration command")
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "wallet migration failed; check explicit inputs, credentials, schema and recovery coverage")
		return 1
	}
	return writeJSON(stdout, output)
}
func readBatch(path string) ([]byte, error) {
	if path == "" {
		return nil, w.ErrInvalid
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, w.ErrInvalid
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > walletsql.MaxImportBytes {
		return nil, w.ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(f, walletsql.MaxImportBytes+1))
	if err != nil || len(raw) > walletsql.MaxImportBytes {
		return nil, w.ErrInvalid
	}
	return raw, nil
}
