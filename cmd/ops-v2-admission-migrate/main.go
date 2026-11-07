// Command ops-v2-admission-migrate performs explicit offline schema/recovery
// operations. The HTTP runtime imports no migrator credentials or DDL path.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"

	a "privacy-proxy/internal/admission"
	"privacy-proxy/internal/operational/admissionsql"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "explicit admission migration command required")
		return 2
	}
	command := args[0]
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dsnEnv := fs.String("dsn-env", "", "explicit environment variable containing offline owner DSN")
	app := fs.String("app-role", "", "pre-existing application role")
	reader := fs.String("reader-role", "", "pre-existing reader role")
	retention := fs.String("retention-role", "", "pre-existing retention role")
	environment := fs.String("environment", "", "selected environment")
	chain := fs.String("chain-id", "", "canonical positive uint64 decimal chain ID")
	genesis := fs.String("genesis-hash", "", "canonical genesis hash")
	deployment := fs.String("deployment-id", "", "stable deployment ID")
	generation := fs.String("generation", "", "explicit generation UUID")
	coverage := fs.String("coverage-digest", "", "operator completeness attestation digest")
	ack := fs.Bool("acknowledge-complete", false, "attest complete restored operational facts")
	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprintln(stdout, "ops-v2-admission-migrate migrate|bootstrap-empty|begin-recovery|finalize --dsn-env NAME [explicit roles/binding/generation/coverage options]")
			return 0
		}
		fmt.Fprintln(stderr, "invalid admission migration arguments")
		return 2
	}
	if fs.NArg() != 0 || !regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`).MatchString(*dsnEnv) {
		fmt.Fprintln(stderr, "explicit DSN environment name required")
		return 2
	}
	dsn := os.Getenv(*dsnEnv)
	if dsn == "" {
		fmt.Fprintln(stderr, "admission migration DSN environment variable is empty")
		return 2
	}
	binding := a.NetworkBinding{Environment: *environment, ChainID: *chain, GenesisHash: *genesis, DeploymentID: *deployment}
	ctx := context.Background()
	var err error
	var out any
	switch command {
	case "migrate":
		err = admissionsql.Migrate(ctx, dsn, *app, *reader, *retention)
		out = map[string]any{"schemaVersion": 1, "sourceChecksum": admissionsql.SchemaChecksum()}
	case "bootstrap-empty":
		err = admissionsql.BootstrapEmpty(ctx, dsn, binding, *generation)
		out = map[string]any{"generation": *generation, "coverageDigest": admissionsql.EmptyCoverage().String(), "ready": true}
	case "begin-recovery":
		err = admissionsql.BeginRecovery(ctx, dsn, binding, *generation)
		out = map[string]any{"generation": *generation, "ready": false}
	case "finalize":
		var digest a.Digest
		digest, err = a.ParseDigest(*coverage)
		if err == nil {
			err = admissionsql.FinalizeRecovery(ctx, dsn, binding, a.ExpectedState{Generation: *generation, Coverage: digest}, *ack)
		}
		out = map[string]any{"generation": *generation, "coverageDigest": *coverage, "ready": true}
	default:
		fmt.Fprintln(stderr, "unknown admission migration command")
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "admission migration failed; check explicit inputs, credentials, schema and recovery coverage")
		return 1
	}
	if json.NewEncoder(stdout).Encode(out) != nil {
		return 1
	}
	return 0
}
