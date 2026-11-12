// Command ops-v2-admission-migrate performs explicit offline schema/recovery
// and retention operations. The HTTP runtime imports no migrator credentials
// or DDL path.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

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
	dsnEnv := fs.String("dsn-env", "", "explicit environment variable containing the selected owner or retention DSN")
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
	recoveryTimeout := fs.Duration("recovery-timeout", 10*time.Minute, "finalize only: finite offline scan budget, at most 30m")
	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprintln(stdout, "ops-v2-admission-migrate migrate|migrate-creation-intents|bootstrap-empty|begin-recovery|finalize|cleanup --dsn-env NAME [explicit roles/binding/generation/coverage options; finalize --recovery-timeout 10m, maximum 30m]; cleanup uses retention credentials and RETENTION_COMPLIANCE_*/RETENTION_TRAVEL_RECORDS settings")
			return 0
		}
		fmt.Fprintln(stderr, "invalid admission migration arguments")
		return 2
	}
	invalidTimeout := *recoveryTimeout <= 0 || *recoveryTimeout > admissionsql.MaxRecoveryTimeout
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "recovery-timeout" && command != "finalize" {
			invalidTimeout = true
		}
	})
	if invalidTimeout {
		fmt.Fprintln(stderr, "recovery timeout must be positive, at most 30m, and used only with finalize")
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
	case "cleanup":
		settings, e := admissionsql.RetentionFromEnv(os.Getenv)
		network, bindingErr := binding.Key()
		digest, digestErr := a.ParseDigest(*coverage)
		expected := a.ExpectedState{Generation: *generation, Coverage: digest}
		if e != nil || bindingErr != nil || digestErr != nil || !expected.Valid() {
			fmt.Fprintln(stderr, "cleanup requires valid retention settings and exact network/generation/coverage binding")
			return 2
		}
		var store *admissionsql.Store
		store, err = admissionsql.OpenRetention(ctx, dsn)
		if err == nil {
			defer store.Close()
			var deleted int64
			deleted, err = store.CleanupOnce(ctx, network, expected, time.Now().UTC(), settings)
			out = map[string]any{"deletedRows": deleted}
		}
	case "migrate":
		err = admissionsql.Migrate(ctx, dsn, *app, *reader, *retention)
		if err == nil {
			out, err = admissionsql.InstalledSchema(ctx, dsn)
		}
	case "migrate-creation-intents":
		err = admissionsql.MigrateCreationIntents(ctx, dsn, *app, *reader, *retention)
		if err == nil {
			out, err = admissionsql.InstalledSchema(ctx, dsn)
		}
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
			err = admissionsql.FinalizeRecoveryWithTimeout(ctx, dsn, binding, a.ExpectedState{Generation: *generation, Coverage: digest}, *ack, *recoveryTimeout)
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
