// Command ops-v2-identity-migrate owns offline broker schema and epoch recovery.
// No runtime command receives its credentials or performs its DDL.
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

	b "privacy-proxy/internal/identitybroker"
	"privacy-proxy/internal/operational/identitysql"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
func run(args []string, out, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "explicit identity migration command required")
		return 2
	}
	command := args[0]
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	env := fs.String("dsn-env", "", "explicit environment variable containing the selected role DSN")
	app := fs.String("app-role", "", "pre-existing application role")
	proof := fs.String("proof-role", "", "pre-existing public-proof role (schema2)")
	retention := fs.String("retention-role", "", "pre-existing retention role")
	environment := fs.String("environment", "", "selected environment")
	deployment := fs.String("deployment-id", "", "stable broker deployment ID")
	issuer := fs.String("issuer", "", "exact approved OPS issuer URI")
	epoch := fs.String("recovery-epoch", "", "externally selected expected UUID")
	drained := fs.Bool("acknowledge-drained", false, "attest ALL broker workers are stopped")
	limit := fs.Int("limit", 1000, "cleanup batch maximum1000")
	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprintln(out, "ops-v2-identity-migrate migrate-v2|migrate-v1|bootstrap-empty|begin-recovery|finalize|cleanup --dsn-env NAME --environment ENV --deployment-id ID --issuer URI --recovery-epoch UUID [roles/drain acknowledgment/limit]")
			return 0
		}
		fmt.Fprintln(stderr, "invalid identity migration arguments")
		return 2
	}
	if fs.NArg() != 0 || !regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`).MatchString(*env) {
		fmt.Fprintln(stderr, "explicit DSN environment name required")
		return 2
	}
	dsn := os.Getenv(*env)
	if dsn == "" {
		fmt.Fprintln(stderr, "identity migration DSN environment variable is empty")
		return 2
	}
	ns, err := (b.ServiceBinding{Environment: *environment, DeploymentID: *deployment}).Namespace(*issuer)
	scope := b.Scope{Namespace: ns, State: b.ExpectedState{RecoveryEpoch: *epoch}}
	if err != nil || !scope.Valid() {
		fmt.Fprintln(stderr, "explicit valid broker namespace binding and epoch required")
		return 2
	}
	ctx := context.Background()
	var result any
	switch command {
	case "migrate-v2":
		err = identitysql.MigrateV2(ctx, dsn, *app, *proof, *retention, scope, *drained)
		result = map[string]any{"schemaVersion": 2, "sourceChecksum": identitysql.SchemaChecksum(), "ready": true}
	case "migrate-v1":
		err = identitysql.Migrate(ctx, dsn, *app, *retention, scope)
		result = map[string]any{"schemaVersion": 1, "sourceChecksum": identitysql.SchemaChecksumV1()}
	case "bootstrap-empty":
		err = identitysql.BootstrapEmpty(ctx, dsn, scope)
		result = map[string]any{"ready": true}
	case "begin-recovery":
		err = identitysql.BeginRecovery(ctx, dsn, scope, *drained)
		result = map[string]any{"ready": false}
	case "finalize":
		err = identitysql.FinalizeRecovery(ctx, dsn, scope, *drained)
		result = map[string]any{"ready": true}
	case "cleanup":
		var store *identitysql.Store
		store, err = identitysql.OpenRetention(ctx, dsn, scope, time.Now)
		if err == nil {
			defer store.Close()
			result, err = store.CleanupOnce(ctx, *limit)
		}
	default:
		fmt.Fprintln(stderr, "unknown identity migration command")
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "identity migration failed; check explicit inputs, role, schema, readiness and recovery epoch")
		return 1
	}
	if err := json.NewEncoder(out).Encode(result); err != nil {
		fmt.Fprintln(stderr, "identity migration output failed")
		return 1
	}
	return 0
}
