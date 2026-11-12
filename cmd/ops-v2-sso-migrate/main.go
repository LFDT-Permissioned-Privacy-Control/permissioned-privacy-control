// Command ops-v2-sso-migrate owns offline SSO schema, readiness and recovery.
// Serving never receives its owner credentials or performs these operations.
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
	"privacy-proxy/internal/operational/ssosql"
	m "privacy-proxy/internal/ssotransaction"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "explicit SSO administration command required")
		return 2
	}
	command := args[0]
	switch command {
	case "migrate", "initialize", "status", "begin-recovery", "finalize", "reconfigure", "cleanup":
	default:
		fmt.Fprintln(stderr, "unknown SSO administration command")
		return 2
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	env := fs.String("dsn-env", "", "explicit environment variable containing the selected role DSN")
	app := fs.String("app-role", "", "pre-existing application role")
	retention := fs.String("retention-role", "", "pre-existing retention role")
	environment := fs.String("environment", "", "approved broker environment")
	deployment := fs.String("deployment-id", "", "stable broker deployment ID")
	issuer := fs.String("issuer", "", "approved OPS issuer")
	origin := fs.String("origin", "", "approved HTTPS broker origin")
	epoch := fs.String("recovery-epoch", "", "expected SSO recovery UUID")
	brokerEpoch := fs.String("broker-recovery-epoch", "", "expected broker recovery UUID")
	newEpoch := fs.String("new-recovery-epoch", "", "new SSO recovery UUID for begin-recovery")
	newBrokerEpoch := fs.String("new-broker-recovery-epoch", "", "new broker recovery UUID for begin-recovery")
	drained := fs.Bool("acknowledge-drained", false, "attest all SSO workers are stopped")
	limit := fs.Int("limit", 999, "cleanup batch size, between 3 and 1000")
	limits := m.DefaultLimits()
	fs.Int64Var(&limits.ActiveRows, "max-active-rows", limits.ActiveRows, "maximum pending and ready rows")
	fs.Int64Var(&limits.ReadyRows, "max-ready-rows", limits.ReadyRows, "maximum ready rows")
	fs.Int64Var(&limits.ActiveCipherBytes, "max-active-bytes", limits.ActiveCipherBytes, "maximum active ciphertext bytes")
	fs.Int64Var(&limits.AllRows, "max-all-rows", limits.AllRows, "maximum rows including terminal audit records")
	fs.Int64Var(&limits.MetadataBytes, "max-metadata-bytes", limits.MetadataBytes, "maximum metadata bytes")
	fs.Int64Var(&limits.AuditRetentionSeconds, "audit-retention-seconds", limits.AuditRetentionSeconds, "terminal audit retention")
	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprintln(out, "ops-v2-sso-migrate migrate|initialize|status|begin-recovery|finalize|reconfigure|cleanup --dsn-env NAME [--app-role ROLE --retention-role ROLE] [--environment ENV --deployment-id ID --issuer ISSUER --origin HTTPS_ORIGIN --recovery-epoch UUID --broker-recovery-epoch UUID] [--acknowledge-drained] [limits]")
			return 0
		}
		fmt.Fprintln(stderr, "invalid SSO administration arguments")
		return 2
	}
	if fs.NArg() != 0 || !regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`).MatchString(*env) {
		fmt.Fprintln(stderr, "explicit DSN environment name required")
		return 2
	}
	dsn := os.Getenv(*env)
	if dsn == "" {
		fmt.Fprintln(stderr, "SSO administration DSN environment variable is empty")
		return 2
	}
	roles := ssosql.Roles{App: *app, Retention: *retention}
	ctx := context.Background()
	var result any
	var err error
	if command == "migrate" {
		if !*drained || *app == "" || *retention == "" {
			fmt.Fprintln(stderr, "migration requires explicit roles and drained acknowledgment")
			return 2
		}
		err = ssosql.Migrate(ctx, dsn, roles, *drained)
		result = map[string]any{"schemaVersion": 1, "sourceChecksum": ssosql.SchemaChecksum()}
	} else {
		brokerNS, e := (b.ServiceBinding{Environment: *environment, DeploymentID: *deployment}).Namespace(*issuer)
		namespace, nerr := m.NamespaceFor(m.Digest(brokerNS), *origin)
		if e != nil || nerr != nil {
			fmt.Fprintln(stderr, "explicit approved broker binding and canonical HTTPS origin required")
			return 2
		}
		scope := m.Scope{Namespace: namespace, Epoch: *epoch, BrokerNamespace: m.Digest(brokerNS), BrokerRecoveryEpoch: *brokerEpoch}
		registration := ssosql.Registration{Namespace: namespace, Epoch: *epoch, BrokerNamespace: m.Digest(brokerNS), BrokerRecoveryEpoch: *brokerEpoch, Limits: limits, Roles: roles}
		if command != "status" && !scope.Valid() {
			fmt.Fprintln(stderr, "explicit valid SSO and broker recovery epochs required")
			return 2
		}
		if command != "status" && command != "cleanup" && !*drained {
			fmt.Fprintln(stderr, "offline SSO mutation requires drained acknowledgment")
			return 2
		}
		switch command {
		case "initialize":
			err = ssosql.Initialize(ctx, dsn, registration, *drained)
			result = map[string]any{"initialized": true}
		case "status":
			result, err = ssosql.Status(ctx, dsn, namespace)
		case "begin-recovery":
			if !m.ValidUUID(*newEpoch) || !m.ValidUUID(*newBrokerEpoch) || *newEpoch == *epoch {
				fmt.Fprintln(stderr, "explicit new SSO epoch and selected new broker epoch required")
				return 2
			}
			registration.Epoch, registration.BrokerRecoveryEpoch = *newEpoch, *newBrokerEpoch
			result, err = ssosql.BeginRecovery(ctx, dsn, scope, registration, *drained)
		case "finalize":
			err = ssosql.FinalizeRecovery(ctx, dsn, scope, *drained)
			result = map[string]any{"ready": true}
		case "reconfigure":
			err = ssosql.Reconfigure(ctx, dsn, scope, limits, *drained)
			result = map[string]any{"ready": false}
		case "cleanup":
			if *limit < 3 || *limit > 1000 {
				fmt.Fprintln(stderr, "cleanup limit must be between 3 and 1000")
				return 2
			}
			var store *ssosql.Store
			store, err = ssosql.OpenRetention(ctx, ssosql.Config{DSN: dsn, Expected: scope, Clock: time.Now})
			if err == nil {
				defer store.Close()
				result, err = store.CleanupOnce(ctx, *limit)
			}
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, "SSO administration failed; check explicit inputs, selected role, schema, readiness and recovery epochs")
		return 1
	}
	if err = json.NewEncoder(out).Encode(result); err != nil {
		fmt.Fprintln(stderr, "SSO administration output failed")
		return 1
	}
	return 0
}
