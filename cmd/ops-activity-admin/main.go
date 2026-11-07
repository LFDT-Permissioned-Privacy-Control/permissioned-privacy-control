// ops-activity-admin is an explicit operator tool for the named activity SQL
// boundary. It is not mounted by Core and never performs runtime DDL.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	a "privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/networkidentity"
	s "privacy-proxy/internal/operational/activitysql"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, os.Getenv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(ctx context.Context, args []string, out, stderr io.Writer, getenv func(string) string) error {
	if len(args) < 1 {
		return errors.New("usage: ops-activity-admin migrate|initialize|status|begin-recovery|reconfigure|finalize-recovery|prune [flags]")
	}
	command := args[0]
	switch command {
	case "migrate", "initialize", "status", "begin-recovery", "reconfigure", "finalize-recovery", "prune":
	default:
		return errors.New("unknown activity admin operation")
	}
	f := flag.NewFlagSet("ops-activity-admin "+command, flag.ContinueOnError)
	f.SetOutput(stderr)
	var network networkidentity.Binding
	var sourceID, generation, configuration string
	var roles s.RoleNames
	limits := s.DefaultStorageLimits()
	var drained, ack bool
	var floor int64
	var batch int
	var timeout time.Duration
	f.StringVar(&network.Environment, "environment", "", "exact operational environment")
	f.StringVar(&network.ChainID, "chain-id", "", "canonical decimal network chain ID")
	f.StringVar(&network.GenesisHash, "genesis-hash", "", "canonical 0x-prefixed genesis hash")
	f.StringVar(&network.DeploymentID, "deployment-id", "", "strong deployment namespace")
	f.StringVar(&sourceID, "source-id", "", "canonical registered source UUID")
	f.StringVar(&generation, "generation", "", "EXACT current generation UUID; read status after begin-recovery")
	f.StringVar(&configuration, "configuration", "", "approved configuration digest: 64 lowercase hex")
	f.StringVar(&roles.Writer, "writer-role", "", "existing disjoint writer LOGIN NOINHERIT role")
	f.StringVar(&roles.Reader, "reader-role", "", "existing disjoint reader LOGIN NOINHERIT role")
	f.StringVar(&roles.Retention, "retention-role", "", "existing disjoint retention LOGIN NOINHERIT role")
	f.Int64Var(&limits.Rows, "max-rows", limits.Rows, "logical retained SEALED row capacity")
	f.Int64Var(&limits.Bytes, "max-bytes", limits.Bytes, "logical encoded metadata capacity, excluding SQL/WAL/index overhead")
	f.Int64Var(&limits.Runs, "max-runs", limits.Runs, "ALL immutable registrations, including unsealed and old generations")
	f.BoolVar(&drained, "drained", false, "operator attests all affected workers stopped and original spools preserved")
	f.BoolVar(&ack, "acknowledge-retained-set", false, "operator attests restored retained SQL/range set is complete; not all executed RPCs")
	f.Int64Var(&floor, "retain-from-us", -1, "explicit monotone retained UTC microsecond floor")
	f.IntVar(&batch, "batch", 5000, "maximum chain-prefix rows to prune in one transaction (1..5000)")
	f.DurationVar(&timeout, "timeout", 10*time.Minute, "finalize recovery timeout (positive, maximum 30m)")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if len(f.Args()) != 0 {
		return errors.New("unexpected positional argument")
	}
	dsn := getenv("OPS_ACTIVITY_OWNER_DATABASE_URL")
	if command == "prune" {
		dsn = getenv("OPS_ACTIVITY_RETENTION_DATABASE_URL")
	}
	if dsn == "" {
		return errors.New("set the selected OPS_ACTIVITY_OWNER_DATABASE_URL or OPS_ACTIVITY_RETENTION_DATABASE_URL; credentials are never command arguments")
	}
	if command == "migrate" {
		if !drained {
			return errors.New("migrate requires --drained and the already-applied exact lean audit001..004 baseline")
		}
		if err := s.Migrate(ctx, dsn, roles.Writer, roles.Reader, roles.Retention, drained); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(struct {
			Schema string `json:"schema"`
		}{"ops_activity_v1/005"})
	}
	key, err := network.Key()
	if err != nil || !a.CanonicalUUID(sourceID) {
		return a.ErrInvalid
	}
	scope := s.Scope{NetworkKey: key, SourceID: sourceID, ExpectedGeneration: generation}
	switch command {
	case "status":
		status, err := s.Status(ctx, dsn, key, sourceID)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(status)
	case "initialize", "reconfigure":
		config, err := a.ParseDigestHex(configuration)
		if err != nil || !roles.Valid() || !limits.Valid() {
			return a.ErrInvalid
		}
		registration := s.Registration{Network: network, SourceID: sourceID, Configuration: [32]byte(config), Limits: limits, Roles: roles}
		if command == "initialize" {
			err = s.Initialize(ctx, dsn, registration, drained)
		} else {
			err = s.Reconfigure(ctx, dsn, scope, registration, drained)
		}
		if err != nil {
			return err
		}
	case "begin-recovery":
		if err := s.BeginRecovery(ctx, dsn, scope, drained); err != nil {
			return err
		}
	case "finalize-recovery":
		if !drained || !ack || timeout <= 0 || timeout > 30*time.Minute {
			return a.ErrInvalid
		}
		if err := s.FinalizeRecovery(ctx, dsn, scope, ack, timeout); err != nil {
			return err
		}
	case "prune":
		retention, err := s.OpenRetention(ctx, dsn, scope)
		if err != nil {
			return err
		}
		defer retention.Close()
		n, err := retention.Prune(ctx, floor, batch)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(struct {
			Deleted int `json:"deleted"`
		}{n})
	}
	return json.NewEncoder(out).Encode(struct{ Operation, Network, SourceID string }{command, hex.EncodeToString(key[:]), sourceID})
}
