package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"regexp"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"privacy-proxy/internal/audit"
)

// runAudit dispatches `privacy-cli audit <subcommand>`. Currently only
// `verify` is implemented (RD-858 short-term tier). Future subcommands
// (e.g. `audit anchor`, `audit dump`) plug in here without competing
// for the top-level `verify` namespace, which belongs to the Foundry
// deployment-verify workflow.
func runAudit(args []string) {
	if len(args) < 1 {
		printAuditUsage()
		os.Exit(1)
	}
	switch args[0] {
	case "verify":
		runAuditVerify(args[1:])
	case "re-anchor":
		runAuditReAnchor(args[1:])
	case "help", "-h", "--help":
		printAuditUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown audit subcommand: %s\n\n", args[0])
		printAuditUsage()
		os.Exit(1)
	}
}

func printAuditUsage() {
	fmt.Print(`privacy-cli audit - Audit log integrity tools (RD-858)

Usage:
  privacy-cli audit <subcommand> [options]

Subcommands:
  verify     Walk an audit hash chain and report the first integrity
             mismatch (or confirm the chain is intact).
  re-anchor  Break-glass: record an authorized audit-chain discontinuity and
             move the verifier's baseline to the current head, after a restore.
             access_logs chain only; dry-run by default, --confirm to write.

Run 'privacy-cli audit verify --help' or 'privacy-cli audit re-anchor --help'
for subcommand-specific options.
`)
}

func runAuditVerify(args []string) {
	fs := flag.NewFlagSet("audit verify", flag.ExitOnError)
	databaseURL := fs.String("database-url", "",
		"Postgres connection string. Falls back to DATABASE_URL env var. The CLI is read-only — connect with an audit-role credential, not the app role.")
	chainFlag := fs.String("chain", "all",
		"Which chain to verify: access_logs | rbac_audit_log | all.")
	timeout := fs.Duration("timeout", 5*time.Minute,
		"Maximum walk duration before the verifier gives up. Long chains on cold storage can need more than the default.")
	fs.Parse(args)

	dsn := *databaseURL
	if dsn == "" {
		dsn = os.Getenv("DATABASE_URL")
	}
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "missing --database-url (or DATABASE_URL env)")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	if err := conn.PingContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "ping database: %v\n", err)
		os.Exit(1)
	}

	reader := &cliSeedReader{conn: conn}
	verifier := audit.NewVerifier(conn, reader)

	chains := chainsFromFlag(*chainFlag)
	exitCode := 0
	for _, chain := range chains {
		res, err := verifier.Verify(ctx, chain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%s] verify failed: %v\n", chain, err)
			exitCode = 1
			continue
		}
		printResult(res)
		if !res.OK {
			exitCode = 1
		}
	}
	os.Exit(exitCode)
}

func chainsFromFlag(s string) []audit.ChainName {
	switch s {
	case "access_logs":
		return []audit.ChainName{audit.ChainAccessLogs}
	case "rbac_audit_log":
		return []audit.ChainName{audit.ChainRBACAuditLog}
	case "", "all":
		return []audit.ChainName{audit.ChainAccessLogs, audit.ChainRBACAuditLog}
	default:
		fmt.Fprintf(os.Stderr, "unknown --chain value %q (allowed: access_logs, rbac_audit_log, all)\n", s)
		os.Exit(2)
	}
	return nil
}

func printResult(res *audit.Result) {
	status := "OK"
	if !res.OK {
		status = "FAIL"
	}
	duration := res.FinishedAt.Sub(res.StartedAt)
	fmt.Printf("[%s] %s scanned=%d null_hash_rows=%d duration=%s\n",
		res.Chain, status, res.ScannedRows, res.NullHashRows, duration)
	fmt.Printf("  seed=%s tail=%s\n", abbrevHash(res.Seed), abbrevHash(res.TailHash))
	if !res.OK {
		fmt.Printf("  first_mismatch: reason=%s id=%d at=%s\n",
			res.FirstMismatchReason, res.FirstMismatchID, res.FirstMismatchTime.Format(time.RFC3339))
		if res.FirstMismatchExpect != "" {
			fmt.Printf("    stored=%s\n", abbrevHash(res.FirstMismatchHash))
			fmt.Printf("    expect=%s\n", abbrevHash(res.FirstMismatchExpect))
		}
	}
}

func abbrevHash(h string) string {
	if len(h) <= 16 {
		return h
	}
	return h[:8] + "..." + h[len(h)-8:]
}

// cliSeedReader implements audit.SeedReader by issuing the same
// queries as db.GetLatestAccessLogHash / GetLatestRBACAuditLogHash.
// Reimplemented here (rather than imported from internal/db) so the
// CLI stays a thin binary that doesn't pull in the full migration /
// connection-pool surface.
type cliSeedReader struct {
	conn *sql.DB
}

func (r *cliSeedReader) GetLatestAccessLogHash(ctx context.Context) (string, error) {
	return r.latestHash(ctx, "access_logs", "access_logs")
}

func (r *cliSeedReader) GetLatestRBACAuditLogHash(ctx context.Context) (string, error) {
	return r.latestHash(ctx, "rbac_audit_log", "rbac_audit_log")
}

func (r *cliSeedReader) latestHash(ctx context.Context, table, chainName string) (string, error) {
	if !regexp.MustCompile(`^[a-zA-Z0-9_]+$`).MatchString(table) {
		return "", fmt.Errorf("invalid table name: %s", table)
	}
	var hash sql.NullString
	q := fmt.Sprintf(
		`SELECT entry_hash FROM %s WHERE entry_hash IS NOT NULL ORDER BY id DESC LIMIT 1`,
		table,
	)
	err := r.conn.QueryRowContext(ctx, q).Scan(&hash)
	if err == nil && hash.Valid && hash.String != "" {
		return hash.String, nil
	}
	if err != nil && err != sql.ErrNoRows {
		return "", fmt.Errorf("read latest %s hash: %w", table, err)
	}
	var anchor sql.NullString
	err = r.conn.QueryRowContext(ctx,
		`SELECT last_pruned_entry_hash FROM audit_chain_anchor WHERE chain_name = $1`,
		chainName,
	).Scan(&anchor)
	if err == nil && anchor.Valid {
		return anchor.String, nil
	}
	if err != nil && err != sql.ErrNoRows {
		return "", fmt.Errorf("read anchor for %s: %w", chainName, err)
	}
	return "", nil
}
