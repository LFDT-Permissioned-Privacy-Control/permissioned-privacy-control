package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/db"
)

// runAuditReAnchor implements `privacy-cli audit re-anchor` (RD-1164 #17): the
// operator entry point for the break-glass audit-chain re-anchor. The logic
// (audit.BreakGlassReAnchor) already existed but had no way to invoke it, so a
// legitimate disaster-recovery restore could not re-establish chain integrity
// without custom code. This wires it with a dry-run default and an explicit
// --confirm gate.
//
// Scope: the access_logs chain only. That is the chain with the checkpoint /
// anchor machinery the re-anchor depends on (it lives in the separate audit
// database, RD-1147); rbac_audit_log has an integrity verifier but no checkpoint
// tooling, so it is intentionally rejected rather than half-supported.
//
// Re-anchor UPSERTs the chain anchor, so it needs the audit database's ADMIN /
// owner credential — the INSERT-only runtime role cannot perform it. This is a
// change-management-relevant, actor-attributed runtime write (NOT a migration):
// it appends a signed audit_chain_reanchor row via the existing code path and
// never hand-inserts audit rows.
func runAuditReAnchor(args []string) {
	fs := flag.NewFlagSet("audit re-anchor", flag.ExitOnError)
	databaseURL := fs.String("database-url", "",
		"Postgres DSN of the AUDIT database (where access_logs lives). Falls back to AUDIT_ADMIN_DATABASE_URL then DATABASE_URL. Must be the admin/owner role — re-anchor UPSERTs the chain anchor, which the INSERT-only runtime role cannot do.")
	chainFlag := fs.String("chain", "access_logs",
		"Chain to re-anchor. Only 'access_logs' is supported (the chain with break-glass checkpoint machinery).")
	actor := fs.String("actor", "",
		"REQUIRED. Operator identity recorded on the re-anchor (e.g. did:operator:on-call or an email). An unattributed break is rejected.")
	reason := fs.String("reason", "",
		"REQUIRED. Why the discontinuity is authorized (e.g. 'restore from backup, incident-1234'). Recorded permanently.")
	dryRun := fs.Bool("dry-run", true,
		"Preview only: print current chain stats and the anchor that would be written, changing nothing. Default true.")
	confirm := fs.Bool("confirm", false,
		"Required to actually write. Without it (or while --dry-run is true) nothing is modified.")
	timeout := fs.Duration("timeout", 2*time.Minute, "Maximum operation duration.")
	fs.Parse(args)

	if *chainFlag != "access_logs" {
		fmt.Fprintf(os.Stderr, "unsupported --chain %q: only 'access_logs' has break-glass re-anchor machinery (rbac_audit_log has an integrity verifier but no checkpoint/anchor tooling)\n", *chainFlag)
		os.Exit(2)
	}
	if *actor == "" || *reason == "" {
		fmt.Fprintln(os.Stderr, "--actor and --reason are both required (an unattributed break is rejected)")
		os.Exit(2)
	}

	dsn := *databaseURL
	if dsn == "" {
		dsn = os.Getenv("AUDIT_ADMIN_DATABASE_URL")
	}
	if dsn == "" {
		dsn = os.Getenv("DATABASE_URL")
	}
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "missing --database-url (or AUDIT_ADMIN_DATABASE_URL / DATABASE_URL env)")
		os.Exit(2)
	}

	key := os.Getenv("AUDIT_CHECKPOINT_KEY")
	if key == "" {
		fmt.Fprintln(os.Stderr, "AUDIT_CHECKPOINT_KEY is required: the re-anchor and its fresh checkpoint must be signed with the same key the integrity verifier uses")
		os.Exit(2)
	}
	// keyID "default" matches the server's checkpoint signer, so the fresh
	// checkpoint this writes verifies under the running verifier's key.
	signer := audit.NewHMACSigner("default", []byte(key))

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	database, err := db.NewWithoutMigrate(dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open audit database: %v\n", err)
		os.Exit(1)
	}
	defer database.Close()

	store := cliReAnchorStore{db: database}

	rowCount, headID, headHash, err := store.ChainStats(ctx, *chainFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read chain stats: %v\n", err)
		os.Exit(1)
	}
	if rowCount == 0 {
		fmt.Fprintf(os.Stderr, "chain %q has no rows in this database — is --database-url pointed at the audit database that holds access_logs?\n", *chainFlag)
		os.Exit(1)
	}

	fmt.Printf("chain=%s rows=%d head_id=%d head_hash=%s\n", *chainFlag, rowCount, headID, abbrevHash(headHash))
	if prev, perr := store.LatestCheckpoint(ctx, *chainFlag); perr == nil && prev != nil {
		fmt.Printf("current checkpoint: head_id=%d head_hash=%s\n", prev.HeadID, abbrevHash(prev.HeadHash))
	} else {
		fmt.Println("current checkpoint: none")
	}
	fmt.Printf("would move anchor -> head_id=%d head_hash=%s (actor=%q reason=%q)\n",
		headID, abbrevHash(headHash), *actor, *reason)

	if *dryRun || !*confirm {
		fmt.Println("\nDRY RUN — nothing written. Re-run with --dry-run=false --confirm to apply.")
		return
	}

	r, err := audit.BreakGlassReAnchor(ctx, store, signer, *chainFlag, *actor, *reason)
	if err != nil {
		fmt.Fprintf(os.Stderr, "re-anchor failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\nre-anchored: chain=%s from(head_id=%d hash=%s) -> to(head_id=%d hash=%s) key_id=%s at=%s\n",
		r.ChainName, r.FromHeadID, abbrevHash(r.FromHash), r.ToHeadID, abbrevHash(r.ToHash), r.KeyID, r.CreatedAt.Format(time.RFC3339))
	fmt.Println("Now run 'privacy-cli audit verify --chain access_logs' to confirm the chain is clean.")
}

// cliReAnchorStore mirrors the server's unexported checkpointAdapter (which the
// CLI cannot import): it bridges *db.DB to audit.ReAnchorStore by delegating to
// the same tested db operations the server uses, so the CLI does not reimplement
// any hash-chain SQL.
type cliReAnchorStore struct{ db *db.DB }

func (a cliReAnchorStore) ChainStats(ctx context.Context, chainName string) (int64, int64, string, error) {
	return a.db.GetAccessLogChainStats(ctx, chainName)
}

func (a cliReAnchorStore) WriteCheckpoint(ctx context.Context, c audit.Checkpoint) error {
	return a.db.WriteAuditChainCheckpoint(ctx, db.AuditChainCheckpointRow{
		ChainName: c.ChainName, HeadID: c.HeadID, HeadHash: c.HeadHash,
		RowCount: c.RowCount, KeyID: c.KeyID, Signature: c.Signature, CreatedAt: c.CreatedAt,
	})
}

func (a cliReAnchorStore) LatestCheckpoint(ctx context.Context, chainName string) (*audit.Checkpoint, error) {
	row, err := a.db.GetLatestAuditChainCheckpoint(ctx, chainName)
	if err != nil || row == nil {
		return nil, err
	}
	return &audit.Checkpoint{
		ChainName: row.ChainName, HeadID: row.HeadID, HeadHash: row.HeadHash,
		RowCount: row.RowCount, KeyID: row.KeyID, Signature: row.Signature, CreatedAt: row.CreatedAt,
	}, nil
}

func (a cliReAnchorStore) SetAnchor(ctx context.Context, chainName string, lastID int64, lastHash string) error {
	return a.db.UpsertAuditChainAnchor(ctx, chainName, lastID, lastHash)
}

func (a cliReAnchorStore) WriteReAnchor(ctx context.Context, r audit.ReAnchor) error {
	return a.db.WriteAuditChainReAnchor(ctx, r.ChainName, r.Reason, r.Actor,
		r.FromHeadID, r.FromHash, r.ToHeadID, r.ToHash, r.KeyID, r.Signature, r.CreatedAt)
}
