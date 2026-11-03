package db

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/nodepolicy"
)

// holdScope opens a transaction that holds the organisation's configuration
// scope (the lock deployment registration and configuration writers take)
// until the returned release function is called.
func holdScope(t *testing.T, d *DB, org string) (release func()) {
	t.Helper()
	locked, done, stop := make(chan error, 1), make(chan error, 1), make(chan struct{})
	go func() {
		done <- d.WithTx(context.Background(), func(tx *Tx) error {
			err := tx.AuthorizeDeploymentRegistration(context.Background(), org)
			locked <- err
			if err != nil {
				return err
			}
			<-stop
			return nil
		})
	}()
	require.NoError(t, <-locked)
	var once bool
	release = func() {
		if !once {
			once = true
			close(stop)
			require.NoError(t, <-done)
		}
	}
	t.Cleanup(release)
	return release
}

// blockedOnLock runs fn in a transaction with a short lock_timeout and
// reports whether it failed because a row lock was held.
func blockedOnLock(t *testing.T, d *DB, fn func(*Tx) error) bool {
	t.Helper()
	err := d.WithTx(context.Background(), func(tx *Tx) error {
		if _, err := tx.tx.ExecContext(context.Background(), `SET LOCAL lock_timeout='200ms'`); err != nil {
			return err
		}
		return fn(tx)
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "55P03" {
		return true
	}
	require.NoError(t, err)
	return false
}

// G68 (RD-1410): the reconciliation scope lock never
// conflicts with the request path's foreign-key checks on the organisation.
// P0 measured every request's compliance_logs INSERT waiting 44 ms behind the
// reconciler's FOR UPDATE on the organisation row (top wait Lock:tuple). The
// lock still excludes every other scope locker and organisation deletion.
func TestReconcileScopeLockDoesNotBlockAdmission(t *testing.T) {
	d := setupTestDB(t)
	ctx := t.Context()
	user, org := cacheGenFixtures(t, d, ctx)
	pending := submissionFixture(user, org)
	require.NoError(t, d.SaveNodeSubmission(ctx, pending))
	release := holdScope(t, d, org)

	// Request path: the compliance decision record references the org. The
	// scope stays held for as long as the test runs, so finishing inside the
	// deadline means the FK check did not wait for it.
	write, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := d.CreateComplianceLog(write, &compliance.ComplianceLog{OrgID: org, UserID: user, TransferType: "native", FromAddress: "0x" + strings.Repeat("11", 20), ToAddress: "0x" + strings.Repeat("22", 20), AmountWei: "1", Currency: "USD", Decision: "allowed"})
	require.NoError(t, err, "a request's FK check waited for the reconciliation scope")

	// A non-registering outcome (pending) is recorded without the scope lock.
	status := nodepolicy.TransactionStatus{TransactionHash: pending.TransactionHash, PrincipalID: user, OrgID: org, ContextID: pending.ContextID, Execution: nodepolicy.ExecutionOutcome{Status: "pending", FactsVersion: 1, Created: []nodepolicy.CreatedContract{}}}
	require.NoError(t, d.RecordNodeOutcome(write, pending.Network, status), "a pending outcome waited for the scope lock")

	// Exclusion is preserved: another scope locker and an org deletion wait.
	require.True(t, blockedOnLock(t, d, func(tx *Tx) error { return tx.AuthorizeDeploymentRegistration(ctx, org) }), "a second scope locker must still wait")
	require.True(t, blockedOnLock(t, d, func(tx *Tx) error {
		_, err := tx.tx.ExecContext(ctx, `DELETE FROM organizations WHERE id=$1`, org)
		return err
	}), "organisation deletion must still wait for the scope")
	require.True(t, blockedOnLock(t, d, func(tx *Tx) error {
		_, err := tx.tx.ExecContext(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, org)
		return err
	}), "the projection guard's FOR UPDATE must still wait for the scope")
	release()
	require.False(t, blockedOnLock(t, d, func(tx *Tx) error { return tx.AuthorizeDeploymentRegistration(ctx, org) }))
}

// A finalized outcome that registers a created contract still takes the
// scope, so it waits for a configuration writer holding it.
func TestRegisteringOutcomeStillTakesTheScope(t *testing.T) {
	d := setupTestDB(t)
	ctx := t.Context()
	user, org := cacheGenFixtures(t, d, ctx)
	in := submissionFixture(user, org)
	require.NoError(t, d.SaveNodeSubmission(ctx, in))
	release := holdScope(t, d, org)
	block := "0x" + strings.Repeat("44", 32)
	number := uint64(12)
	outcome := nodepolicy.TransactionStatus{TransactionHash: in.TransactionHash, PrincipalID: user, OrgID: org, ContextID: in.ContextID, Execution: nodepolicy.ExecutionOutcome{Status: "included", FactsVersion: 7, BlockHash: &block, BlockNumber: &number, Created: []nodepolicy.CreatedContract{{Address: "0x" + strings.Repeat("55", 20), OrgID: org, PrincipalID: user}}}}
	outcome.Execution.Finalized, outcome.Execution.FinalizedBlockHash, outcome.Execution.FinalizedBlockNumber = true, &block, &number
	short, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	var stored NodeSubmission
	err := d.RecordNodeOutcome(short, in.Network, outcome)
	var pgErr *pgconn.PgError
	require.True(t, errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &pgErr) && pgErr.Code == "57014"), "registration must wait for the scope, got %v", err)
	release()
	require.NoError(t, d.RecordNodeOutcome(ctx, in.Network, outcome))
	stored, err = d.GetNodeSubmission(ctx, in.Network, in.TransactionHash)
	require.NoError(t, err)
	require.NotNil(t, stored.ReconciledAt)
}
