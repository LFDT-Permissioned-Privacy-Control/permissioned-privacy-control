package server

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/db"
)

// holdTransaction opens a transaction that has a transaction id (as any write
// does) on the database at url and keeps it open until the test ends.
func holdTransaction(t *testing.T, url string) {
	t.Helper()
	conn, err := sql.Open("pgx", url)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	tx, err := conn.BeginTx(context.Background(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback() })
	_, err = tx.Exec(`SELECT pg_current_xact_id()`)
	require.NoError(t, err)
}

// admitElsewhere records a binding the way another OPS instance would: in
// the tracking database, but not through this instance's writer.
func (f *reconcileFixture) admitElsewhere(t *testing.T, limits db.TrackLimits) (trackedTx, db.AdmitOutcome) {
	t.Helper()
	hash := make([]byte, 32)
	_, _ = rand.Read(hash)
	tx := trackedTx{hash: hash, hex: "0x" + hex.EncodeToString(hash), principal: uuid.New(), org: uuid.New(), context: uuid.New()}
	a := db.TrackAdmission{Hash: hash, PrincipalID: tx.principal, OrgID: tx.org, Signer: hash[:20], Nonce: 1, ContextID: tx.context, EnvelopeHash: hash, ExpiresAt: time.Now().Add(time.Minute), MinVersion: 7, Raw: hash}
	results, err := f.tracking.runtime.AdmitBatch(context.Background(), f.writer.incarnation(), limits, []db.TrackAdmission{a})
	require.NoError(t, err)
	return tx, results[0].Outcome
}

// A write transaction left open in the main database on the same server no
// longer holds up outcome discovery (independent review, finding 3): another
// instance's binding is discovered, becomes provisional and releases its
// pending quota, so the pending-work limit does not fill.
func TestDiscoveryIsNotHeldByAnotherDatabasesTransaction(t *testing.T) {
	f := newReconcileFixture(t, nil)
	require.NoError(t, f.tick(t)) // the term's first scan
	holdTransaction(t, f.tracking.mainURL)
	limit := db.TrackLimits{Global: 1}
	first, outcome := f.admitElsewhere(t, limit)
	require.Equal(t, db.AdmitInserted, outcome)
	f.node.set(first.status("included", 3, 0))
	require.NoError(t, f.tick(t))
	require.Equal(t, db.TrackProvisional, f.state(t, first).State, "discovered and polled despite the other database's transaction")
	_, outcome = f.admitElsewhere(t, limit)
	require.Equal(t, db.AdmitInserted, outcome, "the provisional transition released the pending quota")
}

// This instance's own admissions reach its reconciler in memory, so even a
// transaction held open in the tracking database itself does not delay their
// discovery (finding 3).
func TestOwnAdmissionsAreDiscoveredWithoutTheHorizon(t *testing.T) {
	f := newReconcileFixture(t, nil)
	require.NoError(t, f.tick(t))
	holdTransaction(t, f.tracking.url)
	ctx, cancel := context.WithCancel(context.Background())
	wait := f.writer.run(ctx)
	defer wait()
	defer cancel()
	hash := make([]byte, 32)
	_, _ = rand.Read(hash)
	tx := trackedTx{hash: hash, hex: "0x" + hex.EncodeToString(hash), principal: uuid.New(), org: uuid.New(), context: uuid.New()}
	result, _, err := f.writer.admit(ctx, db.TrackAdmission{Hash: hash, PrincipalID: tx.principal, OrgID: tx.org, Signer: hash[:20], Nonce: 1, ContextID: tx.context, EnvelopeHash: hash, ExpiresAt: time.Now().Add(time.Minute), MinVersion: 7, Raw: hash})
	require.NoError(t, err)
	require.Equal(t, db.AdmitInserted, result.Outcome)
	f.node.set(tx.status("included", 3, 0))
	require.NoError(t, f.tick(t))
	require.Equal(t, db.TrackProvisional, f.state(t, tx).State)
}

// A transaction held open in the tracking database itself stalls the
// discovery horizon: after a bounded wait the stall is alerted and another
// instance's bindings are found by a full scan instead (finding 3).
func TestStalledHorizonFallsBackToAFullScan(t *testing.T) {
	f := newReconcileFixture(t, nil)
	var alerts []string
	f.r.alert = func(kind string) { alerts = append(alerts, kind) }
	now := time.Now()
	f.r.now = func() time.Time { return now }
	require.NoError(t, f.tick(t))
	holdTransaction(t, f.tracking.url)
	other, outcome := f.admitElsewhere(t, db.TrackLimits{})
	require.Equal(t, db.AdmitInserted, outcome)
	f.node.set(other.status("included", 3, 0))
	require.NoError(t, f.tick(t))
	require.Equal(t, db.TrackPending, f.state(t, other).State, "held below the horizon before the stall is detected")
	now = now.Add(discoverStallAfter + time.Second)
	require.NoError(t, f.tick(t))
	require.Equal(t, db.TrackProvisional, f.state(t, other).State, "found by the full scan")
	require.Contains(t, alerts, alertDiscoveryStalled)
}
