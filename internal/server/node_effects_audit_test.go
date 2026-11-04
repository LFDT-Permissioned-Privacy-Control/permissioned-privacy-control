package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/nodepolicy"
	"privacy-proxy/internal/rbac"
)

// methodFailingAudit fails the first times appends that carry an event of
// method (a refusal's audit append, say) and records the rest.
type methodFailingAudit struct {
	*recordingAudit
	method string
	times  int
}

func (a *methodFailingAudit) AppendBatch(data [][]byte) ([]uint64, error) {
	if a.times > 0 {
		for _, d := range data {
			if strings.Contains(string(d), `"`+a.method+`"`) {
				a.times--
				return nil, errInjectedAudit
			}
		}
	}
	return a.recordingAudit.AppendBatch(data)
}

var errInjectedAudit = errors.New("injected audit failure")

type conflictFixture struct {
	*reconcileFixture
	database    *db.DB
	org         uuid.UUID
	taken, free string
	tx          trackedTx
}

// newConflictFixture: a finalized deployment of org that created two
// addresses, one of them already owned by another organization.
func newConflictFixture(t *testing.T) *conflictFixture {
	t.Helper()
	database, err := db.New(sharedTestDBURL(t))
	require.NoError(t, err)
	t.Cleanup(func() { database.Close() })
	require.NoError(t, db.ResetTestDatabase(database))
	ctx := context.Background()
	require.NoError(t, database.EnsureNodeTxEffectsFloor(ctx, reconcileNetwork))
	org, other := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, other} {
		require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: id.String(), Slug: "conf-" + id.String()[:8], Name: "Conflict"}))
	}
	taken, free := "0x"+strings.Repeat("d1", 20), "0x"+strings.Repeat("d2", 20)
	require.NoError(t, database.CreateContract(ctx, &rbac.Contract{ID: uuid.NewString(), OrgID: other.String(), Address: taken, Name: "taken"}))
	f := newReconcileFixture(t, database)
	principal := uuid.New()
	tx := f.admit(t, principal, org)
	status := tx.status("included", 8, 8)
	status.Execution.Created = []nodepolicy.CreatedContract{{Address: taken, OrgID: org.String(), PrincipalID: principal.String()}, {Address: free, OrgID: org.String(), PrincipalID: principal.String()}}
	f.node.set(status)
	return &conflictFixture{reconcileFixture: f, database: database, org: org, taken: taken, free: free, tx: tx}
}

func (f *conflictFixture) owner(t *testing.T, address string) string {
	t.Helper()
	var owner string
	err := f.database.Conn().QueryRow(`SELECT coalesce(max(org_id::text), '') FROM contracts WHERE lower(address) = $1`, address).Scan(&owner)
	require.NoError(t, err)
	return owner
}

func (f *conflictFixture) refusals() int {
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	n := 0
	for _, e := range f.audit.events {
		if e.Method == "ops.system.effects_refused" {
			n++
		}
	}
	return n
}

// The refusal of an address another organization owns is audited before the
// effects commit: when its append fails nothing is applied and the decision
// is retried; once audited, the transaction finalizes with the refusal reason
// (independent review, finding 4).
func TestEffectsRefusalAuditedBeforeCommit(t *testing.T) {
	f := newConflictFixture(t)
	f.r.audit = &methodFailingAudit{recordingAudit: f.audit, method: "ops.system.effects_refused", times: 1}
	err := f.tick(t)
	require.ErrorIs(t, err, errSystemAuditUnavailable)
	require.Equal(t, "", f.owner(t, f.free), "nothing commits before the refusal is audited")
	require.Equal(t, db.TrackPending, f.state(t, f.tx).State)
	require.Zero(t, f.refusals())

	f.r.now = func() time.Time { return time.Now().Add(time.Hour) }
	require.NoError(t, f.tick(t))
	row := f.state(t, f.tx)
	require.Equal(t, db.TrackIncluded, row.State)
	require.Equal(t, db.TrackReasonOwnershipConflict, row.Reason)
	require.Equal(t, 1, f.refusals())
	require.Equal(t, f.org.String(), f.owner(t, f.free), "the other created address is registered")
	require.NotEqual(t, f.org.String(), f.owner(t, f.taken), "the other organization keeps its address")
}

// A crash after the effects committed but before the tracking finalize: the
// next term finalizes with the same refusal reason, never as fully applied
// (independent review, finding 4).
func TestEffectsRefusalReasonSurvivesACrashBeforeFinalize(t *testing.T) {
	f := newConflictFixture(t)
	f.writer.store = &failOnceFinals{countingTracking: f.counting}
	require.Error(t, f.tick(t))
	require.Equal(t, f.org.String(), f.owner(t, f.free), "the effects committed before the crash")
	require.Equal(t, 1, f.refusals())

	f.r = newNodeReconciler(f.writer, f.main, f.node, f.audit, reconcileNetwork) // a new term
	require.NoError(t, f.tick(t))
	row := f.state(t, f.tx)
	require.Equal(t, db.TrackIncluded, row.State)
	require.Equal(t, db.TrackReasonOwnershipConflict, row.Reason, "the refusal reason survives the retry")
}
