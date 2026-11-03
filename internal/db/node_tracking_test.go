package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// trackingFixture is one tracking database with a runtime and an owner handle.
type trackingFixture struct {
	t       *testing.T
	exec    *ExecDB
	admin   *ExecAdminDB
	inc     uuid.UUID
	execURL string
	mainURL string
}

func newTrackingFixture(t *testing.T) *trackingFixture {
	t.Helper()
	_, mainURL := setupMainAndURL(t)
	execURL := newTrackingDatabase(t, mainURL)
	exec, admin, meta := openTracking(t, execURL, trackingTestNetwork)
	return &trackingFixture{t: t, exec: exec, admin: admin, inc: meta.Incarnation, execURL: execURL, mainURL: mainURL}
}

// reset empties every tracking table between subtests.
func (f *trackingFixture) reset() {
	f.t.Helper()
	_, err := f.exec.pool.conn.Exec(`TRUNCATE node_tx_binding, node_tx_payload, node_tx_status, node_tx_identities, pending_quota_principal, pending_quota_org; UPDATE pending_quota SET used = 0`)
	require.NoError(f.t, err)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// admission is a valid admission of hash for principal (org and signer fixed
// per principal unless overridden).
func admission(hash []byte, principal, org uuid.UUID, signer []byte) TrackAdmission {
	return TrackAdmission{Hash: hash, PrincipalID: principal, OrgID: org, Signer: signer, Nonce: 1, ContextID: uuid.New(), EnvelopeHash: randomBytes(32), ExpiresAt: time.Now().Add(5 * time.Minute), MinVersion: 7, Raw: append([]byte{0x02}, hash...), ClaimOwner: uuid.New(), ClaimTTL: 20 * time.Second}
}

type principal struct {
	id, org uuid.UUID
	signer  []byte
}

func newPrincipal() principal {
	return principal{id: uuid.New(), org: uuid.New(), signer: randomBytes(20)}
}

func (p principal) admit(hash []byte) TrackAdmission { return admission(hash, p.id, p.org, p.signer) }

func (f *trackingFixture) admitOne(limit int64, a TrackAdmission) AdmitResult {
	f.t.Helper()
	results, err := f.exec.AdmitBatch(context.Background(), f.inc, TrackLimits{Global: limit}, []TrackAdmission{a})
	require.NoError(f.t, err)
	return results[0]
}

// quotaConsistent asserts used == count(pending) (G63).
func (f *trackingFixture) quotaConsistent() int64 {
	f.t.Helper()
	used, pending, err := f.exec.PendingQuota(context.Background())
	require.NoError(f.t, err)
	require.Equal(f.t, pending, used, "pending_quota.used must equal count(pending rows)")
	return used
}

func (f *trackingFixture) transition(hash []byte, from, to int16, generation int32) bool {
	f.t.Helper()
	block := uint64(10)
	applied, err := f.exec.ApplyTransitions(context.Background(), f.inc, []TrackTransition{{Hash: hash, From: from, To: to, Generation: generation, BlockNumber: &block}})
	require.NoError(f.t, err)
	return applied[0]
}

func (f *trackingFixture) finalize(p principal, hash []byte, state int16) bool {
	f.t.Helper()
	block := uint64(10)
	applied, err := f.exec.FinalizeBatch(context.Background(), f.inc, []TrackFinal{{Hash: hash, State: state, BlockNumber: &block, PrincipalID: p.id, OrgID: p.org}})
	require.NoError(f.t, err)
	return applied[0]
}

func (f *trackingFixture) state(hash []byte) (TrackedTransaction, error) {
	return f.exec.LookupTracked(context.Background(), hash)
}

// TestPendingQuotaIsAtomicAcrossInstances is G63 (plan §4.8.2, §8): the quota
// counts exactly the pending bindings after every committed batch, for every
// transition in the rev 11 table, under concurrency and limits.
func TestPendingQuotaIsAtomicAcrossInstances(t *testing.T) {
	f := newTrackingFixture(t)
	ctx := context.Background()

	t.Run("concurrent admissions on several instances never exceed the limit", func(t *testing.T) {
		f.reset()
		const limit = 20
		p := newPrincipal()
		for i := 0; i < limit-1; i++ {
			require.Equal(t, AdmitInserted, f.admitOne(limit, p.admit(randomBytes(32))).Outcome)
		}
		// Two more "instances": their own pools, the same database.
		var pools []*ExecDB
		for i := 0; i < 2; i++ {
			pool, err := NewWithoutMigrate(f.execURL)
			require.NoError(t, err)
			t.Cleanup(func() { pool.Close() })
			pools = append(pools, NewExecHandle(pool))
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		accepted := 0
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				batch := []TrackAdmission{p.admit(randomBytes(32)), p.admit(randomBytes(32))}
				results, err := pools[i%2].AdmitBatch(ctx, f.inc, TrackLimits{Global: limit}, batch)
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				defer mu.Unlock()
				for _, r := range results {
					if r.Outcome == AdmitInserted {
						accepted++
					} else if r.Outcome != AdmitOverLimit {
						t.Errorf("unexpected outcome %v", r.Outcome)
					}
				}
			}(i)
		}
		wg.Wait()
		require.Equal(t, 1, accepted, "exactly the one remaining slot is granted")
		require.EqualValues(t, limit, f.quotaConsistent())
	})

	t.Run("resubmissions at the limit are accepted without charging", func(t *testing.T) {
		f.reset()
		p := newPrincipal()
		hash := randomBytes(32)
		require.Equal(t, AdmitInserted, f.admitOne(1, p.admit(hash)).Outcome)
		again := f.admitOne(1, p.admit(hash))
		require.Equal(t, AdmitResubmitted, again.Outcome)
		require.EqualValues(t, 2, again.Generation)
		require.Equal(t, AdmitOverLimit, f.admitOne(1, p.admit(randomBytes(32))).Outcome)
		require.EqualValues(t, 1, f.quotaConsistent())
	})

	t.Run("provisional releases, reorg back re-charges over the limit, admissions wait for the drain", func(t *testing.T) {
		f.reset()
		p := newPrincipal()
		a, b := randomBytes(32), randomBytes(32)
		require.Equal(t, AdmitInserted, f.admitOne(2, p.admit(a)).Outcome)
		require.Equal(t, AdmitInserted, f.admitOne(2, p.admit(b)).Outcome)
		require.True(t, f.transition(a, TrackPending, TrackProvisional, 0))
		require.EqualValues(t, 1, f.quotaConsistent())
		c := randomBytes(32)
		require.Equal(t, AdmitInserted, f.admitOne(2, p.admit(c)).Outcome) // the released slot
		require.True(t, f.transition(a, TrackProvisional, TrackPending, 0), "a reorg is never refused")
		require.EqualValues(t, 3, f.quotaConsistent(), "admitted work is not dropped: over the limit")
		require.Equal(t, AdmitOverLimit, f.admitOne(2, p.admit(randomBytes(32))).Outcome)
		require.True(t, f.finalize(p, b, TrackIncluded))
		require.Equal(t, AdmitOverLimit, f.admitOne(2, p.admit(randomBytes(32))).Outcome, "still at the limit")
		require.True(t, f.finalize(p, c, TrackIncluded))
		require.Equal(t, AdmitInserted, f.admitOne(2, p.admit(randomBytes(32))).Outcome)
		f.quotaConsistent()
	})

	t.Run("revival charges as a new admission", func(t *testing.T) {
		f.reset()
		p := newPrincipal()
		h := randomBytes(32)
		require.Equal(t, AdmitInserted, f.admitOne(1, p.admit(h)).Outcome)
		require.True(t, f.transition(h, TrackPending, TrackRenewalStopped, 0))
		require.True(t, f.transition(h, TrackRenewalStopped, TrackTombstone, 0))
		require.EqualValues(t, 0, f.quotaConsistent(), "stops and tombstones carry no quota")
		require.Equal(t, AdmitInserted, f.admitOne(1, p.admit(randomBytes(32))).Outcome)
		require.Equal(t, AdmitOverLimit, f.admitOne(1, p.admit(h)).Outcome, "a revival is refused over the limit")
		got, err := f.state(h)
		require.NoError(t, err)
		require.Equal(t, TrackTombstone, got.State, "a refused revival writes nothing")
		f.quotaConsistent()
	})

	t.Run("every final transition from every state", func(t *testing.T) {
		f.reset()
		p := newPrincipal()
		cases := []struct {
			name  string
			setup []int16 // states to pass through after admission
			final int16
		}{
			{"first-poll finalized include from pending", nil, TrackIncluded},
			{"first-poll finalized revert from pending", nil, TrackReverted},
			{"direct finalized-nonce dropped from pending", nil, TrackDropped},
			{"provisional to included", []int16{TrackProvisional}, TrackIncluded},
			{"renewal_stopped to included", []int16{TrackRenewalStopped}, TrackIncluded},
			{"tombstone to dropped", []int16{TrackRenewalStopped, TrackTombstone}, TrackDropped},
		}
		for _, c := range cases {
			h := randomBytes(32)
			require.Equal(t, AdmitInserted, f.admitOne(0, p.admit(h)).Outcome)
			from := TrackPending
			for _, to := range c.setup {
				require.True(t, f.transition(h, from, to, 0), c.name)
				f.quotaConsistent()
				from = to
			}
			require.True(t, f.finalize(p, h, c.final), c.name)
			f.quotaConsistent()
			got, err := f.state(h)
			require.NoError(t, err, c.name)
			require.Equal(t, c.final, got.State, c.name)
		}
		require.EqualValues(t, 0, f.quotaConsistent())
	})

	t.Run("crash and retry of each batch keeps the invariant", func(t *testing.T) {
		f.reset()
		p := newPrincipal()
		h := randomBytes(32)
		a := p.admit(h)
		// A batch whose commit outcome was lost is retried as is: the retry
		// is a resubmission, not a second charge.
		require.Equal(t, AdmitInserted, f.admitOne(0, a).Outcome)
		require.Equal(t, AdmitResubmitted, f.admitOne(0, a).Outcome)
		require.EqualValues(t, 1, f.quotaConsistent())
		// A rolled-back batch (crash before commit) changes nothing.
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		_, err := f.exec.AdmitBatch(cancelled, f.inc, TrackLimits{}, []TrackAdmission{p.admit(randomBytes(32))})
		require.Error(t, err)
		require.EqualValues(t, 1, f.quotaConsistent())
		// Transitions and finals retried after a lost acknowledgement are no-ops.
		require.True(t, f.transition(h, TrackPending, TrackProvisional, 0))
		require.False(t, f.transition(h, TrackPending, TrackProvisional, 0))
		require.EqualValues(t, 0, f.quotaConsistent())
		require.True(t, f.finalize(p, h, TrackIncluded))
		require.False(t, f.finalize(p, h, TrackIncluded))
		f.quotaConsistent()
		_, err = f.exec.FinalizeBatch(cancelled, f.inc, []TrackFinal{{Hash: randomBytes(32), State: TrackIncluded, PrincipalID: p.id, OrgID: p.org}})
		require.Error(t, err)
		f.quotaConsistent()
	})
}

// TestProvisionalPollingIsFinalityDriven covers the storage half of G62: an
// unchanged or repeated observation writes nothing, and provisional rows carry
// no quota, so a long finality lag never throttles admission.
func TestProvisionalPollingIsFinalityDriven(t *testing.T) {
	f := newTrackingFixture(t)
	p := newPrincipal()
	const limit = 5
	var provisional [][]byte
	for i := 0; i < 50; i++ {
		h := randomBytes(32)
		require.Equal(t, AdmitInserted, f.admitOne(limit, p.admit(h)).Outcome, "provisional rows must not hold the limit")
		require.True(t, f.transition(h, TrackPending, TrackProvisional, 0))
		provisional = append(provisional, h)
	}
	require.EqualValues(t, 0, f.quotaConsistent())
	before := tableMutations(t, f.exec.pool.conn, "node_tx_binding")
	for _, h := range provisional {
		require.False(t, f.transition(h, TrackPending, TrackProvisional, 0), "a repeated provisional observation is a no-op")
	}
	require.Equal(t, before, tableMutations(t, f.exec.pool.conn, "node_tx_binding"), "unchanged polls write nothing")
}

// tableMutations returns n_tup_ins + n_tup_upd + n_tup_del over the table and
// its partitions, after flushing this pool's statistics.
func tableMutations(t *testing.T, conn *sql.DB, prefix string) int64 {
	t.Helper()
	ctx := context.Background()
	c, err := conn.Conn(ctx)
	require.NoError(t, err)
	defer c.Close()
	// Statistics are flushed per backend: flush every idle pooled backend by
	// asking the server, then read a fresh snapshot.
	_, err = c.ExecContext(ctx, `SELECT pg_stat_force_next_flush()`)
	require.NoError(t, err)
	var n int64
	require.Eventually(t, func() bool {
		_, _ = c.ExecContext(ctx, `SELECT pg_stat_clear_snapshot()`)
		var got int64
		if c.QueryRowContext(ctx, `SELECT coalesce(sum(n_tup_ins + n_tup_upd + n_tup_del), 0) FROM pg_stat_user_tables WHERE relname = $1 OR relname LIKE $1 || '\_%'`, prefix).Scan(&got) != nil {
			return false
		}
		stable := got == n
		n = got
		return stable
	}, 5*time.Second, 1100*time.Millisecond)
	return n
}

// TestBatchedIntentInsertDedupesConflictsWithinBatch is G43: duplicates in
// one batch are written in order (the later one as a resubmission of the
// earlier); a different principal in the same batch is a conflict.
func TestBatchedIntentInsertDedupesConflictsWithinBatch(t *testing.T) {
	f := newTrackingFixture(t)
	p, q := newPrincipal(), newPrincipal()
	h, other := randomBytes(32), randomBytes(32)
	batch := []TrackAdmission{p.admit(h), q.admit(h), p.admit(h), p.admit(other)}
	results, err := f.exec.AdmitBatch(context.Background(), f.inc, TrackLimits{}, batch)
	require.NoError(t, err)
	require.Equal(t, AdmitInserted, results[0].Outcome)
	require.Equal(t, AdmitConflict, results[1].Outcome)
	require.Equal(t, AdmitResubmitted, results[2].Outcome)
	require.EqualValues(t, 2, results[2].Generation)
	require.Equal(t, AdmitInserted, results[3].Outcome)
	got, err := f.state(h)
	require.NoError(t, err)
	require.Equal(t, p.id, got.PrincipalID)
	require.Equal(t, batch[2].ContextID, got.ContextID)
	require.ElementsMatch(t, []uuid.UUID{batch[0].ContextID, batch[2].ContextID}, got.IssuedContexts)
	require.EqualValues(t, 2, f.quotaConsistent())
	var history int
	require.NoError(t, f.exec.pool.conn.QueryRow(`SELECT count(*) FROM node_tx_identities WHERE tx_hash = $1 AND generation = 2`, h).Scan(&history))
	require.Equal(t, 1, history, "generations ≥ 2 are recorded in history (G38)")
}

// TestTombstoneRefusesOtherPrincipalUntilFinalizedNonce is G58: the single
// binding row refuses another principal while live, as a tombstone and after
// finality; the same principal may revive a tombstone, and a stale tombstone
// transition after that revival is a no-op by generation.
func TestTombstoneRefusesOtherPrincipalUntilFinalizedNonce(t *testing.T) {
	f := newTrackingFixture(t)
	ctx := context.Background()
	p1, p2 := newPrincipal(), newPrincipal()
	p2.signer = p1.signer // a shared signer
	p2.org = p1.org

	t.Run("live, tombstoned and final bindings refuse another principal", func(t *testing.T) {
		f.reset()
		h := randomBytes(32)
		require.Equal(t, AdmitInserted, f.admitOne(0, p1.admit(h)).Outcome)
		require.Equal(t, AdmitConflict, f.admitOne(0, p2.admit(h)).Outcome)
		require.True(t, f.transition(h, TrackPending, TrackRenewalStopped, 0))
		require.Equal(t, AdmitConflict, f.admitOne(0, p2.admit(h)).Outcome)
		require.True(t, f.transition(h, TrackRenewalStopped, TrackTombstone, 0))
		require.Equal(t, AdmitConflict, f.admitOne(0, p2.admit(h)).Outcome, "a tombstone keeps the binding")
		require.True(t, f.finalize(p1, h, TrackDropped))
		require.Equal(t, AdmitConflict, f.admitOne(0, p2.admit(h)).Outcome, "a final hash is never rebound")
		require.Equal(t, AdmitConflict, f.admitOne(0, p1.admit(h)).Outcome, "a dropped transaction can never execute, not even for its owner")
		included := randomBytes(32)
		require.Equal(t, AdmitInserted, f.admitOne(0, p1.admit(included)).Outcome)
		require.True(t, f.finalize(p1, included, TrackIncluded))
		require.Equal(t, AdmitConflict, f.admitOne(0, p2.admit(included)).Outcome)
		require.Equal(t, AdmitFinal, f.admitOne(0, p1.admit(included)).Outcome, "the owner's resend of an executed hash writes nothing")
		got, err := f.state(h)
		require.NoError(t, err)
		require.Equal(t, TrackDropped, got.State)
		require.Equal(t, p1.id, got.PrincipalID)
		f.quotaConsistent()
	})

	t.Run("an admission paused across tombstoning is refused on the single row", func(t *testing.T) {
		f.reset()
		h := randomBytes(32)
		require.Equal(t, AdmitInserted, f.admitOne(0, p1.admit(h)).Outcome)
		require.True(t, f.transition(h, TrackPending, TrackRenewalStopped, 0))
		// Hold the row lock as the tombstone transition does, then race P2.
		tx, err := f.exec.pool.conn.BeginTx(ctx, nil)
		require.NoError(t, err)
		_, err = tx.Exec(`UPDATE node_tx_binding SET state = 4 WHERE tx_hash = $1`, h)
		require.NoError(t, err)
		done := make(chan AdmitResult, 1)
		go func() {
			r, err := f.exec.AdmitBatch(ctx, f.inc, TrackLimits{}, []TrackAdmission{p2.admit(h)})
			if err != nil {
				t.Error(err)
				close(done)
				return
			}
			done <- r[0]
		}()
		time.Sleep(200 * time.Millisecond)
		require.NoError(t, tx.Commit())
		require.Equal(t, AdmitConflict, (<-done).Outcome)
	})

	t.Run("a same-principal revival beats a stale tombstone transition", func(t *testing.T) {
		f.reset()
		h := randomBytes(32)
		require.Equal(t, AdmitInserted, f.admitOne(0, p1.admit(h)).Outcome)
		require.True(t, f.transition(h, TrackPending, TrackRenewalStopped, 1))
		require.True(t, f.transition(h, TrackRenewalStopped, TrackTombstone, 1))
		revived := f.admitOne(0, p1.admit(h))
		require.Equal(t, AdmitRevived, revived.Outcome)
		require.Equal(t, TrackPending, revived.State)
		require.False(t, f.transition(h, TrackRenewalStopped, TrackTombstone, 1), "a stale transition for generation 1 is a no-op")
		got, err := f.state(h)
		require.NoError(t, err)
		require.Equal(t, TrackPending, got.State)
		raw, err := f.exec.TrackedPayload(ctx, h)
		require.NoError(t, err, "a revival re-inserts the payload")
		require.NotEmpty(t, raw)
		f.quotaConsistent()
	})
}

// TestReleaseUndeliveredOnlyFreshInsert defines the -32012 transition: only a
// fresh, never-acknowledged, never-resubmitted generation-1 binding of this
// context is removed; a resubmitted, revived or acknowledged one is kept.
func TestReleaseUndeliveredOnlyFreshInsert(t *testing.T) {
	f := newTrackingFixture(t)
	ctx := context.Background()
	p := newPrincipal()

	f.reset()
	h := randomBytes(32)
	a := p.admit(h)
	require.Equal(t, AdmitInserted, f.admitOne(0, a).Outcome)
	released, err := f.exec.ReleaseUndelivered(ctx, f.inc, h, uuid.New())
	require.NoError(t, err)
	require.False(t, released, "another context is not this request's insert")
	released, err = f.exec.ReleaseUndelivered(ctx, f.inc, h, a.ContextID)
	require.NoError(t, err)
	require.True(t, released)
	_, err = f.state(h)
	require.ErrorIs(t, err, sql.ErrNoRows)
	require.EqualValues(t, 0, f.quotaConsistent())

	resubmitted := randomBytes(32)
	first := p.admit(resubmitted)
	require.Equal(t, AdmitInserted, f.admitOne(0, first).Outcome)
	require.Equal(t, AdmitResubmitted, f.admitOne(0, p.admit(resubmitted)).Outcome)
	released, err = f.exec.ReleaseUndelivered(ctx, f.inc, resubmitted, first.ContextID)
	require.NoError(t, err)
	require.False(t, released, "a resubmitted binding may have been delivered by the other request")

	acked := randomBytes(32)
	ackedAdmission := p.admit(acked)
	require.Equal(t, AdmitInserted, f.admitOne(0, ackedAdmission).Outcome)
	settled, err := f.exec.FlushAcks(ctx, f.inc, []TrackAck{{Hash: acked, Generation: 1}})
	require.NoError(t, err)
	require.True(t, settled[string(acked)])
	released, err = f.exec.ReleaseUndelivered(ctx, f.inc, acked, ackedAdmission.ContextID)
	require.NoError(t, err)
	require.False(t, released, "an acknowledged binding is never released")

	revived := randomBytes(32)
	require.Equal(t, AdmitInserted, f.admitOne(0, p.admit(revived)).Outcome)
	require.True(t, f.transition(revived, TrackPending, TrackRenewalStopped, 0))
	again := p.admit(revived)
	require.Equal(t, AdmitRevived, f.admitOne(0, again).Outcome)
	released, err = f.exec.ReleaseUndelivered(ctx, f.inc, revived, again.ContextID)
	require.NoError(t, err)
	require.False(t, released, "a revival is never released")
	f.quotaConsistent()
}

// TestAckIsCoalescedIntoTheNextTransition is R12.6: an acknowledgement of a
// row that already went provisional or final writes nothing; the provisional
// transition itself records the delivery to the node boot that observed the
// inclusion, and a reorg back keeps it: that node process still holds the
// identity until finality, so the row needs no renewal unless the boot
// changes, the lease runs out or the pool loses it (B3b).
func TestAckIsCoalescedIntoTheNextTransition(t *testing.T) {
	f := newTrackingFixture(t)
	ctx := context.Background()
	p := newPrincipal()
	h := randomBytes(32)
	require.Equal(t, AdmitInserted, f.admitOne(0, p.admit(h)).Outcome)
	boot := uuid.New()
	block := uint64(9)
	applied, err := f.exec.ApplyTransitions(ctx, f.inc, []TrackTransition{{Hash: h, From: TrackPending, To: TrackProvisional, BlockNumber: &block, Boot: boot}})
	require.NoError(t, err)
	require.Equal(t, []bool{true}, applied)
	var delivered sql.NullInt32
	require.NoError(t, f.exec.pool.conn.QueryRow(`SELECT delivered_generation FROM node_tx_binding WHERE tx_hash = $1`, h).Scan(&delivered))
	require.True(t, delivered.Valid && delivered.Int32 == 1, "inclusion records the delivery")
	before := tableMutations(t, f.exec.pool.conn, "node_tx_binding")
	settled, err := f.exec.FlushAcks(ctx, f.inc, []TrackAck{{Hash: h, Generation: 1}})
	require.NoError(t, err)
	require.True(t, settled[string(h)], "nothing left to record")
	require.Equal(t, before, tableMutations(t, f.exec.pool.conn, "node_tx_binding"), "the late acknowledgement writes nothing")
	require.True(t, f.transition(h, TrackProvisional, TrackPending, 0))
	row, err := f.exec.LookupTracked(ctx, h)
	require.NoError(t, err)
	require.True(t, row.DeliveredTo(boot), "a reorged-out row stays delivered to the boot that holds its identity")
	require.False(t, row.DeliveredTo(uuid.New()), "and is undelivered for any other boot")
}

// TestTrackingLifecycleRowMutations proves R12.6's budget: a normal lifecycle
// is at most 5 row mutations in the tracking database (binding insert,
// payload insert, provisional update carrying the acknowledgement, binding
// delete, status insert); a first-poll final is 4. The payload leaves by
// bucket truncation, not by a per-row delete.
func TestTrackingLifecycleRowMutations(t *testing.T) {
	f := newTrackingFixture(t)
	ctx := context.Background()
	p := newPrincipal()
	f.exec.pool.conn.SetMaxOpenConns(1) // one backend: its statistics are flushed below
	count := func() int64 {
		var n int64
		for _, table := range []string{"node_tx_binding", "node_tx_payload", "node_tx_status", "node_tx_identities"} {
			n += tableMutations(t, f.exec.pool.conn, table)
		}
		return n
	}
	const n = 40
	run := func(provisional bool) int64 {
		hashes := make([][]byte, n)
		batch := make([]TrackAdmission, n)
		for i := range batch {
			hashes[i] = randomBytes(32)
			batch[i] = p.admit(hashes[i])
		}
		start := count()
		_, err := f.exec.AdmitBatch(ctx, f.inc, TrackLimits{}, batch)
		require.NoError(t, err)
		block := uint64(9)
		acks := make([]TrackAck, n)
		for i, h := range hashes {
			acks[i] = TrackAck{Hash: h, Generation: 1}
		}
		if provisional {
			transitions := make([]TrackTransition, n)
			for i, h := range hashes {
				transitions[i] = TrackTransition{Hash: h, From: TrackPending, To: TrackProvisional, BlockNumber: &block}
			}
			_, err = f.exec.ApplyTransitions(ctx, f.inc, transitions)
			require.NoError(t, err)
		}
		// The acknowledgement flush comes after the next transition (it waits
		// a few seconds), so it writes nothing.
		if provisional {
			_, err = f.exec.FlushAcks(ctx, f.inc, acks)
			require.NoError(t, err)
		}
		finals := make([]TrackFinal, n)
		for i, h := range hashes {
			finals[i] = TrackFinal{Hash: h, State: TrackIncluded, BlockNumber: &block, PrincipalID: p.id, OrgID: p.org}
		}
		_, err = f.exec.FinalizeBatch(ctx, f.inc, finals)
		require.NoError(t, err)
		if !provisional {
			_, err = f.exec.FlushAcks(ctx, f.inc, acks)
			require.NoError(t, err)
		}
		return count() - start
	}
	viaProvisional := run(true)
	direct := run(false)
	t.Logf("row mutations per lifecycle: via provisional %.1f, first-poll final %.1f", float64(viaProvisional)/n, float64(direct)/n)
	require.LessOrEqual(t, viaProvisional, int64(5*n))
	require.LessOrEqual(t, direct, int64(4*n))
	f.quotaConsistent()
}

// TestFinalityBatchDeletesInflightAndKeepsOnlyStatus is G42 (rev 12 form): the
// finality batch deletes the binding and inserts the status row in one
// transaction; the raw transaction is gone once its payload bucket is
// truncated; OPS stores the envelope hash only, never envelope bytes.
func TestFinalityBatchDeletesInflightAndKeepsOnlyStatus(t *testing.T) {
	f := newTrackingFixture(t)
	ctx := context.Background()
	p := newPrincipal()
	h := randomBytes(32)
	a := p.admit(h)
	require.Equal(t, AdmitInserted, f.admitOne(0, a).Outcome)
	require.True(t, f.finalize(p, h, TrackIncluded))
	var bindings, statuses int
	require.NoError(t, f.exec.pool.conn.QueryRow(`SELECT (SELECT count(*) FROM node_tx_binding), (SELECT count(*) FROM node_tx_status WHERE tx_hash = $1)`, h).Scan(&bindings, &statuses))
	require.Equal(t, 0, bindings)
	require.Equal(t, 1, statuses)
	_, err := f.exec.TrackedPayload(ctx, h)
	require.ErrorIs(t, err, sql.ErrNoRows, "the raw transaction is not reachable after finality")
	// The bucket is truncated once its window passed (simulated: keep 0 is
	// clamped to 15 minutes, so age the row's bucket out of the window).
	var bucket int16
	require.NoError(t, f.exec.pool.conn.QueryRow(`SELECT bucket FROM node_tx_payload WHERE tx_hash = $1`, h).Scan(&bucket))
	_, err = f.exec.pool.conn.Exec(`INSERT INTO node_tx_payload_`+itoa(int((bucket+8)%16))+` SELECT ($1::smallint), tx_hash, raw_tx FROM node_tx_payload WHERE tx_hash = $2`, (bucket+8)%16, h)
	require.NoError(t, err)
	done, err := f.admin.MaintainTracking(ctx, 2, 0, 15*time.Minute)
	require.NoError(t, err)
	require.Contains(t, done.Truncated, "node_tx_payload_"+itoa(int((bucket+8)%16)), "a bucket two hours old is truncated")
	require.NotContains(t, done.Truncated, "node_tx_payload_"+itoa(int(bucket)), "the current bucket never is")
	var envelopeColumns int
	require.NoError(t, f.exec.pool.conn.QueryRow(`SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public' AND column_name LIKE '%envelope%' AND column_name <> 'envelope_hash'`).Scan(&envelopeColumns))
	require.Equal(t, 0, envelopeColumns, "no envelope bytes are stored in the tracking database")
}

func itoa(n int) string { return strconv.Itoa(n) }

// dbName is the database name of a postgres URL.
func dbName(dsn string) string {
	u, _ := url.Parse(dsn)
	return strings.TrimPrefix(u.Path, "/")
}

// TestBindingNeverDeletedWhileExecutable is G31: a binding row leaves only by
// a final transition (or the -32012 release of a never-delivered fresh
// insert); a tombstone stays until the finalized nonce passes (a dropped
// final); status rows leave only by retention.
func TestBindingNeverDeletedWhileExecutable(t *testing.T) {
	f := newTrackingFixture(t)
	p := newPrincipal()
	h := randomBytes(32)
	require.Equal(t, AdmitInserted, f.admitOne(0, p.admit(h)).Outcome)
	for _, step := range []struct{ from, to int16 }{{TrackPending, TrackProvisional}, {TrackProvisional, TrackPending}, {TrackPending, TrackRenewalStopped}, {TrackRenewalStopped, TrackTombstone}} {
		require.True(t, f.transition(h, step.from, step.to, 0))
		got, err := f.state(h)
		require.NoError(t, err, "binding must survive %d → %d", step.from, step.to)
		require.False(t, got.Final())
	}
	other := newPrincipal()
	require.False(t, f.finalize(other, h, TrackDropped), "a final for another principal never deletes the binding")
	_, err := f.admin.MaintainTracking(context.Background(), 2, time.Hour, 15*time.Minute)
	require.NoError(t, err)
	got, err := f.state(h)
	require.NoError(t, err, "retention never removes an in-flight binding")
	require.Equal(t, TrackTombstone, got.State)
}

// TestIncarnationFencesOutstandingWorkAcrossRecreation is G59 (storage half):
// work issued under one incarnation has no effect once the tracking database
// was dropped and recreated with a new one.
func TestIncarnationFencesOutstandingWorkAcrossRecreation(t *testing.T) {
	f := newTrackingFixture(t)
	ctx := context.Background()
	p := newPrincipal()
	h := randomBytes(32)
	require.Equal(t, AdmitInserted, f.admitOne(0, p.admit(h)).Outcome)
	old := f.inc
	// Recreate: drop and recreate the database, migrate, initialise.
	f.exec.pool.conn.Close()
	main, err := NewWithoutMigrate(f.mainURL)
	require.NoError(t, err)
	defer main.Close()
	_, err = main.conn.Exec(`DROP DATABASE ` + dbName(f.execURL) + ` WITH (FORCE)`)
	require.NoError(t, err)
	_, err = main.conn.Exec(`CREATE DATABASE ` + dbName(f.execURL))
	require.NoError(t, err)
	exec, _, meta := openTracking(t, f.execURL, trackingTestNetwork)
	require.NotEqual(t, old, meta.Incarnation)
	block := uint64(3)
	_, err = exec.AdmitBatch(ctx, old, TrackLimits{}, []TrackAdmission{p.admit(randomBytes(32))})
	require.ErrorIs(t, err, ErrTrackingIncarnation)
	_, err = exec.ApplyTransitions(ctx, old, []TrackTransition{{Hash: h, From: TrackPending, To: TrackProvisional, BlockNumber: &block}})
	require.ErrorIs(t, err, ErrTrackingIncarnation)
	_, err = exec.FinalizeBatch(ctx, old, []TrackFinal{{Hash: h, State: TrackIncluded, PrincipalID: p.id, OrgID: p.org}})
	require.ErrorIs(t, err, ErrTrackingIncarnation)
	_, err = exec.FlushAcks(ctx, old, []TrackAck{{Hash: h, Generation: 1}})
	require.ErrorIs(t, err, ErrTrackingIncarnation)
	_, err = exec.ReleaseUndelivered(ctx, old, h, uuid.New())
	require.ErrorIs(t, err, ErrTrackingIncarnation)
	// Fresh work under the new incarnation proceeds.
	results, err := exec.AdmitBatch(ctx, meta.Incarnation, TrackLimits{}, []TrackAdmission{p.admit(h)})
	require.NoError(t, err)
	require.Equal(t, AdmitInserted, results[0].Outcome)
	_, err = exec.LookupTracked(ctx, h)
	require.NoError(t, err)
	if errors.Is(err, sql.ErrNoRows) {
		t.Fatal("unreachable")
	}
}

// TestInflightUpdatesAreHOT is G45 (gated: OPS_PERF=1): under the lifecycle
// update pattern — group-committed admission batches, 1% resubmissions, one
// provisional batch per block covering a block's rows in one transaction, the
// finality batch a block later — at least 95% of node_tx_binding updates are
// HOT, and with vacuum running the heap does not grow with the number of
// transactions processed.
func TestInflightUpdatesAreHOT(t *testing.T) {
	if os.Getenv("OPS_PERF") != "1" {
		t.Skip("set OPS_PERF=1 to run the HOT-ratio measurement (G45)")
	}
	f := newTrackingFixture(t)
	ctx := context.Background()
	p := newPrincipal()
	const blocks, perBlock, batch = 60, 2000, 25
	var previous [][]byte
	var previousBlock uint64
	var heapAfter10 int64
	for blk := uint64(1); blk <= blocks; blk++ {
		hashes := make([][]byte, perBlock)
		for i := 0; i < perBlock; i += batch {
			admissions := make([]TrackAdmission, batch)
			for k := range admissions {
				hashes[i+k] = randomBytes(32)
				admissions[k] = p.admit(hashes[i+k])
			}
			_, err := f.exec.AdmitBatch(ctx, f.inc, TrackLimits{}, admissions)
			require.NoError(t, err)
		}
		// 1% resubmissions (a second, separate update of those rows).
		for i := 0; i < perBlock; i += 100 {
			_, err := f.exec.AdmitBatch(ctx, f.inc, TrackLimits{}, []TrackAdmission{p.admit(hashes[i])})
			require.NoError(t, err)
		}
		transitions := make([]TrackTransition, perBlock)
		number := blk
		for i, h := range hashes {
			transitions[i] = TrackTransition{Hash: h, From: TrackPending, To: TrackProvisional, BlockNumber: &number}
		}
		_, err := f.exec.ApplyTransitions(ctx, f.inc, transitions)
		require.NoError(t, err)
		if previous != nil {
			finals := make([]TrackFinal, len(previous))
			pb := previousBlock
			for i, h := range previous {
				finals[i] = TrackFinal{Hash: h, State: TrackIncluded, BlockNumber: &pb, PrincipalID: p.id, OrgID: p.org}
			}
			_, err := f.exec.FinalizeBatch(ctx, f.inc, finals)
			require.NoError(t, err)
		}
		previous, previousBlock = hashes, blk
		// Space freed by finalized rows is reused once vacuum records it, so
		// the heap is bounded by the vacuum interval: stand in for autovacuum
		// (row-count triggered on this table) every 10 blocks.
		if blk%10 == 0 {
			_, err := f.exec.pool.conn.Exec(`VACUUM node_tx_binding`)
			require.NoError(t, err)
		}
		if blk == 10 {
			require.NoError(t, f.exec.pool.conn.QueryRow(`SELECT pg_relation_size('node_tx_binding')`).Scan(&heapAfter10))
		}
	}
	var updates, hot, heap int64
	require.Eventually(t, func() bool {
		_, _ = f.exec.pool.conn.Exec(`SELECT pg_stat_force_next_flush()`)
		_, _ = f.exec.pool.conn.Exec(`SELECT pg_stat_clear_snapshot()`)
		return f.exec.pool.conn.QueryRow(`SELECT n_tup_upd, n_tup_hot_upd, pg_relation_size('node_tx_binding') FROM pg_stat_user_tables WHERE relname = 'node_tx_binding'`).Scan(&updates, &hot, &heap) == nil && updates >= blocks*perBlock
	}, 10*time.Second, 500*time.Millisecond)
	ratio := float64(hot) / float64(updates)
	t.Logf("G45: %d updates, %d HOT (ratio %.3f); heap %d KiB after 10 blocks, %d KiB after %d blocks (%d transactions)", updates, hot, ratio, heapAfter10/1024, heap/1024, blocks, blocks*perBlock)
	require.GreaterOrEqual(t, ratio, 0.95)
	require.LessOrEqual(t, heap, 2*heapAfter10, "the binding heap must not grow with the transactions processed")
	f.quotaConsistent()
}

// TestRetentionDropsOnlyExpiredPartitions is G41 (storage half): one
// maintenance pass creates the daily partitions ahead, drops status and
// history partitions whose day ended at least the retention ago, never one
// inside the window, and keeps everything with retention 0 (forever).
func TestRetentionDropsOnlyExpiredPartitions(t *testing.T) {
	f := newTrackingFixture(t)
	ctx := context.Background()
	conn, err := f.exec.pool.conn.Conn(ctx)
	require.NoError(t, err)
	today := time.Now().UTC().Truncate(24 * time.Hour)
	for _, age := range []int{10, 8, 6} {
		day := today.AddDate(0, 0, -age)
		for _, p := range trackingPartitioned {
			_, err := ensureDayPartition(ctx, conn, p.table, p.column, day)
			require.NoError(t, err)
		}
		_, err := conn.ExecContext(ctx, `INSERT INTO node_tx_status (tx_hash, principal_id, org_id, state, final_at) VALUES ($1, $2, $3, 10, $4)`, randomBytes(32), uuid.New(), uuid.New(), day.Add(time.Hour))
		require.NoError(t, err)
	}
	// A partition detached by an interrupted run (detach done, drop not).
	orphan := partitionName("node_tx_status", today.AddDate(0, 0, -12))
	_, err = conn.ExecContext(ctx, `CREATE TABLE `+orphan+` (LIKE node_tx_status)`)
	require.NoError(t, err)
	conn.Close()
	ready, err := f.admin.TrackingPartitionsReady(ctx)
	require.NoError(t, err)
	require.True(t, ready)
	exists := func(name string) bool {
		var ok bool
		require.NoError(t, f.exec.pool.conn.QueryRow(`SELECT to_regclass($1) IS NOT NULL`, name).Scan(&ok))
		return ok
	}
	forever, err := f.admin.MaintainTracking(ctx, 3, 0, time.Hour)
	require.NoError(t, err)
	require.Empty(t, forever.Dropped, "retention 0 keeps every partition")
	done, err := f.admin.MaintainTracking(ctx, 3, 7*24*time.Hour, time.Hour)
	require.NoError(t, err)
	for _, table := range []string{"node_tx_status", "node_tx_identities"} {
		require.False(t, exists(partitionName(table, today.AddDate(0, 0, -10))), "%s: day -10 is past 7 days of retention", table)
		require.False(t, exists(partitionName(table, today.AddDate(0, 0, -8))), "%s: day -8 ended more than 7 days ago", table)
		require.True(t, exists(partitionName(table, today.AddDate(0, 0, -6))), "%s: day -6 is inside the window", table)
		for d := -1; d <= 3; d++ {
			require.True(t, exists(partitionName(table, today.AddDate(0, 0, d))), "%s: day %d must exist ahead", table, d)
		}
	}
	require.Len(t, done.Dropped, 5)
	require.False(t, exists(orphan), "a detached, expired partition is dropped too")
	var rows int
	require.NoError(t, f.exec.pool.conn.QueryRow(`SELECT count(*) FROM node_tx_status`).Scan(&rows))
	require.Equal(t, 1, rows, "only the expired days' rows left")
	again, err := f.admin.MaintainTracking(ctx, 3, 7*24*time.Hour, time.Hour)
	require.NoError(t, err)
	require.Empty(t, again.Created)
	require.Empty(t, again.Dropped)
}

// The same principal resending with another visibility sender is a conflict,
// like another visibility list (the binding's visibility is immutable).
func TestAdmissionRefusesChangedVisibility(t *testing.T) {
	f := newTrackingFixture(t)
	p := newPrincipal()
	h := randomBytes(32)
	a := p.admit(h)
	a.VisibleTo, a.VisibleSender = []string{"did:test:r"}, "did:test:sender"
	require.Equal(t, AdmitInserted, f.admitOne(0, a).Outcome)
	other := p.admit(h)
	other.VisibleTo, other.VisibleSender = []string{"did:test:r"}, "did:test:someone-else"
	require.Equal(t, AdmitConflict, f.admitOne(0, other).Outcome)
	other.VisibleTo, other.VisibleSender = []string{"did:test:x"}, "did:test:sender"
	require.Equal(t, AdmitConflict, f.admitOne(0, other).Outcome)
	same := p.admit(h)
	same.VisibleTo, same.VisibleSender = []string{"did:test:r"}, "did:test:sender"
	require.Equal(t, AdmitResubmitted, f.admitOne(0, same).Outcome)
	// The runtime role cannot rewrite the binding's identity.
	var privileges int
	require.NoError(t, f.exec.pool.conn.QueryRow(`SELECT count(*) FROM information_schema.column_privileges WHERE grantee = 'privacy_proxy_app' AND table_name = 'node_tx_binding' AND privilege_type = 'UPDATE' AND column_name IN ('tx_hash', 'principal_id', 'org_id', 'signer', 'nonce', 'visible_to', 'visible_sender', 'incarnation', 'admit_xid')`).Scan(&privileges))
	require.Equal(t, 0, privileges)
}

// One malformed admission is refused on its own and never fails the requests
// batched with it (code review B3a #1); a dropped final is not answered as
// executed, even to its owner.
func TestAdmissionRefusalsAreIndividual(t *testing.T) {
	f := newTrackingFixture(t)
	p := newPrincipal()
	bad := p.admit(randomBytes(32))
	bad.Nonce = 1 << 63
	good := p.admit(randomBytes(32))
	results, err := f.exec.AdmitBatch(context.Background(), f.inc, TrackLimits{}, []TrackAdmission{bad, good})
	require.NoError(t, err)
	require.Equal(t, AdmitInvalid, results[0].Outcome)
	require.Equal(t, AdmitInserted, results[1].Outcome)
	dropped := randomBytes(32)
	require.Equal(t, AdmitInserted, f.admitOne(0, p.admit(dropped)).Outcome)
	require.True(t, f.finalize(p, dropped, TrackDropped))
	require.Equal(t, AdmitConflict, f.admitOne(0, p.admit(dropped)).Outcome, "a dropped transaction can never execute")
	f.quotaConsistent()
}

// TestPendingQuotaPerPrincipalIsFair is the per-principal half of G63 (B4):
// one principal flooding admissions is capped at its own limit while every
// other principal is still admitted; Δ = 0 retries are never refused by either
// limit; and pending_quota_principal.used equals count(pending) per principal
// after every committed batch, for every transition.
func TestPendingQuotaPerPrincipalIsFair(t *testing.T) {
	f := newTrackingFixture(t)
	ctx := context.Background()
	limits := TrackLimits{Global: 10, Principal: 4}

	t.Run("a flooding principal is capped; others are still admitted", func(t *testing.T) {
		f.reset()
		flood, quiet := newPrincipal(), newPrincipal()
		// Several instances admit the flooding principal's batches at once.
		var pools []*ExecDB
		for i := 0; i < 3; i++ {
			pool, err := NewWithoutMigrate(f.execURL)
			require.NoError(t, err)
			t.Cleanup(func() { pool.Close() })
			pools = append(pools, NewExecHandle(pool))
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		counts := map[AdmitOutcome]int{}
		for i := 0; i < 9; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				batch := []TrackAdmission{flood.admit(randomBytes(32)), flood.admit(randomBytes(32)), flood.admit(randomBytes(32))}
				results, err := pools[i%3].AdmitBatch(ctx, f.inc, limits, batch)
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				defer mu.Unlock()
				for _, r := range results {
					counts[r.Outcome]++
				}
			}(i)
		}
		wg.Wait()
		require.Equal(t, 4, counts[AdmitInserted], "the flooding principal holds exactly its own limit")
		require.Equal(t, 23, counts[AdmitPrincipalOverLimit])
		f.principalQuotaConsistent()
		// The other principal is not blocked by the flood.
		for i := 0; i < 4; i++ {
			require.Equal(t, AdmitInserted, f.admitWith(limits, quiet.admit(randomBytes(32))).Outcome)
		}
		require.Equal(t, AdmitPrincipalOverLimit, f.admitWith(limits, quiet.admit(randomBytes(32))).Outcome)
		// A third principal meets the global limit (8 of 10 used): two more fit.
		third := newPrincipal()
		require.Equal(t, AdmitInserted, f.admitWith(limits, third.admit(randomBytes(32))).Outcome)
		require.Equal(t, AdmitInserted, f.admitWith(limits, third.admit(randomBytes(32))).Outcome)
		require.Equal(t, AdmitOverLimit, f.admitWith(limits, third.admit(randomBytes(32))).Outcome)
		require.EqualValues(t, 10, f.principalQuotaConsistent())
	})

	t.Run("retries of charged hashes are never refused; reorg back may exceed both", func(t *testing.T) {
		f.reset()
		p := newPrincipal()
		var hashes [][]byte
		for i := 0; i < 4; i++ {
			h := randomBytes(32)
			require.Equal(t, AdmitInserted, f.admitWith(limits, p.admit(h)).Outcome)
			hashes = append(hashes, h)
		}
		require.Equal(t, AdmitResubmitted, f.admitWith(limits, p.admit(hashes[0])).Outcome, "a same-H retry at the cap is Δ 0")
		require.True(t, f.transition(hashes[1], TrackPending, TrackProvisional, 0))
		require.Equal(t, AdmitInserted, f.admitWith(limits, p.admit(randomBytes(32))).Outcome, "inclusion released the principal's slot")
		require.True(t, f.transition(hashes[1], TrackProvisional, TrackPending, 0), "a reorg back is never refused")
		require.EqualValues(t, 5, f.principalQuotaConsistent())
		require.Equal(t, AdmitPrincipalOverLimit, f.admitWith(limits, p.admit(randomBytes(32))).Outcome)
		// Revival is a new admission for the cap too.
		require.True(t, f.transition(hashes[2], TrackPending, TrackRenewalStopped, 0))
		require.Equal(t, AdmitPrincipalOverLimit, f.admitWith(limits, p.admit(hashes[2])).Outcome, "4 still pending: the revival needs a fifth slot")
		require.True(t, f.finalize(p, hashes[3], TrackIncluded))
		require.True(t, f.finalize(p, hashes[0], TrackIncluded))
		require.Equal(t, AdmitRevived, f.admitWith(limits, p.admit(hashes[2])).Outcome)
		released, err := f.exec.ReleaseUndelivered(ctx, f.inc, hashes[2], uuid.New())
		require.NoError(t, err)
		require.False(t, released, "a revival is not a fresh insert")
		fresh := p.admit(randomBytes(32))
		require.Equal(t, AdmitInserted, f.admitWith(limits, fresh).Outcome)
		released, err = f.exec.ReleaseUndelivered(ctx, f.inc, fresh.Hash, fresh.ContextID)
		require.NoError(t, err)
		require.True(t, released)
		f.principalQuotaConsistent()
	})

	t.Run("one batch mixing principals refuses only the excess", func(t *testing.T) {
		f.reset()
		p, q := newPrincipal(), newPrincipal()
		var batch []TrackAdmission
		for i := 0; i < 6; i++ {
			batch = append(batch, p.admit(randomBytes(32)), q.admit(randomBytes(32)))
		}
		results, err := f.exec.AdmitBatch(ctx, f.inc, limits, batch)
		require.NoError(t, err)
		per := map[uuid.UUID]map[AdmitOutcome]int{p.id: {}, q.id: {}}
		for i, r := range results {
			per[batch[i].PrincipalID][r.Outcome]++
		}
		require.Equal(t, 4, per[p.id][AdmitInserted])
		require.Equal(t, 4, per[q.id][AdmitInserted])
		require.Equal(t, 2, per[p.id][AdmitPrincipalOverLimit])
		require.Equal(t, 2, per[q.id][AdmitPrincipalOverLimit])
		require.EqualValues(t, 8, f.principalQuotaConsistent())
	})

	t.Run("an organization's principals together are capped; other organizations are still admitted", func(t *testing.T) {
		f.reset()
		orgLimits := TrackLimits{Global: 10, Principal: 4, Org: 6}
		org := uuid.New()
		a, b := principal{id: uuid.New(), org: org, signer: randomBytes(20)}, principal{id: uuid.New(), org: org, signer: randomBytes(20)}
		other := newPrincipal()
		for i := 0; i < 4; i++ {
			require.Equal(t, AdmitInserted, f.admitWith(orgLimits, a.admit(randomBytes(32))).Outcome)
		}
		require.Equal(t, AdmitInserted, f.admitWith(orgLimits, b.admit(randomBytes(32))).Outcome)
		require.Equal(t, AdmitInserted, f.admitWith(orgLimits, b.admit(randomBytes(32))).Outcome)
		require.Equal(t, AdmitOrgOverLimit, f.admitWith(orgLimits, b.admit(randomBytes(32))).Outcome, "the organization holds its own limit")
		for i := 0; i < 4; i++ {
			require.Equal(t, AdmitInserted, f.admitWith(orgLimits, other.admit(randomBytes(32))).Outcome, "another organization is not blocked")
		}
		require.Equal(t, AdmitPrincipalOverLimit, f.admitWith(orgLimits, other.admit(randomBytes(32))).Outcome)
		require.EqualValues(t, 10, f.principalQuotaConsistent())
	})
}

// A per-principal counter that drifted low (an older release kept admitting
// after migration 004) is recounted under its lock when a −1 would take it
// below zero; the batch still applies.
func TestPrincipalQuotaDriftIsRecounted(t *testing.T) {
	f := newTrackingFixture(t)
	p := newPrincipal()
	a, b := randomBytes(32), randomBytes(32)
	require.Equal(t, AdmitInserted, f.admitOne(0, p.admit(a)).Outcome)
	require.Equal(t, AdmitInserted, f.admitOne(0, p.admit(b)).Outcome)
	_, err := f.exec.pool.conn.Exec(`UPDATE pending_quota_principal SET used = 0 WHERE principal_id = $1`, p.id.String())
	require.NoError(t, err)
	_, err = f.exec.pool.conn.Exec(`UPDATE pending_quota_org SET used = 0 WHERE org_id = $1`, p.org.String())
	require.NoError(t, err)
	require.True(t, f.finalize(p, a, TrackIncluded), "a drifted counter never blocks finality")
	f.principalQuotaConsistent()
	// Drift upwards (undetectable by the writers) is repaired by the
	// maintenance pass, which also deletes counters at zero.
	_, err = f.exec.pool.conn.Exec(`UPDATE pending_quota_principal SET used = 9 WHERE principal_id = $1`, p.id.String())
	require.NoError(t, err)
	idle := newPrincipal()
	_, err = f.exec.pool.conn.Exec(`INSERT INTO pending_quota_principal (principal_id, used) VALUES ($1, 0)`, idle.id.String())
	require.NoError(t, err)
	_, err = f.admin.MaintainTracking(context.Background(), 1, 0, time.Hour)
	require.NoError(t, err)
	f.principalQuotaConsistent()
	var zero int
	require.NoError(t, f.exec.pool.conn.QueryRow(`SELECT (SELECT count(*) FROM pending_quota_principal WHERE used = 0) + (SELECT count(*) FROM pending_quota_org WHERE used = 0)`).Scan(&zero))
	require.Zero(t, zero, "counters at zero are deleted")
}

func (f *trackingFixture) admitWith(limits TrackLimits, a TrackAdmission) AdmitResult {
	f.t.Helper()
	results, err := f.exec.AdmitBatch(context.Background(), f.inc, limits, []TrackAdmission{a})
	require.NoError(f.t, err)
	return results[0]
}

// principalQuotaConsistent asserts the global and every per-principal
// invariant and returns the global count.
func (f *trackingFixture) principalQuotaConsistent() int64 {
	f.t.Helper()
	used := f.quotaConsistent()
	mismatched, err := f.exec.PendingQuotaMismatches(context.Background())
	require.NoError(f.t, err)
	require.Zero(f.t, mismatched, "the principal and organization shares must equal count(pending rows) per key")
	return used
}
