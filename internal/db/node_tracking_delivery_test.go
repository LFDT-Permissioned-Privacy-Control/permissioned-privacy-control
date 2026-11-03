package db

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// envelope sets an admission's fact floor and expiry.
func envelope(a TrackAdmission, minVersion uint64, expires time.Time) TrackAdmission {
	a.ContextID, a.EnvelopeHash, a.MinVersion, a.ExpiresAt = uuid.New(), randomBytes(32), minVersion, expires
	return a
}

// G26: A signed before B (lower floor and expiry), B saved and admitted first,
// A saved last: B is kept and stays current; A is answered as dominated, so
// its request sends A (the node answers a dominated attempt as success) but
// never acknowledges B's generation for it.
func TestEnvelopeUpsertIsMonotonicAndReturnsWinner(t *testing.T) {
	f := newTrackingFixture(t)
	p := newPrincipal()
	hash := randomBytes(32)
	base := time.Now().Add(5 * time.Minute).Truncate(time.Second)
	a := envelope(p.admit(hash), 7, base)
	b := envelope(p.admit(hash), 8, base.Add(time.Second))
	require.Equal(t, AdmitInserted, f.admitOne(0, b).Outcome)
	got := f.admitOne(0, a)
	require.Equal(t, AdmitKept, got.Outcome)
	require.Equal(t, b.ContextID, got.ContextID, "the stored winner is returned")
	require.EqualValues(t, 1, got.Generation)
	row, err := f.exec.LookupTracked(context.Background(), hash)
	require.NoError(t, err)
	require.Equal(t, b.ContextID, row.ContextID)
	require.EqualValues(t, 1, row.Generation)
	// The kept envelope may still reach the node (it is sent), so it is
	// recorded before transport, under the stored generation (G38).
	require.Equal(t, 1, f.count("node_tx_identities"))
	require.Contains(t, row.IssuedContexts, a.ContextID)
}

// G34: dominance (§4.8.3). Same-second V→V+1 replaces; equal floor and
// expiry is equivalent (kept, idempotent); a lower floor or expiry is kept;
// an incomparable attempt (higher floor, lower expiry: only after a database
// clock step) is refused for re-signing; the winner always meets the
// attempt's floor.
func TestDominanceUpsert(t *testing.T) {
	f := newTrackingFixture(t)
	base := time.Now().Add(5 * time.Minute).Truncate(time.Second)
	for _, test := range []struct {
		name          string
		stored, next  [2]int64 // floor, expiry offset (s)
		outcome       AdmitOutcome
		generation    int32
		nextIsCurrent bool
	}{
		{"higher floor same second", [2]int64{7, 0}, [2]int64{8, 0}, AdmitResubmitted, 2, true},
		{"later expiry", [2]int64{7, 0}, [2]int64{7, 1}, AdmitResubmitted, 2, true},
		{"equivalent", [2]int64{7, 0}, [2]int64{7, 0}, AdmitKept, 1, false},
		{"lower floor", [2]int64{8, 0}, [2]int64{7, 0}, AdmitKept, 1, false},
		{"earlier expiry", [2]int64{7, 1}, [2]int64{7, 0}, AdmitKept, 1, false},
		{"incomparable", [2]int64{7, 1}, [2]int64{8, 0}, AdmitIncomparable, 1, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f.reset()
			p := newPrincipal()
			hash := randomBytes(32)
			stored := envelope(p.admit(hash), uint64(test.stored[0]), base.Add(time.Duration(test.stored[1])*time.Second))
			next := envelope(p.admit(hash), uint64(test.next[0]), base.Add(time.Duration(test.next[1])*time.Second))
			require.Equal(t, AdmitInserted, f.admitOne(0, stored).Outcome)
			got := f.admitOne(0, next)
			require.Equal(t, test.outcome, got.Outcome)
			require.Equal(t, test.generation, got.Generation)
			row, err := f.exec.LookupTracked(context.Background(), hash)
			require.NoError(t, err)
			if test.nextIsCurrent {
				require.Equal(t, next.ContextID, row.ContextID)
				require.Equal(t, next.ContextID, got.ContextID)
			} else {
				require.Equal(t, stored.ContextID, row.ContextID)
				require.Equal(t, stored.ContextID, got.ContextID)
			}
			if got.Outcome != AdmitIncomparable {
				require.GreaterOrEqual(t, row.MinVersion, next.MinVersion, "the winner meets the attempt's fact floor")
			}
			f.quotaConsistent()
		})
	}
}

// G28 / G35: an acknowledgement is recorded against the boot id of the
// response that carried it, and only for the generation it delivered: an old
// send completing after a renewal, or a send answered by a boot that has
// since restarted, never marks the current generation delivered for the
// current boot.
func TestDeliveryAckFencedByBootAndGeneration(t *testing.T) {
	f := newTrackingFixture(t)
	ctx := context.Background()
	p := newPrincipal()
	hash := randomBytes(32)
	bootA, bootB := uuid.New(), uuid.New()
	first := p.admit(hash)
	require.Equal(t, AdmitInserted, f.admitOne(0, first).Outcome)
	second := envelope(p.admit(hash), 8, first.ExpiresAt.Add(time.Second))
	require.EqualValues(t, 2, f.admitOne(0, second).Generation)
	settled, err := f.exec.FlushAcks(ctx, f.inc, []TrackAck{{Hash: hash, Generation: 1, Boot: bootA}})
	require.NoError(t, err)
	require.True(t, settled[string(hash)], "a stale acknowledgement is settled without effect")
	row, err := f.exec.LookupTracked(ctx, hash)
	require.NoError(t, err)
	require.Nil(t, row.DeliveredGeneration, "generation 1's ack must not mark generation 2 delivered")
	// Generation 2 acknowledged by boot A; the node then restarts as boot B.
	_, err = f.exec.FlushAcks(ctx, f.inc, []TrackAck{{Hash: hash, Generation: 2, Boot: bootA}})
	require.NoError(t, err)
	row, err = f.exec.LookupTracked(ctx, hash)
	require.NoError(t, err)
	require.EqualValues(t, 2, *row.DeliveredGeneration)
	require.Equal(t, bootA, row.DeliveredBoot)
	require.False(t, row.DeliveredTo(bootB), "delivered to boot A is undelivered for boot B")
	require.True(t, row.DeliveredTo(bootA))
	require.Nil(t, row.ClaimExpires, "the acknowledgement releases the delivery claim")
}

// The admission claim names the node boot the request is delivering to; the
// keeper honours it only for that boot and until it expires.
func TestAdmissionClaimNamesTheBoot(t *testing.T) {
	f := newTrackingFixture(t)
	p := newPrincipal()
	hash := randomBytes(32)
	boot := uuid.New()
	a := p.admit(hash)
	a.ClaimBoot = boot
	require.Equal(t, AdmitInserted, f.admitOne(0, a).Outcome)
	row, err := f.exec.LookupTracked(context.Background(), hash)
	require.NoError(t, err)
	require.Equal(t, a.ClaimOwner, row.ClaimOwner)
	require.Equal(t, boot, row.ClaimBoot)
	require.NotNil(t, row.ClaimExpires)
	require.True(t, row.ClaimedFor(boot, row.DBNow))
	require.False(t, row.ClaimedFor(uuid.New(), row.DBNow), "a claim is void once the boot changes")
	require.False(t, row.ClaimedFor(boot, row.ClaimExpires.Add(time.Millisecond)), "a claim expires")
}

// G36 (store half): a renewal is fenced by the generation, context and
// admission it was decided on, records its generation in history with its
// reason and actor, and claims the row for the keeper.
func TestRenewalIsFencedAndRecorded(t *testing.T) {
	f := newTrackingFixture(t)
	ctx := context.Background()
	p := newPrincipal()
	hash := randomBytes(32)
	a := p.admit(hash)
	require.Equal(t, AdmitInserted, f.admitOne(0, a).Outcome)
	row, err := f.exec.LookupTracked(ctx, hash)
	require.NoError(t, err)
	keeper, boot := uuid.New(), uuid.New()
	renewal := TrackRenewal{Hash: hash, Generation: row.Generation, ContextID: row.ContextID, AdmitXid: row.AdmitXid,
		NewContextID: uuid.New(), EnvelopeHash: randomBytes(32), ExpiresAt: row.ExpiresAt.Add(time.Minute), MinVersion: 9,
		Reason: TrackReasonNodeRestarted, ClaimOwner: keeper, ClaimBoot: boot, ClaimTTL: 20 * time.Second}
	stale := renewal
	stale.Generation, stale.NewContextID = row.Generation+5, uuid.New()
	applied, err := f.exec.RenewBatch(ctx, f.inc, []TrackRenewal{stale})
	require.NoError(t, err)
	require.Equal(t, []bool{false}, applied, "a renewal decided on another generation does not apply")
	applied, err = f.exec.RenewBatch(ctx, f.inc, []TrackRenewal{renewal})
	require.NoError(t, err)
	require.Equal(t, []bool{true}, applied)
	again, err := f.exec.RenewBatch(ctx, f.inc, []TrackRenewal{renewal})
	require.NoError(t, err)
	require.Equal(t, []bool{false}, again, "a renewal decided on generation 1 cannot apply twice")
	row, err = f.exec.LookupTracked(ctx, hash)
	require.NoError(t, err)
	require.EqualValues(t, 2, row.Generation)
	require.Equal(t, renewal.NewContextID, row.ContextID)
	require.Contains(t, row.IssuedContexts, a.ContextID, "earlier contexts stay acceptable outcomes")
	require.Equal(t, keeper, row.ClaimOwner)
	require.Equal(t, boot, row.ClaimBoot)
	var reason, actor int16
	require.NoError(t, f.exec.pool.conn.QueryRow(`SELECT reason, actor FROM node_tx_identities WHERE tx_hash = $1 AND generation = 2`, hash).Scan(&reason, &actor))
	require.Equal(t, TrackReasonNodeRestarted, reason)
	require.Equal(t, trackActorSystem, actor)
	f.quotaConsistent()
	// A renewal never revives a stopped row.
	_, err = f.exec.ApplyTransitions(ctx, f.inc, []TrackTransition{{Hash: hash, From: TrackPending, To: TrackRenewalStopped, Generation: 2, Reason: TrackReasonMaxAge}})
	require.NoError(t, err)
	renewal.Generation, renewal.ContextID, renewal.NewContextID = 2, row.ContextID, uuid.New()
	applied, err = f.exec.RenewBatch(ctx, f.inc, []TrackRenewal{renewal})
	require.NoError(t, err)
	require.Equal(t, []bool{false}, applied)
	f.quotaConsistent()
}

func (f *trackingFixture) count(table string) int {
	f.t.Helper()
	var n int
	require.NoError(f.t, f.exec.pool.conn.QueryRow(`SELECT count(*) FROM `+table).Scan(&n))
	return n
}

// An inclusion under an older context (the current generation was recorded
// but its send was lost) does not mark the current generation delivered, so a
// reorg back to pending leaves it undelivered and the keeper renews it.
func TestInclusionRecordsDeliveryOnlyForTheExecutingContext(t *testing.T) {
	f := newTrackingFixture(t)
	ctx := context.Background()
	p := newPrincipal()
	hash := randomBytes(32)
	first := p.admit(hash)
	require.Equal(t, AdmitInserted, f.admitOne(0, first).Outcome)
	second := envelope(p.admit(hash), 8, first.ExpiresAt.Add(time.Second))
	require.EqualValues(t, 2, f.admitOne(0, second).Generation)
	boot := uuid.New()
	block := uint64(3)
	_, err := f.exec.ApplyTransitions(ctx, f.inc, []TrackTransition{{Hash: hash, From: TrackPending, To: TrackProvisional, BlockNumber: &block, Boot: boot, ContextID: first.ContextID}})
	require.NoError(t, err)
	require.True(t, f.transition(hash, TrackProvisional, TrackPending, 0))
	row, err := f.exec.LookupTracked(ctx, hash)
	require.NoError(t, err)
	require.False(t, row.DeliveredTo(boot), "generation 2 was never delivered")
}
