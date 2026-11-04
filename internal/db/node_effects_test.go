package db

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/nodepolicy"
	"privacy-proxy/internal/rbac"
)

var effectsNetwork = nodepolicy.Network{ChainID: 31337, DeploymentID: "effects-" + uuid.NewString()}

// effectsFixture: an organisation with a deploy group and a member deployer.
type effectsFixture struct {
	d                *DB
	network          nodepolicy.Network
	org, deployer    string
	deployerDID      string
	address, txHash  string
	visibleRecipient string
}

func newEffectsFixture(t *testing.T) *effectsFixture {
	t.Helper()
	d := setupTestDB(t)
	t.Cleanup(func() { d.Close() })
	ctx := t.Context()
	user, org := cacheGenFixtures(t, d, ctx)
	group := &rbac.Group{ID: uuid.NewString(), OrgID: org, Slug: "deployers-" + uuid.NewString(), Name: "Deployers", Path: "deployers"}
	require.NoError(t, d.CreateGroup(ctx, group))
	_, err := d.Conn().ExecContext(ctx, `INSERT INTO group_access(id,group_id,allowed_methods,claims) VALUES($1,$2,$3,$4)`, uuid.NewString(), group.ID, []string{"eth_sendRawTransaction"}, []string{"deploy"})
	require.NoError(t, err)
	require.NoError(t, d.CreateMembership(ctx, &rbac.UserMembership{ID: uuid.NewString(), UserID: user, GroupID: group.ID, Source: rbac.MembershipSourceAdmin}))
	// Replay floors intentionally survive ResetTestDatabase. Give each fixture
	// its own network so retention tests cannot change a later test's floor.
	network := nodepolicy.Network{ChainID: 31337, DeploymentID: "effects-" + uuid.NewString()}
	require.NoError(t, d.EnsureNodeTxEffectsFloor(ctx, network))
	return &effectsFixture{d: d, network: network, org: org, deployer: user, deployerDID: "did:test:deployer", address: "0x" + strings.Repeat("ab", 20), txHash: lowerHex(randomBytes(32)), visibleRecipient: "did:test:recipient"}
}

func (f *effectsFixture) effects(block uint64, ownership, visibility bool) NodeTxEffects {
	return NodeTxEffects{TransactionHash: f.txHash, PrincipalID: f.deployer, OrgID: f.org, BlockNumber: block,
		Ownership: ownership, Created: []nodepolicy.CreatedContract{{Address: f.address, OrgID: f.org, PrincipalID: f.deployer}},
		Visibility: visibility, VisibleTo: []string{f.visibleRecipient}, VisibleSender: f.deployerDID}
}

func (f *effectsFixture) counts(t *testing.T) (contracts, grants, visibility int) {
	t.Helper()
	require.NoError(t, f.d.Conn().QueryRow(`SELECT
  (SELECT count(*) FROM contracts WHERE lower(address) = $1),
  (SELECT count(*) FROM contract_grants g JOIN contracts c ON c.id = g.contract_id WHERE lower(c.address) = $1),
  (SELECT count(*) FROM pending_tx_visibility WHERE tx_hash = $2)`, f.address, f.txHash).Scan(&contracts, &grants, &visibility))
	return
}

// TestEffectsAppliedExactlyOnceAcrossDatabases is G48 (main-database half):
// re-running the effects transaction after a crash before the tracking
// finalize — repeatedly — leaves one ownership row, one grant and one
// visibility rule.
func TestEffectsAppliedExactlyOnceAcrossDatabases(t *testing.T) {
	f := newEffectsFixture(t)
	ctx := t.Context()
	first, err := f.d.ApplyNodeTxEffects(ctx, f.network, f.effects(7, true, true))
	require.NoError(t, err)
	require.True(t, first.OwnershipApplied && first.VisibilityApplied)
	for i := 0; i < 3; i++ {
		again, err := f.d.ApplyNodeTxEffects(ctx, f.network, f.effects(7, true, true))
		require.NoError(t, err)
		require.False(t, again.OwnershipApplied || again.VisibilityApplied, "a replay applies nothing")
	}
	contracts, grants, visibility := f.counts(t)
	require.Equal(t, [3]int{1, 1, 1}, [3]int{contracts, grants, visibility})
	stored, err := f.d.GetContractByAddress(ctx, f.org, f.address)
	require.NoError(t, err)
	require.Equal(t, f.deployer, *stored.DeployedByUserID)
	var markers int
	require.NoError(t, f.d.Conn().QueryRow(`SELECT count(*) FROM node_tx_effects_applied`).Scan(&markers))
	require.Equal(t, 1, markers, "only transactions with side effects get a marker")
	none, err := f.d.ApplyNodeTxEffects(ctx, f.network, NodeTxEffects{TransactionHash: lowerHex(randomBytes(32)), PrincipalID: f.deployer, OrgID: f.org, BlockNumber: 8})
	require.NoError(t, err)
	require.False(t, none.OwnershipApplied || none.VisibilityApplied)
	require.NoError(t, f.d.Conn().QueryRow(`SELECT count(*) FROM node_tx_effects_applied`).Scan(&markers))
	require.Equal(t, 1, markers, "a transaction without side effects writes nothing to the main database")
}

// TestRevokedGrantNotReinsertedByReplayOrRecovery and the floor cases are G57.
func TestRevokedGrantNotReinsertedByReplayOrRecovery(t *testing.T) {
	f := newEffectsFixture(t)
	ctx := t.Context()
	_, err := f.d.ApplyNodeTxEffects(ctx, f.network, f.effects(5, true, false))
	require.NoError(t, err)
	_, err = f.d.Conn().ExecContext(ctx, `DELETE FROM contract_grants WHERE contract_id = (SELECT id FROM contracts WHERE lower(address) = $1)`, f.address)
	require.NoError(t, err) // an administrator revokes the deployer grant
	for _, e := range []NodeTxEffects{f.effects(5, true, false), f.effects(5, true, true)} {
		_, err := f.d.ApplyNodeTxEffects(ctx, f.network, e) // replay, then a normal finalize
		require.NoError(t, err)
	}
	_, grants, visibility := f.counts(t)
	require.Equal(t, 0, grants, "a revoked grant stays revoked")
	require.Equal(t, 1, visibility, "the effect not yet applied still is")
}

func TestReplayFloorSurvivesRetentionIncrease(t *testing.T) {
	f := newEffectsFixture(t)
	ctx := t.Context()
	_, err := f.d.ApplyNodeTxEffects(ctx, f.network, f.effects(5, true, false))
	require.NoError(t, err)
	_, err = f.d.Conn().ExecContext(ctx, `DELETE FROM contract_grants`)
	require.NoError(t, err)
	// Retention prunes the marker and raises the floor to its block.
	pruned, err := f.d.PruneNodeTxEffects(ctx, f.network, time.Now().Add(time.Hour))
	require.NoError(t, err)
	require.EqualValues(t, 1, pruned)
	floor, err := f.d.NodeTxEffectsFloor(ctx, f.network)
	require.NoError(t, err)
	require.EqualValues(t, 5, floor)
	// Retention raised (7 → 30 days → forever): a later prune with an older
	// cutoff never lowers the floor, so the old finalizer and an old-manifest
	// recovery stay refused.
	_, err = f.d.PruneNodeTxEffects(ctx, f.network, time.Now().Add(-30*24*time.Hour))
	require.NoError(t, err)
	for _, e := range []NodeTxEffects{f.effects(5, true, true), f.effects(4, true, false)} {
		_, err := f.d.ApplyNodeTxEffects(ctx, f.network, e)
		require.ErrorIs(t, err, ErrBelowReplayFloor)
	}
	_, grants, _ := f.counts(t)
	require.Equal(t, 0, grants)
	// The floor is never lowered, deleted or truncated, and a network without
	// one refuses.
	for _, stmt := range []string{`UPDATE node_tx_effects_floor SET floor_block = 0`, `DELETE FROM node_tx_effects_floor`, `TRUNCATE node_tx_effects_floor CASCADE`} {
		_, err := f.d.Conn().ExecContext(ctx, stmt)
		require.Error(t, err, stmt)
	}
	_, err = f.d.ApplyNodeTxEffects(ctx, nodepolicy.Network{ChainID: 1, DeploymentID: "unregistered"}, f.effects(9, true, false))
	require.ErrorIs(t, err, ErrReplayFloorMissing)
}

// TestFinalizerPausedAfterFloorReadVsCleanup (G57, Codex 5.2): a finalizer
// holding the floor (FOR SHARE) makes cleanup wait; a cleanup that raised the
// floor first makes the finalizer refuse.
func TestFinalizerPausedAfterFloorReadVsCleanup(t *testing.T) {
	f := newEffectsFixture(t)
	ctx := t.Context()
	key := []any{int64(f.network.ChainID), f.network.DeploymentID}

	// A finalizer paused after its floor read: cleanup cannot raise the floor.
	finalizer, err := f.d.Conn().BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = finalizer.Exec(`SELECT floor_block FROM node_tx_effects_floor WHERE chain_id = $1 AND deployment_id = $2 FOR SHARE`, key...)
	require.NoError(t, err)
	require.True(t, blockedOnLock(t, f.d, func(tx *Tx) error {
		_, err := tx.tx.ExecContext(ctx, `SELECT 1 FROM node_tx_effects_floor WHERE chain_id = $1 AND deployment_id = $2 FOR UPDATE`, key...)
		return err
	}), "cleanup waits for the finalizer's commit")
	require.NoError(t, finalizer.Commit())

	// A cleanup that raised the floor and has not committed yet: the finalizer
	// waits, then sees the new floor and refuses.
	cleanup, err := f.d.Conn().BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = cleanup.Exec(`UPDATE node_tx_effects_floor SET floor_block = 6 WHERE chain_id = $1 AND deployment_id = $2`, key...)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, err := f.d.ApplyNodeTxEffects(ctx, f.network, f.effects(6, true, true))
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("the finalizer did not wait for the cleanup: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	require.NoError(t, cleanup.Commit())
	require.ErrorIs(t, <-done, ErrBelowReplayFloor)
	contracts, grants, visibility := f.counts(t)
	require.Equal(t, [3]int{0, 0, 0}, [3]int{contracts, grants, visibility})
}

// TestEffectBitsClaimedAtomically is G67: an ownership-only recovery before,
// and concurrently with, a normal finalize applies ownership once and
// visibility once, whatever the interleaving and retries.
func TestEffectBitsClaimedAtomically(t *testing.T) {
	f := newEffectsFixture(t)
	ctx := t.Context()
	recovery, err := f.d.ApplyNodeTxEffects(ctx, f.network, f.effects(7, true, false))
	require.NoError(t, err)
	require.True(t, recovery.OwnershipApplied)
	normal, err := f.d.ApplyNodeTxEffects(ctx, f.network, f.effects(7, true, true))
	require.NoError(t, err)
	require.False(t, normal.OwnershipApplied, "ownership is never applied twice")
	require.True(t, normal.VisibilityApplied, "recovery left visibility to the finalize")

	f.txHash = lowerHex(randomBytes(32))
	f.address = "0x" + strings.Repeat("cd", 20)
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := f.d.ApplyNodeTxEffects(context.Background(), f.network, f.effects(8, true, i%2 == 0))
			if err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	contracts, grants, visibility := f.counts(t)
	require.Equal(t, [3]int{1, 1, 1}, [3]int{contracts, grants, visibility})
}

// TestComplianceClaimOnePerTx is G60: one travel-rule record per transaction.
func TestComplianceClaimOnePerTx(t *testing.T) {
	d := setupTestDB(t)
	t.Cleanup(func() { d.Close() })
	ctx := t.Context()
	user, org := cacheGenFixtures(t, d, ctx)
	beneficiary := "0x" + strings.Repeat("be", 20)
	record := func(age time.Duration) string {
		var id string
		require.NoError(t, d.Conn().QueryRowContext(ctx, `INSERT INTO travel_rule_records (org_id, originator_user_id, originator_data, beneficiary_data, transfer_type, beneficiary_address, amount_wei, amount_fiat, currency, expires_at, created_at)
 VALUES ($1, $2, '{}', '{}', 'eth', $3, '1000', 5000, 'usd', NOW() + interval '1 day', NOW() - $4 * interval '1 second') RETURNING id`, org, user, beneficiary, age.Seconds()).Scan(&id))
		return id
	}
	used := func(id string) bool {
		var at *time.Time
		require.NoError(t, d.Conn().QueryRowContext(ctx, `SELECT used_at FROM travel_rule_records WHERE id = $1`, id).Scan(&at))
		return at != nil
	}
	claim := func(hash string, userID string) string {
		r, err := d.ClaimTravelRuleRecordForTx(ctx, effectsNetwork.ChainID, effectsNetwork.DeploymentID, hash, org, userID, beneficiary, "native", 1000)
		require.NoError(t, err)
		if r == nil {
			return ""
		}
		return r.ID
	}

	r1 := record(time.Hour)
	h := lowerHex(randomBytes(32))
	require.Equal(t, r1, claim(h, user))
	r2 := record(0) // newer and unused
	require.Equal(t, r1, claim(h, user), "a retry re-finds its own record")
	require.False(t, used(r2), "and never consumes another")
	require.Equal(t, r2, claim(lowerHex(randomBytes(32)), user), "a different transaction cannot reuse r1")
	other := uuid.NewString()
	require.NoError(t, d.CreateUser(ctx, &rbac.User{ID: other, ExternalID: "did:test:other-" + other}))
	require.Equal(t, "", claim(h, other), "a bound record that does not cover the caller is no record")

	// Two concurrent calls for one transaction with two records available:
	// one claim, both return it, the loser's record stays unused.
	a, b := record(2*time.Hour), record(3*time.Hour)
	h2 := lowerHex(randomBytes(32))
	var wg sync.WaitGroup
	got := make([]string, 2)
	for i := range got {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got[i] = claim(h2, user)
		}(i)
	}
	wg.Wait()
	require.NotEmpty(t, got[0])
	require.Equal(t, got[0], got[1])
	require.True(t, used(got[0]))
	loser := a
	if got[0] == a {
		loser = b
	}
	require.False(t, used(loser), "the losing claim was rolled back")
}

// An address another organisation owns is never registered, but the
// transaction's other created contracts still are (security review B3a #4).
func TestOwnershipConflictSkipsOnlyTheConflictingAddress(t *testing.T) {
	f := newEffectsFixture(t)
	ctx := t.Context()
	_, otherOrg := cacheGenFixtures(t, f.d, ctx)
	taken := "0x" + strings.Repeat("ef", 20)
	require.NoError(t, f.d.CreateContract(ctx, &rbac.Contract{ID: uuid.NewString(), OrgID: otherOrg, Address: taken, Name: "taken"}))
	e := f.effects(9, true, false)
	e.Created = []nodepolicy.CreatedContract{{Address: taken, OrgID: f.org, PrincipalID: f.deployer}, {Address: f.address, OrgID: f.org, PrincipalID: f.deployer}}
	result, err := f.d.ApplyNodeTxEffects(ctx, f.network, e)
	require.NoError(t, err)
	require.Equal(t, 1, result.OwnershipConflicts)
	require.True(t, result.OwnershipApplied)
	contracts, grants, _ := f.counts(t)
	require.Equal(t, [2]int{1, 1}, [2]int{contracts, grants}, "the non-conflicting contract is registered with its grant")
	owner, err := f.d.GetContractByAddress(ctx, otherOrg, taken)
	require.NoError(t, err)
	require.NotNil(t, owner, "the other organisation keeps its address")
}

// A refused address is decided once: the marker keeps the conflict count with
// the ownership bit, so a retry after the effects committed (a crash, or a
// failed tracking finalize) reports the same refusal instead of "applied"
// (independent review, finding 4).
func TestOwnershipConflictCountSurvivesARetry(t *testing.T) {
	f := newEffectsFixture(t)
	ctx := t.Context()
	_, otherOrg := cacheGenFixtures(t, f.d, ctx)
	taken := "0x" + strings.Repeat("ee", 20)
	require.NoError(t, f.d.CreateContract(ctx, &rbac.Contract{ID: uuid.NewString(), OrgID: otherOrg, Address: taken, Name: "taken"}))
	e := f.effects(9, true, false)
	e.Created = []nodepolicy.CreatedContract{{Address: taken, OrgID: f.org, PrincipalID: f.deployer}, {Address: f.address, OrgID: f.org, PrincipalID: f.deployer}}
	first, err := f.d.ApplyNodeTxEffects(ctx, f.network, e)
	require.NoError(t, err)
	require.Equal(t, 1, first.OwnershipConflicts)
	again, err := f.d.ApplyNodeTxEffects(ctx, f.network, e)
	require.NoError(t, err)
	require.False(t, again.OwnershipApplied, "a retry applies nothing")
	require.Equal(t, 1, again.OwnershipConflicts, "a retry reports the refusal decided by the first run")
}

// The caller's before-commit step (the refusal's audit event) runs inside the
// effects transaction: when it fails nothing is applied, and the result it
// sees is the one that commits (independent review, finding 4).
func TestEffectsBeforeCommitFailureAppliesNothing(t *testing.T) {
	f := newEffectsFixture(t)
	ctx := t.Context()
	_, otherOrg := cacheGenFixtures(t, f.d, ctx)
	taken := "0x" + strings.Repeat("ed", 20)
	require.NoError(t, f.d.CreateContract(ctx, &rbac.Contract{ID: uuid.NewString(), OrgID: otherOrg, Address: taken, Name: "taken"}))
	e := f.effects(9, true, true)
	e.Created = []nodepolicy.CreatedContract{{Address: taken, OrgID: f.org, PrincipalID: f.deployer}, {Address: f.address, OrgID: f.org, PrincipalID: f.deployer}}
	var seen []NodeTxEffectsResult
	e.BeforeCommit = func(r NodeTxEffectsResult) error {
		seen = append(seen, r)
		return errors.New("audit buffer unavailable")
	}
	_, err := f.d.ApplyNodeTxEffects(ctx, f.network, e)
	require.Error(t, err)
	require.Len(t, seen, 1)
	require.Equal(t, 1, seen[0].OwnershipConflicts)
	contracts, grants, visibility := f.counts(t)
	require.Equal(t, [3]int{0, 0, 0}, [3]int{contracts, grants, visibility}, "nothing commits without the before-commit step")
	var markers int
	require.NoError(t, f.d.Conn().QueryRow(`SELECT count(*) FROM node_tx_effects_applied`).Scan(&markers))
	require.Zero(t, markers)
	e.BeforeCommit = func(r NodeTxEffectsResult) error { seen = append(seen, r); return nil }
	result, err := f.d.ApplyNodeTxEffects(ctx, f.network, e)
	require.NoError(t, err)
	require.Equal(t, seen[1], result, "the before-commit step sees the committed result")
	contracts, grants, visibility = f.counts(t)
	require.Equal(t, [3]int{1, 1, 1}, [3]int{contracts, grants, visibility})
}

// G19 (store half): renewal re-finds only the record bound to its own
// transaction — never claims an unused one, never another transaction's —
// and the binding, not the record's expiry, is the authorization (K13).
func TestBoundTravelRuleRecordIsFindOnly(t *testing.T) {
	d := setupTestDB(t)
	t.Cleanup(func() { d.Close() })
	ctx := t.Context()
	user, org := cacheGenFixtures(t, d, ctx)
	beneficiary := "0x" + strings.Repeat("be", 20)
	var unused string
	require.NoError(t, d.Conn().QueryRowContext(ctx, `INSERT INTO travel_rule_records (org_id, originator_user_id, originator_data, beneficiary_data, transfer_type, beneficiary_address, amount_wei, amount_fiat, currency, expires_at)
 VALUES ($1, $2, '{}', '{}', 'eth', $3, '1000', 5000, 'usd', NOW() + interval '1 day') RETURNING id`, org, user, beneficiary).Scan(&unused))
	bound := func(hash string) *compliance.TravelRuleRecord {
		r, err := d.BoundTravelRuleRecordForTx(ctx, effectsNetwork.ChainID, effectsNetwork.DeploymentID, hash, org, user, beneficiary, "native", 1000)
		require.NoError(t, err)
		return r
	}
	h := lowerHex(randomBytes(32))
	require.Nil(t, bound(h), "nothing bound yet: no record, and none is claimed")
	var usedAt *time.Time
	require.NoError(t, d.Conn().QueryRowContext(ctx, `SELECT used_at FROM travel_rule_records WHERE id = $1`, unused).Scan(&usedAt))
	require.Nil(t, usedAt, "a renewal lookup never consumes a record")
	claimed, err := d.ClaimTravelRuleRecordForTx(ctx, effectsNetwork.ChainID, effectsNetwork.DeploymentID, h, org, user, beneficiary, "native", 1000)
	require.NoError(t, err)
	require.NotNil(t, claimed)
	_, err = d.Conn().ExecContext(ctx, `UPDATE travel_rule_records SET expires_at = NOW() - interval '1 hour' WHERE id = $1`, claimed.ID)
	require.NoError(t, err)
	got := bound(h)
	require.NotNil(t, got, "the bound record is revalidated, its expiry is not re-checked")
	require.Equal(t, claimed.ID, got.ID)
	require.Nil(t, bound(lowerHex(randomBytes(32))), "another transaction cannot use it")
	r, err := d.BoundTravelRuleRecordForTx(ctx, effectsNetwork.ChainID, effectsNetwork.DeploymentID, h, org, user, beneficiary, "native", 6000)
	require.NoError(t, err)
	require.Nil(t, r, "a record that no longer covers the amount is no record")
}
