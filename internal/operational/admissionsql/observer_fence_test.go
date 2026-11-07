package admissionsql_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	a "privacy-proxy/internal/admission"
	"privacy-proxy/internal/creationcapture"
	f "privacy-proxy/internal/creationfacts"
)

// These tests use the real restricted application role and real PostgreSQL
// COMMIT. Channels stop the callback; a TEST-ONLY deferred constraint trigger
// stops COMMIT after the production final check. Neither is a production hook.
func TestObserverCaptureFenceActualPostgres(t *testing.T) {
	d := setupObserver(t)

	t.Run("application_can_read_and_take_shared_advisory_fence_but_not_row_lock", func(t *testing.T) {
		_, scope, _, _, _ := observerScope(t, d)
		conn, err := pgx.Connect(t.Context(), d.db.appDSN)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(context.Background())
		for _, sql := range []string{
			`UPDATE ops_admission_v2.creation_observer_state SET capture_ready=false WHERE network_key=$1`,
			`SELECT network_key FROM ops_admission_v2.creation_observer_state WHERE network_key=$1 FOR SHARE`,
		} {
			_, err := conn.Exec(t.Context(), sql, scope.Network[:])
			var denied *pgconn.PgError
			if !errors.As(err, &denied) || denied.Code != "42501" {
				t.Fatalf("restricted app unexpectedly has row-write/row-lock privilege: %v", err)
			}
		}
		tx, err := conn.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		var ready bool
		if err := tx.QueryRow(t.Context(), `SELECT ready FROM ops_admission_v2.creation_observer_state WHERE network_key=$1`, scope.Network[:]).Scan(&ready); err != nil {
			t.Fatal("app state SELECT", err)
		}
		if _, err := tx.Exec(t.Context(), `SELECT pg_advisory_xact_lock_shared($1::bigint)`, f.CaptureFence(f.Digest(scope.Network))); err != nil {
			t.Fatal("app shared advisory fence", err)
		}
	})

	for _, transition := range []string{"takeover", "quarantine"} {
		t.Run(transition+"_first_denies_stale_callback_and_all_effects", func(t *testing.T) {
			_, scope, m, _, floor := observerScope(t, d)
			snap := activeObserver(t, d, m, floor)
			i := capturedIntent(t, scope)
			i.Anchor.Timestamp = floor.Timestamp
			r := coverageRecord(m, snap, floor)
			prepareFenceTransition(t, d, transition, m)
			if err := runFenceTransition(t.Context(), d, transition, m, snap); err != nil {
				t.Fatal("transition first", err)
			}
			var calls atomic.Int32
			_, err := d.app.WithCoveredRawTransaction(t.Context(), scope, fenceBinding(r), func(raw a.RawTx) (a.CommitKind, error) {
				calls.Add(1)
				return a.CommitAllow, putFenceEffects(raw, scope, i, r)
			})
			if !errors.Is(err, a.ErrUnavailable) || calls.Load() != 0 {
				t.Fatalf("stale callback ran or was accepted: calls=%d err=%v", calls.Load(), err)
			}
			assertFenceEffects(t, d, scope, 0)
		})

		t.Run(transition+"_waits_for_app_before_final_check", func(t *testing.T) {
			_, scope, m, _, floor := observerScope(t, d)
			snap := activeObserver(t, d, m, floor)
			i := capturedIntent(t, scope)
			i.Anchor.Timestamp = floor.Timestamp
			r := coverageRecord(m, snap, floor)
			prepareFenceTransition(t, d, transition, m)
			entered, resume := make(chan struct{}), make(chan struct{})
			var release sync.Once
			defer release.Do(func() { close(resume) })
			appDone := make(chan error, 1)
			go func() {
				_, err := d.app.WithCoveredRawTransaction(t.Context(), scope, fenceBinding(r), func(raw a.RawTx) (a.CommitKind, error) {
					if err := putFenceEffects(raw, scope, i, r); err != nil {
						return 0, err
					}
					close(entered)
					select {
					case <-resume:
						return a.CommitAllow, nil
					case <-t.Context().Done():
						return 0, t.Context().Err()
					}
				})
				appDone <- err
			}()
			awaitFenceCallback(t, entered, appDone)
			transitionDone := make(chan error, 1)
			go func() { transitionDone <- runFenceTransition(t.Context(), d, transition, m, snap) }()
			waitCtx, cancel := context.WithTimeout(t.Context(), 600*time.Millisecond)
			defer cancel()
			pid := waitFenceLock(t, waitCtx, d.db.owner, f.CaptureFence(m.Network.Key), "ExclusiveLock", false, false)
			assertFenceSharedBlocker(t, d.db.owner, pid, f.CaptureFence(m.Network.Key))
			release.Do(func() { close(resume) })
			if err := <-appDone; err != nil {
				t.Fatal("app-first commit", err)
			}
			if err := <-transitionDone; err != nil {
				t.Fatal("exclusive transition after app commit", err)
			}
			assertFenceEffects(t, d, scope, 1)
			assertOldFenceDenied(t, d, scope, i, r)
		})

		t.Run(transition+"_waits_after_final_check_until_actual_commit", func(t *testing.T) {
			_, scope, m, _, floor := observerScope(t, d)
			snap := activeObserver(t, d, m, floor)
			i := capturedIntent(t, scope)
			i.Anchor.Timestamp = floor.Timestamp
			r := coverageRecord(m, snap, floor)
			prepareFenceTransition(t, d, transition, m)
			// The owner holds a DIFFERENT test gate. The deferred trigger cannot
			// execute until COMMIT, after both production durable-state checks.
			const gate int64 = 56178912340977
			installFenceCommitGate(t, d, gate)
			if _, err := d.db.owner.Exec(t.Context(), `SELECT pg_advisory_lock($1::bigint)`, gate); err != nil {
				t.Fatal(err)
			}
			var release sync.Once
			unlock := func() {
				release.Do(func() {
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					if _, err := d.db.owner.Exec(ctx, `SELECT pg_advisory_unlock($1::bigint)`, gate); err != nil {
						t.Error("release test-only COMMIT gate", err)
					}
				})
			}
			defer unlock()
			// One deadline covers BOTH lock observations, comfortably below the
			// production 1s lock timeout. Product transaction bounds are unchanged.
			waitCtx, cancel := context.WithTimeout(t.Context(), 600*time.Millisecond)
			defer cancel()
			appDone := make(chan error, 1)
			go func() {
				_, err := d.app.WithCoveredRawTransaction(t.Context(), scope, fenceBinding(r), func(raw a.RawTx) (a.CommitKind, error) {
					return a.CommitAllow, putFenceEffects(raw, scope, i, r)
				})
				appDone <- err
			}()
			appPID := waitFenceLock(t, waitCtx, d.db.owner, gate, "ExclusiveLock", false, true)
			assertFenceLockHeld(t, d.db.owner, appPID, f.CaptureFence(m.Network.Key), "ShareLock")
			transitionDone := make(chan error, 1)
			go func() { transitionDone <- runFenceTransition(t.Context(), d, transition, m, snap) }()
			transitionPID := waitFenceLock(t, waitCtx, d.db.owner, f.CaptureFence(m.Network.Key), "ExclusiveLock", false, false)
			var blockedByApp bool
			if err := d.db.owner.QueryRow(waitCtx, `SELECT $1::integer=ANY(pg_blocking_pids($2))`, appPID, transitionPID).Scan(&blockedByApp); err != nil || !blockedByApp {
				t.Fatal("actual COMMIT did not retain capture fence against transition", blockedByApp, err)
			}
			unlock()
			if err := <-appDone; err != nil {
				t.Fatal("actual app COMMIT", err)
			}
			if err := <-transitionDone; err != nil {
				t.Fatal("post-COMMIT transition", err)
			}
			assertFenceEffects(t, d, scope, 1)
			assertOldFenceDenied(t, d, scope, i, r)
		})
	}

	t.Run("normal_shared_header_advance_before_capacity_lock_allows_original_late_commit", func(t *testing.T) {
		_, scope, m, _, floor := observerScope(t, d)
		snap := activeObserver(t, d, m, floor)
		i := capturedIntent(t, scope)
		i.Anchor.Timestamp = floor.Timestamp
		r := coverageRecord(m, snap, floor)
		entered, resume := make(chan struct{}), make(chan struct{})
		var release sync.Once
		defer release.Do(func() { close(resume) })
		appDone := make(chan error, 1)
		go func() {
			_, err := d.app.WithCoveredRawTransaction(t.Context(), scope, fenceBinding(r), func(raw a.RawTx) (a.CommitKind, error) {
				close(entered) // No Put yet: app has not taken the capacity row lock.
				select {
				case <-resume:
					return a.CommitAllow, putFenceEffects(raw, scope, i, r)
				case <-t.Context().Done():
					return 0, t.Context().Err()
				}
			})
			appDone <- err
		}()
		awaitFenceCallback(t, entered, appDone)
		next := f.Header{Number: floor.Number + 1, Hash: common.HexToHash("0x1235"), Parent: floor.Hash, Timestamp: floor.Timestamp + 1}
		advanceCtx, cancel := context.WithTimeout(t.Context(), 600*time.Millisecond)
		defer cancel()
		after, err := d.observer.PublishObserverHeaders(advanceCtx, f.HeaderUpdate{Before: snap, Common: floor, Headers: []f.Header{next}, Tip: next})
		if err != nil || after.State.Head != next || after.Lease.CaptureEpoch != snap.Lease.CaptureEpoch {
			t.Fatal("normal prefix failed while app held shared fence before capacity lock", err)
		}
		release.Do(func() { close(resume) })
		if err := <-appDone; err != nil {
			t.Fatal("original ticket late COMMIT after normal prefix advance", err)
		}
		assertFenceEffects(t, d, scope, 1)
		var original []byte
		digest := r.Digest()
		if err := d.db.owner.QueryRow(t.Context(), `SELECT record_digest FROM ops_admission_v2.creation_capture_coverage WHERE network_key=$1 AND tx_hash=$2`, scope.Network[:], scope.Hash[:]).Scan(&original); err != nil || string(original) != string(digest[:]) {
			t.Fatal("normal head advance changed original coverage evidence", err)
		}
	})

	for _, mode := range []string{"callback_rollback", "cancel_after_effects"} {
		t.Run(mode+"_has_zero_effects_and_releases_fence", func(t *testing.T) {
			_, scope, m, _, floor := observerScope(t, d)
			snap := activeObserver(t, d, m, floor)
			i := capturedIntent(t, scope)
			i.Anchor.Timestamp = floor.Timestamp
			r := coverageRecord(m, snap, floor)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			rollback := errors.New("test-only callback rollback")
			_, err := d.app.WithCoveredRawTransaction(ctx, scope, fenceBinding(r), func(raw a.RawTx) (a.CommitKind, error) {
				if err := putFenceEffects(raw, scope, i, r); err != nil {
					return 0, err
				}
				if mode == "cancel_after_effects" {
					cancel()
					return a.CommitAllow, nil
				}
				return 0, rollback
			})
			if err == nil || mode == "callback_rollback" && !errors.Is(err, rollback) {
				t.Fatal("rollback/cancellation accepted", err)
			}
			assertFenceEffects(t, d, scope, 0)
			if err := d.observer.QuarantineObserver(t.Context(), snap, "uncertain-capture-trust"); err != nil {
				t.Fatal("aborted transaction retained shared capture fence", err)
			}
		})
	}
}

func fenceBinding(r f.CoverageRecord) a.CaptureCommitBinding {
	return a.CaptureCommitBinding{ObserverEpoch: r.ObserverEpoch, CaptureEpoch: r.CaptureEpoch, SourceSet: r.SourceSet}
}

func putFenceEffects(raw a.RawTx, scope a.Scope, i a.CreationIntent, r f.CoverageRecord) error {
	_, err := raw.PutOrigin(a.Origin{Network: scope.Network, Hash: scope.Hash, Actor: scope.Actor, Organization: scope.Organization, FirstAdmittedAt: i.CapturedAt, Primary: creationWitness(i, "observer-fence-original")})
	if err != nil {
		return err
	}
	_, err = raw.(a.CoveredCreationRawTx).PutCoveredCreationIntent(i, r)
	return err
}

func prepareFenceTransition(t *testing.T, d *observerDatabase, transition string, m creationcapture.Metadata) {
	t.Helper()
	if transition == "takeover" {
		if _, err := d.db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.creation_observer_state SET lease_expires=clock_timestamp()-interval'1 second' WHERE network_key=$1`, m.Network.Key[:]); err != nil {
			t.Fatal("owner-only fixture lease expiry", err)
		}
	}
}

func runFenceTransition(ctx context.Context, d *observerDatabase, transition string, m creationcapture.Metadata, snap f.ObserverSnapshot) error {
	if transition == "quarantine" {
		return d.observer.QuarantineObserver(ctx, snap, "uncertain-capture-trust")
	}
	_, err := d.observer.AcquireObserverLease(ctx, m.Network.Key, m.State, uuid.NewString(), m.SourceSet, m.Reference)
	return err
}

func awaitFenceCallback(t *testing.T, entered <-chan struct{}, done <-chan error) {
	t.Helper()
	select {
	case <-entered:
	case err := <-done:
		t.Fatal("transaction ended before callback barrier", err)
	case <-time.After(2 * time.Second):
		t.Fatal("callback barrier was not reached")
	}
}

func fenceLockParts(key int64) (int64, int64) {
	return int64(uint64(key) >> 32), int64(uint32(uint64(key)))
}

func waitFenceLock(t *testing.T, ctx context.Context, owner *pgx.Conn, key int64, mode string, granted, atCommit bool) int32 {
	t.Helper()
	hi, lo := fenceLockParts(key)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		var pid int32
		err := owner.QueryRow(ctx, `SELECT l.pid FROM pg_locks l JOIN pg_stat_activity s ON s.pid=l.pid
 WHERE l.locktype='advisory' AND l.classid::bigint=$1 AND l.objid::bigint=$2 AND l.objsubid=1
 AND l.mode=$3 AND l.granted=$4 AND (NOT $5 OR lower(btrim(s.query))='commit') LIMIT 1`, hi, lo, mode, granted, atCommit).Scan(&pid)
		if err == nil {
			t.Logf("observed PostgreSQL advisory lock: pid=%d mode=%s granted=%t actual_commit=%t", pid, mode, granted, atCommit)
			return pid
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("observe actual PostgreSQL fence wait", err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("actual PostgreSQL lock state not reached within test gate budget", ctx.Err())
		case <-tick.C:
		}
	}
}

func assertFenceLockHeld(t *testing.T, owner *pgx.Conn, pid int32, key int64, mode string) {
	t.Helper()
	hi, lo := fenceLockParts(key)
	var held bool
	if err := owner.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND classid::bigint=$2 AND objid::bigint=$3 AND objsubid=1 AND mode=$4 AND granted)`, pid, hi, lo, mode).Scan(&held); err != nil || !held {
		t.Fatalf("pid %d did not retain %s: held=%t err=%v", pid, mode, held, err)
	}
}

func assertFenceSharedBlocker(t *testing.T, owner *pgx.Conn, blocked int32, key int64) {
	t.Helper()
	hi, lo := fenceLockParts(key)
	var blocker int32
	if err := owner.QueryRow(t.Context(), `SELECT pid FROM pg_locks WHERE pid=ANY(pg_blocking_pids($1)) AND locktype='advisory' AND classid::bigint=$2 AND objid::bigint=$3 AND objsubid=1 AND mode='ShareLock' AND granted`, blocked, hi, lo).Scan(&blocker); err != nil {
		t.Fatal("exclusive transition was not blocked by actual app shared fence", err)
	}
}

func installFenceCommitGate(t *testing.T, d *observerDatabase, gate int64) {
	t.Helper()
	// Installed by the owner only in this disposable test database AFTER narrow
	// stores passed normal schema/privilege startup. No runtime grant is widened.
	if _, err := d.db.owner.Exec(t.Context(), fmt.Sprintf(`CREATE FUNCTION ops_admission_v2.test_only_capture_commit_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_catalog.pg_advisory_xact_lock(%d::bigint); RETURN NEW; END $$;
 CREATE CONSTRAINT TRIGGER test_only_capture_commit_gate AFTER INSERT ON ops_admission_v2.creation_capture_coverage DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ops_admission_v2.test_only_capture_commit_gate()`, gate)); err != nil {
		t.Fatal("install owner-only test COMMIT gate", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := d.db.owner.Exec(ctx, `DROP TRIGGER test_only_capture_commit_gate ON ops_admission_v2.creation_capture_coverage; DROP FUNCTION ops_admission_v2.test_only_capture_commit_gate()`); err != nil {
			t.Error("remove test-only COMMIT gate", err)
		}
	})
}

func assertFenceEffects(t *testing.T, d *observerDatabase, scope a.Scope, want int64) {
	t.Helper()
	for _, table := range []string{"qualified_tx_origins", "creation_plans", "creation_authority_refs", "creation_work", "creation_capture_coverage"} {
		var count int64
		if err := d.db.owner.QueryRow(t.Context(), `SELECT count(*) FROM ops_admission_v2.`+table+` WHERE network_key=$1 AND tx_hash=$2`, scope.Network[:], scope.Hash[:]).Scan(&count); err != nil || count != want {
			t.Fatalf("durable %s effects=%d want=%d err=%v", table, count, want, err)
		}
	}
	var work, plans, planBytes, wallet, factory, coverage, coverageBytes int64
	if err := d.db.owner.QueryRow(t.Context(), `SELECT work_count,plan_count,plan_bytes,wallet_ref_count,factory_ref_count,capture_coverage_count,capture_coverage_bytes FROM ops_admission_v2.creation_capacity WHERE network_key=$1`, scope.Network[:]).Scan(&work, &plans, &planBytes, &wallet, &factory, &coverage, &coverageBytes); err != nil {
		t.Fatal(err)
	}
	if work != want || plans != want || factory != want || coverage != want || wallet != 0 || (want == 0 && (planBytes != 0 || coverageBytes != 0)) || (want == 1 && (planBytes <= 0 || coverageBytes <= 0)) {
		t.Fatalf("capacity effects not atomic: work=%d plans=%d bytes=%d wallet=%d factory=%d coverage=%d coverageBytes=%d want=%d", work, plans, planBytes, wallet, factory, coverage, coverageBytes, want)
	}
}

func assertOldFenceDenied(t *testing.T, d *observerDatabase, scope a.Scope, i a.CreationIntent, r f.CoverageRecord) {
	t.Helper()
	iScope := scope
	iScope.Hash = common.HexToHash("0xfefefefe")
	i = capturedIntent(t, iScope)
	i.Anchor.Timestamp = r.HighWater.Timestamp
	if err := commitCovered(t.Context(), d.app, iScope, i, r); !errors.Is(err, a.ErrUnavailable) {
		t.Fatal("old capture binding survived exclusive transition", err)
	}
	for _, table := range []string{"qualified_tx_origins", "creation_plans", "creation_authority_refs", "creation_work", "creation_capture_coverage"} {
		var count int
		if err := d.db.owner.QueryRow(t.Context(), `SELECT count(*) FROM ops_admission_v2.`+table+` WHERE network_key=$1 AND tx_hash=$2`, iScope.Network[:], iScope.Hash[:]).Scan(&count); err != nil || count != 0 {
			t.Fatal("stale second hash leaked durable effects", table, count, err)
		}
	}
}
