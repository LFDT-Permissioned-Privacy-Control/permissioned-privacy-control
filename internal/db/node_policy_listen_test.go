package db

import (
	"context"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/nodepolicy"
)

type listenerEvents struct {
	changed, applied chan uint64
	connected        chan struct{}
	lost             chan error
}

func startNodePolicyListener(t *testing.T, d *DB) (*listenerEvents, context.CancelFunc) {
	t.Helper()
	e := &listenerEvents{changed: make(chan uint64, 64), applied: make(chan uint64, 64), connected: make(chan struct{}, 64), lost: make(chan error, 64)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = d.ListenNodePolicy(ctx, NodePolicyListener{
			Changed:   func(v uint64) { e.changed <- v },
			Applied:   func(v uint64) { e.applied <- v },
			Connected: func() { e.connected <- struct{}{} },
			Lost:      func(err error) { e.lost <- err },
		})
	}()
	t.Cleanup(func() { cancel(); <-done })
	return e, cancel
}

func waitFor[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		var zero T
		return zero
	}
}

// The listener behind G3/G4: a fact change and an acknowledgement each arrive
// as one event; after the connection is killed the listener reports the loss,
// resubscribes and announces that it may have missed notifications.
func TestNodePolicyListenerDeliversAndResubscribes(t *testing.T) {
	d := setupTestDB(t)
	ctx := context.Background()
	userID, _ := cacheGenFixtures(t, d, ctx)
	e, _ := startNodePolicyListener(t, d)
	waitFor(t, e.connected, "first subscription")

	if _, err := d.conn.ExecContext(ctx, `UPDATE users SET banned=NOT banned WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	version := uint64(policyVersion(t, d))
	if got := waitFor(t, e.changed, "change notification"); got != version {
		t.Fatalf("changed %d, want %d", got, version)
	}
	if err := d.AcknowledgeNodePolicy(ctx, "producer", nodepolicy.AppliedState{Version: version, Digest: strings.Repeat("a", 64), ExpiresAt: 2000}); err != nil {
		t.Fatal(err)
	}
	if got := waitFor(t, e.applied, "applied notification"); got != version {
		t.Fatalf("applied %d, want %d", got, version)
	}

	var killed int
	if err := d.conn.QueryRowContext(ctx, `SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1`, NodePolicyListenerApplication).Scan(&killed); err != nil || killed != 1 {
		t.Fatalf("terminated %d listener backends: %v", killed, err)
	}
	waitFor(t, e.lost, "connection loss")
	waitFor(t, e.connected, "resubscription")
	if _, err := d.conn.ExecContext(ctx, `UPDATE users SET banned=NOT banned WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	if got := waitFor(t, e.changed, "change after resubscription"); got != uint64(policyVersion(t, d)) {
		t.Fatalf("changed %d after resubscription", got)
	}
}
