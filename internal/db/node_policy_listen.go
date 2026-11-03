package db

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// NodePolicyListenerApplication is the application_name of the listener's
// database session.
const NodePolicyListenerApplication = "ops-node-policy-listener"

const (
	nodePolicyChangedChannel = "node_policy_changed"
	nodePolicyAppliedChannel = "node_policy_applied"
	// nodePolicyListenProbe is how long the listener waits for a notification
	// before pinging its session, so a dead connection is noticed.
	nodePolicyListenProbe = 30 * time.Second
)

// NodePolicyListener receives the fact stream's notifications (RD-1411).
// Callbacks run on the listener's goroutine and must not block.
type NodePolicyListener struct {
	Changed   func(version uint64) // a fact change committed at version
	Applied   func(version uint64) // the publisher recorded the node's acknowledgement of version
	Connected func()               // (re)subscribed: notifications sent meanwhile may have been missed
	Lost      func(error)          // the subscription failed; it is retried
}

// ListenNodePolicy subscribes to fact changes and node acknowledgements on its
// own database session (not a pool connection) until ctx ends, resubscribing
// after any failure with a backoff from 100 ms to 5 s. Notifications are a
// hint: publication and the status probe keep their timers as fallback.
func (d *DB) ListenNodePolicy(ctx context.Context, l NodePolicyListener) error {
	backoff := 100 * time.Millisecond
	for {
		started := time.Now()
		err := d.listenNodePolicyOnce(ctx, l)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if l.Lost != nil {
			l.Lost(err)
		}
		if time.Since(started) > time.Minute {
			backoff = 100 * time.Millisecond
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, 5*time.Second)
	}
}

func (d *DB) listenNodePolicyOnce(ctx context.Context, l NodePolicyListener) error {
	cfg, err := parseConfigUTC(d.databaseURL)
	if err != nil {
		return err
	}
	cfg.RuntimeParams["application_name"] = NodePolicyListenerApplication
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	for _, channel := range []string{nodePolicyChangedChannel, nodePolicyAppliedChannel} {
		if _, err := conn.Exec(ctx, "LISTEN "+channel); err != nil {
			return err
		}
	}
	if l.Connected != nil {
		l.Connected()
	}
	for {
		wait, cancel := context.WithTimeout(ctx, nodePolicyListenProbe)
		n, err := conn.WaitForNotification(wait)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, context.DeadlineExceeded) || pgconn.Timeout(err) {
				ping, cancel := context.WithTimeout(ctx, 5*time.Second)
				err := conn.Ping(ping)
				cancel()
				if err != nil {
					return err
				}
				continue
			}
			return err
		}
		version, _ := strconv.ParseUint(n.Payload, 10, 64)
		switch n.Channel {
		case nodePolicyChangedChannel:
			if l.Changed != nil {
				l.Changed(version)
			}
		case nodePolicyAppliedChannel:
			if l.Applied != nil {
				l.Applied(version)
			}
		}
	}
}
