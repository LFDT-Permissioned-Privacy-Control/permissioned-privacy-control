package ssosql

import (
	"context"
	"encoding/binary"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"io"
	"net"
	"net/url"
	m "privacy-proxy/internal/ssotransaction"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// commitCut forwards an owned plaintext PG fixture connection. It cuts the
// actual COMMIT CommandComplete AFTER PostgreSQL commits, BEFORE the client
// learns success; it is never used in product code or with external credentials.
type commitCut struct {
	listener    net.Listener
	armed       atomic.Bool
	cut         chan struct{}
	mu          sync.Mutex
	connections []net.Conn
	wg          sync.WaitGroup
}

func newCommitCut(t *testing.T, dsn string) (*commitCut, string) {
	t.Helper()
	u, e := url.Parse(dsn)
	if e != nil {
		t.Fatal(e)
	}
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p := &commitCut{listener: l, cut: make(chan struct{}, 1)}
	upstream := u.Host
	p.wg.Go(func() {
		for {
			client, e := l.Accept()
			if e != nil {
				return
			}
			server, e := net.DialTimeout("tcp", upstream, time.Second)
			if e != nil {
				client.Close()
				continue
			}
			p.mu.Lock()
			p.connections = append(p.connections, client, server)
			p.mu.Unlock()
			p.wg.Go(func() {
				defer client.Close()
				defer server.Close()
				go func() { _, _ = io.Copy(server, client); server.Close() }()
				for {
					var header [5]byte
					if _, e := io.ReadFull(server, header[:]); e != nil {
						return
					}
					n := int(binary.BigEndian.Uint32(header[1:]))
					if n < 4 || n > 1<<20 {
						return
					}
					body := make([]byte, n-4)
					if _, e := io.ReadFull(server, body); e != nil {
						return
					}
					if header[0] == 'C' && string(body) == "COMMIT\x00" && p.armed.CompareAndSwap(true, false) {
						p.cut <- struct{}{}
						return
					}
					if _, e := client.Write(header[:]); e != nil {
						return
					}
					if _, e := client.Write(body); e != nil {
						return
					}
				}
			})
		}
	})
	t.Cleanup(func() {
		l.Close()
		p.mu.Lock()
		for _, c := range p.connections {
			c.Close()
		}
		p.mu.Unlock()
		p.wg.Wait()
	})
	u.Host = l.Addr().String()
	return p, u.String()
}
func TestSSOCommitAndRecoveryControls(t *testing.T) {
	f := setup(t)
	t.Run("uncertain-commit-no-receipt-but-durable-effect", func(t *testing.T) {
		f.reset(t)
		proxy, dsn := newCommitCut(t, f.appDSN)
		s, e := OpenApp(t.Context(), Config{dsn, f.reg.scope(), f.clock})
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(s.Close)
		p := f.pending()
		proxy.armed.Store(true)
		r, e := s.InsertPending(t.Context(), p, noop)
		if !errors.Is(e, ErrUnavailable) || r.ID() != "" {
			t.Fatal("false known commit", e)
		}
		select {
		case <-proxy.cut:
		case <-time.After(time.Second):
			t.Fatal("no actual COMMIT cut")
		}
		var count int
		if e = f.owner.QueryRow(t.Context(), `SELECT count(*) FROM ops_sso_v1.transactions WHERE id=$1::uuid`, p.ID).Scan(&count); e != nil || count != 1 {
			t.Fatal("commit did not occur", count, e)
		}
		same, e := s.InsertPending(t.Context(), p, noop)
		if e != nil || same.ID() != p.ID || status(t, f).Usage.AllRows != 1 {
			t.Fatal("bounded idempotent reread", e)
		}
	})
	t.Run("cancellation-observed-at-state-lock-zero-effects", func(t *testing.T) {
		f.reset(t)
		s := f.app(t)
		lock, e := f.owner.Begin(t.Context())
		if e != nil {
			t.Fatal(e)
		}
		defer rollback(lock)
		if _, e = lock.Exec(t.Context(), `SELECT singleton FROM ops_sso_v1.state FOR UPDATE`); e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		p := f.pending()
		go func() { _, e := s.InsertPending(ctx, p, noop); done <- e }()
		watcher, e := pgx.Connect(t.Context(), f.ownerDSN)
		if e != nil {
			t.Fatal(e)
		}
		defer closeConn(watcher)
		deadline := time.Now().Add(400 * time.Millisecond)
		seen := false
		for time.Now().Before(deadline) {
			if e = watcher.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE NOT l.granted AND a.usename='sso_app')`).Scan(&seen); e != nil {
				t.Fatal(e)
			}
			if seen {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if !seen {
			t.Fatal("actual lock wait not observed")
		}
		cancel()
		if e = <-done; e == nil {
			t.Fatal("cancel accepted")
		}
		rollback(lock)
		if status(t, f).Usage.AllRows != 0 {
			t.Fatal("cancel effects")
		}
	})
	t.Run("reconfigure-only-unready-and-old-retention-immutable", func(t *testing.T) {
		f.reset(t)
		s := f.app(t)
		p := f.pending()
		a := insert(t, s, p)
		v := f.ready(p)
		prepare(t, s, a.Capture(), v)
		before, e := s.ReadFlow(t.Context(), p.ID, p.Recipient)
		if e != nil {
			t.Fatal(e)
		}
		limits := f.reg.Limits
		limits.AuditRetentionSeconds = 3600
		if e = Reconfigure(t.Context(), f.ownerDSN, f.reg.scope(), limits, true); !errors.Is(e, ErrConflict) {
			t.Fatal("ready reconfigure", e)
		}
		next := f.reg
		next.Epoch = uuid.NewString()
		if _, e = BeginRecovery(t.Context(), f.ownerDSN, f.reg.scope(), next, true); e != nil {
			t.Fatal(e)
		}
		if e = Reconfigure(t.Context(), f.ownerDSN, next.scope(), limits, true); e != nil {
			t.Fatal(e)
		}
		if e = FinalizeRecovery(t.Context(), f.ownerDSN, next.scope(), true); e != nil {
			t.Fatal(e)
		}
		var retain int64
		if e = f.owner.QueryRow(t.Context(), `SELECT retain_until_us FROM ops_sso_v1.transactions WHERE id=$1::uuid`, p.ID).Scan(&retain); e != nil || m.Micros(retain) != *before.RetainUntil {
			t.Fatal("retention rewritten", e)
		}
		if _, e = s.ReadFlow(t.Context(), p.ID, p.Recipient); e == nil {
			t.Fatal("oldscope rebound")
		}
	})
	t.Run("bounded-marker-before-null-union", func(t *testing.T) {
		f.reset(t)
		s := f.app(t)
		p := f.pending()
		a := insert(t, s, p)
		r := prepare(t, s, a.Capture(), f.ready(p))
		if _, e := s.Consume(t.Context(), r.Capture(), m.PreparedOutput{Digest: digest("output"), Bytes: 1}, noop); e != nil {
			t.Fatal(e)
		}
		if _, e := f.owner.Exec(t.Context(), `CREATE TEMP TABLE sso_bad AS SELECT * FROM ops_sso_v1.transactions`); e != nil {
			t.Fatal(e)
		}
		defer f.owner.Exec(t.Context(), `DROP TABLE sso_bad`)
		if _, e := f.owner.Exec(t.Context(), `UPDATE sso_bad SET grant_ciphertext=repeat('x',24577)::bytea`); e != nil {
			t.Fatal(e)
		}
		if _, e := scanRecord(f.owner.QueryRow(t.Context(), `SELECT `+rowProjection+` FROM sso_bad`), f.reg.BrokerNamespace); !errors.Is(e, ErrUnavailable) {
			t.Fatal("masked bad optional became NULL", e)
		}
		if _, e := f.owner.Exec(t.Context(), `UPDATE sso_bad SET grant_ciphertext=NULL`); e != nil {
			t.Fatal(e)
		}
		if _, e := scanRecord(f.owner.QueryRow(t.Context(), `SELECT `+rowProjection+` FROM sso_bad`), f.reg.BrokerNamespace); e != nil {
			t.Fatal("repaired optional", e)
		}
	})
	t.Run("other-runtime-role-privilege-drift-denied", func(t *testing.T) {
		f.reset(t)
		s := f.app(t)
		if _, e := f.owner.Exec(t.Context(), `GRANT UPDATE(actor_id) ON ops_sso_v1.transactions TO sso_retention`); e != nil {
			t.Fatal(e)
		}
		if _, e := s.InsertPending(t.Context(), f.pending(), noop); e == nil {
			t.Fatal("retention grant drift hidden from app")
		}
		if _, e := f.owner.Exec(t.Context(), `REVOKE UPDATE(actor_id) ON ops_sso_v1.transactions FROM sso_retention`); e != nil {
			t.Fatal(e)
		}
		insert(t, s, f.pending())
	})
	t.Run("primary-readonly-startup-denied-repair", func(t *testing.T) {
		f.reset(t)
		if _, e := f.owner.Exec(t.Context(), `ALTER ROLE sso_app SET default_transaction_read_only=on`); e != nil {
			t.Fatal(e)
		}
		defer f.owner.Exec(t.Context(), `ALTER ROLE sso_app RESET default_transaction_read_only`)
		if s, e := OpenApp(t.Context(), Config{f.appDSN, f.reg.scope(), f.clock}); e == nil {
			s.Close()
			t.Fatal("readonly writer claimed ready")
		}
		if _, e := f.owner.Exec(t.Context(), `ALTER ROLE sso_app RESET default_transaction_read_only`); e != nil {
			t.Fatal(e)
		}
		f.app(t)
	})
	t.Run("temporary-catalog-shadow-cannot-bias-fixed-queries", func(t *testing.T) {
		f.reset(t)
		s := f.app(t)
		p := f.pending()
		insert(t, s, p)
		conn, e := s.pool.Acquire(t.Context())
		if e != nil {
			t.Fatal(e)
		}
		if _, e = conn.Exec(t.Context(), `CREATE TEMP TABLE pg_class(fake int)`); e != nil {
			conn.Release()
			t.Fatal(e)
		}
		conn.Release()
		if _, e = s.ReadFlow(t.Context(), p.ID, p.Recipient); e != nil {
			t.Fatal("temporary shadow affected catalog qualification", e)
		}
	})

	t.Run("temporary-namespace-cannot-bypass-lifecycle-guard", func(t *testing.T) {
		f.reset(t)
		s := f.app(t)
		p := f.pending()
		a := insert(t, s, p)
		prepare(t, s, a.Capture(), f.ready(p))
		app, e := pgx.Connect(t.Context(), f.appDSN)
		if e != nil {
			t.Fatal(e)
		}
		defer closeConn(app)
		if _, e = app.Exec(t.Context(), `CREATE TEMP TABLE pg_namespace(nspname name,nspowner oid);INSERT INTO pg_temp.pg_namespace VALUES('ops_sso_v1',current_user::regrole::oid)`); e != nil {
			t.Fatal(e)
		}
		if _, e = app.Exec(t.Context(), `UPDATE ops_sso_v1.transactions SET actor_id=$1 WHERE id=$2::uuid`, "ops:p1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", p.ID); e == nil {
			t.Fatal("temporary namespace bypassed immutable prepared-metadata guard")
		}
	})

	t.Run("persistent-schema-lookalikes-are-not-temporary", func(t *testing.T) {
		f.reset(t)
		s := f.app(t)
		p := f.pending()
		insert(t, s, p)
		for _, schema := range []string{"pgxtempyuntrusted", "pgxtoastuntrusted"} {
			quoted := pgx.Identifier{schema}.Sanitize()
			if _, e := f.owner.Exec(t.Context(), `CREATE SCHEMA `+quoted+`;CREATE TABLE `+quoted+`.secret(n int)`); e != nil {
				t.Fatal(e)
			}
			for _, privileges := range [][2]string{{`GRANT CREATE ON SCHEMA ` + quoted + ` TO sso_app`, `REVOKE CREATE ON SCHEMA ` + quoted + ` FROM sso_app`}, {`GRANT SELECT ON ` + quoted + `.secret TO sso_app`, `REVOKE SELECT ON ` + quoted + `.secret FROM sso_app`}} {
				if _, e := f.owner.Exec(t.Context(), privileges[0]); e != nil {
					t.Fatal(e)
				}
				if _, e := s.ReadFlow(t.Context(), p.ID, p.Recipient); e == nil {
					t.Fatal("persistent privilege hidden by schema spelling", schema)
				}
				if opened, e := OpenApp(t.Context(), Config{f.appDSN, f.reg.scope(), f.clock}); e == nil {
					opened.Close()
					t.Fatal("persistent privilege accepted at startup", schema)
				}
				if _, e := f.owner.Exec(t.Context(), privileges[1]); e != nil {
					t.Fatal(e)
				}
				if _, e := s.ReadFlow(t.Context(), p.ID, p.Recipient); e != nil {
					t.Fatal("repaired privilege rejected", schema, e)
				}
			}
			if _, e := f.owner.Exec(t.Context(), `DROP SCHEMA `+quoted+` CASCADE`); e != nil {
				t.Fatal(e)
			}
		}
	})

}
