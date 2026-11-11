package ssosql

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	b "privacy-proxy/internal/identitybroker"
	"privacy-proxy/internal/operational/identitysql"
	m "privacy-proxy/internal/ssotransaction"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Every cipher below is PUBLIC STRUCTURAL TEST DATA, not authenticated tokens.
// These tests prove storage/lifecycle only, never a complete SSO/provider login.
type fixture struct {
	ownerDSN, appDSN, retDSN string
	owner                    *pgx.Conn
	reg                      Registration
	now                      atomic.Int64
}

func digest(s string) m.Digest      { return m.Digest(sha256.Sum256([]byte(s))) }
func (f *fixture) clock() time.Time { return time.UnixMicro(f.now.Load()).UTC() }
func setup(t *testing.T) *fixture {
	t.Helper()
	if _, e := exec.LookPath("docker"); e != nil {
		t.Fatal("owned cached Docker required", e)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	if out, e := exec.CommandContext(ctx, "docker", "image", "inspect", "postgres:16-alpine").CombinedOutput(); e != nil {
		t.Fatal("cached image required", e, string(out))
	}
	out, e := exec.CommandContext(ctx, "docker", "run", "--rm", "--detach", "--pull=never", "--memory=256m", "--cpus=1", "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD=sso-public-test-only", "--env", "POSTGRES_DB=sso_test", "--name", "ops-v2-sso-test-"+uuid.NewString()[:8], "postgres:16-alpine").CombinedOutput()
	if e != nil {
		t.Fatal(e, string(out))
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		ctx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		if out, e := exec.CommandContext(ctx, "docker", "rm", "--force", id).CombinedOutput(); e != nil {
			t.Error("owned cleanup", e, string(out))
		}
	})
	out, e = exec.CommandContext(ctx, "docker", "port", id, "5432/tcp").Output()
	if e != nil {
		t.Fatal(e)
	}
	f := &fixture{ownerDSN: "postgres://postgres:sso-public-test-only@" + strings.TrimSpace(string(out)) + "/sso_test?sslmode=disable"}
	f.now.Store(1794000000000000)
	for ctx.Err() == nil {
		f.owner, e = pgx.Connect(ctx, f.ownerDSN)
		if e == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { closeConn(f.owner) })
	for _, role := range []string{"identity_app", "identity_proof", "identity_retention", "sso_app", "sso_retention"} {
		if _, e = f.owner.Exec(ctx, `CREATE ROLE `+pgx.Identifier{role}.Sanitize()+` LOGIN NOINHERIT PASSWORD 'sso-public-test-only'`); e != nil {
			t.Fatal(e)
		}
	}
	broker := b.Scope{Namespace: b.Hash("public-test-broker", []byte("sso")), State: b.ExpectedState{RecoveryEpoch: uuid.NewString()}}
	if e = identitysql.MigrateV2(ctx, f.ownerDSN, "identity_app", "identity_proof", "identity_retention", broker, true); e != nil {
		t.Fatal("unchanged baseline", e)
	}
	dsn := func(role string) string {
		u, _ := url.Parse(f.ownerDSN)
		u.User = url.UserPassword(role, "sso-public-test-only")
		return u.String()
	}
	f.appDSN = dsn("sso_app")
	f.retDSN = dsn("sso_retention")
	f.reg = Registration{Namespace: digest("sso-namespace"), BrokerNamespace: m.Digest(broker.Namespace), Epoch: uuid.NewString(), BrokerRecoveryEpoch: broker.State.RecoveryEpoch, Limits: m.DefaultLimits(), Roles: Roles{"sso_app", "sso_retention"}}
	if e = Migrate(ctx, f.ownerDSN, f.reg.Roles, true); e != nil {
		t.Fatal("SSO migrate", e)
	}
	if e = Initialize(ctx, f.ownerDSN, f.reg, true); e != nil {
		t.Fatal("SSO initialize", e)
	}
	// Persist only public portable catalog shape when this owned run requests it.
	if directory := os.Getenv("OPS_SSO_TEST_EVIDENCE"); directory != "" {
		var actual []byte
		if e = f.owner.QueryRow(ctx, catalogQuery).Scan(&actual); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(directory, "observed-corrected-catalog.json"), actual, 0600); e != nil {
			t.Fatal(e)
		}
	}
	for _, mode := range []string{"app", "proof", "retention"} {
		var s interface{ Close() }
		switch mode {
		case "app":
			s, e = identitysql.Open(ctx, dsn("identity_app"), broker, f.clock)
		case "proof":
			s, e = identitysql.OpenProofV2(ctx, dsn("identity_proof"), broker, f.clock)
		case "retention":
			s, e = identitysql.OpenRetention(ctx, dsn("identity_retention"), broker, f.clock)
		}
		if e != nil {
			t.Fatal("identity unchanged", mode, e)
		}
		s.Close()
	}
	return f
}
func (f *fixture) reset(t *testing.T) {
	t.Helper()
	f.now.Store(1794000000000000)
	if _, e := f.owner.Exec(t.Context(), `TRUNCATE ops_sso_v1.transactions`); e != nil {
		t.Fatal(e)
	}
	if _, e := f.owner.Exec(t.Context(), `UPDATE ops_sso_v1.state SET active_rows=0,ready_rows=0,active_bytes=0,all_rows=0,last_gc_us=0,ready=true,epoch=$1::uuid,broker_epoch=$2::uuid,max_active_rows=$3,max_ready_rows=$4,max_active_bytes=$5,max_all_rows=$6,max_metadata_bytes=$7,audit_retention_seconds=$8`, f.reg.Epoch, f.reg.BrokerRecoveryEpoch, f.reg.Limits.ActiveRows, f.reg.Limits.ReadyRows, f.reg.Limits.ActiveCipherBytes, f.reg.Limits.AllRows, f.reg.Limits.MetadataBytes, f.reg.Limits.AuditRetentionSeconds); e != nil {
		t.Fatal(e)
	}
}
func (f *fixture) app(t *testing.T) *Store {
	t.Helper()
	s, e := OpenApp(t.Context(), Config{f.appDSN, f.reg.scope(), f.clock})
	if e != nil {
		t.Fatal("OpenApp", e)
	}
	t.Cleanup(s.Close)
	return s
}
func (f *fixture) ret(t *testing.T) *Store {
	t.Helper()
	s, e := OpenRetention(t.Context(), Config{f.retDSN, f.reg.scope(), f.clock})
	if e != nil {
		t.Fatal("OpenRetention", e)
	}
	t.Cleanup(s.Close)
	return s
}
func (f *fixture) pending() m.PendingRecord {
	now := m.Micros(f.now.Load())
	return m.PendingRecord{ID: uuid.NewString(), Scope: f.reg.scope(), ClientID: "explorer", ClientCatalogDigest: digest("clients"), IdentityDigest: digest("identities"), Recipient: digest("recipient"), StateHash: digest("state"), RedirectHash: digest("redirect"), PKCES256: digest("pkce"), ContextKeyID: "context", ContextCiphertext: bytes.Repeat([]byte{0x31}, 128), CreatedAt: now, ExpiresAt: now + 300000000}
}
func (f *fixture) ready(p m.PendingRecord) m.ReadyFields {
	now := m.Micros(f.now.Load())
	return m.ReadyFields{CodeHash: digest(uuid.NewString()), CodeExpiresAt: now + 60000000, GrantKeyID: "grant", GrantCiphertext: bytes.Repeat([]byte{0x32}, 256), ActorID: "ops:p1:" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 32)), ProfileID: "azure", ProfileDigest: digest("profile"), FamilyID: uuid.NewString(), FamilyGeneration: 2, FamilyHandleHash: digest("handle"), AccessDigest: digest("access"), AccessExpiresAt: p.ExpiresAt, FamilyExpiresAt: now + 86400000000, PreparedAt: now, CodeResponseDigest: digest("selected-code-response"), CodeResponseBytes: 200}
}
func noop() error { return nil }
func insert(t *testing.T, s *Store, p m.PendingRecord) Receipt {
	t.Helper()
	r, e := s.InsertPending(t.Context(), p, noop)
	if e != nil {
		t.Fatal("insert", e)
	}
	return r
}
func prepare(t *testing.T, s *Store, c m.Capture, v m.ReadyFields) Receipt {
	t.Helper()
	r, e := s.PrepareReady(t.Context(), c, v, noop)
	if e != nil {
		t.Fatal("ready", e)
	}
	return r
}
func status(t *testing.T, f *fixture) StatusResult {
	t.Helper()
	s, e := Status(t.Context(), f.ownerDSN, f.reg.Namespace)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func TestSSOStoragePostgreSQL(t *testing.T) {
	f := setup(t)
	t.Run("one-use-cipher-clear-audit-and-detachment", func(t *testing.T) {
		f.reset(t)
		s := f.app(t)
		p := f.pending()
		a := insert(t, s, p)
		same, e := s.InsertPending(t.Context(), p, noop)
		if e != nil || same.Capture() != a.Capture() {
			t.Fatal("idempotency", e)
		}
		v := f.ready(p)
		r := prepare(t, s, a.Capture(), v)
		found, e := s.LookupCode(t.Context(), v.CodeHash)
		if e != nil {
			t.Fatal(e)
		}
		found.Ready.GrantCiphertext[0]++
		again, e := s.ReadFlow(t.Context(), p.ID, p.Recipient)
		if e != nil || again.Ready.GrantCiphertext[0] != 0x32 {
			t.Fatal("alias", e)
		}
		out := m.PreparedOutput{Digest: digest("selected-token-response"), Bytes: 500}
		receipt, e := s.Consume(t.Context(), r.Capture(), out, noop)
		if e != nil || receipt.ID() != p.ID {
			t.Fatal("consume", e)
		}
		if _, e = s.Consume(t.Context(), r.Capture(), out, noop); !errors.Is(e, ErrConflict) {
			t.Fatal("replayed", e)
		}
		terminal, e := s.ReadFlow(t.Context(), p.ID, p.Recipient)
		if e != nil || terminal.Phase != m.Consumed || terminal.Pending.ContextCiphertext != nil || terminal.Ready.GrantCiphertext != nil || terminal.TokenResponse.Digest != out.Digest {
			t.Fatal("terminal", e)
		}
		z := status(t, f)
		if z.Usage != (Usage{AllRows: 1, MetadataBytes: 2048}) {
			t.Fatal(z.Usage)
		}
		if *terminal.RetainUntil != v.CodeExpiresAt+86400000000 {
			t.Fatal("retention")
		}
		if _, e = s.ReadFlow(t.Context(), p.ID, digest("wrong-recipient")); !errors.Is(e, ErrNotFound) {
			t.Fatal(e)
		}
	})
	t.Run("two-instances-quota-cas-and-rollback", func(t *testing.T) {
		f.reset(t)
		if _, e := f.owner.Exec(t.Context(), `UPDATE ops_sso_v1.state SET max_active_rows=1,max_ready_rows=1,max_all_rows=1,max_metadata_bytes=2048`); e != nil {
			t.Fatal(e)
		}
		a, b := f.app(t), f.app(t)
		var ok atomic.Int64
		var wg sync.WaitGroup
		for _, s := range []*Store{a, b} {
			p := f.pending()
			wg.Go(func() {
				_, e := s.InsertPending(t.Context(), p, noop)
				if e == nil {
					ok.Add(1)
				} else if !errors.Is(e, ErrCapacity) {
					t.Error(e)
				}
			})
		}
		wg.Wait()
		if ok.Load() != 1 || status(t, f).Usage.AllRows != 1 {
			t.Fatal("quota race")
		}
	})
	t.Run("pending-credit-does-not-reserve-ready-capacity", func(t *testing.T) {
		f.reset(t)
		if _, e := f.owner.Exec(t.Context(), `UPDATE ops_sso_v1.state SET max_ready_rows=1`); e != nil {
			t.Fatal(e)
		}
		s := f.app(t)
		p, q := f.pending(), f.pending()
		a, b := insert(t, s, p), insert(t, s, q)
		prepare(t, s, a.Capture(), f.ready(p))
		before := status(t, f).Usage
		if _, e := s.PrepareReady(t.Context(), b.Capture(), f.ready(q), noop); !errors.Is(e, ErrCapacity) {
			t.Fatal(e)
		}
		if status(t, f).Usage != before {
			t.Fatal("partial effects")
		}
	})
	t.Run("expiry-fair-gc-exact-old-bytes-and-clock-rollback", func(t *testing.T) {
		f.reset(t)
		s, ret := f.app(t), f.ret(t)
		p, q := f.pending(), f.pending()
		insert(t, s, p)
		a := insert(t, s, q)
		v := f.ready(q)
		prepare(t, s, a.Capture(), v)
		f.now.Add(300000001)
		if _, e := s.ReadFlow(t.Context(), p.ID, p.Recipient); !errors.Is(e, ErrExpired) {
			t.Fatal(e)
		}
		n, e := ret.CleanupOnce(t.Context(), 3)
		if e != nil || n != (CleanupCounts{DeletedPending: 1, ExpiredReady: 1}) {
			t.Fatal(n, e)
		}
		if z := status(t, f); z.Usage != (Usage{AllRows: 1, MetadataBytes: 2048}) {
			t.Fatal(z.Usage)
		}
		f.now.Store(int64(v.CodeExpiresAt + 86400000000))
		n, e = ret.CleanupOnce(t.Context(), 3)
		if e != nil || n.DeletedAudit != 1 || status(t, f).Usage.AllRows != 0 {
			t.Fatal(n, e)
		}
		f.now.Add(-1)
		if _, e = ret.CleanupOnce(t.Context(), 3); e == nil {
			t.Fatal("clock forced forward")
		}
	})
	t.Run("gate-rollback-and-expired-after-known-commit", func(t *testing.T) {
		f.reset(t)
		s := f.app(t)
		p := f.pending()
		if _, e := s.InsertPending(t.Context(), p, func() error { return context.Canceled }); !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
		if status(t, f).Usage.AllRows != 0 {
			t.Fatal("rollback")
		}
		var calls int
		receipt, e := s.InsertPending(t.Context(), p, func() error {
			calls++
			if calls == 2 {
				f.now.Store(int64(p.ExpiresAt))
			}
			return nil
		})
		if !errors.Is(e, ErrExpired) || receipt.ID() != "" || status(t, f).Usage.AllRows != 1 {
			t.Fatal("postcommit must withhold not undo", e, receipt.ID())
		}
	})
	t.Run("role-boundaries-and-temporary-create", func(t *testing.T) {
		f.reset(t)
		s := f.app(t)
		ret := f.ret(t)
		p := f.pending()
		a := insert(t, s, p)
		prepare(t, s, a.Capture(), f.ready(p))
		app, e := pgx.Connect(t.Context(), f.appDSN)
		if e != nil {
			t.Fatal(e)
		}
		defer closeConn(app)
		r, e := pgx.Connect(t.Context(), f.retDSN)
		if e != nil {
			t.Fatal(e)
		}
		defer closeConn(r)
		for _, q := range []string{`DELETE FROM ops_sso_v1.transactions`, `UPDATE ops_sso_v1.state SET ready=false`, `UPDATE ops_sso_v1.transactions SET client_id='other'`, `SELECT * FROM ops_identity_v2.renewal_families`, `SELECT ops_sso_v1.guard_transaction()`} {
			if _, e = app.Exec(t.Context(), q); e == nil {
				t.Fatal("role allowed", q)
			}
		}
		for _, q := range []string{`UPDATE ops_sso_v1.transactions SET phase=3`, `UPDATE ops_sso_v1.transactions SET actor_id='other'`, `UPDATE ops_sso_v1.state SET epoch='11111111-1111-4111-8111-111111111111'`} {
			if _, e = r.Exec(t.Context(), q); e == nil {
				t.Fatal("retention allowed", q)
			}
		}
		if _, e = app.Exec(t.Context(), `CREATE TEMP TABLE sso_test_tmp(n int)`); e != nil {
			t.Fatal("normal TEMP", e)
		}
		if _, e = s.ReadFlow(t.Context(), p.ID, p.Recipient); e != nil {
			t.Fatal(e)
		}
		if _, e = ret.InsertPending(t.Context(), f.pending(), noop); !errors.Is(e, ErrRole) {
			t.Fatal("wrongmode", e)
		}
	})
	t.Run("rls-catalog-and-persistent-create-deny-repaired-positive", func(t *testing.T) {
		f.reset(t)
		s := f.app(t)
		p := f.pending()
		insert(t, s, p)
		for _, table := range []string{"state", "transactions"} {
			for _, rls := range []string{"ENABLE", "FORCE"} {
				sql := `ALTER TABLE ops_sso_v1.` + table + ` ` + rls + ` ROW LEVEL SECURITY`
				if _, e := f.owner.Exec(t.Context(), sql); e != nil {
					t.Fatal(e)
				}
				if opened, e := OpenApp(t.Context(), Config{f.appDSN, f.reg.scope(), f.clock}); e == nil {
					opened.Close()
					t.Fatal("altered RLS ready")
				}
				if _, e := s.ReadFlow(t.Context(), p.ID, p.Recipient); e == nil {
					t.Fatal("live altered RLS")
				}
				if _, e := f.owner.Exec(t.Context(), `ALTER TABLE ops_sso_v1.`+table+` NO FORCE ROW LEVEL SECURITY;ALTER TABLE ops_sso_v1.`+table+` DISABLE ROW LEVEL SECURITY`); e != nil {
					t.Fatal(e)
				}
			}
		}
		if _, e := f.owner.Exec(t.Context(), `CREATE SCHEMA sso_foreign_empty;GRANT CREATE ON SCHEMA sso_foreign_empty TO sso_app`); e != nil {
			t.Fatal(e)
		}
		if _, e := s.ReadFlow(t.Context(), p.ID, p.Recipient); e == nil {
			t.Fatal("persistent create")
		}
		if _, e := f.owner.Exec(t.Context(), `REVOKE CREATE ON SCHEMA sso_foreign_empty FROM sso_app;DROP SCHEMA sso_foreign_empty`); e != nil {
			t.Fatal(e)
		}
		if _, e := s.ReadFlow(t.Context(), p.ID, p.Recipient); e != nil {
			t.Fatal("repaired", e)
		}
	})
	t.Run("allrows-max-is-Go-invariant", func(t *testing.T) {
		f.reset(t)
		if _, e := f.owner.Exec(t.Context(), `UPDATE ops_sso_v1.state SET all_rows=max_all_rows+1`); e != nil {
			t.Fatal("SQL intentionally lacks comparison", e)
		}
		if s, e := OpenApp(t.Context(), Config{f.appDSN, f.reg.scope(), f.clock}); e == nil {
			s.Close()
			t.Fatal("AllRows over cap")
		}
		if _, e := f.owner.Exec(t.Context(), `UPDATE ops_sso_v1.state SET all_rows=0`); e != nil {
			t.Fatal(e)
		}
		f.app(t)
	})
	t.Run("all-active-recovery-including-reused-epoch", func(t *testing.T) {
		f.reset(t)
		s := f.app(t)
		p, q := f.pending(), f.pending()
		insert(t, s, p)
		a := insert(t, s, q)
		v := f.ready(q)
		prepare(t, s, a.Capture(), v)
		before, e := s.ReadFlow(t.Context(), q.ID, q.Recipient)
		if e != nil {
			t.Fatal(e)
		}
		current := f.reg.scope()
		current.Epoch = uuid.NewString()
		if _, e = f.owner.Exec(t.Context(), `UPDATE ops_sso_v1.state SET epoch=$1::uuid`, current.Epoch); e != nil {
			t.Fatal(e)
		}
		selected := f.reg // reuse original epochA while restored currentstate isepochB
		next, e := BeginRecovery(t.Context(), f.ownerDSN, current, selected, true)
		if e != nil || next.Ready {
			t.Fatal(e)
		}
		if _, e = s.InsertPending(t.Context(), f.pending(), noop); e == nil {
			t.Fatal("unready app write")
		}
		if _, e = s.PrepareReady(t.Context(), a.Capture(), v, noop); e == nil {
			t.Fatal("stale completion")
		}
		if e = FinalizeRecovery(t.Context(), f.ownerDSN, selected.scope(), true); e != nil {
			t.Fatal("all active finalize", e)
		}
		z := status(t, f)
		if !z.Ready || z.Usage != (Usage{AllRows: 1, MetadataBytes: 2048}) {
			t.Fatal(z)
		}
		s2 := f.app(t)
		after, e := s2.ReadFlow(t.Context(), q.ID, q.Recipient)
		if e != nil || after.Phase != m.Expired || after.Pending.Scope != before.Pending.Scope || *after.RetainUntil != *before.RetainUntil || after.Ready.CodeHash != v.CodeHash || after.Ready.GrantCiphertext != nil || after.Pending.ContextCiphertext != nil {
			t.Fatal("original audit preserved", e)
		}
		if _, e = s2.LookupCode(t.Context(), v.CodeHash); !errors.Is(e, ErrConflict) {
			t.Fatal("old grant active", e)
		}
	})
	t.Run("full-reconciliation-fails-unready-no-silent-counter-repair", func(t *testing.T) {
		f.reset(t)
		next := f.reg
		next.Epoch = uuid.NewString()
		if _, e := BeginRecovery(t.Context(), f.ownerDSN, f.reg.scope(), next, true); e != nil {
			t.Fatal(e)
		}
		if _, e := f.owner.Exec(t.Context(), `UPDATE ops_sso_v1.state SET all_rows=1`); e != nil {
			t.Fatal(e)
		}
		if e := FinalizeRecovery(t.Context(), f.ownerDSN, next.scope(), true); e == nil {
			t.Fatal("counter silently accepted")
		}
		var ready bool
		if e := f.owner.QueryRow(t.Context(), `SELECT ready FROM ops_sso_v1.state`).Scan(&ready); e != nil || ready {
			t.Fatal("became ready")
		}
		if _, e := f.owner.Exec(t.Context(), `UPDATE ops_sso_v1.state SET all_rows=0`); e != nil {
			t.Fatal(e)
		}
		if e := FinalizeRecovery(t.Context(), f.ownerDSN, next.scope(), true); e != nil {
			t.Fatal("explicit repair", e)
		}
	})
}
