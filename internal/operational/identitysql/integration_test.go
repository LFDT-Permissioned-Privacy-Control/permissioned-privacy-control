package identitysql_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"privacy-proxy/internal/brokerpolicy"
	f "privacy-proxy/internal/brokertest"
	d "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/identity"
	b "privacy-proxy/internal/identitybroker"
	"privacy-proxy/internal/identitybroker/azure"
	"privacy-proxy/internal/operational/identitysql"
	"privacy-proxy/internal/policybundle"
)

type fixture struct {
	wallClock                                atomic.Bool
	wallOffset                               atomic.Int64
	ownerDSN, appDSN, proofDSN, retentionDSN string
	owner                                    *pgx.Conn
	one, two                                 *identitysql.Store
	snapshot                                 *policybundle.CatalogSnapshot
	provider                                 *azure.ProviderSet
	entra                                    *f.Entra
	scope                                    b.Scope
	binding                                  b.ServiceBinding
}

func setup(t *testing.T) *fixture {
	return setupConfigured(t, nil)
}
func setupConfigured(t *testing.T, change func(*brokerpolicy.Source)) *fixture {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("requires owned Docker PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--detach", "--pull=never", "--memory=256m", "--cpus=1", "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD=broker-test-only", "--env", "POSTGRES_DB=broker_test", "--name", "ops-v2-broker-test-"+uuid.NewString()[:8], "postgres:16-alpine").CombinedOutput()
	if err != nil {
		t.Fatalf("owned PostgreSQL: %v %s", err, raw)
	}
	id := strings.TrimSpace(string(raw))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "docker", "rm", "--force", id).CombinedOutput(); err != nil {
			t.Logf("owned cleanup: %v %s", err, out)
		}
	})
	raw, err = exec.CommandContext(ctx, "docker", "port", id, "5432/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	x := &fixture{ownerDSN: "postgres://postgres:broker-test-only@" + strings.TrimSpace(string(raw)) + "/broker_test?sslmode=disable", snapshot: f.Snapshot(t, func(_ *identity.SourceCatalog, source *brokerpolicy.Source) {
		if change != nil {
			change(source)
		}
	}), entra: f.NewEntra(t), binding: b.ServiceBinding{Environment: "test", DeploymentID: "broker-fixture", Origin: "https://ops.test"}}
	auth, _ := x.snapshot.AuthBroker()
	authSource := auth.Source()
	x.binding.Origin = authSource.WebOrigin
	for _, p := range auth.Profiles() {
		if p.Definition.Kind == identity.AzureHuman {
			x.entra.SetRedirectURI(p.Binding.RedirectURI)
		}
	}
	for ctx.Err() == nil {
		x.owner, err = pgx.Connect(ctx, x.ownerDSN)
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("owned readiness")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = x.owner.Close(ctx)
	})
	for _, role := range []string{"broker_app", "broker_proof", "broker_retention"} {
		if _, err := x.owner.Exec(t.Context(), `CREATE ROLE `+pgx.Identifier{role}.Sanitize()+` LOGIN PASSWORD 'broker-test-only'`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := x.owner.Exec(t.Context(), `CREATE TABLE public.users(id integer)`); err != nil {
		t.Fatal(err)
	}
	ns, err := x.binding.Namespace("https://ops.test")
	if err != nil {
		t.Fatal(err)
	}
	x.scope = b.Scope{Namespace: ns, State: b.ExpectedState{RecoveryEpoch: uuid.NewString()}}
	if err := identitysql.MigrateV2(t.Context(), x.ownerDSN, "broker_app", "broker_proof", "broker_retention", x.scope, true); err != nil {
		t.Fatal("offline migration", err)
	}
	u, _ := url.Parse(x.ownerDSN)
	u.User = url.UserPassword("broker_app", "broker-test-only")
	x.appDSN = u.String()
	u.User = url.UserPassword("broker_proof", "broker-test-only")
	x.proofDSN = u.String()
	u.User = url.UserPassword("broker_retention", "broker-test-only")
	x.retentionDSN = u.String()
	x.one, err = identitysql.Open(t.Context(), x.appDSN, x.scope, x.clock)
	if err != nil {
		t.Fatal("least privilege app startup", err)
	}
	t.Cleanup(x.one.Close)
	x.two, err = identitysql.Open(t.Context(), x.appDSN, x.scope, x.clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(x.two.Close)
	catalog, _ := x.snapshot.AuthBroker()
	x.provider, err = azure.New(t.Context(), azure.Config{Catalog: catalog, Clock: x.clock, ClientSecrets: map[string]string{"OPS_BROKER_AZURE_TEST": "test-only-secret"}, Transport: x.entra.Transport()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(x.provider.Close)
	return x
}
func (x *fixture) clock() time.Time {
	if x.wallClock.Load() {
		return time.Now().UTC().Add(time.Duration(x.wallOffset.Load()) * time.Second)
	}
	return time.Unix(x.entra.Clock.Load(), 0).UTC()
}
func (x *fixture) service(t *testing.T, store b.Store) *b.Service {
	return x.serviceWithClock(t, store, x.clock)
}
func (x *fixture) serviceWithClock(t *testing.T, store b.Store, clock identity.Clock) *b.Service {
	t.Helper()
	s, err := b.New(b.Config{Snapshot: x.snapshot, Clock: clock, Store: store, AzureProvider: x.provider, AccessSigningBinding: b.AccessSigningBinding{IssuerID: "ops", KeyID: "test", PrivateKey: f.SigningKey()}, RenewalKeyBindings: []b.SecretBinding{{FromEnv: "OPS_BROKER_REFRESH_TEST", Value: bytes.Repeat([]byte{1}, 32)}}, EncryptionKeyBindings: []b.SecretBinding{{FromEnv: "OPS_BROKER_ENCRYPTION_TEST", Value: bytes.Repeat([]byte{2}, 32)}}, ServiceBinding: x.binding, ExpectedState: x.scope.State})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func (x *fixture) begin(t *testing.T, s *b.Service, recipient b.RecipientBinding) string {
	t.Helper()
	start, err := s.BeginAzure(t.Context(), f.HumanProfile, recipient)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(start.AuthorizationURL)
	x.entra.SetNonce(u.Query().Get("nonce"))
	return u.Query().Get("state")
}
func (x *fixture) login(t *testing.T, s *b.Service, recipient b.RecipientBinding) *b.CommittedLogin {
	t.Helper()
	state := x.begin(t, s, recipient)
	result, err := s.CompleteAzure(t.Context(), state, "fixture-code", recipient)
	if err != nil {
		t.Fatal("actual code+SQL+assertion", err)
	}
	return result
}
func credentials(t *testing.T, result interface {
	Credentials() (string, string, error)
}) (string, string) {
	t.Helper()
	a, r, err := result.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	return a, r
}
func count(t *testing.T, x *fixture, table string) int {
	t.Helper()
	var n int
	if err := x.owner.QueryRow(t.Context(), `SELECT count(*) FROM ops_identity_v2.`+pgx.Identifier{table}.Sanitize()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

type wrappedStore struct {
	b.Store
	after      func()
	beforeGate func()
	ambiguous  bool
}

func (w wrappedStore) WithPending(ctx context.Context, scope b.Scope, hash b.Digest, recipient b.RecipientBinding, callback func(b.Pending, b.PendingTx) error, gate func() error) (b.Commit, error) {
	c, err := w.Store.WithPending(ctx, scope, hash, recipient, callback, func() error {
		if w.beforeGate != nil {
			w.beforeGate()
		}
		return gate()
	})
	if err == nil && c.Committed {
		if w.after != nil {
			w.after()
		}
		if w.ambiguous {
			return b.Commit{}, b.ErrUnavailable
		}
	}
	return c, err
}
func (w wrappedStore) WithFamily(ctx context.Context, scope b.Scope, id string, callback func(b.Family) (b.FamilyDecision, error), gate func() error) (b.Commit, error) {
	var final func() error
	if gate != nil {
		final = func() error {
			if w.beforeGate != nil {
				w.beforeGate()
			}
			return gate()
		}
	}
	c, err := w.Store.WithFamily(ctx, scope, id, callback, final)
	if err == nil && c.Committed {
		if w.after != nil {
			w.after()
		}
		if w.ambiguous {
			return b.Commit{}, b.ErrUnavailable
		}
	}
	return c, err
}
func waitForRowLock(t *testing.T, x *fixture) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		if err := x.owner.QueryRow(t.Context(), `SELECT count(*) FROM pg_stat_activity WHERE usename='broker_app' AND wait_event_type='Lock'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("actual app row wait not observed")
}
func TestActualAzureSessionProtocol(t *testing.T) {
	x := setup(t)
	one, two := x.service(t, x.one), x.service(t, x.two)
	recipient := b.RecipientBinding{1}
	reset := func() { x.entra.Clock.Store(d.Now); x.entra.SetRoles("Reader"); x.entra.SetGrantError("", 0) }
	t.Run("fresh grants change mapped groups across replicas", func(t *testing.T) {
		reset()
		login := x.login(t, one, recipient)
		access, handle := credentials(t, login)
		catalog, _ := x.snapshot.Identity()
		verifier, _ := identity.NewVerifier(catalog, x.clock)
		p, err := verifier.VerifyAccess(access)
		if err != nil || len(p.Groups(d.Org)) != 1 || p.Groups(d.Org)[0] != d.AuditorGroup {
			t.Fatal("initial mapped grant", err)
		}
		x.entra.Clock.Add(60)
		x.entra.SetRoles("Admin")
		before := x.entra.Grants.Load()
		renewed, err := two.RenewAzure(t.Context(), handle, recipient)
		if err != nil {
			t.Fatal(err)
		}
		nextAccess, next := credentials(t, renewed)
		p, err = verifier.VerifyAccess(nextAccess)
		if err != nil || len(p.Groups(d.Org)) != 1 || p.Groups(d.Org)[0] != d.AdminGroup || next == handle || x.entra.Grants.Load() != before+1 {
			t.Fatal("fresh mapped grant", err)
		}
		x.entra.Clock.Add(60)
		x.entra.SetRoles()
		renewed, err = one.RenewAzure(t.Context(), next, recipient)
		if err != nil {
			t.Fatal(err)
		}
		nextAccess, _ = credentials(t, renewed)
		p, err = verifier.VerifyAccess(nextAccess)
		if err != nil || len(p.Groups(d.Org)) != 0 {
			t.Fatal("stale role retained", err)
		}
	})
	t.Run("service exchange has no family and cannot freshen old source", func(t *testing.T) {
		reset()
		before := count(t, x, "renewal_families")
		result, err := one.ExchangeAzureService(t.Context(), f.ServiceProfile, x.entra.Access(true, nil))
		if err != nil || result.Metadata().Kind != identity.Service {
			t.Fatal(err)
		}
		if _, err := result.Credentials(); err != nil {
			t.Fatal(err)
		}
		if count(t, x, "renewal_families") != before {
			t.Fatal("service got renewal family")
		}
		source := x.entra.Access(true, nil)
		x.entra.Clock.Add(301)
		if _, err := one.ExchangeAzureService(t.Context(), f.ServiceProfile, source); err == nil {
			t.Fatal("old source got fresh local five minutes")
		}
	})
	t.Run("wrong recipient cannot consume pending", func(t *testing.T) {
		reset()
		state := x.begin(t, one, recipient)
		before := x.entra.Grants.Load()
		if result, err := two.CompleteAzure(t.Context(), state, "code", b.RecipientBinding{2}); err == nil || result != nil {
			t.Fatal("recipient mismatch")
		}
		if x.entra.Grants.Load() != before {
			t.Fatal("wrong recipient reached provider")
		}
		if _, err := one.CompleteAzure(t.Context(), state, "code", recipient); err != nil {
			t.Fatal("wrong recipient consumed request", err)
		}
	})
	t.Run("pending completion is one use across two pools", func(t *testing.T) {
		reset()
		state := x.begin(t, one, recipient)
		before := x.entra.Grants.Load()
		var wg sync.WaitGroup
		results := make(chan error, 2)
		for _, s := range []*b.Service{one, two} {
			wg.Add(1)
			go func(s *b.Service) {
				defer wg.Done()
				_, err := s.CompleteAzure(t.Context(), state, "code", recipient)
				results <- err
			}(s)
		}
		wg.Wait()
		close(results)
		successes := 0
		for err := range results {
			if err == nil {
				successes++
			}
		}
		if successes != 1 || x.entra.Grants.Load() != before+1 {
			t.Fatal("duplicate completion", successes, x.entra.Grants.Load()-before)
		}
	})
	t.Run("authentic old generation commits revocation", func(t *testing.T) {
		reset()
		login := x.login(t, one, recipient)
		_, handle := credentials(t, login)
		fresh, err := two.RenewAzure(t.Context(), handle, recipient)
		if err != nil {
			t.Fatal(err)
		}
		_, next := credentials(t, fresh)
		before := x.entra.Grants.Load()
		if result, err := one.RenewAzure(t.Context(), handle, recipient); !errors.Is(err, b.ErrRelogin) || result != nil {
			t.Fatal("old generation not rejected", err)
		}
		if result, err := two.RenewAzure(t.Context(), next, recipient); err == nil || result != nil {
			t.Fatal("replay revocation rolled back")
		}
		if x.entra.Grants.Load() != before {
			t.Fatal("revoked family reached provider")
		}
	})
	t.Run("same renewal raced across replicas cannot both rotate", func(t *testing.T) {
		reset()
		_, handle := credentials(t, x.login(t, one, recipient))
		before := x.entra.Grants.Load()
		var wg sync.WaitGroup
		results := make(chan error, 2)
		for _, s := range []*b.Service{one, two} {
			wg.Add(1)
			go func(s *b.Service) {
				defer wg.Done()
				_, err := s.RenewAzure(t.Context(), handle, recipient)
				results <- err
			}(s)
		}
		wg.Wait()
		close(results)
		successes := 0
		for err := range results {
			if err == nil {
				successes++
			}
		}
		if successes != 1 || x.entra.Grants.Load() != before+1 {
			t.Fatal("double rotation", successes, x.entra.Grants.Load()-before)
		}
	})
	t.Run("invalid MAC or recipient cannot revoke", func(t *testing.T) {
		reset()
		_, handle := credentials(t, x.login(t, one, recipient))
		before := x.entra.Grants.Load()
		if _, err := two.RenewAzure(t.Context(), handle, b.RecipientBinding{2}); err == nil {
			t.Fatal("recipient mismatch")
		}
		parts := strings.Split(handle, ".")
		parts[2] = "A" + parts[2][1:]
		if parts[2] == strings.Split(handle, ".")[2] {
			parts[2] = "B" + parts[2][1:]
		}
		if _, err := two.RenewAzure(t.Context(), strings.Join(parts, "."), recipient); err == nil {
			t.Fatal("bad MAC")
		}
		if x.entra.Grants.Load() != before {
			t.Fatal("invalid proof reached provider")
		}
		if _, err := one.RenewAzure(t.Context(), handle, recipient); err != nil {
			t.Fatal("invalid caller revoked real family", err)
		}
	})
	t.Run("authenticated future generation and current hash mismatch revoke without provider", func(t *testing.T) {
		reset()
		for _, field := range []string{"gen", "jti"} {
			_, handle := credentials(t, x.login(t, one, recipient))
			claims := jwt.MapClaims{}
			if _, _, err := jwt.NewParser().ParseUnverified(handle, claims); err != nil {
				t.Fatal(err)
			}
			if field == "gen" {
				claims[field] = int64(1)
			} else {
				claims[field] = strings.Repeat("A", 43)
			}
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			token.Header["typ"] = "ops-refresh+jwt"
			token.Header["kid"] = "mac-test"
			modified, err := token.SignedString(bytes.Repeat([]byte{1}, 32))
			if err != nil {
				t.Fatal(err)
			}
			before := x.entra.Grants.Load()
			if _, err := two.RenewAzure(t.Context(), modified, recipient); !errors.Is(err, b.ErrRelogin) {
				t.Fatal("authentic inconsistent handle did not revoke", field, err)
			}
			if _, err := one.RenewAzure(t.Context(), handle, recipient); err == nil {
				t.Fatal("inconsistent handle revocation rolled back", field)
			}
			if x.entra.Grants.Load() != before {
				t.Fatal("inconsistent handle reached provider")
			}
		}
	})
	t.Run("provider invalid grant revokes but infrastructure error rolls back", func(t *testing.T) {
		reset()
		_, handle := credentials(t, x.login(t, one, recipient))
		x.entra.SetGrantError("temporarily_unavailable", 503)
		if _, err := two.RenewAzure(t.Context(), handle, recipient); !errors.Is(err, b.ErrUnavailable) {
			t.Fatal(err)
		}
		x.entra.SetGrantError("", 0)
		if _, err := one.RenewAzure(t.Context(), handle, recipient); err != nil {
			t.Fatal("provider outage consumed current handle", err)
		}
		_, handle = credentials(t, x.login(t, one, recipient))
		x.entra.SetGrantError("invalid_grant", 400)
		if _, err := one.RenewAzure(t.Context(), handle, recipient); !errors.Is(err, b.ErrRelogin) {
			t.Fatal(err)
		}
		before := x.entra.Grants.Load()
		x.entra.SetGrantError("", 0)
		if _, err := two.RenewAzure(t.Context(), handle, recipient); err == nil {
			t.Fatal("invalid grant revocation rolled back")
		}
		if x.entra.Grants.Load() != before {
			t.Fatal("revoked retry reached provider")
		}
	})
	t.Run("known logout blocks renewal while prior access retains bounded life", func(t *testing.T) {
		reset()
		access, handle := credentials(t, x.login(t, one, recipient))
		if err := two.Revoke(t.Context(), handle, recipient); err != nil {
			t.Fatal(err)
		}
		if _, err := one.RenewAzure(t.Context(), handle, recipient); err == nil {
			t.Fatal("logout lost")
		}
		catalog, _ := x.snapshot.Identity()
		v, _ := identity.NewVerifier(catalog, x.clock)
		if _, err := v.VerifyAccess(access); err != nil {
			t.Fatal("incorrect immediate access revocation claim", err)
		}
	})
	t.Run("pending expires after real row lock", func(t *testing.T) {
		reset()
		state := x.begin(t, one, recipient)
		tx, err := x.owner.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		if _, err := tx.Exec(t.Context(), `SELECT request_id FROM ops_identity_v2.pending_requests FOR UPDATE`); err != nil {
			t.Fatal(err)
		}
		before := x.entra.Grants.Load()
		done := make(chan error, 1)
		go func() { _, err := two.CompleteAzure(t.Context(), state, "code", recipient); done <- err }()
		waitForRowLock(t, x)
		x.entra.Clock.Add(300)
		if err := tx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err == nil {
			t.Fatal("pre-lock expiry used")
		}
		if x.entra.Grants.Load() != before {
			t.Fatal("expired pending reached provider")
		}
	})
	t.Run("family expiry is checked after row lock", func(t *testing.T) {
		reset()
		_, handle := credentials(t, x.login(t, one, recipient))
		tx, err := x.owner.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		if _, err := tx.Exec(t.Context(), `SELECT family_id FROM ops_identity_v2.renewal_families FOR UPDATE`); err != nil {
			t.Fatal(err)
		}
		before := x.entra.Grants.Load()
		done := make(chan error, 1)
		go func() { _, err := two.RenewAzure(t.Context(), handle, recipient); done <- err }()
		waitForRowLock(t, x)
		x.entra.Clock.Add(int64(b.FamilyLifetime.Seconds()))
		if err := tx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err == nil {
			t.Fatal("pre-lock family expiry used")
		}
		if x.entra.Grants.Load() != before {
			t.Fatal("expired family reached provider")
		}
	})
	t.Run("time advance after final SQL rolls back creation", func(t *testing.T) {
		reset()
		s := x.service(t, wrappedStore{Store: x.one, beforeGate: func() { x.entra.Clock.Add(300) }})
		state := x.begin(t, s, recipient)
		before := count(t, x, "renewal_families")
		if result, err := s.CompleteAzure(t.Context(), state, "code", recipient); err == nil || result != nil {
			t.Fatal("expired creation committed")
		}
		if count(t, x, "renewal_families") != before {
			t.Fatal("precommit gate lost atomicity")
		}
	})
	t.Run("time advance after final SQL rolls back rotation", func(t *testing.T) {
		reset()
		_, handle := credentials(t, x.login(t, one, recipient))
		s := x.service(t, wrappedStore{Store: x.two, beforeGate: func() { x.entra.Clock.Add(300) }})
		if result, err := s.RenewAzure(t.Context(), handle, recipient); err == nil || result != nil {
			t.Fatal("expired rotation committed")
		}
		x.entra.Clock.Store(d.Now)
		if _, err := one.RenewAzure(t.Context(), handle, recipient); err != nil {
			t.Fatal("failed precommit gate consumed current generation", err)
		}
	})
	t.Run("ambiguous known-underlying commit returns no reconstructable credentials", func(t *testing.T) {
		reset()
		s := x.service(t, wrappedStore{Store: x.one, ambiguous: true})
		state := x.begin(t, s, recipient)
		before := count(t, x, "renewal_families")
		if result, err := s.CompleteAzure(t.Context(), state, "code", recipient); !errors.Is(err, b.ErrUnavailable) || result != nil {
			t.Fatal("ambiguous credentials returned", err)
		}
		if count(t, x, "renewal_families") != before+1 {
			t.Fatal("fixture did not commit")
		}
		if result, err := one.CompleteAzure(t.Context(), state, "code", recipient); err == nil || result != nil {
			t.Fatal("completion response reconstructed")
		}
	})
	t.Run("postcommit expiry suppresses credentials and consumes pending", func(t *testing.T) {
		reset()
		s := x.service(t, wrappedStore{Store: x.one, after: func() { x.entra.Clock.Add(300) }})
		state := x.begin(t, s, recipient)
		before := count(t, x, "renewal_families")
		if result, err := s.CompleteAzure(t.Context(), state, "code", recipient); err == nil || result != nil {
			t.Fatal("expired postcommit credentials returned")
		}
		if count(t, x, "renewal_families") != before+1 {
			t.Fatal("committed state undone")
		}
		if _, err := one.CompleteAzure(t.Context(), state, "code", recipient); err == nil {
			t.Fatal("consumed pending replay")
		}
	})
	t.Run("deferred database failure returns no credentials and rolls back pending consume", func(t *testing.T) {
		reset()
		state := x.begin(t, one, recipient)
		before := count(t, x, "renewal_families")
		if _, err := x.owner.Exec(t.Context(), `CREATE FUNCTION ops_identity_v2.test_commit_failure()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'controlled commit failure';END$$;CREATE CONSTRAINT TRIGGER test_commit_failure AFTER INSERT ON ops_identity_v2.renewal_families DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ops_identity_v2.test_commit_failure()`); err != nil {
			t.Fatal(err)
		}
		defer x.owner.Exec(t.Context(), `DROP TRIGGER IF EXISTS test_commit_failure ON ops_identity_v2.renewal_families;DROP FUNCTION IF EXISTS ops_identity_v2.test_commit_failure()`)
		if result, err := two.CompleteAzure(t.Context(), state, "code", recipient); err == nil || result != nil {
			t.Fatal("credentials before durable commit")
		}
		if count(t, x, "renewal_families") != before {
			t.Fatal("failed commit created family")
		}
		if _, err := x.owner.Exec(t.Context(), `DROP TRIGGER test_commit_failure ON ops_identity_v2.renewal_families;DROP FUNCTION ops_identity_v2.test_commit_failure()`); err != nil {
			t.Fatal(err)
		}
		// This controlled provider permits a repeated code. Real providers may
		// have consumed it already, requiring a fresh browser login instead.
		if _, err := one.CompleteAzure(t.Context(), state, "code", recipient); err != nil {
			t.Fatal("SQL rollback consumed pending", err)
		}
	})
	t.Run("substituted family recipient cannot decrypt even when caller matches row", func(t *testing.T) {
		reset()
		_, handle := credentials(t, x.login(t, one, recipient))
		hash := sha256.Sum256([]byte(handle))
		newRecipient := b.RecipientBinding{3}
		before := x.entra.Grants.Load()
		if _, err := x.owner.Exec(t.Context(), `ALTER TABLE ops_identity_v2.renewal_families DISABLE TRIGGER family_monotonic`); err != nil {
			t.Fatal(err)
		}
		_, err := x.owner.Exec(t.Context(), `UPDATE ops_identity_v2.renewal_families SET recipient_hash=$2 WHERE current_handle_hash=$1`, hash[:], newRecipient[:])
		if _, enableErr := x.owner.Exec(t.Context(), `ALTER TABLE ops_identity_v2.renewal_families ENABLE TRIGGER family_monotonic`); enableErr != nil {
			t.Fatal(enableErr)
		}
		if err != nil {
			t.Fatal(err)
		}
		if result, err := two.RenewAzure(t.Context(), handle, newRecipient); !errors.Is(err, b.ErrRelogin) || result != nil {
			t.Fatal("substituted row bound ciphertext accepted", err)
		}
		if x.entra.Grants.Load() != before {
			t.Fatal("row substitution reached provider")
		}
	})
	t.Run("indexed pending and active-family capacity recover without deleting live rows", func(t *testing.T) {
		reset()
		x.begin(t, one, recipient)
		if _, err := x.owner.Exec(t.Context(), `INSERT INTO ops_identity_v2.pending_requests SELECT gen_random_uuid(),namespace,recovery_epoch,decode(lpad(to_hex(g),64,'0'),'hex'),'capacity-test',profile_digest,recipient_hash,encryption_key_id,secret_ciphertext,$1::timestamptz,$1::timestamptz+interval '300 seconds' FROM(SELECT * FROM ops_identity_v2.pending_requests LIMIT 1)template CROSS JOIN generate_series(1,10000)g`, x.clock()); err != nil {
			t.Fatal(err)
		}
		if _, err := two.BeginAzure(t.Context(), f.HumanProfile, recipient); !errors.Is(err, b.ErrConflict) {
			t.Fatal("pending capacity ignored", err)
		}
		if _, err := x.owner.Exec(t.Context(), `DELETE FROM ops_identity_v2.pending_requests WHERE profile_id='capacity-test'`); err != nil {
			t.Fatal(err)
		}
		x.login(t, one, recipient)
		if _, err := x.owner.Exec(t.Context(), `INSERT INTO ops_identity_v2.renewal_families SELECT gen_random_uuid(),gen_random_uuid(),namespace,recovery_epoch,actor_id,'capacity-test',profile_digest,identity_authority,source_tenant,source_subject,principal_kind,oidc_subject_hash,login_nonce_hash,original_auth_time,recipient_hash,0,current_handle_hash,encryption_key_id,refresh_ciphertext,$1::timestamptz,$1::timestamptz+interval '604800 seconds',$1::timestamptz,NULL FROM(SELECT * FROM ops_identity_v2.renewal_families WHERE revoked_at IS NULL LIMIT 1)template CROSS JOIN generate_series(1,100000)g`, x.clock()); err != nil {
			t.Fatal(err)
		}
		state := x.begin(t, one, recipient)
		if result, err := two.CompleteAzure(t.Context(), state, "code", recipient); !errors.Is(err, b.ErrConflict) || result != nil {
			t.Fatal("family capacity ignored", err)
		}
		if _, err := x.owner.Exec(t.Context(), `DELETE FROM ops_identity_v2.renewal_families WHERE profile_id='capacity-test'`); err != nil {
			t.Fatal(err)
		}
		if _, err := one.CompleteAzure(t.Context(), state, "code", recipient); err != nil {
			t.Fatal("capacity rejection consumed pending", err)
		}
	})
	t.Run("schema privileges retention and epoch recovery", func(t *testing.T) {
		reset()
		_, oldHandle := credentials(t, x.login(t, one, recipient))
		state := x.begin(t, one, recipient)
		if s, err := identitysql.Open(t.Context(), x.ownerDSN, x.scope, x.clock); err == nil {
			s.Close()
			t.Fatal("owner accepted")
		}
		if _, err := identitysql.Open(t.Context(), "", x.scope, x.clock); !errors.Is(err, b.ErrInvalid) {
			t.Fatal("ambient DSN accepted")
		}
		app, err := pgx.Connect(t.Context(), x.appDSN)
		if err != nil {
			t.Fatal(err)
		}
		defer app.Close(t.Context())
		for _, q := range []string{`UPDATE ops_identity_v2.metadata SET ready=true`, `UPDATE ops_identity_v2.pending_requests SET profile_id='x'`, `UPDATE ops_identity_v2.renewal_families SET recipient_hash=decode(repeat('01',32),'hex')`, `DELETE FROM ops_identity_v2.renewal_families`, `SELECT * FROM public.users`} {
			if _, err := app.Exec(t.Context(), q); err == nil {
				t.Fatal("excess privilege", q)
			}
		}
		if _, err := x.owner.Exec(t.Context(), `GRANT UPDATE(actor_id) ON ops_identity_v2.renewal_families TO broker_app`); err != nil {
			t.Fatal(err)
		}
		if bad, err := identitysql.Open(t.Context(), x.appDSN, x.scope, x.clock); err == nil {
			bad.Close()
			t.Fatal("column-only extra privilege accepted")
		}
		if err := identitysql.MigrateV2(t.Context(), x.ownerDSN, "broker_app", "broker_proof", "broker_retention", x.scope, true); err != nil {
			t.Fatal("offline exact role reconciliation", err)
		}
		if clean, err := identitysql.Open(t.Context(), x.appDSN, x.scope, x.clock); err != nil {
			t.Fatal("exact role repair", err)
		} else {
			clean.Close()
		}
		if _, err := app.Exec(t.Context(), `UPDATE ops_identity_v2.renewal_families SET generation=0 WHERE generation>0`); err == nil {
			t.Fatal("generation rollback allowed")
		}
		retention, err := identitysql.OpenRetention(t.Context(), x.retentionDSN, x.scope, x.clock)
		if err != nil {
			t.Fatal(err)
		}
		defer retention.Close()
		x.entra.Clock.Add(300)
		if counts, err := retention.CleanupOnce(t.Context(), 1000); err != nil || counts.Pending == 0 || counts.Families != 0 {
			t.Fatal("retention eligibility", counts, err)
		}
		reset()
		newScope := x.scope
		newScope.State.RecoveryEpoch = uuid.NewString()
		if err := identitysql.BeginRecovery(t.Context(), x.ownerDSN, newScope, false); !errors.Is(err, b.ErrInvalid) {
			t.Fatal("implicit drain")
		}
		if err := identitysql.BeginRecovery(t.Context(), x.ownerDSN, newScope, true); err != nil {
			t.Fatal(err)
		}
		if _, err := one.RenewAzure(t.Context(), oldHandle, recipient); !errors.Is(err, b.ErrUnavailable) {
			t.Fatal("old worker served unready", err)
		}
		if err := identitysql.FinalizeRecovery(t.Context(), x.ownerDSN, newScope, true); err != nil {
			t.Fatal(err)
		}
		if count(t, x, "pending_requests") != 0 || count(t, x, "renewal_families") != 0 {
			t.Fatal("recovery resurrected provider material")
		}
		if _, err := one.CompleteAzure(t.Context(), state, "code", recipient); !errors.Is(err, b.ErrUnavailable) {
			t.Fatal("old worker served wrong epoch", err)
		}
		x.scope = newScope
		freshStore, err := identitysql.Open(t.Context(), x.appDSN, x.scope, x.clock)
		if err != nil {
			t.Fatal(err)
		}
		defer freshStore.Close()
		fresh := x.service(t, freshStore)
		if _, err := fresh.RenewAzure(t.Context(), oldHandle, recipient); err == nil {
			t.Fatal("old handle MAC accepted new epoch")
		}
		x.login(t, fresh, recipient)
		if err := identitysql.BeginRecovery(t.Context(), x.ownerDSN, x.scope, true); !errors.Is(err, b.ErrConflict) {
			t.Fatal("same recovery epoch reused")
		}
	})
}
