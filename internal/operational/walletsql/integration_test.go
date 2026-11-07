package walletsql_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/operational/walletsql"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/walletadapter"
	"privacy-proxy/internal/wallethttp"
	w "privacy-proxy/internal/walletops"
	"privacy-proxy/internal/walletproof"
)

type fixture struct {
	ownerDSN, appDSN, readerDSN, retentionDSN string
	owner                                     *pgx.Conn
	binding                                   w.ServiceBinding
	state                                     w.ExpectedState
	ns                                        w.Namespace
	snapshot                                  *policybundle.CatalogSnapshot
	clock                                     atomic.Int64
	store, other                              *walletsql.Store
	one, two                                  *httptest.Server
	token, otherToken                         string
}

type afterCommit struct {
	w.Store
	after func()
}

func (s afterCommit) WithActorTransaction(ctx context.Context, ns w.Namespace, state w.ExpectedState, actor string, callback func(w.ActorTx) error) error {
	err := s.Store.WithActorTransaction(ctx, ns, state, actor, callback)
	if err == nil {
		s.after()
	}
	return err
}

type ensResolver func(context.Context, common.Address) (w.ENSMetadata, error)

type afterOwnershipInsert struct {
	w.Store
	after func()
}
type afterOwnershipTx struct {
	w.ActorTx
	after func()
}

func (s afterOwnershipInsert) WithActorTransaction(ctx context.Context, ns w.Namespace, state w.ExpectedState, actor string, callback func(w.ActorTx) error) error {
	return s.Store.WithActorTransaction(ctx, ns, state, actor, func(tx w.ActorTx) error { return callback(afterOwnershipTx{tx, s.after}) })
}
func (t afterOwnershipTx) InsertOwnership(link w.Link) (bool, error) {
	inserted, err := t.ActorTx.InsertOwnership(link)
	if err == nil {
		t.after()
	}
	return inserted, err
}

func (fn ensResolver) Lookup(ctx context.Context, address common.Address) (w.ENSMetadata, error) {
	return fn(ctx, address)
}

func setup(t *testing.T) *fixture {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("wallet protocol requires Docker PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--detach", "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD=wallet-test-only", "--env", "POSTGRES_DB=wallet_test", "--name", "ops-v2-wallet-test-"+uuid.NewString()[:8], "postgres:16-alpine").CombinedOutput()
	if err != nil {
		t.Fatalf("owned PostgreSQL: %v %s", err, raw)
	}
	id := strings.TrimSpace(string(raw))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if raw, err := exec.CommandContext(ctx, "docker", "rm", "--force", id).CombinedOutput(); err != nil {
			t.Logf("owned container cleanup: %v %s", err, raw)
		}
	})
	raw, err = exec.CommandContext(ctx, "docker", "port", id, "5432/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	x := &fixture{ownerDSN: "postgres://postgres:wallet-test-only@" + strings.TrimSpace(string(raw)) + "/wallet_test?sslmode=disable"}
	for ctx.Err() == nil {
		x.owner, err = pgx.Connect(ctx, x.ownerDSN)
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("owned PostgreSQL readiness")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = x.owner.Close(ctx)
	})
	for _, role := range []string{"wallet_app", "wallet_reader", "wallet_retention"} {
		if _, err := x.owner.Exec(t.Context(), `CREATE ROLE `+pgx.Identifier{role}.Sanitize()+` LOGIN PASSWORD 'wallet-test-only'`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := x.owner.Exec(t.Context(), `CREATE TABLE public.users(id integer)`); err != nil {
		t.Fatal(err)
	}
	if err := walletsql.Migrate(t.Context(), x.ownerDSN, "wallet_app", "wallet_reader", "wallet_retention"); err != nil {
		t.Fatal("offline wallet migration", err)
	}
	u, _ := url.Parse(x.ownerDSN)
	u.User = url.UserPassword("wallet_app", "wallet-test-only")
	x.appDSN = u.String()
	u.User = url.UserPassword("wallet_reader", "wallet-test-only")
	x.readerDSN = u.String()
	u.User = url.UserPassword("wallet_retention", "wallet-test-only")
	x.retentionDSN = u.String()
	x.binding = w.ServiceBinding{ServiceOrigin: "https://ops.test", Environment: "test", ChainID: "1", GenesisHash: "0x" + strings.Repeat("0", 63) + "1", DeploymentID: "wallet-protocol"}
	x.ns, err = x.binding.Namespace()
	if err != nil {
		t.Fatal(err)
	}
	x.state = w.ExpectedState{Generation: uuid.NewString(), Coverage: walletsql.EmptyCoverage()}
	if err := walletsql.BootstrapEmpty(t.Context(), x.ownerDSN, x.binding, x.state.Generation); err != nil {
		t.Fatal("explicit bootstrap", err)
	}
	x.store, err = walletsql.Open(t.Context(), x.appDSN)
	if err != nil {
		t.Fatal("narrow application startup", err)
	}
	t.Cleanup(x.store.Close)
	x.other, err = walletsql.Open(t.Context(), x.appDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(x.other.Close)
	x.snapshot = f.Snapshot(t, nil)
	x.clock.Store(f.Now)
	x.one = server(t, x, x.store, nil, nil)
	x.two = server(t, x, x.other, nil, nil)
	x.token = f.Token(t, x.snapshot, f.Subject)
	x.otherToken = f.Token(t, x.snapshot, f.AdminSubject)
	return x
}
func server(t *testing.T, x *fixture, store w.Store, ens w.ENSResolver, audit w.AuditSink) *httptest.Server {
	t.Helper()
	service, err := w.New(w.Config{Snapshot: x.snapshot, Clock: func() time.Time { return time.Unix(x.clock.Load(), 0) }, Binding: x.binding, State: x.state, Store: store, ENS: ens, Audit: audit})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := wallethttp.New(service)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}
func request(t *testing.T, s *httptest.Server, token, method, path string, value any) (int, []byte) {
	t.Helper()
	var raw []byte
	switch v := value.(type) {
	case nil:
	case string:
		raw = []byte(v)
	default:
		var err error
		raw, err = json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
	}
	r, err := http.NewRequestWithContext(t.Context(), method, s.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := s.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	out, err := io.ReadAll(io.LimitReader(response.Body, w.MaxResponseBytes+1))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) > w.MaxResponseBytes {
		t.Fatal("unbounded response")
	}
	if response.StatusCode < 400 && response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("missing no-store")
	}
	return response.StatusCode, out
}
func key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}
func address(k *ecdsa.PrivateKey) string { return w.AddressString(crypto.PubkeyToAddress(k.PublicKey)) }
func issue(t *testing.T, x *fixture, token string, k *ecdsa.PrivateKey) w.ChallengeResult {
	t.Helper()
	status, raw := request(t, x.one, token, "POST", "/api/v2/eth/link/challenge", w.ChallengeRequest{Address: address(k)})
	if status != 200 {
		t.Fatalf("issue %d %s", status, raw)
	}
	var c w.ChallengeResult
	if json.Unmarshal(raw, &c) != nil {
		t.Fatal("challenge decode")
	}
	return c
}
func signed(t *testing.T, c w.ChallengeResult, k *ecdsa.PrivateKey) w.VerifyRequest {
	t.Helper()
	sig, err := crypto.Sign(walletproof.HashMessage(c.Message), k)
	if err != nil {
		t.Fatal(err)
	}
	sig[64] += 27
	return w.VerifyRequest{Nonce: c.Nonce, Address: address(k), Signature: "0x" + hex.EncodeToString(sig)}
}
func link(t *testing.T, x *fixture, token string, k *ecdsa.PrivateKey) {
	t.Helper()
	c := issue(t, x, token, k)
	status, raw := request(t, x.two, token, "POST", "/api/v2/eth/link/verify", signed(t, c, k))
	if status != 200 {
		t.Fatalf("link %d %s", status, raw)
	}
}
func rowCount(t *testing.T, x *fixture, table string) int {
	t.Helper()
	var n int
	if err := x.owner.QueryRow(t.Context(), `SELECT count(*) FROM ops_wallet_v2.`+pgx.Identifier{table}.Sanitize()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestWalletPostgresHTTPProtocol(t *testing.T) {
	x := setup(t)
	t.Run("selected binding and identity-only own management", func(t *testing.T) {
		k := key(t)
		c := issue(t, x, x.token, k)
		if !strings.Contains(c.Message, "Actor: "+f.Actor(f.Subject)) || !strings.Contains(c.Message, "Address: "+address(k)) || !strings.Contains(c.Message, "Network: "+x.ns.String()) || strings.HasSuffix(c.Message, "\n") {
			t.Fatal("message not fully bound")
		}
		if status, _ := request(t, x.two, x.token, "POST", "/api/v2/eth/link/verify", signed(t, c, k)); status != 200 {
			t.Fatal(status)
		}
		if status, _ := request(t, x.one, x.token, "POST", "/api/v2/eth/link/verify", signed(t, c, k)); status != 409 {
			t.Fatal("consumed retry", status)
		}
		status, raw := request(t, x.one, x.token, "GET", "/api/v2/eth/addresses", nil)
		if status != 200 || !bytes.Contains(raw, []byte(address(k))) {
			t.Fatalf("own-list %d %s", status, raw)
		}
		status, raw = request(t, x.one, x.otherToken, "GET", "/api/v2/eth/addresses", nil)
		if status != 200 || string(raw) != "[]\n" {
			t.Fatalf("other identity leak %d %s", status, raw)
		}
		bad := x.binding
		bad.ChainID = "2"
		if _, err := w.New(w.Config{Snapshot: x.snapshot, Clock: time.Now, Binding: bad, State: x.state, Store: x.store}); !errors.Is(err, w.ErrInvalid) {
			t.Fatal("snapshot/network mismatch accepted")
		}
	})
	t.Run("wrong actor address key malformed proof and expiry do not consume", func(t *testing.T) {
		k := key(t)
		other := key(t)
		c := issue(t, x, x.token, k)
		req := signed(t, c, k)
		if status, _ := request(t, x.two, x.otherToken, "POST", "/api/v2/eth/link/verify", req); status != 409 {
			t.Fatal("wrong actor", status)
		}
		wrong := req
		wrong.Address = address(other)
		if status, _ := request(t, x.two, x.token, "POST", "/api/v2/eth/link/verify", wrong); status != 409 {
			t.Fatal("wrong address", status)
		}
		wrong = signed(t, c, other)
		wrong.Address = address(k)
		if status, _ := request(t, x.two, x.token, "POST", "/api/v2/eth/link/verify", wrong); status != 400 {
			t.Fatal("wrong signer", status)
		}
		wrong = req
		wrong.Signature = "0x" + strings.Repeat("0", 130)
		if status, _ := request(t, x.two, x.token, "POST", "/api/v2/eth/link/verify", wrong); status != 400 {
			t.Fatal("malformed scalar", status)
		}
		if status, _ := request(t, x.two, x.token, "POST", "/api/v2/eth/link/verify", req); status != 200 {
			t.Fatal("failed proofs consumed nonce", status)
		}
		c = issue(t, x, x.token, key(t))
		x.clock.Store(f.Now + 300)
		if status, _ := request(t, x.two, x.token, "POST", "/api/v2/eth/link/verify", req); status != 401 {
			t.Fatal("expired JWT", status)
		}
		x.clock.Store(f.Now)
	})
	t.Run("concurrent verify and fresh proof preserve immutable link", func(t *testing.T) {
		k := key(t)
		c := issue(t, x, x.token, k)
		req := signed(t, c, k)
		before := rowCount(t, x, "wallet_links")
		codes := make(chan int, 2)
		var wg sync.WaitGroup
		for _, s := range []*httptest.Server{x.one, x.two} {
			wg.Add(1)
			go func(s *httptest.Server) {
				defer wg.Done()
				code, _ := request(t, s, x.token, "POST", "/api/v2/eth/link/verify", req)
				codes <- code
			}(s)
		}
		wg.Wait()
		close(codes)
		seen := map[int]int{}
		for code := range codes {
			seen[code]++
		}
		if seen[200] != 1 || seen[409] != 1 || rowCount(t, x, "wallet_links") != before+1 {
			t.Fatal("verify not one-use", seen)
		}
		var original []byte
		if err := x.owner.QueryRow(t.Context(), `SELECT message FROM ops_wallet_v2.wallet_links WHERE namespace=$1 AND actor_id=$2 AND address=$3`, x.ns[:], f.Actor(f.Subject), common.HexToAddress(address(k)).Bytes()).Scan(&original); err != nil {
			t.Fatal(err)
		}
		x.clock.Store(f.Now + 1)
		link(t, x, x.token, k)
		x.clock.Store(f.Now)
		var retained []byte
		if err := x.owner.QueryRow(t.Context(), `SELECT message FROM ops_wallet_v2.wallet_links WHERE namespace=$1 AND actor_id=$2 AND address=$3`, x.ns[:], f.Actor(f.Subject), common.HexToAddress(address(k)).Bytes()).Scan(&retained); err != nil || !bytes.Equal(original, retained) {
			t.Fatal("duplicate rewrote proof", err)
		}
	})
	t.Run("expired challenge rejected while JWT is still live", func(t *testing.T) {
		defer x.clock.Store(f.Now)
		x.clock.Store(f.Now - 1)
		k := key(t)
		c := issue(t, x, x.token, k)
		x.clock.Store(f.Now + 299)
		if status, _ := request(t, x.two, x.token, "POST", "/api/v2/eth/link/verify", signed(t, c, k)); status != 409 {
			t.Fatal("expired challenge accepted", status)
		}
	})
	t.Run("challenge expires while waiting for another replica actor lock", func(t *testing.T) {
		defer x.clock.Store(f.Now)
		subject := uuid.NewString()
		actor := f.Actor(subject)
		token := f.Token(t, x.snapshot, subject)
		k := key(t)
		x.clock.Store(f.Now - 1)
		c := issue(t, x, token, k)
		x.clock.Store(f.Now + 298)
		a, b := w.ActorLock(x.ns, actor)
		tx, err := x.owner.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		if _, err := tx.Exec(t.Context(), `SELECT pg_advisory_xact_lock($1::integer,$2::integer)`, a, b); err != nil {
			t.Fatal(err)
		}
		done := make(chan int, 1)
		go func() {
			status, _ := request(t, x.two, token, "POST", "/api/v2/eth/link/verify", signed(t, c, k))
			done <- status
		}()
		waiting := false
		deadline := time.Now().Add(800 * time.Millisecond)
		for time.Now().Before(deadline) {
			if err := x.owner.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND classid=$1::oid AND objid=$2::oid AND objsubid=2 AND NOT granted)`, int64(uint32(a)), int64(uint32(b))).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if !waiting {
			t.Fatal("verify never reached actual shared actor lock")
		}
		x.clock.Store(f.Now + 299)
		if err := tx.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
		select {
		case status := <-done:
			if status != 409 {
				t.Fatal("stale pre-lock challenge time accepted", status)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("verify did not finish after lock release")
		}
		var links, challenges int
		if err := x.owner.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM ops_wallet_v2.wallet_links WHERE namespace=$1 AND actor_id=$2),(SELECT count(*)FROM ops_wallet_v2.wallet_challenges WHERE namespace=$1 AND actor_id=$2)`, x.ns[:], actor).Scan(&links, &challenges); err != nil || links != 0 || challenges != 1 {
			t.Fatal("expiry wait consumed or linked", links, challenges, err)
		}
	})
	t.Run("challenge expiry at callback completion rolls back proof and consumption", func(t *testing.T) {
		defer x.clock.Store(f.Now)
		subject := uuid.NewString()
		actor := f.Actor(subject)
		token := f.Token(t, x.snapshot, subject)
		k := key(t)
		x.clock.Store(f.Now - 1)
		c := issue(t, x, token, k)
		x.clock.Store(f.Now + 298)
		s := server(t, x, afterOwnershipInsert{x.store, func() { x.clock.Store(f.Now + 299) }}, nil, nil)
		if status, _ := request(t, s, token, "POST", "/api/v2/eth/link/verify", signed(t, c, k)); status != 409 {
			t.Fatal("expired callback committed", status)
		}
		var links, challenges int
		if err := x.owner.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM ops_wallet_v2.wallet_links WHERE namespace=$1 AND actor_id=$2),(SELECT count(*)FROM ops_wallet_v2.wallet_challenges WHERE namespace=$1 AND actor_id=$2)`, x.ns[:], actor).Scan(&links, &challenges); err != nil || links != 0 || challenges != 1 {
			t.Fatal("late expiry consumed or linked", links, challenges, err)
		}
	})
	t.Run("cross replica challenge capacity includes expired rows and cleanup is bounded", func(t *testing.T) {
		defer x.clock.Store(f.Now)
		x.clock.Store(f.Now - 10)
		token := f.Token(t, x.snapshot, uuid.NewString())
		k := key(t)
		var wg sync.WaitGroup
		codes := make(chan int, 20)
		for i := range 20 {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				s := x.one
				if i%2 == 1 {
					s = x.two
				}
				code, _ := request(t, s, token, "POST", "/api/v2/eth/link/challenge", w.ChallengeRequest{Address: address(k)})
				codes <- code
			}(i)
		}
		wg.Wait()
		close(codes)
		seen := map[int]int{}
		for code := range codes {
			seen[code]++
		}
		if seen[200] != 8 || seen[409] != 12 {
			t.Fatal("actor cap raced", seen)
		}
		x.clock.Store(f.Now + 291)
		if status, _ := request(t, x.one, token, "POST", "/api/v2/eth/link/challenge", w.ChallengeRequest{Address: address(k)}); status != 200 {
			t.Fatal("expired capacity could not recover", status)
		}
	})
	t.Run("tombstones count toward permanent link capacity", func(t *testing.T) {
		subject := uuid.NewString()
		actor := f.Actor(subject)
		token := f.Token(t, x.snapshot, subject)
		if _, err := x.owner.Exec(t.Context(), `INSERT INTO ops_wallet_v2.wallet_links(namespace,actor_id,address,proof_kind,revoked,revoked_at)SELECT $1,$2,decode(lpad(to_hex(g),40,'0'),'hex'),'legacy_revoked',true,$3 FROM generate_series(1,4096)g`, x.ns[:], actor, time.Unix(f.Now-1, 0)); err != nil {
			t.Fatal(err)
		}
		if status, _ := request(t, x.one, token, "POST", "/api/v2/eth/link/challenge", w.ChallengeRequest{Address: address(key(t))}); status != 409 {
			t.Fatal("tombstone capacity bypass", status)
		}
		if status, raw := request(t, x.one, token, "GET", "/api/v2/eth/addresses", nil); status != 200 || string(raw) != "[]\n" {
			t.Fatal("tombstones returned as ownership", status)
		}
	})
	t.Run("deferred commit failure restores nonce and creates no ownership", func(t *testing.T) {
		k := key(t)
		c := issue(t, x, x.token, k)
		req := signed(t, c, k)
		before := rowCount(t, x, "wallet_links")
		if _, err := x.owner.Exec(t.Context(), `CREATE FUNCTION ops_wallet_v2.test_commit_failure()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'controlled commit failure';END$$;CREATE CONSTRAINT TRIGGER test_commit_failure AFTER INSERT ON ops_wallet_v2.wallet_links DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ops_wallet_v2.test_commit_failure()`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_, _ = x.owner.Exec(t.Context(), `DROP TRIGGER IF EXISTS test_commit_failure ON ops_wallet_v2.wallet_links;DROP FUNCTION IF EXISTS ops_wallet_v2.test_commit_failure()`)
		}()
		if status, raw := request(t, x.two, x.token, "POST", "/api/v2/eth/link/verify", req); status != 503 || bytes.Contains(raw, []byte(`"linked"`)) {
			t.Fatal("success before commit", status, string(raw))
		}
		if rowCount(t, x, "wallet_links") != before {
			t.Fatal("failed commit left link")
		}
		if _, err := x.owner.Exec(t.Context(), `DROP TRIGGER test_commit_failure ON ops_wallet_v2.wallet_links;DROP FUNCTION ops_wallet_v2.test_commit_failure()`); err != nil {
			t.Fatal(err)
		}
		if status, _ := request(t, x.two, x.token, "POST", "/api/v2/eth/link/verify", req); status != 200 {
			t.Fatal("rollback lost nonce", status)
		}
	})
	t.Run("expiry after commit suppresses body but does not undo link", func(t *testing.T) {
		k := key(t)
		c := issue(t, x, x.token, k)
		before := rowCount(t, x, "wallet_links")
		s := server(t, x, afterCommit{x.store, func() { x.clock.Store(f.Now + 300) }}, nil, nil)
		status, raw := request(t, s, x.token, "POST", "/api/v2/eth/link/verify", signed(t, c, k))
		x.clock.Store(f.Now)
		if status != 401 || bytes.Contains(raw, []byte(address(k))) {
			t.Fatal("expired response leaked", status, string(raw))
		}
		if rowCount(t, x, "wallet_links") != before+1 {
			t.Fatal("committed link falsely undone")
		}
		if status, _ := request(t, x.one, x.token, "POST", "/api/v2/eth/link/verify", signed(t, c, k)); status != 409 {
			t.Fatal("committed nonce not consumed", status)
		}
	})
	t.Run("permanent own revoke shared wallet and frozen audience", func(t *testing.T) {
		k := key(t)
		link(t, x, x.token, k)
		resolver, err := walletadapter.New(x.store, x.ns, x.state, func() time.Time { return time.Unix(x.clock.Load(), 0) })
		if err != nil {
			t.Fatal(err)
		}
		audience, err := resolver.ResolveRecipients(t.Context(), []string{address(k)})
		if err != nil || len(audience.Actors()) != 1 || audience.Actors()[0] != f.Actor(f.Subject) {
			t.Fatal("first audience", err)
		}
		link(t, x, x.otherToken, k)
		if _, err := resolver.ResolveRecipients(t.Context(), []string{address(k)}); !errors.Is(err, w.ErrConflict) {
			t.Fatal("ambiguous wallet selected arbitrary actor", err)
		}
		if _, err := x.store.ResolveActiveActors(t.Context(), x.ns, x.state, common.HexToAddress(address(k)), 1); !errors.Is(err, w.ErrInvalid) {
			t.Fatal("LIMIT1 ambiguity shortcut allowed", err)
		}
		if _, err := resolver.ResolveRecipients(t.Context(), make([]string, 33)); !errors.Is(err, w.ErrInvalid) {
			t.Fatal("raw recipient cap not enforced", err)
		}
		if _, err := resolver.ResolveRecipients(t.Context(), []string{f.Actor(f.Subject)}); err != nil {
			t.Fatal("explicit actor rejected", err)
		}
		old, err := resolver.Load(t.Context(), f.Actor(f.Subject))
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if status, _ := request(t, x.one, x.token, "DELETE", "/api/v2/eth/addresses/"+address(k), nil); status != 200 {
				t.Fatal("unlink", status)
			}
		}
		current, err := resolver.Load(t.Context(), f.Actor(f.Subject))
		if err != nil || current.Contains(common.HexToAddress(address(k))) || !old.Contains(common.HexToAddress(address(k))) || current.Version() == old.Version() {
			t.Fatal("revoke snapshot boundary", err)
		}
		if status, _ := request(t, x.one, x.token, "POST", "/api/v2/eth/link/challenge", w.ChallengeRequest{Address: address(k)}); status != 409 {
			t.Fatal("revoked link could re-enroll", status)
		}
		if audience.Actors()[0] != f.Actor(f.Subject) {
			t.Fatal("old audience followed new wallet owner")
		}
		fresh, err := resolver.ResolveRecipients(t.Context(), []string{address(k)})
		if err != nil || len(fresh.Actors()) != 1 || fresh.Actors()[0] != f.Actor(f.AdminSubject) {
			t.Fatal("new audience did not resolve current unique owner", err)
		}
		a := audience.Actors()
		a[0] = f.Actor(f.AdminSubject)
		if audience.Actors()[0] != f.Actor(f.Subject) {
			t.Fatal("audience mutable")
		}
	})
	t.Run("strict HTTP boundaries and unknown identity surfaces", func(t *testing.T) {
		for _, body := range []string{`{"Address":"0x0000000000000000000000000000000000000001"}`, `{"address":null}`, `{"address":"x","address":"y"}`, `{"address":"x","actorId":"x"}`, strings.Repeat(" ", w.MaxRequestBytes+1)} {
			if status, _ := request(t, x.one, x.token, "POST", "/api/v2/eth/link/challenge", body); status != 400 {
				t.Fatal("nonclosed request", status)
			}
		}
		for _, p := range []string{"/api/v2/users", "/api/v2/eth/addresses?actorId=somebody"} {
			status, _ := request(t, x.one, x.token, "GET", p, nil)
			if status != 404 && status != 400 {
				t.Fatal("directory/query accepted", status)
			}
		}
		if status, _ := request(t, x.one, x.token, "HEAD", "/api/v2/eth/addresses", nil); status != 405 {
			t.Fatal("HEAD executes GET", status)
		}
		if status, _ := request(t, x.one, "", "GET", "/api/v2/eth/addresses", nil); status != 401 {
			t.Fatal("missing JWT", status)
		}
	})
	t.Run("own ENS refresh forward confirmation and bounded best effort audit", func(t *testing.T) {
		k := key(t)
		events := make(chan w.AuditEvent, 1)
		calls := atomic.Int64{}
		s := server(t, x, x.store, ensResolver(func(ctx context.Context, a common.Address) (w.ENSMetadata, error) {
			calls.Add(1)
			return w.ENSMetadata{Name: "wallet.bank", ForwardAddress: a}, nil
		}), events)
		if status, _ := request(t, s, x.token, "POST", "/api/v2/eth/addresses/"+address(k)+"/refresh-ens", nil); status != 404 || calls.Load() != 0 {
			t.Fatal("unowned ENS lookup", status)
		}
		c := issue(t, x, x.token, k)
		if status, _ := request(t, s, x.token, "POST", "/api/v2/eth/link/verify", signed(t, c, k)); status != 200 {
			t.Fatal(status)
		}
		select {
		case event := <-events:
			if event.Actor != f.Actor(f.Subject) || event.Address != address(k) || event.Action != "link" {
				t.Fatal(event)
			}
		default:
			t.Fatal("missing committed event")
		}
		if status, raw := request(t, s, x.token, "POST", "/api/v2/eth/addresses/"+address(k)+"/refresh-ens", nil); status != 200 || !bytes.Contains(raw, []byte("wallet.bank")) {
			t.Fatal("own ENS", status, string(raw))
		}
		wrong := server(t, x, x.store, ensResolver(func(ctx context.Context, a common.Address) (w.ENSMetadata, error) {
			return w.ENSMetadata{Name: "wallet.bank", ForwardAddress: common.Address{}}, nil
		}), nil)
		if status, _ := request(t, wrong, x.token, "POST", "/api/v2/eth/addresses/"+address(k)+"/refresh-ens", nil); status != 503 {
			t.Fatal("unconfirmed ENS", status)
		}
		events <- w.AuditEvent{}
		if status, _ := request(t, s, x.token, "DELETE", "/api/v2/eth/addresses/"+address(k), nil); status != 200 {
			t.Fatal("full best effort audit blocked unlink", status)
		}
	})
	t.Run("actor advisory lock uses bounded real database wait", func(t *testing.T) {
		subject := uuid.NewString()
		actor := f.Actor(subject)
		token := f.Token(t, x.snapshot, subject)
		a, b := w.ActorLock(x.ns, actor)
		tx, err := x.owner.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		if _, err := tx.Exec(t.Context(), `SELECT pg_advisory_xact_lock($1::integer,$2::integer)`, a, b); err != nil {
			t.Fatal(err)
		}
		if status, _ := request(t, x.one, token, "POST", "/api/v2/eth/link/challenge", w.ChallengeRequest{Address: address(key(t))}); status != 503 {
			t.Fatal("unbounded/ignored actor lock", status)
		}
		if err := tx.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
		if status, _ := request(t, x.one, token, "POST", "/api/v2/eth/link/challenge", w.ChallengeRequest{Address: address(key(t))}); status != 200 {
			t.Fatal("lock failure poisoned pool", status)
		}
	})
	t.Run("least privilege role floors", func(t *testing.T) {
		reader, err := walletsql.OpenReader(t.Context(), x.readerDSN)
		if err != nil {
			t.Fatal("reader", err)
		}
		defer reader.Close()
		if _, err := reader.LoadActive(t.Context(), x.ns, x.state, f.Actor(f.Subject), w.MaxLinks+1); err != nil {
			t.Fatal(err)
		}
		if err := reader.WithActorTransaction(t.Context(), x.ns, x.state, f.Actor(f.Subject), func(w.ActorTx) error { return nil }); !errors.Is(err, w.ErrInvalid) {
			t.Fatal("reader write", err)
		}
		if s, err := walletsql.Open(t.Context(), x.ownerDSN); err == nil {
			s.Close()
			t.Fatal("DB owner accepted")
		}
		if _, err := walletsql.Open(t.Context(), ""); !errors.Is(err, w.ErrInvalid) {
			t.Fatal("ambient PG fallback", err)
		}
		conn, err := pgx.Connect(t.Context(), x.appDSN)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(t.Context())
		for _, sql := range []string{`UPDATE ops_wallet_v2.wallet_links SET message='bad'`, `DELETE FROM ops_wallet_v2.wallet_links`, `UPDATE ops_wallet_v2.wallet_challenges SET message='bad'`, `UPDATE ops_wallet_v2.store_state SET ready=true`, `SELECT * FROM public.users`} {
			if _, err := conn.Exec(t.Context(), sql); err == nil {
				t.Fatal("forbidden privilege", sql)
			}
		}
		if _, err := conn.Exec(t.Context(), `UPDATE ops_wallet_v2.wallet_links SET revoked=false,revoked_at=NULL WHERE revoked`); err == nil {
			t.Fatal("SQL revived tombstone")
		}
		if _, err := x.owner.Exec(t.Context(), `GRANT UPDATE(message) ON ops_wallet_v2.wallet_links TO wallet_app`); err != nil {
			t.Fatal(err)
		}
		if s, err := walletsql.Open(t.Context(), x.appDSN); err == nil {
			s.Close()
			t.Fatal("excess proof update not rejected")
		}
		if _, err := x.owner.Exec(t.Context(), `REVOKE UPDATE(message) ON ops_wallet_v2.wallet_links FROM wallet_app`); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("recovery preserves tombstones invalidates challenges and checks coverage", func(t *testing.T) {
		k := key(t)
		link(t, x, x.token, k)
		if status, _ := request(t, x.one, x.token, "DELETE", "/api/v2/eth/addresses/"+address(k), nil); status != 200 {
			t.Fatal(status)
		}
		pendingKey := key(t)
		c := issue(t, x, x.token, pendingKey)
		oldState := x.state
		newGeneration := uuid.NewString()
		if err := walletsql.BootstrapEmpty(t.Context(), x.ownerDSN, x.binding, newGeneration); !errors.Is(err, w.ErrConflict) {
			t.Fatal("existing namespace reset", err)
		}
		if err := walletsql.BeginRecovery(t.Context(), x.ownerDSN, x.binding, newGeneration); err != nil {
			t.Fatal(err)
		}
		if _, err := x.store.LoadActive(t.Context(), x.ns, oldState, f.Actor(f.Subject), w.MaxLinks+1); !errors.Is(err, w.ErrUnavailable) {
			t.Fatal("unready store served", err)
		}
		x.state = w.ExpectedState{Generation: newGeneration, Coverage: sha256.Sum256([]byte("operator-complete-fixture"))}
		if err := walletsql.FinalizeRecovery(t.Context(), x.ownerDSN, x.binding, x.state, false); !errors.Is(err, w.ErrInvalid) {
			t.Fatal("implicit completeness", err)
		}
		if err := walletsql.FinalizeRecovery(t.Context(), x.ownerDSN, x.binding, x.state, true); err != nil {
			t.Fatal(err)
		}
		if _, err := x.store.LoadActive(t.Context(), x.ns, oldState, f.Actor(f.Subject), w.MaxLinks+1); !errors.Is(err, w.ErrUnavailable) {
			t.Fatal("stale generation served", err)
		}
		bad := x.state
		bad.Coverage = walletsql.EmptyCoverage()
		if _, err := x.store.LoadActive(t.Context(), x.ns, bad, f.Actor(f.Subject), w.MaxLinks+1); !errors.Is(err, w.ErrUnavailable) {
			t.Fatal("wrong coverage served", err)
		}
		current := server(t, x, x.store, nil, nil)
		if status, _ := request(t, current, x.token, "POST", "/api/v2/eth/link/verify", signed(t, c, pendingKey)); status != 409 {
			t.Fatal("pre-restore challenge consumed", status)
		}
		if status, _ := request(t, current, x.token, "POST", "/api/v2/eth/link/challenge", w.ChallengeRequest{Address: address(k)}); status != 409 {
			t.Fatal("restore lost revoke", status)
		}
		// Other subtests keep the old servers; recreate them against new expected state.
		x.one = current
		x.two = server(t, x, x.other, nil, nil)
	})
	t.Run("explicit legacy revocation import coalesces and never promotes ownership", func(t *testing.T) {
		newBinding := x.binding
		newBinding.DeploymentID = "legacy-migration"
		ns, _ := newBinding.Namespace()
		generation := uuid.NewString()
		if err := walletsql.BeginRecovery(t.Context(), x.ownerDSN, newBinding, generation); err != nil {
			t.Fatal("new existing-install namespace unready", err)
		}
		k := key(t)
		batch := walletsql.RevocationBatch{APIVersion: "ops.wallet-revocations/v1", Kind: "WalletRevocationBatch", Namespace: ns.String(), SourceExportDigest: walletsql.DigestString(sha256.Sum256([]byte("source-export"))), Aliases: []walletsql.Alias{{LegacySubject: "did:legacy:one", ActorID: f.Actor(f.Subject), EvidenceDigest: walletsql.DigestString(sha256.Sum256([]byte("alias-evidence"))), IdentityAuthority: "https://login.microsoftonline.com/" + f.Tenant + "/v2.0", SourceTenant: f.Tenant, SourceKind: "human"}}, Revocations: []walletsql.Revocation{{LegacySubject: "did:legacy:one", Address: address(k), RevokedAt: time.Unix(f.Now-100, 0).UTC().Format(time.RFC3339)}}}
		raw, _ := json.Marshal(batch)
		digest := sha256.Sum256(raw)
		for i := range 2 {
			summary, err := walletsql.ImportRevocations(t.Context(), x.ownerDSN, newBinding, generation, raw, digest)
			if err != nil {
				t.Fatal(err)
			}
			if i == 0 && summary.Inserted != 1 || i == 1 && summary.Unchanged != 1 {
				t.Fatal("import idempotency", summary)
			}
		}
		state := w.ExpectedState{Generation: generation, Coverage: sha256.Sum256([]byte("complete-legacy-source"))}
		if err := walletsql.FinalizeRecovery(t.Context(), x.ownerDSN, newBinding, state, true); err != nil {
			t.Fatal(err)
		}
		facts, err := x.store.LoadActive(t.Context(), ns, state, f.Actor(f.Subject), w.MaxLinks+1)
		if err != nil || len(facts) != 0 {
			t.Fatal("legacy row became ownership", err)
		}
		if _, err := walletsql.ImportRevocations(t.Context(), x.ownerDSN, newBinding, generation, raw, digest); !errors.Is(err, w.ErrConflict) {
			t.Fatal("import while serving", err)
		}
	})
	t.Run("bounded challenge cleanup has no link deletion rights", func(t *testing.T) {
		before := rowCount(t, x, "wallet_links")
		retention, err := walletsql.OpenRetention(t.Context(), x.retentionDSN)
		if err != nil {
			t.Fatal(err)
		}
		defer retention.Close()
		if _, err := retention.CleanupOnce(t.Context(), time.Unix(f.Now+600, 0), 1000); err != nil {
			t.Fatal(err)
		}
		if rowCount(t, x, "wallet_links") != before {
			t.Fatal("retention deleted wallet state")
		}
	})
	t.Run("missing store and overprivileged state insert fail closed", func(t *testing.T) {
		dead, err := walletsql.Open(t.Context(), x.appDSN)
		if err != nil {
			t.Fatal(err)
		}
		dead.Close()
		s := server(t, x, dead, nil, nil)
		if status, raw := request(t, s, x.token, "GET", "/api/v2/eth/addresses", nil); status != 503 || string(raw) == "[]\n" {
			t.Fatal("missing store became empty success", status)
		}
		if _, err := x.owner.Exec(t.Context(), `GRANT INSERT(ready) ON ops_wallet_v2.store_state TO wallet_app`); err != nil {
			t.Fatal(err)
		}
		defer x.owner.Exec(t.Context(), `REVOKE INSERT(ready) ON ops_wallet_v2.store_state FROM wallet_app`)
		if store, err := walletsql.Open(t.Context(), x.appDSN); err == nil {
			store.Close()
			t.Fatal("column-only state insert escalation accepted")
		}
	})
	t.Run("network namespace and schema version mismatch reject", func(t *testing.T) {
		foreign := x.binding
		foreign.GenesisHash = "0x" + strings.Repeat("1", 64)
		namespace, _ := foreign.Namespace()
		if _, err := x.store.LoadActive(t.Context(), namespace, x.state, f.Actor(f.Subject), w.MaxLinks+1); !errors.Is(err, w.ErrUnavailable) {
			t.Fatal("foreign genesis reused ownership", err)
		}
		if _, err := x.owner.Exec(t.Context(), `UPDATE ops_wallet_v2.schema_version SET source_checksum='unknown'`); err != nil {
			t.Fatal(err)
		}
		defer x.owner.Exec(t.Context(), `UPDATE ops_wallet_v2.schema_version SET source_checksum=$1`, walletsql.SchemaChecksum())
		if s, err := walletsql.Open(t.Context(), x.appDSN); err == nil {
			s.Close()
			t.Fatal("schema mismatch accepted")
		}
	})
}
