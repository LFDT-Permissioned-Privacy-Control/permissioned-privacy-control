package admissionsql_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
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
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/compliancehttp"
	"privacy-proxy/internal/compliancepolicy"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
	"privacy-proxy/internal/transactioninput"
)

type database struct {
	ownerDSN, appDSN, readerDSN, retentionDSN string
	owner                                     *pgx.Conn
	one, two                                  *admissionsql.Store
}

func setup(t *testing.T) *database {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("requires owned Docker PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--detach", "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD=admission-test-only", "--env", "POSTGRES_DB=admission_test", "--name", "ops-v2-admission-test-"+uuid.NewString()[:8], "postgres:16-alpine").CombinedOutput()
	if err != nil {
		t.Fatalf("owned PostgreSQL: %v %s", err, raw)
	}
	id := strings.TrimSpace(string(raw))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if raw, err := exec.CommandContext(ctx, "docker", "rm", "--force", id).CombinedOutput(); err != nil {
			t.Logf("owned cleanup: %v %s", err, raw)
		}
	})
	raw, err = exec.CommandContext(ctx, "docker", "port", id, "5432/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	d := &database{ownerDSN: "postgres://postgres:admission-test-only@" + strings.TrimSpace(string(raw)) + "/admission_test?sslmode=disable"}
	for ctx.Err() == nil {
		d.owner, err = pgx.Connect(ctx, d.ownerDSN)
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
		_ = d.owner.Close(ctx)
	})
	for _, role := range []string{"admission_app", "admission_reader", "admission_retention"} {
		if _, err := d.owner.Exec(t.Context(), `CREATE ROLE `+pgx.Identifier{role}.Sanitize()+` LOGIN PASSWORD 'admission-test-only'`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.owner.Exec(t.Context(), `CREATE TABLE public.users(id integer)`); err != nil {
		t.Fatal(err)
	}
	if err := admissionsql.Migrate(t.Context(), d.ownerDSN, "admission_app", "admission_reader", "admission_retention"); err != nil {
		t.Fatal("offline migration", err)
	}
	u, _ := url.Parse(d.ownerDSN)
	u.User = url.UserPassword("admission_app", "admission-test-only")
	d.appDSN = u.String()
	u.User = url.UserPassword("admission_reader", "admission-test-only")
	d.readerDSN = u.String()
	u.User = url.UserPassword("admission_retention", "admission-test-only")
	d.retentionDSN = u.String()
	d.one, err = admissionsql.Open(t.Context(), d.appDSN)
	if err != nil {
		t.Fatal("narrow app startup", err)
	}
	t.Cleanup(d.one.Close)
	d.two, err = admissionsql.Open(t.Context(), d.appDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.two.Close)
	return d
}
func source() compliancepolicy.Source {
	s := compliancepolicy.Source{APIVersion: compliancepolicy.APIVersion, Kind: compliancepolicy.Kind, Organizations: []compliancepolicy.OrganizationPolicy{}, Sanctions: []compliancepolicy.SourceSanction{}}
	for _, org := range []string{f.Org, f.OtherOrg} {
		s.Organizations = append(s.Organizations, compliancepolicy.OrganizationPolicy{OrganizationID: org, RecordMaxSeconds: 60, PriceMaxAgeSeconds: 60, Spec: compliancepolicy.SourceSpec{Settings: compliancepolicy.SourceSettings{Enabled: true, ThresholdFiat: 1, Currency: "usd", UnknownPricePolicy: "forbidden", EnforcementMode: "enforce"}, AddressThresholds: []compliancepolicy.SourceThreshold{}, TokenPrices: []compliancepolicy.SourceTokenPrice{{ID: uuid.NewString(), TokenAddress: "native", Symbol: "ETH", Decimals: 18, PricesByCurrency: map[string]float64{"usd": 1}, CoingeckoID: ""}}}})
	}
	return s
}

type fixture struct {
	db           *database
	snapshot     *policybundle.CatalogSnapshot
	binding      a.NetworkBinding
	key          a.Digest
	state        a.ExpectedState
	clock        atomic.Int64
	one, two     *a.Service
	http         *httptest.Server
	token, admin string
	quotes       a.QuoteProvider
}

func newFixture(t *testing.T, d *database, src compliancepolicy.Source) *fixture {
	return newFixtureQuotes(t, d, src, nil)
}
func newFixtureQuotes(t *testing.T, d *database, src compliancepolicy.Source, quotes a.QuoteProvider) *fixture {
	t.Helper()
	x := &fixture{db: d, snapshot: f.ComplianceSnapshot(t, src), binding: a.NetworkBinding{Environment: "test", ChainID: "1", GenesisHash: "0x" + strings.Repeat("0", 63) + "1", DeploymentID: uuid.NewString()}, state: a.ExpectedState{Generation: uuid.NewString(), Coverage: admissionsql.EmptyCoverage()}}
	x.key, _ = x.binding.Key()
	x.quotes = quotes
	x.clock.Store(f.Now)
	if err := admissionsql.BootstrapEmpty(t.Context(), d.ownerDSN, x.binding, x.state.Generation); err != nil {
		t.Fatal(err)
	}
	x.one = x.service(t, d.one, nil)
	x.two = x.service(t, d.two, nil)
	h, err := compliancehttp.New(x.one)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	x.http = httptest.NewServer(mux)
	t.Cleanup(x.http.Close)
	x.token = f.Token(t, x.snapshot, f.Subject, "Auditor")
	x.admin = f.Token(t, x.snapshot, f.AdminSubject, "Admin")
	return x
}
func (x *fixture) service(t *testing.T, store a.Store, quotes a.QuoteProvider) *a.Service {
	t.Helper()
	if quotes == nil {
		quotes = x.quotes
	}
	s, err := a.New(a.Config{Snapshot: x.snapshot, Clock: func() time.Time { return time.Unix(x.clock.Load(), 0).UTC() }, NetworkBinding: x.binding, ExpectedState: x.state, Store: store, QuoteProvider: quotes, ExpectedEvidenceProfile: rpcexecution.GuardRetainedProfileID, CursorKeyring: a.CursorKeyring{Active: a.CursorKey{ID: "test", Key: bytes.Repeat([]byte{8}, 32)}}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func request(t *testing.T, x *fixture, token, method, path string, value any) (int, []byte) {
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
	r, err := http.NewRequestWithContext(t.Context(), method, x.http.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := x.http.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, a.MaxResponseBytes+1))
	if err != nil || len(body) > a.MaxResponseBytes {
		t.Fatal("response bound")
	}
	if resp.StatusCode < 400 && resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("private cache headers")
	}
	return resp.StatusCode, body
}

const base = "/api/v2/orgs/" + f.Org + "/compliance/"

func createRequest(actor string) a.CreateRecordRequest {
	return a.CreateRecordRequest{OriginatorActorID: actor, OriginatorData: json.RawMessage(`{"name":"origin"}`), BeneficiaryData: json.RawMessage(`{"name":"beneficiary"}`), TransferType: compliance.TransferTypeETH, BeneficiaryAddress: "0x0000000000000000000000000000000000000002", AmountWei: "3000000000000000000"}
}
func (x *fixture) record(t *testing.T, actor string) a.RecordDTO {
	t.Helper()
	status, raw := request(t, x, x.admin, "POST", base+"travel-rule-records", createRequest(actor))
	if status != 200 {
		t.Fatalf("create %d %s", status, raw)
	}
	var r a.RecordDTO
	if json.Unmarshal(raw, &r) != nil || r.ID == "" || r.AmountFiat != 3 {
		t.Fatalf("record %s", raw)
	}
	return r
}
func (x *fixture) input(t *testing.T, nonce uint64, value *big.Int, token, org string, qualified bool) a.TrustedRawInput {
	t.Helper()
	key, _ := crypto.HexToECDSA(strings.Repeat("0", 63) + "1")
	to := common.HexToAddress(createRequest("").BeneficiaryAddress)
	tx, err := types.SignTx(types.NewTransaction(nonce, to, value, 100000, big.NewInt(1), nil), types.LatestSignerForChainID(big.NewInt(1)), key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := tx.MarshalBinary()
	v, err := transactioninput.DecodeRaw("0x"+hex.EncodeToString(raw), "1", transactioninput.ProtectedEVMProfile(), transactioninput.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	client, err := rpcexecution.NewClient(http.DefaultTransport, rpcexecution.NodeBinding{OrganizationID: org, URL: "http://127.0.0.1:1", ChainID: "1", Profile: rpcexecution.GuardRetainedProfileID, PragueStartInclusive: 0, PragueEndExclusive: uint64(f.Now + 10000), AllowUnauthenticated: true}, rpcexecution.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	client, err = client.WithCredential("")
	if err != nil {
		t.Fatal(err)
	}
	calls, _ := json.Marshal(map[string]any{"type": "CALL", "from": v.Signer().Hex(), "to": to.Hex(), "input": "0x", "value": "0x" + value.Text(16), "gas": "0x186a0", "gasUsed": "0x5208", "output": "0x", "calls": []any{}, "logs": []any{}})
	execution, err := client.QualifyTrustedGuardEvidence(t.Context(), v, rpcexecution.TrustedGuardEvidence{Profile: rpcexecution.GuardRetainedProfileID, Calls: calls, Prestate: []byte(`{"` + to.Hex() + `":{}}`), ChainID: 1, TransactionHash: v.Hash(), Fingerprint: common.HexToHash("0x1"), HashMode: 3, HeaderHash: common.HexToHash("0x1234"), HeaderNumber: 42, HeaderTimestamp: uint64(f.Now), HeaderPresent: true})
	if err != nil {
		t.Fatal(err)
	}
	factory, err := runtimepolicy.NewFactory(x.snapshot, func() time.Time { return time.Unix(x.clock.Load(), 0).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	view, err := factory.Build(token)
	if err != nil {
		t.Fatal(err)
	}
	input := a.TrustedRawInput{View: view, OrganizationID: org, Transaction: v, Execution: execution}
	if qualified {
		input.WalletSnapshot, err = nativeadmission.NewWalletSnapshot(view.ActorID(), a.HashParts("test-wallet", []byte(view.ActorID())).String(), time.Unix(f.Now-1, 0).UTC(), []common.Address{v.Signer()})
		if err != nil {
			t.Fatal(err)
		}
	}
	return input
}
func count(t *testing.T, x *fixture, table string) int {
	t.Helper()
	var n int
	switch table {
	case "travel_records", "compliance_events", "qualified_tx_origins", "extra_privacy_witnesses", "tx_shares":
	default:
		t.Fatal("invalid test table")
	}
	if err := x.db.owner.QueryRow(t.Context(), `SELECT count(*)FROM ops_admission_v2.`+table+` WHERE network_key=$1`, x.key[:]).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
func check(t *testing.T, s *a.Service, input a.TrustedRawInput, allowed bool) *a.CommittedResult {
	t.Helper()
	r, err := s.CheckAndRecordRaw(t.Context(), input)
	if err != nil {
		t.Fatal("check", err)
	}
	if r.Decision().Allowed != allowed {
		t.Fatalf("allowed=%v want%v", r.Decision().Allowed, allowed)
	}
	receipt, ok := r.Receipt()
	if ok != allowed {
		t.Fatal("receipt decision")
	}
	if allowed {
		if !receipt.Matches(input) || receipt.RequirePublishable() != nil {
			t.Fatal("receipt binding")
		}
	}
	return r
}

func TestPostgresAdmissionProtocol(t *testing.T) {
	d := setup(t)
	t.Run("actual admin HTTP and scoped used retry", func(t *testing.T) {
		x := newFixture(t, d, source())
		record := x.record(t, f.Actor(f.Subject))
		input := x.input(t, 1, big.NewInt(2e18), x.token, f.Org, false)
		r := check(t, x.one, input, true)
		if r.Decision().RecordID != record.ID {
			t.Fatal("wrong claimed record")
		}
		if count(t, x, "compliance_events") != 1 || count(t, x, "qualified_tx_origins") != 0 {
			t.Fatal("unqualified privacy row")
		}
		x.clock.Store(f.Now + 61)
		r = check(t, x.two, input, true)
		if r.Decision().RecordID != record.ID {
			t.Fatal("expired USED retry did not reuse")
		}
		status, body := request(t, x, x.admin, "GET", base+"events", nil)
		if status != 200 || !bytes.Contains(body, []byte(`"root_transfer"`)) {
			t.Fatalf("events %d %s", status, body)
		}
		status, _ = request(t, x, x.admin, "DELETE", base+"travel-rule-records/"+record.ID, nil)
		if status != 409 {
			t.Fatal("deleted used record", status)
		}
		status, body = request(t, x, x.admin, "GET", base+"travel-rule-records", nil)
		if status != 200 || bytes.Contains(body, []byte("originatorData")) {
			t.Fatalf("metadata list %d %s", status, body)
		}
	})
	t.Run("two pools cannot consume one unused record", func(t *testing.T) {
		x := newFixture(t, d, source())
		x.record(t, f.Actor(f.Subject))
		one := x.input(t, 2, big.NewInt(2e18), x.token, f.Org, false)
		two := x.input(t, 3, big.NewInt(2e18), x.token, f.Org, false)
		var wg sync.WaitGroup
		results := make(chan bool, 2)
		failures := make(chan error, 2)
		for i, input := range []a.TrustedRawInput{one, two} {
			wg.Add(1)
			go func(i int, input a.TrustedRawInput) {
				defer wg.Done()
				service := x.one
				if i == 1 {
					service = x.two
				}
				r, err := service.CheckAndRecordRaw(t.Context(), input)
				if err != nil {
					failures <- err
					return
				}
				results <- r.Decision().Allowed
			}(i, input)
		}
		wg.Wait()
		close(results)
		close(failures)
		for err := range failures {
			t.Fatal(err)
		}
		allowed := 0
		for yes := range results {
			if yes {
				allowed++
			}
		}
		if allowed != 1 || count(t, x, "compliance_events") != 2 {
			t.Fatal("non atomic claim", allowed)
		}
	})
	t.Run("readonly financial preview consumes and logs nothing", func(t *testing.T) {
		x := newFixture(t, d, source())
		x.record(t, f.Actor(f.Subject))
		input := x.input(t, 4, big.NewInt(2e18), x.token, f.Org, false)
		before := count(t, x, "compliance_events")
		status, body := request(t, x, x.admin, "POST", base+"preview", a.PreviewRequest{OriginatorActorID: f.Actor(f.Subject), SignedTransaction: input.Transaction.RawHex()})
		if status != 200 || !bytes.Contains(body, []byte(`"allowed":true`)) {
			t.Fatalf("preview %d %s", status, body)
		}
		if count(t, x, "compliance_events") != before {
			t.Fatal("preview logged")
		}
		check(t, x.one, input, true)
	})
	t.Run("audit failure rolls record and every privacy effect back", func(t *testing.T) {
		x := newFixture(t, d, source())
		r := x.record(t, f.Actor(f.Subject))
		input := x.input(t, 5, big.NewInt(2e18), x.token, f.Org, true)
		s := x.service(t, hookStore{Store: d.one, auditFailure: true}, nil)
		result, err := s.CheckAndRecordRaw(t.Context(), input)
		if !errors.Is(err, compliance.ErrAuditUnavailable) || result != nil {
			t.Fatal("audit failure", err)
		}
		if count(t, x, "compliance_events") != 0 || count(t, x, "qualified_tx_origins") != 0 {
			t.Fatal("audit partial commit")
		}
		checkUnused(t, x, r.ID)
		check(t, x.two, input, true)
	})
	t.Run("origin failure rolls financial audit and claim back", func(t *testing.T) {
		x := newFixture(t, d, source())
		r := x.record(t, f.Actor(f.Subject))
		input := x.input(t, 6, big.NewInt(2e18), x.token, f.Org, true)
		s := x.service(t, hookStore{Store: d.one, originFailure: true}, nil)
		result, err := s.CheckAndRecordRaw(t.Context(), input)
		if !errors.Is(err, a.ErrUnavailable) || result != nil {
			t.Fatal("origin failure", err)
		}
		if count(t, x, "compliance_events") != 0 {
			t.Fatal("partial financial audit")
		}
		checkUnused(t, x, r.ID)
	})
	t.Run("denial remains audited when JWT expires after decision", func(t *testing.T) {
		x := newFixture(t, d, source())
		input := x.input(t, 7, big.NewInt(2e18), x.token, f.Org, false)
		s := x.service(t, hookStore{Store: d.one, afterAudit: func() { x.clock.Store(f.Now + 301) }}, nil)
		result, err := s.CheckAndRecordRaw(t.Context(), input)
		if err != nil || result.Decision().Allowed {
			t.Fatal("denial lost", err)
		}
		if _, ok := result.Receipt(); ok || count(t, x, "compliance_events") != 1 {
			t.Fatal("denial receipt or missing audit")
		}
	})
	t.Run("newly claimed record expires before commit", func(t *testing.T) {
		x := newFixture(t, d, source())
		r := x.record(t, f.Actor(f.Subject))
		input := x.input(t, 8, big.NewInt(2e18), x.token, f.Org, true)
		s := x.service(t, hookStore{Store: d.one, afterAudit: func() { x.clock.Store(f.Now + 61) }}, nil)
		result, err := s.CheckAndRecordRaw(t.Context(), input)
		if !errors.Is(err, a.ErrConflict) || result != nil {
			t.Fatal("expired unused claim", err)
		}
		checkUnused(t, x, r.ID)
		if count(t, x, "compliance_events") != 0 || count(t, x, "qualified_tx_origins") != 0 {
			t.Fatal("expired partial commit")
		}
	})
	t.Run("decision clock is sampled after hash lock", func(t *testing.T) {
		x := newFixture(t, d, source())
		r := x.record(t, f.Actor(f.Subject))
		input := x.input(t, 9, big.NewInt(2e18), x.token, f.Org, false)
		hold, err := d.owner.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		first, second := a.HashLock(x.key, input.Transaction.Hash())
		if _, err := hold.Exec(t.Context(), `SELECT pg_advisory_xact_lock($1::integer,$2::integer)`, first, second); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			result, err := x.one.CheckAndRecordRaw(t.Context(), input)
			if err == nil && result.Decision().Allowed {
				err = errors.New("expired unused record allowed")
			}
			done <- err
		}()
		observer, err := pgx.Connect(t.Context(), d.ownerDSN)
		if err != nil {
			t.Fatal(err)
		}
		defer observer.Close(t.Context())
		waiting := false
		for deadline := time.Now().Add(500 * time.Millisecond); time.Now().Before(deadline); {
			if err := observer.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_stat_activity s ON s.pid=l.pid WHERE l.locktype='advisory' AND NOT l.granted AND s.usename='admission_app')`).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if !waiting {
			_ = hold.Rollback(t.Context())
			t.Fatal("no actual lock wait")
		}
		x.clock.Store(f.Now + 61)
		if err := hold.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		checkUnused(t, x, r.ID)
	})
	t.Run("JWT expiry after allowed commit prevents first publication", func(t *testing.T) {
		x := newFixture(t, d, source())
		x.record(t, f.Actor(f.Subject))
		input := x.input(t, 10, big.NewInt(2e18), x.token, f.Org, false)
		s := x.service(t, hookStore{Store: d.one, afterCommit: func() { x.clock.Store(f.Now + 301) }}, nil)
		result, err := s.CheckAndRecordRaw(t.Context(), input)
		if err != nil {
			t.Fatal(err)
		}
		receipt, ok := result.Receipt()
		if !ok || !errors.Is(receipt.RequirePublishable(), a.ErrUnauthorized) {
			t.Fatal("stale publication")
		}
		if count(t, x, "compliance_events") != 1 {
			t.Fatal("not committed")
		}
	})
	t.Run("commit acknowledgment ambiguity produces no receipt", func(t *testing.T) {
		x := newFixture(t, d, source())
		record := x.record(t, f.Actor(f.Subject))
		input := x.input(t, 11, big.NewInt(2e18), x.token, f.Org, false)
		s := x.service(t, hookStore{Store: d.one, commitUnknown: true}, nil)
		result, err := s.CheckAndRecordRaw(t.Context(), input)
		if !errors.Is(err, a.ErrUnavailable) || result != nil {
			t.Fatal("ambiguous commit receipt", err)
		}
		if count(t, x, "compliance_events") != 1 {
			t.Fatal("fixture did not actually commit")
		}
		r := check(t, x.two, input, true)
		if r.Decision().RecordID != record.ID {
			t.Fatal("fresh retry rebound")
		}
	})
	t.Run("database connection teardown before commit rolls back", func(t *testing.T) {
		x := newFixture(t, d, source())
		r := x.record(t, f.Actor(f.Subject))
		input := x.input(t, 12, big.NewInt(2e18), x.token, f.Org, false)
		s := x.service(t, hookStore{Store: d.one, beforeCommit: func() {
			var killed int
			if err := d.owner.QueryRow(t.Context(), `SELECT count(*)FROM(SELECT pg_terminate_backend(pid)FROM pg_stat_activity WHERE usename='admission_app' AND state='idle in transaction')x`).Scan(&killed); err != nil || killed != 1 {
				t.Errorf("teardown %d %v", killed, err)
			}
		}}, nil)
		result, err := s.CheckAndRecordRaw(t.Context(), input)
		if !errors.Is(err, a.ErrUnavailable) || result != nil {
			t.Fatal("torn connection receipt", err)
		}
		checkUnused(t, x, r.ID)
		if count(t, x, "compliance_events") != 0 {
			t.Fatal("torn connection partial commit")
		}
	})
	t.Run("same hash in two actor scopes uses each own record", func(t *testing.T) {
		x := newFixture(t, d, source())
		one := x.record(t, f.Actor(f.Subject))
		two := x.record(t, f.Actor(f.AdminSubject))
		inputA := x.input(t, 13, big.NewInt(2e18), x.token, f.Org, true)
		inputB := x.input(t, 13, big.NewInt(2e18), x.admin, f.Org, true)
		if check(t, x.one, inputA, true).Decision().RecordID != one.ID || check(t, x.two, inputB, true).Decision().RecordID != two.ID {
			t.Fatal("borrowed cross-actor record")
		}
		if count(t, x, "qualified_tx_origins") != 1 || count(t, x, "extra_privacy_witnesses") != 0 {
			t.Fatal("B changed A provenance")
		}
	})
	t.Run("bound coverage mismatch cannot borrow fresh record", func(t *testing.T) {
		src := source()
		x := newFixture(t, d, src)
		x.record(t, f.Actor(f.Subject))
		input := x.input(t, 14, big.NewInt(2e18), x.token, f.Org, false)
		check(t, x.one, input, true)
		// A new approved source values this same transfer higher. Its own
		// unused record would cover it; the immutable old binding does not.
		src.Organizations[0].Spec.TokenPrices[0].PricesByCurrency["usd"] = 2
		x.snapshot = f.ComplianceSnapshot(t, src)
		x.admin = f.Token(t, x.snapshot, f.AdminSubject, "Admin")
		x.token = f.Token(t, x.snapshot, f.Subject, "Auditor")
		x.one = x.service(t, d.one, nil)
		resp, err := x.one.CreateRecord(t.Context(), x.admin, f.Org, createRequest(f.Actor(f.Subject)))
		if err != nil {
			t.Fatal(err)
		}
		var body bytes.Buffer
		if _, err := resp.WriteTo(&body); err != nil {
			t.Fatal(err)
		}
		input = x.input(t, 14, big.NewInt(2e18), x.token, f.Org, false)
		check(t, x.one, input, false)
		var used int
		if err := d.owner.QueryRow(t.Context(), `SELECT count(*)FROM ops_admission_v2.travel_records WHERE network_key=$1 AND used_at IS NOT NULL`, x.key[:]).Scan(&used); err != nil || used != 1 {
			t.Fatal("rebound coverage", used, err)
		}
	})
	t.Run("first nonempty share is immutable and not a recipient union", func(t *testing.T) {
		src := source()
		for i := range src.Organizations {
			src.Organizations[i].Spec.Settings.Enabled = false
		}
		x := newFixture(t, d, src)
		aInput := x.input(t, 15, big.NewInt(2e18), x.token, f.Org, true)
		check(t, x.one, aInput, true)
		if count(t, x, "tx_shares") != 0 {
			t.Fatal("empty share reserved")
		}
		bInput := x.input(t, 15, big.NewInt(2e18), x.admin, f.Org, true)
		bInput.Audience = []string{f.Actor(f.Subject)}
		check(t, x.two, bInput, true)
		check(t, x.one, bInput, true)
		changed := bInput
		changed.Audience = []string{f.Actor(f.AdminSubject)}
		result, err := x.one.CheckAndRecordRaw(t.Context(), changed)
		if !errors.Is(err, a.ErrConflict) || result != nil {
			t.Fatal("widened share", err)
		}
		foreign := x.input(t, 15, big.NewInt(2e18), f.Token(t, x.snapshot, f.AdminSubject, "Foreign"), f.OtherOrg, true)
		foreign.Audience = []string{f.Actor(f.Subject)}
		if _, err := x.two.CheckAndRecordRaw(t.Context(), foreign); !errors.Is(err, a.ErrConflict) {
			t.Fatal("cross-org share", err)
		}
		var owner string
		if err := d.owner.QueryRow(t.Context(), `SELECT actor_id FROM ops_admission_v2.qualified_tx_origins WHERE network_key=$1`, x.key[:]).Scan(&owner); err != nil || owner != aInput.View.ActorID() {
			t.Fatal("rewritten owner")
		}
		if count(t, x, "tx_shares") != 1 || count(t, x, "extra_privacy_witnesses") != 0 {
			t.Fatal("share row or witness amplification")
		}
	})
	for _, qualified := range []bool{false, true} {
		for _, foreign := range []bool{false, true} {
			for _, disabled := range []bool{false, true} {
				name := "other actor relay intent/" + boolText(qualified) + "-proof/" + boolText(foreign) + "-foreign/" + boolText(disabled) + "-disabled"
				t.Run(name, func(t *testing.T) {
					src := source()
					for i := range src.Organizations {
						src.Organizations[i].Spec.Settings.Enabled = !disabled
					}
					x := newFixture(t, d, src)
					value := big.NewInt(0)
					if disabled {
						value = big.NewInt(2e18)
					}
					one := x.input(t, 16, value, x.token, f.Org, true)
					check(t, x.one, one, true)
					before := count(t, x, "compliance_events")
					token, org := x.admin, f.Org
					if foreign {
						token = f.Token(t, x.snapshot, f.AdminSubject, "Foreign")
						org = f.OtherOrg
					}
					two := x.input(t, 16, value, token, org, qualified)
					check(t, x.two, two, true)
					if count(t, x, "compliance_events") != before+1 || count(t, x, "qualified_tx_origins") != 1 || count(t, x, "extra_privacy_witnesses") != 0 {
						t.Fatal("missing own intent or forged A witness")
					}
					var actor, kind string
					if err := d.owner.QueryRow(t.Context(), `SELECT actor_id,kind FROM ops_admission_v2.compliance_events WHERE network_key=$1 ORDER BY id DESC LIMIT 1`, x.key[:]).Scan(&actor, &kind); err != nil || actor != two.View.ActorID() || kind != "admission_only" {
						t.Fatal("false intent", err)
					}
				})
			}
		}
	}
}

func boolText(b bool) string {
	if b {
		return "with"
	}
	return "without"
}
func checkUnused(t *testing.T, x *fixture, id string) {
	t.Helper()
	var unused bool
	if err := x.db.owner.QueryRow(t.Context(), `SELECT used_at IS NULL FROM ops_admission_v2.travel_records WHERE id=$1::uuid`, id).Scan(&unused); err != nil || !unused {
		t.Fatal("record consumed", err)
	}
}

type hookStore struct {
	a.Store
	auditFailure, originFailure, commitUnknown bool
	afterAudit, beforeCommit, afterCommit      func()
}

func (s hookStore) WithRawTransaction(ctx context.Context, scope a.Scope, fn func(a.RawTx) (a.CommitKind, error)) (a.CommitReceipt, error) {
	r, err := s.Store.WithRawTransaction(ctx, scope, func(tx a.RawTx) (a.CommitKind, error) {
		kind, err := fn(hookTx{RawTx: tx, store: s})
		if err == nil && s.beforeCommit != nil {
			s.beforeCommit()
		}
		return kind, err
	})
	if err == nil {
		if s.afterCommit != nil {
			s.afterCommit()
		}
		if s.commitUnknown {
			return a.CommitReceipt{}, a.ErrUnavailable
		}
	}
	return r, err
}

type hookTx struct {
	a.RawTx
	store hookStore
}

func (t hookTx) AppendEvent(e a.Event) (int64, error) {
	if t.store.auditFailure {
		return 0, a.ErrUnavailable
	}
	id, err := t.RawTx.AppendEvent(e)
	if err == nil && t.store.afterAudit != nil {
		t.store.afterAudit()
	}
	return id, err
}
func (t hookTx) PutOrigin(o a.Origin) (bool, error) {
	if t.store.originFailure {
		return false, a.ErrUnavailable
	}
	return t.RawTx.PutOrigin(o)
}
