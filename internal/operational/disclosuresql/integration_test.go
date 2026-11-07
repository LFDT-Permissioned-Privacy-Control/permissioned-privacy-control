package disclosuresql_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	c "privacy-proxy/internal/disclosurecase"
	"privacy-proxy/internal/disclosurehttp"
	p "privacy-proxy/internal/disclosurepolicy"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/operational/disclosuresql"
	"privacy-proxy/internal/policybundle"
)

func database(t *testing.T) (string, string, string, *pgx.Conn) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("isolated PostgreSQL integration requires Docker")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	name := "ops-v2-disclosure-test-" + uuid.NewString()[:8]
	raw, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--detach", "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD=disclosure-test-only", "--env", "POSTGRES_DB=disclosure_test", "--name", name, "postgres:16-alpine").CombinedOutput()
	if err != nil {
		t.Fatalf("start owned PostgreSQL: %v %s", err, raw)
	}
	id := strings.TrimSpace(string(raw))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if raw, err := exec.CommandContext(ctx, "docker", "rm", "--force", id).CombinedOutput(); err != nil {
			t.Logf("owned test-container cleanup: %v %s", err, raw)
		}
	})
	raw, err = exec.CommandContext(ctx, "docker", "port", id, "5432/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	address := strings.TrimSpace(string(raw))
	ownerDSN := "postgres://postgres:disclosure-test-only@" + address + "/disclosure_test?sslmode=disable"
	var owner *pgx.Conn
	for ctx.Err() == nil {
		owner, err = pgx.Connect(ctx, ownerDSN)
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("owned PostgreSQL not ready")
	}
	t.Cleanup(func() { owner.Close(context.Background()) })
	for _, role := range []string{"discl_app", "discl_retention"} {
		if _, err := owner.Exec(t.Context(), `CREATE ROLE `+pgx.Identifier{role}.Sanitize()+` LOGIN PASSWORD 'disclosure-test-only'`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := owner.Exec(t.Context(), `CREATE TABLE public.users(id integer)`); err != nil {
		t.Fatal(err)
	}
	if err := disclosuresql.Migrate(t.Context(), ownerDSN, "discl_app", "discl_retention"); err != nil {
		t.Fatal("offline migration", err)
	}
	parsed, _ := url.Parse(ownerDSN)
	parsed.User = url.UserPassword("discl_app", "disclosure-test-only")
	appDSN := parsed.String()
	parsed.User = url.UserPassword("discl_retention", "disclosure-test-only")
	return ownerDSN, appDSN, parsed.String(), owner
}
func server(t *testing.T, snapshot *policybundle.CatalogSnapshot, store c.Store, clock *atomic.Int64, epoch string) (*httptest.Server, *c.Service) {
	t.Helper()
	service, err := c.New(c.Config{Snapshot: snapshot, Clock: func() time.Time { return time.Unix(clock.Load(), 0) }, Store: store, StoreEpoch: epoch, CursorKeys: c.CursorKeys{Active: c.CursorKey{ID: "test", Key: bytes.Repeat([]byte{7}, 32)}}})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := disclosurehttp.New(service)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s, service
}
func request(t *testing.T, s *httptest.Server, token, method, path string, body any) (int, []byte) {
	t.Helper()
	var raw []byte
	switch v := body.(type) {
	case string:
		raw = []byte(v)
	case nil:
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
	r.Header.Set("Content-Type", "application/json")
	response, err := s.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	out, err := io.ReadAll(io.LimitReader(response.Body, c.MaxResponseBytes+1))
	if err != nil {
		t.Fatal(err)
	}
	if response.Header.Get("Cache-Control") != "no-store" && response.StatusCode < 400 {
		t.Fatal("missing no-store")
	}
	return response.StatusCode, out
}
func createRequest() c.CreateRequest {
	return c.CreateRequest{RuleID: "auditor", RecipientActorID: f.Actor(f.Subject), CaseReference: "INV-123", Purpose: "Review bounded treasury activity", LegalBasis: "Institution-authorized investigation", Scope: f.Scope(), ExpiresAt: f.Now + 1200, IdempotencyKey: uuid.NewString()}
}
func count(t *testing.T, owner *pgx.Conn, table string) int {
	t.Helper()
	var n int
	if err := owner.QueryRow(t.Context(), `SELECT count(*) FROM ops_v2.`+pgx.Identifier{table}.Sanitize()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

type afterCommit struct {
	c.Store
	after func()
}

func (s afterCommit) WithLockedCase(ctx context.Context, id, epoch string, version int64, authorize func(c.Case) (c.Event, error)) (c.CommitReceipt, error) {
	receipt, err := s.Store.WithLockedCase(ctx, id, epoch, version, authorize)
	if err == nil {
		s.after()
	}
	return receipt, err
}

func TestCaseHTTPAndPostgresSecurityProtocol(t *testing.T) {
	ownerDSN, appDSN, retentionDSN, owner := database(t)
	store, err := disclosuresql.Open(t.Context(), appDSN)
	if err != nil {
		t.Fatal("app startup schema check", err)
	}
	t.Cleanup(store.Close)
	second, err := disclosuresql.Open(t.Context(), appDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(second.Close)
	snapshot := f.Snapshot(t, nil)
	var clock atomic.Int64
	clock.Store(f.Now)
	s, service := server(t, snapshot, store, &clock, "epoch1")
	s2, _ := server(t, snapshot, second, &clock, "epoch1")
	token := f.Token(t, snapshot, f.Subject, "Auditor")
	admin := f.Token(t, snapshot, f.AdminSubject, "Admin")
	lost := f.Token(t, snapshot, f.Subject)
	req := createRequest()
	status, body := request(t, s, token, "POST", "/api/v1/disclosure/cases", req)
	var created c.CaseResponse
	if status != 201 || json.Unmarshal(body, &created) != nil || created.CaseID == "" || created.Status != "open" || count(t, owner, "disclosure_events") != 1 {
		t.Fatalf("real create failed: %d %s", status, body)
	}
	path := "/api/v1/disclosure/cases/" + created.CaseID
	t.Run("same key canonical request and conflicting retry", func(t *testing.T) {
		status, body := request(t, s2, token, "POST", "/api/v1/disclosure/cases", req)
		var again c.CaseResponse
		if status != 200 || json.Unmarshal(body, &again) != nil || again.CaseID != created.CaseID || count(t, owner, "disclosure_cases") != 1 {
			t.Fatalf("retry %d %s", status, body)
		}
		var openings int
		if err := owner.QueryRow(t.Context(), `SELECT count(*) FROM ops_v2.disclosure_events WHERE action='case_opened'`).Scan(&openings); err != nil || openings != 1 {
			t.Fatal("duplicate opening event")
		}
		conflict := req
		conflict.Purpose = "Different request"
		if code, _ := request(t, s, token, "POST", "/api/v1/disclosure/cases", conflict); code != 409 {
			t.Fatal("conflicting idempotency key", code)
		}
	})
	t.Run("authority floors and absent protected routes", func(t *testing.T) {
		before := count(t, owner, "disclosure_events")
		if code, _ := request(t, s, token, "HEAD", path, nil); code != 405 || count(t, owner, "disclosure_events") != before {
			t.Fatal("implicit HEAD executed a GET operation", code)
		}
		for _, roles := range [][]string{{}, {"Readonly"}, {"Local"}, {"Foreign"}} {
			bad := f.Token(t, snapshot, f.AdminSubject, roles...)
			if code, raw := request(t, s, bad, "GET", path, nil); code != 404 || bytes.Contains(raw, []byte(req.Purpose)) {
				t.Fatalf("metadata leak %v %d %s", roles, code, raw)
			}
		}
		if code, _ := request(t, s, admin, "GET", path, nil); code != 200 {
			t.Fatal("true own-org admin history", code)
		}
		if code, _ := request(t, s, "", "GET", path, nil); code != 401 {
			t.Fatal("unauthenticated case read", code)
		}
		if code, _ := request(t, s, token, "POST", "/api/v1/disclosure/cases", `{"ruleId":"auditor","ruleId":"auditor"}`); code != 400 {
			t.Fatal("duplicate JSON accepted", code)
		}
		for _, suffix := range []string{"/activity", "/reports/activity_summary", "/approve", "/events"} {
			if code, _ := request(t, s, token, "GET", path+suffix, nil); code != 404 {
				t.Fatal("unfinished protected/approval route mounted", suffix, code)
			}
		}
	})
	t.Run("rule removed retry admin and recipient metadata gate", func(t *testing.T) {
		removed := f.Snapshot(t, []p.RuleSource{})
		gone, _ := server(t, removed, store, &clock, "epoch1")
		if code, raw := request(t, gone, token, "GET", path, nil); code != 404 || bytes.Contains(raw, []byte(req.Purpose)) {
			t.Fatal("removed rule recipient metadata", code)
		}
		// Admin created its own idempotent request; source removal must not turn
		// a current own-org management retry into active data authority.
		adminReq := createRequest()
		code, raw := request(t, s, admin, "POST", "/api/v1/disclosure/cases", adminReq)
		if code != 201 {
			t.Fatalf("admin initial %d %s", code, raw)
		}
		code, raw = request(t, gone, admin, "POST", "/api/v1/disclosure/cases", adminReq)
		if code != 200 {
			t.Fatalf("admin history retry %d %s", code, raw)
		}
		if code, _ := request(t, gone, token, "POST", path+"/revoke", map[string]string{"reason": "Stop access"}); code != 200 {
			t.Fatal("recipient lost-rule revoke", code)
		}
	})
	t.Run("monotonic revoke minimal after role loss", func(t *testing.T) {
		code, raw := request(t, s, lost, "POST", path+"/revoke", map[string]string{"reason": "Stop access again"})
		var result map[string]any
		if code != 200 || json.Unmarshal(raw, &result) != nil || len(result) != 3 || result["status"] != "revoked" || result["version"] != float64(2) {
			t.Fatalf("minimal idempotent revoke %d %s", code, raw)
		}
		if bytes.Contains(raw, []byte(req.Purpose)) || bytes.Contains(raw, []byte("targetActors")) {
			t.Fatal("revoke leaked metadata")
		}
		if code, _ := request(t, s, lost, "GET", path, nil); code != 404 {
			t.Fatal("role loss allowed full metadata", code)
		}
	})
	t.Run("audit failure rolls back create and suppresses output", func(t *testing.T) {
		if _, err := owner.Exec(t.Context(), `REVOKE INSERT ON ops_v2.disclosure_events FROM discl_app`); err != nil {
			t.Fatal(err)
		}
		before := count(t, owner, "disclosure_cases")
		code, raw := request(t, s, token, "POST", "/api/v1/disclosure/cases", createRequest())
		if code != 503 || count(t, owner, "disclosure_cases") != before || bytes.Contains(raw, []byte("caseId")) {
			t.Fatalf("audit failed open %d %s", code, raw)
		}
		if code, raw := request(t, s, admin, "GET", path, nil); code != 503 || bytes.Contains(raw, []byte(req.Purpose)) {
			t.Fatal("unaudited metadata returned", code)
		}
		if _, err := owner.Exec(t.Context(), `GRANT INSERT ON ops_v2.disclosure_events TO discl_app`); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("expiry after committed audit before bytes", func(t *testing.T) {
		before := count(t, owner, "disclosure_events")
		expired, _ := server(t, snapshot, afterCommit{Store: store, after: func() { clock.Store(f.Now + 300) }}, &clock, "epoch1")
		code, raw := request(t, expired, token, "GET", path, nil)
		clock.Store(f.Now)
		if code != 401 || bytes.Contains(raw, []byte(req.Purpose)) || count(t, owner, "disclosure_events") != before+1 {
			t.Fatalf("postcommit expiry %d %s", code, raw)
		}
	})
	t.Run("rule expiry during commit", func(t *testing.T) {
		rule := f.DefaultRule()
		rule.Validity.ExpiresAt = f.Now + 10
		tight := f.Snapshot(t, []p.RuleSource{rule})
		before := count(t, owner, "disclosure_events")
		expired, _ := server(t, tight, afterCommit{Store: store, after: func() { clock.Store(f.Now + 11) }}, &clock, "epoch1")
		code, raw := request(t, expired, token, "GET", path, nil)
		clock.Store(f.Now)
		if code != 404 || bytes.Contains(raw, []byte(req.Purpose)) || count(t, owner, "disclosure_events") != before+1 {
			t.Fatalf("postcommit rule expiry %d %s", code, raw)
		}
	})
	t.Run("schema roles immutable columns and no reopen", func(t *testing.T) {
		app, err := pgx.Connect(t.Context(), appDSN)
		if err != nil {
			t.Fatal(err)
		}
		defer app.Close(context.Background())
		for _, sql := range []string{`UPDATE ops_v2.disclosure_cases SET purpose='changed'`, `DELETE FROM ops_v2.disclosure_events`, `SELECT * FROM public.users`, `UPDATE ops_v2.disclosure_schema_version SET version=2`, `UPDATE ops_v2.disclosure_cases SET status='open',version=version+1 WHERE status='revoked'`} {
			if _, err := app.Exec(t.Context(), sql); err == nil {
				t.Fatal("application role escaped envelope", sql)
			}
		}
		if err := disclosuresql.Migrate(t.Context(), ownerDSN, "discl_app", "discl_retention"); err != nil {
			t.Fatal("idempotent offline schema", err)
		}
		if _, err := owner.Exec(t.Context(), `UPDATE ops_v2.disclosure_schema_version SET version=2`); err != nil {
			t.Fatal(err)
		}
		bad, err := disclosuresql.Open(t.Context(), appDSN)
		if bad != nil {
			bad.Close()
		}
		if err == nil {
			t.Fatal("unknown schema auto-accepted")
		}
		if _, err := owner.Exec(t.Context(), `UPDATE ops_v2.disclosure_schema_version SET version=1`); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("concurrent duplicate across two stores", func(t *testing.T) {
		wanted := createRequest()
		var wg sync.WaitGroup
		var ids [2]string
		var failures [2]error
		for i, endpoint := range []*httptest.Server{s, s2} {
			wg.Add(1)
			go func(i int, endpoint *httptest.Server) {
				defer wg.Done()
				raw, _ := json.Marshal(wanted)
				r, _ := http.NewRequestWithContext(t.Context(), "POST", endpoint.URL+"/api/v1/disclosure/cases", bytes.NewReader(raw))
				r.Header.Set("Authorization", "Bearer "+token)
				response, err := endpoint.Client().Do(r)
				if err != nil {
					failures[i] = err
					return
				}
				defer response.Body.Close()
				var out c.CaseResponse
				if json.NewDecoder(response.Body).Decode(&out) != nil || response.StatusCode >= 300 {
					failures[i] = fmt.Errorf("status %d", response.StatusCode)
					return
				}
				ids[i] = out.CaseID
			}(i, endpoint)
		}
		wg.Wait()
		if failures[0] != nil || failures[1] != nil || ids[0] == "" || ids[0] != ids[1] {
			t.Fatal("concurrent idempotency", ids, failures)
		}
	})
	t.Run("restore epoch rejects rows and old unique key", func(t *testing.T) {
		restored, _ := server(t, snapshot, store, &clock, "epoch2")
		if code, _ := request(t, restored, admin, "GET", path, nil); code != 404 {
			t.Fatal("old epoch row returned", code)
		}
		if code, _ := request(t, restored, token, "POST", "/api/v1/disclosure/cases", req); code != 409 {
			t.Fatal("old epoch unique key leaked or reopened", code)
		}
	})
	t.Run("case audit separate from chain-event output", func(t *testing.T) {
		code, raw := request(t, s, token, "GET", path+"/audit?limit=1", nil)
		var page struct {
			Items  []map[string]any `json:"items"`
			Cursor string           `json:"nextCursor"`
		}
		if code != 200 || json.Unmarshal(raw, &page) != nil || len(page.Items) != 1 || page.Cursor == "" {
			t.Fatalf("audit page %d %s", code, raw)
		}
		if bytes.Contains(raw, []byte(req.Purpose)) || bytes.Contains(raw, []byte("targetActors")) {
			t.Fatal("audit leaked scope/free text")
		}
		if code, _ := request(t, s, admin, "GET", path+"/audit?limit=1&cursor="+url.QueryEscape(page.Cursor), nil); code != 409 {
			t.Fatal("cross-actor cursor accepted", code)
		}
		if code, _ := request(t, s, token, "GET", path+"/audit?limit=1&cursor="+url.QueryEscape(page.Cursor+"A"), nil); code != 400 {
			t.Fatal("tampered cursor accepted", code)
		}
	})
	t.Run("prepared but unsent audit and bounded retention", func(t *testing.T) {
		before := count(t, owner, "disclosure_events")
		prepared, err := service.Get(t.Context(), admin, created.CaseID)
		if err != nil || prepared == nil || count(t, owner, "disclosure_events") != before+1 {
			t.Fatal("prepared audit not durable", err)
		}
		r := disclosuresql.DefaultRetention()
		r.Batch = 1
		events, cases, err := disclosuresql.CleanupOnce(t.Context(), retentionDSN, time.Unix(f.Now, 0).Add(8*365*24*time.Hour), r)
		if err != nil || events > 1 || cases > 1 {
			t.Fatal("bounded retention", events, cases, err)
		}
	})
	t.Run("actual commit failure returns no receipt or metadata", func(t *testing.T) {
		_, err := owner.Exec(t.Context(), `CREATE FUNCTION ops_v2.test_fail_commit()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'test commit failure';END;$$;CREATE CONSTRAINT TRIGGER test_fail_commit AFTER INSERT ON ops_v2.disclosure_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ops_v2.test_fail_commit()`)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := owner.Exec(context.Background(), `DROP TRIGGER test_fail_commit ON ops_v2.disclosure_events;DROP FUNCTION ops_v2.test_fail_commit()`); err != nil {
				t.Error(err)
			}
		})
		before := count(t, owner, "disclosure_events")
		code, raw := request(t, s, admin, "GET", path, nil)
		if code != 503 || bytes.Contains(raw, []byte(req.Purpose)) || count(t, owner, "disclosure_events") != before {
			t.Fatalf("commit failed open %d %s", code, raw)
		}
		beforeCases := count(t, owner, "disclosure_cases")
		code, raw = request(t, s, token, "POST", "/api/v1/disclosure/cases", createRequest())
		if code != 503 || bytes.Contains(raw, []byte("caseId")) || count(t, owner, "disclosure_cases") != beforeCases {
			t.Fatalf("create commit failed open %d %s", code, raw)
		}
	})
	t.Run("lock timeout suppresses unaudited metadata", func(t *testing.T) {
		tx, err := owner.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(t.Context(), `SELECT case_id FROM ops_v2.disclosure_cases WHERE case_id=$1::uuid FOR UPDATE`, created.CaseID); err != nil {
			t.Fatal(err)
		}
		before := count(t, owner, "disclosure_events")
		code, raw := request(t, s2, admin, "GET", path, nil)
		if code != 503 || bytes.Contains(raw, []byte(req.Purpose)) || count(t, owner, "disclosure_events") != before {
			t.Fatal("lock timeout failed open", code)
		}
	})
	t.Run("whole original metadata scope after rule narrowing", func(t *testing.T) {
		rule := f.DefaultRule()
		rule.Resources = []p.Resource{p.ActivitySummary}
		narrow := f.Snapshot(t, []p.RuleSource{rule})
		tight, _ := server(t, narrow, store, &clock, "epoch1")
		if code, raw := request(t, tight, token, "GET", path, nil); code != 404 || bytes.Contains(raw, []byte(req.Purpose)) {
			t.Fatal("old transaction metadata survived narrower rule", code)
		}
		if code, _ := request(t, tight, admin, "GET", path, nil); code != 200 {
			t.Fatal("narrowing removed true-admin history", code)
		}
		if code, raw := request(t, tight, token, "POST", path+"/revoke", map[string]string{"reason": "Stop narrowed case"}); code != 200 || bytes.Contains(raw, []byte(req.Purpose)) {
			t.Fatal("narrowing revoke metadata leak", code)
		}
	})
	t.Run("startup rejects owner and legacy broad credentials", func(t *testing.T) {
		bad, err := disclosuresql.Open(t.Context(), ownerDSN)
		if bad != nil {
			bad.Close()
		}
		if err == nil {
			t.Fatal("owner credentials accepted by app adapter")
		}
		if _, err := owner.Exec(t.Context(), `GRANT SELECT ON public.users TO discl_app`); err != nil {
			t.Fatal(err)
		}
		bad, err = disclosuresql.Open(t.Context(), appDSN)
		if bad != nil {
			bad.Close()
		}
		if _, restoreErr := owner.Exec(t.Context(), `REVOKE SELECT ON public.users FROM discl_app`); restoreErr != nil {
			t.Fatal(restoreErr)
		}
		if err == nil {
			t.Fatal("legacy broad credentials accepted")
		}
	})
	t.Run("SQL byte constraint counts UTF8 bytes", func(t *testing.T) {
		wanted := createRequest()
		wanted.CaseReference = strings.Repeat("€", 100)
		if code, _ := request(t, s, token, "POST", "/api/v1/disclosure/cases", wanted); code != 400 {
			t.Fatal("service character count bypass", code)
		}
		app, err := pgx.Connect(t.Context(), appDSN)
		if err != nil {
			t.Fatal(err)
		}
		defer app.Close(context.Background())
		_, err = app.Exec(t.Context(), `INSERT INTO ops_v2.disclosure_cases SELECT gen_random_uuid(),store_epoch,creator_actor,recipient_actor,rule_id,data_org,original_rule_digest,original_bundle_digest,request_digest,immutable_scope,$1,purpose,legal_basis,created_at,expires_at,'open',1,gen_random_uuid(),NULL,NULL,NULL FROM ops_v2.disclosure_cases WHERE case_id=$2::uuid`, strings.Repeat("€", 100), created.CaseID)
		if err == nil {
			t.Fatal("SQL character count bypass")
		}
	})
	t.Run("two stores serialize read audit against revoke", func(t *testing.T) {
		code, raw := request(t, s, token, "POST", "/api/v1/disclosure/cases", createRequest())
		var opened c.CaseResponse
		if code != 201 || json.Unmarshal(raw, &opened) != nil {
			t.Fatalf("race fixture %d %s", code, raw)
		}
		namespace, namespaceErr := c.Namespace(snapshot.Metadata(), "epoch1")
		if namespaceErr != nil {
			t.Fatal(namespaceErr)
		}
		row, err := store.Get(t.Context(), opened.CaseID, namespace)
		if err != nil {
			t.Fatal(err)
		}
		event := func(row c.Case, action string) c.Event {
			return c.Event{ID: uuid.NewString(), CaseID: row.ID, Epoch: row.Epoch, Actor: f.Actor(f.Subject), Action: action, Outcome: "allowed", RuleID: row.RuleID, RuleDigest: row.OriginalRuleDigest, BundleDigest: row.OriginalBundleDigest, AttemptID: uuid.NewString(), CaseVersion: row.Version, PreparedAt: time.Unix(f.Now, 0), Summary: c.EventSummary{Count: 1, RuleContext: "current"}}
		}
		started := make(chan struct{})
		release := make(chan struct{})
		readDone := make(chan error, 1)
		revokeDone := make(chan error, 1)
		go func() {
			receipt, err := store.WithLockedCase(t.Context(), row.ID, row.Epoch, row.Version, func(locked c.Case) (c.Event, error) {
				close(started)
				select {
				case <-release:
				case <-t.Context().Done():
					return c.Event{}, t.Context().Err()
				}
				return event(locked, "metadata_read"), nil
			})
			if err == nil && receipt.AttemptID == "" {
				err = fmt.Errorf("no committed read receipt")
			}
			readDone <- err
		}()
		<-started
		go func() {
			updated, receipt, err := second.Revoke(t.Context(), row.ID, row.Epoch, row.RecipientActor, "Stop access", func(current c.Case) error {
				if current.RecipientActor != row.RecipientActor {
					return c.ErrNotFound
				}
				return nil
			}, func(current c.Case) (c.Event, error) { return event(current, "case_revoked"), nil })
			if err == nil && (updated.Version != 2 || receipt.AttemptID == "") {
				err = fmt.Errorf("no committed revoke transition")
			}
			revokeDone <- err
		}()
		close(release)
		if err := <-readDone; err != nil {
			t.Fatal("read-first linearization", err)
		}
		if err := <-revokeDone; err != nil {
			t.Fatal("revoke-after-read", err)
		}
		if _, err := store.WithLockedCase(t.Context(), row.ID, row.Epoch, row.Version, func(current c.Case) (c.Event, error) { return event(current, "metadata_read"), nil }); !errors.Is(err, c.ErrConflict) {
			t.Fatal("stale pre-revoke version accepted", err)
		}
	})
	t.Run("filtered scan cap returns encrypted continuation", func(t *testing.T) {
		_, err := owner.Exec(t.Context(), `INSERT INTO ops_v2.disclosure_cases SELECT gen_random_uuid(),store_epoch,creator_actor,recipient_actor,rule_id,data_org,original_rule_digest,original_bundle_digest,request_digest,immutable_scope,case_reference,purpose,legal_basis,created_at+n*INTERVAL '1 microsecond',expires_at,'open',1,gen_random_uuid(),NULL,NULL,NULL FROM ops_v2.disclosure_cases CROSS JOIN generate_series(1,501)n WHERE case_id=$1::uuid`, created.CaseID)
		if err != nil {
			t.Fatal(err)
		}
		removed := f.Snapshot(t, []p.RuleSource{})
		filtered, _ := server(t, removed, store, &clock, "epoch1")
		var page struct {
			Items    []c.CaseResponse `json:"items"`
			Cursor   string           `json:"nextCursor"`
			Complete bool             `json:"scanComplete"`
		}
		code, raw := request(t, filtered, token, "GET", "/api/v1/disclosure/cases?limit=1", nil)
		if code != 200 || json.Unmarshal(raw, &page) != nil || len(page.Items) != 0 || page.Complete || page.Cursor == "" || strings.Contains(page.Cursor, created.CaseID) {
			t.Fatalf("scan cap false end/leak %d %s", code, raw)
		}
		code, raw = request(t, filtered, token, "GET", "/api/v1/disclosure/cases?limit=1&cursor="+url.QueryEscape(page.Cursor), nil)
		page.Items = nil
		if code != 200 || json.Unmarshal(raw, &page) != nil || len(page.Items) != 0 || !page.Complete || page.Cursor != "" {
			t.Fatalf("continuation did not complete %d %s", code, raw)
		}
	})
	t.Run("selected environment and chain isolate shared storage", func(t *testing.T) {
		for _, selection := range []struct{ environment, chain string }{{"other-env", "1"}, {"test", "2"}} {
			other := f.SelectedSnapshot(t, nil, selection.environment, selection.chain)
			endpoint, _ := server(t, other, store, &clock, "epoch1")
			if code, _ := request(t, endpoint, admin, "GET", path, nil); code != 404 {
				t.Fatal("cross-selection case returned", selection, code)
			}
			if code, _ := request(t, endpoint, token, "POST", "/api/v1/disclosure/cases", req); code != 409 {
				t.Fatal("cross-selection physical unique key reopened", selection, code)
			}
		}
	})
}
