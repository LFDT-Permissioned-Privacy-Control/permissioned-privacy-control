package protectedsource

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
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
	c "privacy-proxy/internal/disclosurecase"
	d "privacy-proxy/internal/disclosuredata"
	"privacy-proxy/internal/disclosurehttp"
	p "privacy-proxy/internal/disclosurepolicy"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/operational/disclosuresql"
)

// This hook schedules changes in the actual fixture after qualification and
// before its real final check. It supplies no facts, permissions or verdicts.
type eventsSourceHook struct {
	d.RetainedSources
	mu     sync.Mutex
	before func()
}
type eventsSnapshotHook struct {
	d.RetainedSnapshot
	owner *eventsSourceHook
}

func (s *eventsSourceHook) OpenRetained(ctx context.Context, scope d.ReadScope, refs []d.SourceRef, basis *d.RetainedBasis, after *d.Position) (d.RetainedSnapshot, error) {
	read, err := s.RetainedSources.OpenRetained(ctx, scope, refs, basis, after)
	if err != nil {
		return nil, err
	}
	return &eventsSnapshotHook{read, s}, nil
}
func (s *eventsSnapshotHook) CheckCurrent(ctx context.Context) error {
	s.owner.mu.Lock()
	fn := s.owner.before
	s.owner.before = nil
	s.owner.mu.Unlock()
	if fn != nil {
		fn()
	}
	return s.RetainedSnapshot.CheckCurrent(ctx)
}

// A changed, well-formed canonical header arrives through the real node
// transport. This is a deterministic reorg fault, not an ownership substitute.
type eventsCanonicalFault struct {
	base    http.RoundTripper
	enabled atomic.Bool
}

func (f *eventsCanonicalFault) RoundTrip(req *http.Request) (*http.Response, error) {
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(bytes.NewReader(raw))
	response, err := f.base.RoundTrip(req)
	if err != nil || !f.enabled.Load() {
		return response, err
	}
	var query struct {
		Method string `json:"method"`
	}
	if json.Unmarshal(raw, &query) != nil || query.Method != "eth_getHeaderByNumber" {
		return response, nil
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(body, &envelope) != nil {
		return nil, io.ErrUnexpectedEOF
	}
	var header types.Header
	if json.Unmarshal(envelope["result"], &header) == nil && header.Number != nil && header.Number.Sign() > 0 {
		header.Extra = append(append([]byte{}, header.Extra...), 1)
		envelope["result"], err = json.Marshal(&header)
		if err != nil {
			return nil, err
		}
		body, err = json.Marshal(envelope)
		if err != nil {
			return nil, err
		}
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	response.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return response, nil
}

type eventsHTTPFixture struct {
	t          *testing.T
	config     Config
	control    functionalControl
	source     *Sources
	hook       *eventsSourceHook
	store      *disclosuresql.Store
	owner      *pgx.Conn
	service    *c.Service
	server     *httptest.Server
	caseConfig c.Config
	dataConfig c.RetainedDataConfig
	now        *atomic.Int64
	token      string
	fault      *eventsCanonicalFault
}
type eventsHTTPPage struct {
	ReadID   string        `json:"readId"`
	Coverage d.CoverageDTO `json:"coverage"`
	Result   struct {
		Version    uint8        `json:"v"`
		Population string       `json:"population"`
		Items      []d.EventDTO `json:"items"`
		NextCursor *string      `json:"nextCursor"`
	} `json:"result"`
}

func actualEventsHTTP(t *testing.T, node *functionalNode) *eventsHTTPFixture {
	t.Helper()
	fault := &eventsCanonicalFault{base: node.config.Transport}
	node.config.Transport = fault
	var control functionalControl
	config := actualFunctionalConfig(t, node, func(c functionalControl) { control = c })
	// This approved snapshot deliberately grants no ordinary RPC methods or
	// Explorer contract access. Only explicit case/rule authority is relevant.
	state := f.DefaultStateFixture(t)
	state.DeliveryConsumer = true
	for org, groups := range state.Groups {
		for i := range groups {
			if !groups[i].IsOrgAdmin && !groups[i].IsOrgReadonlyAdmin {
				groups[i].AllowedMethods = []string{}
			}
		}
		state.Groups[org] = groups
	}
	rule := f.DefaultRule()
	rule.Resources = []p.Resource{p.Events, p.Transactions}
	rule.MaxLevel = p.Full
	txOnly := rule
	txOnly.ID = "transactions-only"
	txOnly.Resources = []p.Resource{p.Transactions}
	state.DisclosureRules = []p.RuleSource{rule, txOnly}
	config.Snapshot = f.StateSnapshot(t, state)
	group, ok := config.Snapshot.Group(f.Org, f.AuditorGroup)
	if !ok || len(group.AllowedMethods) != 0 {
		t.Fatal("ordinary permissions were not removed")
	}
	now := &atomic.Int64{}
	now.Store(f.Now)
	config.Clock = func() time.Time { return time.Unix(now.Load(), 0).UTC() }
	source, err := New(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	// Reuse the one task-owned PG server, not a second container.
	functionalExec(t, control.admission, `CREATE DATABASE events_cases`)
	u, err := url.Parse(control.admission.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/events_cases"
	owner, err := pgx.Connect(t.Context(), u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close(context.Background()) })
	for _, role := range []string{"events_case_app", "events_case_retention"} {
		functionalRole(t, owner, role)
	}
	if err = disclosuresql.Migrate(t.Context(), u.String(), "events_case_app", "events_case_retention"); err != nil {
		t.Fatal(err)
	}
	store, err := disclosuresql.Open(t.Context(), functionalDSN(u.String(), "events_case_app"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	hook := &eventsSourceHook{RetainedSources: source}
	cfg := c.Config{Snapshot: config.Snapshot, Clock: config.Clock, Store: store, StoreEpoch: "events-http", CursorKeys: c.CursorKeys{Active: c.CursorKey{ID: "admin", Key: bytes.Repeat([]byte{31}, 32)}}}
	data := c.RetainedDataConfig{Network: config.Network, Sources: hook, RenderKeys: config.RenderKeys, CursorKeys: d.Keys{Active: d.Key{ID: "data", Bytes: bytes.Repeat([]byte{32}, 32)}}}
	service, err := c.NewWithRetainedData(cfg, data)
	if err != nil {
		t.Fatal(err)
	}
	h := &eventsHTTPFixture{t: t, config: config, control: control, source: source, hook: hook, store: store, owner: owner, service: service, caseConfig: cfg, dataConfig: data, now: now, token: f.Token(t, config.Snapshot, f.Subject, "Auditor"), fault: fault}
	h.server = h.serve(service)
	return h
}
func (h *eventsHTTPFixture) serve(service *c.Service) *httptest.Server {
	h.t.Helper()
	handler, err := disclosurehttp.NewWithData(service)
	if err != nil {
		h.t.Fatal(err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	server := httptest.NewTLSServer(mux)
	h.t.Cleanup(server.Close)
	return server
}
func (h *eventsHTTPFixture) request(server *httptest.Server, token, path string, body any, want int) []byte {
	h.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		h.t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(h.t.Context(), http.MethodPost, server.URL+path, bytes.NewReader(raw))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	response, err := server.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err = io.ReadAll(io.LimitReader(response.Body, c.MaxResponseBytes+1))
	if err != nil {
		h.t.Fatal(err)
	}
	detail := raw
	if len(detail) > 4096 {
		detail = detail[:4096]
	}
	if want == 0 {
		if response.StatusCode < 400 || response.StatusCode > 599 {
			h.t.Fatalf("failure released HTTP%d %s", response.StatusCode, detail)
		}
	} else if response.StatusCode != want {
		h.t.Fatalf("HTTP%d want%d %s", response.StatusCode, want, detail)
	}
	if response.StatusCode >= 400 {
		var value map[string]json.RawMessage
		if json.Unmarshal(raw, &value) != nil || value["result"] != nil || value["readId"] != nil {
			h.t.Fatalf("protected failure body: %s", raw)
		}
	}
	return raw
}
func (h *eventsHTTPFixture) openCase(rule string, resources []p.Resource, level p.Level, expires int64) string {
	h.t.Helper()
	scope := p.Scope{TargetActors: []string{f.Actor(f.Subject)}, Resources: resources, Addresses: p.Addresses{Mode: "all-target-addresses", Values: []string{}}, DataTime: p.Interval{Start: f.Now - 200, End: f.Now + 10}, Level: level}
	raw := h.request(h.server, h.token, "/api/v1/disclosure/cases", c.CreateRequest{RuleID: rule, RecipientActorID: f.Actor(f.Subject), CaseReference: "EVENTS-INQUIRY", Purpose: "Receipt evidence", Scope: scope, ExpiresAt: expires, IdempotencyKey: uuid.NewString()}, 201)
	var result c.CaseResponse
	if json.Unmarshal(raw, &result) != nil || result.CaseID == "" {
		h.t.Fatal("case not created", string(raw))
	}
	return result.CaseID
}
func (h *eventsHTTPFixture) page(id string, query d.Query) (eventsHTTPPage, []byte) {
	h.t.Helper()
	raw := h.request(h.server, h.token, "/api/v1/disclosure/cases/"+id+"/read", query, 200)
	var page eventsHTTPPage
	if json.Unmarshal(raw, &page) != nil || page.Result.Version != 1 || page.Result.Population != "EVENTS_FROM_DISCLOSED_TRANSACTIONS" || page.Result.Items == nil || page.Coverage.Status != "RETAINED_AT_READ" || page.Coverage.SourceBasisDigest == "" {
		h.t.Fatal("actual Events DTO", string(raw))
	}
	wantPopulation := "RETAINED_SAME_ORG_EVENTS_FROM_DISCLOSED_TRANSACTIONS"
	found := false
	for _, s := range page.Coverage.Populations {
		if s == wantPopulation {
			found = true
		}
	}
	if !found {
		h.t.Fatal("wrong Events source population", page.Coverage)
	}
	var summaryRaw []byte
	if err := h.owner.QueryRow(h.t.Context(), `SELECT summary FROM ops_v2.disclosure_events WHERE attempt_id=$1::uuid`, page.ReadID).Scan(&summaryRaw); err != nil {
		h.t.Fatal(err)
	}
	var summary c.EventSummary
	sum := sha256.Sum256(raw)
	if json.Unmarshal(summaryRaw, &summary) != nil || summary.Count != len(page.Result.Items) || summary.Exposure == nil || summary.Exposure.Resource != p.Events || summary.Exposure.View != d.List || summary.Exposure.OutputBytes != uint32(len(raw)) || summary.Exposure.OutputDigest != "sha256:"+hex.EncodeToString(sum[:]) {
		h.t.Fatal("missing exact mandatory Events exposure", string(summaryRaw))
	}
	return page, raw
}
func (h *eventsHTTPFixture) schedule(fn func()) {
	h.hook.mu.Lock()
	h.hook.before = fn
	h.hook.mu.Unlock()
}
func (h *eventsHTTPFixture) subtest(name string, fn func(*testing.T)) {
	parent := h.t
	parent.Run(name, func(t *testing.T) { h.t = t; defer func() { h.t = parent }(); fn(t) })
}

func TestActualDisclosureEventsHTTPPaginationPrivacyAndFences(t *testing.T) {
	root := common.HexToAddress("0x1000000000000000000000000000000000000001")
	nested := common.HexToAddress("0x2000000000000000000000000000000000000002")
	foreign := common.HexToAddress("0x3000000000000000000000000000000000000003")
	unknown := common.HexToAddress("0x4000000000000000000000000000000000000004")
	canary := []byte("other-bank-batch-party-canary")
	logs := make([]*types.Log, 205)
	for i := range logs {
		logs[i] = &types.Log{Address: root, Topics: []common.Hash{{1}, {2}, {3}}, Data: append(append([]byte{}, canary...), byte(i))}
	}
	logs[0].Topics = []common.Hash{}
	logs[0].Data = []byte{}
	withheld := make([]*types.Log, 1025)
	for i := range withheld {
		withheld[i] = &types.Log{Address: foreign, Topics: []common.Hash{{9}}, Data: canary}
	}
	nestedLogs := make([]*types.Log, 207)
	for i := 0; i < 205; i++ {
		nestedLogs[i] = &types.Log{Address: nested, Topics: []common.Hash{{4}}, Data: canary}
	}
	nestedLogs[205] = &types.Log{Address: foreign, Topics: []common.Hash{{5}}, Data: canary}
	nestedLogs[206] = &types.Log{Address: unknown, Topics: []common.Hash{{6}}, Data: canary}
	node := ownedFunctionalEventNode(t, functionalEventNodeOptions{Logs: [][]*types.Log{nil, logs, withheld, nestedLogs}, Emitters: []functionalEmitter{{Address: nested, Organization: f.Org}, {Address: foreign, Organization: f.OtherOrg}}})
	h := actualEventsHTTP(t, node)
	id := h.openCase("auditor", []p.Resource{p.Events}, p.Full, f.Now+120)
	query := d.Query{Version: 1, Resource: p.Events, View: d.List, Limit: ptrFinance(uint16(100))}
	first, firstRaw := h.page(id, query)
	if len(first.Result.Items) != 100 || first.Result.NextCursor == nil || first.Result.Items[0].BlockNumber != "2" || first.Result.Items[0].LogIndex != 0 || first.Result.Items[0].Topics == nil || len(*first.Result.Items[0].Topics) != 0 || first.Result.Items[0].Data == nil || *first.Result.Items[0].Data != "0x" {
		t.Fatal("real empty log payload or zero-log parent lost", string(firstRaw))
	}
	if !strings.Contains(string(firstRaw), hex.EncodeToString(canary)) {
		t.Fatal("Full payload missing actual third-party values")
	}
	seen := map[string]bool{}
	coordinates := map[string]bool{}
	emptyAdvancing := 0
	pages := 0
	last := first
	for {
		pages++
		for _, event := range last.Result.Items {
			key := string(event.BlockNumber) + "/" + strconv.FormatUint(uint64(event.TransactionIndex), 10) + "/" + strconv.FormatUint(uint64(event.LogIndex), 10)
			if seen[event.EventID] || coordinates[key] || event.Payload != "disclosed" || event.TransactionHash == nil || event.BlockHash == nil || event.Topics == nil || event.Data == nil || event.Emitter == strings.ToLower(foreign.Hex()) || event.Emitter == strings.ToLower(unknown.Hex()) {
				t.Fatal("duplicate/private/unqualified event", key, event)
			}
			seen[event.EventID], coordinates[key] = true, true
		}
		if len(last.Result.Items) == 0 && last.Result.NextCursor != nil {
			emptyAdvancing++
		}
		if last.Result.NextCursor == nil {
			break
		}
		if pages > 10 {
			t.Fatal("nonterminating receipt continuation")
		}
		query.Cursor = last.Result.NextCursor
		last, _ = h.page(id, query)
	}
	if len(seen) != 410 || emptyAdvancing < 2 || len(last.Result.Items) != 0 {
		t.Fatal("receipt logs missing or hidden scan progress lost", len(seen), pages, emptyAdvancing)
	}
	if !coordinates["4/0/0"] || !coordinates["4/0/204"] || coordinates["4/0/205"] || coordinates["4/0/206"] {
		t.Fatal("nested emitter attribution incorrect", coordinates)
	}

	h.subtest("lower levels omit entire raw payload", func(t *testing.T) {
		for _, level := range []p.Level{p.Pseudonymous, p.Redacted} {
			q := d.Query{Version: 1, Resource: p.Events, View: d.List, Limit: ptrFinance(uint16(100)), Level: &level}
			page, raw := h.page(id, q)
			if len(page.Result.Items) != 100 || page.Result.Items[0].EventID != first.Result.Items[0].EventID {
				t.Fatal("lower-level event identity changed")
			}
			var decoded struct {
				Result struct{ Items []map[string]json.RawMessage }
			}
			if json.Unmarshal(raw, &decoded) != nil {
				t.Fatal("DTO")
			}
			for i, event := range page.Result.Items {
				if event.Payload != "withheld" || event.TransactionHash != nil || event.BlockHash != nil || event.Topics != nil || event.Data != nil {
					t.Fatal("raw lower-level payload", event)
				}
				for _, name := range []string{"transactionHash", "blockHash", "topics", "data", "targetActorIds", "isMine", "addressId"} {
					if _, ok := decoded.Result.Items[i][name]; ok {
						t.Fatal("forbidden emitter/payload field", name)
					}
				}
				if level == p.Redacted && event.Emitter != "[PRIVATE]" || level == p.Pseudonymous && !strings.HasPrefix(event.Emitter, "Address-") {
					t.Fatal("emitter display", event.Emitter)
				}
			}
			if strings.Contains(string(raw), hex.EncodeToString(canary)) || strings.Contains(string(raw), strings.ToLower(root.Hex())) || strings.Contains(string(raw), node.transactions[1].Hash().Hex()) {
				t.Fatal("lower-level raw canary leaked", string(raw))
			}
		}
	})

	h.subtest("explicit rule case recipient and filter bindings", func(t *testing.T) {
		path := "/api/v1/disclosure/cases/" + id + "/read"
		for _, token := range []string{f.Token(t, h.config.Snapshot, f.AdminSubject, "Auditor"), f.Token(t, h.config.Snapshot, f.AdminSubject, "Admin"), f.Token(t, h.config.Snapshot, f.Subject, "Foreign")} {
			h.request(h.server, token, path, d.Query{Version: 1, Resource: p.Events, View: d.List}, 404)
		}
		txID := h.openCase("transactions-only", []p.Resource{p.Transactions}, p.Full, f.Now+120)
		h.request(h.server, h.token, "/api/v1/disclosure/cases/"+txID+"/read", d.Query{Version: 1, Resource: p.Events, View: d.List}, 400)
		badScope := f.Scope()
		badScope.Resources = []p.Resource{p.Events}
		badScope.Level = p.Full
		h.request(h.server, h.token, "/api/v1/disclosure/cases", c.CreateRequest{RuleID: "transactions-only", RecipientActorID: f.Actor(f.Subject), CaseReference: "NO-EVENTS-RULE", Purpose: "Rule closure", Scope: badScope, ExpiresAt: f.Now + 120, IdempotencyKey: uuid.NewString()}, 404)
		q := d.Query{Version: 1, Resource: p.Events, View: d.List, Limit: ptrFinance(uint16(100)), Cursor: first.Result.NextCursor}
		other := h.openCase("auditor", []p.Resource{p.Events}, p.Full, f.Now+120)
		h.request(h.server, h.token, "/api/v1/disclosure/cases/"+other+"/read", q, 409)
		level := p.Redacted
		q.Level = &level
		h.request(h.server, h.token, path, q, 409)
		q.Level = nil
		q.DataTime = &p.Interval{Start: f.Now - 100, End: f.Now}
		h.request(h.server, h.token, path, q, 409)
		q.DataTime = nil
		tamper := *q.Cursor
		lastByte := byte('A')
		if tamper[len(tamper)-1] == 'A' {
			lastByte = 'B'
		}
		tamper = tamper[:len(tamper)-1] + string(lastByte)
		q.Cursor = &tamper
		h.request(h.server, h.token, path, q, 400)
	})

	h.subtest("authenticated pending claim still needs actual receipt", func(t *testing.T) {
		var epoch string
		if err := h.owner.QueryRow(t.Context(), `SELECT store_epoch FROM ops_v2.disclosure_cases WHERE case_id=$1::uuid`, id).Scan(&epoch); err != nil {
			t.Fatal(err)
		}
		catalog, _ := h.config.Snapshot.Disclosure()
		rule, _ := catalog.Rule("auditor")
		scope := p.Scope{TargetActors: []string{f.Actor(f.Subject)}, Resources: []p.Resource{p.Events}, Addresses: p.Addresses{Mode: "all-target-addresses", Values: []string{}}, DataTime: p.Interval{Start: f.Now - 200, End: f.Now + 10}, Level: p.Full}
		q := d.Query{Version: 1, Resource: p.Events, View: d.List, Limit: ptrFinance(uint16(100))}
		normal, err := d.NormalizeRetained(q, scope)
		if err != nil {
			t.Fatal(err)
		}
		generation, err := d.RenderGeneration(h.config.RenderKeys)
		if err != nil {
			t.Fatal(err)
		}
		plan := h.source.Plan()
		binding := d.CursorBinding{Namespace: d.Digest(epoch), CaseID: id, CaseVersion: 1, RecipientActorID: f.Actor(f.Subject), BundleDigest: plan.BundleDigest, RuleDigest: d.Digest(rule.Digest()), QueryDigest: normal.Digest(), RenderGeneration: generation, SourcePlanDigest: plan.PlanDigest}
		ring, err := d.NewCursor(h.dataConfig.CursorKeys)
		if err != nil {
			t.Fatal(err)
		}
		original, err := ring.OpenRetained(*first.Result.NextCursor, plan, binding, p.Events, h.config.Clock())
		if err != nil {
			t.Fatal(err)
		}
		for _, change := range []func(*d.Position){func(pos *d.Position) { *pos.Events.NextLogIndex = 999 }, func(pos *d.Position) { pos.Events.Parent.TransactionIndex++ }, func(pos *d.Position) { pos.Events.Parent.Hash[0] ^= 1 }} {
			pos := original.Position()
			change(&pos)
			raw, err := ring.SealRetained(plan, binding, p.Events, original.Basis(), first.Coverage.SourceBasisDigest, original.References(), pos, h.config.Clock().Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			q.Cursor = &raw
			h.request(h.server, h.token, "/api/v1/disclosure/cases/"+id+"/read", q, 0)
		}
	})

	h.subtest("final source and live authority failures release no output", func(t *testing.T) {
		path := "/api/v1/disclosure/cases/" + id + "/read"
		q := d.Query{Version: 1, Resource: p.Events, View: d.List, Limit: ptrFinance(uint16(1))}
		h.schedule(func() { h.fault.enabled.Store(true) })
		h.request(h.server, h.token, path, q, 0)
		h.fault.enabled.Store(false)
		h.schedule(func() {
			functionalExec(t, h.control.admission, `UPDATE ops_history_namespace_v1.namespace_network_state SET ready=false`)
		})
		h.request(h.server, h.token, path, q, 0)
		functionalExec(t, h.control.admission, `UPDATE ops_history_namespace_v1.namespace_network_state SET ready=true`)
		var revision int64
		if err := h.control.admission.QueryRow(t.Context(), `SELECT revision FROM ops_history_namespace_v1.namespace_network_state`).Scan(&revision); err != nil {
			t.Fatal(err)
		}
		functionalExec(t, h.control.admission, `UPDATE ops_history_namespace_v1.namespace_network_state SET revision=revision+1`)
		cursorQuery := q
		cursorQuery.Limit = ptrFinance(uint16(100))
		cursorQuery.Cursor = first.Result.NextCursor
		h.request(h.server, h.token, path, cursorQuery, 0)
		functionalExec(t, h.control.admission, `UPDATE ops_history_namespace_v1.namespace_network_state SET revision=$1`, revision)
		var epoch string
		if err := h.control.index.QueryRow(t.Context(), `SELECT dataset_epoch::text FROM indexer_dataset_metadata WHERE id=1`).Scan(&epoch); err != nil {
			t.Fatal(err)
		}
		h.schedule(func() {
			functionalExec(t, h.control.index, `UPDATE indexer_dataset_metadata SET dataset_epoch=$1::uuid WHERE id=1`, uuid.NewString())
		})
		h.request(h.server, h.token, path, q, 0)
		functionalExec(t, h.control.index, `UPDATE indexer_dataset_metadata SET dataset_epoch=$1::uuid WHERE id=1`, epoch)
		functionalExec(t, h.control.index, `UPDATE prune_state SET pruned_through=$1,pruned_through_ts=$2 WHERE id=1`, node.head.Number.Int64(), node.head.Time)
		h.request(h.server, h.token, path, cursorQuery, 0)
		functionalExec(t, h.control.index, `UPDATE prune_state SET pruned_through=0,pruned_through_ts=0 WHERE id=1`)
		short := h.openCase("auditor", []p.Resource{p.Events}, p.Full, f.Now+1)
		h.now.Store(f.Now + 2)
		before := node.attempts()
		h.request(h.server, h.token, "/api/v1/disclosure/cases/"+short+"/read", q, 404)
		if node.attempts() != before {
			t.Fatal("expired case dispatched source I/O")
		}
		h.now.Store(f.Now)
		long := h.openCase("auditor", []p.Resource{p.Events}, p.Full, f.Now+1200)
		h.schedule(func() { h.now.Store(f.Now + 301) })
		h.request(h.server, h.token, "/api/v1/disclosure/cases/"+long+"/read", q, 0)
		h.now.Store(f.Now)
		revoked := h.openCase("auditor", []p.Resource{p.Events}, p.Full, f.Now+120)
		h.schedule(func() {
			h.request(h.server, h.token, "/api/v1/disclosure/cases/"+revoked+"/revoke", map[string]string{"reason": "Investigation closed"}, 200)
		})
		h.request(h.server, h.token, "/api/v1/disclosure/cases/"+revoked+"/read", q, 0)
	})

	h.subtest("failed exposure COMMIT releases no page", func(t *testing.T) {
		// First prove the same actual source/case is currently deliverable.
		q := d.Query{Version: 1, Resource: p.Events, View: d.List, Limit: ptrFinance(uint16(1))}
		h.page(id, q)
		var before int64
		if err := h.owner.QueryRow(t.Context(), `SELECT count(*) FROM ops_v2.disclosure_events WHERE action='exposure_prepared'`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		// Sequence increments survive rollback. This proves the deferred trigger
		// really reached COMMIT instead of accepting an earlier source failure.
		functionalExec(t, h.owner, `CREATE SEQUENCE public.events_test_commit_probe;GRANT USAGE ON SEQUENCE public.events_test_commit_probe TO events_case_app`)
		functionalExec(t, h.owner, `CREATE FUNCTION public.events_test_commit_failure() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.action='exposure_prepared' THEN PERFORM nextval('public.events_test_commit_probe');RAISE EXCEPTION 'test exposure commit rejected'; END IF;RETURN NEW;END$$`)
		functionalExec(t, h.owner, `CREATE CONSTRAINT TRIGGER events_test_commit_failure AFTER INSERT ON ops_v2.disclosure_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.events_test_commit_failure()`)
		defer functionalExec(t, h.owner, `DROP TRIGGER events_test_commit_failure ON ops_v2.disclosure_events;DROP FUNCTION public.events_test_commit_failure();DROP SEQUENCE public.events_test_commit_probe`)
		h.request(h.server, h.token, "/api/v1/disclosure/cases/"+id+"/read", q, 503)
		var reached bool
		if err := h.owner.QueryRow(t.Context(), `SELECT is_called FROM public.events_test_commit_probe`).Scan(&reached); err != nil || !reached {
			t.Fatal("failed request did not reach actual deferred exposure COMMIT", reached, err)
		}
		var after int64
		if err := h.owner.QueryRow(t.Context(), `SELECT count(*) FROM ops_v2.disclosure_events WHERE action='exposure_prepared'`).Scan(&after); err != nil || after != before {
			t.Fatal("failed exposure transaction persisted", before, after, err)
		}
	})

	h.subtest("wallet unlink is monotonic and invalidates prepared evidence", func(t *testing.T) {
		q := d.Query{Version: 1, Resource: p.Events, View: d.List, Limit: ptrFinance(uint16(1))}
		h.page(id, q)
		h.schedule(func() {
			functionalExec(t, h.control.wallet.Owner, `UPDATE ops_wallet_v2.wallet_links SET revoked=true,revoked_at=now() WHERE namespace=$1`, h.control.wallet.Namespace[:])
		})
		h.request(h.server, h.token, "/api/v1/disclosure/cases/"+id+"/read", q, 0)
		// Keep the revoke in place; the real SQL monotonicity guard is never
		// bypassed merely to reset a fixture for another positive read.
	})
}

func TestActualDisclosureEventsRelayerAndOversizedPayload(t *testing.T) {
	root := common.HexToAddress("0x1000000000000000000000000000000000000001")
	other, err := crypto.HexToECDSA(strings.Repeat("22", 32))
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.HexToECDSA(strings.Repeat("11", 32))
	if err != nil {
		t.Fatal(err)
	}
	subject := crypto.PubkeyToAddress(key.PublicKey)
	large := bytes.Repeat([]byte{0xab}, (d.MaxResponseBytes/2)+1)
	medium := make([]*types.Log, 5)
	for i := range medium {
		medium[i] = &types.Log{Address: root, Topics: []common.Hash{{7}}, Data: bytes.Repeat([]byte{byte(i + 1)}, 180<<10)}
	}
	node := ownedFunctionalEventNode(t, functionalEventNodeOptions{Logs: [][]*types.Log{{{Address: root, Topics: []common.Hash{{1}, common.BytesToHash(subject.Bytes())}, Data: subject.Bytes()}}, {{Address: root, Topics: []common.Hash{}, Data: large}}, medium}, Keys: map[int]*ecdsa.PrivateKey{0: other}})
	h := actualEventsHTTP(t, node)
	id := h.openCase("auditor", []p.Resource{p.Events}, p.Full, f.Now+120)
	q := d.Query{Version: 1, Resource: p.Events, View: d.List, DataTime: &p.Interval{Start: int64(node.blocks[0].Time), End: int64(node.blocks[0].Time)}}
	page, _ := h.page(id, q)
	if len(page.Result.Items) != 0 || page.Result.NextCursor != nil {
		t.Fatal("topic-only subject was treated as parent participant", page)
	}
	q.DataTime = &p.Interval{Start: int64(node.blocks[1].Time), End: int64(node.blocks[1].Time)}
	h.request(h.server, h.token, "/api/v1/disclosure/cases/"+id+"/read", q, 0)
	level := p.Redacted
	q.Level = &level
	// This receipt exceeds the existing upstream raw-receipt limit; neither
	// privacy level may turn invalid source evidence into a successful page.
	h.request(h.server, h.token, "/api/v1/disclosure/cases/"+id+"/read", q, 0)
	q.DataTime = &p.Interval{Start: int64(node.blocks[2].Time), End: int64(node.blocks[2].Time)}
	q.Level = nil
	page, _ = h.page(id, q)
	if len(page.Result.Items) < 1 || len(page.Result.Items) >= len(medium) || page.Result.NextCursor == nil {
		t.Fatal("Full projection budget did not preserve a bounded prefix", len(page.Result.Items))
	}
	seen := map[string]bool{}
	for pages := 0; ; pages++ {
		for _, event := range page.Result.Items {
			if seen[event.EventID] || event.Data == nil || len(*event.Data) != 2+(180<<10)*2 {
				t.Fatal("large event skipped, repeated or truncated", event.EventID)
			}
			seen[event.EventID] = true
		}
		if page.Result.NextCursor == nil {
			break
		}
		if pages > 4 {
			t.Fatal("large receipt continuation did not finish")
		}
		q.Cursor = page.Result.NextCursor
		page, _ = h.page(id, q)
	}
	if len(seen) != len(medium) {
		t.Fatal("Full prefix lost unconsumed events", len(seen))
	}
	q.Cursor = nil
	q.Level = &level
	page, _ = h.page(id, q)
	if len(page.Result.Items) != len(medium) || page.Result.NextCursor != nil {
		t.Fatal("metadata-only lower projection inherited Full payload limit", page)
	}
	for _, event := range page.Result.Items {
		if event.Payload != "withheld" || event.Data != nil || event.Topics != nil {
			t.Fatal("lower raw payload copied", event)
		}
	}
}
