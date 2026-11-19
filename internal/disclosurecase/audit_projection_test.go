package disclosurecase_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	c "privacy-proxy/internal/disclosurecase"
	d "privacy-proxy/internal/disclosuredata"
	p "privacy-proxy/internal/disclosurepolicy"
	f "privacy-proxy/internal/disclosuretest"
)

type auditProjectionStore struct {
	c.Store
	current    c.Case
	events     []c.Event
	committed  []c.Event
	failCommit bool
	reads      int
}

func (s *auditProjectionStore) Get(_ context.Context, id, epoch string) (c.Case, error) {
	if id != s.current.ID || epoch != s.current.Epoch {
		return c.Case{}, c.ErrNotFound
	}
	return s.current, nil
}
func (s *auditProjectionStore) Events(_ context.Context, id, epoch string, after *c.Position, limit int) ([]c.Event, error) {
	s.reads++
	if id != s.current.ID || epoch != s.current.Epoch || after != nil || limit < len(s.events) {
		return nil, c.ErrUnavailable
	}
	return s.events, nil
}
func (s *auditProjectionStore) WithLockedCase(_ context.Context, id, epoch string, version int64, authorize func(c.Case) (c.Event, error)) (c.CommitReceipt, error) {
	if id != s.current.ID || epoch != s.current.Epoch || version != s.current.Version {
		return c.CommitReceipt{}, c.ErrConflict
	}
	event, err := authorize(s.current)
	if err != nil {
		return c.CommitReceipt{}, err
	}
	if c.ValidateEvent(event) != nil || s.failCommit {
		return c.CommitReceipt{}, c.ErrUnavailable
	}
	s.committed = append(s.committed, event)
	return c.CommitReceipt{AttemptID: event.AttemptID}, nil
}

func TestCaseAuditProjectsOnlyValidatedRecordedExposureResourceAndView(t *testing.T) {
	snapshot := f.Snapshot(t, nil)
	catalog, _ := snapshot.Disclosure()
	rule, _ := catalog.Rule("auditor")
	epoch, err := c.Namespace(snapshot.Metadata(), "epoch")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(f.Now, 0).UTC()
	store := &auditProjectionStore{current: c.Case{ID: uuid.NewString(), Epoch: epoch, CreatorActor: f.Actor(f.Subject), RecipientActor: f.Actor(f.Subject), RuleID: "auditor", DataOrg: f.Org, OriginalRuleDigest: rule.Digest(), OriginalBundleDigest: string(snapshot.Metadata().ManifestDigest), RequestDigest: "sha256:" + strings.Repeat("a", 64), Scope: f.Scope(), Reference: "CASE-1", Purpose: "Audit", Status: "open", Version: 1, CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), IdempotencyKey: uuid.NewString()}}
	service, err := c.New(c.Config{Snapshot: snapshot, Clock: func() time.Time { return now }, Store: store, StoreEpoch: "epoch", CursorKeys: c.CursorKeys{Active: c.CursorKey{ID: "admin", Key: bytes.Repeat([]byte{3}, 32)}}})
	if err != nil {
		t.Fatal(err)
	}
	event := c.Event{ID: uuid.NewString(), CaseID: store.current.ID, Epoch: epoch, Actor: f.Actor(f.AdminSubject), Action: "exposure_prepared", Outcome: "allowed", RuleID: "auditor", RuleDigest: rule.Digest(), BundleDigest: string(snapshot.Metadata().ManifestDigest), AttemptID: uuid.NewString(), CaseVersion: 1, PreparedAt: now.Add(-time.Second), Summary: c.EventSummary{Count: 2, RuleContext: "current", Exposure: &c.ExposureSummary{Version: 1, Resource: p.Transactions, View: d.List, QueryDigest: "sha256:" + strings.Repeat("b", 64), SourceSetDigest: "sha256:" + strings.Repeat("c", 64), RenderDigest: "sha256:" + strings.Repeat("d", 64), OutputDigest: "sha256:" + strings.Repeat("e", 64), OutputBytes: 100, ReturnedRows: 2}}}
	if err := c.ValidateEvent(event); err != nil {
		t.Fatal("invalid original receipt fixture", err)
	}
	legacy := event
	legacy.ID, legacy.AttemptID = uuid.NewString(), uuid.NewString()
	legacy.Summary = c.EventSummary{Count: 1, RuleContext: "current"}
	metadata := legacy
	metadata.ID, metadata.AttemptID, metadata.Action = uuid.NewString(), uuid.NewString(), "metadata_read"
	store.events = []c.Event{event, legacy, metadata}
	read := func(token string) ([]map[string]any, []byte) {
		t.Helper()
		response, err := service.Audit(t.Context(), token, store.current.ID, "", 50)
		if err != nil {
			t.Fatal(err)
		}
		var raw bytes.Buffer
		if _, err := response.WriteTo(&raw); err != nil {
			t.Fatal(err)
		}
		var page struct {
			Items []map[string]any `json:"items"`
		}
		if json.Unmarshal(raw.Bytes(), &page) != nil || len(page.Items) != 3 {
			t.Fatal("invalid audit page")
		}
		return page.Items, raw.Bytes()
	}
	token := f.Token(t, snapshot, f.Subject, "Auditor")
	items, raw := read(token)
	if items[0]["resource"] != "transactions" || items[0]["view"] != "list" {
		t.Fatal("recorded resource/view omitted", items[0])
	}
	if _, ok := items[0]["actor"]; ok {
		t.Fatal("another actor unmasked for recipient")
	}
	for _, item := range items[1:] {
		if _, ok := item["resource"]; ok {
			t.Fatal("unrecorded legacy/admin resource invented", item)
		}
		if _, ok := item["view"]; ok {
			t.Fatal("unrecorded legacy/admin view invented", item)
		}
	}
	for _, private := range []string{"queryDigest", "sourceSetDigest", "renderDigest", "outputDigest", "outputBytes", "targetActors", store.current.Purpose, event.AttemptID} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("private receipt/case detail leaked", private)
		}
	}
	if len(store.committed) != 1 || store.committed[0].Action != "audit_read" || store.committed[0].Summary.Count != 3 {
		t.Fatal("mandatory audited read changed")
	}
	adminItems, _ := read(f.Token(t, snapshot, f.AdminSubject, "Admin"))
	if adminItems[0]["actor"] != event.Actor {
		t.Fatal("data-org admin lost recorded actor")
	}
	before := store.reads
	if _, err := service.Audit(t.Context(), f.Token(t, snapshot, f.AdminSubject, "Foreign"), store.current.ID, "", 50); !errors.Is(err, c.ErrNotFound) || store.reads != before {
		t.Fatal("foreign org accessed audit", err)
	}
	store.failCommit = true
	if response, err := service.Audit(t.Context(), token, store.current.ID, "", 50); err == nil || response != nil {
		t.Fatal("failed audit commit released projection")
	}
	store.failCommit = false
	store.events[0].Summary.Exposure.View = d.Report
	if response, err := service.Audit(t.Context(), token, store.current.ID, "", 50); !errors.Is(err, c.ErrUnavailable) || response != nil {
		t.Fatal("invalid stored resource/view accepted", err)
	}
	store.events[0].Summary.Exposure.View = d.List
	response, err := service.Audit(t.Context(), token, store.current.ID, "", 50)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(301 * time.Second)
	var expired bytes.Buffer
	if _, err := response.WriteTo(&expired); err == nil || expired.Len() != 0 {
		t.Fatal("expired owner received audit projection")
	}
}
