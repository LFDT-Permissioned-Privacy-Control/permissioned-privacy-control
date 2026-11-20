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

type metadataRoleStore struct {
	auditProjectionStore
	managementWrites int
}

func (s *metadataRoleStore) GetByKey(context.Context, string, string, string) (c.Case, error) {
	return c.Case{}, c.ErrNotFound
}

func (s *metadataRoleStore) Candidates(_ context.Context, query c.CandidateQuery) ([]c.Case, error) {
	if query.Epoch != s.current.Epoch {
		return nil, c.ErrUnavailable
	}
	if query.Organization != "" && query.Organization != s.current.DataOrg || query.Recipient != "" && query.Recipient != s.current.RecipientActor {
		return []c.Case{}, nil
	}
	return []c.Case{s.current}, nil
}

func (s *metadataRoleStore) Revoke(_ context.Context, id, epoch, actor, reason string, authorize func(c.Case) error, event func(c.Case) (c.Event, error)) (c.Case, c.CommitReceipt, error) {
	if id != s.current.ID || epoch != s.current.Epoch {
		return c.Case{}, c.CommitReceipt{}, c.ErrNotFound
	}
	if err := authorize(s.current); err != nil {
		return c.Case{}, c.CommitReceipt{}, err
	}
	s.managementWrites++
	return c.Case{}, c.CommitReceipt{}, c.ErrUnavailable
}

func TestReadonlyOrganizationMetadataDoesNotGrantManagementOrDataAuthority(t *testing.T) {
	snapshot := f.Snapshot(t, nil)
	catalog, _ := snapshot.Disclosure()
	rule, _ := catalog.Rule("auditor")
	epoch, err := c.Namespace(snapshot.Metadata(), "epoch")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(f.Now, 0).UTC()
	store := &metadataRoleStore{auditProjectionStore: auditProjectionStore{current: c.Case{
		ID: uuid.NewString(), Epoch: epoch, CreatorActor: f.Actor(f.Subject), RecipientActor: f.Actor(f.Subject),
		RuleID: "auditor", DataOrg: f.Org, OriginalRuleDigest: rule.Digest(), OriginalBundleDigest: string(snapshot.Metadata().ManifestDigest),
		RequestDigest: "sha256:" + strings.Repeat("a", 64), Scope: f.Scope(), Reference: "READONLY-1", Purpose: "Institution audit", Status: "open", Version: 1,
		CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), IdempotencyKey: uuid.NewString(),
	}}}
	eventActor := f.Actor(f.AdminSubject)
	store.events = []c.Event{{ID: uuid.NewString(), CaseID: store.current.ID, Epoch: epoch, Actor: eventActor, Action: "metadata_read", Outcome: "allowed", RuleID: "auditor", RuleDigest: rule.Digest(), BundleDigest: string(snapshot.Metadata().ManifestDigest), AttemptID: uuid.NewString(), CaseVersion: 1, PreparedAt: now.Add(-time.Second), Summary: c.EventSummary{Count: 1, RuleContext: "current"}}}
	cfg := c.Config{Snapshot: snapshot, Clock: func() time.Time { return now }, Store: store, StoreEpoch: "epoch", CursorKeys: c.CursorKeys{Active: c.CursorKey{ID: "metadata", Key: bytes.Repeat([]byte{3}, 32)}}}
	service, err := c.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	readonly := f.Token(t, snapshot, "cccccccc-cccc-cccc-cccc-cccccccccccc", "Readonly")
	write := func(response *c.Response, err error) []byte {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		var body bytes.Buffer
		if _, err := response.WriteTo(&body); err != nil {
			t.Fatal(err)
		}
		return body.Bytes()
	}
	get, err := service.Get(t.Context(), readonly, store.current.ID)
	if !bytes.Contains(write(get, err), []byte(store.current.Purpose)) {
		t.Fatal("read-only own-org detail omitted metadata")
	}
	list, err := service.List(t.Context(), readonly, c.ListOptions{Role: "data-org-admin", Organization: f.Org})
	if !bytes.Contains(write(list, err), []byte(store.current.ID)) {
		t.Fatal("read-only own-org listing omitted case")
	}
	audit, err := service.Audit(t.Context(), readonly, store.current.ID, "", 50)
	var page struct {
		Items []map[string]any `json:"items"`
	}
	if json.Unmarshal(write(audit, err), &page) != nil || len(page.Items) != 1 || page.Items[0]["actor"] != eventActor {
		t.Fatal("read-only organization audit did not retain recorded actor")
	}
	if len(store.committed) != 3 {
		t.Fatal("metadata escaped the mandatory commit-before-bytes audit")
	}
	for _, bad := range []string{f.Token(t, snapshot, f.AdminSubject), f.Token(t, snapshot, f.AdminSubject, "Local"), f.Token(t, snapshot, f.AdminSubject, "Foreign")} {
		if response, err := service.Get(t.Context(), bad, store.current.ID); !errors.Is(err, c.ErrNotFound) || response != nil {
			t.Fatal("nonadministrative/foreign role obtained detail", err)
		}
	}
	if response, err := service.List(t.Context(), readonly, c.ListOptions{Role: "data-org-admin", Organization: f.OtherOrg}); !errors.Is(err, c.ErrNotFound) || response != nil {
		t.Fatal("read-only actor inspected another organization", err)
	}
	if response, err := service.Revoke(t.Context(), readonly, store.current.ID, "Not permitted"); !errors.Is(err, c.ErrNotFound) || response != nil || store.managementWrites != 0 {
		t.Fatal("read-only metadata authority widened revocation", err)
	}
	request := c.CreateRequest{RuleID: "auditor", RecipientActorID: f.Actor(f.Subject), CaseReference: "NO-DELEGATION", Purpose: "No creation", LegalBasis: "Not permitted", Scope: f.Scope(), ExpiresAt: f.Now + 60, IdempotencyKey: uuid.NewString()}
	if response, err := service.Create(t.Context(), readonly, request); !errors.Is(err, c.ErrNotFound) || response != nil {
		t.Fatal("read-only metadata authority widened create/delegation", err)
	}
	protected, err := c.NewWithData(cfg, sourceConfig(snapshot))
	if err != nil {
		t.Fatal(err)
	}
	if response, err := protected.Read(t.Context(), readonly, store.current.ID, d.Query{Version: 1, Resource: p.ActivitySummary, View: d.Report}); !errors.Is(err, c.ErrNotFound) || response != nil {
		t.Fatal("read-only metadata authority reached protected data", err)
	}
	store.failCommit = true
	if response, err := service.Get(t.Context(), readonly, store.current.ID); err == nil || response != nil {
		t.Fatal("read-only metadata released without audit commit")
	}
	store.failCommit = false
	prepared, err := service.Get(t.Context(), readonly, store.current.ID)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(301 * time.Second)
	var expired bytes.Buffer
	if _, err := prepared.WriteTo(&expired); !errors.Is(err, c.ErrUnauthorized) || expired.Len() != 0 {
		t.Fatal("read-only metadata publication outlived original authority", err)
	}
}
