package disclosurecase

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
	"privacy-proxy/internal/disclosurepolicy"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/runtimepolicy"
)

type Config struct {
	Snapshot   *policybundle.CatalogSnapshot
	Clock      func() time.Time
	Store      Store
	StoreEpoch string
	CursorKeys CursorKeys
}
type Service struct {
	snapshot *policybundle.CatalogSnapshot
	catalog  *disclosurepolicy.Catalog
	factory  *runtimepolicy.Factory
	clock    func() time.Time
	store    Store
	epoch    string
	cursors  *cursorRing
	data     *dataState
}

func New(config Config) (*Service, error) {
	if config.Snapshot == nil || config.Clock == nil || config.Store == nil || !ValidEpoch(config.StoreEpoch) {
		return nil, ErrInvalid
	}
	catalog, ok := config.Snapshot.Disclosure()
	if !ok {
		return nil, ErrInvalid
	}
	factory, err := runtimepolicy.NewFactory(config.Snapshot, config.Clock)
	if err != nil {
		return nil, ErrInvalid
	}
	keys, err := newCursorRing(config.CursorKeys)
	if err != nil {
		return nil, err
	}
	epoch, err := Namespace(config.Snapshot.Metadata(), config.StoreEpoch)
	if err != nil {
		return nil, err
	}
	return &Service{snapshot: config.Snapshot, catalog: catalog, factory: factory, clock: config.Clock, store: config.Store, epoch: epoch, cursors: keys}, nil
}

// Response exposes bytes only through a final operation-specific time/access
// check after durable commit. An event can therefore truthfully remain prepared
// but unsent if access expires before WriteTo. It never proves client receipt.
type Response struct {
	body     []byte
	gate     func() error
	status   int
	download bool
}

func (r *Response) Status() int          { return r.status }
func (r *Response) ReportDownload() bool { return r.download }
func (r *Response) WriteTo(w io.Writer) (int64, error) {
	if err := r.gate(); err != nil {
		return 0, err
	}
	n, err := w.Write(r.body)
	return int64(n), err
}
func response(value any, status int, gate func() error) (*Response, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw)+1 > MaxResponseBytes {
		return nil, ErrInvalid
	}
	return &Response{body: append(raw, '\n'), gate: gate, status: status}, nil
}
func (s *Service) view(token string) (*runtimepolicy.View, error) {
	v, err := s.factory.Build(token)
	if err != nil {
		return nil, ErrUnauthorized
	}
	return v, nil
}
func (s *Service) admin(v *runtimepolicy.View, org string) bool {
	o, ok := v.Org(org)
	return ok && o.IsOrgAdmin()
}
func (s *Service) groups(v *runtimepolicy.View, r *disclosurepolicy.Rule) []disclosurepolicy.GroupRef {
	refs := []disclosurepolicy.GroupRef{}
	for _, ref := range r.Source().Viewers.Groups {
		if o, ok := v.Org(ref.OrganizationID); ok {
			if o.HasGroup(ref.GroupID) {
				refs = append(refs, ref)
			}
		}
	}
	return refs
}
func (s *Service) eligible(v *runtimepolicy.View, r *disclosurepolicy.Rule) bool {
	return r.Eligible(v.ActorID(), s.groups(v, r), s.clock())
}
func (s *Service) metadata(v *runtimepolicy.View, c Case) error {
	if v.RequireLive() != nil {
		return ErrUnauthorized
	}
	if c.Epoch != s.epoch || ValidateCase(c) != nil {
		return ErrNotFound
	}
	if s.admin(v, c.DataOrg) {
		return nil
	}
	r, ok := s.catalog.Rule(c.RuleID)
	if !ok || c.RecipientActor != v.ActorID() || r.Source().DataOrganizationID != c.DataOrg || !s.eligible(v, r) || !r.Covers(c.Scope) {
		return ErrNotFound
	}
	return nil
}
func (s *Service) canCreate(v *runtimepolicy.View, r *disclosurepolicy.Rule, req CreateRequest) error {
	if v.RequireLive() != nil {
		return ErrUnauthorized
	}
	src := r.Source()
	if !r.Active(s.clock()) || !r.Covers(req.Scope) {
		return ErrNotFound
	}
	if len(src.Viewers.Actors) > 0 {
		found := false
		for _, actor := range src.Viewers.Actors {
			found = found || actor == req.RecipientActorID
		}
		if !found {
			return ErrNotFound
		}
	}
	if s.admin(v, src.DataOrganizationID) {
		return nil
	}
	if req.RecipientActorID != v.ActorID() || !s.eligible(v, r) {
		return ErrNotFound
	}
	return nil
}
func (s *Service) newEvent(v *runtimepolicy.View, c Case, action string) (Event, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return Event{}, ErrUnavailable
	}
	attempt, err := uuid.NewRandom()
	if err != nil {
		return Event{}, ErrUnavailable
	}
	digest, context := c.OriginalRuleDigest, "original-history"
	if r, ok := s.catalog.Rule(c.RuleID); ok {
		digest, context = r.Digest(), "current"
	}
	e := Event{ID: id.String(), CaseID: c.ID, Epoch: s.epoch, Actor: v.ActorID(), Action: action, Outcome: "allowed", RuleID: c.RuleID, RuleDigest: digest, BundleDigest: string(s.snapshot.Metadata().ManifestDigest), AttemptID: attempt.String(), CaseVersion: c.Version, PreparedAt: s.clock().UTC(), Summary: EventSummary{Count: 1, RuleContext: context}}
	if action == "case_revoked" {
		e.Outcome = "revoked"
	}
	return e, ValidateEvent(e)
}
func (s *Service) Create(ctx context.Context, token string, req CreateRequest) (*Response, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	v, err := s.view(token)
	if err != nil {
		return nil, err
	}
	normalized, err := disclosurepolicy.NormalizeScope(req.Scope, disclosurepolicy.DefaultLimits())
	if err != nil || !disclosurepolicy.Text(req.RuleID, 128) || req.ExpiresAt < 0 || req.ExpiresAt > disclosurepolicy.MaxUnixSeconds || !validMetadata(req.CaseReference, req.Purpose, req.LegalBasis) || !ValidUUID(req.IdempotencyKey) || !identity.ValidActorID(req.RecipientActorID) {
		return nil, ErrInvalid
	}
	req.Scope = normalized
	existing, lookupErr := s.store.GetByKey(ctx, s.epoch, v.ActorID(), req.IdempotencyKey)
	if lookupErr == nil {
		if existing.RequestDigest != disclosurepolicy.Digest(req) {
			return nil, ErrConflict
		}
		return s.readMetadata(ctx, v, existing)
	}
	if !errors.Is(lookupErr, ErrNotFound) {
		return nil, lookupErr
	}
	r, ok := s.catalog.Rule(req.RuleID)
	if !ok {
		return nil, ErrNotFound
	}
	if err := s.canCreate(v, r, req); err != nil {
		return nil, err
	}
	now := s.clock().UTC()
	if req.ExpiresAt <= now.Unix() || req.ExpiresAt > disclosurepolicy.MaxUnixSeconds {
		return nil, ErrInvalid
	}
	expires := r.ProtectedUntil(now, time.Unix(req.ExpiresAt, 0))
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, ErrUnavailable
	}
	c := Case{ID: id.String(), Epoch: s.epoch, CreatorActor: v.ActorID(), RecipientActor: req.RecipientActorID, RuleID: req.RuleID, DataOrg: r.Source().DataOrganizationID, OriginalRuleDigest: r.Digest(), OriginalBundleDigest: string(s.snapshot.Metadata().ManifestDigest), RequestDigest: disclosurepolicy.Digest(req), Scope: normalized, Reference: req.CaseReference, Purpose: req.Purpose, LegalBasis: req.LegalBasis, CreatedAt: now, ExpiresAt: expires, Status: "open", Version: 1, IdempotencyKey: req.IdempotencyKey}
	if ValidateCase(c) != nil {
		return nil, ErrInvalid
	}
	event, err := s.newEvent(v, c, "case_opened")
	if err != nil {
		return nil, err
	}
	isNew := false
	stored, receipt, err := s.store.CreateOrGet(ctx, c, event, func(actual Case, new bool) error {
		isNew = new
		if new {
			return s.canCreate(v, r, req)
		}
		return s.metadata(v, actual)
	})
	if err != nil {
		return nil, err
	}
	if receipt.AttemptID == "" {
		return nil, ErrUnavailable
	}
	gate := func() error {
		if isNew {
			return s.canCreate(v, r, req)
		}
		return s.metadata(v, stored)
	}
	status := 200
	if isNew {
		status = 201
	}
	return response(stored.Response(), status, gate)
}

func (s *Service) Get(ctx context.Context, token, id string) (*Response, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	v, err := s.view(token)
	if err != nil {
		return nil, err
	}
	if !ValidUUID(id) {
		return nil, ErrNotFound
	}
	c, err := s.store.Get(ctx, id, s.epoch)
	if err != nil {
		return nil, err
	}
	return s.readMetadata(ctx, v, c)
}

func (s *Service) readMetadata(ctx context.Context, v *runtimepolicy.View, c Case) (*Response, error) {
	if err := s.metadata(v, c); err != nil {
		return nil, err
	}
	result, err := response(c.Response(), 200, func() error { return s.metadata(v, c) })
	if err != nil {
		return nil, err
	}
	receipt, err := s.store.WithLockedCase(ctx, c.ID, s.epoch, c.Version, func(current Case) (Event, error) {
		if err := s.metadata(v, current); err != nil {
			return Event{}, err
		}
		return s.newEvent(v, current, "metadata_read")
	})
	if err != nil {
		return nil, err
	}
	if receipt.AttemptID == "" {
		return nil, ErrUnavailable
	}
	return result, nil
}
func (s *Service) Revoke(ctx context.Context, token, id, reason string) (*Response, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	v, err := s.view(token)
	if err != nil {
		return nil, err
	}
	if !ValidUUID(id) {
		return nil, ErrNotFound
	}
	if !disclosurepolicy.Text(reason, 2048) {
		return nil, ErrInvalid
	}
	authorize := func(c Case) error {
		if v.RequireLive() != nil {
			return ErrUnauthorized
		}
		if c.Epoch != s.epoch || ValidateCase(c) != nil || c.RecipientActor != v.ActorID() && !s.admin(v, c.DataOrg) {
			return ErrNotFound
		}
		return nil
	}
	c, receipt, err := s.store.Revoke(ctx, id, s.epoch, v.ActorID(), reason, authorize, func(updated Case) (Event, error) { return s.newEvent(v, updated, "case_revoked") })
	if err != nil {
		return nil, err
	}
	if receipt.AttemptID == "" {
		return nil, ErrUnavailable
	}
	return response(struct {
		CaseID  string `json:"caseId"`
		Status  string `json:"status"`
		Version int64  `json:"version"`
	}{c.ID, c.Status, c.Version}, 200, func() error { return authorize(c) })
}
