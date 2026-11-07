package disclosurecase

import (
	"context"
	"sort"
	"time"

	"privacy-proxy/internal/disclosurepolicy"
	"privacy-proxy/internal/runtimepolicy"
)

type ListOptions struct {
	Role, Organization, Cursor string
	Limit                      int
}
type casePage struct {
	Items        []CaseResponse `json:"items"`
	NextCursor   string         `json:"nextCursor"`
	ScanComplete bool           `json:"scanComplete"`
}
type auditItem struct {
	EventID      string `json:"eventId"`
	Time         int64  `json:"time"`
	Action       string `json:"action"`
	Outcome      string `json:"outcome"`
	Count        int    `json:"count"`
	RuleDigest   string `json:"ruleDigest"`
	BundleDigest string `json:"bundleDigest"`
	Actor        string `json:"actor,omitempty"`
}
type auditPage struct {
	Items        []auditItem `json:"items"`
	NextCursor   string      `json:"nextCursor"`
	ScanComplete bool        `json:"scanComplete"`
}

func (s *Service) cursorContext(v *runtimepolicy.View, role, org, endpoint, caseID string, limit int) cursorPayload {
	query := disclosurepolicy.Digest(struct {
		Endpoint, CaseID, Role, Organization string
		Limit                                int
	}{endpoint, caseID, role, org, limit})
	return cursorPayload{Version: 1, Epoch: s.epoch, Actor: v.ActorID(), Bundle: string(s.snapshot.Metadata().ManifestDigest), Disclosure: s.catalog.Digest(), Role: role, Organization: org, Query: query}
}
func (s *Service) nextCursor(v *runtimepolicy.View, p cursorPayload, last Position) (string, error) {
	p.LastID = last.ID
	p.LastTime = last.Time.UnixMicro()
	until := s.clock().Add(300 * time.Second)
	if v.ExpiresAt().Before(until) {
		until = v.ExpiresAt()
	}
	p.Expires = until.Unix()
	if p.Expires <= s.clock().Unix() {
		return "", ErrUnauthorized
	}
	return s.cursors.seal(p)
}
func normalizeList(options ListOptions) (ListOptions, error) {
	if options.Role == "" {
		options.Role = "recipient"
	}
	if options.Limit == 0 {
		options.Limit = 50
	}
	if options.Limit < 1 || options.Limit > 100 {
		return options, ErrInvalid
	}
	if options.Role == "recipient" {
		if options.Organization != "" {
			return options, ErrInvalid
		}
	} else if options.Role != "data-org-admin" || !ValidUUID(options.Organization) {
		return options, ErrInvalid
	}
	return options, nil
}

func (s *Service) List(ctx context.Context, token string, options ListOptions) (*Response, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	v, err := s.view(token)
	if err != nil {
		return nil, err
	}
	options, err = normalizeList(options)
	if err != nil {
		return nil, err
	}
	if options.Role == "data-org-admin" && !s.admin(v, options.Organization) {
		return nil, ErrNotFound
	}
	payload := s.cursorContext(v, options.Role, options.Organization, "case-list", "", options.Limit)
	var after *Position
	if options.Cursor != "" {
		after, err = s.cursors.open(options.Cursor, payload, s.clock())
		if err != nil {
			return nil, err
		}
	}
	query := CandidateQuery{Epoch: s.epoch, After: after, Limit: 500}
	if options.Role == "recipient" {
		query.Recipient = v.ActorID()
	} else {
		query.Organization = options.Organization
	}
	candidates, err := s.store.Candidates(ctx, query)
	if err != nil {
		return nil, err
	}
	if len(candidates) > 500 {
		return nil, ErrUnavailable
	}
	page := casePage{Items: []CaseResponse{}, ScanComplete: len(candidates) < 500}
	selected := []Case{}
	var last *Position
	for i, c := range candidates {
		if ValidateCase(c) != nil || c.Epoch != s.epoch {
			return nil, ErrUnavailable
		}
		position := Position{c.CreatedAt, c.ID}
		last = &position
		matches := options.Role == "recipient" && c.RecipientActor == v.ActorID() || options.Role == "data-org-admin" && c.DataOrg == options.Organization
		if matches && s.metadata(v, c) == nil {
			page.Items = append(page.Items, c.Response())
			selected = append(selected, c)
		}
		if len(page.Items) == options.Limit {
			page.ScanComplete = i == len(candidates)-1 && len(candidates) < 500
			break
		}
	}
	if !page.ScanComplete && last != nil {
		page.NextCursor, err = s.nextCursor(v, payload, *last)
		if err != nil {
			return nil, err
		}
	}
	gate := func() error {
		if v.RequireLive() != nil {
			return ErrUnauthorized
		}
		if options.Role == "data-org-admin" && !s.admin(v, options.Organization) {
			return ErrNotFound
		}
		for _, c := range selected {
			if err := s.metadata(v, c); err != nil {
				return err
			}
		}
		return nil
	}
	result, err := response(page, 200, gate)
	if err != nil {
		return nil, err
	}
	// Each case is locked and committed independently in stable UUID order;
	// no transaction holds one case lock while waiting for a second one.
	locked := append([]Case(nil), selected...)
	sort.Slice(locked, func(i, j int) bool { return locked[i].ID < locked[j].ID })
	for _, c := range locked {
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
	}
	return result, nil
}

func (s *Service) Audit(ctx context.Context, token, id, cursor string, limit int) (*Response, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	v, err := s.view(token)
	if err != nil {
		return nil, err
	}
	if !ValidUUID(id) {
		return nil, ErrNotFound
	}
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	c, err := s.store.Get(ctx, id, s.epoch)
	if err != nil {
		return nil, err
	}
	if err := s.metadata(v, c); err != nil {
		return nil, err
	}
	role := "recipient"
	if s.admin(v, c.DataOrg) {
		role = "data-org-admin"
	}
	payload := s.cursorContext(v, role, c.DataOrg, "case-audit", id, limit)
	var after *Position
	if cursor != "" {
		after, err = s.cursors.open(cursor, payload, s.clock())
		if err != nil {
			return nil, err
		}
	}
	events, err := s.store.Events(ctx, id, s.epoch, after, limit+1)
	if err != nil {
		return nil, err
	}
	if len(events) > limit+1 {
		return nil, ErrUnavailable
	}
	page := auditPage{Items: []auditItem{}, ScanComplete: len(events) <= limit}
	if len(events) > limit {
		events = events[:limit]
	}
	for _, event := range events {
		if ValidateEvent(event) != nil || event.CaseID != id || event.Epoch != s.epoch {
			return nil, ErrUnavailable
		}
		item := auditItem{EventID: event.ID, Time: event.PreparedAt.Unix(), Action: event.Action, Outcome: event.Outcome, Count: event.Summary.Count, RuleDigest: event.RuleDigest, BundleDigest: event.BundleDigest}
		if event.Actor == v.ActorID() || role == "data-org-admin" {
			item.Actor = event.Actor
		}
		page.Items = append(page.Items, item)
	}
	if !page.ScanComplete && len(events) > 0 {
		last := events[len(events)-1]
		page.NextCursor, err = s.nextCursor(v, payload, Position{last.PreparedAt, last.ID})
		if err != nil {
			return nil, err
		}
	}
	result, err := response(page, 200, func() error { return s.metadata(v, c) })
	if err != nil {
		return nil, err
	}
	receipt, err := s.store.WithLockedCase(ctx, id, s.epoch, c.Version, func(current Case) (Event, error) {
		if err := s.metadata(v, current); err != nil {
			return Event{}, err
		}
		e, err := s.newEvent(v, current, "audit_read")
		e.Summary.Count = len(page.Items)
		return e, err
	})
	if err != nil {
		return nil, err
	}
	if receipt.AttemptID == "" {
		return nil, ErrUnavailable
	}
	return result, nil
}
