package accesslog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"time"

	a "privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/activitymethoddata"
	"privacy-proxy/internal/activityreasondata"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/runtimepolicy"
)

const maxResponse = 192 << 10

type Config struct {
	Snapshot *policybundle.CatalogSnapshot
	Reader   Reader
	Expected a.StoreMetadata
	Clock    func() time.Time
	Keys     Keys
}
type Service struct {
	factory  *runtimepolicy.Factory
	reader   Reader
	expected a.StoreMetadata
	clock    func() time.Time
	cursors  *cursorRing
}

func New(c Config) (*Service, error) {
	if c.Clock == nil || c.Reader == nil || !a.CanonicalUUID(c.Expected.SourceID) || !a.CanonicalUUID(c.Expected.Generation) || c.Expected.Format != a.Format() || c.Expected.NetworkKey == (a.Digest{}) || c.Expected.Configuration == (a.Digest{}) {
		return nil, ErrInvalid
	}
	f, e := runtimepolicy.NewFactory(c.Snapshot, c.Clock)
	if e != nil {
		return nil, ErrInvalid
	}
	ring, e := newCursor(c.Keys)
	if e != nil {
		return nil, e
	}
	return &Service{f, c.Reader, c.Expected, c.Clock, ring}, nil
}
func authorize(v *runtimepolicy.View, org string) error {
	if v.RequireLive() != nil {
		return ErrUnauthorized
	}
	o, ok := v.Org(org)
	if !ok || !o.IsOrgAdmin() && !o.IsOrgReadonlyAdmin() {
		return ErrForbidden
	}
	return nil
}

type Response struct {
	body []byte
	gate func() error
}

// observation is private evidence from this service's actual verified view.
// Neither a URL organization nor an actor filter may populate these fields.
type observation struct {
	actor, org string
	policy     a.Digest
	live       func() error
}

func (r *Response) WriteTo(w io.Writer) (int64, error) {
	if e := r.gate(); e != nil {
		return 0, e
	}
	n, e := w.Write(r.body)
	return int64(n), e
}
func digest(raw []byte) string { h := sha256.Sum256(raw); return "sha256:" + hex.EncodeToString(h[:]) }
func asTime(us int64) string   { return time.UnixMicro(us).UTC().Format(time.RFC3339Nano) }
func (s *Service) Read(ctx context.Context, token, org string, q Query, cursor string) (*Response, error) {
	return s.read(ctx, token, org, q, cursor, nil)
}

func (s *Service) read(ctx context.Context, token, org string, q Query, cursor string, observed *observation) (*Response, error) {
	if !a.CanonicalUUID(org) || !q.Valid() {
		return nil, ErrInvalid
	}
	v, e := s.factory.Build(token)
	if e != nil {
		return nil, ErrUnauthorized
	}
	if observed != nil {
		observed.actor = v.ActorID()
		observed.live = func() error {
			if v.RequireLive() != nil {
				return ErrUnauthorized
			}
			return nil
		}
		manifest := string(v.Metadata().ManifestDigest)
		if len(manifest) != 71 || manifest[:7] != "sha256:" {
			return nil, ErrUnavailable
		}
		raw, err := hex.DecodeString(manifest[7:])
		if err != nil || len(raw) != 32 {
			return nil, ErrUnavailable
		}
		copy(observed.policy[:], raw)
	}
	if e = authorize(v, org); e != nil {
		return nil, e
	}
	if observed != nil {
		observed.org = org
		observed.live = func() error { return authorize(v, org) }
	}
	profile, pd := v.SourceProfile()
	raw, _ := json.Marshal(q)
	population := activitymethoddata.RequestPredicateDigest()
	state := cursorState{PopulationDigest: "sha256:" + hex.EncodeToString(population[:]), Version: 1, Actor: v.ActorID(), Profile: profile, ProfileDigest: pd, Bundle: string(v.Metadata().ManifestDigest), Organization: org, Query: digest(raw), Expires: s.clock().Add(5 * time.Minute).Unix()}
	var after *Position
	if cursor != "" {
		state, e = s.cursors.open(cursor, state, s.clock())
		if e != nil {
			return nil, e
		}
		if !state.Last.Valid(q) {
			return nil, ErrInvalid
		}
		after = &state.Last
	}
	ref := ""
	if after != nil {
		ref = state.Cut.Reference
	}
	snap, e := s.reader.OpenAdmin(ctx, ref, q.FromMicros)
	if e != nil {
		return nil, e
	}
	defer snap.Close()
	cut := snap.Cut()
	if cut.Metadata != s.expected || cut.Population != activitymethoddata.PopulationRequests || cut.Reference == "" || cut.Coverage == "" || cut.RetainedFromMicros < 0 {
		return nil, ErrUnavailable
	}
	if cut.RetainedFromMicros > q.FromMicros {
		return nil, &RetentionError{FromMicros: cut.RetainedFromMicros}
	}
	if after != nil {
		if state.Cut.Metadata != cut.Metadata || state.Cut.Reference != cut.Reference || state.Cut.Coverage != cut.Coverage || state.Cut.Population != cut.Population {
			return nil, ErrCursor
		}
	} else {
		state.Cut = cut
	}
	rows, end, e := snap.ReadOrgPage(ctx, org, q, after)
	if e != nil {
		return nil, e
	}
	if len(rows) > q.Limit {
		return nil, ErrUnavailable
	}
	page := Page{Items: make([]Item, 0, len(rows)), Source: Source{SourceID: cut.Metadata.SourceID, Generation: cut.Metadata.Generation, NetworkDigest: "sha256:" + hex.EncodeToString(cut.Metadata.NetworkKey[:]), ConfigurationDigest: "sha256:" + hex.EncodeToString(cut.Metadata.Configuration[:]), HeadReference: state.Cut.Reference, SourceAsOf: asTime(state.Cut.AsOfMicros), RetainedFrom: asTime(cut.RetainedFromMicros), Population: cut.Population, Coverage: "committed-sealed-prefix"}}
	for _, row := range rows {
		if row.DataOrg != org || !a.CanonicalUUID(row.RecordID) || row.ObservedMicros < q.FromMicros || row.ObservedMicros >= q.ToMicros {
			return nil, ErrUnavailable
		}
		var policy *string
		if row.Policy != "" {
			p := "sha256:" + row.Policy
			policy = &p
		}
		var ip *string
		if row.IP != "" {
			value := row.IP
			ip = &value
		}
		reason := activityreasondata.NotRecorded
		switch row.Version {
		case 1:
			if row.Reason != "" {
				return nil, ErrUnavailable
			}
		case 2:
			if !activityreasondata.AllowedOutcome(row.Reason, row.Outcome) {
				return nil, ErrUnavailable
			}
			reason = row.Reason
		default:
			return nil, ErrUnavailable
		}
		page.Items = append(page.Items, Item{row.RecordID, asTime(row.ObservedMicros), row.ActorID, row.DataOrg, row.Method, row.Outcome, row.HTTP, row.RPCError, row.Status, policy, "sha256:" + row.Configuration, string(reason), ip})
	}
	if !end {
		if len(rows) == 0 {
			return nil, ErrUnavailable
		}
		last := rows[len(rows)-1]
		ordinal, e := strconv.ParseInt(last.Ordinal, 10, 64)
		if e != nil {
			return nil, ErrUnavailable
		}
		state.Last = Position{last.ObservedMicros, last.ProducerID, last.RunID, ordinal, last.RecordID}
		next, e := s.cursors.seal(state)
		if e != nil {
			return nil, e
		}
		page.Next = &next
	}
	snap.Close()
	if e = snap.CheckCurrent(ctx); e != nil {
		return nil, e
	}
	if e = authorize(v, org); e != nil {
		return nil, e
	}
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	body, e := json.Marshal(page)
	if e != nil || len(body) > maxResponse {
		return nil, ErrUnavailable
	}
	body = append(body, '\n')
	return &Response{body, func() error {
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		if e := snap.CheckCurrent(ctx); e != nil {
			return e
		}
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		return authorize(v, org) // Last authority gate follows the final SQL IO.
	}}, nil
}
