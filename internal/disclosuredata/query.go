package disclosuredata

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"slices"
	"sort"
	"strings"

	p "privacy-proxy/internal/disclosurepolicy"
	"privacy-proxy/internal/strictjson"
)

type NormalizedQuery struct {
	resource        p.Resource
	view            View
	scope           p.Scope
	limit           uint16
	addressID, hash string
	digest          Digest
}

func (n NormalizedQuery) Digest() Digest          { return n.digest }
func (n NormalizedQuery) Resource() p.Resource    { return n.resource }
func (n NormalizedQuery) View() View              { return n.view }
func (n NormalizedQuery) Scope() p.Scope          { return cloneScope(n.scope) }
func (n NormalizedQuery) Limit() uint16           { return n.limit }
func (n NormalizedQuery) AddressID() string       { return n.addressID }
func (n NormalizedQuery) TransactionHash() string { return n.hash }
func rank(l p.Level) int {
	switch l {
	case p.Redacted:
		return 0
	case p.Pseudonymous:
		return 1
	case p.Full:
		return 2
	}
	return -1
}
func combination(r p.Resource, v View) bool {
	switch r {
	case p.AddressHistory:
		return v == List || v == Resolve
	case p.Transactions:
		return v == List || v == Detail
	case p.ActivityLogs, p.Events:
		return v == List
	case p.ActivitySummary, p.SanctionsReport, p.ComplianceReport:
		return v == Report
	}
	return false
}
func DecodeQuery(raw []byte) (Query, error) {
	var q Query
	if len(raw) == 0 || len(raw) > MaxRequestBytes {
		return q, ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, e := strictjson.ReadValue(dec, 0, 16)
	if e != nil {
		return q, ErrInvalid
	}
	if _, e = dec.Token(); e != io.EOF {
		return q, ErrInvalid
	}
	m, ok := v.(map[string]any)
	if !ok || hasNull(v) {
		return q, ErrInvalid
	}
	ver, ok := m["v"].(json.Number)
	if !ok || ver.String() != "1" {
		return q, ErrInvalid
	}
	for k, v := range m {
		if k == "dataTime" {
			t, ok := v.(map[string]any)
			if !ok || len(t) != 2 || t["start"] == nil || t["end"] == nil {
				return q, ErrInvalid
			}
		}
		if v == nil {
			return q, ErrInvalid
		}
		switch k {
		case "targetActorIds":
			a, ok := v.([]any)
			if !ok || len(a) < 1 || len(a) > 256 {
				return q, ErrInvalid
			}
		case "addresses":
			a, ok := v.([]any)
			if !ok || len(a) < 1 || len(a) > 1024 {
				return q, ErrInvalid
			}
		}
	}
	if strictjson.ExactDecodeWithOptions(v, &q, strictjson.ShapeOptions{OptionalOmitEmpty: true}) != nil || q.Version != 1 || !combination(q.Resource, q.View) {
		return Query{}, ErrInvalid
	}
	if q.Limit != nil && (*q.Limit < 1 || *q.Limit > MaxPage) || q.Cursor != nil && (len(*q.Cursor) < 1 || len(*q.Cursor) > 2048) || q.AddressID != nil && len(*q.AddressID) > 128 || q.TransactionHash != nil && len(*q.TransactionHash) > 128 {
		return Query{}, ErrInvalid
	}
	if q.View != List && (q.Limit != nil || q.Cursor != nil) {
		return Query{}, ErrInvalid
	}
	if q.View != Resolve && q.View != Detail && q.AddressID != nil || !(q.Resource == p.Transactions && q.View == Detail) && q.TransactionHash != nil {
		return Query{}, ErrInvalid
	}
	// Required/value checks for detail locator/hash deliberately follow the service's Full gate.
	return q, nil
}
func validLocator(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 || parts[0] != "da1" || !keyID(parts[1]) {
		return false
	}
	b, e := base64.RawURLEncoding.DecodeString(parts[2])
	return e == nil && len(b) == 16 && base64.RawURLEncoding.EncodeToString(b) == parts[2]
}
func Normalize(q Query, original p.Scope) (NormalizedQuery, error) {
	return normalize(q, original, false)
}

// NormalizeRetained also accepts an opaque address selector for a transaction
// list. The operational source resolves it only within actual current targets.
func NormalizeRetained(q Query, original p.Scope) (NormalizedQuery, error) {
	return normalize(q, original, true)
}

func normalize(q Query, original p.Scope, retained bool) (NormalizedQuery, error) {
	var n NormalizedQuery
	s, e := p.NormalizeScope(original, p.DefaultLimits())
	if e != nil || q.Version != 1 || !combination(q.Resource, q.View) || !slices.Contains(s.Resources, q.Resource) {
		return n, ErrInvalid
	}
	addressList := retained && q.Resource == p.Transactions && q.View == List && q.AddressID != nil
	if q.View != List && (q.Limit != nil || q.Cursor != nil) || q.View != Resolve && q.View != Detail && !addressList && q.AddressID != nil || !(q.Resource == p.Transactions && q.View == Detail) && q.TransactionHash != nil {
		return n, ErrInvalid
	}
	n.resource = q.Resource
	n.view = q.View
	n.scope = cloneScope(s)
	n.scope.Resources = []p.Resource{q.Resource}
	if q.TargetActorIDs != nil {
		if len(q.TargetActorIDs) < 1 || len(q.TargetActorIDs) > 256 {
			return n, ErrInvalid
		}
		n.scope.TargetActors = append([]string{}, q.TargetActorIDs...)
		sort.Strings(n.scope.TargetActors)
		for i, a := range n.scope.TargetActors {
			if !actor(a) || !slices.Contains(s.TargetActors, a) || i > 0 && a == n.scope.TargetActors[i-1] {
				return n, ErrInvalid
			}
		}
	}
	if q.Addresses != nil {
		if len(q.Addresses) < 1 || len(q.Addresses) > 1024 {
			return n, ErrInvalid
		}
		n.scope.Addresses = p.Addresses{Mode: "list", Values: []string{}}
		for _, a := range q.Addresses {
			parsed, e := address(a)
			if e != nil {
				return n, ErrInvalid
			}
			canonical := addressString(parsed)
			if s.Addresses.Mode == "list" && !slices.Contains(s.Addresses.Values, canonical) {
				return n, ErrInvalid
			}
			n.scope.Addresses.Values = append(n.scope.Addresses.Values, canonical)
		}
		sort.Strings(n.scope.Addresses.Values)
		for i := 1; i < len(n.scope.Addresses.Values); i++ {
			if n.scope.Addresses.Values[i] == n.scope.Addresses.Values[i-1] {
				return n, ErrInvalid
			}
		}
	}
	if q.DataTime != nil {
		if q.DataTime.Start < s.DataTime.Start || q.DataTime.End > s.DataTime.End || q.DataTime.End < q.DataTime.Start {
			return n, ErrInvalid
		}
		n.scope.DataTime = *q.DataTime
	}
	if q.Level != nil {
		if rank(*q.Level) < 0 || rank(*q.Level) > rank(s.Level) {
			return n, ErrInvalid
		}
		n.scope.Level = *q.Level
	}
	if q.View == List {
		n.limit = 50
		if q.Limit != nil {
			n.limit = *q.Limit
		}
		if n.limit < 1 || n.limit > 100 {
			return n, ErrInvalid
		}
	}
	if q.View == Resolve || q.View == Detail || addressList {
		if q.AddressID == nil || !validLocator(*q.AddressID) {
			return n, ErrInvalid
		}
		n.addressID = *q.AddressID
	}
	if q.Resource == p.Transactions && q.View == Detail {
		if q.TransactionHash == nil || len(*q.TransactionHash) != 66 || !strings.HasPrefix(*q.TransactionHash, "0x") {
			return n, ErrInvalid
		}
		for _, c := range (*q.TransactionHash)[2:] {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return n, ErrInvalid
			}
		}
		n.hash = *q.TransactionHash
		if n.scope.Level != p.Full {
			return n, ErrUnsupported
		}
	}
	if (q.Resource == p.ActivityLogs || q.Resource == p.ActivitySummary || q.Resource == p.ComplianceReport) && s.Addresses.Mode == "list" {
		return n, ErrUnsupported
	}
	if q.Resource == p.Events {
		return n, ErrUnsupported
	}
	canonical := struct {
		Version   uint8       `json:"v"`
		Resource  p.Resource  `json:"resource"`
		View      View        `json:"view"`
		Targets   []string    `json:"targetActorIds"`
		Addresses p.Addresses `json:"addresses"`
		Time      p.Interval  `json:"dataTime"`
		Level     p.Level     `json:"level"`
		Limit     *uint16     `json:"limit,omitempty"`
		AddressID *string     `json:"addressId,omitempty"`
		Hash      *string     `json:"transactionHash,omitempty"`
	}{1, n.resource, n.view, n.scope.TargetActors, n.scope.Addresses, n.scope.DataTime, n.scope.Level, nil, nil, nil}
	if n.view == List {
		canonical.Limit = &n.limit
	}
	if n.addressID != "" {
		canonical.AddressID = &n.addressID
	}
	if n.hash != "" {
		canonical.Hash = &n.hash
	}
	raw, _ := jsonBytes(canonical)
	n.digest = hashParts("ops.disclosure.query/v1", raw)
	return n, nil
}
