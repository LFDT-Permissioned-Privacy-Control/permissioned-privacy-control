package compliancepolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/strictjson"
)

var ErrInvalid = errors.New("invalid compliance source")
var ErrUnsupported = errors.New("unsupported compliance runtime profile")

func Decode(raw []byte, l Limits) (Source, error) {
	if !l.Valid() || len(raw) == 0 || len(raw) > l.MaxDocumentBytes || !utf8.Valid(raw) {
		return Source{}, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, e := strictjson.ReadValue(d, 0, l.MaxJSONDepth)
	if e != nil {
		return Source{}, ErrInvalid
	}
	if _, e = d.Token(); e != io.EOF {
		return Source{}, ErrInvalid
	}
	object, ok := v.(map[string]any)
	if !ok {
		return Source{}, ErrInvalid
	}
	orgs, ok := object["organizations"].([]any)
	if !ok || len(orgs) > l.MaxOrganizations {
		return Source{}, ErrInvalid
	}
	sanctions, ok := object["sanctions"].([]any)
	if !ok || len(sanctions) > l.MaxSanctions {
		return Source{}, ErrInvalid
	}
	thresholds, prices := 0, 0
	for _, item := range orgs {
		o, ok := item.(map[string]any)
		if !ok {
			return Source{}, ErrInvalid
		}
		spec, ok := o["spec"].(map[string]any)
		if !ok {
			return Source{}, ErrInvalid
		}
		a, ok := spec["addressThresholds"].([]any)
		if !ok || len(a) > l.MaxThresholds-thresholds {
			return Source{}, ErrInvalid
		}
		b, ok := spec["tokenPrices"].([]any)
		if !ok || len(b) > l.MaxTokenPrices-prices {
			return Source{}, ErrInvalid
		}
		thresholds += len(a)
		prices += len(b)
	}
	if e = compliance.ValidateWireNumbers(v); e != nil {
		return Source{}, e
	}
	var s Source
	if e = strictjson.ExactDecode(v, &s); e != nil {
		return Source{}, ErrInvalid
	}
	if !sourceBounds(s, l) {
		return Source{}, ErrInvalid
	}
	return s, nil
}

func sourceBounds(s Source, l Limits) bool {
	if !l.Valid() || len(s.Organizations) > l.MaxOrganizations || len(s.Sanctions) > l.MaxSanctions {
		return false
	}
	thresholds, prices := 0, 0
	for _, o := range s.Organizations {
		if len(o.Spec.AddressThresholds) > l.MaxThresholds-thresholds || len(o.Spec.TokenPrices) > l.MaxTokenPrices-prices {
			return false
		}
		thresholds += len(o.Spec.AddressThresholds)
		prices += len(o.Spec.TokenPrices)
	}
	remaining := l.MaxStringBytes
	var walk func(reflect.Value) bool
	walk = func(v reflect.Value) bool {
		switch v.Kind() {
		case reflect.String:
			s := v.String()
			if len(s) > remaining || !utf8.ValidString(s) {
				return false
			}
			remaining -= len(s)
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if !walk(v.Field(i)) {
					return false
				}
			}
		case reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				if !walk(v.Index(i)) {
					return false
				}
			}
		case reflect.Map:
			iter := v.MapRange()
			for iter.Next() {
				if !walk(iter.Key()) || !walk(iter.Value()) {
					return false
				}
			}
		}
		return true
	}
	return walk(reflect.ValueOf(s))
}

type Catalog struct {
	source        Source
	digest        string
	requirements  []string
	organizations map[string]OrganizationPolicy
	sanctioned    map[string]bool
}

func Compile(s Source, index OrgIndex, l Limits) (*Catalog, error) {
	if index == nil || !sourceBounds(s, l) {
		return nil, ErrInvalid
	}
	supplied := index.OrganizationIDs()
	if len(supplied) > l.MaxOrganizations {
		return nil, ErrInvalid
	}
	ids := slices.Clone(supplied)
	known := map[string]bool{}
	for _, id := range ids {
		if !canonicalUUID(id) || known[id] {
			return nil, ErrInvalid
		}
		known[id] = true
	}
	if len(known) != len(s.Organizations) {
		return nil, ErrInvalid
	}
	raw, e := json.Marshal(s)
	if e != nil {
		return nil, ErrInvalid
	}
	s, e = Decode(raw, l)
	if e != nil {
		return nil, e
	}
	if s.APIVersion != APIVersion || s.Kind != Kind {
		return nil, ErrInvalid
	}
	seen := map[string]bool{}
	caps := map[string]bool{"catalog.compliance-validate/v1": true}
	for i := range s.Organizations {
		o := &s.Organizations[i]
		if !known[o.OrganizationID] || seen[o.OrganizationID] || o.RecordMaxSeconds <= 0 || o.RecordMaxSeconds > 30*24*3600 || o.PriceMaxAgeSeconds <= 0 || o.PriceMaxAgeSeconds > 24*3600 {
			return nil, ErrInvalid
		}
		seen[o.OrganizationID] = true
		if e := NormalizeSpec(&o.Spec); e != nil {
			return nil, e
		}
		nativeRow := false
		quotes := false
		for _, p := range o.Spec.TokenPrices {
			if p.Decimals > 77 {
				return nil, ErrUnsupported
			}
			nativeRow = nativeRow || p.TokenAddress == "native"
			quotes = quotes || p.CoingeckoID != ""
		}
		if o.Spec.Settings.Enabled {
			caps["operational.travel-rule/v1"] = true
			if quotes || !nativeRow {
				caps["inputs.price-quotes/v1"] = true
			}
		}
	}
	seenIDs, seenScope := map[string]bool{}, map[string]bool{}
	for _, row := range s.Sanctions {
		key := row.Scope + "/" + row.OrganizationID + "/" + row.Address
		if !canonicalUUID(row.ID) || seenIDs[row.ID] || seenScope[key] || !canonicalAddress(row.Address) || len(row.Reason) > 4096 || len(row.Source) > 1024 {
			return nil, ErrInvalid
		}
		if (row.Scope == "global" && row.OrganizationID != "") || (row.Scope == "organization" && !known[row.OrganizationID]) || (row.Scope != "global" && row.Scope != "organization") {
			return nil, ErrInvalid
		}
		seenIDs[row.ID] = true
		seenScope[key] = true
	}
	if len(s.Sanctions) > 0 {
		caps["policy.sanctions/v1"] = true
	}
	sort.Slice(s.Organizations, func(i, j int) bool { return s.Organizations[i].OrganizationID < s.Organizations[j].OrganizationID })
	sort.Slice(s.Sanctions, func(i, j int) bool { return s.Sanctions[i].ID < s.Sanctions[j].ID })
	raw, e = json.Marshal(s)
	if e != nil {
		return nil, ErrInvalid
	}
	sum := sha256.Sum256(raw)
	c := &Catalog{source: s, digest: "sha256:" + hex.EncodeToString(sum[:]), organizations: map[string]OrganizationPolicy{}, sanctioned: map[string]bool{}}
	for _, o := range s.Organizations {
		c.organizations[o.OrganizationID] = o
	}
	for _, r := range s.Sanctions {
		c.sanctioned[r.OrganizationID+"/"+r.Address] = true
	}
	for cap := range caps {
		c.requirements = append(c.requirements, cap)
	}
	sort.Strings(c.requirements)
	return c, nil
}
func (c *Catalog) Digest() string         { return c.digest }
func (c *Catalog) Requirements() []string { return slices.Clone(c.requirements) }
func (c *Catalog) DetachedSource() Source {
	raw, _ := json.Marshal(c.source)
	var s Source
	_ = json.Unmarshal(raw, &s)
	return s
}
func (c *Catalog) OrgPolicy(org string) (OrganizationPolicy, bool) {
	o, ok := c.organizations[org]
	if !ok {
		return OrganizationPolicy{}, false
	}
	raw, _ := json.Marshal(o)
	var detached OrganizationPolicy
	_ = json.Unmarshal(raw, &detached)
	return detached, true
}
func (c *Catalog) Sanctions() []SourceSanction { return slices.Clone(c.source.Sanctions) }
func (c *Catalog) IsSanctioned(org, address string) bool {
	address = strings.ToLower(address)
	return c.sanctioned["/"+address] || c.sanctioned[org+"/"+address]
}
