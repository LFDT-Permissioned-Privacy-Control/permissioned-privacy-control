package disclosuresanctions_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	c "privacy-proxy/internal/compliancepolicy"
	d "privacy-proxy/internal/disclosuredata"
	p "privacy-proxy/internal/disclosurepolicy"
	"privacy-proxy/internal/disclosuresanctions"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/policybundle"
)

func address(n uint32) [20]byte {
	var a [20]byte
	binary.BigEndian.PutUint32(a[16:], n)
	return a
}

func source(rows []c.SourceSanction) c.Source {
	s := c.Source{APIVersion: c.APIVersion, Kind: c.Kind, Organizations: []c.OrganizationPolicy{}, Sanctions: rows}
	for _, org := range []string{f.Org, f.OtherOrg} {
		s.Organizations = append(s.Organizations, c.OrganizationPolicy{OrganizationID: org, RecordMaxSeconds: 86400, PriceMaxAgeSeconds: 600, Spec: c.SourceSpec{Settings: c.SourceSettings{Currency: "eur", ThresholdFiat: 100, UnknownPricePolicy: "forbidden", EnforcementMode: "enforce"}, AddressThresholds: []c.SourceThreshold{}, TokenPrices: []c.SourceTokenPrice{}}})
	}
	return s
}

func sanction(n int, scope, org string, a [20]byte, reason string) c.SourceSanction {
	return c.SourceSanction{ID: fmt.Sprintf("%08x-aaaa-4aaa-8aaa-aaaaaaaaaaaa", n), Scope: scope, OrganizationID: org, Address: "0x" + hex.EncodeToString(a[:]), Reason: reason, Source: "public fixture source"}
}

func fixture(t *testing.T) (*disclosuresanctions.Projector, *policybundle.CatalogSnapshot, c.Source) {
	t.Helper()
	// Deliberately unsorted source IDs; the actual compiler establishes order.
	s := source([]c.SourceSanction{
		sanction(4, "organization", f.OtherOrg, address(1), "foreign reason"),
		sanction(3, "organization", f.Org, address(1), "sensitive <bank reason>"),
		sanction(2, "global", "", address(2), "other address reason"),
		sanction(1, "global", "", address(1), "global reason"),
	})
	snapshot := f.ComplianceSnapshot(t, s)
	projector, err := disclosuresanctions.New(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return projector, snapshot, s
}

func TestExactApprovedRowsOrgIsolationAndDetachedResults(t *testing.T) {
	projector, snapshot, original := fixture(t)
	got, err := projector.Match(t.Context(), f.Org, [][20]byte{address(1)})
	if err != nil {
		t.Fatal(err)
	}
	catalog, _ := snapshot.Compliance()
	if got.BundleDigest != d.Digest(snapshot.Metadata().ManifestDigest) || got.CatalogDigest != d.Digest(catalog.Digest()) || got.ScopedAddressCount != 1 || len(got.Matches) != 2 || got.Matches[0].SourceID != original.Sanctions[3].ID || got.Matches[1].SourceID != original.Sanctions[1].ID || got.Matches[1].Reason != original.Sanctions[1].Reason {
		t.Fatal(got)
	}
	other, err := projector.Match(t.Context(), f.OtherOrg, [][20]byte{address(1)})
	if err != nil || len(other.Matches) != 2 || other.Matches[0].SourceID != got.Matches[0].SourceID || other.Matches[1].SourceID != original.Sanctions[0].ID {
		t.Fatal("org boundary", other, err)
	}
	before := slices.Clone(got.Matches)
	got.Matches[0].Reason = "changed output"
	got.Matches[0].Address = address(99)
	original.Sanctions[3].Reason = "changed constructor source"
	detached := catalog.Sanctions()
	detached[0].Reason = "changed detached catalog"
	input := [][20]byte{address(1)}
	again, err := projector.Match(t.Context(), f.Org, input)
	input[0] = address(2)
	if err != nil || !slices.Equal(again.Matches, before) {
		t.Fatal("mutable state escaped", again, err)
	}

	var group sync.WaitGroup
	for i := 0; i < 12; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for j := 0; j < 16; j++ {
				x, err := projector.Match(t.Context(), f.Org, [][20]byte{address(1)})
				if err != nil || !slices.Equal(x.Matches, before) {
					t.Error("concurrent immutable match", x, err)
					return
				}
				x.Matches[0].Reason = "private result mutation"
			}
		}()
	}
	group.Wait()
}

func TestInvalidInputsAndExactAddressBound(t *testing.T) {
	projector, _, _ := fixture(t)
	var zero *disclosuresanctions.Projector
	for _, test := range []struct {
		name string
		p    *disclosuresanctions.Projector
		ctx  context.Context
		org  string
		in   [][20]byte
		want error
	}{
		{"nil projector", zero, t.Context(), f.Org, nil, d.ErrInvalid},
		{"zero projector", &disclosuresanctions.Projector{}, t.Context(), f.Org, nil, d.ErrInvalid},
		{"nil context", projector, nil, f.Org, nil, d.ErrInvalid},
		{"malformed org", projector, t.Context(), "{11111111-1111-1111-1111-111111111111}", nil, d.ErrInvalid},
		{"unknown org", projector, t.Context(), "99999999-9999-4999-8999-999999999999", nil, d.ErrInvalid},
		{"duplicate", projector, t.Context(), f.Org, [][20]byte{address(1), address(1)}, d.ErrInvalid},
		{"unsorted", projector, t.Context(), f.Org, [][20]byte{address(2), address(1)}, d.ErrInvalid},
		{"too many", projector, t.Context(), f.Org, make([][20]byte, 4097), d.ErrTooBroad},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.p.Match(test.ctx, test.org, test.in); !errors.Is(err, test.want) {
				t.Fatal(err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := projector.Match(ctx, f.Org, nil); !errors.Is(err, d.ErrUnavailable) {
		t.Fatal(err)
	}
	addresses := make([][20]byte, 4096)
	for i := range addresses {
		addresses[i] = address(uint32(i))
	}
	x, err := projector.Match(t.Context(), f.Org, addresses)
	if err != nil || x.ScopedAddressCount != 4096 || len(x.Matches) != 3 {
		t.Fatal("exact max population", x, err)
	}
}

func TestAbsentCatalogEmptyPopulationAndExactZeroAddress(t *testing.T) {
	if _, err := disclosuresanctions.New(nil); !errors.Is(err, d.ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := disclosuresanctions.New(f.Snapshot(t, nil)); !errors.Is(err, d.ErrUnsupported) {
		t.Fatal("missing catalog became approved empty", err)
	}
	for _, rows := range [][]c.SourceSanction{{}, {sanction(1, "global", "", address(0), "zero address")}} {
		projector, err := disclosuresanctions.New(f.ComplianceSnapshot(t, source(rows)))
		if err != nil {
			t.Fatal(err)
		}
		x, err := projector.Match(t.Context(), f.Org, nil)
		if err != nil || x.ScopedAddressCount != 0 || x.Matches == nil || len(x.Matches) != 0 {
			t.Fatal("empty input is an exact empty input only", x, err)
		}
		x, err = projector.Match(t.Context(), f.Org, [][20]byte{address(0)})
		if err != nil || len(x.Matches) != len(rows) {
			t.Fatal("zero address invented identity restriction", x, err)
		}
	}
}

func TestProjectedReasonsReachOnlyFullRendererOutput(t *testing.T) {
	projector, _, _ := fixture(t)
	projected, err := projector.Match(t.Context(), f.Org, [][20]byte{address(1)})
	if err != nil {
		t.Fatal(err)
	}
	// Synthetic source descriptors below exercise the renderer boundary only.
	// They do not qualify real history or a mounted disclosure source.
	digest := func(n byte) d.Digest { return d.Digest(fmt.Sprintf("sha256:%064x", n)) }
	at := time.Unix(f.Now, 0).UTC()
	for _, level := range []p.Level{p.Redacted, p.Pseudonymous, p.Full} {
		t.Run(string(level), func(t *testing.T) {
			scope := p.Scope{TargetActors: []string{f.Actor(f.Subject)}, Resources: []p.Resource{p.SanctionsReport}, Addresses: p.Addresses{Mode: "all-target-addresses", Values: []string{}}, DataTime: p.Interval{Start: f.Now - 60, End: f.Now}, Level: level}
			query, err := d.Normalize(d.Query{Version: 1, Resource: p.SanctionsReport, View: d.Report}, scope)
			if err != nil {
				t.Fatal(err)
			}
			read := d.ReadScope{Namespace: digest(1), CaseID: "11111111-1111-4111-8111-111111111111", CaseVersion: 1, RecipientActorID: f.Actor(f.AdminSubject), DataOrganizationID: f.Org, BundleDigest: projected.BundleDigest, RuleDigest: digest(2), EffectiveUntil: at.Add(time.Minute), Query: query}
			context := d.RenderContext{PreparedAt: at, Namespace: read.Namespace, CaseID: read.CaseID, DataOrganizationID: f.Org, RecipientActorID: read.RecipientActorID, Keys: d.Keys{Active: d.Key{ID: "projection-test", Bytes: bytes.Repeat([]byte{3}, 32)}}, Query: query, EffectiveUntil: read.EffectiveUntil}
			descriptors := []d.SourceDescriptor{}
			for i, kind := range []d.SourceKind{d.HistorySource, d.SanctionsSource, d.WalletSource} {
				population := map[d.SourceKind]string{d.HistorySource: "CURRENT_SCOPED_WALLET_HISTORY", d.SanctionsSource: "CURRENT_APPROVED_SANCTIONS", d.WalletSource: "CURRENT_PROVED_ASSOCIATIONS"}[kind]
				descriptors = append(descriptors, d.SourceDescriptor{Version: 1, Kind: kind, Reference: digest(byte(i + 10)), NetworkKey: digest(4), Epoch: digest(5), Generation: "22222222-2222-4222-8222-222222222222", PlanDigest: digest(6), FormatDigest: digest(7), CoverageDigest: digest(8), AsOf: at, Population: population})
			}
			facts := d.Facts{End: true, Wallets: []d.WalletFact{{ActorID: f.Actor(f.Subject), Address: address(1), AcceptedAt: at}}, Sanctions: &d.SanctionsAggregate{Status: "hit", Matches: projected.Matches, ScopedAddressCount: projected.ScopedAddressCount, SourceDigest: descriptors[1].Reference, CheckedAt: at}}
			result, err := d.Render(read, descriptors, facts, context, "33333333-3333-4333-8333-333333333333")
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			for _, text := range []string{"global reason", "sensitive", `"reason"`} {
				if strings.Contains(string(raw), text) != (level == p.Full) {
					t.Fatal("reason projection", text, string(raw))
				}
			}
			if strings.Contains(string(raw), "foreign reason") || strings.Contains(string(raw), "<bank reason>") {
				t.Fatal("foreign or unescaped reason", string(raw))
			}
		})
	}
}
