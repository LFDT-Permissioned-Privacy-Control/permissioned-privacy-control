package disclosuredata

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	p "privacy-proxy/internal/disclosurepolicy"
)

func testActor(b byte) string {
	return "ops:p1:" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))
}
func testDigest(b byte) Digest { return Digest(fmt.Sprintf("sha256:%064x", b)) }
func testAddress(b byte) [20]byte {
	var a [20]byte
	for i := range a {
		a[i] = b
	}
	return a
}
func testHash(b byte) [32]byte {
	var h [32]byte
	for i := range h {
		h[i] = b
	}
	return h
}
func testFixture(t *testing.T, r p.Resource, v View, level p.Level) (ReadScope, []SourceDescriptor, Facts, RenderContext) {
	t.Helper()
	at := time.Unix(1800000000, 0).UTC()
	scope := p.Scope{TargetActors: []string{testActor(1)}, Resources: []p.Resource{r}, Addresses: p.Addresses{Mode: "all-target-addresses", Values: []string{}}, DataTime: p.Interval{Start: at.Add(-31 * 24 * time.Hour).Unix(), End: at.Add(time.Minute).Unix()}, Level: level}
	rc := RenderContext{PreparedAt: at, Namespace: testDigest(10), CaseID: "11111111-1111-4111-8111-111111111111", DataOrganizationID: "22222222-2222-4222-8222-222222222222", RecipientActorID: testActor(2), Keys: Keys{Active: Key{ID: "render-test", Bytes: bytes.Repeat([]byte{0x33}, 32)}}, EffectiveUntil: at.Add(time.Minute)}
	q := Query{Version: 1, Resource: r, View: v}
	if v == Detail || v == Resolve {
		q.AddressID = ptr(locator(rc.Keys.Active, rc, testAddress(1)))
	}
	if v == Detail {
		q.TransactionHash = ptr(hashString(testHash(2)))
	}
	n, e := Normalize(q, scope)
	if e != nil {
		t.Fatal(e)
	}
	rc.Query = n
	rs := ReadScope{Namespace: rc.Namespace, CaseID: rc.CaseID, CaseVersion: 1, RecipientActorID: rc.RecipientActorID, DataOrganizationID: rc.DataOrganizationID, BundleDigest: testDigest(11), RuleDigest: testDigest(12), EffectiveUntil: rc.EffectiveUntil, Query: n}
	kinds, _ := RequiredKinds(r)
	ds := []SourceDescriptor{}
	refs := map[SourceKind]Digest{}
	for i, k := range kinds {
		ref := testDigest(byte(20 + i))
		refs[k] = ref
		ds = append(ds, SourceDescriptor{Version: 1, Kind: k, Reference: ref, NetworkKey: testDigest(13), Epoch: testDigest(14), Generation: "33333333-3333-4333-8333-333333333333", PlanDigest: testDigest(15), FormatDigest: testDigest(16), CoverageDigest: testDigest(17), AsOf: at, Population: population(k)})
	}
	f := Facts{End: true}
	provenance := func(k SourceKind, kind string) Provenance {
		return Provenance{Source: refs[k], DataOrganizationID: rs.DataOrganizationID, TargetActorIDs: []string{testActor(1)}, Kind: kind}
	}
	wallet := []WalletFact{{ActorID: testActor(1), Address: testAddress(1), AcceptedAt: at.Add(-time.Hour)}}
	switch r {
	case p.AddressHistory:
		f.Addresses = []AddressFact{{Provenance: provenance(HistorySource, "CURRENT_SCOPED_WALLET_HISTORY"), Address: testAddress(1)}}
		f.Wallets = wallet
	case p.Transactions:
		f.Transactions = []TransactionFact{{Provenance: provenance(HistorySource, "CURRENT_SCOPED_WALLET_HISTORY"), Hash: testHash(2), BlockHash: testHash(3), BlockNumber: "5", BlockTime: at.Unix(), From: testAddress(1), To: ptr(testAddress(3)), Value: "12", GasUsed: "21000", Status: 1, Direction: "outgoing"}}
		f.Wallets = wallet
		if v == Detail {
			f.Transactions[0].Full = &TransactionDetailFact{SignedLegacyGasPrice: ptr(Amount("30")), EffectiveGasPrice: "30", GasLimit: "21000", Nonce: "1", Type: 0, Input: "0x"}
		}
	case p.ActivityLogs:
		f.Activities = []ActivityFact{{Provenance: provenance(ActivitySource, "AUTHENTICATED_RECORDED_REQUEST_DATA_ORG"), ID: "44444444-4444-4444-8444-444444444444", ProducerID: "55555555-5555-4555-8555-555555555555", RunID: "66666666-6666-4666-8666-666666666666", CompletionOrdinal: "1", ObservedAt: at, Method: "eth_call", StatusCode: 200, TrustedIP: ptr("192.0.2.1")}}
	case p.ActivitySummary:
		f.ActivitySummary = &ActivityAggregate{Total: "20000", Successful: "19999", Failed: "1", Methods: []MethodCount{{Method: "eth_call", Total: "20000", Successful: "19999", Failed: "1"}}}
	case p.SanctionsReport:
		f.Sanctions = &SanctionsAggregate{Status: "hit", Matches: []SanctionMatch{{Address: testAddress(1), SourceID: "77777777-7777-4777-8777-777777777777", Reason: "source reason"}}, ScopedAddressCount: 1, SourceDigest: refs[SanctionsSource], CheckedAt: at}
		f.Wallets = wallet
	case p.ComplianceReport:
		f.Compliance = &ComplianceAggregate{Activity: ActivityAggregate{Total: "0", Successful: "0", Failed: "0", Methods: []MethodCount{}}, Sanctions: SanctionsAggregate{Status: "clear", Matches: []SanctionMatch{}, ScopedAddressCount: 1, SourceDigest: refs[SanctionsSource], CheckedAt: at}, Evidence: []ComplianceEvidence{}, KYC: "not_evaluated"}
		f.Wallets = wallet
	}
	return rs, ds, f, rc
}
