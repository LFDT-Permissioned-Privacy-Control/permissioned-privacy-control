package disclosuredata

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"

	p "privacy-proxy/internal/disclosurepolicy"
)

const readUUID = "88888888-8888-4888-8888-888888888888"

func TestProjectionNeverLeaksFullFieldsAtLowerLevels(t *testing.T) {
	for _, level := range []p.Level{p.Redacted, p.Pseudonymous, p.Full} {
		t.Run(string(level), func(t *testing.T) {
			s, ds, f, c := testFixture(t, p.Transactions, List, level)
			r, e := Render(s, ds, f, c, readUUID)
			if e != nil {
				t.Fatal(e)
			}
			raw, e := json.Marshal(r)
			if e != nil {
				t.Fatal(e)
			}
			for _, word := range []string{`"transactionHash"`, `"value"`, `"addressId"`, addressString(testAddress(1)), addressString(testAddress(3))} {
				if bytes.Contains(raw, []byte(word)) != (level == p.Full) {
					t.Fatal("field projection", word, string(raw))
				}
			}
			s, ds, f, c = testFixture(t, p.ActivityLogs, List, level)
			r, e = Render(s, ds, f, c, readUUID)
			if e != nil {
				t.Fatal(e)
			}
			raw, _ = json.Marshal(r)
			if bytes.Contains(raw, []byte("192.0.2.1")) != (level == p.Full) || bytes.Contains(raw, []byte(`"actorId"`)) != (level == p.Full) {
				t.Fatal("activity field projection", string(raw))
			}
		})
	}
}
func TestEarlyAggregateBudgetBeforeCopyScanHashAndMarshal(t *testing.T) {
	s, ds, f, c := testFixture(t, p.SanctionsReport, Report, p.Full)
	reason := strings.Repeat("<", 1<<20)
	m := f.Sanctions.Matches[0]
	m.Reason = reason
	f.Sanctions.Matches = []SanctionMatch{m, m, m}
	hit := false
	_, e := render(s, ds, f, c, readUUID, func() { hit = true })
	if !errors.Is(e, ErrTooBroad) || hit {
		t.Fatal("late aggregate rejection", e, hit)
	}
	b := NewBudget()
	if !errors.Is(b.AddRepeatedBytes(math.MaxUint64, 2), ErrTooBroad) {
		t.Fatal("multiplication overflow")
	}
	if b.AddBytes(MaxVariableBytes) != nil || !errors.Is(b.AddBytes(1), ErrTooBroad) {
		t.Fatal("addition overflow")
	}
	s, ds, f, c = testFixture(t, p.Transactions, Detail, p.Full)
	f.Transactions[0].Full.Input = "0x" + strings.Repeat("00", (1<<20)/2-1)
	f.Transactions[0].Full.GasLimit = "20000000"
	f.Transactions[0].GasUsed = "16800000"
	r, e := Render(s, ds, f, c, readUUID)
	if e != nil {
		t.Fatal("valid large canonical hex rejected by worst escape multiplier", e)
	}
	raw, e := json.Marshal(r)
	if e != nil || len(raw) > MaxResponseBytes {
		t.Fatal("large hex actual encoding", len(raw), e)
	}
}
func TestFullFeePriceIsReceiptEffectivePriceNotFeeCap(t *testing.T) {
	s, ds, f, c := testFixture(t, p.Transactions, Detail, p.Full)
	v := f.Transactions[0].Full
	v.Type = 2
	v.SignedLegacyGasPrice = nil
	v.MaxFeePerGas = ptr(Amount("100"))
	v.MaxPriorityFeePerGas = ptr(Amount("2"))
	v.BlockBaseFeePerGas = ptr(Amount("10"))
	v.EffectiveGasPrice = "12"
	r, e := Render(s, ds, f, c, readUUID)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(r)
	if !bytes.Contains(raw, []byte(`"gasPrice":"12"`)) || !bytes.Contains(raw, []byte(`"maxFeePerGas":"100"`)) {
		t.Fatal("fee distinction", string(raw))
	}
	v.EffectiveGasPrice = "100"
	if _, e := Render(s, ds, f, c, readUUID); !errors.Is(e, ErrUnavailable) {
		t.Fatal("signed cap mislabeled actual price", e)
	}
	v.EffectiveGasPrice = "12"
	v.Input = "0x"
	v.Error = ptr("<script>\n& failure")
	r, e = Render(s, ds, f, c, readUUID)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ = json.Marshal(r)
	if bytes.Contains(raw, []byte("<script>")) || !bytes.Contains(raw, []byte(`\u003cscript\u003e`)) {
		t.Fatal("unsafe raw JSON string", string(raw))
	}
}
func TestCompleteResolveBeyondFirstPageAndDetailParticipant(t *testing.T) {
	s, ds, f, c := testFixture(t, p.AddressHistory, Resolve, p.Redacted)
	template := f.Addresses[0]
	wallet := f.Wallets[0]
	f.Addresses = []AddressFact{}
	f.Wallets = []WalletFact{}
	for i := 1; i <= 4096; i++ {
		var a [20]byte
		binary.BigEndian.PutUint32(a[16:], uint32(i))
		entry := template
		entry.Address = a
		f.Addresses = append(f.Addresses, entry)
		w := wallet
		w.Address = a
		f.Wallets = append(f.Wallets, w)
	}
	wanted := f.Addresses[4095].Address
	q := Query{Version: 1, Resource: p.AddressHistory, View: Resolve, AddressID: ptr(locator(c.Keys.Active, c, wanted))}
	n, e := Normalize(q, s.Query.Scope())
	if e != nil {
		t.Fatal(e)
	}
	s.Query = n
	c.Query = n
	r, e := Render(s, ds, f, c, readUUID)
	if e != nil {
		t.Fatal("resolve falsely limited to first page", e)
	}
	raw, _ := json.Marshal(r)
	if bytes.Contains(raw, []byte(addressString(wanted))) || !bytes.Contains(raw, []byte("[PRIVATE]")) {
		t.Fatal("resolve became raw address capability", string(raw))
	}
	f.End = false
	if _, e := Render(s, ds, f, c, readUUID); !errors.Is(e, ErrUnavailable) {
		t.Fatal("incomplete candidates returned a false notfound", e)
	}
	s, ds, f, c = testFixture(t, p.Transactions, Detail, p.Full)
	other := testAddress(9)
	f.Wallets = append(f.Wallets, WalletFact{ActorID: testActor(1), Address: other, AcceptedAt: f.Wallets[0].AcceptedAt})
	q = Query{Version: 1, Resource: p.Transactions, View: Detail, AddressID: ptr(locator(c.Keys.Active, c, other)), TransactionHash: ptr(hashString(f.Transactions[0].Hash))}
	n, e = Normalize(q, s.Query.Scope())
	if e != nil {
		t.Fatal(e)
	}
	s.Query = n
	c.Query = n
	if _, e := Render(s, ds, f, c, readUUID); !errors.Is(e, ErrNotFound) {
		t.Fatal("unrelated case wallet locator authorized tx detail", e)
	}
}
func TestRequiredSourceKindAndStrictAuthenticatedOrder(t *testing.T) {
	s, ds, f, _ := testFixture(t, p.Transactions, List, p.Full)
	f.Transactions[0].Provenance.Source = ds[len(ds)-1].Reference
	if e := ValidateFacts(s, ds, f, nil); !errors.Is(e, ErrUnavailable) {
		t.Fatal("wallet descriptor stood in for history", e)
	}
	s, ds, f, _ = testFixture(t, p.ActivityLogs, List, p.Full)
	pos := Position{Kind: ActivitySource, Activity: &ActivityPosition{f.Activities[0].ObservedAt.UnixMicro(), f.Activities[0].ProducerID, f.Activities[0].RunID, f.Activities[0].CompletionOrdinal, f.Activities[0].ID}}
	if e := ValidateFacts(s, ds, f, &pos); !errors.Is(e, ErrUnavailable) {
		t.Fatal("duplicate after-key accepted", e)
	}
	f.Activities[0].CompletionOrdinal = "2"
	if e := ValidateFacts(s, ds, f, &pos); e != nil {
		t.Fatal("strict advancing page rejected", e)
	}
	f.Activities = append(f.Activities, f.Activities[0])
	if e := ValidateFacts(s, ds, f, nil); !errors.Is(e, ErrUnavailable) {
		t.Fatal("renderer sorted/accepted duplicate source rows", e)
	}
}
