package admissionsql

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"github.com/ethereum/go-ethereum/common"
	"os"
	a "privacy-proxy/internal/admission"
	p "privacy-proxy/internal/disclosurepolicy"
	"strconv"
	"testing"
	"time"
)

func TestFinanceIndependentWireVectors(t *testing.T) {
	var v struct {
		Inputs   struct{ NetworkRawHex, Generation, ExpectedCoverageRawHex, PlanRawHex, Actor, Org string }
		Scope    struct{ Expected string }
		OneEvent struct {
			Expected           string
			OrderedRawPartsHex []string
		}
		Sets []struct {
			Name                string
			Coverage, Reference struct{ Expected string }
		}
	}
	raw, err := os.ReadFile("testdata/finance-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	decode := func(x string) []byte {
		b, e := hex.DecodeString(x)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	digest := func(x string) a.Digest { var d a.Digest; copy(d[:], decode(x)); return d }
	r := &FinanceReader{network: digest(v.Inputs.NetworkRawHex), state: a.ExpectedState{Generation: v.Inputs.Generation, Coverage: digest(v.Inputs.ExpectedCoverageRawHex)}, planDigest: digest(v.Inputs.PlanRawHex)}
	sc := p.Scope{TargetActors: []string{v.Inputs.Actor}, DataTime: p.Interval{Start: 100, End: 200}, Addresses: p.Addresses{Mode: "all-target-addresses", Values: []string{}}}
	parts, _, err := financeScopeParts(v.Inputs.Org, sc)
	if err != nil || a.HashParts("ops.disclosure.finance-scope/v1", parts...).String() != v.Scope.Expected {
		t.Fatal("scope vector", err)
	}
	from, to := common.BytesToAddress(bytes.Repeat([]byte{0xaa}, 20)), common.BytesToAddress(bytes.Repeat([]byte{0xbb}, 20))
	wei, currency := "1", "usd"
	fiat, threshold := 2.0, 100.0
	e := a.Event{ID: 1, Scope: a.Scope{Actor: v.Inputs.Actor, Organization: v.Inputs.Org, Hash: common.BytesToHash(bytes.Repeat([]byte{0x22}, 32))}, Kind: "root_native", Coverage: "root_transfer", From: &from, To: &to, AmountWei: &wei, AmountFiat: &fiat, Threshold: &threshold, Currency: &currency, Decision: "allowed", DecisionAt: time.Unix(100, 0).UTC(), PolicyDigest: digest(hex.EncodeToString(bytes.Repeat([]byte{0x66}, 32)))}
	e.Anchor.Hash = [32]byte(bytes.Repeat([]byte{0x77}, 32))
	e.Anchor.Number = 9
	e.Anchor.Timestamp = 99
	e.Anchor.Profile = "geth-prague-lifecycle-signed/v1"
	row, _, err := financeEventParts(e)
	if err != nil {
		t.Fatal(err)
	}
	if len(row) != 30 {
		t.Fatal("row shape", len(row))
	}
	for i, part := range row {
		if !bytes.Equal(part, decode(v.OneEvent.OrderedRawPartsHex[i])) {
			t.Fatalf("independent row part %d actual=%q expected=%q", i, part, decode(v.OneEvent.OrderedRawPartsHex[i]))
		}
	}
	if a.HashParts("ops.disclosure.finance-event/v1", row...).String() != v.OneEvent.Expected {
		t.Fatal("event vector")
	}
	for _, set := range v.Sets {
		t.Run(set.Name, func(t *testing.T) {
			events := []a.Event{}
			if set.Name == "one" {
				events = append(events, e)
			}
			ref, coverage, err := r.reference(v.Inputs.Org, sc, events)
			if err != nil || ref.String() != set.Reference.Expected || coverage.String() != set.Coverage.Expected {
				t.Fatal("reference vector", ref, coverage, err)
			}
		})
	}
	e.AmountFiat = nil
	absent, _, _ := financeEventParts(e)
	zero := 0.0
	e.AmountFiat = &zero
	present, _, _ := financeEventParts(e)
	if bytes.Equal(absent[10], present[10]) {
		t.Fatal("nil conflated with zero")
	}
	e.Monitored = true
	monitored, _, _ := financeEventParts(e)
	if string(monitored[14]) != "1" {
		t.Fatal("monitored wire value")
	}
	t.Log("100 maximum framed rows plus bounded scope overhead", strconv.Itoa(100*(MaxFinanceRowBytes+31*4)+65536+16384))
	if 100*(MaxFinanceRowBytes+31*4)+65536+16384 > MaxFinanceHashInputBytes {
		t.Fatal("hash ceiling")
	}
}
