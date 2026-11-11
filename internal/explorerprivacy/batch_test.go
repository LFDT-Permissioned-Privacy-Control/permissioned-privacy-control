package explorerprivacy

import (
	"reflect"
	"testing"

	"privacy-proxy/internal/readprivacy"
)

func TestCompleteBatchStrictDerivedRowsAndHolderFields(t *testing.T) {
	const own, hidden, token, redacted = "own", "hidden", "token", "registered-no-access"
	to := func(s string) *string { return &s }
	detailed := map[string]AddressVisibility{own: {Level: VisibilityFull}, hidden: {Level: VisibilityHidden}, token: {Level: VisibilityFull}, redacted: {Level: VisibilityRedacted}}
	b := Batch{
		Transfers: &TransferInput{Rows: []TokenTransfer{{TxHash: "one", LogIndex: 3, TokenAddress: token, From: hidden, To: own, Value: "7"}, {TxHash: "one", LogIndex: 4, TokenAddress: token, From: hidden, To: own, Value: "9"}}, Profile: readprivacy.ReadProfileStrict, Detailed: detailed, ViewerAddresses: map[string]bool{own: true}, StrictAdmitted: map[string]bool{TransferLogKey("one", 3): true, TransferLogKey("one", 4): false}},
		Internals: &InternalInput{Rows: []InternalTransaction{{TxHash: "one", From: token, To: to(hidden), Value: "3", Input: to("private-call"), Output: to("private-output"), Error: to("private-reason")}, {TxHash: "other", From: token, To: to(hidden), Value: "4"}}, Profile: readprivacy.ReadProfileStrict, Detailed: detailed, ViewerAddresses: map[string]bool{own: true}, Parents: map[string]*Transaction{"one": {From: own, To: to(token)}, "other": {From: hidden, To: to(token)}}},
		Holders:   &HolderInput{Rows: []TokenHolder{{Address: hidden, Balance: "9"}, {Address: redacted, Balance: "8", Percentage: 40}, {Address: own, Balance: "7", Percentage: 60}}, Visibility: VisibilityMap{hidden: VisibilityHidden, redacted: VisibilityRedacted, own: VisibilityFull}},
		Options:   RedactOpts{ListedTxHashes: map[string]bool{"other": true}, VisibleTxHashes: map[string]bool{"other": true}, ViewerIsAdmin: true, OrgAdminViewUserTxs: true},
	}
	out, err := RedactBatch(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Transfers) != 1 || out.Transfers[0].LogIndex != 3 || out.Transfers[0].From != "[PRIVATE]" || out.Transfers[0].Value != "7" {
		t.Fatalf("strict transfer did not render only its exact admitted log: %+v", out.Transfers)
	}
	if len(out.Internals) != 1 || *out.Internals[0].To != "[PRIVATE]" || out.Internals[0].Value != "3" || out.Internals[0].Input != nil || out.Internals[0].Output != nil || out.Internals[0].Error != nil {
		t.Fatalf("strict parent/frame field boundaries drifted: %+v", out.Internals)
	}
	if len(out.Holders) != 2 || out.Holders[0].Address != "[PRIVATE]" || out.Holders[0].Balance != "" || out.Holders[0].Percentage != 0 || out.Holders[1].Balance != "7" {
		t.Fatalf("holder address/financial masking drifted: %+v", out.Holders)
	}
	for _, change := range []struct{ remove, restore func() }{
		{func() { b.Internals.Profile = readprivacy.ReadProfileStandard }, func() { b.Internals.Profile = readprivacy.ReadProfileStrict }},
		{func() { delete(b.Transfers.StrictAdmitted, TransferLogKey("one", 4)) }, func() { b.Transfers.StrictAdmitted[TransferLogKey("one", 4)] = false }},
		{func() { delete(b.Internals.Parents, "other") }, func() { b.Internals.Parents["other"] = &Transaction{From: hidden, To: to(token)} }},
		{func() { delete(b.Holders.Visibility, hidden) }, func() { b.Holders.Visibility[hidden] = VisibilityHidden }},
	} {
		change.remove()
		if got, err := RedactBatch(b); err == nil || !reflect.DeepEqual(got, BatchOutput{}) {
			t.Fatal("missing complete derived context produced output")
		}
		change.restore()
	}
}
