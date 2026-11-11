package explorer

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"

	"privacy-proxy/internal/explorerprivacy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/readprivacyabi"
)

const pureOwn = "0x1111111111111111111111111111111111111111"
const pureHidden = "0x2222222222222222222222222222222222222222"
const pureContract = "0x3333333333333333333333333333333333333333"
const pureToken = "0x4444444444444444444444444444444444444444"
const pureFunctionABI = `[{"type":"function","name":"mintFor","inputs":[{"name":"who","type":"address"}],"outputs":[],"stateMutability":"nonpayable"}]`
const pureEventABI = `[{"type":"event","name":"Transfer","anonymous":false,"inputs":[{"name":"from","type":"address","indexed":true},{"name":"to","type":"address","indexed":true},{"name":"value","type":"uint256","indexed":false}]}]`

func pureDB() *mockDB {
	return &mockDB{visMap: VisibilityMap{pureOwn: VisibilityFull, pureHidden: VisibilityHidden, pureContract: VisibilityRedacted, pureToken: VisibilityFull}, linkedAddrs: []string{pureOwn}, eventAccessMap: map[string]bool{pureToken: false}}
}

func TestPureBatchTransactionParityAndIndependentSignals(t *testing.T) {
	selector := hex.EncodeToString(crypto.Keccak256([]byte("mintFor(address)"))[:4])
	input := "0x" + selector + encodeAddressSlot(pureOwn)
	nonce := uint64(17)
	rows := []Transaction{
		{Hash: "own", From: pureOwn, To: strPtr(pureHidden), Nonce: &nonce, Value: "1"},
		// Same hash intentionally: ABI participation belongs to this actual
		// row's input, not a hash-keyed cache that could borrow its sibling.
		{Hash: "duplicate", From: pureHidden, To: strPtr(pureContract), InputData: input, Value: "2"},
		{Hash: "duplicate", From: pureHidden, To: strPtr(pureContract), InputData: "0x12345678", Value: "3"},
		{Hash: "log", From: pureHidden, To: strPtr(pureContract), Value: "4"},
		{Hash: "share", From: pureHidden, To: strPtr(pureContract), Value: "5"},
		{Hash: "union", From: pureHidden, To: strPtr(pureContract), InputData: "0x1234", Value: "6"},
		{Hash: "creation", From: pureHidden, ContractAddress: strPtr(pureContract), Value: "7"},
		{Hash: "event-count", From: pureOwn, To: strPtr(pureToken), TokenTransferCount: 2, TxCategories: []string{"token_transfer"}},
	}
	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		for _, audit := range []bool{false, true} {
			t.Run(profile.String()+map[bool]string{false: "/ordinary", true: "/admin-volume"}[audit], func(t *testing.T) {
				db := pureDB()
				engine := NewRedactionEngine(nil, db, profile)
				engine.SetABIResolver(&stubABIResolver{byAddr: map[string]string{pureContract: pureFunctionABI}})
				engine.SetLogParticipantStore(&stubLogParticipantStore{TxHashes: map[string]bool{"log": true}})
				opts := RedactOpts{VisibleTxHashes: map[string]bool{"union": true}, ListedTxHashes: map[string]bool{"share": true}, ViewerIsAdmin: audit, OrgAdminViewUserTxs: audit, Stats: &RedactStats{}}
				legacy, err := engine.RedactTransactions(context.Background(), rows, "actor", opts)
				if err != nil {
					t.Fatal(err)
				}
				detailed, _ := db.GetBatchVisibilityDetailed(context.Background(), "actor", nil)
				abiMatches := make([]bool, len(rows))
				logMatches := make(map[string]bool)
				for i, row := range rows {
					logMatches[strings.ToLower(row.Hash)] = row.Hash == "log"
					if row.HasRecipient() && *row.To == pureContract {
						abiMatches[i] = readprivacyabi.IsViewerInCalldataABI(row.InputData, pureFunctionABI, map[string]bool{pureOwn: true})
					}
				}
				pureOpts := opts
				pureOpts.Stats = &RedactStats{}
				got, err := explorerprivacy.RedactBatch(explorerprivacy.Batch{Transactions: &explorerprivacy.TransactionInput{Rows: rows, Profile: profile, Detailed: detailed, ViewerAddresses: map[string]bool{pureOwn: true}, LogParticipants: logMatches, CalldataParticipants: abiMatches}, Options: pureOpts, EventAccess: map[string]bool{pureToken: false}})
				if err != nil || !reflect.DeepEqual(got.Transactions, legacy) || !reflect.DeepEqual(pureOpts.Stats, opts.Stats) {
					t.Fatalf("pure/legacy row or audit-count drift: error=%v\npure=%+v\nlegacy=%+v", err, got.Transactions, legacy)
				}
				seen := make(map[string]int)
				for _, row := range got.Transactions {
					seen[row.Hash]++
					if row.Hash == "union" && !profile.Strict() && !audit && (row.From != "[PRIVATE]" || row.Value != "" || row.InputData != "") {
						t.Fatal("transfer union revealed fields beyond row survival")
					}
					if row.Hash == "event-count" && row.TokenTransferCount != 0 && (profile.Strict() || !audit) {
						t.Fatal("event-derived count escaped field policy")
					}
				}
				if profile.Strict() && (len(got.Transactions) != 2 || seen["duplicate"] != 0 || seen["share"] != 0 || seen["union"] != 0 || seen["log"] != 0) {
					t.Fatal("strict inherited ABI/log/share/admin participation")
				}
				if !profile.Strict() && !audit && seen["duplicate"] != 1 {
					t.Fatal("position-aligned ABI participation was lost or borrowed")
				}
			})
		}
	}
}

func pureLogInput(profile rbac.ReadProfile) explorerprivacy.LogInput {
	topic0 := eventTopic0("Transfer(address,address,uint256)")
	from, to := "0x"+encodeAddressSlot(pureHidden), "0x"+encodeAddressSlot(pureOwn)
	return explorerprivacy.LogInput{
		Rows: []Log{{TxHash: "tx", Address: pureToken, Topic0: &topic0, Topic1: &from, Topic2: &to, Data: "0x" + strings.Repeat("0", 63) + "1"}}, Profile: profile,
		Visibility: VisibilityMap{pureToken: VisibilityFull, pureHidden: VisibilityHidden, pureOwn: VisibilityFull}, MasterMetadata: map[string]VisibilityReason{pureToken: ReasonPublicAddress, pureHidden: ReasonNoAccess, pureOwn: ReasonPublicAddress}, ViewerAddresses: map[string]bool{pureOwn: true},
		Rules: map[string]EventRulesResolution{pureToken: {Wildcard: true}}, RulesResolved: map[string]bool{pureToken: true}, AdminContracts: map[string]bool{pureToken: false}, UnlockableContracts: map[string]bool{pureToken: false}, AllowDynamicPayload: map[string]bool{pureToken: false}, ContractABIs: map[string]json.RawMessage{pureToken: json.RawMessage(pureEventABI)}, ResolvedABIs: map[string]string{pureToken: pureEventABI},
	}
}

func TestPureBatchLogParityAndPrivateMetadataKeys(t *testing.T) {
	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		t.Run(profile.String(), func(t *testing.T) {
			in := pureLogInput(profile)
			engine := NewRedactionEngine(nil, pureDB(), profile)
			engine.SetABIResolver(&stubABIResolver{byAddr: map[string]string{pureToken: pureEventABI}})
			engine.SetEventRuleChecker(&stubEventRuleChecker{byAddr: in.Rules})
			legacy, err := engine.RedactLogs(context.Background(), in.Rows, "actor")
			if err != nil {
				t.Fatal(err)
			}
			got, err := explorerprivacy.RedactBatch(explorerprivacy.Batch{Logs: &in})
			if err != nil || !reflect.DeepEqual(got.Logs, legacy) || len(got.Logs) != 1 {
				t.Fatalf("log drift: %v pure=%+v legacy=%+v", err, got.Logs, legacy)
			}
			if *got.Logs[0].Topic1 != "0x"+strings.Repeat("0", 64) || got.Logs[0].AddressMetadata[pureHidden] != "" {
				t.Fatal("masked private address escaped through a topic/metadata key")
			}
		})
	}
}

func TestPureBatchRejectsMissingContextBeforeAnyRow(t *testing.T) {
	mutations := map[string]func(*explorerprivacy.LogInput){
		"unknown-profile":    func(in *explorerprivacy.LogInput) { in.Profile = rbac.ReadProfile(255) },
		"emitter":            func(in *explorerprivacy.LogInput) { delete(in.Visibility, pureToken) },
		"embedded":           func(in *explorerprivacy.LogInput) { delete(in.Visibility, pureHidden) },
		"rule":               func(in *explorerprivacy.LogInput) { delete(in.Rules, pureToken) },
		"unresolved-rule":    func(in *explorerprivacy.LogInput) { in.RulesResolved[pureToken] = false },
		"admin-fact":         func(in *explorerprivacy.LogInput) { delete(in.AdminContracts, pureToken) },
		"ABI":                func(in *explorerprivacy.LogInput) { delete(in.ContractABIs, pureToken) },
		"ABI-mismatch":       func(in *explorerprivacy.LogInput) { in.ResolvedABIs[pureToken] = "[]" },
		"legacy-ABI-posture": func(in *explorerprivacy.LogInput) { in.ABIResolverAbsent = true },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			in := pureLogInput(rbac.ReadProfileStandard)
			mutate(&in)
			out, err := explorerprivacy.RedactBatch(explorerprivacy.Batch{Logs: &in, Holders: &explorerprivacy.HolderInput{Rows: []TokenHolder{{Address: pureOwn, Balance: "9"}}, Visibility: VisibilityMap{pureOwn: VisibilityFull}}})
			if err == nil || !reflect.DeepEqual(out, explorerprivacy.BatchOutput{}) {
				t.Fatal("incomplete batch produced a partial or wildcard-admitted result")
			}
		})
	}
}
