package rpcengine_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	p "privacy-proxy/internal/disclosurepolicy"
	f "privacy-proxy/internal/disclosuretest"
)

// Standing disclosure rules are case authority, never ambient RPC authority.
// Exercise the real V2 engine with identical chain data and ordinary rights.
func TestHistoryDisclosureEventsRulesDoNotWidenOrdinaryRPC(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, grant := range []bool{false, true} {
			name := "standard"
			if strict {
				name = "strict"
			}
			if grant {
				name += "/contract-grant"
			} else {
				name += "/no-contract-grant"
			}
			t.Run(name, func(t *testing.T) {
				configure := func(disclosure bool) func(*f.StateFixture) {
					return func(state *f.StateFixture) {
						if !grant {
							contracts := state.Contracts[f.Org]
							contracts[0].ReadGrants = contracts[0].ReadGrants[:0]
							state.Contracts[f.Org] = contracts
						}
						state.DisclosureRules = []p.RuleSource{}
						if disclosure {
							rule := f.DefaultRule()
							rule.Resources = []p.Resource{p.Events, p.Transactions}
							rule.MaxLevel = p.Full
							state.DisclosureRules = []p.RuleSource{rule}
						}
					}
				}
				baseline := newHistoryEngineFixture(t, strict, false, historyABI, configure(false))
				disclosure := newHistoryEngineFixture(t, strict, false, historyABI, configure(true))
				for _, fixture := range []*historyEngineFixture{baseline, disclosure} {
					engine := fixture.engine(t)
					token := f.Token(t, fixture.config.Snapshot, f.Subject, "Auditor")
					for _, request := range []struct{ method, params string }{
						{"eth_getLogs", `[{"fromBlock":"0x1","toBlock":"0x1"}]`},
						{"eth_getTransactionReceipt", `["` + fixture.txs[0].Hash().Hex() + `"]`},
						{"eth_getTransactionByHash", `["` + fixture.txs[1].Hash().Hex() + `"]`},
					} {
						result := historyResponse(t, engine, token, f.Org, request.method, request.params, `1`)
						if result["error"] != nil {
							t.Fatal(request.method, string(result["error"]))
						}
						if bytes.Contains(bytes.ToLower(result["result"]), []byte(strings.ToLower(fixture.hidden.Hex()[2:]))) {
							t.Fatal("ordinary RPC exposed a hidden embedded address")
						}
						if request.method == "eth_getLogs" && (string(result["result"]) == "[]") == grant {
							t.Fatal("ordinary event population does not match the contract grant")
						}
						if fixture == baseline {
							continue
						}
						before := historyResponse(t, baseline.engine(t), f.Token(t, baseline.config.Snapshot, f.Subject, "Auditor"), f.Org, request.method, request.params, `1`)
						beforeJSON, _ := json.Marshal(before)
						afterJSON, _ := json.Marshal(result)
						if !bytes.Equal(beforeJSON, afterJSON) {
							t.Fatalf("disclosure rule changed ordinary %s\nbefore: %s\nafter: %s", request.method, beforeJSON, afterJSON)
						}
					}
				}
			})
		}
	}
}
