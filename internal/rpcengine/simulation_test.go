package rpcengine_test

import (
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
)

func TestSimulationActualHTTPDeploymentHasNoFinancialOrGuardEffects(t *testing.T) {
	d := rawPostgres(t)
	for _, mode := range []string{policybundle.RawSubmissionOPSPreflight, policybundle.RawSubmissionGuardV1} {
		for _, scenario := range []string{"success", "ordinary-call", "null-to", "request-nonce-ignored", "empty-initcode", "proved-from", "unproved-from", "explicit-zero-from", "missing-deploy", "other-group-deploy", "foreign-root-no-hop", "ambiguous-org", "revert", "out-of-gas", "private-child-denied", "signer-absent", "historical-nonadmin", "historical-admin", "method-denied", "expiry-after-nonce", "expiry-after-trace", "old-profile-closed"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				f := lifecycleFixture(mode)
				f.simulation = scenario != "old-profile-closed"
				var clock atomic.Int64
				clock.Store(now)
				f.clock, f.producer = &clock, &faultProducer{}
				from := common.Address{}
				call := map[string]any{"input": "0x6001"}
				if scenario == "ordinary-call" {
					call["to"] = addressA
				}
				if scenario == "proved-from" || scenario == "unproved-from" || scenario == "signer-absent" {
					from = signedValue(t, 1).Signer()
					call["from"] = from.Hex()
					f.linkSigner = scenario != "unproved-from"
				}
				if scenario == "explicit-zero-from" {
					call["from"] = from.Hex()
				}
				if scenario == "null-to" {
					call["to"] = nil
				}
				if scenario == "request-nonce-ignored" {
					call["nonce"] = "0x7b"
				}
				if scenario == "empty-initcode" {
					call["input"] = "0x"
				}
				if scenario == "missing-deploy" || scenario == "other-group-deploy" {
					f.groups[0].Claims = []string{}
					if scenario == "other-group-deploy" {
						f.groups = append(f.groups, policybundle.Group{ID: second, Slug: "deployer", Name: "Deployer", AllowedMethods: []string{}, Claims: []string{"deploy"}})
						f.roles = append(f.roles, second)
					}
				}
				var block any
				if scenario == "historical-nonadmin" || scenario == "historical-admin" {
					block = "0x1"
					if scenario == "historical-admin" {
						f.groups[0].IsOrgAdmin, f.groups[0].Claims = true, []string{}
					}
				}
				if scenario == "method-denied" {
					f.groups[0].AllowedMethods = []string{"eth_sendTransaction"}
				}
				if scenario == "signer-absent" {
					var abi any
					json.Unmarshal([]byte(`[{"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"name":"who","type":"address"}],"outputs":[{"type":"uint256"}]}]`), &abi)
					canonical := encoded(t, abi)
					f.contracts[0].ABI = canonical
					f.bindings[0].Allow[0] = policycore.FrameRule{StorageAddress: addressA, Selector: "0x70a08231", ABIDigest: policycore.ABIDigest(string(canonical)), Args: []policycore.ArgConstraint{{Index: 0, AddressEquals: &policycore.AddressMatch{Source: policycore.AddressSourceSigner}}}}
					f.capability(policybundle.CapabilityCalldata)
				}
				destination := crypto.CreateAddress(from, 9)
				explicit := orgA
				if scenario == "foreign-root-no-hop" {
					f.roles = append(f.roles, foreign)
					f.bContracts = []policybundle.Contract{contract("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", strings.ToLower(destination.Hex()))}
				}
				if scenario == "ambiguous-org" {
					f.roles, explicit = append(f.roles, foreign), ""
				}
				n := &node{nonce: "0x9", pre: map[string]any{from.Hex(): map[string]any{"nonce": 9}, destination.Hex(): map[string]any{}}}
				n.mutate = func(root map[string]any) {
					if scenario == "ordinary-call" {
						return
					}
					root["type"], root["to"], root["output"] = "CREATE", destination.Hex(), "0xfeed"
					if scenario == "revert" {
						root["error"], root["output"] = "execution reverted", "0xdead"
					}
					if scenario == "out-of-gas" {
						root["error"], root["output"] = "out of gas", "0x"
					}
					if scenario == "private-child-denied" {
						root["calls"] = []any{child("CALL", destination.Hex(), addressB, "0x")}
					}
					if scenario == "signer-absent" {
						root["calls"] = []any{child("CALL", destination.Hex(), addressA, "0x70a08231"+common.Bytes2Hex(common.LeftPadBytes(from.Bytes(), 32)))}
					}
				}
				if scenario == "expiry-after-nonce" {
					n.onNonce = func() { clock.Store(now + 300) }
				}
				if scenario == "expiry-after-trace" {
					n.onTrace = func() { clock.Store(now + 300) }
				}
				e, tok, financial, _ := mountedRawEngine(t, f, n, d, false)
				out, raw := request(t, e, tok, explicit, call, block)
				e.Close() // Flush any accidental enqueue before observing producer.
				allow := scenario == "success" || scenario == "ordinary-call" || scenario == "null-to" || scenario == "request-nonce-ignored" || scenario == "empty-initcode" || scenario == "proved-from" || scenario == "historical-admin"
				if allow {
					if out.Error != nil || out.Result == nil || *out.Result != "0xfeed" {
						t.Fatalf("authorized constructor output unavailable: %s", raw)
					}
				} else if scenario == "revert" {
					if out.Error == nil || out.Error.Code != 3 || out.Error.Data != "0xdead" {
						t.Fatalf("real revert output lost: %s", raw)
					}
				} else if scenario == "out-of-gas" {
					if out.Error == nil || out.Error.Code != -32000 || out.Error.Data != nil {
						t.Fatalf("non-revert leaked/misclassified: %s", raw)
					}
				} else if out.Error == nil || out.Result != nil || strings.Contains(string(raw), "0xfeed") {
					t.Fatalf("denied constructor exposed result: %s", raw)
				}
				methods, _ := n.counts()
				preNode := scenario == "unproved-from" || scenario == "explicit-zero-from" || scenario == "ambiguous-org" || scenario == "old-profile-closed" || scenario == "historical-nonadmin" || scenario == "method-denied"
				preTrace := preNode || scenario == "foreign-root-no-hop" || scenario == "expiry-after-nonce"
				traces := 0
				for _, method := range methods {
					if method == "debug_traceCall" {
						traces++
					}
					if method == "eth_sendRawTransaction" || method == "eth_call" {
						t.Fatal("simulation broadcast or issued another execution", methods)
					}
				}
				if (preNode && len(methods) != 0) || (preTrace && traces != 0) || (!preTrace && traces != 1) {
					t.Fatal("scope/from/liveness/work ordering changed", methods)
				}
				var events, origins, shares int
				network := financial.Metadata().NetworkKey
				if err := d.owner.QueryRow(t.Context(), `SELECT (SELECT count(*)FROM ops_admission_v2.compliance_events WHERE network_key=$1),(SELECT count(*)FROM ops_admission_v2.qualified_tx_origins WHERE network_key=$1),(SELECT count(*)FROM ops_admission_v2.tx_shares WHERE network_key=$1)`, network[:]).Scan(&events, &origins, &shares); err != nil {
					t.Fatal(err)
				}
				if events != 0 || origins != 0 || shares != 0 || f.producer.deliveries.Load() != 0 {
					t.Fatal("simulation created financial/privacy/Guard effects", events, origins, shares, f.producer.deliveries.Load())
				}
			})
		}
	}
}
