package rpcengine_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"privacy-proxy/internal/admission"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/nodeapproval"
	"privacy-proxy/internal/nodeapproval/approvalpb"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/operational/walletsql"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/transactioninput"
	"privacy-proxy/internal/walletadapter"
	"privacy-proxy/internal/walletops"
)

// These tests mount the actual new constructor with REAL financial/wallet SQL
// stores. The node/producers are bounded loopback protocol fixtures, not a
// fake native verdict, financial receipt or production-backend qualification.
func multiOrgEngine(t *testing.T, f fixture, n *node, d rawDatabase) (*rpcengine.Engine, string, *admission.Service, *policybundle.CatalogSnapshot) {
	t.Helper()
	return mountedRawEngine(t, f, n, d, true)
}

func mountedRawEngine(t *testing.T, f fixture, n *node, d rawDatabase, multiOrg bool) (*rpcengine.Engine, string, *admission.Service, *policybundle.CatalogSnapshot) {
	t.Helper()
	f.multiOrg = multiOrg
	if f.rawMode == "" {
		f.rawMode = policybundle.RawSubmissionOPSPreflight
	}
	if !slices.Contains(f.groups[0].AllowedMethods, "eth_sendTransaction") {
		f.groups[0].AllowedMethods = append(slices.Clone(f.groups[0].AllowedMethods), "eth_sendTransaction")
	}
	snapshot := f.load(t)
	clock := func() time.Time { return time.Unix(now, 0) }
	if _, err := nativeadmission.NewRaw(snapshot, clock); multiOrg && err == nil {
		t.Fatal("old native constructor accepted v3")
	}
	binding := walletops.ServiceBinding{ServiceOrigin: "https://ops.test", Environment: "test", ChainID: "1", GenesisHash: nodeHash, DeploymentID: "multi-" + uuid.NewString()}
	network := admission.NetworkBinding{Environment: binding.Environment, ChainID: binding.ChainID, GenesisHash: binding.GenesisHash, DeploymentID: binding.DeploymentID}
	gen, walletGen := uuid.NewString(), uuid.NewString()
	if err := admissionsql.BootstrapEmpty(t.Context(), d.ownerDSN, network, gen); err != nil {
		t.Fatal(err)
	}
	if err := walletsql.BootstrapEmpty(t.Context(), d.ownerDSN, binding, walletGen); err != nil {
		t.Fatal(err)
	}
	store, err := admissionsql.Open(t.Context(), d.appDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	walletStore, err := walletsql.Open(t.Context(), d.walletDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(walletStore.Close)
	namespace, _ := binding.Namespace()
	walletState := walletops.ExpectedState{Generation: walletGen, Coverage: walletsql.EmptyCoverage()}
	resolver, err := walletadapter.New(walletStore, namespace, walletState, clock)
	if err != nil {
		t.Fatal(err)
	}
	profile := rpcexecution.SignedCallProfileID
	if f.rawMode == policybundle.RawSubmissionGuardV1 {
		profile = rpcexecution.GuardRetainedProfileID
	}
	financial, err := admission.New(admission.Config{Snapshot: snapshot, Clock: clock, NetworkBinding: network, ExpectedState: admission.ExpectedState{Generation: gen, Coverage: admissionsql.EmptyCoverage()}, Store: store, ExpectedEvidenceProfile: profile})
	if err != nil {
		t.Fatal(err)
	}
	if n.onSend == nil {
		n.onSend = func(raw string) string {
			tx, err := transactioninput.DecodeRaw(raw, "1", transactioninput.ProtectedEVMProfile(), transactioninput.DefaultLimits())
			if err != nil {
				t.Error(err)
				return common.Hash{}.Hex()
			}
			return tx.Hash().Hex()
		}
	}
	nodeServer := httptest.NewServer(n)
	t.Cleanup(nodeServer.Close)
	clients := map[string]*rpcexecution.Client{}
	for _, org := range []string{orgA, orgB} {
		client, err := rpcexecution.NewClient(nodeServer.Client().Transport, rpcexecution.NodeBinding{OrganizationID: org, URL: nodeServer.URL, ChainID: "1", Profile: rpcexecution.NodeProfileID, PragueStartInclusive: 10, PragueEndExclusive: 20, AllowUnauthenticated: true}, rpcexecution.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		clients[org] = client
	}
	rawNode := rpcengine.RawNodeOptions{Binding: rpcexecution.NodeBinding{OrganizationID: orgA, URL: nodeServer.URL, ChainID: "1", Profile: profile, PragueStartInclusive: 10, PragueEndExclusive: 20, AllowUnauthenticated: true}, Transport: nodeServer.Client().Transport, Limits: rpcexecution.DefaultLimits()}
	if f.rawMode == policybundle.RawSubmissionGuardV1 {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		producer := &faultProducer{batches: make(chan []byte, 16)}
		server := grpc.NewServer()
		approvalpb.RegisterApprovalDeliveryServer(server, producer)
		go server.Serve(listener)
		t.Cleanup(server.Stop)
		rawNode.HashMode, rawNode.Seed, rawNode.KeyID, rawNode.MaxBatch = nodeapproval.HashCalls, bytes.Repeat([]byte{7}, 32), "pair-key", 32
		rawNode.Delivery = nodeapproval.DeliveryOptions{Targets: []string{listener.Addr().String()}, Timeout: time.Second, MaxInFlight: 1, RetainMax: 32}
	}
	options := rpcengine.RawOptions{CallClients: clients, RawNodes: map[string]rpcengine.RawNodeOptions{orgA: rawNode}, Wallets: resolver, WalletBinding: binding, WalletState: walletState, Admission: financial, Clock: clock}
	constructor := rpcengine.NewRaw
	if multiOrg {
		if _, err := rpcengine.NewRaw(snapshot, options); err == nil {
			t.Fatal("old RPC constructor accepted v3")
		}
		constructor = rpcengine.NewMultiOrg
	}
	e, err := constructor(snapshot, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e, token(t, snapshot, f.roles), financial, snapshot
}

func foreignGrant() policybundle.Contract {
	c := contract("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", addressB)
	c.ReadGrants = []policybundle.ReadGrant{{ID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", GroupID: foreign, EventRules: policybundle.EventRules{Mode: "none", Rules: []policybundle.EventRule{}}}}
	return c
}

func TestMultiOrgActualHTTPReplaysPrivateSharedAndGuardFloors(t *testing.T) {
	d := rawPostgres(t)
	type scenario struct {
		name                                 string
		member, grant, shared, scope, signed bool
		mode                                 string
		allowed                              bool
	}
	for _, kind := range []string{"CALL", "STATICCALL", "DELEGATECALL", "CALLCODE"} {
		borrowed := kind == "DELEGATECALL" || kind == "CALLCODE"
		scenarios := []scenario{
			{"membershipAB-grantsAB", true, true, false, true, false, "", true},
			{"membershipA-only", false, true, false, true, false, "", false},
			{"membershipAB-grantA-only", true, false, false, true, false, "", false},
			{"membershipAB-scoping-off", true, false, false, false, false, "", true},
			{"membershipAB-sharedB", true, true, true, true, false, "", !borrowed},
			{"guard-membershipAB-grantsAB", true, true, false, true, true, policybundle.RawSubmissionGuardV1, true},
			{"guard-membershipA-only", false, true, false, true, true, policybundle.RawSubmissionGuardV1, false},
			{"guard-membershipAB-grantA-only", true, false, false, true, true, policybundle.RawSubmissionGuardV1, false},
			{"direct-signed-membershipAB", true, true, false, true, true, policybundle.RawSubmissionOPSPreflight, true},
			{"direct-signed-membershipA-only", false, true, false, true, true, policybundle.RawSubmissionOPSPreflight, false},
		}
		for _, scenario := range scenarios {
			t.Run(kind+"/"+scenario.name, func(t *testing.T) {
				f := newFixture()
				f.rawMode = scenario.mode
				f.runtime.IntraOrgGrantTracing = scenario.scope
				if scenario.member {
					f.roles = append(f.roles, foreign)
				}
				if scenario.grant {
					f.bContracts = []policybundle.Contract{foreignGrant()}
				}
				if borrowed {
					f.bindings[0].Allow = append(f.bindings[0].Allow, policycore.FrameRule{StorageAddress: addressA, CodeAddress: addressB, Selector: "*", CallTypes: []policycore.CallType{policycore.CallType(strings.ToLower(kind))}})
					f.capability(policybundle.CapabilityForeignCode)
					// B deliberately has NO native rules: borrowed code access is
					// not a second B function matcher or B operational claim.
				} else if scenario.grant || !scenario.scope {
					f.bBindings = []policycore.Binding{{Group: foreign, Allow: []policycore.FrameRule{{StorageAddress: addressB, Selector: "*"}}}}
				}
				if scenario.shared {
					f.runtime.SharedInfrastructure = []policybundle.SharedInfrastructure{{Address: addressB}}
					f.bindings[0].Allow = append(f.bindings[0].Allow, policycore.FrameRule{TargetClass: "shared", Selector: "*"})
					f.capability(policybundle.CapabilitySharedCode)
				}
				var muxTraces atomic.Int64
				n := &node{onTrace: func() { muxTraces.Add(1) }, mutate: func(root map[string]any) {
					nested := child(kind, addressA, addressB, "0x")
					if kind == "DELEGATECALL" {
						nested["value"] = root["value"]
					}
					root["calls"] = []any{nested}
				}}
				e, token, financial, _ := multiOrgEngine(t, f, n, d)
				var response rpcengine.Response
				if scenario.signed {
					server := httptest.NewServer(e.Handler(orgA))
					defer server.Close()
					tx := signedValue(t, 900)
					deadline := time.Now().Add(3 * time.Second)
					for {
						response = rawHTTP(t, server, token, tx, nil)
						methods, _ := n.counts()
						if f.rawMode != policybundle.RawSubmissionGuardV1 || response.Error == nil || response.Error.Code != -32002 || len(methods) != 0 || time.Now().After(deadline) {
							break
						}
						time.Sleep(2 * time.Millisecond) // bounded CLIENT readiness retry, zero node work
					}
					counts := rawCounts(t, d, financial.Metadata().NetworkKey, tx.Hash())
					if (!scenario.allowed && counts != (admissionCounts{})) || (scenario.allowed && counts.allowed != 1) {
						t.Fatal("native denial/effects ordering", counts)
					}
				} else {
					response, _ = request(t, e, token, orgA, map[string]any{"to": addressA}, nil)
				}
				if (response.Error == nil) != scenario.allowed {
					t.Fatalf("want allow=%v, got %+v", scenario.allowed, response)
				}
				methods, _ := n.counts()
				// Guard retains its unchanged separate prestate-diff query. Only
				// one mux execution supplies the validated tree/output per request.
				if muxTraces.Load() != 1 {
					t.Fatal("changed org retraced execution", methods)
				}
			})
		}
	}
	testMultiOrgDispatchAndBudgets(t, d)
}

func testMultiOrgDispatchAndBudgets(t *testing.T, database rawDatabase) {
	const bImplementation = "0x5555555555555555555555555555555555555555"
	for _, bUpgrade := range []bool{false, true} {
		t.Run(fmt.Sprintf("private-B-upgrade/own-claim=%v", bUpgrade), func(t *testing.T) {
			f := newFixture()
			f.roles = append(f.roles, foreign)
			f.groups[0].IsOrgAdmin = true
			claims := []string{}
			if bUpgrade {
				claims = []string{"upgrade"}
			}
			f.bGroups = []policybundle.Group{{ID: foreign, Slug: "b", Name: "B", AllowedMethods: []string{"eth_call"}, Claims: claims}}
			f.bBindings = []policycore.Binding{{Group: foreign, Allow: []policycore.FrameRule{{StorageAddress: addressB, Selector: "*", AllowUpgrade: true}}}}
			f.bContracts = []policybundle.Contract{foreignGrant(), contract("dddddddd-dddd-4ddd-8ddd-dddddddddddd", bImplementation)}
			f.capability(policybundle.CapabilityUpgradeFacts)
			input := "0x3659cfe6" + common.Bytes2Hex(common.LeftPadBytes(common.HexToAddress(bImplementation).Bytes(), 32))
			n := &node{codes: map[string]string{bImplementation: "0x6000"}, mutate: func(root map[string]any) { root["calls"] = []any{child("CALL", addressA, addressB, input)} }}
			e, jwt, _, _ := multiOrgEngine(t, f, n, database)
			out, _ := request(t, e, jwt, orgA, map[string]any{"to": addressA}, nil)
			if (out.Error == nil) != bUpgrade {
				t.Fatal("root-A claims replaced B operational authority", out)
			}
		})
	}
	for _, bTarget := range []bool{false, true} {
		t.Run(fmt.Sprintf("B-storage-borrows-A-code/B-implementation=%v", bTarget), func(t *testing.T) {
			f := newFixture()
			f.roles = append(f.roles, foreign)
			f.groups[0].IsOrgAdmin = true
			f.bGroups = []policybundle.Group{{ID: foreign, Slug: "b", Name: "B", AllowedMethods: []string{"eth_call"}, Claims: []string{"upgrade"}}}
			f.bBindings = []policycore.Binding{{Group: foreign, Allow: []policycore.FrameRule{{StorageAddress: addressB, Selector: "*"}, {StorageAddress: addressB, CodeAddress: addressC, Selector: "*", CallTypes: []policycore.CallType{policycore.CallTypeDelegateCall}, AllowUpgrade: true}}}}
			f.bContracts = []policybundle.Contract{foreignGrant(), contract("dddddddd-dddd-4ddd-8ddd-dddddddddddd", bImplementation)}
			f.capability(policybundle.CapabilityUpgradeFacts)
			f.capability(policybundle.CapabilityForeignCode)
			target := addressC
			if bTarget {
				target = bImplementation
			}
			input := "0x3659cfe6" + common.Bytes2Hex(common.LeftPadBytes(common.HexToAddress(target).Bytes(), 32))
			n := &node{codes: map[string]string{bImplementation: "0x6000"}, mutate: func(root map[string]any) {
				b := child("CALL", addressA, addressB, "0x")
				b["calls"] = []any{child("DELEGATECALL", addressB, addressC, input)}
				root["calls"] = []any{b}
			}}
			e, jwt, _, _ := multiOrgEngine(t, f, n, database)
			out, _ := request(t, e, jwt, orgA, map[string]any{"to": addressA}, nil)
			if (out.Error == nil) != bTarget {
				t.Fatal("B storage borrowed root-A implementation namespace", out)
			}
		})
	}
	for _, bad := range []string{"", "depth", "caller", "value"} {
		t.Run("B-frame-constraints/"+bad, func(t *testing.T) {
			f := newFixture()
			f.roles = append(f.roles, foreign)
			min, max, value, caller := 1, int64(1), "0", addressA
			if bad == "depth" {
				min, max = 2, 2
			}
			if bad == "caller" {
				caller = addressC
			}
			f.bBindings = []policycore.Binding{{Group: foreign, Allow: []policycore.FrameRule{{StorageAddress: addressB, Selector: "*", MinDepth: &min, MaxDepth: &max, MaxValue: &value, CallerAddress: caller}}}}
			for _, capability := range []string{policybundle.CapabilityDepth, policybundle.CapabilityValue, policybundle.CapabilityCaller} {
				f.capability(capability)
			}
			n := &node{mutate: func(root map[string]any) {
				b := child("CALL", addressA, addressB, "0x")
				if bad == "value" {
					b["value"] = "0x1"
					b["error"] = "insufficient balance"
				}
				root["calls"] = []any{b}
			}}
			e, jwt, _, _ := multiOrgEngine(t, f, n, database)
			out, _ := request(t, e, jwt, orgA, map[string]any{"to": addressA}, nil)
			if (out.Error == nil) != (bad == "") {
				t.Fatal("real frame facts changed during org dispatch", out)
			}
		})
	}
	for _, bSharedRule := range []bool{false, true} {
		t.Run(fmt.Sprintf("shared-descendant-inherits-B/rule=%v", bSharedRule), func(t *testing.T) {
			f := newFixture()
			f.roles = append(f.roles, foreign)
			f.runtime.SharedInfrastructure = []policybundle.SharedInfrastructure{{Address: addressC}}
			f.capability(policybundle.CapabilitySharedCode)
			// A has a shared rule in both cases. It must never rescue B.
			f.bindings[0].Allow = append(f.bindings[0].Allow, policycore.FrameRule{TargetClass: "shared", Selector: "*"})
			f.bBindings = []policycore.Binding{{Group: foreign, Allow: []policycore.FrameRule{{StorageAddress: addressB, Selector: "*"}}}}
			if bSharedRule {
				f.bBindings[0].Allow = append(f.bBindings[0].Allow, policycore.FrameRule{TargetClass: "shared", Selector: "*"})
			}
			n := &node{mutate: func(root map[string]any) {
				b := child("CALL", addressA, addressB, "0x")
				b["calls"] = []any{child("STATICCALL", addressB, addressC, "0x")}
				root["calls"] = []any{b}
			}}
			e, jwt, _, _ := multiOrgEngine(t, f, n, database)
			out, _ := request(t, e, jwt, orgA, map[string]any{"to": addressA}, nil)
			if (out.Error == nil) != bSharedRule {
				t.Fatal("parent org dispatch lost", out)
			}
		})
	}
	t.Run("registered-shared-root-does-not-borrow-A", func(t *testing.T) {
		f := newFixture()
		f.runtime.SharedInfrastructure = []policybundle.SharedInfrastructure{{Address: addressB}}
		f.capability(policybundle.CapabilitySharedCode)
		f.bindings[0].Allow = append(f.bindings[0].Allow, policycore.FrameRule{TargetClass: "shared", Selector: "*"})
		n := &node{}
		e, jwt, _, _ := multiOrgEngine(t, f, n, database)
		out, _ := request(t, e, jwt, orgA, map[string]any{"to": addressB}, nil)
		methods, _ := n.counts()
		if out.Error == nil || len(methods) != 0 {
			t.Fatal("shared root bypassed registered owner", out, methods)
		}
	})
	for _, bRule := range []bool{false, true} {
		t.Run(fmt.Sprintf("caught-reverted-descendant/rule=%v", bRule), func(t *testing.T) {
			f := newFixture()
			f.roles = append(f.roles, foreign)
			if bRule {
				f.bBindings = []policycore.Binding{{Group: foreign, Allow: []policycore.FrameRule{{StorageAddress: addressB, Selector: "*"}}}}
			}
			n := &node{mutate: func(root map[string]any) {
				b := child("CALL", addressA, addressB, "0x")
				b["error"] = "execution reverted"
				b["output"] = "0x"
				root["calls"] = []any{b}
			}}
			e, jwt, _, _ := multiOrgEngine(t, f, n, database)
			out, _ := request(t, e, jwt, orgA, map[string]any{"to": addressA}, nil)
			if (out.Error == nil) != bRule {
				t.Fatal("caught frame skipped or relabeled", out)
			}
		})
	}
	for _, ownImplementation := range []bool{false, true} {
		for _, aUpgrade := range []bool{false, true} {
			t.Run(fmt.Sprintf("borrowed-upgrade/own-impl=%v/A-upgrade=%v", ownImplementation, aUpgrade), func(t *testing.T) {
				f := newFixture()
				f.roles = append(f.roles, foreign)
				f.bContracts = []policybundle.Contract{foreignGrant()}
				f.bGroups = []policybundle.Group{{ID: foreign, Slug: "foreign", Name: "B admin", IsOrgAdmin: true, AllowedMethods: []string{"eth_call"}, Claims: []string{}}}
				if aUpgrade {
					f.groups[0].Claims = []string{"upgrade"}
				}
				f.capability(policybundle.CapabilityUpgradeFacts)
				f.capability(policybundle.CapabilityForeignCode)
				f.bindings[0].Allow = append(f.bindings[0].Allow, policycore.FrameRule{StorageAddress: addressA, CodeAddress: addressB, Selector: "*", CallTypes: []policycore.CallType{policycore.CallTypeDelegateCall}, AllowUpgrade: true})
				implementation := addressB
				if ownImplementation {
					implementation = addressC
				}
				input := "0x3659cfe6" + common.Bytes2Hex(common.LeftPadBytes(common.HexToAddress(implementation).Bytes(), 32))
				n := &node{mutate: func(root map[string]any) { root["calls"] = []any{child("DELEGATECALL", addressA, addressB, input)} }}
				e, jwt, _, _ := multiOrgEngine(t, f, n, database)
				out, _ := request(t, e, jwt, orgA, map[string]any{"to": addressA}, nil)
				if (out.Error == nil) != (aUpgrade && ownImplementation) {
					t.Fatal("B code claims or foreign implementation supplied A authority", out)
				}
			})
		}
	}
	for _, source := range []policycore.AddressSource{policycore.AddressSourceSigner, policycore.AddressSourcePrincipalLinked} {
		t.Run("foreign-ABI-exact/"+string(source), func(t *testing.T) {
			f := newFixture()
			f.roles = append(f.roles, foreign)
			f.rawMode = policybundle.RawSubmissionOPSPreflight
			b := foreignGrant()
			var abi any
			json.Unmarshal([]byte(`[{"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"name":"who","type":"address"}],"outputs":[{"type":"uint256"}]}]`), &abi)
			b.ABI = encoded(t, abi)
			f.bContracts = []policybundle.Contract{b}
			f.bindings[0].Allow = append(f.bindings[0].Allow, policycore.FrameRule{StorageAddress: addressA, CodeAddress: addressB, Selector: "0x70a08231", ABIDigest: policycore.ABIDigest(string(b.ABI)), CallTypes: []policycore.CallType{policycore.CallTypeDelegateCall}, Args: []policycore.ArgConstraint{{Index: 0, AddressEquals: &policycore.AddressMatch{Source: source}}}})
			f.capability(policybundle.CapabilityForeignCode)
			f.capability(policybundle.CapabilityCalldata)
			if source == policycore.AddressSourcePrincipalLinked {
				f.capability(policybundle.CapabilityLinkedWallets)
			}
			tx := signedValue(t, 901)
			input := "0x70a08231" + common.Bytes2Hex(common.LeftPadBytes(tx.Signer().Bytes(), 32))
			n := &node{mutate: func(root map[string]any) {
				b := child("DELEGATECALL", addressA, addressB, input)
				b["value"] = root["value"]
				root["calls"] = []any{b}
			}}
			e, jwt, _, _ := multiOrgEngine(t, f, n, database)
			server := httptest.NewServer(e.Handler(orgA))
			defer server.Close()
			out := rawHTTP(t, server, jwt, tx, nil)
			if (out.Error == nil) != (source == policycore.AddressSourceSigner) {
				t.Fatal("foreign ABI/signer/principal distinction lost", out)
			}
			if source == policycore.AddressSourceSigner {
				out, _ = request(t, e, jwt, orgA, map[string]any{"to": addressA}, nil)
				if out.Error == nil {
					t.Fatal("simulation borrowed signed principal")
				}
			}
		})
	}
	t.Run("all-mapped-org-zero-rule-budget", func(t *testing.T) {
		f := newFixture()
		f.roles = append(f.roles, foreign)
		f.bGroups = []policybundle.Group{}
		f.bBindings = []policycore.Binding{}
		for i := 0; i < 4000; i++ {
			f.bGroups = append(f.bGroups, policybundle.Group{ID: fmt.Sprintf("bbbbbbbb-bbbb-4bbb-8bbb-%012x", i+1), Slug: fmt.Sprintf("b-%d", i), Name: fmt.Sprintf("Unused %d", i), AllowedMethods: []string{}, Claims: []string{}})
		}
		n := &node{mutate: func(root map[string]any) {
			calls := make([]any, 500)
			for i := range calls {
				calls[i] = child("CALL", addressA, addressA, "0x")
			}
			root["calls"] = calls
		}}
		e, jwt, _, snapshot := multiOrgEngine(t, f, n, database)
		out, _ := request(t, e, jwt, orgA, map[string]any{"to": addressA}, nil)
		if out.Error == nil {
			t.Fatal("root-only bound ignored mapped B zero-rule groups")
		}
		jwt = token(t, snapshot, []string{reader})
		out, _ = request(t, e, jwt, orgA, map[string]any{"to": addressA}, nil)
		if out.Error != nil {
			t.Fatal("same complete frames fail without B work", out)
		}
	})
	t.Run("repeated-foreign-association-is-charged-and-cached-once", func(t *testing.T) {
		f := newFixture()
		f.roles = append(f.roles, foreign)
		f.bGroups = []policybundle.Group{{ID: foreign, Slug: "foreign", Name: "Mapped", AllowedMethods: []string{}, Claims: []string{}}}
		f.bMappedGroups = []string{foreign}
		b := foreignGrant()
		for i := 1; i < 4000; i++ {
			id := fmt.Sprintf("bbbbbbbb-bbbb-4bbb-8bbb-%012x", i)
			f.bGroups = append(f.bGroups, policybundle.Group{ID: id, Slug: fmt.Sprintf("b-%d", i), Name: fmt.Sprintf("Unmapped %d", i), AllowedMethods: []string{}, Claims: []string{}})
			b.ReadGrants = append(b.ReadGrants, policybundle.ReadGrant{ID: fmt.Sprintf("cccccccc-cccc-4ccc-8ccc-%012x", i), GroupID: id, EventRules: policybundle.EventRules{Mode: "none", Rules: []policybundle.EventRule{}}})
		}
		f.bContracts = []policybundle.Contract{b}
		f.capability(policybundle.CapabilityForeignCode)
		f.bindings[0].Allow = append(f.bindings[0].Allow, policycore.FrameRule{StorageAddress: addressA, CodeAddress: addressB, Selector: "*", CallTypes: []policycore.CallType{policycore.CallTypeDelegateCall}})
		n := &node{mutate: func(root map[string]any) {
			calls := make([]any, 512)
			for i := range calls {
				calls[i] = child("DELEGATECALL", addressA, addressB, "0x")
			}
			root["calls"] = calls
		}}
		e, jwt, _, _ := multiOrgEngine(t, f, n, database)
		out, _ := request(t, e, jwt, orgA, map[string]any{"to": addressA}, nil)
		if out.Error != nil {
			t.Fatal("one bounded B association rescanned/charged per frame", out)
		}
	})
}
