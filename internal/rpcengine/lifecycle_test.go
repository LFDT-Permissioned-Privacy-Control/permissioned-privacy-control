package rpcengine_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"google.golang.org/grpc"

	"privacy-proxy/internal/admission"
	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/compliancepolicy"
	"privacy-proxy/internal/nodeapproval"
	"privacy-proxy/internal/nodeapproval/approvalpb"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
	"privacy-proxy/internal/transactioninput"
)

const createdAddress = "0x5555555555555555555555555555555555555555"

func lifecycleRule(class string, kinds ...policycore.CallType) policycore.FrameRule {
	return policycore.FrameRule{TargetClass: class, Selector: "*", CallTypes: kinds}
}

func TestLifecycleFinancialFailureNeverQueuesOrBroadcasts(t *testing.T) {
	for _, mode := range []string{policybundle.RawSubmissionOPSPreflight, policybundle.RawSubmissionGuardV1} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			producer := &faultProducer{}
			server := grpc.NewServer()
			approvalpb.RegisterApprovalDeliveryServer(server, producer)
			go server.Serve(listener)
			defer server.Stop()
			f := lifecycleFixture(mode)
			f.groups[0].AllowedMethods = []string{"eth_sendTransaction"}
			x := rawFaultSetup(t, f, &boundedWalletFacts{}, func(o *rpcengine.RawOptions) {
				if mode == policybundle.RawSubmissionGuardV1 {
					n := o.RawNodes[orgA]
					n.HashMode, n.Seed, n.KeyID, n.MaxBatch = nodeapproval.HashCalls, []byte(strings.Repeat("x", 32)), "pair-key", 32
					n.Delivery = nodeapproval.DeliveryOptions{Targets: []string{listener.Addr().String()}, Timeout: time.Second, MaxInFlight: 1, RetainMax: 32}
					o.RawNodes[orgA] = n
				}
			})
			tx := signedCreation(t, 456, common.FromHex("0x6001"))
			destination := crypto.CreateAddress(tx.Signer(), tx.Nonce())
			x.node.pre = map[string]any{destination.Hex(): map[string]any{}, tx.Signer().Hex(): map[string]any{"nonce": tx.Nonce()}}
			x.node.mutate = func(root map[string]any) {
				root["type"], root["to"], root["output"] = "CREATE", destination.Hex(), "0x6002"
			}
			out := lifecycleSubmission(t, x.engine, x.token, x.node, tx, nil)
			x.engine.Close()
			if out.Error == nil || out.Error.Code != -32002 || x.store.calls.Load() != 1 || producer.deliveries.Load() != 0 {
				t.Fatal("uncommitted creation financial outcome escaped", out, x.store.calls.Load(), producer.deliveries.Load())
			}
			methods, _ := x.node.counts()
			for _, method := range methods {
				if method == "eth_sendRawTransaction" {
					t.Fatal("creation was broadcast without COMMIT")
				}
			}
		})
	}
}

func lifecycleFixture(mode string) fixture {
	f := newFixture()
	f.lifecycle, f.rawMode = true, mode
	f.groups[0].Claims = []string{"deploy"}
	f.bindings[0].Allow = append(f.bindings[0].Allow,
		policycore.FrameRule{StorageAddress: addressC, Selector: "*"},
		lifecycleRule("create", policycore.CallTypeCreate, policycore.CallTypeCreate2),
		lifecycleRule("deployment-context", policycore.CallTypeCall, policycore.CallTypeStaticCall))
	return f
}

func lifecycleSubmission(t *testing.T, e *rpcengine.Engine, tok string, n *node, tx transactioninput.VerifiedTransaction, audience []string) rpcengine.Response {
	t.Helper()
	server := httptest.NewServer(e.Handler(orgA))
	defer server.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		response := rawHTTP(t, server, tok, tx, audience)
		methods, _ := n.counts()
		if response.Error == nil || response.Error.Code != -32002 || len(methods) != 0 || time.Now().After(deadline) {
			return response
		}
		time.Sleep(time.Millisecond) // bounded producer-start readiness; zero node work
	}
}

func TestLifecycleActualBothModesTemporalAndNamespaceAuthority(t *testing.T) {
	d := rawPostgres(t)
	for _, mode := range []string{policybundle.RawSubmissionOPSPreflight, policybundle.RawSubmissionGuardV1} {
		for _, scenario := range []string{"fresh-runtime", "empty-initcode", "unresolved-failed-leaf", "child-context", "missing-own-deploy", "other-group-deploy", "foreign-create-A-only", "foreign-create-B-member", "rollback-inside", "rollback-after", "precompile-binary", "self-foreign-beneficiary", "self-unregistered-empty", "self-precompile", "self-private-member", "self-foreign-empty"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				f := lifecycleFixture(mode)
				creation := child("CREATE", addressA, createdAddress, "0x6001")
				creation["output"] = "0x6002"
				calls := []any{creation, child("CALL", addressA, createdAddress, "0x")}
				allow := true
				n := &node{pre: map[string]any{createdAddress: map[string]any{}}}
				switch scenario {
				case "empty-initcode":
					creation["input"], creation["output"] = "0x", "0x"
				case "unresolved-failed-leaf":
					delete(creation, "to")
					creation["error"] = "execution reverted"
					creation["output"] = "0x"
					calls = []any{creation}
				case "child-context":
					delete(creation, "to")
					creation["error"], creation["output"] = "execution reverted", "0x"
					creation["calls"] = []any{child("CALL", createdAddress, createdAddress, "0x")}
					calls = []any{creation}
				case "missing-own-deploy", "other-group-deploy":
					f.groups[0].Claims, allow = []string{}, false
					if scenario == "other-group-deploy" {
						f.groups = append(f.groups, policybundle.Group{ID: second, Slug: "deployer", Name: "Deployer", Claims: []string{"deploy"}, AllowedMethods: []string{}})
						f.roles = append(f.roles, second)
					}
				case "foreign-create-A-only", "foreign-create-B-member":
					creation["to"] = addressB
					n.pre[addressB] = map[string]any{}
					calls = []any{creation}
					allow = scenario == "foreign-create-B-member"
					f.bGroups = []policybundle.Group{{ID: foreign, Slug: "b-deployer", Name: "B deployer", Claims: []string{"deploy"}, AllowedMethods: []string{}}}
					f.bBindings = []policycore.Binding{{Group: foreign, Allow: []policycore.FrameRule{lifecycleRule("create", policycore.CallTypeCreate)}}}
					if allow {
						f.roles = append(f.roles, foreign)
					}
				case "rollback-inside", "rollback-after":
					creation["from"] = addressC
					ancestor := child("CALL", addressA, addressC, "0x")
					ancestor["error"], ancestor["calls"] = "execution reverted", []any{creation, child("CALL", addressC, createdAddress, "0x")}
					calls = []any{ancestor}
					if scenario == "rollback-after" {
						calls, allow = append(calls, child("CALL", addressA, createdAddress, "0x")), false
					}
				case "precompile-binary":
					f.bindings[0].Allow = append(f.bindings[0].Allow, lifecycleRule("precompile", policycore.CallTypeDelegateCall))
					creation["calls"] = []any{child("DELEGATECALL", createdAddress, common.HexToAddress("0x1").Hex(), "0x3659cfe6")}
				case "self-foreign-beneficiary", "self-unregistered-empty", "self-precompile", "self-private-member", "self-foreign-empty":
					to := addressB
					allow = scenario == "self-unregistered-empty"
					if allow {
						to = walletAddress
					}
					if scenario == "self-precompile" {
						to, allow = common.HexToAddress("0x1").Hex(), true
					}
					if scenario == "self-private-member" {
						f.roles, f.bContracts, allow = append(f.roles, foreign), []policybundle.Contract{foreignGrant()}, true
					}
					if scenario == "self-foreign-empty" {
						n.pre[addressB] = map[string]any{}
					}
					creation["calls"] = []any{child("SELFDESTRUCT", createdAddress, to, "0x")}
				}
				n.mutate = func(root map[string]any) { root["calls"] = calls }
				e, tok, financial, _ := mountedRawEngine(t, f, n, d, false)
				tx := signedValue(t, 101)
				response := lifecycleSubmission(t, e, tok, n, tx, nil)
				if (response.Error == nil) != allow {
					t.Fatalf("want allow=%v, response=%+v", allow, response)
				}
				counts := rawCounts(t, d, financial.Metadata().NetworkKey, tx.Hash())
				if (!allow && counts != (admissionCounts{})) || (allow && counts.allowed != 1) {
					t.Fatal("temporal denial/COMMIT ordering", counts)
				}
				methods, _ := n.counts()
				for _, method := range methods {
					if !allow && method == "eth_sendRawTransaction" {
						t.Fatal("denied temporal execution was published")
					}
				}
			})
		}
	}
}

func signedCreation(t *testing.T, nonce uint64, input []byte) transactioninput.VerifiedTransaction {
	t.Helper()
	key, _ := crypto.HexToECDSA(strings.Repeat("0", 63) + "1")
	tx, err := types.SignTx(types.NewContractCreation(nonce, new(big.Int).Mul(big.NewInt(2), big.NewInt(1e18)), 100000, big.NewInt(1), input), types.LatestSignerForChainID(big.NewInt(1)), key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := tx.MarshalBinary()
	verified, err := transactioninput.DecodeRaw("0x"+hex.EncodeToString(raw), "1", transactioninput.ProtectedEVMProfile(), transactioninput.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func TestLifecycleActualRootCreationUsesOneNativeFinancialProjection(t *testing.T) {
	d := rawPostgres(t)
	for _, scenario := range []struct {
		mode       string
		simulation bool
	}{{policybundle.RawSubmissionOPSPreflight, false}, {policybundle.RawSubmissionGuardV1, false}, {policybundle.RawSubmissionOPSPreflight, true}, {policybundle.RawSubmissionGuardV1, true}} {
		mode, name := scenario.mode, scenario.mode
		if scenario.simulation {
			name += "-simulation"
		}
		t.Run(name, func(t *testing.T) {
			f := lifecycleFixture(mode)
			f.simulation = scenario.simulation
			f.groups[0].IsOrgAdmin = true
			f.groups[0].Claims = []string{}
			f.linkSigner = true
			f.capability("operational.travel-rule/v1")
			f.complianceHook = func(s *compliancepolicy.Source) {
				for i := range s.Organizations {
					spec := &s.Organizations[i].Spec
					spec.Settings = compliancepolicy.SourceSettings{Enabled: true, Currency: "usd", ThresholdFiat: 1, UnknownPricePolicy: "forbidden", EnforcementMode: "enforce"}
					spec.TokenPrices = []compliancepolicy.SourceTokenPrice{{ID: fmt.Sprintf("dddddddd-dddd-4ddd-8ddd-%012d", i+1), TokenAddress: "native", Symbol: "ETH", Decimals: 18, PricesByCurrency: map[string]float64{"usd": 1}}}
				}
			}
			// Valid transfer-shaped bytes are INITCODE, not a transfer call.
			input := common.FromHex("0xa9059cbb" + strings.Repeat("0", 24) + strings.TrimPrefix(addressB, "0x") + fmt.Sprintf("%064x", 5))
			tx := signedCreation(t, 123, input)
			destination := crypto.CreateAddress(tx.Signer(), tx.Nonce())
			n := &node{pre: map[string]any{destination.Hex(): map[string]any{}, tx.Signer().Hex(): map[string]any{"nonce": tx.Nonce()}}}
			n.mutate = func(root map[string]any) {
				root["type"], root["to"], root["output"] = "CREATE", destination.Hex(), "0x6001"
			}
			e, tok, financial, snapshot := mountedRawEngine(t, f, n, d, false)
			factory, _ := runtimepolicy.NewFactory(snapshot, func() time.Time { return time.Unix(now, 0) })
			view, err := factory.Build(tok)
			if err != nil {
				t.Fatal(err)
			}
			preview := func() map[string]any {
				r, err := financial.FinancialPreview(t.Context(), tok, orgA, admission.PreviewRequest{OriginatorActorID: view.ActorID(), SignedTransaction: tx.RawHex()})
				if err != nil {
					t.Fatal(err)
				}
				var out map[string]any
				if json.Unmarshal(materialize(t, r), &out) != nil {
					t.Fatal("preview shape")
				}
				return out
			}
			if p := preview(); p["allowed"] != false || p["coverage"] != "root_transfer" {
				t.Fatal("creation value escaped ordinary travel rule in preview", p)
			}
			if c := rawCounts(t, d, financial.Metadata().NetworkKey, tx.Hash()); c != (admissionCounts{}) {
				t.Fatal("preview wrote operational effects", c)
			}
			blocked := lifecycleSubmission(t, e, tok, n, tx, nil)
			if blocked.Error == nil || blocked.Error.Code != -32003 {
				t.Fatal("creation without record was not financially blocked", blocked)
			}
			r, err := financial.CreateRecord(t.Context(), tok, orgA, admission.CreateRecordRequest{OriginatorActorID: view.ActorID(), OriginatorData: json.RawMessage(`{"name":"origin"}`), BeneficiaryData: json.RawMessage(`{"name":"beneficiary"}`), TransferType: compliance.TransferTypeETH, BeneficiaryAddress: strings.ToLower(destination.Hex()), AmountWei: "3000000000000000000"})
			if err != nil {
				t.Fatal(err)
			}
			materialize(t, r)
			if p := preview(); p["allowed"] != true {
				t.Fatal("preview did not use same native-value projection", p)
			}
			n.onSend = func(raw string) string {
				if raw != tx.RawHex() {
					t.Error("creation bytes changed")
				}
				c := rawCounts(t, d, financial.Metadata().NetworkKey, tx.Hash())
				if c.used != 1 || c.allowed < 1 || c.denied != 1 || c.shares != 0 || c.origins != 1 {
					t.Error("publication preceded creation financial COMMIT", c)
				}
				return tx.Hash().Hex()
			}
			out := lifecycleSubmission(t, e, tok, n, tx, nil)
			if out.Error != nil || out.Result == nil || *out.Result != tx.Hash().Hex() {
				t.Fatal("approved creation did not publish", out)
			}
			var kind, to, profile string
			networkKey := financial.Metadata().NetworkKey
			if err := d.owner.QueryRow(t.Context(), `SELECT kind,encode(to_address,'hex'),evidence_profile FROM ops_admission_v2.compliance_events WHERE network_key=$1 AND tx_hash=$2 AND decision='allowed'`, networkKey[:], tx.Hash().Bytes()).Scan(&kind, &to, &profile); err != nil {
				t.Fatal(err)
			}
			if kind != "root_native" || to != strings.ToLower(hex.EncodeToString(destination[:])) || profile != financial.Metadata().EvidenceProfile {
				t.Fatal("initcode was treated as ERC20/incorrect destination/profile", kind, to, profile)
			}
			listed, err := financial.ListEvents(t.Context(), tok, orgA, admission.ListOptions{})
			if err != nil || !strings.Contains(string(materialize(t, listed)), "root_native") {
				t.Fatal("canonical reader rejected new retained event profile", err)
			}
			// Reuse reads the qualified origin through the canonical witness
			// scanner; new profile strings do not require rewriting old SQL data.
			if repeat := lifecycleSubmission(t, e, tok, n, tx, nil); repeat.Error != nil {
				t.Fatal("canonical new-profile origin reuse failed", repeat)
			}
			before, _ := n.counts()
			if shared := lifecycleSubmission(t, e, tok, n, tx, []string{view.ActorID()}); shared.Error == nil || shared.Error.Code != -32001 {
				t.Fatal("creation acquired visibleTo", shared)
			}
			after, _ := n.counts()
			if len(before) != len(after) {
				t.Fatal("creation audience denial reached node acquisition")
			}
			preserved := rawCounts(t, d, financial.Metadata().NetworkKey, tx.Hash())
			generation := uuid.NewString()
			state := admission.ExpectedState{Generation: generation, Coverage: admission.HashParts("explicit-test-restored-complete")}
			if err := admissionsql.BeginRecovery(t.Context(), d.ownerDSN, financial.Metadata().Network, generation); err != nil {
				t.Fatal(err)
			}
			if err := admissionsql.FinalizeRecovery(t.Context(), d.ownerDSN, financial.Metadata().Network, state, true); err != nil {
				t.Fatal("canonical recovery rejected new evidence profiles", err)
			}
			old := newFixture()
			old.rawMode, old.complianceHook = mode, f.complianceHook
			old.groups[0].IsOrgAdmin = true
			old.groups[0].AllowedMethods = []string{"eth_call", "eth_sendTransaction"}
			old.capability("operational.travel-rule/v1")
			oldSnapshot := old.load(t)
			store, err := admissionsql.Open(t.Context(), d.appDSN)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			oldProfile := rpcexecution.SignedCallProfileID
			if mode == policybundle.RawSubmissionGuardV1 {
				oldProfile = rpcexecution.GuardRetainedProfileID
			}
			rolledBack, err := admission.New(admission.Config{Snapshot: oldSnapshot, Clock: func() time.Time { return time.Unix(now, 0) }, NetworkBinding: financial.Metadata().Network, ExpectedState: state, Store: store, ExpectedEvidenceProfile: oldProfile, CursorKeyring: admission.CursorKeyring{Active: admission.CursorKey{ID: "test", Key: []byte(strings.Repeat("x", 32))}}})
			if err != nil {
				t.Fatal(err)
			}
			oldEvents, err := rolledBack.ListEvents(t.Context(), token(t, oldSnapshot, old.roles), orgA, admission.ListOptions{})
			if err != nil || !strings.Contains(string(materialize(t, oldEvents)), "root_native") {
				t.Fatal("new binary with old approved bundle cannot read retained v4 rows", err)
			}
			if c := rawCounts(t, d, financial.Metadata().NetworkKey, tx.Hash()); c != preserved {
				t.Fatal("recovery/old-bundle selection erased retained facts", c, preserved)
			}
		})
	}
}

func TestLifecycleActualDynamicCodeNamespaceIsNotRegistryOwnership(t *testing.T) {
	d := rawPostgres(t)
	const codeAddress = "0x6666666666666666666666666666666666666666"
	for _, mode := range []string{policybundle.RawSubmissionOPSPreflight, policybundle.RawSubmissionGuardV1} {
		for _, scenario := range []string{"same-namespace", "foreign-member", "foreign-not-member", "foreign-no-deploy", "omitted-code-address", "unrelated-anchored-code"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				f := lifecycleFixture(mode)
				borrow := lifecycleRule("deployment-context", policycore.CallTypeDelegateCall)
				borrow.CodeAddress = codeAddress
				if scenario == "omitted-code-address" {
					// One combined same-address rule; a duplicate class/selector
					// would itself correctly fail the existing ambiguity checker.
					f.bindings[0].Allow[3].CallTypes = append(f.bindings[0].Allow[3].CallTypes, policycore.CallTypeDelegateCall)
				} else {
					f.bindings[0].Allow = append(f.bindings[0].Allow, borrow)
				}
				codeCreation := child("CREATE", addressA, codeAddress, "0x6001")
				codeCreation["output"] = "0x6002"
				storageCreation := child("CREATE", addressA, createdAddress, "0x6001")
				storageCreation["output"] = "0x6002"
				storageCreation["calls"] = []any{child("DELEGATECALL", createdAddress, codeAddress, "0x")}
				calls := []any{codeCreation, storageCreation}
				allow := scenario == "same-namespace" || scenario == "foreign-member"
				if strings.HasPrefix(scenario, "foreign-") {
					f.roles = append(f.roles, foreign)
					if scenario == "foreign-not-member" {
						f.roles = []string{reader}
					}
					f.bGroups = []policybundle.Group{{ID: foreign, Slug: "deployer", Name: "B deployer", AllowedMethods: []string{}, Claims: []string{"deploy"}}}
					if scenario == "foreign-no-deploy" {
						f.bGroups[0].Claims = []string{}
					}
					f.bBindings = []policycore.Binding{{Group: foreign, Allow: []policycore.FrameRule{{StorageAddress: addressB, Selector: "*"}, lifecycleRule("create", policycore.CallTypeCreate)}}}
					codeCreation["from"] = addressB
					b := child("CALL", addressA, addressB, "0x")
					b["calls"] = []any{codeCreation}
					calls = []any{b, storageCreation}
				}
				n := &node{pre: map[string]any{createdAddress: map[string]any{}, codeAddress: map[string]any{}}}
				if scenario == "unrelated-anchored-code" {
					n.pre[codeAddress] = map[string]any{"code": "0x6002", "nonce": 1}
					calls = []any{storageCreation}
				}
				n.mutate = func(root map[string]any) { root["calls"] = calls }
				e, tok, financial, _ := mountedRawEngine(t, f, n, d, false)
				tx := signedValue(t, 303)
				out := lifecycleSubmission(t, e, tok, n, tx, nil)
				if (out.Error == nil) != allow {
					t.Fatalf("want allow=%v, got %+v", allow, out)
				}
				if c := rawCounts(t, d, financial.Metadata().NetworkKey, tx.Hash()); (!allow && c != (admissionCounts{})) || (allow && c.allowed != 1) {
					t.Fatal("namespace permissions/effects were mixed", c)
				}
			})
		}
	}
}

func TestLifecycleActualConstructorPinsStayTemporalAndExact(t *testing.T) {
	d := rawPostgres(t)
	for _, mode := range []string{policybundle.RawSubmissionOPSPreflight, policybundle.RawSubmissionGuardV1} {
		for _, scenario := range []string{"self-empty", "other-empty", "unknown-entry", "installed-mismatch", "empty-after-exit", "private-B-delegate", "private-B-callcode", "B-no-membership", "B-no-association", "shared-B-M6", "B-pin-mismatch", "borrow-after-empty-exit", "SELF-strict-pin"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				f := lifecycleFixture(mode)
				pin := crypto.Keccak256Hash(common.FromHex("0x6002")).Hex()
				f.runtime.SharedInfrastructure = []policybundle.SharedInfrastructure{{Address: createdAddress, CodeHash: &pin}}
				f.capability(policybundle.CapabilitySharedCode)
				n := &node{pre: map[string]any{createdAddress: map[string]any{}, walletAddress: map[string]any{}}}
				creation := child("CREATE", addressA, createdAddress, "0x6001")
				creation["output"] = "0x6002"
				inside := child("CALL", createdAddress, createdAddress, "0x")
				creation["calls"] = []any{inside}
				calls := []any{creation}
				allow := scenario == "self-empty" || scenario == "private-B-delegate" || scenario == "private-B-callcode"
				switch scenario {
				case "other-empty":
					inside["to"] = walletAddress
				case "unknown-entry":
					delete(n.pre, createdAddress)
					n.failMethod = "eth_getCode"
				case "installed-mismatch":
					creation["output"] = "0x6003"
					calls = append(calls, child("CALL", addressA, createdAddress, "0x"))
				case "empty-after-exit":
					creation["output"] = "0x"
					calls = append(calls, child("CALL", addressA, createdAddress, "0x"))
				case "SELF-strict-pin":
					creation["calls"] = []any{child("SELFDESTRUCT", createdAddress, createdAddress, "0x")}
				default:
					if scenario != "self-empty" {
						kind, nativeKind := "DELEGATECALL", policycore.CallTypeDelegateCall
						if scenario == "private-B-callcode" {
							kind, nativeKind = "CALLCODE", policycore.CallTypeCallCode
						}
						inside = child(kind, createdAddress, addressB, "0x")
						creation["calls"] = []any{inside}
						borrow := lifecycleRule("deployment-context", nativeKind)
						borrow.CodeAddress = addressB
						f.bindings[0].Allow = append(f.bindings[0].Allow, borrow)
						f.capability(policybundle.CapabilityForeignCode)
						f.roles = append(f.roles, foreign)
						f.bContracts = []policybundle.Contract{foreignGrant()}
						if scenario == "B-no-membership" {
							f.roles = []string{reader}
						}
						if scenario == "B-no-association" {
							f.bContracts = []policybundle.Contract{contract("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", addressB)}
						}
						if scenario == "shared-B-M6" {
							f.runtime.SharedInfrastructure = append(f.runtime.SharedInfrastructure, policybundle.SharedInfrastructure{Address: addressB})
						}
						if scenario == "B-pin-mismatch" {
							f.runtime.SharedInfrastructure = append(f.runtime.SharedInfrastructure, policybundle.SharedInfrastructure{Address: addressB, CodeHash: &pin})
						}
						if scenario == "borrow-after-empty-exit" {
							creation["output"] = "0x"
							creation["calls"] = []any{}
							// Empty runtime remains a created context, but its constructor
							// is no longer active: future storage pin must apply again.
							post := child("CALL", addressA, createdAddress, "0x")
							post["calls"] = []any{inside}
							calls = append(calls, post)
						}
					}
				}
				n.mutate = func(root map[string]any) { root["calls"] = calls }
				e, tok, financial, _ := mountedRawEngine(t, f, n, d, false)
				tx := signedValue(t, 202)
				out := lifecycleSubmission(t, e, tok, n, tx, nil)
				if (out.Error == nil) != allow {
					t.Fatalf("want allow=%v, got %+v", allow, out)
				}
				if c := rawCounts(t, d, financial.Metadata().NetworkKey, tx.Hash()); (!allow && c != (admissionCounts{})) || (allow && c.allowed != 1) {
					t.Fatal("pin/access denial was published or committed", c)
				}
			})
		}
	}
}

func TestLifecycleActualContextUpgradeKeepsSameGroupAndRuntimeTarget(t *testing.T) {
	d := rawPostgres(t)
	const implementation = "0x6666666666666666666666666666666666666666"
	for _, mode := range []string{policybundle.RawSubmissionOPSPreflight, policybundle.RawSubmissionGuardV1} {
		for _, scenario := range []string{"same-group-runtime", "other-group-upgrade", "foreign-runtime", "under-construction-target"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				f := lifecycleFixture(mode)
				f.groups[0].Claims = []string{"deploy", "upgrade"}
				f.capability(policybundle.CapabilityUpgradeFacts)
				borrow := lifecycleRule("deployment-context", policycore.CallTypeDelegateCall)
				borrow.CodeAddress, borrow.AllowUpgrade = addressC, true
				f.bindings[0].Allow = append(f.bindings[0].Allow, borrow)
				target := implementation
				switch scenario {
				case "other-group-upgrade":
					f.groups[0].Claims = []string{"deploy"}
					f.groups = append(f.groups, policybundle.Group{ID: second, Slug: "upgrader", Name: "Upgrader", AllowedMethods: []string{}, Claims: []string{"upgrade"}})
					f.roles = append(f.roles, second)
				case "foreign-runtime":
					target = addressB
				case "under-construction-target":
					target = createdAddress
				}
				impl := child("CREATE", addressA, implementation, "0x6001")
				impl["output"] = "0x6002"
				creation := child("CREATE", addressA, createdAddress, "0x6001")
				creation["output"] = "0x6002"
				creation["calls"] = []any{child("DELEGATECALL", createdAddress, addressC, "0x3659cfe6"+strings.Repeat("0", 24)+strings.TrimPrefix(target, "0x"))}
				n := &node{pre: map[string]any{createdAddress: map[string]any{}, implementation: map[string]any{}}, mutate: func(root map[string]any) { root["calls"] = []any{impl, creation} }}
				e, tok, financial, _ := mountedRawEngine(t, f, n, d, false)
				tx := signedValue(t, 404)
				out := lifecycleSubmission(t, e, tok, n, tx, nil)
				allow := scenario == "same-group-runtime"
				if (out.Error == nil) != allow {
					t.Fatalf("want allow=%v, got %+v", allow, out)
				}
				if c := rawCounts(t, d, financial.Metadata().NetworkKey, tx.Hash()); (!allow && c != (admissionCounts{})) || (allow && c.allowed != 1) {
					t.Fatal("upgrade context escaped own group/runtime target floor", c)
				}
			})
		}
	}
}
