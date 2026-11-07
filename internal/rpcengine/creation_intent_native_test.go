package rpcengine_test

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/admission"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
)

func creationIntentRuntimeFixture() fixture {
	f := lifecycleFixture(policybundle.RawSubmissionOPSPreflight)
	f.creationAttribution = &policybundle.CreationAttribution{Factories: []policybundle.FactoryAttribution{{Address: addressA, OrganizationID: orgA, CodeHash: crypto.Keccak256Hash(common.FromHex("0x6000")).Hex(), Scope: policybundle.FactoryCreationSubtree}}}
	return f
}

func creationFrame(creator, destination string) map[string]any {
	return map[string]any{"type": "CREATE", "from": creator, "to": destination, "input": "0x6001", "output": "0x6000", "value": "0x0", "gas": "0x10000", "gasUsed": "0x1"}
}

func intentCallFrame(from, to string, children []any) map[string]any {
	return map[string]any{"type": "CALL", "from": from, "to": to, "input": "0x", "output": "0x", "value": "0x0", "gas": "0x10000", "gasUsed": "0x1", "calls": children}
}

func intentCheck(t *testing.T, f fixture, n *node, check func(*nativeadmission.Engine, *runtimepolicy.Factory, *runtimepolicy.View, *rpcexecution.CallExecution, nativeadmission.WalletSnapshot)) {
	t.Helper()
	snapshot := f.load(t)
	clock := func() time.Time { return time.Unix(now, 0) }
	factory, err := runtimepolicy.NewFactory(snapshot, clock)
	if err != nil {
		t.Fatal(err)
	}
	view, err := factory.Build(token(t, snapshot, f.roles))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := nativeadmission.NewCreationIntents(snapshot, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nativeadmission.NewSimulation(snapshot, clock); err == nil {
		t.Fatal("old constructor accepted new attribution")
	}
	tx := rawTransaction(t, []byte{1, 2})
	if n.pre == nil {
		n.pre = map[string]any{}
	}
	n.pre[tx.Signer().Hex()] = map[string]any{"nonce": tx.Nonce()}
	server := httptest.NewServer(n)
	defer server.Close()
	client, err := rpcexecution.NewClient(server.Client().Transport, rpcexecution.NodeBinding{OrganizationID: orgA, URL: server.URL, ChainID: "1", Profile: rpcexecution.LifecycleSignedProfileID, PragueStartInclusive: 10, PragueEndExclusive: 20, AllowUnauthenticated: true}, rpcexecution.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	client, _ = client.WithCredential("")
	execution, err := client.AcquireLifecycleSigned(t.Context(), tx)
	if err != nil {
		t.Fatal(err)
	}
	wallets, _ := nativeadmission.NewWalletSnapshot(view.ActorID(), "same-native-snapshot", clock(), []common.Address{tx.Signer()})
	check(engine, factory, view, execution, wallets)
}

func TestCreationIntentNativeApprovalIsSamePassAndObjectBound(t *testing.T) {
	f := creationIntentRuntimeFixture()
	n := &node{pre: map[string]any{createdAddress: map[string]any{}}}
	n.mutate = func(root map[string]any) { root["calls"] = []any{creationFrame(addressA, createdAddress)} }
	intentCheck(t, f, n, func(engine *nativeadmission.Engine, factory *runtimepolicy.Factory, view *runtimepolicy.View, execution *rpcexecution.CallExecution, wallets nativeadmission.WalletSnapshot) {
		approval, err := engine.CheckSignedWithCreationPlan(t.Context(), view, orgA, execution, wallets)
		if err != nil || approval == nil || approval.RequireMatches(view, orgA, execution, wallets) != nil {
			t.Fatal("successful same pass not captured", err)
		}
		plan := approval.Plan()
		if plan == nil || len(plan.Data().Entries) != 1 || !plan.HasFactoryAuthority() || plan.Digest() != nativeadmission.CreationPlanDigest(plan.Encoded()) {
			t.Fatal("missing bounded intent")
		}
		if _, err := admission.DecodeCreationPlan(plan.Encoded(), admission.Digest(plan.Digest())); err != nil {
			t.Fatal("actual captured plan cannot be restored", err)
		}
		d := plan.Data()
		if d.Entries[0].Creator != common.HexToAddress(addressA) || d.Entries[0].Namespace != orgA || d.Entries[0].FactoryRoot != 0 || d.Entries[0].CreationParent != -1 {
			t.Fatal("wrong captured authority", d)
		}
		d.Entries[0].Namespace = orgB
		b := plan.Encoded()
		b[0] = '!'
		if plan.Data().Entries[0].Namespace != orgA || plan.Digest() != nativeadmission.CreationPlanDigest(plan.Encoded()) {
			t.Fatal("mutable plan escaped")
		}
		otherView, _ := factory.Build(token(t, f.load(t), f.roles))
		if approval.RequireMatches(otherView, orgA, execution, wallets) == nil || approval.RequireMatches(view, orgB, execution, wallets) == nil {
			t.Fatal("swapped view/org accepted")
		}
		swapped, _ := nativeadmission.NewWalletSnapshot(view.ActorID(), wallets.Version(), wallets.EvidenceAt(), nil)
		if approval.RequireMatches(view, orgA, execution, swapped) == nil {
			t.Fatal("same version different wallet contents accepted")
		}
		var zero nativeadmission.ApprovedSignedCheck
		if zero.RequireMatches(view, orgA, execution, wallets) == nil {
			t.Fatal("caller-created approval accepted")
		}
	})
}

func TestCreationIntentFactoryScopeStopsAtForeignCallWithoutCreation(t *testing.T) {
	f := creationIntentRuntimeFixture()
	f.roles = append(f.roles, foreign)
	f.bGroups = []policybundle.Group{{ID: foreign, Slug: "foreign", Name: "Foreign", AllowedMethods: []string{"eth_call"}, Claims: []string{}}}
	f.bBindings = []policycore.Binding{{Group: foreign, Allow: []policycore.FrameRule{{StorageAddress: addressB, Selector: "*"}}}}
	last := "0x6666666666666666666666666666666666666666"
	sibling := "0x7777777777777777777777777777777777777777"
	n := &node{pre: map[string]any{createdAddress: map[string]any{}, last: map[string]any{}, sibling: map[string]any{}}}
	n.mutate = func(root map[string]any) {
		first := creationFrame(addressA, createdAddress)
		first["calls"] = []any{intentCallFrame(createdAddress, addressB, []any{intentCallFrame(addressB, addressC, []any{creationFrame(addressC, last)})}), creationFrame(createdAddress, sibling)}
		root["calls"] = []any{first}
	}
	intentCheck(t, f, n, func(engine *nativeadmission.Engine, _ *runtimepolicy.Factory, view *runtimepolicy.View, execution *rpcexecution.CallExecution, wallets nativeadmission.WalletSnapshot) {
		approval, err := engine.CheckSignedWithCreationPlan(t.Context(), view, orgA, execution, wallets)
		if err != nil {
			t.Fatal("actual routed scope fixture denied", err)
		}
		d := approval.Plan().Data()
		if len(d.Entries) != 3 || d.Entries[1].CreationParent != 0 || d.Entries[1].Namespace != orgA || d.Entries[1].FactoryRoot != -1 || d.Entries[2].CreationParent != 0 || d.Entries[2].FactoryRoot != 0 || len(d.FactoryRoots) != 1 {
			t.Fatal("foreign CALL did not terminate factory authority", d)
		}
	})
}

func TestCreationIntentDeniedLaterFrameNeverExposesApprovedPlan(t *testing.T) {
	for _, kind := range []string{"CALL", "SELFDESTRUCT"} {
		t.Run(kind, func(t *testing.T) {
			f := creationIntentRuntimeFixture()
			n := &node{pre: map[string]any{createdAddress: map[string]any{}}}
			n.mutate = func(root map[string]any) {
				root["calls"] = []any{creationFrame(addressA, createdAddress), child(kind, addressA, addressB, "0x")}
			}
			intentCheck(t, f, n, func(engine *nativeadmission.Engine, _ *runtimepolicy.Factory, view *runtimepolicy.View, execution *rpcexecution.CallExecution, wallets nativeadmission.WalletSnapshot) {
				approval, err := engine.CheckSignedWithCreationPlan(t.Context(), view, orgA, execution, wallets)
				if err == nil || approval != nil {
					t.Fatal("earlier permitted creation escaped later native denial")
				}
			})
		})
	}
}

func TestCreationIntentCaptureLimitsAndOneFactoryRootSet(t *testing.T) {
	for _, count := range []int{0, 9, 128, 129} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			f := creationIntentRuntimeFixture()
			n := &node{pre: map[string]any{}}
			calls := []any{}
			for i := 0; i < count; i++ {
				address := fmt.Sprintf("0x%040x", 4096+i)
				calls = append(calls, creationFrame(addressA, address))
				n.pre[address] = map[string]any{}
			}
			n.mutate = func(root map[string]any) { root["calls"] = calls }
			intentCheck(t, f, n, func(engine *nativeadmission.Engine, _ *runtimepolicy.Factory, view *runtimepolicy.View, execution *rpcexecution.CallExecution, wallets nativeadmission.WalletSnapshot) {
				a, err := engine.CheckSignedWithCreationPlan(t.Context(), view, orgA, execution, wallets)
				if count > nativeadmission.MaxCreationEntries {
					if err == nil || a != nil {
						t.Fatal("overlimit exposed approval")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if count == 0 {
					if a.Plan() != nil {
						t.Fatal("no-create manufactured work")
					}
					return
				}
				d := a.Plan().Data()
				if _, err := admission.DecodeCreationPlan(a.Plan().Encoded(), admission.Digest(a.Plan().Digest())); err != nil {
					t.Fatal("bounded plan restore", err)
				}
				if len(d.Entries) != count || len(d.FactoryRoots) != count || len(d.Declarations) != 1 || len(a.Plan().Encoded()) > nativeadmission.MaxCreationPlanBytes {
					t.Fatal("wrong whole factory root set", len(d.Entries), len(d.FactoryRoots))
				}
			})
		})
	}
}
