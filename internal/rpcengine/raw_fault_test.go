package rpcengine_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"google.golang.org/grpc"
	"privacy-proxy/internal/admission"
	"privacy-proxy/internal/nodeapproval"
	"privacy-proxy/internal/nodeapproval/approvalpb"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/walletadapter"
	"privacy-proxy/internal/walletops"
)

// These unit faults cannot mint a committed receipt. The required successful
// send/order qualification uses the real PostgreSQL service separately.
type unavailableAdmission struct {
	admission.Store
	calls atomic.Int64
}

func (s *unavailableAdmission) WithRawTransaction(context.Context, admission.Scope, func(admission.RawTx) (admission.CommitKind, error)) (admission.CommitReceipt, error) {
	s.calls.Add(1)
	return admission.CommitReceipt{}, admission.ErrUnavailable
}

type boundedWalletFacts struct {
	walletops.Store
	calls     atomic.Int64
	fail      bool
	addresses []common.Address
}

func (s *boundedWalletFacts) LoadActive(_ context.Context, ns walletops.Namespace, _ walletops.ExpectedState, actor string, _ int) ([]walletops.OwnershipFact, error) {
	s.calls.Add(1)
	if s.fail {
		return nil, walletops.ErrUnavailable
	}
	out := []walletops.OwnershipFact{}
	for _, address := range s.addresses {
		out = append(out, walletops.OwnershipFact{Namespace: ns, Actor: actor, Address: address, ProofVersion: 2, VerifiedAt: time.Unix(now, 0)})
	}
	return out, nil
}

type rawFaultFixture struct {
	engine   *rpcengine.Engine
	token    string
	node     *node
	store    *unavailableAdmission
	wallet   *boundedWalletFacts
	clock    *atomic.Int64
	options  rpcengine.RawOptions
	snapshot *policybundle.CatalogSnapshot
}

func rawFaultSetup(t *testing.T, f fixture, wallet *boundedWalletFacts, tweaks ...func(*rpcengine.RawOptions)) *rawFaultFixture {
	t.Helper()
	if f.rawMode == "" {
		f.rawMode = policybundle.RawSubmissionOPSPreflight
	}
	evidenceProfile := rpcexecution.SignedCallProfileID
	if f.rawMode == policybundle.RawSubmissionGuardV1 {
		evidenceProfile = rpcexecution.GuardRetainedProfileID
	}
	snapshot := f.load(t)
	x := &rawFaultFixture{node: &node{}, store: &unavailableAdmission{}, wallet: wallet, clock: &atomic.Int64{}, snapshot: snapshot}
	x.clock.Store(now)
	server := httptest.NewServer(x.node)
	t.Cleanup(server.Close)
	clock := func() time.Time { return time.Unix(x.clock.Load(), 0) }
	wb := walletops.ServiceBinding{ServiceOrigin: "https://ops.test", Environment: "test", ChainID: "1", GenesisHash: nodeHash, DeploymentID: "raw-fault"}
	ns, err := wb.Namespace()
	if err != nil {
		t.Fatal(err)
	}
	state := walletops.ExpectedState{Generation: orgA}
	resolver, err := walletadapter.New(wallet, ns, state, clock)
	if err != nil {
		t.Fatal(err)
	}
	financial, err := admission.New(admission.Config{Snapshot: snapshot, Clock: clock, NetworkBinding: admission.NetworkBinding{Environment: wb.Environment, ChainID: wb.ChainID, GenesisHash: wb.GenesisHash, DeploymentID: wb.DeploymentID}, ExpectedState: admission.ExpectedState{Generation: orgA}, Store: x.store, ExpectedEvidenceProfile: evidenceProfile})
	if err != nil {
		t.Fatal(err)
	}
	callClients := map[string]*rpcexecution.Client{}
	for _, org := range []string{orgA, orgB} {
		refs := map[string]rpcexecution.Credential{}
		if org == orgA {
			for _, g := range f.groups {
				if g.RpcCredential != nil {
					refs[g.RpcCredential.FromEnv] = rpcexecution.Credential{Header: "X-Key", Value: g.RpcCredential.FromEnv}
				}
			}
		}
		c, err := rpcexecution.NewClient(server.Client().Transport, rpcexecution.NodeBinding{OrganizationID: org, URL: server.URL, ChainID: "1", Profile: rpcexecution.NodeProfileID, PragueStartInclusive: 10, PragueEndExclusive: 20, AllowUnauthenticated: true, Credentials: refs}, rpcexecution.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		callClients[org] = c
	}
	needed := false
	credentials := map[string]rpcexecution.Credential{}
	for _, g := range f.groups {
		for _, m := range g.AllowedMethods {
			if m == "eth_sendTransaction" {
				needed = true
				if g.RpcCredential != nil {
					credentials[g.RpcCredential.FromEnv] = rpcexecution.Credential{Header: "X-Key", Value: g.RpcCredential.FromEnv}
				}
			}
		}
	}
	rawNodes := map[string]rpcengine.RawNodeOptions{}
	if needed {
		rawNodes[orgA] = rpcengine.RawNodeOptions{Binding: rpcexecution.NodeBinding{OrganizationID: orgA, URL: server.URL, ChainID: "1", Profile: evidenceProfile, PragueStartInclusive: 10, PragueEndExclusive: 20, AllowUnauthenticated: true, Credentials: credentials}, Transport: server.Client().Transport, Limits: rpcexecution.DefaultLimits()}
	}
	x.options = rpcengine.RawOptions{CallClients: callClients, RawNodes: rawNodes, Wallets: resolver, WalletBinding: wb, WalletState: state, Admission: financial, Clock: clock}
	for _, tweak := range tweaks {
		tweak(&x.options)
	}
	x.engine, err = rpcengine.NewRaw(snapshot, x.options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(x.engine.Close)
	x.token = token(t, snapshot, f.roles)
	return x
}

type faultProducer struct {
	approvalpb.UnimplementedApprovalDeliveryServer
	deliveries atomic.Int64
	approvals  atomic.Int64
	batches    chan []byte
}

func (p *faultProducer) Status(context.Context, *approvalpb.StatusRequest) (*approvalpb.StatusResponse, error) {
	return &approvalpb.StatusResponse{BootId: "fault-boot", ChainId: 1, TrustedKeyIds: []string{"pair-key"}, MaxTtlMs: uint64(time.Hour.Milliseconds()), Capacity: 10000, WaitMs: 5000}, nil
}
func (p *faultProducer) Deliver(_ context.Context, req *approvalpb.DeliverRequest) (*approvalpb.DeliverResponse, error) {
	p.deliveries.Add(1)
	count := uint32(1)
	offset := len("OPS_APPROVAL_BATCH_V2\x00")
	if len(req.Batch) > offset {
		offset += 1 + int(req.Batch[offset]) + 16
		if len(req.Batch) >= offset+4 {
			count = binary.BigEndian.Uint32(req.Batch[offset:])
		}
	}
	p.approvals.Add(int64(count))
	if p.batches != nil {
		select {
		case p.batches <- bytes.Clone(req.Batch):
		default:
		}
	}
	return &approvalpb.DeliverResponse{BootId: "fault-boot", Stored: count}, nil
}

func TestGuardRawHTTPFinancialFailureNeverEnqueuesOrBroadcasts(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	producer := &faultProducer{}
	grpcServer := grpc.NewServer()
	approvalpb.RegisterApprovalDeliveryServer(grpcServer, producer)
	go grpcServer.Serve(listener)
	defer grpcServer.Stop()
	f := newFixture()
	f.rawMode = policybundle.RawSubmissionGuardV1
	f.groups[0].AllowedMethods = []string{"eth_sendTransaction"}
	x := rawFaultSetup(t, f, &boundedWalletFacts{}, func(o *rpcengine.RawOptions) {
		n := o.RawNodes[orgA]
		n.HashMode = nodeapproval.HashCalls
		n.Seed = bytes.Repeat([]byte{7}, 32)
		n.KeyID = "pair-key"
		n.MaxBatch = 32
		n.Delivery = nodeapproval.DeliveryOptions{Targets: []string{listener.Addr().String()}, Timeout: time.Second, MaxInFlight: 1, RetainMax: 32}
		o.RawNodes[orgA] = n
	})
	body := rawFaultBody(t, nil)
	deadline := time.Now().Add(3 * time.Second)
	for {
		out := submitFaultHTTP(t, x, body)
		if out.Error == nil || out.Error.Code != -32002 {
			t.Fatal("financial fault not sanitized", out)
		}
		methods, _ := x.node.counts()
		if x.store.calls.Load() == 1 {
			break
		}
		if len(methods) != 0 || time.Now().After(deadline) {
			t.Fatal("Guard qualification never reached financial boundary", methods, out)
		}
		// Only a known zero-node/zero-financial readiness refusal is retried by
		// this test client. No possibly accepted submission is retried.
		time.Sleep(2 * time.Millisecond)
	}
	x.engine.Close()
	methods, _ := x.node.counts()
	for _, method := range methods {
		if method == "eth_sendRawTransaction" {
			t.Fatal("broadcast before financial commit")
		}
	}
	if producer.deliveries.Load() != 0 {
		t.Fatal("approval queued before financial commit")
	}
}

func submitFaultHTTP(t *testing.T, x *rawFaultFixture, raw []byte) rpcengine.Response {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/rpc", strings.NewReader(string(raw)))
	r.Header.Set("Authorization", "Bearer "+x.token)
	w := httptest.NewRecorder()
	x.engine.Handler(orgA).ServeHTTP(w, r)
	var out rpcengine.Response
	if json.Unmarshal(w.Body.Bytes(), &out) != nil {
		t.Fatal(w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("missing cache policy")
	}
	return out
}
func rawFaultBody(t *testing.T, extra map[string]any) []byte {
	tx := rawTransaction(t, []byte{1, 2})
	m := map[string]any{"jsonrpc": "2.0", "id": "raw", "method": "eth_sendRawTransaction", "params": []any{tx.RawHex()}}
	for k, v := range extra {
		m[k] = v
	}
	return encoded(t, m)
}

func TestActualRawHTTPMethodNativeAndWalletFaultsNeverPublish(t *testing.T) {
	for _, scenario := range []string{"send-only", "raw-only", "no-native-admin", "conflicting-credentials", "wallet-unavailable", "expired-after-trace", "denied-child", "root-revert"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture()
			f.groups[0].AllowedMethods = []string{"eth_sendTransaction"}
			wallet := &boundedWalletFacts{}
			switch scenario {
			case "raw-only":
				f.groups[0].AllowedMethods = []string{"eth_sendRawTransaction"}
			case "no-native-admin":
				f.groups[0].IsOrgAdmin = true
				f.bindings[0].Allow = []policycore.FrameRule{}
			case "conflicting-credentials":
				f.groups[0].RpcCredential = &policybundle.SecretRef{FromEnv: "OPS_RPC_CREDENTIAL_11111111111111111111111111111111_RAW_ONE"}
				f.groups = append(f.groups, policybundle.Group{ID: second, Slug: "second", Name: "Second", AllowedMethods: []string{"eth_sendTransaction"}, Claims: []string{}, RpcCredential: &policybundle.SecretRef{FromEnv: "OPS_RPC_CREDENTIAL_11111111111111111111111111111111_RAW_TWO"}})
				f.bindings = append(f.bindings, policycore.Binding{Group: second, Allow: []policycore.FrameRule{}})
				f.roles = append(f.roles, second)
				f.capability(policybundle.CapabilityRPCCredential)
			case "wallet-unavailable":
				wallet.fail = true
			}
			x := rawFaultSetup(t, f, wallet)
			switch scenario {
			case "expired-after-trace":
				x.node.onTrace = func() { x.clock.Store(now + 300) }
			case "denied-child":
				x.node.mutate = func(root map[string]any) {
					root["calls"] = []any{map[string]any{"type": "CALL", "from": addressA, "to": addressC, "input": "0x", "value": "0x0", "gas": "0x100", "gasUsed": "0x1", "output": "0x", "error": "execution reverted"}}
				}
			case "root-revert":
				x.node.mutate = func(root map[string]any) { root["error"] = "execution reverted"; root["output"] = "0xdeadbeef" }
			}
			out := submitFaultHTTP(t, x, rawFaultBody(t, nil))
			if out.Error == nil || out.Result != nil {
				t.Fatal("fault published", out)
			}
			financial := scenario == "send-only" || scenario == "root-revert"
			if (x.store.calls.Load() == 1) != financial {
				t.Fatal("wrong gate reached financial service", x.store.calls.Load(), out)
			}
			want := -32001
			if financial || scenario == "wallet-unavailable" {
				want = -32002
			}
			if out.Error.Code != want {
				t.Fatal("wrong sanitized class", out)
			}
			methods, _ := x.node.counts()
			for _, method := range methods {
				if method == "eth_sendRawTransaction" {
					t.Fatal("broadcast despite failed financial/native gate")
				}
			}
			if scenario == "raw-only" || scenario == "conflicting-credentials" || scenario == "wallet-unavailable" {
				if len(methods) != 0 {
					t.Fatal("early denial reached node", methods)
				}
			}
			raw, _ := json.Marshal(out)
			if strings.Contains(string(raw), "deadbeef") || strings.Contains(string(raw), "feed") {
				t.Fatal("trace output leaked")
			}
		})
	}
}

func TestActualStrictRawHTTPRejectsAnyMetadataBeforeWalletNodeSQL(t *testing.T) {
	f := newFixture()
	f.groups[0].AllowedMethods = []string{"eth_sendTransaction"}
	f.runtime.ReadProfile = "strict"
	x := rawFaultSetup(t, f, &boundedWalletFacts{})
	for _, value := range []any{nil, []string{}, []string{"invalid"}} {
		out := submitFaultHTTP(t, x, rawFaultBody(t, map[string]any{"visibleTo": value}))
		if out.Error == nil || out.Error.Code != -32602 {
			t.Fatal(out)
		}
	}
	methods, _ := x.node.counts()
	if x.wallet.calls.Load() != 0 || x.store.calls.Load() != 0 || len(methods) != 0 {
		t.Fatal("strict presence progressed")
	}
}

func TestRawHTTPMalformedSignedInputAndClosedEngineStayBeforeEffects(t *testing.T) {
	f := newFixture()
	f.groups[0].AllowedMethods = []string{"eth_sendTransaction"}
	x := rawFaultSetup(t, f, &boundedWalletFacts{})
	for _, raw := range []string{"0x03c0", "0x04c0", "0x" + strings.Repeat("00", (512<<10)+1), "0xnothex"} {
		body := encoded(t, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "eth_sendRawTransaction", "params": []any{raw}})
		out := submitFaultHTTP(t, x, body)
		if out.Error == nil || out.Error.Code != -32602 {
			t.Fatal("unsupported/oversized input reached admission", out)
		}
	}
	x.engine.Close()
	out := submitFaultHTTP(t, x, rawFaultBody(t, nil))
	if out.Error == nil || out.Error.Code != -32002 {
		t.Fatal("closed engine admitted a new request", out)
	}
	methods, _ := x.node.counts()
	if len(methods) != 0 || x.wallet.calls.Load() != 0 || x.store.calls.Load() != 0 {
		t.Fatal("input/closed gate performed work")
	}
}

func TestRawConstructorBindsNetworkManifestAndCallCredentialsSeparately(t *testing.T) {
	f := newFixture()
	f.groups[0].AllowedMethods = []string{"eth_sendTransaction"}
	f.groups[0].RpcCredential = &policybundle.SecretRef{FromEnv: "OPS_RPC_CREDENTIAL_11111111111111111111111111111111_SEND_ONLY"}
	f.groups = append(f.groups, policybundle.Group{ID: second, Slug: "call", Name: "Call", AllowedMethods: []string{"eth_call"}, Claims: []string{}, RpcCredential: &policybundle.SecretRef{FromEnv: "OPS_RPC_CREDENTIAL_11111111111111111111111111111111_CALL_ONLY"}})
	f.bindings = append(f.bindings, policycore.Binding{Group: second, Allow: []policycore.FrameRule{{StorageAddress: addressA, Selector: "*"}}})
	f.roles = append(f.roles, second)
	f.capability(policybundle.CapabilityRPCCredential)
	x := rawFaultSetup(t, f, &boundedWalletFacts{})
	// Rebuild a call binding with ONLY its used ref; the send ref is not a
	// call requirement merely because another source group has it.
	n := x.options.RawNodes[orgA]
	n.Binding.Profile = rpcexecution.NodeProfileID
	n.Binding.Credentials = map[string]rpcexecution.Credential{"OPS_RPC_CREDENTIAL_11111111111111111111111111111111_CALL_ONLY": {Header: "X-Key", Value: "call"}}
	call, err := rpcexecution.NewClient(n.Transport, n.Binding, n.Limits)
	if err != nil {
		t.Fatal(err)
	}
	x.options.CallClients[orgA] = call
	e, err := rpcengine.NewRaw(x.snapshot, x.options)
	if err != nil {
		t.Fatal("send credential leaked into call startup", err)
	}
	e.Close()
	for _, change := range []func(*rpcengine.RawOptions){func(o *rpcengine.RawOptions) { o.WalletBinding.DeploymentID = "wrong" }, func(o *rpcengine.RawOptions) { o.WalletState.Generation = orgB }, func(o *rpcengine.RawOptions) {
		node := o.RawNodes[orgA]
		node.Binding.Profile = rpcexecution.NodeProfileID
		o.RawNodes = map[string]rpcengine.RawNodeOptions{orgA: node}
	}, func(o *rpcengine.RawOptions) { o.RawNodes = map[string]rpcengine.RawNodeOptions{} }, func(o *rpcengine.RawOptions) {
		node := o.RawNodes[orgA]
		node.Binding.Credentials = map[string]rpcexecution.Credential{}
		o.RawNodes = map[string]rpcengine.RawNodeOptions{orgA: node}
	}} {
		o := x.options
		change(&o)
		if e, err := rpcengine.NewRaw(x.snapshot, o); err == nil {
			e.Close()
			t.Fatal("inconsistent trusted binding accepted")
		}
	}
	wrongFork := x.options
	node := wrongFork.RawNodes[orgA]
	node.Binding.PragueEndExclusive++
	wrongFork.RawNodes = map[string]rpcengine.RawNodeOptions{orgA: node}
	if engine, err := rpcengine.NewRaw(x.snapshot, wrongFork); err == nil {
		engine.Close()
		t.Fatal("call and raw use different fork interpretations")
	}
}

func TestSignedRawKeepsStorageOwnerAndSameGroupUpgradeFences(t *testing.T) {
	for _, scenario := range []string{"own-implementation", "foreign-implementation", "foreign-storage-own-code", "foreign-storage-upgrade", "other-group-upgrade", "same-group-upgrade"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture()
			f.groups[0].AllowedMethods = []string{"eth_sendTransaction"}
			var mutate func(map[string]any)
			switch scenario {
			case "own-implementation", "foreign-implementation":
				f.bindings[0].Allow = []policycore.FrameRule{{TargetClass: "org", Selector: "*", CallTypes: []policycore.CallType{policycore.CallTypeCall, policycore.CallTypeDelegateCall}}}
				implementation := addressC
				if scenario == "foreign-implementation" {
					implementation = addressB
				}
				mutate = func(root map[string]any) {
					root["calls"] = []any{child("DELEGATECALL", addressA, implementation, "0x")}
				}
			case "foreign-storage-own-code", "foreign-storage-upgrade":
				minimum := 1
				f.runtime.SharedInfrastructure = []policybundle.SharedInfrastructure{{Address: addressB}}
				f.capability(policybundle.CapabilitySharedCode)
				f.capability(policybundle.CapabilityDepth)
				f.bindings[0].Allow = append(f.bindings[0].Allow, policycore.FrameRule{TargetClass: "shared", Selector: "*", MinDepth: &minimum})
				if scenario == "foreign-storage-own-code" {
					f.bindings[0].Allow = append(f.bindings[0].Allow, policycore.FrameRule{TargetClass: "org", Selector: "*", CallTypes: []policycore.CallType{policycore.CallTypeDelegateCall}})
					mutate = func(root map[string]any) {
						parent := child("CALL", addressA, addressB, "0x")
						parent["calls"] = []any{child("DELEGATECALL", addressB, addressC, "0x")}
						root["calls"] = []any{parent}
					}
				} else {
					f.groups[0].Claims = []string{"upgrade"}
					f.bindings[0].Allow[1].AllowUpgrade = true
					f.capability(policybundle.CapabilityUpgradeFacts)
					mutate = func(root map[string]any) {
						data := "0x3659cfe6" + common.Bytes2Hex(common.LeftPadBytes(common.HexToAddress(addressC).Bytes(), 32))
						root["calls"] = []any{child("CALL", addressA, addressB, data)}
					}
				}
			case "other-group-upgrade", "same-group-upgrade":
				f.groups = append(f.groups, policybundle.Group{ID: second, Slug: "upgrade", Name: "Upgrade", AllowedMethods: []string{}, Claims: []string{"upgrade"}})
				f.roles = append(f.roles, second)
				f.bindings[0].Allow[0].AllowUpgrade = true
				f.capability(policybundle.CapabilityUpgradeFacts)
				if scenario == "same-group-upgrade" {
					f.groups[0].Claims = []string{"upgrade"}
				}
			}
			x := rawFaultSetup(t, f, &boundedWalletFacts{})
			x.node.mutate = mutate
			body := rawFaultBody(t, nil)
			if scenario == "other-group-upgrade" || scenario == "same-group-upgrade" {
				input := append(common.FromHex("0x3659cfe6"), common.LeftPadBytes(common.HexToAddress(addressC).Bytes(), 32)...)
				tx := rawTransaction(t, input)
				body = encoded(t, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "eth_sendRawTransaction", "params": []any{tx.RawHex()}})
			}
			out := submitFaultHTTP(t, x, body)
			nativeAllowed := scenario == "own-implementation" || scenario == "same-group-upgrade"
			if (x.store.calls.Load() == 1) != nativeAllowed {
				t.Fatal("storage/group fence changed", scenario, out, x.store.calls.Load())
			}
			want := -32001
			if nativeAllowed {
				want = -32002
			}
			if out.Error == nil || out.Error.Code != want {
				t.Fatal(out)
			}
		})
	}
}
