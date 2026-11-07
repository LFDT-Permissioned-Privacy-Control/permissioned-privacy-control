package rpcengine_test

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
)

func TestHTTPCredentialConflictsDenyBeforeAnyNodeWork(t *testing.T) {
	const one = "OPS_RPC_CREDENTIAL_11111111111111111111111111111111_ONE"
	const two = "OPS_RPC_CREDENTIAL_11111111111111111111111111111111_TWO"
	f := newFixture()
	f.groups[0].RpcCredential = &policybundle.SecretRef{FromEnv: one}
	f.groups = append(f.groups, policybundle.Group{ID: second, Slug: "second", Name: "Second", AllowedMethods: []string{"eth_call"}, Claims: []string{}, RpcCredential: &policybundle.SecretRef{FromEnv: two}})
	f.roles = append(f.roles, second)
	f.capability(policybundle.CapabilityRPCCredential)
	n := &node{}
	var clock atomic.Int64
	e, tok, _ := engine(t, f, n, nil, &clock)
	response, _ := request(t, e, tok, orgA, map[string]any{"to": addressA}, nil)
	methods, _ := n.counts()
	if response.Error == nil || len(methods) != 0 {
		t.Fatal("ambiguous credential selected a fallback", response, methods)
	}
}

func TestNativeAdmissionRejectsAnUnrelatedCapturedPolicyView(t *testing.T) {
	f := newFixture()
	a := f.load(t)
	f.runtime.ReadProfile = "strict"
	b := f.load(t)
	clock := func() time.Time { return time.Unix(now, 0) }
	admission, err := nativeadmission.New(a, clock)
	if err != nil {
		t.Fatal(err)
	}
	factory, err := runtimepolicy.NewFactory(b, clock)
	if err != nil {
		t.Fatal(err)
	}
	view, err := factory.Build(token(t, b, f.roles))
	if err != nil {
		t.Fatal(err)
	}
	n := &node{}
	server := httptest.NewServer(n)
	defer server.Close()
	client, err := rpcexecution.NewClient(http.DefaultTransport, rpcexecution.NodeBinding{OrganizationID: orgA, URL: server.URL, ChainID: "1", Profile: rpcexecution.NodeProfileID, PragueStartInclusive: 10, PragueEndExclusive: 20, AllowUnauthenticated: true}, rpcexecution.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	client, _ = client.WithCredential("")
	call, _ := rpcexecution.NormalizeCall([]byte(`{"to":"` + addressA + `"}`))
	block, _ := rpcexecution.ParseBlockSelector(nil)
	execution, err := client.AcquireCall(t.Context(), call, block)
	if err != nil {
		t.Fatal(err)
	}
	if admission.Check(t.Context(), view, orgA, execution, nativeadmission.WalletSnapshot{}).Allowed {
		t.Fatal("View from another selected bundle was accepted")
	}
	matching, err := nativeadmission.New(b, clock)
	if err != nil {
		t.Fatal(err)
	}
	if !matching.Check(t.Context(), view, orgA, execution, nativeadmission.WalletSnapshot{}).Allowed {
		t.Fatal("matching snapshot unexpectedly denied")
	}
}
