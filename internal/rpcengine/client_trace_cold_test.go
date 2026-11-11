package rpcengine

import (
	"net/http"
	df "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcexecution"
	"testing"
)

func TestClientTraceColdTraceOnlyCredentialMap(t *testing.T) {
	const ref = "OPS_RPC_CREDENTIAL_11111111111111111111111111111111_TRACE"
	f := df.DefaultStateFixture(t)
	f.Methods.Assignable = append(f.Methods.Assignable, "bank_trace")
	f.Methods.Aliases["bank_trace"] = "debug_traceCall"
	for org, groups := range f.Groups {
		for i := range groups {
			groups[i].AllowedMethods = []string{"eth_call"}
			if org == df.Org && groups[i].ID == df.AuditorGroup {
				groups[i].AllowedMethods = []string{"bank_trace"}
				groups[i].RpcCredential = &policybundle.SecretRef{FromEnv: ref}
			}
		}
		f.Groups[org] = groups
	}
	snapshot := df.StateSnapshot(t, f)
	for _, bound := range []bool{false, true} {
		clients := map[string]*rpcexecution.Client{}
		for _, o := range snapshot.Organizations() {
			credentials := map[string]rpcexecution.Credential{}
			if bound {
				credentials[ref] = rpcexecution.Credential{Header: "X-Test", Value: "only-fixture"}
			}
			c, err := rpcexecution.NewClient(http.DefaultTransport, rpcexecution.NodeBinding{OrganizationID: o.ID, URL: "http://127.0.0.1:1", ChainID: "1", Profile: rpcexecution.SimulationCallProfileID, PragueStartInclusive: 1, PragueEndExclusive: 100, AllowUnauthenticated: true, Credentials: credentials}, rpcexecution.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			clients[o.ID] = c
		}
		e := &Engine{snapshot: snapshot, current: &nativeAddressSource{}, clients: clients}
		if err := e.initClientTrace(); (err == nil) != bound {
			t.Fatal("trace-only credential was skipped or lost", bound, err)
		}
	}
}

func TestClientTraceColdBoundsAreLowerOnly(t *testing.T) {
	d := rpcexecution.DefaultLimits()
	if !clientTraceLimits(d) {
		t.Fatal("default rejected")
	}
	d.MaxMuxBytes++
	if clientTraceLimits(d) {
		t.Fatal("trace allowed larger mux bound")
	}
	d = rpcexecution.DefaultLimits()
	d.Trace.MaxRawBytes++
	if clientTraceLimits(d) {
		t.Fatal("trace allowed larger child bound")
	}
	d = rpcexecution.DefaultLimits()
	d.AcquisitionTimeout++
	if clientTraceLimits(d) {
		t.Fatal("trace allowed renewed acquisition bound")
	}
}
