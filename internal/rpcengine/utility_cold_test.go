package rpcengine

import (
	"net/http"
	df "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcexecution"
	"slices"
	"testing"
)

func TestUtilityColdAliasOnlyCredentialBinding(t *testing.T) {
	const reference = "OPS_RPC_CREDENTIAL_11111111111111111111111111111111_UTILITY"
	fixture := df.DefaultStateFixture(t)
	for _, method := range []string{"eth_estimateGas", "bank_estimate"} {
		if !slices.Contains(fixture.Methods.Assignable, method) {
			fixture.Methods.Assignable = append(fixture.Methods.Assignable, method)
		}
	}
	fixture.Methods.Aliases["bank_estimate"] = "eth_estimateGas"
	for org, groups := range fixture.Groups {
		for i := range groups {
			groups[i].AllowedMethods = []string{"eth_call"}
			if org == df.Org && groups[i].ID == df.AuditorGroup {
				groups[i].AllowedMethods = []string{"bank_estimate"}
				groups[i].RpcCredential = &policybundle.SecretRef{FromEnv: reference}
			}
		}
		fixture.Groups[org] = groups
	}
	snapshot := df.StateSnapshot(t, fixture)
	for _, bound := range []bool{false, true} {
		clients := map[string]*rpcexecution.Client{}
		for _, org := range snapshot.Organizations() {
			credentials := map[string]rpcexecution.Credential{}
			if bound {
				credentials[reference] = rpcexecution.Credential{Header: "Idempotency-Key", Value: "utility-only"}
			}
			client, err := rpcexecution.NewClient(http.DefaultTransport, rpcexecution.NodeBinding{OrganizationID: org.ID, URL: "http://127.0.0.1:1", ChainID: "1", Profile: rpcexecution.SimulationCallProfileID, PragueStartInclusive: 1, PragueEndExclusive: 100, AllowUnauthenticated: true, Credentials: credentials}, rpcexecution.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			clients[org.ID] = client
		}
		engine := &Engine{snapshot: snapshot, current: &nativeAddressSource{}, raw: &rawEngine{readProfile: "strict"}, clients: clients}
		if err := engine.initExecutionUtilities(ExecutionUtilityOptions{}); (err == nil) != bound {
			t.Fatal("utility-only credential was skipped or replaced with anonymous fallback", bound, err)
		}
	}
}
