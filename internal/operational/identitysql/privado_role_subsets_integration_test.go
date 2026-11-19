package identitysql_test

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	f "privacy-proxy/internal/brokertest"
	d "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/identityhttp"
)

// The same public entry/request template accepts different holders and only
// their actually proved roles. These are real SDK AuthV2/SigV2 proofs, actual
// broker SQL/HTTP completion and normal Core JWT-to-group mapping.
func TestActualPrivadoWalletOptionalRoleSubsets(t *testing.T) {
	if os.Getenv("OPS_PRIVADO_WALLET_INTEGRATION") != "1" {
		t.Skip("set OPS_PRIVADO_WALLET_INTEGRATION=1 for the pinned actual prover")
	}
	t.Setenv("OPS_PRIVADO_WALLET_ROLE_SUBSETS", "1")
	wallet := startWalletProcess(t)
	rpc := newWalletRPC(t, wallet)
	x := newMultiHTTPFixture(t, func(x *multiHTTPFixture) {
		configureWalletFixtureSources(t, x, wallet, rpc, func(ids *identity.SourceCatalog) {
			for i := range ids.Profiles {
				if ids.Profiles[i].ID == f.PrivadoRoleProfile {
					ids.Profiles[i].Predicates = []identity.Predicate{
						{ID: "alpha-unmatched", Field: "role", Operator: "eq", Value: "9", Optional: true},
						{ID: "reader", Field: "role", Operator: "eq", Value: "7", Optional: true},
						{ID: "writer", Field: "role", Operator: "eq", Value: "8", Optional: true},
					}
				}
			}
			ids.Mappings = append(ids.Mappings, identity.Mapping{ID: "privado-writer", ProfileID: f.PrivadoRoleProfile, OrganizationID: d.Org, PrincipalKind: identity.Human, Fact: identity.Fact{Kind: "privado.predicate", Value: "writer"}, GroupIDs: []string{d.AdminGroup}})
		})
	})
	ids, _ := x.db.snapshot.Identity()
	core, err := identity.NewVerifier(ids, x.db.clock)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		holder, did string
		facts       []identity.Fact
		groups      []string
	}{
		{"a", wallet.ready.HolderA, []identity.Fact{{Kind: "privado.predicate", Value: "reader"}}, []string{d.AuditorGroup}},
		{"multi", wallet.ready.HolderMulti, []identity.Fact{{Kind: "privado.predicate", Value: "reader"}, {Kind: "privado.predicate", Value: "writer"}}, []string{d.AuditorGroup, d.AdminGroup}},
		{"zero", wallet.ready.HolderZero, []identity.Fact{}, []string{}},
	} {
		t.Run(tc.holder, func(t *testing.T) {
			start := x.startPrivado(t, nil)
			proof := x.walletProof(t, wallet, start, tc.holder, "")
			if !proof.Diagnostics.BypassProofsCache || !proof.Diagnostics.StateCacheDisabled || proof.Diagnostics.RoleGenerations != len(tc.facts) || proof.Diagnostics.OuterGenerations != 1 {
				t.Fatal("expected fresh, actual subset proofs", proof.Diagnostics)
			}
			status, _, raw := x.postWalletProof(t, start.RequestID, proof)
			if status != 200 || len(raw) != 0 {
				t.Fatal("subset callback failed", status)
			}
			candidate := x.candidate(t, start.RequestID)
			if candidate.HolderDID != tc.did || candidate.SourceProfile != f.PrivadoRoleProfile {
				t.Fatal("common profile/holder changed")
			}
			result := x.confirm(t, candidate, nil)
			claims := accessClaims(t, result)
			if !reflect.DeepEqual(claims.Facts, tc.facts) {
				t.Fatal("granted unproved or lost proved predicate", claims.Facts)
			}
			principal, err := core.VerifyAccess(result.AccessToken)
			if err != nil {
				t.Fatal(err)
			}
			want := append([]string{}, tc.groups...)
			sort.Strings(want)
			got := principal.Groups(d.Org)
			if len(got) != len(want) || len(want) > 0 && !reflect.DeepEqual(got, want) {
				t.Fatal("Core group mapping differs from actual proof subset", got, want)
			}
			if claims.ClaimsAsOf != proof.ClaimsAsOf || claims.Expires > claims.ClaimsAsOf+300 {
				t.Fatal("subset extended original evidence age")
			}
			// Restore across the alternating service pools with the provider unavailable.
			// This must rotate the same family and preserve its original evidence,
			// including a genuinely empty verified role set, without a new proof.
			rpc.fail.Store(true)
			hits := rpc.hits.Load()
			status, headers, raw := x.request(t, x.client, "POST", identityhttp.Prefix+"renew", map[string]string{"mode": "bootstrap"}, nil)
			rpc.fail.Store(false)
			var restored identityhttp.AccessDTO
			if status != 200 || len(headers.Values("Set-Cookie")) != 2 || json.Unmarshal(raw, &restored) != nil || restored.BrowserSessionID != result.BrowserSessionID || restored.ActorID != result.ActorID || restored.AccessToken == result.AccessToken || rpc.hits.Load() != hits {
				t.Fatal("still-fresh session did not restore without a provider proof", status, string(raw))
			}
			restoredClaims := accessClaims(t, restored)
			if restoredClaims.ClaimsAsOf != claims.ClaimsAsOf || restoredClaims.SourceVerifiedAt != claims.SourceVerifiedAt || restoredClaims.Expires != claims.Expires || !reflect.DeepEqual(restoredClaims.Facts, claims.Facts) {
				t.Fatal("restoration extended or replaced verified evidence")
			}
			restoredPrincipal, err := core.VerifyAccess(restored.AccessToken)
			if err != nil || !reflect.DeepEqual(restoredPrincipal.Groups(d.Org), principal.Groups(d.Org)) {
				t.Fatal("restored token changed Core group mapping", err)
			}
		})
	}
	t.Run("invalid supplied optional proof is not silently skipped", func(t *testing.T) {
		start := x.startPrivado(t, nil)
		status, _, raw := x.request(t, x.client, "GET", identityhttp.Prefix+"privado/requests/"+start.RequestID, nil, nil)
		if status != 200 {
			t.Fatal("original request unavailable", status)
		}
		var changed map[string]any
		if json.Unmarshal(raw, &changed) != nil {
			t.Fatal("request JSON")
		}
		scope := changed["body"].(map[string]any)["scope"].([]any)
		scope[1].(map[string]any)["query"].(map[string]any)["credentialSubject"].(map[string]any)["role"].(map[string]any)["$eq"] = 8
		altered, err := json.Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
		defer cancel()
		proof, err := wallet.prove(ctx, altered, "multi", "")
		if err != nil {
			t.Fatal(err)
		}
		// The wallet generated genuine cryptography, but one supplied predicate
		// answers a different question. Optional does not mean ignore bad proofs.
		before := familyCount(t, x)
		status, _, raw = x.postWalletProof(t, start.RequestID, proof)
		if status != 401 {
			t.Fatal("invalid supplied optional proof was not rejected", status)
		}
		status, _, raw = x.request(t, x.client, "POST", identityhttp.Prefix+"privado/preview", map[string]string{"requestId": start.RequestID}, nil)
		var preview struct{ Status string }
		if status != 200 || json.Unmarshal(raw, &preview) != nil || preview.Status != "waiting" || familyCount(t, x) != before {
			t.Fatal("unproved optional fact offered a candidate or issued a family", status, preview.Status)
		}
	})

}
