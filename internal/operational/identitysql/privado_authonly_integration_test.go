package identitysql_test

import (
	"encoding/json"
	"os"
	"testing"

	"privacy-proxy/internal/brokerpolicy"
	f "privacy-proxy/internal/brokertest"
	d "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/identity"
	b "privacy-proxy/internal/identitybroker"
	"privacy-proxy/internal/identityhttp"
)

// Actual AuthV2 crypto, controlled state ABI, native HTTP, SQL commit and Core
// token verification. No hosted issuer or physical wallet UI is implied.
func TestActualPrivadoWalletAuthOnlySession(t *testing.T) {
	if os.Getenv("OPS_PRIVADO_WALLET_INTEGRATION") != "1" {
		t.Skip("explicit actual SDK/prover integration required")
	}
	wallet := startWalletProcess(t)
	rpc := newWalletRPC(t, wallet)
	x := newMultiHTTPFixture(t, func(x *multiHTTPFixture) {
		configureWalletFixture(t, x, wallet, rpc)
		ids, _ := x.db.snapshot.Identity()
		source := ids.Source()
		catalog, _ := x.db.snapshot.AuthBroker()
		broker, _ := catalog.MultiSource()
		broker.PrivadoProfiles = []brokerpolicy.PrivadoBinding{{ProfileID: f.PrivadoProfile}}
		broker.PinnedDocuments = []brokerpolicy.PinnedDocumentRef{}
		for i := range source.Profiles {
			if source.Profiles[i].ID == f.PrivadoProfile {
				source.Profiles[i].VerifierID = wallet.ready.VerifierDID
				source.Profiles[i].Network = wallet.ready.Network
				source.Profiles[i].IdentityStateContract = wallet.ready.StateContract
			}
		}
		x.db.snapshot = f.MultiSnapshotSources(t, source, broker, map[string][]byte{})
	})
	catalog, _ := x.db.snapshot.Identity()
	verifier, err := identity.NewVerifier(catalog, x.db.clock)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(result identityhttp.AccessDTO) {
		t.Helper()
		claims := accessClaims(t, result)
		principal, err := verifier.VerifyAccess(result.AccessToken)
		if err != nil || principal.ActorID() != result.ActorID || len(principal.Groups(d.Org)) != 0 || claims.SourceNotAfter != nil || len(claims.Facts) != 0 || claims.Expires > claims.ClaimsAsOf+300 {
			t.Fatal("auth-only access was rejected, granted roles, or extended freshness", err)
		}
	}
	status, _, raw := x.request(t, x.client, "POST", identityhttp.Prefix+"privado/start", map[string]string{"profileId": f.PrivadoProfile}, nil)
	var start privadoStartDTO
	if status != 200 || json.Unmarshal(raw, &start) != nil {
		t.Fatal("auth-only start", status)
	}
	proof := x.walletProof(t, wallet, start, "a", "")
	status, _, raw = x.postWalletProof(t, start.RequestID, proof)
	if status != 200 || len(raw) != 0 {
		t.Fatal("actual auth-only proof", status)
	}
	first := x.confirm(t, x.candidate(t, start.RequestID), nil)
	verify(first)
	status, _, raw = x.request(t, x.client, "POST", identityhttp.Prefix+"renew", renewal(first), nil)
	var pending b.ProofRequired
	if status != 200 || json.Unmarshal(raw, &pending) != nil || pending.Status != "proof_required" || pending.BrowserSessionID != first.BrowserSessionID {
		t.Fatal("auth-only renewal", status)
	}
	fresh := privadoStartDTO{RequestID: pending.RequestID, RequestURI: pending.RequestURI, ExpiresAt: pending.ExpiresAt, SourceProfile: pending.SourceProfile}
	freshProof := x.walletProof(t, wallet, fresh, "a", "")
	status, _, raw = x.postWalletProof(t, fresh.RequestID, freshProof)
	if status != 200 || len(raw) != 0 {
		t.Fatal("fresh auth-only renewal proof", status)
	}
	second := x.confirm(t, x.candidate(t, fresh.RequestID), &first.BrowserSessionID)
	verify(second)
	family, err := x.db.one.ReadPrivadoFamily(t.Context(), x.db.scope, first.BrowserSessionID)
	if err != nil || family.Generation != 1 || second.ActorID != first.ActorID || familyCount(t, x) != 1 {
		t.Fatal("auth-only family continuity", err)
	}
}
