package identitysql_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	d "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/identity"
	b "privacy-proxy/internal/identitybroker"
	"privacy-proxy/internal/identityhttp"
)

type candidateDTO struct {
	Status, RequestID, HolderDID, Network, ActorID, SourceProfile, ProofDigest string
	VerifiedAt, ExpiresAt                                                      int64
}

func TestActualPrivadoWalletStateChange(t *testing.T) {
	if os.Getenv("OPS_PRIVADO_WALLET_INTEGRATION") != "1" {
		t.Skip("set OPS_PRIVADO_WALLET_INTEGRATION=1 for the actual pinned SDK/prover client")
	}
	wallet := startWalletProcess(t)
	rpc := newWalletRPC(t, wallet)
	x := newMultiHTTPFixture(t, func(x *multiHTTPFixture) { configureWalletFixture(t, x, wallet, rpc) })
	start := x.startPrivado(t, nil)
	proof := x.walletProof(t, wallet, start, "a", "")
	status, _, raw := x.postWalletProof(t, start.RequestID, proof)
	if status != 200 || len(raw) != 0 {
		t.Fatal("actual callback before state change", status, string(raw))
	}
	candidate := x.candidate(t, start.RequestID)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if e := wallet.advanceGIST(ctx); e != nil {
		t.Fatal(e)
	}
	status, headers, _ := x.request(t, x.client, "POST", identityhttp.Prefix+"privado/complete", confirmationBody(candidate, nil), nil)
	if status != 401 || len(headers.Values("Set-Cookie")) != 0 || familyCount(t, x) != 0 {
		t.Fatal("saved actual proof bypassed strictlatest GIST secondVerify", status)
	}
	// A new request and actual new AuthV2/SigV2 witness must work against the
	// changed real sparse tree, including its real noninclusion nodeAux.
	fresh := x.startPrivado(t, nil)
	freshProof := x.walletProof(t, wallet, fresh, "a", "")
	if freshProof.Diagnostics.RoleGenerations != 1 || freshProof.Diagnostics.OuterGenerations != 1 || !freshProof.Diagnostics.StateCacheDisabled {
		t.Fatal("new actual witness/current state missing")
	}
	status, _, raw = x.postWalletProof(t, fresh.RequestID, freshProof)
	if status != 200 || len(raw) != 0 {
		t.Fatal("fresh changedGIST proof", status, string(raw))
	}
	result := x.confirm(t, x.candidate(t, fresh.RequestID), nil)
	if result.ActorID != candidate.ActorID || familyCount(t, x) != 1 {
		t.Fatal("new actual proof did not recover the same holder")
	}
	t.Logf("real memoryGIST replacement rejects saved originalproof and new actual AuthV2/SigV2/currenttree succeeds; wire requests=%d", rpc.hits.Load())
}

func (x *multiHTTPFixture) candidate(t *testing.T, id string) candidateDTO {
	t.Helper()
	status, h, raw := x.request(t, x.client, "POST", identityhttp.Prefix+"privado/preview", map[string]string{"requestId": id}, nil)
	var out candidateDTO
	if status != 200 || len(h.Values("Set-Cookie")) != 0 || json.Unmarshal(raw, &out) != nil || out.Status != "candidate" || out.RequestID != id {
		t.Fatal("actual verified candidate", status, string(raw))
	}
	return out
}
func confirmationBody(candidate candidateDTO, session *string) map[string]any {
	out := map[string]any{"requestId": candidate.RequestID, "expectedActorId": candidate.ActorID, "expectedHolderDid": candidate.HolderDID, "proofDigest": candidate.ProofDigest}
	if session != nil {
		out["expectedSessionId"] = *session
	}
	return out
}
func (x *multiHTTPFixture) confirm(t *testing.T, candidate candidateDTO, session *string) identityhttp.AccessDTO {
	t.Helper()
	status, h, raw := x.request(t, x.client, "POST", identityhttp.Prefix+"privado/complete", confirmationBody(candidate, session), nil)
	var out identityhttp.AccessDTO
	if status != 200 || len(h.Values("Set-Cookie")) != 2 || json.Unmarshal(raw, &out) != nil || out.Provider != "privado" || out.ActorID != candidate.ActorID || out.SourceProfile != candidate.SourceProfile || !b.ValidUUID(out.BrowserSessionID) {
		t.Fatal("actual Privado completion", status, string(raw))
	}
	return out
}
func accessClaims(t *testing.T, dto identityhttp.AccessDTO) identity.AccessClaims {
	t.Helper()
	parts := strings.Split(dto.AccessToken, ".")
	if len(parts) != 3 {
		t.Fatal("compact access")
	}
	raw, e := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if e != nil {
		t.Fatal(e)
	}
	var out identity.AccessClaims
	if json.Unmarshal(raw, &out) != nil {
		t.Fatal("access claims")
	}
	return out
}
func familyCount(t *testing.T, x *multiHTTPFixture) int {
	t.Helper()
	var n int
	if e := x.db.owner.QueryRow(t.Context(), `SELECT count(*) FROM ops_identity_v2.renewal_families`).Scan(&n); e != nil {
		t.Fatal(e)
	}
	return n
}
func TestActualPrivadoWalletSession(t *testing.T) {
	if os.Getenv("OPS_PRIVADO_WALLET_INTEGRATION") != "1" {
		t.Skip("set OPS_PRIVADO_WALLET_INTEGRATION=1 for the actual pinned SDK/prover client")
	}
	wallet := startWalletProcess(t)
	rpc := newWalletRPC(t, wallet)
	x := newMultiHTTPFixture(t, func(x *multiHTTPFixture) { configureWalletFixture(t, x, wallet, rpc) })
	start := x.startPrivado(t, nil)
	firstProof := x.walletProof(t, wallet, start, "a", "")
	if !firstProof.Diagnostics.BypassProofsCache || !firstProof.Diagnostics.StateCacheDisabled || firstProof.Diagnostics.RoleGenerations != 1 || firstProof.Diagnostics.OuterGenerations != 1 {
		t.Fatal("actual first witness generation missing")
	}
	reads := x.familyReads.Load()
	status, h, raw := x.postWalletProof(t, start.RequestID, firstProof)
	if status != 200 || len(raw) != 0 || len(h.Values("Set-Cookie")) != 0 || x.familyReads.Load() != reads {
		t.Fatal("public proof ACK escaped boundary", status, string(raw))
	}
	if familyCount(t, x) != 0 {
		t.Fatal("public proof created family")
	}
	// Same real proof is idempotent before consume without extending the saved
	// observation; every attempt still uses the real verifier/current state.
	status, h, raw = x.postWalletProof(t, start.RequestID, firstProof)
	if status != 200 || len(raw) != 0 || len(h.Values("Set-Cookie")) != 0 {
		t.Fatal("duplicate callback ACK", status, string(raw))
	}
	hits := rpc.hits.Load()
	candidate := x.candidate(t, start.RequestID)
	if candidate.HolderDID != wallet.ready.HolderA || rpc.hits.Load() != hits || familyCount(t, x) != 0 {
		t.Fatal("preview must authenticate saved metadata without issuing or fresh verification")
	}
	// Completion rechecks the actual source, not the saved callback flag.
	rpc.fail.Store(true)
	status, h, _ = x.request(t, x.client, "POST", identityhttp.Prefix+"privado/complete", confirmationBody(candidate, nil), nil)
	rpc.fail.Store(false)
	if status != 503 || len(h.Values("Set-Cookie")) != 0 || familyCount(t, x) != 0 {
		t.Fatal("completion accepted unavailable current source", status)
	}
	first := x.confirm(t, candidate, nil)
	claims := accessClaims(t, first)
	if claims.SourceSubject != wallet.ready.HolderA || claims.ClaimsAsOf != firstProof.ClaimsAsOf || claims.SourceNotAfter == nil || claims.Expires > *claims.SourceNotAfter || claims.Expires > claims.ClaimsAsOf+300 {
		t.Fatal("original proof source age changed")
	}
	ids, _ := x.db.snapshot.Identity()
	verifier, e := identity.NewVerifier(ids, x.db.clock)
	if e != nil {
		t.Fatal(e)
	}
	principal, e := verifier.VerifyAccess(first.AccessToken)
	if e != nil || !reflect.DeepEqual(principal.Groups(d.Org), []string{d.AuditorGroup}) {
		t.Fatal("Core did not verify actual configured role mapping", e)
	}
	originalFamily, e := x.db.one.ReadPrivadoFamily(t.Context(), x.db.scope, first.BrowserSessionID)
	if e != nil {
		t.Fatal(e)
	}
	reads = x.familyReads.Load()
	wrong := renewal(first)
	wrong["expectedSessionId"] = "00000000-0000-4000-8000-000000000099"
	status, h, _ = x.request(t, x.client, "POST", identityhttp.Prefix+"renew", wrong, nil)
	if status != 409 || len(h.Values("Set-Cookie")) != 0 || x.familyReads.Load() != reads {
		t.Fatal("wrong expected pair reached family", status)
	}
	status, h, raw = x.request(t, x.client, "POST", identityhttp.Prefix+"renew", renewal(first), nil)
	var pending b.ProofRequired
	if status != 200 || len(h.Values("Set-Cookie")) != 0 || json.Unmarshal(raw, &pending) != nil || pending.Status != "proof_required" || pending.ActorID != first.ActorID || pending.BrowserSessionID != first.BrowserSessionID || pending.SourceProfile != first.SourceProfile {
		t.Fatal("samefamily pending renewal", status, string(raw))
	}
	renewStart := privadoStartDTO{RequestID: pending.RequestID, RequestURI: pending.RequestURI, ExpiresAt: pending.ExpiresAt, SourceProfile: pending.SourceProfile}
	secondProof := x.walletProof(t, wallet, renewStart, "a", "")
	if !secondProof.Diagnostics.HadCache || secondProof.Diagnostics.RoleGenerations != 1 || secondProof.Diagnostics.OuterGenerations != 1 || !secondProof.Diagnostics.BypassProofsCache || reflect.DeepEqual(secondProof.Diagnostics.InnerProofDigests, firstProof.Diagnostics.InnerProofDigests) {
		t.Fatal("subsequent client reused inner proof")
	}
	status, h, raw = x.postWalletProof(t, pending.RequestID, secondProof)
	if status != 200 || len(raw) != 0 || len(h.Values("Set-Cookie")) != 0 {
		t.Fatal("fresh renewal ACK", status, string(raw))
	}
	renewCandidate := x.candidate(t, pending.RequestID)
	second := x.confirm(t, renewCandidate, &first.BrowserSessionID)
	if second.BrowserSessionID != first.BrowserSessionID || second.ActorID != first.ActorID {
		t.Fatal("renewal replaced family")
	}
	current, e := x.db.one.ReadPrivadoFamily(t.Context(), x.db.scope, first.BrowserSessionID)
	if e != nil || current.Generation != 1 || current.RevokedAt != nil || current.RequestID != originalFamily.RequestID || !current.AbsoluteExpiresAt.Equal(originalFamily.AbsoluteExpiresAt) {
		t.Fatal("family continuity/absolute cutoff changed", e)
	}
	secondClaims := accessClaims(t, second)
	if secondClaims.ClaimsAsOf != secondProof.ClaimsAsOf || secondClaims.Expires > secondClaims.ClaimsAsOf+300 {
		t.Fatal("renewal source age reset")
	}
	status, _, _ = x.postWalletProof(t, pending.RequestID, secondProof)
	if status != 401 {
		t.Fatal("late proof callback unexpectedly accepted", status)
	}
	status, _, _ = x.request(t, x.client, "POST", identityhttp.Prefix+"privado/complete", confirmationBody(renewCandidate, &first.BrowserSessionID), nil)
	if status != 401 {
		t.Fatal("late private completion unexpectedly accepted", status)
	}
	current, e = x.db.one.ReadPrivadoFamily(t.Context(), x.db.scope, first.BrowserSessionID)
	if e != nil || current.RevokedAt != nil {
		t.Fatal("late proof revoked family", e)
	}
	// A second public holder cannot satisfy an explicitly selected login holder.
	selected := x.startPrivado(t, &wallet.ready.HolderA)
	otherProof := x.walletProof(t, wallet, selected, "b", "")
	status, h, _ = x.postWalletProof(t, selected.RequestID, otherProof)
	if status != 401 || len(h.Values("Set-Cookie")) != 0 || familyCount(t, x) != 1 {
		t.Fatal("foreign actual holder crossed expected-holder boundary", status)
	}
	// Intentional actual SDK cache reuse changes ONLY a newly generated outer
	// proof. Advance the test clock, keep the cached SigV2 timestamp untouched,
	// and demonstrate the production challenge/source-age rejection.
	x.db.wallOffset.Store(31)
	cachedStart := x.startPrivado(t, nil)
	cached := x.walletProof(t, wallet, cachedStart, "a", "use")
	status, h, _ = x.postWalletProof(t, cachedStart.RequestID, cached)
	x.db.wallOffset.Store(0)
	if !cached.Diagnostics.HadCache || cached.Diagnostics.RoleGenerations != 0 || cached.Diagnostics.OuterGenerations != 1 || cached.Diagnostics.BypassProofsCache || status != 401 || len(h.Values("Set-Cookie")) != 0 {
		t.Fatal("cached inner role evidence freshened", status)
	}
	status, h, _ = x.request(t, x.client, "POST", identityhttp.Prefix+"logout", expected(second), nil)
	if status != 204 || len(h.Values("Set-Cookie")) != 2 {
		t.Fatal("Privado samefamily logout", status)
	}
	t.Logf("actual SDK1.43 first+fresh same-family renewal through AuthV2/SigV2+TLS+PG+Core PASS; provider wire requests=%d; no physical wallet UI claim", rpc.hits.Load())
}
