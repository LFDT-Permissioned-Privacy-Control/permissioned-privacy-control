package identitysql_test

import (
	"encoding/json"
	"net/url"
	"os"
	d "privacy-proxy/internal/disclosuretest"
	b "privacy-proxy/internal/identitybroker"
	"privacy-proxy/internal/identityhttp"
	"privacy-proxy/internal/operational/ssohttp"
	"strings"
	"testing"
)

func TestE1ActualPrivadoSSOHandoff(t *testing.T) {
	if os.Getenv("OPS_PRIVADO_WALLET_INTEGRATION") != "1" {
		t.Skip("requires actual pinned SDK/prover fixtures; set OPS_PRIVADO_WALLET_INTEGRATION=1")
	}
	wallet := startWalletProcess(t)
	rpc := newWalletRPC(t, wallet)
	x := newMultiHTTPFixture(t, func(x *multiHTTPFixture) { configureWalletFixture(t, x, wallet, rpc) })
	s := attachSSO(t, x.browserFixture, []string{d.Org}, false)
	start := x.startPrivado(t, nil)
	proof := x.walletProof(t, wallet, start, "a", "")
	status, _, raw := x.postWalletProof(t, start.RequestID, proof)
	if status != 200 {
		t.Fatal(status, string(raw))
	}
	dto := x.confirm(t, x.candidate(t, start.RequestID), nil)
	before := rpc.hits.Load()
	code, pkce, _ := s.ready(t, dto)
	status, raw = s.exchange(t, "app-a", code, pkce, nil)
	if status != 200 {
		t.Fatal("actual Privado handoff", status, string(raw))
	}
	var token ssohttp.TokenResponse
	if json.Unmarshal(raw, &token) != nil || token.AccessToken != dto.AccessToken {
		t.Fatal("Privado original JWT changed")
	}
	if rpc.hits.Load() != before {
		t.Fatal("current live-token SSO checked IdP/state per request")
	}
	// Existing renewal requires a genuine fresh proof; the renewal cookie alone
	// must not mint another access JWT for a new central document.
	oldCode, oldPKCE, _ := s.ready(t, dto)
	origin, _ := url.Parse(x.origin)
	var oldHandle, recipient string
	for _, c := range x.client.Jar.Cookies(origin) {
		if c.Name == identityhttp.RenewalCookie {
			oldHandle = c.Value
		}
		if c.Name == identityhttp.RecipientCookie {
			recipient = c.Value
		}
	}
	status, _, raw = x.request(t, x.client, "POST", identityhttp.Prefix+"renew", renewal(dto), nil)
	var pending b.ProofRequired
	if status != 200 || json.Unmarshal(raw, &pending) != nil || pending.Status != "proof_required" || pending.RequestID == "" || strings.Contains(string(raw), "accessToken") {
		t.Fatal("cookie reconstructed fresh JWT", status, string(raw))
	}
	freshProof := x.walletProof(t, wallet, privadoStartDTO{RequestID: pending.RequestID}, "a", "")
	if freshProof.Diagnostics.RoleGenerations != 1 || freshProof.Diagnostics.OuterGenerations != 1 || !freshProof.Diagnostics.BypassProofsCache {
		t.Fatal("real fresh witness missing")
	}
	status, _, raw = x.postWalletProof(t, pending.RequestID, freshProof)
	if status != 200 {
		t.Fatal("fresh proof callback", status, string(raw))
	}
	sessionID := dto.BrowserSessionID
	fresh := x.confirm(t, x.candidate(t, pending.RequestID), &sessionID)
	binding, e := identityhttp.CentralRecipientBinding(recipient)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = x.serviceOne.AuthenticateCurrentSession(t.Context(), oldHandle, binding, b.ExpectedSession{ActorID: dto.ActorID, SessionID: dto.BrowserSessionID}); e == nil {
		t.Fatal("stale Privado handle accepted")
	}
	status, raw = s.exchange(t, "app-a", oldCode, oldPKCE, nil)
	if status < 400 || strings.Contains(string(raw), dto.AccessToken) {
		t.Fatal("pre-rotation grant accepted")
	}
	freshCode, freshPKCE, _ := s.ready(t, fresh)
	status, raw = s.exchange(t, "app-a", freshCode, freshPKCE, nil)
	if status != 200 {
		t.Fatal("fresh Privado session damaged by stale read", status, string(raw))
	}
	if json.Unmarshal(raw, &token) != nil || token.AccessToken != fresh.AccessToken {
		t.Fatal("fresh JWT changed")
	}
}
