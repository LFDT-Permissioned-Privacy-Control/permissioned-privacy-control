package selfhttp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	f "privacy-proxy/internal/brokertest"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/policybundle"
)

const testNow = int64(1800000000)

func signed(t *testing.T, snapshot *policybundle.CatalogSnapshot, service bool, roles ...string) string {
	t.Helper()
	c, _ := snapshot.Identity()
	profile, kind := f.HumanProfile, identity.Human
	if service {
		profile, kind = f.ServiceProfile, identity.Service
	}
	var p identity.Profile
	for _, v := range c.Source().Profiles {
		if v.ID == profile {
			p = v
		}
	}
	source := identity.SourceIdentity{ProfileID: profile, Kind: kind, Authority: p.Issuer, Subject: "cccccccc-1111-1111-1111-111111111111", Tenant: &p.TenantID}
	actor, err := c.SourceActorID(source)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := c.ProfileDigest(profile)
	facts := []identity.Fact{}
	for _, role := range roles {
		facts = append(facts, identity.Fact{Kind: "azure.role", Value: role})
	}
	claims := jwt.MapClaims{"iss": "https://ops.test", "aud": "core", "sub": actor, "jti": "own-self-test", "iat": testNow, "nbf": testNow, "exp": testNow + 300, "principal_kind": kind, "source_profile": profile, "source_profile_digest": digest, "identity_authority": p.Issuer, "source_subject": source.Subject, "source_tenant": p.TenantID, "source_verified_at": testNow, "claims_as_of": testNow, "facts": facts}
	claims["source_not_after"] = testNow + 3600
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["typ"], token.Header["kid"] = "ops-access+jwt", "test"
	raw, err := token.SignedString(f.SigningKey())
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestActualVerifiedOwnSelfHumanServiceAndStrictIngress(t *testing.T) {
	snapshot := f.Snapshot(t, nil)
	h, err := New(Config{Snapshot: snapshot, Origin: "https://ops.test", Clock: func() time.Time { return time.Unix(testNow, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(h)
	defer server.Close()
	for _, tc := range []struct {
		name, method, target, body, origin, host string
		tokens                                   []string
		want                                     int
		service                                  bool
		roles                                    []string
	}{
		{name: "human admin", want: 200, roles: []string{"Admin"}},
		{name: "service own", want: 200, service: true, roles: []string{"Service"}},
		{name: "unmapped empty own scope", want: 200},
		{name: "no bearer", want: 401, tokens: []string{}},
		{name: "duplicate bearer", want: 401, tokens: []string{"Bearer one", "Bearer two"}},
		{name: "oversized bearer", want: 401, tokens: []string{"Bearer " + strings.Repeat("a", 16385)}},
		{name: "cookie is no authority", want: 401, tokens: []string{}},
		{name: "query selector", target: Path + "?actorId=other", want: 400},
		{name: "force query", target: Path + "?", want: 400},
		{name: "body selector", body: "x", want: 400},
		{name: "post", method: "POST", want: 405},
		{name: "head", method: "HEAD", want: 405},
		{name: "foreign host", host: "evil.test", want: 403},
		{name: "foreign origin", origin: "https://evil.test", want: 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			method := tc.method
			if method == "" {
				method = "GET"
			}
			target := tc.target
			if target == "" {
				target = Path
			}
			r, _ := http.NewRequest(method, server.URL+target, strings.NewReader(tc.body))
			r.Host = "ops.test"
			if tc.host != "" {
				r.Host = tc.host
			}
			r.Header.Set("Cookie", "forged-user=admin")
			if tc.tokens == nil {
				r.Header.Set("Authorization", "Bearer "+signed(t, snapshot, tc.service, tc.roles...))
			} else {
				for _, v := range tc.tokens {
					r.Header.Add("Authorization", v)
				}
			}
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			res, e := server.Client().Do(r)
			if e != nil {
				t.Fatal(e)
			}
			defer res.Body.Close()
			raw, _ := io.ReadAll(res.Body)
			if res.StatusCode != tc.want {
				t.Fatalf("status=%d want=%d", res.StatusCode, tc.want)
			}
			if res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("Referrer-Policy") != "no-referrer" || res.Header.Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("unsafe response headers")
			}
			if tc.want == 200 {
				var dto Response
				if json.Unmarshal(raw, &dto) != nil || !identity.ValidActorID(dto.ActorID) || dto.ExpiresAt != testNow+300 {
					t.Fatal("invalid own DTO")
				}
				if tc.service && dto.PrincipalKind != identity.Service {
					t.Fatal("service rewritten as human")
				}
				if len(tc.roles) == 0 && len(dto.Organizations) != 0 {
					t.Fatal("unmapped principal acquired organization")
				}
				if tc.name == "human admin" && (len(dto.Organizations) != 1 || !dto.Organizations[0].IsOrgAdmin) {
					t.Fatal("View admin flag missing")
				}
				for _, forbidden := range []string{"accessToken", "groups", "source_subject", "userId", "principal_kind"} {
					if bytes.Contains(raw, []byte(forbidden)) {
						t.Fatal("unexpected identity/directory data", forbidden)
					}
				}
			}
		})
	}
}

func TestOriginalExpiryGateBeforeFirstSelfBytes(t *testing.T) {
	snapshot := f.Snapshot(t, nil)
	var calls atomic.Int64
	h, err := New(Config{Snapshot: snapshot, Origin: "https://ops.test", Clock: func() time.Time {
		if calls.Add(1) >= 3 {
			return time.Unix(testNow+300, 0)
		}
		return time.Unix(testNow, 0)
	}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(h)
	defer server.Close()
	r, _ := http.NewRequest("GET", server.URL+Path, nil)
	r.Host = "ops.test"
	r.Header.Set("Authorization", "Bearer "+signed(t, snapshot, false, "Admin"))
	res, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != 401 || bytes.Contains(raw, []byte("organizations")) || calls.Load() < 3 {
		t.Fatal("expired original evidence reached output", res.StatusCode, calls.Load())
	}
}

func TestSelfMaximumUnicodeJSONAndCanonicalOrigins(t *testing.T) {
	response := Response{ActorID: "ops:p1:" + strings.Repeat("a", 43), PrincipalKind: identity.Service, SourceProfile: strings.Repeat("<", 128), SourceProfileDigest: "sha256:" + strings.Repeat("f", 64), ExpiresAt: 999999999999, Organizations: []Organization{}}
	for i := 0; i < 256; i++ {
		response.Organizations = append(response.Organizations, Organization{ID: strings.Repeat("a", 36), Slug: strings.Repeat("a", 100), Name: strings.Repeat("<", 256)})
	}
	var b bytes.Buffer
	if json.NewEncoder(&b).Encode(response) != nil || b.Len() != 448505 || b.Len() > MaxResponseBytes {
		t.Fatal("maximum supported JSON bound", b.Len())
	}
	response.Organizations[0].Name = "<>&\"\\\u2028\u2029Банк🏦"
	raw, _ := json.Marshal(response)
	var round Response
	if json.Unmarshal(raw, &round) != nil || round.Organizations[0].Name != response.Organizations[0].Name {
		t.Fatal("Unicode altered")
	}
	snapshot := f.Snapshot(t, nil)
	for _, origin := range []string{"https://127.1", "https://2130706433", "https://0177.0.0.1", "https://0x7f000001", "https://example.123", "https://[ops.test]", "https://ops.test:", "https://ops.test:443", "https://ops.test:0443", "https://OPS.test", "https://user@ops.test", "https://ops.test/", "https://ops.test?"} {
		if _, e := New(Config{Snapshot: snapshot, Origin: origin, Clock: time.Now}); e == nil {
			t.Fatal("ambiguous origin accepted", origin)
		}
	}
	for _, origin := range []string{"https://ops.test", "https://127.0.0.1:8443", "https://[::1]", "https://ops.test:8443"} {
		if _, e := New(Config{Snapshot: snapshot, Origin: origin, Clock: time.Now}); e != nil {
			t.Fatal("canonical origin rejected", origin)
		}
	}
}
