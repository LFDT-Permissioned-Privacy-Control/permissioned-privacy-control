package selfhttp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"privacy-proxy/internal/brokerpolicy"
	f "privacy-proxy/internal/brokertest"
	df "privacy-proxy/internal/disclosuretest"
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
				for _, forbidden := range []string{"accessToken", "source_subject", "userId", "principal_kind", "allowedMethods", "rpcCredential", "verboseErrors", "claims"} {
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
		response.Organizations = append(response.Organizations, Organization{ID: strings.Repeat("a", 36), Slug: strings.Repeat("a", 100), Name: strings.Repeat("<", 256), Groups: []Group{}})
	}
	var b bytes.Buffer
	if json.NewEncoder(&b).Encode(response) != nil || b.Len() != 461561 || b.Len() > MaxResponseBytes {
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

func ownResponse(t *testing.T, h *Handler, token string) (Response, int, []byte) {
	t.Helper()
	server := httptest.NewTLSServer(h)
	defer server.Close()
	request, _ := http.NewRequest("GET", server.URL+Path, nil)
	request.Host = "ops.test"
	request.Header.Set("Authorization", "Bearer "+token)
	result, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Body.Close()
	raw, _ := io.ReadAll(result.Body)
	var dto Response
	if result.StatusCode == 200 && json.Unmarshal(raw, &dto) != nil {
		t.Fatal("invalid own response")
	}
	return dto, result.StatusCode, raw
}
func ownHandler(t *testing.T, snapshot *policybundle.CatalogSnapshot) *Handler {
	t.Helper()
	h, err := New(Config{Snapshot: snapshot, Origin: "https://ops.test", Clock: func() time.Time { return time.Unix(testNow, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func TestOwnMappedGroupsFollowSelectedMappingAndFreshEvidence(t *testing.T) {
	original := f.Snapshot(t, nil)
	before, status, raw := ownResponse(t, ownHandler(t, original), signed(t, original, false, "Reader"))
	if status != 200 || len(before.Organizations) != 1 {
		t.Fatal(status, string(raw))
	}
	org := before.Organizations[0]
	if org.GroupCount != 1 || org.GroupsTruncated || !slices.Equal(org.Groups, []Group{{ID: df.AuditorGroup, Name: "Reader", Slug: "reader"}}) || org.IsOrgAdmin {
		t.Fatal("incorrect own group projection", org)
	}
	if bytes.Contains(raw, []byte(df.AdminGroup)) || bytes.Contains(raw, []byte("allowedMethods")) {
		t.Fatal("foreign membership or private group data exposed")
	}
	changed := f.Snapshot(t, func(c *identity.SourceCatalog, _ *brokerpolicy.Source) {
		c.Mappings[0].GroupIDs = []string{df.AdminGroup}
	})
	current := ownHandler(t, changed)
	after, status, _ := ownResponse(t, current, signed(t, changed, false, "Reader"))
	if status != 200 || after.ActorID != before.ActorID || after.ExpiresAt != before.ExpiresAt || !after.Organizations[0].IsOrgAdmin || after.Organizations[0].Groups[0].ID != df.AdminGroup {
		t.Fatal("fresh mapped own projection missing")
	}
	remapped, status, _ := ownResponse(t, current, signed(t, original, false, "Reader"))
	if status != 200 || remapped.Organizations[0].Groups[0].ID != df.AdminGroup {
		t.Fatal("still-live verified facts did not use current selected mapping", status)
	}
	lost, status, _ := ownResponse(t, current, signed(t, changed, false))
	if status != 200 || lost.ActorID != before.ActorID || len(lost.Organizations) != 0 {
		t.Fatal("removed verified role retained own groups")
	}
	unchanged, status, _ := ownResponse(t, ownHandler(t, original), signed(t, original, false, "Reader"))
	if status != 200 || unchanged.Organizations[0].Groups[0].ID != df.AuditorGroup {
		t.Fatal("selected snapshot was mutated")
	}
}
func TestOwnGroupProjectionBoundsAndEscapedEnvelope(t *testing.T) {
	groups := []policybundle.Group{{ID: df.AuditorGroup, Slug: "reader", Name: "Reader", AllowedMethods: []string{"eth_call"}, Claims: []string{}}, {ID: df.AdminGroup, Slug: "admin", Name: "Admin", AllowedMethods: []string{"eth_getCode"}, IsOrgAdmin: true, Claims: []string{}}}
	ids := []string{}
	for i := 1; i <= 300; i++ {
		id := fmt.Sprintf("%08x-1111-1111-1111-111111111111", i)
		ids = append(ids, id)
		groups = append(groups, policybundle.Group{ID: id, Slug: fmt.Sprintf("g%03d", i) + strings.Repeat("g", 96), Name: fmt.Sprintf("%03d", i) + strings.Repeat("<", 253), AllowedMethods: []string{"eth_call"}, Claims: []string{}})
	}
	snapshot := f.SnapshotWithGroups(t, groups, func(c *identity.SourceCatalog) { c.Mappings[0].GroupIDs = ids })
	h := ownHandler(t, snapshot)
	dto, status, raw := ownResponse(t, h, signed(t, snapshot, false, "Reader"))
	if status != 200 || len(dto.Organizations) != 1 || dto.Organizations[0].GroupCount != 300 || !dto.Organizations[0].GroupsTruncated || len(dto.Organizations[0].Groups) != MaxDisplayedGroups || len(raw) > MaxResponseBytes {
		t.Fatal("high own membership broke display bounds", status, len(raw))
	}
	if !slices.Equal(dto.Organizations[0].Groups[:2], []Group{{ID: ids[0], Name: groups[2].Name, Slug: groups[2].Slug}, {ID: ids[1], Name: groups[3].Name, Slug: groups[3].Slug}}) {
		t.Fatal("projection is not stable selected metadata")
	}
	// Reserve worst-case organization text and the exact count frame before
	// rows. Escaped group names must trigger measured-byte truncation, not 503.
	projected := Response{ActorID: dto.ActorID, PrincipalKind: dto.PrincipalKind, SourceProfile: dto.SourceProfile, SourceProfileDigest: dto.SourceProfileDigest, ExpiresAt: dto.ExpiresAt, Organizations: []Organization{}}
	memberships := make([][]string, MaxOrganizations)
	for i := 0; i < MaxOrganizations; i++ {
		projected.Organizations = append(projected.Organizations, Organization{ID: fmt.Sprintf("%08x-2222-2222-2222-222222222222", i+1), Name: strings.Repeat("<", 256), Slug: strings.Repeat("a", 100), Groups: []Group{}})
	}
	projected.Organizations[0].ID = df.Org
	projected.Organizations[0].GroupCount = len(ids)
	projected.Organizations[0].GroupsTruncated = true
	memberships[0] = ids
	if h.projectGroups(&projected, memberships) != nil {
		t.Fatal("display bytes caused invalid baseline self")
	}
	encoded, _ := json.Marshal(projected)
	if len(encoded) > MaxResponseBytes || len(projected.Organizations[0].Groups) == 0 || len(projected.Organizations[0].Groups) >= MaxDisplayedGroups || !projected.Organizations[0].GroupsTruncated || projected.Organizations[0].GroupCount != 300 {
		t.Fatal("encoded-byte projection failed", len(encoded), len(projected.Organizations[0].Groups))
	}
	again, status, second := ownResponse(t, h, signed(t, snapshot, false, "Reader"))
	if status != 200 || !bytes.Equal(raw, second) || again.Organizations[0].GroupCount != 300 {
		t.Fatal("nondeterministic own projection")
	}
}

// U+FEFF is not Go Unicode whitespace. ECMAScript String.trim removes it,
// so the browser must use the source's White_Space contract for these names.
func TestOwnGroupNameGoWhitespaceFixture(t *testing.T) {
	name := "\ufeffReader\ufeff"
	if strings.TrimSpace(name) != name || strings.TrimSpace("\u0085Reader\u0085") != "Reader" {
		t.Fatal("unexpected Go whitespace contract")
	}
	original := f.Snapshot(t, nil)
	reader, _ := original.Group(df.Org, df.AuditorGroup)
	admin, _ := original.Group(df.Org, df.AdminGroup)
	reader.Name = name
	selected := f.SnapshotWithGroups(t, []policybundle.Group{reader, admin}, nil)
	dto, status, _ := ownResponse(t, ownHandler(t, selected), signed(t, selected, false, "Reader"))
	if status != 200 || len(dto.Organizations) != 1 || len(dto.Organizations[0].Groups) != 1 || dto.Organizations[0].Groups[0].Name != name {
		t.Fatal("approved U+FEFF display name changed or rejected", status)
	}
}
