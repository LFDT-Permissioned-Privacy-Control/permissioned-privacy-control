package identitysql_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	f "privacy-proxy/internal/brokertest"
	d "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/identity"
	b "privacy-proxy/internal/identitybroker"
	"privacy-proxy/internal/identitybroker/azure"
	"privacy-proxy/internal/identityhttp"
	"privacy-proxy/internal/operational/identitysql"
	"privacy-proxy/internal/operational/ssohttp"
	"privacy-proxy/internal/operational/ssosql"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/policyprofiles"
	"privacy-proxy/internal/ssopolicy"
	m "privacy-proxy/internal/ssotransaction"
	"strings"
	"sync"
	"testing"
	"time"
)

// The approved test bundle is loaded through real prepare/load. The second
// organization maps the same verified Reader fact, exercising ALL-org trust.
func ssoSnapshot(t *testing.T, origin string, foreign bool) *policybundle.CatalogSnapshot {
	t.Helper()
	ids, auth := f.MultiIdentitySource(t), f.MultiBrokerSource()
	auth.WebOrigin = origin
	auth.CompletionURI = origin + "/auth/complete"
	auth.AzureProfiles[0].RedirectURI = origin + "/auth/azure/callback"
	orgs := []policybundle.Organization{{ID: d.Org, Slug: "a", Name: "A"}}
	groups := map[string][]policybundle.Group{d.Org: {{ID: d.AuditorGroup, Slug: "reader", Name: "Reader", Claims: []string{}, AllowedMethods: []string{"eth_call"}}, {ID: d.AdminGroup, Slug: "admin", Name: "Admin", IsOrgAdmin: true, Claims: []string{}, AllowedMethods: []string{"eth_getCode"}}}}
	if foreign {
		orgs = append(orgs, policybundle.Organization{ID: d.OtherOrg, Slug: "b", Name: "B"})
		groups[d.OtherOrg] = []policybundle.Group{{ID: d.ForeignGroup, Slug: "foreign", Name: "Foreign", Claims: []string{}, AllowedMethods: []string{}}}
		ids.Mappings = append(ids.Mappings, identity.Mapping{ID: "foreign", ProfileID: f.HumanProfile, OrganizationID: d.OtherOrg, PrincipalKind: identity.Human, Fact: identity.Fact{Kind: "azure.role", Value: "Reader"}, GroupIDs: []string{d.ForeignGroup}})
	}
	dir := t.TempDir()
	write := func(path string, value any) {
		raw, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, path), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	draft := policybundle.Draft{APIVersion: policybundle.DraftAPIVersion, Kind: policybundle.DraftKind, Environment: "test", ChainID: "1", EvaluatorVersion: policybundle.NativeV2EvaluatorVersion, Profile: policybundle.BrokerMultiProfileID, SourceRevision: "sso-test", Organizations: orgs, Documents: []policybundle.DraftDocument{}, IdentityCatalog: &policybundle.DraftIdentity{Path: "identity.json"}, AuthCatalog: &policybundle.DraftIdentity{Path: "auth.json"}}
	for _, org := range orgs {
		for _, doc := range []struct {
			kind   policybundle.Kind
			suffix string
			spec   any
		}{{policybundle.Groups, "groups", policybundle.GroupsSpec{Groups: groups[org.ID]}}, {policybundle.ContractRegistry, "registry", policybundle.RegistrySpec{Contracts: []policybundle.Contract{}}}, {policybundle.ExecutionRules, "execution", policybundle.ExecutionSpec{Policy: &policycore.Policy{APIVersion: policycore.NativeV2APIVersion, Kind: policycore.Kind, Org: org.ID, NestedCalls: policycore.NestedCallsRequireOwnRule, Bindings: []policycore.Binding{}}}}} {
			name := org.Slug + "-" + doc.suffix + ".json"
			draft.Documents = append(draft.Documents, policybundle.DraftDocument{Kind: doc.kind, OrganizationID: org.ID, Path: name})
			write(name, map[string]any{"apiVersion": policybundle.DocumentAPIVersion, "kind": doc.kind, "organizationId": org.ID, "spec": doc.spec})
		}
	}
	write("draft.json", draft)
	write("identity.json", ids)
	write("auth.json", auth)
	if e := os.WriteFile(filepath.Join(dir, "role-context.json"), f.PrivadoContext, 0600); e != nil {
		t.Fatal(e)
	}
	options, _, e := policyprofiles.Options(draft.Profile)
	if e != nil {
		t.Fatal(e)
	}
	artifact, e := policybundle.PrepareDirectory(t.Context(), policybundle.DraftSelection{Directory: dir}, options)
	if e != nil {
		t.Fatal(e)
	}
	out := t.TempDir()
	for _, file := range artifact.Files() {
		if e = os.WriteFile(filepath.Join(out, file.Path), file.Bytes, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.WriteFile(filepath.Join(out, "manifest.json"), artifact.ManifestBytes(), 0600); e != nil {
		t.Fatal(e)
	}
	snapshot, e := policybundle.LoadDirectory(t.Context(), policybundle.Selection{Directory: out, ExpectedManifestDigest: artifact.ManifestDigest(), ExpectedEnvironment: "test", ExpectedChainID: "1"}, options)
	if e != nil {
		t.Fatal(e)
	}
	return snapshot
}
func newSSOAzureFixture(t *testing.T, foreign bool) *browserFixture {
	t.Helper()
	muxes := []*http.ServeMux{http.NewServeMux(), http.NewServeMux()}
	one, two := httptest.NewUnstartedServer(muxes[0]), httptest.NewUnstartedServer(muxes[1])
	t.Cleanup(one.Close)
	t.Cleanup(two.Close)
	_, port, _ := strings.Cut(one.Listener.Addr().String(), ":")
	origin := "https://ops.test:" + port
	x := &browserFixture{origin: origin, first: one, second: two, muxes: muxes}
	x.db = setup(t)
	x.db.binding.Origin = origin
	x.db.snapshot = ssoSnapshot(t, origin, foreign)
	x.db.entra.SetRedirectURI(origin + "/auth/azure/callback")
	auth, _ := x.db.snapshot.AuthBroker()
	provider, e := azure.New(t.Context(), azure.Config{Catalog: auth, Clock: x.db.clock, ClientSecrets: map[string]string{"OPS_BROKER_AZURE_TEST": "test-only-secret"}, Transport: x.db.entra.Transport()})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(provider.Close)
	x.db.provider = provider
	proof, e := identitysql.OpenProofV2(t.Context(), x.db.proofDSN, x.db.scope, x.db.clock)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(proof.Close)
	for i, store := range []*identitysql.Store{x.db.one, x.db.two} {
		s, e := b.NewMulti(b.MultiConfig{Snapshot: x.db.snapshot, Clock: x.db.clock, Store: store, PublicProofStore: proof, AzureProvider: provider, AccessSigningBinding: b.AccessSigningBinding{IssuerID: "ops", KeyID: "test", PrivateKey: f.SigningKey()}, RenewalKeyBindings: []b.SecretBinding{{FromEnv: "OPS_BROKER_REFRESH_TEST", Value: bytes.Repeat([]byte{1}, 32)}}, EncryptionKeyBindings: []b.SecretBinding{{FromEnv: "OPS_BROKER_ENCRYPTION_TEST", Value: bytes.Repeat([]byte{2}, 32)}}, ServiceBinding: x.db.binding, ExpectedState: x.db.scope.State})
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(s.Close)
		if i == 0 {
			x.serviceOne = s
		} else {
			x.serviceTwo = s
		}
		h, e := identityhttp.NewMulti(identityhttp.Config{Snapshot: x.db.snapshot, Service: s, Clock: x.db.clock})
		if e != nil {
			t.Fatal(e)
		}
		h.Register(muxes[i])
	}
	for _, s := range []*httptest.Server{one, two} {
		s.Config.ReadHeaderTimeout = 5 * time.Second
		s.Config.MaxHeaderBytes = 64 << 10
		s.StartTLS()
	}
	x.client = x.newClient(t, true)
	return x
}

type ssoReferences struct{ snapshot *policybundle.CatalogSnapshot }

func (r ssoReferences) Organization(id string) bool {
	for _, o := range r.snapshot.Organizations() {
		if o.ID == id {
			return true
		}
	}
	return false
}
func (r ssoReferences) Group(org, id string) bool { _, ok := r.snapshot.Group(org, id); return ok }

type ssoLogs struct {
	mu sync.Mutex
	bytes.Buffer
}

func (l *ssoLogs) Write(raw []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.Buffer.Write(raw)
}
func (l *ssoLogs) text() string { l.mu.Lock(); defer l.mu.Unlock(); return l.Buffer.String() }

type ssoFixture struct {
	x                *browserFixture
	scope            m.Scope
	configs          []ssohttp.Config
	stores           []*ssosql.Store
	logs             *ssoLogs
	secretA, secretB string
	appDSN           string
}

func attachSSO(t *testing.T, x *browserFixture, trust []string, profileMode bool) *ssoFixture {
	t.Helper()
	for _, role := range []string{"sso_app", "sso_retention"} {
		if _, e := x.db.owner.Exec(t.Context(), `CREATE ROLE `+pgx.Identifier{role}.Sanitize()+` LOGIN NOINHERIT PASSWORD 'sso-test-only'`); e != nil {
			t.Fatal(e)
		}
	}
	ns, e := m.NamespaceFor(m.Digest(x.db.scope.Namespace), x.origin)
	if e != nil {
		t.Fatal(e)
	}
	scope := m.Scope{Namespace: ns, Epoch: uuid.NewString(), BrokerNamespace: m.Digest(x.db.scope.Namespace), BrokerRecoveryEpoch: x.db.scope.State.RecoveryEpoch}
	reg := ssosql.Registration{Namespace: ns, BrokerNamespace: scope.BrokerNamespace, Epoch: scope.Epoch, BrokerRecoveryEpoch: scope.BrokerRecoveryEpoch, Limits: m.DefaultLimits(), Roles: ssosql.Roles{App: "sso_app", Retention: "sso_retention"}}
	if e = ssosql.Migrate(t.Context(), x.db.ownerDSN, reg.Roles, true); e != nil {
		t.Fatal(e)
	}
	if e = ssosql.Initialize(t.Context(), x.db.ownerDSN, reg, true); e != nil {
		t.Fatal(e)
	}
	source := ssopolicy.Source{APIVersion: ssopolicy.APIVersion, Kind: ssopolicy.Kind, Clients: []ssopolicy.ClientSource{}}
	for _, row := range []struct{ id, ref string }{{"app-a", "SSO_APP_A"}, {"app-b", "SSO_APP_B"}} {
		client := ssopolicy.ClientSource{ID: row.id, DisplayName: "App " + row.id, Authentication: "client_secret_basic", Secret: ssopolicy.SecretRef{FromEnv: row.ref}, TrustMode: "first-party-full-core-bearer", TrustedOrganizationIDs: trust, EligibleGroups: []ssopolicy.GroupRef{{OrganizationID: d.Org, GroupID: d.AuditorGroup}}, Eligibility: ssopolicy.GroupEligibility, AllowedProfiles: []string{f.HumanProfile, f.PrivadoRoleProfile}, RedirectURIs: []string{"https://app.test/callback"}}
		if profileMode {
			client.Eligibility = ssopolicy.ProfileEligibility
			client.EligibleGroups = []ssopolicy.GroupRef{}
		}
		source.Clients = append(source.Clients, client)
	}
	raw, _ := json.Marshal(source)
	ids, _ := x.db.snapshot.Identity()
	clients, e := ssopolicy.Compile(raw, ids, ssoReferences{x.db.snapshot})
	if e != nil {
		t.Fatal(e)
	}
	runtime := ssohttp.RuntimeSource{APIVersion: "ops.sso.runtime/v1", Kind: "SSORuntime", CoreManifestDigest: string(x.db.snapshot.Metadata().ManifestDigest), BrokerManifestDigest: string(x.db.snapshot.Metadata().ManifestDigest), ClientCatalogDigest: clients.Digest(), ContextKey: ssohttp.KeyRef{ID: "context", FromEnv: "SSO_CONTEXT"}, GrantKey: ssohttp.KeyRef{ID: "grant", FromEnv: "SSO_GRANT"}}
	runtimeRaw, _ := json.Marshal(runtime)
	u, _ := url.Parse(x.db.ownerDSN)
	u.User = url.UserPassword("sso_app", "sso-test-only")
	out := &ssoFixture{x: x, scope: scope, logs: &ssoLogs{}, secretA: strings.Repeat("a", 32) + "+%:", secretB: strings.Repeat("b", 32), appDSN: u.String()}
	for i, service := range []*b.Service{x.serviceOne, x.serviceTwo} {
		store, e := ssosql.OpenApp(t.Context(), ssosql.Config{DSN: out.appDSN, Expected: scope, Clock: x.db.clock})
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(store.Close)
		out.stores = append(out.stores, store)
		config := ssohttp.Config{CoreSnapshot: x.db.snapshot, BrokerSnapshot: x.db.snapshot, Broker: service, Store: store, Clients: clients, RuntimeSourceJSON: runtimeRaw, ExpectedSourceSHA256: sha256.Sum256(runtimeRaw), EncryptionBindings: []ssohttp.SecretBinding{{FromEnv: "SSO_CONTEXT", Value: bytes.Repeat([]byte{3}, 32)}, {FromEnv: "SSO_GRANT", Value: bytes.Repeat([]byte{4}, 32)}}, ClientSecretBindings: []ssohttp.SecretBinding{{FromEnv: "SSO_APP_A", Value: []byte(out.secretA)}, {FromEnv: "SSO_APP_B", Value: []byte(out.secretB)}}, Clock: x.db.clock, SecurityLog: slog.New(slog.NewJSONHandler(out.logs, nil))}
		out.configs = append(out.configs, config)
		h, e := ssohttp.New(config)
		if e != nil {
			t.Fatal("SSO startup", e)
		}
		h.Register(x.muxes[i])
	}
	return out
}
func (s *ssoFixture) start(t *testing.T, client, state string) (id, pkce string) {
	t.Helper()
	pkce = strings.Repeat("v", 43)
	challenge := sha256.Sum256([]byte(pkce))
	q := url.Values{"client_id": {client}, "redirect_uri": {"https://app.test/callback"}, "response_type": {"code"}, "state": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"}}
	status, header, raw := s.x.request(t, s.x.client, "GET", ssohttp.Prefix+"authorize?"+q.Encode(), nil, nil)
	if status != 303 || len(raw) != 0 {
		t.Fatal("authorize", status, string(raw))
	}
	u, e := url.Parse(header.Get("Location"))
	if e != nil || u.Scheme+"://"+u.Host != s.x.origin || u.Path != "/auth/sso" || !b.ValidUUID(u.Query().Get("flow")) {
		t.Fatal("untrusted start redirect")
	}
	return u.Query().Get("flow"), pkce
}
func (s *ssoFixture) complete(t *testing.T, id string, dto identityhttp.AccessDTO) (int, string) {
	t.Helper()
	status, _, raw := s.x.request(t, s.x.client, "POST", ssohttp.Prefix+"flow", map[string]string{"action": "complete", "flowId": id, "expectedActorId": dto.ActorID, "expectedSessionId": dto.BrowserSessionID}, func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+dto.AccessToken) })
	if status != 200 {
		return status, string(raw)
	}
	var response ssohttp.CompleteResponse
	if json.Unmarshal(raw, &response) != nil {
		t.Fatal("invalid complete body")
	}
	return status, response.RedirectTo
}
func (s *ssoFixture) exchange(t *testing.T, id, code, pkce string, change func(*http.Request)) (int, []byte) {
	t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {id}, "code": {code}, "redirect_uri": {"https://app.test/callback"}, "code_verifier": {pkce}}
	status, _, raw := s.x.request(t, s.x.newClient(t, false), "POST", ssohttp.Prefix+"token", form.Encode(), func(r *http.Request) {
		r.Header.Del("Origin")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		secret := s.secretA
		if id == "app-b" {
			secret = s.secretB
		}
		r.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))
		if change != nil {
			change(r)
		}
	})
	return status, raw
}
func (s *ssoFixture) ready(t *testing.T, dto identityhttp.AccessDTO) (code, pkce, id string) {
	t.Helper()
	id, pkce = s.start(t, "app-a", "state+%&")
	status, redirect := s.complete(t, id, dto)
	if status != 200 {
		t.Fatal("complete", status, redirect)
	}
	u, e := url.Parse(redirect)
	if e != nil || u.Scheme+"://"+u.Host+u.Path != "https://app.test/callback" || u.Query().Get("state") != "state+%&" || len(u.Query().Get("code")) != 43 {
		t.Fatal("callback changed state")
	}
	return u.Query().Get("code"), pkce, id
}
func TestE1ActualSSOAzureHTTP(t *testing.T) {
	x := newSSOAzureFixture(t, false)
	s := attachSSO(t, x, []string{d.Org}, false)
	dto := x.complete(t, x.client, x.start(t, x.client))
	x.db.entra.Clock.Add(17) // Handoff must retain the original age, never reset to300s.
	before := x.db.entra.Grants.Load()
	t.Run("original JWT two replicas known commit and one use", func(t *testing.T) {
		code, pkce, id := s.ready(t, dto)
		status, raw := s.exchange(t, "app-a", code, pkce, nil)
		if status != 200 {
			t.Fatal(status, string(raw))
		}
		var response ssohttp.TokenResponse
		if json.Unmarshal(raw, &response) != nil || response.AccessToken != dto.AccessToken || response.ExpiresIn != dto.ExpiresAt-x.db.clock().Unix() || bytes.Contains(raw, []byte("refresh_token")) {
			t.Fatal("original token/lifetime changed")
		}
		var phase int
		var cipherGone bool
		if e := x.db.owner.QueryRow(t.Context(), `SELECT phase,context_ciphertext IS NULL AND grant_ciphertext IS NULL FROM ops_sso_v1.transactions WHERE id=$1::uuid`, id).Scan(&phase, &cipherGone); e != nil || phase != 3 || !cipherGone {
			t.Fatal("not durably consumed", e)
		}
		status, raw = s.exchange(t, "app-a", code, pkce, nil)
		if status < 400 || bytes.Contains(raw, []byte(dto.AccessToken)) {
			t.Fatal("code replay")
		}
	})
	t.Run("Basic form and code-client mixup reject without consumption", func(t *testing.T) {
		code, pkce, _ := s.ready(t, dto)
		for _, change := range []func(*http.Request){func(r *http.Request) { r.SetBasicAuth("app-b", url.QueryEscape(s.secretB)) }, func(r *http.Request) { r.Header.Add("Authorization", r.Header.Get("Authorization")) }, func(r *http.Request) { r.Header.Set("Origin", "https://attacker.test") }, func(r *http.Request) { r.Header.Set("Cookie", "other=value") }} {
			status, raw := s.exchange(t, "app-a", code, pkce, change)
			if status < 400 || bytes.Contains(raw, []byte(dto.AccessToken)) {
				t.Fatal("mixup accepted")
			}
		}
		status, _ := s.exchange(t, "app-b", code, pkce, nil)
		if status < 400 {
			t.Fatal("B exchanged A code")
		}
		status, _ = s.exchange(t, "app-a", code, strings.Repeat("z", 43), nil)
		if status < 400 {
			t.Fatal("wrong PKCE accepted")
		}
		status, _ = s.exchange(t, "app-a", code, pkce, nil)
		if status != 200 {
			t.Fatal("denials consumed code", status)
		}
	})
	t.Run("same source restart and encrypted source swap", func(t *testing.T) {
		code, pkce, _ := s.ready(t, dto)
		if _, e := ssohttp.New(s.configs[0]); e != nil {
			t.Fatal("restart rejected", e)
		}
		bad := s.configs[0]
		bad.RuntimeSourceJSON = bytes.ReplaceAll(bad.RuntimeSourceJSON, []byte(`"context"`), []byte(`"changed-context"`))
		bad.ExpectedSourceSHA256 = sha256.Sum256(bad.RuntimeSourceJSON)
		h, e := ssohttp.New(bad)
		if e != nil {
			t.Fatal("valid key-ID cutover startup", e)
		}
		server := httptest.NewTLSServer(h)
		defer server.Close()
		form := url.Values{"grant_type": {"authorization_code"}, "client_id": {"app-a"}, "code": {code}, "redirect_uri": {"https://app.test/callback"}, "code_verifier": {pkce}}
		req, _ := http.NewRequestWithContext(t.Context(), "POST", server.URL+ssohttp.Prefix+"token", strings.NewReader(form.Encode()))
		req.Host = strings.TrimPrefix(x.origin, "https://")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("app-a", url.QueryEscape(s.secretA))
		res, e := server.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode < 400 || bytes.Contains(raw, []byte(dto.AccessToken)) {
			t.Fatal("source-swapped capsule accepted")
		}
		status, _ := s.exchange(t, "app-a", code, pkce, nil)
		if status != 200 {
			t.Fatal("source swap consumed code")
		}
	})
	if x.db.entra.Grants.Load() != before {
		t.Fatal("SSO unexpectedly requested provider refresh")
	}
	for _, secret := range []string{dto.AccessToken, s.secretA, s.secretB, "state+%&"} {
		if strings.Contains(s.logs.text(), secret) {
			t.Fatal("credential/state in logs")
		}
	}
}
func TestE1CurrentSessionReadNeverRevokesStaleHandle(t *testing.T) {
	x := newSSOAzureFixture(t, false)
	dto := x.complete(t, x.client, x.start(t, x.client))
	u, _ := url.Parse(x.origin)
	cookies := x.client.Jar.Cookies(u)
	var handle, recipient string
	for _, c := range cookies {
		if c.Name == identityhttp.RenewalCookie {
			handle = c.Value
		}
		if c.Name == identityhttp.RecipientCookie {
			recipient = c.Value
		}
	}
	binding, e := identityhttp.CentralRecipientBinding(recipient)
	if e != nil {
		t.Fatal(e)
	}
	expected := b.ExpectedSession{ActorID: dto.ActorID, SessionID: dto.BrowserSessionID}
	session, e := x.serviceOne.AuthenticateCurrentSession(t.Context(), handle, binding, expected)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = session.MetadataFor(x.serviceTwo); e == nil {
		t.Fatal("foreign owner accepted")
	}
	if e = x.serviceTwo.RecheckCurrentSession(t.Context(), session); e == nil {
		t.Fatal("foreign binding accepted")
	}
	status, _, raw := x.request(t, x.client, "POST", identityhttp.Prefix+"renew", renewal(dto), nil)
	if status != 200 {
		t.Fatal(status, string(raw))
	}
	if _, e = x.serviceOne.AuthenticateCurrentSession(t.Context(), handle, binding, expected); !errors.Is(e, b.ErrSessionChanged) {
		t.Fatal("stale handle not denied", e)
	}
	if e = x.serviceOne.RecheckCurrentSession(t.Context(), session); !errors.Is(e, b.ErrSessionChanged) {
		t.Fatal("stale capture accepted", e)
	}
	var revoked bool
	var generation int64
	if e = x.db.owner.QueryRow(t.Context(), `SELECT revoked_at IS NOT NULL,generation FROM ops_identity_v2.renewal_families WHERE family_id=$1::uuid`, dto.BrowserSessionID).Scan(&revoked, &generation); e != nil || revoked || generation != 1 {
		t.Fatal("read mutated family", revoked, generation, e)
	}
}
func TestE1AllMappedOrganizationsAndEmptyTrust(t *testing.T) {
	for _, row := range []struct {
		name                        string
		foreign, zeroFacts, profile bool
		trust                       []string
		want                        int
	}{{"all mapped orgs must be trusted", true, false, false, []string{d.Org}, 403}, {"both orgs explicitly trusted", true, false, false, []string{d.Org, d.OtherOrg}, 200}, {"empty trusts only zero org", false, false, true, []string{}, 403}, {"explicit profile permits zero org", false, true, true, []string{}, 200}} {
		t.Run(row.name, func(t *testing.T) {
			x := newSSOAzureFixture(t, row.foreign)
			if row.zeroFacts {
				x.db.entra.SetRoles()
			}
			s := attachSSO(t, x, row.trust, row.profile)
			dto := x.complete(t, x.client, x.start(t, x.client))
			id, _ := s.start(t, "app-a", "state")
			status, raw := s.complete(t, id, dto)
			if status != row.want {
				t.Fatal(status, raw)
			}
		})
	}
}

type ssoAfterRead struct {
	b.MultiStore
	after func()
}

func (p ssoAfterRead) WithProviderFamily(ctx context.Context, scope b.Scope, provider b.FamilyProvider, id string, decide func(b.Family) (b.FamilyDecision, error), gate func() error) (b.Commit, error) {
	result, e := p.MultiStore.WithProviderFamily(ctx, scope, provider, id, decide, gate)
	if e == nil && result.Committed && result.Kind == b.DenyUnchanged {
		p.after()
	}
	return result, e
}
func ssoService(t *testing.T, x *browserFixture, store b.MultiStore) *b.Service {
	t.Helper()
	proof, e := identitysql.OpenProofV2(t.Context(), x.db.proofDSN, x.db.scope, x.db.clock)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(proof.Close)
	s, e := b.NewMulti(b.MultiConfig{Snapshot: x.db.snapshot, Clock: x.db.clock, Store: store, PublicProofStore: proof, AzureProvider: x.db.provider, AccessSigningBinding: b.AccessSigningBinding{IssuerID: "ops", KeyID: "test", PrivateKey: f.SigningKey()}, RenewalKeyBindings: []b.SecretBinding{{FromEnv: "OPS_BROKER_REFRESH_TEST", Value: bytes.Repeat([]byte{1}, 32)}}, EncryptionKeyBindings: []b.SecretBinding{{FromEnv: "OPS_BROKER_ENCRYPTION_TEST", Value: bytes.Repeat([]byte{2}, 32)}}, ServiceBinding: x.db.binding, ExpectedState: x.db.scope.State})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	return s
}
func TestE1ReadOnlySessionExplicitPostgate(t *testing.T) {
	x := newSSOAzureFixture(t, false)
	dto := x.complete(t, x.client, x.start(t, x.client))
	u, _ := url.Parse(x.origin)
	var handle, recipient string
	for _, c := range x.client.Jar.Cookies(u) {
		if c.Name == identityhttp.RenewalCookie {
			handle = c.Value
		}
		if c.Name == identityhttp.RecipientCookie {
			recipient = c.Value
		}
	}
	binding, e := identityhttp.CentralRecipientBinding(recipient)
	if e != nil {
		t.Fatal(e)
	}
	start := x.db.entra.Clock.Load()
	for _, mode := range []string{"cancel", "expiry"} {
		t.Run(mode, func(t *testing.T) {
			x.db.entra.Clock.Store(start)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			wrapped := ssoAfterRead{MultiStore: x.db.one, after: func() {
				if mode == "cancel" {
					cancel()
				} else {
					x.db.entra.Clock.Store(start + int64(b.FamilyLifetime/time.Second))
				}
			}}
			service := ssoService(t, x, wrapped)
			session, e := service.AuthenticateCurrentSession(ctx, handle, binding, b.ExpectedSession{ActorID: dto.ActorID, SessionID: dto.BrowserSessionID})
			if e == nil || session != nil {
				t.Fatal("known DenyUnchanged COMMIT skipped caller postgate")
			}
		})
	}
	x.db.entra.Clock.Store(start)
	if _, e = x.serviceOne.AuthenticateCurrentSession(t.Context(), handle, binding, b.ExpectedSession{ActorID: dto.ActorID, SessionID: dto.BrowserSessionID}); e != nil {
		t.Fatal("read-only denial mutated family", e)
	}
}
func TestE1StartupSelectedSecretsAndBindings(t *testing.T) {
	x := newSSOAzureFixture(t, false)
	s := attachSSO(t, x, []string{d.Org}, false)
	base := s.configs[0]
	for _, name := range []string{"missing client", "extra client", "same client bytes", "client equals context", "client equals grant", "same ref different bytes", "context equals broker MAC", "grant equals broker AES", "signing seed", "shared selected client reference plus extra binding"} {
		t.Run(name, func(t *testing.T) {
			c := base
			c.ClientSecretBindings = append([]ssohttp.SecretBinding(nil), base.ClientSecretBindings...)
			c.EncryptionBindings = append([]ssohttp.SecretBinding(nil), base.EncryptionBindings...)
			switch name {
			case "missing client":
				c.ClientSecretBindings = c.ClientSecretBindings[:1]
			case "extra client":
				c.ClientSecretBindings = append(c.ClientSecretBindings, ssohttp.SecretBinding{FromEnv: "EXTRA", Value: bytes.Repeat([]byte{'Z'}, 32)})
			case "same client bytes":
				c.ClientSecretBindings[1].Value = bytes.Clone(c.ClientSecretBindings[0].Value)
			case "client equals context":
				c.EncryptionBindings[0].Value = bytes.Repeat([]byte{'C'}, 32)
				c.ClientSecretBindings[0].Value = bytes.Clone(c.EncryptionBindings[0].Value)
			case "client equals grant":
				c.EncryptionBindings[1].Value = bytes.Repeat([]byte{'G'}, 32)
				c.ClientSecretBindings[0].Value = bytes.Clone(c.EncryptionBindings[1].Value)
			case "same ref different bytes":
				c.ClientSecretBindings[0].FromEnv = c.EncryptionBindings[0].FromEnv
			case "context equals broker MAC":
				c.EncryptionBindings[0].Value = bytes.Repeat([]byte{1}, 32)
			case "grant equals broker AES":
				c.EncryptionBindings[1].Value = bytes.Repeat([]byte{2}, 32)
			case "signing seed":
				c.ClientSecretBindings[0].Value = f.SigningKey().Seed()
			case "shared selected client reference plus extra binding":
				source := ssopolicy.Source{APIVersion: ssopolicy.APIVersion, Kind: ssopolicy.Kind, Clients: []ssopolicy.ClientSource{}}
				for _, client := range base.Clients.Clients() {
					source.Clients = append(source.Clients, client.Source())
				}
				source.Clients[1].Secret = source.Clients[0].Secret
				raw, _ := json.Marshal(source)
				ids, _ := base.CoreSnapshot.Identity()
				clients, e := ssopolicy.Compile(raw, ids, ssoReferences{base.CoreSnapshot})
				if e != nil {
					t.Fatal(e)
				}
				c.Clients = clients
				var runtime ssohttp.RuntimeSource
				if json.Unmarshal(base.RuntimeSourceJSON, &runtime) != nil {
					t.Fatal("runtime decode")
				}
				runtime.ClientCatalogDigest = clients.Digest()
				c.RuntimeSourceJSON, _ = json.Marshal(runtime)
				c.ExpectedSourceSHA256 = sha256.Sum256(c.RuntimeSourceJSON)
			}
			h, e := ssohttp.New(c)
			if e == nil || h != nil {
				t.Fatal("invalid startup accepted")
			}
		})
	}
	bad := base
	bad.CoreSnapshot = f.Snapshot(t, nil)
	if h, e := ssohttp.New(bad); e == nil || h != nil {
		t.Fatal("different actual Core accepted")
	}
	closedStore, e := ssosql.OpenApp(t.Context(), ssosql.Config{DSN: s.appDSN, Expected: s.scope, Clock: x.db.clock})
	if e != nil {
		t.Fatal(e)
	}
	closedStore.Close()
	bad = base
	bad.Store = closedStore
	if h, e := ssohttp.New(bad); e == nil || h != nil {
		t.Fatal("closed actual app accepted")
	}
}
