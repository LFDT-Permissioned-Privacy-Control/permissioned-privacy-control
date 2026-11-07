package privado

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/iden3comm/v2/packers"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/iden3/iden3comm/v2/utils"
	f "privacy-proxy/internal/brokertest"
	"privacy-proxy/internal/identity"
)

const fixtureContract = "0x1111111111111111111111111111111111111111"
const fixtureContextURL = "https://schemas.test/bank-role.jsonld"

var fixtureContext = []byte(`{"@context":{"role":{"@id":"https://schemas.test/role","@type":"http://www.w3.org/2001/XMLSchema#integer"},"BankRole":"https://schemas.test/BankRole"}}`)

type groups struct{}
type publicProofFixture struct {
	TestOnly string
	Request  Request
	Compact  string
}
type roundTripper func(*http.Request) (*http.Response, error)

func (r roundTripper) RoundTrip(q *http.Request) (*http.Response, error) { return r(q) }
func (groups) HasGroup(string, string) bool                              { return true }

func fixtureDID(t *testing.T, network string, state int64) (core.ID, string) {
	t.Helper()
	parts := strings.Split(network, ":")
	b, err := core.GetBlockchain(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	n, err := core.GetNetwork(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	typ, err := core.BuildDIDType(core.DIDMethodIden3, b, n)
	if err != nil {
		t.Fatal(err)
	}
	id, err := core.NewIDFromIdenState(typ, new(big.Int).Lsh(big.NewInt(state), 40))
	if err != nil {
		t.Fatal(err)
	}
	did, err := core.ParseDIDFromID(*id)
	if err != nil {
		t.Fatal(err)
	}
	return *id, did.String()
}
func fixtureSource(t *testing.T) identity.SourceCatalog {
	_, verifier := fixtureDID(t, "polygon:mumbai", 11)
	_, issuer := fixtureDID(t, "polygon:mumbai", 12)
	s := f.IdentitySource()
	s.Profiles = append(s.Profiles, identity.Profile{ID: "privado", Kind: identity.PrivadoIdentity, VerifierID: verifier, Network: "polygon:mumbai", IdentityStateContract: fixtureContract}, identity.Profile{ID: "role", Kind: identity.PrivadoRole, VerifierID: verifier, Network: "polygon:mumbai", IdentityStateContract: fixtureContract, AllowedCredentialIssuers: []string{issuer}, Context: fixtureContextURL, ContextDigest: hashBytes(fixtureContext), Type: "BankRole", CircuitID: "credentialAtomicQuerySigV2", Predicates: []identity.Predicate{{ID: "reader", Field: "role", Operator: "eq", Value: "7"}}})
	s.Issuers[0].AllowedProfiles = append(s.Issuers[0].AllowedProfiles, "privado", "role")
	return s
}
func compileFixture(t *testing.T, s identity.SourceCatalog) *identity.Catalog {
	t.Helper()
	c, e := identity.Compile(s, groups{}, identity.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func fixtureOptions(t *testing.T) Options {
	t.Helper()
	return Options{Catalog: compileFixture(t, fixtureSource(t)), ProfileIDs: []string{"privado", "role"}, Networks: []NetworkBinding{{Network: "polygon:mumbai", ChainID: "80001", StateContract: fixtureContract, URL: "https://state.test/rpc"}}, Documents: []PinnedDocument{{URL: fixtureContextURL, RawBytes: bytes.Clone(fixtureContext)}}, Clock: time.Now}
}
func fixtureProvider(t *testing.T, change func(*Options)) *Provider {
	t.Helper()
	o := fixtureOptions(t)
	if change != nil {
		change(&o)
	}
	p, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}
func fixtureRequest(t *testing.T, p *Provider, profile string) Request {
	t.Helper()
	now := time.Unix(time.Now().Unix(), 0).UTC()
	r, err := p.CreateRequest(RequestContext{ProfileID: profile, RequestID: uuid.NewString(), Nonce32: [32]byte{1}, CreatedAt: now, ExpiresAt: now.Add(MaxAge), CallbackURL: "https://ops.test/callback?request=public-id", Mode: Login})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func sdkRequest(t *testing.T, r Request) protocol.AuthorizationRequestMessage {
	t.Helper()
	var s protocol.AuthorizationRequestMessage
	if json.Unmarshal(r.AuthorizationJSON, &s) != nil {
		t.Fatal("canonical request")
	}
	return s
}

func TestStartupSnapshotsOnlyPublicPlans(t *testing.T) {
	o := fixtureOptions(t)
	o.Networks[0].Credential = &CredentialBinding{RefID: "STATE_RPC_KEY", Header: "Authorization", Value: "Bearer test-only-material"}
	p, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	meta := p.Metadata()
	o.Networks[0].Credential.Value = "Bearer other-length-material-that-must-not-change-public-digest"
	p2, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	if p2.Metadata() != meta {
		t.Fatal("resolved secret enters public metadata")
	}
	o.Networks[0].Credential.RefID = "OTHER_REF"
	p3, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	defer p3.Close()
	if p3.Metadata() == meta {
		t.Fatal("approved public credential reference not bound")
	}
	o.Documents[0].RawBytes[0] = '!'
	o.ProfileIDs[0] = "bad"
	o.Networks[0].URL = "https://changed.test/"
	if p.Metadata() != meta || p.networks["polygon:mumbai"].binding.Credential.Value != "Bearer test-only-material" {
		t.Fatal("caller mutation reaches provider")
	}
	l := documentLoader{p}
	a, err := l.LoadDocument(fixtureContextURL)
	if err != nil {
		t.Fatal(err)
	}
	a.Document.(map[string]any)["@context"] = nil
	b, err := l.LoadDocument(fixtureContextURL)
	if err != nil || b.Document.(map[string]any)["@context"] == nil {
		t.Fatal("mutable shared JSON-LD context")
	}
	for _, uri := range []string{"file:///tmp/context", "https://other.test/context", "ipfs://unapproved"} {
		if _, e := l.LoadDocument(uri); e == nil {
			t.Fatal("loader fallback")
		}
	}
}

func TestUnsupportedSelectedSourceFailsCold(t *testing.T) {
	for name, change := range map[string]func(*Options){
		"unknown profile":            func(o *Options) { o.ProfileIDs = []string{"missing"} },
		"duplicate profile":          func(o *Options) { o.ProfileIDs = append(o.ProfileIDs, "role") },
		"missing network":            func(o *Options) { o.Networks = nil },
		"conflicting state contract": func(o *Options) { o.Networks[0].StateContract = "0x2222222222222222222222222222222222222222" },
		"endpoint query":             func(o *Options) { o.Networks[0].URL += "?key=never" },
		"credential control": func(o *Options) {
			o.Networks[0].Credential = &CredentialBinding{RefID: "RPC", Header: "Authorization", Value: "x\r\ny"}
		},
		"credential header": func(o *Options) {
			o.Networks[0].Credential = &CredentialBinding{RefID: "RPC", Header: "Host", Value: "other.test"}
		},
		"context missing":  func(o *Options) { o.Documents = nil },
		"context mismatch": func(o *Options) { o.Documents[0].RawBytes = []byte(`{"@context":{}}`) },
		"verifier identifier not DID": func(o *Options) {
			s := fixtureSource(t)
			s.Profiles[len(s.Profiles)-1].VerifierID = "https://ops.test"
			o.Catalog = compileFixture(t, s)
		},
		"large static scopes": func(o *Options) {
			s := fixtureSource(t)
			v := &s.Profiles[len(s.Profiles)-1]
			for i := 1; i < 16; i++ {
				v.Predicates = append(v.Predicates, identity.Predicate{ID: fmt.Sprintf("p%d", i), Field: "role", Operator: "eq", Value: "7"})
			}
			for i := 20; i < 70; i++ {
				_, did := fixtureDID(t, "polygon:mumbai", int64(i))
				v.AllowedCredentialIssuers = append(v.AllowedCredentialIssuers, did)
			}
			o.Catalog = compileFixture(t, s)
		},
	} {
		t.Run(name, func(t *testing.T) {
			o := fixtureOptions(t)
			change(&o)
			if p, e := New(o); e == nil {
				p.Close()
				t.Fatal("unsupported source accepted")
			}
		})
	}
}

func TestCanonicalRequestRequiresAllConfiguredProofs(t *testing.T) {
	p := fixtureProvider(t, nil)
	r := fixtureRequest(t, p, "role")
	s := sdkRequest(t, r)
	if len(s.Body.Accept) != 1 {
		t.Fatal("ambiguous wallet envelope negotiation")
	}
	accepted, err := utils.ParseAcceptProfile(s.Body.Accept[0])
	if err != nil || accepted.Env != packers.MediaTypeZKPMessage || len(accepted.AcceptCircuits) != 1 || accepted.AcceptCircuits[0] != circuits.AuthV2CircuitID || len(accepted.AcceptJwzAlgorithms) != 1 || accepted.AcceptJwzAlgorithms[0] != protocol.JwzAlgorithmsGroth16 {
		t.Fatal("actual SDK parser did not negotiate exactly Groth16 AuthV2", err)
	}
	if len(s.Body.Scope) != 1 || s.Body.Scope[0].Optional == nil || *s.Body.Scope[0].Optional || s.Body.Message == "" || s.ThreadID != r.Context.RequestID || s.From != p.profiles["role"].source.VerifierID {
		t.Fatal("weak challenge or query")
	}
	if s.Body.Scope[0].Query["skipClaimRevocationCheck"] != false || s.Body.Scope[0].CircuitID != "credentialAtomicQuerySigV2" {
		t.Fatal("revocation/circuit query changed")
	}
	if len(sdkRequest(t, fixtureRequest(t, p, "privado")).Body.Scope) != 0 {
		t.Fatal("identity-only request gained role facts")
	}
	mutated := r
	mutated.AuthorizationJSON = append(bytes.Clone(r.AuthorizationJSON), ' ')
	if _, e := p.Verify(t.Context(), mutated, "not-a-token"); !errors.Is(e, ErrEvidence) {
		t.Fatal("saved query not rebuilt")
	}
	for name, change := range map[string]func(*RequestContext){"zero nonce": func(c *RequestContext) { c.Nonce32 = [32]byte{} }, "long lifetime": func(c *RequestContext) { c.ExpiresAt = c.CreatedAt.Add(301 * time.Second) }, "expired": func(c *RequestContext) { c.ExpiresAt = c.CreatedAt }, "renew without actor": func(c *RequestContext) { c.Mode = Renew }, "login with actor": func(c *RequestContext) { c.ExpectedActorID = "ops:p1:" + strings.Repeat("A", 43) }} {
		t.Run(name, func(t *testing.T) {
			c := r.Context
			change(&c)
			if _, e := p.CreateRequest(c); e == nil {
				t.Fatal("invalid context")
			}
		})
	}
	r.AuthorizationJSON[0] = '!'
	if _, e := p.CreateRequest(r.Context); e != nil {
		t.Fatal("output mutation changed provider")
	}
}

func TestRequestFloorsTimesAndBoundsEscapedCallback(t *testing.T) {
	p := fixtureProvider(t, nil)
	c := fixtureRequest(t, p, "role").Context
	c.CreatedAt = c.CreatedAt.Add(990 * time.Millisecond).In(time.FixedZone("fixture", 7200))
	c.ExpiresAt = c.CreatedAt.Add(MaxAge)
	prefix := "https://ops.test/callback?x="
	c.CallbackURL = prefix + strings.Repeat("&", 2048-len(prefix))
	r, e := p.CreateRequest(c)
	if e != nil {
		t.Fatal(e)
	}
	if len(r.AuthorizationJSON) > MaxRequestBytes || r.Context.CreatedAt.Nanosecond() != 0 || r.Context.ExpiresAt.Nanosecond() != 0 || r.Context.ExpiresAt.After(c.ExpiresAt) || r.Context.ExpiresAt.Sub(r.Context.CreatedAt) > MaxAge {
		t.Fatal("request duration rounded up or valid envelope oversized")
	}
	if sdkRequest(t, r).Body.CallbackURL != c.CallbackURL {
		t.Fatal("callback correlation query not preserved")
	}
	c.CallbackURL += "&"
	if _, e := p.CreateRequest(c); e == nil {
		t.Fatal("oversized callback accepted")
	}
}

func TestVerifyAdmissionPrecedesAnyInputWork(t *testing.T) {
	p := fixtureProvider(t, nil)
	for i := 0; i < MaxInFlight; i++ {
		p.slots <- struct{}{}
	}
	if _, e := p.Verify(context.Background(), Request{}, strings.Repeat("a", MaxCompactBytes+1)); !errors.Is(e, ErrBusy) {
		t.Fatal("parser precedes admission", e)
	}
	for i := 0; i < MaxInFlight; i++ {
		<-p.slots
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e := p.Verify(ctx, Request{}, "bad"); !errors.Is(e, ErrProvider) {
		t.Fatal("canceled attempt ran")
	}
	p.Close()
	if _, e := p.CreateRequest(RequestContext{}); !errors.Is(e, ErrProvider) {
		t.Fatal("closed provider used")
	}
}

func unprovedCompact(t *testing.T, r Request, holder string) string {
	t.Helper()
	req := sdkRequest(t, r)
	id, _, e := parseIdentityDID(holder)
	if e != nil {
		t.Fatal(e)
	}
	header := map[string]any{"alg": "groth16", "circuitId": "authV2", "typ": "application/iden3-zkp-json", "crit": []string{"circuitId"}}
	payload := map[string]any{"id": uuid.NewString(), "type": string(protocol.AuthorizationResponseMessageType), "thid": req.ID, "from": holder, "to": req.From, "body": map[string]any{"message": req.Body.Message, "scope": []any{}}}
	proof := map[string]any{"proof": map[string]any{"pi_a": []string{"1", "2", "1"}, "pi_b": [][]string{{"1", "2"}, {"3", "4"}, {"1", "0"}}, "pi_c": []string{"1", "2", "1"}, "protocol": "groth16"}, "pub_signals": []string{id.BigInt().String(), "1", "1234"}}
	var parts []string
	for _, value := range []any{header, payload, proof} {
		raw, _ := json.Marshal(value)
		parts = append(parts, base64.RawURLEncoding.EncodeToString(raw))
	}
	return strings.Join(parts, ".")
}
func TestUnverifiedStructureCannotProduceEvidence(t *testing.T) {
	var calls atomic.Int64
	p := fixtureProvider(t, func(o *Options) {
		o.Transport = roundTripper(func(*http.Request) (*http.Response, error) { calls.Add(1); return nil, ErrProvider })
	})
	r := fixtureRequest(t, p, "privado")
	_, holder := fixtureDID(t, "polygon:mumbai", 13)
	compact := unprovedCompact(t, r, holder)
	if _, e := parseCompact(compact, sdkRequest(t, r), p.profiles["privado"], time.Now().Unix()); e != nil {
		t.Fatal("structural positive control", e)
	}
	if result, e := p.Verify(t.Context(), r, compact); e == nil || result != nil {
		t.Fatal("preflight tags granted verified proof")
	}
	if calls.Load() != 0 {
		t.Fatal("invalid outer Groth16 reached resolver")
	}
}
