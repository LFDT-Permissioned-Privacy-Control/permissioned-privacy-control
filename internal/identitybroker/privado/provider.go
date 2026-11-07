package privado

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/textproto"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/iden3comm/v2/packers"
	"github.com/iden3/iden3comm/v2/protocol"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/netguard"
)

type selectedProfile struct {
	source identity.Profile
	digest string
}
type network struct {
	binding   NetworkBinding
	transport http.RoundTripper
	owned     *http.Transport
}
type Provider struct {
	catalog   *identity.Catalog
	metadata  Metadata
	profiles  map[string]selectedProfile
	networks  map[string]*network
	documents map[string][]byte
	clock     identity.Clock
	slots     chan struct{}
	closed    atomic.Bool
}

func (p *Provider) Metadata() Metadata { return p.metadata }
func (p *Provider) Close() {
	if p == nil || p.closed.Swap(true) {
		return
	}
	for _, n := range p.networks {
		if n.owned != nil {
			n.owned.CloseIdleConnections()
		}
	}
}
func (p *Provider) now() (int64, error) {
	if p == nil || p.clock == nil || p.closed.Load() {
		return 0, ErrProvider
	}
	now := p.clock().UTC().Unix()
	if now < 0 || now > 253402300499 {
		return 0, ErrProvider
	}
	return now, nil
}
func New(o Options) (*Provider, error) {
	if o.Catalog == nil || o.Clock == nil || len(o.ProfileIDs) == 0 || len(o.ProfileIDs) > MaxProfiles || len(o.Networks) == 0 || len(o.Networks) > MaxNetworks || len(o.Documents) > 16 {
		return nil, ErrInvalid
	}
	p := &Provider{catalog: o.Catalog, profiles: map[string]selectedProfile{}, networks: map[string]*network{}, documents: map[string][]byte{}, clock: o.Clock, slots: make(chan struct{}, MaxInFlight)}
	if _, err := p.now(); err != nil {
		return nil, err
	}
	needed := map[string]bool{}
	available := map[string]identity.Profile{}
	for _, v := range o.Catalog.Source().Profiles {
		available[v.ID] = v
	}
	ids := slices.Clone(o.ProfileIDs)
	sort.Strings(ids)
	profilePlan := []struct{ ID, Digest string }{}
	for _, id := range ids {
		v, ok := available[id]
		if !ok || (v.Kind != identity.PrivadoIdentity && v.Kind != identity.PrivadoRole) || p.profiles[id].digest != "" || len(v.Predicates) > MaxPredicates {
			return nil, ErrInvalid
		}
		verifier, err := w3c.ParseDID(v.VerifierID)
		if err != nil || verifier.String() != v.VerifierID {
			return nil, ErrInvalid
		}
		if !knownNetwork(v.Network) {
			return nil, ErrInvalid
		}
		// Canonical scope has its own cold bound. The other half of the 64KiB
		// envelope covers worst-case JSON escaping: callback2048*6 + verifier
		// DID1024*6 + fixed UUID/message/header/times, without guessed issuer
		// truncation. This precedes clients, transports and proof work.
		if raw, err := json.Marshal(profileScopes(v)); err != nil || len(raw) > MaxScopeBytes {
			return nil, ErrInvalid
		}
		needed[v.Network] = true
		for _, issuer := range v.AllowedCredentialIssuers {
			_, network, err := parseIdentityDID(issuer)
			if err != nil {
				return nil, ErrInvalid
			}
			needed[network] = true
		}
		digest, _ := o.Catalog.ProfileDigest(id)
		p.profiles[id] = selectedProfile{v, digest}
		profilePlan = append(profilePlan, struct{ ID, Digest string }{id, digest})
	}
	if len(needed) != len(o.Networks) {
		return nil, ErrInvalid
	}
	type publicNetwork struct {
		Network, ChainID, StateContract, URL string
		AllowPrivate                         bool
		CredentialRef, Header                string
	}
	networkPlan := []publicNetwork{}
	for _, raw := range o.Networks {
		b := raw
		if !needed[b.Network] || p.networks[b.Network] != nil || !canonicalHTTPS(b.URL, false) || !canonicalAddress(b.StateContract) || !positiveDecimal(b.ChainID, 78) {
			p.Close()
			return nil, ErrInvalid
		}
		chain, _ := new(big.Int).SetString(b.ChainID, 10)
		if chain.BitLen() > 256 {
			p.Close()
			return nil, ErrInvalid
		}
		pub := publicNetwork{Network: b.Network, ChainID: b.ChainID, StateContract: b.StateContract, URL: b.URL, AllowPrivate: b.AllowPrivate}
		if b.Credential != nil {
			c := *b.Credential
			if !name(c.RefID, 128) || c.Header != textproto.CanonicalMIMEHeaderKey(c.Header) || !credentialHeader(c.Header) || !printable(c.Value, 8192) {
				p.Close()
				return nil, ErrInvalid
			}
			b.Credential = &c
			pub.CredentialRef = c.RefID
			pub.Header = c.Header
		}
		n := &network{binding: b, transport: o.Transport}
		if n.transport == nil {
			n.owned = netguard.GuardedTransport(b.AllowPrivate)
			n.owned.MaxConnsPerHost = MaxInFlight
			n.owned.MaxIdleConnsPerHost = MaxInFlight
			n.owned.MaxIdleConns = MaxInFlight
			n.transport = n.owned
		}
		p.networks[b.Network] = n
		networkPlan = append(networkPlan, pub)
	}
	for _, profile := range p.profiles {
		if p.networks[profile.source.Network].binding.StateContract != profile.source.IdentityStateContract {
			p.Close()
			return nil, ErrInvalid
		}
	}
	sort.Slice(networkPlan, func(i, j int) bool { return networkPlan[i].Network < networkPlan[j].Network })
	total := 0
	docPlan := []struct{ URL, Digest string }{}
	for _, d := range o.Documents {
		if !canonicalHTTPS(d.URL, false) || len(d.RawBytes) == 0 || len(d.RawBytes) > 1<<20 || len(d.RawBytes) > 2<<20-total || !utf8.Valid(d.RawBytes) {
			p.Close()
			return nil, ErrInvalid
		}
		total += len(d.RawBytes)
		if prior, found := p.documents[d.URL]; found {
			if !bytes.Equal(prior, d.RawBytes) {
				p.Close()
				return nil, ErrInvalid
			}
			continue
		}
		var document any
		if json.Unmarshal(d.RawBytes, &document) != nil {
			p.Close()
			return nil, ErrInvalid
		}
		if _, ok := document.(map[string]any); !ok {
			p.Close()
			return nil, ErrInvalid
		}
		p.documents[d.URL] = bytes.Clone(d.RawBytes)
		docPlan = append(docPlan, struct{ URL, Digest string }{d.URL, hashBytes(d.RawBytes)})
	}
	for _, profile := range p.profiles {
		if profile.source.Kind == identity.PrivadoRole {
			if raw, ok := p.documents[profile.source.Context]; !ok || hashBytes(raw) != profile.source.ContextDigest {
				p.Close()
				return nil, ErrInvalid
			}
		}
	}
	sort.Slice(docPlan, func(i, j int) bool { return docPlan[i].URL < docPlan[j].URL })
	p.metadata = Metadata{o.Catalog.Digest(), hashJSON(profilePlan), hashJSON(networkPlan), hashJSON(docPlan)}
	return p, nil
}

func (p *Provider) CreateRequest(c RequestContext) (Request, error) {
	now, err := p.now()
	if err != nil {
		return Request{}, err
	}
	profile, ok := p.profiles[c.ProfileID]
	if !ok || !canonicalUUID(c.RequestID) || c.Nonce32 == ([32]byte{}) || !canonicalHTTPS(c.CallbackURL, true) ||
		c.CreatedAt.Unix() < 0 || c.CreatedAt.Unix() > now+30 || c.ExpiresAt.Unix() <= now || c.ExpiresAt.Unix() > 253402300799 ||
		c.ExpiresAt.Unix() <= c.CreatedAt.Unix() || c.ExpiresAt.Unix()-c.CreatedAt.Unix() > 300 ||
		(c.Mode != Login && c.Mode != Renew) || c.Mode == Login && c.ExpectedActorID != "" || c.Mode == Renew && !identity.ValidActorID(c.ExpectedActorID) {
		return Request{}, ErrInvalid
	}
	c.CreatedAt = time.Unix(c.CreatedAt.Unix(), 0).UTC()
	c.ExpiresAt = time.Unix(c.ExpiresAt.Unix(), 0).UTC()
	created, expires := c.CreatedAt.Unix(), c.ExpiresAt.Unix()
	request := protocol.AuthorizationRequestMessage{ID: c.RequestID, ThreadID: c.RequestID, Typ: packers.MediaTypePlainMessage, Type: protocol.AuthorizationRequestMessageType, From: profile.source.VerifierID, CreatedTime: &created, ExpiresTime: &expires}
	request.Body = protocol.AuthorizationRequestMessageBody{CallbackURL: c.CallbackURL, Message: "ops.privado.challenge/v1:" + c.RequestID + ":" + base64.RawURLEncoding.EncodeToString(c.Nonce32[:]), Scope: []protocol.ZeroKnowledgeProofRequest{}, Accept: []string{"iden3comm/v1;env=application/iden3-zkp-json;alg=groth16;circuitId=authV2"}}
	request.Body.Scope = profileScopes(profile.source)
	raw, err := json.Marshal(request)
	if err != nil || len(raw) > MaxRequestBytes {
		return Request{}, ErrInvalid
	}
	return Request{c, profile.digest, p.metadata, raw}, nil
}

func profileScopes(profile identity.Profile) []protocol.ZeroKnowledgeProofRequest {
	scopes := []protocol.ZeroKnowledgeProofRequest{}
	for i, predicate := range profile.Predicates {
		optional := false
		value, _ := strconv.ParseUint(predicate.Value, 10, 32)
		query := map[string]any{"allowedIssuers": slices.Clone(profile.AllowedCredentialIssuers), "context": profile.Context, "type": profile.Type, "proofType": "BJJSignature2021", "skipClaimRevocationCheck": false, "credentialSubject": map[string]any{predicate.Field: map[string]any{"$eq": value}}}
		scopes = append(scopes, protocol.ZeroKnowledgeProofRequest{ID: uint32(i + 1), CircuitID: "credentialAtomicQuerySigV2", Optional: &optional, Query: query})
	}
	return scopes
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func hashJSON(v any) string { raw, _ := json.Marshal(v); return hashBytes(raw) }
func canonicalUUID(s string) bool {
	u, e := uuid.Parse(s)
	return e == nil && u != uuid.Nil && u.String() == s
}
func canonicalAddress(s string) bool {
	return len(s) == 42 && s == strings.ToLower(s) && common.IsHexAddress(s) && common.HexToAddress(s) != (common.Address{})
}
func canonicalHTTPS(s string, query bool) bool {
	if !printable(s, 2048) {
		return false
	}
	u, e := url.Parse(s)
	return e == nil && u.Scheme == "https" && u.Host != "" && u.Host == strings.ToLower(u.Host) && u.User == nil && u.Fragment == "" && u.Opaque == "" && (!u.ForceQuery && (query || u.RawQuery == "")) && u.String() == s && !strings.Contains(s, "\\")
}
func printable(s string, max int) bool {
	if len(s) == 0 || len(s) > max || strings.TrimSpace(s) != s {
		return false
	}
	for _, c := range []byte(s) {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}
func name(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func positiveDecimal(s string, max int) bool { return s != "0" && decimal(s, max) }
func decimal(s string, max int) bool {
	if len(s) == 0 || len(s) > max || len(s) > 1 && s[0] == '0' {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func credentialHeader(s string) bool {
	if !printable(s, 128) {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	switch strings.ToLower(s) {
	case "host", "cookie", "content-length", "content-type", "connection", "transfer-encoding", "accept-encoding", "proxy-authorization", "origin", "referer":
		return false
	}
	return true
}
func knownNetwork(s string) bool {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return false
	}
	b, err := core.GetBlockchain(parts[0])
	if err != nil {
		return false
	}
	n, err := core.GetNetwork(parts[1])
	if err != nil {
		return false
	}
	_, err = core.BuildDIDType(core.DIDMethodIden3, b, n)
	return err == nil
}
func parseIdentityDID(s string) (core.ID, string, error) {
	d, err := w3c.ParseDID(s)
	if err != nil || d.String() != s {
		return core.ID{}, "", ErrEvidence
	}
	id, err := core.IDFromDID(*d)
	if err != nil {
		return core.ID{}, "", ErrEvidence
	}
	canonical, err := core.ParseDIDFromID(id)
	if err != nil || canonical.String() != s {
		return core.ID{}, "", ErrEvidence
	}
	return id, networkOf(id), nil
}
func networkOf(id core.ID) string {
	b, e1 := core.BlockchainFromID(id)
	n, e2 := core.NetworkIDFromID(id)
	if e1 != nil || e2 != nil {
		return ""
	}
	return string(b) + ":" + string(n)
}

func operation(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, OperationTimeout)
}
