package azure

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"privacy-proxy/internal/brokerpolicy"
	"privacy-proxy/internal/identity"
)

var (
	ErrInvalid  = errors.New("invalid Azure provider binding")
	ErrProvider = errors.New("Azure provider unavailable")
	ErrEvidence = errors.New("invalid Azure evidence")
	ErrRelogin  = errors.New("Azure reauthentication required")
)

type Config struct {
	Catalog       *brokerpolicy.Catalog
	Clock         identity.Clock
	ClientSecrets map[string]string
	Transport     http.RoundTripper
}
type Metadata struct{ BrokerDigest, IdentityDigest string }
type providerProfile struct {
	source                     brokerpolicy.Profile
	provider                   *oidc.Provider
	oauth                      oauth2.Config
	accessVerifier, idVerifier *oidc.IDTokenVerifier
}
type ProviderSet struct {
	metadata       Metadata
	clock          identity.Clock
	profiles       map[string]*providerProfile
	client         *http.Client
	ownedTransport *http.Transport
}
type Continuity struct {
	OID, Tenant                string
	OIDCSubjectHash, NonceHash [32]byte
	OriginalAuthTime           *int64
	InitialLoginAt             int64
}
type Evidence struct {
	profile, profileDigest, authority, tenant, subject string
	kind                                               identity.Kind
	issued, expires, observed                          int64
	facts                                              []identity.Fact
	refresh                                            string
	oidcSubjectHash, nonceHash                         [32]byte
	originalAuthTime                                   *int64
	valid                                              bool
}

func (e Evidence) Valid() bool { return e.valid }
func (e Evidence) Identity() identity.SourceIdentity {
	tenant := e.tenant
	return identity.SourceIdentity{ProfileID: e.profile, Kind: e.kind, Authority: e.authority, Subject: e.subject, Tenant: &tenant}
}
func (e Evidence) Facts() []identity.Fact                   { return slices.Clone(e.facts) }
func (e Evidence) Times() (issued, expires, observed int64) { return e.issued, e.expires, e.observed }
func (e Evidence) ProfileDigest() string                    { return e.profileDigest }
func (e Evidence) RefreshToken() string                     { return e.refresh }
func (e Evidence) Continuity(initialLoginAt int64) Continuity {
	out := Continuity{OID: e.subject, Tenant: e.tenant, OIDCSubjectHash: e.oidcSubjectHash, NonceHash: e.nonceHash, InitialLoginAt: initialLoginAt}
	if e.originalAuthTime != nil {
		value := *e.originalAuthTime
		out.OriginalAuthTime = &value
	}
	return out
}
func (p *ProviderSet) Metadata() Metadata { return p.metadata }
func (p *ProviderSet) Close() {
	if p.ownedTransport != nil {
		p.ownedTransport.CloseIdleConnections()
	}
}
func New(ctx context.Context, c Config) (*ProviderSet, error) {
	if c.Catalog == nil || c.Clock == nil {
		return nil, ErrInvalid
	}
	profiles := c.Catalog.Profiles()
	issuers := []string{}
	needed := map[string]bool{}
	for _, profile := range profiles {
		issuers = append(issuers, profile.Definition.Issuer)
		if profile.Binding.ClientSecret != nil {
			needed[profile.Binding.ClientSecret.FromEnv] = true
		}
	}
	if len(needed) != len(c.ClientSecrets) {
		return nil, ErrInvalid
	}
	for ref := range needed {
		value, ok := c.ClientSecrets[ref]
		if !ok || value == "" || len(value) > 8192 {
			return nil, ErrInvalid
		}
	}
	client, owned := newClient(c.Transport, issuers)
	set := &ProviderSet{metadata: Metadata{c.Catalog.Digest(), c.Catalog.IdentityDigest()}, clock: c.Clock, profiles: map[string]*providerProfile{}, client: client, ownedTransport: owned}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	ctx = oidc.ClientContext(ctx, client)
	providers := map[string]*oidc.Provider{}
	for _, profile := range profiles {
		definition := profile.Definition
		provider := providers[definition.Issuer]
		if provider == nil {
			var err error
			provider, err = oidc.NewProvider(ctx, definition.Issuer)
			if err != nil {
				set.Close()
				return nil, ErrProvider
			}
			providers[definition.Issuer] = provider
		}
		if err := validateDiscovery(provider, definition); err != nil {
			set.Close()
			return nil, err
		}
		entry := &providerProfile{source: profile, provider: provider}
		entry.accessVerifier = provider.Verifier(&oidc.Config{ClientID: definition.APIAudience, SupportedSigningAlgs: []string{"RS256"}, Now: c.Clock})
		if definition.Kind == identity.AzureHuman {
			entry.idVerifier = provider.Verifier(&oidc.Config{ClientID: definition.ClientID, SupportedSigningAlgs: []string{"RS256"}, Now: c.Clock})
			endpoint := provider.Endpoint()
			endpoint.AuthStyle = oauth2.AuthStyleInParams
			entry.oauth = oauth2.Config{ClientID: definition.ClientID, ClientSecret: c.ClientSecrets[profile.Binding.ClientSecret.FromEnv], RedirectURL: profile.Binding.RedirectURI, Endpoint: endpoint, Scopes: []string{oidc.ScopeOpenID, "profile", "email", "offline_access", definition.DelegatedScope}}
		}
		set.profiles[definition.ID] = entry
	}
	return set, nil
}
func validateDiscovery(provider *oidc.Provider, profile identity.Profile) error {
	var doc struct {
		Issuer string `json:"issuer"`
		JWKS   string `json:"jwks_uri"`
	}
	if provider.Claims(&doc) != nil || doc.Issuer != profile.Issuer {
		return ErrProvider
	}
	root := "https://login.microsoftonline.com/" + profile.TenantID
	if doc.JWKS != root+"/discovery/v2.0/keys" && doc.JWKS != "https://login.microsoftonline.com/common/discovery/v2.0/keys" {
		return ErrProvider
	}
	endpoint := provider.Endpoint()
	if endpoint.AuthURL != root+"/oauth2/v2.0/authorize" || endpoint.TokenURL != root+"/oauth2/v2.0/token" {
		return ErrProvider
	}
	return nil
}
func (p *ProviderSet) AuthorizationURL(profileID, state, nonce, verifier string) (string, error) {
	entry := p.profiles[profileID]
	if entry == nil || entry.source.Definition.Kind != identity.AzureHuman || !boundedText(state, 128) || !boundedText(nonce, 128) || len(verifier) < 43 || len(verifier) > 128 {
		return "", ErrInvalid
	}
	return entry.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), nil
}
func (p *ProviderSet) ExchangeCode(ctx context.Context, profileID, code, verifier, nonce string) (Evidence, error) {
	entry := p.profiles[profileID]
	if entry == nil || entry.source.Definition.Kind != identity.AzureHuman || len(code) == 0 || len(code) > 8192 || len(verifier) < 43 || len(verifier) > 128 || !boundedText(nonce, 128) {
		return Evidence{}, ErrInvalid
	}
	ctx, cancel := operation(ctx)
	defer cancel()
	ctx = oidc.ClientContext(ctx, p.client)
	token, err := entry.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Evidence{}, grantError(err)
	}
	evidence, err := p.access(ctx, entry, token.AccessToken, false)
	if err != nil {
		return Evidence{}, err
	}
	idToken, ok := token.Extra("id_token").(string)
	if !ok || idToken == "" {
		return Evidence{}, ErrEvidence
	}
	if err := p.checkID(ctx, entry, idToken, &evidence, nil, nonce); err != nil {
		return Evidence{}, err
	}
	if token.RefreshToken == "" || len(token.RefreshToken) > 32<<10 {
		return Evidence{}, ErrEvidence
	}
	evidence.refresh = token.RefreshToken
	return evidence, nil
}
func (p *ProviderSet) Refresh(ctx context.Context, profileID, refresh string, continuity Continuity) (Evidence, error) {
	entry := p.profiles[profileID]
	if entry == nil || entry.source.Definition.Kind != identity.AzureHuman || len(refresh) == 0 || len(refresh) > 32<<10 {
		return Evidence{}, ErrInvalid
	}
	ctx, cancel := operation(ctx)
	defer cancel()
	ctx = oidc.ClientContext(ctx, p.client)
	// A new refresh-only source is deliberate. A retained TokenSource or a
	// valid AccessToken here would silently reissue cached role evidence.
	token, err := entry.oauth.TokenSource(ctx, &oauth2.Token{RefreshToken: refresh}).Token()
	if err != nil {
		return Evidence{}, grantError(err)
	}
	evidence, err := p.access(ctx, entry, token.AccessToken, false)
	if err != nil {
		return Evidence{}, err
	}
	if evidence.subject != continuity.OID || evidence.tenant != continuity.Tenant {
		return Evidence{}, ErrEvidence
	}
	if raw := token.Extra("id_token"); raw != nil {
		compact, ok := raw.(string)
		if !ok || compact == "" {
			return Evidence{}, ErrEvidence
		}
		if err := p.checkID(ctx, entry, compact, &evidence, &continuity, ""); err != nil {
			return Evidence{}, err
		}
	} else {
		evidence.oidcSubjectHash = continuity.OIDCSubjectHash
		evidence.nonceHash = continuity.NonceHash
		evidence.originalAuthTime = continuity.OriginalAuthTime
	}
	if token.RefreshToken == "" || len(token.RefreshToken) > 32<<10 {
		return Evidence{}, ErrEvidence
	}
	evidence.refresh = token.RefreshToken
	return evidence, nil
}
func (p *ProviderSet) VerifyService(ctx context.Context, profileID, compact string) (Evidence, error) {
	entry := p.profiles[profileID]
	if entry == nil || entry.source.Definition.Kind != identity.AzureService {
		return Evidence{}, ErrInvalid
	}
	ctx, cancel := operation(ctx)
	defer cancel()
	return p.access(ctx, entry, compact, true)
}
func grantError(err error) error {
	var response *oauth2.RetrieveError
	if errors.As(err, &response) {
		switch response.ErrorCode {
		case "invalid_grant", "interaction_required", "login_required":
			return ErrRelogin
		}
	}
	return ErrProvider
}
func (p *ProviderSet) access(ctx context.Context, entry *providerProfile, compact string, service bool) (Evidence, error) {
	if ctx.Err() != nil {
		return Evidence{}, ErrProvider
	}
	claims, err := jwtObject(compact)
	if err != nil {
		return Evidence{}, err
	}
	now := p.clock().Unix()
	issued, expires, err := times(claims, now)
	if err != nil {
		return Evidence{}, err
	}
	definition := entry.source.Definition
	if claims["ver"] != "2.0" || claims["aud"] != definition.APIAudience {
		return Evidence{}, ErrEvidence
	}
	oidValue, err := canonicalUUID(claims["oid"])
	if err != nil {
		return Evidence{}, err
	}
	tenant, err := canonicalUUID(claims["tid"])
	if err != nil || tenant != definition.TenantID {
		return Evidence{}, ErrEvidence
	}
	client, err := canonicalUUID(claims["azp"])
	if err != nil {
		return Evidence{}, err
	}
	kind := identity.Human
	if service {
		if claims["idtyp"] != "app" || !slices.Contains(definition.AllowedClientIDs, client) {
			return Evidence{}, ErrEvidence
		}
		if _, exists := claims["scp"]; exists {
			return Evidence{}, ErrEvidence
		}
		kind = identity.Service
	} else {
		if claims["idtyp"] == "app" || client != definition.ClientID {
			return Evidence{}, ErrEvidence
		}
		scope, ok := claims["scp"].(string)
		if !ok || !scopeContains(scope, entry.source.ScopeWord) {
			return Evidence{}, ErrEvidence
		}
	}
	if _, err := entry.accessVerifier.Verify(ctx, compact); err != nil {
		if ctx.Err() != nil {
			return Evidence{}, ErrProvider
		}
		return Evidence{}, ErrEvidence
	}
	facts, err := selectedFacts(claims, definition)
	if err != nil {
		return Evidence{}, err
	}
	verifiedAt := p.clock().Unix()
	if ctx.Err() != nil {
		return Evidence{}, ErrProvider
	}
	if _, _, err := times(claims, verifiedAt); err != nil {
		return Evidence{}, err
	}
	return Evidence{profile: definition.ID, profileDigest: entry.source.Digest, authority: definition.Issuer, tenant: tenant, subject: oidValue, kind: kind, issued: issued, expires: expires, observed: verifiedAt, facts: facts, valid: true}, nil
}
func scopeContains(raw, word string) bool {
	if len(raw) > 8192 || word == "" {
		return false
	}
	for _, b := range []byte(raw) {
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	return slices.Contains(strings.Split(raw, " "), word)
}
func (p *ProviderSet) checkID(ctx context.Context, entry *providerProfile, compact string, evidence *Evidence, old *Continuity, nonce string) error {
	claims, err := jwtObject(compact)
	if err != nil {
		return err
	}
	if _, _, err := times(claims, p.clock().Unix()); err != nil {
		return err
	}
	// The SDK accepts a client among several audiences. This deliberately
	// narrower broker profile requires the selected client's single audience.
	if audience, ok := claims["aud"].(string); !ok || audience != entry.source.Definition.ClientID {
		return ErrEvidence
	}
	verified, err := entry.idVerifier.Verify(ctx, compact)
	if err != nil {
		if ctx.Err() != nil {
			return ErrProvider
		}
		return ErrEvidence
	}
	// The SDK permits expiry equal to its current time. Apply this profile's
	// strict boundary again after signature/JWKS work, as for access evidence.
	if ctx.Err() != nil {
		return ErrProvider
	}
	if _, _, err := times(claims, p.clock().Unix()); err != nil {
		return err
	}
	oidValue, err := canonicalUUID(claims["oid"])
	if err != nil || oidValue != evidence.subject {
		return ErrEvidence
	}
	tenant, err := canonicalUUID(claims["tid"])
	if err != nil || tenant != evidence.tenant {
		return ErrEvidence
	}
	subject, ok := claims["sub"].(string)
	if !ok || !boundedText(subject, 1024) || verified.Subject != subject {
		return ErrEvidence
	}
	subjectHash := sha256.Sum256([]byte(subject))
	if old == nil {
		if verified.Nonce != nonce {
			return ErrEvidence
		}
		evidence.oidcSubjectHash = subjectHash
		evidence.nonceHash = sha256.Sum256([]byte(nonce))
	} else {
		if subjectHash != old.OIDCSubjectHash {
			return ErrEvidence
		}
		if raw, present := claims["nonce"]; present {
			value, ok := raw.(string)
			if !ok || sha256.Sum256([]byte(value)) != old.NonceHash {
				return ErrEvidence
			}
		}
		evidence.oidcSubjectHash = old.OIDCSubjectHash
		evidence.nonceHash = old.NonceHash
	}
	authTime, present, err := integer(claims, "auth_time", false)
	if err != nil {
		return err
	}
	if old == nil {
		if present {
			if authTime > evidence.observed {
				return ErrEvidence
			}
			evidence.originalAuthTime = &authTime
		}
	} else {
		if present && (authTime > old.InitialLoginAt || old.OriginalAuthTime != nil && authTime != *old.OriginalAuthTime) {
			return ErrEvidence
		}
		evidence.originalAuthTime = old.OriginalAuthTime
	}
	return nil
}
